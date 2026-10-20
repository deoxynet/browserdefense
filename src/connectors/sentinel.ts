/**
 * BrowserDefense Microsoft Sentinel Connector
 *
 * Sends forensics events to Microsoft Sentinel via the Log Analytics Data Collector API.
 * Uses Azure Shared Key authentication (HMAC-SHA256).
 *
 * @see https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
 */

import { BaseConnector, connectorRegistry } from './base';
import {
  ConnectorType,
  ForensicsEvent,
  SendResult,
  SentinelConnectorConfig,
} from './types';

// =============================================================================
// Constants
// =============================================================================

/** Maximum payload size per POST request (32MB) */
const MAX_PAYLOAD_SIZE = 32 * 1024 * 1024;

/** API version for Log Analytics Data Collector API */
const API_VERSION = '2016-04-01';

/** Content type for requests */
const CONTENT_TYPE = 'application/json';

// =============================================================================
// Sentinel Log Entry Types
// =============================================================================

/**
 * Event action type for block/unblock events.
 */
export type SentinelEventAction = 'blocked' | 'unblocked';

/**
 * Format of a single log entry sent to Sentinel.
 * Field names will be suffixed with type indicators in Sentinel:
 * - _s for strings
 * - _t for timestamps
 * - _b for booleans
 * - _d for numbers
 */
export interface SentinelLogEntry {
  /** Event type identifier (blockioc:block or blockioc:unblock) */
  event_type: 'blockioc:block' | 'blockioc:unblock';
  /** Action taken (blocked or unblocked) */
  action: SentinelEventAction;
  /** The blocked URL that triggered the event */
  blocked_url: string;
  /** ISO8601 timestamp when the block occurred */
  timestamp: string;
  /** Chain of redirects leading to the blocked URL (JSON array string) */
  redirect_chain: string;
  /** Organization identifier */
  org_id: string;
  /** Unique event identifier */
  event_id: string;
  /** IOC type that matched (domain, url, hash) */
  match_type: string;
  /** The specific IOC pattern that matched */
  matched_indicator: string;
  /** Tab ID where the block occurred */
  tab_id: number;
  /** URL of the page that initiated the blocked navigation */
  initiator_url: string;
  /** Title of the tab at block time */
  tab_title: string;
  /** Whether the tab was in incognito mode */
  incognito: boolean;
  /** User identifier (if available) */
  user_id: string;
  /** Device identifier (if available) */
  device_id: string;
}

// =============================================================================
// Crypto Utilities
// =============================================================================

/**
 * Compute HMAC-SHA256 using Web Crypto API.
 */
async function hmacSha256(key: Uint8Array, message: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const messageBytes = encoder.encode(message);

  // Create a new ArrayBuffer copy to ensure TypeScript compatibility
  const keyBuffer = new ArrayBuffer(key.length);
  new Uint8Array(keyBuffer).set(key);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageBytes);
  return new Uint8Array(signature);
}

/**
 * Base64 decode helper.
 */
function base64Decode(str: string): Uint8Array {
  // Handle both browser and Node.js environments
  if (typeof atob === 'function') {
    const binaryString = atob(str);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
  // Node.js Buffer fallback
  return new Uint8Array(Buffer.from(str, 'base64'));
}

/**
 * Base64 encode helper.
 */
function base64Encode(bytes: Uint8Array): string {
  // Handle both browser and Node.js environments
  if (typeof btoa === 'function') {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  // Node.js Buffer fallback
  return Buffer.from(bytes).toString('base64');
}

// =============================================================================
// Sentinel Connector Implementation
// =============================================================================

/**
 * Microsoft Sentinel connector implementation.
 *
 * Sends forensics events to Azure Log Analytics workspace using the
 * Data Collector API with Shared Key authentication.
 *
 * Features:
 * - Shared Key (HMAC-SHA256) authentication
 * - Batch support (up to 32MB per request)
 * - Custom log type naming
 * - Time-generated field support
 * - Azure resource context for resource-centric logs
 *
 * Data will appear in Sentinel as a custom log table with the name:
 * {logType}_CL (e.g., BrowserDefense_Forensics_CL)
 */
export class SentinelConnector extends BaseConnector {
  readonly type: ConnectorType = 'sentinel';

  private readonly workspaceId: string;
  private readonly sharedKey: string;
  private readonly logType: string;
  private readonly azureResourceId?: string;
  private readonly timeGeneratedField?: string;
  private readonly apiUrl: string;

  constructor(config: SentinelConnectorConfig) {
    super(config);
    this.workspaceId = config.workspaceId;
    this.sharedKey = config.sharedKey;
    this.logType = config.logType;
    this.azureResourceId = config.azureResourceId;
    this.timeGeneratedField = config.timeGeneratedField;
    this.apiUrl = `https://${this.workspaceId}.ods.opinsights.azure.com/api/logs?api-version=${API_VERSION}`;
  }

  // ===========================================================================
  // Abstract method implementations
  // ===========================================================================

  protected async doInit(): Promise<void> {
    // Validate configuration
    if (!this.workspaceId) {
      throw new Error('Sentinel connector requires workspaceId');
    }
    if (!this.sharedKey) {
      throw new Error('Sentinel connector requires sharedKey');
    }
    if (!this.logType) {
      throw new Error('Sentinel connector requires logType');
    }

    // Validate logType format (alphanumeric and underscore only, must start with letter)
    if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(this.logType)) {
      throw new Error(
        'logType must start with a letter and contain only alphanumeric characters and underscores'
      );
    }

    // Validate shared key by attempting to decode it
    try {
      const keyBytes = base64Decode(this.sharedKey);
      if (keyBytes.length === 0) {
        throw new Error('sharedKey decodes to empty');
      }
    } catch (error) {
      throw new Error(`Invalid sharedKey: ${error instanceof Error ? error.message : error}`);
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const logEntry = this.transformEvent(event);
    const body = JSON.stringify([logEntry]);
    const bodyBytes = new TextEncoder().encode(body);

    // Check payload size
    if (bodyBytes.length > MAX_PAYLOAD_SIZE) {
      return {
        success: false,
        eventId: event.eventId,
        error: `Payload size ${bodyBytes.length} exceeds maximum ${MAX_PAYLOAD_SIZE}`,
        retryable: false,
      };
    }

    try {
      const result = await this.sendToSentinel(body, bodyBytes.length);
      return {
        success: result.success,
        eventId: event.eventId,
        error: result.error,
        retryable: result.retryable,
        response: result.response,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      // Network errors are retryable
      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable: true,
      };
    }
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    // Log Analytics Data Collector API doesn't have a dedicated health endpoint.
    // Verify the configuration is valid by testing signature generation.
    try {
      const testDate = new Date().toUTCString();
      await this.buildSignature(testDate, 2); // Test with minimal content length
      return {
        healthy: true,
        message: `Sentinel connector ready for workspace ${this.workspaceId}`,
      };
    } catch (error) {
      return {
        healthy: false,
        message: `Sentinel connector configuration error: ${error instanceof Error ? error.message : error}`,
      };
    }
  }

  protected async doClose(): Promise<void> {
    // No persistent connections to close
  }

  // ===========================================================================
  // Override batch sending for efficiency
  // ===========================================================================

  /**
   * Send multiple events in a single request.
   * Log Analytics supports batching up to 32MB per request.
   */
  async sendBatch(events: ForensicsEvent[]): Promise<SendResult[]> {
    this.ensureInitialized();

    // Filter events
    const filtered = events.filter((e) => this.shouldProcess(e));
    if (filtered.length === 0) {
      return events.map((e) => ({
        success: true,
        eventId: e.eventId,
        response: { filtered: true },
      }));
    }

    // Transform all events
    const logEntries = filtered.map((e) => this.transformEvent(e));
    const body = JSON.stringify(logEntries);
    const bodyBytes = new TextEncoder().encode(body);

    // Check if we need to split into multiple requests
    if (bodyBytes.length > MAX_PAYLOAD_SIZE) {
      // Fall back to individual sends for large batches
      return super.sendBatch(events);
    }

    try {
      const result = await this.sendToSentinel(body, bodyBytes.length);

      // Map result to all events in batch
      const results: SendResult[] = filtered.map((e) => ({
        success: result.success,
        eventId: e.eventId,
        error: result.error,
        retryable: result.retryable,
        response: result.response,
      }));

      // Add filtered results
      const filteredResults: SendResult[] = events
        .filter((e) => !this.shouldProcess(e))
        .map((e) => ({
          success: true,
          eventId: e.eventId,
          response: { filtered: true },
        }));

      return [...results, ...filteredResults];
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return filtered.map((e) => ({
        success: false,
        eventId: e.eventId,
        error: errorMessage,
        retryable: true,
      }));
    }
  }

  // ===========================================================================
  // Private helper methods
  // ===========================================================================

  /**
   * Transform a ForensicsEvent to Sentinel log entry format.
   */
  private transformEvent(event: ForensicsEvent): SentinelLogEntry {
    // Determine action from raw payload, default to 'blocked'
    const rawAction = event.raw?.action;
    const action: SentinelEventAction =
      rawAction === 'unblocked' ? 'unblocked' : 'blocked';
    const eventType: 'blockioc:block' | 'blockioc:unblock' =
      action === 'unblocked' ? 'blockioc:unblock' : 'blockioc:block';

    return {
      event_type: eventType,
      action,
      blocked_url: event.blockedUrl,
      timestamp: event.timestamp,
      redirect_chain: JSON.stringify(event.redirectChain),
      org_id: event.orgId,
      event_id: event.eventId,
      match_type: event.matchType,
      matched_indicator: event.matchedIndicator,
      tab_id: event.tabContext.tabId,
      initiator_url: event.tabContext.initiatorUrl || '',
      tab_title: event.tabContext.tabTitle || '',
      incognito: event.tabContext.incognito,
      user_id: event.userId || '',
      device_id: event.deviceId || '',
    };
  }

  /**
   * Send data to Sentinel Log Analytics.
   */
  private async sendToSentinel(
    body: string,
    contentLength: number
  ): Promise<{
    success: boolean;
    error?: string;
    retryable?: boolean;
    response?: Record<string, unknown>;
  }> {
    const dateString = new Date().toUTCString();
    const signature = await this.buildSignature(dateString, contentLength);

    const headers: Record<string, string> = {
      'Content-Type': CONTENT_TYPE,
      'Log-Type': this.logType,
      'x-ms-date': dateString,
      Authorization: `SharedKey ${this.workspaceId}:${signature}`,
    };

    // Add optional headers
    if (this.timeGeneratedField) {
      headers['time-generated-field'] = this.timeGeneratedField;
    }
    if (this.azureResourceId) {
      headers['x-ms-AzureResourceId'] = this.azureResourceId;
    }

    const response = await fetch(this.apiUrl, {
      method: 'POST',
      headers,
      body,
    });

    if (response.ok) {
      return {
        success: true,
        response: {
          status: response.status,
          statusText: response.statusText,
        },
      };
    }

    // Handle error responses
    const errorBody = await response.text();
    const isRetryable = response.status >= 500 || response.status === 429;

    return {
      success: false,
      error: `Sentinel API error: ${response.status} ${response.statusText} - ${errorBody}`,
      retryable: isRetryable,
      response: {
        status: response.status,
        statusText: response.statusText,
        body: errorBody,
      },
    };
  }

  /**
   * Build the authorization signature for Azure Shared Key authentication.
   *
   * The signature is computed as:
   * Base64(HMAC-SHA256(SharedKey, StringToSign))
   *
   * Where StringToSign is:
   * POST\n{content-length}\napplication/json\nx-ms-date:{date}\n/api/logs
   *
   * @see https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api#authorization
   */
  private async buildSignature(dateString: string, contentLength: number): Promise<string> {
    const stringToSign = [
      'POST',
      contentLength.toString(),
      CONTENT_TYPE,
      `x-ms-date:${dateString}`,
      '/api/logs',
    ].join('\n');

    // Decode the base64 shared key
    const keyBytes = base64Decode(this.sharedKey);

    // Compute HMAC-SHA256
    const signatureBytes = await hmacSha256(keyBytes, stringToSign);

    // Return base64-encoded signature
    return base64Encode(signatureBytes);
  }
}

// =============================================================================
// Factory and Registration
// =============================================================================

/**
 * Create a Sentinel connector from configuration.
 */
export function createSentinelConnector(config: SentinelConnectorConfig): SentinelConnector {
  return new SentinelConnector(config);
}

// Register the connector factory
connectorRegistry.register('sentinel', createSentinelConnector);
