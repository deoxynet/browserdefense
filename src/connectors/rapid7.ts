/**
 * BrowserDefense Rapid7 InsightIDR Connector
 *
 * Sends forensics events to Rapid7 InsightIDR via the Log Ingestion API.
 * Events are formatted as JSON logs and sent to the configured log set.
 *
 * Unblock Support:
 * - Sends an unblock log event for correlation
 * - Uses same event_id for linking to original block
 * - Always succeeds (fire-and-forget logging)
 *
 * @see https://docs.rapid7.com/insightidr/log-ingestion-api
 */

import {
  BaseConnector,
  connectorRegistry,
  EventTransformer,
} from './base';
import {
  ForensicsEvent,
  InsightIDRConnectorConfig,
  InsightIDRRegion,
  SendResult,
  UnblockResult,
} from './types';

// =============================================================================
// Constants
// =============================================================================

/**
 * Regional endpoint mapping for InsightIDR Log Ingestion API.
 * Each region has its own data center with a specific hostname.
 */
const REGION_ENDPOINTS: Record<InsightIDRRegion, string> = {
  us: 'us.data.logs.insight.rapid7.com',
  us2: 'us2.data.logs.insight.rapid7.com',
  us3: 'us3.data.logs.insight.rapid7.com',
  eu: 'eu.data.logs.insight.rapid7.com',
  ca: 'ca.data.logs.insight.rapid7.com',
  au: 'au.data.logs.insight.rapid7.com',
  ap: 'ap.data.logs.insight.rapid7.com',
};

/**
 * Default request timeout in milliseconds.
 */
const DEFAULT_TIMEOUT_MS = 30000;

// =============================================================================
// InsightIDR Log Format
// =============================================================================

/**
 * InsightIDR log entry format.
 * This is the structure sent to the Log Ingestion API.
 */
export interface InsightIDRLogEntry {
  /** Timestamp in milliseconds since epoch */
  timestamp: number;
  /** Human-readable message for the log entry */
  message: string;
  /** The blocked URL that triggered the event */
  blocked_url: string;
  /** Chain of redirects leading to the blocked URL */
  redirect_chain: string[];
  /** Organization identifier */
  org_id: string;
  /** Unique event identifier */
  event_id: string;
  /** IOC type that matched (domain, url, hash) */
  match_type: string;
  /** The specific IOC pattern that matched */
  matched_indicator: string;
  /** Tab context information */
  tab_context: {
    tab_id: number;
    window_id: number;
    initiator_url?: string;
    tab_title?: string;
    incognito: boolean;
  };
  /** User identifier if available */
  user_id?: string;
  /** Device identifier if available */
  device_id?: string;
}

// =============================================================================
// InsightIDR Connector Implementation
// =============================================================================

/**
 * Transforms a ForensicsEvent to InsightIDR log format.
 */
export const transformToInsightIDRLog: EventTransformer<InsightIDRLogEntry> = (
  event: ForensicsEvent
): InsightIDRLogEntry => {
  return {
    timestamp: new Date(event.timestamp).getTime(),
    message: `BrowserDefense blocked navigation to ${event.blockedUrl}`,
    blocked_url: event.blockedUrl,
    redirect_chain: event.redirectChain,
    org_id: event.orgId,
    event_id: event.eventId,
    match_type: event.matchType,
    matched_indicator: event.matchedIndicator,
    tab_context: {
      tab_id: event.tabContext.tabId,
      window_id: event.tabContext.windowId,
      initiator_url: event.tabContext.initiatorUrl,
      tab_title: event.tabContext.tabTitle,
      incognito: event.tabContext.incognito,
    },
    user_id: event.userId,
    device_id: event.deviceId,
  };
};

/**
 * Rapid7 InsightIDR connector implementation.
 *
 * Sends forensics events to InsightIDR's Log Ingestion API.
 * Supports all InsightIDR regions and uses log token authentication.
 *
 * @example
 * ```typescript
 * const connector = new InsightIDRConnector({
 *   name: 'insightidr-prod',
 *   type: 'insightidr',
 *   enabled: true,
 *   region: 'us',
 *   logToken: 'your-log-token-here',
 *   logSet: 'BrowserDefense',
 * });
 *
 * await connector.init();
 * await connector.send(event);
 * ```
 */
export class InsightIDRConnector extends BaseConnector {
  readonly type = 'insightidr' as const;

  /**
   * InsightIDR supports unblock via logging an unblock event.
   * The event is correlated with the original block by event_id.
   */
  readonly supportsUnblock = true;

  private readonly region: InsightIDRRegion;
  private readonly logToken: string;
  private readonly logSet?: string;
  private readonly timeout: number;
  private readonly endpoint: string;

  constructor(config: InsightIDRConnectorConfig) {
    super(config);

    this.region = config.region;
    this.logToken = config.logToken;
    this.logSet = config.logSet;
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;

    // Construct the endpoint URL
    const host = REGION_ENDPOINTS[this.region];
    if (!host) {
      throw new Error(`Invalid InsightIDR region: ${this.region}`);
    }
    this.endpoint = `https://${host}/v1/noformat/${this.logToken}`;
  }

  /**
   * Get the API endpoint URL.
   * Exposed for testing purposes.
   */
  getEndpoint(): string {
    return this.endpoint;
  }

  /**
   * Initialize the connector.
   * Validates the configuration and tests connectivity.
   */
  protected async doInit(): Promise<void> {
    // Validate log token format (should be a UUID-like string)
    if (!this.logToken || this.logToken.length < 10) {
      throw new Error('Invalid InsightIDR log token: token is missing or too short');
    }

    // Log initialization
    console.log(`[InsightIDR] Initialized connector for region: ${this.region}`);
    if (this.logSet) {
      console.log(`[InsightIDR] Log set: ${this.logSet}`);
    }
  }

  /**
   * Send a single event to InsightIDR.
   */
  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const logEntry = transformToInsightIDRLog(event);

    try {
      const response = await this.sendRequest(JSON.stringify(logEntry));

      if (response.ok) {
        return {
          success: true,
          eventId: event.eventId,
          response: {
            status: response.status,
            statusText: response.statusText,
          },
        };
      }

      // Handle rate limiting (429)
      if (response.status === 429) {
        return {
          success: false,
          eventId: event.eventId,
          error: 'Rate limited by InsightIDR',
          retryable: true,
          response: {
            status: response.status,
          },
        };
      }

      // Handle server errors (5xx)
      if (response.status >= 500) {
        return {
          success: false,
          eventId: event.eventId,
          error: `InsightIDR server error: ${response.status} ${response.statusText}`,
          retryable: true,
          response: {
            status: response.status,
            statusText: response.statusText,
          },
        };
      }

      // Client errors (4xx) - typically not retryable
      const errorText = await response.text().catch(() => 'Unknown error');
      return {
        success: false,
        eventId: event.eventId,
        error: `InsightIDR error: ${response.status} ${response.statusText} - ${errorText}`,
        retryable: false,
        response: {
          status: response.status,
          statusText: response.statusText,
          body: errorText,
        },
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Network errors are typically retryable
      return {
        success: false,
        eventId: event.eventId,
        error: `InsightIDR request failed: ${errorMessage}`,
        retryable: true,
      };
    }
  }

  /**
   * Send multiple events as a batch.
   * InsightIDR supports newline-delimited JSON for batch uploads.
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

    // Transform all events to log entries
    const logEntries = filtered.map(transformToInsightIDRLog);

    // Create newline-delimited JSON (NDJSON)
    const ndjson = logEntries.map((entry) => JSON.stringify(entry)).join('\n');

    try {
      const response = await this.sendRequest(ndjson);

      if (response.ok) {
        // All events succeeded
        return filtered.map((e) => ({
          success: true,
          eventId: e.eventId,
          response: {
            status: response.status,
            batched: true,
          },
        }));
      }

      // Batch failed - mark all as failed
      const isRetryable = response.status === 429 || response.status >= 500;
      const errorText = await response.text().catch(() => 'Unknown error');

      return filtered.map((e) => ({
        success: false,
        eventId: e.eventId,
        error: `InsightIDR batch error: ${response.status} - ${errorText}`,
        retryable: isRetryable,
      }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      return filtered.map((e) => ({
        success: false,
        eventId: e.eventId,
        error: `InsightIDR batch request failed: ${errorMessage}`,
        retryable: true,
      }));
    }
  }

  /**
   * Perform a health check by sending a ping to the API.
   */
  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      // Send a minimal test log entry
      const testEntry = {
        timestamp: Date.now(),
        message: 'BrowserDefense health check',
        event_type: 'health_check',
      };

      const response = await this.sendRequest(JSON.stringify(testEntry));

      if (response.ok) {
        return {
          healthy: true,
          message: `InsightIDR connection healthy (${this.region})`,
        };
      }

      return {
        healthy: false,
        message: `InsightIDR returned ${response.status}: ${response.statusText}`,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        healthy: false,
        message: `InsightIDR health check failed: ${errorMessage}`,
      };
    }
  }

  /**
   * Clean up resources.
   */
  protected async doClose(): Promise<void> {
    console.log(`[InsightIDR] Closed connector: ${this.name}`);
  }

  /**
   * Send an unblock event to InsightIDR for correlation.
   * This logs an unblock event that can be correlated with the original block.
   */
  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    const unblockEntry = this.transformToUnblockLog(event);

    try {
      const response = await this.sendRequest(JSON.stringify(unblockEntry));

      if (response.ok) {
        return {
          success: true,
          eventId: event.eventId,
          incidentId: `unblock-${event.eventId}`,
        };
      }

      // Handle errors
      const isRetryable = response.status === 429 || response.status >= 500;
      const errorText = await response.text().catch(() => 'Unknown error');

      return {
        success: false,
        eventId: event.eventId,
        error: `InsightIDR unblock error: ${response.status} - ${errorText}`,
        retryable: isRetryable,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      return {
        success: false,
        eventId: event.eventId,
        error: `InsightIDR unblock request failed: ${errorMessage}`,
        retryable: true,
      };
    }
  }

  /**
   * Transform a ForensicsEvent to an unblock log entry.
   */
  private transformToUnblockLog(event: ForensicsEvent): Record<string, unknown> {
    return {
      timestamp: Date.now(),
      message: `BrowserDefense unblocked navigation to ${event.blockedUrl}`,
      event_type: 'unblock',
      action: 'unblock',
      blocked_url: event.blockedUrl,
      org_id: event.orgId,
      event_id: event.eventId,
      original_event_id: event.eventId,
      match_type: event.matchType,
      matched_indicator: event.matchedIndicator,
      user_id: event.userId,
      device_id: event.deviceId,
    };
  }

  /**
   * Internal method to send HTTP requests to InsightIDR.
   */
  private async sendRequest(body: string): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      return await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Insight-Token': this.logToken,
        },
        body,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Factory function for creating InsightIDR connector instances.
 */
export function createInsightIDRConnector(
  config: InsightIDRConnectorConfig
): InsightIDRConnector {
  return new InsightIDRConnector(config);
}

// Register the connector factory
connectorRegistry.register('insightidr', createInsightIDRConnector);
