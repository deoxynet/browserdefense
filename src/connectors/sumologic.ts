/**
 * BrowserDefense Sumo Logic Connector
 *
 * Sends forensics events to Sumo Logic via HTTP Source API.
 * Supports batching (newline-delimited JSON), source metadata, and custom fields.
 *
 * Unblock Support:
 * - Sends an unblock log event for correlation
 * - Uses eventType='browserdefense:unblock'
 * - Links to original block via eventId
 *
 * @see https://help.sumologic.com/docs/send-data/hosted-collectors/http-source/
 * @audit 2026-01-09 Verified against official Sumo Logic HTTP Source API docs.
 *        Headers (X-Sumo-Category/Name/Host/Fields), error codes, and batch format aligned.
 */

import { BaseConnector, connectorRegistry } from './base';
import {
  ForensicsEvent,
  SendResult,
  SumoLogicConnectorConfig,
  UnblockResult,
} from './types';

// =============================================================================
// Sumo Logic Event Format
// =============================================================================

/**
 * Sumo Logic event format.
 * Maps BrowserDefense forensics events to Sumo Logic's expected JSON structure.
 */
export interface SumoLogicEvent {
  /** ISO8601 timestamp */
  timestamp: string;
  /** Event type identifier */
  eventType: 'browserdefense:block';
  /** Organization ID */
  orgId: string;
  /** Unique event ID */
  eventId: string;
  /** The blocked URL */
  blockedUrl: string;
  /** IOC match type */
  matchType: 'domain' | 'url' | 'hash';
  /** The matched indicator */
  matchedIndicator: string;
  /** Redirect chain leading to blocked URL */
  redirectChain: string[];
  /** Tab context */
  tabContext: {
    tabId: number;
    windowId: number;
    initiatorUrl?: string;
    tabTitle?: string;
    incognito: boolean;
  };
  /** User ID if available */
  userId?: string;
  /** Device ID if available */
  deviceId?: string;
  /** Custom fields from configuration */
  fields?: Record<string, string>;
}

// =============================================================================
// Sumo Logic Connector Implementation
// =============================================================================

/**
 * Connector for sending forensics events to Sumo Logic HTTP Source.
 *
 * Features:
 * - HTTP Source API integration
 * - Source metadata (category, name, host)
 * - Custom fields support
 * - Batch support via newline-delimited JSON
 * - Health check via empty POST
 */
export class SumoLogicConnector extends BaseConnector {
  readonly type = 'sumologic' as const;

  /**
   * Sumo Logic supports unblock via logging an unblock event.
   * The event is correlated with the original block by eventId.
   */
  readonly supportsUnblock = true;

  private readonly httpSourceUrl: string;
  private readonly sourceCategory: string;
  private readonly sourceName: string;
  private readonly sourceHost: string;
  private readonly fields?: Record<string, string>;
  private readonly timestampField: string;

  constructor(config: SumoLogicConnectorConfig) {
    super(config);
    this.httpSourceUrl = config.httpSourceUrl;
    this.sourceCategory = config.sourceCategory || 'security/browserdefense';
    this.sourceName = config.sourceName || 'browserdefense-connector';
    this.sourceHost = config.sourceHost || 'browserdefense';
    this.fields = config.fields;
    this.timestampField = config.timestampField || 'timestamp';
  }

  // ===========================================================================
  // Abstract method implementations
  // ===========================================================================

  protected async doInit(): Promise<void> {
    // Validate HTTP Source URL format
    if (!this.httpSourceUrl) {
      throw new Error('Sumo Logic HTTP Source URL is required');
    }

    try {
      const url = new URL(this.httpSourceUrl);
      if (!url.hostname.includes('sumologic.com') && !url.hostname.includes('localhost')) {
        // Allow non-sumologic URLs but warn (for testing)
        console.warn(
          `[SumoLogic] HTTP Source URL does not appear to be a Sumo Logic endpoint: ${url.hostname}`
        );
      }
    } catch {
      throw new Error(`Invalid Sumo Logic HTTP Source URL: ${this.httpSourceUrl}`);
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const sumoEvent = this.transformEvent(event);
    const payload = JSON.stringify(sumoEvent);

    try {
      const response = await fetch(this.httpSourceUrl, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: payload,
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        const retryable = this.isRetryableStatus(response.status);

        return {
          success: false,
          eventId: event.eventId,
          error: `Sumo Logic returned ${response.status}: ${errorText}`,
          retryable,
          response: {
            status: response.status,
            statusText: response.statusText,
          },
        };
      }

      return {
        success: true,
        eventId: event.eventId,
        response: {
          status: response.status,
        },
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const retryable = this.isRetryableError(error);

      return {
        success: false,
        eventId: event.eventId,
        error: `Failed to send to Sumo Logic: ${errorMessage}`,
        retryable,
      };
    }
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      // Sumo Logic accepts empty POST as health check
      const response = await fetch(this.httpSourceUrl, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: '',
      });

      if (response.ok) {
        return {
          healthy: true,
          message: 'Sumo Logic HTTP Source is reachable',
        };
      }

      // Some non-2xx responses may still indicate the endpoint is reachable
      // 4xx errors typically mean auth/validation issues but endpoint is up
      if (response.status >= 400 && response.status < 500) {
        return {
          healthy: true,
          message: `Sumo Logic HTTP Source returned ${response.status} (endpoint reachable)`,
        };
      }

      return {
        healthy: false,
        message: `Sumo Logic HTTP Source returned ${response.status}`,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        healthy: false,
        message: `Failed to reach Sumo Logic: ${errorMessage}`,
      };
    }
  }

  protected async doClose(): Promise<void> {
    // No persistent connections to close
  }

  /**
   * Send an unblock event to Sumo Logic for correlation.
   * This logs an unblock event that can be correlated with the original block.
   */
  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    const unblockEvent = this.transformUnblockEvent(event);
    const payload = JSON.stringify(unblockEvent);

    try {
      const response = await fetch(this.httpSourceUrl, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: payload,
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        const retryable = this.isRetryableStatus(response.status);

        return {
          success: false,
          eventId: event.eventId,
          error: `Sumo Logic unblock returned ${response.status}: ${errorText}`,
          retryable,
        };
      }

      return {
        success: true,
        eventId: event.eventId,
        incidentId: `unblock-${event.eventId}`,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const retryable = this.isRetryableError(error);

      return {
        success: false,
        eventId: event.eventId,
        error: `Failed to send unblock to Sumo Logic: ${errorMessage}`,
        retryable,
      };
    }
  }

  // ===========================================================================
  // Override batch sending for efficiency
  // ===========================================================================

  /**
   * Send multiple events in a single request using newline-delimited JSON.
   * This is more efficient than individual sends for high-volume scenarios.
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
    const sumoEvents = filtered.map((e) => this.transformEvent(e));

    // Create newline-delimited JSON payload
    const payload = sumoEvents.map((e) => JSON.stringify(e)).join('\n');

    try {
      const response = await fetch(this.httpSourceUrl, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: payload,
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        const retryable = this.isRetryableStatus(response.status);

        // Return failure for all events in batch
        return filtered.map((e) => ({
          success: false,
          eventId: e.eventId,
          error: `Sumo Logic returned ${response.status}: ${errorText}`,
          retryable,
          response: {
            status: response.status,
            statusText: response.statusText,
          },
        }));
      }

      // Success - update metrics for all events
      const results = filtered.map((e) => ({
        success: true,
        eventId: e.eventId,
        response: { status: response.status, batchSize: filtered.length },
      }));

      // Add filtered results
      const filteredResults = events
        .filter((e) => !this.shouldProcess(e))
        .map((e) => ({
          success: true,
          eventId: e.eventId,
          response: { filtered: true },
        }));

      return [...results, ...filteredResults];
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const retryable = this.isRetryableError(error);

      return filtered.map((e) => ({
        success: false,
        eventId: e.eventId,
        error: `Failed to send batch to Sumo Logic: ${errorMessage}`,
        retryable,
      }));
    }
  }

  // ===========================================================================
  // Helper methods
  // ===========================================================================

  /**
   * Transform a BrowserDefense forensics event to Sumo Logic format.
   */
  private transformEvent(event: ForensicsEvent): SumoLogicEvent {
    const sumoEvent: SumoLogicEvent = {
      timestamp: event.timestamp,
      eventType: 'browserdefense:block',
      orgId: event.orgId,
      eventId: event.eventId,
      blockedUrl: event.blockedUrl,
      matchType: event.matchType,
      matchedIndicator: event.matchedIndicator,
      redirectChain: event.redirectChain,
      tabContext: {
        tabId: event.tabContext.tabId,
        windowId: event.tabContext.windowId,
        initiatorUrl: event.tabContext.initiatorUrl,
        tabTitle: event.tabContext.tabTitle,
        incognito: event.tabContext.incognito,
      },
    };

    // Add optional fields
    if (event.userId) {
      sumoEvent.userId = event.userId;
    }
    if (event.deviceId) {
      sumoEvent.deviceId = event.deviceId;
    }

    // Add custom fields from configuration
    if (this.fields) {
      sumoEvent.fields = { ...this.fields };
    }

    return sumoEvent;
  }

  /**
   * Transform a BrowserDefense forensics event to Sumo Logic unblock format.
   */
  private transformUnblockEvent(event: ForensicsEvent): Record<string, unknown> {
    const unblockEvent: Record<string, unknown> = {
      timestamp: new Date().toISOString(),
      eventType: 'browserdefense:unblock',
      action: 'unblock',
      orgId: event.orgId,
      eventId: event.eventId,
      originalEventId: event.eventId,
      blockedUrl: event.blockedUrl,
      matchType: event.matchType,
      matchedIndicator: event.matchedIndicator,
    };

    // Add optional fields
    if (event.userId) {
      unblockEvent.userId = event.userId;
    }
    if (event.deviceId) {
      unblockEvent.deviceId = event.deviceId;
    }

    // Add custom fields from configuration
    if (this.fields) {
      unblockEvent.fields = { ...this.fields };
    }

    return unblockEvent;
  }

  /**
   * Build HTTP headers for Sumo Logic request.
   */
  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Sumo-Category': this.sourceCategory,
      'X-Sumo-Name': this.sourceName,
      'X-Sumo-Host': this.sourceHost,
    };

    // Add custom fields as X-Sumo-Fields header (key=value,key=value format)
    if (this.fields && Object.keys(this.fields).length > 0) {
      const fieldsHeader = Object.entries(this.fields)
        .map(([k, v]) => `${k}=${v}`)
        .join(',');
      headers['X-Sumo-Fields'] = fieldsHeader;
    }

    return headers;
  }

  /**
   * Check if HTTP status code indicates a retryable error.
   */
  private isRetryableStatus(status: number): boolean {
    // Retry on server errors (5xx) and rate limiting (429)
    return status >= 500 || status === 429;
  }

  /**
   * Check if an error is retryable (network errors, timeouts).
   */
  private isRetryableError(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      return (
        message.includes('network') ||
        message.includes('timeout') ||
        message.includes('econnrefused') ||
        message.includes('econnreset') ||
        message.includes('fetch failed')
      );
    }
    return true; // Default to retryable for unknown errors
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Factory function for creating SumoLogicConnector instances.
 */
export function createSumoLogicConnector(
  config: SumoLogicConnectorConfig
): SumoLogicConnector {
  return new SumoLogicConnector(config);
}

// Register with the global connector registry
connectorRegistry.register('sumologic', createSumoLogicConnector);
