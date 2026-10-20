/**
 * BrowserDefense Splunk HEC (HTTP Event Collector) Connector
 *
 * Sends forensics events to Splunk via the HTTP Event Collector API.
 * Supports token authentication, index targeting, and batch sending.
 *
 * @see https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
 */

import { BaseConnector, connectorRegistry } from './base';
import {
  ForensicsEvent,
  SendResult,
  SplunkConnectorConfig,
} from './types';

// =============================================================================
// Splunk HEC Event Format
// =============================================================================

/**
 * Splunk HEC event wrapper format.
 * @see https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
 */
export interface SplunkHecEvent {
  /** Event timestamp in epoch seconds (with millisecond precision) */
  time: number;
  /** Target index (optional, defaults to HEC token's default) */
  index?: string;
  /** Source type for the event */
  sourcetype?: string;
  /** Source identifier */
  source?: string;
  /** Host identifier */
  host?: string;
  /** The actual event payload */
  event: SplunkEventPayload;
}

/**
 * BrowserDefense event payload structure for Splunk.
 * Maps forensics events to a Splunk-friendly format.
 * Supports both block and unblock events.
 */
export interface SplunkEventPayload {
  /** Event type identifier - block or unblock */
  event_type: 'browserdefense:block' | 'browserdefense:unblock';
  /** Unique event ID */
  event_id: string;
  /** Organization ID */
  org_id: string;
  /** The blocked URL */
  blocked_url: string;
  /** IOC match type */
  match_type: 'domain' | 'url' | 'hash';
  /** The matched indicator */
  matched_indicator: string;
  /** Redirect chain leading to blocked URL */
  redirect_chain: string[];
  /** Tab context information */
  tab_context: {
    tab_id: number;
    window_id: number;
    initiator_url?: string;
    tab_title?: string;
    incognito: boolean;
  };
  /** User ID if available */
  user_id?: string;
  /** Device ID if available */
  device_id?: string;
  /** Severity level for Splunk ES */
  severity: 'medium' | 'informational';
  /** Action taken - blocked or unblocked */
  action: 'blocked' | 'unblocked';
  /** Product identifier for Splunk CIM compliance */
  product: 'BrowserDefense';
  /** Vendor identifier for Splunk CIM compliance */
  vendor: 'BrowserDefense';
}

/**
 * Splunk HEC API response format.
 */
interface SplunkHecResponse {
  /** Response text (usually "Success") */
  text: string;
  /** Error code (0 = success) */
  code: number;
  /** Invalid event count (for batch requests) */
  invalid_event_number?: number;
  /** Ack ID for indexed event acknowledgement */
  ackId?: number;
}

// =============================================================================
// Splunk HEC Connector Implementation
// =============================================================================

/**
 * Splunk HTTP Event Collector connector.
 *
 * Sends BrowserDefense forensics events to Splunk HEC endpoint with proper
 * formatting for Splunk Enterprise Security and SIEM use cases.
 *
 * @example
 * ```typescript
 * const connector = new SplunkConnector({
 *   name: 'splunk-prod',
 *   type: 'splunk',
 *   enabled: true,
 *   hecUrl: 'https://splunk.example.com:8088/services/collector/event',
 *   hecToken: 'your-hec-token',
 *   index: 'security',
 *   sourceType: 'browserdefense:forensics',
 *   source: 'browserdefense-extension',
 * });
 *
 * await connector.init();
 * await connector.send(event);
 * ```
 */
export class SplunkConnector extends BaseConnector {
  readonly type = 'splunk' as const;

  private readonly splunkConfig: SplunkConnectorConfig;
  private readonly hecEndpoint: string;
  private readonly rawEndpoint: string;

  constructor(config: SplunkConnectorConfig) {
    super(config);
    this.splunkConfig = config;

    // Normalize HEC URL - ensure it ends with the collector endpoint
    const baseUrl = config.hecUrl.replace(/\/$/, '');
    if (baseUrl.endsWith('/services/collector/event')) {
      this.hecEndpoint = baseUrl;
      this.rawEndpoint = baseUrl.replace('/event', '/raw');
    } else if (baseUrl.endsWith('/services/collector/raw')) {
      this.rawEndpoint = baseUrl;
      this.hecEndpoint = baseUrl.replace('/raw', '/event');
    } else if (baseUrl.endsWith('/services/collector')) {
      this.hecEndpoint = `${baseUrl}/event`;
      this.rawEndpoint = `${baseUrl}/raw`;
    } else {
      // Assume base URL without path
      this.hecEndpoint = `${baseUrl}/services/collector/event`;
      this.rawEndpoint = `${baseUrl}/services/collector/raw`;
    }
  }

  // ===========================================================================
  // Abstract method implementations
  // ===========================================================================

  protected async doInit(): Promise<void> {
    // Validate HEC URL
    if (!this.splunkConfig.hecUrl) {
      throw new Error('Splunk HEC URL is required');
    }

    // Validate HEC token
    if (!this.splunkConfig.hecToken) {
      throw new Error('Splunk HEC token is required');
    }

    // Validate URL format
    try {
      new URL(this.splunkConfig.hecUrl);
    } catch {
      throw new Error(`Invalid Splunk HEC URL: ${this.splunkConfig.hecUrl}`);
    }

    // Test connectivity with a health check
    const healthResult = await this.doHealth();
    if (!healthResult.healthy) {
      throw new Error(`Splunk HEC connectivity check failed: ${healthResult.message}`);
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const hecEvent = this.transformEvent(event);

    try {
      const response = await fetch(this.hecEndpoint, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: JSON.stringify(hecEvent),
      });

      if (response.ok) {
        const result = await response.json() as SplunkHecResponse;
        if (result.code === 0) {
          return {
            success: true,
            eventId: event.eventId,
            response: {
              text: result.text,
              ackId: result.ackId,
            },
          };
        }
        // HEC returned success HTTP status but error in body
        return {
          success: false,
          eventId: event.eventId,
          error: `Splunk HEC error (code ${result.code}): ${result.text}`,
          retryable: this.isRetryableHecCode(result.code),
        };
      }

      // Handle HTTP error responses
      return this.handleHttpError(event.eventId, response);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        eventId: event.eventId,
        error: `Network error: ${message}`,
        retryable: true,
      };
    }
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      // Splunk HEC health check - send minimal payload to /services/collector/health
      // If that endpoint is not available, try a test event
      const healthUrl = this.hecEndpoint.replace('/services/collector/event', '/services/collector/health');

      const response = await fetch(healthUrl, {
        method: 'GET',
        headers: {
          'Authorization': `Splunk ${this.splunkConfig.hecToken}`,
        },
      });

      if (response.ok) {
        return {
          healthy: true,
          message: 'Splunk HEC is healthy',
        };
      }

      // Health endpoint might not be enabled, try a different approach
      // Send empty body to event endpoint - should return 400 but proves connectivity
      const testResponse = await fetch(this.hecEndpoint, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: '',
      });

      // 400 error with specific Splunk error codes means HEC is reachable
      if (testResponse.status === 400) {
        try {
          const result = await testResponse.json() as SplunkHecResponse;
          // Code 5 = "No data" or Code 6 = "Invalid data format" means HEC is working
          if (result.code === 5 || result.code === 6) {
            return {
              healthy: true,
              message: 'Splunk HEC is reachable',
            };
          }
        } catch {
          // If we can't parse the response, still consider it reachable
          return {
            healthy: true,
            message: 'Splunk HEC endpoint is responding',
          };
        }
      }

      // Auth errors
      if (testResponse.status === 401 || testResponse.status === 403) {
        return {
          healthy: false,
          message: 'Splunk HEC authentication failed - check token',
        };
      }

      return {
        healthy: false,
        message: `Splunk HEC returned ${testResponse.status}`,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        healthy: false,
        message: `Splunk HEC health check failed: ${message}`,
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
   * Splunk HEC supports multiple JSON objects in a single request body
   * (concatenated without delimiters).
   */
  async sendBatch(events: ForensicsEvent[]): Promise<SendResult[]> {
    this.ensureInitialized();

    // Filter events first
    const filtered = events.filter((e) => this.shouldProcess(e));

    if (filtered.length === 0) {
      return events.map((e) => ({
        success: true,
        eventId: e.eventId,
        response: { filtered: true },
      }));
    }

    // Transform all events to HEC format
    const hecEvents = filtered.map((e) => this.transformEvent(e));

    // Splunk HEC accepts multiple JSON objects concatenated together
    // (no array wrapping, no delimiters needed)
    const payload = hecEvents.map((e) => JSON.stringify(e)).join('');

    try {
      const response = await fetch(this.hecEndpoint, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: payload,
      });

      if (response.ok) {
        const result = await response.json() as SplunkHecResponse;

        if (result.code === 0) {
          // All events succeeded
          this.metrics.eventsSent += filtered.length;

          const results: SendResult[] = filtered.map((e) => ({
            success: true,
            eventId: e.eventId,
            response: { text: result.text, ackId: result.ackId },
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
        }

        // HEC returned error code
        this.metrics.eventsFailed += filtered.length;

        return filtered.map((e) => ({
          success: false,
          eventId: e.eventId,
          error: `Splunk HEC error (code ${result.code}): ${result.text}`,
          retryable: this.isRetryableHecCode(result.code),
        }));
      }

      // HTTP error - apply to all events in batch
      const errorResult = await this.handleHttpError('batch', response);
      this.metrics.eventsFailed += filtered.length;

      return filtered.map((e) => ({
        success: false,
        eventId: e.eventId,
        error: errorResult.error,
        retryable: errorResult.retryable,
      }));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.metrics.eventsFailed += filtered.length;

      return events.map((e) => ({
        success: false,
        eventId: e.eventId,
        error: `Network error: ${message}`,
        retryable: true,
      }));
    }
  }

  // ===========================================================================
  // Event transformation
  // ===========================================================================

  /**
   * Transform a ForensicsEvent to Splunk HEC format.
   */
  private transformEvent(event: ForensicsEvent): SplunkHecEvent {
    // Parse timestamp to epoch seconds with millisecond precision
    const time = new Date(event.timestamp).getTime() / 1000;

    // Determine event type and action based on event.action (default to block for backwards compat)
    const isUnblock = event.action === 'unblock';
    const eventType: SplunkEventPayload['event_type'] = isUnblock
      ? 'browserdefense:unblock'
      : 'browserdefense:block';
    const action: SplunkEventPayload['action'] = isUnblock ? 'unblocked' : 'blocked';
    // Unblock events are informational, block events are medium severity
    const severity: SplunkEventPayload['severity'] = isUnblock ? 'informational' : 'medium';

    const eventPayload: SplunkEventPayload = {
      event_type: eventType,
      event_id: event.eventId,
      org_id: event.orgId,
      blocked_url: event.blockedUrl,
      match_type: event.matchType,
      matched_indicator: event.matchedIndicator,
      redirect_chain: event.redirectChain,
      tab_context: {
        tab_id: event.tabContext.tabId,
        window_id: event.tabContext.windowId,
        initiator_url: event.tabContext.initiatorUrl,
        tab_title: event.tabContext.tabTitle,
        incognito: event.tabContext.incognito,
      },
      severity,
      action,
      product: 'BrowserDefense',
      vendor: 'BrowserDefense',
    };

    // Add optional fields
    if (event.userId) {
      eventPayload.user_id = event.userId;
    }
    if (event.deviceId) {
      eventPayload.device_id = event.deviceId;
    }

    const hecEvent: SplunkHecEvent = {
      time,
      event: eventPayload,
    };

    // Add optional HEC metadata
    if (this.splunkConfig.index) {
      hecEvent.index = this.splunkConfig.index;
    }
    if (this.splunkConfig.sourceType) {
      hecEvent.sourcetype = this.splunkConfig.sourceType;
    }
    if (this.splunkConfig.source) {
      hecEvent.source = this.splunkConfig.source;
    }
    if (this.splunkConfig.host) {
      hecEvent.host = this.splunkConfig.host;
    }

    return hecEvent;
  }

  // ===========================================================================
  // HTTP helpers
  // ===========================================================================

  /**
   * Build HTTP headers for Splunk HEC requests.
   */
  private buildHeaders(): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Splunk ${this.splunkConfig.hecToken}`,
    };
  }

  /**
   * Handle HTTP error response from Splunk HEC.
   */
  private async handleHttpError(
    eventId: string,
    response: Response
  ): Promise<SendResult> {
    // Handle rate limiting
    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After');
      return {
        success: false,
        eventId,
        error: `Rate limited. Retry after: ${retryAfter || 'unknown'}`,
        retryable: true,
      };
    }

    // Handle auth errors (non-retryable)
    if (response.status === 401) {
      return {
        success: false,
        eventId,
        error: 'Authentication failed - invalid HEC token',
        retryable: false,
      };
    }

    if (response.status === 403) {
      return {
        success: false,
        eventId,
        error: 'Forbidden - HEC token lacks permissions',
        retryable: false,
      };
    }

    // Handle server errors (retryable)
    if (response.status >= 500) {
      return {
        success: false,
        eventId,
        error: `Server error: ${response.status}`,
        retryable: true,
      };
    }

    // Try to get error details from response body
    let errorDetail = '';
    try {
      const body = await response.json() as SplunkHecResponse;
      errorDetail = body.text || '';
    } catch {
      try {
        errorDetail = await response.text();
      } catch {
        errorDetail = 'Unknown error';
      }
    }

    // Other client errors (generally non-retryable)
    return {
      success: false,
      eventId,
      error: `HTTP ${response.status}: ${errorDetail}`,
      retryable: false,
    };
  }

  /**
   * Check if a Splunk HEC error code is retryable.
   * @see https://docs.splunk.com/Documentation/Splunk/latest/Data/TroubleshootHTTPEventCollector
   */
  private isRetryableHecCode(code: number): boolean {
    // HEC error codes:
    // 0 = Success
    // 1 = Token disabled
    // 2 = Token required
    // 3 = Invalid authorization
    // 4 = Invalid token
    // 5 = No data
    // 6 = Invalid data format
    // 7 = Incorrect index
    // 8 = Internal server error
    // 9 = Server busy
    // 10 = Data channel missing
    // 11 = Invalid data channel
    // 12 = Event field required
    // 13 = Event field blank
    // 14 = ACK disabled
    // 18 = HEC is unhealthy, queues are full

    // Retryable: server errors (8, 9) and queue full (18)
    return code === 8 || code === 9 || code === 18;
  }

  // ===========================================================================
  // Public getters
  // ===========================================================================

  /**
   * Get the configured HEC endpoint URL.
   */
  get endpoint(): string {
    return this.hecEndpoint;
  }

  /**
   * Get the configured Splunk index.
   */
  get index(): string | undefined {
    return this.splunkConfig.index;
  }

  /**
   * Get the configured source type.
   */
  get sourceType(): string | undefined {
    return this.splunkConfig.sourceType;
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Create a Splunk connector from configuration.
 */
export function createSplunkConnector(
  config: SplunkConnectorConfig
): SplunkConnector {
  return new SplunkConnector(config);
}

// Register with the global connector registry
connectorRegistry.register('splunk', createSplunkConnector);
