/**
 * BrowserDefense Datadog Connector
 *
 * Sends forensics events to Datadog Logs API.
 * Supports API key authentication and proper log formatting with tags.
 *
 * @see https://docs.datadoghq.com/api/latest/logs/
 */

import { BaseConnector, connectorRegistry, EventTransformer } from './base';
import {
  DatadogConnectorConfig,
  ForensicsEvent,
  IocAction,
  SendResult,
} from './types';

// =============================================================================
// Datadog Log Format Types
// =============================================================================

/**
 * Datadog log entry format.
 * @see https://docs.datadoghq.com/api/latest/logs/#send-logs
 */
interface DatadogLogEntry {
  /** Log message */
  message: string;
  /** RFC3339 timestamp */
  ddsource?: string;
  /** Tags in key:value format */
  ddtags?: string;
  /** Hostname */
  hostname?: string;
  /** Service name */
  service?: string;
  /** Additional attributes */
  [key: string]: unknown;
}

// =============================================================================
// Datadog Connector Implementation
// =============================================================================

/**
 * Datadog Logs connector.
 *
 * Sends BrowserDefense forensics events to Datadog's Logs API with proper
 * formatting, tags, and attributes for security analysis.
 *
 * @example
 * ```typescript
 * const connector = new DatadogConnector({
 *   name: 'datadog-prod',
 *   type: 'datadog',
 *   enabled: true,
 *   site: 'datadoghq.com',
 *   apiKey: 'your-api-key',
 *   service: 'browserdefense',
 *   source: 'browser-extension',
 *   tags: ['env:production', 'team:security'],
 * });
 *
 * await connector.init();
 * await connector.send(event);
 * ```
 */
export class DatadogConnector extends BaseConnector {
  readonly type = 'datadog' as const;

  private readonly datadogConfig: DatadogConnectorConfig;
  private readonly apiUrl: string;
  private lastHealthCheck: { healthy: boolean; message: string } | null = null;

  constructor(config: DatadogConnectorConfig) {
    super(config);
    this.datadogConfig = config;

    // Construct the API URL based on the site
    // Datadog Logs API: https://http-intake.logs.<site>/api/v2/logs
    this.apiUrl = `https://http-intake.logs.${config.site}/api/v2/logs`;
  }

  // ===========================================================================
  // Abstract method implementations
  // ===========================================================================

  protected async doInit(): Promise<void> {
    // Validate configuration
    if (!this.datadogConfig.apiKey) {
      throw new Error('Datadog API key is required');
    }
    if (!this.datadogConfig.site) {
      throw new Error('Datadog site is required');
    }

    // Test connectivity with a health check
    const healthResult = await this.doHealth();
    if (!healthResult.healthy) {
      throw new Error(`Datadog connectivity check failed: ${healthResult.message}`);
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const logEntry = this.transformEvent(event);

    try {
      const response = await fetch(this.apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'DD-API-KEY': this.datadogConfig.apiKey,
        },
        body: JSON.stringify([logEntry]),
      });

      if (response.ok) {
        return {
          success: true,
          eventId: event.eventId,
          response: { status: response.status },
        };
      }

      // Handle rate limiting
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        return {
          success: false,
          eventId: event.eventId,
          error: `Rate limited. Retry after: ${retryAfter || 'unknown'}`,
          retryable: true,
        };
      }

      // Handle auth errors (non-retryable)
      if (response.status === 401 || response.status === 403) {
        return {
          success: false,
          eventId: event.eventId,
          error: `Authentication failed: ${response.status}`,
          retryable: false,
        };
      }

      // Handle server errors (retryable)
      if (response.status >= 500) {
        return {
          success: false,
          eventId: event.eventId,
          error: `Server error: ${response.status}`,
          retryable: true,
        };
      }

      // Other client errors (non-retryable)
      const errorBody = await response.text().catch(() => 'Unknown error');
      return {
        success: false,
        eventId: event.eventId,
        error: `HTTP ${response.status}: ${errorBody}`,
        retryable: false,
      };
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
      // Datadog doesn't have a dedicated health endpoint for logs API.
      // We'll use the validate endpoint to check API key validity.
      const validateUrl = `https://api.${this.datadogConfig.site}/api/v1/validate`;

      const response = await fetch(validateUrl, {
        method: 'GET',
        headers: {
          'DD-API-KEY': this.datadogConfig.apiKey,
        },
      });

      if (response.ok) {
        this.lastHealthCheck = { healthy: true, message: 'Connected to Datadog' };
        return this.lastHealthCheck;
      }

      if (response.status === 401 || response.status === 403) {
        this.lastHealthCheck = {
          healthy: false,
          message: 'Invalid API key',
        };
        return this.lastHealthCheck;
      }

      this.lastHealthCheck = {
        healthy: false,
        message: `Health check failed: HTTP ${response.status}`,
      };
      return this.lastHealthCheck;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.lastHealthCheck = {
        healthy: false,
        message: `Health check failed: ${message}`,
      };
      return this.lastHealthCheck;
    }
  }

  protected async doClose(): Promise<void> {
    // No persistent connections to close
    this.lastHealthCheck = null;
  }

  // ===========================================================================
  // Batch override for bulk sending
  // ===========================================================================

  /**
   * Override sendBatch to use Datadog's bulk log endpoint.
   * The Logs API accepts arrays of log entries natively.
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

    // Transform all events to Datadog format
    const logEntries = filtered.map((e) => this.transformEvent(e));

    try {
      const response = await fetch(this.apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'DD-API-KEY': this.datadogConfig.apiKey,
        },
        body: JSON.stringify(logEntries),
      });

      const success = response.ok;
      const error = success ? undefined : `HTTP ${response.status}`;

      // Return results for all events
      const results: SendResult[] = filtered.map((e) => ({
        success,
        eventId: e.eventId,
        error,
        retryable: response.status >= 500 || response.status === 429,
        response: { status: response.status },
      }));

      // Add filtered results
      const filteredResults: SendResult[] = events
        .filter((e) => !this.shouldProcess(e))
        .map((e) => ({
          success: true,
          eventId: e.eventId,
          response: { filtered: true },
        }));

      // Track metrics
      if (success) {
        this.metrics.eventsSent += filtered.length;
      } else {
        this.metrics.eventsFailed += filtered.length;
      }

      return [...results, ...filteredResults];
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
   * Transform a ForensicsEvent to Datadog log format.
   */
  private transformEvent: EventTransformer<DatadogLogEntry> = (
    event: ForensicsEvent
  ): DatadogLogEntry => {
    // Determine action (default to 'block' for backwards compatibility)
    const action: IocAction = event.action ?? 'block';
    const isBlock = action === 'block';

    // Build tags array
    const tags: string[] = [
      `action:${action}`,
      `match_type:${event.matchType}`,
      `org_id:${event.orgId}`,
      ...(this.datadogConfig.tags || []),
    ];

    // Add optional user/device tags
    if (event.userId) {
      tags.push(`user_id:${event.userId}`);
    }
    if (event.deviceId) {
      tags.push(`device_id:${event.deviceId}`);
    }

    // Build action-aware message
    const actionVerb = isBlock ? 'Blocked' : 'Unblocked';
    const message = `BrowserDefense: ${actionVerb} ${event.matchType} - ${event.matchedIndicator}`;

    return {
      // Required fields
      message,

      // Standard Datadog fields
      ddsource: this.datadogConfig.source || 'browserdefense',
      ddtags: tags.join(','),
      hostname: this.datadogConfig.hostname,
      service: this.datadogConfig.service || 'browserdefense',

      // BrowserDefense event attributes
      browserdefense: {
        event_id: event.eventId,
        event_type: isBlock ? 'browserdefense:block' : 'browserdefense:unblock',
        action,
        blocked_url: event.blockedUrl,
        matched_indicator: event.matchedIndicator,
        match_type: event.matchType,
        timestamp: event.timestamp,
        org_id: event.orgId,
        user_id: event.userId,
        device_id: event.deviceId,
        redirect_chain: event.redirectChain,
        tab_context: {
          tab_id: event.tabContext.tabId,
          window_id: event.tabContext.windowId,
          initiator_url: event.tabContext.initiatorUrl,
          tab_title: event.tabContext.tabTitle,
          incognito: event.tabContext.incognito,
        },
      },

      // Security-specific attributes for Datadog Security Monitoring
      network: {
        client: {
          ip: undefined, // Not available in browser context
        },
        destination: {
          domain: new URL(event.blockedUrl).hostname,
        },
      },

      // Severity level - warn for block, info for unblock
      status: isBlock ? 'warn' : 'info',
    };
  };

  // ===========================================================================
  // Public getters
  // ===========================================================================

  /**
   * Get the configured Datadog site.
   */
  get site(): string {
    return this.datadogConfig.site;
  }

  /**
   * Get the Datadog API URL.
   */
  get endpoint(): string {
    return this.apiUrl;
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Create a Datadog connector from configuration.
 */
export function createDatadogConnector(
  config: DatadogConnectorConfig
): DatadogConnector {
  return new DatadogConnector(config);
}

// Register with the global connector registry
connectorRegistry.register('datadog', createDatadogConnector);
