/**
 * BrowserDefense CrowdStrike Falcon Connector
 *
 * Sends forensics events to CrowdStrike Falcon via their API.
 * Supports:
 * - OAuth2 client credentials authentication
 * - LogScale (Humio) JSON ingestion
 * - Custom IOC creation via IOC Manager API
 *
 * Unblock Support:
 * - Sends unblock event to LogScale for correlation
 * - Deletes IOC from IOC Manager if that target was used
 * - Deletes indicator from Intel if that target was used
 * - Treats not-found as success (idempotent)
 *
 * @see https://falcon.crowdstrike.com/documentation/
 */

import {
  BaseConnector,
  connectorRegistry,
  EventTransformer,
} from './base';
import {
  CrowdStrikeConnectorConfig,
  ForensicsEvent,
  SendResult,
  UnblockResult,
} from './types';

// =============================================================================
// CrowdStrike API Types
// =============================================================================

/**
 * OAuth2 token response from CrowdStrike.
 */
interface OAuth2TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

/**
 * LogScale event format for ingestion.
 */
interface LogScaleEvent {
  timestamp: string;
  attributes: {
    blocked_url: string;
    redirect_chain: string[];
    org_id: string;
    event_id: string;
    match_type: string;
    matched_indicator: string;
    tab_context: {
      tab_id: number;
      window_id: number;
      initiator_url?: string;
      tab_title?: string;
      incognito: boolean;
    };
    user_id?: string;
    device_id?: string;
    /** Action type for event (block/unblock) */
    action?: string;
  };
}

/**
 * LogScale ingestion payload.
 */
interface LogScalePayload {
  tags: {
    source: string;
    [key: string]: string;
  };
  events: LogScaleEvent[];
}

/**
 * Custom IOC format for CrowdStrike IOC Manager.
 */
interface CrowdStrikeIOC {
  type: 'domain' | 'ipv4' | 'ipv6' | 'md5' | 'sha256';
  value: string;
  action: 'no_action' | 'allow' | 'detect' | 'block' | 'block_hide';
  platforms: Array<'windows' | 'mac' | 'linux'>;
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  source: string;
  applied_globally: boolean;
  host_groups?: string[];
  description?: string;
  expiration?: string;
  tags?: string[];
  metadata?: {
    signed_on?: string;
    signed_by?: string;
  };
}

/**
 * IOC Manager API request payload.
 */
interface IOCManagerPayload {
  indicators: CrowdStrikeIOC[];
  comment?: string;
}

/**
 * Intel indicator format for CrowdStrike Threat Intel.
 */
interface IntelIndicator {
  type: string;
  indicator: string;
  action: string;
  description?: string;
  labels?: Array<{ name: string }>;
  malicious_confidence?: 'high' | 'medium' | 'low' | 'unverified';
}

/**
 * CrowdStrike API error response.
 */
interface CrowdStrikeError {
  meta: {
    query_time: number;
    trace_id: string;
  };
  errors: Array<{
    code: number;
    message: string;
  }>;
}

// =============================================================================
// CrowdStrike Cloud Regions
// =============================================================================

/**
 * CrowdStrike cloud region to base URL mapping.
 */
const CLOUD_REGIONS: Record<string, string> = {
  'us-1': 'https://api.crowdstrike.com',
  'us-2': 'https://api.us-2.crowdstrike.com',
  'eu-1': 'https://api.eu-1.crowdstrike.com',
  'us-gov-1': 'https://api.laggar.gcw.crowdstrike.com',
  'us-gov-2': 'https://api.laggar.gcw.crowdstrike.com',
};

// =============================================================================
// CrowdStrike Connector Implementation
// =============================================================================

/**
 * CrowdStrike Falcon connector for forwarding forensics events.
 *
 * Authentication uses OAuth2 client credentials flow:
 * 1. Exchange client_id + client_secret for access_token
 * 2. Use access_token for API requests
 * 3. Token is automatically refreshed before expiry
 *
 * Event delivery supports two targets:
 * - `ioc-manager`: Creates custom IOCs in Falcon IOC Management
 * - `intel-indicator`: Creates indicators in Threat Intelligence
 *
 * Both options also send events to LogScale for logging/analytics.
 */
export class CrowdStrikeConnector extends BaseConnector {
  readonly type = 'crowdstrike' as const;

  /**
   * CrowdStrike supports unblock via IOC/indicator deletion.
   * Also logs unblock events to LogScale for correlation.
   */
  readonly supportsUnblock = true;

  private readonly crowdStrikeConfig: CrowdStrikeConnectorConfig;
  private accessToken: string | null = null;
  private tokenExpiresAt: number = 0;

  // Token refresh buffer (refresh 5 minutes before expiry)
  private static readonly TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000;

  constructor(config: CrowdStrikeConnectorConfig) {
    super(config);
    this.crowdStrikeConfig = config;
  }

  // ===========================================================================
  // Abstract method implementations
  // ===========================================================================

  protected async doInit(): Promise<void> {
    // Validate configuration
    this.validateConfig();

    // Get initial access token
    await this.refreshToken();
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    try {
      // Ensure we have a valid token
      await this.ensureValidToken();

      // Send to LogScale for logging (always)
      const logScaleResult = await this.sendToLogScale(event);
      if (!logScaleResult.success) {
        return logScaleResult;
      }

      // Optionally create IOC based on target
      if (this.crowdStrikeConfig.iocTarget === 'ioc-manager') {
        return await this.createIOC(event);
      } else if (this.crowdStrikeConfig.iocTarget === 'intel-indicator') {
        return await this.createIntelIndicator(event);
      }

      return logScaleResult;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const isRetryable = this.isRetryableError(error);

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable: isRetryable,
      };
    }
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      // Check token validity
      await this.ensureValidToken();

      // Perform a simple API check (get system info)
      const response = await this.makeRequest('GET', '/sensors/combined/sensor-installers/v1?limit=1');

      if (response.ok) {
        return {
          healthy: true,
          message: 'CrowdStrike Falcon API is reachable',
        };
      }

      const errorBody = await response.json() as CrowdStrikeError;
      return {
        healthy: false,
        message: `CrowdStrike API error: ${errorBody.errors?.[0]?.message || 'Unknown error'}`,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        healthy: false,
        message: `CrowdStrike health check failed: ${errorMessage}`,
      };
    }
  }

  protected async doClose(): Promise<void> {
    // Clear token on close
    this.accessToken = null;
    this.tokenExpiresAt = 0;
  }

  /**
   * Unblock by sending event to LogScale and deleting IOC/indicator.
   */
  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    try {
      await this.ensureValidToken();

      // Send unblock event to LogScale for logging
      await this.sendUnblockToLogScale(event);

      // Delete IOC or indicator based on target
      if (this.crowdStrikeConfig.iocTarget === 'ioc-manager') {
        return await this.deleteIOC(event);
      } else if (this.crowdStrikeConfig.iocTarget === 'intel-indicator') {
        return await this.deleteIntelIndicator(event);
      }

      // LogScale-only mode - unblock event logged successfully
      return {
        success: true,
        eventId: event.eventId,
        incidentId: `unblock-${event.eventId}`,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const isRetryable = this.isRetryableError(error);

      return {
        success: false,
        eventId: event.eventId,
        error: `CrowdStrike unblock failed: ${errorMessage}`,
        retryable: isRetryable,
      };
    }
  }

  /**
   * Send an unblock event to LogScale for correlation.
   */
  private async sendUnblockToLogScale(event: ForensicsEvent): Promise<void> {
    const payload: LogScalePayload = {
      tags: {
        source: 'browserdefense',
        org_id: event.orgId,
        action: 'unblock',
      },
      events: [{
        timestamp: new Date().toISOString(),
        attributes: {
          blocked_url: event.blockedUrl,
          redirect_chain: [],
          org_id: event.orgId,
          event_id: event.eventId,
          match_type: event.matchType,
          matched_indicator: event.matchedIndicator,
          tab_context: {
            tab_id: 0,
            window_id: 0,
            incognito: false,
          },
          action: 'unblock',
        },
      }],
    };

    await this.makeRequest('POST', '/humio/api/v1/ingest/json', payload);
  }

  /**
   * Delete an IOC from IOC Manager by indicator value.
   */
  private async deleteIOC(event: ForensicsEvent): Promise<UnblockResult> {
    const iocType = this.mapMatchTypeToIOCType(event.matchType);
    if (!iocType) {
      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: true,
      };
    }

    // Query for IOCs with matching value
    const filter = encodeURIComponent(`value:'${event.matchedIndicator}'+source:'BrowserDefense'`);
    const queryResponse = await this.makeRequest(
      'GET',
      `/iocs/combined/indicator/v1?filter=${filter}`
    );

    if (!queryResponse.ok) {
      // Query failed - treat as not found
      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: true,
      };
    }

    const queryData = await queryResponse.json() as {
      resources?: Array<{ id: string }>;
    };

    if (!queryData.resources || queryData.resources.length === 0) {
      // No matching IOCs found
      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: true,
      };
    }

    // Delete all matching IOCs
    const ids = queryData.resources.map(r => r.id).join('&ids=');
    const deleteResponse = await this.makeRequest(
      'DELETE',
      `/iocs/entities/indicators/v1?ids=${ids}`
    );

    if (deleteResponse.ok || deleteResponse.status === 404) {
      return {
        success: true,
        eventId: event.eventId,
        incidentId: ids,
      };
    }

    const errorBody = await deleteResponse.json() as CrowdStrikeError;
    return {
      success: false,
      eventId: event.eventId,
      error: `IOC deletion failed: ${errorBody.errors?.[0]?.message || deleteResponse.status}`,
      retryable: this.isRetryableStatus(deleteResponse.status),
    };
  }

  /**
   * Delete an intel indicator by value.
   */
  private async deleteIntelIndicator(event: ForensicsEvent): Promise<UnblockResult> {
    const indicatorType = this.mapMatchTypeToIntelType(event.matchType);
    if (!indicatorType) {
      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: true,
      };
    }

    // Query for indicators with matching value
    const filter = encodeURIComponent(`indicator:'${event.matchedIndicator}'`);
    const queryResponse = await this.makeRequest(
      'GET',
      `/intel/combined/indicators/v1?filter=${filter}`
    );

    if (!queryResponse.ok) {
      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: true,
      };
    }

    const queryData = await queryResponse.json() as {
      resources?: Array<{ id: string }>;
    };

    if (!queryData.resources || queryData.resources.length === 0) {
      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: true,
      };
    }

    // Delete all matching indicators
    const ids = queryData.resources.map(r => r.id).join('&ids=');
    const deleteResponse = await this.makeRequest(
      'DELETE',
      `/intel/entities/indicators/v1?ids=${ids}`
    );

    if (deleteResponse.ok || deleteResponse.status === 404) {
      return {
        success: true,
        eventId: event.eventId,
        incidentId: ids,
      };
    }

    const errorBody = await deleteResponse.json() as CrowdStrikeError;
    return {
      success: false,
      eventId: event.eventId,
      error: `Intel indicator deletion failed: ${errorBody.errors?.[0]?.message || deleteResponse.status}`,
      retryable: this.isRetryableStatus(deleteResponse.status),
    };
  }

  // ===========================================================================
  // OAuth2 Token Management
  // ===========================================================================

  /**
   * Validate the connector configuration.
   */
  private validateConfig(): void {
    if (!this.crowdStrikeConfig.clientId) {
      throw new Error('CrowdStrike connector requires clientId');
    }
    if (!this.crowdStrikeConfig.clientSecret) {
      throw new Error('CrowdStrike connector requires clientSecret');
    }
    if (!this.crowdStrikeConfig.baseUrl) {
      throw new Error('CrowdStrike connector requires baseUrl');
    }
  }

  /**
   * Ensure we have a valid access token, refreshing if needed.
   */
  private async ensureValidToken(): Promise<void> {
    const now = Date.now();
    if (this.accessToken && this.tokenExpiresAt > now + CrowdStrikeConnector.TOKEN_REFRESH_BUFFER_MS) {
      return; // Token is still valid
    }
    await this.refreshToken();
  }

  /**
   * Exchange client credentials for an access token.
   */
  private async refreshToken(): Promise<void> {
    const tokenUrl = `${this.crowdStrikeConfig.baseUrl}/oauth2/token`;

    const body = new URLSearchParams();
    body.append('client_id', this.crowdStrikeConfig.clientId);
    body.append('client_secret', this.crowdStrikeConfig.clientSecret);

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`OAuth2 token request failed: ${response.status} ${errorBody}`);
    }

    const tokenData = await response.json() as OAuth2TokenResponse;

    this.accessToken = tokenData.access_token;
    // Set expiry time (in milliseconds)
    this.tokenExpiresAt = Date.now() + (tokenData.expires_in * 1000);
  }

  // ===========================================================================
  // API Request Helper
  // ===========================================================================

  /**
   * Make an authenticated request to the CrowdStrike API.
   */
  private async makeRequest(
    method: string,
    path: string,
    body?: unknown,
    customHeaders?: Record<string, string>
  ): Promise<Response> {
    const url = `${this.crowdStrikeConfig.baseUrl}${path}`;

    const headers: Record<string, string> = {
      'Authorization': `Bearer ${this.accessToken}`,
      'Accept': 'application/json',
      ...customHeaders,
    };

    if (body) {
      headers['Content-Type'] = 'application/json';
    }

    return fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  // ===========================================================================
  // LogScale (Humio) Integration
  // ===========================================================================

  /**
   * Transform a forensics event to LogScale format.
   */
  private readonly toLogScaleEvent: EventTransformer<LogScaleEvent> = (event) => ({
    timestamp: event.timestamp,
    attributes: {
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
    },
  });

  /**
   * Send an event to LogScale (Humio) for logging.
   */
  private async sendToLogScale(event: ForensicsEvent): Promise<SendResult> {
    const payload: LogScalePayload = {
      tags: {
        source: 'browserdefense',
        org_id: event.orgId,
      },
      events: [this.toLogScaleEvent(event)],
    };

    const response = await this.makeRequest(
      'POST',
      '/humio/api/v1/ingest/json',
      payload
    );

    if (response.ok) {
      return {
        success: true,
        eventId: event.eventId,
        response: { target: 'logscale' },
      };
    }

    const errorBody = await response.json() as CrowdStrikeError;
    const errorMessage = errorBody.errors?.[0]?.message || `HTTP ${response.status}`;

    return {
      success: false,
      eventId: event.eventId,
      error: `LogScale ingestion failed: ${errorMessage}`,
      retryable: this.isRetryableStatus(response.status),
    };
  }

  // ===========================================================================
  // IOC Manager Integration
  // ===========================================================================

  /**
   * Create a custom IOC in CrowdStrike IOC Manager.
   */
  private async createIOC(event: ForensicsEvent): Promise<SendResult> {
    // Map match type to CrowdStrike IOC type
    const iocType = this.mapMatchTypeToIOCType(event.matchType);
    if (!iocType) {
      return {
        success: true, // Not an error, just unsupported type
        eventId: event.eventId,
        response: { skipped: true, reason: 'Unsupported match type for IOC' },
      };
    }

    const ioc: CrowdStrikeIOC = {
      type: iocType,
      value: event.matchedIndicator,
      action: 'detect', // Alert but don't block at endpoint level
      platforms: ['windows', 'mac', 'linux'],
      severity: 'medium',
      source: 'BrowserDefense',
      applied_globally: true,
      description: `Blocked navigation to ${event.blockedUrl} from browser extension`,
      tags: ['browserdefense', event.orgId],
      metadata: {
        signed_on: event.timestamp,
      },
    };

    const payload: IOCManagerPayload = {
      indicators: [ioc],
      comment: `BlockIOC detection: ${event.matchType} indicator from org ${event.orgId}`,
    };

    const response = await this.makeRequest(
      'POST',
      '/iocs/entities/indicators/v1',
      payload
    );

    if (response.ok || response.status === 201) {
      const responseBody = await response.json();
      return {
        success: true,
        eventId: event.eventId,
        response: { target: 'ioc-manager', ...(responseBody as Record<string, unknown>) },
      };
    }

    const errorBody = await response.json() as CrowdStrikeError;
    const errorMessage = errorBody.errors?.[0]?.message || `HTTP ${response.status}`;

    return {
      success: false,
      eventId: event.eventId,
      error: `IOC creation failed: ${errorMessage}`,
      retryable: this.isRetryableStatus(response.status),
    };
  }

  // ===========================================================================
  // Intel Indicator Integration
  // ===========================================================================

  /**
   * Create an intel indicator in CrowdStrike Threat Intelligence.
   */
  private async createIntelIndicator(event: ForensicsEvent): Promise<SendResult> {
    const indicatorType = this.mapMatchTypeToIntelType(event.matchType);
    if (!indicatorType) {
      return {
        success: true,
        eventId: event.eventId,
        response: { skipped: true, reason: 'Unsupported match type for intel indicator' },
      };
    }

    const indicator: IntelIndicator = {
      type: indicatorType,
      indicator: event.matchedIndicator,
      action: 'detect',
      description: `BrowserDefense: ${event.blockedUrl}`,
      labels: [
        { name: 'browserdefense' },
        { name: event.orgId },
      ],
      malicious_confidence: 'high',
    };

    const response = await this.makeRequest(
      'POST',
      '/intel/entities/indicators/v1',
      { indicators: [indicator] }
    );

    if (response.ok || response.status === 201) {
      const responseBody = await response.json();
      return {
        success: true,
        eventId: event.eventId,
        response: { target: 'intel-indicator', ...(responseBody as Record<string, unknown>) },
      };
    }

    const errorBody = await response.json() as CrowdStrikeError;
    const errorMessage = errorBody.errors?.[0]?.message || `HTTP ${response.status}`;

    return {
      success: false,
      eventId: event.eventId,
      error: `Intel indicator creation failed: ${errorMessage}`,
      retryable: this.isRetryableStatus(response.status),
    };
  }

  // ===========================================================================
  // Helper Methods
  // ===========================================================================

  /**
   * Map BrowserDefense match type to CrowdStrike IOC type.
   */
  private mapMatchTypeToIOCType(matchType: string): CrowdStrikeIOC['type'] | null {
    switch (matchType) {
      case 'domain':
        return 'domain';
      case 'hash':
        return 'sha256'; // Assume SHA256, could be refined
      case 'url':
        // URLs are not directly supported, would need to extract domain
        return null;
      default:
        return null;
    }
  }

  /**
   * Map BrowserDefense match type to CrowdStrike Intel indicator type.
   */
  private mapMatchTypeToIntelType(matchType: string): string | null {
    switch (matchType) {
      case 'domain':
        return 'domain';
      case 'hash':
        return 'hash_sha256';
      case 'url':
        return 'url';
      default:
        return null;
    }
  }

  /**
   * Check if an HTTP status code indicates a retryable error.
   */
  private isRetryableStatus(status: number): boolean {
    // Retry on server errors and rate limiting
    return status >= 500 || status === 429;
  }

  /**
   * Check if an error is retryable.
   */
  private isRetryableError(error: unknown): boolean {
    if (error instanceof Error) {
      // Network errors are typically retryable
      const message = error.message.toLowerCase();
      return (
        message.includes('network') ||
        message.includes('timeout') ||
        message.includes('econnrefused') ||
        message.includes('econnreset')
      );
    }
    return false;
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Create a CrowdStrike connector from configuration.
 */
export function createCrowdStrikeConnector(
  config: CrowdStrikeConnectorConfig
): CrowdStrikeConnector {
  return new CrowdStrikeConnector(config);
}

// Register the connector factory
connectorRegistry.register('crowdstrike', createCrowdStrikeConnector);

// =============================================================================
// Utility Exports
// =============================================================================

/**
 * Get the base URL for a CrowdStrike cloud region.
 */
export function getCloudBaseUrl(region: string): string | undefined {
  return CLOUD_REGIONS[region];
}

/**
 * Available CrowdStrike cloud regions.
 */
export const CROWDSTRIKE_REGIONS = Object.keys(CLOUD_REGIONS);
