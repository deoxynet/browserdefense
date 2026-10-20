/**
 * BrowserDefense SentinelOne Connector
 *
 * Forwards forensics events to SentinelOne via the Threat Intelligence API.
 * Creates threat indicators from blocked IOCs for correlation with endpoint telemetry.
 *
 * API Reference: https://usea1-partners.sentinelone.net/api-doc/api-details
 */

import {
  BaseConnector,
  connectorRegistry,
  type EventTransformer,
} from './base';
import {
  type ForensicsEvent,
  type SendResult,
  type UnblockResult,
  type SentinelOneConnectorConfig,
} from './types';

// =============================================================================
// SentinelOne API Types
// =============================================================================

/**
 * SentinelOne threat indicator type.
 * Maps to the indicator types supported by the Threat Intelligence API.
 */
type S1IndicatorType = 'DNS' | 'URL' | 'SHA256' | 'SHA1' | 'MD5' | 'IPV4' | 'IPV6';

/**
 * SentinelOne threat indicator for the Threat Intelligence API.
 * Fields aligned with official API schema per Demisto/XSOAR reference.
 */
interface S1ThreatIndicator {
  /** Required: Indicator name for identification */
  name: string;
  /** Required: Comparison method for IOC matching (always "EQUALS") */
  method: 'EQUALS';
  /** Required: Expiration timestamp in ISO 8601 format */
  validUntil: string;
  /** Required: Indicator type (DNS for domains, URL for full URLs) */
  type: S1IndicatorType;
  /** Required: The indicator value */
  value: string;
  /** Required: Source of the indicator */
  source: string;
  /** Optional: Human-readable description */
  description: string;
  /** Optional: External ID for correlation */
  externalId?: string;
}

/**
 * Filter wrapper for SentinelOne API requests.
 * Required by the Threat Intelligence API.
 */
interface S1RequestFilter {
  /** Account IDs to scope the request */
  accountIds?: string[];
  /** Site IDs to scope the request */
  siteIds?: string[];
}

/**
 * Request body for creating threat indicators.
 * SentinelOne API requires the filter wrapper with accountIds.
 */
interface S1CreateIndicatorsRequest {
  /** Filter to scope the IOCs (required for Threat Intelligence API) */
  filter: S1RequestFilter;
  /** Array of threat indicators to create */
  data: S1ThreatIndicator[];
}

/**
 * SentinelOne API response wrapper.
 */
interface S1ApiResponse<T = unknown> {
  data?: T;
  errors?: Array<{
    code: number;
    detail: string;
    title: string;
  }>;
  pagination?: {
    totalItems: number;
    nextCursor?: string;
  };
}

/**
 * Health check response from SentinelOne system info endpoint.
 */
interface S1SystemInfo {
  data?: {
    health?: string;
    version?: string;
  };
}

/**
 * SentinelOne IOC record returned from search.
 */
interface S1IocRecord {
  id: string;
  value: string;
  type: S1IndicatorType;
  externalId?: string;
  name?: string;
}

/**
 * Response from IOC delete operation.
 */
interface S1DeleteResponse {
  data?: {
    affected: number;
  };
}

// =============================================================================
// SentinelOne Connector Implementation
// =============================================================================

/**
 * SentinelOne connector for forwarding forensics events as threat indicators.
 *
 * Creates IOC entries in SentinelOne's Threat Intelligence database, enabling:
 * - Correlation with endpoint detections
 * - Automatic threat hunting across managed endpoints
 * - Alert enrichment with browser-based context
 */
/** Default IOC expiration in days if not configured */
const DEFAULT_IOC_EXPIRATION_DAYS = 90;

export class SentinelOneConnector extends BaseConnector {
  readonly type = 'sentinelone' as const;
  readonly supportsUnblock = true;

  private readonly consoleUrl: string;
  private readonly apiToken: string;
  private readonly siteId?: string;
  private readonly accountId?: string;
  private readonly baseApiUrl: string;
  private readonly iocExpirationDays: number;

  constructor(config: SentinelOneConnectorConfig) {
    super(config);

    // Normalize console URL (remove trailing slash)
    this.consoleUrl = config.consoleUrl.replace(/\/+$/, '');
    this.apiToken = config.apiToken;
    this.siteId = config.siteId;
    this.accountId = config.accountId;
    this.iocExpirationDays = config.iocExpirationDays ?? DEFAULT_IOC_EXPIRATION_DAYS;

    // API v2.1 endpoint
    this.baseApiUrl = `${this.consoleUrl}/web/api/v2.1`;
  }

  // ===========================================================================
  // Abstract method implementations
  // ===========================================================================

  protected async doInit(): Promise<void> {
    // Validate configuration
    if (!this.consoleUrl) {
      throw new Error('SentinelOne console URL is required');
    }
    if (!this.apiToken) {
      throw new Error('SentinelOne API token is required');
    }

    // Verify connectivity and API token validity
    const healthResult = await this.doHealth();
    if (!healthResult.healthy) {
      throw new Error(`SentinelOne initialization failed: ${healthResult.message}`);
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const indicator = this.transformEvent(event);

    // Build filter with accountIds/siteIds as required by the API
    const filter: S1RequestFilter = {};
    if (this.accountId) {
      filter.accountIds = [this.accountId];
    }
    if (this.siteId) {
      filter.siteIds = [this.siteId];
    }

    const requestBody: S1CreateIndicatorsRequest = {
      filter,
      data: [indicator],
    };

    try {
      const response = await this.makeApiRequest<S1ApiResponse>(
        '/threat-intelligence/iocs',
        'POST',
        requestBody
      );

      // Check for API errors
      if (response.errors && response.errors.length > 0) {
        const errorMessages = response.errors.map((e) => e.detail).join('; ');
        const isRetryable = response.errors.some(
          (e) => e.code === 429 || e.code >= 500
        );

        return {
          success: false,
          eventId: event.eventId,
          error: errorMessages,
          retryable: isRetryable,
          response: response as unknown as Record<string, unknown>,
        };
      }

      return {
        success: true,
        eventId: event.eventId,
        response: response as unknown as Record<string, unknown>,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Determine if the error is retryable
      // - Network errors are always retryable
      // - Rate limiting (429) is retryable
      // - Server errors (5xx) are retryable
      const isRetryableError = errorMessage.includes('fetch') ||
                               errorMessage.includes('network') ||
                               errorMessage.includes('timeout') ||
                               errorMessage.includes('Rate limited') ||
                               /\b5\d{2}\b/.test(errorMessage);

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable: isRetryableError,
      };
    }
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      // Use the system/info endpoint to check API connectivity
      // This is a lightweight read-only endpoint
      const response = await this.makeApiRequest<S1SystemInfo>(
        '/system/info',
        'GET'
      );

      if (response.data?.health === 'ok' || response.data) {
        return {
          healthy: true,
          message: `Connected to SentinelOne${response.data?.version ? ` v${response.data.version}` : ''}`,
        };
      }

      return {
        healthy: true,
        message: 'Connected to SentinelOne',
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        healthy: false,
        message: `SentinelOne health check failed: ${errorMessage}`,
      };
    }
  }

  protected async doClose(): Promise<void> {
    // No persistent connections to close
  }

  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    try {
      // Search for the IOC by externalId (which matches event.eventId)
      const ioc = await this.findIocByExternalId(event.eventId);

      if (!ioc) {
        // IOC not found - already deleted or never created
        return {
          success: true,
          eventId: event.eventId,
          alreadyClosed: true,
        };
      }

      // Delete the IOC by its internal ID
      await this.deleteIoc(ioc.id);

      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: false,
        incidentId: ioc.id,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Check for 404 - IOC already deleted
      if (errorMessage.includes('404') || errorMessage.includes('not found')) {
        return {
          success: true,
          eventId: event.eventId,
          alreadyClosed: true,
        };
      }

      // Determine if error is retryable
      const isRetryable =
        errorMessage.includes('Rate limited') ||
        errorMessage.includes('timeout') ||
        errorMessage.includes('network') ||
        /\b5\d{2}\b/.test(errorMessage);

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable: isRetryable,
      };
    }
  }

  /**
   * Find an IOC by its external ID (event.eventId).
   * Returns null if not found.
   */
  private async findIocByExternalId(externalId: string): Promise<S1IocRecord | null> {
    const response = await this.makeApiRequest<S1ApiResponse<S1IocRecord[]>>(
      `/threat-intelligence/iocs?externalId=${encodeURIComponent(externalId)}`,
      'GET'
    );

    if (response.data && response.data.length > 0) {
      return response.data[0];
    }

    return null;
  }

  /**
   * Delete an IOC by its internal ID.
   */
  private async deleteIoc(iocId: string): Promise<void> {
    await this.makeApiRequest<S1DeleteResponse>(
      `/threat-intelligence/iocs/${iocId}`,
      'DELETE'
    );
  }

  // ===========================================================================
  // Event transformation
  // ===========================================================================

  /**
   * Transform a forensics event to a SentinelOne threat indicator.
   * Includes all required fields per official API schema.
   */
  private transformEvent: EventTransformer<S1ThreatIndicator> = (event) => {
    const indicatorType = this.mapMatchTypeToS1Type(event);
    const indicatorValue = this.extractIndicatorValue(event);

    // Calculate expiration date
    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + this.iocExpirationDays);

    return {
      name: `BlockIOC-${event.eventId}`,
      method: 'EQUALS',
      validUntil: expirationDate.toISOString(),
      type: indicatorType,
      value: indicatorValue,
      source: 'BrowserDefense',
      description: this.buildDescription(event),
      externalId: event.eventId,
    };
  };

  /**
   * Map BrowserDefense match type to SentinelOne indicator type.
   * For hash matches, detects SHA256 (64 chars), SHA1 (40 chars), or MD5 (32 chars).
   */
  private mapMatchTypeToS1Type(event: ForensicsEvent): S1IndicatorType {
    switch (event.matchType) {
      case 'domain':
        return 'DNS';
      case 'url':
        return 'URL';
      case 'hash':
        return this.detectHashType(event.matchedIndicator);
      default:
        return 'URL';
    }
  }

  /**
   * Detect hash type based on length of the hash string.
   */
  private detectHashType(hash: string): 'SHA256' | 'SHA1' | 'MD5' {
    const cleanHash = hash.trim().toLowerCase();
    switch (cleanHash.length) {
      case 64:
        return 'SHA256';
      case 40:
        return 'SHA1';
      case 32:
        return 'MD5';
      default:
        // Default to SHA256 for unknown lengths
        return 'SHA256';
    }
  }

  /**
   * Extract the appropriate indicator value based on match type.
   */
  private extractIndicatorValue(event: ForensicsEvent): string {
    switch (event.matchType) {
      case 'domain':
        // Extract domain from blocked URL
        try {
          const url = new URL(event.blockedUrl);
          return url.hostname;
        } catch {
          // If URL parsing fails, use the matched indicator directly
          return event.matchedIndicator;
        }
      case 'hash':
        return event.matchedIndicator;
      case 'url':
      default:
        return event.blockedUrl;
    }
  }

  /**
   * Build a human-readable description for the indicator.
   */
  private buildDescription(event: ForensicsEvent): string {
    const parts: string[] = [
      `Blocked navigation to ${event.matchType} IOC`,
      `at ${new Date(event.timestamp).toISOString()}`,
    ];

    if (event.tabContext.initiatorUrl) {
      parts.push(`from ${event.tabContext.initiatorUrl}`);
    }

    if (event.redirectChain.length > 0) {
      parts.push(`(${event.redirectChain.length} redirects)`);
    }

    return parts.join(' ');
  }

  // ===========================================================================
  // HTTP client
  // ===========================================================================

  /**
   * Make an authenticated request to the SentinelOne API.
   * Note: Account/site scoping is done via filter wrapper in POST body.
   * For GET requests, query params are used for scoping.
   */
  private async makeApiRequest<T>(
    endpoint: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    body?: unknown
  ): Promise<T> {
    const url = new URL(`${this.baseApiUrl}${endpoint}`);

    // Add site/account scoping to query params for GET requests only.
    // For POST/PUT requests, these are included in the request body filter.
    if (method === 'GET') {
      if (this.siteId) {
        url.searchParams.set('siteIds', this.siteId);
      }
      if (this.accountId) {
        url.searchParams.set('accountIds', this.accountId);
      }
    }

    const headers: Record<string, string> = {
      'Authorization': `ApiToken ${this.apiToken}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    const fetchOptions: RequestInit = {
      method,
      headers,
    };

    if (body && (method === 'POST' || method === 'PUT')) {
      fetchOptions.body = JSON.stringify(body);
    }

    const response = await fetch(url.toString(), fetchOptions);

    // Handle rate limiting
    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After');
      throw new Error(
        `Rate limited by SentinelOne API${retryAfter ? `, retry after ${retryAfter}s` : ''}`
      );
    }

    // Handle authentication errors
    if (response.status === 401) {
      throw new Error('SentinelOne API authentication failed: Invalid or expired API token');
    }

    // Handle authorization errors
    if (response.status === 403) {
      throw new Error(
        'SentinelOne API authorization failed: Token lacks required scopes (threat-intelligence:write)'
      );
    }

    // Handle other HTTP errors
    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(
        `SentinelOne API error (${response.status}): ${errorBody || response.statusText}`
      );
    }

    return response.json() as Promise<T>;
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Factory function for creating SentinelOne connector instances.
 */
export function createSentinelOneConnector(
  config: SentinelOneConnectorConfig
): SentinelOneConnector {
  return new SentinelOneConnector(config);
}

// Register with the connector registry
connectorRegistry.register('sentinelone', createSentinelOneConnector);
