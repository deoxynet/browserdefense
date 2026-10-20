/**
 * BrowserDefense VMware Carbon Black Cloud Connector
 *
 * Sends forensics events to Carbon Black Cloud as threat intelligence reports.
 * Uses the Threat Intelligence Feed Manager API to create IOC entries.
 *
 * Authentication: API Key (API ID + API Secret)
 * Format: X-Auth-Token: {api_secret}/{api_id}
 *
 * API Documentation:
 * https://developer.carbonblack.com/reference/carbon-black-cloud/
 */

import { BaseConnector, connectorRegistry } from './base';
import {
  CarbonBlackConnectorConfig,
  ForensicsEvent,
  SendResult,
  UnblockResult,
} from './types';

// =============================================================================
// Carbon Black API Types
// =============================================================================

/**
 * IOC v2 format for Carbon Black threat intelligence.
 */
interface CarbonBlackIOC {
  /** Unique identifier for this IOC */
  id: string;
  /** Match type (equality, query, regex) */
  match_type: 'equality' | 'query' | 'regex';
  /** Field to match against */
  field: CarbonBlackIOCField;
  /** Values to match */
  values: string[];
  /** Link for more information */
  link?: string;
}

/**
 * Supported IOC fields in Carbon Black.
 */
type CarbonBlackIOCField =
  | 'netconn_domain'
  | 'netconn_ipv4'
  | 'netconn_ipv6'
  | 'process_hash'
  | 'process_name'
  | 'filemod_hash'
  | 'filemod_name'
  | 'regmod_name';

/**
 * Report format for Carbon Black threat intelligence feed.
 */
interface CarbonBlackReport {
  /** Unique identifier for the report */
  id: string;
  /** Report title */
  title: string;
  /** Report description */
  description: string;
  /** Severity (1-10) */
  severity: number;
  /** Link to more information */
  link?: string;
  /** Unix timestamp */
  timestamp: number;
  /** IOCs in this report */
  iocs_v2: CarbonBlackIOC[];
  /** Tags for categorization */
  tags: string[];
  /** Visibility (org_only or visible to all) */
  visibility?: 'org_only' | 'visible';
}

/**
 * Feed information structure.
 */
interface CarbonBlackFeed {
  /** Feed ID */
  id: string;
  /** Feed name */
  name: string;
  /** Feed provider URL */
  provider_url: string;
  /** Summary of the feed */
  summary: string;
  /** Category */
  category: string;
  /** Whether feed is enabled */
  access: 'private' | 'public';
}

/**
 * API response for feed operations.
 */
interface FeedResponse {
  feedinfo: CarbonBlackFeed;
}

/**
 * API response for report operations.
 */
interface ReportResponse {
  success: boolean;
  message?: string;
}

/**
 * Organization validation response.
 */
interface OrgValidationResponse {
  organization_key: string;
  organization_name: string;
}

// =============================================================================
// Carbon Black Connector Implementation
// =============================================================================

/**
 * VMware Carbon Black Cloud connector.
 *
 * Sends forensics events as threat intelligence reports to Carbon Black Cloud.
 * Creates IOC entries that can be used for detection and hunting.
 *
 * Features:
 * - Automatic feed creation if not exists
 * - IOC v2 format support
 * - Domain/URL/hash IOC types
 * - Configurable severity and tags
 *
 * @example
 * ```typescript
 * const connector = new CarbonBlackConnector({
 *   name: 'cb-prod',
 *   enabled: true,
 *   type: 'carbonblack',
 *   url: 'https://defense-prod05.conferdeploy.net',
 *   orgKey: 'ABC123',
 *   apiId: 'api-id',
 *   apiSecret: 'api-secret',
 *   feedId: 'browserdefense',
 * });
 *
 * await connector.init();
 * await connector.send(event);
 * ```
 */
export class CarbonBlackConnector extends BaseConnector {
  readonly type = 'carbonblack' as const;
  readonly supportsUnblock = true;

  private readonly carbonBlackConfig: CarbonBlackConnectorConfig;
  private readonly feedId: string;
  private readonly defaultSeverity: number;
  private readonly defaultTags: string[];
  private feedExists: boolean = false;

  constructor(config: CarbonBlackConnectorConfig) {
    super(config);
    this.carbonBlackConfig = config;
    this.feedId = config.feedId || 'browserdefense';
    this.defaultSeverity = config.defaultSeverity ?? 5;
    this.defaultTags = config.tags || ['browserdefense', 'browser-block'];
  }

  // ===========================================================================
  // Abstract method implementations
  // ===========================================================================

  /**
   * Initialize the connector.
   * Validates credentials and ensures the feed exists.
   */
  protected async doInit(): Promise<void> {
    // Validate org key
    await this.validateOrganization();

    // Ensure feed exists (create if not)
    await this.ensureFeedExists();
  }

  /**
   * Send a forensics event to Carbon Black.
   * Creates a threat intelligence report with IOC entries.
   */
  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const report = this.createReport(event);

    try {
      const response = await this.createOrUpdateReport(report);

      return {
        success: true,
        eventId: event.eventId,
        response: {
          reportId: report.id,
          feedId: this.feedId,
          ...response,
        },
      };
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

  /**
   * Perform health check.
   * Validates API connectivity and organization access.
   */
  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      await this.validateOrganization();
      return {
        healthy: true,
        message: `Connected to Carbon Black Cloud (org: ${this.carbonBlackConfig.orgKey})`,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        healthy: false,
        message: `Carbon Black health check failed: ${errorMessage}`,
      };
    }
  }

  /**
   * Clean up resources.
   */
  protected async doClose(): Promise<void> {
    // No persistent connections to clean up
  }

  /**
   * Unblock/revoke a previously blocked indicator.
   * Deletes the threat intelligence report from Carbon Black.
   *
   * Uses the deterministic report ID based on eventId to target the unblock.
   * Handles idempotent case when the report is already deleted (404 = alreadyClosed).
   */
  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    const reportId = this.getReportId(event.eventId);

    try {
      await this.deleteReport(reportId);

      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: false,
        incidentId: reportId,
      };
    } catch (error) {
      // Handle idempotent case: report already deleted
      if (error instanceof CarbonBlackApiError && error.statusCode === 404) {
        return {
          success: true,
          eventId: event.eventId,
          alreadyClosed: true,
          incidentId: reportId,
        };
      }

      const errorMessage = error instanceof Error ? error.message : String(error);
      const isRetryable = this.isRetryableError(error);

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable: isRetryable,
        incidentId: reportId,
      };
    }
  }

  // ===========================================================================
  // Private helper methods
  // ===========================================================================

  /**
   * Generate a deterministic report ID from an event ID.
   * This allows targeting specific reports for unblock operations.
   */
  private getReportId(eventId: string): string {
    return `browserdefense-${eventId}`;
  }

  /**
   * Get the authentication header value.
   */
  private getAuthToken(): string {
    return `${this.carbonBlackConfig.apiSecret}/${this.carbonBlackConfig.apiId}`;
  }

  /**
   * Build the base API URL for the organization.
   */
  private getApiUrl(path: string): string {
    const baseUrl = this.carbonBlackConfig.url.replace(/\/$/, '');
    return `${baseUrl}${path}`;
  }

  /**
   * Make an authenticated API request.
   */
  private async apiRequest<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = this.getApiUrl(path);

    const headers: Record<string, string> = {
      'X-Auth-Token': this.getAuthToken(),
      'Content-Type': 'application/json',
    };

    const options: RequestInit = {
      method,
      headers,
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      throw new CarbonBlackApiError(
        `Carbon Black API error: ${response.status} ${response.statusText} - ${errorText}`,
        response.status,
        errorText
      );
    }

    // Some endpoints return empty responses
    const text = await response.text();
    if (!text) {
      return {} as T;
    }

    return JSON.parse(text) as T;
  }

  /**
   * Validate the organization key and API credentials.
   */
  private async validateOrganization(): Promise<void> {
    try {
      // Use the device API to validate credentials
      // This is a lightweight endpoint that requires valid org access
      await this.apiRequest<OrgValidationResponse>(
        'GET',
        `/appservices/v6/orgs/${this.carbonBlackConfig.orgKey}/alerts/_search?rows=1`
      );
    } catch (error) {
      if (error instanceof CarbonBlackApiError && error.statusCode === 401) {
        throw new Error('Invalid Carbon Black API credentials');
      }
      if (error instanceof CarbonBlackApiError && error.statusCode === 403) {
        throw new Error('Insufficient permissions for Carbon Black organization');
      }
      if (error instanceof CarbonBlackApiError && error.statusCode === 404) {
        throw new Error(`Carbon Black organization not found: ${this.carbonBlackConfig.orgKey}`);
      }
      throw error;
    }
  }

  /**
   * Ensure the threat intelligence feed exists, creating it if necessary.
   */
  private async ensureFeedExists(): Promise<void> {
    if (this.feedExists) {
      return;
    }

    try {
      // Try to get existing feed
      await this.apiRequest<FeedResponse>(
        'GET',
        `/threathunter/feedmgr/v2/orgs/${this.carbonBlackConfig.orgKey}/feeds/${this.feedId}`
      );
      this.feedExists = true;
    } catch (error) {
      if (error instanceof CarbonBlackApiError && error.statusCode === 404) {
        // Feed doesn't exist, create it
        await this.createFeed();
        this.feedExists = true;
      } else {
        throw error;
      }
    }
  }

  /**
   * Create a new threat intelligence feed.
   */
  private async createFeed(): Promise<void> {
    const feedInfo: CarbonBlackFeed = {
      id: this.feedId,
      name: 'BrowserDefense Browser Threat Feed',
      provider_url: 'https://browserdefense.com',
      summary: 'Threat intelligence from browser-based IOC blocking',
      category: 'Partner',
      access: 'private',
    };

    await this.apiRequest<FeedResponse>(
      'POST',
      `/threathunter/feedmgr/v2/orgs/${this.carbonBlackConfig.orgKey}/feeds`,
      { feedinfo: feedInfo }
    );
  }

  /**
   * Create or update a threat intelligence report.
   */
  private async createOrUpdateReport(report: CarbonBlackReport): Promise<ReportResponse> {
    return this.apiRequest<ReportResponse>(
      'POST',
      `/threathunter/feedmgr/v2/orgs/${this.carbonBlackConfig.orgKey}/feeds/${this.feedId}/reports`,
      report
    );
  }

  /**
   * Delete a threat intelligence report.
   * Used for unblock operations to remove IOCs from the feed.
   *
   * @param reportId - ID of the report to delete
   * @throws CarbonBlackApiError with 404 if report doesn't exist
   */
  private async deleteReport(reportId: string): Promise<void> {
    await this.apiRequest<void>(
      'DELETE',
      `/threathunter/feedmgr/v2/orgs/${this.carbonBlackConfig.orgKey}/feeds/${this.feedId}/reports/${reportId}`
    );
  }

  /**
   * Create a Carbon Black report from a forensics event.
   */
  private createReport(event: ForensicsEvent): CarbonBlackReport {
    const iocs = this.createIOCs(event);
    const timestamp = Math.floor(new Date(event.timestamp).getTime() / 1000);

    return {
      id: this.getReportId(event.eventId),
      title: `BrowserDefense: ${this.truncate(event.blockedUrl, 100)}`,
      description: this.createDescription(event),
      severity: this.defaultSeverity,
      link: event.blockedUrl,
      timestamp,
      iocs_v2: iocs,
      tags: [...this.defaultTags, event.matchType],
      visibility: 'org_only',
    };
  }

  /**
   * Create IOC entries from a forensics event.
   */
  private createIOCs(event: ForensicsEvent): CarbonBlackIOC[] {
    const iocs: CarbonBlackIOC[] = [];

    // Create IOC based on match type
    const iocField = this.getIOCField(event.matchType);
    const iocValue = this.getIOCValue(event);

    if (iocField && iocValue) {
      iocs.push({
        id: `ioc-${event.eventId}`,
        match_type: 'equality',
        field: iocField,
        values: [iocValue],
        link: event.blockedUrl,
      });
    }

    // Also add domain IOC if we have redirect chain
    if (event.redirectChain.length > 0) {
      const domains = this.extractDomains(event.redirectChain);
      if (domains.length > 0) {
        iocs.push({
          id: `ioc-${event.eventId}-chain`,
          match_type: 'equality',
          field: 'netconn_domain',
          values: domains,
        });
      }
    }

    return iocs;
  }

  /**
   * Map match type to Carbon Black IOC field.
   */
  private getIOCField(matchType: ForensicsEvent['matchType']): CarbonBlackIOCField | null {
    switch (matchType) {
      case 'domain':
        return 'netconn_domain';
      case 'url':
        return 'netconn_domain'; // CB doesn't have URL field, use domain
      case 'hash':
        return 'process_hash';
      default:
        return null;
    }
  }

  /**
   * Extract the IOC value from the event.
   */
  private getIOCValue(event: ForensicsEvent): string | null {
    switch (event.matchType) {
      case 'domain':
        return event.matchedIndicator;
      case 'url':
        // Extract domain from URL for Carbon Black
        try {
          const url = new URL(event.blockedUrl);
          return url.hostname;
        } catch {
          return event.matchedIndicator;
        }
      case 'hash':
        return event.matchedIndicator;
      default:
        return null;
    }
  }

  /**
   * Extract unique domains from URLs.
   */
  private extractDomains(urls: string[]): string[] {
    const domains = new Set<string>();

    for (const urlStr of urls) {
      try {
        const url = new URL(urlStr);
        domains.add(url.hostname);
      } catch {
        // Skip invalid URLs
      }
    }

    return Array.from(domains);
  }

  /**
   * Create a detailed description for the report.
   */
  private createDescription(event: ForensicsEvent): string {
    const parts = [
      `Browser blocked navigation to: ${event.blockedUrl}`,
      `Timestamp: ${event.timestamp}`,
      `Match Type: ${event.matchType}`,
      `Matched Indicator: ${event.matchedIndicator}`,
    ];

    if (event.tabContext.initiatorUrl) {
      parts.push(`Initiator: ${event.tabContext.initiatorUrl}`);
    }

    if (event.redirectChain.length > 0) {
      parts.push(`Redirect Chain: ${event.redirectChain.join(' -> ')}`);
    }

    if (event.userId) {
      parts.push(`User: ${event.userId}`);
    }

    if (event.deviceId) {
      parts.push(`Device: ${event.deviceId}`);
    }

    return parts.join('\n');
  }

  /**
   * Truncate a string to a maximum length.
   */
  private truncate(str: string, maxLength: number): string {
    if (str.length <= maxLength) {
      return str;
    }
    return str.substring(0, maxLength - 3) + '...';
  }

  /**
   * Check if an error is retryable.
   */
  private isRetryableError(error: unknown): boolean {
    if (error instanceof CarbonBlackApiError) {
      // Retry on server errors and rate limits
      return error.statusCode >= 500 || error.statusCode === 429;
    }
    // Retry on network errors
    return error instanceof TypeError && error.message.includes('fetch');
  }
}

// =============================================================================
// Error Types
// =============================================================================

/**
 * Carbon Black API error with status code information.
 */
export class CarbonBlackApiError extends Error {
  readonly statusCode: number;
  readonly responseBody: string;

  constructor(message: string, statusCode: number, responseBody: string) {
    super(message);
    this.name = 'CarbonBlackApiError';
    this.statusCode = statusCode;
    this.responseBody = responseBody;
  }
}

// =============================================================================
// Registry Registration
// =============================================================================

// Register the connector factory
connectorRegistry.register('carbonblack', (config) => {
  return new CarbonBlackConnector(config as CarbonBlackConnectorConfig);
});
