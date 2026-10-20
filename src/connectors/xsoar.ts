/**
 * BrowserDefense Palo Alto Cortex XSOAR Connector
 *
 * Sends forensics events to Cortex XSOAR (formerly Demisto) as incidents.
 * Supports API key authentication and optional playbook triggering.
 *
 * @see https://xsoar.pan.dev/docs/reference/api/create-incident
 */

import { BaseConnector, connectorRegistry } from './base';
import {
  ForensicsEvent,
  SendResult,
  UnblockResult,
  XsoarConnectorConfig,
} from './types';

// =============================================================================
// XSOAR API Types
// =============================================================================

/**
 * XSOAR incident structure for API calls.
 */
interface XsoarIncident {
  name: string;
  type: string;
  severity: number;
  createInvestigation?: boolean;
  playbookId?: string;
  CustomFields?: Record<string, unknown>;
  details?: string;
  labels?: Array<{ type: string; value: string }>;
}

/**
 * XSOAR API response for incident creation.
 */
interface XsoarIncidentResponse {
  id: string;
  name: string;
  status: number;
  created: string;
  investigationId?: string;
}

/**
 * XSOAR health check response.
 */
interface XsoarHealthResponse {
  status: string;
  version?: string;
}

/**
 * XSOAR incident search request.
 */
interface XsoarIncidentSearchRequest {
  filter: {
    query: string;
    size?: number;
  };
}

/**
 * XSOAR incident search response.
 */
interface XsoarIncidentSearchResponse {
  data: XsoarIncidentSearchResult[];
  total: number;
}

/**
 * XSOAR incident from search results.
 */
interface XsoarIncidentSearchResult {
  id: string;
  name: string;
  status: number;
  closeReason?: string;
  closingUserId?: string;
  CustomFields?: Record<string, unknown>;
}

/**
 * XSOAR incident update request.
 */
interface XsoarIncidentUpdateRequest {
  id: string;
  status?: number;
  closeReason?: string;
  closeNotes?: string;
}

/**
 * XSOAR entry (comment/note) request.
 */
interface XsoarEntryRequest {
  investigationId: string;
  data: string;
  markdown?: boolean;
}

/**
 * XSOAR incident status codes.
 * 0 = Pending, 1 = Active, 2 = Done, 3 = Archive
 */
const XSOAR_STATUS = {
  PENDING: 0,
  ACTIVE: 1,
  DONE: 2,
  ARCHIVE: 3,
} as const;

// =============================================================================
// Severity Mapping
// =============================================================================

/**
 * Map match types to XSOAR severity levels.
 * XSOAR uses: 0 = Unknown, 1 = Informational, 2 = Low, 3 = Medium, 4 = High
 */
function getSeverityFromMatchType(matchType: ForensicsEvent['matchType']): number {
  switch (matchType) {
    case 'hash':
      return 4; // High - file hash matches are typically high-confidence
    case 'url':
      return 3; // Medium - exact URL matches
    case 'domain':
      return 2; // Low - domain-level matches may have false positives
    default:
      return 2;
  }
}

// =============================================================================
// XSOAR Connector Implementation
// =============================================================================

/**
 * Connector for Palo Alto Cortex XSOAR (Demisto).
 *
 * Creates security incidents from BrowserDefense forensics events, enabling
 * automated response through XSOAR playbooks.
 *
 * Authentication uses XSOAR API key in the Authorization header.
 *
 * @example
 * ```typescript
 * const connector = new XsoarConnector({
 *   name: 'Production XSOAR',
 *   enabled: true,
 *   type: 'xsoar',
 *   serverUrl: 'https://xsoar.company.com',
 *   apiKey: 'your-api-key',
 *   incidentType: 'BrowserDefense Alert',
 *   playbookId: 'BrowserDefense_Response',
 * });
 *
 * await connector.init();
 * await connector.send(forensicsEvent);
 * ```
 */
export class XsoarConnector extends BaseConnector {
  readonly type = 'xsoar' as const;

  private readonly serverUrl: string;
  private readonly apiKey: string;
  private readonly incidentType: string;
  private readonly playbookId?: string;
  private readonly tlsVerify: boolean;

  constructor(config: XsoarConnectorConfig) {
    super(config);

    // Normalize server URL (remove trailing slash)
    this.serverUrl = config.serverUrl.replace(/\/$/, '');
    this.apiKey = config.apiKey;
    this.incidentType = config.incidentType || 'BrowserDefense Alert';
    this.playbookId = config.playbookId;
    this.tlsVerify = config.tls?.verify ?? true;
  }

  // ===========================================================================
  // Abstract Method Implementations
  // ===========================================================================

  /**
   * Initialize the connector.
   * Validates the API key by making a test request.
   */
  protected async doInit(): Promise<void> {
    // Validate configuration
    if (!this.serverUrl) {
      throw new Error('XSOAR serverUrl is required');
    }
    if (!this.apiKey) {
      throw new Error('XSOAR apiKey is required');
    }

    // Test connection by checking server health
    const healthResult = await this.doHealth();
    if (!healthResult.healthy) {
      throw new Error(`XSOAR health check failed: ${healthResult.message}`);
    }
  }

  /**
   * Send a forensics event to XSOAR as an incident.
   */
  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const incident = this.buildIncident(event);

    try {
      const response = await this.makeRequest<XsoarIncidentResponse>(
        '/incident',
        'POST',
        incident
      );

      return {
        success: true,
        eventId: event.eventId,
        response: {
          incidentId: response.id,
          investigationId: response.investigationId,
        },
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Determine if error is retryable
      const retryable = this.isRetryableError(error);

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable,
      };
    }
  }

  /**
   * Check XSOAR server health.
   */
  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      // Use the health endpoint or fall back to a simple API call
      const response = await this.makeRequest<XsoarHealthResponse>(
        '/health',
        'GET'
      );

      return {
        healthy: response.status === 'ok' || response.status === 'healthy',
        message: `XSOAR version: ${response.version || 'unknown'}`,
      };
    } catch (error) {
      // Try alternate endpoint for older XSOAR versions
      try {
        await this.makeRequest('/user', 'GET');
        return {
          healthy: true,
          message: 'XSOAR server accessible (health endpoint unavailable)',
        };
      } catch {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return {
          healthy: false,
          message: `XSOAR health check failed: ${errorMessage}`,
        };
      }
    }
  }

  /**
   * Close the connector (no persistent connections to clean up).
   */
  protected async doClose(): Promise<void> {
    // No persistent resources to clean up
  }

  // ===========================================================================
  // Unblock Support
  // ===========================================================================

  /**
   * Unblock an IOC by closing/resolving the associated incident.
   *
   * Finds the incident by eventId (stored in CustomFields.eventid),
   * updates its status to Done/Closed, and adds an unblock note.
   * Handles already-closed incidents idempotently.
   *
   * @param event - Forensics event with action='unblock'
   * @returns Result indicating success, whether already closed, etc.
   *
   * @example
   * ```typescript
   * const result = await connector.unblock({ eventId: 'event-abc-456', ... });
   * if (result.success) {
   *   console.log(`Incident ${result.incidentId} closed`);
   * }
   * ```
   */
  async unblock(event: ForensicsEvent): Promise<UnblockResult> {
    this.ensureInitialized();

    const eventId = event.eventId;
    const reason = (event.raw?.unblockReason as string) || undefined;

    try {
      // Search for incident by eventId
      const incident = await this.findIncidentByEventId(eventId);

      if (!incident) {
        return {
          success: false,
          eventId,
          error: `No incident found for eventId: ${eventId}`,
          retryable: false,
        };
      }

      // Check if already closed (idempotent handling)
      if (incident.status === XSOAR_STATUS.DONE || incident.status === XSOAR_STATUS.ARCHIVE) {
        return {
          success: true,
          eventId,
          alreadyClosed: true,
          incidentId: incident.id,
        };
      }

      // Close the incident
      await this.closeIncident(incident.id, reason);

      // Add unblock entry/note to the investigation
      await this.addUnblockEntry(incident.id, eventId, reason);

      return {
        success: true,
        eventId,
        incidentId: incident.id,
        alreadyClosed: false,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const retryable = this.isRetryableError(error);

      return {
        success: false,
        eventId,
        error: errorMessage,
        retryable,
      };
    }
  }

  /**
   * Find an incident by its associated eventId.
   */
  private async findIncidentByEventId(eventId: string): Promise<XsoarIncidentSearchResult | null> {
    const searchRequest: XsoarIncidentSearchRequest = {
      filter: {
        query: `CustomFields.eventid:"${eventId}"`,
        size: 1,
      },
    };

    const response = await this.makeRequest<XsoarIncidentSearchResponse>(
      '/incidents/search',
      'POST',
      searchRequest
    );

    if (response.data && response.data.length > 0) {
      return response.data[0];
    }

    return null;
  }

  /**
   * Close an incident with a reason.
   */
  private async closeIncident(incidentId: string, reason?: string): Promise<void> {
    const updateRequest: XsoarIncidentUpdateRequest = {
      id: incidentId,
      status: XSOAR_STATUS.DONE,
      closeReason: 'Resolved',
      closeNotes: reason || 'IOC unblocked via BlockIOC',
    };

    await this.makeRequest('/incident', 'POST', updateRequest);
  }

  /**
   * Add an unblock entry/note to the incident investigation.
   */
  private async addUnblockEntry(incidentId: string, eventId: string, reason?: string): Promise<void> {
    const entryContent = this.buildUnblockEntryContent(eventId, reason);

    const entryRequest: XsoarEntryRequest = {
      investigationId: incidentId,
      data: entryContent,
      markdown: true,
    };

    try {
      await this.makeRequest('/entry', 'POST', entryRequest);
    } catch (error) {
      // Entry creation is best-effort - don't fail the unblock if entry fails
      console.warn(`Failed to add unblock entry for incident ${incidentId}:`, error);
    }
  }

  /**
   * Build markdown content for the unblock entry.
   */
  private buildUnblockEntryContent(eventId: string, reason?: string): string {
    const lines = [
      `## IOC Unblocked`,
      ``,
      `**Event ID:** ${eventId}`,
      `**Unblocked At:** ${new Date().toISOString()}`,
    ];

    if (reason) {
      lines.push(`**Reason:** ${reason}`);
    }

    lines.push(``, `This IOC has been removed from the blocklist.`);

    return lines.join('\n');
  }

  // ===========================================================================
  // Private Helper Methods
  // ===========================================================================

  /**
   * Build an XSOAR incident from a forensics event.
   */
  private buildIncident(event: ForensicsEvent): XsoarIncident {
    const severity = getSeverityFromMatchType(event.matchType);

    const incident: XsoarIncident = {
      name: `BrowserDefense Alert: ${this.truncateUrl(event.blockedUrl, 100)}`,
      type: this.incidentType,
      severity,
      createInvestigation: true,
      details: this.buildIncidentDetails(event),
      labels: [
        { type: 'source', value: 'BrowserDefense' },
        { type: 'matchType', value: event.matchType },
        { type: 'orgId', value: event.orgId },
      ],
      CustomFields: {
        blockedurl: event.blockedUrl,
        matchedindicator: event.matchedIndicator,
        matchtype: event.matchType,
        redirectchain: event.redirectChain.join(' -> '),
        timestamp: event.timestamp,
        orgid: event.orgId,
        eventid: event.eventId,
        // Tab context
        initiatorurl: event.tabContext.initiatorUrl,
        tabtitle: event.tabContext.tabTitle,
        incognito: event.tabContext.incognito,
        // Optional fields
        userid: event.userId,
        deviceid: event.deviceId,
      },
    };

    // Add playbook if configured
    if (this.playbookId) {
      incident.playbookId = this.playbookId;
    }

    return incident;
  }

  /**
   * Build detailed incident description.
   */
  private buildIncidentDetails(event: ForensicsEvent): string {
    const lines = [
      `## BrowserDefense Alert`,
      ``,
      `**Blocked URL:** ${event.blockedUrl}`,
      `**Match Type:** ${event.matchType}`,
      `**Matched Indicator:** ${event.matchedIndicator}`,
      `**Timestamp:** ${event.timestamp}`,
      ``,
      `### Redirect Chain`,
      event.redirectChain.length > 0
        ? event.redirectChain.map((url, i) => `${i + 1}. ${url}`).join('\n')
        : 'No redirects detected',
      ``,
      `### Tab Context`,
      `- **Initiator URL:** ${event.tabContext.initiatorUrl || 'Unknown'}`,
      `- **Tab Title:** ${event.tabContext.tabTitle || 'Unknown'}`,
      `- **Incognito:** ${event.tabContext.incognito ? 'Yes' : 'No'}`,
      ``,
      `### Identifiers`,
      `- **Organization ID:** ${event.orgId}`,
      `- **Event ID:** ${event.eventId}`,
      event.userId ? `- **User ID:** ${event.userId}` : '',
      event.deviceId ? `- **Device ID:** ${event.deviceId}` : '',
    ];

    return lines.filter(Boolean).join('\n');
  }

  /**
   * Make an HTTP request to the XSOAR API.
   */
  private async makeRequest<T>(
    path: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    body?: unknown
  ): Promise<T> {
    const url = `${this.serverUrl}${path}`;

    const headers: Record<string, string> = {
      'Authorization': this.apiKey,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
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
      const errorBody = await response.text();
      throw new XsoarApiError(
        `XSOAR API error: ${response.status} ${response.statusText}`,
        response.status,
        errorBody
      );
    }

    // Handle empty responses
    const text = await response.text();
    if (!text) {
      return {} as T;
    }

    return JSON.parse(text) as T;
  }

  /**
   * Determine if an error is retryable.
   */
  private isRetryableError(error: unknown): boolean {
    if (error instanceof XsoarApiError) {
      // Retry on server errors and rate limiting
      return error.statusCode >= 500 || error.statusCode === 429;
    }
    // Retry on network errors
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return true;
    }
    return false;
  }

  /**
   * Truncate URL for display purposes.
   */
  private truncateUrl(url: string, maxLength: number): string {
    if (url.length <= maxLength) {
      return url;
    }
    return url.substring(0, maxLength - 3) + '...';
  }
}

// =============================================================================
// Error Classes
// =============================================================================

/**
 * Error class for XSOAR API errors.
 */
export class XsoarApiError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly responseBody: string
  ) {
    super(message);
    this.name = 'XsoarApiError';
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Factory function for creating XSOAR connectors.
 */
export function createXsoarConnector(config: XsoarConnectorConfig): XsoarConnector {
  return new XsoarConnector(config);
}

// Register with the connector registry
connectorRegistry.register('xsoar', createXsoarConnector);
