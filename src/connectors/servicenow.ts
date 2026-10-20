/**
 * BrowserDefense ServiceNow Security Operations Connector
 *
 * Creates security incidents in ServiceNow via the Table API.
 * Supports basic authentication and OAuth2.
 *
 * Unblock Support:
 * - Queries incidents by u_event_id field
 * - Updates incident state to Closed (7)
 * - Treats not-found as success (idempotent)
 */

import { BaseConnector, connectorRegistry } from './base';
import {
  ForensicsEvent,
  SendResult,
  ServiceNowConnectorConfig,
  UnblockResult,
} from './types';

// =============================================================================
// ServiceNow Security Incident Types
// =============================================================================

/**
 * ServiceNow security incident payload.
 * Maps BrowserDefense forensics events to ServiceNow's security incident schema.
 */
interface ServiceNowSecurityIncident {
  /** Brief description of the incident */
  short_description: string;
  /** Detailed description of the incident */
  description: string;
  /** Incident category */
  category: string;
  /** Incident subcategory */
  subcategory: string;
  /** Priority level (1=Critical, 2=High, 3=Medium, 4=Low) */
  priority: string;
  /** Assignment group for incident handling */
  assignment_group?: string;
  /** Source system identifier */
  u_source?: string;
  /** Blocked URL (custom field) */
  u_blocked_url?: string;
  /** Match type (custom field) */
  u_match_type?: string;
  /** Matched indicator (custom field) */
  u_matched_indicator?: string;
  /** Organization ID (custom field) */
  u_org_id?: string;
  /** Event ID for correlation (custom field) */
  u_event_id?: string;
  /** Additional custom fields */
  [key: string]: string | undefined;
}

/**
 * ServiceNow API response structure.
 */
interface ServiceNowResponse {
  result: {
    sys_id: string;
    number?: string;
    [key: string]: unknown;
  };
}

/**
 * OAuth2 token response from ServiceNow.
 */
interface OAuth2TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

// =============================================================================
// ServiceNow Connector Implementation
// =============================================================================

/**
 * ServiceNow Security Operations connector.
 *
 * Creates security incidents in ServiceNow when BrowserDefense blocks malicious URLs.
 * Supports both basic authentication and OAuth2 for enterprise deployments.
 *
 * Usage:
 * ```typescript
 * const connector = new ServiceNowConnector({
 *   name: 'servicenow-prod',
 *   enabled: true,
 *   type: 'servicenow',
 *   instance: 'acme',
 *   auth: { type: 'basic', username: 'admin', password: 'secret' },
 *   table: 'sn_si_incident',
 *   assignmentGroup: 'Security Operations',
 *   priority: '3',
 * });
 *
 * await connector.init();
 * await connector.send(event);
 * ```
 */
export class ServiceNowConnector extends BaseConnector {
  readonly type = 'servicenow' as const;

  /**
   * ServiceNow supports unblock via incident state update.
   * Incidents are closed when the IOC is unblocked.
   */
  readonly supportsUnblock = true;

  private readonly instanceUrl: string;
  private readonly table: string;
  private readonly assignmentGroup?: string;
  private readonly priority: string;
  private readonly customFields: Record<string, string>;
  private readonly authConfig: ServiceNowConnectorConfig['auth'];

  // OAuth2 token management
  private accessToken?: string;
  private tokenExpiresAt?: number;

  constructor(config: ServiceNowConnectorConfig) {
    super(config);

    this.instanceUrl = `https://${config.instance}.service-now.com`;
    this.table = config.table ?? 'sn_si_incident';
    this.assignmentGroup = config.assignmentGroup;
    this.priority = config.priority ?? '3';
    this.customFields = config.customFields ?? {};
    this.authConfig = config.auth;
  }

  // ===========================================================================
  // Abstract method implementations
  // ===========================================================================

  protected async doInit(): Promise<void> {
    // Validate configuration
    this.validateConfig();

    // For OAuth2, fetch initial token
    if (this.authConfig.type === 'oauth2') {
      await this.refreshOAuth2Token();
    }

    // Verify connectivity by checking table access
    await this.checkTableAccess();
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const incident = this.mapToSecurityIncident(event);

    try {
      const response = await this.createIncident(incident);

      return {
        success: true,
        eventId: event.eventId,
        response: {
          sysId: response.result.sys_id,
          incidentNumber: response.result.number,
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

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      await this.checkTableAccess();
      return { healthy: true, message: 'ServiceNow connection healthy' };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return { healthy: false, message: `ServiceNow health check failed: ${errorMessage}` };
    }
  }

  protected async doClose(): Promise<void> {
    // Clear OAuth2 token
    this.accessToken = undefined;
    this.tokenExpiresAt = undefined;
  }

  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    try {
      // Find the incident by event ID
      const incident = await this.findIncidentByEventId(event.eventId);

      if (!incident) {
        // No incident found - treat as success (already closed or never created)
        return {
          success: true,
          eventId: event.eventId,
          alreadyClosed: true,
        };
      }

      // Check if already closed
      const state = String(incident.state);
      if (state === '6' || state === '7') {
        // 6 = Resolved, 7 = Closed
        return {
          success: true,
          eventId: event.eventId,
          alreadyClosed: true,
          incidentId: incident.sys_id,
        };
      }

      // Close the incident
      await this.closeIncident(
        incident.sys_id,
        `IOC unblocked via BrowserDefense at ${new Date().toISOString()}`
      );

      return {
        success: true,
        eventId: event.eventId,
        incidentId: incident.sys_id,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Treat 404 as success (incident not found)
      if (errorMessage.includes('404')) {
        return {
          success: true,
          eventId: event.eventId,
          alreadyClosed: true,
        };
      }

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable: this.isRetryableError(error),
      };
    }
  }

  // ===========================================================================
  // ServiceNow-specific methods
  // ===========================================================================

  /**
   * Map a forensics event to ServiceNow security incident format.
   */
  private mapToSecurityIncident(event: ForensicsEvent): ServiceNowSecurityIncident {
    const redirectChainStr = event.redirectChain.length > 0
      ? event.redirectChain.join(' -> ')
      : 'None';

    const incident: ServiceNowSecurityIncident = {
      short_description: `BrowserDefense: Blocked ${event.matchType} - ${this.truncate(event.blockedUrl, 80)}`,
      description: this.formatDescription(event, redirectChainStr),
      category: 'Security',
      subcategory: this.getSubcategory(event.matchType),
      priority: this.priority,
      assignment_group: this.assignmentGroup,
      u_source: 'BrowserDefense',
      u_blocked_url: event.blockedUrl,
      u_match_type: event.matchType,
      u_matched_indicator: event.matchedIndicator,
      u_org_id: event.orgId,
      u_event_id: event.eventId,
    };

    // Add custom fields from configuration
    for (const [key, value] of Object.entries(this.customFields)) {
      incident[key] = this.interpolateField(value, event);
    }

    return incident;
  }

  /**
   * Format the incident description with event details.
   */
  private formatDescription(event: ForensicsEvent, redirectChainStr: string): string {
    const lines = [
      'Browser blocked navigation to malicious URL.',
      '',
      `URL: ${event.blockedUrl}`,
      `Time: ${event.timestamp}`,
      `Match Type: ${event.matchType}`,
      `Matched Indicator: ${event.matchedIndicator}`,
      `Redirect Chain: ${redirectChainStr}`,
      `Organization: ${event.orgId}`,
      `Event ID: ${event.eventId}`,
    ];

    if (event.userId) {
      lines.push(`User: ${event.userId}`);
    }

    if (event.deviceId) {
      lines.push(`Device: ${event.deviceId}`);
    }

    if (event.tabContext.initiatorUrl) {
      lines.push(`Initiator URL: ${event.tabContext.initiatorUrl}`);
    }

    if (event.tabContext.tabTitle) {
      lines.push(`Tab Title: ${event.tabContext.tabTitle}`);
    }

    return lines.join('\n');
  }

  /**
   * Get subcategory based on match type.
   */
  private getSubcategory(matchType: ForensicsEvent['matchType']): string {
    switch (matchType) {
      case 'domain':
        return 'Phishing';
      case 'url':
        return 'Malicious URL';
      case 'hash':
        return 'Malware';
      default:
        return 'Unknown';
    }
  }

  /**
   * Truncate a string to a maximum length.
   */
  private truncate(str: string, maxLength: number): string {
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength - 3) + '...';
  }

  /**
   * Interpolate event fields into a custom field value.
   * Supports placeholders like {blockedUrl}, {orgId}, etc.
   */
  private interpolateField(template: string, event: ForensicsEvent): string {
    return template.replace(/\{(\w+)\}/g, (_, key) => {
      if (key in event) {
        const value = event[key as keyof ForensicsEvent];
        if (typeof value === 'string') return value;
        if (typeof value === 'number') return String(value);
        if (Array.isArray(value)) return value.join(', ');
      }
      return `{${key}}`;
    });
  }

  /**
   * Create an incident in ServiceNow.
   */
  private async createIncident(incident: ServiceNowSecurityIncident): Promise<ServiceNowResponse> {
    const url = `${this.instanceUrl}/api/now/table/${this.table}`;
    const headers = await this.getAuthHeaders();

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...headers,
      },
      body: JSON.stringify(incident),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`ServiceNow API error: ${response.status} ${response.statusText} - ${errorBody}`);
    }

    return response.json() as Promise<ServiceNowResponse>;
  }

  /**
   * Find an incident by its BrowserDefense event ID.
   * Returns null if no incident is found.
   */
  private async findIncidentByEventId(eventId: string): Promise<{
    sys_id: string;
    state: string;
    number?: string;
  } | null> {
    // Query for incident with matching u_event_id
    const query = encodeURIComponent(`u_event_id=${eventId}`);
    const url = `${this.instanceUrl}/api/now/table/${this.table}?sysparm_query=${query}&sysparm_fields=sys_id,state,number&sysparm_limit=1`;
    const headers = await this.getAuthHeaders();

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        ...headers,
      },
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`ServiceNow query failed: ${response.status} ${response.statusText} - ${errorBody}`);
    }

    const data = await response.json() as { result: Array<{ sys_id: string; state: string; number?: string }> };

    if (!data.result || data.result.length === 0) {
      return null;
    }

    return data.result[0];
  }

  /**
   * Close an incident by sys_id.
   * Sets state to 7 (Closed) and adds close notes.
   */
  private async closeIncident(sysId: string, closeNotes: string): Promise<void> {
    const url = `${this.instanceUrl}/api/now/table/${this.table}/${sysId}`;
    const headers = await this.getAuthHeaders();

    const response = await fetch(url, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...headers,
      },
      body: JSON.stringify({
        state: '7', // Closed
        close_notes: closeNotes,
        close_code: 'Closed/Resolved by Caller', // Standard close code
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`ServiceNow update failed: ${response.status} ${response.statusText} - ${errorBody}`);
    }
  }

  /**
   * Check table access to verify connectivity.
   */
  private async checkTableAccess(): Promise<void> {
    const url = `${this.instanceUrl}/api/now/table/${this.table}?sysparm_limit=1`;
    const headers = await this.getAuthHeaders();

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        ...headers,
      },
    });

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        throw new Error(`Authentication failed for ServiceNow instance: ${response.status}`);
      }
      if (response.status === 404) {
        throw new Error(`Table '${this.table}' not found in ServiceNow instance`);
      }
      throw new Error(`ServiceNow connectivity check failed: ${response.status} ${response.statusText}`);
    }
  }

  /**
   * Get authentication headers based on auth configuration.
   */
  private async getAuthHeaders(): Promise<Record<string, string>> {
    if (this.authConfig.type === 'basic') {
      const { username, password } = this.authConfig;
      if (!username || !password) {
        throw new Error('Basic auth requires username and password');
      }
      const credentials = btoa(`${username}:${password}`);
      return { 'Authorization': `Basic ${credentials}` };
    }

    if (this.authConfig.type === 'oauth2') {
      const token = await this.getOAuth2Token();
      return { 'Authorization': `Bearer ${token}` };
    }

    throw new Error(`Unsupported auth type: ${this.authConfig.type}`);
  }

  /**
   * Get OAuth2 access token, refreshing if necessary.
   */
  private async getOAuth2Token(): Promise<string> {
    // Check if we have a valid token
    if (this.accessToken && this.tokenExpiresAt) {
      // Refresh if token expires in less than 5 minutes
      if (Date.now() < this.tokenExpiresAt - 5 * 60 * 1000) {
        return this.accessToken;
      }
    }

    await this.refreshOAuth2Token();
    return this.accessToken!;
  }

  /**
   * Refresh the OAuth2 access token.
   */
  private async refreshOAuth2Token(): Promise<void> {
    const oauth2Config = this.authConfig.oauth2;
    if (!oauth2Config) {
      throw new Error('OAuth2 configuration required for oauth2 auth type');
    }

    const tokenUrl = oauth2Config.tokenUrl || `${this.instanceUrl}/oauth_token.do`;

    const params = new URLSearchParams({
      grant_type: oauth2Config.grantType,
      client_id: oauth2Config.clientId,
      client_secret: oauth2Config.clientSecret,
    });

    if (oauth2Config.scopes && oauth2Config.scopes.length > 0) {
      params.set('scope', oauth2Config.scopes.join(' '));
    }

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`OAuth2 token request failed: ${response.status} ${response.statusText} - ${errorBody}`);
    }

    const tokenResponse = await response.json() as OAuth2TokenResponse;

    this.accessToken = tokenResponse.access_token;
    this.tokenExpiresAt = Date.now() + tokenResponse.expires_in * 1000;
  }

  /**
   * Validate connector configuration.
   */
  private validateConfig(): void {
    if (this.authConfig.type === 'basic') {
      if (!this.authConfig.username || !this.authConfig.password) {
        throw new Error('Basic auth requires username and password');
      }
    } else if (this.authConfig.type === 'oauth2') {
      if (!this.authConfig.oauth2) {
        throw new Error('OAuth2 auth requires oauth2 configuration');
      }
      if (!this.authConfig.oauth2.clientId || !this.authConfig.oauth2.clientSecret) {
        throw new Error('OAuth2 requires clientId and clientSecret');
      }
    } else {
      throw new Error(`Unsupported auth type: ${this.authConfig.type}`);
    }
  }

  /**
   * Determine if an error is retryable.
   */
  private isRetryableError(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      // Network errors and server errors (5xx) are retryable
      if (message.includes('network') || message.includes('fetch')) {
        return true;
      }
      // 5xx errors are retryable
      if (message.includes('500') || message.includes('502') ||
          message.includes('503') || message.includes('504')) {
        return true;
      }
      // Rate limiting is retryable
      if (message.includes('429')) {
        return true;
      }
      // Auth errors are not retryable (need config change)
      if (message.includes('401') || message.includes('403')) {
        return false;
      }
    }
    return false;
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Factory function for creating ServiceNow connectors.
 */
export function createServiceNowConnector(
  config: ServiceNowConnectorConfig
): ServiceNowConnector {
  return new ServiceNowConnector(config);
}

// Register the connector factory
connectorRegistry.register('servicenow', createServiceNowConnector);
