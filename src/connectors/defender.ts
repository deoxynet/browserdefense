/**
 * Microsoft Defender for Endpoint Connector
 *
 * Sends forensics events to MS Defender via the Security Center API.
 * Creates custom indicators from block events for endpoint correlation.
 *
 * Features:
 * - Azure AD authentication (OAuth2 client credentials flow)
 * - Custom Indicator submission (URLs, domains)
 * - Token caching with automatic refresh
 * - Health check via permissions validation
 *
 * Unblock Support:
 * - Queries indicators by type and value
 * - Deletes matching indicators via API
 * - Treats not-found as success (idempotent)
 */

import { BaseConnector, connectorRegistry } from './base';
import {
  DefenderConnectorConfig,
  ForensicsEvent,
  SendResult,
  UnblockResult,
} from './types';

// =============================================================================
// Constants
// =============================================================================

/** Microsoft login endpoint for OAuth2 token requests */
const AZURE_LOGIN_URL = 'https://login.microsoftonline.com';

/** Microsoft Defender for Endpoint API base URL */
const DEFENDER_API_URL = 'https://api.securitycenter.microsoft.com';

/** OAuth2 scope for Defender API access */
const DEFENDER_SCOPE = 'https://api.securitycenter.microsoft.com/.default';

/** Token refresh buffer - refresh 5 minutes before expiry */
const TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000;

/** Default indicator expiration time in hours (30 days) */
const DEFAULT_INDICATOR_EXPIRATION_HOURS = 30 * 24;

// =============================================================================
// Types
// =============================================================================

/**
 * Azure AD OAuth2 token response.
 */
interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  ext_expires_in?: number;
}

/**
 * Cached token with expiration tracking.
 */
interface CachedToken {
  accessToken: string;
  expiresAt: number;
}

/**
 * Defender indicator types supported by the API.
 */
type IndicatorType = 'Url' | 'DomainName' | 'IpAddress' | 'FileSha1' | 'FileSha256';

/**
 * Indicator action types.
 */
type IndicatorAction = 'Alert' | 'AlertAndBlock' | 'Allowed';

/**
 * Indicator submission mode.
 */
type IndicatorMode = 'block' | 'unblock';

/**
 * Indicator severity levels.
 */
type IndicatorSeverity = 'Informational' | 'Low' | 'Medium' | 'High';

/**
 * Defender custom indicator payload.
 */
interface DefenderIndicator {
  indicatorValue: string;
  indicatorType: IndicatorType;
  action: IndicatorAction;
  title: string;
  description: string;
  severity: IndicatorSeverity;
  recommendedActions?: string;
  expirationTime?: string;
  generateAlert: boolean;
}

/**
 * Defender API error response.
 */
interface DefenderApiError {
  error: {
    code: string;
    message: string;
  };
}

/**
 * Extended configuration with runtime options.
 */
interface DefenderRuntimeConfig extends DefenderConnectorConfig {
  /** Indicator action (default: Alert) */
  action?: IndicatorAction;
  /** Indicator mode (default: block) */
  mode?: IndicatorMode;
  /** Indicator severity (default: Medium) */
  severity?: IndicatorSeverity;
  /** Generate alerts for indicators (default: true) */
  generateAlert?: boolean;
  /** Indicator expiration in hours (default: 720 = 30 days) */
  expirationHours?: number;
}

// =============================================================================
// Defender Connector Implementation
// =============================================================================

/**
 * Microsoft Defender for Endpoint connector.
 *
 * Integrates with the Defender Security Center API to:
 * - Submit blocked URLs/domains as custom indicators
 * - Correlate browser block events with endpoint telemetry
 * - Enable SOC investigation of blocked threats
 *
 * @example
 * ```typescript
 * const connector = new DefenderConnector({
 *   type: 'defender',
 *   name: 'production-defender',
 *   enabled: true,
 *   tenantId: process.env.AZURE_TENANT_ID!,
 *   clientId: process.env.AZURE_CLIENT_ID!,
 *   clientSecret: process.env.AZURE_CLIENT_SECRET!,
 * });
 *
 * await connector.init();
 * await connector.send(forensicsEvent);
 * ```
 */
export class DefenderConnector extends BaseConnector {
  readonly type = 'defender' as const;

  /**
   * Defender supports unblock via indicator deletion.
   * Indicators are queried by type/value and deleted via API.
   */
  readonly supportsUnblock = true;

  private readonly tenantId: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly certificatePath?: string;
  private readonly indicatorAction: IndicatorAction;
  private readonly indicatorMode: IndicatorMode;
  private readonly indicatorSeverity: IndicatorSeverity;
  private readonly generateAlert: boolean;
  private readonly expirationHours: number;

  private cachedToken: CachedToken | null = null;

  constructor(config: DefenderRuntimeConfig) {
    super(config);
    this.tenantId = config.tenantId;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.certificatePath = config.certificatePath;
    this.indicatorAction = config.action ?? 'Alert';
    this.indicatorMode = config.mode ?? 'block';
    this.indicatorSeverity = config.severity ?? 'Medium';
    this.generateAlert = config.generateAlert ?? true;
    this.expirationHours = config.expirationHours ?? DEFAULT_INDICATOR_EXPIRATION_HOURS;
  }

  // ===========================================================================
  // Abstract method implementations
  // ===========================================================================

  /**
   * Initialize the connector by validating credentials.
   * Performs a token fetch to ensure Azure AD credentials are valid.
   */
  protected async doInit(): Promise<void> {
    // Validate required configuration
    if (!this.tenantId) {
      throw new Error('DefenderConnector: tenantId is required');
    }
    if (!this.clientId) {
      throw new Error('DefenderConnector: clientId is required');
    }
    if (!this.clientSecret && !this.certificatePath) {
      throw new Error('DefenderConnector: clientSecret or certificatePath is required');
    }

    // Validate credentials by fetching a token
    try {
      await this.getAccessToken();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`DefenderConnector: Failed to authenticate with Azure AD: ${message}`);
    }
  }

  /**
   * Send a forensics event to Defender as a custom indicator.
   */
  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    try {
      const token = await this.getAccessToken();
      if (this.indicatorMode === 'unblock') {
        const { indicatorType, indicatorValue } = this.getIndicatorTypeAndValue(event);
        const ids = await this.findIndicatorIds(token, indicatorType, indicatorValue);

        for (const id of ids) {
          await this.deleteIndicator(token, id);
        }

        return {
          success: true,
          eventId: event.eventId,
          response: { removed: ids.length },
        };
      }

      const indicator = this.buildIndicator(event);

      const response = await fetch(
        `${DEFENDER_API_URL}/api/indicators`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(indicator),
        }
      );

      if (response.ok) {
        const data = await response.json() as { id?: string };
        return {
          success: true,
          eventId: event.eventId,
          response: { indicatorId: data.id },
        };
      }

      // Handle error responses
      const errorBody = await this.parseErrorResponse(response);
      const isRetryable = this.isRetryableError(response.status, errorBody);

      return {
        success: false,
        eventId: event.eventId,
        error: `Defender API error: ${response.status} - ${errorBody?.error?.message ?? response.statusText}`,
        retryable: isRetryable,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        eventId: event.eventId,
        error: `Failed to send to Defender: ${message}`,
        retryable: true,
      };
    }
  }

  /**
   * Check Defender API health by validating token and permissions.
   */
  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      const token = await this.getAccessToken();

      // Test API access by listing indicators (limited to 1)
      const response = await fetch(
        `${DEFENDER_API_URL}/api/indicators?$top=1`,
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      );

      if (response.ok) {
        return {
          healthy: true,
          message: 'Connected to Microsoft Defender API',
        };
      }

      // Check for permission issues
      if (response.status === 403) {
        return {
          healthy: false,
          message: 'Insufficient permissions. Ensure Ti.ReadWrite permission is granted.',
        };
      }

      return {
        healthy: false,
        message: `Defender API returned ${response.status}: ${response.statusText}`,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        healthy: false,
        message: `Health check failed: ${message}`,
      };
    }
  }

  /**
   * Clean up connector resources.
   */
  protected async doClose(): Promise<void> {
    // Clear cached token
    this.cachedToken = null;
  }

  /**
   * Delete indicators matching the event from Defender.
   * Queries indicators by type and value, then deletes each match.
   */
  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    try {
      const token = await this.getAccessToken();
      const { indicatorType, indicatorValue } = this.getIndicatorTypeAndValue(event);

      // Find matching indicators
      const ids = await this.findIndicatorIds(token, indicatorType, indicatorValue);

      if (ids.length === 0) {
        // No indicators found - treat as success (already deleted or never created)
        return {
          success: true,
          eventId: event.eventId,
          alreadyClosed: true,
        };
      }

      // Delete all matching indicators
      const errors: string[] = [];
      for (const id of ids) {
        try {
          await this.deleteIndicator(token, id);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          // 404 means already deleted - not an error
          if (!message.includes('404')) {
            errors.push(`${id}: ${message}`);
          }
        }
      }

      if (errors.length > 0) {
        return {
          success: false,
          eventId: event.eventId,
          error: `Failed to delete some indicators: ${errors.join('; ')}`,
          retryable: true,
        };
      }

      return {
        success: true,
        eventId: event.eventId,
        incidentId: ids.join(','),
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      // Treat 404 as success (indicator not found)
      if (message.includes('404')) {
        return {
          success: true,
          eventId: event.eventId,
          alreadyClosed: true,
        };
      }

      return {
        success: false,
        eventId: event.eventId,
        error: `Failed to unblock from Defender: ${message}`,
        retryable: this.isRetryableUnblockError(message),
      };
    }
  }

  // ===========================================================================
  // Private helpers
  // ===========================================================================

  /**
   * Get a valid access token, fetching a new one if needed.
   * Implements token caching with automatic refresh.
   */
  private async getAccessToken(): Promise<string> {
    // Check if we have a valid cached token
    if (this.cachedToken) {
      const now = Date.now();
      if (this.cachedToken.expiresAt > now + TOKEN_REFRESH_BUFFER_MS) {
        return this.cachedToken.accessToken;
      }
    }

    // Fetch new token
    const tokenUrl = `${AZURE_LOGIN_URL}/${this.tenantId}/oauth2/v2.0/token`;

    const params = new URLSearchParams({
      client_id: this.clientId,
      client_secret: this.clientSecret,
      scope: DEFENDER_SCOPE,
      grant_type: 'client_credentials',
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token request failed: ${response.status} - ${errorText}`);
    }

    const tokenResponse: TokenResponse = await response.json();

    // Cache the token with expiration time
    this.cachedToken = {
      accessToken: tokenResponse.access_token,
      expiresAt: Date.now() + (tokenResponse.expires_in * 1000),
    };

    return this.cachedToken.accessToken;
  }

  /**
   * Build a Defender indicator from a forensics event.
   */
  private buildIndicator(event: ForensicsEvent): DefenderIndicator {
    const { indicatorType, indicatorValue } = this.getIndicatorTypeAndValue(event);

    // Calculate expiration time
    const expirationTime = new Date(
      Date.now() + this.expirationHours * 60 * 60 * 1000
    ).toISOString();

    return {
      indicatorValue,
      indicatorType,
      action: this.indicatorAction,
      title: 'BrowserDefense - Blocked Navigation',
      description: this.buildDescription(event),
      severity: this.indicatorSeverity,
      recommendedActions: 'Investigate user activity and endpoint. Check for additional IOC matches.',
      expirationTime,
      generateAlert: this.generateAlert,
    };
  }

  /**
   * Determine the appropriate indicator type based on the event.
   */
  private determineIndicatorType(event: ForensicsEvent): IndicatorType {
    const candidate = event.matchedIndicator || event.blockedUrl;
    if (candidate && this.isIpAddress(candidate)) {
      return 'IpAddress';
    }

    switch (event.matchType) {
      case 'domain':
        return 'DomainName';
      case 'url':
        return 'Url';
      case 'hash': {
        // Determine hash type from length
        const hashLength = event.matchedIndicator.length;
        if (hashLength === 40) return 'FileSha1';
        if (hashLength === 64) return 'FileSha256';
        return 'Url'; // Fallback to URL
      }
      default:
        return 'Url';
    }
  }

  /**
   * Extract the indicator value from the event.
   */
  private extractIndicatorValue(event: ForensicsEvent, indicatorType: IndicatorType): string {
    switch (indicatorType) {
      case 'DomainName':
        // Extract domain from URL
        try {
          const url = new URL(event.blockedUrl);
          return url.hostname;
        } catch {
          return event.matchedIndicator;
        }
      case 'Url':
        return event.blockedUrl;
      case 'IpAddress': {
        const candidate = event.matchedIndicator || event.blockedUrl;
        return this.extractIpAddress(candidate);
      }
      case 'FileSha1':
      case 'FileSha256':
        return event.matchedIndicator;
      default:
        return event.blockedUrl;
    }
  }

  /**
   * Build a description for the indicator.
   */
  private buildDescription(event: ForensicsEvent): string {
    const parts = [
      `Browser blocked navigation to malicious ${event.matchType} at ${event.timestamp}.`,
    ];

    if (event.userId) {
      parts.push(`User: ${event.userId}`);
    }

    if (event.deviceId) {
      parts.push(`Device: ${event.deviceId}`);
    }

    if (event.redirectChain.length > 0) {
      parts.push(`Redirect chain: ${event.redirectChain.length} hops`);
    }

    parts.push(`Event ID: ${event.eventId}`);
    parts.push(`Org: ${event.orgId}`);

    return parts.join(' | ');
  }

  /**
   * Resolve indicator type and value from the event.
   */
  private getIndicatorTypeAndValue(event: ForensicsEvent): {
    indicatorType: IndicatorType;
    indicatorValue: string;
  } {
    const indicatorType = this.determineIndicatorType(event);
    const indicatorValue = this.extractIndicatorValue(event, indicatorType);

    if (!indicatorValue) {
      throw new Error('DefenderConnector: Missing indicator value for event');
    }

    return { indicatorType, indicatorValue };
  }

  /**
   * Fetch matching indicator IDs for unblock mode.
   */
  private async findIndicatorIds(
    token: string,
    indicatorType: IndicatorType,
    indicatorValue: string
  ): Promise<string[]> {
    const filter = this.buildFilter(indicatorType, indicatorValue);
    const url = `${DEFENDER_API_URL}/api/indicators?${filter}`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`DefenderConnector: Indicator lookup failed: ${response.status} - ${errorText}`);
    }

    const data = await response.json() as { value?: Array<{ id?: string }> };
    return (data.value ?? [])
      .map((item) => item.id)
      .filter((id): id is string => Boolean(id));
  }

  private async deleteIndicator(token: string, indicatorId: string): Promise<void> {
    const response = await fetch(`${DEFENDER_API_URL}/api/indicators/${indicatorId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`DefenderConnector: Indicator delete failed: ${response.status} - ${errorText}`);
    }
  }

  private buildFilter(indicatorType: IndicatorType, indicatorValue: string): string {
    const escapedValue = indicatorValue.replace(/'/g, "''");
    const escapedType = indicatorType.replace(/'/g, "''");
    return `$filter=${encodeURIComponent(`indicatorType eq '${escapedType}' and indicatorValue eq '${escapedValue}'`)}`;
  }

  private isIpAddress(value: string): boolean {
    const candidate = this.extractHostname(value);
    return /^(\\d{1,3}\\.){3}\\d{1,3}$/.test(candidate) ||
      (candidate.includes(':') && /^[0-9a-fA-F:]+$/.test(candidate));
  }

  private extractIpAddress(candidate: string): string {
    const hostname = this.extractHostname(candidate);
    return hostname || candidate;
  }

  private extractHostname(candidate: string): string {
    try {
      const url = new URL(candidate);
      return url.hostname;
    } catch {
      return candidate;
    }
  }

  /**
   * Parse error response from Defender API.
   */
  private async parseErrorResponse(response: Response): Promise<DefenderApiError | null> {
    try {
      const text = await response.text();
      return JSON.parse(text) as DefenderApiError;
    } catch {
      return null;
    }
  }

  /**
   * Determine if an error is retryable.
   */
  private isRetryableError(status: number, error: DefenderApiError | null): boolean {
    // Rate limiting
    if (status === 429) return true;

    // Server errors
    if (status >= 500) return true;

    // Specific Defender error codes that are retryable
    const retryableCodes = [
      'TooManyRequests',
      'ServiceUnavailable',
      'GatewayTimeout',
    ];

    if (error?.error?.code && retryableCodes.includes(error.error.code)) {
      return true;
    }

    // Authentication errors are retryable (token may have expired)
    if (status === 401) {
      // Clear cached token to force refresh
      this.cachedToken = null;
      return true;
    }

    // Client errors are generally not retryable
    if (status >= 400 && status < 500) return false;

    return true;
  }

  /**
   * Determine if an unblock error is retryable based on error message.
   */
  private isRetryableUnblockError(message: string): boolean {
    const lowerMessage = message.toLowerCase();

    // Network/connection errors
    if (lowerMessage.includes('network') || lowerMessage.includes('fetch')) {
      return true;
    }

    // Rate limiting
    if (lowerMessage.includes('429') || lowerMessage.includes('too many')) {
      return true;
    }

    // Server errors
    if (lowerMessage.includes('500') || lowerMessage.includes('502') ||
        lowerMessage.includes('503') || lowerMessage.includes('504')) {
      return true;
    }

    // Auth errors - token might need refresh
    if (lowerMessage.includes('401') || lowerMessage.includes('unauthorized')) {
      this.cachedToken = null;
      return true;
    }

    // Permission/forbidden errors are not retryable
    if (lowerMessage.includes('403') || lowerMessage.includes('forbidden')) {
      return false;
    }

    return false;
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Create a DefenderConnector instance from configuration.
 */
export function createDefenderConnector(config: DefenderConnectorConfig): DefenderConnector {
  return new DefenderConnector(config as DefenderRuntimeConfig);
}

// Register with the global connector registry
connectorRegistry.register('defender', createDefenderConnector);
