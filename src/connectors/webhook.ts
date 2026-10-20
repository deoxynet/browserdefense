/**
 * BrowserDefense Generic Webhook Connector
 *
 * A universal connector for sending forensics events to any HTTP endpoint.
 * Supports custom headers, multiple auth methods, and Handlebars templates.
 *
 * Use cases:
 * - Custom SIEM/SOAR integrations
 * - Internal security tools
 * - Slack/Teams/PagerDuty alerting
 * - Ticketing systems (Jira, ServiceNow)
 * - Data lakes (Snowflake, Databricks)
 */

import { BaseConnector, connectorRegistry } from './base';
import {
  ForensicsEvent,
  SendResult,
  UnblockResult,
  WebhookConnectorConfig,
  WebhookAuth,
  OAuth2Config,
} from './types';

// =============================================================================
// Template Engine (Handlebars-like)
// =============================================================================

/**
 * Simple Handlebars-like template engine for transforming events.
 * Supports:
 * - {{variable}} - simple replacement
 * - {{nested.path}} - dot notation for nested objects
 * - Arrays are JSON-stringified
 */
export function renderTemplate(template: string, event: ForensicsEvent): string {
  return template.replace(/\{\{([^}]+)\}\}/g, (match, path: string) => {
    const trimmedPath = path.trim();
    const value = getNestedValue(event, trimmedPath);

    if (value === undefined || value === null) {
      return '';
    }

    if (typeof value === 'object') {
      return JSON.stringify(value);
    }

    return String(value);
  });
}

/**
 * Get a nested value from an object using dot notation.
 */
function getNestedValue(obj: Record<string, unknown> | object, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined) {
      return undefined;
    }
    if (typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

// =============================================================================
// OAuth2 Token Management
// =============================================================================

interface OAuth2Token {
  accessToken: string;
  expiresAt: number;
}

/**
 * OAuth2 token cache for connectors using OAuth2 authentication.
 */
const tokenCache = new Map<string, OAuth2Token>();

/**
 * Fetch an OAuth2 access token using client credentials grant.
 */
async function fetchOAuth2Token(config: OAuth2Config): Promise<string> {
  const cacheKey = `${config.tokenUrl}:${config.clientId}`;
  const cached = tokenCache.get(cacheKey);

  // Return cached token if still valid (with 60s buffer)
  if (cached && cached.expiresAt > Date.now() + 60000) {
    return cached.accessToken;
  }

  const body = new URLSearchParams();
  body.append('grant_type', config.grantType);
  body.append('client_id', config.clientId);
  body.append('client_secret', config.clientSecret);

  if (config.scopes && config.scopes.length > 0) {
    body.append('scope', config.scopes.join(' '));
  }

  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OAuth2 token fetch failed: ${response.status} ${errorText}`);
  }

  const data = await response.json() as {
    access_token: string;
    expires_in?: number;
    token_type?: string;
  };

  const expiresIn = data.expires_in || 3600; // Default 1 hour
  const token: OAuth2Token = {
    accessToken: data.access_token,
    expiresAt: Date.now() + expiresIn * 1000,
  };

  tokenCache.set(cacheKey, token);
  return token.accessToken;
}

// =============================================================================
// Webhook Connector Implementation
// =============================================================================

/**
 * HTTP status codes that indicate a retryable error.
 */
const RETRYABLE_STATUS_CODES = new Set([
  408, // Request Timeout
  429, // Too Many Requests
  500, // Internal Server Error
  502, // Bad Gateway
  503, // Service Unavailable
  504, // Gateway Timeout
]);

/**
 * Generic webhook connector for sending forensics events to any HTTP endpoint.
 *
 * Features:
 * - Multiple authentication methods (Basic, Bearer, API Key, OAuth2)
 * - Custom headers
 * - Handlebars-like templates for payload transformation
 * - Retry with exponential backoff (inherited from BaseConnector)
 * - Health checks via OPTIONS/GET
 */
export class WebhookConnector extends BaseConnector {
  readonly type = 'webhook' as const;
  readonly supportsUnblock = true;

  private readonly webhookConfig: WebhookConnectorConfig;
  private lastHealthCheck: { healthy: boolean; message: string } | null = null;

  constructor(config: WebhookConnectorConfig) {
    super(config);
    this.webhookConfig = config;
  }

  // ===========================================================================
  // BaseConnector Abstract Method Implementations
  // ===========================================================================

  protected async doInit(): Promise<void> {
    // Validate configuration
    if (!this.webhookConfig.url) {
      throw new Error('Webhook URL is required');
    }

    // Validate URL format
    try {
      new URL(this.webhookConfig.url);
    } catch {
      throw new Error(`Invalid webhook URL: ${this.webhookConfig.url}`);
    }

    // Validate auth configuration if provided
    if (this.webhookConfig.auth) {
      this.validateAuthConfig(this.webhookConfig.auth);
    }

    // Perform initial health check
    const health = await this.doHealth();
    if (!health.healthy) {
      console.warn(`[WebhookConnector] Initial health check failed: ${health.message}`);
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    try {
      // Build request body
      const body = this.buildRequestBody(event);

      // Build headers
      const headers = await this.buildHeaders();

      // Send request
      const response = await fetch(this.webhookConfig.url, {
        method: this.webhookConfig.method,
        headers,
        body,
      });

      // Check response status
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

      // Handle error response
      const errorBody = await response.text().catch(() => '(unable to read body)');
      const isRetryable = RETRYABLE_STATUS_CODES.has(response.status);

      return {
        success: false,
        eventId: event.eventId,
        error: `HTTP ${response.status}: ${response.statusText}. Body: ${errorBody}`,
        retryable: isRetryable,
        response: {
          status: response.status,
          statusText: response.statusText,
          body: errorBody,
        },
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Network errors are generally retryable
      const isNetworkError =
        errorMessage.includes('fetch') ||
        errorMessage.includes('network') ||
        errorMessage.includes('ECONNREFUSED') ||
        errorMessage.includes('ETIMEDOUT');

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable: isNetworkError,
      };
    }
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      // Try OPTIONS first (most webhook endpoints support this)
      const response = await fetch(this.webhookConfig.url, {
        method: 'OPTIONS',
      });

      // Some servers return 405 for OPTIONS, try HEAD
      if (response.status === 405) {
        const headResponse = await fetch(this.webhookConfig.url, {
          method: 'HEAD',
        });

        // HEAD might also return 405, consider endpoint reachable
        if (headResponse.status === 405 || headResponse.ok) {
          this.lastHealthCheck = { healthy: true, message: 'Endpoint reachable' };
          return this.lastHealthCheck;
        }
      }

      if (response.ok || response.status < 500) {
        this.lastHealthCheck = { healthy: true, message: 'Endpoint healthy' };
        return this.lastHealthCheck;
      }

      this.lastHealthCheck = {
        healthy: false,
        message: `Endpoint returned ${response.status}: ${response.statusText}`,
      };
      return this.lastHealthCheck;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.lastHealthCheck = { healthy: false, message: `Health check failed: ${errorMessage}` };
      return this.lastHealthCheck;
    }
  }

  protected async doClose(): Promise<void> {
    // Clear any cached OAuth2 tokens for this connector
    if (this.webhookConfig.auth?.oauth2) {
      const cacheKey = `${this.webhookConfig.auth.oauth2.tokenUrl}:${this.webhookConfig.auth.oauth2.clientId}`;
      tokenCache.delete(cacheKey);
    }
  }

  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    // Webhook connector handles unblock by sending the event with action='unblock'
    // Templates can use {{action}} to customize the payload for unblock events
    const sendResult = await this.doSend(event);

    if (sendResult.success) {
      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: false,
      };
    }

    return {
      success: false,
      eventId: event.eventId,
      error: sendResult.error,
      retryable: sendResult.retryable,
    };
  }

  // ===========================================================================
  // Private Helper Methods
  // ===========================================================================

  /**
   * Validate authentication configuration.
   */
  private validateAuthConfig(auth: WebhookAuth): void {
    switch (auth.type) {
      case 'bearer':
        if (!auth.token) {
          throw new Error('Bearer auth requires a token');
        }
        break;

      case 'basic':
        if (!auth.username || !auth.password) {
          throw new Error('Basic auth requires username and password');
        }
        break;

      case 'api-key':
        if (!auth.apiKeyHeader || !auth.apiKey) {
          throw new Error('API key auth requires apiKeyHeader and apiKey');
        }
        break;

      case 'oauth2':
        if (!auth.oauth2) {
          throw new Error('OAuth2 auth requires oauth2 configuration');
        }
        if (!auth.oauth2.tokenUrl || !auth.oauth2.clientId || !auth.oauth2.clientSecret) {
          throw new Error('OAuth2 auth requires tokenUrl, clientId, and clientSecret');
        }
        break;
    }
  }

  /**
   * Build request body from event, optionally using a template.
   */
  private buildRequestBody(event: ForensicsEvent): string {
    if (this.webhookConfig.template) {
      return renderTemplate(this.webhookConfig.template, event);
    }

    // Default: send event as JSON
    return JSON.stringify(event);
  }

  /**
   * Build request headers including authentication.
   */
  private async buildHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'BrowserDefense/1.0 WebhookConnector',
    };

    // Add custom headers
    if (this.webhookConfig.headers) {
      Object.assign(headers, this.webhookConfig.headers);
    }

    // Add authentication header
    if (this.webhookConfig.auth) {
      const authHeader = await this.buildAuthHeader(this.webhookConfig.auth);
      Object.assign(headers, authHeader);
    }

    return headers;
  }

  /**
   * Build authentication header based on auth type.
   */
  private async buildAuthHeader(auth: WebhookAuth): Promise<Record<string, string>> {
    switch (auth.type) {
      case 'bearer':
        return { Authorization: `Bearer ${auth.token}` };

      case 'basic': {
        const credentials = btoa(`${auth.username}:${auth.password}`);
        return { Authorization: `Basic ${credentials}` };
      }

      case 'api-key':
        return { [auth.apiKeyHeader!]: auth.apiKey! };

      case 'oauth2': {
        const token = await fetchOAuth2Token(auth.oauth2!);
        return { Authorization: `Bearer ${token}` };
      }

      default:
        return {};
    }
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Create a WebhookConnector instance from configuration.
 */
export function createWebhookConnector(config: WebhookConnectorConfig): WebhookConnector {
  return new WebhookConnector(config);
}

// Register with the global connector registry
connectorRegistry.register('webhook', createWebhookConnector);
