/**
 * BlockIOC Zscaler Connector
 *
 * Pushes blocked indicators to Zscaler Internet Access (ZIA) URL blacklist.
 * Supports both block and unblock operations via the blacklistUrls endpoint.
 */

import { BaseConnector, connectorRegistry } from './base';
import type { ForensicsEvent, SendResult, ZscalerConnectorConfig } from './types';

// =============================================================================
// Constants
// =============================================================================

const DEFAULT_SESSION_TTL_MS = 5 * 60 * 1000;

// =============================================================================
// Types
// =============================================================================

type ZscalerAction = 'block' | 'unblock';

type ZscalerListAction = 'ADD_TO_LIST' | 'REMOVE_FROM_LIST';

interface ZscalerAuthPayload {
  apiKey: string;
  username: string;
  password: string;
  timestamp: number;
}

// =============================================================================
// Zscaler Connector Implementation
// =============================================================================

export class ZscalerConnector extends BaseConnector {
  readonly type = 'zscaler' as const;

  private readonly baseUrl: string;
  private readonly username: string;
  private readonly password: string;
  private readonly apiKey: string;
  private readonly action: ZscalerAction;
  private readonly activateChanges: boolean;

  private sessionCookie: string | null = null;
  private sessionExpiresAt = 0;

  constructor(config: ZscalerConnectorConfig) {
    super(config);

    this.baseUrl = this.resolveBaseUrl(config);
    this.username = config.username;
    this.password = config.password;
    this.apiKey = config.apiKey;
    this.action = config.action ?? 'block';
    this.activateChanges = config.activateChanges ?? false;
  }

  // ==========================================================================
  // BaseConnector Abstract Method Implementations
  // ==========================================================================

  protected async doInit(): Promise<void> {
    if (!this.baseUrl) {
      throw new Error('Zscaler base URL or cloudName is required');
    }
    if (!this.username) {
      throw new Error('Zscaler username is required');
    }
    if (!this.password) {
      throw new Error('Zscaler password is required');
    }
    if (!this.apiKey) {
      throw new Error('Zscaler apiKey is required');
    }

    await this.ensureSession();

    const health = await this.doHealth();
    if (!health.healthy) {
      throw new Error(`Zscaler health check failed: ${health.message}`);
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    let indicator: string;

    try {
      indicator = this.extractIndicator(event);
    } catch (error) {
      return {
        success: false,
        eventId: event.eventId,
        error: error instanceof Error ? error.message : String(error),
        retryable: false,
      };
    }

    try {
      const listAction = this.action === 'block' ? 'ADD_TO_LIST' : 'REMOVE_FROM_LIST';
      const response = await this.updateBlacklist([indicator], listAction);

      if (this.activateChanges) {
        await this.postActivateChanges();
      }

      return {
        success: true,
        eventId: event.eventId,
        response: response as Record<string, unknown>,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const retryable = /\b(429|5\d{2})\b/.test(message) || message.includes('fetch');

      return {
        success: false,
        eventId: event.eventId,
        error: message,
        retryable,
      };
    }
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      const response = await this.makeRequest('/security/advanced', 'GET');
      return { healthy: response.ok, message: response.ok ? 'ok' : `status ${response.status}` };
    } catch (error) {
      return {
        healthy: false,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  protected async doClose(): Promise<void> {
    this.sessionCookie = null;
    this.sessionExpiresAt = 0;
  }

  // ==========================================================================
  // Internal helpers
  // ==========================================================================

  private resolveBaseUrl(config: ZscalerConnectorConfig): string {
    if (config.baseUrl) {
      return config.baseUrl.replace(/\/+$/, '');
    }
    if (config.cloudName) {
      return `https://zsapi.${config.cloudName}/api/v1`;
    }
    return '';
  }

  private extractIndicator(event: ForensicsEvent): string {
    if (event.matchType === 'hash') {
      throw new Error('Zscaler does not support hash indicators');
    }

    const indicator = event.matchedIndicator || event.blockedUrl;
    if (!indicator) {
      throw new Error('No indicator value found in event');
    }

    return indicator;
  }

  private async ensureSession(): Promise<void> {
    if (this.sessionCookie && Date.now() < this.sessionExpiresAt) {
      return;
    }

    const { timestamp, key } = this.obfuscateApiKey(this.apiKey);
    const payload: ZscalerAuthPayload = {
      apiKey: key,
      username: this.username,
      password: this.password,
      timestamp,
    };

    const response = await fetch(`${this.baseUrl}/authenticatedSession`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Zscaler authentication failed (${response.status}): ${text}`);
    }

    const setCookie = response.headers.get('set-cookie') ?? '';
    const match = /JSESSIONID=([^;]+)/.exec(setCookie);
    if (!match) {
      throw new Error('Zscaler authentication failed: missing session cookie');
    }

    this.sessionCookie = `JSESSIONID=${match[1]}`;
    this.sessionExpiresAt = Date.now() + DEFAULT_SESSION_TTL_MS;
  }

  private async updateBlacklist(indicators: string[], action: ZscalerListAction): Promise<unknown> {
    const response = await this.makeRequest('/security/advanced/blacklistUrls', 'POST', {
      blacklistUrls: indicators,
    }, { action });

    const body = await response.text();
    if (!response.ok) {
      throw new Error(`Zscaler blacklist update failed (${response.status}): ${body}`);
    }

    return body ? JSON.parse(body) : {};
  }

  private async postActivateChanges(): Promise<void> {
    const response = await this.makeRequest('/status/activate', 'POST');
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Zscaler activate changes failed (${response.status}): ${text}`);
    }
  }

  private async makeRequest(
    path: string,
    method: string,
    body?: Record<string, unknown>,
    params?: Record<string, string>
  ): Promise<Response> {
    await this.ensureSession();

    const url = new URL(`${this.baseUrl}${path}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
      }
    }

    return fetch(url.toString(), {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Cookie': this.sessionCookie ?? '',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  private obfuscateApiKey(apiKey: string): { timestamp: number; key: string } {
    const timestamp = Date.now();
    const n = String(timestamp).slice(-6);
    const r = String(Number(n) >> 1).padStart(6, '0');

    let key = '';
    for (const digit of n) {
      key += apiKey[Number(digit)];
    }
    for (const digit of r) {
      key += apiKey[Number(digit) + 2];
    }

    return { timestamp, key };
  }
}

export function createZscalerConnector(config: ZscalerConnectorConfig): ZscalerConnector {
  return new ZscalerConnector(config);
}

connectorRegistry.register('zscaler', createZscalerConnector);
