/**
 * BlockIOC Palo Alto Cortex XDR Connector
 *
 * Adds hash indicators to the Cortex XDR hash blocklist.
 */

import { BaseConnector, connectorRegistry } from './base';
import type { CortexXdrConnectorConfig, ForensicsEvent, SendResult } from './types';

// =============================================================================
// Types
// =============================================================================

type CortexXdrAction = 'block' | 'unblock';

interface CortexXdrResponse {
  reply?: {
    err_code?: number;
    err_msg?: string;
    err_extra?: string;
  };
}

// =============================================================================
// Connector Implementation
// =============================================================================

export class CortexXdrConnector extends BaseConnector {
  readonly type = 'cortexxdr' as const;

  private readonly fqdn: string;
  private readonly apiKey: string;
  private readonly apiKeyId: string;
  private readonly incidentId: number;
  private readonly action: CortexXdrAction;
  private readonly commentPrefix: string;

  constructor(config: CortexXdrConnectorConfig) {
    super(config);

    this.fqdn = this.formatFqdn(config.fqdn);
    this.apiKey = config.apiKey;
    this.apiKeyId = config.apiKeyId;
    this.incidentId = config.incidentId;
    this.action = config.action ?? 'block';
    this.commentPrefix = config.commentPrefix ?? 'BlockIOC';
  }

  protected async doInit(): Promise<void> {
    if (!this.fqdn) {
      throw new Error('Cortex XDR fqdn is required');
    }
    if (!this.apiKey) {
      throw new Error('Cortex XDR apiKey is required');
    }
    if (!this.apiKeyId) {
      throw new Error('Cortex XDR apiKeyId is required');
    }
    if (!Number.isFinite(this.incidentId)) {
      throw new Error('Cortex XDR incidentId is required');
    }

    const health = await this.doHealth();
    if (!health.healthy) {
      throw new Error(`Cortex XDR health check failed: ${health.message}`);
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    if (this.action !== 'block') {
      return {
        success: false,
        eventId: event.eventId,
        error: 'Cortex XDR connector only supports block actions',
        retryable: false,
      };
    }

    if (event.matchType !== 'hash') {
      return {
        success: false,
        eventId: event.eventId,
        error: 'Cortex XDR hash block requires matchType=hash',
        retryable: false,
      };
    }

    const indicator = event.matchedIndicator || event.blockedUrl;
    if (!indicator) {
      return {
        success: false,
        eventId: event.eventId,
        error: 'No hash indicator value found in event',
        retryable: false,
      };
    }

    const payload = {
      request_data: {
        hash_list: [indicator],
        comment: `${this.commentPrefix} event ${event.eventId}`,
        incident_id: this.incidentId,
      },
    };

    try {
      const response = await fetch(`${this.fqdn}/public_api/v1/hash_exceptions/blocklist`, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: JSON.stringify(payload),
      });

      const data = (await response.json()) as CortexXdrResponse;
      const errorMessage = this.extractError(data);
      if (!response.ok || errorMessage) {
        return {
          success: false,
          eventId: event.eventId,
          error: errorMessage ?? `Cortex XDR request failed (${response.status})`,
          retryable: response.status >= 500 || response.status === 429,
        };
      }

      return {
        success: true,
        eventId: event.eventId,
        response: data as Record<string, unknown>,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        eventId: event.eventId,
        error: message,
        retryable: message.includes('fetch') || /\b(429|5\d{2})\b/.test(message),
      };
    }
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      const response = await fetch(`${this.fqdn}/public_api/v1/health`, {
        method: 'GET',
        headers: this.buildHeaders(),
      });

      if (response.ok) {
        return { healthy: true, message: 'ok' };
      }

      return { healthy: false, message: `status ${response.status}` };
    } catch (error) {
      return {
        healthy: false,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  protected async doClose(): Promise<void> {
    return;
  }

  private buildHeaders(): Record<string, string> {
    return {
      'x-xdr-auth-id': this.apiKeyId,
      'Authorization': this.apiKey,
      'Content-Type': 'application/json',
    };
  }

  private extractError(response: CortexXdrResponse): string | null {
    const reply = response.reply;
    if (!reply || !reply.err_code) {
      return null;
    }

    const extra = reply.err_extra ? ` ${reply.err_extra}` : '';
    return `Cortex XDR error ${reply.err_code}: ${reply.err_msg ?? 'Unknown'}${extra}`;
  }

  private formatFqdn(fqdn: string): string {
    const trimmed = fqdn.replace(/\/+$/, '');

    if (trimmed.startsWith('https://')) {
      return trimmed;
    }

    if (trimmed.startsWith('api-')) {
      return `https://${trimmed}`;
    }

    return `https://api-${trimmed}`;
  }
}

export function createCortexXdrConnector(config: CortexXdrConnectorConfig): CortexXdrConnector {
  return new CortexXdrConnector(config);
}

connectorRegistry.register('cortexxdr', createCortexXdrConnector);
