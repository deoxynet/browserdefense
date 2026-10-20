/**
 * BlockIOC HarfangLab Connector
 *
 * Creates or removes IOC rules in HarfangLab Threat Intelligence.
 */

import { BaseConnector, connectorRegistry } from './base';
import type { ForensicsEvent, HarfangLabConnectorConfig, SendResult } from './types';

// =============================================================================
// Types
// =============================================================================

type HarfangLabAction = 'block' | 'unblock';

interface HarfangLabIocRule {
  source_id: string;
  type: string;
  value: string;
  block_on_agent: boolean;
  quarantine_on_agent: boolean;
  endpoint_detection: boolean;
  enabled: boolean;
  description?: string;
}

interface HarfangLabSearchResponse {
  results?: Array<{ id: string }>;
}

// =============================================================================
// Connector Implementation
// =============================================================================

export class HarfangLabConnector extends BaseConnector {
  readonly type = 'harfanglab' as const;

  private readonly apiUrl: string;
  private readonly apiToken: string;
  private readonly sourceId: string;
  private readonly action: HarfangLabAction;
  private readonly blockOnAgent: boolean;
  private readonly quarantineOnAgent: boolean;
  private readonly detectOnAgent: boolean;
  private readonly descriptionPrefix: string;

  constructor(config: HarfangLabConnectorConfig) {
    super(config);

    this.apiUrl = config.apiUrl.replace(/\/+$/, '');
    this.apiToken = config.apiToken;
    this.sourceId = config.sourceId;
    this.action = config.action ?? 'block';
    this.blockOnAgent = config.blockOnAgent ?? true;
    this.quarantineOnAgent = config.quarantineOnAgent ?? false;
    this.detectOnAgent = config.detectOnAgent ?? true;
    this.descriptionPrefix = config.descriptionPrefix ?? 'BlockIOC';
  }

  protected async doInit(): Promise<void> {
    if (!this.apiUrl) {
      throw new Error('HarfangLab apiUrl is required');
    }
    if (!this.apiToken) {
      throw new Error('HarfangLab apiToken is required');
    }
    if (!this.sourceId) {
      throw new Error('HarfangLab sourceId is required');
    }

    const health = await this.doHealth();
    if (!health.healthy) {
      throw new Error(`HarfangLab health check failed: ${health.message}`);
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    try {
      const indicator = this.getIndicatorValue(event);
      const indicatorType = this.mapIndicatorType(event);

      if (this.action === 'block') {
        const payload = this.buildIocRule(event, indicator, indicatorType);
        const response = await this.createIndicator(payload);

        if (!response.ok) {
          const text = await response.text();
          return {
            success: false,
            eventId: event.eventId,
            error: `HarfangLab create IOC failed (${response.status}): ${text}`,
            retryable: response.status >= 500 || response.status === 429,
          };
        }

        return {
          success: true,
          eventId: event.eventId,
          response: (await response.json()) as Record<string, unknown>,
        };
      }

      const ids = await this.findIndicatorIds(indicator);
      if (ids.length === 0) {
        return {
          success: true,
          eventId: event.eventId,
          response: { removed: 0 },
        };
      }

      for (const id of ids) {
        await this.deleteIndicator(id);
      }

      return {
        success: true,
        eventId: event.eventId,
        response: { removed: ids.length },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const retryable = message.includes('fetch') || /\b(429|5\d{2})\b/.test(message);

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
      const response = await fetch(`${this.apiUrl}/api/data/threat_intelligence/IOCRule/`, {
        method: 'GET',
        headers: this.buildHeaders(),
      });

      return {
        healthy: response.ok,
        message: response.ok ? 'ok' : `status ${response.status}`,
      };
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

  // ==========================================================================
  // Internal helpers
  // ==========================================================================

  private buildHeaders(): Record<string, string> {
    return {
      'Authorization': `Token ${this.apiToken}`,
      'Content-Type': 'application/json',
    };
  }

  private getIndicatorValue(event: ForensicsEvent): string {
    const indicator = event.matchedIndicator || event.blockedUrl;
    if (!indicator) {
      throw new Error('No indicator value found in event');
    }
    return indicator;
  }

  private mapIndicatorType(event: ForensicsEvent): string {
    switch (event.matchType) {
      case 'domain':
        return 'domain_name';
      case 'url':
        return 'url';
      case 'hash':
        return 'hash';
      default:
        return 'url';
    }
  }

  private buildIocRule(event: ForensicsEvent, value: string, type: string): HarfangLabIocRule {
    return {
      source_id: this.sourceId,
      type,
      value,
      block_on_agent: this.blockOnAgent,
      quarantine_on_agent: this.quarantineOnAgent,
      endpoint_detection: this.detectOnAgent,
      enabled: true,
      description: `${this.descriptionPrefix} event ${event.eventId}`,
    };
  }

  private async createIndicator(payload: HarfangLabIocRule): Promise<Response> {
    return fetch(`${this.apiUrl}/api/data/threat_intelligence/IOCRule/`, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify(payload),
    });
  }

  private async findIndicatorIds(value: string): Promise<string[]> {
    const url = new URL(`${this.apiUrl}/api/data/threat_intelligence/IOCRule/`);
    url.searchParams.set('search', value);
    url.searchParams.set('source_id', this.sourceId);

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: this.buildHeaders(),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`HarfangLab search failed (${response.status}): ${text}`);
    }

    const data = (await response.json()) as HarfangLabSearchResponse;
    return (data.results ?? []).map((item) => item.id);
  }

  private async deleteIndicator(id: string): Promise<void> {
    const response = await fetch(`${this.apiUrl}/api/data/threat_intelligence/IOCRule/${id}`, {
      method: 'DELETE',
      headers: this.buildHeaders(),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`HarfangLab delete failed (${response.status}): ${text}`);
    }
  }
}

export function createHarfangLabConnector(config: HarfangLabConnectorConfig): HarfangLabConnector {
  return new HarfangLabConnector(config);
}

connectorRegistry.register('harfanglab', createHarfangLabConnector);
