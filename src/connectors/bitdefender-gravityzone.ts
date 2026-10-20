/**
 * BlockIOC Bitdefender GravityZone Connector
 *
 * Pushes hash/path/connection blocks into Bitdefender GravityZone blocklists.
 * Uses the JSON-RPC API for add/remove blocklist entries.
 */

import { randomUUID } from 'crypto';
import { BaseConnector, connectorRegistry } from './base';
import type {
  BitdefenderGravityZoneConnectorConfig,
  ForensicsEvent,
  SendResult,
} from './types';

// =============================================================================
// Constants
// =============================================================================

const JSONRPC_VERSION = '2.0';
const DEFAULT_PAGE_SIZE = 100;
const BLOCKLIST_API = '/api/v1.2/jsonrpc/incidents';

// =============================================================================
// Types
// =============================================================================

type BlockType = 'hash' | 'path' | 'connection';

type BlockAction = 'block' | 'unblock';

interface JsonRpcRequest {
  jsonrpc: string;
  method: string;
  params: Record<string, unknown>;
  id: string;
}

interface BlockListItem {
  type: string;
  id: string;
  details: Record<string, unknown>;
}

interface BlockListResponse {
  total?: number;
  page?: number;
  perPage?: number;
  pagesCount?: number;
  items?: BlockListItem[];
}

// =============================================================================
// Connector Implementation
// =============================================================================

export class BitdefenderGravityZoneConnector extends BaseConnector {
  readonly type = 'bitdefender-gravityzone' as const;

  private readonly apiUrl: string;
  private readonly apiKey: string;
  private readonly blockType: BlockType;
  private readonly action: BlockAction;
  private readonly hashAlgorithm?: string;
  private readonly ruleNamePrefix: string;
  private readonly connectionDefaults?: BitdefenderGravityZoneConnectorConfig['connectionDefaults'];

  constructor(config: BitdefenderGravityZoneConnectorConfig) {
    super(config);

    this.apiUrl = config.apiUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.blockType = config.blockType ?? 'hash';
    this.action = config.action ?? 'block';
    this.hashAlgorithm = config.hashAlgorithm;
    this.ruleNamePrefix = config.ruleNamePrefix ?? 'blockioc-';
    this.connectionDefaults = config.connectionDefaults;
  }

  protected async doInit(): Promise<void> {
    if (!this.apiUrl) {
      throw new Error('Bitdefender GravityZone API URL is required');
    }
    if (!this.apiKey) {
      throw new Error('Bitdefender GravityZone API key is required');
    }

    const health = await this.doHealth();
    if (!health.healthy) {
      throw new Error(`Bitdefender GravityZone health check failed: ${health.message}`);
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    try {
      if (this.action === 'block') {
        const payload = this.buildBlockPayload(event);
        const response = await this.sendJsonRpc('addToBlocklist', payload);

        return {
          success: true,
          eventId: event.eventId,
          response: response as Record<string, unknown>,
        };
      }

      const ids = await this.findBlockIds(event);
      if (ids.length === 0) {
        return {
          success: true,
          eventId: event.eventId,
          response: { removed: 0 },
        };
      }

      const response = await this.sendJsonRpc('removeFromBlocklist', { ids });
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
      await this.sendJsonRpc('getBlocklistItems', { page: 1, perPage: 1 });
      return { healthy: true, message: 'ok' };
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

  private buildBlockPayload(event: ForensicsEvent): Record<string, unknown> {
    const indicator = event.matchedIndicator || event.blockedUrl;
    if (!indicator) {
      throw new Error('No indicator value found in event');
    }

    if (this.blockType === 'hash') {
      if (event.matchType !== 'hash') {
        throw new Error('Bitdefender hash block requires matchType=hash');
      }

      const algorithm = this.hashAlgorithm ?? this.detectHashAlgorithm(indicator);
      if (!algorithm) {
        throw new Error('Unable to determine hash algorithm for indicator');
      }

      return {
        type: 'hash',
        rules: [
          {
            details: {
              algorithm,
              hash: indicator,
            },
          },
        ],
      };
    }

    if (this.blockType === 'path') {
      return {
        type: 'path',
        rules: [
          {
            details: {
              path: indicator,
            },
          },
        ],
      };
    }

    return {
      type: 'connection',
      rules: [
        {
          details: this.buildConnectionDetails(indicator, event),
        },
      ],
    };
  }

  private buildConnectionDetails(indicator: string, event: ForensicsEvent): Record<string, unknown> {
    const defaults = this.connectionDefaults ?? {};
    const details: Record<string, unknown> = {
      ruleName: `${this.ruleNamePrefix}${event.eventId}`,
      commandLine: defaults.commandLine ?? null,
      protocol: defaults.protocol ?? 'any',
      direction: defaults.direction ?? 'both',
      ipVersion: defaults.ipVersion ?? 'any',
      localAddress: defaults.localAddress ?? { any: true },
      remoteAddress: defaults.remoteAddress ?? { any: true },
      directlyConnected: defaults.directlyConnected ?? { enable: false },
    };

    if (this.isIpAddress(indicator)) {
      const remoteAddress = { ...(details.remoteAddress as Record<string, unknown>) };
      if (remoteAddress.any !== false) {
        remoteAddress.any = false;
      }
      remoteAddress.ipMask = this.formatIpMask(indicator);
      details.remoteAddress = remoteAddress;
    }

    return details;
  }

  private detectHashAlgorithm(hash: string): string | null {
    const normalized = hash.replace(/[^a-fA-F0-9]/g, '');
    if (normalized.length === 32) {
      return 'md5';
    }
    if (normalized.length === 40) {
      return 'sha1';
    }
    if (normalized.length === 64) {
      return 'sha256';
    }
    return null;
  }

  private formatIpMask(ip: string): string {
    if (ip.includes(':')) {
      return `${ip}/128`;
    }
    return `${ip}/32`;
  }

  private isIpAddress(value: string): boolean {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(':');
  }

  private async findBlockIds(event: ForensicsEvent): Promise<string[]> {
    const indicator = event.matchedIndicator || event.blockedUrl;
    if (!indicator) {
      return [];
    }

    const ids: string[] = [];
    let page = 1;
    let pages = 1;

    while (page <= pages) {
      const result = await this.sendJsonRpc('getBlocklistItems', {
        page,
        perPage: DEFAULT_PAGE_SIZE,
      });

      const response = (result as { result?: BlockListResponse }).result;
      const items = response?.items ?? [];

      for (const item of items) {
        if (item.type !== this.blockType) {
          continue;
        }
        if (this.matchesIndicator(item, indicator)) {
          ids.push(item.id);
        }
      }

      pages = response?.pagesCount ?? 1;
      page += 1;
    }

    return ids;
  }

  private matchesIndicator(item: BlockListItem, indicator: string): boolean {
    const details = item.details ?? {};

    if (item.type === 'hash') {
      const hash = String(details.hash ?? '').toLowerCase();
      return hash === indicator.toLowerCase();
    }

    if (item.type === 'path') {
      return String(details.path ?? '') === indicator;
    }

    if (item.type === 'connection') {
      const remoteAddress = details.remoteAddress as Record<string, unknown> | undefined;
      const localAddress = details.localAddress as Record<string, unknown> | undefined;
      const remoteMask = remoteAddress?.ipMask ? String(remoteAddress.ipMask) : '';
      const localMask = localAddress?.ipMask ? String(localAddress.ipMask) : '';
      return remoteMask.includes(indicator) || localMask.includes(indicator);
    }

    return false;
  }

  private async sendJsonRpc(method: string, params: Record<string, unknown>): Promise<unknown> {
    const request: JsonRpcRequest = {
      jsonrpc: JSONRPC_VERSION,
      method,
      params,
      id: randomUUID(),
    };

    const response = await fetch(`${this.apiUrl}${BLOCKLIST_API}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${Buffer.from(`${this.apiKey}:`).toString('base64')}`,
      },
      body: JSON.stringify(request),
    });

    const bodyText = await response.text();
    if (!response.ok) {
      throw new Error(`Bitdefender GravityZone request failed (${response.status}): ${bodyText}`);
    }

    const body = bodyText ? JSON.parse(bodyText) : {};
    if (body.error) {
      const message = body.error.message ?? 'Unknown error';
      throw new Error(`Bitdefender GravityZone API error: ${message}`);
    }

    return body;
  }
}

export function createBitdefenderGravityZoneConnector(
  config: BitdefenderGravityZoneConnectorConfig
): BitdefenderGravityZoneConnector {
  return new BitdefenderGravityZoneConnector(config);
}

connectorRegistry.register('bitdefender-gravityzone', createBitdefenderGravityZoneConnector);
