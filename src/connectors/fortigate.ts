/**
 * BlockIOC Fortigate Connector
 *
 * Creates or removes firewall address objects and optionally updates an address group.
 */

import { BaseConnector, connectorRegistry } from './base';
import type { ForensicsEvent, FortigateConnectorConfig, SendResult } from './types';

// =============================================================================
// Types
// =============================================================================

type FortigateAction = 'block' | 'unblock';

type AddressType = 'ip' | 'fqdn' | 'auto';

interface FortigateAddressGroup {
  results?: Array<{ member?: Array<{ name: string }> }>;
}

// =============================================================================
// Connector Implementation
// =============================================================================

export class FortigateConnector extends BaseConnector {
  readonly type = 'fortigate' as const;

  private readonly firewalls: FortigateConnectorConfig['firewalls'];
  private readonly addressGroup?: string;
  private readonly addressType: AddressType;
  private readonly action: FortigateAction;
  private readonly addressNamePrefix: string;
  private readonly associatedInterface: string;
  private readonly commentPrefix: string;
  private readonly tlsVerify: boolean;

  constructor(config: FortigateConnectorConfig) {
    super(config);

    this.firewalls = config.firewalls;
    this.addressGroup = config.addressGroup;
    this.addressType = config.addressType ?? 'auto';
    this.action = config.action ?? 'block';
    this.addressNamePrefix = config.addressNamePrefix ?? 'blockioc-';
    this.associatedInterface = config.associatedInterface ?? '';
    this.commentPrefix = config.commentPrefix ?? 'BlockIOC';
    this.tlsVerify = config.tlsVerify ?? true;
  }

  protected async doInit(): Promise<void> {
    if (!this.firewalls || this.firewalls.length === 0) {
      throw new Error('Fortigate firewalls configuration is required');
    }

    for (const firewall of this.firewalls) {
      if (!firewall.baseIp || !firewall.basePort || !firewall.apiKey) {
        throw new Error('Fortigate firewall configuration requires baseIp, basePort, and apiKey');
      }
    }
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const indicator = event.matchedIndicator || event.blockedUrl;
    if (!indicator) {
      return {
        success: false,
        eventId: event.eventId,
        error: 'No indicator value found in event',
        retryable: false,
      };
    }

    const resolvedType = this.resolveAddressType(event, indicator);
    if (!resolvedType) {
      return {
        success: false,
        eventId: event.eventId,
        error: 'Unable to resolve Fortigate address type for event',
        retryable: false,
      };
    }

    const addressName = this.buildAddressName(indicator);

    try {
      for (const firewall of this.firewalls) {
        if (this.action === 'block') {
          await this.createAddressObject(firewall, addressName, indicator, resolvedType, event);
          if (this.addressGroup) {
            await this.ensureGroupMembership(firewall, addressName);
          }
        } else {
          if (this.addressGroup) {
            await this.removeGroupMembership(firewall, addressName);
          }
          await this.deleteAddressObject(firewall, addressName);
        }
      }

      return {
        success: true,
        eventId: event.eventId,
        response: {
          action: this.action,
          addressName,
        },
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
    return { healthy: true, message: 'ok' };
  }

  protected async doClose(): Promise<void> {
    return;
  }

  // ==========================================================================
  // Internal helpers
  // ==========================================================================

  private resolveAddressType(event: ForensicsEvent, indicator: string): AddressType | null {
    if (this.addressType !== 'auto') {
      return this.addressType;
    }

    if (event.matchType === 'hash') {
      return null;
    }

    if (this.isIpAddress(indicator)) {
      return 'ip';
    }

    return 'fqdn';
  }

  private buildAddressName(indicator: string): string {
    const normalized = indicator.replace(/[^a-zA-Z0-9-_]/g, '-').slice(0, 32);
    const suffix = Buffer.from(indicator).toString('hex').slice(0, 8);
    return `${this.addressNamePrefix}${normalized}-${suffix}`;
  }

  private async createAddressObject(
    firewall: FortigateConnectorConfig['firewalls'][number],
    name: string,
    indicator: string,
    type: AddressType,
    event: ForensicsEvent
  ): Promise<void> {
    const payload: Record<string, unknown> = {
      type: type === 'ip' ? 'ipmask' : 'fqdn',
      name,
      'associated-interface': this.associatedInterface,
      comment: `${this.commentPrefix} event ${event.eventId}`,
    };

    if (type === 'ip') {
      payload.subnet = indicator.includes('/') ? indicator : `${indicator}/32`;
    } else {
      payload.fqdn = this.extractFqdn(indicator);
    }

    const response = await this.makeRequest(
      firewall,
      '/api/v2/cmdb/firewall/address/',
      'POST',
      payload
    );

    if (response.ok) {
      return;
    }

    const text = await response.text();
    if (response.status === 409 || text.includes('entry already exists')) {
      return;
    }

    throw new Error(`Fortigate create address failed (${response.status}): ${text}`);
  }

  private async deleteAddressObject(
    firewall: FortigateConnectorConfig['firewalls'][number],
    name: string
  ): Promise<void> {
    const response = await this.makeRequest(
      firewall,
      `/api/v2/cmdb/firewall/address/${encodeURIComponent(name)}`,
      'DELETE'
    );

    if (response.ok || response.status === 404) {
      return;
    }

    const text = await response.text();
    throw new Error(`Fortigate delete address failed (${response.status}): ${text}`);
  }

  private async ensureGroupMembership(
    firewall: FortigateConnectorConfig['firewalls'][number],
    name: string
  ): Promise<void> {
    const group = this.addressGroup;
    if (!group) {
      return;
    }

    const response = await this.makeRequest(
      firewall,
      `/api/v2/cmdb/firewall/addrgrp/${encodeURIComponent(group)}`,
      'GET'
    );

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Fortigate get address group failed (${response.status}): ${text}`);
    }

    const data = (await response.json()) as FortigateAddressGroup;
    const members = data.results?.[0]?.member ?? [];
    const memberNames = new Set(members.map((member) => member.name));

    if (memberNames.has(name)) {
      return;
    }

    const updatedMembers = [...members, { name }];
    await this.updateGroupMembers(firewall, group, updatedMembers);
  }

  private async removeGroupMembership(
    firewall: FortigateConnectorConfig['firewalls'][number],
    name: string
  ): Promise<void> {
    const group = this.addressGroup;
    if (!group) {
      return;
    }

    const response = await this.makeRequest(
      firewall,
      `/api/v2/cmdb/firewall/addrgrp/${encodeURIComponent(group)}`,
      'GET'
    );

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Fortigate get address group failed (${response.status}): ${text}`);
    }

    const data = (await response.json()) as FortigateAddressGroup;
    const members = data.results?.[0]?.member ?? [];
    const updatedMembers = members.filter((member) => member.name !== name);

    if (updatedMembers.length === members.length) {
      return;
    }

    await this.updateGroupMembers(firewall, group, updatedMembers);
  }

  private async updateGroupMembers(
    firewall: FortigateConnectorConfig['firewalls'][number],
    group: string,
    members: Array<{ name: string }>
  ): Promise<void> {
    const response = await this.makeRequest(
      firewall,
      `/api/v2/cmdb/firewall/addrgrp/${encodeURIComponent(group)}`,
      'PUT',
      { member: members }
    );

    if (response.ok) {
      return;
    }

    const text = await response.text();
    throw new Error(`Fortigate update address group failed (${response.status}): ${text}`);
  }

  private extractFqdn(indicator: string): string {
    try {
      const url = new URL(indicator);
      return url.hostname;
    } catch {
      return indicator;
    }
  }

  private isIpAddress(value: string): boolean {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(':');
  }

  private async makeRequest(
    firewall: FortigateConnectorConfig['firewalls'][number],
    path: string,
    method: string,
    body?: Record<string, unknown>
  ): Promise<Response> {
    const baseUrl = `https://${firewall.baseIp}:${firewall.basePort}`;
    const url = new URL(`${baseUrl}${path}`);
    url.searchParams.set('vdom', firewall.vdom ?? 'root');

    const init: RequestInit & { dispatcher?: unknown } = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${firewall.apiKey}`,
      },
      body: body ? JSON.stringify({ json: body }) : undefined,
    };

    if (!this.tlsVerify && typeof globalThis.process !== 'undefined') {
      try {
        const undici = await import('undici');
        init.dispatcher = new undici.Agent({
          connect: {
            rejectUnauthorized: false,
          },
        });
      } catch {
        // Fallback to default fetch dispatcher if undici is unavailable.
      }
    }

    return fetch(url.toString(), init);
  }
}

export function createFortigateConnector(config: FortigateConnectorConfig): FortigateConnector {
  return new FortigateConnector(config);
}

connectorRegistry.register('fortigate', createFortigateConnector);
