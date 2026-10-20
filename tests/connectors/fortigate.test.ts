import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { FortigateConnector, createFortigateConnector } from '../../src/connectors/fortigate';
import { ForensicsEvent, FortigateConnectorConfig } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    blockedUrl: 'https://evil.com/phishing',
    timestamp: '2024-01-15T10:30:00.000Z',
    redirectChain: ['https://legit.com', 'https://redirect.com', 'https://evil.com/phishing'],
    tabContext: {
      tabId: 123,
      windowId: 1,
      initiatorUrl: 'https://email.example.com',
      tabTitle: 'Check your account',
      incognito: false,
    },
    orgId: 'org-123',
    eventId: 'evt-456',
    matchType: 'url',
    matchedIndicator: 'evil.com',
    userId: 'user-789',
    raw: {},
    ...overrides,
  };
}

function createTestConfig(overrides: Partial<FortigateConnectorConfig> = {}): FortigateConnectorConfig {
  return {
    type: 'fortigate',
    name: 'test-fortigate',
    enabled: true,
    firewalls: [
      {
        baseIp: '192.168.1.1',
        basePort: 443,
        apiKey: 'test-api-key-123',
        vdom: 'root',
      },
    ],
    // Disable batching for simpler testing
    batch: { maxSize: 1, maxWaitMs: 0 },
    ...overrides,
  };
}

// =============================================================================
// FortigateConnector Tests
// =============================================================================

describe('FortigateConnector', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    global.fetch = mockFetch as typeof fetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('initialization', () => {
    it('should create a connector with valid config', () => {
      const config = createTestConfig();
      const connector = new FortigateConnector(config);

      expect(connector.type).toBe('fortigate');
      expect(connector.name).toBe('test-fortigate');
    });

    it('should throw on missing firewalls configuration', async () => {
      const config = createTestConfig({ firewalls: [] });
      const connector = new FortigateConnector(config);

      await expect(connector.init()).rejects.toThrow('Fortigate firewalls configuration is required');
    });

    it('should throw on missing firewall baseIp', async () => {
      const config = createTestConfig({
        firewalls: [{ baseIp: '', basePort: 443, apiKey: 'key' }],
      });
      const connector = new FortigateConnector(config);

      await expect(connector.init()).rejects.toThrow('Fortigate firewall configuration requires baseIp, basePort, and apiKey');
    });

    it('should throw on missing firewall basePort', async () => {
      const config = createTestConfig({
        firewalls: [{ baseIp: '192.168.1.1', basePort: 0, apiKey: 'key' }],
      });
      const connector = new FortigateConnector(config);

      await expect(connector.init()).rejects.toThrow('Fortigate firewall configuration requires baseIp, basePort, and apiKey');
    });

    it('should throw on missing firewall apiKey', async () => {
      const config = createTestConfig({
        firewalls: [{ baseIp: '192.168.1.1', basePort: 443, apiKey: '' }],
      });
      const connector = new FortigateConnector(config);

      await expect(connector.init()).rejects.toThrow('Fortigate firewall configuration requires baseIp, basePort, and apiKey');
    });

    it('should initialize with valid config', async () => {
      const config = createTestConfig();
      const connector = new FortigateConnector(config);

      await connector.init();
      // Should not throw
    });
  });

  describe('send - block action', () => {
    it('should create address object for FQDN indicator', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(''),
      });

      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent({ matchedIndicator: 'evil.com' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-456');
      expect(result.response).toMatchObject({
        action: 'block',
      });

      // Verify API call
      const call = mockFetch.mock.calls[0];
      expect(call[0]).toContain('/api/v2/cmdb/firewall/address/');
      expect(call[1].method).toBe('POST');
      expect(call[1].headers['Authorization']).toBe('Bearer test-api-key-123');

      const body = JSON.parse(call[1].body);
      expect(body.json.type).toBe('fqdn');
      expect(body.json.fqdn).toBe('evil.com');
    });

    it('should create address object for IP indicator', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(''),
      });

      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent({ matchedIndicator: '192.168.1.100' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.json.type).toBe('ipmask');
      expect(body.json.subnet).toBe('192.168.1.100/32');
    });

    it('should handle IP with CIDR notation when addressType is forced to ip', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(''),
      });

      // Force ip type since auto detection doesn't recognize CIDR
      const config = createTestConfig({ addressType: 'ip' });
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent({ matchedIndicator: '10.0.0.0/8' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.json.subnet).toBe('10.0.0.0/8');
    });

    it('should extract FQDN from domain indicator', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(''),
      });

      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent({ matchedIndicator: 'malware.evil.com' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.json.fqdn).toBe('malware.evil.com');
    });

    it('should handle existing address (409 conflict)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 409,
        text: () => Promise.resolve('entry already exists'),
      });

      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
    });

    it('should add address to group when addressGroup configured', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: () => Promise.resolve(''),
        }) // create address
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            results: [{ member: [{ name: 'existing-addr' }] }],
          }),
        }) // get group
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: () => Promise.resolve(''),
        }); // update group

      const config = createTestConfig({ addressGroup: 'block-group' });
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      // Verify group update
      expect(mockFetch).toHaveBeenCalledTimes(3);
      const updateCall = mockFetch.mock.calls[2];
      expect(updateCall[0]).toContain('/api/v2/cmdb/firewall/addrgrp/block-group');
      expect(updateCall[1].method).toBe('PUT');
    });

    it('should skip group update if address already member', async () => {
      const addressName = 'blockioc-evil-com-6576696c'; // Generated name pattern

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: () => Promise.resolve(''),
        }) // create address
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            results: [{ member: [{ name: addressName }] }],
          }),
        }); // get group (address already member)

      const config = createTestConfig({ addressGroup: 'block-group' });
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent({ matchedIndicator: 'evil.com' });
      await connector.send(event);

      // Should only have 2 calls (create + get), no PUT
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should return error when no indicator found', async () => {
      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent({ matchedIndicator: undefined, blockedUrl: undefined });
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('No indicator value found');
      expect(result.retryable).toBe(false);
    });

    it('should return error for hash match type with auto address type', async () => {
      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: 'abc123def456',
      });
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Unable to resolve Fortigate address type');
      expect(result.retryable).toBe(false);
    });

    it('should use forced address type when configured', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(''),
      });

      const config = createTestConfig({ addressType: 'fqdn' });
      const connector = new FortigateConnector(config);
      await connector.init();

      // Even IP address should be treated as FQDN
      const event = createTestEvent({ matchedIndicator: '192.168.1.1' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.json.type).toBe('fqdn');
    });
  });

  describe('send - unblock action', () => {
    it('should delete address object for unblock action', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(''),
      });

      const config = createTestConfig({ action: 'unblock' });
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toMatchObject({
        action: 'unblock',
      });

      const call = mockFetch.mock.calls[0];
      expect(call[1].method).toBe('DELETE');
      expect(call[0]).toContain('/api/v2/cmdb/firewall/address/');
    });

    it('should handle address not found on delete (404)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        text: () => Promise.resolve('entry not found'),
      });

      const config = createTestConfig({ action: 'unblock' });
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
    });

    it('should remove from group before deleting when addressGroup configured', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            results: [{ member: [
              { name: 'other-addr' },
              { name: 'blockioc-evil-com-6576696c' },
            ] }],
          }),
        }) // get group
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: () => Promise.resolve(''),
        }) // update group
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: () => Promise.resolve(''),
        }); // delete address

      const config = createTestConfig({
        action: 'unblock',
        addressGroup: 'block-group',
      });
      const connector = new FortigateConnector(config);
      await connector.init();

      const event = createTestEvent({ matchedIndicator: 'evil.com' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(3);

      // Verify group update removes the address
      const updateCall = mockFetch.mock.calls[1];
      expect(updateCall[1].method).toBe('PUT');
    });
  });

  describe('error handling', () => {
    it('should return retryable error for 5xx responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
        text: () => Promise.resolve('Service Unavailable'),
      });

      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('503');
    });

    it('should return retryable error for 429 responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        text: () => Promise.resolve('Too Many Requests'),
      });

      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should return non-retryable error for 4xx responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: () => Promise.resolve('Unauthorized'),
      });

      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
      expect(result.error).toContain('401');
    });

    it('should return retryable error for network failures', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed: ECONNREFUSED'));

      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('ECONNREFUSED');
    });

    it('should handle group get failure', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: () => Promise.resolve(''),
        }) // create address
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          text: () => Promise.resolve('Internal error'),
        }); // get group fails

      const config = createTestConfig({ addressGroup: 'block-group' });
      const connector = new FortigateConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('get address group failed');
    });

    it('should handle group update failure', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: () => Promise.resolve(''),
        }) // create address
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            results: [{ member: [] }],
          }),
        }) // get group
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          text: () => Promise.resolve('Update failed'),
        }); // update group fails

      const config = createTestConfig({ addressGroup: 'block-group' });
      const connector = new FortigateConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('update address group failed');
    });
  });

  describe('multiple firewalls', () => {
    it('should send to all configured firewalls', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, text: () => Promise.resolve('') })
        .mockResolvedValueOnce({ ok: true, status: 200, text: () => Promise.resolve('') });

      const config = createTestConfig({
        firewalls: [
          { baseIp: '192.168.1.1', basePort: 443, apiKey: 'key1' },
          { baseIp: '192.168.1.2', basePort: 443, apiKey: 'key2' },
        ],
      });
      const connector = new FortigateConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(2);

      // Verify different hosts
      expect(mockFetch.mock.calls[0][0]).toContain('192.168.1.1');
      expect(mockFetch.mock.calls[1][0]).toContain('192.168.1.2');
    });

    it('should fail if any firewall fails', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, text: () => Promise.resolve('') })
        .mockResolvedValueOnce({ ok: false, status: 500, text: () => Promise.resolve('Error') });

      const config = createTestConfig({
        firewalls: [
          { baseIp: '192.168.1.1', basePort: 443, apiKey: 'key1' },
          { baseIp: '192.168.1.2', basePort: 443, apiKey: 'key2' },
        ],
      });
      const connector = new FortigateConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
    });
  });

  describe('health', () => {
    it('should report healthy', async () => {
      const config = createTestConfig();
      const connector = new FortigateConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toBe('ok');
    });
  });

  describe('configuration options', () => {
    it('should use custom address name prefix', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(''),
      });

      const config = createTestConfig({ addressNamePrefix: 'custom-' });
      const connector = new FortigateConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.json.name).toMatch(/^custom-/);
    });

    it('should use custom comment prefix', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(''),
      });

      const config = createTestConfig({ commentPrefix: 'MyOrg' });
      const connector = new FortigateConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.json.comment).toContain('MyOrg');
    });

    it('should use custom vdom', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(''),
      });

      const config = createTestConfig({
        firewalls: [{ baseIp: '192.168.1.1', basePort: 443, apiKey: 'key', vdom: 'custom-vdom' }],
      });
      const connector = new FortigateConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toContain('vdom=custom-vdom');
    });

    it('should use associated interface when configured', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(''),
      });

      const config = createTestConfig({ associatedInterface: 'wan1' });
      const connector = new FortigateConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.json['associated-interface']).toBe('wan1');
    });
  });
});

// =============================================================================
// Factory Registration Tests
// =============================================================================

describe('FortigateConnector Factory', () => {
  it('should create connector via factory function', () => {
    const config = createTestConfig();
    const connector = createFortigateConnector(config);

    expect(connector).toBeInstanceOf(FortigateConnector);
    expect(connector.type).toBe('fortigate');
  });

  it('should be registered in the global registry', () => {
    expect(connectorRegistry.has('fortigate')).toBe(true);
  });

  it('should create connector via registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);

    expect(connector.type).toBe('fortigate');
    expect(connector.name).toBe('test-fortigate');
  });
});
