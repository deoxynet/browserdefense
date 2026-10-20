import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  BitdefenderGravityZoneConnector,
  createBitdefenderGravityZoneConnector,
} from '../../src/connectors/bitdefender-gravityzone';
import type { ForensicsEvent, BitdefenderGravityZoneConnectorConfig } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    blockedUrl: 'https://evil.com/phishing',
    timestamp: '2024-01-15T10:30:00.000Z',
    redirectChain: ['https://legit.com', 'https://evil.com/phishing'],
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
    matchedIndicator: 'evil.com/phishing',
    userId: 'user-789',
    raw: {},
    ...overrides,
  };
}

function createTestConfig(
  overrides: Partial<BitdefenderGravityZoneConnectorConfig> = {}
): BitdefenderGravityZoneConnectorConfig {
  return {
    type: 'bitdefender-gravityzone',
    name: 'test-bitdefender',
    enabled: true,
    apiUrl: 'https://gravityzone.example.com',
    apiKey: 'test-api-key-123',
    batch: { maxSize: 1, maxWaitMs: 0 },
    ...overrides,
  };
}

function mockJsonRpcResponse(result: unknown = {}) {
  return {
    ok: true,
    status: 200,
    text: () => Promise.resolve(JSON.stringify({ jsonrpc: '2.0', result, id: 'test-id' })),
  };
}

function mockJsonRpcError(message: string, code = -32000) {
  return {
    ok: true,
    status: 200,
    text: () =>
      Promise.resolve(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: 'test-id' })),
  };
}

// =============================================================================
// BitdefenderGravityZoneConnector Tests
// =============================================================================

describe('BitdefenderGravityZoneConnector', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    global.fetch = mockFetch as typeof fetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ===========================================================================
  // Initialization
  // ===========================================================================

  describe('initialization', () => {
    it('should create connector with valid config', () => {
      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);

      expect(connector.type).toBe('bitdefender-gravityzone');
      expect(connector.name).toBe('test-bitdefender');
    });

    it('should strip trailing slashes from apiUrl', async () => {
      mockFetch.mockResolvedValue(mockJsonRpcResponse({ items: [] }));

      const config = createTestConfig({ apiUrl: 'https://gravityzone.example.com///' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://gravityzone.example.com/api/v1.2/jsonrpc/incidents',
        expect.any(Object)
      );
    });

    it('should throw on missing apiUrl', async () => {
      const config = createTestConfig({ apiUrl: '' });
      const connector = new BitdefenderGravityZoneConnector(config);

      await expect(connector.init()).rejects.toThrow('Bitdefender GravityZone API URL is required');
    });

    it('should throw on missing apiKey', async () => {
      const config = createTestConfig({ apiKey: '' });
      const connector = new BitdefenderGravityZoneConnector(config);

      await expect(connector.init()).rejects.toThrow('Bitdefender GravityZone API key is required');
    });

    it('should perform health check on init', async () => {
      mockFetch.mockResolvedValue(mockJsonRpcResponse({ items: [] }));

      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.method).toBe('getBlocklistItems');
      expect(body.params).toEqual({ page: 1, perPage: 1 });
    });

    it('should throw on failed health check', async () => {
      mockFetch.mockResolvedValue(mockJsonRpcError('Unauthorized'));

      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);

      await expect(connector.init()).rejects.toThrow('Bitdefender GravityZone health check failed');
    });

    it('should use default blockType of hash', () => {
      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);

      expect((connector as unknown as { blockType: string }).blockType).toBe('hash');
    });

    it('should use default action of block', () => {
      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);

      expect((connector as unknown as { action: string }).action).toBe('block');
    });
  });

  // ===========================================================================
  // Block Action - Hash Type
  // ===========================================================================

  describe('send (block action - hash type)', () => {
    it('should block hash with auto-detected MD5 algorithm', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] })) // health
        .mockResolvedValueOnce(mockJsonRpcResponse({ id: 'block-123' })); // block

      const config = createTestConfig({ blockType: 'hash' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: 'd41d8cd98f00b204e9800998ecf8427e', // MD5 (32 chars)
      });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const sendCall = mockFetch.mock.calls[1];
      const body = JSON.parse(sendCall[1].body);
      expect(body.method).toBe('addToBlocklist');
      expect(body.params).toEqual({
        type: 'hash',
        rules: [
          {
            details: {
              algorithm: 'md5',
              hash: 'd41d8cd98f00b204e9800998ecf8427e',
            },
          },
        ],
      });
    });

    it('should block hash with auto-detected SHA1 algorithm', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce(mockJsonRpcResponse({ id: 'block-123' }));

      const config = createTestConfig({ blockType: 'hash' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', // SHA1 (40 chars)
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.params.rules[0].details.algorithm).toBe('sha1');
    });

    it('should block hash with auto-detected SHA256 algorithm', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce(mockJsonRpcResponse({ id: 'block-123' }));

      const config = createTestConfig({ blockType: 'hash' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // SHA256 (64 chars)
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.params.rules[0].details.algorithm).toBe('sha256');
    });

    it('should use explicit hashAlgorithm when configured', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce(mockJsonRpcResponse({ id: 'block-123' }));

      const config = createTestConfig({ blockType: 'hash', hashAlgorithm: 'sha512' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: 'somehash',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.params.rules[0].details.algorithm).toBe('sha512');
    });

    it('should throw error when matchType is not hash for hash blockType', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }));

      const config = createTestConfig({ blockType: 'hash' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({ matchType: 'url' });
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('matchType=hash');
    });

    it('should throw error when hash algorithm cannot be determined', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }));

      const config = createTestConfig({ blockType: 'hash' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: 'abc123', // Invalid length
      });
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Unable to determine hash algorithm');
    });
  });

  // ===========================================================================
  // Block Action - Path Type
  // ===========================================================================

  describe('send (block action - path type)', () => {
    it('should block path indicator', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce(mockJsonRpcResponse({ id: 'block-123' }));

      const config = createTestConfig({ blockType: 'path' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: 'C:\\Windows\\malware.exe',
      });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.method).toBe('addToBlocklist');
      expect(body.params).toEqual({
        type: 'path',
        rules: [
          {
            details: {
              path: 'C:\\Windows\\malware.exe',
            },
          },
        ],
      });
    });
  });

  // ===========================================================================
  // Block Action - Connection Type
  // ===========================================================================

  describe('send (block action - connection type)', () => {
    it('should block connection with default settings', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce(mockJsonRpcResponse({ id: 'block-123' }));

      const config = createTestConfig({ blockType: 'connection' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: 'malicious.domain.com',
      });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.params.type).toBe('connection');
      expect(body.params.rules[0].details).toMatchObject({
        ruleName: 'blockioc-evt-456',
        protocol: 'any',
        direction: 'both',
        ipVersion: 'any',
      });
    });

    it('should use custom ruleNamePrefix', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce(mockJsonRpcResponse({ id: 'block-123' }));

      const config = createTestConfig({
        blockType: 'connection',
        ruleNamePrefix: 'custom-prefix-',
      });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.params.rules[0].details.ruleName).toBe('custom-prefix-evt-456');
    });

    it('should set IPv4 address with /32 mask', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce(mockJsonRpcResponse({ id: 'block-123' }));

      const config = createTestConfig({ blockType: 'connection' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: '192.168.1.100',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      const details = body.params.rules[0].details;
      expect(details.remoteAddress.ipMask).toBe('192.168.1.100/32');
      expect(details.remoteAddress.any).toBe(false);
    });

    it('should set IPv6 address with /128 mask', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce(mockJsonRpcResponse({ id: 'block-123' }));

      const config = createTestConfig({ blockType: 'connection' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: '2001:db8::1',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      const details = body.params.rules[0].details;
      expect(details.remoteAddress.ipMask).toBe('2001:db8::1/128');
    });

    it('should use connectionDefaults when provided', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce(mockJsonRpcResponse({ id: 'block-123' }));

      const config = createTestConfig({
        blockType: 'connection',
        connectionDefaults: {
          protocol: 'tcp',
          direction: 'outbound',
          ipVersion: 'IPV4',
        },
      });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      const details = body.params.rules[0].details;
      expect(details.protocol).toBe('tcp');
      expect(details.direction).toBe('outbound');
      expect(details.ipVersion).toBe('IPV4');
    });
  });

  // ===========================================================================
  // Unblock Action
  // ===========================================================================

  describe('send (unblock action)', () => {
    it('should find and remove matching blocklist items', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] })) // health
        .mockResolvedValueOnce(
          mockJsonRpcResponse({
            items: [
              { type: 'hash', id: 'item-1', details: { hash: 'abc123def456' } },
              { type: 'hash', id: 'item-2', details: { hash: 'different' } },
            ],
            pagesCount: 1,
          })
        ) // search
        .mockResolvedValueOnce(mockJsonRpcResponse({})); // remove

      const config = createTestConfig({ blockType: 'hash', action: 'unblock' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: 'abc123def456',
      });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      // Verify remove call
      const removeCall = mockFetch.mock.calls[2];
      const body = JSON.parse(removeCall[1].body);
      expect(body.method).toBe('removeFromBlocklist');
      expect(body.params).toEqual({ ids: ['item-1'] });
    });

    it('should return success with removed=0 when no items found', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] })) // health
        .mockResolvedValueOnce(
          mockJsonRpcResponse({
            items: [],
            pagesCount: 1,
          })
        ); // search

      const config = createTestConfig({ action: 'unblock' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ removed: 0 });

      // Should not have a remove call
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should handle pagination when searching for items', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] })) // health
        .mockResolvedValueOnce(
          mockJsonRpcResponse({
            items: [{ type: 'hash', id: 'item-1', details: { hash: 'target' } }],
            pagesCount: 2,
          })
        ) // page 1
        .mockResolvedValueOnce(
          mockJsonRpcResponse({
            items: [{ type: 'hash', id: 'item-2', details: { hash: 'target' } }],
            pagesCount: 2,
          })
        ) // page 2
        .mockResolvedValueOnce(mockJsonRpcResponse({})); // remove

      const config = createTestConfig({ blockType: 'hash', action: 'unblock' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: 'target',
      });
      await connector.send(event);

      // Verify both items were found and removed
      const removeCall = mockFetch.mock.calls[3];
      const body = JSON.parse(removeCall[1].body);
      expect(body.params.ids).toContain('item-1');
      expect(body.params.ids).toContain('item-2');
    });

    it('should match path indicator for unblock', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] })) // health
        .mockResolvedValueOnce(
          mockJsonRpcResponse({
            items: [{ type: 'path', id: 'path-1', details: { path: '/usr/bin/malware' } }],
            pagesCount: 1,
          })
        )
        .mockResolvedValueOnce(mockJsonRpcResponse({}));

      const config = createTestConfig({ blockType: 'path', action: 'unblock' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: '/usr/bin/malware',
      });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
    });

    it('should match connection indicator by remote address for unblock', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] })) // health
        .mockResolvedValueOnce(
          mockJsonRpcResponse({
            items: [
              {
                type: 'connection',
                id: 'conn-1',
                details: { remoteAddress: { ipMask: '10.0.0.1/32' } },
              },
            ],
            pagesCount: 1,
          })
        )
        .mockResolvedValueOnce(mockJsonRpcResponse({}));

      const config = createTestConfig({ blockType: 'connection', action: 'unblock' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: '10.0.0.1',
      });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
    });
  });

  // ===========================================================================
  // Error Handling
  // ===========================================================================

  describe('error handling', () => {
    it('should return retryable error on 5xx response', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          text: () => Promise.resolve('Service unavailable'),
        });

      const config = createTestConfig({ blockType: 'path' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('503');
    });

    it('should return retryable error on 429 response', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          text: () => Promise.resolve('Rate limited'),
        });

      const config = createTestConfig({ blockType: 'path' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should return retryable error on network failure', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockRejectedValueOnce(new Error('fetch failed: ECONNREFUSED'));

      const config = createTestConfig({ blockType: 'path' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('ECONNREFUSED');
    });

    it('should handle JSON-RPC error response', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }))
        .mockResolvedValueOnce(mockJsonRpcError('Invalid parameters'));

      const config = createTestConfig({ blockType: 'path' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid parameters');
    });

    it('should throw error when no indicator value found', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonRpcResponse({ items: [] }));

      const config = createTestConfig({ blockType: 'path' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: undefined,
        blockedUrl: undefined as unknown as string,
      });
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('No indicator value found');
    });
  });

  // ===========================================================================
  // Health Check
  // ===========================================================================

  describe('health', () => {
    it('should report healthy when API returns success', async () => {
      mockFetch.mockResolvedValue(mockJsonRpcResponse({ items: [] }));

      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toBe('ok');
    });

    it('should report unhealthy on API error', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] })) // init
        .mockResolvedValueOnce(mockJsonRpcError('Server error'));

      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Server error');
    });

    it('should report unhealthy on network error', async () => {
      mockFetch
        .mockResolvedValueOnce(mockJsonRpcResponse({ items: [] })) // init
        .mockRejectedValueOnce(new Error('Network timeout'));

      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Network timeout');
    });
  });

  // ===========================================================================
  // Authentication
  // ===========================================================================

  describe('authentication', () => {
    it('should include Basic auth header with API key', async () => {
      mockFetch.mockResolvedValue(mockJsonRpcResponse({ items: [] }));

      const config = createTestConfig({ apiKey: 'my-secret-key' });
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const call = mockFetch.mock.calls[0];
      const expectedAuth = Buffer.from('my-secret-key:').toString('base64');
      expect(call[1].headers['Authorization']).toBe(`Basic ${expectedAuth}`);
    });
  });

  // ===========================================================================
  // JSON-RPC Format
  // ===========================================================================

  describe('JSON-RPC format', () => {
    it('should send proper JSON-RPC 2.0 request', async () => {
      mockFetch.mockResolvedValue(mockJsonRpcResponse({ items: [] }));

      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      const call = mockFetch.mock.calls[0];
      const body = JSON.parse(call[1].body);

      expect(body.jsonrpc).toBe('2.0');
      expect(body.method).toBe('getBlocklistItems');
      expect(body.params).toBeDefined();
      expect(body.id).toBeDefined();
    });

    it('should use correct API endpoint', async () => {
      mockFetch.mockResolvedValue(mockJsonRpcResponse({ items: [] }));

      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://gravityzone.example.com/api/v1.2/jsonrpc/incidents',
        expect.any(Object)
      );
    });
  });

  // ===========================================================================
  // Close
  // ===========================================================================

  describe('close', () => {
    it('should close gracefully', async () => {
      mockFetch.mockResolvedValue(mockJsonRpcResponse({ items: [] }));

      const config = createTestConfig();
      const connector = new BitdefenderGravityZoneConnector(config);
      await connector.init();

      await expect(connector.close()).resolves.toBeUndefined();
    });
  });
});

// =============================================================================
// Factory Registration Tests
// =============================================================================

describe('BitdefenderGravityZoneConnector Factory', () => {
  it('should create connector via factory function', () => {
    const config = createTestConfig();
    const connector = createBitdefenderGravityZoneConnector(config);

    expect(connector).toBeInstanceOf(BitdefenderGravityZoneConnector);
    expect(connector.type).toBe('bitdefender-gravityzone');
  });

  it('should be registered in the global registry', () => {
    expect(connectorRegistry.has('bitdefender-gravityzone')).toBe(true);
  });

  it('should create connector via registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);

    expect(connector.type).toBe('bitdefender-gravityzone');
    expect(connector.name).toBe('test-bitdefender');
  });
});
