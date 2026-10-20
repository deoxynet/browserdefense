import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { CortexXdrConnector, createCortexXdrConnector } from '../../src/connectors/cortexxdr';
import { ForensicsEvent, CortexXdrConnectorConfig } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    blockedUrl: 'https://evil.com/malware.exe',
    timestamp: '2024-01-15T10:30:00.000Z',
    redirectChain: [],
    tabContext: {
      tabId: 123,
      windowId: 1,
      initiatorUrl: 'https://email.example.com',
      tabTitle: 'Download',
      incognito: false,
    },
    orgId: 'org-123',
    eventId: 'evt-456',
    matchType: 'hash',
    matchedIndicator: 'abc123def456abc123def456abc123def456abc123def456abc123def456abc1',
    userId: 'user-789',
    raw: {},
    ...overrides,
  };
}

function createTestConfig(overrides: Partial<CortexXdrConnectorConfig> = {}): CortexXdrConnectorConfig {
  return {
    type: 'cortexxdr',
    name: 'test-cortexxdr',
    enabled: true,
    fqdn: 'api-test.xdr.paloaltonetworks.com',
    apiKey: 'test-api-key-123',
    apiKeyId: 'test-key-id-456',
    incidentId: 12345,
    // Disable batching for simpler testing
    batch: { maxSize: 1, maxWaitMs: 0 },
    ...overrides,
  };
}

// =============================================================================
// CortexXdrConnector Tests
// =============================================================================

describe('CortexXdrConnector', () => {
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
      const connector = new CortexXdrConnector(config);

      expect(connector.type).toBe('cortexxdr');
      expect(connector.name).toBe('test-cortexxdr');
    });

    it('should fail health check with invalid fqdn', async () => {
      // Empty fqdn gets formatted to 'https://api-' which fails health check
      mockFetch.mockRejectedValueOnce(new Error('Invalid URL'));

      const config = createTestConfig({ fqdn: '' });
      const connector = new CortexXdrConnector(config);

      await expect(connector.init()).rejects.toThrow('Cortex XDR health check failed');
    });

    it('should throw on missing apiKey', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });
      const config = createTestConfig({ apiKey: '' });
      const connector = new CortexXdrConnector(config);

      await expect(connector.init()).rejects.toThrow('Cortex XDR apiKey is required');
    });

    it('should throw on missing apiKeyId', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });
      const config = createTestConfig({ apiKeyId: '' });
      const connector = new CortexXdrConnector(config);

      await expect(connector.init()).rejects.toThrow('Cortex XDR apiKeyId is required');
    });

    it('should throw on missing incidentId', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });
      const config = createTestConfig({ incidentId: undefined as unknown as number });
      const connector = new CortexXdrConnector(config);

      await expect(connector.init()).rejects.toThrow('Cortex XDR incidentId is required');
    });

    it('should perform health check on init', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api-test.xdr.paloaltonetworks.com/public_api/v1/health',
        expect.objectContaining({ method: 'GET' })
      );
    });

    it('should throw if health check fails', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 503 });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);

      await expect(connector.init()).rejects.toThrow('Cortex XDR health check failed');
    });

    it('should format fqdn correctly without https prefix', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig({ fqdn: 'test.xdr.paloaltonetworks.com' });
      const connector = new CortexXdrConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api-test.xdr.paloaltonetworks.com/public_api/v1/health',
        expect.anything()
      );
    });

    it('should format fqdn correctly with api- prefix', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig({ fqdn: 'api-myorg.xdr.paloaltonetworks.com' });
      const connector = new CortexXdrConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api-myorg.xdr.paloaltonetworks.com/public_api/v1/health',
        expect.anything()
      );
    });

    it('should format fqdn correctly with https prefix', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig({ fqdn: 'https://custom.xdr.example.com' });
      const connector = new CortexXdrConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://custom.xdr.example.com/public_api/v1/health',
        expect.anything()
      );
    });

    it('should strip trailing slashes from fqdn', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig({ fqdn: 'https://api-test.xdr.paloaltonetworks.com///' });
      const connector = new CortexXdrConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api-test.xdr.paloaltonetworks.com/public_api/v1/health',
        expect.anything()
      );
    });
  });

  describe('send - block action', () => {
    it('should send hash to blocklist', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ reply: {} }),
        });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-456');

      // Verify API call
      const call = mockFetch.mock.calls[1];
      expect(call[0]).toBe('https://api-test.xdr.paloaltonetworks.com/public_api/v1/hash_exceptions/blocklist');
      expect(call[1].method).toBe('POST');
      expect(call[1].headers['x-xdr-auth-id']).toBe('test-key-id-456');
      expect(call[1].headers['Authorization']).toBe('test-api-key-123');

      const body = JSON.parse(call[1].body);
      expect(body.request_data.hash_list).toContain('abc123def456abc123def456abc123def456abc123def456abc123def456abc1');
      expect(body.request_data.incident_id).toBe(12345);
    });

    it('should include comment with event ID', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ reply: {} }),
        });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      const call = mockFetch.mock.calls[1];
      const body = JSON.parse(call[1].body);
      expect(body.request_data.comment).toContain('BlockIOC');
      expect(body.request_data.comment).toContain('evt-456');
    });

    it('should use custom comment prefix', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ reply: {} }),
        });

      const config = createTestConfig({ commentPrefix: 'MyOrg Security' });
      const connector = new CortexXdrConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      const call = mockFetch.mock.calls[1];
      const body = JSON.parse(call[1].body);
      expect(body.request_data.comment).toContain('MyOrg Security');
    });

    it('should reject non-hash match types', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const event = createTestEvent({ matchType: 'url' });
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('requires matchType=hash');
      expect(result.retryable).toBe(false);
    });

    it('should reject domain match type', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const event = createTestEvent({ matchType: 'domain' });
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('requires matchType=hash');
    });

    it('should return error when no indicator found', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: undefined,
        blockedUrl: undefined,
      });
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('No hash indicator value found');
      expect(result.retryable).toBe(false);
    });

    it('should use blockedUrl as fallback indicator', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ reply: {} }),
        });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: undefined,
        blockedUrl: 'fallback-hash-value',
      });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const call = mockFetch.mock.calls[1];
      const body = JSON.parse(call[1].body);
      expect(body.request_data.hash_list).toContain('fallback-hash-value');
    });
  });

  describe('send - unblock action', () => {
    it('should reject unblock action', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig({ action: 'block' });
      const connector = new CortexXdrConnector(config);
      await connector.init();

      // Manually set action to unblock for testing
      (connector as unknown as { action: string }).action = 'unblock';

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('only supports block actions');
      expect(result.retryable).toBe(false);
    });
  });

  describe('error handling', () => {
    it('should return retryable error for 5xx responses', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          json: () => Promise.resolve({}),
        });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('503');
    });

    it('should return retryable error for 429 responses', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          json: () => Promise.resolve({}),
        });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should return non-retryable error for 4xx responses', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: () => Promise.resolve({}),
        });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
    });

    it('should extract Cortex XDR error from response', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: false,
          status: 400,
          json: () => Promise.resolve({
            reply: {
              err_code: 500,
              err_msg: 'Invalid hash format',
              err_extra: 'SHA256 expected',
            },
          }),
        });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('Cortex XDR error 500');
      expect(result.error).toContain('Invalid hash format');
      expect(result.error).toContain('SHA256 expected');
    });

    it('should handle error without err_extra', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: false,
          status: 400,
          json: () => Promise.resolve({
            reply: {
              err_code: 100,
              err_msg: 'Bad request',
            },
          }),
        });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('Cortex XDR error 100');
      expect(result.error).toContain('Bad request');
    });

    it('should return retryable error for network failures', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockRejectedValueOnce(new Error('fetch failed: ECONNREFUSED'));

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('ECONNREFUSED');
    });

    it('should handle successful response with error in body', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            reply: {
              err_code: 401,
              err_msg: 'Authentication failed',
            },
          }),
        });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('Authentication failed');
    });
  });

  describe('health', () => {
    it('should report healthy when health endpoint succeeds', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toBe('ok');
    });

    it('should report unhealthy on error response', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // init health check
        .mockResolvedValueOnce({ ok: false, status: 500 }); // subsequent health check

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('500');
    });

    it('should report unhealthy on network error', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockRejectedValueOnce(new Error('Network unreachable'));

      const config = createTestConfig();
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Network unreachable');
    });
  });

  describe('authentication headers', () => {
    it('should include correct authentication headers', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig({
        apiKey: 'my-secret-api-key',
        apiKeyId: 'my-key-id-123',
      });
      const connector = new CortexXdrConnector(config);
      await connector.init();

      const call = mockFetch.mock.calls[0];
      expect(call[1].headers['x-xdr-auth-id']).toBe('my-key-id-123');
      expect(call[1].headers['Authorization']).toBe('my-secret-api-key');
      expect(call[1].headers['Content-Type']).toBe('application/json');
    });
  });
});

// =============================================================================
// Factory Registration Tests
// =============================================================================

describe('CortexXdrConnector Factory', () => {
  it('should create connector via factory function', () => {
    const config = createTestConfig();
    const connector = createCortexXdrConnector(config);

    expect(connector).toBeInstanceOf(CortexXdrConnector);
    expect(connector.type).toBe('cortexxdr');
  });

  it('should be registered in the global registry', () => {
    expect(connectorRegistry.has('cortexxdr')).toBe(true);
  });

  it('should create connector via registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);

    expect(connector.type).toBe('cortexxdr');
    expect(connector.name).toBe('test-cortexxdr');
  });
});
