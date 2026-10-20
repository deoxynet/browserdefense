import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { HarfangLabConnector, createHarfangLabConnector } from '../../src/connectors/harfanglab';
import type { ForensicsEvent, HarfangLabConnectorConfig } from '../../src/connectors/types';
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

function createTestConfig(overrides: Partial<HarfangLabConnectorConfig> = {}): HarfangLabConnectorConfig {
  return {
    type: 'harfanglab',
    name: 'test-harfanglab',
    enabled: true,
    apiUrl: 'https://harfanglab.example.com',
    apiToken: 'test-api-token-123',
    sourceId: 'blockioc-source',
    batch: { maxSize: 1, maxWaitMs: 0 },
    ...overrides,
  };
}

// =============================================================================
// HarfangLabConnector Tests
// =============================================================================

describe('HarfangLabConnector', () => {
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
      const connector = new HarfangLabConnector(config);

      expect(connector.type).toBe('harfanglab');
      expect(connector.name).toBe('test-harfanglab');
    });

    it('should strip trailing slashes from apiUrl', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig({ apiUrl: 'https://harfanglab.example.com///' });
      const connector = new HarfangLabConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://harfanglab.example.com/api/data/threat_intelligence/IOCRule/',
        expect.any(Object)
      );
    });

    it('should throw on missing apiUrl', async () => {
      const config = createTestConfig({ apiUrl: '' });
      const connector = new HarfangLabConnector(config);

      await expect(connector.init()).rejects.toThrow('HarfangLab apiUrl is required');
    });

    it('should throw on missing apiToken', async () => {
      const config = createTestConfig({ apiToken: '' });
      const connector = new HarfangLabConnector(config);

      await expect(connector.init()).rejects.toThrow('HarfangLab apiToken is required');
    });

    it('should throw on missing sourceId', async () => {
      const config = createTestConfig({ sourceId: '' });
      const connector = new HarfangLabConnector(config);

      await expect(connector.init()).rejects.toThrow('HarfangLab sourceId is required');
    });

    it('should perform health check on init', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://harfanglab.example.com/api/data/threat_intelligence/IOCRule/',
        expect.objectContaining({
          method: 'GET',
          headers: {
            'Authorization': 'Token test-api-token-123',
            'Content-Type': 'application/json',
          },
        })
      );
    });

    it('should throw on failed health check', async () => {
      mockFetch.mockResolvedValue({ ok: false, status: 401 });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);

      await expect(connector.init()).rejects.toThrow('HarfangLab health check failed: status 401');
    });

    it('should use default action of block', () => {
      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);

      // Access internal via testing - action defaults to 'block'
      expect((connector as unknown as { action: string }).action).toBe('block');
    });

    it('should respect action config', () => {
      const config = createTestConfig({ action: 'unblock' });
      const connector = new HarfangLabConnector(config);

      expect((connector as unknown as { action: string }).action).toBe('unblock');
    });
  });

  // ===========================================================================
  // Block Action (Create IOC)
  // ===========================================================================

  describe('send (block action)', () => {
    it('should create IOC rule with correct payload', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health
        .mockResolvedValueOnce({
          ok: true,
          status: 201,
          json: () => Promise.resolve({ id: 'ioc-123', value: 'evil.com/phishing' }),
        });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-456');

      const sendCall = mockFetch.mock.calls[1];
      expect(sendCall[0]).toBe('https://harfanglab.example.com/api/data/threat_intelligence/IOCRule/');
      expect(sendCall[1].method).toBe('POST');

      const body = JSON.parse(sendCall[1].body);
      expect(body).toEqual({
        source_id: 'blockioc-source',
        type: 'url',
        value: 'evil.com/phishing',
        block_on_agent: true,
        quarantine_on_agent: false,
        endpoint_detection: true,
        enabled: true,
        description: 'BlockIOC event evt-456',
      });
    });

    it('should use matchedIndicator when available', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 201,
          json: () => Promise.resolve({ id: 'ioc-123' }),
        });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: 'specific-indicator.com',
        blockedUrl: 'https://different-url.com',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.value).toBe('specific-indicator.com');
    });

    it('should fallback to blockedUrl when no matchedIndicator', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 201,
          json: () => Promise.resolve({ id: 'ioc-123' }),
        });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: undefined,
        blockedUrl: 'https://fallback-url.com/path',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.value).toBe('https://fallback-url.com/path');
    });

    it('should map domain matchType to domain_name', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 201,
          json: () => Promise.resolve({ id: 'ioc-123' }),
        });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent({ matchType: 'domain' });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.type).toBe('domain_name');
    });

    it('should map hash matchType to hash', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 201,
          json: () => Promise.resolve({ id: 'ioc-123' }),
        });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent({ matchType: 'hash' });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.type).toBe('hash');
    });

    it('should default unknown matchType to url', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 201,
          json: () => Promise.resolve({ id: 'ioc-123' }),
        });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent({ matchType: 'unknown' as ForensicsEvent['matchType'] });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.type).toBe('url');
    });

    it('should use custom description prefix', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 201,
          json: () => Promise.resolve({ id: 'ioc-123' }),
        });

      const config = createTestConfig({ descriptionPrefix: 'BrowserDefense' });
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.description).toBe('BrowserDefense event evt-456');
    });

    it('should respect agent options', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: true,
          status: 201,
          json: () => Promise.resolve({ id: 'ioc-123' }),
        });

      const config = createTestConfig({
        blockOnAgent: false,
        quarantineOnAgent: true,
        detectOnAgent: false,
      });
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.block_on_agent).toBe(false);
      expect(body.quarantine_on_agent).toBe(true);
      expect(body.endpoint_detection).toBe(false);
    });

    it('should return retryable error on 5xx response', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          text: () => Promise.resolve('Service unavailable'),
        });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('503');
    });

    it('should return retryable error on 429 response', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          text: () => Promise.resolve('Rate limited'),
        });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should return non-retryable error on 4xx response', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockResolvedValueOnce({
          ok: false,
          status: 400,
          text: () => Promise.resolve('Bad request'),
        });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
      expect(result.error).toContain('400');
    });

    it('should return retryable error on network failure', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockRejectedValueOnce(new Error('fetch failed: ECONNREFUSED'));

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('ECONNREFUSED');
    });

    it('should throw error when no indicator value found', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
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
  // Unblock Action (Delete IOC)
  // ===========================================================================

  describe('send (unblock action)', () => {
    it('should search and delete existing IOCs', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ results: [{ id: 'ioc-1' }, { id: 'ioc-2' }] }),
        }) // search
        .mockResolvedValueOnce({ ok: true, status: 204 }) // delete 1
        .mockResolvedValueOnce({ ok: true, status: 204 }); // delete 2

      const config = createTestConfig({ action: 'unblock' });
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ removed: 2 });

      // Verify search call
      const searchCall = mockFetch.mock.calls[1];
      expect(searchCall[0]).toContain('/api/data/threat_intelligence/IOCRule/');
      expect(searchCall[0]).toContain('search=evil.com%2Fphishing');
      expect(searchCall[0]).toContain('source_id=blockioc-source');
      expect(searchCall[1].method).toBe('GET');

      // Verify delete calls
      expect(mockFetch.mock.calls[2][0]).toBe(
        'https://harfanglab.example.com/api/data/threat_intelligence/IOCRule/ioc-1'
      );
      expect(mockFetch.mock.calls[2][1].method).toBe('DELETE');
      expect(mockFetch.mock.calls[3][0]).toBe(
        'https://harfanglab.example.com/api/data/threat_intelligence/IOCRule/ioc-2'
      );
    });

    it('should return success with removed=0 when no IOCs found', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ results: [] }),
        }); // search

      const config = createTestConfig({ action: 'unblock' });
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ removed: 0 });

      // Only health + search, no deletes
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should handle missing results in search response', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({}), // No results field
        });

      const config = createTestConfig({ action: 'unblock' });
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ removed: 0 });
    });

    it('should throw error on search failure', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          text: () => Promise.resolve('Internal error'),
        });

      const config = createTestConfig({ action: 'unblock' });
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('search failed');
      expect(result.error).toContain('500');
    });

    it('should throw error on delete failure', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ results: [{ id: 'ioc-1' }] }),
        }) // search
        .mockResolvedValueOnce({
          ok: false,
          status: 404,
          text: () => Promise.resolve('Not found'),
        }); // delete fails

      const config = createTestConfig({ action: 'unblock' });
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('delete failed');
      expect(result.error).toContain('404');
    });
  });

  // ===========================================================================
  // Health Check
  // ===========================================================================

  describe('health', () => {
    it('should report healthy when API returns 200', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toBe('ok');
    });

    it('should report unhealthy on API error', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // init health passes
        .mockResolvedValueOnce({ ok: false, status: 500 }); // subsequent health fails

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      // Reset mock for the health check
      mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });
      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('500');
    });

    it('should report unhealthy on network error', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // init
        .mockRejectedValueOnce(new Error('Network timeout'));

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Network timeout');
    });
  });

  // ===========================================================================
  // Close
  // ===========================================================================

  describe('close', () => {
    it('should close gracefully', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new HarfangLabConnector(config);
      await connector.init();

      await expect(connector.close()).resolves.toBeUndefined();
    });
  });

  // ===========================================================================
  // Authentication
  // ===========================================================================

  describe('authentication', () => {
    it('should include Token authorization header', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig({ apiToken: 'my-secret-token' });
      const connector = new HarfangLabConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Token my-secret-token',
          }),
        })
      );
    });
  });
});

// =============================================================================
// Factory Registration Tests
// =============================================================================

describe('HarfangLabConnector Factory', () => {
  it('should create connector via factory function', () => {
    const config = createTestConfig();
    const connector = createHarfangLabConnector(config);

    expect(connector).toBeInstanceOf(HarfangLabConnector);
    expect(connector.type).toBe('harfanglab');
  });

  it('should be registered in the global registry', () => {
    expect(connectorRegistry.has('harfanglab')).toBe(true);
  });

  it('should create connector via registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);

    expect(connector.type).toBe('harfanglab');
    expect(connector.name).toBe('test-harfanglab');
  });
});
