/**
 * Tests for Rapid7 InsightIDR Connector
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  InsightIDRConnector,
  transformToInsightIDRLog,
  createInsightIDRConnector,
} from '../../src/connectors/rapid7';
import type {
  ForensicsEvent,
  InsightIDRConnectorConfig,
} from '../../src/connectors/types';

// =============================================================================
// Test Fixtures
// =============================================================================

const createMockEvent = (overrides: Partial<ForensicsEvent> = {}): ForensicsEvent => ({
  blockedUrl: 'https://malicious.example.com/payload',
  timestamp: '2024-01-15T10:30:00.000Z',
  redirectChain: ['https://initial.com', 'https://redirect.com'],
  tabContext: {
    tabId: 123,
    windowId: 1,
    initiatorUrl: 'https://legitimate-site.com',
    tabTitle: 'Test Page',
    incognito: false,
  },
  orgId: 'org-123',
  eventId: 'event-abc-123',
  matchType: 'domain',
  matchedIndicator: 'malicious.example.com',
  userId: 'user@example.com',
  deviceId: 'device-xyz',
  raw: {},
  ...overrides,
});

const createMockConfig = (
  overrides: Partial<InsightIDRConnectorConfig> = {}
): InsightIDRConnectorConfig => ({
  type: 'insightidr',
  name: 'test-insightidr',
  enabled: true,
  region: 'us',
  logToken: 'test-log-token-12345',
  logSet: 'BrowserDefense',
  // Disable batching for unit tests (default is 100)
  batch: { maxSize: 1, maxWaitMs: 5000 },
  ...overrides,
});

// =============================================================================
// Event Transformation Tests
// =============================================================================

describe('transformToInsightIDRLog', () => {
  it('should transform ForensicsEvent to InsightIDR log format', () => {
    const event = createMockEvent();
    const log = transformToInsightIDRLog(event);

    expect(log.timestamp).toBe(new Date(event.timestamp).getTime());
    expect(log.message).toBe('BrowserDefense blocked navigation to https://malicious.example.com/payload');
    expect(log.blocked_url).toBe(event.blockedUrl);
    expect(log.redirect_chain).toEqual(event.redirectChain);
    expect(log.org_id).toBe(event.orgId);
    expect(log.event_id).toBe(event.eventId);
    expect(log.match_type).toBe(event.matchType);
    expect(log.matched_indicator).toBe(event.matchedIndicator);
    expect(log.user_id).toBe(event.userId);
    expect(log.device_id).toBe(event.deviceId);
  });

  it('should transform tab context correctly', () => {
    const event = createMockEvent();
    const log = transformToInsightIDRLog(event);

    expect(log.tab_context.tab_id).toBe(event.tabContext.tabId);
    expect(log.tab_context.window_id).toBe(event.tabContext.windowId);
    expect(log.tab_context.initiator_url).toBe(event.tabContext.initiatorUrl);
    expect(log.tab_context.tab_title).toBe(event.tabContext.tabTitle);
    expect(log.tab_context.incognito).toBe(event.tabContext.incognito);
  });

  it('should handle optional fields being undefined', () => {
    const event = createMockEvent({
      userId: undefined,
      deviceId: undefined,
      tabContext: {
        tabId: 1,
        windowId: 1,
        incognito: false,
        initiatorUrl: undefined,
        tabTitle: undefined,
      },
    });
    const log = transformToInsightIDRLog(event);

    expect(log.user_id).toBeUndefined();
    expect(log.device_id).toBeUndefined();
    expect(log.tab_context.initiator_url).toBeUndefined();
    expect(log.tab_context.tab_title).toBeUndefined();
  });

  it('should handle empty redirect chain', () => {
    const event = createMockEvent({ redirectChain: [] });
    const log = transformToInsightIDRLog(event);

    expect(log.redirect_chain).toEqual([]);
  });
});

// =============================================================================
// Connector Construction Tests
// =============================================================================

describe('InsightIDRConnector', () => {
  describe('construction', () => {
    it('should create connector with valid config', () => {
      const config = createMockConfig();
      const connector = new InsightIDRConnector(config);

      expect(connector.type).toBe('insightidr');
      expect(connector.name).toBe('test-insightidr');
    });

    it('should construct correct endpoint for US region', () => {
      const config = createMockConfig({ region: 'us' });
      const connector = new InsightIDRConnector(config);

      expect(connector.getEndpoint()).toBe(
        'https://us.data.logs.insight.rapid7.com/v1/noformat/test-log-token-12345'
      );
    });

    it('should construct correct endpoint for EU region', () => {
      const config = createMockConfig({ region: 'eu' });
      const connector = new InsightIDRConnector(config);

      expect(connector.getEndpoint()).toBe(
        'https://eu.data.logs.insight.rapid7.com/v1/noformat/test-log-token-12345'
      );
    });

    it('should construct correct endpoint for all regions', () => {
      const regionEndpoints: Record<string, string> = {
        us: 'us.data.logs.insight.rapid7.com',
        us2: 'us2.data.logs.insight.rapid7.com',
        us3: 'us3.data.logs.insight.rapid7.com',
        eu: 'eu.data.logs.insight.rapid7.com',
        ca: 'ca.data.logs.insight.rapid7.com',
        au: 'au.data.logs.insight.rapid7.com',
        ap: 'ap.data.logs.insight.rapid7.com',
      };

      for (const [region, host] of Object.entries(regionEndpoints)) {
        const config = createMockConfig({ region: region as any });
        const connector = new InsightIDRConnector(config);

        expect(connector.getEndpoint()).toBe(
          `https://${host}/v1/noformat/test-log-token-12345`
        );
      }
    });

    it('should throw on invalid region', () => {
      const config = createMockConfig({ region: 'invalid' as any });

      expect(() => new InsightIDRConnector(config)).toThrow('Invalid InsightIDR region');
    });
  });

  describe('initialization', () => {
    it('should initialize successfully with valid config', async () => {
      const connector = new InsightIDRConnector(createMockConfig());
      await expect(connector.init()).resolves.not.toThrow();
    });

    it('should reject initialization with empty log token', async () => {
      const config = createMockConfig({ logToken: '' });
      const connector = new InsightIDRConnector(config);

      await expect(connector.init()).rejects.toThrow('Invalid InsightIDR log token');
    });

    it('should reject initialization with short log token', async () => {
      const config = createMockConfig({ logToken: 'abc' });
      const connector = new InsightIDRConnector(config);

      await expect(connector.init()).rejects.toThrow('Invalid InsightIDR log token');
    });

    it('should prevent double initialization', async () => {
      const connector = new InsightIDRConnector(createMockConfig());
      await connector.init();

      await expect(connector.init()).rejects.toThrow('already initialized');
    });
  });
});

// =============================================================================
// HTTP Request Tests (with mocked fetch)
// =============================================================================

describe('InsightIDRConnector HTTP operations', () => {
  let connector: InsightIDRConnector;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);

    connector = new InsightIDRConnector(createMockConfig());
    await connector.init();
  });

  afterEach(async () => {
    await connector.close();
    vi.unstubAllGlobals();
  });

  describe('send', () => {
    it('should send event successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
      });

      const event = createMockEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe(event.eventId);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should include correct headers in request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
      });

      await connector.send(createMockEvent());

      const [url, options] = mockFetch.mock.calls[0];
      expect(options.method).toBe('POST');
      expect(options.headers['Content-Type']).toBe('application/json');
      expect(options.headers['X-Insight-Token']).toBe('test-log-token-12345');
    });

    it('should send transformed event body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
      });

      const event = createMockEvent();
      await connector.send(event);

      const [, options] = mockFetch.mock.calls[0];
      const body = JSON.parse(options.body);

      expect(body.blocked_url).toBe(event.blockedUrl);
      expect(body.org_id).toBe(event.orgId);
      expect(body.event_id).toBe(event.eventId);
    });

    it('should handle rate limiting (429) as retryable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
      });

      const result = await connector.send(createMockEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('Rate limited');
    });

    it('should handle server errors (5xx) as retryable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        text: vi.fn().mockResolvedValue('Server maintenance'),
      });

      const result = await connector.send(createMockEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('503');
    });

    it('should handle client errors (4xx) as non-retryable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        text: vi.fn().mockResolvedValue('Invalid token'),
      });

      const result = await connector.send(createMockEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
      expect(result.error).toContain('401');
    });

    it('should handle network errors as retryable', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const result = await connector.send(createMockEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('Network error');
    });
  });

  describe('sendBatch', () => {
    it('should send multiple events as NDJSON', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
      });

      const events = [
        createMockEvent({ eventId: 'event-1' }),
        createMockEvent({ eventId: 'event-2' }),
        createMockEvent({ eventId: 'event-3' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results).toHaveLength(3);
      expect(results.every((r) => r.success)).toBe(true);

      const [, options] = mockFetch.mock.calls[0];
      const lines = options.body.split('\n');
      expect(lines).toHaveLength(3);

      // Verify each line is valid JSON
      lines.forEach((line: string, index: number) => {
        const parsed = JSON.parse(line);
        expect(parsed.event_id).toBe(events[index].eventId);
      });
    });

    it('should handle batch failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: vi.fn().mockResolvedValue('Server error'),
      });

      const events = [
        createMockEvent({ eventId: 'event-1' }),
        createMockEvent({ eventId: 'event-2' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results).toHaveLength(2);
      expect(results.every((r) => !r.success)).toBe(true);
      expect(results.every((r) => r.retryable)).toBe(true);
    });

    it('should handle empty batch', async () => {
      const results = await connector.sendBatch([]);

      expect(results).toHaveLength(0);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('health check', () => {
    it('should report healthy when API responds successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
      });

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('healthy');
    });

    it('should report unhealthy when API returns error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
      });

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('401');
    });

    it('should report unhealthy on network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Connection refused');
    });
  });
});

// =============================================================================
// Filtering Tests
// =============================================================================

describe('InsightIDRConnector filtering', () => {
  let connector: InsightIDRConnector;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
    });
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(async () => {
    if (connector) {
      await connector.close();
    }
    vi.unstubAllGlobals();
  });

  it('should filter events by org ID', async () => {
    const config = createMockConfig({
      filter: {
        orgIds: ['allowed-org'],
      },
    });
    connector = new InsightIDRConnector(config);
    await connector.init();

    const allowedEvent = createMockEvent({ orgId: 'allowed-org' });
    const blockedEvent = createMockEvent({ orgId: 'blocked-org' });

    const result1 = await connector.send(allowedEvent);
    const result2 = await connector.send(blockedEvent);

    expect(result1.success).toBe(true);
    expect(result2.success).toBe(true);
    expect(result2.response).toEqual({ filtered: true });

    // Only one actual API call (for allowed event)
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('should filter events by match type', async () => {
    const config = createMockConfig({
      filter: {
        matchTypes: ['domain', 'url'],
      },
    });
    connector = new InsightIDRConnector(config);
    await connector.init();

    const domainEvent = createMockEvent({ matchType: 'domain' });
    const hashEvent = createMockEvent({ matchType: 'hash' });

    const result1 = await connector.send(domainEvent);
    const result2 = await connector.send(hashEvent);

    expect(result1.success).toBe(true);
    expect(result2.response).toEqual({ filtered: true });
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('should filter events by exclude patterns', async () => {
    const config = createMockConfig({
      filter: {
        excludePatterns: ['^https://internal\\.'],
      },
    });
    connector = new InsightIDRConnector(config);
    await connector.init();

    const externalEvent = createMockEvent({ blockedUrl: 'https://malware.com' });
    const internalEvent = createMockEvent({ blockedUrl: 'https://internal.company.com/test' });

    const result1 = await connector.send(externalEvent);
    const result2 = await connector.send(internalEvent);

    expect(result1.success).toBe(true);
    expect(result2.response).toEqual({ filtered: true });
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

// =============================================================================
// Factory Tests
// =============================================================================

describe('createInsightIDRConnector', () => {
  it('should create connector instance', () => {
    const config = createMockConfig();
    const connector = createInsightIDRConnector(config);

    expect(connector).toBeInstanceOf(InsightIDRConnector);
    expect(connector.type).toBe('insightidr');
  });
});

// =============================================================================
// Registry Tests
// =============================================================================

describe('InsightIDR connector registry', () => {
  it('should be registered in global registry', async () => {
    // Import the registry after the connector module to ensure registration
    const { connectorRegistry } = await import('../../src/connectors/base');

    expect(connectorRegistry.has('insightidr')).toBe(true);
  });

  it('should create connector via registry', async () => {
    const { connectorRegistry } = await import('../../src/connectors/base');

    const config = createMockConfig();
    const connector = connectorRegistry.create(config);

    expect(connector.type).toBe('insightidr');
    expect(connector.name).toBe('test-insightidr');
  });
});
