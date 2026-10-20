/**
 * Tests for VMware Carbon Black Cloud Connector
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  CarbonBlackConnector,
  CarbonBlackApiError,
  connectorRegistry,
} from '../../src/connectors';
import type {
  CarbonBlackConnectorConfig,
  ForensicsEvent,
} from '../../src/connectors/types';

// =============================================================================
// Test Fixtures
// =============================================================================

const createTestConfig = (
  overrides: Partial<CarbonBlackConnectorConfig> = {}
): CarbonBlackConnectorConfig => ({
  type: 'carbonblack',
  name: 'test-cb-connector',
  enabled: true,
  url: 'https://defense-test.conferdeploy.net',
  orgKey: 'TESTORG123',
  apiId: 'test-api-id',
  apiSecret: 'test-api-secret',
  feedId: 'test-feed',
  // Disable batching for tests to get immediate sends
  batch: {
    maxSize: 1,
    maxWaitMs: 0,
  },
  ...overrides,
});

const createTestEvent = (
  overrides: Partial<ForensicsEvent> = {}
): ForensicsEvent => ({
  eventId: 'evt-12345',
  blockedUrl: 'https://malware.example.com/payload',
  timestamp: '2024-01-15T10:30:00Z',
  matchType: 'domain',
  matchedIndicator: 'malware.example.com',
  redirectChain: [],
  orgId: 'org-123',
  tabContext: {
    tabId: 1,
    windowId: 1,
    incognito: false,
    initiatorUrl: 'https://legitimate.com',
    tabTitle: 'Test Page',
  },
  raw: {},
  ...overrides,
});

// =============================================================================
// Mock Setup
// =============================================================================

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

/**
 * Create a mock fetch response.
 */
const mockResponse = (status: number, body: unknown = {}, ok = status < 400) => {
  return Promise.resolve({
    ok,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    text: () => Promise.resolve(JSON.stringify(body)),
    json: () => Promise.resolve(body),
  });
};

// =============================================================================
// Tests
// =============================================================================

describe('CarbonBlackConnector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('constructor', () => {
    it('should create connector with default values', () => {
      const connector = new CarbonBlackConnector(createTestConfig());
      expect(connector.name).toBe('test-cb-connector');
      expect(connector.type).toBe('carbonblack');
    });

    it('should use provided feedId', () => {
      const connector = new CarbonBlackConnector(
        createTestConfig({ feedId: 'custom-feed' })
      );
      expect(connector.name).toBe('test-cb-connector');
    });

    it('should default feedId to browserdefense if not provided', () => {
      const config = createTestConfig();
      delete config.feedId;
      const connector = new CarbonBlackConnector(config);
      expect(connector.name).toBe('test-cb-connector');
    });
  });

  describe('init', () => {
    it('should validate organization and ensure feed exists', async () => {
      // Mock successful org validation
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] })) // org validation
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} })); // feed exists

      const connector = new CarbonBlackConnector(createTestConfig());
      await connector.init();

      expect(mockFetch).toHaveBeenCalledTimes(2);
      // Check org validation call
      expect(mockFetch.mock.calls[0][0]).toContain('/appservices/v6/orgs/TESTORG123/alerts');
      // Check feed check call
      expect(mockFetch.mock.calls[1][0]).toContain('/threathunter/feedmgr/v2/orgs/TESTORG123/feeds/test-feed');
    });

    it('should create feed if it does not exist', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] })) // org validation
        .mockResolvedValueOnce(mockResponse(404, {}, false)) // feed not found
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} })); // feed created

      const connector = new CarbonBlackConnector(createTestConfig());
      await connector.init();

      expect(mockFetch).toHaveBeenCalledTimes(3);
      // Check feed creation call
      const createCall = mockFetch.mock.calls[2];
      expect(createCall[0]).toContain('/threathunter/feedmgr/v2/orgs/TESTORG123/feeds');
      expect(createCall[1].method).toBe('POST');
    });

    it('should throw on invalid credentials', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(401, { error: 'Unauthorized' }, false));

      const connector = new CarbonBlackConnector(createTestConfig());
      await expect(connector.init()).rejects.toThrow('Invalid Carbon Black API credentials');
    });

    it('should throw on insufficient permissions', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(403, { error: 'Forbidden' }, false));

      const connector = new CarbonBlackConnector(createTestConfig());
      await expect(connector.init()).rejects.toThrow('Insufficient permissions');
    });

    it('should throw on organization not found', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(404, { error: 'Not found' }, false));

      const connector = new CarbonBlackConnector(createTestConfig());
      await expect(connector.init()).rejects.toThrow('organization not found');
    });

    it('should not allow double initialization', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      const connector = new CarbonBlackConnector(createTestConfig());
      await connector.init();

      await expect(connector.init()).rejects.toThrow('already initialized');
    });
  });

  describe('send', () => {
    let connector: CarbonBlackConnector;

    beforeEach(async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      connector = new CarbonBlackConnector(createTestConfig());
      await connector.init();
      mockFetch.mockClear();
    });

    it('should send event as threat intelligence report', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(200, { success: true }));

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-12345');
      expect(result.response).toHaveProperty('reportId');
      expect(result.response).toHaveProperty('feedId', 'test-feed');

      // Verify API call
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toContain('/threathunter/feedmgr/v2/orgs/TESTORG123/feeds/test-feed/reports');
      expect(options.method).toBe('POST');

      // Verify auth header format
      expect(options.headers['X-Auth-Token']).toBe('test-api-secret/test-api-id');

      // Verify report body
      const body = JSON.parse(options.body);
      expect(body.id).toContain('browserdefense-evt-12345');
      expect(body.title).toContain('BrowserDefense:');
      expect(body.iocs_v2).toBeInstanceOf(Array);
      expect(body.iocs_v2.length).toBeGreaterThan(0);
      expect(body.tags).toContain('browserdefense');
    });

    it('should create domain IOC for domain match type', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(200, { success: true }));

      const event = createTestEvent({
        matchType: 'domain',
        matchedIndicator: 'evil.example.com',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      const ioc = body.iocs_v2[0];
      expect(ioc.field).toBe('netconn_domain');
      expect(ioc.values).toContain('evil.example.com');
    });

    it('should extract domain for URL match type', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(200, { success: true }));

      const event = createTestEvent({
        matchType: 'url',
        blockedUrl: 'https://phishing.example.org/login',
        matchedIndicator: 'https://phishing.example.org/login',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      const ioc = body.iocs_v2[0];
      expect(ioc.field).toBe('netconn_domain');
      expect(ioc.values).toContain('phishing.example.org');
    });

    it('should create hash IOC for hash match type', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(200, { success: true }));

      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: 'abc123hash',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      const ioc = body.iocs_v2[0];
      expect(ioc.field).toBe('process_hash');
      expect(ioc.values).toContain('abc123hash');
    });

    it('should include redirect chain domains as IOCs', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(200, { success: true }));

      const event = createTestEvent({
        redirectChain: [
          'https://legit.com/click',
          'https://redirect1.com/hop',
          'https://redirect2.net/landing',
        ],
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      // Should have at least 2 IOCs: main indicator + redirect chain
      expect(body.iocs_v2.length).toBeGreaterThanOrEqual(2);

      const chainIoc = body.iocs_v2.find((ioc: { id: string }) => ioc.id.includes('chain'));
      expect(chainIoc).toBeDefined();
      expect(chainIoc.values).toContain('redirect1.com');
      expect(chainIoc.values).toContain('redirect2.net');
    });

    it('should handle API errors gracefully', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(500, { error: 'Server error' }, false));

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Carbon Black API error');
      expect(result.retryable).toBe(true); // 500 errors are retryable
    });

    it('should mark 429 rate limit errors as retryable', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(429, { error: 'Rate limited' }, false));

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should mark 400 errors as non-retryable', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(400, { error: 'Bad request' }, false));

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
    });

    it('should use custom severity and tags from config', async () => {
      // Re-create connector with custom settings
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      const customConnector = new CarbonBlackConnector(
        createTestConfig({
          defaultSeverity: 8,
          tags: ['custom-tag', 'threat-intel'],
        })
      );
      await customConnector.init();
      mockFetch.mockClear();

      mockFetch.mockResolvedValueOnce(mockResponse(200, { success: true }));

      await customConnector.send(createTestEvent());

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.severity).toBe(8);
      expect(body.tags).toContain('custom-tag');
      expect(body.tags).toContain('threat-intel');
    });

    it('should include event details in description', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(200, { success: true }));

      const event = createTestEvent({
        userId: 'user@company.com',
        deviceId: 'device-abc-123',
        tabContext: {
          tabId: 1,
          windowId: 1,
          incognito: false,
          initiatorUrl: 'https://email.example.com/link',
          tabTitle: 'Email Link',
        },
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.description).toContain('malware.example.com');
      expect(body.description).toContain('user@company.com');
      expect(body.description).toContain('device-abc-123');
      expect(body.description).toContain('email.example.com');
    });
  });

  describe('sendBatch', () => {
    let connector: CarbonBlackConnector;

    beforeEach(async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      connector = new CarbonBlackConnector(createTestConfig());
      await connector.init();
      mockFetch.mockClear();
    });

    it('should send multiple events', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { success: true }))
        .mockResolvedValueOnce(mockResponse(200, { success: true }))
        .mockResolvedValueOnce(mockResponse(200, { success: true }));

      const events = [
        createTestEvent({ eventId: 'evt-1' }),
        createTestEvent({ eventId: 'evt-2' }),
        createTestEvent({ eventId: 'evt-3' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results).toHaveLength(3);
      expect(results.every((r) => r.success)).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should handle partial failures', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { success: true }))
        .mockResolvedValueOnce(mockResponse(500, { error: 'Server error' }, false))
        .mockResolvedValueOnce(mockResponse(200, { success: true }));

      const events = [
        createTestEvent({ eventId: 'evt-1' }),
        createTestEvent({ eventId: 'evt-2' }),
        createTestEvent({ eventId: 'evt-3' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results).toHaveLength(3);
      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(false);
      expect(results[2].success).toBe(true);
    });
  });

  describe('health', () => {
    let connector: CarbonBlackConnector;

    beforeEach(async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      connector = new CarbonBlackConnector(createTestConfig());
      await connector.init();
      mockFetch.mockClear();
    });

    it('should return healthy status when API is accessible', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(200, { results: [] }));

      const status = await connector.health();

      expect(status.healthy).toBe(true);
      expect(status.message).toContain('Connected to Carbon Black Cloud');
      expect(status.message).toContain('TESTORG123');
      expect(status.metrics).toBeDefined();
    });

    it('should return unhealthy status when API fails', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(503, { error: 'Service unavailable' }, false));

      const status = await connector.health();

      expect(status.healthy).toBe(false);
      expect(status.message).toContain('health check failed');
    });

    it('should track metrics after sending events', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { success: true }))
        .mockResolvedValueOnce(mockResponse(200, { success: true }))
        .mockResolvedValueOnce(mockResponse(200, { results: [] }));

      await connector.send(createTestEvent({ eventId: 'evt-1' }));
      await connector.send(createTestEvent({ eventId: 'evt-2' }));

      const status = await connector.health();

      expect(status.metrics?.eventsSent).toBe(2);
      expect(status.metrics?.eventsFailed).toBe(0);
    });
  });

  describe('shouldProcess (filtering)', () => {
    it('should filter by org ID', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      const connector = new CarbonBlackConnector(
        createTestConfig({
          filter: {
            orgIds: ['allowed-org-1', 'allowed-org-2'],
          },
        })
      );
      await connector.init();

      // Event from allowed org
      const allowedEvent = createTestEvent({ orgId: 'allowed-org-1' });
      expect(connector.shouldProcess(allowedEvent)).toBe(true);

      // Event from non-allowed org
      const blockedEvent = createTestEvent({ orgId: 'other-org' });
      expect(connector.shouldProcess(blockedEvent)).toBe(false);
    });

    it('should filter by match type', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      const connector = new CarbonBlackConnector(
        createTestConfig({
          filter: {
            matchTypes: ['domain', 'hash'],
          },
        })
      );
      await connector.init();

      expect(connector.shouldProcess(createTestEvent({ matchType: 'domain' }))).toBe(true);
      expect(connector.shouldProcess(createTestEvent({ matchType: 'hash' }))).toBe(true);
      expect(connector.shouldProcess(createTestEvent({ matchType: 'url' }))).toBe(false);
    });

    it('should filter by exclude patterns', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      const connector = new CarbonBlackConnector(
        createTestConfig({
          filter: {
            excludePatterns: ['\\.internal\\.', 'localhost'],
          },
        })
      );
      await connector.init();

      // Should be excluded
      expect(
        connector.shouldProcess(
          createTestEvent({ blockedUrl: 'https://test.internal.company.com/page' })
        )
      ).toBe(false);
      expect(
        connector.shouldProcess(createTestEvent({ blockedUrl: 'http://localhost:8080/api' }))
      ).toBe(false);

      // Should be allowed
      expect(
        connector.shouldProcess(
          createTestEvent({ blockedUrl: 'https://malware.example.com/payload' })
        )
      ).toBe(true);
    });
  });

  describe('unblock', () => {
    let connector: CarbonBlackConnector;

    beforeEach(async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      connector = new CarbonBlackConnector(createTestConfig());
      await connector.init();
      mockFetch.mockClear();
    });

    it('should support unblock operations', () => {
      expect(connector.supportsUnblock).toBe(true);
    });

    it('should delete report on unblock', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(200, {}));

      const event = createTestEvent({ eventId: 'evt-12345' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-12345');
      expect(result.alreadyClosed).toBe(false);
      expect(result.incidentId).toBe('browserdefense-evt-12345');

      // Verify DELETE API call
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toContain('/threathunter/feedmgr/v2/orgs/TESTORG123/feeds/test-feed/reports/browserdefense-evt-12345');
      expect(options.method).toBe('DELETE');
    });

    it('should handle idempotent unblock (already deleted)', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(404, { error: 'Not found' }, false));

      const event = createTestEvent({ eventId: 'evt-already-gone' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(true);
      expect(result.alreadyClosed).toBe(true);
      expect(result.incidentId).toBe('browserdefense-evt-already-gone');
    });

    it('should handle API errors on unblock', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(500, { error: 'Server error' }, false));

      const event = createTestEvent({ eventId: 'evt-error' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Carbon Black API error');
      expect(result.retryable).toBe(true);
      expect(result.incidentId).toBe('browserdefense-evt-error');
    });

    it('should mark 400 errors as non-retryable on unblock', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(400, { error: 'Bad request' }, false));

      const event = createTestEvent({ eventId: 'evt-bad' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
    });

    it('should use deterministic report ID from eventId', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(200, {}));

      const event = createTestEvent({ eventId: 'unique-event-id-123' });
      await connector.unblock(event);

      const [url] = mockFetch.mock.calls[0];
      expect(url).toContain('browserdefense-unique-event-id-123');
    });
  });

  describe('close', () => {
    it('should close gracefully', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      const connector = new CarbonBlackConnector(createTestConfig());
      await connector.init();

      await expect(connector.close()).resolves.not.toThrow();
    });

    it('should not allow operations after close', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse(200, { results: [] }))
        .mockResolvedValueOnce(mockResponse(200, { feedinfo: {} }));

      const connector = new CarbonBlackConnector(createTestConfig());
      await connector.init();
      await connector.close();

      await expect(connector.send(createTestEvent())).rejects.toThrow('has been closed');
    });
  });

  describe('registry', () => {
    it('should be registered in the connector registry', () => {
      expect(connectorRegistry.has('carbonblack')).toBe(true);
    });

    it('should create connector from registry', () => {
      const connector = connectorRegistry.create(createTestConfig());
      expect(connector).toBeInstanceOf(CarbonBlackConnector);
      expect(connector.type).toBe('carbonblack');
    });
  });
});

describe('CarbonBlackApiError', () => {
  it('should store status code and response body', () => {
    const error = new CarbonBlackApiError('Test error', 401, '{"error": "unauthorized"}');

    expect(error.message).toBe('Test error');
    expect(error.statusCode).toBe(401);
    expect(error.responseBody).toBe('{"error": "unauthorized"}');
    expect(error.name).toBe('CarbonBlackApiError');
  });
});
