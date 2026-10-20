/**
 * Tests for Sumo Logic Connector
 *
 * Tests the SumoLogicConnector implementation including:
 * - Configuration validation
 * - Event transformation
 * - HTTP Source API integration
 * - Batch sending
 * - Health checks
 * - Error handling and retries
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  SumoLogicConnector,
  createSumoLogicConnector,
  SumoLogicEvent,
} from '../../src/connectors/sumologic';
import {
  ForensicsEvent,
  SumoLogicConnectorConfig,
} from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

/**
 * Create a mock forensics event for testing.
 */
function createMockEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    blockedUrl: 'https://malicious.example.com/phishing',
    timestamp: '2024-01-15T10:30:00.000Z',
    redirectChain: ['https://original.com', 'https://redirect.com'],
    tabContext: {
      tabId: 123,
      windowId: 1,
      initiatorUrl: 'https://safe-site.com',
      tabTitle: 'Test Page',
      incognito: false,
    },
    orgId: 'org-123',
    eventId: 'evt-abc123',
    matchType: 'domain',
    matchedIndicator: 'malicious.example.com',
    raw: {},
    ...overrides,
  };
}

/**
 * Create a mock connector config for testing.
 * Note: batch.maxSize is set to 1 to disable buffering for unit tests.
 */
function createMockConfig(
  overrides: Partial<SumoLogicConnectorConfig> = {}
): SumoLogicConnectorConfig {
  return {
    type: 'sumologic',
    name: 'test-sumo-connector',
    enabled: true,
    httpSourceUrl: 'https://collectors.sumologic.com/receiver/v1/http/test-token',
    sourceCategory: 'security/browserdefense',
    sourceName: 'browserdefense-test',
    sourceHost: 'test-host',
    // Disable batching for unit tests to send events immediately
    batch: { maxSize: 1, maxWaitMs: 5000 },
    ...overrides,
  };
}

// =============================================================================
// Mock fetch
// =============================================================================

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// =============================================================================
// Tests: Connector Creation and Configuration
// =============================================================================

describe('SumoLogicConnector', () => {
  describe('creation and configuration', () => {
    it('should create connector with valid config', () => {
      const config = createMockConfig();
      const connector = new SumoLogicConnector(config);

      expect(connector.name).toBe('test-sumo-connector');
      expect(connector.type).toBe('sumologic');
    });

    it('should use default values for optional config', () => {
      const config = createMockConfig({
        sourceCategory: undefined,
        sourceName: undefined,
        sourceHost: undefined,
      });
      const connector = new SumoLogicConnector(config);

      expect(connector.name).toBe('test-sumo-connector');
    });

    it('should be registered in connector registry', () => {
      expect(connectorRegistry.has('sumologic')).toBe(true);
    });

    it('should create connector via factory function', () => {
      const config = createMockConfig();
      const connector = createSumoLogicConnector(config);

      expect(connector).toBeInstanceOf(SumoLogicConnector);
      expect(connector.name).toBe('test-sumo-connector');
    });

    it('should create connector via registry', () => {
      const config = createMockConfig();
      const connector = connectorRegistry.create(config);

      expect(connector.type).toBe('sumologic');
    });
  });

  // ===========================================================================
  // Tests: Initialization
  // ===========================================================================

  describe('initialization', () => {
    it('should initialize successfully with valid URL', async () => {
      const connector = new SumoLogicConnector(createMockConfig());

      await expect(connector.init()).resolves.not.toThrow();
    });

    it('should throw error for missing HTTP Source URL', async () => {
      const config = createMockConfig({ httpSourceUrl: '' });
      const connector = new SumoLogicConnector(config);

      await expect(connector.init()).rejects.toThrow(
        'Sumo Logic HTTP Source URL is required'
      );
    });

    it('should throw error for invalid URL format', async () => {
      const config = createMockConfig({ httpSourceUrl: 'not-a-valid-url' });
      const connector = new SumoLogicConnector(config);

      await expect(connector.init()).rejects.toThrow('Invalid Sumo Logic HTTP Source URL');
    });

    it('should warn for non-sumologic URLs', async () => {
      const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const config = createMockConfig({
        httpSourceUrl: 'https://custom-endpoint.example.com/events',
      });
      const connector = new SumoLogicConnector(config);

      await connector.init();

      expect(consoleWarn).toHaveBeenCalledWith(
        expect.stringContaining('does not appear to be a Sumo Logic endpoint')
      );

      consoleWarn.mockRestore();
    });

    it('should not allow double initialization', async () => {
      const connector = new SumoLogicConnector(createMockConfig());
      await connector.init();

      await expect(connector.init()).rejects.toThrow('already initialized');
    });
  });

  // ===========================================================================
  // Tests: Event Sending
  // ===========================================================================

  describe('event sending', () => {
    let connector: SumoLogicConnector;

    beforeEach(async () => {
      connector = new SumoLogicConnector(createMockConfig());
      await connector.init();
    });

    it('should send event successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
      });

      const event = createMockEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-abc123');
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should send correct headers', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      await connector.send(createMockEvent());

      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toContain('sumologic.com');
      expect(options.method).toBe('POST');
      expect(options.headers['Content-Type']).toBe('application/json');
      expect(options.headers['X-Sumo-Category']).toBe('security/browserdefense');
      expect(options.headers['X-Sumo-Name']).toBe('browserdefense-test');
      expect(options.headers['X-Sumo-Host']).toBe('test-host');
    });

    it('should transform event to Sumo Logic format', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      await connector.send(createMockEvent());

      const [, options] = mockFetch.mock.calls[0];
      const payload: SumoLogicEvent = JSON.parse(options.body);

      expect(payload.eventType).toBe('browserdefense:block');
      expect(payload.blockedUrl).toBe('https://malicious.example.com/phishing');
      expect(payload.matchType).toBe('domain');
      expect(payload.matchedIndicator).toBe('malicious.example.com');
      expect(payload.orgId).toBe('org-123');
      expect(payload.eventId).toBe('evt-abc123');
      expect(payload.redirectChain).toEqual([
        'https://original.com',
        'https://redirect.com',
      ]);
      expect(payload.tabContext.tabId).toBe(123);
    });

    it('should include optional userId and deviceId', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      await connector.send(
        createMockEvent({
          userId: 'user-456',
          deviceId: 'device-789',
        })
      );

      const [, options] = mockFetch.mock.calls[0];
      const payload: SumoLogicEvent = JSON.parse(options.body);

      expect(payload.userId).toBe('user-456');
      expect(payload.deviceId).toBe('device-789');
    });

    it('should include custom fields from config', async () => {
      const configWithFields = createMockConfig({
        fields: {
          environment: 'production',
          region: 'us-west-2',
        },
      });
      const connectorWithFields = new SumoLogicConnector(configWithFields);
      await connectorWithFields.init();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      await connectorWithFields.send(createMockEvent());

      const [, options] = mockFetch.mock.calls[0];
      const payload: SumoLogicEvent = JSON.parse(options.body);

      expect(payload.fields).toEqual({
        environment: 'production',
        region: 'us-west-2',
      });

      // Also check X-Sumo-Fields header
      expect(options.headers['X-Sumo-Fields']).toContain('environment=production');
      expect(options.headers['X-Sumo-Fields']).toContain('region=us-west-2');
    });

    it('should handle 500 error as retryable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: () => Promise.resolve('Server error'),
      });

      const result = await connector.send(createMockEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('500');
    });

    it('should handle 429 rate limit as retryable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        text: () => Promise.resolve('Rate limited'),
      });

      const result = await connector.send(createMockEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should handle 400 error as non-retryable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: () => Promise.resolve('Invalid payload'),
      });

      const result = await connector.send(createMockEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
    });

    it('should handle network errors as retryable', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const result = await connector.send(createMockEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('Network error');
    });

    it('should throw if not initialized', async () => {
      const uninitConnector = new SumoLogicConnector(createMockConfig());

      await expect(uninitConnector.send(createMockEvent())).rejects.toThrow(
        'not initialized'
      );
    });
  });

  // ===========================================================================
  // Tests: Batch Sending
  // ===========================================================================

  describe('batch sending', () => {
    let connector: SumoLogicConnector;

    beforeEach(async () => {
      connector = new SumoLogicConnector(createMockConfig());
      await connector.init();
    });

    it('should send batch as newline-delimited JSON', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      const events = [
        createMockEvent({ eventId: 'evt-1' }),
        createMockEvent({ eventId: 'evt-2' }),
        createMockEvent({ eventId: 'evt-3' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results).toHaveLength(3);
      expect(results.every((r) => r.success)).toBe(true);

      // Verify newline-delimited format
      const [, options] = mockFetch.mock.calls[0];
      const lines = options.body.split('\n');
      expect(lines).toHaveLength(3);

      // Each line should be valid JSON
      for (const line of lines) {
        expect(() => JSON.parse(line)).not.toThrow();
      }
    });

    it('should include batch size in response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      const events = [
        createMockEvent({ eventId: 'evt-1' }),
        createMockEvent({ eventId: 'evt-2' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results[0].response?.batchSize).toBe(2);
    });

    it('should handle batch failure for all events', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        text: () => Promise.resolve('Service down'),
      });

      const events = [
        createMockEvent({ eventId: 'evt-1' }),
        createMockEvent({ eventId: 'evt-2' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results).toHaveLength(2);
      expect(results.every((r) => !r.success)).toBe(true);
      expect(results.every((r) => r.retryable)).toBe(true);
    });

    it('should filter events in batch', async () => {
      const configWithFilter = createMockConfig({
        filter: {
          orgIds: ['org-allowed'],
        },
      });
      const connectorWithFilter = new SumoLogicConnector(configWithFilter);
      await connectorWithFilter.init();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      const events = [
        createMockEvent({ eventId: 'evt-1', orgId: 'org-allowed' }),
        createMockEvent({ eventId: 'evt-2', orgId: 'org-blocked' }),
      ];

      const results = await connectorWithFilter.sendBatch(events);

      expect(results).toHaveLength(2);

      // evt-1 should be sent
      const sent = results.find((r) => r.eventId === 'evt-1');
      expect(sent?.success).toBe(true);
      expect(sent?.response?.filtered).toBeUndefined();

      // evt-2 should be filtered
      const filtered = results.find((r) => r.eventId === 'evt-2');
      expect(filtered?.success).toBe(true);
      expect(filtered?.response?.filtered).toBe(true);
    });

    it('should return filtered results for all events if all filtered', async () => {
      const configWithFilter = createMockConfig({
        filter: {
          orgIds: ['org-other'],
        },
      });
      const connectorWithFilter = new SumoLogicConnector(configWithFilter);
      await connectorWithFilter.init();

      const events = [
        createMockEvent({ eventId: 'evt-1', orgId: 'org-123' }),
        createMockEvent({ eventId: 'evt-2', orgId: 'org-123' }),
      ];

      const results = await connectorWithFilter.sendBatch(events);

      expect(results).toHaveLength(2);
      expect(results.every((r) => r.response?.filtered)).toBe(true);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // Tests: Health Check
  // ===========================================================================

  describe('health check', () => {
    let connector: SumoLogicConnector;

    beforeEach(async () => {
      connector = new SumoLogicConnector(createMockConfig());
      await connector.init();
    });

    it('should report healthy when endpoint is reachable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('reachable');
    });

    it('should send empty body for health check', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      await connector.health();

      const [, options] = mockFetch.mock.calls[0];
      expect(options.body).toBe('');
    });

    it('should report healthy for 4xx responses (endpoint reachable)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
      });

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('endpoint reachable');
    });

    it('should report unhealthy for 5xx responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
      });

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('503');
    });

    it('should report unhealthy on network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Connection refused');
    });

    it('should include metrics in health response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      const health = await connector.health();

      expect(health.metrics).toBeDefined();
      expect(typeof health.metrics?.eventsSent).toBe('number');
      expect(typeof health.metrics?.eventsFailed).toBe('number');
      expect(typeof health.metrics?.uptimeSeconds).toBe('number');
    });
  });

  // ===========================================================================
  // Tests: Filtering
  // ===========================================================================

  describe('event filtering', () => {
    it('should filter by orgId', async () => {
      const config = createMockConfig({
        filter: {
          orgIds: ['org-allowed'],
        },
      });
      const connector = new SumoLogicConnector(config);
      await connector.init();

      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      // Allowed org should be sent
      const allowedResult = await connector.send(
        createMockEvent({ orgId: 'org-allowed' })
      );
      expect(allowedResult.response?.filtered).toBeUndefined();
      expect(mockFetch).toHaveBeenCalledTimes(1);

      mockFetch.mockClear();

      // Blocked org should be filtered
      const blockedResult = await connector.send(
        createMockEvent({ orgId: 'org-blocked' })
      );
      expect(blockedResult.success).toBe(true);
      expect(blockedResult.response?.filtered).toBe(true);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should filter by match type', async () => {
      const config = createMockConfig({
        filter: {
          matchTypes: ['domain', 'url'],
        },
      });
      const connector = new SumoLogicConnector(config);
      await connector.init();

      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      // domain match should be sent
      await connector.send(createMockEvent({ matchType: 'domain' }));
      expect(mockFetch).toHaveBeenCalledTimes(1);

      mockFetch.mockClear();

      // hash match should be filtered
      const hashResult = await connector.send(
        createMockEvent({ matchType: 'hash' })
      );
      expect(hashResult.response?.filtered).toBe(true);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should filter by exclude patterns', async () => {
      const config = createMockConfig({
        filter: {
          excludePatterns: ['^https://internal\\.'],
        },
      });
      const connector = new SumoLogicConnector(config);
      await connector.init();

      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      // Internal URL should be filtered
      const internalResult = await connector.send(
        createMockEvent({ blockedUrl: 'https://internal.example.com/test' })
      );
      expect(internalResult.response?.filtered).toBe(true);
      expect(mockFetch).not.toHaveBeenCalled();

      // External URL should be sent
      await connector.send(
        createMockEvent({ blockedUrl: 'https://external.example.com/test' })
      );
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  // ===========================================================================
  // Tests: Connector Lifecycle
  // ===========================================================================

  describe('lifecycle', () => {
    it('should close gracefully', async () => {
      const connector = new SumoLogicConnector(createMockConfig());
      await connector.init();

      await expect(connector.close()).resolves.not.toThrow();
    });

    it('should allow multiple close calls', async () => {
      const connector = new SumoLogicConnector(createMockConfig());
      await connector.init();

      await connector.close();
      await expect(connector.close()).resolves.not.toThrow();
    });

    it('should throw if used after close', async () => {
      const connector = new SumoLogicConnector(createMockConfig());
      await connector.init();
      await connector.close();

      await expect(connector.send(createMockEvent())).rejects.toThrow('closed');
    });
  });
});
