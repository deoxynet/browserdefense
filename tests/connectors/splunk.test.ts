import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SplunkConnector, createSplunkConnector } from '../../src/connectors/splunk';
import type { SplunkConnectorConfig, ForensicsEvent } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestConfig(
  overrides: Partial<SplunkConnectorConfig> = {}
): SplunkConnectorConfig {
  return {
    name: 'test-splunk',
    type: 'splunk',
    enabled: true,
    hecUrl: 'https://splunk.example.com:8088/services/collector/event',
    hecToken: 'test-hec-token-12345',
    index: 'security',
    sourceType: 'browserdefense:forensics',
    source: 'browserdefense-extension',
    host: 'test-host',
    // Disable batching for tests to get direct send behavior
    batch: { maxSize: 1, maxWaitMs: 0 },
    // Disable retries for most tests
    retry: { maxAttempts: 0, initialDelayMs: 0, maxDelayMs: 0, backoffMultiplier: 1 },
    ...overrides,
  };
}

function createTestEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    eventId: 'evt-12345',
    blockedUrl: 'https://malicious-site.com/phishing',
    timestamp: '2024-01-15T10:30:00.000Z',
    redirectChain: ['https://original.com', 'https://redirect.com'],
    tabContext: {
      tabId: 1,
      windowId: 1,
      initiatorUrl: 'https://email.example.com',
      tabTitle: 'Inbox',
      incognito: false,
    },
    orgId: 'org-123',
    matchType: 'domain',
    matchedIndicator: 'malicious-site.com',
    userId: 'user-456',
    deviceId: 'device-789',
    raw: {},
    ...overrides,
  };
}

// Mock successful Splunk HEC response
function mockSuccessResponse(): Response {
  return new Response(JSON.stringify({ text: 'Success', code: 0 }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

// Mock Splunk HEC health check response (400 with code 5 = no data, means HEC is working)
function mockHealthCheckResponse(): Response {
  return new Response(JSON.stringify({ text: 'No data', code: 5 }), {
    status: 400,
    headers: { 'Content-Type': 'application/json' },
  });
}

// =============================================================================
// Mock Fetch
// =============================================================================

const mockFetch = vi.fn();

beforeEach(() => {
  global.fetch = mockFetch;
  mockFetch.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// =============================================================================
// Tests
// =============================================================================

describe('SplunkConnector', () => {
  describe('constructor', () => {
    it('should create connector with correct type', () => {
      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      expect(connector.type).toBe('splunk');
    });

    it('should set name from config', () => {
      const config = createTestConfig({ name: 'my-splunk-connector' });
      const connector = new SplunkConnector(config);
      expect(connector.name).toBe('my-splunk-connector');
    });

    it('should normalize HEC URL with /event endpoint', () => {
      const config = createTestConfig({
        hecUrl: 'https://splunk.example.com:8088/services/collector/event',
      });
      const connector = new SplunkConnector(config);
      expect(connector.endpoint).toBe('https://splunk.example.com:8088/services/collector/event');
    });

    it('should normalize HEC URL without /event endpoint', () => {
      const config = createTestConfig({
        hecUrl: 'https://splunk.example.com:8088/services/collector',
      });
      const connector = new SplunkConnector(config);
      expect(connector.endpoint).toBe('https://splunk.example.com:8088/services/collector/event');
    });

    it('should normalize HEC URL from base URL only', () => {
      const config = createTestConfig({
        hecUrl: 'https://splunk.example.com:8088',
      });
      const connector = new SplunkConnector(config);
      expect(connector.endpoint).toBe('https://splunk.example.com:8088/services/collector/event');
    });

    it('should strip trailing slash from URL', () => {
      const config = createTestConfig({
        hecUrl: 'https://splunk.example.com:8088/',
      });
      const connector = new SplunkConnector(config);
      expect(connector.endpoint).toBe('https://splunk.example.com:8088/services/collector/event');
    });

    it('should expose index from config', () => {
      const config = createTestConfig({ index: 'custom_index' });
      const connector = new SplunkConnector(config);
      expect(connector.index).toBe('custom_index');
    });

    it('should expose sourceType from config', () => {
      const config = createTestConfig({ sourceType: 'custom:sourcetype' });
      const connector = new SplunkConnector(config);
      expect(connector.sourceType).toBe('custom:sourcetype');
    });
  });

  describe('init', () => {
    it('should succeed when HEC is reachable', async () => {
      // Health check response (400 with code 5 indicates HEC is working)
      mockFetch.mockResolvedValueOnce(
        new Response('', { status: 404 }) // Health endpoint not found
      ).mockResolvedValueOnce(mockHealthCheckResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await expect(connector.init()).resolves.toBeUndefined();
    });

    it('should throw when HEC URL is missing', async () => {
      const config = createTestConfig({ hecUrl: '' });
      const connector = new SplunkConnector(config);
      await expect(connector.init()).rejects.toThrow('Splunk HEC URL is required');
    });

    it('should throw when HEC token is missing', async () => {
      const config = createTestConfig({ hecToken: '' });
      const connector = new SplunkConnector(config);
      await expect(connector.init()).rejects.toThrow('Splunk HEC token is required');
    });

    it('should throw when HEC URL is invalid', async () => {
      const config = createTestConfig({ hecUrl: 'not-a-url' });
      const connector = new SplunkConnector(config);
      await expect(connector.init()).rejects.toThrow('Invalid Splunk HEC URL');
    });

    it('should throw when health check fails', async () => {
      mockFetch.mockResolvedValueOnce(
        new Response('', { status: 404 }) // Health endpoint not found
      ).mockResolvedValueOnce(
        new Response(JSON.stringify({ text: 'Invalid token', code: 4 }), { status: 401 })
      );

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await expect(connector.init()).rejects.toThrow('Splunk HEC connectivity check failed');
    });

    it('should throw if init called twice', async () => {
      mockFetch.mockResolvedValue(mockHealthCheckResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();
      await expect(connector.init()).rejects.toThrow('already initialized');
    });
  });

  describe('send', () => {
    it('should send event successfully', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 })) // health endpoint
        .mockResolvedValueOnce(mockHealthCheckResponse()) // health check
        .mockResolvedValueOnce(mockSuccessResponse()); // send

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-12345');
    });

    it('should include Authorization header with HEC token', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(mockSuccessResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      // Check the send call (third fetch - after health endpoint + health check)
      const sendCall = mockFetch.mock.calls[2];
      expect(sendCall[1].headers['Authorization']).toBe('Splunk test-hec-token-12345');
    });

    it('should format HEC event correctly', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(mockSuccessResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      const sendCall = mockFetch.mock.calls[2];
      const body = JSON.parse(sendCall[1].body);

      // Check HEC wrapper fields
      expect(body.time).toBeDefined();
      expect(typeof body.time).toBe('number');
      expect(body.index).toBe('security');
      expect(body.sourcetype).toBe('browserdefense:forensics');
      expect(body.source).toBe('browserdefense-extension');
      expect(body.host).toBe('test-host');

      // Check event payload
      expect(body.event).toBeDefined();
      expect(body.event.event_type).toBe('browserdefense:block');
      expect(body.event.event_id).toBe('evt-12345');
      expect(body.event.blocked_url).toBe('https://malicious-site.com/phishing');
      expect(body.event.matched_indicator).toBe('malicious-site.com');
      expect(body.event.match_type).toBe('domain');
    });

    it('should convert timestamp to epoch seconds', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(mockSuccessResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent({ timestamp: '2024-01-15T10:30:00.000Z' });
      await connector.send(event);

      const sendCall = mockFetch.mock.calls[2];
      const body = JSON.parse(sendCall[1].body);

      // 2024-01-15T10:30:00.000Z in epoch seconds
      const expectedTime = new Date('2024-01-15T10:30:00.000Z').getTime() / 1000;
      expect(body.time).toBe(expectedTime);
    });

    it('should include CIM-compliant fields', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(mockSuccessResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      const sendCall = mockFetch.mock.calls[2];
      const body = JSON.parse(sendCall[1].body);

      expect(body.event.severity).toBe('medium');
      expect(body.event.action).toBe('blocked');
      expect(body.event.product).toBe('BrowserDefense');
      expect(body.event.vendor).toBe('BrowserDefense');
    });

    it('should include tab context', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(mockSuccessResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      const sendCall = mockFetch.mock.calls[2];
      const body = JSON.parse(sendCall[1].body);

      expect(body.event.tab_context).toBeDefined();
      expect(body.event.tab_context.tab_id).toBe(1);
      expect(body.event.tab_context.window_id).toBe(1);
      expect(body.event.tab_context.initiator_url).toBe('https://email.example.com');
      expect(body.event.tab_context.tab_title).toBe('Inbox');
      expect(body.event.tab_context.incognito).toBe(false);
    });

    it('should include optional user and device IDs', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(mockSuccessResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent({
        userId: 'user-456',
        deviceId: 'device-789',
      });
      await connector.send(event);

      const sendCall = mockFetch.mock.calls[2];
      const body = JSON.parse(sendCall[1].body);

      expect(body.event.user_id).toBe('user-456');
      expect(body.event.device_id).toBe('device-789');
    });

    it('should handle rate limiting with retryable result', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(
          new Response('', {
            status: 429,
            headers: { 'Retry-After': '60' },
          })
        );

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('Rate limited');
    });

    it('should handle auth errors as non-retryable', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ text: 'Invalid token', code: 4 }), { status: 401 })
        );

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
      expect(result.error).toContain('Authentication failed');
    });

    it('should handle forbidden errors as non-retryable', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ text: 'Forbidden', code: 3 }), { status: 403 })
        );

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
      expect(result.error).toContain('Forbidden');
    });

    it('should handle server errors as retryable', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(
          new Response('Internal Server Error', { status: 500 })
        );

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('Server error');
    });

    it('should handle HEC error code 8 (internal server error) as retryable', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ text: 'Internal server error', code: 8 }), { status: 200 })
        );

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should handle HEC error code 9 (server busy) as retryable', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ text: 'Server busy', code: 9 }), { status: 200 })
        );

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should handle network errors as retryable', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockRejectedValueOnce(new Error('Network timeout'));

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('Network error');
    });

    it('should throw if not initialized', async () => {
      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      const event = createTestEvent();

      await expect(connector.send(event)).rejects.toThrow('not initialized');
    });
  });

  describe('sendBatch', () => {
    it('should send multiple events in one request', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(mockSuccessResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const events = [
        createTestEvent({ eventId: 'evt-1' }),
        createTestEvent({ eventId: 'evt-2' }),
        createTestEvent({ eventId: 'evt-3' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results.length).toBe(3);
      expect(results.every((r) => r.success)).toBe(true);
    });

    it('should concatenate events without delimiters for HEC', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(mockSuccessResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const events = [
        createTestEvent({ eventId: 'evt-1' }),
        createTestEvent({ eventId: 'evt-2' }),
      ];

      await connector.sendBatch(events);

      const sendCall = mockFetch.mock.calls[2];
      const body = sendCall[1].body;

      // Splunk HEC expects concatenated JSON objects without delimiters
      // Verify we can parse the body by splitting on }{ and re-joining
      expect(body).toContain('}{');
      const parts = body.split('}{').map((p: string, i: number, arr: string[]) => {
        if (i === 0) return p + '}';
        if (i === arr.length - 1) return '{' + p;
        return '{' + p + '}';
      });
      expect(parts.length).toBe(2);
      parts.forEach((p: string) => {
        const parsed = JSON.parse(p);
        expect(parsed.event).toBeDefined();
      });
    });

    it('should filter events based on config', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(mockSuccessResponse());

      const config = createTestConfig({
        filter: {
          orgIds: ['org-123'],
        },
      });
      const connector = new SplunkConnector(config);
      await connector.init();

      const events = [
        createTestEvent({ eventId: 'evt-1', orgId: 'org-123' }),
        createTestEvent({ eventId: 'evt-2', orgId: 'org-other' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results.length).toBe(2);

      // Find the result for the filtered event
      const filteredResult = results.find((r) => r.eventId === 'evt-2');
      expect(filteredResult?.response).toEqual({ filtered: true });
    });

    it('should handle batch failure for all events', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ text: 'Server busy', code: 9 }), { status: 200 })
        );

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const events = [
        createTestEvent({ eventId: 'evt-1' }),
        createTestEvent({ eventId: 'evt-2' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results.every((r) => !r.success)).toBe(true);
      expect(results.every((r) => r.retryable)).toBe(true);
    });
  });

  describe('health', () => {
    it('should return healthy status when HEC is reachable', async () => {
      mockFetch.mockResolvedValue(mockHealthCheckResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
    });

    it('should return unhealthy status for auth failure', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse()) // init health check
        .mockResolvedValueOnce(new Response('', { status: 404 })) // subsequent health
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ text: 'Invalid token', code: 4 }), { status: 401 })
        );

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('authentication');
    });

    it('should include metrics in health status', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse())
        .mockResolvedValueOnce(mockSuccessResponse())
        .mockResolvedValueOnce(mockSuccessResponse())
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      // Send some events
      await connector.send(createTestEvent({ eventId: 'evt-1' }));
      await connector.send(createTestEvent({ eventId: 'evt-2' }));

      const health = await connector.health();

      expect(health.metrics).toBeDefined();
      expect(health.metrics?.eventsSent).toBeGreaterThanOrEqual(0);
    });
  });

  describe('close', () => {
    it('should close gracefully', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();

      await expect(connector.close()).resolves.toBeUndefined();
    });

    it('should reject operations after close', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse());

      const config = createTestConfig();
      const connector = new SplunkConnector(config);
      await connector.init();
      await connector.close();

      const event = createTestEvent();
      await expect(connector.send(event)).rejects.toThrow('closed');
    });
  });

  describe('shouldProcess', () => {
    it('should filter by orgId', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse());

      const config = createTestConfig({
        filter: {
          orgIds: ['allowed-org'],
        },
      });
      const connector = new SplunkConnector(config);
      await connector.init();

      const allowedEvent = createTestEvent({ orgId: 'allowed-org' });
      const blockedEvent = createTestEvent({ orgId: 'blocked-org' });

      expect(connector.shouldProcess(allowedEvent)).toBe(true);
      expect(connector.shouldProcess(blockedEvent)).toBe(false);
    });

    it('should filter by matchType', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse());

      const config = createTestConfig({
        filter: {
          matchTypes: ['domain', 'url'],
        },
      });
      const connector = new SplunkConnector(config);
      await connector.init();

      const domainEvent = createTestEvent({ matchType: 'domain' });
      const hashEvent = createTestEvent({ matchType: 'hash' });

      expect(connector.shouldProcess(domainEvent)).toBe(true);
      expect(connector.shouldProcess(hashEvent)).toBe(false);
    });

    it('should filter by exclude patterns', async () => {
      mockFetch
        .mockResolvedValueOnce(new Response('', { status: 404 }))
        .mockResolvedValueOnce(mockHealthCheckResponse());

      const config = createTestConfig({
        filter: {
          excludePatterns: ['\\.internal\\.'],
        },
      });
      const connector = new SplunkConnector(config);
      await connector.init();

      const externalEvent = createTestEvent({
        blockedUrl: 'https://malicious.external.com',
      });
      const internalEvent = createTestEvent({
        blockedUrl: 'https://test.internal.example.com',
      });

      expect(connector.shouldProcess(externalEvent)).toBe(true);
      expect(connector.shouldProcess(internalEvent)).toBe(false);
    });
  });
});

describe('createSplunkConnector', () => {
  it('should create SplunkConnector instance', () => {
    const config = createTestConfig();
    const connector = createSplunkConnector(config);
    expect(connector).toBeInstanceOf(SplunkConnector);
  });
});

describe('ConnectorRegistry', () => {
  it('should have splunk type registered', () => {
    // Import the splunk module to trigger registration
    expect(connectorRegistry.has('splunk')).toBe(true);
  });

  it('should create splunk connector from registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);
    expect(connector.type).toBe('splunk');
  });
});

describe('Event transformation edge cases', () => {
  beforeEach(() => {
    mockFetch
      .mockResolvedValueOnce(new Response('', { status: 404 }))
      .mockResolvedValueOnce(mockHealthCheckResponse())
      .mockResolvedValue(mockSuccessResponse());
  });

  it('should handle event without optional fields', async () => {
    const config = createTestConfig({
      index: undefined,
      sourceType: undefined,
      source: undefined,
      host: undefined,
    });
    const connector = new SplunkConnector(config);
    await connector.init();

    const event = createTestEvent({
      userId: undefined,
      deviceId: undefined,
    });

    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);

    // Should not include undefined fields
    expect(body.index).toBeUndefined();
    expect(body.sourcetype).toBeUndefined();
    expect(body.source).toBeUndefined();
    expect(body.host).toBeUndefined();
    expect(body.event.user_id).toBeUndefined();
    expect(body.event.device_id).toBeUndefined();
  });

  it('should handle URL match type', async () => {
    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const event = createTestEvent({
      matchType: 'url',
      matchedIndicator: 'https://malicious.com/phishing-page',
    });

    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);
    expect(body.event.match_type).toBe('url');
  });

  it('should handle hash match type', async () => {
    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const event = createTestEvent({
      matchType: 'hash',
      matchedIndicator: 'abc123def456',
    });

    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);
    expect(body.event.match_type).toBe('hash');
  });

  it('should include redirect chain', async () => {
    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const event = createTestEvent({
      redirectChain: ['https://start.com', 'https://middle.com', 'https://end.com'],
    });

    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);
    expect(body.event.redirect_chain).toEqual([
      'https://start.com',
      'https://middle.com',
      'https://end.com',
    ]);
  });

  it('should handle incognito mode', async () => {
    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const event = createTestEvent({
      tabContext: {
        tabId: 1,
        windowId: 1,
        incognito: true,
      },
    });

    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);
    expect(body.event.tab_context.incognito).toBe(true);
  });
});

describe('HEC error codes', () => {
  beforeEach(() => {
    mockFetch
      .mockResolvedValueOnce(new Response('', { status: 404 }))
      .mockResolvedValueOnce(mockHealthCheckResponse());
  });

  it('should handle HEC code 1 (token disabled) as non-retryable', async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ text: 'Token disabled', code: 1 }), { status: 200 })
    );

    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const result = await connector.send(createTestEvent());
    expect(result.success).toBe(false);
    expect(result.retryable).toBe(false);
  });

  it('should handle HEC code 7 (incorrect index) as non-retryable', async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ text: 'Incorrect index', code: 7 }), { status: 200 })
    );

    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const result = await connector.send(createTestEvent());
    expect(result.success).toBe(false);
    expect(result.retryable).toBe(false);
  });

  it('should handle HEC code 18 (queues full) as retryable', async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ text: 'HEC is unhealthy, queues are full', code: 18 }), { status: 200 })
    );

    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const result = await connector.send(createTestEvent());
    expect(result.success).toBe(false);
    expect(result.retryable).toBe(true);
  });
});

describe('Block/Unblock action support', () => {
  beforeEach(() => {
    mockFetch
      .mockResolvedValueOnce(new Response('', { status: 404 }))
      .mockResolvedValueOnce(mockHealthCheckResponse())
      .mockResolvedValue(mockSuccessResponse());
  });

  it('should emit browserdefense:unblock event type for unblock action', async () => {
    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const event = createTestEvent({ action: 'unblock' });
    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);

    expect(body.event.event_type).toBe('browserdefense:unblock');
  });

  it('should emit unblocked action for unblock event', async () => {
    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const event = createTestEvent({ action: 'unblock' });
    await connector.send(event);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);

    expect(body.event.action).toBe('unblocked');
  });

  it('should set informational severity for unblock events', async () => {
    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const event = createTestEvent({ action: 'unblock' });
    await connector.send(event);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);

    expect(body.event.severity).toBe('informational');
  });

  it('should emit browserdefense:block event type for block action', async () => {
    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const event = createTestEvent({ action: 'block' });
    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);

    expect(body.event.event_type).toBe('browserdefense:block');
    expect(body.event.action).toBe('blocked');
    expect(body.event.severity).toBe('medium');
  });

  it('should default to block when action is not specified', async () => {
    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    // Create event without action field (backwards compatibility)
    const event = createTestEvent();
    delete (event as Partial<ForensicsEvent>).action;

    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);

    expect(body.event.event_type).toBe('browserdefense:block');
    expect(body.event.action).toBe('blocked');
    expect(body.event.severity).toBe('medium');
  });

  it('should preserve all other fields in unblock events', async () => {
    const config = createTestConfig();
    const connector = new SplunkConnector(config);
    await connector.init();

    const event = createTestEvent({
      action: 'unblock',
      eventId: 'unblock-evt-123',
      matchedIndicator: 'example.com',
    });
    await connector.send(event);

    const sendCall = mockFetch.mock.calls[2];
    const body = JSON.parse(sendCall[1].body);

    // Verify unblock-specific fields
    expect(body.event.event_type).toBe('browserdefense:unblock');
    expect(body.event.action).toBe('unblocked');

    // Verify other fields are preserved
    expect(body.event.event_id).toBe('unblock-evt-123');
    expect(body.event.matched_indicator).toBe('example.com');
    expect(body.event.product).toBe('BrowserDefense');
    expect(body.event.vendor).toBe('BrowserDefense');
    expect(body.event.tab_context).toBeDefined();
  });
});
