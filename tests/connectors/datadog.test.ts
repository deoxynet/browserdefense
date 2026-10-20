import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DatadogConnector, createDatadogConnector } from '../../src/connectors/datadog';
import type { DatadogConnectorConfig, ForensicsEvent } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestConfig(
  overrides: Partial<DatadogConnectorConfig> = {}
): DatadogConnectorConfig {
  return {
    name: 'test-datadog',
    type: 'datadog',
    enabled: true,
    site: 'datadoghq.com',
    apiKey: 'test-api-key-12345',
    service: 'browserdefense-test',
    source: 'browser-extension',
    hostname: 'test-host',
    tags: ['env:test', 'team:security'],
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

describe('DatadogConnector', () => {
  describe('constructor', () => {
    it('should create connector with correct type', () => {
      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      expect(connector.type).toBe('datadog');
    });

    it('should set name from config', () => {
      const config = createTestConfig({ name: 'my-datadog-connector' });
      const connector = new DatadogConnector(config);
      expect(connector.name).toBe('my-datadog-connector');
    });

    it('should construct correct API URL for US site', () => {
      const config = createTestConfig({ site: 'datadoghq.com' });
      const connector = new DatadogConnector(config);
      expect(connector.endpoint).toBe('https://http-intake.logs.datadoghq.com/api/v2/logs');
    });

    it('should construct correct API URL for EU site', () => {
      const config = createTestConfig({ site: 'datadoghq.eu' });
      const connector = new DatadogConnector(config);
      expect(connector.endpoint).toBe('https://http-intake.logs.datadoghq.eu/api/v2/logs');
    });

    it('should construct correct API URL for US3 site', () => {
      const config = createTestConfig({ site: 'us3.datadoghq.com' });
      const connector = new DatadogConnector(config);
      expect(connector.endpoint).toBe('https://http-intake.logs.us3.datadoghq.com/api/v2/logs');
    });
  });

  describe('init', () => {
    it('should succeed when API key is valid', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await expect(connector.init()).resolves.toBeUndefined();
    });

    it('should throw when API key is missing', async () => {
      const config = createTestConfig({ apiKey: '' });
      const connector = new DatadogConnector(config);
      await expect(connector.init()).rejects.toThrow('Datadog API key is required');
    });

    it('should throw when site is missing', async () => {
      const config = createTestConfig({ site: '' });
      const connector = new DatadogConnector(config);
      await expect(connector.init()).rejects.toThrow('Datadog site is required');
    });

    it('should throw when health check fails', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
      });

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await expect(connector.init()).rejects.toThrow('Datadog connectivity check failed');
    });

    it('should throw if init called twice', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();
      await expect(connector.init()).rejects.toThrow('already initialized');
    });
  });

  describe('send', () => {
    it('should send event successfully', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({ ok: true, status: 200 }); // send

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-12345');
    });

    it('should include API key in header', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({ ok: true, status: 200 }); // send

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      // Check the send call (second fetch)
      const sendCall = mockFetch.mock.calls[1];
      expect(sendCall[1].headers['DD-API-KEY']).toBe('test-api-key-12345');
    });

    it('should format log entry correctly', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({ ok: true, status: 200 }); // send

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      // Check the send call body
      const sendCall = mockFetch.mock.calls[1];
      const body = JSON.parse(sendCall[1].body);

      expect(Array.isArray(body)).toBe(true);
      expect(body.length).toBe(1);

      const logEntry = body[0];
      expect(logEntry.message).toContain('BrowserDefense');
      expect(logEntry.message).toContain('domain');
      expect(logEntry.message).toContain('malicious-site.com');
      expect(logEntry.ddsource).toBe('browser-extension');
      expect(logEntry.service).toBe('browserdefense-test');
      expect(logEntry.hostname).toBe('test-host');
    });

    it('should include proper tags', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({ ok: true, status: 200 }); // send

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      const sendCall = mockFetch.mock.calls[1];
      const body = JSON.parse(sendCall[1].body);
      const logEntry = body[0];

      // Check tags
      expect(logEntry.ddtags).toContain('match_type:domain');
      expect(logEntry.ddtags).toContain('org_id:org-123');
      expect(logEntry.ddtags).toContain('env:test');
      expect(logEntry.ddtags).toContain('team:security');
      expect(logEntry.ddtags).toContain('user_id:user-456');
      expect(logEntry.ddtags).toContain('device_id:device-789');
    });

    it('should include browserdefense attributes', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({ ok: true, status: 200 }); // send

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      const sendCall = mockFetch.mock.calls[1];
      const body = JSON.parse(sendCall[1].body);
      const logEntry = body[0];

      expect(logEntry.browserdefense).toBeDefined();
      expect(logEntry.browserdefense.event_id).toBe('evt-12345');
      expect(logEntry.browserdefense.blocked_url).toBe('https://malicious-site.com/phishing');
      expect(logEntry.browserdefense.matched_indicator).toBe('malicious-site.com');
      expect(logEntry.browserdefense.match_type).toBe('domain');
      expect(logEntry.browserdefense.redirect_chain).toEqual([
        'https://original.com',
        'https://redirect.com',
      ]);
    });

    it('should handle rate limiting with retryable result', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          headers: { get: () => '60' },
        });

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('Rate limited');
    });

    it('should handle auth errors as non-retryable', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({ ok: false, status: 403 });

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
      expect(result.error).toContain('Authentication failed');
    });

    it('should handle server errors as retryable', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({ ok: false, status: 503 });

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('Server error');
    });

    it('should handle network errors as retryable', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockRejectedValueOnce(new Error('Network timeout'));

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('Network error');
    });

    it('should throw if not initialized', async () => {
      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      const event = createTestEvent();

      await expect(connector.send(event)).rejects.toThrow('not initialized');
    });
  });

  describe('sendBatch', () => {
    it('should send multiple events in one request', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({ ok: true, status: 200 }); // batch send

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const events = [
        createTestEvent({ eventId: 'evt-1' }),
        createTestEvent({ eventId: 'evt-2' }),
        createTestEvent({ eventId: 'evt-3' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results.length).toBe(3);
      expect(results.every((r) => r.success)).toBe(true);

      // Check that all events were sent in one request
      const sendCall = mockFetch.mock.calls[1];
      const body = JSON.parse(sendCall[1].body);
      expect(body.length).toBe(3);
    });

    it('should filter events based on config', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // health check
        .mockResolvedValueOnce({ ok: true, status: 200 }); // batch send

      const config = createTestConfig({
        filter: {
          orgIds: ['org-123'],
        },
      });
      const connector = new DatadogConnector(config);
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
  });

  describe('health', () => {
    it('should return healthy status when API is reachable', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('Connected');
    });

    it('should return unhealthy status for invalid API key', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200 }) // init health check
        .mockResolvedValueOnce({ ok: false, status: 401 }); // subsequent health check

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Invalid API key');
    });

    it('should include metrics in health status', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      // Send some events to generate metrics
      await connector.send(createTestEvent({ eventId: 'evt-1' }));
      await connector.send(createTestEvent({ eventId: 'evt-2' }));

      const health = await connector.health();

      expect(health.metrics).toBeDefined();
      expect(health.metrics?.eventsSent).toBeGreaterThanOrEqual(0);
    });
  });

  describe('close', () => {
    it('should close gracefully', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();

      await expect(connector.close()).resolves.toBeUndefined();
    });

    it('should reject operations after close', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig();
      const connector = new DatadogConnector(config);
      await connector.init();
      await connector.close();

      const event = createTestEvent();
      await expect(connector.send(event)).rejects.toThrow('closed');
    });
  });

  describe('shouldProcess', () => {
    it('should filter by orgId', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig({
        filter: {
          orgIds: ['allowed-org'],
        },
      });
      const connector = new DatadogConnector(config);
      await connector.init();

      const allowedEvent = createTestEvent({ orgId: 'allowed-org' });
      const blockedEvent = createTestEvent({ orgId: 'blocked-org' });

      expect(connector.shouldProcess(allowedEvent)).toBe(true);
      expect(connector.shouldProcess(blockedEvent)).toBe(false);
    });

    it('should filter by matchType', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig({
        filter: {
          matchTypes: ['domain', 'url'],
        },
      });
      const connector = new DatadogConnector(config);
      await connector.init();

      const domainEvent = createTestEvent({ matchType: 'domain' });
      const hashEvent = createTestEvent({ matchType: 'hash' });

      expect(connector.shouldProcess(domainEvent)).toBe(true);
      expect(connector.shouldProcess(hashEvent)).toBe(false);
    });

    it('should filter by exclude patterns', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200 });

      const config = createTestConfig({
        filter: {
          excludePatterns: ['\\.internal\\.'],
        },
      });
      const connector = new DatadogConnector(config);
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

describe('createDatadogConnector', () => {
  it('should create DatadogConnector instance', () => {
    const config = createTestConfig();
    const connector = createDatadogConnector(config);
    expect(connector).toBeInstanceOf(DatadogConnector);
  });
});

describe('ConnectorRegistry', () => {
  it('should have datadog type registered', () => {
    // Import the datadog module to trigger registration
    expect(connectorRegistry.has('datadog')).toBe(true);
  });

  it('should create datadog connector from registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);
    expect(connector.type).toBe('datadog');
  });
});

describe('Action support (block/unblock)', () => {
  beforeEach(() => {
    mockFetch.mockResolvedValue({ ok: true, status: 200 });
  });

  it('should default to block action when not specified', async () => {
    const config = createTestConfig();
    const connector = new DatadogConnector(config);
    await connector.init();

    const event = createTestEvent(); // No action specified
    await connector.send(event);

    const sendCall = mockFetch.mock.calls[1];
    const body = JSON.parse(sendCall[1].body);
    const logEntry = body[0];

    expect(logEntry.ddtags).toContain('action:block');
    expect(logEntry.browserdefense.action).toBe('block');
    expect(logEntry.browserdefense.event_type).toBe('browserdefense:block');
    expect(logEntry.message).toContain('Blocked');
    expect(logEntry.status).toBe('warn');
  });

  it('should handle explicit block action', async () => {
    const config = createTestConfig();
    const connector = new DatadogConnector(config);
    await connector.init();

    const event = createTestEvent({ action: 'block' });
    await connector.send(event);

    const sendCall = mockFetch.mock.calls[1];
    const body = JSON.parse(sendCall[1].body);
    const logEntry = body[0];

    expect(logEntry.ddtags).toContain('action:block');
    expect(logEntry.browserdefense.action).toBe('block');
    expect(logEntry.browserdefense.event_type).toBe('browserdefense:block');
    expect(logEntry.message).toBe('BrowserDefense: Blocked domain - malicious-site.com');
    expect(logEntry.status).toBe('warn');
  });

  it('should handle unblock action', async () => {
    const config = createTestConfig();
    const connector = new DatadogConnector(config);
    await connector.init();

    const event = createTestEvent({ action: 'unblock' });
    await connector.send(event);

    const sendCall = mockFetch.mock.calls[1];
    const body = JSON.parse(sendCall[1].body);
    const logEntry = body[0];

    expect(logEntry.ddtags).toContain('action:unblock');
    expect(logEntry.browserdefense.action).toBe('unblock');
    expect(logEntry.browserdefense.event_type).toBe('browserdefense:unblock');
    expect(logEntry.message).toBe('BrowserDefense: Unblocked domain - malicious-site.com');
    expect(logEntry.status).toBe('info');
  });

  it('should use info severity for unblock events', async () => {
    const config = createTestConfig();
    const connector = new DatadogConnector(config);
    await connector.init();

    const event = createTestEvent({ action: 'unblock' });
    await connector.send(event);

    const sendCall = mockFetch.mock.calls[1];
    const body = JSON.parse(sendCall[1].body);

    expect(body[0].status).toBe('info');
  });

  it('should use warn severity for block events', async () => {
    const config = createTestConfig();
    const connector = new DatadogConnector(config);
    await connector.init();

    const event = createTestEvent({ action: 'block' });
    await connector.send(event);

    const sendCall = mockFetch.mock.calls[1];
    const body = JSON.parse(sendCall[1].body);

    expect(body[0].status).toBe('warn');
  });

  it('should include action in batch events', async () => {
    const config = createTestConfig();
    const connector = new DatadogConnector(config);
    await connector.init();

    const events = [
      createTestEvent({ eventId: 'evt-1', action: 'block' }),
      createTestEvent({ eventId: 'evt-2', action: 'unblock' }),
      createTestEvent({ eventId: 'evt-3' }), // defaults to block
    ];

    await connector.sendBatch(events);

    const sendCall = mockFetch.mock.calls[1];
    const body = JSON.parse(sendCall[1].body);

    expect(body[0].browserdefense.action).toBe('block');
    expect(body[1].browserdefense.action).toBe('unblock');
    expect(body[2].browserdefense.action).toBe('block');

    expect(body[0].message).toContain('Blocked');
    expect(body[1].message).toContain('Unblocked');
    expect(body[2].message).toContain('Blocked');
  });
});

describe('Event transformation edge cases', () => {
  beforeEach(() => {
    mockFetch.mockResolvedValue({ ok: true, status: 200 });
  });

  it('should handle event without optional fields', async () => {
    const config = createTestConfig({
      service: undefined,
      source: undefined,
      hostname: undefined,
      tags: undefined,
    });
    const connector = new DatadogConnector(config);
    await connector.init();

    const event = createTestEvent({
      userId: undefined,
      deviceId: undefined,
    });

    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[1];
    const body = JSON.parse(sendCall[1].body);
    const logEntry = body[0];

    // Should use defaults
    expect(logEntry.ddsource).toBe('browserdefense');
    expect(logEntry.service).toBe('browserdefense');
    // Should not include undefined tags
    expect(logEntry.ddtags).not.toContain('user_id:');
    expect(logEntry.ddtags).not.toContain('device_id:');
  });

  it('should handle URL match type', async () => {
    const config = createTestConfig();
    const connector = new DatadogConnector(config);
    await connector.init();

    const event = createTestEvent({
      matchType: 'url',
      matchedIndicator: 'https://malicious.com/phishing-page',
    });

    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[1];
    const body = JSON.parse(sendCall[1].body);
    expect(body[0].ddtags).toContain('match_type:url');
  });

  it('should handle hash match type', async () => {
    const config = createTestConfig();
    const connector = new DatadogConnector(config);
    await connector.init();

    const event = createTestEvent({
      matchType: 'hash',
      matchedIndicator: 'abc123def456',
    });

    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[1];
    const body = JSON.parse(sendCall[1].body);
    expect(body[0].ddtags).toContain('match_type:hash');
  });

  it('should extract domain for network attributes', async () => {
    const config = createTestConfig();
    const connector = new DatadogConnector(config);
    await connector.init();

    const event = createTestEvent({
      blockedUrl: 'https://evil-domain.com:8443/path?query=1',
    });

    const result = await connector.send(event);
    expect(result.success).toBe(true);

    const sendCall = mockFetch.mock.calls[1];
    const body = JSON.parse(sendCall[1].body);
    expect(body[0].network.destination.domain).toBe('evil-domain.com');
  });
});
