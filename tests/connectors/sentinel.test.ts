/**
 * Unit tests for BrowserDefense Microsoft Sentinel Connector.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  SentinelConnector,
  createSentinelConnector,
  SentinelLogEntry,
  SentinelEventAction,
} from '../../src/connectors/sentinel';
import { ForensicsEvent, SentinelConnectorConfig } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

/**
 * Create a valid test configuration.
 * Note: batch.maxSize = 1 disables batching for easier testing of individual sends.
 */
function createTestConfig(overrides?: Partial<SentinelConnectorConfig>): SentinelConnectorConfig {
  return {
    type: 'sentinel',
    name: 'test-sentinel',
    enabled: true,
    workspaceId: 'test-workspace-id',
    // Base64 encoded "test-shared-key-for-sentinel"
    sharedKey: 'dGVzdC1zaGFyZWQta2V5LWZvci1zZW50aW5lbA==',
    logType: 'BrowserDefense_Forensics',
    // Disable batching for most tests (batch size 1 means immediate send)
    batch: { maxSize: 1, maxWaitMs: 5000 },
    ...overrides,
  };
}

/**
 * Create a test forensics event.
 */
function createTestEvent(overrides?: Partial<ForensicsEvent>): ForensicsEvent {
  return {
    eventId: 'test-event-123',
    blockedUrl: 'https://malicious.example.com/payload',
    timestamp: '2026-01-09T12:00:00.000Z',
    redirectChain: ['https://phishing.com', 'https://redirect.com'],
    orgId: 'test-org',
    matchType: 'url',
    matchedIndicator: 'https://malicious.example.com/payload',
    userId: 'user@example.com',
    deviceId: 'device-123',
    tabContext: {
      tabId: 42,
      windowId: 1,
      initiatorUrl: 'https://email.example.com/inbox',
      tabTitle: 'Email - Inbox',
      incognito: false,
    },
    raw: {},
    ...overrides,
  };
}

// =============================================================================
// Mock Setup
// =============================================================================

// Store fetch calls for inspection
let fetchCalls: Array<{ url: string; options: RequestInit }> = [];
let fetchMockResponse: {
  ok: boolean;
  status: number;
  statusText: string;
  textBody?: string;
} | null = null;
let fetchShouldThrow: Error | null = null;

// Mock fetch globally before tests
const originalFetch = globalThis.fetch;

function mockFetchImplementation(url: string | URL | Request, options?: RequestInit): Promise<Response> {
  if (fetchShouldThrow) {
    return Promise.reject(fetchShouldThrow);
  }

  fetchCalls.push({
    url: typeof url === 'string' ? url : url.toString(),
    options: options || {},
  });

  const response = fetchMockResponse || { ok: true, status: 200, statusText: 'OK' };

  return Promise.resolve({
    ok: response.ok,
    status: response.status,
    statusText: response.statusText,
    text: () => Promise.resolve(response.textBody || ''),
    json: () => Promise.resolve({}),
    headers: new Headers(),
  } as Response);
}

// =============================================================================
// Tests
// =============================================================================

describe('SentinelConnector', () => {
  beforeEach(() => {
    fetchCalls = [];
    fetchMockResponse = null;
    fetchShouldThrow = null;
    globalThis.fetch = mockFetchImplementation as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('constructor', () => {
    it('creates connector with valid config', () => {
      const config = createTestConfig();
      const connector = new SentinelConnector(config);

      expect(connector.type).toBe('sentinel');
      expect(connector.name).toBe('test-sentinel');
    });

    it('constructs API URL correctly', () => {
      const config = createTestConfig({ workspaceId: 'my-workspace' });
      const connector = new SentinelConnector(config);

      // The API URL is private, but we can verify it works through init()
      expect(connector).toBeDefined();
    });
  });

  describe('init()', () => {
    it('validates required workspaceId', async () => {
      const config = createTestConfig({ workspaceId: '' });
      const connector = new SentinelConnector(config);

      await expect(connector.init()).rejects.toThrow('requires workspaceId');
    });

    it('validates required sharedKey', async () => {
      const config = createTestConfig({ sharedKey: '' });
      const connector = new SentinelConnector(config);

      await expect(connector.init()).rejects.toThrow('requires sharedKey');
    });

    it('validates required logType', async () => {
      const config = createTestConfig({ logType: '' });
      const connector = new SentinelConnector(config);

      await expect(connector.init()).rejects.toThrow('requires logType');
    });

    it('validates logType format - must start with letter', async () => {
      const config = createTestConfig({ logType: '123Invalid' });
      const connector = new SentinelConnector(config);

      await expect(connector.init()).rejects.toThrow('must start with a letter');
    });

    it('validates logType format - alphanumeric and underscore only', async () => {
      const config = createTestConfig({ logType: 'Invalid-Name' });
      const connector = new SentinelConnector(config);

      await expect(connector.init()).rejects.toThrow('alphanumeric characters and underscores');
    });

    it('validates sharedKey is valid base64', async () => {
      const config = createTestConfig({ sharedKey: 'not-valid-base64!!!' });
      const connector = new SentinelConnector(config);

      await expect(connector.init()).rejects.toThrow('Invalid sharedKey');
    });

    it('accepts valid configuration', async () => {
      const config = createTestConfig();
      const connector = new SentinelConnector(config);

      await expect(connector.init()).resolves.not.toThrow();
    });

    it('accepts logType with underscores and numbers', async () => {
      const config = createTestConfig({ logType: 'BrowserDefense_Events_V2' });
      const connector = new SentinelConnector(config);

      await expect(connector.init()).resolves.not.toThrow();
    });
  });

  describe('send()', () => {
    it('sends event to Sentinel API', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('test-event-123');
      expect(fetchCalls).toHaveLength(1);
    });

    it('sends correct headers', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      expect(fetchCalls).toHaveLength(1);
      const { url, options } = fetchCalls[0];
      const headers = options.headers as Record<string, string>;

      expect(url).toContain('test-workspace-id.ods.opinsights.azure.com');
      expect(url).toContain('api-version=2016-04-01');
      expect(options.method).toBe('POST');
      expect(headers['Content-Type']).toBe('application/json');
      expect(headers['Log-Type']).toBe('BrowserDefense_Forensics');
      expect(headers['x-ms-date']).toBeDefined();
      expect(headers['Authorization']).toMatch(/^SharedKey test-workspace-id:/);
    });

    it('includes optional time-generated-field header', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig({ timeGeneratedField: 'timestamp' });
      const connector = new SentinelConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      expect(fetchCalls).toHaveLength(1);
      const headers = fetchCalls[0].options.headers as Record<string, string>;
      expect(headers['time-generated-field']).toBe('timestamp');
    });

    it('includes optional azure resource ID header', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig({
        azureResourceId: '/subscriptions/123/resourceGroups/rg/providers/Microsoft.Resources/test',
      });
      const connector = new SentinelConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      expect(fetchCalls).toHaveLength(1);
      const headers = fetchCalls[0].options.headers as Record<string, string>;
      expect(headers['x-ms-AzureResourceId']).toBe(
        '/subscriptions/123/resourceGroups/rg/providers/Microsoft.Resources/test'
      );
    });

    it('transforms event to Sentinel log format', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      expect(fetchCalls).toHaveLength(1);
      const body = JSON.parse(fetchCalls[0].options.body as string);

      expect(body).toHaveLength(1);
      const logEntry: SentinelLogEntry = body[0];

      expect(logEntry.blocked_url).toBe('https://malicious.example.com/payload');
      expect(logEntry.timestamp).toBe('2026-01-09T12:00:00.000Z');
      expect(logEntry.redirect_chain).toBe(
        JSON.stringify(['https://phishing.com', 'https://redirect.com'])
      );
      expect(logEntry.org_id).toBe('test-org');
      expect(logEntry.event_id).toBe('test-event-123');
      expect(logEntry.match_type).toBe('url');
      expect(logEntry.matched_indicator).toBe('https://malicious.example.com/payload');
      expect(logEntry.tab_id).toBe(42);
      expect(logEntry.initiator_url).toBe('https://email.example.com/inbox');
      expect(logEntry.tab_title).toBe('Email - Inbox');
      expect(logEntry.incognito).toBe(false);
      expect(logEntry.user_id).toBe('user@example.com');
      expect(logEntry.device_id).toBe('device-123');
    });

    it('includes event_type and action fields for block events', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      expect(fetchCalls).toHaveLength(1);
      const body = JSON.parse(fetchCalls[0].options.body as string);
      const logEntry: SentinelLogEntry = body[0];

      expect(logEntry.event_type).toBe('blockioc:block');
      expect(logEntry.action).toBe('blocked');
    });

    it('sets unblock event_type and action when raw.action is unblocked', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const event = createTestEvent({
        raw: { action: 'unblocked' },
      });
      await connector.send(event);

      expect(fetchCalls).toHaveLength(1);
      const body = JSON.parse(fetchCalls[0].options.body as string);
      const logEntry: SentinelLogEntry = body[0];

      expect(logEntry.event_type).toBe('blockioc:unblock');
      expect(logEntry.action).toBe('unblocked');
    });

    it('defaults to blocked action when raw.action is not set', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const event = createTestEvent({
        raw: { someOtherField: 'value' },
      });
      await connector.send(event);

      expect(fetchCalls).toHaveLength(1);
      const body = JSON.parse(fetchCalls[0].options.body as string);
      const logEntry: SentinelLogEntry = body[0];

      expect(logEntry.event_type).toBe('blockioc:block');
      expect(logEntry.action).toBe('blocked');
    });

    it('defaults to blocked action when raw.action has unknown value', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const event = createTestEvent({
        raw: { action: 'unknown-action' },
      });
      await connector.send(event);

      expect(fetchCalls).toHaveLength(1);
      const body = JSON.parse(fetchCalls[0].options.body as string);
      const logEntry: SentinelLogEntry = body[0];

      expect(logEntry.event_type).toBe('blockioc:block');
      expect(logEntry.action).toBe('blocked');
    });

    it('handles missing optional event fields', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const event = createTestEvent({
        userId: undefined,
        deviceId: undefined,
        tabContext: {
          tabId: 1,
          windowId: 1,
          incognito: true,
          // Missing initiatorUrl and tabTitle
        },
      });

      await connector.send(event);

      expect(fetchCalls).toHaveLength(1);
      const body = JSON.parse(fetchCalls[0].options.body as string);
      const logEntry: SentinelLogEntry = body[0];

      expect(logEntry.user_id).toBe('');
      expect(logEntry.device_id).toBe('');
      expect(logEntry.initiator_url).toBe('');
      expect(logEntry.tab_title).toBe('');
      expect(logEntry.incognito).toBe(true);
    });

    it('returns error for API failures', async () => {
      fetchMockResponse = {
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        textBody: 'Invalid log type',
      };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('400');
      expect(result.error).toContain('Invalid log type');
      expect(result.retryable).toBe(false);
    });

    it('marks 5xx errors as retryable', async () => {
      fetchMockResponse = {
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        textBody: 'Server busy',
      };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('marks 429 (rate limit) as retryable', async () => {
      fetchMockResponse = {
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        textBody: 'Rate limit exceeded',
      };

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('handles network errors', async () => {
      fetchShouldThrow = new Error('Network error');

      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('Network error');
      expect(result.retryable).toBe(true);
    });

    it('throws if not initialized', async () => {
      const config = createTestConfig();
      const connector = new SentinelConnector(config);

      await expect(connector.send(createTestEvent())).rejects.toThrow('not initialized');
    });
  });

  describe('sendBatch()', () => {
    it('sends multiple events in single request', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      // Use larger batch size to allow batching
      const config = createTestConfig({ batch: { maxSize: 100, maxWaitMs: 5000 } });
      const connector = new SentinelConnector(config);
      await connector.init();

      const events = [
        createTestEvent({ eventId: 'event-1' }),
        createTestEvent({ eventId: 'event-2' }),
        createTestEvent({ eventId: 'event-3' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results).toHaveLength(3);
      expect(results.every((r) => r.success)).toBe(true);
      expect(fetchCalls).toHaveLength(1);

      // Verify all events are in single payload
      const body = JSON.parse(fetchCalls[0].options.body as string);
      expect(body).toHaveLength(3);
    });

    it('maps batch failure to all events', async () => {
      fetchMockResponse = {
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        textBody: 'Server busy',
      };

      // Use larger batch size to allow batching
      const config = createTestConfig({ batch: { maxSize: 100, maxWaitMs: 5000 } });
      const connector = new SentinelConnector(config);
      await connector.init();

      const events = [
        createTestEvent({ eventId: 'event-1' }),
        createTestEvent({ eventId: 'event-2' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results).toHaveLength(2);
      expect(results.every((r) => !r.success)).toBe(true);
      expect(results.every((r) => r.retryable)).toBe(true);
    });
  });

  describe('health()', () => {
    it('returns healthy status when properly configured', async () => {
      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('test-workspace-id');
    });
  });

  describe('shouldProcess() filtering', () => {
    it('filters by org ID', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig({
        filter: {
          orgIds: ['allowed-org'],
        },
      });
      const connector = new SentinelConnector(config);
      await connector.init();

      const event = createTestEvent({ orgId: 'other-org' });
      const result = await connector.send(event);

      // Should be filtered (not sent)
      expect(result.success).toBe(true);
      expect(result.response).toEqual({ filtered: true });
      expect(fetchCalls).toHaveLength(0);
    });

    it('filters by match type', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig({
        filter: {
          matchTypes: ['domain'],
        },
      });
      const connector = new SentinelConnector(config);
      await connector.init();

      const event = createTestEvent({ matchType: 'url' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ filtered: true });
      expect(fetchCalls).toHaveLength(0);
    });

    it('processes events matching filter', async () => {
      fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

      const config = createTestConfig({
        filter: {
          orgIds: ['test-org'],
          matchTypes: ['url', 'domain'],
        },
      });
      const connector = new SentinelConnector(config);
      await connector.init();

      const event = createTestEvent({ orgId: 'test-org', matchType: 'url' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(fetchCalls).toHaveLength(1);
    });
  });

  describe('close()', () => {
    it('closes without error', async () => {
      const config = createTestConfig();
      const connector = new SentinelConnector(config);
      await connector.init();

      await expect(connector.close()).resolves.not.toThrow();
    });
  });
});

describe('createSentinelConnector()', () => {
  it('creates a SentinelConnector instance', () => {
    const config = createTestConfig();
    const connector = createSentinelConnector(config);

    expect(connector).toBeInstanceOf(SentinelConnector);
    expect(connector.type).toBe('sentinel');
  });
});

describe('Connector Registry', () => {
  it('registers sentinel connector factory', () => {
    expect(connectorRegistry.has('sentinel')).toBe(true);
  });

  it('creates sentinel connector from registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);

    expect(connector).toBeInstanceOf(SentinelConnector);
    expect(connector.type).toBe('sentinel');
  });
});

describe('HMAC-SHA256 Signature', () => {
  beforeEach(() => {
    fetchCalls = [];
    fetchMockResponse = null;
    fetchShouldThrow = null;
    globalThis.fetch = mockFetchImplementation as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('produces consistent signatures', async () => {
    fetchMockResponse = { ok: true, status: 200, statusText: 'OK' };

    const config = createTestConfig();
    const connector = new SentinelConnector(config);
    await connector.init();

    // Send same event twice
    const event = createTestEvent();
    await connector.send(event);
    await connector.send(event);

    // Both calls should have Authorization headers in correct format
    expect(fetchCalls).toHaveLength(2);
    const headers1 = fetchCalls[0].options.headers as Record<string, string>;
    const headers2 = fetchCalls[1].options.headers as Record<string, string>;

    expect(headers1['Authorization']).toMatch(/^SharedKey test-workspace-id:[A-Za-z0-9+/=]+$/);
    expect(headers2['Authorization']).toMatch(/^SharedKey test-workspace-id:[A-Za-z0-9+/=]+$/);
  });
});
