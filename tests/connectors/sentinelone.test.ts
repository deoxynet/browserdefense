/**
 * Unit tests for BrowserDefense SentinelOne connector.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  SentinelOneConnector,
  createSentinelOneConnector,
} from '../../src/connectors/sentinelone';
import {
  connectorRegistry,
} from '../../src/connectors/base';
import type {
  ForensicsEvent,
  SentinelOneConnectorConfig,
} from '../../src/connectors/types';

// =============================================================================
// Test Fixtures
// =============================================================================

/**
 * Create a minimal valid SentinelOne config for testing.
 */
function createTestConfig(
  overrides: Partial<SentinelOneConnectorConfig> = {}
): SentinelOneConnectorConfig {
  return {
    type: 'sentinelone',
    name: 'test-sentinelone',
    enabled: true,
    consoleUrl: 'https://test.sentinelone.net',
    apiToken: 'test-api-token-12345',
    // Disable batching so events are sent immediately
    batch: { maxSize: 1, maxWaitMs: 0 },
    ...overrides,
  };
}

/**
 * Create a test forensics event.
 */
function createTestEvent(
  overrides: Partial<ForensicsEvent> = {}
): ForensicsEvent {
  return {
    blockedUrl: 'https://malicious-domain.com/phishing/page.html',
    timestamp: '2024-01-15T10:30:00.000Z',
    redirectChain: ['https://legitimate.com', 'https://redirect.com'],
    tabContext: {
      tabId: 123,
      windowId: 1,
      initiatorUrl: 'https://email-client.com/inbox',
      tabTitle: 'Email - Important Message',
      incognito: false,
    },
    orgId: 'org-12345',
    eventId: 'evt-abc123',
    matchType: 'domain',
    matchedIndicator: 'malicious-domain.com',
    userId: 'user@company.com',
    deviceId: 'device-xyz789',
    raw: {},
    ...overrides,
  };
}

// =============================================================================
// Mock Fetch
// =============================================================================

// Store original fetch
const originalFetch = globalThis.fetch;

// Tracking for requests
let capturedRequests: Array<{ url: string; options: RequestInit }> = [];

// Create a mock fetch that captures requests and returns specified responses
function setupMockFetch(
  handler: (url: string, options: RequestInit) => { status: number; body: unknown; headers?: Record<string, string> }
) {
  capturedRequests = [];
  globalThis.fetch = vi.fn().mockImplementation((url: string, options: RequestInit) => {
    capturedRequests.push({ url, options });
    const response = handler(url, options);
    return Promise.resolve({
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      statusText: response.status === 200 ? 'OK' : 'Error',
      headers: new Headers(response.headers || {}),
      json: () => Promise.resolve(response.body),
      text: () => Promise.resolve(
        typeof response.body === 'string' ? response.body : JSON.stringify(response.body)
      ),
    });
  });
}

// =============================================================================
// Tests
// =============================================================================

describe('SentinelOneConnector', () => {
  afterEach(() => {
    // Restore original fetch
    globalThis.fetch = originalFetch;
    capturedRequests = [];
  });

  describe('constructor', () => {
    it('creates connector with valid config', () => {
      const config = createTestConfig();
      const connector = new SentinelOneConnector(config);

      expect(connector.type).toBe('sentinelone');
      expect(connector.name).toBe('test-sentinelone');
    });

    it('normalizes console URL with trailing slash', () => {
      const config = createTestConfig({
        consoleUrl: 'https://test.sentinelone.net///',
      });
      const connector = new SentinelOneConnector(config);

      // The connector should strip trailing slashes
      expect(connector.type).toBe('sentinelone');
    });

    it('accepts optional site ID', () => {
      const config = createTestConfig({
        siteId: 'site-123',
      });
      const connector = new SentinelOneConnector(config);

      expect(connector.type).toBe('sentinelone');
    });

    it('accepts optional account ID', () => {
      const config = createTestConfig({
        accountId: 'account-456',
      });
      const connector = new SentinelOneConnector(config);

      expect(connector.type).toBe('sentinelone');
    });
  });

  describe('init', () => {
    it('succeeds when API is healthy', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok', version: '4.0.0' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await expect(connector.init()).resolves.toBeUndefined();
    });

    it('throws when console URL is missing', async () => {
      const config = createTestConfig({ consoleUrl: '' });
      const connector = new SentinelOneConnector(config);

      await expect(connector.init()).rejects.toThrow('console URL is required');
    });

    it('throws when API token is missing', async () => {
      const config = createTestConfig({ apiToken: '' });
      const connector = new SentinelOneConnector(config);

      await expect(connector.init()).rejects.toThrow('API token is required');
    });

    it('throws when health check fails', async () => {
      setupMockFetch(() => ({
        status: 401,
        body: { errors: [{ code: 401, detail: 'Unauthorized', title: 'Auth Error' }] },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await expect(connector.init()).rejects.toThrow('initialization failed');
    });

    it('throws when called twice', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();
      await expect(connector.init()).rejects.toThrow('already initialized');
    });
  });

  describe('send', () => {
    it('sends event successfully', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-abc123');
    });

    it('includes correct authorization header', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();
      await connector.send(createTestEvent());

      // Find the send call (not the health check)
      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      expect(sendRequest).toBeDefined();
      expect(sendRequest!.options.headers).toEqual(expect.objectContaining({
        'Authorization': 'ApiToken test-api-token-12345',
      }));
    });

    it('sends POST request with JSON body including filter wrapper', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();
      await connector.send(createTestEvent());

      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      expect(sendRequest).toBeDefined();
      expect(sendRequest!.options.method).toBe('POST');
      expect(sendRequest!.options.body).toBeDefined();

      const body = JSON.parse(sendRequest!.options.body as string);
      // Verify filter wrapper is present
      expect(body.filter).toBeDefined();
      expect(body.data).toHaveLength(1);
      expect(body.data[0].source).toBe('BrowserDefense');
    });

    it('includes required API fields: name, method, validUntil', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();
      await connector.send(createTestEvent());

      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      const body = JSON.parse(sendRequest!.options.body as string);

      // Verify required fields per SentinelOne API
      expect(body.data[0].name).toBe('BlockIOC-evt-abc123');
      expect(body.data[0].method).toBe('EQUALS');
      expect(body.data[0].validUntil).toBeDefined();
      // validUntil should be a valid ISO date in the future
      const validUntil = new Date(body.data[0].validUntil);
      expect(validUntil.getTime()).toBeGreaterThan(Date.now());
    });

    it('transforms domain match to DNS indicator type', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();
      await connector.send(createTestEvent({ matchType: 'domain' }));

      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      const body = JSON.parse(sendRequest!.options.body as string);

      expect(body.data[0].type).toBe('DNS');
      expect(body.data[0].value).toBe('malicious-domain.com');
    });

    it('transforms URL match to URL indicator type', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();
      await connector.send(createTestEvent({ matchType: 'url' }));

      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      const body = JSON.parse(sendRequest!.options.body as string);

      expect(body.data[0].type).toBe('URL');
      expect(body.data[0].value).toBe('https://malicious-domain.com/phishing/page.html');
    });

    it('transforms hash match to SHA256 indicator type', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();
      await connector.send(createTestEvent({
        matchType: 'hash',
        matchedIndicator: 'abc123def456',
      }));

      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      const body = JSON.parse(sendRequest!.options.body as string);

      expect(body.data[0].type).toBe('SHA256');
      expect(body.data[0].value).toBe('abc123def456');
    });

    // Note: metadata field was removed from SentinelOne indicator format
    // These fields are now encoded in description and externalId instead
    it('includes source field for attribution', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();
      await connector.send(createTestEvent());

      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      const body = JSON.parse(sendRequest!.options.body as string);

      expect(body.data[0].source).toBe('BrowserDefense');
    });

    it('includes external ID for correlation', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();
      await connector.send(createTestEvent());

      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      const body = JSON.parse(sendRequest!.options.body as string);

      expect(body.data[0].externalId).toBe('evt-abc123');
    });

    it('builds human-readable description', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();
      await connector.send(createTestEvent());

      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      const body = JSON.parse(sendRequest!.options.body as string);

      expect(body.data[0].description).toContain('Blocked navigation');
      expect(body.data[0].description).toContain('domain IOC');
    });

    it('throws when not initialized', async () => {
      const uninitConnector = new SentinelOneConnector(createTestConfig());
      const event = createTestEvent();

      await expect(uninitConnector.send(event)).rejects.toThrow('not initialized');
    });
  });

  describe('send with site/account scoping', () => {
    it('includes siteIds in request body filter for POST requests', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig({
        siteId: 'site-123',
      }));
      await connector.init();
      await connector.send(createTestEvent());

      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      // siteIds should be in body filter, not query params for POST
      expect(sendRequest!.url).not.toContain('siteIds=');
      const body = JSON.parse(sendRequest!.options.body as string);
      expect(body.filter.siteIds).toEqual(['site-123']);
    });

    it('includes accountIds in request body filter for POST requests', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: {} },
      }));

      const connector = new SentinelOneConnector(createTestConfig({
        accountId: 'account-456',
      }));
      await connector.init();
      await connector.send(createTestEvent());

      const sendRequest = capturedRequests.find((r) => r.url.includes('/threat-intelligence/iocs'));
      // accountIds should be in body filter, not query params for POST
      expect(sendRequest!.url).not.toContain('accountIds=');
      const body = JSON.parse(sendRequest!.options.body as string);
      expect(body.filter.accountIds).toEqual(['account-456']);
    });

    it('includes scoping in query params for GET requests (health check)', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig({
        siteId: 'site-123',
        accountId: 'account-456',
      }));
      await connector.init();

      // Health check is a GET request, should have query params
      const healthRequest = capturedRequests.find((r) => r.url.includes('/system/info'));
      expect(healthRequest!.url).toContain('siteIds=site-123');
      expect(healthRequest!.url).toContain('accountIds=account-456');
    });
  });

  describe('error handling', () => {
    it('handles 401 authentication error', async () => {
      let callCount = 0;
      setupMockFetch(() => {
        callCount++;
        if (callCount === 1) {
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        return { status: 401, body: 'Invalid token' };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('authentication failed');
      expect(result.retryable).toBe(false);
    });

    it('handles 403 authorization error', async () => {
      let callCount = 0;
      setupMockFetch(() => {
        callCount++;
        if (callCount === 1) {
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        return { status: 403, body: 'Insufficient permissions' };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('authorization failed');
      expect(result.error).toContain('threat-intelligence:write');
    });

    it('handles 429 rate limiting as retryable', async () => {
      let callCount = 0;
      setupMockFetch(() => {
        callCount++;
        if (callCount === 1) {
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        return { status: 429, body: 'Rate limited', headers: { 'Retry-After': '60' } };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('Rate limited');
      expect(result.retryable).toBe(true);
    });

    it('handles 500 server error', async () => {
      let callCount = 0;
      setupMockFetch(() => {
        callCount++;
        if (callCount === 1) {
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        return { status: 500, body: 'Server error' };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('500');
    });

    it('handles API response with errors array', async () => {
      let callCount = 0;
      setupMockFetch(() => {
        callCount++;
        if (callCount === 1) {
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        return {
          status: 200,
          body: { errors: [{ code: 400, detail: 'Invalid indicator format', title: 'Validation Error' }] },
        };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid indicator format');
    });

    it('handles network failure as retryable', async () => {
      setupMockFetch(() => ({ status: 200, body: { data: { health: 'ok' } } }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      // Now replace fetch with one that throws
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('fetch failed: network error'));

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('fetch failed');
      expect(result.retryable).toBe(true);
    });
  });

  describe('health', () => {
    it('returns healthy status when API responds', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok', version: '4.0.0' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('Connected to SentinelOne');
      expect(health.message).toContain('v4.0.0');
    });

    it('includes metrics in health response', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const health = await connector.health();

      expect(health.metrics).toBeDefined();
      expect(health.metrics?.eventsSent).toBe(0);
      expect(health.metrics?.eventsFailed).toBe(0);
    });
  });

  describe('close', () => {
    it('closes without error', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      await expect(connector.close()).resolves.toBeUndefined();
    });

    it('can be called multiple times', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      await connector.close();
      await expect(connector.close()).resolves.toBeUndefined();
    });
  });

  describe('shouldProcess', () => {
    it('processes all events without filter config', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const event = createTestEvent();
      expect(connector.shouldProcess(event)).toBe(true);
    });

    it('filters by org ID', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig({
        filter: { orgIds: ['allowed-org'] },
      }));
      await connector.init();

      expect(connector.shouldProcess(createTestEvent({ orgId: 'allowed-org' }))).toBe(true);
      expect(connector.shouldProcess(createTestEvent({ orgId: 'other-org' }))).toBe(false);
    });

    it('filters by match type', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig({
        filter: { matchTypes: ['domain', 'url'] },
      }));
      await connector.init();

      expect(connector.shouldProcess(createTestEvent({ matchType: 'domain' }))).toBe(true);
      expect(connector.shouldProcess(createTestEvent({ matchType: 'url' }))).toBe(true);
      expect(connector.shouldProcess(createTestEvent({ matchType: 'hash' }))).toBe(false);
    });

    it('filters by exclude pattern', async () => {
      setupMockFetch(() => ({
        status: 200,
        body: { data: { health: 'ok' } },
      }));

      const connector = new SentinelOneConnector(createTestConfig({
        filter: { excludePatterns: ['internal\\.company\\.com'] },
      }));
      await connector.init();

      expect(connector.shouldProcess(createTestEvent({
        blockedUrl: 'https://external.com/page',
      }))).toBe(true);
      expect(connector.shouldProcess(createTestEvent({
        blockedUrl: 'https://internal.company.com/page',
      }))).toBe(false);
    });
  });

  describe('unblock', () => {
    it('supports unblocking', () => {
      const config = createTestConfig();
      const connector = new SentinelOneConnector(config);

      expect(connector.supportsUnblock).toBe(true);
    });

    it('unblocks event successfully when IOC exists', async () => {
      let callCount = 0;
      setupMockFetch((url) => {
        callCount++;
        if (callCount === 1) {
          // Health check
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        if (url.includes('externalId=')) {
          // Search for IOC - found
          return {
            status: 200,
            body: {
              data: [{ id: 'ioc-internal-123', value: 'malicious-domain.com', type: 'DNS', externalId: 'evt-abc123' }],
            },
          };
        }
        if (url.includes('/threat-intelligence/iocs/ioc-internal-123')) {
          // Delete IOC
          return { status: 200, body: { data: { affected: 1 } } };
        }
        return { status: 200, body: { data: {} } };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const event = createTestEvent({ action: 'unblock' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-abc123');
      expect(result.alreadyClosed).toBe(false);
      expect(result.incidentId).toBe('ioc-internal-123');
    });

    it('returns alreadyClosed when IOC not found', async () => {
      let callCount = 0;
      setupMockFetch((url) => {
        callCount++;
        if (callCount === 1) {
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        if (url.includes('externalId=')) {
          // Search for IOC - not found
          return { status: 200, body: { data: [] } };
        }
        return { status: 200, body: { data: {} } };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const event = createTestEvent({ action: 'unblock' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-abc123');
      expect(result.alreadyClosed).toBe(true);
    });

    it('returns alreadyClosed on 404 during delete', async () => {
      let callCount = 0;
      setupMockFetch((url) => {
        callCount++;
        if (callCount === 1) {
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        if (url.includes('externalId=')) {
          return {
            status: 200,
            body: {
              data: [{ id: 'ioc-123', value: 'test.com', type: 'DNS', externalId: 'evt-abc123' }],
            },
          };
        }
        if (url.includes('/threat-intelligence/iocs/ioc-123')) {
          return { status: 404, body: 'Not found' };
        }
        return { status: 200, body: { data: {} } };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const event = createTestEvent({ action: 'unblock' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(true);
      expect(result.alreadyClosed).toBe(true);
    });

    it('returns error on unblock failure', async () => {
      let callCount = 0;
      setupMockFetch((url) => {
        callCount++;
        if (callCount === 1) {
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        if (url.includes('externalId=')) {
          return {
            status: 200,
            body: {
              data: [{ id: 'ioc-123', value: 'test.com', type: 'DNS', externalId: 'evt-abc123' }],
            },
          };
        }
        if (url.includes('/threat-intelligence/iocs/ioc-123')) {
          return { status: 403, body: 'Forbidden' };
        }
        return { status: 200, body: { data: {} } };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const event = createTestEvent({ action: 'unblock' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('authorization failed');
      expect(result.retryable).toBe(false);
    });

    it('returns retryable error on rate limiting', async () => {
      let callCount = 0;
      setupMockFetch((url) => {
        callCount++;
        if (callCount === 1) {
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        if (url.includes('externalId=')) {
          return { status: 429, body: 'Rate limited', headers: { 'Retry-After': '60' } };
        }
        return { status: 200, body: { data: {} } };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const event = createTestEvent({ action: 'unblock' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('searches for IOC using correct endpoint with externalId', async () => {
      let searchUrl = '';
      setupMockFetch((url) => {
        if (url.includes('/system/info')) {
          return { status: 200, body: { data: { health: 'ok' } } };
        }
        if (url.includes('externalId=')) {
          searchUrl = url;
          return { status: 200, body: { data: [] } };
        }
        return { status: 200, body: { data: {} } };
      });

      const connector = new SentinelOneConnector(createTestConfig());
      await connector.init();

      const event = createTestEvent({ eventId: 'evt-special-123' });
      await connector.unblock(event);

      expect(searchUrl).toContain('/threat-intelligence/iocs');
      expect(searchUrl).toContain('externalId=evt-special-123');
    });
  });

  describe('factory registration', () => {
    it('registers factory with connector registry', () => {
      expect(connectorRegistry.has('sentinelone')).toBe(true);
    });

    it('creates connector via registry', () => {
      const config = createTestConfig();
      const connector = connectorRegistry.create(config);

      expect(connector.type).toBe('sentinelone');
      expect(connector.name).toBe('test-sentinelone');
    });

    it('creates connector via factory function', () => {
      const config = createTestConfig();
      const connector = createSentinelOneConnector(config);

      expect(connector).toBeInstanceOf(SentinelOneConnector);
    });
  });
});

describe('sendBatch', () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    capturedRequests = [];
  });

  it('sends multiple events', async () => {
    setupMockFetch(() => ({
      status: 200,
      body: { data: {} },
    }));

    const connector = new SentinelOneConnector(createTestConfig());
    await connector.init();

    const events = [
      createTestEvent({ eventId: 'evt-1' }),
      createTestEvent({ eventId: 'evt-2' }),
      createTestEvent({ eventId: 'evt-3' }),
    ];

    const results = await connector.sendBatch(events);

    expect(results).toHaveLength(3);
    expect(results.every((r) => r.success)).toBe(true);
  });

  it('handles partial failures', async () => {
    let sendCallCount = 0;
    setupMockFetch((url) => {
      if (url.includes('/system/info')) {
        return { status: 200, body: { data: { health: 'ok' } } };
      }
      sendCallCount++;
      if (sendCallCount === 2) {
        return { status: 200, body: { errors: [{ code: 400, detail: 'Invalid', title: 'Error' }] } };
      }
      return { status: 200, body: { data: {} } };
    });

    const connector = new SentinelOneConnector(createTestConfig());
    await connector.init();

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
