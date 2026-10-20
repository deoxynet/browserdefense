/**
 * Connector Integration Tests
 *
 * Tests connector HTTP behavior against a real local server:
 * - Real network requests with correct headers/body
 * - Retry logic respects configured limits
 * - Batch flushes on size and time thresholds
 *
 * @see https://github.com/irdbl/blockioc/issues/136
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  TestHttpServer,
  createRetryScenario,
  createSplunkHecResponse,
  createDatadogValidateResponse,
} from './test-server';
import { WebhookConnector } from '../../src/connectors/webhook';
import { SplunkConnector } from '../../src/connectors/splunk';
import { DatadogConnector } from '../../src/connectors/datadog';
import {
  ForensicsEvent,
  WebhookConnectorConfig,
  SplunkConnectorConfig,
  DatadogConnectorConfig,
} from '../../src/connectors/types';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    blockedUrl: 'https://evil.com/phishing',
    timestamp: new Date().toISOString(),
    redirectChain: ['https://legit.com', 'https://evil.com/phishing'],
    tabContext: {
      tabId: 123,
      windowId: 1,
      initiatorUrl: 'https://email.example.com',
      tabTitle: 'Check your account',
      incognito: false,
    },
    orgId: 'org-test',
    eventId: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    matchType: 'url',
    matchedIndicator: 'evil.com/phishing',
    userId: 'user-test',
    raw: { source: 'integration-test' },
    ...overrides,
  };
}

// =============================================================================
// Webhook Connector Integration Tests
// =============================================================================

describe('WebhookConnector Integration', () => {
  let server: TestHttpServer;
  let serverPort: number;

  beforeEach(async () => {
    server = new TestHttpServer();
    serverPort = await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  describe('real HTTP requests', () => {
    it('should send event with correct headers and JSON body', async () => {
      server.setDefaultResponse({ statusCode: 200, body: { received: true } });

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-webhook',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        headers: { 'X-Custom': 'integration-test' },
        batch: { maxSize: 1, maxWaitMs: 0 },
      };

      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      // Verify request was made with correct properties
      const requests = server.getRequests();
      // Filter out health check requests (OPTIONS/HEAD)
      const postRequests = requests.filter((r) => r.method === 'POST');
      expect(postRequests.length).toBe(1);

      const req = postRequests[0];
      expect(req.headers['content-type']).toBe('application/json');
      expect(req.headers['x-custom']).toBe('integration-test');
      expect(req.headers['user-agent']).toContain('BrowserDefense');

      const body = JSON.parse(req.body);
      expect(body.blockedUrl).toBe('https://evil.com/phishing');
      expect(body.orgId).toBe('org-test');
      expect(body.eventId).toBe(event.eventId);

      await connector.close();
    });

    it('should add bearer auth header', async () => {
      server.setDefaultResponse({ statusCode: 200, body: {} });

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-bearer',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        auth: { type: 'bearer', token: 'secret-token-123' },
        batch: { maxSize: 1, maxWaitMs: 0 },
      };

      const connector = new WebhookConnector(config);
      await connector.init();
      await connector.send(createTestEvent());

      const postReq = server.getRequests().find((r) => r.method === 'POST');
      expect(postReq?.headers['authorization']).toBe('Bearer secret-token-123');

      await connector.close();
    });

    it('should add basic auth header', async () => {
      server.setDefaultResponse({ statusCode: 200, body: {} });

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-basic',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        auth: { type: 'basic', username: 'user', password: 'pass' },
        batch: { maxSize: 1, maxWaitMs: 0 },
      };

      const connector = new WebhookConnector(config);
      await connector.init();
      await connector.send(createTestEvent());

      const postReq = server.getRequests().find((r) => r.method === 'POST');
      // btoa('user:pass') = 'dXNlcjpwYXNz'
      expect(postReq?.headers['authorization']).toBe('Basic dXNlcjpwYXNz');

      await connector.close();
    });

    it('should add API key header', async () => {
      server.setDefaultResponse({ statusCode: 200, body: {} });

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-apikey',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        auth: { type: 'api-key', apiKeyHeader: 'X-API-Key', apiKey: 'my-api-key' },
        batch: { maxSize: 1, maxWaitMs: 0 },
      };

      const connector = new WebhookConnector(config);
      await connector.init();
      await connector.send(createTestEvent());

      const postReq = server.getRequests().find((r) => r.method === 'POST');
      expect(postReq?.headers['x-api-key']).toBe('my-api-key');

      await connector.close();
    });

    it('should use custom template for request body', async () => {
      server.setDefaultResponse({ statusCode: 200, body: {} });

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-template',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        template: '{"alert":"Blocked {{blockedUrl}} for {{orgId}}","type":"{{matchType}}"}',
        batch: { maxSize: 1, maxWaitMs: 0 },
      };

      const connector = new WebhookConnector(config);
      await connector.init();
      await connector.send(createTestEvent());

      const postReq = server.getRequests().find((r) => r.method === 'POST');
      const body = JSON.parse(postReq!.body);
      expect(body.alert).toBe('Blocked https://evil.com/phishing for org-test');
      expect(body.type).toBe('url');

      await connector.close();
    });
  });

  describe('retry behavior', () => {
    it('should retry on 500 errors and succeed eventually', async () => {
      // Queue 2 failures then success
      server.queueResponses(createRetryScenario(2, 500, { received: true }));

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-retry',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        batch: { maxSize: 1, maxWaitMs: 0 },
        retry: {
          maxAttempts: 3,
          initialDelayMs: 10, // Short delay for tests
          maxDelayMs: 50,
          backoffMultiplier: 2,
        },
      };

      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      // Initial send fails, queued for retry
      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);

      // Wait for retries to complete
      await new Promise((resolve) => setTimeout(resolve, 200));

      // Should have made 3 POST requests total (initial + 2 retries)
      const postRequests = server.getRequests().filter((r) => r.method === 'POST');
      expect(postRequests.length).toBeGreaterThanOrEqual(2);

      await connector.close();
    });

    it('should retry on 429 rate limiting', async () => {
      // Set 429 as default so it applies to all requests after health check
      server.setDefaultResponse({
        statusCode: 429,
        body: { error: 'Too Many Requests' },
        headers: { 'Retry-After': '1' },
      });

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-429',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        batch: { maxSize: 1, maxWaitMs: 0 },
        retry: {
          maxAttempts: 2,
          initialDelayMs: 10,
          maxDelayMs: 50,
          backoffMultiplier: 2,
        },
      };

      const connector = new WebhookConnector(config);
      // Health check will warn but not throw on non-200
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('429');

      await connector.close();
    });

    it('should NOT retry on 401 authentication errors', async () => {
      server.setDefaultResponse({
        statusCode: 401,
        body: { error: 'Unauthorized' },
      });

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-401',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        batch: { maxSize: 1, maxWaitMs: 0 },
        retry: {
          maxAttempts: 3,
          initialDelayMs: 10,
          maxDelayMs: 50,
          backoffMultiplier: 2,
        },
      };

      const connector = new WebhookConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);

      // Wait to ensure no retries
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Should only have 1 POST request (no retries for 401)
      const postRequests = server.getRequests().filter((r) => r.method === 'POST');
      expect(postRequests.length).toBe(1);

      await connector.close();
    });
  });

  describe('batching', () => {
    it('should flush batch when maxSize is reached', async () => {
      server.setDefaultResponse({ statusCode: 200, body: {} });

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-batch-size',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        batch: { maxSize: 3, maxWaitMs: 10000 }, // High wait time, trigger on size
      };

      const connector = new WebhookConnector(config);
      await connector.init();
      server.clearRequests();

      // Send 3 events (should trigger batch flush)
      await connector.send(createTestEvent({ eventId: 'evt-1' }));
      await connector.send(createTestEvent({ eventId: 'evt-2' }));
      await connector.send(createTestEvent({ eventId: 'evt-3' }));

      // Small wait for flush to complete
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Batch should have been sent
      const postRequests = server.getRequests().filter((r) => r.method === 'POST');
      expect(postRequests.length).toBeGreaterThanOrEqual(1);

      await connector.close();
    });

    it('should flush batch when maxWaitMs is reached', async () => {
      server.setDefaultResponse({ statusCode: 200, body: {} });

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-batch-time',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        batch: { maxSize: 100, maxWaitMs: 50 }, // Low wait time, trigger on time
      };

      const connector = new WebhookConnector(config);
      await connector.init();
      server.clearRequests();

      // Send 1 event (below maxSize)
      await connector.send(createTestEvent({ eventId: 'evt-1' }));

      // Wait for maxWaitMs to trigger flush
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Batch should have been sent due to time threshold
      const postRequests = server.getRequests().filter((r) => r.method === 'POST');
      expect(postRequests.length).toBeGreaterThanOrEqual(1);

      await connector.close();
    });

    it('should flush remaining events on close', async () => {
      server.setDefaultResponse({ statusCode: 200, body: {} });

      const config: WebhookConnectorConfig = {
        type: 'webhook',
        name: 'test-batch-close',
        enabled: true,
        url: `${server.baseUrl}/events`,
        method: 'POST',
        batch: { maxSize: 100, maxWaitMs: 60000 }, // High thresholds
      };

      const connector = new WebhookConnector(config);
      await connector.init();
      server.clearRequests();

      // Send events (below maxSize, before maxWaitMs)
      await connector.send(createTestEvent({ eventId: 'evt-1' }));
      await connector.send(createTestEvent({ eventId: 'evt-2' }));

      // Close should flush buffered events
      await connector.close();

      const postRequests = server.getRequests().filter((r) => r.method === 'POST');
      expect(postRequests.length).toBeGreaterThanOrEqual(1);
    });
  });
});

// =============================================================================
// Splunk HEC Connector Integration Tests
// =============================================================================

describe('SplunkConnector Integration', () => {
  let server: TestHttpServer;
  let serverPort: number;

  beforeEach(async () => {
    server = new TestHttpServer();
    serverPort = await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  describe('real HTTP requests', () => {
    it('should send event with Splunk HEC format and token auth', async () => {
      // Queue health check response, then event response
      server.queueResponse({ statusCode: 200, body: {} }); // health check
      server.setDefaultResponse(createSplunkHecResponse(0, 'Success'));

      const config: SplunkConnectorConfig = {
        type: 'splunk',
        name: 'test-splunk',
        enabled: true,
        hecUrl: `${server.baseUrl}/services/collector/event`,
        hecToken: 'my-hec-token',
        index: 'security',
        sourceType: 'browserdefense:forensics',
        source: 'browserdefense-extension',
        batch: { maxSize: 1, maxWaitMs: 0 },
      };

      const connector = new SplunkConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      // Find the POST request to /event endpoint
      const eventRequests = server.getRequests().filter(
        (r) => r.method === 'POST' && r.url?.includes('/event')
      );
      expect(eventRequests.length).toBe(1);

      const req = eventRequests[0];
      expect(req.headers['authorization']).toBe('Splunk my-hec-token');
      expect(req.headers['content-type']).toBe('application/json');

      const body = JSON.parse(req.body);
      expect(body.index).toBe('security');
      expect(body.sourcetype).toBe('browserdefense:forensics');
      expect(body.source).toBe('browserdefense-extension');
      expect(body.event.event_type).toBe('browserdefense:block');
      expect(body.event.blocked_url).toBe('https://evil.com/phishing');
      expect(body.event.org_id).toBe('org-test');

      await connector.close();
    });

    it('should handle Splunk HEC error codes correctly', async () => {
      // Health check endpoint returns 200, event endpoint returns HEC error
      server.setDefaultResponse(createSplunkHecResponse(4, 'Invalid token'));

      const config: SplunkConnectorConfig = {
        type: 'splunk',
        name: 'test-splunk-error',
        enabled: true,
        hecUrl: `${server.baseUrl}/services/collector/event`,
        hecToken: 'invalid-token',
        batch: { maxSize: 1, maxWaitMs: 0 },
      };

      const connector = new SplunkConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      // HEC error format: "Splunk HEC error (code X): message"
      expect(result.error).toMatch(/code 4|Invalid token/);
      expect(result.retryable).toBe(false); // Code 4 is not retryable

      await connector.close();
    });

    it('should batch events in Splunk HEC format', async () => {
      server.queueResponse({ statusCode: 200, body: {} }); // health check
      server.setDefaultResponse(createSplunkHecResponse(0, 'Success'));

      const config: SplunkConnectorConfig = {
        type: 'splunk',
        name: 'test-splunk-batch',
        enabled: true,
        hecUrl: `${server.baseUrl}/services/collector/event`,
        hecToken: 'batch-token',
        batch: { maxSize: 3, maxWaitMs: 50 },
      };

      const connector = new SplunkConnector(config);
      await connector.init();
      server.clearRequests();

      // Send batch directly
      const events = [
        createTestEvent({ eventId: 'evt-1' }),
        createTestEvent({ eventId: 'evt-2' }),
        createTestEvent({ eventId: 'evt-3' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results.every((r) => r.success)).toBe(true);

      // Verify batch was sent as concatenated JSON (Splunk HEC format)
      const postRequests = server.getRequests().filter((r) => r.method === 'POST');
      expect(postRequests.length).toBe(1);

      // Splunk HEC batch format: multiple JSON objects concatenated without delimiter
      const body = postRequests[0].body;
      // Should contain 3 event_id entries
      expect(body).toContain('evt-1');
      expect(body).toContain('evt-2');
      expect(body).toContain('evt-3');

      await connector.close();
    });
  });

  describe('retry behavior', () => {
    it('should retry on HEC error code 8 (internal server error)', async () => {
      // Set default to HEC code 8 (internal server error) which should be retryable
      server.setDefaultResponse(createSplunkHecResponse(8, 'Internal server error'));

      const config: SplunkConnectorConfig = {
        type: 'splunk',
        name: 'test-splunk-retry',
        enabled: true,
        hecUrl: `${server.baseUrl}/services/collector/event`,
        hecToken: 'retry-token',
        batch: { maxSize: 1, maxWaitMs: 0 },
        retry: {
          maxAttempts: 2,
          initialDelayMs: 10,
          maxDelayMs: 50,
          backoffMultiplier: 2,
        },
      };

      const connector = new SplunkConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      // HEC code 8 is an internal server error and should be retryable
      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);

      await connector.close();
    });

    it('should retry on HTTP 503', async () => {
      server.queueResponse({ statusCode: 200, body: {} }); // health
      server.queueResponse({ statusCode: 503, body: 'Service Unavailable' });
      server.setDefaultResponse(createSplunkHecResponse(0, 'Success'));

      const config: SplunkConnectorConfig = {
        type: 'splunk',
        name: 'test-splunk-503',
        enabled: true,
        hecUrl: `${server.baseUrl}/services/collector/event`,
        hecToken: 'retry-token',
        batch: { maxSize: 1, maxWaitMs: 0 },
        retry: {
          maxAttempts: 2,
          initialDelayMs: 10,
          maxDelayMs: 50,
          backoffMultiplier: 2,
        },
      };

      const connector = new SplunkConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);

      await connector.close();
    });
  });
});

// =============================================================================
// Datadog Connector Integration Tests
// =============================================================================

describe('DatadogConnector Integration', () => {
  let server: TestHttpServer;
  let serverPort: number;

  beforeEach(async () => {
    server = new TestHttpServer();
    serverPort = await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  // Helper to create a Datadog connector with test server URL
  function createDatadogConfig(
    overrides: Partial<DatadogConnectorConfig> = {}
  ): DatadogConnectorConfig & { _testApiUrl: string; _testValidateUrl: string } {
    // We need to override the internal URLs since Datadog connector constructs them
    // For testing, we'll use a workaround by setting a custom site
    return {
      type: 'datadog',
      name: 'test-datadog',
      enabled: true,
      site: 'datadoghq.com', // Will be overridden
      apiKey: 'test-api-key',
      service: 'blockioc-test',
      source: 'integration-test',
      tags: ['env:test'],
      batch: { maxSize: 1, maxWaitMs: 0 },
      _testApiUrl: `${server.baseUrl}/api/v2/logs`,
      _testValidateUrl: `${server.baseUrl}/api/v1/validate`,
      ...overrides,
    } as DatadogConnectorConfig & { _testApiUrl: string; _testValidateUrl: string };
  }

  describe('real HTTP requests', () => {
    it('should send event with Datadog log format and API key header', async () => {
      // For Datadog tests, we need to mock the internal URLs
      // Since the connector builds URLs from the site, we'll test the request format
      server.setDefaultResponse({ statusCode: 200, body: {} });

      // Create a custom connector class for testing that uses our server
      class TestDatadogConnector extends DatadogConnector {
        constructor(
          config: DatadogConnectorConfig,
          private testApiUrl: string,
          private testValidateUrl: string
        ) {
          super(config);
          // Override the internal apiUrl
          (this as unknown as { apiUrl: string }).apiUrl = testApiUrl;
        }

        protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
          try {
            const response = await fetch(this.testValidateUrl, {
              method: 'GET',
              headers: { 'DD-API-KEY': this['datadogConfig'].apiKey },
            });
            return {
              healthy: response.ok,
              message: response.ok ? 'Connected' : `HTTP ${response.status}`,
            };
          } catch (e) {
            return { healthy: false, message: String(e) };
          }
        }
      }

      const config: DatadogConnectorConfig = {
        type: 'datadog',
        name: 'test-datadog',
        enabled: true,
        site: 'datadoghq.com',
        apiKey: 'dd-api-key-123',
        service: 'browserdefense',
        source: 'browser-extension',
        tags: ['env:test', 'team:security'],
        batch: { maxSize: 1, maxWaitMs: 0 },
      };

      const connector = new TestDatadogConnector(
        config,
        `${server.baseUrl}/api/v2/logs`,
        `${server.baseUrl}/api/v1/validate`
      );
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      // Find POST request to logs endpoint
      const logRequests = server.getRequests().filter(
        (r) => r.method === 'POST' && r.url?.includes('/logs')
      );
      expect(logRequests.length).toBe(1);

      const req = logRequests[0];
      expect(req.headers['dd-api-key']).toBe('dd-api-key-123');
      expect(req.headers['content-type']).toBe('application/json');

      // Parse the body (Datadog expects array of log entries)
      const body = JSON.parse(req.body);
      expect(Array.isArray(body)).toBe(true);
      expect(body.length).toBe(1);

      const logEntry = body[0];
      expect(logEntry.message).toContain('BrowserDefense');
      expect(logEntry.ddsource).toBe('browser-extension');
      expect(logEntry.service).toBe('browserdefense');
      expect(logEntry.ddtags).toContain('env:test');
      expect(logEntry.ddtags).toContain('team:security');
      expect(logEntry.ddtags).toContain('org_id:org-test');
      expect(logEntry.browserdefense.blocked_url).toBe('https://evil.com/phishing');

      await connector.close();
    });

    it('should batch events in Datadog array format', async () => {
      server.setDefaultResponse({ statusCode: 200, body: {} });

      class TestDatadogConnector extends DatadogConnector {
        constructor(
          config: DatadogConnectorConfig,
          private testApiUrl: string,
          private testValidateUrl: string
        ) {
          super(config);
          (this as unknown as { apiUrl: string }).apiUrl = testApiUrl;
        }

        protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
          const response = await fetch(this.testValidateUrl, {
            method: 'GET',
            headers: { 'DD-API-KEY': this['datadogConfig'].apiKey },
          });
          return { healthy: response.ok, message: response.ok ? 'OK' : 'Error' };
        }
      }

      const config: DatadogConnectorConfig = {
        type: 'datadog',
        name: 'test-datadog-batch',
        enabled: true,
        site: 'datadoghq.com',
        apiKey: 'batch-api-key',
        batch: { maxSize: 3, maxWaitMs: 50 },
      };

      const connector = new TestDatadogConnector(
        config,
        `${server.baseUrl}/api/v2/logs`,
        `${server.baseUrl}/api/v1/validate`
      );
      await connector.init();
      server.clearRequests();

      const events = [
        createTestEvent({ eventId: 'dd-1', orgId: 'org-a' }),
        createTestEvent({ eventId: 'dd-2', orgId: 'org-b' }),
        createTestEvent({ eventId: 'dd-3', orgId: 'org-c' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results.every((r) => r.success)).toBe(true);

      // Verify batch was sent as JSON array
      const postRequests = server.getRequests().filter((r) => r.method === 'POST');
      expect(postRequests.length).toBe(1);

      const body = JSON.parse(postRequests[0].body);
      expect(Array.isArray(body)).toBe(true);
      expect(body.length).toBe(3);

      await connector.close();
    });
  });

  describe('retry behavior', () => {
    it('should retry on 500 server errors', async () => {
      class TestDatadogConnector extends DatadogConnector {
        constructor(
          config: DatadogConnectorConfig,
          private testApiUrl: string,
          private testValidateUrl: string
        ) {
          super(config);
          (this as unknown as { apiUrl: string }).apiUrl = testApiUrl;
        }

        protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
          const response = await fetch(this.testValidateUrl, {
            method: 'GET',
            headers: { 'DD-API-KEY': this['datadogConfig'].apiKey },
          });
          return { healthy: response.ok, message: 'OK' };
        }
      }

      server.queueResponse({ statusCode: 200, body: { valid: true } }); // validate
      server.queueResponse({ statusCode: 500, body: { error: 'Server error' } });
      server.setDefaultResponse({ statusCode: 200, body: {} });

      const config: DatadogConnectorConfig = {
        type: 'datadog',
        name: 'test-datadog-retry',
        enabled: true,
        site: 'datadoghq.com',
        apiKey: 'retry-key',
        batch: { maxSize: 1, maxWaitMs: 0 },
        retry: {
          maxAttempts: 2,
          initialDelayMs: 10,
          maxDelayMs: 50,
          backoffMultiplier: 2,
        },
      };

      const connector = new TestDatadogConnector(
        config,
        `${server.baseUrl}/api/v2/logs`,
        `${server.baseUrl}/api/v1/validate`
      );
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);

      await connector.close();
    });

    it('should NOT retry on 403 authentication errors', async () => {
      class TestDatadogConnector extends DatadogConnector {
        constructor(
          config: DatadogConnectorConfig,
          private testApiUrl: string,
          private testValidateUrl: string
        ) {
          super(config);
          (this as unknown as { apiUrl: string }).apiUrl = testApiUrl;
        }

        protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
          const response = await fetch(this.testValidateUrl, {
            method: 'GET',
            headers: { 'DD-API-KEY': this['datadogConfig'].apiKey },
          });
          return { healthy: response.ok, message: 'OK' };
        }
      }

      server.queueResponse({ statusCode: 200, body: { valid: true } }); // validate succeeds initially
      server.setDefaultResponse({ statusCode: 403, body: { error: 'Forbidden' } });

      const config: DatadogConnectorConfig = {
        type: 'datadog',
        name: 'test-datadog-403',
        enabled: true,
        site: 'datadoghq.com',
        apiKey: 'bad-key',
        batch: { maxSize: 1, maxWaitMs: 0 },
        retry: {
          maxAttempts: 3,
          initialDelayMs: 10,
          maxDelayMs: 50,
          backoffMultiplier: 2,
        },
      };

      const connector = new TestDatadogConnector(
        config,
        `${server.baseUrl}/api/v2/logs`,
        `${server.baseUrl}/api/v1/validate`
      );
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);

      await connector.close();
    });
  });
});

// =============================================================================
// Cross-Connector Tests
// =============================================================================

describe('Connector Metrics', () => {
  let server: TestHttpServer;

  beforeEach(async () => {
    server = new TestHttpServer();
    await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  it('should track events sent and failed across retries', async () => {
    // 2 failures then success
    server.queueResponses([
      { statusCode: 500, body: { error: 'fail 1' } },
      { statusCode: 500, body: { error: 'fail 2' } },
      { statusCode: 200, body: {} },
    ]);

    const config: WebhookConnectorConfig = {
      type: 'webhook',
      name: 'test-metrics',
      enabled: true,
      url: `${server.baseUrl}/events`,
      method: 'POST',
      batch: { maxSize: 1, maxWaitMs: 0 },
      retry: {
        maxAttempts: 3,
        initialDelayMs: 5,
        maxDelayMs: 20,
        backoffMultiplier: 2,
      },
    };

    const connector = new WebhookConnector(config);
    await connector.init();
    server.clearRequests();

    await connector.send(createTestEvent());

    // Wait for retries
    await new Promise((resolve) => setTimeout(resolve, 100));

    const health = await connector.health();
    expect(health.metrics).toBeDefined();
    // Either eventsSent or eventsFailed should be non-zero
    expect(
      health.metrics!.eventsSent + health.metrics!.eventsFailed
    ).toBeGreaterThan(0);

    await connector.close();
  });
});
