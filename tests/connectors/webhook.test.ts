import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { WebhookConnector, renderTemplate, createWebhookConnector } from '../../src/connectors/webhook';
import { ForensicsEvent, WebhookConnectorConfig } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    blockedUrl: 'https://evil.com/phishing',
    timestamp: '2024-01-15T10:30:00.000Z',
    redirectChain: ['https://legit.com', 'https://redirect.com', 'https://evil.com/phishing'],
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
    raw: {
      original: true,
      custom: 'data',
    },
    ...overrides,
  };
}

function createTestConfig(overrides: Partial<WebhookConnectorConfig> = {}): WebhookConnectorConfig {
  return {
    type: 'webhook',
    name: 'test-webhook',
    enabled: true,
    url: 'https://webhook.example.com/events',
    method: 'POST',
    // Disable batching by default for simpler testing
    batch: { maxSize: 1, maxWaitMs: 0 },
    ...overrides,
  };
}

// =============================================================================
// Template Engine Tests
// =============================================================================

describe('renderTemplate', () => {
  const event = createTestEvent();

  it('should render simple variable substitution', () => {
    const template = 'Blocked URL: {{blockedUrl}}';
    const result = renderTemplate(template, event);
    expect(result).toBe('Blocked URL: https://evil.com/phishing');
  });

  it('should render nested object paths', () => {
    const template = 'Tab ID: {{tabContext.tabId}}, Title: {{tabContext.tabTitle}}';
    const result = renderTemplate(template, event);
    expect(result).toBe('Tab ID: 123, Title: Check your account');
  });

  it('should render arrays as JSON', () => {
    const template = 'Chain: {{redirectChain}}';
    const result = renderTemplate(template, event);
    expect(result).toBe('Chain: ["https://legit.com","https://redirect.com","https://evil.com/phishing"]');
  });

  it('should render objects as JSON', () => {
    const template = 'Raw: {{raw}}';
    const result = renderTemplate(template, event);
    expect(result).toBe('Raw: {"original":true,"custom":"data"}');
  });

  it('should handle undefined values as empty string', () => {
    const template = 'Device: {{deviceId}}';
    const result = renderTemplate(template, event);
    expect(result).toBe('Device: ');
  });

  it('should handle multiple substitutions', () => {
    const template = '[{{orgId}}] {{matchType}} match: {{matchedIndicator}}';
    const result = renderTemplate(template, event);
    expect(result).toBe('[org-123] url match: evil.com/phishing');
  });

  it('should render a Slack-style template', () => {
    const template = `{
  "text": "BrowserDefense Alert",
  "blocks": [{
    "type": "section",
    "text": {
      "type": "mrkdwn",
      "text": "*Blocked:* {{blockedUrl}}\\nOrg: {{orgId}}"
    }
  }]
}`;
    const result = renderTemplate(template, event);
    expect(result).toContain('"text": "BrowserDefense Alert"');
    expect(result).toContain('*Blocked:* https://evil.com/phishing');
    expect(result).toContain('Org: org-123');
  });

  it('should handle deeply nested paths', () => {
    const eventWithDeepNesting = createTestEvent({
      raw: {
        level1: {
          level2: {
            value: 'deep-value',
          },
        },
      },
    });
    const template = 'Deep: {{raw.level1.level2.value}}';
    const result = renderTemplate(template, eventWithDeepNesting);
    expect(result).toBe('Deep: deep-value');
  });

  it('should handle invalid paths gracefully', () => {
    const template = 'Invalid: {{nonexistent.path.here}}';
    const result = renderTemplate(template, event);
    expect(result).toBe('Invalid: ');
  });

  it('should preserve template content without variables', () => {
    const template = 'Static content without variables';
    const result = renderTemplate(template, event);
    expect(result).toBe('Static content without variables');
  });
});

// =============================================================================
// WebhookConnector Tests
// =============================================================================

describe('WebhookConnector', () => {
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
      const connector = new WebhookConnector(config);

      expect(connector.type).toBe('webhook');
      expect(connector.name).toBe('test-webhook');
    });

    it('should throw on missing URL', async () => {
      const config = createTestConfig({ url: '' });
      const connector = new WebhookConnector(config);

      await expect(connector.init()).rejects.toThrow('Webhook URL is required');
    });

    it('should throw on invalid URL', async () => {
      const config = createTestConfig({ url: 'not-a-valid-url' });
      const connector = new WebhookConnector(config);

      await expect(connector.init()).rejects.toThrow('Invalid webhook URL');
    });

    it('should validate bearer auth requires token', async () => {
      const config = createTestConfig({
        auth: { type: 'bearer' },
      });
      const connector = new WebhookConnector(config);

      await expect(connector.init()).rejects.toThrow('Bearer auth requires a token');
    });

    it('should validate basic auth requires credentials', async () => {
      const config = createTestConfig({
        auth: { type: 'basic', username: 'user' },
      });
      const connector = new WebhookConnector(config);

      await expect(connector.init()).rejects.toThrow('Basic auth requires username and password');
    });

    it('should validate api-key auth requires header and key', async () => {
      const config = createTestConfig({
        auth: { type: 'api-key', apiKey: 'secret' },
      });
      const connector = new WebhookConnector(config);

      await expect(connector.init()).rejects.toThrow('API key auth requires apiKeyHeader and apiKey');
    });

    it('should validate oauth2 auth requires config', async () => {
      const config = createTestConfig({
        auth: { type: 'oauth2' },
      });
      const connector = new WebhookConnector(config);

      await expect(connector.init()).rejects.toThrow('OAuth2 auth requires oauth2 configuration');
    });

    it('should validate oauth2 auth requires all fields', async () => {
      const config = createTestConfig({
        auth: {
          type: 'oauth2',
          oauth2: {
            tokenUrl: 'https://auth.example.com/token',
            clientId: 'client-id',
            clientSecret: '',
            grantType: 'client_credentials',
          },
        },
      });
      const connector = new WebhookConnector(config);

      await expect(connector.init()).rejects.toThrow('OAuth2 auth requires tokenUrl, clientId, and clientSecret');
    });

    it('should perform health check on init', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
      });

      const config = createTestConfig();
      const connector = new WebhookConnector(config);

      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://webhook.example.com/events',
        { method: 'OPTIONS' }
      );
    });
  });

  describe('send', () => {
    it('should send event as JSON by default', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' }) // health check
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' }); // send

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-456');

      const sendCall = mockFetch.mock.calls[1];
      expect(sendCall[0]).toBe('https://webhook.example.com/events');
      expect(sendCall[1].method).toBe('POST');
      expect(sendCall[1].headers['Content-Type']).toBe('application/json');
      expect(JSON.parse(sendCall[1].body)).toMatchObject({
        blockedUrl: 'https://evil.com/phishing',
        orgId: 'org-123',
      });
    });

    it('should use template when provided', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        template: '{"alert": "Blocked {{blockedUrl}} for org {{orgId}}"}',
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent();
      await connector.send(event);

      const sendCall = mockFetch.mock.calls[1];
      expect(sendCall[1].body).toBe('{"alert": "Blocked https://evil.com/phishing for org org-123"}');
    });

    it('should add custom headers', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        headers: {
          'X-Custom-Header': 'custom-value',
          'X-Source': 'browserdefense',
        },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      const headers = mockFetch.mock.calls[1][1].headers;
      expect(headers['X-Custom-Header']).toBe('custom-value');
      expect(headers['X-Source']).toBe('browserdefense');
    });

    it('should add bearer auth header', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        auth: { type: 'bearer', token: 'my-secret-token' },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      const headers = mockFetch.mock.calls[1][1].headers;
      expect(headers['Authorization']).toBe('Bearer my-secret-token');
    });

    it('should add basic auth header', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        auth: { type: 'basic', username: 'user', password: 'pass' },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      const headers = mockFetch.mock.calls[1][1].headers;
      // btoa('user:pass') = 'dXNlcjpwYXNz'
      expect(headers['Authorization']).toBe('Basic dXNlcjpwYXNz');
    });

    it('should add api-key header', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        auth: { type: 'api-key', apiKeyHeader: 'X-API-Key', apiKey: 'secret-key-123' },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      const headers = mockFetch.mock.calls[1][1].headers;
      expect(headers['X-API-Key']).toBe('secret-key-123');
    });

    it('should fetch and use OAuth2 token', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' }) // health
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            access_token: 'oauth2-token-xyz',
            expires_in: 3600,
          }),
        }) // token fetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' }); // send

      const config = createTestConfig({
        auth: {
          type: 'oauth2',
          oauth2: {
            tokenUrl: 'https://auth.example.com/oauth/token',
            clientId: 'client-123',
            clientSecret: 'client-secret',
            grantType: 'client_credentials',
            scopes: ['read', 'write'],
          },
        },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      // Verify token request
      const tokenCall = mockFetch.mock.calls[1];
      expect(tokenCall[0]).toBe('https://auth.example.com/oauth/token');
      expect(tokenCall[1].method).toBe('POST');
      expect(tokenCall[1].headers['Content-Type']).toBe('application/x-www-form-urlencoded');

      // Verify send request uses token
      const sendCall = mockFetch.mock.calls[2];
      expect(sendCall[1].headers['Authorization']).toBe('Bearer oauth2-token-xyz');
    });

    it('should return retryable error for 5xx responses', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          statusText: 'Service Unavailable',
          text: () => Promise.resolve('Server overloaded'),
        });

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('503');
      expect(result.error).toContain('Service Unavailable');
    });

    it('should return non-retryable error for 4xx responses', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          text: () => Promise.resolve('Invalid credentials'),
        });

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
      expect(result.error).toContain('401');
    });

    it('should return retryable error for 429 Too Many Requests', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          statusText: 'Too Many Requests',
          text: () => Promise.resolve('Rate limited'),
        });

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should return retryable error for network failures', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockRejectedValueOnce(new Error('fetch failed: ECONNREFUSED'));

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('ECONNREFUSED');
    });

    it('should use PUT method when configured', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({ method: 'PUT' });
      const connector = new WebhookConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      expect(mockFetch.mock.calls[1][1].method).toBe('PUT');
    });
  });

  describe('health', () => {
    it('should report healthy when OPTIONS succeeds', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
    });

    it('should try HEAD when OPTIONS returns 405', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: false, status: 405, statusText: 'Method Not Allowed' }) // OPTIONS
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' }); // HEAD

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://webhook.example.com/events',
        { method: 'OPTIONS' }
      );
      expect(mockFetch).toHaveBeenCalledWith(
        'https://webhook.example.com/events',
        { method: 'HEAD' }
      );
    });

    it('should report unhealthy on 5xx response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      // Init will warn but not throw on health check failure
      console.warn = vi.fn();
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('500');
    });

    it('should report unhealthy on network error', async () => {
      mockFetch.mockRejectedValue(new Error('Network unreachable'));

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      console.warn = vi.fn();
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Network unreachable');
    });

    it('should include metrics in health status', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' }) // init health
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' }) // send
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' }); // health check

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();
      await connector.send(createTestEvent());

      const health = await connector.health();

      expect(health.metrics).toBeDefined();
      expect(health.metrics!.eventsSent).toBe(1);
      expect(health.metrics!.uptimeSeconds).toBeGreaterThanOrEqual(0);
    });
  });

  describe('filtering', () => {
    it('should filter events by orgId', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        filter: { orgIds: ['org-allowed'] },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent({ orgId: 'org-other' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ filtered: true });

      // Should only have one call (health check), not the send
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should filter events by matchType', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        filter: { matchTypes: ['domain'] },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent({ matchType: 'url' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ filtered: true });
    });

    it('should filter events by exclude pattern', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        filter: { excludePatterns: ['^https://internal\\.'] },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent({ blockedUrl: 'https://internal.example.com/test' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ filtered: true });
    });

    it('should send event when all filters pass', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        filter: {
          orgIds: ['org-123'],
          matchTypes: ['url', 'domain'],
        },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent({ orgId: 'org-123', matchType: 'url' });
      await connector.send(event);

      // Should have two calls: health check + send
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('close', () => {
    it('should flush buffered events on close', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        batch: { maxSize: 10, maxWaitMs: 60000 },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      // Send event (will be buffered)
      await connector.send(createTestEvent());

      // Close should flush
      await connector.close();

      // Health check + batched send
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should prevent further operations after close', async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();
      await connector.close();

      await expect(connector.send(createTestEvent())).rejects.toThrow('has been closed');
    });
  });

  describe('unblock', () => {
    it('should support unblocking', () => {
      const config = createTestConfig();
      const connector = new WebhookConnector(config);

      expect(connector.supportsUnblock).toBe(true);
    });

    it('should send unblock event successfully', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' }) // health
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' }); // unblock

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent({ action: 'unblock' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-456');
      expect(result.alreadyClosed).toBe(false);

      // Verify the event was sent with action=unblock in the body
      const sendCall = mockFetch.mock.calls[1];
      const body = JSON.parse(sendCall[1].body);
      expect(body.action).toBe('unblock');
    });

    it('should use template with action field for unblock', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        template: '{"type": "{{action}}", "url": "{{blockedUrl}}", "event_id": "{{eventId}}"}',
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent({ action: 'unblock' });
      await connector.unblock(event);

      const sendCall = mockFetch.mock.calls[1];
      expect(sendCall[1].body).toBe('{"type": "unblock", "url": "https://evil.com/phishing", "event_id": "evt-456"}');
    });

    it('should return error on unblock failure', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          text: () => Promise.resolve('Invalid payload'),
        });

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent({ action: 'unblock' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('400');
      expect(result.retryable).toBe(false);
    });

    it('should return retryable error for 5xx unblock failures', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          statusText: 'Service Unavailable',
          text: () => Promise.resolve('Server overloaded'),
        });

      const config = createTestConfig();
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent({ action: 'unblock' });
      const result = await connector.unblock(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should use authentication for unblock requests', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' })
        .mockResolvedValueOnce({ ok: true, status: 200, statusText: 'OK' });

      const config = createTestConfig({
        auth: { type: 'bearer', token: 'my-secret-token' },
      });
      const connector = new WebhookConnector(config);
      await connector.init();

      const event = createTestEvent({ action: 'unblock' });
      await connector.unblock(event);

      const headers = mockFetch.mock.calls[1][1].headers;
      expect(headers['Authorization']).toBe('Bearer my-secret-token');
    });
  });
});

// =============================================================================
// Factory Registration Tests
// =============================================================================

describe('WebhookConnector Factory', () => {
  it('should create connector via factory function', () => {
    const config = createTestConfig();
    const connector = createWebhookConnector(config);

    expect(connector).toBeInstanceOf(WebhookConnector);
    expect(connector.type).toBe('webhook');
  });

  it('should be registered in the global registry', () => {
    expect(connectorRegistry.has('webhook')).toBe(true);
  });

  it('should create connector via registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);

    expect(connector.type).toBe('webhook');
    expect(connector.name).toBe('test-webhook');
  });
});
