import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ZscalerConnector, createZscalerConnector } from '../../src/connectors/zscaler';
import type { ForensicsEvent, ZscalerConnectorConfig } from '../../src/connectors/types';
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

function createTestConfig(overrides: Partial<ZscalerConnectorConfig> = {}): ZscalerConnectorConfig {
  return {
    type: 'zscaler',
    name: 'test-zscaler',
    enabled: true,
    baseUrl: 'https://zsapi.zscaler.net/api/v1',
    username: 'test-user@example.com',
    password: 'test-password-123',
    apiKey: 'abcdefghij0123456789', // 20 chars for obfuscation
    batch: { maxSize: 1, maxWaitMs: 0 },
    ...overrides,
  };
}

function mockAuthResponse() {
  return {
    ok: true,
    status: 200,
    headers: new Headers({
      'set-cookie': 'JSESSIONID=test-session-id-123; Path=/; HttpOnly',
    }),
    text: () => Promise.resolve('{}'),
  };
}

function mockApiResponse(body: unknown = {}) {
  return {
    ok: true,
    status: 200,
    text: () => Promise.resolve(JSON.stringify(body)),
  };
}

// =============================================================================
// ZscalerConnector Tests
// =============================================================================

describe('ZscalerConnector', () => {
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
    it('should create connector with valid config using baseUrl', () => {
      const config = createTestConfig();
      const connector = new ZscalerConnector(config);

      expect(connector.type).toBe('zscaler');
      expect(connector.name).toBe('test-zscaler');
    });

    it('should create connector with cloudName', () => {
      const config = createTestConfig({
        baseUrl: undefined,
        cloudName: 'zscaler.net',
      });
      const connector = new ZscalerConnector(config);

      expect(connector.type).toBe('zscaler');
    });

    it('should strip trailing slashes from baseUrl', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse());

      const config = createTestConfig({ baseUrl: 'https://zsapi.zscaler.net/api/v1///' });
      const connector = new ZscalerConnector(config);
      await connector.init();

      // Check that the auth URL doesn't have trailing slashes
      expect(mockFetch.mock.calls[0][0]).toBe(
        'https://zsapi.zscaler.net/api/v1/authenticatedSession'
      );
    });

    it('should throw on missing baseUrl and cloudName', async () => {
      const config = createTestConfig({ baseUrl: undefined, cloudName: undefined });
      const connector = new ZscalerConnector(config);

      await expect(connector.init()).rejects.toThrow('Zscaler base URL or cloudName is required');
    });

    it('should throw on missing username', async () => {
      const config = createTestConfig({ username: '' });
      const connector = new ZscalerConnector(config);

      await expect(connector.init()).rejects.toThrow('Zscaler username is required');
    });

    it('should throw on missing password', async () => {
      const config = createTestConfig({ password: '' });
      const connector = new ZscalerConnector(config);

      await expect(connector.init()).rejects.toThrow('Zscaler password is required');
    });

    it('should throw on missing apiKey', async () => {
      const config = createTestConfig({ apiKey: '' });
      const connector = new ZscalerConnector(config);

      await expect(connector.init()).rejects.toThrow('Zscaler apiKey is required');
    });

    it('should authenticate and get session cookie on init', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse());

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const authCall = mockFetch.mock.calls[0];
      expect(authCall[0]).toBe('https://zsapi.zscaler.net/api/v1/authenticatedSession');
      expect(authCall[1].method).toBe('POST');

      const body = JSON.parse(authCall[1].body);
      expect(body.username).toBe('test-user@example.com');
      expect(body.password).toBe('test-password-123');
      expect(body.apiKey).toBeDefined();
      expect(body.timestamp).toBeDefined();
    });

    it('should throw on auth failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: () => Promise.resolve('Invalid credentials'),
      });

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);

      await expect(connector.init()).rejects.toThrow('Zscaler authentication failed (401)');
    });

    it('should throw on missing session cookie', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({}), // No set-cookie header
        text: () => Promise.resolve('{}'),
      });

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);

      await expect(connector.init()).rejects.toThrow('missing session cookie');
    });

    it('should perform health check after authentication', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse());

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const healthCall = mockFetch.mock.calls[1];
      expect(healthCall[0]).toContain('/security/advanced');
      expect(healthCall[1].method).toBe('GET');
      expect(healthCall[1].headers['Cookie']).toBe('JSESSIONID=test-session-id-123');
    });

    it('should throw on failed health check', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce({ ok: false, status: 500 });

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);

      await expect(connector.init()).rejects.toThrow('Zscaler health check failed');
    });

    it('should use default action of block', () => {
      const config = createTestConfig();
      const connector = new ZscalerConnector(config);

      expect((connector as unknown as { action: string }).action).toBe('block');
    });

    it('should resolve baseUrl from cloudName', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse());

      const config = createTestConfig({
        baseUrl: undefined,
        cloudName: 'zscalertwo.net',
      });
      const connector = new ZscalerConnector(config);
      await connector.init();

      expect(mockFetch.mock.calls[0][0]).toBe(
        'https://zsapi.zscalertwo.net/api/v1/authenticatedSession'
      );
    });
  });

  // ===========================================================================
  // Block Action
  // ===========================================================================

  describe('send (block action)', () => {
    it('should add indicator to blacklist', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse()) // auth
        .mockResolvedValueOnce(mockApiResponse()) // health
        .mockResolvedValueOnce(mockApiResponse({ success: true })); // block

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-456');

      const sendCall = mockFetch.mock.calls[2];
      expect(sendCall[0]).toContain('/security/advanced/blacklistUrls');
      expect(sendCall[0]).toContain('action=ADD_TO_LIST');
      expect(sendCall[1].method).toBe('POST');

      const body = JSON.parse(sendCall[1].body);
      expect(body.blacklistUrls).toEqual(['evil.com/phishing']);
    });

    it('should use matchedIndicator when available', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce(mockApiResponse({ success: true }));

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: 'specific-indicator.com',
        blockedUrl: 'https://different-url.com',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[2][1].body);
      expect(body.blacklistUrls).toEqual(['specific-indicator.com']);
    });

    it('should fallback to blockedUrl when no matchedIndicator', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce(mockApiResponse({ success: true }));

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const event = createTestEvent({
        matchedIndicator: undefined,
        blockedUrl: 'https://fallback-url.com/path',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[2][1].body);
      expect(body.blacklistUrls).toEqual(['https://fallback-url.com/path']);
    });

    it('should activate changes when configured', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce(mockApiResponse({ success: true })) // block
        .mockResolvedValueOnce(mockApiResponse()); // activate

      const config = createTestConfig({ activateChanges: true });
      const connector = new ZscalerConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const activateCall = mockFetch.mock.calls[3];
      expect(activateCall[0]).toContain('/status/activate');
      expect(activateCall[1].method).toBe('POST');
    });

    it('should not activate changes by default', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce(mockApiResponse({ success: true }));

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      // Only auth, health, and block calls - no activate
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should reject hash indicators', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse());

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const event = createTestEvent({ matchType: 'hash' });
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('does not support hash indicators');
      expect(result.retryable).toBe(false);
    });

    it('should return error when no indicator value found', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse());

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
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
  // Unblock Action
  // ===========================================================================

  describe('send (unblock action)', () => {
    it('should remove indicator from blacklist', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce(mockApiResponse({ success: true }));

      const config = createTestConfig({ action: 'unblock' });
      const connector = new ZscalerConnector(config);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const sendCall = mockFetch.mock.calls[2];
      expect(sendCall[0]).toContain('action=REMOVE_FROM_LIST');
    });
  });

  // ===========================================================================
  // Error Handling
  // ===========================================================================

  describe('error handling', () => {
    it('should return retryable error on 5xx response', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          text: () => Promise.resolve('Service unavailable'),
        });

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('503');
    });

    it('should return retryable error on 429 response', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          text: () => Promise.resolve('Rate limited'),
        });

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should return retryable error on network failure', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockRejectedValueOnce(new Error('fetch failed: ECONNREFUSED'));

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('ECONNREFUSED');
    });

    it('should return non-retryable error on 4xx response', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce({
          ok: false,
          status: 400,
          text: () => Promise.resolve('Bad request'),
        });

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
    });

    it('should fail if activate changes fails', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce(mockApiResponse({ success: true }))
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          text: () => Promise.resolve('Activate failed'),
        });

      const config = createTestConfig({ activateChanges: true });
      const connector = new ZscalerConnector(config);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('activate changes failed');
    });
  });

  // ===========================================================================
  // Session Management
  // ===========================================================================

  describe('session management', () => {
    it('should reuse session cookie for subsequent requests', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce(mockApiResponse({ success: true }))
        .mockResolvedValueOnce(mockApiResponse({ success: true }));

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      await connector.send(createTestEvent());
      await connector.send(createTestEvent());

      // Only one auth call
      const authCalls = mockFetch.mock.calls.filter((call) =>
        call[0].includes('authenticatedSession')
      );
      expect(authCalls.length).toBe(1);
    });

    it('should include session cookie in all API requests', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse())
        .mockResolvedValueOnce(mockApiResponse({ success: true }));

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      await connector.send(createTestEvent());

      // Check health and send calls have cookie
      const healthCall = mockFetch.mock.calls[1];
      const sendCall = mockFetch.mock.calls[2];

      expect(healthCall[1].headers['Cookie']).toBe('JSESSIONID=test-session-id-123');
      expect(sendCall[1].headers['Cookie']).toBe('JSESSIONID=test-session-id-123');
    });
  });

  // ===========================================================================
  // Health Check
  // ===========================================================================

  describe('health', () => {
    it('should report healthy when API returns 200', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse()) // init health
        .mockResolvedValueOnce(mockApiResponse()); // subsequent health

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toBe('ok');
    });

    it('should report unhealthy on API error', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse()) // init health
        .mockResolvedValueOnce({ ok: false, status: 500 }); // subsequent health

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('500');
    });

    it('should report unhealthy on network error', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse()) // init health
        .mockRejectedValueOnce(new Error('Network timeout'));

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
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
    it('should clear session on close', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse());

      const config = createTestConfig();
      const connector = new ZscalerConnector(config);
      await connector.init();

      await connector.close();

      // Session should be cleared
      expect((connector as unknown as { sessionCookie: string | null }).sessionCookie).toBeNull();
    });
  });

  // ===========================================================================
  // API Key Obfuscation
  // ===========================================================================

  describe('API key obfuscation', () => {
    it('should obfuscate API key in auth request', async () => {
      mockFetch
        .mockResolvedValueOnce(mockAuthResponse())
        .mockResolvedValueOnce(mockApiResponse());

      const config = createTestConfig({ apiKey: 'abcdefghij0123456789' });
      const connector = new ZscalerConnector(config);
      await connector.init();

      const authCall = mockFetch.mock.calls[0];
      const body = JSON.parse(authCall[1].body);

      // The obfuscated key should not equal the original
      expect(body.apiKey).not.toBe('abcdefghij0123456789');
      // Should include timestamp
      expect(body.timestamp).toBeGreaterThan(0);
      // Obfuscated key should be 12 characters (6 from n + 6 from r)
      expect(body.apiKey.length).toBe(12);
    });
  });
});

// =============================================================================
// Factory Registration Tests
// =============================================================================

describe('ZscalerConnector Factory', () => {
  it('should create connector via factory function', () => {
    const config = createTestConfig();
    const connector = createZscalerConnector(config);

    expect(connector).toBeInstanceOf(ZscalerConnector);
    expect(connector.type).toBe('zscaler');
  });

  it('should be registered in the global registry', () => {
    expect(connectorRegistry.has('zscaler')).toBe(true);
  });

  it('should create connector via registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);

    expect(connector.type).toBe('zscaler');
    expect(connector.name).toBe('test-zscaler');
  });
});
