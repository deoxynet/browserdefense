import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  ChronicleConnector,
  ChronicleApiError,
  type ChronicleConnectorConfig,
  type ForensicsEvent,
} from '../../src/connectors';

// =============================================================================
// Test Fixtures
// =============================================================================

/**
 * Mock service account credentials for testing.
 * Note: This uses a proper PEM format but with mock content.
 */
const mockCredentials = {
  type: 'service_account' as const,
  project_id: 'test-project',
  private_key_id: 'key-id-123',
  private_key: ['-----BEGIN PRIVATE KEY-----', btoa('test-only-not-a-key'), '-----END PRIVATE KEY-----'].join('\n'),
  client_email: 'test@test-project.iam.gserviceaccount.com',
  client_id: '123456789',
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://oauth2.googleapis.com/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url:
    'https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project.iam.gserviceaccount.com',
};

/**
 * Create a test config.
 * By default disables batching (maxSize: 1) for easier testing.
 */
function createTestConfig(
  overrides: Partial<ChronicleConnectorConfig> = {}
): ChronicleConnectorConfig {
  return {
    type: 'chronicle',
    name: 'test-chronicle',
    enabled: true,
    customerId: 'test-customer-123',
    region: 'us',
    credentials: mockCredentials,
    logType: 'BROWSERDEFENSE',
    // Disable batching for tests by setting maxSize to 1
    batch: { maxSize: 1, maxWaitMs: 5000 },
    ...overrides,
  };
}

/**
 * Create a test forensics event.
 */
function createTestEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    blockedUrl: 'https://evil.com/phishing',
    timestamp: '2024-01-15T10:30:00.000Z',
    redirectChain: ['https://legitimate.com/link'],
    tabContext: {
      tabId: 123,
      windowId: 1,
      initiatorUrl: 'https://legitimate.com',
      tabTitle: 'Test Page',
      incognito: false,
    },
    orgId: 'org-123',
    eventId: 'evt-456',
    matchType: 'domain',
    matchedIndicator: 'evil.com',
    raw: {},
    ...overrides,
  };
}

// =============================================================================
// Mock setup
// =============================================================================

let mockFetch: ReturnType<typeof vi.fn>;

beforeEach(() => {
  // Mock fetch
  mockFetch = vi.fn();
  vi.stubGlobal('fetch', mockFetch);

  // Mock crypto.subtle methods for JWT signing
  const mockCryptoKey = { type: 'private' } as CryptoKey;
  vi.spyOn(crypto.subtle, 'importKey').mockResolvedValue(mockCryptoKey);
  vi.spyOn(crypto.subtle, 'sign').mockResolvedValue(new Uint8Array(256).buffer);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// =============================================================================
// Tests
// =============================================================================

describe('ChronicleConnector', () => {
  describe('constructor', () => {
    it('should create connector with valid config', () => {
      const config = createTestConfig();
      const connector = new ChronicleConnector(config);

      expect(connector.type).toBe('chronicle');
      expect(connector.name).toBe('test-chronicle');
    });

    it('should accept all valid regions', () => {
      const regions: Array<'us' | 'europe' | 'asia-southeast1'> = [
        'us',
        'europe',
        'asia-southeast1',
      ];

      for (const region of regions) {
        const config = createTestConfig({ region });
        const connector = new ChronicleConnector(config);
        expect(connector.type).toBe('chronicle');
      }
    });

    it('should throw on invalid region', () => {
      const config = createTestConfig({ region: 'invalid' as 'us' });
      expect(() => new ChronicleConnector(config)).toThrow('Unknown Chronicle region');
    });
  });

  describe('init', () => {
    it('should initialize with valid credentials', async () => {
      const config = createTestConfig();
      const connector = new ChronicleConnector(config);

      // Mock token endpoint
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await expect(connector.init()).resolves.toBeUndefined();
    });

    it('should throw on invalid credentials object', async () => {
      const config = createTestConfig({
        credentials: {
          ...mockCredentials,
          client_email: '',
        },
      });
      const connector = new ChronicleConnector(config);

      await expect(connector.init()).rejects.toThrow('missing client_email');
    });

    it('should throw on invalid credentials JSON string', async () => {
      const config = createTestConfig({
        credentials: '{invalid json',
      });
      const connector = new ChronicleConnector(config);

      await expect(connector.init()).rejects.toThrow('Invalid JSON');
    });

    it('should parse credentials from JSON string', async () => {
      const config = createTestConfig({
        credentials: JSON.stringify(mockCredentials),
      });
      const connector = new ChronicleConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await expect(connector.init()).resolves.toBeUndefined();
    });

    it('should throw on file path credentials (not supported in browser)', async () => {
      const config = createTestConfig({
        credentials: '/path/to/credentials.json',
      });
      const connector = new ChronicleConnector(config);

      await expect(connector.init()).rejects.toThrow('File-based credentials not supported');
    });

    it('should throw if token fetch fails', async () => {
      const config = createTestConfig();
      const connector = new ChronicleConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: () => Promise.resolve('Invalid credentials'),
      });

      await expect(connector.init()).rejects.toThrow('Failed to get access token');
    });
  });

  describe('send', () => {
    let connector: ChronicleConnector;

    beforeEach(async () => {
      const config = createTestConfig();
      connector = new ChronicleConnector(config);

      // Mock token fetch for init
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await connector.init();
    });

    it('should send event successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-456');
    });

    it('should transform event to UDM format', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return {
          ok: true,
          json: () => Promise.resolve({}),
        };
      });

      const event = createTestEvent();
      await connector.send(event);

      expect(capturedBody).toBeDefined();
      const body = JSON.parse(capturedBody!);

      expect(body.customer_id).toBe('test-customer-123');
      expect(body.log_type).toBe('BROWSERDEFENSE');
      expect(body.events).toHaveLength(1);

      const udmEvent = body.events[0].udm;
      expect(udmEvent.metadata.event_type).toBe('NETWORK_HTTP');
      expect(udmEvent.metadata.product_name).toBe('BrowserDefense');
      expect(udmEvent.target.url).toBe('https://evil.com/phishing');
      expect(udmEvent.security_result[0].action).toContain('BLOCK');
    });

    it('should use correct regional endpoint', async () => {
      let capturedUrl: string | undefined;

      mockFetch.mockImplementationOnce(async (url: string) => {
        capturedUrl = url;
        return {
          ok: true,
          json: () => Promise.resolve({}),
        };
      });

      await connector.send(createTestEvent());

      expect(capturedUrl).toBe(
        'https://malachiteingestion-pa.googleapis.com/v2/udmevents:batchCreate'
      );
    });

    it('should include authorization header', async () => {
      let capturedHeaders: HeadersInit | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedHeaders = options.headers;
        return {
          ok: true,
          json: () => Promise.resolve({}),
        };
      });

      await connector.send(createTestEvent());

      expect(capturedHeaders).toBeDefined();
      const headers = capturedHeaders as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer test-token');
    });

    it('should handle API errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        text: () => Promise.resolve('Bad request'),
      });

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.error).toContain('Chronicle API error');
      expect(result.retryable).toBe(false);
    });

    it('should mark 5xx errors as retryable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
        text: () => Promise.resolve('Service unavailable'),
      });

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should mark 429 errors as retryable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        text: () => Promise.resolve('Rate limited'),
      });

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should throw if not initialized', async () => {
      const uninitConnector = new ChronicleConnector(createTestConfig());

      await expect(uninitConnector.send(createTestEvent())).rejects.toThrow(
        'not initialized'
      );
    });
  });

  describe('sendBatch', () => {
    let connector: ChronicleConnector;

    beforeEach(async () => {
      const config = createTestConfig();
      connector = new ChronicleConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await connector.init();
    });

    it('should send multiple events in one request', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return {
          ok: true,
          json: () => Promise.resolve({}),
        };
      });

      const events = [
        createTestEvent({ eventId: 'evt-1' }),
        createTestEvent({ eventId: 'evt-2' }),
        createTestEvent({ eventId: 'evt-3' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results).toHaveLength(3);
      expect(results.every((r) => r.success)).toBe(true);

      const body = JSON.parse(capturedBody!);
      expect(body.events).toHaveLength(3);
    });

    it('should handle batch failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal error'),
      });

      const events = [
        createTestEvent({ eventId: 'evt-1' }),
        createTestEvent({ eventId: 'evt-2' }),
      ];

      const results = await connector.sendBatch(events);

      expect(results).toHaveLength(2);
      expect(results.every((r) => !r.success)).toBe(true);
      expect(results.every((r) => r.retryable)).toBe(true);
    });
  });

  describe('health', () => {
    it('should return healthy when auth succeeds', async () => {
      const connector = new ChronicleConnector(createTestConfig());

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('Connected to Chronicle');
    });

    it('should return unhealthy when auth fails', async () => {
      const connector = new ChronicleConnector(createTestConfig());

      // First call succeeds (init)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 1, // Expire immediately
            token_type: 'Bearer',
          }),
      });

      await connector.init();

      // Wait for token to expire
      await new Promise((r) => setTimeout(r, 10));

      // Second call fails (health check)
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: () => Promise.resolve('Unauthorized'),
      });

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('auth failed');
    });

    it('should include metrics', async () => {
      const connector = new ChronicleConnector(createTestConfig());

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await connector.init();

      // Send an event
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

      await connector.send(createTestEvent());

      const health = await connector.health();

      expect(health.metrics).toBeDefined();
      expect(health.metrics!.eventsSent).toBeGreaterThanOrEqual(1);
    });
  });

  describe('close', () => {
    it('should clear token cache', async () => {
      const connector = new ChronicleConnector(createTestConfig());

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await connector.init();
      await connector.close();

      // Should not be able to send after close
      await expect(connector.send(createTestEvent())).rejects.toThrow('has been closed');
    });
  });

  describe('filtering', () => {
    it('should filter by org ID', async () => {
      const config = createTestConfig({
        filter: {
          orgIds: ['allowed-org'],
        },
      });
      const connector = new ChronicleConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await connector.init();

      // Event with non-matching org should be filtered
      const event = createTestEvent({ orgId: 'other-org' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ filtered: true });
    });

    it('should filter by match type', async () => {
      const config = createTestConfig({
        filter: {
          matchTypes: ['hash'],
        },
      });
      const connector = new ChronicleConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await connector.init();

      // Domain event should be filtered when only hash is allowed
      const event = createTestEvent({ matchType: 'domain' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ filtered: true });
    });
  });

  describe('UDM transformation', () => {
    let connector: ChronicleConnector;

    beforeEach(async () => {
      connector = new ChronicleConnector(createTestConfig());

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await connector.init();
    });

    it('should map domain match type to phishing category', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent({ matchType: 'domain' }));

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.security_result[0].category_details).toContain(
        'MALWARE_CATEGORY_PHISHING'
      );
    });

    it('should map url match type to malicious URL category', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent({ matchType: 'url' }));

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.security_result[0].category_details).toContain(
        'MALWARE_CATEGORY_MALICIOUS_URL'
      );
    });

    it('should map hash match type to malware category', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent({ matchType: 'hash' }));

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.security_result[0].category_details).toContain(
        'MALWARE_CATEGORY_MALWARE'
      );
    });

    it('should include user ID when present', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent({ userId: 'user@example.com' }));

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.principal.user.userid).toBe('user@example.com');
    });

    it('should include device ID when present', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent({ deviceId: 'device-123' }));

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.principal.asset.asset_id).toBe('device-123');
    });

    it('should include redirect chain in referral URL', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(
        createTestEvent({
          redirectChain: ['https://first.com', 'https://second.com'],
        })
      );

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.network.http.referral_url).toBe('https://first.com');
    });

    it('should include additional fields', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent());

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.additional.fields.org_id.string_value).toBe('org-123');
      expect(udm.additional.fields.match_type.string_value).toBe('domain');
      expect(udm.additional.fields.matched_indicator.string_value).toBe('evil.com');
    });

    it('should default to BLOCK action when not specified', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent());

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.security_result[0].action).toContain('BLOCK');
      expect(udm.additional.fields.ioc_action.string_value).toBe('block');
      expect(udm.metadata.description).toContain('Blocked');
      expect(udm.security_result[0].severity).toBe('MEDIUM');
    });

    it('should use ALLOW action for unblock events', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent({ action: 'unblock' }));

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.security_result[0].action).toContain('ALLOW');
      expect(udm.additional.fields.ioc_action.string_value).toBe('unblock');
    });

    it('should set correct description for unblock events', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent({ action: 'unblock' }));

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.metadata.description).toContain('Unblocked');
      expect(udm.security_result[0].description).toContain('Unblocked');
    });

    it('should set lower severity for unblock events', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent({ action: 'unblock' }));

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.security_result[0].severity).toBe('LOW');
    });

    it('should set correct rule name for unblock events', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent({ action: 'unblock', matchType: 'domain' }));

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.security_result[0].rule_name).toBe('browserdefense_domain_unblocked');
    });

    it('should use BLOCK action for explicit block events', async () => {
      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent({ action: 'block' }));

      const body = JSON.parse(capturedBody!);
      const udm = body.events[0].udm;
      expect(udm.security_result[0].action).toContain('BLOCK');
      expect(udm.security_result[0].severity).toBe('MEDIUM');
      expect(udm.security_result[0].rule_name).toBe('browserdefense_domain_blocked');
    });
  });

  describe('custom labels', () => {
    it('should include custom labels in request', async () => {
      const config = createTestConfig({
        labels: [
          { key: 'environment', value: 'production' },
          { key: 'team', value: 'security' },
        ],
      });
      const connector = new ChronicleConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await connector.init();

      let capturedBody: string | undefined;

      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedBody = options.body as string;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent());

      const body = JSON.parse(capturedBody!);
      expect(body.labels).toEqual([
        { key: 'environment', value: 'production' },
        { key: 'team', value: 'security' },
      ]);
    });
  });

  describe('token caching', () => {
    it('should reuse cached token within expiry', async () => {
      const connector = new ChronicleConnector(createTestConfig());

      // Token fetch during init
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            access_token: 'cached-token',
            expires_in: 3600,
            token_type: 'Bearer',
          }),
      });

      await connector.init();

      // Send event - should reuse token, not fetch new one
      let capturedHeaders: HeadersInit | undefined;
      mockFetch.mockImplementationOnce(async (_url: string, options: RequestInit) => {
        capturedHeaders = options.headers;
        return { ok: true, json: () => Promise.resolve({}) };
      });

      await connector.send(createTestEvent());

      // Token should be reused
      const headers = capturedHeaders as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer cached-token');
    });
  });
});

describe('ChronicleApiError', () => {
  it('should include status code', () => {
    const error = new ChronicleApiError('Test error', 503);

    expect(error.message).toBe('Test error');
    expect(error.statusCode).toBe(503);
    expect(error.name).toBe('ChronicleApiError');
  });
});

describe('connectorRegistry', () => {
  it('should register chronicle connector', async () => {
    // Import to trigger registration
    await import('../../src/connectors/chronicle');

    const { connectorRegistry } = await import('../../src/connectors');

    expect(connectorRegistry.has('chronicle')).toBe(true);
  });

  it('should create chronicle connector from registry', async () => {
    const { connectorRegistry } = await import('../../src/connectors');

    const config = createTestConfig();
    const connector = connectorRegistry.create(config);

    expect(connector.type).toBe('chronicle');
    expect(connector.name).toBe('test-chronicle');
  });
});
