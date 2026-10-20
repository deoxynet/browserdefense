import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { DefenderConnector, createDefenderConnector } from '../../src/connectors/defender';
import { DefenderConnectorConfig, ForensicsEvent } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

const validConfig: DefenderConnectorConfig = {
  type: 'defender',
  name: 'test-defender',
  enabled: true,
  tenantId: 'test-tenant-id',
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  // Disable batching for tests to get direct send results
  batch: { maxSize: 1, maxWaitMs: 0 },
};

const createTestEvent = (overrides: Partial<ForensicsEvent> = {}): ForensicsEvent => ({
  blockedUrl: 'https://evil.com/phishing',
  timestamp: '2024-01-15T10:30:00.000Z',
  redirectChain: ['https://legit.com', 'https://redirect.com'],
  tabContext: {
    tabId: 123,
    windowId: 1,
    initiatorUrl: 'https://email.com/inbox',
    tabTitle: 'Your Account',
    incognito: false,
  },
  orgId: 'org-123',
  eventId: 'evt-abc-123',
  matchType: 'url',
  matchedIndicator: 'evil.com/phishing',
  userId: 'user@example.com',
  deviceId: 'device-456',
  raw: {},
  ...overrides,
});

// =============================================================================
// Mock Setup
// =============================================================================

const mockFetch = vi.fn();
global.fetch = mockFetch;

// Helper to create mock responses
const mockTokenResponse = (accessToken = 'mock-access-token', expiresIn = 3600) => ({
  ok: true,
  json: async () => ({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: expiresIn,
  }),
});

const mockIndicatorResponse = (id = 'indicator-123') => ({
  ok: true,
  json: async () => ({ id }),
});

const mockHealthResponse = () => ({
  ok: true,
  json: async () => ({ value: [] }),
});

const mockErrorResponse = (status: number, message: string, code?: string) => ({
  ok: false,
  status,
  statusText: message,
  text: async () => JSON.stringify({ error: { code: code ?? 'Error', message } }),
});

// =============================================================================
// Tests
// =============================================================================

describe('DefenderConnector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('constructor', () => {
    it('should create connector with valid config', () => {
      const connector = new DefenderConnector(validConfig);
      expect(connector.type).toBe('defender');
      expect(connector.name).toBe('test-defender');
    });

    it('should accept optional runtime config', () => {
      const configWithOptions = {
        ...validConfig,
        action: 'AlertAndBlock' as const,
        severity: 'High' as const,
        generateAlert: false,
        expirationHours: 24,
      };
      const connector = new DefenderConnector(configWithOptions);
      expect(connector.name).toBe('test-defender');
    });
  });

  describe('init()', () => {
    it('should initialize successfully with valid credentials', async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());

      const connector = new DefenderConnector(validConfig);
      await expect(connector.init()).resolves.not.toThrow();
    });

    it('should throw if tenantId is missing', async () => {
      const config = { ...validConfig, tenantId: '' };
      const connector = new DefenderConnector(config);
      await expect(connector.init()).rejects.toThrow('tenantId is required');
    });

    it('should throw if clientId is missing', async () => {
      const config = { ...validConfig, clientId: '' };
      const connector = new DefenderConnector(config);
      await expect(connector.init()).rejects.toThrow('clientId is required');
    });

    it('should throw if both clientSecret and certificatePath are missing', async () => {
      const config = { ...validConfig, clientSecret: '' };
      const connector = new DefenderConnector(config);
      await expect(connector.init()).rejects.toThrow('clientSecret or certificatePath is required');
    });

    it('should throw if token fetch fails', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: async () => 'Invalid client credentials',
      });

      const connector = new DefenderConnector(validConfig);
      await expect(connector.init()).rejects.toThrow('Failed to authenticate with Azure AD');
    });

    it('should throw if already initialized', async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());

      const connector = new DefenderConnector(validConfig);
      await connector.init();
      await expect(connector.init()).rejects.toThrow('already initialized');
    });
  });

  describe('send()', () => {
    it('should send event as indicator', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse()) // init token
        .mockResolvedValueOnce(mockIndicatorResponse('ind-789')); // send indicator

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-abc-123');
      expect(result.response).toEqual({ indicatorId: 'ind-789' });

      // Verify the indicator API call
      expect(mockFetch).toHaveBeenCalledTimes(2);
      const sendCall = mockFetch.mock.calls[1];
      expect(sendCall[0]).toBe('https://api.securitycenter.microsoft.com/api/indicators');
      expect(sendCall[1].method).toBe('POST');
      expect(sendCall[1].headers['Authorization']).toBe('Bearer mock-access-token');

      const body = JSON.parse(sendCall[1].body);
      expect(body.indicatorValue).toBe('https://evil.com/phishing');
      expect(body.indicatorType).toBe('Url');
      expect(body.action).toBe('Alert');
      expect(body.severity).toBe('Medium');
      expect(body.generateAlert).toBe(true);
    });

    it('should use cached token for subsequent sends', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse()) // init token
        .mockResolvedValueOnce(mockIndicatorResponse())
        .mockResolvedValueOnce(mockIndicatorResponse());

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      await connector.send(createTestEvent({ eventId: 'evt-1' }));
      await connector.send(createTestEvent({ eventId: 'evt-2' }));

      // Should only call token endpoint once
      const tokenCalls = mockFetch.mock.calls.filter(call =>
        call[0].includes('oauth2/v2.0/token')
      );
      expect(tokenCalls.length).toBe(1);
    });

    it('should refresh token when expired', async () => {
      // Token expires in 10 min, buffer is 5 min, so valid for ~5 min
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse('token-1', 600))
        .mockResolvedValueOnce(mockIndicatorResponse())
        .mockResolvedValueOnce(mockTokenResponse('token-2', 3600)) // new token
        .mockResolvedValueOnce(mockIndicatorResponse());

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      await connector.send(createTestEvent({ eventId: 'evt-1' }));

      // Fast-forward past the effective validity (expiry - buffer = 600 - 300 = 300s)
      vi.advanceTimersByTime(350 * 1000);

      await connector.send(createTestEvent({ eventId: 'evt-2' }));

      // Should have fetched token twice
      const tokenCalls = mockFetch.mock.calls.filter(call =>
        call[0].includes('oauth2/v2.0/token')
      );
      expect(tokenCalls.length).toBe(2);
    });

    it('should handle API errors with retryable status', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockResolvedValueOnce(mockErrorResponse(429, 'Too many requests', 'TooManyRequests'));

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('429');
    });

    it('should handle API errors with non-retryable status', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockResolvedValueOnce(mockErrorResponse(400, 'Bad request'));

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
      expect(result.error).toContain('400');
    });

    it('should handle network errors', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockRejectedValueOnce(new Error('Network error'));

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
      expect(result.error).toContain('Network error');
    });

    it('should throw if not initialized', async () => {
      const connector = new DefenderConnector(validConfig);
      await expect(connector.send(createTestEvent())).rejects.toThrow('not initialized');
    });
  });

  describe('health()', () => {
    it('should return healthy status when API is accessible', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockResolvedValueOnce(mockHealthResponse());

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('Connected to Microsoft Defender API');
    });

    it('should return unhealthy status on permission error', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockResolvedValueOnce(mockErrorResponse(403, 'Forbidden'));

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Insufficient permissions');
    });

    it('should return unhealthy status on API error', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockResolvedValueOnce(mockErrorResponse(500, 'Internal Server Error'));

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('500');
    });

    it('should return unhealthy status on network error', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockRejectedValueOnce(new Error('Connection refused'));

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Connection refused');
    });
  });

  describe('close()', () => {
    it('should close successfully', async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());

      const connector = new DefenderConnector(validConfig);
      await connector.init();
      await expect(connector.close()).resolves.not.toThrow();
    });

    it('should clear cached token on close', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse('token-1'))
        .mockResolvedValueOnce(mockIndicatorResponse())
        .mockResolvedValueOnce(mockTokenResponse('token-2')) // reinit token
        .mockResolvedValueOnce(mockIndicatorResponse());

      const connector = new DefenderConnector(validConfig);
      await connector.init();
      await connector.send(createTestEvent());
      await connector.close();

      // After closing, a new init should fetch a fresh token
      const connector2 = new DefenderConnector(validConfig);
      await connector2.init();
      await connector2.send(createTestEvent());

      const tokenCalls = mockFetch.mock.calls.filter(call =>
        call[0].includes('oauth2/v2.0/token')
      );
      expect(tokenCalls.length).toBe(2);
    });
  });

  describe('indicator type mapping', () => {
    it('should map domain match to DomainName indicator', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockResolvedValueOnce(mockIndicatorResponse());

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const event = createTestEvent({
        matchType: 'domain',
        matchedIndicator: 'evil.com',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.indicatorType).toBe('DomainName');
      expect(body.indicatorValue).toBe('evil.com');
    });

    it('should map url match to Url indicator', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockResolvedValueOnce(mockIndicatorResponse());

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const event = createTestEvent({
        matchType: 'url',
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.indicatorType).toBe('Url');
    });

    it('should map SHA256 hash to FileSha256 indicator', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockResolvedValueOnce(mockIndicatorResponse());

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const sha256 = 'a'.repeat(64);
      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: sha256,
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.indicatorType).toBe('FileSha256');
      expect(body.indicatorValue).toBe(sha256);
    });

    it('should map SHA1 hash to FileSha1 indicator', async () => {
      mockFetch
        .mockResolvedValueOnce(mockTokenResponse())
        .mockResolvedValueOnce(mockIndicatorResponse());

      const connector = new DefenderConnector(validConfig);
      await connector.init();

      const sha1 = 'b'.repeat(40);
      const event = createTestEvent({
        matchType: 'hash',
        matchedIndicator: sha1,
      });
      await connector.send(event);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.indicatorType).toBe('FileSha1');
      expect(body.indicatorValue).toBe(sha1);
    });
  });

  describe('shouldProcess filtering', () => {
    it('should filter events based on orgId', async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());

      const config: DefenderConnectorConfig = {
        ...validConfig,
        filter: {
          orgIds: ['org-allowed'],
        },
      };

      const connector = new DefenderConnector(config);
      await connector.init();

      const allowedEvent = createTestEvent({ orgId: 'org-allowed' });
      const deniedEvent = createTestEvent({ orgId: 'org-denied' });

      expect(connector.shouldProcess(allowedEvent)).toBe(true);
      expect(connector.shouldProcess(deniedEvent)).toBe(false);
    });

    it('should filter events based on matchType', async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());

      const config: DefenderConnectorConfig = {
        ...validConfig,
        filter: {
          matchTypes: ['domain', 'url'],
        },
      };

      const connector = new DefenderConnector(config);
      await connector.init();

      const domainEvent = createTestEvent({ matchType: 'domain' });
      const hashEvent = createTestEvent({ matchType: 'hash' });

      expect(connector.shouldProcess(domainEvent)).toBe(true);
      expect(connector.shouldProcess(hashEvent)).toBe(false);
    });

    it('should filter events based on excludePatterns', async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());

      const config: DefenderConnectorConfig = {
        ...validConfig,
        filter: {
          excludePatterns: ['^https://internal\\.'],
        },
      };

      const connector = new DefenderConnector(config);
      await connector.init();

      const externalEvent = createTestEvent({ blockedUrl: 'https://evil.com/page' });
      const internalEvent = createTestEvent({ blockedUrl: 'https://internal.example.com/page' });

      expect(connector.shouldProcess(externalEvent)).toBe(true);
      expect(connector.shouldProcess(internalEvent)).toBe(false);
    });
  });

  describe('registry integration', () => {
    it('should be registered in connector registry', () => {
      expect(connectorRegistry.has('defender')).toBe(true);
    });

    it('should create connector via registry', async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());

      const connector = connectorRegistry.create(validConfig);
      expect(connector.type).toBe('defender');
      expect(connector.name).toBe('test-defender');
      await connector.init();
    });

    it('should create connector via factory function', async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());

      const connector = createDefenderConnector(validConfig);
      expect(connector).toBeInstanceOf(DefenderConnector);
      await connector.init();
    });
  });
});
