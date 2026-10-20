/**
 * CrowdStrike Falcon Connector Tests
 *
 * Tests OAuth2 authentication, LogScale ingestion, and IOC creation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  CrowdStrikeConnector,
  createCrowdStrikeConnector,
  getCloudBaseUrl,
  CROWDSTRIKE_REGIONS,
} from '../../src/connectors/crowdstrike';
import {
  CrowdStrikeConnectorConfig,
  ForensicsEvent,
  connectorRegistry,
} from '../../src/connectors';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestConfig(overrides?: Partial<CrowdStrikeConnectorConfig>): CrowdStrikeConnectorConfig {
  return {
    type: 'crowdstrike',
    name: 'test-crowdstrike',
    enabled: true,
    baseUrl: 'https://api.crowdstrike.com',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    iocTarget: 'ioc-manager',
    // Disable batching for unit tests to get synchronous behavior
    batch: { maxSize: 1, maxWaitMs: 0 },
    ...overrides,
  };
}

function createTestEvent(overrides?: Partial<ForensicsEvent>): ForensicsEvent {
  return {
    blockedUrl: 'https://malicious.example.com/phishing',
    timestamp: '2024-01-15T10:30:00Z',
    redirectChain: ['https://legitimate.com', 'https://redirect.com'],
    tabContext: {
      tabId: 123,
      windowId: 1,
      initiatorUrl: 'https://email.example.com',
      tabTitle: 'Test Email',
      incognito: false,
    },
    orgId: 'org-123',
    eventId: 'evt-456',
    matchType: 'domain',
    matchedIndicator: 'malicious.example.com',
    userId: 'user@example.com',
    deviceId: 'device-789',
    raw: {},
    ...overrides,
  };
}

// =============================================================================
// Mock Fetch
// =============================================================================

const mockFetch = vi.fn();
global.fetch = mockFetch;

function mockTokenResponse() {
  return {
    ok: true,
    json: () => Promise.resolve({
      access_token: 'mock-access-token',
      token_type: 'bearer',
      expires_in: 1800,
    }),
  };
}

function mockSuccessResponse(data = {}) {
  return {
    ok: true,
    status: 200,
    json: () => Promise.resolve(data),
  };
}

function mockCreatedResponse(data = {}) {
  return {
    ok: true,
    status: 201,
    json: () => Promise.resolve(data),
  };
}

function mockErrorResponse(status: number, message: string) {
  return {
    ok: false,
    status,
    json: () => Promise.resolve({
      meta: { query_time: 0.1, trace_id: 'trace-123' },
      errors: [{ code: status, message }],
    }),
  };
}

// =============================================================================
// Tests
// =============================================================================

describe('CrowdStrikeConnector', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('constructor and type', () => {
    it('should have correct type', () => {
      const connector = new CrowdStrikeConnector(createTestConfig());
      expect(connector.type).toBe('crowdstrike');
    });

    it('should have correct name from config', () => {
      const connector = new CrowdStrikeConnector(createTestConfig({ name: 'my-cs-connector' }));
      expect(connector.name).toBe('my-cs-connector');
    });
  });

  describe('init()', () => {
    it('should fetch OAuth2 token on init', async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());

      const connector = new CrowdStrikeConnector(createTestConfig());
      await connector.init();

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.crowdstrike.com/oauth2/token',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded',
          }),
        })
      );
    });

    it('should throw on missing clientId', async () => {
      const connector = new CrowdStrikeConnector(createTestConfig({ clientId: '' }));
      await expect(connector.init()).rejects.toThrow('requires clientId');
    });

    it('should throw on missing clientSecret', async () => {
      const connector = new CrowdStrikeConnector(createTestConfig({ clientSecret: '' }));
      await expect(connector.init()).rejects.toThrow('requires clientSecret');
    });

    it('should throw on missing baseUrl', async () => {
      const connector = new CrowdStrikeConnector(createTestConfig({ baseUrl: '' }));
      await expect(connector.init()).rejects.toThrow('requires baseUrl');
    });

    it('should throw on OAuth2 failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: () => Promise.resolve('Invalid credentials'),
      });

      const connector = new CrowdStrikeConnector(createTestConfig());
      await expect(connector.init()).rejects.toThrow('OAuth2 token request failed');
    });
  });

  describe('send()', () => {
    let connector: CrowdStrikeConnector;

    beforeEach(async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());
      connector = new CrowdStrikeConnector(createTestConfig());
      await connector.init();
      mockFetch.mockReset();
    });

    it('should send event to LogScale', async () => {
      mockFetch.mockResolvedValueOnce(mockSuccessResponse());
      mockFetch.mockResolvedValueOnce(mockCreatedResponse({ resources: ['ioc-id-1'] }));

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe(event.eventId);
    });

    it('should include correct LogScale payload', async () => {
      mockFetch.mockResolvedValueOnce(mockSuccessResponse());
      mockFetch.mockResolvedValueOnce(mockCreatedResponse());

      const event = createTestEvent();
      await connector.send(event);

      // First call should be to LogScale
      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'https://api.crowdstrike.com/humio/api/v1/ingest/json',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"source":"browserdefense"'),
        })
      );
    });

    it('should create IOC when iocTarget is ioc-manager', async () => {
      mockFetch.mockResolvedValueOnce(mockSuccessResponse()); // LogScale
      mockFetch.mockResolvedValueOnce(mockCreatedResponse({ resources: ['ioc-1'] })); // IOC

      const event = createTestEvent({ matchType: 'domain' });
      await connector.send(event);

      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        'https://api.crowdstrike.com/iocs/entities/indicators/v1',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"type":"domain"'),
        })
      );
    });

    it('should include applied_globally and comment in IOC payload', async () => {
      mockFetch.mockResolvedValueOnce(mockSuccessResponse()); // LogScale
      mockFetch.mockResolvedValueOnce(mockCreatedResponse({ resources: ['ioc-1'] })); // IOC

      const event = createTestEvent({ matchType: 'domain', orgId: 'test-org' });
      await connector.send(event);

      const iocCall = mockFetch.mock.calls[1];
      const iocBody = JSON.parse(iocCall[1].body);

      expect(iocBody.indicators[0].applied_globally).toBe(true);
      expect(iocBody.comment).toContain('BlockIOC detection');
      expect(iocBody.comment).toContain('test-org');
    });

    it('should handle LogScale failure', async () => {
      mockFetch.mockResolvedValueOnce(mockErrorResponse(500, 'Internal server error'));

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('LogScale ingestion failed');
      expect(result.retryable).toBe(true);
    });

    it('should skip IOC creation for unsupported match types', async () => {
      // URL match type is not supported for IOC Manager
      mockFetch.mockResolvedValueOnce(mockSuccessResponse()); // LogScale only

      const event = createTestEvent({ matchType: 'url' });
      const result = await connector.send(event);

      // Should succeed with LogScale only
      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(1); // Only LogScale, no IOC call
    });

    it('should retry on 429 rate limit', async () => {
      mockFetch.mockResolvedValueOnce(mockErrorResponse(429, 'Rate limit exceeded'));

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should retry on 5xx server errors', async () => {
      mockFetch.mockResolvedValueOnce(mockErrorResponse(503, 'Service unavailable'));

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should not retry on 4xx client errors', async () => {
      mockFetch.mockResolvedValueOnce(mockErrorResponse(400, 'Bad request'));

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
    });
  });

  describe('send() with intel-indicator target', () => {
    let connector: CrowdStrikeConnector;

    beforeEach(async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());
      connector = new CrowdStrikeConnector(createTestConfig({ iocTarget: 'intel-indicator' }));
      await connector.init();
      mockFetch.mockReset();
    });

    it('should create intel indicator', async () => {
      mockFetch.mockResolvedValueOnce(mockSuccessResponse()); // LogScale
      mockFetch.mockResolvedValueOnce(mockCreatedResponse({ resources: ['indicator-1'] })); // Intel

      const event = createTestEvent({ matchType: 'domain' });
      await connector.send(event);

      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        'https://api.crowdstrike.com/intel/entities/indicators/v1',
        expect.objectContaining({
          method: 'POST',
        })
      );
    });

    it('should support URL match type for intel indicators', async () => {
      mockFetch.mockResolvedValueOnce(mockSuccessResponse()); // LogScale
      mockFetch.mockResolvedValueOnce(mockCreatedResponse()); // Intel

      const event = createTestEvent({ matchType: 'url' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('send() with no iocTarget', () => {
    let connector: CrowdStrikeConnector;

    beforeEach(async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());
      connector = new CrowdStrikeConnector(createTestConfig({ iocTarget: undefined }));
      await connector.init();
      mockFetch.mockReset();
    });

    it('should only send to LogScale', async () => {
      mockFetch.mockResolvedValueOnce(mockSuccessResponse());

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(1); // Only LogScale
    });
  });

  describe('health()', () => {
    let connector: CrowdStrikeConnector;

    beforeEach(async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());
      connector = new CrowdStrikeConnector(createTestConfig());
      await connector.init();
      mockFetch.mockReset();
    });

    it('should return healthy when API is reachable', async () => {
      mockFetch.mockResolvedValueOnce(mockSuccessResponse());

      const status = await connector.health();

      expect(status.healthy).toBe(true);
      expect(status.message).toContain('reachable');
    });

    it('should return unhealthy on API error', async () => {
      mockFetch.mockResolvedValueOnce(mockErrorResponse(500, 'Server error'));

      const status = await connector.health();

      expect(status.healthy).toBe(false);
      expect(status.message).toContain('Server error');
    });

    it('should return unhealthy on network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const status = await connector.health();

      expect(status.healthy).toBe(false);
      expect(status.message).toContain('Network error');
    });
  });

  describe('close()', () => {
    it('should close without error', async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());
      const connector = new CrowdStrikeConnector(createTestConfig());
      await connector.init();

      await expect(connector.close()).resolves.not.toThrow();
    });
  });

  describe('shouldProcess()', () => {
    let connector: CrowdStrikeConnector;

    beforeEach(async () => {
      mockFetch.mockResolvedValueOnce(mockTokenResponse());
    });

    it('should process all events without filter', async () => {
      connector = new CrowdStrikeConnector(createTestConfig());
      await connector.init();

      const event = createTestEvent();
      expect(connector.shouldProcess(event)).toBe(true);
    });

    it('should filter by orgId', async () => {
      connector = new CrowdStrikeConnector(createTestConfig({
        filter: { orgIds: ['org-123'] },
      }));
      await connector.init();

      expect(connector.shouldProcess(createTestEvent({ orgId: 'org-123' }))).toBe(true);
      expect(connector.shouldProcess(createTestEvent({ orgId: 'org-456' }))).toBe(false);
    });

    it('should filter by matchType', async () => {
      connector = new CrowdStrikeConnector(createTestConfig({
        filter: { matchTypes: ['domain', 'hash'] },
      }));
      await connector.init();

      expect(connector.shouldProcess(createTestEvent({ matchType: 'domain' }))).toBe(true);
      expect(connector.shouldProcess(createTestEvent({ matchType: 'hash' }))).toBe(true);
      expect(connector.shouldProcess(createTestEvent({ matchType: 'url' }))).toBe(false);
    });

    it('should exclude patterns', async () => {
      connector = new CrowdStrikeConnector(createTestConfig({
        filter: { excludePatterns: ['example\\.com'] },
      }));
      await connector.init();

      expect(connector.shouldProcess(createTestEvent({ blockedUrl: 'https://malicious.example.com' }))).toBe(false);
      expect(connector.shouldProcess(createTestEvent({ blockedUrl: 'https://other.com' }))).toBe(true);
    });
  });

  describe('token refresh', () => {
    it('should refresh token when expired', async () => {
      // Initial token
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          access_token: 'token-1',
          token_type: 'bearer',
          expires_in: 1, // Expires in 1 second
        }),
      });

      const connector = new CrowdStrikeConnector(createTestConfig());
      await connector.init();

      // Wait for token to expire
      await new Promise(resolve => setTimeout(resolve, 100));

      mockFetch.mockReset();

      // Should refresh token before making API call
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          access_token: 'token-2',
          token_type: 'bearer',
          expires_in: 1800,
        }),
      });
      mockFetch.mockResolvedValueOnce(mockSuccessResponse()); // LogScale
      mockFetch.mockResolvedValueOnce(mockCreatedResponse()); // IOC

      const event = createTestEvent();
      await connector.send(event);

      // First call should be token refresh
      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'https://api.crowdstrike.com/oauth2/token',
        expect.any(Object)
      );
    });
  });
});

describe('createCrowdStrikeConnector', () => {
  it('should create connector instance', () => {
    const connector = createCrowdStrikeConnector(createTestConfig());
    expect(connector).toBeInstanceOf(CrowdStrikeConnector);
    expect(connector.type).toBe('crowdstrike');
  });
});

describe('connectorRegistry', () => {
  it('should have crowdstrike connector registered', () => {
    expect(connectorRegistry.has('crowdstrike')).toBe(true);
  });

  it('should create crowdstrike connector from registry', () => {
    const connector = connectorRegistry.create(createTestConfig());
    expect(connector).toBeInstanceOf(CrowdStrikeConnector);
  });
});

describe('getCloudBaseUrl', () => {
  it('should return correct URL for us-1', () => {
    expect(getCloudBaseUrl('us-1')).toBe('https://api.crowdstrike.com');
  });

  it('should return correct URL for us-2', () => {
    expect(getCloudBaseUrl('us-2')).toBe('https://api.us-2.crowdstrike.com');
  });

  it('should return correct URL for eu-1', () => {
    expect(getCloudBaseUrl('eu-1')).toBe('https://api.eu-1.crowdstrike.com');
  });

  it('should return correct URL for us-gov-1', () => {
    expect(getCloudBaseUrl('us-gov-1')).toBe('https://api.laggar.gcw.crowdstrike.com');
  });

  it('should return correct URL for us-gov-2', () => {
    expect(getCloudBaseUrl('us-gov-2')).toBe('https://api.laggar.gcw.crowdstrike.com');
  });

  it('should return undefined for unknown region', () => {
    expect(getCloudBaseUrl('unknown')).toBeUndefined();
  });
});

describe('CROWDSTRIKE_REGIONS', () => {
  it('should contain all supported regions', () => {
    expect(CROWDSTRIKE_REGIONS).toContain('us-1');
    expect(CROWDSTRIKE_REGIONS).toContain('us-2');
    expect(CROWDSTRIKE_REGIONS).toContain('eu-1');
    expect(CROWDSTRIKE_REGIONS).toContain('us-gov-1');
    expect(CROWDSTRIKE_REGIONS).toContain('us-gov-2');
  });
});
