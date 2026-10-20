/**
 * ServiceNow Connector Tests
 *
 * Tests for the ServiceNow Security Operations connector.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ServiceNowConnector, createServiceNowConnector } from '../../src/connectors/servicenow';
import { ForensicsEvent, ServiceNowConnectorConfig } from '../../src/connectors/types';

// =============================================================================
// Test Fixtures
// =============================================================================

const createMockEvent = (overrides?: Partial<ForensicsEvent>): ForensicsEvent => ({
  blockedUrl: 'https://evil.example.com/malware',
  timestamp: '2024-01-15T10:30:00Z',
  redirectChain: ['https://legit.com', 'https://redirect.com'],
  tabContext: {
    tabId: 123,
    windowId: 1,
    initiatorUrl: 'https://email.example.com',
    tabTitle: 'Suspicious Email',
    incognito: false,
  },
  orgId: 'org-123',
  eventId: 'evt-abc-123',
  matchType: 'domain',
  matchedIndicator: 'evil.example.com',
  userId: 'user@example.com',
  deviceId: 'device-456',
  raw: {},
  ...overrides,
});

const createBasicAuthConfig = (overrides?: Partial<ServiceNowConnectorConfig>): ServiceNowConnectorConfig => ({
  name: 'servicenow-test',
  enabled: true,
  type: 'servicenow',
  instance: 'acme',
  auth: {
    type: 'basic',
    username: 'admin',
    password: 'secret123',
  },
  table: 'sn_si_incident',
  assignmentGroup: 'Security Operations',
  priority: '3',
  // Disable batching for tests to get immediate results
  batch: { maxSize: 1, maxWaitMs: 0 },
  ...overrides,
});

const createOAuth2Config = (overrides?: Partial<ServiceNowConnectorConfig>): ServiceNowConnectorConfig => ({
  name: 'servicenow-oauth',
  enabled: true,
  type: 'servicenow',
  instance: 'acme',
  auth: {
    type: 'oauth2',
    oauth2: {
      tokenUrl: 'https://acme.service-now.com/oauth_token.do',
      clientId: 'client-id-123',
      clientSecret: 'client-secret-456',
      grantType: 'client_credentials',
      scopes: ['useraccount'],
    },
  },
  table: 'sn_si_incident',
  assignmentGroup: 'SOC Team',
  priority: '2',
  // Disable batching for tests to get immediate results
  batch: { maxSize: 1, maxWaitMs: 0 },
  ...overrides,
});

// =============================================================================
// Mock fetch
// =============================================================================

const mockFetch = vi.fn();
global.fetch = mockFetch;

// =============================================================================
// Tests
// =============================================================================

describe('ServiceNowConnector', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should create connector with basic auth config', () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      expect(connector.type).toBe('servicenow');
      expect(connector.name).toBe('servicenow-test');
    });

    it('should create connector with OAuth2 config', () => {
      const config = createOAuth2Config();
      const connector = new ServiceNowConnector(config);

      expect(connector.type).toBe('servicenow');
      expect(connector.name).toBe('servicenow-oauth');
    });

    it('should use default table if not specified', () => {
      const config = createBasicAuthConfig({ table: undefined });
      const connector = new ServiceNowConnector(config);

      expect(connector.type).toBe('servicenow');
    });

    it('should use default priority if not specified', () => {
      const config = createBasicAuthConfig({ priority: undefined });
      const connector = new ServiceNowConnector(config);

      expect(connector.type).toBe('servicenow');
    });
  });

  describe('init', () => {
    it('should initialize with basic auth and verify table access', async () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      // Mock table access check
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://acme.service-now.com/api/now/table/sn_si_incident?sysparm_limit=1',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'Accept': 'application/json',
            'Authorization': expect.stringContaining('Basic'),
          }),
        })
      );
    });

    it('should initialize with OAuth2 and fetch token', async () => {
      const config = createOAuth2Config();
      const connector = new ServiceNowConnector(config);

      // Mock token fetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'test-access-token',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
      });

      // Mock table access check
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      expect(mockFetch).toHaveBeenCalledTimes(2);
      // First call is token request
      expect(mockFetch.mock.calls[0][0]).toBe('https://acme.service-now.com/oauth_token.do');
    });

    it('should throw on invalid basic auth config', async () => {
      const config = createBasicAuthConfig({
        auth: { type: 'basic', username: 'admin', password: undefined },
      });
      const connector = new ServiceNowConnector(config);

      await expect(connector.init()).rejects.toThrow('Basic auth requires username and password');
    });

    it('should throw on invalid OAuth2 config', async () => {
      const config = createOAuth2Config({
        auth: { type: 'oauth2', oauth2: undefined },
      });
      const connector = new ServiceNowConnector(config);

      await expect(connector.init()).rejects.toThrow('OAuth2 auth requires oauth2 configuration');
    });

    it('should throw on authentication failure', async () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
      });

      await expect(connector.init()).rejects.toThrow('Authentication failed for ServiceNow instance: 401');
    });

    it('should throw on table not found', async () => {
      const config = createBasicAuthConfig({ table: 'nonexistent_table' });
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(connector.init()).rejects.toThrow("Table 'nonexistent_table' not found in ServiceNow instance");
    });
  });

  describe('send', () => {
    it('should create security incident for domain match', async () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      // Mock init
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      // Mock incident creation
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: {
            sys_id: 'incident-sys-id-123',
            number: 'INC0012345',
          },
        }),
      });

      const event = createMockEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-abc-123');
      expect(result.response).toEqual({
        sysId: 'incident-sys-id-123',
        incidentNumber: 'INC0012345',
      });

      // Verify incident payload
      const createCall = mockFetch.mock.calls[1];
      expect(createCall[0]).toBe('https://acme.service-now.com/api/now/table/sn_si_incident');

      const body = JSON.parse(createCall[1].body);
      expect(body.short_description).toContain('BrowserDefense: Blocked domain');
      expect(body.category).toBe('Security');
      expect(body.subcategory).toBe('Phishing');
      expect(body.priority).toBe('3');
      expect(body.assignment_group).toBe('Security Operations');
      expect(body.u_source).toBe('BrowserDefense');
      expect(body.u_blocked_url).toBe('https://evil.example.com/malware');
      expect(body.u_match_type).toBe('domain');
      expect(body.u_org_id).toBe('org-123');
    });

    it('should create incident for URL match', async () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: { sys_id: 'sys-456', number: 'INC0012346' },
        }),
      });

      const event = createMockEvent({ matchType: 'url' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.subcategory).toBe('Malicious URL');
    });

    it('should create incident for hash match', async () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: { sys_id: 'sys-789', number: 'INC0012347' },
        }),
      });

      const event = createMockEvent({ matchType: 'hash' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.subcategory).toBe('Malware');
    });

    it('should return failure on API error', async () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: async () => 'Database error',
      });

      const event = createMockEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('ServiceNow API error: 500');
      expect(result.retryable).toBe(true);
    });

    it('should not retry on 401 error', async () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        text: async () => 'Invalid credentials',
      });

      const event = createMockEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);
    });

    it('should include custom fields in incident', async () => {
      const config = createBasicAuthConfig({
        customFields: {
          u_custom_field: 'Custom value for {orgId}',
          u_another_field: 'Static value',
        },
      });
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: { sys_id: 'sys-custom', number: 'INC0012348' },
        }),
      });

      const event = createMockEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.u_custom_field).toBe('Custom value for org-123');
      expect(body.u_another_field).toBe('Static value');
    });

    it('should handle events without redirect chain', async () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: { sys_id: 'sys-no-chain', number: 'INC0012349' },
        }),
      });

      const event = createMockEvent({ redirectChain: [] });
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.description).toContain('Redirect Chain: None');
    });
  });

  describe('OAuth2 token management', () => {
    it('should refresh token on OAuth2', async () => {
      const config = createOAuth2Config();
      const connector = new ServiceNowConnector(config);

      // Mock token fetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'initial-token',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
      });

      // Mock table access
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      // Mock incident creation
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: { sys_id: 'sys-oauth', number: 'INC0012350' },
        }),
      });

      const event = createMockEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);

      // Verify Bearer token is used
      const createCall = mockFetch.mock.calls[2];
      expect(createCall[1].headers['Authorization']).toBe('Bearer initial-token');
    });

    it('should handle OAuth2 token refresh failure', async () => {
      const config = createOAuth2Config();
      const connector = new ServiceNowConnector(config);

      // Mock token fetch failure
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: async () => 'Invalid client credentials',
      });

      await expect(connector.init()).rejects.toThrow('OAuth2 token request failed');
    });
  });

  describe('health', () => {
    it('should return healthy when table is accessible', async () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toBe('ServiceNow connection healthy');
    });

    it('should return unhealthy when table is not accessible', async () => {
      const config = createBasicAuthConfig();
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
      });

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('ServiceNow health check failed');
    });
  });

  describe('close', () => {
    it('should close connector and clear OAuth token', async () => {
      const config = createOAuth2Config();
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'test-token',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();
      await connector.close();

      // Connector should be closed - trying to send should fail
      await expect(connector.send(createMockEvent())).rejects.toThrow('has been closed');
    });
  });

  describe('filtering', () => {
    it('should filter events by org ID', async () => {
      const config = createBasicAuthConfig({
        filter: { orgIds: ['allowed-org'] },
      });
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      const event = createMockEvent({ orgId: 'different-org' });
      const result = await connector.send(event);

      // Event should be filtered, not sent to ServiceNow
      expect(result.success).toBe(true);
      expect(result.response).toEqual({ filtered: true });
      expect(mockFetch).toHaveBeenCalledTimes(1); // Only init call
    });

    it('should filter events by match type', async () => {
      const config = createBasicAuthConfig({
        filter: { matchTypes: ['hash'] },
      });
      const connector = new ServiceNowConnector(config);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: [] }),
      });

      await connector.init();

      const event = createMockEvent({ matchType: 'domain' });
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.response).toEqual({ filtered: true });
    });
  });

  describe('factory', () => {
    it('should create connector via factory function', () => {
      const config = createBasicAuthConfig();
      const connector = createServiceNowConnector(config);

      expect(connector).toBeInstanceOf(ServiceNowConnector);
      expect(connector.type).toBe('servicenow');
      expect(connector.name).toBe('servicenow-test');
    });
  });
});
