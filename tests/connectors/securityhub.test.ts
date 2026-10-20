/**
 * Tests for AWS Security Hub Connector
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  SecurityHubConnector,
  createSecurityHubConnector,
} from '../../src/connectors/securityhub';
import type { ForensicsEvent, SecurityHubConnectorConfig } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

const createMockEvent = (overrides: Partial<ForensicsEvent> = {}): ForensicsEvent => ({
  blockedUrl: 'https://evil.com/malware.exe',
  timestamp: '2024-01-15T10:30:00Z',
  redirectChain: ['https://legitimate.com', 'https://redirect.com'],
  tabContext: {
    tabId: 123,
    windowId: 1,
    initiatorUrl: 'https://email.example.com',
    tabTitle: 'Your Invoice',
    incognito: false,
  },
  orgId: 'org-123',
  eventId: 'evt-abc-123',
  matchType: 'url',
  matchedIndicator: 'evil.com/malware.exe',
  userId: 'user@example.com',
  deviceId: 'device-456',
  raw: { original: 'data' },
  ...overrides,
});

const createMockConfig = (
  overrides: Partial<SecurityHubConnectorConfig> = {}
): SecurityHubConnectorConfig => ({
  name: 'test-securityhub',
  enabled: true,
  type: 'securityhub',
  region: 'us-east-1',
  productArn: 'arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default',
  accessKeyId: 'EXAMPLEACCESSKEY12345',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  // Disable batching by default for unit tests (send immediately)
  batch: { maxSize: 1, maxWaitMs: 0 },
  ...overrides,
});

// =============================================================================
// Constructor Tests
// =============================================================================

describe('SecurityHubConnector', () => {
  describe('constructor', () => {
    it('should create connector with valid config', () => {
      const config = createMockConfig();
      const connector = new SecurityHubConnector(config);

      expect(connector.name).toBe('test-securityhub');
      expect(connector.type).toBe('securityhub');
    });

    it('should extract account ID from product ARN', () => {
      const config = createMockConfig({
        productArn: 'arn:aws:securityhub:eu-west-1:987654321098:product/987654321098/default',
      });
      const connector = new SecurityHubConnector(config);

      // The account ID is extracted internally - we verify via the finding generation
      expect(connector).toBeDefined();
    });

    it('should throw error for invalid product ARN format', () => {
      const config = createMockConfig({
        productArn: 'invalid-arn',
      });

      expect(() => new SecurityHubConnector(config)).toThrow(
        'Invalid product ARN format'
      );
    });

    it('should use custom endpoint when provided', () => {
      const config = createMockConfig({
        endpoint: 'https://vpce-xxx.securityhub.us-east-1.vpce.amazonaws.com',
      });
      const connector = new SecurityHubConnector(config);

      expect(connector).toBeDefined();
    });
  });

  // ===========================================================================
  // Initialization Tests
  // ===========================================================================

  describe('init', () => {
    let connector: SecurityHubConnector;
     
    let fetchSpy: any;

    beforeEach(() => {
      fetchSpy = vi.spyOn(globalThis, 'fetch');
    });

    afterEach(() => {
      fetchSpy.mockRestore();
    });

    it('should initialize successfully with valid credentials', async () => {
      const config = createMockConfig();
      connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({ AutoEnableControls: true }), {
          status: 200,
        })
      );

      await expect(connector.init()).resolves.toBeUndefined();
    });

    it('should fail initialization when API returns error', async () => {
      const config = createMockConfig();
      connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response('Unauthorized', { status: 401, statusText: 'Unauthorized' })
      );

      await expect(connector.init()).rejects.toThrow('Failed to connect to Security Hub');
    });

    it('should fail initialization without credentials', async () => {
      // Clear environment variables
      const originalEnv = process.env;
      process.env = { ...originalEnv };
      delete process.env.AWS_ACCESS_KEY_ID;
      delete process.env.AWS_SECRET_ACCESS_KEY;

      const config = createMockConfig({
        accessKeyId: undefined,
        secretAccessKey: undefined,
      });
      connector = new SecurityHubConnector(config);

      await expect(connector.init()).rejects.toThrow('AWS credentials not found');

      process.env = originalEnv;
    });

    it('should load credentials from environment variables', async () => {
      const originalEnv = process.env;
      process.env = {
        ...originalEnv,
        AWS_ACCESS_KEY_ID: 'ENV_ACCESS_KEY',
        AWS_SECRET_ACCESS_KEY: 'ENV_SECRET_KEY',
      };

      const config = createMockConfig({
        accessKeyId: undefined,
        secretAccessKey: undefined,
      });
      connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({ AutoEnableControls: true }), {
          status: 200,
        })
      );

      await expect(connector.init()).resolves.toBeUndefined();

      process.env = originalEnv;
    });

    it('should not allow double initialization', async () => {
      const config = createMockConfig();
      connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValue(
        new Response(JSON.stringify({ AutoEnableControls: true }), {
          status: 200,
        })
      );

      await connector.init();
      await expect(connector.init()).rejects.toThrow('already initialized');
    });
  });

  // ===========================================================================
  // Send Tests
  // ===========================================================================

  describe('send', () => {
    let connector: SecurityHubConnector;
     
    let fetchSpy: any;

    beforeEach(async () => {
      fetchSpy = vi.spyOn(globalThis, 'fetch');
      const config = createMockConfig();
      connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );
      await connector.init();
    });

    afterEach(() => {
      fetchSpy.mockRestore();
    });

    it('should send event successfully', async () => {
      const event = createMockEvent();

      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            SuccessCount: 1,
            FailedCount: 0,
            FailedFindings: [],
          }),
          { status: 200 }
        )
      );

      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-abc-123');
      expect(result.response).toHaveProperty('findingId');
    });

    it('should include AWS Sigv4 headers in request', async () => {
      const event = createMockEvent();

      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            SuccessCount: 1,
            FailedCount: 0,
            FailedFindings: [],
          }),
          { status: 200 }
        )
      );

      await connector.send(event);

      // Verify the fetch was called with proper headers
      const fetchCall = fetchSpy.mock.calls[1]; // Second call (first is init)
      const init = fetchCall?.[1] as RequestInit | undefined;
      const headers = init?.headers as Record<string, string>;

      expect(headers).toHaveProperty('Authorization');
      expect(headers.Authorization).toMatch(/^AWS4-HMAC-SHA256/);
      expect(headers).toHaveProperty('x-amz-date');
      expect(headers).toHaveProperty('x-amz-content-sha256');
    });

    it('should handle failed finding import', async () => {
      const event = createMockEvent();

      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            SuccessCount: 0,
            FailedCount: 1,
            FailedFindings: [
              {
                Id: 'browserdefense/org-123/evt-abc-123',
                ErrorCode: 'InvalidInput',
                ErrorMessage: 'Invalid finding format',
              },
            ],
          }),
          { status: 200 }
        )
      );

      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('InvalidInput');
      expect(result.error).toContain('Invalid finding format');
    });

    it('should handle HTTP errors', async () => {
      const event = createMockEvent();

      fetchSpy.mockResolvedValueOnce(
        new Response('Service unavailable', {
          status: 503,
          statusText: 'Service Unavailable',
        })
      );

      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('503');
      expect(result.retryable).toBe(true);
    });

    it('should handle network errors', async () => {
      const event = createMockEvent();

      fetchSpy.mockRejectedValueOnce(new Error('Network timeout'));

      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('timeout');
      expect(result.retryable).toBe(true);
    });

    it('should require initialization before send', async () => {
      const config = createMockConfig();
      const uninitConnector = new SecurityHubConnector(config);
      const event = createMockEvent();

      await expect(uninitConnector.send(event)).rejects.toThrow(
        'not initialized'
      );
    });
  });

  // ===========================================================================
  // ASFF Mapping Tests
  // ===========================================================================

  describe('ASFF mapping', () => {
    let connector: SecurityHubConnector;
     
    let fetchSpy: any;
    let capturedBody: string | null = null;

    beforeEach(async () => {
      fetchSpy = vi.spyOn(globalThis, 'fetch');
      const config = createMockConfig({
        companyName: 'BrowserDefense Inc',
        productName: 'BrowserDefense Browser Security',
      });
      connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );
      await connector.init();
    });

    afterEach(() => {
      fetchSpy.mockRestore();
      capturedBody = null;
    });

    it('should generate correct finding structure', async () => {
      const event = createMockEvent();

      fetchSpy.mockImplementationOnce(async (_url: string, init: RequestInit) => {
        capturedBody = (init as RequestInit)?.body as string;
        return new Response(
          JSON.stringify({ SuccessCount: 1, FailedCount: 0, FailedFindings: [] }),
          { status: 200 }
        );
      });

      await connector.send(event);

      const body = JSON.parse(capturedBody!);
      const finding = body.Findings[0];

      expect(finding.SchemaVersion).toBe('2018-10-08');
      expect(finding.Id).toBe('browserdefense/org-123/evt-abc-123');
      expect(finding.ProductArn).toBe(
        'arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default'
      );
      expect(finding.GeneratorId).toBe('browserdefense-connector');
      expect(finding.AwsAccountId).toBe('123456789012');
    });

    it('should include event details in finding', async () => {
      const event = createMockEvent();

      fetchSpy.mockImplementationOnce(async (_url: string, init: RequestInit) => {
        capturedBody = (init as RequestInit)?.body as string;
        return new Response(
          JSON.stringify({ SuccessCount: 1, FailedCount: 0, FailedFindings: [] }),
          { status: 200 }
        );
      });

      await connector.send(event);

      const body = JSON.parse(capturedBody!);
      const finding = body.Findings[0];

      expect(finding.Title).toContain('Blocked navigation');
      expect(finding.Description).toContain('evil.com/malware.exe');
      expect(finding.Description).toContain('Redirect chain');
      expect(finding.CreatedAt).toBe('2024-01-15T10:30:00Z');
    });

    it('should set correct severity based on match type', async () => {
      const urlEvent = createMockEvent({ matchType: 'url' });
      const domainEvent = createMockEvent({
        eventId: 'evt-domain',
        matchType: 'domain',
      });
      const hashEvent = createMockEvent({
        eventId: 'evt-hash',
        matchType: 'hash',
      });

      const findings: Array<{ Severity: { Label: string } }> = [];

      fetchSpy.mockImplementation(async (_url: string, init: RequestInit) => {
        const body = JSON.parse((init as RequestInit)?.body as string);
        findings.push(body.Findings[0]);
        return new Response(
          JSON.stringify({ SuccessCount: 1, FailedCount: 0, FailedFindings: [] }),
          { status: 200 }
        );
      });

      await connector.send(urlEvent);
      await connector.send(domainEvent);
      await connector.send(hashEvent);

      expect(findings[0].Severity.Label).toBe('HIGH');
      expect(findings[1].Severity.Label).toBe('MEDIUM');
      expect(findings[2].Severity.Label).toBe('HIGH');
    });

    it('should use config severity override', async () => {
      fetchSpy.mockRestore();
      fetchSpy = vi.spyOn(globalThis, 'fetch');

      const configWithSeverity = createMockConfig({
        severityLabel: 'CRITICAL',
      });
      const connectorWithSeverity = new SecurityHubConnector(configWithSeverity);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );
      await connectorWithSeverity.init();

      fetchSpy.mockImplementationOnce(async (_url: string, init: RequestInit) => {
        capturedBody = (init as RequestInit)?.body as string;
        return new Response(
          JSON.stringify({ SuccessCount: 1, FailedCount: 0, FailedFindings: [] }),
          { status: 200 }
        );
      });

      await connectorWithSeverity.send(createMockEvent());

      const body = JSON.parse(capturedBody!);
      expect(body.Findings[0].Severity.Label).toBe('CRITICAL');
    });

    it('should include user-defined fields', async () => {
      const event = createMockEvent({
        userId: 'john.doe@example.com',
        deviceId: 'LAPTOP-001',
      });

      fetchSpy.mockImplementationOnce(async (_url: string, init: RequestInit) => {
        capturedBody = (init as RequestInit)?.body as string;
        return new Response(
          JSON.stringify({ SuccessCount: 1, FailedCount: 0, FailedFindings: [] }),
          { status: 200 }
        );
      });

      await connector.send(event);

      const body = JSON.parse(capturedBody!);
      const userFields = body.Findings[0].UserDefinedFields;

      expect(userFields['browserdefense/orgId']).toBe('org-123');
      expect(userFields['browserdefense/eventId']).toBe('evt-abc-123');
      expect(userFields['browserdefense/userId']).toBe('john.doe@example.com');
      expect(userFields['browserdefense/deviceId']).toBe('LAPTOP-001');
    });

    it('should include product fields with company/product names', async () => {
      const event = createMockEvent();

      fetchSpy.mockImplementationOnce(async (_url: string, init: RequestInit) => {
        capturedBody = (init as RequestInit)?.body as string;
        return new Response(
          JSON.stringify({ SuccessCount: 1, FailedCount: 0, FailedFindings: [] }),
          { status: 200 }
        );
      });

      await connector.send(event);

      const body = JSON.parse(capturedBody!);
      const productFields = body.Findings[0].ProductFields;

      expect(productFields['browserdefense/version']).toBe('1.0.0');
      expect(productFields['ProviderName']).toBe('BrowserDefense Inc');
      expect(productFields['ProductName']).toBe('BrowserDefense Browser Security');
    });
  });

  // ===========================================================================
  // Batch Send Tests
  // ===========================================================================

  describe('sendBatch', () => {
    let connector: SecurityHubConnector;
     
    let fetchSpy: any;

    beforeEach(async () => {
      fetchSpy = vi.spyOn(globalThis, 'fetch');
      const config = createMockConfig();
      connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );
      await connector.init();
    });

    afterEach(() => {
      fetchSpy.mockRestore();
    });

    it('should send multiple events in a batch', async () => {
      const events = [
        createMockEvent({ eventId: 'evt-1' }),
        createMockEvent({ eventId: 'evt-2' }),
        createMockEvent({ eventId: 'evt-3' }),
      ];

      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            SuccessCount: 3,
            FailedCount: 0,
            FailedFindings: [],
          }),
          { status: 200 }
        )
      );

      const results = await connector.sendBatch(events);

      expect(results.length).toBe(3);
      expect(results.every((r) => r.success)).toBe(true);
    });

    it('should handle partial failures in batch', async () => {
      const events = [
        createMockEvent({ eventId: 'evt-1' }),
        createMockEvent({ eventId: 'evt-2' }),
        createMockEvent({ eventId: 'evt-3' }),
      ];

      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            SuccessCount: 2,
            FailedCount: 1,
            FailedFindings: [
              {
                Id: 'browserdefense/org-123/evt-2',
                ErrorCode: 'InvalidInput',
                ErrorMessage: 'Failed',
              },
            ],
          }),
          { status: 200 }
        )
      );

      const results = await connector.sendBatch(events);

      const successCount = results.filter((r) => r.success).length;
      const failedCount = results.filter((r) => !r.success).length;

      expect(successCount).toBe(2);
      expect(failedCount).toBe(1);
    });

    it('should split large batches (>100 events)', async () => {
      const events = Array.from({ length: 150 }, (_, i) =>
        createMockEvent({ eventId: `evt-${i}` })
      );

      // First batch (100 events)
      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            SuccessCount: 100,
            FailedCount: 0,
            FailedFindings: [],
          }),
          { status: 200 }
        )
      );

      // Second batch (50 events)
      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            SuccessCount: 50,
            FailedCount: 0,
            FailedFindings: [],
          }),
          { status: 200 }
        )
      );

      const results = await connector.sendBatch(events);

      expect(results.length).toBe(150);
      expect(fetchSpy).toHaveBeenCalledTimes(3); // init + 2 batches
    });
  });

  // ===========================================================================
  // Health Check Tests
  // ===========================================================================

  describe('health', () => {
    let connector: SecurityHubConnector;
     
    let fetchSpy: any;

    beforeEach(async () => {
      fetchSpy = vi.spyOn(globalThis, 'fetch');
      const config = createMockConfig();
      connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );
      await connector.init();
    });

    afterEach(() => {
      fetchSpy.mockRestore();
    });

    it('should report healthy when API is accessible', async () => {
      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({ AutoEnableControls: true }), {
          status: 200,
        })
      );

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('Connected');
    });

    it('should report unhealthy when API fails', async () => {
      fetchSpy.mockResolvedValueOnce(
        new Response('Error', { status: 500, statusText: 'Internal Server Error' })
      );

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('error');
    });

    it('should include metrics', async () => {
      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );

      const health = await connector.health();

      expect(health.metrics).toBeDefined();
      expect(health.metrics).toHaveProperty('eventsSent');
      expect(health.metrics).toHaveProperty('eventsFailed');
      expect(health.metrics).toHaveProperty('uptimeSeconds');
    });
  });

  // ===========================================================================
  // Filter Tests
  // ===========================================================================

  describe('filtering', () => {
    let connector: SecurityHubConnector;
     
    let fetchSpy: any;

    beforeEach(async () => {
      fetchSpy = vi.spyOn(globalThis, 'fetch');
      const config = createMockConfig({
        filter: {
          orgIds: ['org-123', 'org-456'],
          matchTypes: ['url', 'hash'],
          excludePatterns: ['.*\\.google\\.com.*'],
        },
      });
      connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );
      await connector.init();
    });

    afterEach(() => {
      fetchSpy.mockRestore();
    });

    it('should filter events by org ID', async () => {
      const allowedEvent = createMockEvent({ orgId: 'org-123' });
      const filteredEvent = createMockEvent({
        eventId: 'filtered',
        orgId: 'org-999',
      });

      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ SuccessCount: 1, FailedCount: 0, FailedFindings: [] }),
          { status: 200 }
        )
      );

      const result1 = await connector.send(allowedEvent);
      const result2 = await connector.send(filteredEvent);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(result2.response).toHaveProperty('filtered', true);
    });

    it('should filter events by match type', async () => {
      const allowedEvent = createMockEvent({ matchType: 'url' });
      const filteredEvent = createMockEvent({
        eventId: 'filtered',
        matchType: 'domain',
      });

      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ SuccessCount: 1, FailedCount: 0, FailedFindings: [] }),
          { status: 200 }
        )
      );

      const result1 = await connector.send(allowedEvent);
      const result2 = await connector.send(filteredEvent);

      expect(result1.success).toBe(true);
      expect(result2.response).toHaveProperty('filtered', true);
    });

    it('should filter events by exclude pattern', async () => {
      const allowedEvent = createMockEvent({
        blockedUrl: 'https://evil.com/malware',
      });
      const filteredEvent = createMockEvent({
        eventId: 'filtered',
        blockedUrl: 'https://mail.google.com/phishing',
      });

      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ SuccessCount: 1, FailedCount: 0, FailedFindings: [] }),
          { status: 200 }
        )
      );

      const result1 = await connector.send(allowedEvent);
      const result2 = await connector.send(filteredEvent);

      expect(result1.success).toBe(true);
      expect(result2.response).toHaveProperty('filtered', true);
    });
  });

  // ===========================================================================
  // Factory Registration Tests
  // ===========================================================================

  describe('factory registration', () => {
    it('should register securityhub connector type', () => {
      expect(connectorRegistry.has('securityhub')).toBe(true);
    });

    it('should create connector via registry', () => {
      const config = createMockConfig();
      const connector = connectorRegistry.create(config);

      expect(connector).toBeInstanceOf(SecurityHubConnector);
      expect(connector.type).toBe('securityhub');
    });

    it('should create connector via factory function', () => {
      const config = createMockConfig();
      const connector = createSecurityHubConnector(config);

      expect(connector).toBeInstanceOf(SecurityHubConnector);
    });
  });

  // ===========================================================================
  // Retry Logic Tests
  // ===========================================================================

  describe('retry logic', () => {
    it('should identify retryable errors', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      const config = createMockConfig();
      const connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );
      await connector.init();

      // Throttling error should be retryable
      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            SuccessCount: 0,
            FailedCount: 1,
            FailedFindings: [
              {
                Id: 'test',
                ErrorCode: 'ThrottlingException',
                ErrorMessage: 'Rate exceeded',
              },
            ],
          }),
          { status: 200 }
        )
      );

      const result = await connector.send(createMockEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);

      fetchSpy.mockRestore();
    });

    it('should identify non-retryable errors', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      const config = createMockConfig();
      const connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );
      await connector.init();

      // Invalid input error should not be retryable
      fetchSpy.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            SuccessCount: 0,
            FailedCount: 1,
            FailedFindings: [
              {
                Id: 'test',
                ErrorCode: 'InvalidInputException',
                ErrorMessage: 'Bad data',
              },
            ],
          }),
          { status: 200 }
        )
      );

      const result = await connector.send(createMockEvent());

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false);

      fetchSpy.mockRestore();
    });
  });

  // ===========================================================================
  // Close/Cleanup Tests
  // ===========================================================================

  describe('close', () => {
    it('should close without error', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      const config = createMockConfig();
      const connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );
      await connector.init();

      await expect(connector.close()).resolves.toBeUndefined();

      fetchSpy.mockRestore();
    });

    it('should not allow operations after close', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      const config = createMockConfig();
      const connector = new SecurityHubConnector(config);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );
      await connector.init();
      await connector.close();

      await expect(connector.send(createMockEvent())).rejects.toThrow(
        'has been closed'
      );

      fetchSpy.mockRestore();
    });
  });
});
