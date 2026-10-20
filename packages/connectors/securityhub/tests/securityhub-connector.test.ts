import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SecurityHubConnector } from '../src/securityhub-connector.js';
import type { SecurityHubConnectorConfig } from '../src/types.js';
import type { ForensicsEvent } from '@blockioc/connector-sdk';

// Mock the AWS SDK
vi.mock('@aws-sdk/client-securityhub', () => ({
  SecurityHubClient: vi.fn().mockImplementation(() => ({
    send: vi.fn(),
    destroy: vi.fn(),
  })),
  BatchImportFindingsCommand: vi.fn().mockImplementation((input) => ({
    input,
  })),
  DescribeHubCommand: vi.fn().mockImplementation(() => ({})),
}));

function createTestConfig(
  overrides?: Partial<SecurityHubConnectorConfig>
): SecurityHubConnectorConfig {
  return {
    type: 'securityhub',
    name: 'test-connector',
    enabled: true,
    region: 'us-east-1',
    awsAccountId: '123456789012',
    ...overrides,
  };
}

function createTestEvent(
  overrides?: Partial<ForensicsEvent>
): ForensicsEvent {
  return {
    eventId: 'evt-test-123',
    blockedUrl: 'https://evil.com/phish',
    timestamp: '2024-01-15T10:30:00Z',
    redirectChain: ['https://example.com', 'https://evil.com/phish'],
    tabContext: {
      tabId: 1,
      windowId: 1,
      incognito: false,
      initiatorUrl: 'https://legit-site.com',
      tabTitle: 'Test Page',
    },
    orgId: 'org-123',
    matchType: 'domain',
    matchedIndicator: 'evil.com',
    userId: 'user-456',
    deviceId: 'device-789',
    raw: {},
    ...overrides,
  };
}

describe('SecurityHubConnector', () => {
  let connector: SecurityHubConnector;
  let mockClient: { send: ReturnType<typeof vi.fn>; destroy: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    vi.clearAllMocks();

    const { SecurityHubClient } = await import(
      '@aws-sdk/client-securityhub'
    );

    mockClient = {
      send: vi.fn().mockResolvedValue({}),
      destroy: vi.fn(),
    };

    (SecurityHubClient as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      () => mockClient
    );
  });

  afterEach(async () => {
    if (connector) {
      await connector.close();
    }
  });

  describe('initialization', () => {
    it('should initialize successfully with valid config', async () => {
      connector = new SecurityHubConnector(createTestConfig());
      await expect(connector.init()).resolves.not.toThrow();
    });

    it('should throw if region is missing', async () => {
      connector = new SecurityHubConnector(
        createTestConfig({ region: '' })
      );
      await expect(connector.init()).rejects.toThrow('region is required');
    });

    it('should throw if awsAccountId is missing', async () => {
      connector = new SecurityHubConnector(
        createTestConfig({ awsAccountId: '' })
      );
      await expect(connector.init()).rejects.toThrow(
        'awsAccountId is required'
      );
    });

    it('should generate default product ARN if not provided', async () => {
      connector = new SecurityHubConnector(createTestConfig());
      await connector.init();

      // The productArn is internal, but we can verify by sending an event
      mockClient.send.mockResolvedValue({ SuccessCount: 1, FailedCount: 0 });
      const result = await connector.send(createTestEvent());

      expect(result.success).toBe(true);
    });

    it('should use custom product ARN if provided', async () => {
      const customArn = 'arn:aws:securityhub:us-east-1:123456789012:product/custom';
      connector = new SecurityHubConnector(
        createTestConfig({ productArn: customArn })
      );
      await connector.init();

      mockClient.send.mockResolvedValue({ SuccessCount: 1, FailedCount: 0 });
      await connector.send(createTestEvent());

      // Verify the custom ARN was used in the finding
      const { BatchImportFindingsCommand } = await import(
        '@aws-sdk/client-securityhub'
      );
      expect(BatchImportFindingsCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          Findings: expect.arrayContaining([
            expect.objectContaining({
              ProductArn: customArn,
            }),
          ]),
        })
      );
    });
  });

  describe('send', () => {
    beforeEach(async () => {
      connector = new SecurityHubConnector(createTestConfig());
      await connector.init();
    });

    it('should send event successfully', async () => {
      mockClient.send.mockResolvedValue({ SuccessCount: 1, FailedCount: 0 });

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe(event.eventId);
    });

    it('should transform event to ASFF format', async () => {
      mockClient.send.mockResolvedValue({ SuccessCount: 1, FailedCount: 0 });

      const event = createTestEvent();
      await connector.send(event);

      const { BatchImportFindingsCommand } = await import(
        '@aws-sdk/client-securityhub'
      );

      expect(BatchImportFindingsCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          Findings: expect.arrayContaining([
            expect.objectContaining({
              SchemaVersion: '2018-10-08',
              Id: `blockioc-${event.eventId}`,
              AwsAccountId: '123456789012',
              Severity: { Label: 'HIGH' },
              Title: expect.stringContaining('BlockIOC: Blocked domain'),
              Types: expect.arrayContaining([
                expect.stringContaining('MaliciousDomain'),
              ]),
              Resources: expect.arrayContaining([
                expect.objectContaining({
                  Type: 'Other',
                  Id: event.blockedUrl,
                }),
              ]),
            }),
          ]),
        })
      );
    });

    it('should handle URL match type', async () => {
      mockClient.send.mockResolvedValue({ SuccessCount: 1, FailedCount: 0 });

      const event = createTestEvent({ matchType: 'url' });
      await connector.send(event);

      const { BatchImportFindingsCommand } = await import(
        '@aws-sdk/client-securityhub'
      );

      expect(BatchImportFindingsCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          Findings: expect.arrayContaining([
            expect.objectContaining({
              Types: expect.arrayContaining([
                expect.stringContaining('MaliciousURL'),
              ]),
            }),
          ]),
        })
      );
    });

    it('should handle hash match type', async () => {
      mockClient.send.mockResolvedValue({ SuccessCount: 1, FailedCount: 0 });

      const event = createTestEvent({ matchType: 'hash' });
      await connector.send(event);

      const { BatchImportFindingsCommand } = await import(
        '@aws-sdk/client-securityhub'
      );

      expect(BatchImportFindingsCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          Findings: expect.arrayContaining([
            expect.objectContaining({
              Types: expect.arrayContaining([
                expect.stringContaining('MaliciousHash'),
              ]),
            }),
          ]),
        })
      );
    });

    it('should return error on API failure', async () => {
      mockClient.send.mockResolvedValue({
        SuccessCount: 0,
        FailedCount: 1,
        FailedFindings: [
          {
            Id: 'test',
            ErrorCode: 'InvalidInputException',
            ErrorMessage: 'Invalid finding format',
          },
        ],
      });

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid finding format');
      expect(result.retryable).toBe(false);
    });

    it('should mark throttling errors as retryable', async () => {
      mockClient.send.mockResolvedValue({
        SuccessCount: 0,
        FailedCount: 1,
        FailedFindings: [
          {
            Id: 'test',
            ErrorCode: 'ThrottlingException',
            ErrorMessage: 'Rate exceeded',
          },
        ],
      });

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true);
    });

    it('should handle exception during send', async () => {
      mockClient.send.mockRejectedValue(new Error('Network error'));

      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Network error');
    });

    it('should use custom severity label', async () => {
      await connector.close();
      connector = new SecurityHubConnector(
        createTestConfig({ severityLabel: 'CRITICAL' })
      );
      await connector.init();

      mockClient.send.mockResolvedValue({ SuccessCount: 1, FailedCount: 0 });
      await connector.send(createTestEvent());

      const { BatchImportFindingsCommand } = await import(
        '@aws-sdk/client-securityhub'
      );

      expect(BatchImportFindingsCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          Findings: expect.arrayContaining([
            expect.objectContaining({
              Severity: { Label: 'CRITICAL' },
            }),
          ]),
        })
      );
    });
  });

  describe('health', () => {
    it('should return healthy when connected', async () => {
      connector = new SecurityHubConnector(createTestConfig());
      await connector.init();

      mockClient.send.mockResolvedValue({});
      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('Connected');
    });

    it('should return unhealthy when not initialized', async () => {
      connector = new SecurityHubConnector(createTestConfig());

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toBe('Not initialized');
    });

    it('should return unhealthy on connection error', async () => {
      connector = new SecurityHubConnector(createTestConfig());
      await connector.init();

      mockClient.send.mockRejectedValue(new Error('Connection refused'));
      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('Connection refused');
    });
  });

  describe('close', () => {
    it('should cleanup resources on close', async () => {
      connector = new SecurityHubConnector(createTestConfig());
      await connector.init();

      await connector.close();

      expect(mockClient.destroy).toHaveBeenCalled();
    });

    it('should be safe to call close multiple times', async () => {
      connector = new SecurityHubConnector(createTestConfig());
      await connector.init();

      await connector.close();
      await expect(connector.close()).resolves.not.toThrow();
    });

    it('should be safe to close without init', async () => {
      connector = new SecurityHubConnector(createTestConfig());
      await expect(connector.close()).resolves.not.toThrow();
    });
  });
});
