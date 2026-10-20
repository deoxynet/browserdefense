/**
 * AWS Security Hub Connector
 *
 * Forwards BlockIOC forensics events to AWS Security Hub as security findings
 * using the AWS Security Finding Format (ASFF).
 */

import {
  SecurityHubClient,
  BatchImportFindingsCommand,
  DescribeHubCommand,
  type AwsSecurityFinding as SdkAwsSecurityFinding,
} from '@aws-sdk/client-securityhub';
import {
  BaseConnector,
  type ForensicsEvent,
  type SendResult,
  type HealthResult,
} from '@blockioc/connector-sdk';
import type {
  SecurityHubConnectorConfig,
  AwsSecurityFinding,
} from './types.js';

export class SecurityHubConnector extends BaseConnector<SecurityHubConnectorConfig> {
  readonly type = 'securityhub' as const;
  private client: SecurityHubClient | null = null;
  private productArn: string = '';

  constructor(config: SecurityHubConnectorConfig) {
    super(config);
  }

  protected async doInit(): Promise<void> {
    // Validate required config
    if (!this.config.region) {
      throw new Error('region is required');
    }
    if (!this.config.awsAccountId) {
      throw new Error('awsAccountId is required');
    }

    // Build credentials config
    const credentials = this.buildCredentials();

    // Initialize Security Hub client
    this.client = new SecurityHubClient({
      region: this.config.region,
      credentials,
    });

    // Generate or use provided product ARN
    this.productArn =
      this.config.productArn ??
      `arn:aws:securityhub:${this.config.region}:${this.config.awsAccountId}:product/${this.config.awsAccountId}/default`;

    // Verify Security Hub is enabled by describing the hub
    await this.client.send(new DescribeHubCommand({}));
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    if (!this.client) {
      throw new Error('Connector not initialized');
    }

    const finding = this.transformToFinding(event);

    try {
      const command = new BatchImportFindingsCommand({
        Findings: [finding as SdkAwsSecurityFinding],
      });
      const response = await this.client.send(command);

      if (response.FailedCount && response.FailedCount > 0) {
        const failedFinding = response.FailedFindings?.[0];
        return {
          success: false,
          eventId: event.eventId,
          error:
            failedFinding?.ErrorMessage ??
            `Failed to import finding: ${failedFinding?.ErrorCode}`,
          retryable: this.isRetryableError(failedFinding?.ErrorCode),
        };
      }

      return {
        success: true,
        eventId: event.eventId,
        response: {
          successCount: response.SuccessCount,
          findingId: finding.Id,
        },
      };
    } catch (error) {
      const isRetryable = this.isRetryableException(error);
      return {
        success: false,
        eventId: event.eventId,
        error: error instanceof Error ? error.message : String(error),
        retryable: isRetryable,
      };
    }
  }

  protected async doHealth(): Promise<HealthResult> {
    if (!this.client) {
      return { healthy: false, message: 'Not initialized' };
    }

    try {
      await this.client.send(new DescribeHubCommand({}));
      return { healthy: true, message: 'Connected to AWS Security Hub' };
    } catch (error) {
      return {
        healthy: false,
        message: error instanceof Error ? error.message : 'Connection failed',
      };
    }
  }

  protected async doClose(): Promise<void> {
    if (this.client) {
      this.client.destroy();
      this.client = null;
    }
  }

  /**
   * Transform a BlockIOC forensics event into an ASFF finding.
   */
  private transformToFinding(event: ForensicsEvent): AwsSecurityFinding {
    const now = new Date().toISOString();
    const eventTime = event.timestamp;
    const severityLabel = this.config.severityLabel ?? 'HIGH';
    const typePrefix =
      this.config.findingTypePrefix ??
      'Software and Configuration Checks/BlockIOC';

    // Generate a unique finding ID
    const findingId = `blockioc-${event.eventId}`;

    // Determine finding type based on match type
    const findingType = `${typePrefix}/${this.getFindingTypeSuffix(event.matchType)}`;

    return {
      SchemaVersion: '2018-10-08',
      Id: findingId,
      ProductArn: this.productArn,
      GeneratorId: 'blockioc-extension',
      AwsAccountId: this.config.awsAccountId,
      Types: [findingType],
      CreatedAt: eventTime,
      UpdatedAt: now,
      Severity: {
        Label: severityLabel,
      },
      Title: `BlockIOC: Blocked ${event.matchType} - ${this.truncate(event.matchedIndicator, 80)}`,
      Description: this.buildDescription(event),
      Resources: [
        {
          Type: 'Other',
          Id: event.blockedUrl,
          Details: {
            Other: {
              BlockedUrl: event.blockedUrl,
              MatchType: event.matchType,
              MatchedIndicator: event.matchedIndicator,
              ...(event.deviceId && { DeviceId: event.deviceId }),
              ...(event.userId && { UserId: event.userId }),
            },
          },
        },
      ],
      ProductFields: {
        'blockioc/version': '1.0',
        'blockioc/orgId': event.orgId,
        'blockioc/matchType': event.matchType,
        'blockioc/matchedIndicator': event.matchedIndicator,
        ...(event.tabContext.initiatorUrl && {
          'blockioc/initiatorUrl': event.tabContext.initiatorUrl,
        }),
      },
      UserDefinedFields: {
        EventId: event.eventId,
        OrgId: event.orgId,
        ...(event.userId && { UserId: event.userId }),
        ...(event.deviceId && { DeviceId: event.deviceId }),
        RedirectChainLength: String(event.redirectChain.length),
      },
      RecordState: 'ACTIVE',
      Workflow: {
        Status: 'NEW',
      },
    };
  }

  /**
   * Build a description for the finding.
   */
  private buildDescription(event: ForensicsEvent): string {
    const parts: string[] = [
      `BlockIOC blocked navigation to a known malicious ${event.matchType}.`,
      ``,
      `**Blocked URL:** ${event.blockedUrl}`,
      `**Matched Indicator:** ${event.matchedIndicator}`,
      `**Match Type:** ${event.matchType}`,
    ];

    if (event.redirectChain.length > 1) {
      parts.push(``, `**Redirect Chain:**`);
      event.redirectChain.forEach((url, i) => {
        parts.push(`  ${i + 1}. ${url}`);
      });
    }

    if (event.tabContext.initiatorUrl) {
      parts.push(``, `**Initiator URL:** ${event.tabContext.initiatorUrl}`);
    }

    if (event.tabContext.tabTitle) {
      parts.push(`**Tab Title:** ${event.tabContext.tabTitle}`);
    }

    if (event.userId) {
      parts.push(``, `**User ID:** ${event.userId}`);
    }

    if (event.deviceId) {
      parts.push(`**Device ID:** ${event.deviceId}`);
    }

    return parts.join('\n');
  }

  /**
   * Get finding type suffix based on match type.
   */
  private getFindingTypeSuffix(
    matchType: ForensicsEvent['matchType']
  ): string {
    switch (matchType) {
      case 'domain':
        return 'MaliciousDomain';
      case 'url':
        return 'MaliciousURL';
      case 'hash':
        return 'MaliciousHash';
      default:
        return 'Unknown';
    }
  }

  /**
   * Build AWS credentials from config.
   */
  private buildCredentials():
    | {
        accessKeyId: string;
        secretAccessKey: string;
        sessionToken?: string;
      }
    | undefined {
    const creds = this.config.credentials;

    if (!creds) {
      // Use default credential chain (env vars, IAM role, etc.)
      return undefined;
    }

    switch (creds.type) {
      case 'access-key':
        return {
          accessKeyId: creds.accessKeyId,
          secretAccessKey: creds.secretAccessKey,
          sessionToken: creds.sessionToken,
        };
      case 'iam-role':
      case 'profile':
        // These are handled by the default credential provider chain
        return undefined;
      default:
        return undefined;
    }
  }

  /**
   * Check if an error code indicates a retryable failure.
   */
  private isRetryableError(errorCode?: string): boolean {
    if (!errorCode) return false;
    const retryableCodes = [
      'InternalException',
      'ServiceUnavailable',
      'ThrottlingException',
      'RequestLimitExceeded',
    ];
    return retryableCodes.includes(errorCode);
  }

  /**
   * Check if an exception is retryable.
   */
  private isRetryableException(error: unknown): boolean {
    if (!(error instanceof Error)) return false;

    // Check for AWS SDK error codes
    const awsError = error as { name?: string; $retryable?: boolean };
    if (awsError.$retryable) return true;

    const retryableNames = [
      'InternalException',
      'ServiceUnavailable',
      'ThrottlingException',
      'RequestLimitExceeded',
      'NetworkingError',
      'TimeoutError',
    ];
    return retryableNames.includes(awsError.name ?? '');
  }

  /**
   * Truncate a string to a maximum length.
   */
  private truncate(str: string, maxLength: number): string {
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength - 3) + '...';
  }
}
