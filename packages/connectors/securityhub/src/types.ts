/**
 * AWS Security Hub Connector Types
 */

import type { BaseConnectorConfig } from '@blockioc/connector-sdk';

/**
 * AWS credential configuration.
 * Supports multiple authentication methods.
 */
export type AwsCredentials =
  | {
      /** Use explicit access key credentials */
      type: 'access-key';
      accessKeyId: string;
      secretAccessKey: string;
      sessionToken?: string;
    }
  | {
      /** Use IAM role (for EC2, ECS, Lambda) */
      type: 'iam-role';
    }
  | {
      /** Use AWS profile from ~/.aws/credentials */
      type: 'profile';
      profile: string;
    };

/**
 * Configuration for the AWS Security Hub connector.
 */
export interface SecurityHubConnectorConfig extends BaseConnectorConfig {
  type: 'securityhub';

  /** AWS region (e.g., 'us-east-1') */
  region: string;

  /** AWS credentials configuration */
  credentials?: AwsCredentials;

  /** AWS account ID (required for finding IDs) */
  awsAccountId: string;

  /** Product ARN for BlockIOC findings (auto-generated if not provided) */
  productArn?: string;

  /** Severity label for findings (default: 'HIGH') */
  severityLabel?: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  /** Custom finding type prefix (default: 'Software and Configuration Checks/BlockIOC') */
  findingTypePrefix?: string;
}

/**
 * AWS Security Finding Format (ASFF) - subset of fields we use.
 * Full spec: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
 */
export interface AwsSecurityFinding {
  SchemaVersion: '2018-10-08';
  Id: string;
  ProductArn: string;
  GeneratorId: string;
  AwsAccountId: string;
  Types: string[];
  CreatedAt: string;
  UpdatedAt: string;
  Severity: {
    Label: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  };
  Title: string;
  Description: string;
  Resources: Array<{
    Type: string;
    Id: string;
    Region?: string;
    Details?: Record<string, unknown>;
  }>;
  ProductFields?: Record<string, string>;
  UserDefinedFields?: Record<string, string>;
  RecordState?: 'ACTIVE' | 'ARCHIVED';
  Workflow?: {
    Status: 'NEW' | 'NOTIFIED' | 'RESOLVED' | 'SUPPRESSED';
  };
}

/**
 * Response from BatchImportFindings API.
 */
export interface BatchImportFindingsResponse {
  FailedCount: number;
  SuccessCount: number;
  FailedFindings?: Array<{
    Id: string;
    ErrorCode: string;
    ErrorMessage: string;
  }>;
}
