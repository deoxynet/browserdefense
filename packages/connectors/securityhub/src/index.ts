/**
 * AWS Security Hub Connector for BlockIOC
 *
 * Forwards decrypted forensics events to AWS Security Hub as ASFF findings.
 */

export { SecurityHubConnector } from './securityhub-connector.js';
export type {
  SecurityHubConnectorConfig,
  AwsCredentials,
  AwsSecurityFinding,
  BatchImportFindingsResponse,
} from './types.js';
