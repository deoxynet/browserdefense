/**
 * BrowserDefense AWS Security Hub Connector
 *
 * Sends forensics events to AWS Security Hub as findings using the
 * BatchImportFindings API. Uses AWS Signature Version 4 for authentication.
 *
 * Features:
 * - AWS Sigv4 authentication (supports IAM credentials and roles)
 * - ASFF (AWS Security Finding Format) mapping
 * - Batch import support (up to 100 findings per request)
 * - Finding deduplication via consistent ID generation
 * - Health check via DescribeHub API
 * - Unblock support via BatchUpdateFindings (resolve and archive findings)
 */

import { BaseConnector, connectorRegistry } from './base';
import {
  ForensicsEvent,
  SecurityHubConnectorConfig,
  SendResult,
  UnblockResult,
} from './types';

// =============================================================================
// ASFF Types
// =============================================================================

/**
 * AWS Security Finding Format (ASFF) severity levels.
 */
type SeverityLabel = 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * ASFF Resource type.
 */
interface AsffResource {
  Type: string;
  Id: string;
  Details?: Record<string, unknown>;
}

/**
 * ASFF Finding structure for BatchImportFindings.
 */
interface AsffFinding {
  SchemaVersion: string;
  Id: string;
  ProductArn: string;
  GeneratorId: string;
  AwsAccountId: string;
  Types: string[];
  CreatedAt: string;
  UpdatedAt: string;
  Severity: {
    Label: SeverityLabel;
  };
  Title: string;
  Description: string;
  Resources: AsffResource[];
  ProductFields?: Record<string, string>;
  UserDefinedFields?: Record<string, string>;
}

/**
 * BatchImportFindings response structure.
 */
interface BatchImportFindingsResponse {
  FailedCount: number;
  FailedFindings: Array<{
    Id: string;
    ErrorCode: string;
    ErrorMessage: string;
  }>;
  SuccessCount: number;
}

/**
 * Finding identifier for BatchUpdateFindings.
 */
interface FindingIdentifier {
  Id: string;
  ProductArn: string;
}

/**
 * BatchUpdateFindings update payload.
 */
interface FindingUpdate {
  Workflow?: { Status: 'NEW' | 'NOTIFIED' | 'RESOLVED' | 'SUPPRESSED' };
  RecordState?: 'ACTIVE' | 'ARCHIVED';
  Note?: {
    Text: string;
    UpdatedBy: string;
  };
}

/**
 * BatchUpdateFindings response structure.
 */
interface BatchUpdateFindingsResponse {
  ProcessedFindings?: FindingIdentifier[];
  UnprocessedFindings?: Array<{
    FindingIdentifier: FindingIdentifier;
    ErrorCode: string;
    ErrorMessage: string;
  }>;
}

// =============================================================================
// AWS Sigv4 Implementation
// =============================================================================

/**
 * AWS credentials for Sigv4 signing.
 */
interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

/**
 * Create a SHA-256 hash of the input.
 */
async function sha256(data: string | ArrayBuffer): Promise<ArrayBuffer> {
  if (typeof data === 'string') {
    const encoder = new TextEncoder();
    return crypto.subtle.digest('SHA-256', encoder.encode(data));
  }
  return crypto.subtle.digest('SHA-256', data);
}

/**
 * Create HMAC-SHA256.
 */
async function hmacSha256(
  key: ArrayBuffer,
  data: string
): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
}

/**
 * Convert ArrayBuffer to hex string.
 */
function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Get AWS Sigv4 signing key.
 */
async function getSigningKey(
  secretKey: string,
  dateStamp: string,
  region: string,
  service: string
): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  // Convert Uint8Array to ArrayBuffer for the first key
  const initialKey = encoder.encode('AWS4' + secretKey);
  const kDate = await hmacSha256(
    initialKey.buffer.slice(initialKey.byteOffset, initialKey.byteOffset + initialKey.byteLength),
    dateStamp
  );
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  const kSigning = await hmacSha256(kService, 'aws4_request');
  return kSigning;
}

/**
 * Sign a request using AWS Signature Version 4.
 */
async function signRequest(
  method: string,
  url: URL,
  headers: Record<string, string>,
  body: string,
  credentials: AwsCredentials,
  region: string,
  service: string
): Promise<Record<string, string>> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.substring(0, 8);

  // Create signed headers
  const signedHeaders: Record<string, string> = {
    ...headers,
    host: url.host,
    'x-amz-date': amzDate,
  };

  // Add session token if present
  if (credentials.sessionToken) {
    signedHeaders['x-amz-security-token'] = credentials.sessionToken;
  }

  // Create canonical request
  const sortedHeaderKeys = Object.keys(signedHeaders).sort();
  const canonicalHeaders = sortedHeaderKeys
    .map((k) => `${k.toLowerCase()}:${signedHeaders[k].trim()}`)
    .join('\n');
  const signedHeadersStr = sortedHeaderKeys
    .map((k) => k.toLowerCase())
    .join(';');

  const payloadHash = toHex(await sha256(body));

  const canonicalRequest = [
    method,
    url.pathname,
    url.search.substring(1), // Remove leading '?'
    canonicalHeaders + '\n',
    signedHeadersStr,
    payloadHash,
  ].join('\n');

  // Create string to sign
  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    toHex(await sha256(canonicalRequest)),
  ].join('\n');

  // Create signature
  const signingKey = await getSigningKey(
    credentials.secretAccessKey,
    dateStamp,
    region,
    service
  );
  const signature = toHex(await hmacSha256(signingKey, stringToSign));

  // Create authorization header
  const authorization = [
    `${algorithm} Credential=${credentials.accessKeyId}/${credentialScope}`,
    `SignedHeaders=${signedHeadersStr}`,
    `Signature=${signature}`,
  ].join(', ');

  return {
    ...signedHeaders,
    Authorization: authorization,
    'x-amz-content-sha256': payloadHash,
  };
}

// =============================================================================
// Security Hub Connector
// =============================================================================

/**
 * AWS Security Hub connector implementation.
 *
 * Sends BrowserDefense forensics events as Security Hub findings using the
 * BatchImportFindings API with ASFF format.
 */
export class SecurityHubConnector extends BaseConnector {
  readonly type = 'securityhub' as const;

  /**
   * Security Hub supports unblock via BatchUpdateFindings.
   * Findings are resolved and archived on unblock.
   */
  readonly supportsUnblock = true;

  private readonly securityHubConfig: SecurityHubConnectorConfig;
  private readonly awsAccountId: string;
  private readonly endpoint: string;
  private credentials: AwsCredentials | null = null;

  constructor(config: SecurityHubConnectorConfig) {
    super(config);
    this.securityHubConfig = config;

    // Extract account ID from product ARN
    // Format: arn:aws:securityhub:<region>:<account-id>:product/<account-id>/default
    const arnParts = config.productArn.split(':');
    if (arnParts.length < 5) {
      throw new Error(
        `Invalid product ARN format: ${config.productArn}. ` +
          'Expected format: arn:aws:securityhub:<region>:<account-id>:product/<account-id>/default'
      );
    }
    this.awsAccountId = arnParts[4];

    // Set endpoint (custom or default)
    this.endpoint =
      config.endpoint ||
      `https://securityhub.${config.region}.amazonaws.com`;
  }

  /**
   * Initialize the connector by loading AWS credentials.
   */
  protected async doInit(): Promise<void> {
    // Load credentials from config or environment
    this.credentials = this.loadCredentials();

    if (!this.credentials) {
      throw new Error(
        'AWS credentials not found. Provide accessKeyId/secretAccessKey in config ' +
          'or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY environment variables.'
      );
    }

    // Validate connectivity by describing the hub
    try {
      await this.describeHub();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to connect to Security Hub: ${message}`);
    }
  }

  /**
   * Load AWS credentials from config or environment.
   */
  private loadCredentials(): AwsCredentials | null {
    // Check config first
    if (
      this.securityHubConfig.accessKeyId &&
      this.securityHubConfig.secretAccessKey
    ) {
      return {
        accessKeyId: this.securityHubConfig.accessKeyId,
        secretAccessKey: this.securityHubConfig.secretAccessKey,
        sessionToken: this.securityHubConfig.sessionToken,
      };
    }

    // Fall back to environment variables
    const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
    const sessionToken = process.env.AWS_SESSION_TOKEN;

    if (accessKeyId && secretAccessKey) {
      return { accessKeyId, secretAccessKey, sessionToken };
    }

    return null;
  }

  /**
   * Send a forensics event to Security Hub as a finding.
   */
  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const finding = this.mapToAsff(event);

    try {
      const response = await this.batchImportFindings([finding]);

      if (response.FailedCount > 0) {
        const failure = response.FailedFindings[0];
        return {
          success: false,
          eventId: event.eventId,
          error: `${failure.ErrorCode}: ${failure.ErrorMessage}`,
          retryable: this.isRetryableError(failure.ErrorCode),
          response: response as unknown as Record<string, unknown>,
        };
      }

      return {
        success: true,
        eventId: event.eventId,
        response: { findingId: finding.Id, successCount: response.SuccessCount },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        eventId: event.eventId,
        error: message,
        retryable: this.isRetryableHttpError(error),
      };
    }
  }

  /**
   * Send multiple events in a batch (up to 100 findings per request).
   */
  async sendBatch(events: ForensicsEvent[]): Promise<SendResult[]> {
    this.ensureInitialized();

    // Filter events
    const filtered = events.filter((e) => this.shouldProcess(e));
    const results: SendResult[] = [];

    // Process in batches of 100 (AWS limit)
    const batchSize = 100;
    for (let i = 0; i < filtered.length; i += batchSize) {
      const batch = filtered.slice(i, i + batchSize);
      const findings = batch.map((e) => this.mapToAsff(e));

      try {
        const response = await this.batchImportFindings(findings);

        // Map results back to events
        const failedIds = new Set(
          response.FailedFindings.map((f) => f.Id)
        );

        for (let j = 0; j < batch.length; j++) {
          const event = batch[j];
          const finding = findings[j];

          if (failedIds.has(finding.Id)) {
            const failure = response.FailedFindings.find(
              (f) => f.Id === finding.Id
            );
            results.push({
              success: false,
              eventId: event.eventId,
              error: failure
                ? `${failure.ErrorCode}: ${failure.ErrorMessage}`
                : 'Unknown error',
              retryable: failure
                ? this.isRetryableError(failure.ErrorCode)
                : true,
            });
          } else {
            results.push({
              success: true,
              eventId: event.eventId,
              response: { findingId: finding.Id },
            });
          }
        }
      } catch (error) {
        // If the entire batch fails, mark all as failed
        const message = error instanceof Error ? error.message : String(error);
        for (const event of batch) {
          results.push({
            success: false,
            eventId: event.eventId,
            error: message,
            retryable: this.isRetryableHttpError(error),
          });
        }
      }
    }

    // Add filtered results
    for (const event of events) {
      if (!this.shouldProcess(event)) {
        results.push({
          success: true,
          eventId: event.eventId,
          response: { filtered: true },
        });
      }
    }

    return results;
  }

  /**
   * Perform a health check by calling DescribeHub.
   */
  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      await this.describeHub();
      return { healthy: true, message: 'Connected to Security Hub' };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { healthy: false, message: `Security Hub error: ${message}` };
    }
  }

  /**
   * Clean up (no persistent connections to close).
   */
  protected async doClose(): Promise<void> {
    // No cleanup needed - we use fetch for HTTP requests
  }

  /**
   * Unblock a previously blocked indicator by resolving and archiving the finding.
   *
   * Uses BatchUpdateFindings to set:
   * - Workflow.Status = RESOLVED
   * - RecordState = ARCHIVED
   * - Note with resolution details
   *
   * Treats not-found as success (idempotent operation).
   */
  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    // Generate the same finding ID used when creating the finding
    const findingId = `browserdefense/${event.orgId}/${event.eventId}`;

    try {
      const response = await this.batchUpdateFindings(
        [
          {
            Id: findingId,
            ProductArn: this.securityHubConfig.productArn,
          },
        ],
        {
          Workflow: { Status: 'RESOLVED' },
          RecordState: 'ARCHIVED',
          Note: {
            Text: `IOC unblocked via BrowserDefense at ${new Date().toISOString()}`,
            UpdatedBy: 'browserdefense-connector',
          },
        }
      );

      // Check for failures
      if (response.UnprocessedFindings && response.UnprocessedFindings.length > 0) {
        const failure = response.UnprocessedFindings[0];

        // Treat "not found" as success - the finding may not exist
        // or was already archived
        if (
          failure.ErrorCode === 'FindingNotFound' ||
          failure.ErrorCode === 'InvalidAccess' ||
          failure.ErrorMessage?.includes('not found')
        ) {
          return {
            success: true,
            eventId: event.eventId,
            alreadyClosed: true,
          };
        }

        return {
          success: false,
          eventId: event.eventId,
          error: `${failure.ErrorCode}: ${failure.ErrorMessage}`,
          retryable: this.isRetryableError(failure.ErrorCode),
        };
      }

      return {
        success: true,
        eventId: event.eventId,
        incidentId: findingId,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      // Treat 404-like errors as success (finding not found = already resolved)
      if (
        message.includes('not found') ||
        message.includes('404') ||
        message.includes('FindingNotFound')
      ) {
        return {
          success: true,
          eventId: event.eventId,
          alreadyClosed: true,
        };
      }

      return {
        success: false,
        eventId: event.eventId,
        error: message,
        retryable: this.isRetryableHttpError(error),
      };
    }
  }

  // ===========================================================================
  // Private helper methods
  // ===========================================================================

  /**
   * Map a forensics event to ASFF format.
   */
  private mapToAsff(event: ForensicsEvent): AsffFinding {
    const now = new Date().toISOString();

    // Generate a consistent finding ID for deduplication
    // Using eventId ensures the same event always produces the same finding
    const findingId = `browserdefense/${event.orgId}/${event.eventId}`;

    // Determine severity based on match type
    const severity = this.determineSeverity(event);

    // Map redirect chain to a description
    const redirectInfo =
      event.redirectChain.length > 0
        ? `\n\nRedirect chain: ${event.redirectChain.join(' -> ')} -> ${event.blockedUrl}`
        : '';

    // Build user-defined fields for additional context
    const userDefinedFields: Record<string, string> = {
      'browserdefense/orgId': event.orgId,
      'browserdefense/eventId': event.eventId,
      'browserdefense/matchType': event.matchType,
      'browserdefense/matchedIndicator': event.matchedIndicator,
    };

    if (event.userId) {
      userDefinedFields['browserdefense/userId'] = event.userId;
    }
    if (event.deviceId) {
      userDefinedFields['browserdefense/deviceId'] = event.deviceId;
    }
    if (event.tabContext.initiatorUrl) {
      userDefinedFields['browserdefense/initiatorUrl'] = event.tabContext.initiatorUrl;
    }

    return {
      SchemaVersion: '2018-10-08',
      Id: findingId,
      ProductArn: this.securityHubConfig.productArn,
      GeneratorId: 'browserdefense-connector',
      AwsAccountId: this.awsAccountId,
      Types: this.securityHubConfig.findingTypes || [
        'TTPs/Initial Access/Phishing',
      ],
      CreatedAt: event.timestamp,
      UpdatedAt: now,
      Severity: {
        Label: severity,
      },
      Title: `BrowserDefense: Blocked navigation to malicious ${event.matchType}`,
      Description:
        `Browser blocked navigation to ${event.blockedUrl} ` +
        `(matched ${event.matchType}: ${event.matchedIndicator}).${redirectInfo}`,
      Resources: [
        {
          Type: 'Other',
          Id: event.blockedUrl,
          Details: {
            Other: {
              blockedUrl: event.blockedUrl,
              matchType: event.matchType,
              matchedIndicator: event.matchedIndicator,
              tabId: String(event.tabContext.tabId),
              incognito: String(event.tabContext.incognito),
            },
          },
        },
      ],
      ProductFields: {
        'browserdefense/version': '1.0.0',
        'browserdefense/connector': 'securityhub',
        ...(this.securityHubConfig.companyName && {
          'ProviderName': this.securityHubConfig.companyName,
        }),
        ...(this.securityHubConfig.productName && {
          'ProductName': this.securityHubConfig.productName,
        }),
      },
      UserDefinedFields: userDefinedFields,
    };
  }

  /**
   * Determine the severity label for a finding.
   */
  private determineSeverity(event: ForensicsEvent): SeverityLabel {
    // Use config override if set
    if (this.securityHubConfig.severityLabel) {
      return this.securityHubConfig.severityLabel;
    }

    // Default severity based on match type
    switch (event.matchType) {
      case 'hash':
        // Hash matches are typically high confidence
        return 'HIGH';
      case 'url':
        // Full URL matches are high confidence
        return 'HIGH';
      case 'domain':
        // Domain matches may include subdomains, slightly lower confidence
        return 'MEDIUM';
      default:
        return 'MEDIUM';
    }
  }

  /**
   * Check if an error code is retryable.
   */
  private isRetryableError(errorCode: string): boolean {
    const retryableCodes = [
      'InternalException',
      'InternalServiceException',
      'ServiceUnavailableException',
      'ThrottlingException',
      'Throttling',
      'RequestThrottled',
      'RequestTimeout',
    ];
    return retryableCodes.includes(errorCode);
  }

  /**
   * Check if an HTTP error is retryable.
   */
  private isRetryableHttpError(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      // Retry on network errors
      if (
        message.includes('timeout') ||
        message.includes('network') ||
        message.includes('econnrefused') ||
        message.includes('econnreset') ||
        message.includes('throttl')
      ) {
        return true;
      }
      // Retry on 5xx HTTP errors (server-side issues)
      const statusMatch = message.match(/failed: (\d{3})/);
      if (statusMatch) {
        const statusCode = parseInt(statusMatch[1], 10);
        return statusCode >= 500 && statusCode < 600;
      }
    }
    return true; // Default to retryable for unknown errors
  }

  /**
   * Call BatchImportFindings API.
   */
  private async batchImportFindings(
    findings: AsffFinding[]
  ): Promise<BatchImportFindingsResponse> {
    const url = new URL(this.endpoint);
    url.pathname = '/findings/import';

    const body = JSON.stringify({ Findings: findings });

    const headers = await signRequest(
      'POST',
      url,
      {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body,
      this.credentials!,
      this.securityHubConfig.region,
      'securityhub'
    );

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers,
      body,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `BatchImportFindings failed: ${response.status} ${response.statusText} - ${errorText}`
      );
    }

    return (await response.json()) as BatchImportFindingsResponse;
  }

  /**
   * Call BatchUpdateFindings API to update finding status.
   * Used for resolving and archiving findings on unblock.
   */
  private async batchUpdateFindings(
    findingIdentifiers: FindingIdentifier[],
    update: FindingUpdate
  ): Promise<BatchUpdateFindingsResponse> {
    const url = new URL(this.endpoint);
    url.pathname = '/findings/batchupdate';

    const body = JSON.stringify({
      FindingIdentifiers: findingIdentifiers,
      ...update,
    });

    const headers = await signRequest(
      'PATCH',
      url,
      {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body,
      this.credentials!,
      this.securityHubConfig.region,
      'securityhub'
    );

    const response = await fetch(url.toString(), {
      method: 'PATCH',
      headers,
      body,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `BatchUpdateFindings failed: ${response.status} ${response.statusText} - ${errorText}`
      );
    }

    return (await response.json()) as BatchUpdateFindingsResponse;
  }

  /**
   * Call DescribeHub API for health check.
   */
  private async describeHub(): Promise<void> {
    const url = new URL(this.endpoint);
    url.pathname = '/accounts';

    const headers = await signRequest(
      'GET',
      url,
      {
        Accept: 'application/json',
      },
      '',
      this.credentials!,
      this.securityHubConfig.region,
      'securityhub'
    );

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `DescribeHub failed: ${response.status} ${response.statusText} - ${errorText}`
      );
    }
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Create a Security Hub connector from configuration.
 */
export function createSecurityHubConnector(
  config: SecurityHubConnectorConfig
): SecurityHubConnector {
  return new SecurityHubConnector(config);
}

// Register the connector factory
connectorRegistry.register('securityhub', createSecurityHubConnector);
