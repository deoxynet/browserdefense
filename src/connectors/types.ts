/**
 * BrowserDefense Enterprise Connector Types
 *
 * Shared type definitions for all enterprise connectors (SIEMs, EDRs, SOARs).
 * These types define the contract between the connector framework and individual
 * connector implementations.
 */

// =============================================================================
// Core Event Types
// =============================================================================

/**
 * Tab context captured when a block event occurs.
 * Provides contextual information about where the blocked navigation originated.
 */
export interface TabContext {
  /** Tab ID where the block occurred */
  tabId: number;
  /** Window ID containing the tab */
  windowId: number;
  /** URL of the page that initiated the blocked navigation */
  initiatorUrl?: string;
  /** Title of the tab at block time */
  tabTitle?: string;
  /** Whether the tab was in incognito mode */
  incognito: boolean;
}

/**
 * IOC action type - block or unblock.
 */
export type IocAction = 'block' | 'unblock';

/**
 * Core forensics event - decrypted payload from the browser extension.
 * This is the primary data structure that connectors receive and forward.
 */
export interface ForensicsEvent {
  /** Action type - block or unblock (defaults to 'block' for backwards compat) */
  action?: IocAction;
  /** The blocked URL that triggered the event */
  blockedUrl: string;
  /** ISO8601 timestamp when the block occurred */
  timestamp: string;
  /** Chain of redirects leading to the blocked URL */
  redirectChain: string[];
  /** Browser tab context at block time */
  tabContext: TabContext;
  /** Organization identifier for multi-tenant deployments */
  orgId: string;
  /** Unique event identifier */
  eventId: string;
  /** IOC type that matched (domain, url, hash) */
  matchType: 'domain' | 'url' | 'hash';
  /** The specific IOC pattern that matched */
  matchedIndicator: string;
  /** User identifier (if available from enterprise directory) */
  userId?: string;
  /** Device identifier (if available from MDM) */
  deviceId?: string;
  /** Original raw decrypted payload for custom processing */
  raw: Record<string, unknown>;
}

// =============================================================================
// Connector Configuration Types
// =============================================================================

/**
 * Base configuration shared by all connectors.
 */
export interface BaseConnectorConfig {
  /** Unique name for this connector instance */
  name: string;
  /** Whether this connector is enabled */
  enabled: boolean;
  /** Retry configuration for failed sends */
  retry?: RetryConfig;
  /** Batch configuration for high-volume scenarios */
  batch?: BatchConfig;
  /** Filter rules to selectively forward events */
  filter?: FilterConfig;
}

/**
 * Retry configuration for failed event delivery.
 */
export interface RetryConfig {
  /** Maximum number of retry attempts */
  maxAttempts: number;
  /** Initial delay between retries in milliseconds */
  initialDelayMs: number;
  /** Maximum delay between retries in milliseconds */
  maxDelayMs: number;
  /** Exponential backoff multiplier */
  backoffMultiplier: number;
}

/**
 * Batch configuration for high-volume event processing.
 */
export interface BatchConfig {
  /** Maximum events per batch */
  maxSize: number;
  /** Maximum time to wait before flushing batch in milliseconds */
  maxWaitMs: number;
}

/**
 * Filter configuration for selective event forwarding.
 */
export interface FilterConfig {
  /** Only forward events matching these org IDs */
  orgIds?: string[];
  /** Only forward events matching these match types */
  matchTypes?: Array<'domain' | 'url' | 'hash'>;
  /** Exclude events matching these patterns (regex) */
  excludePatterns?: string[];
}

// =============================================================================
// SIEM Connector Types
// =============================================================================

/**
 * Configuration for Splunk HEC (HTTP Event Collector) connector.
 */
export interface SplunkConnectorConfig extends BaseConnectorConfig {
  type: 'splunk';
  /** Splunk HEC endpoint URL */
  hecUrl: string;
  /** HEC token for authentication */
  hecToken: string;
  /** Splunk index to write events to */
  index?: string;
  /** Source type for events */
  sourceType?: string;
  /** Source identifier */
  source?: string;
  /** Custom host value */
  host?: string;
  /** TLS verification settings */
  tls?: TlsConfig;
}

/**
 * Configuration for Elastic/OpenSearch connector.
 */
export interface ElasticConnectorConfig extends BaseConnectorConfig {
  type: 'elastic';
  /**
   * Elasticsearch node URLs (e.g., ['https://localhost:9200']).
   * Not required when using cloudId.
   */
  nodes: string[];
  /** Index name pattern (supports date placeholders like blockioc-%{+yyyy.MM.dd}) */
  indexPattern: string;
  /**
   * API key for authentication.
   * Must be the base64-encoded value of "id:api_key" as returned by
   * the Elasticsearch Create API Key API. The connector prepends "ApiKey "
   * to form the Authorization header.
   * @example base64("VuaCfGcBCdbkQm-e5aOx:ui2lp2axTNmsyakw9tvNnw")
   * @see https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html
   */
  apiKey?: string;
  /** Username for basic auth */
  username?: string;
  /** Password for basic auth */
  password?: string;
  /**
   * Cloud ID for Elastic Cloud deployments.
   * Found in the deployment overview page. When provided, the connector
   * decodes the Cloud ID to extract the Elasticsearch endpoint URL.
   * Format: "deployment-name:base64(host$esId$kibanaId)"
   */
  cloudId?: string;
  /** TLS verification settings */
  tls?: TlsConfig;
}

/**
 * Syslog message format.
 */
export type SyslogFormat = 'cef' | 'leef' | 'json' | 'raw';

/**
 * RFC 5424 structured data element.
 */
export interface StructuredDataElement {
  /** SD-ID (e.g., 'BrowserDefense@12345') */
  id: string;
  /** SD-PARAMs as key-value pairs */
  params: Record<string, string>;
}

/**
 * Configuration for generic Syslog connector (RFC 5424).
 */
export interface SyslogConnectorConfig extends BaseConnectorConfig {
  type: 'syslog';
  /** Syslog server hostname */
  host: string;
  /** Syslog server port */
  port: number;
  /** Protocol (udp, tcp, tcp+tls) */
  protocol: 'udp' | 'tcp' | 'tcp+tls';
  /** Message format (cef, leef, json, raw) - defaults to 'cef' */
  format?: SyslogFormat;
  /** Syslog facility (0-23) - defaults to 16 (local0) */
  facility?: number;
  /** Syslog severity (0-7) - defaults to 5 (notice) */
  severity?: number;
  /** App name for syslog messages - defaults to 'browserdefense-connector' */
  appName?: string;
  /** Process ID for syslog messages - defaults to '-' */
  procId?: string;
  /** Message ID for syslog messages - defaults to '-' */
  msgId?: string;
  /** CEF vendor field - defaults to 'BrowserDefense' */
  cefVendor?: string;
  /** CEF product field - defaults to 'Connector' */
  cefProduct?: string;
  /** CEF version field - defaults to '1.0' */
  cefVersion?: string;
  /** Include RFC 5424 structured data */
  includeStructuredData?: boolean;
  /** Custom structured data elements */
  structuredData?: StructuredDataElement[];
  /** TLS configuration for tcp+tls */
  tls?: TlsConfig;
  /** Connection timeout in milliseconds - defaults to 5000 */
  connectTimeoutMs?: number;
  /** TCP socket keep-alive - defaults to true */
  keepAlive?: boolean;
}

/**
 * Configuration for Sumo Logic HTTP Source connector.
 */
export interface SumoLogicConnectorConfig extends BaseConnectorConfig {
  type: 'sumologic';
  /** Sumo Logic HTTP Source URL (unique per collector) */
  httpSourceUrl: string;
  /** Source category for event categorization */
  sourceCategory?: string;
  /** Source name identifier */
  sourceName?: string;
  /** Source host identifier */
  sourceHost?: string;
  /** Custom fields to add to all events */
  fields?: Record<string, string>;
  /** Timestamp field name in the event (defaults to 'timestamp') */
  timestampField?: string;
}

/**
 * Configuration for IBM QRadar connector.
 * Supports Syslog (LEEF format) and REST API integration.
 */
export interface QRadarConnectorConfig extends BaseConnectorConfig {
  type: 'qradar';
  /** QRadar Console hostname or IP */
  host: string;
  /** Syslog port (default: 514) */
  port: number;
  /** Protocol for syslog transport (udp, tcp, tcp+tls) */
  protocol: 'udp' | 'tcp' | 'tcp+tls';
  /** Message format (leef or cef) */
  format?: 'leef' | 'cef';
  /** Syslog facility (0-23, default: 16 - local0) */
  facility?: number;
  /** Syslog severity (0-7, default: 5 - notice) */
  severity?: number;
  /** App name for syslog header */
  appName?: string;
  /** TLS configuration for tcp+tls protocol */
  tls?: TlsConfig;
  /** Optional REST API configuration for advanced features */
  restApi?: QRadarRestApiConfig;
}

/**
 * QRadar REST API configuration for advanced features.
 * Used for reference data updates, custom event properties, etc.
 */
export interface QRadarRestApiConfig {
  /** QRadar Console URL (e.g., https://qradar.corp.local) */
  consoleUrl: string;
  /** SEC token for API authentication */
  secToken: string;
  /** API version (default: 17.0) */
  apiVersion?: string;
  /** TLS verification settings */
  tls?: TlsConfig;
}

/**
 * InsightIDR region codes.
 * Different regions have different data center endpoints.
 */
export type InsightIDRRegion = 'us' | 'us2' | 'us3' | 'eu' | 'ca' | 'au' | 'ap';

/**
 * Configuration for Rapid7 InsightIDR connector.
 * Uses the Log Ingestion API to send events to InsightIDR log sets.
 */
export interface InsightIDRConnectorConfig extends BaseConnectorConfig {
  type: 'insightidr';
  /** Region code for the InsightIDR instance */
  region: InsightIDRRegion;
  /** Log set token from InsightIDR (found in Log Collection setup) */
  logToken: string;
  /** Optional log set name for identification */
  logSet?: string;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** TLS verification settings */
  tls?: TlsConfig;
}

/**
 * Configuration for Microsoft Sentinel connector via Log Analytics Data Collector API.
 */
export interface SentinelConnectorConfig extends BaseConnectorConfig {
  type: 'sentinel';
  /** Log Analytics workspace ID */
  workspaceId: string;
  /** Log Analytics shared key (primary or secondary) */
  sharedKey: string;
  /** Custom log type name (will be suffixed with _CL in Sentinel) */
  logType: string;
  /** Optional Azure resource ID for resource-context logs */
  azureResourceId?: string;
  /** Optional time-generated field name (for custom timestamp) */
  timeGeneratedField?: string;
}

/**
 * Configuration for Google Chronicle/SecOps connector.
 * Uses the Ingestion API with UDM (Unified Data Model) format.
 */
export interface ChronicleConnectorConfig extends BaseConnectorConfig {
  type: 'chronicle';
  /** Chronicle customer ID */
  customerId: string;
  /** Chronicle region (us, europe, asia-southeast1) */
  region: 'us' | 'europe' | 'asia-southeast1';
  /**
   * Google Cloud service account credentials.
   * Can be provided as:
   * - Path to JSON key file
   * - JSON string of service account key
   * - Inline service account object
   */
  credentials:
    | string
    | {
        type: 'service_account';
        project_id: string;
        private_key_id: string;
        private_key: string;
        client_email: string;
        client_id: string;
        auth_uri: string;
        token_uri: string;
        auth_provider_x509_cert_url: string;
        client_x509_cert_url: string;
      };
  /** Log type identifier in Chronicle (default: BROWSERDEFENSE) */
  logType?: string;
  /** Custom labels to add to events */
  labels?: Array<{ key: string; value: string }>;
}

// =============================================================================
// EDR Connector Types
// =============================================================================

/**
 * Configuration for CrowdStrike Falcon connector.
 */
export interface CrowdStrikeConnectorConfig extends BaseConnectorConfig {
  type: 'crowdstrike';
  /** CrowdStrike API base URL */
  baseUrl: string;
  /** OAuth2 client ID */
  clientId: string;
  /** OAuth2 client secret */
  clientSecret: string;
  /** Target for custom IOC ingestion */
  iocTarget?: 'ioc-manager' | 'intel-indicator';
  /** TLS verification settings */
  tls?: TlsConfig;
}

/**
 * Configuration for SentinelOne connector.
 */
export interface SentinelOneConnectorConfig extends BaseConnectorConfig {
  type: 'sentinelone';
  /** SentinelOne management console URL */
  consoleUrl: string;
  /** API token for authentication */
  apiToken: string;
  /** Site ID for multi-site deployments */
  siteId?: string;
  /** Account ID for multi-account deployments */
  accountId?: string;
  /** IOC expiration in days (default: 90) */
  iocExpirationDays?: number;
  /** TLS verification settings */
  tls?: TlsConfig;
}

/**
 * Configuration for Microsoft Defender connector.
 */
export interface DefenderConnectorConfig extends BaseConnectorConfig {
  type: 'defender';
  /** Azure AD tenant ID */
  tenantId: string;
  /** Azure AD application (client) ID */
  clientId: string;
  /** Azure AD client secret */
  clientSecret: string;
  /** Optional certificate for app-only auth */
  certificatePath?: string;
  /** Indicator action (default: Alert) */
  action?: 'Alert' | 'AlertAndBlock' | 'Allowed';
  /** Indicator mode (default: block) */
  mode?: 'block' | 'unblock';
  /** Indicator severity (default: Medium) */
  severity?: 'Informational' | 'Low' | 'Medium' | 'High';
  /** Generate alerts for indicators (default: true) */
  generateAlert?: boolean;
  /** Indicator expiration in hours (default: 720 = 30 days) */
  expirationHours?: number;
}

/**
 * Configuration for VMware Carbon Black Cloud connector.
 */
export interface CarbonBlackConnectorConfig extends BaseConnectorConfig {
  type: 'carbonblack';
  /** Carbon Black Cloud API URL (varies by region, e.g., https://defense-prod05.conferdeploy.net) */
  url: string;
  /** Organization key */
  orgKey: string;
  /** API ID for authentication */
  apiId: string;
  /** API secret for authentication */
  apiSecret: string;
  /** Feed ID for IOC reports (defaults to 'browserdefense') */
  feedId?: string;
  /** Default severity for IOC reports (1-10, defaults to 5) */
  defaultSeverity?: number;
  /** Custom tags to add to reports */
  tags?: string[];
  /** TLS verification settings */
  tls?: TlsConfig;
}

/**
 * Configuration for Bitdefender GravityZone connector.
 */
export interface BitdefenderGravityZoneConnectorConfig extends BaseConnectorConfig {
  type: 'bitdefender-gravityzone';
  /** GravityZone API base URL */
  apiUrl: string;
  /** GravityZone API key (basic auth username) */
  apiKey: string;
  /** Blocklist type to manage (hash, path, connection) */
  blockType?: 'hash' | 'path' | 'connection';
  /** Action to perform (block or unblock) */
  action?: 'block' | 'unblock';
  /** Hash algorithm override (md5, sha1, sha256) */
  hashAlgorithm?: string;
  /** Prefix for generated connection rule names */
  ruleNamePrefix?: string;
  /** Default connection rule values for connection block type */
  connectionDefaults?: {
    commandLine?: string | null;
    protocol?: string;
    direction?: 'both' | 'inbound' | 'outbound';
    ipVersion?: 'any' | 'IPV4' | 'IPV6';
    localAddress?: {
      any?: boolean;
      ipMask?: string;
      portRange?: string;
    };
    remoteAddress?: {
      any?: boolean;
      ipMask?: string;
      portRange?: string;
    };
    directlyConnected?: {
      enable?: boolean;
      remoteMac?: string;
    };
  };
}

/**
 * Configuration for HarfangLab connector.
 */
export interface HarfangLabConnectorConfig extends BaseConnectorConfig {
  type: 'harfanglab';
  /** HarfangLab API base URL */
  apiUrl: string;
  /** API token for authentication */
  apiToken: string;
  /** Source ID for IOC rules */
  sourceId: string;
  /** Action to perform (block or unblock) */
  action?: 'block' | 'unblock';
  /** Block indicator on agent */
  blockOnAgent?: boolean;
  /** Quarantine indicator on agent */
  quarantineOnAgent?: boolean;
  /** Enable endpoint detection */
  detectOnAgent?: boolean;
  /** Prefix for indicator descriptions */
  descriptionPrefix?: string;
}

/**
 * Configuration for Cortex XDR connector.
 */
export interface CortexXdrConnectorConfig extends BaseConnectorConfig {
  type: 'cortexxdr';
  /** Cortex XDR tenant FQDN */
  fqdn: string;
  /** API key for authentication */
  apiKey: string;
  /** API key ID for authentication */
  apiKeyId: string;
  /** Incident ID for hash blocklist submissions */
  incidentId: number;
  /** Action to perform (block only) */
  action?: 'block';
  /** Prefix for blocklist comments */
  commentPrefix?: string;
}

/**
 * Configuration for Fortigate connector.
 */
export interface FortigateConnectorConfig extends BaseConnectorConfig {
  type: 'fortigate';
  /** List of Fortigate firewalls to manage */
  firewalls: Array<{
    baseIp: string;
    basePort: number | string;
    apiKey: string;
    vdom?: string;
  }>;
  /** Optional address group name to manage membership */
  addressGroup?: string;
  /** Address type (auto chooses ip/fqdn based on indicator) */
  addressType?: 'ip' | 'fqdn' | 'auto';
  /** Action to perform (block or unblock) */
  action?: 'block' | 'unblock';
  /** Prefix for generated address object names */
  addressNamePrefix?: string;
  /** Associated interface for address objects */
  associatedInterface?: string;
  /** Prefix for address object comments */
  commentPrefix?: string;
  /** Whether to verify TLS certificates (default true) */
  tlsVerify?: boolean;
}

/**
 * Configuration for Zscaler ZIA connector.
 */
export interface ZscalerConnectorConfig extends BaseConnectorConfig {
  type: 'zscaler';
  /** Zscaler cloud name (e.g., zscaler.net) */
  cloudName?: string;
  /** Explicit API base URL (overrides cloudName) */
  baseUrl?: string;
  /** Zscaler username */
  username: string;
  /** Zscaler password */
  password: string;
  /** Zscaler API key */
  apiKey: string;
  /** Action to perform (block or unblock) */
  action?: 'block' | 'unblock';
  /** Activate changes after updates */
  activateChanges?: boolean;
}

// =============================================================================
// SOAR Connector Types
// =============================================================================

/**
 * Configuration for generic webhook connector.
 * Supports custom SOAR integrations and automation platforms.
 */
export interface WebhookConnectorConfig extends BaseConnectorConfig {
  type: 'webhook';
  /** Webhook endpoint URL */
  url: string;
  /** HTTP method */
  method: 'POST' | 'PUT';
  /** Custom headers */
  headers?: Record<string, string>;
  /** Authentication configuration */
  auth?: WebhookAuth;
  /** TLS verification settings */
  tls?: TlsConfig;
  /** Template for transforming events (Handlebars syntax) */
  template?: string;
}

/**
 * Webhook authentication options.
 */
export interface WebhookAuth {
  type: 'bearer' | 'basic' | 'api-key' | 'oauth2';
  /** Token for bearer auth */
  token?: string;
  /** Username for basic auth */
  username?: string;
  /** Password for basic auth */
  password?: string;
  /** Header name for API key auth */
  apiKeyHeader?: string;
  /** API key value */
  apiKey?: string;
  /** OAuth2 configuration */
  oauth2?: OAuth2Config;
}

/**
 * OAuth2 configuration for connectors that require it.
 */
export interface OAuth2Config {
  /** Token endpoint URL */
  tokenUrl: string;
  /** Client ID */
  clientId: string;
  /** Client secret */
  clientSecret: string;
  /** OAuth2 scopes */
  scopes?: string[];
  /** Grant type */
  grantType: 'client_credentials' | 'password' | 'authorization_code';
}

/**
 * Configuration for XSOAR (Demisto) connector.
 */
export interface XsoarConnectorConfig extends BaseConnectorConfig {
  type: 'xsoar';
  /** XSOAR server URL */
  serverUrl: string;
  /** API key for authentication */
  apiKey: string;
  /** Incident type to create */
  incidentType?: string;
  /** Playbook to trigger on incident creation */
  playbookId?: string;
  /** TLS verification settings */
  tls?: TlsConfig;
}

/**
 * Authentication configuration for ServiceNow connector.
 */
export interface ServiceNowAuth {
  /** Authentication type */
  type: 'basic' | 'oauth2';
  /** Username for basic auth */
  username?: string;
  /** Password for basic auth */
  password?: string;
  /** OAuth2 configuration */
  oauth2?: OAuth2Config;
}

/**
 * Configuration for ServiceNow Security Operations connector.
 * Creates security incidents via the ServiceNow Table API.
 */
export interface ServiceNowConnectorConfig extends BaseConnectorConfig {
  type: 'servicenow';
  /** ServiceNow instance name (e.g., 'acme' for acme.service-now.com) */
  instance: string;
  /** Authentication configuration */
  auth: ServiceNowAuth;
  /** Target table for incident creation */
  table?: 'sn_si_incident' | 'em_event' | 'sn_ti_observable' | string;
  /** Assignment group for created incidents */
  assignmentGroup?: string;
  /** Default priority (1=Critical, 2=High, 3=Medium, 4=Low) */
  priority?: '1' | '2' | '3' | '4';
  /** Custom field mappings (u_* fields) */
  customFields?: Record<string, string>;
  /** TLS verification settings */
  tls?: TlsConfig;
}

/**
 * Configuration for Datadog Logs connector.
 */
export interface DatadogConnectorConfig extends BaseConnectorConfig {
  type: 'datadog';
  /** Datadog site (e.g., 'datadoghq.com', 'datadoghq.eu', 'us3.datadoghq.com') */
  site: string;
  /** Datadog API key for authentication */
  apiKey: string;
  /** Service name for log entries */
  service?: string;
  /** Source name for log entries */
  source?: string;
  /** Hostname to associate with logs */
  hostname?: string;
  /** Additional tags to include with all logs (key:value format) */
  tags?: string[];
  /** TLS verification settings */
  tls?: TlsConfig;
}

// =============================================================================
// Cloud Security Connector Types
// =============================================================================

/**
 * Configuration for AWS Security Hub connector.
 * Sends findings to AWS Security Hub via BatchImportFindings API.
 */
export interface SecurityHubConnectorConfig extends BaseConnectorConfig {
  type: 'securityhub';
  /** AWS region for Security Hub (e.g., 'us-east-1') */
  region: string;
  /**
   * Product ARN for the findings.
   * Format: arn:aws:securityhub:<region>:<account-id>:product/<account-id>/default
   */
  productArn: string;
  /** AWS access key ID (optional if using IAM role) */
  accessKeyId?: string;
  /** AWS secret access key (optional if using IAM role) */
  secretAccessKey?: string;
  /** AWS session token for temporary credentials (optional) */
  sessionToken?: string;
  /** Custom Security Hub endpoint URL (optional, for VPC endpoints) */
  endpoint?: string;
  /** Finding severity label override */
  severityLabel?: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  /** Finding types for ASFF (defaults to ['TTPs/Initial Access/Phishing']) */
  findingTypes?: string[];
  /** Company name for the product fields */
  companyName?: string;
  /** Product name for the product fields */
  productName?: string;
}

// =============================================================================
// Shared Types
// =============================================================================

/**
 * TLS configuration for secure connections.
 */
export interface TlsConfig {
  /** Verify server certificate */
  verify: boolean;
  /** Path to CA certificate bundle */
  caCertPath?: string;
  /** Path to client certificate for mTLS */
  clientCertPath?: string;
  /** Path to client key for mTLS */
  clientKeyPath?: string;
  /** Minimum TLS version */
  minVersion?: 'TLS1.2' | 'TLS1.3';
}

/**
 * Health check result returned by connectors.
 */
export interface HealthStatus {
  /** Whether the connector is healthy */
  healthy: boolean;
  /** Human-readable status message */
  message: string;
  /** Last successful operation timestamp */
  lastSuccess?: string;
  /** Last error message if unhealthy */
  lastError?: string;
  /** Additional health metrics */
  metrics?: HealthMetrics;
}

/**
 * Health metrics for monitoring.
 */
export interface HealthMetrics {
  /** Total events sent since startup */
  eventsSent: number;
  /** Total events failed since startup */
  eventsFailed: number;
  /** Events currently in retry queue */
  eventsInRetryQueue: number;
  /** Average latency in milliseconds */
  avgLatencyMs: number;
  /** Connection uptime in seconds */
  uptimeSeconds: number;
}

/**
 * Result of a send operation.
 */
export interface SendResult {
  /** Whether the send was successful */
  success: boolean;
  /** Event ID that was sent */
  eventId: string;
  /** Error message if failed */
  error?: string;
  /** Whether the event should be retried */
  retryable?: boolean;
  /** Response from the destination (for debugging) */
  response?: Record<string, unknown>;
}

/**
 * Result of an unblock operation.
 * Used when closing/resolving incidents created from block events.
 */
export interface UnblockResult {
  /** Whether the unblock was successful */
  success: boolean;
  /** Event ID of the original block event */
  eventId: string;
  /** Error message if failed */
  error?: string;
  /** Whether the operation should be retried */
  retryable?: boolean;
  /** Whether the incident was already closed (idempotent) */
  alreadyClosed?: boolean;
  /** Incident ID that was updated */
  incidentId?: string;
}

/**
 * Union type for all connector configurations.
 */
export type ConnectorConfig =
  | SplunkConnectorConfig
  | ElasticConnectorConfig
  | SyslogConnectorConfig
  | SumoLogicConnectorConfig
  | QRadarConnectorConfig
  | InsightIDRConnectorConfig
  | SentinelConnectorConfig
  | ChronicleConnectorConfig
  | CrowdStrikeConnectorConfig
  | SentinelOneConnectorConfig
  | DefenderConnectorConfig
  | CarbonBlackConnectorConfig
  | BitdefenderGravityZoneConnectorConfig
  | HarfangLabConnectorConfig
  | CortexXdrConnectorConfig
  | FortigateConnectorConfig
  | ZscalerConnectorConfig
  | WebhookConnectorConfig
  | XsoarConnectorConfig
  | ServiceNowConnectorConfig
  | DatadogConnectorConfig
  | SecurityHubConnectorConfig;

/**
 * Connector type discriminator for runtime type checking.
 */
export type ConnectorType = ConnectorConfig['type'];

// =============================================================================
// Encrypted Payload Types (from extension)
// =============================================================================

/**
 * Encrypted forensics payload as received from the browser extension.
 * This is the input to the decryption engine.
 */
export interface EncryptedForensicsPayload {
  /** RSA-OAEP encrypted AES key */
  encryptedKey: string;
  /** 96-bit IV for AES-GCM, base64 encoded */
  iv: string;
  /** AES-GCM encrypted payload, base64 encoded */
  ciphertext: string;
  /** Organization ID for key lookup */
  orgId: string;
  /** Key version for key rotation support */
  keyVersion: number;
  /** Timestamp when payload was created */
  timestamp: string;
}

/**
 * Key store entry for customer RSA private keys.
 */
export interface KeyEntry {
  /** Key identifier (typically orgId:keyVersion) */
  keyId: string;
  /** Organization ID this key belongs to */
  orgId: string;
  /** Key version number */
  version: number;
  /** Private key in JWK format (RSA-OAEP) */
  privateKey: JsonWebKey;
  /** When this key was added */
  createdAt: string;
  /** When this key expires (for rotation) */
  expiresAt?: string;
  /** Whether this is the active key for the org */
  active: boolean;
}

// =============================================================================
// Server Configuration Types
// =============================================================================

/**
 * Main connector service configuration.
 */
export interface ConnectorServiceConfig {
  /** Server configuration */
  server: ServerConfig;
  /** Key store configuration */
  keyStore: KeyStoreConfig;
  /** List of connector configurations */
  connectors: ConnectorConfig[];
  /** Logging configuration */
  logging: LoggingConfig;
  /** Metrics configuration */
  metrics: MetricsConfig;
}

/**
 * HTTP server configuration.
 */
export interface ServerConfig {
  /** Bind address */
  host: string;
  /** Listen port */
  port: number;
  /** TLS configuration (required for production) */
  tls: TlsConfig & { certPath: string; keyPath: string };
  /** API key for authenticating extension requests */
  apiKeys: string[];
  /** Request timeout in seconds */
  timeoutSeconds: number;
  /** Maximum request body size in bytes */
  maxBodyBytes: number;
}

/**
 * Key store backend configuration.
 */
export interface KeyStoreConfig {
  /** Key store backend type */
  type: 'file' | 'vault' | 'env';
  /** Path to key file (for file backend) */
  filePath?: string;
  /** HashiCorp Vault configuration */
  vault?: VaultConfig;
  /** Environment variable prefix (for env backend) */
  envPrefix?: string;
}

/**
 * HashiCorp Vault configuration.
 */
export interface VaultConfig {
  /** Vault server address */
  address: string;
  /** Authentication method */
  authMethod: 'token' | 'kubernetes' | 'approle';
  /** Vault token (for token auth) */
  token?: string;
  /** Kubernetes role (for kubernetes auth) */
  k8sRole?: string;
  /** AppRole role ID */
  roleId?: string;
  /** AppRole secret ID */
  secretId?: string;
  /** Secret mount path */
  mountPath: string;
  /** Secret path template (supports {org_id} placeholder) */
  secretPath: string;
}

/**
 * Logging configuration.
 */
export interface LoggingConfig {
  /** Log level */
  level: 'trace' | 'debug' | 'info' | 'warn' | 'error';
  /** Output format */
  format: 'json' | 'pretty';
  /** Audit log path for decrypt operations */
  auditLogPath?: string;
}

/**
 * Metrics configuration.
 */
export interface MetricsConfig {
  /** Enable Prometheus metrics endpoint */
  enabled: boolean;
  /** Metrics endpoint path */
  path: string;
  /** Metrics port (if different from main server) */
  port?: number;
}
