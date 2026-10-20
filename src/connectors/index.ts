/**
 * BrowserDefense Enterprise Connectors
 *
 * Main export point for the connector framework.
 */

// Core types
export type {
  // Event types
  ForensicsEvent,
  TabContext,
  IocAction,

  // Configuration types
  BaseConnectorConfig,
  BatchConfig,
  RetryConfig,
  FilterConfig,
  TlsConfig,

  // SIEM connectors
  SplunkConnectorConfig,
  ElasticConnectorConfig,
  SyslogConnectorConfig,
  SumoLogicConnectorConfig,
  QRadarConnectorConfig,
  QRadarRestApiConfig,
  SyslogFormat,
  StructuredDataElement,
  InsightIDRConnectorConfig,
  InsightIDRRegion,
  SentinelConnectorConfig,
  ChronicleConnectorConfig,

  // EDR connectors
  CrowdStrikeConnectorConfig,
  SentinelOneConnectorConfig,
  DefenderConnectorConfig,
  CarbonBlackConnectorConfig,
  BitdefenderGravityZoneConnectorConfig,
  HarfangLabConnectorConfig,
  CortexXdrConnectorConfig,
  FortigateConnectorConfig,
  ZscalerConnectorConfig,

  // SOAR connectors
  WebhookConnectorConfig,
  XsoarConnectorConfig,
  ServiceNowConnectorConfig,
  ServiceNowAuth,
  WebhookAuth,
  OAuth2Config,

  // Observability connectors
  DatadogConnectorConfig,

  // Cloud security connectors
  SecurityHubConnectorConfig,

  // Union types
  ConnectorConfig,
  ConnectorType,

  // Results and status
  SendResult,
  UnblockResult,
  HealthStatus,
  HealthMetrics,

  // Encrypted payload types
  EncryptedForensicsPayload,
  KeyEntry,

  // Service configuration
  ConnectorServiceConfig,
  ServerConfig,
  KeyStoreConfig,
  VaultConfig,
  LoggingConfig,
  MetricsConfig,
} from './types';

// Base connector implementation
export type { Connector } from './base';
export {
  BaseConnector,
  ConnectorRegistry,
  connectorRegistry,
} from './base';

export type {
  ConnectorFactory,
  ConfigForType,
  EventTransformer,
  HttpClientOptions,
} from './base';

// CrowdStrike connector
export {
  CrowdStrikeConnector,
  createCrowdStrikeConnector,
  getCloudBaseUrl,
  CROWDSTRIKE_REGIONS,
} from './crowdstrike';

// Webhook connector
export { WebhookConnector, createWebhookConnector, renderTemplate } from './webhook';

// SOAR Connectors
export { XsoarConnector, XsoarApiError, createXsoarConnector } from './xsoar';

// Elastic/ELK Stack connector
export { ElasticConnector, createElasticConnector } from './elastic';
export type { EcsDocument } from './elastic';

// Sumo Logic connector
export {
  SumoLogicConnector,
  createSumoLogicConnector,
} from './sumologic';

export type { SumoLogicEvent } from './sumologic';

// Defender connector
export { DefenderConnector, createDefenderConnector } from './defender';

// Carbon Black connector
export { CarbonBlackConnector, CarbonBlackApiError } from './carbonblack';

// Bitdefender GravityZone connector
export { BitdefenderGravityZoneConnector, createBitdefenderGravityZoneConnector } from './bitdefender-gravityzone';

// HarfangLab connector
export { HarfangLabConnector, createHarfangLabConnector } from './harfanglab';

// Cortex XDR connector
export { CortexXdrConnector, createCortexXdrConnector } from './cortexxdr';

// Fortigate connector
export { FortigateConnector, createFortigateConnector } from './fortigate';

// Zscaler connector
export { ZscalerConnector, createZscalerConnector } from './zscaler';

// QRadar connector
export {
  QRadarConnector,
  createQRadarConnector,
  formatLeef as qradarFormatLeef,
  formatCef as qradarFormatCef,
  buildSyslogMessage as qradarBuildSyslogMessage,
} from './qradar';

// Syslog connector
export {
  SyslogConnector,
  createSyslogConnector,
  // Formatters
  formatCef,
  formatLeef,
  formatJson,
  formatRaw,
  buildStructuredData,
  buildSyslogMessage,
  // Escape utilities
  escapeCefValue,
  escapeLeefValue,
  escapeSDValue,
  // Constants
  CEF_SIG_ID,
  CEF_SEVERITY,
  DEFAULT_FACILITY,
  DEFAULT_SEVERITY,
  DEFAULT_APP_NAME,
  DEFAULT_CEF_VENDOR,
  DEFAULT_CEF_PRODUCT,
  DEFAULT_CEF_VERSION,
  BROWSERDEFENSE_PEN,
} from './syslog';

// InsightIDR (Rapid7) connector
export {
  InsightIDRConnector,
  createInsightIDRConnector,
  transformToInsightIDRLog,
} from './rapid7';

export type { InsightIDRLogEntry } from './rapid7';

// Sentinel connector
export { SentinelConnector, createSentinelConnector, type SentinelLogEntry } from './sentinel';

// Datadog connector
export { DatadogConnector, createDatadogConnector } from './datadog';

// SentinelOne connector
export {
  SentinelOneConnector,
  createSentinelOneConnector,
} from './sentinelone';

// Security Hub connector
export { SecurityHubConnector, createSecurityHubConnector } from './securityhub';

// Chronicle connector
export { ChronicleConnector, ChronicleApiError } from './chronicle';

// Splunk HEC connector
export {
  SplunkConnector,
  createSplunkConnector,
} from './splunk';
export type { SplunkHecEvent, SplunkEventPayload } from './splunk';

// ServiceNow connector
export {
  ServiceNowConnector,
  createServiceNowConnector,
} from './servicenow';
