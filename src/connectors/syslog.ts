/**
 * BrowserDefense Syslog Connector
 *
 * Generic syslog connector supporting:
 * - CEF (Common Event Format) - ArcSight compatible
 * - LEEF (Log Event Extended Format) - QRadar compatible
 * - JSON and raw formats
 * - UDP, TCP, and TLS transport
 * - RFC 5424 structured data
 *
 * Unblock Support:
 * - Sends unblock event in configured format
 * - Uses Unblock action/event ID for correlation
 * - Always succeeds (fire-and-forget logging)
 */

import { BaseConnector, connectorRegistry } from './base';
import {
  ForensicsEvent,
  SendResult,
  SyslogConnectorConfig,
  SyslogFormat,
  StructuredDataElement,
  UnblockResult,
} from './types';

// =============================================================================
// Constants
// =============================================================================

/** Default syslog facility (local0 = 16) */
const DEFAULT_FACILITY = 16;

/** Default syslog severity (notice = 5) */
const DEFAULT_SEVERITY = 5;

/** Default app name */
const DEFAULT_APP_NAME = 'browserdefense-connector';

/** Default CEF vendor */
const DEFAULT_CEF_VENDOR = 'BrowserDefense';

/** Default CEF product */
const DEFAULT_CEF_PRODUCT = 'Connector';

/** Default CEF version */
const DEFAULT_CEF_VERSION = '1.0';

/** Default connection timeout */
const _DEFAULT_CONNECT_TIMEOUT_MS = 5000;

/** BrowserDefense IANA PEN for structured data (using example PEN - replace with actual) */
const BROWSERDEFENSE_PEN = '55555';

/** CEF event signature IDs */
const CEF_SIG_ID = {
  BLOCKED_NAVIGATION: '100',
  BLOCKED_DOMAIN: '101',
  BLOCKED_URL: '102',
  BLOCKED_HASH: '103',
  UNBLOCKED_NAVIGATION: '200',
  UNBLOCKED_DOMAIN: '201',
  UNBLOCKED_URL: '202',
  UNBLOCKED_HASH: '203',
};

/** CEF severity mapping (0-10 scale) */
const CEF_SEVERITY = {
  LOW: '3',
  MEDIUM: '5',
  HIGH: '7',
  CRITICAL: '10',
};

// =============================================================================
// Message Formatters
// =============================================================================

/**
 * Escape special characters in CEF extension values.
 * CEF requires escaping: backslash, equals, and newlines.
 */
function escapeCefValue(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/=/g, '\\=')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

/**
 * Escape special characters in LEEF attribute values.
 * LEEF requires escaping: tab, newline, carriage return.
 */
function escapeLeefValue(value: string): string {
  return value
    .replace(/\t/g, '\\t')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

/**
 * Escape special characters in RFC 5424 structured data values.
 * SD-PARAM values must escape: backslash, double-quote, right bracket.
 */
function escapeSDValue(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\]/g, '\\]');
}

/**
 * Format event as CEF (Common Event Format).
 * CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
 */
function formatCef(
  event: ForensicsEvent,
  vendor: string,
  product: string,
  version: string
): string {
  // Determine signature ID based on match type
  let sigId = CEF_SIG_ID.BLOCKED_NAVIGATION;
  let name = 'Blocked Navigation';
  switch (event.matchType) {
    case 'domain':
      sigId = CEF_SIG_ID.BLOCKED_DOMAIN;
      name = 'Blocked Domain';
      break;
    case 'url':
      sigId = CEF_SIG_ID.BLOCKED_URL;
      name = 'Blocked URL';
      break;
    case 'hash':
      sigId = CEF_SIG_ID.BLOCKED_HASH;
      name = 'Blocked Hash';
      break;
  }

  // Build extension fields
  const extensions: string[] = [];

  // Standard CEF fields
  extensions.push(`rt=${new Date(event.timestamp).getTime()}`);
  extensions.push(`request=${escapeCefValue(event.blockedUrl)}`);
  extensions.push(`src=${escapeCefValue(event.orgId)}`);
  extensions.push(`cat=WebSecurity`);
  extensions.push(`act=Block`);

  // Custom fields
  extensions.push(`cs1=${escapeCefValue(event.matchedIndicator)} cs1Label=MatchedIndicator`);
  extensions.push(`cs2=${escapeCefValue(event.matchType)} cs2Label=MatchType`);
  extensions.push(`cs3=${escapeCefValue(event.eventId)} cs3Label=EventId`);

  // Redirect chain
  if (event.redirectChain.length > 0) {
    extensions.push(
      `cs4=${escapeCefValue(event.redirectChain.join(' -> '))} cs4Label=RedirectChain`
    );
  }

  // Tab context
  if (event.tabContext.initiatorUrl) {
    extensions.push(`surl=${escapeCefValue(event.tabContext.initiatorUrl)}`);
  }

  // User and device IDs if available
  if (event.userId) {
    extensions.push(`suser=${escapeCefValue(event.userId)}`);
  }
  if (event.deviceId) {
    extensions.push(`dvchost=${escapeCefValue(event.deviceId)}`);
  }

  // Build CEF message
  return `CEF:0|${escapeCefValue(vendor)}|${escapeCefValue(product)}|${escapeCefValue(version)}|${sigId}|${name}|${CEF_SEVERITY.MEDIUM}|${extensions.join(' ')}`;
}

/**
 * Format event as LEEF (Log Event Extended Format) for IBM QRadar.
 * LEEF:Version|Vendor|Product|Version|EventID|key=value<tab>key=value
 */
function formatLeef(
  event: ForensicsEvent,
  vendor: string,
  product: string,
  version: string
): string {
  // Determine event ID
  let eventId = 'BlockedNavigation';
  switch (event.matchType) {
    case 'domain':
      eventId = 'BlockedDomain';
      break;
    case 'url':
      eventId = 'BlockedURL';
      break;
    case 'hash':
      eventId = 'BlockedHash';
      break;
  }

  // Build attributes (tab-separated)
  const attrs: string[] = [];

  // Standard LEEF fields
  attrs.push(`devTime=${new Date(event.timestamp).toISOString()}`);
  attrs.push(`devTimeFormat=ISO8601`);
  attrs.push(`url=${escapeLeefValue(event.blockedUrl)}`);
  attrs.push(`src=${escapeLeefValue(event.orgId)}`);
  attrs.push(`cat=WebSecurity`);
  attrs.push(`action=Block`);

  // Custom fields
  attrs.push(`matchedIndicator=${escapeLeefValue(event.matchedIndicator)}`);
  attrs.push(`matchType=${escapeLeefValue(event.matchType)}`);
  attrs.push(`eventId=${escapeLeefValue(event.eventId)}`);

  // Redirect chain
  if (event.redirectChain.length > 0) {
    attrs.push(`redirectChain=${escapeLeefValue(event.redirectChain.join(' -> '))}`);
  }

  // Tab context
  if (event.tabContext.initiatorUrl) {
    attrs.push(`srcUrl=${escapeLeefValue(event.tabContext.initiatorUrl)}`);
  }

  // User and device IDs
  if (event.userId) {
    attrs.push(`usrName=${escapeLeefValue(event.userId)}`);
  }
  if (event.deviceId) {
    attrs.push(`identHostName=${escapeLeefValue(event.deviceId)}`);
  }

  // Build LEEF message (LEEF 2.0 uses tab as default delimiter)
  return `LEEF:2.0|${vendor}|${product}|${version}|${eventId}|${attrs.join('\t')}`;
}

/**
 * Format event as JSON.
 */
function formatJson(event: ForensicsEvent): string {
  return JSON.stringify(event);
}

/**
 * Format event as raw text.
 */
function formatRaw(event: ForensicsEvent): string {
  return `BrowserDefense blocked_url=${event.blockedUrl} match_type=${event.matchType} indicator=${event.matchedIndicator} org_id=${event.orgId} event_id=${event.eventId}`;
}

// =============================================================================
// RFC 5424 Syslog Message Builder
// =============================================================================

/**
 * Build RFC 5424 structured data string.
 */
function buildStructuredData(
  event: ForensicsEvent,
  includeDefault: boolean,
  customElements?: StructuredDataElement[]
): string {
  const elements: string[] = [];

  // Add default BrowserDefense structured data
  if (includeDefault) {
    const params = [
      `blockedUrl="${escapeSDValue(event.blockedUrl)}"`,
      `matchType="${escapeSDValue(event.matchType)}"`,
      `matchedIndicator="${escapeSDValue(event.matchedIndicator)}"`,
      `orgId="${escapeSDValue(event.orgId)}"`,
      `eventId="${escapeSDValue(event.eventId)}"`,
    ];

    if (event.userId) {
      params.push(`userId="${escapeSDValue(event.userId)}"`);
    }
    if (event.deviceId) {
      params.push(`deviceId="${escapeSDValue(event.deviceId)}"`);
    }
    if (event.redirectChain.length > 0) {
      params.push(`redirectChain="${escapeSDValue(event.redirectChain.join(' -> '))}"`);
    }
    if (event.tabContext.initiatorUrl) {
      params.push(`initiatorUrl="${escapeSDValue(event.tabContext.initiatorUrl)}"`);
    }

    elements.push(`[BrowserDefense@${BROWSERDEFENSE_PEN} ${params.join(' ')}]`);
  }

  // Add custom structured data elements
  if (customElements) {
    for (const elem of customElements) {
      const params = Object.entries(elem.params)
        .map(([k, v]) => `${k}="${escapeSDValue(v)}"`)
        .join(' ');
      elements.push(`[${elem.id} ${params}]`);
    }
  }

  return elements.length > 0 ? elements.join('') : '-';
}

/**
 * Build complete RFC 5424 syslog message.
 *
 * Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
 */
function buildSyslogMessage(
  event: ForensicsEvent,
  config: SyslogConnectorConfig,
  payload: string
): string {
  const facility = config.facility ?? DEFAULT_FACILITY;
  const severity = config.severity ?? DEFAULT_SEVERITY;
  const appName = config.appName ?? DEFAULT_APP_NAME;
  const procId = config.procId ?? '-';
  const msgId = config.msgId ?? '-';

  // Calculate PRI (Priority = Facility * 8 + Severity)
  const pri = facility * 8 + severity;

  // RFC 5424 timestamp
  const timestamp = new Date(event.timestamp).toISOString();

  // Hostname (use org ID or '-')
  const hostname = event.orgId || '-';

  // Build structured data
  const structuredData = buildStructuredData(
    event,
    config.includeStructuredData ?? false,
    config.structuredData
  );

  // RFC 5424 message format
  // BOM is optional but recommended for UTF-8 messages
  const bom = '\uFEFF';
  return `<${pri}>1 ${timestamp} ${hostname} ${appName} ${procId} ${msgId} ${structuredData} ${bom}${payload}`;
}

// =============================================================================
// Transport Layer
// =============================================================================

/**
 * Socket connection wrapper for TCP/TLS.
 * In a real implementation, this would use Node.js net/tls modules.
 * For browser context, this is a mock interface.
 */
interface SocketConnection {
  write(data: string): Promise<void>;
  close(): Promise<void>;
  isConnected(): boolean;
}

/**
 * Mock socket implementation for browser context.
 * Real implementation would use Node.js net/tls or WebSocket bridge.
 */
class MockSocket implements SocketConnection {
  private connected = false;
  private host: string;
  private port: number;
  private protocol: 'udp' | 'tcp' | 'tcp+tls';

  constructor(host: string, port: number, protocol: 'udp' | 'tcp' | 'tcp+tls') {
    this.host = host;
    this.port = port;
    this.protocol = protocol;
  }

  async connect(): Promise<void> {
    // In real implementation: establish TCP/TLS connection
    // For now, simulate successful connection
    this.connected = true;
  }

  async write(data: string): Promise<void> {
    if (!this.connected) {
      throw new Error('Socket not connected');
    }
    // In real implementation: send data over socket
    // For UDP: dgram.send()
    // For TCP: socket.write()
    // For TLS: tls.connect() then write()

    // Mock: log to console in development
    if (typeof process !== 'undefined' && process.env?.NODE_ENV === 'development') {
      console.log(`[SyslogConnector] ${this.protocol}://${this.host}:${this.port}`, data);
    }
  }

  async close(): Promise<void> {
    this.connected = false;
  }

  isConnected(): boolean {
    return this.connected;
  }
}

// =============================================================================
// Syslog Connector Implementation
// =============================================================================

/**
 * Syslog connector for sending forensics events to syslog servers.
 *
 * Supports:
 * - CEF (Common Event Format) - ArcSight, Splunk, etc.
 * - LEEF (Log Event Extended Format) - IBM QRadar
 * - JSON - Generic JSON format
 * - Raw - Simple key=value format
 *
 * Transport protocols:
 * - UDP - Fast, no acknowledgment (port 514)
 * - TCP - Reliable, with octet counting (RFC 6587)
 * - TCP+TLS - Encrypted TCP (port 6514)
 */
export class SyslogConnector extends BaseConnector {
  readonly type = 'syslog' as const;

  /**
   * Syslog supports unblock via logging an unblock event.
   * The event is correlated with the original block by eventId.
   */
  readonly supportsUnblock = true;

  private readonly syslogConfig: SyslogConnectorConfig;
  private socket: SocketConnection | null = null;
  private lastHealthCheck: Date | null = null;
  private consecutiveFailures = 0;

  constructor(config: SyslogConnectorConfig) {
    super(config);
    this.syslogConfig = config;
  }

  /**
   * Initialize the connector.
   * Establishes connection for TCP/TLS protocols.
   */
  protected async doInit(): Promise<void> {
    // Validate configuration
    if (!this.syslogConfig.host) {
      throw new Error('Syslog host is required');
    }
    if (!this.syslogConfig.port || this.syslogConfig.port < 1 || this.syslogConfig.port > 65535) {
      throw new Error('Valid syslog port (1-65535) is required');
    }

    // Validate facility (0-23)
    const facility = this.syslogConfig.facility ?? DEFAULT_FACILITY;
    if (facility < 0 || facility > 23) {
      throw new Error('Syslog facility must be between 0 and 23');
    }

    // Validate severity (0-7)
    const severity = this.syslogConfig.severity ?? DEFAULT_SEVERITY;
    if (severity < 0 || severity > 7) {
      throw new Error('Syslog severity must be between 0 and 7');
    }

    // For TCP/TLS, establish persistent connection
    if (this.syslogConfig.protocol !== 'udp') {
      await this.connect();
    }
  }

  /**
   * Establish connection to syslog server.
   */
  private async connect(): Promise<void> {
    this.socket = new MockSocket(
      this.syslogConfig.host,
      this.syslogConfig.port,
      this.syslogConfig.protocol
    );

    // In real implementation, this would:
    // 1. Create TCP socket with optional TLS
    // 2. Set connection timeout
    // 3. Configure keep-alive
    // 4. Handle TLS certificate verification

    await (this.socket as MockSocket).connect();
  }

  /**
   * Reconnect to syslog server.
   */
  private async reconnect(): Promise<void> {
    if (this.socket) {
      try {
        await this.socket.close();
      } catch {
        // Ignore close errors
      }
    }
    await this.connect();
  }

  /**
   * Send a forensics event to the syslog server.
   */
  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    try {
      // Format the message payload based on configured format
      const format = this.syslogConfig.format ?? 'cef';
      const payload = this.formatPayload(event, format);

      // Build complete syslog message
      const message = buildSyslogMessage(event, this.syslogConfig, payload);

      // Send via appropriate transport
      await this.sendMessage(message);

      this.consecutiveFailures = 0;

      return {
        success: true,
        eventId: event.eventId,
        response: {
          format,
          protocol: this.syslogConfig.protocol,
          messageLength: message.length,
        },
      };
    } catch (error) {
      this.consecutiveFailures++;

      const errorMessage = error instanceof Error ? error.message : String(error);

      // Determine if error is retryable
      const retryable = this.isRetryableError(error);

      // Attempt reconnection for TCP/TLS on connection errors
      if (retryable && this.syslogConfig.protocol !== 'udp') {
        try {
          await this.reconnect();
        } catch {
          // Reconnection failed, will retry on next send
        }
      }

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable,
      };
    }
  }

  /**
   * Format event payload based on configured format.
   */
  private formatPayload(event: ForensicsEvent, format: SyslogFormat): string {
    switch (format) {
      case 'cef':
        return formatCef(
          event,
          this.syslogConfig.cefVendor ?? DEFAULT_CEF_VENDOR,
          this.syslogConfig.cefProduct ?? DEFAULT_CEF_PRODUCT,
          this.syslogConfig.cefVersion ?? DEFAULT_CEF_VERSION
        );
      case 'leef':
        return formatLeef(
          event,
          this.syslogConfig.cefVendor ?? DEFAULT_CEF_VENDOR,
          this.syslogConfig.cefProduct ?? DEFAULT_CEF_PRODUCT,
          this.syslogConfig.cefVersion ?? DEFAULT_CEF_VERSION
        );
      case 'json':
        return formatJson(event);
      case 'raw':
        return formatRaw(event);
      default: {
        // TypeScript exhaustiveness check
        const _exhaustive: never = format;
        throw new Error(`Unknown format: ${_exhaustive}`);
      }
    }
  }

  /**
   * Send message via configured transport protocol.
   */
  private async sendMessage(message: string): Promise<void> {
    switch (this.syslogConfig.protocol) {
      case 'udp':
        await this.sendUdp(message);
        break;
      case 'tcp':
      case 'tcp+tls':
        await this.sendTcp(message);
        break;
    }
  }

  /**
   * Send message via UDP.
   * UDP messages are fire-and-forget, no framing needed.
   */
  private async sendUdp(message: string): Promise<void> {
    // Create ephemeral socket for each UDP send
    const socket = new MockSocket(
      this.syslogConfig.host,
      this.syslogConfig.port,
      'udp'
    );
    await (socket as MockSocket).connect();

    try {
      await socket.write(message);
    } finally {
      await socket.close();
    }
  }

  /**
   * Send message via TCP with octet counting (RFC 6587).
   * Format: <MSG_LEN> <MSG>
   */
  private async sendTcp(message: string): Promise<void> {
    if (!this.socket || !this.socket.isConnected()) {
      await this.connect();
    }

    // RFC 6587 octet counting: prefix message with its length
    const framedMessage = `${Buffer.byteLength(message, 'utf8')} ${message}`;
    await this.socket!.write(framedMessage);
  }

  /**
   * Check if an error is retryable.
   */
  private isRetryableError(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      // Connection errors are retryable
      return (
        message.includes('econnrefused') ||
        message.includes('econnreset') ||
        message.includes('etimedout') ||
        message.includes('enetunreach') ||
        message.includes('ehostunreach') ||
        message.includes('socket not connected')
      );
    }
    return true; // Default to retryable for unknown errors
  }

  /**
   * Perform health check.
   */
  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    this.lastHealthCheck = new Date();

    // Check consecutive failures
    if (this.consecutiveFailures >= 3) {
      return {
        healthy: false,
        message: `${this.consecutiveFailures} consecutive failures`,
      };
    }

    // For TCP/TLS, check connection status
    if (this.syslogConfig.protocol !== 'udp') {
      if (!this.socket || !this.socket.isConnected()) {
        try {
          await this.connect();
        } catch (error) {
          return {
            healthy: false,
            message: `Connection failed: ${error instanceof Error ? error.message : String(error)}`,
          };
        }
      }
    }

    return {
      healthy: true,
      message: `Connected to ${this.syslogConfig.host}:${this.syslogConfig.port} via ${this.syslogConfig.protocol}`,
    };
  }

  /**
   * Close the connector and clean up resources.
   */
  protected async doClose(): Promise<void> {
    if (this.socket) {
      try {
        await this.socket.close();
      } catch {
        // Ignore close errors
      }
      this.socket = null;
    }
  }

  /**
   * Send an unblock event to the syslog server for correlation.
   */
  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    try {
      // Format the unblock message payload
      const format = this.syslogConfig.format ?? 'cef';
      const payload = this.formatUnblockPayload(event, format);

      // Build complete syslog message (reuse existing builder with modified event)
      const unblockEvent: ForensicsEvent = {
        ...event,
        timestamp: new Date().toISOString(),
      };
      const message = buildSyslogMessage(unblockEvent, this.syslogConfig, payload);

      // Send via appropriate transport
      await this.sendMessage(message);

      return {
        success: true,
        eventId: event.eventId,
        incidentId: `unblock-${event.eventId}`,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const retryable = this.isRetryableError(error);

      return {
        success: false,
        eventId: event.eventId,
        error: `Syslog unblock failed: ${errorMessage}`,
        retryable,
      };
    }
  }

  /**
   * Format unblock event payload based on configured format.
   */
  private formatUnblockPayload(event: ForensicsEvent, format: SyslogFormat): string {
    switch (format) {
      case 'cef':
        return this.formatUnblockCef(event);
      case 'leef':
        return this.formatUnblockLeef(event);
      case 'json':
        return this.formatUnblockJson(event);
      case 'raw':
        return this.formatUnblockRaw(event);
      default: {
        const _exhaustive: never = format;
        throw new Error(`Unknown format: ${_exhaustive}`);
      }
    }
  }

  /**
   * Format unblock event as CEF.
   */
  private formatUnblockCef(event: ForensicsEvent): string {
    let sigId = CEF_SIG_ID.UNBLOCKED_NAVIGATION;
    let name = 'Unblocked Navigation';
    switch (event.matchType) {
      case 'domain':
        sigId = CEF_SIG_ID.UNBLOCKED_DOMAIN;
        name = 'Unblocked Domain';
        break;
      case 'url':
        sigId = CEF_SIG_ID.UNBLOCKED_URL;
        name = 'Unblocked URL';
        break;
      case 'hash':
        sigId = CEF_SIG_ID.UNBLOCKED_HASH;
        name = 'Unblocked Hash';
        break;
    }

    const extensions: string[] = [];
    extensions.push(`rt=${Date.now()}`);
    extensions.push(`request=${escapeCefValue(event.blockedUrl)}`);
    extensions.push(`src=${escapeCefValue(event.orgId)}`);
    extensions.push(`cat=WebSecurity`);
    extensions.push(`act=Unblock`);
    extensions.push(`cs1=${escapeCefValue(event.matchedIndicator)} cs1Label=MatchedIndicator`);
    extensions.push(`cs2=${escapeCefValue(event.matchType)} cs2Label=MatchType`);
    extensions.push(`cs3=${escapeCefValue(event.eventId)} cs3Label=EventId`);

    if (event.userId) {
      extensions.push(`suser=${escapeCefValue(event.userId)}`);
    }
    if (event.deviceId) {
      extensions.push(`dvchost=${escapeCefValue(event.deviceId)}`);
    }

    const vendor = this.syslogConfig.cefVendor ?? DEFAULT_CEF_VENDOR;
    const product = this.syslogConfig.cefProduct ?? DEFAULT_CEF_PRODUCT;
    const version = this.syslogConfig.cefVersion ?? DEFAULT_CEF_VERSION;

    return `CEF:0|${escapeCefValue(vendor)}|${escapeCefValue(product)}|${escapeCefValue(version)}|${sigId}|${name}|${CEF_SEVERITY.LOW}|${extensions.join(' ')}`;
  }

  /**
   * Format unblock event as LEEF.
   */
  private formatUnblockLeef(event: ForensicsEvent): string {
    let eventId = 'UnblockedNavigation';
    switch (event.matchType) {
      case 'domain':
        eventId = 'UnblockedDomain';
        break;
      case 'url':
        eventId = 'UnblockedURL';
        break;
      case 'hash':
        eventId = 'UnblockedHash';
        break;
    }

    const attrs: string[] = [];
    attrs.push(`devTime=${new Date().toISOString()}`);
    attrs.push(`devTimeFormat=ISO8601`);
    attrs.push(`url=${escapeLeefValue(event.blockedUrl)}`);
    attrs.push(`src=${escapeLeefValue(event.orgId)}`);
    attrs.push(`cat=WebSecurity`);
    attrs.push(`action=Unblock`);
    attrs.push(`matchedIndicator=${escapeLeefValue(event.matchedIndicator)}`);
    attrs.push(`matchType=${escapeLeefValue(event.matchType)}`);
    attrs.push(`eventId=${escapeLeefValue(event.eventId)}`);

    if (event.userId) {
      attrs.push(`usrName=${escapeLeefValue(event.userId)}`);
    }
    if (event.deviceId) {
      attrs.push(`identHostName=${escapeLeefValue(event.deviceId)}`);
    }

    const vendor = this.syslogConfig.cefVendor ?? DEFAULT_CEF_VENDOR;
    const product = this.syslogConfig.cefProduct ?? DEFAULT_CEF_PRODUCT;
    const version = this.syslogConfig.cefVersion ?? DEFAULT_CEF_VERSION;

    return `LEEF:2.0|${vendor}|${product}|${version}|${eventId}|${attrs.join('\t')}`;
  }

  /**
   * Format unblock event as JSON.
   */
  private formatUnblockJson(event: ForensicsEvent): string {
    return JSON.stringify({
      timestamp: new Date().toISOString(),
      eventType: 'unblock',
      action: 'unblock',
      blockedUrl: event.blockedUrl,
      matchType: event.matchType,
      matchedIndicator: event.matchedIndicator,
      orgId: event.orgId,
      eventId: event.eventId,
      originalEventId: event.eventId,
      userId: event.userId,
      deviceId: event.deviceId,
    });
  }

  /**
   * Format unblock event as raw text.
   */
  private formatUnblockRaw(event: ForensicsEvent): string {
    return `BrowserDefense action=unblock blocked_url=${event.blockedUrl} match_type=${event.matchType} indicator=${event.matchedIndicator} org_id=${event.orgId} event_id=${event.eventId}`;
  }

  // ===========================================================================
  // Public Formatting Methods (for testing and direct use)
  // ===========================================================================

  /**
   * Format an event as CEF without sending.
   * Useful for testing or when you need the formatted string.
   */
  public formatAsCef(event: ForensicsEvent): string {
    return formatCef(
      event,
      this.syslogConfig.cefVendor ?? DEFAULT_CEF_VENDOR,
      this.syslogConfig.cefProduct ?? DEFAULT_CEF_PRODUCT,
      this.syslogConfig.cefVersion ?? DEFAULT_CEF_VERSION
    );
  }

  /**
   * Format an event as LEEF without sending.
   */
  public formatAsLeef(event: ForensicsEvent): string {
    return formatLeef(
      event,
      this.syslogConfig.cefVendor ?? DEFAULT_CEF_VENDOR,
      this.syslogConfig.cefProduct ?? DEFAULT_CEF_PRODUCT,
      this.syslogConfig.cefVersion ?? DEFAULT_CEF_VERSION
    );
  }

  /**
   * Format an event as JSON without sending.
   */
  public formatAsJson(event: ForensicsEvent): string {
    return formatJson(event);
  }

  /**
   * Format an event as raw without sending.
   */
  public formatAsRaw(event: ForensicsEvent): string {
    return formatRaw(event);
  }

  /**
   * Build a complete RFC 5424 syslog message without sending.
   */
  public buildMessage(event: ForensicsEvent): string {
    const format = this.syslogConfig.format ?? 'cef';
    const payload = this.formatPayload(event, format);
    return buildSyslogMessage(event, this.syslogConfig, payload);
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Factory function for creating SyslogConnector instances.
 */
export function createSyslogConnector(config: SyslogConnectorConfig): SyslogConnector {
  return new SyslogConnector(config);
}

// Register with the global connector registry
connectorRegistry.register('syslog', createSyslogConnector);

// =============================================================================
// Exported Utilities
// =============================================================================

export {
  formatCef,
  formatLeef,
  formatJson,
  formatRaw,
  buildStructuredData,
  buildSyslogMessage,
  escapeCefValue,
  escapeLeefValue,
  escapeSDValue,
  CEF_SIG_ID,
  CEF_SEVERITY,
  DEFAULT_FACILITY,
  DEFAULT_SEVERITY,
  DEFAULT_APP_NAME,
  DEFAULT_CEF_VENDOR,
  DEFAULT_CEF_PRODUCT,
  DEFAULT_CEF_VERSION,
  BROWSERDEFENSE_PEN,
};
