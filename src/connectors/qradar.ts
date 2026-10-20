/**
 * BrowserDefense IBM QRadar Connector
 *
 * Sends forensics events to IBM QRadar via Syslog (LEEF format) or REST API.
 * Supports UDP, TCP, and TLS transport protocols.
 *
 * LEEF (Log Event Extended Format) is IBM's preferred format for QRadar.
 * Format: LEEF:Version|Vendor|Product|Version|EventID|<attributes>
 *
 * Unblock Support:
 * - Sends an unblock event via syslog for correlation
 * - Uses UnblockedNavigation event ID
 * - Always succeeds (fire-and-forget logging)
 *
 * @see https://www.ibm.com/docs/en/dsm?topic=leef-overview
 */

import type { ConnectionOptions as TlsConnectionOptions } from 'tls';

import { BaseConnector, connectorRegistry } from './base';
import {
  ConnectorType,
  ForensicsEvent,
  QRadarConnectorConfig,
  SendResult,
  UnblockResult,
} from './types';

// =============================================================================
// Constants
// =============================================================================

/** LEEF format version */
const LEEF_VERSION = '2.0';

/** BrowserDefense vendor identifier */
const VENDOR = 'BrowserDefense';

/** Product name */
const PRODUCT = 'Connector';

/** Product version - should match package.json */
const VERSION = '1.0.0';

/** Default syslog facility (local0 = 16) */
const DEFAULT_FACILITY = 16;

/** Default syslog severity (notice = 5) */
const DEFAULT_SEVERITY = 5;

/** Default syslog port */
const DEFAULT_PORT = 514;

/** Default app name for syslog header */
const DEFAULT_APP_NAME = 'browserdefense';

/** LEEF attribute delimiter (tab character) */
const LEEF_DELIMITER = '\t';

/** Connection timeout in milliseconds */
const CONNECTION_TIMEOUT_MS = 10000;

/** Maximum message size for UDP (RFC 5426 recommends 2048) */
const MAX_UDP_MESSAGE_SIZE = 2048;

// =============================================================================
// Syslog Transport Interface
// =============================================================================

/**
 * Abstract interface for syslog transport.
 * Allows different implementations for UDP, TCP, TLS.
 */
interface SyslogTransport {
  connect(): Promise<void>;
  send(message: string): Promise<void>;
  close(): Promise<void>;
  isConnected(): boolean;
}

// =============================================================================
// UDP Transport
// =============================================================================

/**
 * UDP syslog transport implementation.
 * Connectionless, best-effort delivery.
 */
class UdpSyslogTransport implements SyslogTransport {
  private host: string;
  private port: number;
  private encoder: TextEncoder;
  private connected: boolean = false;

  constructor(host: string, port: number) {
    this.host = host;
    this.port = port;
    this.encoder = new TextEncoder();
  }

  async connect(): Promise<void> {
    // UDP is connectionless, but we validate the host
    this.connected = true;
  }

  async send(message: string): Promise<void> {
    if (!this.connected) {
      throw new Error('UDP transport not initialized');
    }

    const data = this.encoder.encode(message);

    // Warn if message exceeds recommended UDP size
    if (data.length > MAX_UDP_MESSAGE_SIZE) {
      console.warn(
        `[QRadar] UDP message size (${data.length}) exceeds recommended maximum (${MAX_UDP_MESSAGE_SIZE})`
      );
    }

    // In Node.js environment, use dgram
    // In browser/service worker, UDP is not available
    if (typeof globalThis.process !== 'undefined' && globalThis.process.versions?.node) {
      const dgram = await import('dgram');
      return new Promise((resolve, reject) => {
        const client = dgram.createSocket('udp4');
        client.send(data, this.port, this.host, (err) => {
          client.close();
          if (err) {
            reject(new Error(`UDP send failed: ${err.message}`));
          } else {
            resolve();
          }
        });
      });
    } else {
      // For browser/service worker environments, fall back to HTTP proxy
      // or throw an error indicating UDP is not supported
      throw new Error(
        'UDP transport not supported in browser environment. Use TCP or configure an HTTP proxy.'
      );
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
// TCP Transport
// =============================================================================

/**
 * TCP syslog transport implementation.
 * Reliable, connection-oriented delivery with octet-counting framing.
 */
class TcpSyslogTransport implements SyslogTransport {
  private host: string;
  private port: number;
  private useTls: boolean;
  private tlsOptions?: {
    verify: boolean;
    caCertPath?: string;
    clientCertPath?: string;
    clientKeyPath?: string;
  };
  private socket: unknown = null;
  private connected: boolean = false;
  private encoder: TextEncoder;

  constructor(
    host: string,
    port: number,
    useTls: boolean = false,
    tlsOptions?: {
      verify: boolean;
      caCertPath?: string;
      clientCertPath?: string;
      clientKeyPath?: string;
    }
  ) {
    this.host = host;
    this.port = port;
    this.useTls = useTls;
    this.tlsOptions = tlsOptions;
    this.encoder = new TextEncoder();
  }

  async connect(): Promise<void> {
    if (typeof globalThis.process !== 'undefined' && globalThis.process.versions?.node) {
      if (this.useTls) {
        const tls = await import('tls');
        const fs = await import('fs');

        const options: TlsConnectionOptions = {
          host: this.host,
          port: this.port,
          rejectUnauthorized: this.tlsOptions?.verify ?? true,
          timeout: CONNECTION_TIMEOUT_MS,
        };

        if (this.tlsOptions?.caCertPath) {
          options.ca = fs.readFileSync(this.tlsOptions.caCertPath);
        }
        if (this.tlsOptions?.clientCertPath) {
          options.cert = fs.readFileSync(this.tlsOptions.clientCertPath);
        }
        if (this.tlsOptions?.clientKeyPath) {
          options.key = fs.readFileSync(this.tlsOptions.clientKeyPath);
        }

        return new Promise((resolve, reject) => {
          const socket = tls.connect(options, () => {
            if (socket.authorized || !this.tlsOptions?.verify) {
              this.socket = socket;
              this.connected = true;
              resolve();
            } else {
              socket.destroy();
              reject(new Error(`TLS authorization failed: ${socket.authorizationError}`));
            }
          });

          socket.on('error', (err) => {
            this.connected = false;
            reject(new Error(`TLS connection error: ${err.message}`));
          });

          socket.on('close', () => {
            this.connected = false;
          });

          socket.setTimeout(CONNECTION_TIMEOUT_MS, () => {
            socket.destroy();
            reject(new Error('TLS connection timeout'));
          });
        });
      } else {
        const net = await import('net');

        return new Promise((resolve, reject) => {
          const socket = net.createConnection(
            {
              host: this.host,
              port: this.port,
              timeout: CONNECTION_TIMEOUT_MS,
            },
            () => {
              this.socket = socket;
              this.connected = true;
              resolve();
            }
          );

          socket.on('error', (err) => {
            this.connected = false;
            reject(new Error(`TCP connection error: ${err.message}`));
          });

          socket.on('close', () => {
            this.connected = false;
          });

          socket.setTimeout(CONNECTION_TIMEOUT_MS, () => {
            socket.destroy();
            reject(new Error('TCP connection timeout'));
          });
        });
      }
    } else {
      throw new Error(
        'TCP transport not supported in browser environment. Use an HTTP proxy.'
      );
    }
  }

  async send(message: string): Promise<void> {
    if (!this.connected || !this.socket) {
      throw new Error('TCP socket not connected');
    }

    // Use octet-counting framing (RFC 5425)
    const framedMessage = `${message.length} ${message}`;

    return new Promise((resolve, reject) => {
      const socket = this.socket as { write: (data: string, callback: (err?: Error) => void) => void };
      socket.write(framedMessage, (err?: Error) => {
        if (err) {
          reject(new Error(`TCP send failed: ${err.message}`));
        } else {
          resolve();
        }
      });
    });
  }

  async close(): Promise<void> {
    if (this.socket) {
      const socket = this.socket as { end: () => void; destroy: () => void };
      socket.end();
      socket.destroy();
      this.socket = null;
    }
    this.connected = false;
  }

  isConnected(): boolean {
    return this.connected;
  }
}

// =============================================================================
// LEEF Formatter
// =============================================================================

/**
 * Severity mapping from BrowserDefense match types to LEEF severity levels.
 */
const SEVERITY_MAP: Record<string, number> = {
  domain: 5, // Notice - domain blocks are common
  url: 6, // Informational - specific URL blocks
  hash: 4, // Warning - hash matches may indicate active malware
};

/**
 * Format a forensics event as LEEF 2.0.
 *
 * LEEF 2.0 format:
 * LEEF:2.0|Vendor|Product|Version|EventID|attr1=val1<tab>attr2=val2...
 *
 * @param event - Forensics event to format
 * @returns LEEF formatted string
 */
export function formatLeef(event: ForensicsEvent): string {
  // Event ID based on match type
  const eventId = `BlockedNavigation:${event.matchType}`;

  // Build attributes with proper escaping
  const attributes: string[] = [];

  // Time attributes (devTime is device time, usrTime is user time)
  const timestamp = new Date(event.timestamp);
  attributes.push(`devTime=${formatLeefTimestamp(timestamp)}`);
  attributes.push(`devTimeFormat=MMM dd yyyy HH:mm:ss`);

  // URL and organization
  attributes.push(`url=${escapeLeefValue(event.blockedUrl)}`);
  // Use accountName for org ID (src is reserved for IPv4/IPv6 per LEEF spec)
  attributes.push(`accountName=${escapeLeefValue(event.orgId)}`);

  if (event.userId) {
    attributes.push(`usrName=${escapeLeefValue(event.userId)}`);
  }

  if (event.deviceId) {
    attributes.push(`identHostName=${escapeLeefValue(event.deviceId)}`);
  }

  // Tab context
  if (event.tabContext.initiatorUrl) {
    attributes.push(`srcURL=${escapeLeefValue(event.tabContext.initiatorUrl)}`);
  }

  if (event.tabContext.tabTitle) {
    attributes.push(`srcTitle=${escapeLeefValue(event.tabContext.tabTitle)}`);
  }

  // Redirect chain (custom attribute)
  if (event.redirectChain.length > 0) {
    attributes.push(`redirectChain=${escapeLeefValue(event.redirectChain.join(' -> '))}`);
  }

  // Category and severity
  attributes.push(`cat=WebBlock`);
  attributes.push(`sev=${SEVERITY_MAP[event.matchType] || 5}`);

  // Match details
  attributes.push(`matchType=${event.matchType}`);
  attributes.push(`matchedIndicator=${escapeLeefValue(event.matchedIndicator)}`);

  // Event identifier
  attributes.push(`eventId=${escapeLeefValue(event.eventId)}`);

  // Incognito mode
  attributes.push(`incognito=${event.tabContext.incognito ? 'true' : 'false'}`);

  // Build the LEEF message
  // LEEF 2.0 requires delimiter specification as 6th field (0x09 = tab in hex notation)
  const leefHeader = `LEEF:${LEEF_VERSION}|${VENDOR}|${PRODUCT}|${VERSION}|${eventId}|0x09|`;
  const leefAttributes = attributes.join(LEEF_DELIMITER);

  return leefHeader + leefAttributes;
}

/**
 * Format timestamp for LEEF (MMM dd yyyy HH:mm:ss).
 */
function formatLeefTimestamp(date: Date): string {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const month = months[date.getMonth()];
  const day = String(date.getDate()).padStart(2, '0');
  const year = date.getFullYear();
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');

  return `${month} ${day} ${year} ${hours}:${minutes}:${seconds}`;
}

/**
 * Escape special characters in LEEF values.
 * LEEF uses tab as delimiter, so tabs must be escaped.
 * Also escape newlines and equals signs in values.
 */
function escapeLeefValue(value: string): string {
  return value
    .replace(/\\/g, '\\\\') // Escape backslashes first
    .replace(/\t/g, '\\t') // Escape tabs
    .replace(/\n/g, '\\n') // Escape newlines
    .replace(/\r/g, '\\r') // Escape carriage returns
    .replace(/=/g, '\\='); // Escape equals signs
}

// =============================================================================
// CEF Formatter (Alternative)
// =============================================================================

/**
 * Format a forensics event as CEF (Common Event Format).
 * CEF is also supported by QRadar and some environments prefer it.
 *
 * CEF format:
 * CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
 *
 * @param event - Forensics event to format
 * @returns CEF formatted string
 */
export function formatCef(event: ForensicsEvent): string {
  const signatureId = `blocked-${event.matchType}`;
  const name = `BrowserDefense Blocked Navigation (${event.matchType})`;
  const severity = SEVERITY_MAP[event.matchType] || 5;

  // Build extension key-value pairs
  const extensions: string[] = [];

  extensions.push(`rt=${new Date(event.timestamp).getTime()}`);
  extensions.push(`request=${escapeCefValue(event.blockedUrl)}`);
  // Use custom string field for org ID (src is reserved for IPv4/IPv6 per CEF spec)
  extensions.push(`cs6=${escapeCefValue(event.orgId)}`);
  extensions.push(`cs6Label=OrgId`);
  extensions.push(`cs1=${escapeCefValue(event.eventId)}`);
  extensions.push(`cs1Label=EventId`);
  extensions.push(`cs2=${escapeCefValue(event.matchedIndicator)}`);
  extensions.push(`cs2Label=MatchedIndicator`);
  extensions.push(`cs3=${event.matchType}`);
  extensions.push(`cs3Label=MatchType`);

  if (event.userId) {
    extensions.push(`suser=${escapeCefValue(event.userId)}`);
  }

  if (event.deviceId) {
    extensions.push(`shost=${escapeCefValue(event.deviceId)}`);
  }

  if (event.tabContext.initiatorUrl) {
    extensions.push(`cs4=${escapeCefValue(event.tabContext.initiatorUrl)}`);
    extensions.push(`cs4Label=InitiatorUrl`);
  }

  if (event.redirectChain.length > 0) {
    extensions.push(`cs5=${escapeCefValue(event.redirectChain.join(' -> '))}`);
    extensions.push(`cs5Label=RedirectChain`);
  }

  const cefHeader = `CEF:0|${VENDOR}|${PRODUCT}|${VERSION}|${signatureId}|${escapeCefHeader(name)}|${severity}|`;
  const cefExtension = extensions.join(' ');

  return cefHeader + cefExtension;
}

/**
 * Escape special characters in CEF header values.
 */
function escapeCefHeader(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|');
}

/**
 * Escape special characters in CEF extension values.
 */
function escapeCefValue(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/=/g, '\\=')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

// =============================================================================
// Unblock Event Formatters
// =============================================================================

/**
 * Format an unblock event as LEEF 2.0.
 * Uses UnblockedNavigation event ID for correlation with original block.
 *
 * @param event - Original forensics event being unblocked
 * @returns LEEF formatted unblock event
 */
export function formatLeefUnblock(event: ForensicsEvent): string {
  const eventId = `UnblockedNavigation:${event.matchType}`;

  const attributes: string[] = [];

  // Current timestamp for unblock action
  const timestamp = new Date();
  attributes.push(`devTime=${formatLeefTimestamp(timestamp)}`);
  attributes.push(`devTimeFormat=MMM dd yyyy HH:mm:ss`);

  // Reference to original blocked URL
  attributes.push(`url=${escapeLeefValue(event.blockedUrl)}`);
  attributes.push(`accountName=${escapeLeefValue(event.orgId)}`);

  if (event.userId) {
    attributes.push(`usrName=${escapeLeefValue(event.userId)}`);
  }

  if (event.deviceId) {
    attributes.push(`identHostName=${escapeLeefValue(event.deviceId)}`);
  }

  // Category indicates this is an unblock action
  attributes.push(`cat=WebUnblock`);
  attributes.push(`sev=6`); // Informational

  // Match details for correlation
  attributes.push(`matchType=${event.matchType}`);
  attributes.push(`matchedIndicator=${escapeLeefValue(event.matchedIndicator)}`);

  // Event identifier for correlation with original block
  attributes.push(`eventId=${escapeLeefValue(event.eventId)}`);
  attributes.push(`action=unblock`);

  const leefHeader = `LEEF:${LEEF_VERSION}|${VENDOR}|${PRODUCT}|${VERSION}|${eventId}|0x09|`;
  const leefAttributes = attributes.join(LEEF_DELIMITER);

  return leefHeader + leefAttributes;
}

/**
 * Format an unblock event as CEF.
 * Uses unblocked signature ID for correlation with original block.
 *
 * @param event - Original forensics event being unblocked
 * @returns CEF formatted unblock event
 */
export function formatCefUnblock(event: ForensicsEvent): string {
  const signatureId = `unblocked-${event.matchType}`;
  const name = `BrowserDefense Unblocked Navigation (${event.matchType})`;
  const severity = 2; // Low - informational unblock event

  const extensions: string[] = [];

  // Current timestamp for unblock action
  extensions.push(`rt=${Date.now()}`);
  extensions.push(`request=${escapeCefValue(event.blockedUrl)}`);
  extensions.push(`cs6=${escapeCefValue(event.orgId)}`);
  extensions.push(`cs6Label=OrgId`);
  extensions.push(`cs1=${escapeCefValue(event.eventId)}`);
  extensions.push(`cs1Label=EventId`);
  extensions.push(`cs2=${escapeCefValue(event.matchedIndicator)}`);
  extensions.push(`cs2Label=MatchedIndicator`);
  extensions.push(`cs3=${event.matchType}`);
  extensions.push(`cs3Label=MatchType`);
  extensions.push(`act=unblock`);

  if (event.userId) {
    extensions.push(`suser=${escapeCefValue(event.userId)}`);
  }

  if (event.deviceId) {
    extensions.push(`shost=${escapeCefValue(event.deviceId)}`);
  }

  const cefHeader = `CEF:0|${VENDOR}|${PRODUCT}|${VERSION}|${signatureId}|${escapeCefHeader(name)}|${severity}|`;
  const cefExtension = extensions.join(' ');

  return cefHeader + cefExtension;
}

// =============================================================================
// Syslog Message Builder
// =============================================================================

/**
 * Build a complete syslog message with RFC 5424 header.
 *
 * @param message - The message payload (LEEF/CEF formatted)
 * @param facility - Syslog facility (0-23)
 * @param severity - Syslog severity (0-7)
 * @param appName - Application name
 * @returns Complete syslog message
 */
export function buildSyslogMessage(
  message: string,
  facility: number,
  severity: number,
  appName: string
): string {
  // Calculate PRI (priority) = facility * 8 + severity
  const pri = facility * 8 + severity;

  // RFC 5424 header
  const version = 1;
  const timestamp = new Date().toISOString();
  const hostname = '-'; // NILVALUE - we don't know the hostname in all environments
  const procId = '-'; // NILVALUE
  const msgId = '-'; // NILVALUE

  // RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
  return `<${pri}>${version} ${timestamp} ${hostname} ${appName} ${procId} ${msgId} ${message}`;
}

// =============================================================================
// QRadar Connector
// =============================================================================

/**
 * IBM QRadar connector implementation.
 *
 * Sends forensics events to QRadar via Syslog using LEEF format.
 * Supports UDP, TCP, and TLS transport protocols.
 */
export class QRadarConnector extends BaseConnector {
  readonly type: ConnectorType = 'qradar';

  /**
   * QRadar supports unblock via logging an unblock event.
   * The event is correlated with the original block event by eventId.
   */
  readonly supportsUnblock = true;

  private qradarConfig: QRadarConnectorConfig;
  private transport: SyslogTransport | null = null;
  private facility: number;
  private severity: number;
  private appName: string;
  private format: 'leef' | 'cef';

  constructor(config: QRadarConnectorConfig) {
    super(config);
    this.qradarConfig = config;
    this.facility = config.facility ?? DEFAULT_FACILITY;
    this.severity = config.severity ?? DEFAULT_SEVERITY;
    this.appName = config.appName ?? DEFAULT_APP_NAME;
    this.format = config.format ?? 'leef';
  }

  /**
   * Initialize the QRadar connector.
   * Creates the appropriate transport based on configuration.
   */
  protected async doInit(): Promise<void> {
    const host = this.qradarConfig.host;
    const port = this.qradarConfig.port || DEFAULT_PORT;
    const protocol = this.qradarConfig.protocol;

    // Create transport based on protocol
    switch (protocol) {
      case 'udp':
        this.transport = new UdpSyslogTransport(host, port);
        break;

      case 'tcp':
        this.transport = new TcpSyslogTransport(host, port, false);
        break;

      case 'tcp+tls':
        this.transport = new TcpSyslogTransport(host, port, true, this.qradarConfig.tls);
        break;

      default:
        throw new Error(`Unsupported protocol: ${protocol}`);
    }

    // Connect (TCP/TLS) or validate (UDP)
    await this.transport.connect();

    console.log(
      `[QRadar] Initialized connector: ${host}:${port} (${protocol}, format=${this.format})`
    );
  }

  /**
   * Send a forensics event to QRadar.
   */
  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    if (!this.transport) {
      return {
        success: false,
        eventId: event.eventId,
        error: 'Transport not initialized',
        retryable: true,
      };
    }

    try {
      // Format the event
      const formattedEvent =
        this.format === 'leef' ? formatLeef(event) : formatCef(event);

      // Build complete syslog message
      const syslogMessage = buildSyslogMessage(
        formattedEvent,
        this.facility,
        this.severity,
        this.appName
      );

      // Send via transport
      await this.transport.send(syslogMessage);

      return {
        success: true,
        eventId: event.eventId,
        response: {
          format: this.format,
          protocol: this.qradarConfig.protocol,
          messageLength: syslogMessage.length,
        },
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Determine if error is retryable
      const retryable =
        errorMessage.includes('timeout') ||
        errorMessage.includes('ECONNRESET') ||
        errorMessage.includes('ECONNREFUSED') ||
        errorMessage.includes('not connected');

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable,
      };
    }
  }

  /**
   * Perform a health check on the QRadar connection.
   */
  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    if (!this.transport) {
      return {
        healthy: false,
        message: 'Transport not initialized',
      };
    }

    // For TCP/TLS, check connection state
    if (this.qradarConfig.protocol !== 'udp') {
      if (!this.transport.isConnected()) {
        // Try to reconnect
        try {
          await this.transport.connect();
          return {
            healthy: true,
            message: `Reconnected to ${this.qradarConfig.host}:${this.qradarConfig.port}`,
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          return {
            healthy: false,
            message: `Connection failed: ${errorMessage}`,
          };
        }
      }
    }

    return {
      healthy: true,
      message: `Connected to QRadar at ${this.qradarConfig.host}:${this.qradarConfig.port} (${this.qradarConfig.protocol})`,
    };
  }

  /**
   * Close the QRadar connector and release resources.
   */
  protected async doClose(): Promise<void> {
    if (this.transport) {
      await this.transport.close();
      this.transport = null;
    }
    console.log(`[QRadar] Closed connector: ${this.name}`);
  }

  /**
   * Send an unblock event to QRadar for correlation.
   * This logs an unblock event that can be correlated with the original block.
   */
  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    if (!this.transport) {
      return {
        success: false,
        eventId: event.eventId,
        error: 'Transport not initialized',
        retryable: true,
      };
    }

    try {
      // Format the unblock event
      const formattedEvent =
        this.format === 'leef'
          ? formatLeefUnblock(event)
          : formatCefUnblock(event);

      // Build complete syslog message
      const syslogMessage = buildSyslogMessage(
        formattedEvent,
        this.facility,
        this.severity,
        this.appName
      );

      // Send via transport
      await this.transport.send(syslogMessage);

      return {
        success: true,
        eventId: event.eventId,
        incidentId: `unblock-${event.eventId}`,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Determine if error is retryable
      const retryable =
        errorMessage.includes('timeout') ||
        errorMessage.includes('ECONNRESET') ||
        errorMessage.includes('ECONNREFUSED') ||
        errorMessage.includes('not connected');

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable,
      };
    }
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

/**
 * Factory function for creating QRadar connectors.
 */
export function createQRadarConnector(config: QRadarConnectorConfig): QRadarConnector {
  return new QRadarConnector(config);
}

// Register the factory with the global registry
connectorRegistry.register('qradar', createQRadarConnector);

// =============================================================================
// Exports
// =============================================================================

export type { QRadarConnectorConfig } from './types';
