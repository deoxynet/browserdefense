/**
 * EDR Enrichment Export Types
 *
 * Types for exporting BrowserDefense forensic artifacts to EDR systems.
 * This is READ-ONLY enrichment data for attaching to EDR alerts.
 * NO control actions are performed - enrichment only.
 *
 * Use cases:
 * - Attach phishing/malware context to EDR browser process alerts
 * - Correlate browser block events with endpoint detections
 * - Provide URL/redirect chain for threat hunting
 *
 * Reference: Issue #169
 */

import type { FormSchema } from '../content/form-schema';
import type { TLSMetadata } from './tls-metadata';

// ============ Core Types ============

/**
 * Process context for browser-to-executable correlation.
 * Helps EDR agents correlate browser events with process tree.
 *
 * NOTE: Browser extensions cannot directly access OS process info.
 * This provides correlation hints for server-side matching.
 */
export interface BrowserProcessContext {
  /** Timestamp when event occurred (high precision for correlation) */
  eventTimestamp: string;
  /** Unix timestamp in milliseconds for precise matching */
  eventTimestampMs: number;
  /** User agent string (contains browser version, OS info) */
  userAgent: string;
  /** Browser name extracted from user agent */
  browserName: 'chrome' | 'edge' | 'chromium' | 'unknown';
  /** Browser version */
  browserVersion?: string;
  /** Operating system from user agent */
  platform: 'windows' | 'macos' | 'linux' | 'unknown';
  /** Chrome tab ID (for multi-tab correlation) */
  tabId: number;
  /** Chrome window ID */
  windowId?: number;
  /** Whether tab was in incognito mode */
  incognito: boolean;
  /** Tab title at time of event (may help identify context) */
  tabTitle?: string;
  /**
   * Correlation hints for EDR matching.
   * EDR should look for browser process with:
   * - Matching timestamp (±2 seconds)
   * - Network connection to blocked URL/IP
   * - Matching user session
   */
  correlationHints: {
    /** Hostname of blocked URL (for network connection matching) */
    targetHostname: string;
    /** Port of blocked URL */
    targetPort: number;
    /** IP addresses if resolved (for connection matching) */
    targetIPs?: string[];
    /** Time window for correlation (ms before/after event) */
    correlationWindowMs: number;
  };
}

/**
 * DOM fingerprint artifact for EDR enrichment.
 * Identifies phishing kit variants and attack patterns.
 */
export interface DOMFingerprintArtifact {
  /** SHA-256 hash of DOM skeleton */
  domHash: string;
  /** Known phishing kit ID (if recognized by threat intel) */
  kitId?: string;
  /** Kit family/variant name (e.g., "Office365-Kit-v2") */
  kitName?: string;
  /** Confidence score (0-100) from threat intel */
  confidence?: number;
  /** Whether this is a novel/first-seen fingerprint */
  isNovel?: boolean;
  /** Global occurrence count (how many orgs have seen this) */
  globalOccurrences?: number;
  /** Tags from threat intel (e.g., ["credential-harvester", "o365-themed"]) */
  tags?: string[];
}

/**
 * Screenshot artifact reference for EDR enrichment.
 * Contains metadata only - actual image stored separately.
 *
 * NOTE: Screenshot shows BLOCK PAGE, not malicious content.
 * Watermarked for audit trail.
 */
export interface ScreenshotArtifact {
  /** Whether screenshot was captured */
  captured: boolean;
  /** SHA-256 hash of screenshot image (for integrity/dedup) */
  imageHash?: string;
  /** Image dimensions */
  dimensions?: {
    width: number;
    height: number;
  };
  /** Capture timestamp */
  capturedAt?: string;
  /** Reference ID for retrieving encrypted screenshot */
  screenshotId?: string;
  /** Reason if not captured (e.g., "disabled", "failed", "not-configured") */
  notCapturedReason?: string;
}

/**
 * Form schema artifact for credential harvesting detection.
 * Structure only - NO user input values.
 */
export interface FormSchemaArtifact {
  /** Number of forms on the page */
  formCount: number;
  /** Whether any form appears to be a login form */
  hasLoginForm: boolean;
  /** Whether any form appears to be a payment form */
  hasPaymentForm: boolean;
  /** Types of input fields present (e.g., ["email", "password", "text"]) */
  inputTypes: string[];
  /** Form action URLs (submission targets) */
  actionUrls: string[];
  /** Full form schemas (structure only) */
  schemas?: FormSchema[];
}

/**
 * URL and redirect chain artifact.
 * Shows the full navigation path to the blocked URL.
 */
export interface URLArtifact {
  /** The blocked URL */
  blockedUrl: string;
  /** Normalized/canonicalized URL that matched the IOC */
  normalizedUrl: string;
  /** Full redirect chain leading to blocked URL */
  redirectChain?: string[];
  /** Number of redirects in chain */
  redirectCount: number;
  /** Initial URL that started the redirect chain */
  initialUrl?: string;
  /** Navigation trigger type */
  initiator?: 'link' | 'typed' | 'bookmark' | 'redirect' | 'script' | 'unknown';
  /** URL of the page that initiated the navigation */
  sourceUrl?: string;
}

/**
 * IOC match details for EDR enrichment.
 */
export interface IOCMatchArtifact {
  /** Type of IOC that matched */
  matchType: 'domain' | 'url' | 'hash' | 'ip';
  /** The specific IOC pattern that matched */
  matchedIndicator: string;
  /** IOC source/feed name */
  source?: string;
  /** IOC severity/priority */
  priority?: 'critical' | 'high' | 'medium' | 'low';
  /** IOC categories/tags */
  categories?: string[];
  /** When the IOC was added to blocklist */
  iocAddedAt?: string;
  /** IOC expiration (if applicable) */
  iocExpiresAt?: string;
}

/**
 * Complete EDR Enrichment Artifact bundle.
 * Contains all forensic data for attaching to EDR alerts.
 */
export interface EDREnrichmentArtifact {
  /** Unique artifact bundle ID */
  artifactId: string;
  /** Schema version for forward compatibility */
  schemaVersion: '1.0';
  /** Artifact type identifier */
  artifactType: 'browserdefense-enrichment';

  /** When this artifact bundle was created */
  createdAt: string;
  /** Organization ID */
  orgId: string;

  /** Block event details */
  blockEvent: {
    /** Block timestamp */
    timestamp: string;
    /** Block reason */
    reason: string;
    /** Unique event ID */
    eventId: string;
  };

  /** Process context for browser→exe correlation */
  processContext: BrowserProcessContext;

  /** URL and redirect chain */
  url: URLArtifact;

  /** IOC match details */
  iocMatch: IOCMatchArtifact;

  /** DOM fingerprint (phishing kit detection) */
  domFingerprint?: DOMFingerprintArtifact;

  /** Screenshot artifact (reference only) */
  screenshot?: ScreenshotArtifact;

  /** Form schemas (credential harvesting detection) */
  formSchemas?: FormSchemaArtifact;

  /** TLS/certificate metadata */
  tlsMetadata?: TLSMetadata;

  /** Enterprise context (populated server-side) */
  enterpriseContext?: {
    /** User identity from directory */
    userId?: string;
    /** User email */
    userEmail?: string;
    /** Device ID from MDM */
    deviceId?: string;
    /** Device hostname */
    deviceHostname?: string;
    /** Organizational unit */
    orgUnit?: string;
  };

  /** Raw data for custom processing */
  raw?: Record<string, unknown>;
}

// ============ Export Configuration ============

/**
 * EDR enrichment export configuration.
 */
export interface EDREnrichmentConfig {
  /** Whether EDR enrichment export is enabled */
  enabled: boolean;
  /** Include DOM fingerprint in export */
  includeDOMFingerprint: boolean;
  /** Include screenshot reference in export */
  includeScreenshot: boolean;
  /** Include form schemas in export */
  includeFormSchemas: boolean;
  /** Include TLS metadata in export */
  includeTLSMetadata: boolean;
  /** Include full redirect chain (may be long) */
  includeRedirectChain: boolean;
  /** Maximum redirect chain length to include */
  maxRedirectChainLength: number;
  /** Correlation window for process matching (ms) */
  correlationWindowMs: number;
}

/**
 * Default EDR enrichment configuration.
 */
export const DEFAULT_EDR_ENRICHMENT_CONFIG: EDREnrichmentConfig = {
  enabled: true,
  includeDOMFingerprint: true,
  includeScreenshot: true,
  includeFormSchemas: true,
  includeTLSMetadata: true,
  includeRedirectChain: true,
  maxRedirectChainLength: 10,
  correlationWindowMs: 2000, // ±2 seconds for process matching
};

// ============ Export Formats ============

/**
 * EDR export format options.
 * Different EDRs prefer different formats.
 */
export type EDRExportFormat = 'json' | 'stix' | 'cef' | 'leef';

/**
 * STIX 2.1 Observable for EDR integration.
 * Minimal STIX representation for URL observables.
 */
export interface STIXObservable {
  type: 'observed-data';
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  first_observed: string;
  last_observed: string;
  number_observed: number;
  object_refs: string[];
  objects: Record<string, STIXObject>;
}

export interface STIXObject {
  type: 'url' | 'domain-name' | 'x509-certificate' | 'x-browserdefense-enrichment';
  id?: string;
  value?: string;
  [key: string]: unknown;
}

// ============ Helper Functions ============

/**
 * Parse user agent to extract browser and platform info.
 */
export function parseUserAgent(userAgent: string): {
  browserName: BrowserProcessContext['browserName'];
  browserVersion?: string;
  platform: BrowserProcessContext['platform'];
} {
  const ua = userAgent.toLowerCase();

  // Detect browser
  let browserName: BrowserProcessContext['browserName'] = 'unknown';
  let browserVersion: string | undefined;

  if (ua.includes('edg/')) {
    browserName = 'edge';
    const match = userAgent.match(/Edg\/(\d+\.\d+)/);
    browserVersion = match?.[1];
  } else if (ua.includes('chrome/')) {
    browserName = 'chrome';
    const match = userAgent.match(/Chrome\/(\d+\.\d+)/);
    browserVersion = match?.[1];
  } else if (ua.includes('chromium/')) {
    browserName = 'chromium';
    const match = userAgent.match(/Chromium\/(\d+\.\d+)/);
    browserVersion = match?.[1];
  }

  // Detect platform
  let platform: BrowserProcessContext['platform'] = 'unknown';

  if (ua.includes('windows')) {
    platform = 'windows';
  } else if (ua.includes('mac os x') || ua.includes('macos')) {
    platform = 'macos';
  } else if (ua.includes('linux')) {
    platform = 'linux';
  }

  return { browserName, browserVersion, platform };
}

/**
 * Extract hostname and port from URL.
 */
export function extractHostnamePort(url: string): { hostname: string; port: number } {
  try {
    const parsed = new URL(url);
    const port = parsed.port
      ? parseInt(parsed.port, 10)
      : parsed.protocol === 'https:'
        ? 443
        : 80;
    return { hostname: parsed.hostname, port };
  } catch {
    return { hostname: '', port: 0 };
  }
}

/**
 * Generate a unique artifact ID.
 */
export function generateArtifactId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `bioc-${timestamp}-${random}`;
}
