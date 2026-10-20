/**
 * EDR Enrichment Export Module
 *
 * Creates forensic artifact bundles for EDR enrichment.
 * This is READ-ONLY - no control actions, enrichment only.
 *
 * Exports:
 * - DOM hash/fingerprint (phishing kit detection)
 * - Screenshot reference (not the actual image)
 * - Form schemas (credential harvesting detection)
 * - TLS/certificate metadata
 * - Redirect chain (full navigation path)
 * - Process context (browser→exe correlation hints)
 *
 * Use case: Attach context to EDR alerts about suspicious browser processes.
 *
 * Reference: Issue #169
 */

import type { ForensicsPayload } from './forensics';
import type { FingerprintResponse } from './fingerprint-uplink';
import {
  DEFAULT_EDR_ENRICHMENT_CONFIG,
  parseUserAgent,
  extractHostnamePort,
  generateArtifactId,
  type EDREnrichmentArtifact,
  type EDREnrichmentConfig,
  type BrowserProcessContext,
  type URLArtifact,
  type IOCMatchArtifact,
  type DOMFingerprintArtifact,
  type ScreenshotArtifact,
  type FormSchemaArtifact,
  type EDRExportFormat,
  type STIXObservable,
  type STIXObject,
} from '../types/edr-enrichment';

// Re-export config type for consumers
export type { EDREnrichmentConfig } from '../types/edr-enrichment';

// ============ Constants ============

const STORAGE_KEY = 'browserdefense_edr_enrichment_config';
const _ARTIFACT_CACHE_KEY = 'browserdefense_edr_artifacts';
const MAX_CACHED_ARTIFACTS = 100;
const SCHEMA_VERSION = '1.0' as const;

// ============ In-Memory Storage ============

/** Recent artifacts for retrieval */
const recentArtifacts = new Map<string, EDREnrichmentArtifact>();

/** DOM fingerprint data by tab (populated from fingerprint uplink) */
const fingerprintByTab = new Map<
  number,
  {
    hash: string;
    response?: FingerprintResponse;
    capturedAt: number;
  }
>();

// ============ Configuration ============

/**
 * Get EDR enrichment configuration from storage.
 */
export async function getEDREnrichmentConfig(): Promise<EDREnrichmentConfig> {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  const stored = result[STORAGE_KEY] as Partial<EDREnrichmentConfig> | undefined;

  return {
    ...DEFAULT_EDR_ENRICHMENT_CONFIG,
    ...stored,
  };
}

/**
 * Update EDR enrichment configuration.
 */
export async function updateEDREnrichmentConfig(
  config: Partial<EDREnrichmentConfig>
): Promise<EDREnrichmentConfig> {
  const current = await getEDREnrichmentConfig();
  const updated = { ...current, ...config };

  await chrome.storage.local.set({ [STORAGE_KEY]: updated });
  console.log('[BrowserDefense] EDR enrichment config updated:', updated);

  return updated;
}

// ============ Fingerprint Storage ============

/**
 * Store DOM fingerprint for a tab.
 * Called from fingerprint uplink after server response.
 */
export function storeFingerprintForTab(
  tabId: number,
  hash: string,
  response?: FingerprintResponse
): void {
  fingerprintByTab.set(tabId, {
    hash,
    response,
    capturedAt: Date.now(),
  });
}

/**
 * Get and remove fingerprint for a tab.
 */
export function consumeFingerprintForTab(
  tabId: number
): { hash: string; response?: FingerprintResponse } | null {
  const data = fingerprintByTab.get(tabId);
  fingerprintByTab.delete(tabId);
  return data ?? null;
}

/**
 * Clear fingerprint for a tab.
 */
export function clearFingerprintForTab(tabId: number): void {
  fingerprintByTab.delete(tabId);
}

// ============ Artifact Creation ============

/**
 * Create an EDR enrichment artifact from forensics data.
 * This bundles all available forensic artifacts into a single export.
 *
 * @param forensics - Base forensics payload from block event
 * @param options - Additional data sources
 * @returns Complete EDR enrichment artifact
 */
export async function createEDREnrichmentArtifact(
  forensics: ForensicsPayload,
  options: {
    orgId: string;
    eventId?: string;
    fingerprint?: { hash: string; response?: FingerprintResponse };
    screenshotHash?: string;
    screenshotDimensions?: { width: number; height: number };
    screenshotId?: string;
    matchType?: 'domain' | 'url' | 'hash' | 'ip';
    matchedIndicator?: string;
    iocSource?: string;
    iocPriority?: 'critical' | 'high' | 'medium' | 'low';
  }
): Promise<EDREnrichmentArtifact> {
  const config = await getEDREnrichmentConfig();
  const artifactId = generateArtifactId();
  const eventId = options.eventId ?? artifactId;

  // Build process context
  const userAgent = navigator.userAgent;
  const { browserName, browserVersion, platform } = parseUserAgent(userAgent);
  const { hostname: targetHostname, port: targetPort } = extractHostnamePort(
    forensics.blockedUrl
  );

  const processContext: BrowserProcessContext = {
    eventTimestamp: forensics.timestamp,
    eventTimestampMs: new Date(forensics.timestamp).getTime(),
    userAgent,
    browserName,
    browserVersion,
    platform,
    tabId: forensics.tabId,
    windowId: undefined, // Not available in ForensicsPayload
    incognito: false, // Would need tab query to determine
    tabTitle: undefined, // Would need tab query
    correlationHints: {
      targetHostname,
      targetPort,
      correlationWindowMs: config.correlationWindowMs,
    },
  };

  // Build URL artifact
  const redirectChain = config.includeRedirectChain
    ? forensics.redirectChain?.slice(0, config.maxRedirectChainLength)
    : undefined;

  const urlArtifact: URLArtifact = {
    blockedUrl: forensics.blockedUrl,
    normalizedUrl: forensics.normalizedUrl ?? forensics.blockedUrl,
    redirectChain,
    redirectCount: forensics.redirectChain?.length ?? 0,
    initialUrl: forensics.redirectChain?.[0],
    initiator: mapInitiator(forensics.initiator),
    sourceUrl: forensics.initiator,
  };

  // Build IOC match artifact
  const iocMatch: IOCMatchArtifact = {
    matchType: options.matchType ?? 'url',
    matchedIndicator: options.matchedIndicator ?? forensics.normalizedUrl ?? '',
    source: options.iocSource,
    priority: options.iocPriority,
  };

  // Build DOM fingerprint artifact
  let domFingerprint: DOMFingerprintArtifact | undefined;
  if (config.includeDOMFingerprint && options.fingerprint) {
    domFingerprint = {
      domHash: options.fingerprint.hash,
      kitId: options.fingerprint.response?.kitId,
      confidence: options.fingerprint.response?.confidence,
      isNovel: options.fingerprint.response?.isNovel,
      globalOccurrences: options.fingerprint.response?.occurrenceCount,
    };
  }

  // Build screenshot artifact
  let screenshot: ScreenshotArtifact | undefined;
  if (config.includeScreenshot) {
    if (options.screenshotHash) {
      screenshot = {
        captured: true,
        imageHash: options.screenshotHash,
        dimensions: options.screenshotDimensions,
        screenshotId: options.screenshotId,
      };
    } else {
      screenshot = {
        captured: false,
        notCapturedReason: forensics.screenshot ? 'reference-only' : 'not-configured',
      };
    }
  }

  // Build form schema artifact
  let formSchemas: FormSchemaArtifact | undefined;
  if (config.includeFormSchemas && forensics.formSchemas && forensics.formSchemas.length > 0) {
    const schemas = forensics.formSchemas;
    const inputTypes = new Set<string>();
    const actionUrls = new Set<string>();
    let hasLoginForm = false;
    let hasPaymentForm = false;

    for (const schema of schemas) {
      if (schema.action) actionUrls.add(schema.action);
      if (schema.isLoginForm) hasLoginForm = true;
      if (schema.isPaymentForm) hasPaymentForm = true;

      for (const field of schema.fields) {
        if (field.type) inputTypes.add(field.type);
      }
    }

    formSchemas = {
      formCount: schemas.length,
      hasLoginForm,
      hasPaymentForm,
      inputTypes: Array.from(inputTypes),
      actionUrls: Array.from(actionUrls),
      schemas,
    };
  }

  // Build complete artifact
  const artifact: EDREnrichmentArtifact = {
    artifactId,
    schemaVersion: SCHEMA_VERSION,
    artifactType: 'browserdefense-enrichment',
    createdAt: new Date().toISOString(),
    orgId: options.orgId,
    blockEvent: {
      timestamp: forensics.timestamp,
      reason: forensics.reason,
      eventId,
    },
    processContext,
    url: urlArtifact,
    iocMatch,
    domFingerprint,
    screenshot,
    formSchemas,
    tlsMetadata: config.includeTLSMetadata ? forensics.tlsMetadata : undefined,
  };

  // Cache artifact for retrieval
  cacheArtifact(artifact);

  return artifact;
}

/**
 * Map initiator string to known type.
 */
function mapInitiator(
  initiator?: string
): 'link' | 'typed' | 'bookmark' | 'redirect' | 'script' | 'unknown' {
  if (!initiator) return 'unknown';

  const lower = initiator.toLowerCase();
  if (lower.includes('typed')) return 'typed';
  if (lower.includes('bookmark')) return 'bookmark';
  if (lower.includes('redirect')) return 'redirect';
  if (lower.includes('script')) return 'script';
  if (lower.includes('link') || lower.includes('http')) return 'link';

  return 'unknown';
}

// ============ Artifact Caching ============

/**
 * Cache artifact for later retrieval.
 */
function cacheArtifact(artifact: EDREnrichmentArtifact): void {
  recentArtifacts.set(artifact.artifactId, artifact);

  // Prune if too many
  if (recentArtifacts.size > MAX_CACHED_ARTIFACTS) {
    const oldest = recentArtifacts.keys().next().value;
    if (oldest) {
      recentArtifacts.delete(oldest);
    }
  }
}

/**
 * Get a cached artifact by ID.
 */
export function getArtifact(artifactId: string): EDREnrichmentArtifact | null {
  return recentArtifacts.get(artifactId) ?? null;
}

/**
 * List recent artifacts.
 */
export function listArtifacts(
  limit: number = 20
): Array<{ id: string; timestamp: string; blockedUrl: string }> {
  const artifacts = Array.from(recentArtifacts.values());
  return artifacts
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, limit)
    .map((a) => ({
      id: a.artifactId,
      timestamp: a.createdAt,
      blockedUrl: a.url.blockedUrl,
    }));
}

/**
 * Clear all cached artifacts.
 */
export function clearArtifacts(): void {
  recentArtifacts.clear();
  fingerprintByTab.clear();
  console.log('[BrowserDefense] EDR enrichment artifacts cleared');
}

// ============ Export Formats ============

/**
 * Export artifact in specified format.
 */
export function exportArtifact(
  artifact: EDREnrichmentArtifact,
  format: EDRExportFormat
): string | object {
  switch (format) {
    case 'json':
      return artifact;

    case 'stix':
      return toSTIX(artifact);

    case 'cef':
      return toCEF(artifact);

    case 'leef':
      return toLEEF(artifact);

    default:
      return artifact;
  }
}

/**
 * Convert artifact to STIX 2.1 format.
 */
function toSTIX(artifact: EDREnrichmentArtifact): STIXObservable {
  const objects: Record<string, STIXObject> = {};

  // URL observable
  objects['url--0'] = {
    type: 'url',
    value: artifact.url.blockedUrl,
  };

  // Domain observable
  const { hostname } = extractHostnamePort(artifact.url.blockedUrl);
  if (hostname) {
    objects['domain--0'] = {
      type: 'domain-name',
      value: hostname,
    };
  }

  // Custom BrowserDefense extension
  objects['x-browserdefense--0'] = {
    type: 'x-browserdefense-enrichment',
    dom_hash: artifact.domFingerprint?.domHash,
    kit_id: artifact.domFingerprint?.kitId,
    confidence: artifact.domFingerprint?.confidence,
    has_login_form: artifact.formSchemas?.hasLoginForm,
    redirect_count: artifact.url.redirectCount,
    tls_issuer: artifact.tlsMetadata?.certificate?.issuerCN,
  };

  const stix: STIXObservable = {
    type: 'observed-data',
    spec_version: '2.1',
    id: `observed-data--${artifact.artifactId}`,
    created: artifact.createdAt,
    modified: artifact.createdAt,
    first_observed: artifact.blockEvent.timestamp,
    last_observed: artifact.blockEvent.timestamp,
    number_observed: 1,
    object_refs: Object.keys(objects),
    objects,
  };

  return stix;
}

/**
 * Convert artifact to CEF (Common Event Format).
 */
function toCEF(artifact: EDREnrichmentArtifact): string {
  const { hostname } = extractHostnamePort(artifact.url.blockedUrl);
  const severity = mapPriorityToSeverity(artifact.iocMatch.priority);

  // CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
  const header = `CEF:0|BrowserDefense|Browser|1.0|${artifact.blockEvent.eventId}|IOC Block|${severity}`;

  const extension = [
    `dvchost=${artifact.processContext.platform}`,
    `request=${artifact.url.blockedUrl}`,
    `dhost=${hostname}`,
    `rt=${new Date(artifact.blockEvent.timestamp).getTime()}`,
    `msg=${artifact.blockEvent.reason}`,
    `cs1=${artifact.domFingerprint?.domHash ?? 'N/A'}`,
    `cs1Label=DOMHash`,
    `cs2=${artifact.iocMatch.matchedIndicator}`,
    `cs2Label=MatchedIOC`,
    `cn1=${artifact.domFingerprint?.confidence ?? 0}`,
    `cn1Label=Confidence`,
    `flexString1=${artifact.domFingerprint?.kitId ?? 'unknown'}`,
    `flexString1Label=KitID`,
  ].join(' ');

  return `${header}|${extension}`;
}

/**
 * Convert artifact to LEEF (Log Event Extended Format).
 */
function toLEEF(artifact: EDREnrichmentArtifact): string {
  const { hostname } = extractHostnamePort(artifact.url.blockedUrl);

  // LEEF format: LEEF:Version|Vendor|Product|Version|EventID|
  const header = `LEEF:2.0|BrowserDefense|Browser|1.0|${artifact.blockEvent.eventId}|`;

  const attributes = [
    `devTime=${new Date(artifact.blockEvent.timestamp).toISOString()}`,
    `url=${artifact.url.blockedUrl}`,
    `dstName=${hostname}`,
    `reason=${artifact.blockEvent.reason}`,
    `domHash=${artifact.domFingerprint?.domHash ?? 'N/A'}`,
    `matchedIOC=${artifact.iocMatch.matchedIndicator}`,
    `confidence=${artifact.domFingerprint?.confidence ?? 0}`,
    `kitId=${artifact.domFingerprint?.kitId ?? 'unknown'}`,
    `hasLoginForm=${artifact.formSchemas?.hasLoginForm ?? false}`,
    `redirectCount=${artifact.url.redirectCount}`,
  ].join('\t');

  return `${header}${attributes}`;
}

/**
 * Map IOC priority to CEF severity (0-10).
 */
function mapPriorityToSeverity(priority?: string): number {
  switch (priority) {
    case 'critical':
      return 10;
    case 'high':
      return 8;
    case 'medium':
      return 5;
    case 'low':
      return 3;
    default:
      return 5;
  }
}

// ============ Cleanup ============

/**
 * Set up tab removal listener to clean up fingerprint data.
 */
export function setupEDREnrichmentCleanup(): void {
  chrome.tabs.onRemoved.addListener((tabId) => {
    clearFingerprintForTab(tabId);
  });
}

// ============ Export for Testing ============

export {
  fingerprintByTab as _fingerprintByTab,
  recentArtifacts as _recentArtifacts,
};
