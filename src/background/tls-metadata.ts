/**
 * TLS & Certificate Metadata Capture Module
 *
 * Captures TLS connection metadata and security headers for blocked pages.
 * Optionally enriches with certificate details from a server-side endpoint.
 *
 * PRIVACY GUARANTEES:
 * - Captures only public metadata (no private keys, no session data)
 * - Enrichment server receives only hostname (no URLs, no user data)
 * - Certificate details are standard public information
 *
 * ARCHITECTURE:
 * - Local capture: Security headers via webRequest.onHeadersReceived
 * - Server enrichment: Optional lookup for certificate details
 * - Storage: In-memory by tab ID (consumed on block)
 *
 * LIMITATION: Chrome extensions cannot directly access SSL certificates.
 * Certificate details (issuer, SANs, fingerprint) require server-side enrichment.
 *
 * Reference: Issue #168
 */

import type {
  TLSMetadata,
  TLSConnectionMetadata,
  CertificateMetadata,
  SecurityHeaders,
  TLSCaptureConfig,
  CertificateEnrichmentRequest,
  CertificateEnrichmentResponse,
} from '../types/tls-metadata';
import {
  DEFAULT_TLS_CAPTURE_CONFIG,
  parseHSTSHeader,
  extractHostPort,
  truncateHeader,
} from '../types/tls-metadata';

// Re-export types for convenience
export type {
  TLSMetadata,
  TLSConnectionMetadata,
  CertificateMetadata,
  SecurityHeaders,
  TLSCaptureConfig,
};
export { DEFAULT_TLS_CAPTURE_CONFIG };

// ============ Constants ============

const STORAGE_KEY = 'browserdefense_tls_capture_config';
const CACHE_KEY = 'browserdefense_tls_enrichment_cache';
const MAX_CACHE_SIZE = 1000;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Security headers to capture
const _SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-content-type-options',
  'x-frame-options',
  'x-xss-protection',
  'referrer-policy',
  'permissions-policy',
];

// ============ In-Memory Storage ============

/** TLS metadata stored by tab ID */
const tlsMetadataByTab = new Map<number, TLSMetadata>();

/** Security headers stored by tab ID */
const securityHeadersByTab = new Map<number, SecurityHeaders>();

/** Enrichment cache by hostname:port */
interface CachedEnrichment {
  response: CertificateEnrichmentResponse;
  cachedAt: number;
}
const enrichmentCache = new Map<string, CachedEnrichment>();

// ============ Configuration ============

/**
 * Get TLS capture configuration from storage.
 */
export async function getTLSCaptureConfig(): Promise<TLSCaptureConfig> {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  const stored = result[STORAGE_KEY] as Partial<TLSCaptureConfig> | undefined;

  return {
    ...DEFAULT_TLS_CAPTURE_CONFIG,
    ...stored,
  };
}

/**
 * Update TLS capture configuration.
 */
export async function updateTLSCaptureConfig(
  config: Partial<TLSCaptureConfig>
): Promise<TLSCaptureConfig> {
  const current = await getTLSCaptureConfig();
  const updated = { ...current, ...config };

  await chrome.storage.local.set({ [STORAGE_KEY]: updated });
  console.log('[BrowserDefense] TLS capture config updated:', updated);

  return updated;
}

// ============ Header Capture ============

/**
 * Initialize TLS metadata capture.
 * Sets up webRequest listener for security headers.
 */
export function initTLSCapture(): void {
  // Capture security headers from responses
  chrome.webRequest.onHeadersReceived.addListener(
    (details): chrome.webRequest.BlockingResponse | undefined => {
      // Only capture main frame responses
      if (details.type !== 'main_frame') return undefined;

      // Skip non-HTTP(S) schemes
      if (!details.url.startsWith('http://') && !details.url.startsWith('https://')) {
        return undefined;
      }

      // Extract security headers
      const headers = extractSecurityHeaders(details.responseHeaders ?? [], DEFAULT_TLS_CAPTURE_CONFIG.maxHeaderLength ?? 500);

      // Store by tab ID
      if (details.tabId >= 0) {
        securityHeadersByTab.set(details.tabId, headers);
      }

      // Build initial TLS metadata from headers
      const { hostname, port } = extractHostPort(details.url);
      const hstsData = parseHSTSHeader(headers.strictTransportSecurity ?? '');

      const connection: TLSConnectionMetadata = {
        isSecure: details.url.startsWith('https://'),
        scheme: details.url.startsWith('https://') ? 'https' : 'http',
        hasHSTS: !!headers.strictTransportSecurity,
        hstsMaxAge: hstsData.maxAge,
        hstsIncludeSubdomains: hstsData.includeSubdomains,
        hstsPreload: hstsData.preload,
      };

      const metadata: TLSMetadata = {
        hostname,
        port,
        connection,
        capturedAt: Date.now(),
        certificateSource: 'unavailable',
      };

      if (details.tabId >= 0) {
        tlsMetadataByTab.set(details.tabId, metadata);
      }

      return undefined;
    },
    {
      urls: ['http://*/*', 'https://*/*'],
      types: ['main_frame'],
    },
    ['responseHeaders']
  );

  console.log('[BrowserDefense] TLS metadata capture initialized');
}

/**
 * Extract security headers from response.
 */
function extractSecurityHeaders(
  responseHeaders: chrome.webRequest.HttpHeader[],
  maxLength: number
): SecurityHeaders {
  const headers: SecurityHeaders = {};

  for (const header of responseHeaders) {
    const name = header.name.toLowerCase();
    const value = header.value ?? '';

    switch (name) {
      case 'strict-transport-security':
        headers.strictTransportSecurity = truncateHeader(value, maxLength);
        break;
      case 'content-security-policy':
        headers.contentSecurityPolicy = truncateHeader(value, maxLength);
        break;
      case 'x-content-type-options':
        headers.xContentTypeOptions = value;
        break;
      case 'x-frame-options':
        headers.xFrameOptions = value;
        break;
      case 'x-xss-protection':
        headers.xXSSProtection = value;
        break;
      case 'referrer-policy':
        headers.referrerPolicy = value;
        break;
      case 'permissions-policy':
        headers.permissionsPolicy = truncateHeader(value, maxLength);
        break;
    }
  }

  return headers;
}

// ============ Metadata Retrieval ============

/**
 * Get TLS metadata for a tab.
 * Call this when a page is blocked to include in forensics.
 *
 * @param tabId - Chrome tab ID
 * @returns TLS metadata or null if not available
 */
export function getTLSMetadata(tabId: number): TLSMetadata | null {
  return tlsMetadataByTab.get(tabId) ?? null;
}

/**
 * Get security headers for a tab.
 *
 * @param tabId - Chrome tab ID
 * @returns Security headers or null if not available
 */
export function getSecurityHeaders(tabId: number): SecurityHeaders | null {
  return securityHeadersByTab.get(tabId) ?? null;
}

/**
 * Consume TLS metadata for a tab (get and remove).
 * Use this when capturing forensics - prevents duplicate capture.
 *
 * @param tabId - Chrome tab ID
 * @returns TLS metadata or null if not available
 */
export function consumeTLSMetadata(tabId: number): TLSMetadata | null {
  const metadata = tlsMetadataByTab.get(tabId);
  tlsMetadataByTab.delete(tabId);
  securityHeadersByTab.delete(tabId);
  return metadata ?? null;
}

/**
 * Clear TLS metadata for a tab.
 * Called when tab is closed.
 *
 * @param tabId - Chrome tab ID
 */
export function clearTLSMetadata(tabId: number): void {
  tlsMetadataByTab.delete(tabId);
  securityHeadersByTab.delete(tabId);
}

// ============ Certificate Enrichment ============

/**
 * Enrich TLS metadata with certificate details from server.
 *
 * This sends only the hostname to the enrichment server.
 * No URLs or user data are transmitted.
 *
 * @param metadata - TLS metadata to enrich
 * @param config - TLS capture config with enrichment endpoint
 * @returns Enriched metadata or original if enrichment fails
 */
export async function enrichWithCertificate(
  metadata: TLSMetadata,
  config?: TLSCaptureConfig
): Promise<TLSMetadata> {
  const cfg = config ?? await getTLSCaptureConfig();

  // Skip if no enrichment endpoint configured
  if (!cfg.enrichmentEndpoint) {
    return {
      ...metadata,
      certificateSource: 'unavailable',
      certificateError: 'No enrichment endpoint configured',
    };
  }

  // Check cache first
  const cacheKey = `${metadata.hostname}:${metadata.port}`;
  if (cfg.cacheEnrichment) {
    const cached = enrichmentCache.get(cacheKey);
    if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
      if (cached.response.success && cached.response.certificate) {
        return {
          ...metadata,
          certificate: cached.response.certificate,
          certificateSource: 'enrichment_server',
          connection: {
            ...metadata.connection,
            protocolVersion: cached.response.connection?.protocolVersion ?? metadata.connection.protocolVersion,
          },
        };
      }
    }
  }

  // Request enrichment from server
  const request: CertificateEnrichmentRequest = {
    hostname: metadata.hostname,
    port: metadata.port,
  };

  try {
    const response = await fetch(cfg.enrichmentEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(cfg.enrichmentTimeoutMs ?? 3000),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const result: CertificateEnrichmentResponse = await response.json();

    // Cache the result
    if (cfg.cacheEnrichment) {
      enrichmentCache.set(cacheKey, {
        response: result,
        cachedAt: Date.now(),
      });

      // Prune cache if too large
      if (enrichmentCache.size > MAX_CACHE_SIZE) {
        const entries = Array.from(enrichmentCache.entries());
        entries.sort((a, b) => a[1].cachedAt - b[1].cachedAt);
        const toDelete = entries.slice(0, enrichmentCache.size - MAX_CACHE_SIZE);
        for (const [key] of toDelete) {
          enrichmentCache.delete(key);
        }
      }
    }

    if (result.success && result.certificate) {
      return {
        ...metadata,
        certificate: result.certificate,
        certificateSource: 'enrichment_server',
        connection: {
          ...metadata.connection,
          protocolVersion: result.connection?.protocolVersion ?? metadata.connection.protocolVersion,
        },
      };
    }

    return {
      ...metadata,
      certificateSource: 'unavailable',
      certificateError: result.error ?? 'Unknown error',
    };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    console.warn('[BrowserDefense] Certificate enrichment failed:', errorMessage);

    return {
      ...metadata,
      certificateSource: 'unavailable',
      certificateError: errorMessage,
    };
  }
}

/**
 * Get TLS metadata with optional certificate enrichment.
 * Combines local capture with server-side enrichment.
 *
 * @param tabId - Chrome tab ID
 * @param doEnrichment - Whether to enrich with certificate data
 * @returns Complete TLS metadata or null if not available
 */
export async function getTLSMetadataEnriched(
  tabId: number,
  doEnrichment: boolean = true
): Promise<TLSMetadata | null> {
  const metadata = getTLSMetadata(tabId);
  if (!metadata) {
    return null;
  }

  if (!doEnrichment) {
    return metadata;
  }

  const config = await getTLSCaptureConfig();
  if (!config.enabled || !config.enrichmentEndpoint) {
    return metadata;
  }

  // Only enrich HTTPS connections
  if (!metadata.connection.isSecure) {
    return metadata;
  }

  return enrichWithCertificate(metadata, config);
}

// ============ Manual Capture ============

/**
 * Manually capture TLS metadata for a URL.
 * Useful for capturing metadata after a page is blocked.
 *
 * @param url - URL to capture metadata for
 * @param tabId - Chrome tab ID (for storage)
 * @returns TLS metadata
 */
export async function captureTLSMetadata(
  url: string,
  tabId?: number
): Promise<TLSMetadata> {
  const { hostname, port } = extractHostPort(url);
  const isSecure = url.startsWith('https://');

  const connection: TLSConnectionMetadata = {
    isSecure,
    scheme: isSecure ? 'https' : 'http',
    hasHSTS: false,
    // Headers not available for manual capture
  };

  const metadata: TLSMetadata = {
    hostname,
    port,
    connection,
    capturedAt: Date.now(),
    certificateSource: 'unavailable',
  };

  // Store if tab ID provided
  if (tabId !== undefined && tabId >= 0) {
    tlsMetadataByTab.set(tabId, metadata);
  }

  return metadata;
}

/**
 * Capture and enrich TLS metadata for a URL.
 * Combines local capture with server-side enrichment.
 *
 * @param url - URL to capture metadata for
 * @returns Complete TLS metadata
 */
export async function captureTLSMetadataEnriched(url: string): Promise<TLSMetadata> {
  const metadata = await captureTLSMetadata(url);

  const config = await getTLSCaptureConfig();
  if (!config.enabled || !config.enrichmentEndpoint) {
    return metadata;
  }

  // Only enrich HTTPS connections
  if (!metadata.connection.isSecure) {
    return metadata;
  }

  return enrichWithCertificate(metadata, config);
}

// ============ Cleanup ============

/**
 * Clear all stored TLS metadata.
 * Useful for testing or reset.
 */
export function clearAllTLSMetadata(): void {
  tlsMetadataByTab.clear();
  securityHeadersByTab.clear();
  console.log('[BrowserDefense] All TLS metadata cleared');
}

/**
 * Clear enrichment cache.
 */
export async function clearEnrichmentCache(): Promise<void> {
  enrichmentCache.clear();
  await chrome.storage.local.remove(CACHE_KEY);
  console.log('[BrowserDefense] TLS enrichment cache cleared');
}

/**
 * Get enrichment cache statistics.
 */
export function getEnrichmentCacheStats(): {
  size: number;
  oldestEntry?: number;
  newestEntry?: number;
} {
  const entries = Array.from(enrichmentCache.values());
  const timestamps = entries.map((e) => e.cachedAt);

  return {
    size: enrichmentCache.size,
    oldestEntry: timestamps.length > 0 ? Math.min(...timestamps) : undefined,
    newestEntry: timestamps.length > 0 ? Math.max(...timestamps) : undefined,
  };
}

// ============ Tab Cleanup ============

/**
 * Set up tab removal listener to clean up TLS metadata.
 */
export function setupTLSCleanup(): void {
  chrome.tabs.onRemoved.addListener((tabId) => {
    clearTLSMetadata(tabId);
  });
}

// ============ Export for Testing ============

export {
  extractSecurityHeaders as _extractSecurityHeaders,
  enrichmentCache as _enrichmentCache,
  tlsMetadataByTab as _tlsMetadataByTab,
  securityHeadersByTab as _securityHeadersByTab,
};
