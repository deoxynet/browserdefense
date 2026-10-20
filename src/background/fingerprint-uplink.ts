/**
 * Phishing Kit Fingerprint Uplink
 *
 * Sends ONLY DOM skeleton hashes + timestamps to server for global correlation.
 * This is the foundation of kit-level detection.
 *
 * PRIVACY GUARANTEES (CRITICAL):
 * - NO URLs transmitted
 * - NO DOM content transmitted
 * - NO screenshots
 * - NO user data
 * - ONLY hash + timestamp
 *
 * Reference: docs/Architecture_v2_DOM_Detection.md Section "Hash-Only Uplink"
 */

import { sha256 } from '../crypto/hashing';
import type { DOMSkeleton } from '../content/dom-skeleton';
import type { LSHSketches } from '../content/lsh-sketch';
import { getOrComputeSkeletonHash } from './skeleton-cache';
import {
  getShadowTelemetryConfig,
  sendShadowTelemetryWithLSH,
  type LSHSketchesForTelemetry,
} from './shadow-telemetry';
import { processShadowDetection } from './shadow-detection';
import { getDOMSignatureMatcher, hasDOMSignatures } from './dom-sig-matcher';

// ============ Types ============

/**
 * Fingerprint uplink payload - MINIMAL by design.
 * Contains ONLY hash and timestamp, nothing else.
 */
export interface FingerprintPayload {
  /** SHA-256 hash of DOM skeleton (hex string) */
  hash: string;
  /** Unix timestamp in milliseconds */
  timestamp: number;
}

/**
 * Server response for fingerprint lookup.
 */
export interface FingerprintResponse {
  /** Confidence score (0-100) */
  confidence: number;
  /** Known phishing kit ID if recognized */
  kitId?: string;
  /** Recommended action based on confidence */
  action: 'block' | 'shadow' | 'allow';
  /** Whether this is a novel fingerprint (first time seen) */
  isNovel: boolean;
  /** Global occurrence count (if available) */
  occurrenceCount?: number;
}

/**
 * Configuration for fingerprint uplink.
 */
export interface FingerprintUplinkConfig {
  /** Server endpoint URL */
  endpoint: string;
  /** Request timeout in milliseconds */
  timeoutMs?: number;
  /** Whether to cache seen hashes locally */
  enableLocalCache?: boolean;
}

// ============ Constants ============

const DEFAULT_TIMEOUT_MS = 5000;
const LOCAL_CACHE_KEY = 'browserdefense_fingerprint_cache';
const MAX_CACHE_SIZE = 10000;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// ============ Local Cache ============

interface CachedFingerprint {
  hash: string;
  timestamp: number;
  response?: FingerprintResponse;
}

/**
 * Get the local fingerprint cache.
 */
async function getCache(): Promise<Map<string, CachedFingerprint>> {
  const result = await chrome.storage.local.get(LOCAL_CACHE_KEY);
  const data = result[LOCAL_CACHE_KEY] as [string, CachedFingerprint][] | undefined;
  return new Map(data ?? []);
}

/**
 * Save the local fingerprint cache.
 */
async function saveCache(cache: Map<string, CachedFingerprint>): Promise<void> {
  // Prune old entries if cache is too large
  if (cache.size > MAX_CACHE_SIZE) {
    const entries = Array.from(cache.entries());
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
    const toDelete = entries.slice(0, cache.size - MAX_CACHE_SIZE);
    for (const [key] of toDelete) {
      cache.delete(key);
    }
  }

  // Prune expired entries
  const now = Date.now();
  for (const [key, value] of cache) {
    if (now - value.timestamp > CACHE_TTL_MS) {
      cache.delete(key);
    }
  }

  await chrome.storage.local.set({
    [LOCAL_CACHE_KEY]: Array.from(cache.entries()),
  });
}

/**
 * Check if a fingerprint is in the local cache.
 */
async function checkCache(hash: string): Promise<CachedFingerprint | null> {
  const cache = await getCache();
  const entry = cache.get(hash);

  if (!entry) {
    return null;
  }

  // Check if expired
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    cache.delete(hash);
    await saveCache(cache);
    return null;
  }

  return entry;
}

/**
 * Add a fingerprint to the local cache.
 */
async function addToCache(
  hash: string,
  response?: FingerprintResponse
): Promise<void> {
  const cache = await getCache();
  cache.set(hash, {
    hash,
    timestamp: Date.now(),
    response,
  });
  await saveCache(cache);
}

// ============ Hashing ============

/**
 * Compute deterministic hash of a DOM skeleton.
 *
 * The hash is computed from the serialized skeleton structure.
 * This ensures identical page structures produce identical hashes
 * regardless of when/where they are encountered.
 *
 * @param skeleton - DOM skeleton to hash
 * @returns SHA-256 hash as hex string
 */
export async function hashSkeleton(skeleton: DOMSkeleton): Promise<string> {
  // Create a deterministic string representation
  // We hash the tagTree plus form metadata for a complete fingerprint
  const fingerprint = JSON.stringify({
    tagTree: skeleton.tagTree,
    formCount: skeleton.formCount,
    inputTypes: skeleton.inputTypes,
    // Note: actionUrls excluded as they may contain path information
    // that could leak site structure
    hasLoginForm: skeleton.hasLoginForm,
    hasPaymentForm: skeleton.hasPaymentForm,
  });

  return sha256(fingerprint);
}

// ============ Uplink ============

/**
 * Send fingerprint to server for correlation.
 *
 * PRIVACY: This function sends ONLY hash + timestamp.
 * It does NOT send URLs, DOM content, or any user data.
 *
 * @param skeleton - DOM skeleton to fingerprint
 * @param config - Uplink configuration
 * @returns Server response or null if upload failed
 */
export async function uploadFingerprint(
  skeleton: DOMSkeleton,
  config: FingerprintUplinkConfig
): Promise<FingerprintResponse | null> {
  // Compute hash
  const hash = await hashSkeleton(skeleton);
  const timestamp = Date.now();

  // Check local cache (skip upload if recently seen)
  if (config.enableLocalCache !== false) {
    const cached = await checkCache(hash);
    if (cached?.response) {
      console.log(`[BrowserDefense] Fingerprint cache hit: ${hash.slice(0, 16)}...`);
      return cached.response;
    }
  }

  // Build minimal payload - ONLY hash and timestamp
  const payload: FingerprintPayload = {
    hash,
    timestamp,
  };

  // Validate payload before sending (defense in depth)
  assertMinimalPayload(payload);

  try {
    const response = await fetch(config.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(config.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });

    if (!response.ok) {
      console.warn(`[BrowserDefense] Fingerprint uplink failed: HTTP ${response.status}`);
      // Cache the hash even on failure (to deduplicate retries)
      if (config.enableLocalCache !== false) {
        await addToCache(hash);
      }
      return null;
    }

    const result: FingerprintResponse = await response.json();

    // Cache successful response
    if (config.enableLocalCache !== false) {
      await addToCache(hash, result);
    }

    console.log(
      `[BrowserDefense] Fingerprint uploaded: ${hash.slice(0, 16)}... ` +
      `(confidence: ${result.confidence}, action: ${result.action})`
    );

    return result;
  } catch (err) {
    console.warn('[BrowserDefense] Fingerprint uplink error:', (err as Error).message);

    // Cache the hash even on error (to deduplicate retries)
    if (config.enableLocalCache !== false) {
      await addToCache(hash);
    }

    return null;
  }
}

/**
 * Upload a pre-computed fingerprint hash to server.
 *
 * This variant skips hash computation (used when hash is already cached).
 * PRIVACY: This function sends ONLY hash + timestamp.
 *
 * @param hash - Pre-computed SHA-256 hash
 * @param config - Uplink configuration
 * @returns Server response or null if upload failed
 */
async function uploadFingerprintWithHash(
  hash: string,
  config: FingerprintUplinkConfig
): Promise<FingerprintResponse | null> {
  const timestamp = Date.now();

  // Check local cache (skip upload if recently seen)
  if (config.enableLocalCache !== false) {
    const cached = await checkCache(hash);
    if (cached?.response) {
      console.log(`[BrowserDefense] Fingerprint cache hit: ${hash.slice(0, 16)}...`);
      return cached.response;
    }
  }

  // Build minimal payload - ONLY hash and timestamp
  const payload: FingerprintPayload = {
    hash,
    timestamp,
  };

  // Validate payload before sending (defense in depth)
  assertMinimalPayload(payload);

  try {
    const response = await fetch(config.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(config.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const result: FingerprintResponse = await response.json();

    // Cache the response
    if (config.enableLocalCache !== false) {
      await addToCache(hash, result);
    }

    console.log(
      `[BrowserDefense] Fingerprint uploaded: ${hash.slice(0, 16)}... ` +
        `(confidence: ${result.confidence}, action: ${result.action})`
    );

    return result;
  } catch (err) {
    console.warn('[BrowserDefense] Fingerprint uplink error:', (err as Error).message);

    // Cache the hash even on error (to deduplicate retries)
    if (config.enableLocalCache !== false) {
      await addToCache(hash);
    }

    return null;
  }
}

/**
 * Assert that payload contains ONLY hash and timestamp.
 * This is a defense-in-depth check to ensure we never accidentally
 * send more data than intended.
 *
 * @throws Error if payload contains unexpected fields
 */
function assertMinimalPayload(payload: FingerprintPayload): void {
  const allowedKeys = new Set(['hash', 'timestamp']);
  const actualKeys = Object.keys(payload);

  for (const key of actualKeys) {
    if (!allowedKeys.has(key)) {
      throw new Error(
        `[BrowserDefense] PRIVACY VIOLATION: Fingerprint payload contains unexpected field: ${key}`
      );
    }
  }

  // Validate hash format (should be hex string, 64 chars for SHA-256)
  if (typeof payload.hash !== 'string' || !/^[a-f0-9]{64}$/i.test(payload.hash)) {
    throw new Error('[BrowserDefense] Invalid hash format in fingerprint payload');
  }

  // Validate timestamp (should be positive number)
  if (typeof payload.timestamp !== 'number' || payload.timestamp <= 0) {
    throw new Error('[BrowserDefense] Invalid timestamp in fingerprint payload');
  }
}

// ============ Message Handler ============

/**
 * Handle DOM_SKELETON message from content script.
 *
 * This is the main entry point for fingerprint processing.
 *
 * Flow:
 * 1. Check URL-based IndexedDB cache (skip hashing if cached)
 * 2. If not cached, compute hash and cache by URL
 * 3. Check hash-based uplink cache (skip upload if recently sent)
 * 4. Upload to server if needed
 *
 * @param message - Message from content script
 * @returns Fingerprint response or null
 */
export async function handleSkeletonMessage(
  message: {
    type: string;
    payload: DOMSkeleton;
    url: string;
    timestamp: number;
    lshSketches?: LSHSketches;
  }
): Promise<FingerprintResponse | null> {
  if (message.type !== 'DOM_SKELETON') {
    return null;
  }

  // Step 1: Check URL-based IndexedDB cache first
  // This skips hashing entirely for repeat visits
  const hashResult = await getOrComputeSkeletonHash(message.url, message.payload);

  if (hashResult.cached) {
    console.log(
      `[BrowserDefense] Skeleton cache hit for ${hashResult.normalizedUrl.slice(0, 50)}... ` +
      `(hash: ${hashResult.hash.slice(0, 16)}...)`
    );
    // Return cached data - skip uplink for already-seen pages
    // This dramatically reduces server load
    return null;
  }

  console.log(
    `[BrowserDefense] New page fingerprinted: ${hashResult.normalizedUrl.slice(0, 50)}... ` +
    `(hash: ${hashResult.hash.slice(0, 16)}...)`
  );

  // Step 1.5 (NEW): Check local DOM signature threat intel FIRST
  // This enables offline blocking of known-bad DOM signatures without server round-trip
  if (hasDOMSignatures()) {
    try {
      const matcher = getDOMSignatureMatcher();
      const localMatch = await matcher.match(hashResult.hash, message.lshSketches);

      if (localMatch.matched) {
        console.log(
          `[BrowserDefense] Local DOM signature match: ${hashResult.hash.slice(0, 16)}... ` +
          `(type: ${localMatch.matchType}, confidence: ${localMatch.confidence}, action: ${localMatch.action})`
        );

        // Return result from local threat intel - no server round-trip needed
        return {
          confidence: localMatch.confidence,
          kitId: localMatch.kitId,
          action: localMatch.action === 'alert' ? 'shadow' : localMatch.action,
          isNovel: false,
        };
      }
    } catch (err) {
      console.warn('[BrowserDefense] DOM signature match error:', err);
      // Continue with server uplink on error
    }
  }

  // Step 2: Send shadow telemetry with LSH sketches (hash-only, no URL)
  // This runs independently of fingerprint uplink and does not affect blocking
  const shadowConfig = await getShadowTelemetryConfig();
  if (shadowConfig) {
    // Convert LSH sketches to telemetry format if present
    const lshForTelemetry: LSHSketchesForTelemetry | undefined = message.lshSketches
      ? {
          dom_layout_lsh: message.lshSketches.dom_layout_lsh,
          form_structure_lsh: message.lshSketches.form_structure_lsh,
          script_structure_lsh: message.lshSketches.script_structure_lsh,
        }
      : undefined;

    // Fire-and-forget: don't block on shadow telemetry
    sendShadowTelemetryWithLSH(hashResult.hash, shadowConfig, lshForTelemetry).catch((err) => {
      console.warn('[BrowserDefense] Shadow telemetry failed:', err);
    });
  }

  // Step 3: Get uplink endpoint from config
  const config = await getFingerprintUplinkConfig();
  if (!config) {
    // No endpoint configured, fingerprint stored locally only
    console.log(`[BrowserDefense] Fingerprint stored locally (no uplink configured)`);
    return null;
  }

  // Step 4: Upload fingerprint using the pre-computed hash
  const response = await uploadFingerprintWithHash(hashResult.hash, config);

  // Step 5: Process through shadow detection (Issue #171)
  // This logs novel/low-confidence fingerprints for analyst review without blocking
  if (response) {
    const shadowResult = await processShadowDetection(hashResult.hash, response);

    if (shadowResult.shadowMode) {
      console.log(
        `[BrowserDefense] Shadow detection applied: ${hashResult.hash.slice(0, 16)}... ` +
        `(reason: ${shadowResult.reason}, alert: ${shadowResult.alertSent})`
      );

      // If shadow mode applies, override server action to 'shadow'
      // This ensures no blocking occurs for uncertain detections
      if (response.action === 'block') {
        return {
          ...response,
          action: 'shadow' as const,
        };
      }
    }
  }

  return response;
}

/**
 * Get fingerprint uplink configuration from storage.
 */
async function getFingerprintUplinkConfig(): Promise<FingerprintUplinkConfig | null> {
  const { browserdefense_config } = await chrome.storage.local.get('browserdefense_config');

  if (!browserdefense_config?.fingerprint_endpoint) {
    return null;
  }

  return {
    endpoint: browserdefense_config.fingerprint_endpoint,
    timeoutMs: browserdefense_config.fingerprint_timeout_ms ?? DEFAULT_TIMEOUT_MS,
    enableLocalCache: browserdefense_config.fingerprint_cache_enabled ?? true,
  };
}

// ============ Cache Management ============

/**
 * Clear the local fingerprint cache.
 * Useful for testing or when privacy reset is needed.
 */
export async function clearFingerprintCache(): Promise<void> {
  await chrome.storage.local.remove(LOCAL_CACHE_KEY);
  console.log('[BrowserDefense] Fingerprint cache cleared');
}

/**
 * Get fingerprint cache statistics.
 */
export async function getFingerprintCacheStats(): Promise<{
  size: number;
  oldestEntry?: number;
  newestEntry?: number;
}> {
  const cache = await getCache();
  const timestamps = Array.from(cache.values()).map((v) => v.timestamp);

  return {
    size: cache.size,
    oldestEntry: timestamps.length > 0 ? Math.min(...timestamps) : undefined,
    newestEntry: timestamps.length > 0 ? Math.max(...timestamps) : undefined,
  };
}

// ============ Exports for Testing ============

export {
  assertMinimalPayload as _assertMinimalPayload,
  checkCache as _checkCache,
  addToCache as _addToCache,
  getCache as _getCache,
};
