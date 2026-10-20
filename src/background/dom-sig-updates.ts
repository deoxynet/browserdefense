/**
 * DOM Signature Update Client
 *
 * Fetches signed DOM signature updates from a configured endpoint,
 * verifies signatures, and applies updates to the local store.
 *
 * Features:
 * - P-256 ECDSA / Ed25519 signature verification
 * - Version tracking (rejects old updates)
 * - Delta updates (fetches delta if available, falls back to snapshot)
 * - JSON data format with SHA-256 integrity verification
 * - Exponential backoff retry
 * - Stale-protect: continues with old signatures on failure
 */

import { verifyDOMSignatureManifest } from '../crypto/signing';
import { sha256 } from '../crypto/hashing';
import {
  initDOMSignatureStore,
  saveDOMSignatureStore,
  bulkLoadSignatures,
  addDOMSignature,
  removeDOMSignature,
  setStoreVersion,
  getDOMSignatureStats,
  saveDOMSignatureUpdateMeta,
  loadDOMSignatureUpdateMeta,
  pruneExpiredSignatures,
} from '../storage/dom-sig-store';
import {
  DOM_SIG_UPDATE_CONFIG_KEY,
  DOM_SIG_UPDATE_ALARM,
} from '../config/storage-keys';
import type {
  DOMSignatureManifest,
  DOMSignatureEntry,
  DOMSignatureDeltaInfo,
  DOMSignatureUpdateConfig,
  DOMSignatureUpdateMeta,
  DOMSignatureUpdateResult,
} from '../types/dom-sig-manifest';

// Re-export for test access
export { DOM_SIG_UPDATE_CONFIG_KEY, DOM_SIG_UPDATE_ALARM } from '../config/storage-keys';

// ============ Constants ============

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_BASE_DELAY_MS = 1000;
const DEFAULT_MAX_DELAY_MS = 30000;
const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_MAX_DELTA_SIZE = 512 * 1024; // 512KB for DOM sigs (smaller than IOC blocklist)

// ============ Types ============

export type DOMSigUpdateErrorCode =
  | 'NETWORK_ERROR'
  | 'INVALID_SIGNATURE'
  | 'INTEGRITY_ERROR'
  | 'PARSE_ERROR'
  | 'VERSION_ERROR'
  | 'STORAGE_ERROR';

// ============ Public API ============

/**
 * Fetch and apply a DOM signature update.
 */
export async function fetchDOMSignatureUpdate(
  config: DOMSignatureUpdateConfig
): Promise<DOMSignatureUpdateResult> {
  const maxRetries = config.maxRetries ?? DEFAULT_MAX_RETRIES;
  const baseDelayMs = config.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  const maxDelayMs = config.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let lastError = 'Unknown error';

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      // Fetch manifest
      const manifestUrl = resolveUrl(config.endpoint, 'dom-sig-manifest.json');
      const manifest = await fetchManifest(manifestUrl, timeoutMs);

      // Verify signature using DOM-signature-specific verification
      const isValid = await verifyDOMSignatureManifest(
        manifest as unknown as Record<string, unknown>,
        manifest.signature,
        config.publicKey
      );
      if (!isValid) {
        console.error('[BrowserDefense] Invalid signature on DOM signature update');
        return { success: false, error: 'Invalid signature' };
      }

      // Check version
      const meta = await loadDOMSignatureUpdateMeta();
      if (meta && manifest.version <= meta.version) {
        console.log(
          `[BrowserDefense] DOM sig update version ${manifest.version} <= current ${meta.version}, skipping`
        );
        return {
          success: true,
          version: meta.version,
          exactCount: meta.exactCount,
          lshCount: meta.lshCount,
          type: 'snapshot',
        };
      }

      // Try delta update if available
      if (meta && manifest.deltas && manifest.deltas.length > 0) {
        const delta = findApplicableDelta(
          manifest.deltas,
          meta.version,
          manifest.version,
          DEFAULT_MAX_DELTA_SIZE
        );
        if (delta) {
          const deltaResult = await applyDeltaUpdate(config.endpoint, delta, manifest, timeoutMs);
          if (deltaResult.success) {
            return deltaResult;
          }
          console.warn('[BrowserDefense] Delta update failed, falling back to snapshot');
        }
      }

      // Full snapshot update
      const dataUrl = manifest.data_url
        ? resolveUrl(config.endpoint, manifest.data_url)
        : resolveUrl(config.endpoint, 'dom-signatures.json');

      // Fetch raw text first to hash before parsing
      // (JSON.stringify doesn't preserve original formatting/key order)
      const { text: rawText, entries } = await fetchSignatureDataWithRaw(dataUrl, timeoutMs);

      // Verify integrity against raw response text
      const dataHash = await sha256(rawText);
      if (dataHash !== manifest.sha256_root) {
        console.error(
          `[BrowserDefense] DOM signature data integrity check failed: ` +
          `expected ${manifest.sha256_root.slice(0, 16)}..., got ${dataHash.slice(0, 16)}...`
        );
        return { success: false, error: 'Integrity check failed' };
      }

      // Initialize store if needed
      await initDOMSignatureStore();

      // Apply update
      bulkLoadSignatures(entries);
      setStoreVersion(manifest.version);

      // Save to storage
      await saveDOMSignatureStore();

      // Save metadata
      await saveDOMSignatureUpdateMeta({
        version: manifest.version,
        timestamp: manifest.created_at ?? new Date().toISOString(),
        updatedAt: Date.now(),
        exactCount: manifest.exact_count,
        lshCount: manifest.lsh_count,
      });

      // Prune expired signatures
      const pruned = pruneExpiredSignatures();
      if (pruned > 0) {
        console.log(`[BrowserDefense] Pruned ${pruned} expired DOM signatures`);
        await saveDOMSignatureStore();
      }

      console.log(
        `[BrowserDefense] DOM signature update applied: version ${manifest.version}, ` +
        `${manifest.exact_count} exact, ${manifest.lsh_count} LSH`
      );

      return {
        success: true,
        version: manifest.version,
        exactCount: manifest.exact_count,
        lshCount: manifest.lsh_count,
        type: 'snapshot',
      };
    } catch (err) {
      lastError = (err as Error).message;
      console.warn(
        `[BrowserDefense] DOM signature update attempt ${attempt + 1}/${maxRetries} failed:`,
        lastError
      );

      // Exponential backoff
      if (attempt < maxRetries - 1) {
        const delay = Math.min(baseDelayMs * Math.pow(2, attempt), maxDelayMs);
        await sleep(delay);
      }
    }
  }

  console.error('[BrowserDefense] DOM signature update failed after retries:', lastError);
  return { success: false, error: lastError };
}

/**
 * Schedule periodic DOM signature updates.
 */
export async function scheduleDOMSignatureUpdates(
  config: DOMSignatureUpdateConfig,
  intervalMinutes = 60
): Promise<void> {
  // Store config for alarm handler
  await chrome.storage.local.set({ [DOM_SIG_UPDATE_CONFIG_KEY]: config });

  // Create periodic alarm
  await chrome.alarms.create(DOM_SIG_UPDATE_ALARM, {
    periodInMinutes: intervalMinutes,
    delayInMinutes: 0, // Run immediately
  });

  console.log(
    `[BrowserDefense] DOM signature updates scheduled every ${intervalMinutes} minutes`
  );
}

/**
 * Handle DOM signature update alarm.
 */
export async function handleDOMSignatureUpdateAlarm(): Promise<void> {
  const result = await chrome.storage.local.get(DOM_SIG_UPDATE_CONFIG_KEY);
  const config = result[DOM_SIG_UPDATE_CONFIG_KEY] as DOMSignatureUpdateConfig | undefined;

  if (!config) {
    console.warn('[BrowserDefense] No DOM signature update config found');
    return;
  }

  await fetchDOMSignatureUpdate(config);
}

/**
 * Cancel scheduled DOM signature updates.
 */
export async function cancelDOMSignatureUpdates(): Promise<void> {
  await chrome.alarms.clear(DOM_SIG_UPDATE_ALARM);
  await chrome.storage.local.remove(DOM_SIG_UPDATE_CONFIG_KEY);
  console.log('[BrowserDefense] DOM signature updates cancelled');
}

/**
 * Get current update metadata.
 */
export async function getDOMSignatureUpdateMeta(): Promise<DOMSignatureUpdateMeta | null> {
  return loadDOMSignatureUpdateMeta();
}

// ============ Internal Functions ============

/**
 * Fetch manifest from URL.
 */
async function fetchManifest(url: string, timeoutMs: number): Promise<DOMSignatureManifest> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Fetch signature data from URL, returning both raw text and parsed entries.
 * Raw text is needed for integrity verification (JSON.stringify doesn't preserve formatting).
 */
async function fetchSignatureDataWithRaw(
  url: string,
  timeoutMs: number
): Promise<{ text: string; entries: DOMSignatureEntry[] }> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const text = await response.text();
  const entries = JSON.parse(text) as DOMSignatureEntry[];

  return { text, entries };
}

/**
 * Find applicable delta update.
 * Verifies both source (from) and target (to) versions match expected values.
 */
function findApplicableDelta(
  deltas: DOMSignatureDeltaInfo[],
  currentVersion: number,
  targetVersion: number,
  maxSize: number
): DOMSignatureDeltaInfo | null {
  // Find delta that starts from current version AND targets manifest version
  const applicable = deltas.find(
    (d) => d.from === currentVersion && d.to === targetVersion && d.size <= maxSize
  );
  return applicable ?? null;
}

/**
 * Apply delta update.
 */
async function applyDeltaUpdate(
  endpoint: string,
  delta: DOMSignatureDeltaInfo,
  manifest: DOMSignatureManifest,
  timeoutMs: number
): Promise<DOMSignatureUpdateResult> {
  try {
    const deltaUrl = resolveUrl(endpoint, delta.url);
    const response = await fetch(deltaUrl, {
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const deltaData = await response.json() as {
      added: DOMSignatureEntry[];
      removed: string[];
    };

    // Initialize store if needed
    await initDOMSignatureStore();

    // Apply removals
    for (const hash of deltaData.removed) {
      removeDOMSignature(hash);
    }

    // Apply additions
    for (const entry of deltaData.added) {
      addDOMSignature(entry);
    }

    setStoreVersion(manifest.version);

    // Verify counts match manifest
    const stats = getDOMSignatureStats();
    if (stats.exactCount !== manifest.exact_count) {
      throw new Error(
        `Exact count mismatch after delta: ${stats.exactCount} != ${manifest.exact_count}`
      );
    }
    if (stats.lshCount !== manifest.lsh_count) {
      throw new Error(
        `LSH count mismatch after delta: ${stats.lshCount} != ${manifest.lsh_count}`
      );
    }

    // Save to storage
    await saveDOMSignatureStore();

    // Save metadata
    await saveDOMSignatureUpdateMeta({
      version: manifest.version,
      timestamp: manifest.created_at ?? new Date().toISOString(),
      updatedAt: Date.now(),
      exactCount: manifest.exact_count,
      lshCount: manifest.lsh_count,
    });

    console.log(
      `[BrowserDefense] DOM signature delta update applied: ` +
      `+${deltaData.added.length} -${deltaData.removed.length}`
    );

    return {
      success: true,
      version: manifest.version,
      exactCount: manifest.exact_count,
      lshCount: manifest.lsh_count,
      type: 'delta',
    };
  } catch (err) {
    console.warn('[BrowserDefense] Delta update failed:', (err as Error).message);
    return { success: false, error: (err as Error).message };
  }
}

/**
 * Resolve relative URL against base.
 */
function resolveUrl(base: string, relative: string): string {
  // Handle absolute URLs
  if (relative.startsWith('http://') || relative.startsWith('https://')) {
    return relative;
  }

  // Ensure base ends with /
  const normalizedBase = base.endsWith('/') ? base : `${base}/`;
  return `${normalizedBase}${relative}`;
}

/**
 * Sleep for specified milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============ Exports for Testing ============

export {
  fetchManifest as _fetchManifest,
  fetchSignatureDataWithRaw as _fetchSignatureDataWithRaw,
  findApplicableDelta as _findApplicableDelta,
  applyDeltaUpdate as _applyDeltaUpdate,
  resolveUrl as _resolveUrl,
};
