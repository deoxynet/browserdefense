/**
 * Local History-Derived Bloom Filter (Issue #161)
 *
 * Opt-in Bloom filter from browser history to skip DOM analysis on
 * previously visited domains. Uses eTLD+1 normalization for privacy.
 *
 * PRIVACY GUARANTEES (CRITICAL):
 * - Uses eTLD+1 only (e.g., example.com, not sub.example.com/path)
 * - NEVER transmitted to server
 * - NEVER logged
 * - Stored locally only
 * - User must explicitly enable
 * - Requires optional history permission
 *
 * Purpose: Reduce DOM fingerprinting volume >80% by skipping known domains.
 * This is a PERFORMANCE optimization, not a security feature.
 */

import { BloomFilter } from '../storage/bloom-filter';
import { extractRegistrableDomain } from '../crypto/canonicalize';

// ============ Constants ============

/** Storage key for history Bloom filter data */
const HISTORY_BLOOM_DATA_KEY = 'history_bloom_data';

/** Storage key for history Bloom filter metadata */
const HISTORY_BLOOM_META_KEY = 'history_bloom_meta';

/** Storage key for history Bloom config */
const HISTORY_BLOOM_CONFIG_KEY = 'history_bloom_config';

/** Default false positive rate (1%) */
const DEFAULT_FP_RATE = 0.01;

/** Maximum history entries to scan (30 days typical = ~3000 entries) */
const MAX_HISTORY_ENTRIES = 50000;

/** How far back to scan history (30 days in ms) */
const HISTORY_LOOKBACK_MS = 30 * 24 * 60 * 60 * 1000;

/** Minimum interval between rebuilds (1 hour) */
const MIN_REBUILD_INTERVAL_MS = 60 * 60 * 1000;

// ============ Types ============

/**
 * Configuration for history-derived Bloom filter.
 */
export interface HistoryBloomConfig {
  /** Whether the feature is enabled (default: false) */
  enabled: boolean;
  /** Last rebuild timestamp (ISO 8601) */
  lastRebuild?: string;
  /** Number of unique domains in filter */
  domainCount?: number;
}

/**
 * Result of checking if history permission is available.
 */
export interface HistoryPermissionStatus {
  /** Whether the permission is granted */
  granted: boolean;
  /** Whether the permission can be requested */
  canRequest: boolean;
}

// ============ In-Memory Cache ============

let cachedFilter: BloomFilter | null = null;
let cachedConfig: HistoryBloomConfig | null = null;

// ============ Permission Handling ============

/**
 * Check if history permission is granted.
 */
export async function checkHistoryPermission(): Promise<HistoryPermissionStatus> {
  try {
    const granted = await chrome.permissions.contains({ permissions: ['history'] });
    return { granted, canRequest: true };
  } catch {
    return { granted: false, canRequest: false };
  }
}

/**
 * Request history permission from user.
 * Must be called from a user gesture (e.g., button click).
 *
 * @returns true if permission was granted
 */
export async function requestHistoryPermission(): Promise<boolean> {
  try {
    const granted = await chrome.permissions.request({ permissions: ['history'] });
    return granted;
  } catch (error) {
    console.warn('[BrowserDefense] Failed to request history permission:', error);
    return false;
  }
}

/**
 * Remove history permission.
 */
export async function removeHistoryPermission(): Promise<boolean> {
  try {
    await chrome.permissions.remove({ permissions: ['history'] });
    // Also disable the feature and clear the filter
    await disableHistoryBloom();
    return true;
  } catch (error) {
    console.warn('[BrowserDefense] Failed to remove history permission:', error);
    return false;
  }
}

// ============ Configuration ============

/**
 * Get history Bloom filter configuration.
 */
export async function getHistoryBloomConfig(): Promise<HistoryBloomConfig> {
  if (cachedConfig) {
    return cachedConfig;
  }

  const result = await chrome.storage.local.get(HISTORY_BLOOM_CONFIG_KEY);
  const config: HistoryBloomConfig = result[HISTORY_BLOOM_CONFIG_KEY] ?? { enabled: false };
  cachedConfig = config;
  return config;
}

/**
 * Save history Bloom filter configuration.
 */
async function saveHistoryBloomConfig(config: HistoryBloomConfig): Promise<void> {
  await chrome.storage.local.set({ [HISTORY_BLOOM_CONFIG_KEY]: config });
  cachedConfig = config;
}

/**
 * Enable history Bloom filter feature.
 * Requires history permission to be granted first.
 *
 * @returns true if enabled successfully
 */
export async function enableHistoryBloom(): Promise<boolean> {
  const permission = await checkHistoryPermission();
  if (!permission.granted) {
    console.warn('[BrowserDefense] Cannot enable history bloom: permission not granted');
    return false;
  }

  const config = await getHistoryBloomConfig();
  config.enabled = true;
  await saveHistoryBloomConfig(config);

  // Trigger initial build
  await rebuildHistoryBloom();

  console.log('[BrowserDefense] History bloom filter enabled');
  return true;
}

/**
 * Disable history Bloom filter feature and clear data.
 */
export async function disableHistoryBloom(): Promise<void> {
  const config = await getHistoryBloomConfig();
  config.enabled = false;
  config.lastRebuild = undefined;
  config.domainCount = undefined;
  await saveHistoryBloomConfig(config);

  // Clear stored filter
  await chrome.storage.local.remove([HISTORY_BLOOM_DATA_KEY, HISTORY_BLOOM_META_KEY]);
  cachedFilter = null;

  console.log('[BrowserDefense] History bloom filter disabled and cleared');
}

/**
 * Check if history Bloom filter is enabled and ready.
 */
export async function isHistoryBloomEnabled(): Promise<boolean> {
  const config = await getHistoryBloomConfig();
  if (!config.enabled) {
    return false;
  }

  const permission = await checkHistoryPermission();
  return permission.granted;
}

// ============ Bloom Filter Operations ============

/**
 * Load history Bloom filter from storage.
 */
async function loadHistoryBloom(): Promise<BloomFilter | null> {
  if (cachedFilter) {
    return cachedFilter;
  }

  try {
    const result = await chrome.storage.local.get([HISTORY_BLOOM_DATA_KEY, HISTORY_BLOOM_META_KEY]);

    if (!result[HISTORY_BLOOM_DATA_KEY] || !result[HISTORY_BLOOM_META_KEY]) {
      return null;
    }

    cachedFilter = BloomFilter.deserializeFromBase64(
      result[HISTORY_BLOOM_DATA_KEY],
      result[HISTORY_BLOOM_META_KEY]
    );

    return cachedFilter;
  } catch (error) {
    console.warn('[BrowserDefense] Failed to load history bloom filter:', error);
    return null;
  }
}

/**
 * Save history Bloom filter to storage.
 */
async function saveHistoryBloom(filter: BloomFilter): Promise<void> {
  await chrome.storage.local.set({
    [HISTORY_BLOOM_DATA_KEY]: filter.serializeToBase64(),
    [HISTORY_BLOOM_META_KEY]: filter.getMeta(),
  });
  cachedFilter = filter;
}

/**
 * Rebuild history Bloom filter from browser history.
 * Scans history and extracts unique eTLD+1 domains.
 *
 * @param force - Force rebuild even if recently rebuilt
 * @returns Number of unique domains added to filter
 */
export async function rebuildHistoryBloom(force: boolean = false): Promise<number> {
  const config = await getHistoryBloomConfig();

  if (!config.enabled) {
    console.log('[BrowserDefense] History bloom is disabled, skipping rebuild');
    return 0;
  }

  const permission = await checkHistoryPermission();
  if (!permission.granted) {
    console.log('[BrowserDefense] History permission not granted, skipping rebuild');
    return 0;
  }

  // Check if recently rebuilt
  if (!force && config.lastRebuild) {
    const lastRebuild = new Date(config.lastRebuild).getTime();
    if (Date.now() - lastRebuild < MIN_REBUILD_INTERVAL_MS) {
      console.log('[BrowserDefense] History bloom recently rebuilt, skipping');
      return config.domainCount ?? 0;
    }
  }

  console.log('[BrowserDefense] Rebuilding history bloom filter...');
  const startTime = Date.now();

  // Scan history
  const domains = await scanHistoryForDomains();

  if (domains.size === 0) {
    console.log('[BrowserDefense] No domains found in history');
    return 0;
  }

  // Create new Bloom filter
  const filter = BloomFilter.create({
    expectedItems: domains.size,
    falsePositiveRate: DEFAULT_FP_RATE,
  });

  // Add domains to filter (hash the eTLD+1 strings)
  for (const domain of domains) {
    const hash = await hashDomain(domain);
    filter.add(hash);
  }

  filter.markClean();

  // Save filter
  await saveHistoryBloom(filter);

  // Update config
  config.lastRebuild = new Date().toISOString();
  config.domainCount = domains.size;
  await saveHistoryBloomConfig(config);

  const elapsed = Date.now() - startTime;
  console.log(
    `[BrowserDefense] History bloom rebuilt: ${domains.size} domains in ${elapsed}ms ` +
      `(${filter.byteLength} bytes, FP rate: ${(filter.estimatedFalsePositiveRate * 100).toFixed(2)}%)`
  );

  return domains.size;
}

/**
 * Scan browser history and extract unique eTLD+1 domains.
 */
async function scanHistoryForDomains(): Promise<Set<string>> {
  const domains = new Set<string>();

  try {
    const startTime = Date.now() - HISTORY_LOOKBACK_MS;

    const historyItems = await chrome.history.search({
      text: '',
      startTime,
      maxResults: MAX_HISTORY_ENTRIES,
    });

    for (const item of historyItems) {
      if (!item.url) continue;

      try {
        const url = new URL(item.url);

        // Skip non-HTTP(S) URLs
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
          continue;
        }

        // Extract eTLD+1
        const domain = extractRegistrableDomain(url.hostname);
        if (domain) {
          domains.add(domain.toLowerCase());
        }
      } catch {
        // Invalid URL, skip
      }
    }
  } catch (error) {
    console.warn('[BrowserDefense] Failed to scan history:', error);
  }

  return domains;
}

/**
 * Hash a domain string for Bloom filter storage.
 * Uses SHA-256 for consistent hashing.
 */
async function hashDomain(domain: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(domain.toLowerCase());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

// ============ Domain Checking ============

/**
 * Check if a domain has been previously visited.
 * Returns true if domain is in history (skip DOM analysis),
 * false if domain is new (perform DOM analysis).
 *
 * IMPORTANT: This is a performance optimization only.
 * False positives mean we skip analysis on a new domain (acceptable).
 * False negatives never occur (we always analyze truly new domains).
 *
 * @param url - URL to check
 * @returns true if domain was previously visited, false otherwise
 */
export async function isDomainInHistory(url: string): Promise<boolean> {
  const config = await getHistoryBloomConfig();
  if (!config.enabled) {
    return false;
  }

  const filter = await loadHistoryBloom();
  if (!filter) {
    return false;
  }

  try {
    const parsedUrl = new URL(url);

    // Skip non-HTTP(S) URLs
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false;
    }

    // Extract eTLD+1
    const domain = extractRegistrableDomain(parsedUrl.hostname);
    if (!domain) {
      return false;
    }

    // Hash and check
    const hash = await hashDomain(domain);
    return filter.mightContain(hash);
  } catch {
    return false;
  }
}

/**
 * Check if a domain (already extracted eTLD+1) is in history.
 * Faster version when domain is already normalized.
 */
export async function isDomainInHistoryDirect(domain: string): Promise<boolean> {
  const config = await getHistoryBloomConfig();
  if (!config.enabled) {
    return false;
  }

  const filter = await loadHistoryBloom();
  if (!filter) {
    return false;
  }

  try {
    const hash = await hashDomain(domain.toLowerCase());
    return filter.mightContain(hash);
  } catch {
    return false;
  }
}

// ============ Statistics ============

/**
 * Get history Bloom filter statistics.
 */
export async function getHistoryBloomStats(): Promise<{
  enabled: boolean;
  permissionGranted: boolean;
  domainCount: number;
  filterSizeBytes: number;
  estimatedFPRate: number;
  fillRatio: number;
  lastRebuild?: string;
}> {
  const config = await getHistoryBloomConfig();
  const permission = await checkHistoryPermission();
  const filter = await loadHistoryBloom();

  return {
    enabled: config.enabled,
    permissionGranted: permission.granted,
    domainCount: config.domainCount ?? 0,
    filterSizeBytes: filter?.byteLength ?? 0,
    estimatedFPRate: filter?.estimatedFalsePositiveRate ?? 0,
    fillRatio: filter?.fillRatio ?? 0,
    lastRebuild: config.lastRebuild,
  };
}

// ============ Initialization ============

/**
 * Initialize history Bloom filter on extension startup.
 * Loads existing filter or triggers rebuild if needed.
 */
export async function initializeHistoryBloom(): Promise<void> {
  const config = await getHistoryBloomConfig();

  if (!config.enabled) {
    console.log('[BrowserDefense] History bloom is disabled');
    return;
  }

  const permission = await checkHistoryPermission();
  if (!permission.granted) {
    console.log('[BrowserDefense] History permission not granted, disabling history bloom');
    config.enabled = false;
    await saveHistoryBloomConfig(config);
    return;
  }

  // Try to load existing filter
  const filter = await loadHistoryBloom();

  if (filter) {
    console.log(
      `[BrowserDefense] History bloom loaded: ${config.domainCount} domains, ` +
        `${filter.byteLength} bytes`
    );
  } else {
    // No filter exists, trigger rebuild
    console.log('[BrowserDefense] No history bloom found, triggering rebuild');
    await rebuildHistoryBloom();
  }
}

// ============ Periodic Updates ============

/**
 * Schedule periodic history Bloom filter updates.
 * Called from background script initialization.
 */
export function scheduleHistoryBloomUpdates(): void {
  // Update every 6 hours
  chrome.alarms.create('historyBloomUpdate', {
    periodInMinutes: 6 * 60,
  });

  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'historyBloomUpdate') {
      rebuildHistoryBloom().catch((err) => {
        console.warn('[BrowserDefense] History bloom update failed:', err);
      });
    }
  });
}

// ============ Exports for Testing ============

/**
 * Reset in-memory caches. FOR TESTING ONLY.
 */
export function _resetCaches(): void {
  cachedFilter = null;
  cachedConfig = null;
}

export {
  hashDomain as _hashDomain,
  scanHistoryForDomains as _scanHistoryForDomains,
  loadHistoryBloom as _loadHistoryBloom,
  saveHistoryBloom as _saveHistoryBloom,
  HISTORY_BLOOM_DATA_KEY as _HISTORY_BLOOM_DATA_KEY,
  HISTORY_BLOOM_META_KEY as _HISTORY_BLOOM_META_KEY,
  HISTORY_BLOOM_CONFIG_KEY as _HISTORY_BLOOM_CONFIG_KEY,
};
