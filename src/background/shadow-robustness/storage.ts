/**
 * Storage Robustness for Shadow Detection (Issue #251)
 *
 * Provides:
 * - LRU eviction for shadow detection cache
 * - Graceful degradation when IndexedDB quota exceeded
 * - Recovery from corrupted storage state
 * - Bounded storage with configurable limits
 *
 * Design: Shadow detection storage failures must NEVER affect
 * core blocking or user experience.
 */

import type {
  LRUCacheEntry,
  LRUCacheConfig,
  StorageQuotaStatus,
  StorageHealthStatus,
} from '../../types/shadow-robustness';
import { DEFAULT_SHADOW_ROBUSTNESS_CONFIG } from '../../types/shadow-robustness';

// ============ Constants ============

const STORAGE_KEY_PREFIX = 'browserdefense_shadow_robust_';
const CACHE_DATA_KEY = STORAGE_KEY_PREFIX + 'cache';
const CACHE_INDEX_KEY = STORAGE_KEY_PREFIX + 'index';
const HEALTH_KEY = STORAGE_KEY_PREFIX + 'health';

// Quota thresholds
const QUOTA_WARNING_PERCENT = 80;
const QUOTA_CRITICAL_PERCENT = 95;

// ============ Storage Health Tracking ============

const storageHealth: StorageHealthStatus = {
  accessible: true,
  errorCount: 0,
  degraded: false,
};

/**
 * Get current storage health status.
 */
export function getStorageHealth(): StorageHealthStatus {
  return { ...storageHealth };
}

/**
 * Record a successful storage operation.
 */
function recordStorageSuccess(): void {
  storageHealth.accessible = true;
  storageHealth.lastSuccessfulAccess = Date.now();
  storageHealth.errorCount = 0;
  storageHealth.degraded = false;
}

/**
 * Record a storage error.
 */
function recordStorageError(error: Error): void {
  storageHealth.errorCount++;
  storageHealth.lastError = error.message;

  // After 3 consecutive errors, enter degraded mode
  if (storageHealth.errorCount >= 3) {
    storageHealth.degraded = true;
    storageHealth.accessible = false;
    console.warn('[BrowserDefense] Shadow storage entering degraded mode after', storageHealth.errorCount, 'errors');
  }
}

/**
 * Attempt to recover from degraded mode.
 */
export async function attemptStorageRecovery(): Promise<boolean> {
  if (!storageHealth.degraded) {
    return true;
  }

  try {
    // Try a simple read operation
    await chrome.storage.local.get(HEALTH_KEY);
    recordStorageSuccess();
    console.log('[BrowserDefense] Shadow storage recovered from degraded mode');
    return true;
  } catch (err) {
    console.warn('[BrowserDefense] Shadow storage recovery failed:', err);
    return false;
  }
}

// ============ Quota Management ============

/**
 * Get storage quota status.
 * Uses navigator.storage.estimate() when available.
 */
export async function getQuotaStatus(): Promise<StorageQuotaStatus> {
  try {
    // Try using StorageManager API if available
    if (navigator.storage && navigator.storage.estimate) {
      const estimate = await navigator.storage.estimate();
      const usedBytes = estimate.usage ?? 0;
      const quotaBytes = estimate.quota ?? 0;
      const usagePercent = quotaBytes > 0 ? (usedBytes / quotaBytes) * 100 : 0;

      return {
        usedBytes,
        quotaBytes,
        usagePercent,
        isNearQuota: usagePercent >= QUOTA_WARNING_PERCENT,
        isAtQuota: usagePercent >= QUOTA_CRITICAL_PERCENT,
      };
    }

    // Fallback: estimate from chrome.storage.local
    const bytesInUse = await chrome.storage.local.getBytesInUse();
    // chrome.storage.local quota is typically 10MB (10485760 bytes)
    const quotaBytes = 10 * 1024 * 1024;
    const usagePercent = (bytesInUse / quotaBytes) * 100;

    return {
      usedBytes: bytesInUse,
      quotaBytes,
      usagePercent,
      isNearQuota: usagePercent >= QUOTA_WARNING_PERCENT,
      isAtQuota: usagePercent >= QUOTA_CRITICAL_PERCENT,
    };
  } catch (err) {
    console.warn('[BrowserDefense] Failed to get quota status:', err);
    // Return safe defaults
    return {
      usedBytes: 0,
      quotaBytes: 10 * 1024 * 1024,
      usagePercent: 0,
      isNearQuota: false,
      isAtQuota: false,
    };
  }
}

// ============ LRU Cache Implementation ============

interface CacheIndex {
  /** Map of key -> last access time for LRU ordering */
  accessTimes: Record<string, number>;
  /** Map of key -> size in bytes */
  sizes: Record<string, number>;
  /** Total size in bytes */
  totalSize: number;
  /** Entry count */
  entryCount: number;
  /** Last cleanup timestamp */
  lastCleanup: number;
}

/**
 * Load cache index from storage.
 */
async function loadCacheIndex(): Promise<CacheIndex> {
  try {
    const result = await chrome.storage.local.get(CACHE_INDEX_KEY);
    const index = result[CACHE_INDEX_KEY] as CacheIndex | undefined;

    if (index) {
      recordStorageSuccess();
      return index;
    }

    return {
      accessTimes: {},
      sizes: {},
      totalSize: 0,
      entryCount: 0,
      lastCleanup: Date.now(),
    };
  } catch (err) {
    recordStorageError(err as Error);
    return {
      accessTimes: {},
      sizes: {},
      totalSize: 0,
      entryCount: 0,
      lastCleanup: Date.now(),
    };
  }
}

/**
 * Save cache index to storage.
 */
async function saveCacheIndex(index: CacheIndex): Promise<void> {
  if (storageHealth.degraded) {
    return; // Don't try to save in degraded mode
  }

  try {
    await chrome.storage.local.set({ [CACHE_INDEX_KEY]: index });
    recordStorageSuccess();
  } catch (err) {
    recordStorageError(err as Error);
  }
}

/**
 * Estimate size of a value in bytes.
 */
function estimateSize(value: unknown): number {
  try {
    return JSON.stringify(value).length * 2; // UTF-16 = 2 bytes per char
  } catch {
    return 1000; // Default estimate if stringify fails
  }
}

/**
 * Get cache key with prefix.
 */
function getCacheKey(key: string): string {
  return CACHE_DATA_KEY + ':' + key;
}

/**
 * LRU cache for shadow detection data.
 */
export class ShadowLRUCache<T> {
  private config: LRUCacheConfig;

  constructor(config: Partial<LRUCacheConfig> = {}) {
    this.config = {
      ...DEFAULT_SHADOW_ROBUSTNESS_CONFIG.cache,
      ...config,
    };
  }

  /**
   * Get a value from cache.
   * Updates access time for LRU tracking.
   */
  async get(key: string): Promise<T | null> {
    if (storageHealth.degraded) {
      return null; // Graceful degradation
    }

    try {
      const storageKey = getCacheKey(key);
      const result = await chrome.storage.local.get(storageKey);
      const entry = result[storageKey] as LRUCacheEntry<T> | undefined;

      if (!entry) {
        return null;
      }

      // Check TTL
      if (this.config.ttlMs > 0 && Date.now() - entry.createdAt > this.config.ttlMs) {
        // Entry expired, remove it
        await this.delete(key);
        return null;
      }

      // Update access time (fire-and-forget)
      this.updateAccessTime(key).catch(() => {
        // Ignore errors updating access time
      });

      recordStorageSuccess();
      return entry.value;
    } catch (err) {
      recordStorageError(err as Error);
      return null; // Graceful degradation
    }
  }

  /**
   * Set a value in cache.
   * May trigger eviction if at capacity.
   */
  async set(key: string, value: T): Promise<boolean> {
    if (storageHealth.degraded) {
      return false; // Graceful degradation
    }

    try {
      // Check quota before writing
      const quota = await getQuotaStatus();
      if (quota.isAtQuota) {
        // Try emergency eviction
        await this.evictEntries(this.config.evictionBatchSize * 2);
        const newQuota = await getQuotaStatus();
        if (newQuota.isAtQuota) {
          console.warn('[BrowserDefense] Shadow cache: quota exceeded, dropping write');
          return false;
        }
      }

      const now = Date.now();
      const sizeBytes = estimateSize(value);

      const entry: LRUCacheEntry<T> = {
        value,
        lastAccess: now,
        createdAt: now,
        sizeBytes,
      };

      // Load index
      const index = await loadCacheIndex();

      // Check if we need to evict
      if (
        index.entryCount >= this.config.maxEntries ||
        index.totalSize + sizeBytes > this.config.maxSizeBytes
      ) {
        await this.evictEntries(this.config.evictionBatchSize);
      }

      // Save entry
      const storageKey = getCacheKey(key);
      await chrome.storage.local.set({ [storageKey]: entry });

      // Update index
      const oldSize = index.sizes[key] ?? 0;
      index.accessTimes[key] = now;
      index.sizes[key] = sizeBytes;
      index.totalSize = index.totalSize - oldSize + sizeBytes;
      if (!oldSize) {
        index.entryCount++;
      }

      await saveCacheIndex(index);
      recordStorageSuccess();
      return true;
    } catch (err) {
      recordStorageError(err as Error);
      return false;
    }
  }

  /**
   * Delete a value from cache.
   */
  async delete(key: string): Promise<boolean> {
    if (storageHealth.degraded) {
      return false;
    }

    try {
      const storageKey = getCacheKey(key);
      await chrome.storage.local.remove(storageKey);

      // Update index
      const index = await loadCacheIndex();
      const size = index.sizes[key] ?? 0;
      delete index.accessTimes[key];
      delete index.sizes[key];
      index.totalSize -= size;
      index.entryCount = Math.max(0, index.entryCount - 1);

      await saveCacheIndex(index);
      recordStorageSuccess();
      return true;
    } catch (err) {
      recordStorageError(err as Error);
      return false;
    }
  }

  /**
   * Update access time for a key (for LRU tracking).
   */
  private async updateAccessTime(key: string): Promise<void> {
    const index = await loadCacheIndex();
    if (index.accessTimes[key] !== undefined) {
      index.accessTimes[key] = Date.now();
      await saveCacheIndex(index);
    }
  }

  /**
   * Evict least recently used entries.
   */
  async evictEntries(count: number): Promise<number> {
    if (storageHealth.degraded) {
      return 0;
    }

    try {
      const index = await loadCacheIndex();

      // Sort keys by access time (oldest first)
      const sortedKeys = Object.entries(index.accessTimes)
        .sort((a, b) => a[1] - b[1])
        .map(([key]) => key);

      // Evict oldest entries
      const toEvict = sortedKeys.slice(0, count);
      const keysToRemove = toEvict.map((key) => getCacheKey(key));

      if (keysToRemove.length > 0) {
        await chrome.storage.local.remove(keysToRemove);

        // Update index
        for (const key of toEvict) {
          const size = index.sizes[key] ?? 0;
          delete index.accessTimes[key];
          delete index.sizes[key];
          index.totalSize -= size;
          index.entryCount--;
        }

        index.lastCleanup = Date.now();
        await saveCacheIndex(index);

        console.log('[BrowserDefense] Shadow cache: evicted', toEvict.length, 'entries');
      }

      recordStorageSuccess();
      return toEvict.length;
    } catch (err) {
      recordStorageError(err as Error);
      return 0;
    }
  }

  /**
   * Evict expired entries (based on TTL).
   */
  async evictExpired(): Promise<number> {
    if (storageHealth.degraded || this.config.ttlMs <= 0) {
      return 0;
    }

    try {
      const index = await loadCacheIndex();
      const now = Date.now();
      const cutoff = now - this.config.ttlMs;

      // Find expired entries (created before cutoff)
      // Note: We use accessTime as a proxy since we don't store createdAt in index
      const expiredKeys = Object.entries(index.accessTimes)
        .filter(([, time]) => time < cutoff)
        .map(([key]) => key);

      if (expiredKeys.length > 0) {
        const keysToRemove = expiredKeys.map((key) => getCacheKey(key));
        await chrome.storage.local.remove(keysToRemove);

        // Update index
        for (const key of expiredKeys) {
          const size = index.sizes[key] ?? 0;
          delete index.accessTimes[key];
          delete index.sizes[key];
          index.totalSize -= size;
          index.entryCount--;
        }

        index.lastCleanup = now;
        await saveCacheIndex(index);

        console.log('[BrowserDefense] Shadow cache: evicted', expiredKeys.length, 'expired entries');
      }

      recordStorageSuccess();
      return expiredKeys.length;
    } catch (err) {
      recordStorageError(err as Error);
      return 0;
    }
  }

  /**
   * Get cache statistics.
   */
  async getStats(): Promise<{
    entryCount: number;
    totalSize: number;
    maxEntries: number;
    maxSize: number;
    lastCleanup: number;
  }> {
    const index = await loadCacheIndex();
    return {
      entryCount: index.entryCount,
      totalSize: index.totalSize,
      maxEntries: this.config.maxEntries,
      maxSize: this.config.maxSizeBytes,
      lastCleanup: index.lastCleanup,
    };
  }

  /**
   * Clear the entire cache.
   */
  async clear(): Promise<void> {
    try {
      const index = await loadCacheIndex();
      const keysToRemove = Object.keys(index.accessTimes).map((key) => getCacheKey(key));
      keysToRemove.push(CACHE_INDEX_KEY);

      await chrome.storage.local.remove(keysToRemove);
      recordStorageSuccess();
      console.log('[BrowserDefense] Shadow cache cleared');
    } catch (err) {
      recordStorageError(err as Error);
    }
  }
}

// ============ Corruption Recovery ============

/**
 * Validate cache integrity.
 * Returns true if cache appears valid.
 */
export async function validateCacheIntegrity(): Promise<{
  valid: boolean;
  errors: string[];
}> {
  const errors: string[] = [];

  try {
    const index = await loadCacheIndex();

    // Check index consistency
    const keyCount = Object.keys(index.accessTimes).length;
    const sizeCount = Object.keys(index.sizes).length;

    if (keyCount !== sizeCount) {
      errors.push('Index key count mismatch: accessTimes=' + keyCount + ', sizes=' + sizeCount);
    }

    if (keyCount !== index.entryCount) {
      errors.push('Index entry count mismatch: keys=' + keyCount + ', entryCount=' + index.entryCount);
    }

    // Check a sample of entries exist
    const sampleKeys = Object.keys(index.accessTimes).slice(0, 5);
    for (const key of sampleKeys) {
      const storageKey = getCacheKey(key);
      const result = await chrome.storage.local.get(storageKey);
      if (!result[storageKey]) {
        errors.push('Missing entry for indexed key: ' + key);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  } catch (err) {
    errors.push('Validation failed: ' + (err as Error).message);
    return { valid: false, errors };
  }
}

/**
 * Repair cache by rebuilding index from stored entries.
 * Use this if validateCacheIntegrity returns invalid.
 */
export async function repairCache(): Promise<{
  success: boolean;
  entriesRecovered: number;
  entriesLost: number;
}> {
  try {
    // Get all storage keys
    const all = await chrome.storage.local.get(null);
    const cachePrefix = CACHE_DATA_KEY + ':';

    const newIndex: CacheIndex = {
      accessTimes: {},
      sizes: {},
      totalSize: 0,
      entryCount: 0,
      lastCleanup: Date.now(),
    };

    let recovered = 0;
    let lost = 0;

    for (const [storageKey, value] of Object.entries(all)) {
      if (!storageKey.startsWith(cachePrefix)) {
        continue;
      }

      const key = storageKey.slice(cachePrefix.length);
      const entry = value as LRUCacheEntry<unknown> | undefined;

      if (entry && typeof entry.lastAccess === 'number' && typeof entry.sizeBytes === 'number') {
        newIndex.accessTimes[key] = entry.lastAccess;
        newIndex.sizes[key] = entry.sizeBytes;
        newIndex.totalSize += entry.sizeBytes;
        newIndex.entryCount++;
        recovered++;
      } else {
        // Invalid entry, remove it
        await chrome.storage.local.remove(storageKey);
        lost++;
      }
    }

    // Save rebuilt index
    await chrome.storage.local.set({ [CACHE_INDEX_KEY]: newIndex });

    console.log('[BrowserDefense] Shadow cache repaired: recovered=' + recovered + ', lost=' + lost);

    return {
      success: true,
      entriesRecovered: recovered,
      entriesLost: lost,
    };
  } catch (err) {
    console.error('[BrowserDefense] Shadow cache repair failed:', err);
    return {
      success: false,
      entriesRecovered: 0,
      entriesLost: 0,
    };
  }
}

// ============ Singleton Cache Instance ============

let defaultCache: ShadowLRUCache<unknown> | null = null;

/**
 * Get the default shadow LRU cache instance.
 */
export function getDefaultCache(): ShadowLRUCache<unknown> {
  if (!defaultCache) {
    defaultCache = new ShadowLRUCache();
  }
  return defaultCache;
}

// ============ Exports for Testing ============

export {
  loadCacheIndex as _loadCacheIndex,
  saveCacheIndex as _saveCacheIndex,
  estimateSize as _estimateSize,
  getCacheKey as _getCacheKey,
  recordStorageSuccess as _recordStorageSuccess,
  recordStorageError as _recordStorageError,
};
