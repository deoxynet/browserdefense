/**
 * BrowserDefense Storage Module
 *
 * Binary compact format for hash sets with IndexedDB persistence.
 * Supports 100k+ IOCs without size limits (unlike chrome.storage.local's 10MB limit).
 *
 * Migration: Automatically migrates existing data from chrome.storage.local to IndexedDB.
 */

export { BinaryHashSet, hexToBytes, bytesToHex } from './binary-set';
export {
  BloomFilter,
  BLOOM_STORAGE_KEYS,
  needsRebuild,
  type BloomFilterMeta,
  type BloomFilterConfig,
} from './bloom-filter';
export {
  saveIOCMetadata,
  loadIOCMetadata,
  getIOCMetadata,
  setIOCMetadata,
  removeIOCMetadata,
  clearIOCMetadata,
  shouldCaptureScreenshotForIOC,
  getScreenshotEnabledHashes,
  getMetadataStats,
  type IOCMetadata,
  type IOCMetadataMap,
} from './ioc-metadata';

import { BinaryHashSet } from './binary-set';
import { BloomFilter, BLOOM_STORAGE_KEYS, type BloomFilterMeta } from './bloom-filter';
import {
  saveBlocklistToIDB,
  loadBlocklistFromIDB,
  clearBlocklistFromIDB,
  getIDBStats,
  isIndexedDBAvailable,
  saveMetaToIDB,
  loadMetaFromIDB,
  deleteMetaFromIDB,
} from './idb';
import {
  BLOCKLIST_STORAGE_KEY,
  MIGRATION_FLAG_KEY,
} from '../config/storage-keys';

// Re-export for backwards compatibility and test access
export { BLOCKLIST_STORAGE_KEY, MIGRATION_FLAG_KEY } from '../config/storage-keys';

const LEGACY_STORAGE_KEY = BLOCKLIST_STORAGE_KEY;

/** Track if migration has been checked this session */
let migrationChecked = false;

/**
 * Check and perform migration from chrome.storage.local to IndexedDB.
 * Only runs once per session.
 */
async function ensureMigrated(): Promise<void> {
  if (migrationChecked) {
    return;
  }
  migrationChecked = true;

  // Check if already migrated
  const result = await chrome.storage.local.get(MIGRATION_FLAG_KEY);
  if (result[MIGRATION_FLAG_KEY]) {
    return;
  }

  // Check if there's legacy data to migrate
  const legacyResult = await chrome.storage.local.get(LEGACY_STORAGE_KEY);
  const legacyData = legacyResult[LEGACY_STORAGE_KEY];

  if (legacyData) {
    console.log('[BrowserDefense] Migrating blocklist from chrome.storage.local to IndexedDB...');

    try {
      // Save to IndexedDB
      await saveBlocklistToIDB(legacyData);

      // Verify migration
      const verifyData = await loadBlocklistFromIDB();
      if (verifyData === legacyData) {
        // Migration successful - remove legacy data and set flag
        await chrome.storage.local.remove(LEGACY_STORAGE_KEY);
        await chrome.storage.local.set({ [MIGRATION_FLAG_KEY]: true });
        console.log('[BrowserDefense] Migration complete');
      } else {
        console.error('[BrowserDefense] Migration verification failed, keeping legacy data');
      }
    } catch (err) {
      console.error('[BrowserDefense] Migration failed:', err);
      // Keep legacy data on failure - will retry next session
    }
  } else {
    // No legacy data, just set the flag
    await chrome.storage.local.set({ [MIGRATION_FLAG_KEY]: true });
  }
}

/**
 * Save a BinaryHashSet to storage (IndexedDB).
 */
export async function saveBlocklist(hashSet: BinaryHashSet): Promise<void> {
  if (!isIndexedDBAvailable()) {
    // Fallback to chrome.storage.local if IndexedDB not available
    const data = hashSet.serialize();
    await chrome.storage.local.set({ [LEGACY_STORAGE_KEY]: data });
    return;
  }

  await ensureMigrated();
  const data = hashSet.serialize();
  await saveBlocklistToIDB(data);
}

/**
 * Load a BinaryHashSet from storage (IndexedDB with migration).
 * Returns an empty set if nothing is stored.
 */
export async function loadBlocklist(): Promise<BinaryHashSet> {
  if (!isIndexedDBAvailable()) {
    // Fallback to chrome.storage.local if IndexedDB not available
    const result = await chrome.storage.local.get(LEGACY_STORAGE_KEY);
    const data = result[LEGACY_STORAGE_KEY];
    if (!data) {
      return new BinaryHashSet();
    }
    return BinaryHashSet.deserialize(data);
  }

  await ensureMigrated();

  const data = await loadBlocklistFromIDB();

  if (!data) {
    return new BinaryHashSet();
  }

  return BinaryHashSet.deserialize(data);
}

/**
 * Clear the stored blocklist.
 */
export async function clearBlocklist(): Promise<void> {
  if (!isIndexedDBAvailable()) {
    await chrome.storage.local.remove(LEGACY_STORAGE_KEY);
    return;
  }

  await clearBlocklistFromIDB();
}

/**
 * Get storage stats for the blocklist.
 */
export async function getBlocklistStats(): Promise<{
  count: number;
  bytesUsed: number;
  storageType: 'indexeddb' | 'chrome.storage.local';
}> {
  if (!isIndexedDBAvailable()) {
    const result = await chrome.storage.local.get(LEGACY_STORAGE_KEY);
    const data = result[LEGACY_STORAGE_KEY] as string | undefined;
    const bytesUsed = data ? data.length : 0;
    const count = data ? Math.floor(atob(data).length / 32) : 0;
    return { count, bytesUsed, storageType: 'chrome.storage.local' };
  }

  await ensureMigrated();
  const stats = await getIDBStats();

  const count =
    stats.dataSize > 0
      ? Math.floor(atob((await loadBlocklistFromIDB()) || '').length / 32)
      : 0;

  return {
    count,
    bytesUsed: stats.dataSize,
    storageType: 'indexeddb',
  };
}

/**
 * Reset migration state (for testing).
 */
export function resetMigrationState(): void {
  migrationChecked = false;
}

// ============ Bloom Filter Storage ============

/**
 * Save a BloomFilter to storage (IndexedDB).
 * Stores both the binary data and metadata.
 */
export async function saveBloomFilter(filter: BloomFilter): Promise<void> {
  if (!isIndexedDBAvailable()) {
    // Fallback to chrome.storage.local
    const data = filter.serializeToBase64();
    const meta = filter.getMeta();
    await chrome.storage.local.set({
      [BLOOM_STORAGE_KEYS.DATA]: data,
      [BLOOM_STORAGE_KEYS.META]: meta,
    });
    return;
  }

  const data = filter.serializeToBase64();
  const meta = filter.getMeta();

  await Promise.all([
    saveMetaToIDB(BLOOM_STORAGE_KEYS.DATA, data),
    saveMetaToIDB(BLOOM_STORAGE_KEYS.META, meta),
  ]);
}

/**
 * Load a BloomFilter from storage (IndexedDB).
 * Returns null if no bloom filter is stored.
 */
export async function loadBloomFilter(): Promise<BloomFilter | null> {
  if (!isIndexedDBAvailable()) {
    // Fallback to chrome.storage.local
    const result = await chrome.storage.local.get([
      BLOOM_STORAGE_KEYS.DATA,
      BLOOM_STORAGE_KEYS.META,
    ]);
    const data = result[BLOOM_STORAGE_KEYS.DATA] as string | undefined;
    const meta = result[BLOOM_STORAGE_KEYS.META] as BloomFilterMeta | undefined;

    if (!data || !meta) {
      return null;
    }

    return BloomFilter.deserializeFromBase64(data, meta);
  }

  const [data, meta] = await Promise.all([
    loadMetaFromIDB<string>(BLOOM_STORAGE_KEYS.DATA),
    loadMetaFromIDB<BloomFilterMeta>(BLOOM_STORAGE_KEYS.META),
  ]);

  if (!data || !meta) {
    return null;
  }

  return BloomFilter.deserializeFromBase64(data, meta);
}

/**
 * Clear the stored bloom filter.
 */
export async function clearBloomFilter(): Promise<void> {
  if (!isIndexedDBAvailable()) {
    await chrome.storage.local.remove([BLOOM_STORAGE_KEYS.DATA, BLOOM_STORAGE_KEYS.META]);
    return;
  }

  await Promise.all([
    deleteMetaFromIDB(BLOOM_STORAGE_KEYS.DATA),
    deleteMetaFromIDB(BLOOM_STORAGE_KEYS.META),
  ]);
}

/**
 * Mark the stored bloom filter as dirty (needs rebuild).
 * Call this when items are deleted from the blocklist.
 */
export async function markBloomFilterDirty(): Promise<void> {
  const filter = await loadBloomFilter();
  if (filter) {
    filter.markDirty();
    await saveBloomFilter(filter);
  }
}

/**
 * Get bloom filter metadata without loading the full filter.
 */
export async function getBloomFilterMeta(): Promise<BloomFilterMeta | null> {
  if (!isIndexedDBAvailable()) {
    const result = await chrome.storage.local.get(BLOOM_STORAGE_KEYS.META);
    return (result[BLOOM_STORAGE_KEYS.META] as BloomFilterMeta) ?? null;
  }

  return loadMetaFromIDB<BloomFilterMeta>(BLOOM_STORAGE_KEYS.META);
}

/**
 * Build a new bloom filter from a BinaryHashSet.
 * Automatically sizes the filter based on the hash set size.
 *
 * @param hashSet - The source hash set to build from
 * @param sourceVersion - Optional version number for tracking rebuilds
 * @returns The newly built BloomFilter
 */
export function buildBloomFilter(
  hashSet: BinaryHashSet,
  sourceVersion?: number
): BloomFilter {
  const itemCount = hashSet.count;
  const filter = BloomFilter.create({
    expectedItems: Math.max(itemCount, 100), // Minimum 100 items for reasonable sizing
  });

  for (const hash of hashSet.hashes()) {
    filter.add(hash);
  }

  filter.markClean(sourceVersion);
  return filter;
}

/**
 * Rebuild and save the bloom filter from the current blocklist.
 * Call this periodically or when the filter is dirty.
 *
 * @param sourceVersion - Optional version number for tracking
 * @returns The rebuilt filter, or null if no blocklist exists
 */
export async function rebuildBloomFilter(sourceVersion?: number): Promise<BloomFilter | null> {
  const hashSet = await loadBlocklist();
  if (hashSet.count === 0) {
    await clearBloomFilter();
    return null;
  }

  const filter = buildBloomFilter(hashSet, sourceVersion);
  await saveBloomFilter(filter);

  console.log(
    `[BrowserDefense] Bloom filter rebuilt: ${filter.itemCount} items, ` +
      `${filter.byteLength} bytes, ~${(filter.estimatedFalsePositiveRate * 100).toFixed(2)}% FPR`
  );

  return filter;
}

// Re-export IDB utilities for direct access if needed
export {
  saveBlocklistToIDB,
  loadBlocklistFromIDB,
  clearBlocklistFromIDB,
  isIndexedDBAvailable,
  closeDB,
} from './idb';
