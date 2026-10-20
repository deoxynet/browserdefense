/**
 * Tests for IndexedDB storage module.
 *
 * Uses fake-indexeddb to mock IndexedDB in Node.js environment.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';

// Must import after fake-indexeddb is set up
import {
  saveBlocklistToIDB,
  loadBlocklistFromIDB,
  clearBlocklistFromIDB,
  saveMetaToIDB,
  loadMetaFromIDB,
  deleteMetaFromIDB,
  getIDBStats,
  isIndexedDBAvailable,
  closeDB,
} from '../src/storage/idb';

describe('IndexedDB Storage', () => {
  beforeEach(async () => {
    // Close any existing connection before each test
    await closeDB();
    // Clear the fake IndexedDB
    indexedDB.deleteDatabase('browserdefense');
  });

  afterEach(async () => {
    await closeDB();
  });

  describe('isIndexedDBAvailable', () => {
    it('should return true when IndexedDB is available', () => {
      expect(isIndexedDBAvailable()).toBe(true);
    });
  });

  describe('blocklist operations', () => {
    it('should save and load blocklist data', async () => {
      const testData = 'dGVzdCBkYXRh'; // "test data" in base64

      await saveBlocklistToIDB(testData);
      const loaded = await loadBlocklistFromIDB();

      expect(loaded).toBe(testData);
    });

    it('should return null when no blocklist exists', async () => {
      const loaded = await loadBlocklistFromIDB();
      expect(loaded).toBeNull();
    });

    it('should clear blocklist data', async () => {
      const testData = 'dGVzdCBkYXRh';

      await saveBlocklistToIDB(testData);
      await clearBlocklistFromIDB();

      const loaded = await loadBlocklistFromIDB();
      expect(loaded).toBeNull();
    });

    it('should overwrite existing data on save', async () => {
      const data1 = 'ZGF0YTE='; // "data1"
      const data2 = 'ZGF0YTI='; // "data2"

      await saveBlocklistToIDB(data1);
      await saveBlocklistToIDB(data2);

      const loaded = await loadBlocklistFromIDB();
      expect(loaded).toBe(data2);
    });

    it('should handle large blocklist data', async () => {
      // Generate ~1MB of base64 data (simulating ~750KB of binary data)
      const largeData = 'A'.repeat(1_000_000);

      await saveBlocklistToIDB(largeData);
      const loaded = await loadBlocklistFromIDB();

      expect(loaded).toBe(largeData);
      expect(loaded?.length).toBe(1_000_000);
    });
  });

  describe('metadata operations', () => {
    it('should save and load metadata', async () => {
      const meta = { version: 1, updatedAt: '2024-01-01' };

      await saveMetaToIDB('updateInfo', meta);
      const loaded = await loadMetaFromIDB<typeof meta>('updateInfo');

      expect(loaded).toEqual(meta);
    });

    it('should return null for non-existent key', async () => {
      const loaded = await loadMetaFromIDB('nonexistent');
      expect(loaded).toBeNull();
    });

    it('should delete metadata', async () => {
      await saveMetaToIDB('key', { value: 123 });
      await deleteMetaFromIDB('key');

      const loaded = await loadMetaFromIDB('key');
      expect(loaded).toBeNull();
    });

    it('should handle different metadata types', async () => {
      await saveMetaToIDB('string', 'hello');
      await saveMetaToIDB('number', 42);
      await saveMetaToIDB('boolean', true);
      await saveMetaToIDB('array', [1, 2, 3]);
      await saveMetaToIDB('object', { nested: { value: 'test' } });

      expect(await loadMetaFromIDB('string')).toBe('hello');
      expect(await loadMetaFromIDB('number')).toBe(42);
      expect(await loadMetaFromIDB('boolean')).toBe(true);
      expect(await loadMetaFromIDB('array')).toEqual([1, 2, 3]);
      expect(await loadMetaFromIDB('object')).toEqual({ nested: { value: 'test' } });
    });
  });

  describe('getIDBStats', () => {
    it('should report no data when empty', async () => {
      const stats = await getIDBStats();

      expect(stats.hasData).toBe(false);
      expect(stats.dataSize).toBe(0);
    });

    it('should report data size when blocklist exists', async () => {
      const testData = 'dGVzdCBkYXRh'; // 12 characters

      await saveBlocklistToIDB(testData);
      const stats = await getIDBStats();

      expect(stats.hasData).toBe(true);
      expect(stats.dataSize).toBe(12);
    });
  });

  describe('concurrent operations', () => {
    it('should handle concurrent saves', async () => {
      const saves = [];
      for (let i = 0; i < 10; i++) {
        saves.push(saveBlocklistToIDB(`data${i}`));
      }

      await Promise.all(saves);

      // Last write wins - order isn't guaranteed with concurrent writes
      const loaded = await loadBlocklistFromIDB();
      expect(loaded).toMatch(/^data\d$/);
    });

    it('should handle concurrent reads', async () => {
      const testData = 'concurrent_test';
      await saveBlocklistToIDB(testData);

      const reads = [];
      for (let i = 0; i < 10; i++) {
        reads.push(loadBlocklistFromIDB());
      }

      const results = await Promise.all(reads);
      results.forEach((result) => {
        expect(result).toBe(testData);
      });
    });
  });
});

describe('Storage Migration', () => {
  // These tests require mocking chrome.storage.local
  // which is handled by the existing chrome mock in the test setup

  const mockChromeStorage: Record<string, unknown> = {};

  beforeEach(async () => {
    await closeDB();
    indexedDB.deleteDatabase('browserdefense');

    // Reset migration state for this test
    const { resetMigrationState } = await import('../src/storage/index');
    resetMigrationState();

    // Reset chrome.storage.local mock
    Object.keys(mockChromeStorage).forEach((key) => delete mockChromeStorage[key]);

    // Mock chrome.storage.local for migration tests
    globalThis.chrome = {
      storage: {
        local: {
          get: vi.fn().mockImplementation(async (keys: string | string[]) => {
            if (typeof keys === 'string') {
              return { [keys]: mockChromeStorage[keys] };
            }
            const result: Record<string, unknown> = {};
            keys.forEach((key) => {
              result[key] = mockChromeStorage[key];
            });
            return result;
          }),
          set: vi.fn().mockImplementation(async (items: Record<string, unknown>) => {
            Object.assign(mockChromeStorage, items);
          }),
          remove: vi.fn().mockImplementation(async (keys: string | string[]) => {
            const keyArray = typeof keys === 'string' ? [keys] : keys;
            keyArray.forEach((key) => delete mockChromeStorage[key]);
          }),
        },
      },
    } as unknown as typeof chrome;
  });

  afterEach(async () => {
    await closeDB();
  });

  it('should migrate from chrome.storage.local to IndexedDB', async () => {
    // Import storage module after mock is set up
    const { loadBlocklist } = await import('../src/storage/index');

    // Set up legacy data - must be valid BinaryHashSet format (32 bytes per hash)
    // Create a valid 32-byte hash (all zeros) encoded as base64
    const validHash = new Uint8Array(32).fill(0);
    const legacyData = btoa(String.fromCharCode(...validHash));
    mockChromeStorage['browserdefense_blocklist'] = legacyData;

    // First load should trigger migration
    await loadBlocklist();

    // Check IndexedDB has data
    const idbData = await loadBlocklistFromIDB();
    expect(idbData).toBe(legacyData);

    // Check legacy data was removed and migration flag set
    expect(mockChromeStorage['browserdefense_blocklist']).toBeUndefined();
    expect(mockChromeStorage['browserdefense_idb_migrated']).toBe(true);
  });
});
