/**
 * Tests for Binary Bloom Filter
 *
 * Reference: Issue #160
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  BloomFilter,
  BLOOM_STORAGE_KEYS,
  needsRebuild,
  type BloomFilterMeta,
  type BloomFilterConfig,
} from '../src/storage/bloom-filter';

describe('BloomFilter', () => {
  describe('construction', () => {
    it('should create a filter with specified size', () => {
      const filter = new BloomFilter(10000);
      expect(filter.bitCount).toBeGreaterThanOrEqual(10000);
      expect(filter.itemCount).toBe(0);
      expect(filter.isDirty).toBe(false);
    });

    it('should enforce minimum size', () => {
      const filter = new BloomFilter(100); // Below MIN_BITS (1024)
      expect(filter.bitCount).toBeGreaterThanOrEqual(1024);
    });

    it('should reject oversized filters', () => {
      expect(() => new BloomFilter(2 * 1024 * 1024 * 1024)).toThrow(/too large/);
    });

    it('should use default hash count', () => {
      const filter = new BloomFilter(10000);
      expect(filter.hashCount).toBe(7); // DEFAULT_K
    });

    it('should accept custom hash count', () => {
      const filter = new BloomFilter(10000, 5);
      expect(filter.hashCount).toBe(5);
    });
  });

  describe('BloomFilter.create()', () => {
    it('should create optimally sized filter for expected items', () => {
      const filter = BloomFilter.create({ expectedItems: 1000 });
      expect(filter.bitCount).toBeGreaterThan(1000); // Should be ~10x for 1% FPR
      expect(filter.itemCount).toBe(0);
    });

    it('should respect custom false positive rate', () => {
      const filter1 = BloomFilter.create({ expectedItems: 1000, falsePositiveRate: 0.01 });
      const filter2 = BloomFilter.create({ expectedItems: 1000, falsePositiveRate: 0.001 });
      // Tighter FPR needs more bits
      expect(filter2.bitCount).toBeGreaterThan(filter1.bitCount);
    });

    it('should handle very small item counts', () => {
      const filter = BloomFilter.create({ expectedItems: 1 });
      expect(filter.bitCount).toBeGreaterThanOrEqual(1024); // Min size
    });
  });

  describe('add and mightContain', () => {
    let filter: BloomFilter;
    const testHash = new Uint8Array(32);
    const testHash2 = new Uint8Array(32);

    beforeEach(() => {
      filter = BloomFilter.create({ expectedItems: 100 });
      // Create different test hashes
      testHash.fill(0xAB);
      testHash2.fill(0xCD);
    });

    it('should find added items', () => {
      filter.add(testHash);
      expect(filter.mightContain(testHash)).toBe(true);
    });

    it('should increment item count on add', () => {
      expect(filter.itemCount).toBe(0);
      filter.add(testHash);
      expect(filter.itemCount).toBe(1);
      filter.add(testHash2);
      expect(filter.itemCount).toBe(2);
    });

    it('should likely not find items that were never added', () => {
      filter.add(testHash);
      // Not guaranteed, but with proper sizing should be very unlikely
      const notAdded = new Uint8Array(32);
      notAdded.fill(0xFF);
      // This is probabilistic - for a properly sized filter, FP rate should be low
      // We test with a filter much larger than needed to ensure this passes reliably
      const largeFilter = BloomFilter.create({ expectedItems: 100000 });
      largeFilter.add(testHash);
      expect(largeFilter.mightContain(notAdded)).toBe(false);
    });

    it('should handle ArrayBuffer input', () => {
      const buffer = testHash.buffer;
      filter.add(buffer);
      expect(filter.mightContain(buffer)).toBe(true);
    });
  });

  describe('addHex and mightContainHex', () => {
    let filter: BloomFilter;

    beforeEach(() => {
      filter = BloomFilter.create({ expectedItems: 100 });
    });

    it('should add hex strings', () => {
      const hexHash = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
      filter.addHex(hexHash);
      expect(filter.mightContainHex(hexHash)).toBe(true);
    });

    it('should handle 0x prefix', () => {
      const hexHash = '0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
      filter.addHex(hexHash);
      expect(filter.mightContainHex(hexHash)).toBe(true);
    });

    it('should be case insensitive', () => {
      const hexLower = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
      const hexUpper = 'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789';
      filter.addHex(hexLower);
      expect(filter.mightContainHex(hexUpper)).toBe(true);
    });
  });

  describe('dirty flag', () => {
    let filter: BloomFilter;

    beforeEach(() => {
      filter = BloomFilter.create({ expectedItems: 100 });
    });

    it('should start clean', () => {
      expect(filter.isDirty).toBe(false);
    });

    it('should mark dirty', () => {
      filter.markDirty();
      expect(filter.isDirty).toBe(true);
    });

    it('should mark clean with timestamp', () => {
      filter.markDirty();
      filter.markClean();
      expect(filter.isDirty).toBe(false);
      expect(filter.lastRebuild).toBeDefined();
    });

    it('should track source version', () => {
      filter.markClean(42);
      expect(filter.sourceVersion).toBe(42);
    });
  });

  describe('reset', () => {
    it('should clear all state', () => {
      const filter = BloomFilter.create({ expectedItems: 100 });
      const hash = new Uint8Array(32);
      hash.fill(0xAB);

      filter.add(hash);
      filter.markDirty();
      filter.markClean(1);

      filter.reset();

      expect(filter.itemCount).toBe(0);
      expect(filter.isDirty).toBe(false);
      expect(filter.lastRebuild).toBeUndefined();
      expect(filter.sourceVersion).toBeUndefined();
      expect(filter.mightContain(hash)).toBe(false);
    });
  });

  describe('serialization', () => {
    let filter: BloomFilter;
    const testHash = new Uint8Array(32);

    beforeEach(() => {
      filter = BloomFilter.create({ expectedItems: 100 });
      testHash.fill(0xAB);
    });

    it('should serialize to Uint8Array', () => {
      filter.add(testHash);
      const serialized = filter.serialize();
      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBe(filter.byteLength);
    });

    it('should serialize to base64', () => {
      filter.add(testHash);
      const base64 = filter.serializeToBase64();
      expect(typeof base64).toBe('string');
      expect(base64.length).toBeGreaterThan(0);
    });

    it('should deserialize and preserve items', () => {
      filter.add(testHash);
      filter.markClean(5);

      const data = filter.serialize();
      const meta = filter.getMeta();

      const restored = BloomFilter.deserialize(data, meta);
      expect(restored.mightContain(testHash)).toBe(true);
      expect(restored.itemCount).toBe(filter.itemCount);
      expect(restored.isDirty).toBe(false);
      expect(restored.sourceVersion).toBe(5);
    });

    it('should deserialize from base64', () => {
      filter.add(testHash);

      const base64 = filter.serializeToBase64();
      const meta = filter.getMeta();

      const restored = BloomFilter.deserializeFromBase64(base64, meta);
      expect(restored.mightContain(testHash)).toBe(true);
    });
  });

  describe('getMeta', () => {
    it('should return complete metadata', () => {
      const filter = BloomFilter.create({ expectedItems: 100 });
      const hash = new Uint8Array(32);
      hash.fill(0xAB);
      filter.add(hash);
      filter.markClean(42);

      const meta = filter.getMeta();
      expect(meta.itemCount).toBe(1);
      expect(meta.bitCount).toBeGreaterThan(0);
      expect(meta.hashCount).toBeGreaterThan(0);
      expect(meta.isDirty).toBe(false);
      expect(meta.lastRebuild).toBeDefined();
      expect(meta.sourceVersion).toBe(42);
    });
  });

  describe('statistics', () => {
    it('should calculate estimated false positive rate', () => {
      const filter = BloomFilter.create({ expectedItems: 1000 });
      expect(filter.estimatedFalsePositiveRate).toBe(0); // Empty filter

      // Add some items
      for (let i = 0; i < 100; i++) {
        const hash = new Uint8Array(32);
        hash[0] = i;
        filter.add(hash);
      }

      const fpr = filter.estimatedFalsePositiveRate;
      expect(fpr).toBeGreaterThan(0);
      expect(fpr).toBeLessThan(0.1); // Should be quite low with 1000 expected, only 100 added
    });

    it('should calculate fill ratio', () => {
      const filter = new BloomFilter(1024); // Small filter for testing
      expect(filter.fillRatio).toBe(0);

      const hash = new Uint8Array(32);
      hash.fill(0xAB);
      filter.add(hash);

      expect(filter.fillRatio).toBeGreaterThan(0);
      expect(filter.fillRatio).toBeLessThan(1);
    });
  });

  describe('fromHashes factory', () => {
    it('should build filter from hash iterator', () => {
      const hashes = [
        new Uint8Array(32).fill(0x11),
        new Uint8Array(32).fill(0x22),
        new Uint8Array(32).fill(0x33),
      ];

      const filter = BloomFilter.fromHashes(hashes, 3, 1);

      expect(filter.itemCount).toBe(3);
      expect(filter.isDirty).toBe(false);
      expect(filter.sourceVersion).toBe(1);

      for (const hash of hashes) {
        expect(filter.mightContain(hash)).toBe(true);
      }
    });
  });

  describe('fromHexHashes factory', () => {
    it('should build filter from hex strings', () => {
      const hexHashes = [
        'a'.repeat(64),
        'b'.repeat(64),
        'c'.repeat(64),
      ];

      const filter = BloomFilter.fromHexHashes(hexHashes, 3, 2);

      expect(filter.itemCount).toBe(3);
      expect(filter.sourceVersion).toBe(2);

      for (const hex of hexHashes) {
        expect(filter.mightContainHex(hex)).toBe(true);
      }
    });
  });
});

describe('needsRebuild', () => {
  it('should return true if dirty', () => {
    const meta: BloomFilterMeta = {
      itemCount: 100,
      bitCount: 10000,
      hashCount: 7,
      isDirty: true,
    };
    expect(needsRebuild(meta)).toBe(true);
  });

  it('should return true if source version mismatch', () => {
    const meta: BloomFilterMeta = {
      itemCount: 100,
      bitCount: 10000,
      hashCount: 7,
      isDirty: false,
      sourceVersion: 1,
    };
    expect(needsRebuild(meta, 2)).toBe(true);
  });

  it('should return false if versions match', () => {
    const meta: BloomFilterMeta = {
      itemCount: 100,
      bitCount: 10000,
      hashCount: 7,
      isDirty: false,
      sourceVersion: 5,
    };
    expect(needsRebuild(meta, 5)).toBe(false);
  });

  it('should return true if filter is overfilled', () => {
    const meta: BloomFilterMeta = {
      itemCount: 2000,
      bitCount: 10000, // Only 10000 bits for 2000 items = 5 bits/item (overfilled)
      hashCount: 7,
      isDirty: false,
    };
    // Default threshold is 0.5, with BITS_PER_ITEM=10, 2000 items need 20000 bits
    // estimatedFill = 20000/10000 = 2.0 (clamped to 1.0), which > 0.5
    expect(needsRebuild(meta)).toBe(true);
  });

  it('should respect custom fill threshold', () => {
    const meta: BloomFilterMeta = {
      itemCount: 300,
      bitCount: 10000,
      hashCount: 7,
      isDirty: false,
    };
    // 300 items * 10 bits = 3000, fill = 3000/10000 = 0.3
    expect(needsRebuild(meta, undefined, 0.2)).toBe(true); // 0.3 > 0.2
    expect(needsRebuild(meta, undefined, 0.5)).toBe(false); // 0.3 < 0.5
  });
});

describe('BLOOM_STORAGE_KEYS', () => {
  it('should have correct keys', () => {
    expect(BLOOM_STORAGE_KEYS.DATA).toBe('bloom_data');
    expect(BLOOM_STORAGE_KEYS.META).toBe('bloom_meta');
  });
});

describe('False positive guarantees', () => {
  it('should NEVER produce false negatives', () => {
    // This is the critical property of bloom filters
    const filter = BloomFilter.create({ expectedItems: 1000 });
    const hashes: Uint8Array[] = [];

    // Add 1000 random hashes
    for (let i = 0; i < 1000; i++) {
      const hash = new Uint8Array(32);
      // Create pseudo-random but deterministic hashes
      for (let j = 0; j < 32; j++) {
        hash[j] = (i * 31 + j * 17) % 256;
      }
      hashes.push(hash);
      filter.add(hash);
    }

    // EVERY added hash MUST be found
    for (const hash of hashes) {
      expect(filter.mightContain(hash)).toBe(true);
    }
  });
});
