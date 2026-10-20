/**
 * DOM Signature Store Tests
 *
 * Tests for the DOM signature storage layer including:
 * - Exact hash matching with BinaryHashSet
 * - LSH band indexing for similarity search
 * - Metadata storage and retrieval
 * - Serialization/deserialization
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock chrome APIs before importing
const mockStorage = {
  local: {
    get: vi.fn(),
    set: vi.fn(),
  },
};

globalThis.chrome = {
  storage: mockStorage,
} as unknown as typeof chrome;

// Import after mocking
import {
  initDOMSignatureStore,
  saveDOMSignatureStore,
  addDOMSignature,
  removeDOMSignature,
  hasExactMatch,
  getMetadata,
  findLSHCandidates,
  getLSHSignature,
  clearDOMSignatureStore,
  bulkLoadSignatures,
  getDOMSignatureStats,
  setStoreVersion,
  getStoreVersion,
  pruneExpiredSignatures,
  saveDOMSignatureUpdateMeta,
  loadDOMSignatureUpdateMeta,
  _extractBands,
  _NUM_BANDS,
  _ROWS_PER_BAND,
  _EXPECTED_SKETCH_LENGTH,
} from '../src/storage/dom-sig-store';
import type { DOMSignatureEntry } from '../src/types/dom-sig-manifest';

// Helper to generate valid 64-char hex hash
function generateHash(seed: number = 0): string {
  const hex = '0123456789abcdef';
  let hash = '';
  for (let i = 0; i < 64; i++) {
    hash += hex[(seed + i) % 16];
  }
  return hash;
}

// Helper to generate valid 512-char LSH sketch
function generateSketch(seed: number = 0): string {
  const hex = '0123456789abcdef';
  let sketch = '';
  for (let i = 0; i < 512; i++) {
    sketch += hex[(seed + i) % 16];
  }
  return sketch;
}

describe('DOM Signature Store', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    mockStorage.local.get.mockResolvedValue({});
    mockStorage.local.set.mockResolvedValue(undefined);
    // Initialize with empty store
    await initDOMSignatureStore();
    clearDOMSignatureStore();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Constants', () => {
    it('should have correct band configuration', () => {
      expect(_NUM_BANDS).toBe(8);
      expect(_ROWS_PER_BAND).toBe(8);
      expect(_EXPECTED_SKETCH_LENGTH).toBe(512); // 8 * 8 * 8
    });
  });

  describe('initDOMSignatureStore', () => {
    it('should initialize empty store when no data exists', async () => {
      mockStorage.local.get.mockResolvedValue({});
      await initDOMSignatureStore();

      const stats = getDOMSignatureStats();
      expect(stats.exactCount).toBe(0);
      expect(stats.lshCount).toBe(0);
      expect(stats.version).toBe(0);
    });

    it('should load existing data from storage', async () => {
      // This would require more complex mocking of the serialized format
      // For now, just verify it doesn't throw
      mockStorage.local.get.mockResolvedValue({});
      await expect(initDOMSignatureStore()).resolves.not.toThrow();
    });
  });

  describe('addDOMSignature', () => {
    it('should add exact-match-only signature', () => {
      const hash = generateHash(1);
      const entry: DOMSignatureEntry = {
        hash,
        confidence: 90,
        action: 'block',
      };

      addDOMSignature(entry);

      expect(hasExactMatch(hash)).toBe(true);
      const metadata = getMetadata(hash);
      expect(metadata?.confidence).toBe(90);
      expect(metadata?.action).toBe('block');
    });

    it('should add signature with LSH sketches', () => {
      const hash = generateHash(2);
      const entry: DOMSignatureEntry = {
        hash,
        confidence: 85,
        action: 'shadow',
        kitId: 'test-kit',
        lsh: {
          dom_layout: generateSketch(1),
          form_structure: generateSketch(2),
          script_structure: generateSketch(3),
        },
        similarityThreshold: 0.9,
      };

      addDOMSignature(entry);

      expect(hasExactMatch(hash)).toBe(true);
      const lshSig = getLSHSignature(hash);
      expect(lshSig).toBeDefined();
      expect(lshSig?.kitId).toBe('test-kit');
      expect(lshSig?.similarityThreshold).toBe(0.9);
    });

    it('should store metadata correctly', () => {
      const hash = generateHash(3);
      const entry: DOMSignatureEntry = {
        hash,
        confidence: 75,
        action: 'alert',
        kitId: 'phish-kit-123',
        expiresAt: Date.now() + 86400000,
        captureScreenshot: true,
      };

      addDOMSignature(entry);

      const metadata = getMetadata(hash);
      expect(metadata).toBeDefined();
      expect(metadata?.confidence).toBe(75);
      expect(metadata?.action).toBe('alert');
      expect(metadata?.kitId).toBe('phish-kit-123');
      expect(metadata?.expiresAt).toBeGreaterThan(Date.now());
      expect(metadata?.captureScreenshot).toBe(true);
    });

    it('should use default similarity threshold when not provided', () => {
      const hash = generateHash(4);
      const entry: DOMSignatureEntry = {
        hash,
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: generateSketch(10),
          form_structure: generateSketch(11),
          script_structure: generateSketch(12),
        },
      };

      addDOMSignature(entry);

      const lshSig = getLSHSignature(hash);
      expect(lshSig?.similarityThreshold).toBe(0.85); // Default
    });
  });

  describe('removeDOMSignature', () => {
    it('should remove existing signature', () => {
      const hash = generateHash(5);
      addDOMSignature({
        hash,
        confidence: 90,
        action: 'block',
      });

      expect(hasExactMatch(hash)).toBe(true);

      const removed = removeDOMSignature(hash);
      expect(removed).toBe(true);
      expect(hasExactMatch(hash)).toBe(false);
      expect(getMetadata(hash)).toBeUndefined();
    });

    it('should return false for non-existent signature', () => {
      const hash = generateHash(6);
      const removed = removeDOMSignature(hash);
      expect(removed).toBe(false);
    });

    it('should remove LSH index entries', () => {
      const hash = generateHash(7);
      const sketch = generateSketch(20);
      addDOMSignature({
        hash,
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: sketch,
          form_structure: generateSketch(21),
          script_structure: generateSketch(22),
        },
      });

      expect(getLSHSignature(hash)).toBeDefined();

      removeDOMSignature(hash);

      expect(getLSHSignature(hash)).toBeUndefined();
    });
  });

  describe('hasExactMatch', () => {
    it('should return true for existing hash', () => {
      const hash = generateHash(8);
      addDOMSignature({
        hash,
        confidence: 90,
        action: 'block',
      });

      expect(hasExactMatch(hash)).toBe(true);
    });

    it('should return false for non-existent hash', () => {
      const hash = generateHash(9);
      expect(hasExactMatch(hash)).toBe(false);
    });

    it('should handle case-insensitive matching', () => {
      const hashLower = generateHash(10);
      const hashUpper = hashLower.toUpperCase();

      addDOMSignature({
        hash: hashLower,
        confidence: 90,
        action: 'block',
      });

      // Binary set stores bytes, so case shouldn't matter for hex
      expect(hasExactMatch(hashLower)).toBe(true);
      expect(hasExactMatch(hashUpper)).toBe(true);
    });
  });

  describe('findLSHCandidates', () => {
    it('should find candidates with matching bands', () => {
      const hash = generateHash(11);
      const sketch = generateSketch(30);

      addDOMSignature({
        hash,
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: sketch,
          form_structure: generateSketch(31),
          script_structure: generateSketch(32),
        },
      });

      // Search with same sketch should find the signature
      const candidates = findLSHCandidates(
        sketch,
        generateSketch(31),
        generateSketch(32)
      );

      expect(candidates.size).toBeGreaterThan(0);
      expect(candidates.has(hash.toLowerCase())).toBe(true);
    });

    it('should return empty set when no matches', () => {
      const hash = generateHash(12);
      addDOMSignature({
        hash,
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: generateSketch(40),
          form_structure: generateSketch(41),
          script_structure: generateSketch(42),
        },
      });

      // Search with completely different sketches
      const candidates = findLSHCandidates(
        generateSketch(100),
        generateSketch(101),
        generateSketch(102)
      );

      // Should not find any candidates (different sketches)
      expect(candidates.has(hash.toLowerCase())).toBe(false);
    });
  });

  describe('bulkLoadSignatures', () => {
    it('should clear existing and load new signatures', () => {
      // Add initial signature
      addDOMSignature({
        hash: generateHash(13),
        confidence: 90,
        action: 'block',
      });

      expect(getDOMSignatureStats().exactCount).toBe(1);

      // Bulk load new signatures
      const entries: DOMSignatureEntry[] = [
        { hash: generateHash(14), confidence: 80, action: 'block' },
        { hash: generateHash(15), confidence: 85, action: 'shadow' },
        { hash: generateHash(16), confidence: 70, action: 'alert' },
      ];

      bulkLoadSignatures(entries);

      const stats = getDOMSignatureStats();
      expect(stats.exactCount).toBe(3);

      // Original signature should be gone
      expect(hasExactMatch(generateHash(13))).toBe(false);

      // New signatures should exist
      expect(hasExactMatch(generateHash(14))).toBe(true);
      expect(hasExactMatch(generateHash(15))).toBe(true);
      expect(hasExactMatch(generateHash(16))).toBe(true);
    });
  });

  describe('pruneExpiredSignatures', () => {
    it('should remove expired signatures', () => {
      const expiredHash = generateHash(17);
      const validHash = generateHash(18);

      addDOMSignature({
        hash: expiredHash,
        confidence: 90,
        action: 'block',
        expiresAt: Date.now() - 1000, // Expired
      });

      addDOMSignature({
        hash: validHash,
        confidence: 90,
        action: 'block',
        expiresAt: Date.now() + 86400000, // Not expired
      });

      expect(getDOMSignatureStats().exactCount).toBe(2);

      const pruned = pruneExpiredSignatures();
      expect(pruned).toBe(1);
      expect(getDOMSignatureStats().exactCount).toBe(1);
      expect(hasExactMatch(expiredHash)).toBe(false);
      expect(hasExactMatch(validHash)).toBe(true);
    });

    it('should return 0 when no signatures are expired', () => {
      addDOMSignature({
        hash: generateHash(19),
        confidence: 90,
        action: 'block',
        expiresAt: Date.now() + 86400000,
      });

      const pruned = pruneExpiredSignatures();
      expect(pruned).toBe(0);
    });

    it('should handle signatures without expiration', () => {
      addDOMSignature({
        hash: generateHash(20),
        confidence: 90,
        action: 'block',
        // No expiresAt
      });

      const pruned = pruneExpiredSignatures();
      expect(pruned).toBe(0);
      expect(getDOMSignatureStats().exactCount).toBe(1);
    });
  });

  describe('version management', () => {
    it('should track store version', () => {
      expect(getStoreVersion()).toBe(0);

      setStoreVersion(5);
      expect(getStoreVersion()).toBe(5);

      setStoreVersion(10);
      expect(getStoreVersion()).toBe(10);
    });
  });

  describe('extractBands', () => {
    it('should extract correct number of bands', () => {
      const sketch = generateSketch(50);
      const bands = _extractBands(sketch);

      expect(bands.length).toBe(_NUM_BANDS);
      expect(bands.every((b) => b.length === _ROWS_PER_BAND * 8)).toBe(true);
    });

    it('should throw on invalid sketch length', () => {
      expect(() => _extractBands('abc')).toThrow('Invalid LSH sketch length');
      expect(() => _extractBands('')).toThrow('Invalid LSH sketch length');
      expect(() => _extractBands('a'.repeat(511))).toThrow('Invalid LSH sketch length');
    });
  });

  describe('saveDOMSignatureStore', () => {
    it('should serialize and save to storage', async () => {
      addDOMSignature({
        hash: generateHash(21),
        confidence: 90,
        action: 'block',
      });

      await saveDOMSignatureStore();

      expect(mockStorage.local.set).toHaveBeenCalled();
      const setCall = mockStorage.local.set.mock.calls[0][0];
      expect(setCall).toHaveProperty('browserdefense_dom_sig_store');
    });
  });

  describe('update metadata', () => {
    it('should save and load update metadata', async () => {
      const meta = {
        version: 5,
        timestamp: '2024-01-01T00:00:00Z',
        updatedAt: Date.now(),
        exactCount: 100,
        lshCount: 50,
      };

      await saveDOMSignatureUpdateMeta(meta);

      expect(mockStorage.local.set).toHaveBeenCalled();

      mockStorage.local.get.mockResolvedValue({
        browserdefense_dom_sig_meta: meta,
      });

      const loaded = await loadDOMSignatureUpdateMeta();
      expect(loaded).toEqual(meta);
    });

    it('should return null when no metadata exists', async () => {
      mockStorage.local.get.mockResolvedValue({});
      const loaded = await loadDOMSignatureUpdateMeta();
      expect(loaded).toBeNull();
    });
  });

  describe('getDOMSignatureStats', () => {
    it('should return accurate statistics', () => {
      // Add some exact-only signatures
      addDOMSignature({ hash: generateHash(22), confidence: 90, action: 'block' });
      addDOMSignature({ hash: generateHash(23), confidence: 90, action: 'block' });

      // Add signature with LSH
      addDOMSignature({
        hash: generateHash(24),
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: generateSketch(60),
          form_structure: generateSketch(61),
          script_structure: generateSketch(62),
        },
      });

      setStoreVersion(7);

      const stats = getDOMSignatureStats();
      expect(stats.exactCount).toBe(3);
      expect(stats.lshCount).toBe(1);
      expect(stats.version).toBe(7);
      expect(stats.bandIndexSize).toBeGreaterThan(0);
    });
  });
});
