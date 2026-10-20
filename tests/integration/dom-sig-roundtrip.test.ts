/**
 * Integration Test: DOM Signature Roundtrip
 *
 * Tests the end-to-end flow for DOM signature threat intel:
 * 1. Add signatures to store (exact + LSH)
 * 2. Serialize to chrome.storage format
 * 3. Deserialize from storage
 * 4. Verify matching works correctly
 * 5. Verify FCM-style add/remove operations
 *
 * This catches:
 * - Serialization/deserialization bugs
 * - LSH band indexing consistency
 * - Metadata preservation across storage cycles
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Track what gets stored
let storedData: Record<string, unknown> = {};

// Mock chrome APIs
const mockStorage = {
  local: {
    get: vi.fn(async (keys: string | string[]) => {
      if (typeof keys === 'string') {
        return { [keys]: storedData[keys] };
      }
      const result: Record<string, unknown> = {};
      for (const key of keys) {
        if (storedData[key] !== undefined) {
          result[key] = storedData[key];
        }
      }
      return result;
    }),
    set: vi.fn(async (items: Record<string, unknown>) => {
      Object.assign(storedData, items);
    }),
    remove: vi.fn(async (keys: string | string[]) => {
      const keyList = typeof keys === 'string' ? [keys] : keys;
      for (const key of keyList) {
        delete storedData[key];
      }
    }),
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
  getDOMSignatureStats,
  setStoreVersion,
  getStoreVersion,
  pruneExpiredSignatures,
} from '../../src/storage/dom-sig-store';

import {
  matchDOMSignature,
  hasDOMSignatures,
  getDOMMatcherStats,
} from '../../src/background/dom-sig-matcher';

import { estimateSimilarity } from '../../src/content/lsh-sketch';

import type { DOMSignatureEntry } from '../../src/types/dom-sig-manifest';
import type { LSHSketches } from '../../src/content/lsh-sketch';

// ============ Test Helpers ============

function generateHash(seed: number): string {
  // Use a simple PRNG to generate unique 64-char hex strings
  let state = seed + 1; // Avoid 0
  const hex = '0123456789abcdef';
  let hash = '';
  for (let i = 0; i < 64; i++) {
    // Simple LCG: state = (state * 1103515245 + 12345) % 2^31
    state = ((state * 1103515245) + 12345) >>> 0;
    hash += hex[(state >>> 16) % 16];
  }
  return hash;
}

function generateSketch(seed: number): string {
  // Use a simple PRNG to generate unique 512-char hex strings
  let state = seed + 1; // Avoid 0
  const hex = '0123456789abcdef';
  let sketch = '';
  for (let i = 0; i < 512; i++) {
    state = ((state * 1103515245) + 12345) >>> 0;
    sketch += hex[(state >>> 16) % 16];
  }
  return sketch;
}

function createSketches(domSeed: number, formSeed: number, scriptSeed: number): LSHSketches {
  return {
    dom_layout_lsh: generateSketch(domSeed),
    form_structure_lsh: generateSketch(formSeed),
    script_structure_lsh: generateSketch(scriptSeed),
    generationTimeMs: 0,
  };
}

// ============ Tests ============

describe('DOM Signature Roundtrip Integration', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    storedData = {};
    await initDOMSignatureStore();
    clearDOMSignatureStore();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Storage Roundtrip', () => {
    it('should preserve exact-match signatures through save/load cycle', async () => {
      // Add signatures
      const hash1 = generateHash(1);
      const hash2 = generateHash(2);

      addDOMSignature({
        hash: hash1,
        confidence: 95,
        action: 'block',
        kitId: 'phish-kit-1',
      });

      addDOMSignature({
        hash: hash2,
        confidence: 80,
        action: 'shadow',
        captureScreenshot: true,
      });

      setStoreVersion(5);

      // Save to storage
      await saveDOMSignatureStore();

      // Clear in-memory state
      clearDOMSignatureStore();
      expect(hasExactMatch(hash1)).toBe(false);
      expect(hasExactMatch(hash2)).toBe(false);

      // Reload from storage
      await initDOMSignatureStore();

      // Verify signatures restored
      expect(hasExactMatch(hash1)).toBe(true);
      expect(hasExactMatch(hash2)).toBe(true);

      // Verify metadata preserved
      const meta1 = getMetadata(hash1);
      expect(meta1?.confidence).toBe(95);
      expect(meta1?.action).toBe('block');
      expect(meta1?.kitId).toBe('phish-kit-1');

      const meta2 = getMetadata(hash2);
      expect(meta2?.confidence).toBe(80);
      expect(meta2?.action).toBe('shadow');
      expect(meta2?.captureScreenshot).toBe(true);

      // Verify version preserved
      expect(getStoreVersion()).toBe(5);
    });

    it('should preserve LSH signatures through save/load cycle', async () => {
      const hash = generateHash(10);
      const domSketch = generateSketch(100);
      const formSketch = generateSketch(101);
      const scriptSketch = generateSketch(102);

      addDOMSignature({
        hash,
        confidence: 85,
        action: 'block',
        kitId: 'lsh-kit',
        lsh: {
          dom_layout: domSketch,
          form_structure: formSketch,
          script_structure: scriptSketch,
        },
        similarityThreshold: 0.9,
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Verify LSH signature restored
      const lshSig = getLSHSignature(hash);
      expect(lshSig).toBeDefined();
      expect(lshSig?.dom_layout_lsh).toBe(domSketch);
      expect(lshSig?.form_structure_lsh).toBe(formSketch);
      expect(lshSig?.script_structure_lsh).toBe(scriptSketch);
      expect(lshSig?.similarityThreshold).toBe(0.9);
      expect(lshSig?.kitId).toBe('lsh-kit');

      // Verify LSH candidates work after reload
      const candidates = findLSHCandidates(domSketch, formSketch, scriptSketch);
      expect(candidates.has(hash.toLowerCase())).toBe(true);
    });

    it('should handle large number of signatures', async () => {
      const count = 1000;
      const hashes: string[] = [];

      // Add many signatures
      for (let i = 0; i < count; i++) {
        const hash = generateHash(i);
        hashes.push(hash);
        addDOMSignature({
          hash,
          confidence: 70 + (i % 30),
          action: i % 3 === 0 ? 'block' : i % 3 === 1 ? 'shadow' : 'alert',
        });
      }

      const statsBefore = getDOMSignatureStats();
      expect(statsBefore.exactCount).toBe(count);

      // Save and reload
      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      const statsAfter = getDOMSignatureStats();
      expect(statsAfter.exactCount).toBe(count);

      // Spot check some hashes
      expect(hasExactMatch(hashes[0])).toBe(true);
      expect(hasExactMatch(hashes[500])).toBe(true);
      expect(hasExactMatch(hashes[999])).toBe(true);
    });
  });

  describe('Match Pipeline Roundtrip', () => {
    it('should match exact hash after storage roundtrip', async () => {
      const hash = generateHash(20);

      addDOMSignature({
        hash,
        confidence: 92,
        action: 'block',
        kitId: 'exact-test',
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Use matcher API
      const result = await matchDOMSignature(hash);

      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('exact');
      expect(result.confidence).toBe(92);
      expect(result.action).toBe('block');
      expect(result.kitId).toBe('exact-test');
    });

    it('should match LSH similarity after storage roundtrip', async () => {
      const storedHash = generateHash(30);
      const queryHash = generateHash(999); // Different hash

      const domSketch = generateSketch(200);
      const formSketch = generateSketch(201);
      const scriptSketch = generateSketch(202);

      addDOMSignature({
        hash: storedHash,
        confidence: 88,
        action: 'shadow',
        kitId: 'lsh-test',
        lsh: {
          dom_layout: domSketch,
          form_structure: formSketch,
          script_structure: scriptSketch,
        },
        similarityThreshold: 0.5, // Low threshold for testing
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Query with same LSH sketches but different hash
      const sketches = createSketches(200, 201, 202);
      const result = await matchDOMSignature(queryHash, sketches);

      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('lsh');
      expect(result.confidence).toBe(88);
      expect(result.action).toBe('shadow');
      expect(result.kitId).toBe('lsh-test');
      expect(result.similarity).toBeGreaterThan(0.5);
    });

    it('should not match expired signatures after roundtrip', async () => {
      const hash = generateHash(40);

      addDOMSignature({
        hash,
        confidence: 90,
        action: 'block',
        expiresAt: Date.now() - 1000, // Already expired
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      const result = await matchDOMSignature(hash);
      expect(result.matched).toBe(false);
      expect(result.action).toBe('allow');
    });
  });

  describe('FCM-style Operations Roundtrip', () => {
    it('should add and remove signatures like FCM would', async () => {
      // Simulate FCM DOM_SIG_BLOCK
      const hash1 = generateHash(50);
      addDOMSignature({
        hash: hash1,
        confidence: 85,
        action: 'block',
      });
      await saveDOMSignatureStore();

      expect(hasExactMatch(hash1)).toBe(true);

      // Simulate FCM DOM_SIG_UNBLOCK
      removeDOMSignature(hash1);
      await saveDOMSignatureStore();

      // Reload and verify removed
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      expect(hasExactMatch(hash1)).toBe(false);
    });

    it('should add shadow signatures like FCM would', async () => {
      const hash = generateHash(60);

      // Simulate FCM DOM_SIG_SHADOW
      addDOMSignature({
        hash,
        confidence: 60,
        action: 'shadow',
        kitId: 'suspected-kit',
      });
      await saveDOMSignatureStore();

      clearDOMSignatureStore();
      await initDOMSignatureStore();

      const result = await matchDOMSignature(hash);
      expect(result.matched).toBe(true);
      expect(result.action).toBe('shadow');
    });

    it('should handle rapid add/remove cycles', async () => {
      const hashes = [generateHash(70), generateHash(71), generateHash(72)];

      // Add all
      for (const hash of hashes) {
        addDOMSignature({ hash, confidence: 90, action: 'block' });
      }
      await saveDOMSignatureStore();

      // Remove middle one
      removeDOMSignature(hashes[1]);
      await saveDOMSignatureStore();

      // Reload and verify
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      expect(hasExactMatch(hashes[0])).toBe(true);
      expect(hasExactMatch(hashes[1])).toBe(false);
      expect(hasExactMatch(hashes[2])).toBe(true);
    });
  });

  describe('Expiration Handling Roundtrip', () => {
    it('should prune expired signatures correctly', async () => {
      const expiredHash = generateHash(80);
      const validHash = generateHash(81);

      addDOMSignature({
        hash: expiredHash,
        confidence: 90,
        action: 'block',
        expiresAt: Date.now() - 1000,
      });

      addDOMSignature({
        hash: validHash,
        confidence: 90,
        action: 'block',
        expiresAt: Date.now() + 86400000,
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Prune expired
      const pruned = pruneExpiredSignatures();
      expect(pruned).toBe(1);

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Verify only valid remains
      expect(hasExactMatch(expiredHash)).toBe(false);
      expect(hasExactMatch(validHash)).toBe(true);
    });
  });

  describe('LSH Similarity Verification', () => {
    it('should correctly compute similarity for identical sketches', () => {
      const sketch = generateSketch(300);
      const similarity = estimateSimilarity(sketch, sketch);
      expect(similarity).toBe(1.0);
    });

    it('should correctly compute similarity for different sketches', () => {
      const sketch1 = generateSketch(400);
      const sketch2 = generateSketch(500);
      const similarity = estimateSimilarity(sketch1, sketch2);
      // Different seeds should produce low similarity
      expect(similarity).toBeLessThan(0.5);
    });

    it('should find similar sketches via LSH band index', async () => {
      // Add signature with specific sketches
      const hash = generateHash(90);
      const sketch = generateSketch(600);

      addDOMSignature({
        hash,
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: sketch,
          form_structure: generateSketch(601),
          script_structure: generateSketch(602),
        },
        similarityThreshold: 0.3,
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Search with same dom_layout sketch
      const candidates = findLSHCandidates(
        sketch,
        generateSketch(999), // Different
        generateSketch(998)  // Different
      );

      // Should find via dom_layout match
      expect(candidates.has(hash.toLowerCase())).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty store roundtrip', async () => {
      // Save empty store
      await saveDOMSignatureStore();

      // Reload
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      expect(getDOMSignatureStats().exactCount).toBe(0);
      expect(getDOMSignatureStats().lshCount).toBe(0);
      expect(hasDOMSignatures()).toBe(false);
    });

    it('should handle case-insensitive hash lookups after roundtrip', async () => {
      const hash = generateHash(110);
      const upperHash = hash.toUpperCase();
      const lowerHash = hash.toLowerCase();

      addDOMSignature({
        hash: upperHash, // Add with uppercase
        confidence: 90,
        action: 'block',
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Should find with lowercase
      expect(hasExactMatch(lowerHash)).toBe(true);
      // Should find with uppercase
      expect(hasExactMatch(upperHash)).toBe(true);
      // Metadata should be accessible with either case
      expect(getMetadata(lowerHash)?.confidence).toBe(90);
      expect(getMetadata(upperHash)?.confidence).toBe(90);
    });

    it('should update metadata when adding duplicate hash', async () => {
      const hash = generateHash(120);

      // Add first time
      addDOMSignature({
        hash,
        confidence: 70,
        action: 'shadow',
        kitId: 'original-kit',
      });

      // Add again with different metadata
      addDOMSignature({
        hash,
        confidence: 95,
        action: 'block',
        kitId: 'updated-kit',
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Should have updated metadata
      const meta = getMetadata(hash);
      expect(meta?.confidence).toBe(95);
      expect(meta?.action).toBe('block');
      expect(meta?.kitId).toBe('updated-kit');

      // Should still only count as one signature
      expect(getDOMSignatureStats().exactCount).toBe(1);
    });

    it('should handle removing non-existent signature', async () => {
      const existingHash = generateHash(130);
      const nonExistentHash = generateHash(131);

      addDOMSignature({
        hash: existingHash,
        confidence: 90,
        action: 'block',
      });

      await saveDOMSignatureStore();

      // Remove non-existent hash should return false and not corrupt state
      const removed = removeDOMSignature(nonExistentHash);
      expect(removed).toBe(false);

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Existing signature should still be there
      expect(hasExactMatch(existingHash)).toBe(true);
    });

    it('should clean up LSH band index when signature is removed', async () => {
      const hash = generateHash(140);
      const domSketch = generateSketch(800);
      const formSketch = generateSketch(801);
      const scriptSketch = generateSketch(802);

      addDOMSignature({
        hash,
        confidence: 85,
        action: 'block',
        lsh: {
          dom_layout: domSketch,
          form_structure: formSketch,
          script_structure: scriptSketch,
        },
      });

      await saveDOMSignatureStore();

      // Verify it's findable via LSH
      let candidates = findLSHCandidates(domSketch, formSketch, scriptSketch);
      expect(candidates.has(hash.toLowerCase())).toBe(true);

      // Remove signature
      removeDOMSignature(hash);
      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Should no longer be found via LSH
      candidates = findLSHCandidates(domSketch, formSketch, scriptSketch);
      expect(candidates.has(hash.toLowerCase())).toBe(false);

      // Stats should reflect removal
      expect(getDOMSignatureStats().lshCount).toBe(0);
    });

    it('should select best match when multiple LSH signatures match', async () => {
      const queryHash = generateHash(999);
      const domSketch = generateSketch(900);
      const formSketch = generateSketch(901);
      const scriptSketch = generateSketch(902);

      // Add two signatures with same LSH sketches but different confidence
      addDOMSignature({
        hash: generateHash(150),
        confidence: 70,
        action: 'alert',
        kitId: 'low-confidence',
        lsh: {
          dom_layout: domSketch,
          form_structure: formSketch,
          script_structure: scriptSketch,
        },
        similarityThreshold: 0.3,
      });

      addDOMSignature({
        hash: generateHash(151),
        confidence: 95,
        action: 'block',
        kitId: 'high-confidence',
        lsh: {
          dom_layout: domSketch,
          form_structure: formSketch,
          script_structure: scriptSketch,
        },
        similarityThreshold: 0.3,
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Query should match one of them (implementation picks highest similarity,
      // but with identical sketches it's deterministic based on order/hash)
      const sketches = createSketches(900, 901, 902);
      const result = await matchDOMSignature(queryHash, sketches);

      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('lsh');
      // Should have found one of the two
      expect(['low-confidence', 'high-confidence']).toContain(result.kitId);
    });

    it('should handle signature with only partial LSH sketches', async () => {
      const hash = generateHash(160);
      const domSketch = generateSketch(950);

      // Add signature with only dom_layout sketch (others empty)
      addDOMSignature({
        hash,
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: domSketch,
          form_structure: '', // Empty
          script_structure: '', // Empty
        },
        similarityThreshold: 0.5,
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Should still find via dom_layout match only
      const candidates = findLSHCandidates(domSketch, '', '');
      expect(candidates.has(hash.toLowerCase())).toBe(true);
    });

    it('should handle boundary confidence values', async () => {
      const hash1 = generateHash(170);
      const hash2 = generateHash(171);

      addDOMSignature({
        hash: hash1,
        confidence: 0, // Minimum
        action: 'alert',
      });

      addDOMSignature({
        hash: hash2,
        confidence: 100, // Maximum
        action: 'block',
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      expect(getMetadata(hash1)?.confidence).toBe(0);
      expect(getMetadata(hash2)?.confidence).toBe(100);
    });

    it('should handle expiration exactly at current time', async () => {
      const hash = generateHash(180);
      const now = Date.now();

      addDOMSignature({
        hash,
        confidence: 90,
        action: 'block',
        expiresAt: now, // Exactly now
      });

      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Expiration is inclusive, even when the clock has not advanced.
      const result = await matchDOMSignature(hash);
      expect(result.matched).toBe(false);
    });

    it('should handle re-adding removed signature with LSH', async () => {
      const hash = generateHash(190);
      const domSketch = generateSketch(980);
      const formSketch = generateSketch(981);
      const scriptSketch = generateSketch(982);

      // Add with LSH
      addDOMSignature({
        hash,
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: domSketch,
          form_structure: formSketch,
          script_structure: scriptSketch,
        },
      });
      await saveDOMSignatureStore();

      // Remove
      removeDOMSignature(hash);
      await saveDOMSignatureStore();

      // Re-add with different metadata
      addDOMSignature({
        hash,
        confidence: 95,
        action: 'shadow',
        lsh: {
          dom_layout: domSketch,
          form_structure: formSketch,
          script_structure: scriptSketch,
        },
      });
      await saveDOMSignatureStore();

      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Should have new metadata
      expect(getMetadata(hash)?.confidence).toBe(95);
      expect(getMetadata(hash)?.action).toBe('shadow');

      // LSH should still work
      const candidates = findLSHCandidates(domSketch, formSketch, scriptSketch);
      expect(candidates.has(hash.toLowerCase())).toBe(true);
    });
  });

  describe('Stats Consistency', () => {
    it('should maintain accurate stats through operations', async () => {
      // Start empty
      expect(getDOMSignatureStats().exactCount).toBe(0);
      expect(getDOMSignatureStats().lshCount).toBe(0);

      // Add exact-only
      addDOMSignature({
        hash: generateHash(100),
        confidence: 90,
        action: 'block',
      });
      expect(getDOMSignatureStats().exactCount).toBe(1);
      expect(getDOMSignatureStats().lshCount).toBe(0);

      // Add with LSH
      addDOMSignature({
        hash: generateHash(101),
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: generateSketch(700),
          form_structure: generateSketch(701),
          script_structure: generateSketch(702),
        },
      });
      expect(getDOMSignatureStats().exactCount).toBe(2);
      expect(getDOMSignatureStats().lshCount).toBe(1);

      // Save/reload
      await saveDOMSignatureStore();
      clearDOMSignatureStore();
      await initDOMSignatureStore();

      // Verify stats match
      expect(getDOMSignatureStats().exactCount).toBe(2);
      expect(getDOMSignatureStats().lshCount).toBe(1);

      // Verify matcher stats match
      const matcherStats = getDOMMatcherStats();
      expect(matcherStats.exactCount).toBe(2);
      expect(matcherStats.lshCount).toBe(1);
    });
  });
});
