/**
 * DOM Signature Matcher Tests
 *
 * Tests for the DOM signature matching engine including:
 * - Exact hash matching
 * - LSH similarity matching
 * - Expiration handling
 * - Match result formatting
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

// Import store functions to set up test data
import {
  initDOMSignatureStore,
  addDOMSignature,
  clearDOMSignatureStore,
} from '../src/storage/dom-sig-store';

// Import matcher functions
import {
  initDOMSignatureMatcher,
  matchDOMSignature,
  hasDOMSignatures,
  getDOMMatcherStats,
  getDOMSignatureMatcher,
  _matchExact,
  _matchLSH,
} from '../src/background/dom-sig-matcher';

import type { LSHSketches } from '../src/content/lsh-sketch';

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

// Helper to create LSH sketches for testing
function createSketches(domSeed: number, formSeed: number, scriptSeed: number): LSHSketches {
  return {
    dom_layout_lsh: generateSketch(domSeed),
    form_structure_lsh: generateSketch(formSeed),
    script_structure_lsh: generateSketch(scriptSeed),
    generationTimeMs: 0,
  };
}

describe('DOM Signature Matcher', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    mockStorage.local.get.mockResolvedValue({});
    mockStorage.local.set.mockResolvedValue(undefined);
    await initDOMSignatureStore();
    clearDOMSignatureStore();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('initDOMSignatureMatcher', () => {
    it('should initialize without error', async () => {
      await expect(initDOMSignatureMatcher()).resolves.not.toThrow();
    });
  });

  describe('hasDOMSignatures', () => {
    it('should return false when store is empty', () => {
      expect(hasDOMSignatures()).toBe(false);
    });

    it('should return true when signatures exist', () => {
      addDOMSignature({
        hash: generateHash(1),
        confidence: 90,
        action: 'block',
      });

      expect(hasDOMSignatures()).toBe(true);
    });
  });

  describe('matchDOMSignature - exact match', () => {
    it('should find exact hash match', async () => {
      const hash = generateHash(2);
      addDOMSignature({
        hash,
        confidence: 95,
        action: 'block',
        kitId: 'test-kit',
      });

      const result = await matchDOMSignature(hash);

      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('exact');
      expect(result.confidence).toBe(95);
      expect(result.action).toBe('block');
      expect(result.kitId).toBe('test-kit');
      expect(result.matchedSignature).toBe(hash.toLowerCase());
    });

    it('should return allow for non-matching hash', async () => {
      addDOMSignature({
        hash: generateHash(3),
        confidence: 90,
        action: 'block',
      });

      const result = await matchDOMSignature(generateHash(100));

      expect(result.matched).toBe(false);
      expect(result.matchType).toBe('none');
      expect(result.action).toBe('allow');
    });

    it('should not match expired signatures', async () => {
      const hash = generateHash(4);
      addDOMSignature({
        hash,
        confidence: 90,
        action: 'block',
        expiresAt: Date.now() - 1000, // Expired
      });

      const result = await matchDOMSignature(hash);

      expect(result.matched).toBe(false);
      expect(result.action).toBe('allow');
    });

    it('should include captureScreenshot in result', async () => {
      const hash = generateHash(5);
      addDOMSignature({
        hash,
        confidence: 90,
        action: 'block',
        captureScreenshot: true,
      });

      const result = await matchDOMSignature(hash);

      expect(result.matched).toBe(true);
      expect(result.captureScreenshot).toBe(true);
    });
  });

  describe('matchDOMSignature - LSH similarity match', () => {
    it('should find LSH similarity match when exact match fails', async () => {
      const storedHash = generateHash(6);
      const queryHash = generateHash(100); // Different hash
      const sketch = generateSketch(10);

      addDOMSignature({
        hash: storedHash,
        confidence: 85,
        action: 'shadow',
        kitId: 'phish-kit',
        lsh: {
          dom_layout: sketch,
          form_structure: generateSketch(11),
          script_structure: generateSketch(12),
        },
        similarityThreshold: 0.5, // Low threshold for testing
      });

      // Query with same LSH sketches should match via LSH
      const sketches = createSketches(10, 11, 12);
      const result = await matchDOMSignature(queryHash, sketches);

      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('lsh');
      expect(result.confidence).toBe(85);
      expect(result.action).toBe('shadow');
      expect(result.kitId).toBe('phish-kit');
      expect(result.similarity).toBeDefined();
      expect(result.similarity).toBeGreaterThan(0);
    });

    it('should prefer exact match over LSH match', async () => {
      const hash = generateHash(7);
      const sketch = generateSketch(20);

      addDOMSignature({
        hash,
        confidence: 90,
        action: 'block',
        kitId: 'exact-kit',
        lsh: {
          dom_layout: sketch,
          form_structure: generateSketch(21),
          script_structure: generateSketch(22),
        },
      });

      // Query with exact hash and LSH sketches
      const sketches = createSketches(20, 21, 22);
      const result = await matchDOMSignature(hash, sketches);

      // Should return exact match, not LSH
      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('exact');
      expect(result.kitId).toBe('exact-kit');
    });

    it('should not match LSH when below threshold', async () => {
      const storedHash = generateHash(8);
      const queryHash = generateHash(101);

      addDOMSignature({
        hash: storedHash,
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: generateSketch(30),
          form_structure: generateSketch(31),
          script_structure: generateSketch(32),
        },
        similarityThreshold: 0.99, // Very high threshold
      });

      // Query with different sketches
      const sketches = createSketches(100, 101, 102);
      const result = await matchDOMSignature(queryHash, sketches);

      expect(result.matched).toBe(false);
      expect(result.action).toBe('allow');
    });

    it('should not match expired LSH signatures', async () => {
      const storedHash = generateHash(9);
      const queryHash = generateHash(102);
      const sketch = generateSketch(40);

      addDOMSignature({
        hash: storedHash,
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: sketch,
          form_structure: generateSketch(41),
          script_structure: generateSketch(42),
        },
        similarityThreshold: 0.5,
        expiresAt: Date.now() - 1000, // Expired
      });

      const sketches = createSketches(40, 41, 42);
      const result = await matchDOMSignature(queryHash, sketches);

      expect(result.matched).toBe(false);
    });
  });

  describe('_matchExact (internal)', () => {
    it('should return match with metadata', () => {
      const hash = generateHash(10);
      addDOMSignature({
        hash,
        confidence: 88,
        action: 'alert',
        kitId: 'internal-kit',
      });

      const result = _matchExact(hash.toLowerCase());

      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('exact');
      expect(result.confidence).toBe(88);
      expect(result.action).toBe('alert');
      expect(result.kitId).toBe('internal-kit');
    });

    it('should return no match for unknown hash', () => {
      const result = _matchExact(generateHash(200));

      expect(result.matched).toBe(false);
      expect(result.matchType).toBe('none');
      expect(result.confidence).toBe(0);
      expect(result.action).toBe('allow');
    });
  });

  describe('_matchLSH (internal)', () => {
    it('should find best matching signature', () => {
      // Add two signatures with different similarity thresholds
      addDOMSignature({
        hash: generateHash(11),
        confidence: 70,
        action: 'alert',
        lsh: {
          dom_layout: generateSketch(50),
          form_structure: generateSketch(51),
          script_structure: generateSketch(52),
        },
        similarityThreshold: 0.3,
      });

      addDOMSignature({
        hash: generateHash(12),
        confidence: 90,
        action: 'block',
        lsh: {
          dom_layout: generateSketch(50), // Same sketch
          form_structure: generateSketch(51),
          script_structure: generateSketch(52),
        },
        similarityThreshold: 0.3,
      });

      const sketches = createSketches(50, 51, 52);
      const result = _matchLSH(sketches);

      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('lsh');
      // Should match one of them (highest similarity)
      expect([70, 90]).toContain(result.confidence);
    });

    it('should return no match when no candidates', () => {
      const sketches = createSketches(200, 201, 202);
      const result = _matchLSH(sketches);

      expect(result.matched).toBe(false);
      expect(result.matchType).toBe('none');
    });
  });

  describe('getDOMMatcherStats', () => {
    it('should return accurate statistics', async () => {
      await initDOMSignatureMatcher();

      addDOMSignature({
        hash: generateHash(13),
        confidence: 90,
        action: 'block',
      });

      addDOMSignature({
        hash: generateHash(14),
        confidence: 80,
        action: 'block',
        lsh: {
          dom_layout: generateSketch(60),
          form_structure: generateSketch(61),
          script_structure: generateSketch(62),
        },
      });

      const stats = getDOMMatcherStats();

      expect(stats.initialized).toBe(true);
      expect(stats.exactCount).toBe(2);
      expect(stats.lshCount).toBe(1);
    });
  });

  describe('DOMSignatureMatcher class', () => {
    it('should provide singleton instance', () => {
      const matcher1 = getDOMSignatureMatcher();
      const matcher2 = getDOMSignatureMatcher();

      expect(matcher1).toBe(matcher2);
    });

    it('should have working match method', async () => {
      const matcher = getDOMSignatureMatcher();
      await matcher.init();

      const hash = generateHash(15);
      addDOMSignature({
        hash,
        confidence: 92,
        action: 'block',
      });

      const result = await matcher.match(hash);

      expect(result.matched).toBe(true);
      expect(result.confidence).toBe(92);
    });

    it('should have working hasSignatures method', () => {
      const matcher = getDOMSignatureMatcher();

      clearDOMSignatureStore();
      expect(matcher.hasSignatures()).toBe(false);

      addDOMSignature({
        hash: generateHash(16),
        confidence: 90,
        action: 'block',
      });

      expect(matcher.hasSignatures()).toBe(true);
    });
  });

  describe('action types', () => {
    it('should support block action', async () => {
      const hash = generateHash(17);
      addDOMSignature({
        hash,
        confidence: 90,
        action: 'block',
      });

      const result = await matchDOMSignature(hash);
      expect(result.action).toBe('block');
    });

    it('should support shadow action', async () => {
      const hash = generateHash(18);
      addDOMSignature({
        hash,
        confidence: 75,
        action: 'shadow',
      });

      const result = await matchDOMSignature(hash);
      expect(result.action).toBe('shadow');
    });

    it('should support alert action', async () => {
      const hash = generateHash(19);
      addDOMSignature({
        hash,
        confidence: 60,
        action: 'alert',
      });

      const result = await matchDOMSignature(hash);
      expect(result.action).toBe('alert');
    });
  });
});
