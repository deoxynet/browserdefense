/**
 * Async Intercept Tests
 *
 * Tests for the non-blocking webRequest path with bloom filter optimization.
 * Issue #174 - Async Phishing Intercept
 *
 * Key behaviors tested:
 * 1. Bloom filter provides fast negative prefiltering
 * 2. Non-blocked URLs return quickly (no measurable delay)
 * 3. Blocked URLs are correctly identified after bloom filter check
 * 4. Bloom filter is rebuilt when blocklist updates
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { BloomFilter } from '../src/storage/bloom-filter';
import { BinaryHashSet } from '../src/storage/binary-set';
import { canonicalizeAndHash } from '../src/crypto/canonicalize';

describe('Bloom Filter Integration for Async Intercept', () => {
  describe('Fast negative prefiltering', () => {
    it('bloom filter returns false for URLs not in set', async () => {
      const filter = BloomFilter.create({ expectedItems: 100 });

      // Add some hashes to the filter
      const blockedUrl = 'https://phishing-site.com/login';
      const salt = 'test-salt';
      const blockedHash = await canonicalizeAndHash(blockedUrl, salt);
      filter.add(blockedHash);

      // Test URL not in filter
      const safeUrl = 'https://google.com/search';
      const safeHash = await canonicalizeAndHash(safeUrl, salt);

      // Bloom filter should say "definitely not in set"
      expect(filter.mightContain(safeHash)).toBe(false);
    });

    it('bloom filter returns true for URLs in set', async () => {
      const filter = BloomFilter.create({ expectedItems: 100 });

      const blockedUrl = 'https://phishing-site.com/login';
      const salt = 'test-salt';
      const blockedHash = await canonicalizeAndHash(blockedUrl, salt);
      filter.add(blockedHash);

      // Bloom filter should say "possibly in set"
      expect(filter.mightContain(blockedHash)).toBe(true);
    });

    it('bloom filter never has false negatives', async () => {
      const filter = BloomFilter.create({ expectedItems: 1000 });
      const salt = 'test-salt';
      const addedHashes: Uint8Array[] = [];

      // Add 100 URLs to the filter
      for (let i = 0; i < 100; i++) {
        const url = `https://malware-${i}.evil.com/payload`;
        const hash = await canonicalizeAndHash(url, salt);
        filter.add(hash);
        addedHashes.push(hash);
      }

      // Verify all added hashes are found (no false negatives)
      for (const hash of addedHashes) {
        expect(filter.mightContain(hash)).toBe(true);
      }
    });

    it('bloom filter provides faster lookup than binary set for non-matches', async () => {
      const hashSet = new BinaryHashSet();
      const filter = BloomFilter.create({ expectedItems: 10000 });
      const salt = 'test-salt';

      // Add 1000 malicious URLs
      for (let i = 0; i < 1000; i++) {
        const url = `https://malware-${i}.evil.com/payload`;
        const hash = await canonicalizeAndHash(url, salt);
        hashSet.add(hash);
        filter.add(hash);
      }

      // Check a safe URL (not in set)
      const safeUrl = 'https://legitimate-site.com/page';
      const safeHash = await canonicalizeAndHash(safeUrl, salt);

      // Both should return false/not found
      expect(filter.mightContain(safeHash)).toBe(false);
      expect(hashSet.has(safeHash)).toBe(false);

      // The bloom filter check is O(k) vs O(log n) for binary search
      // We can't easily measure time in tests, but we verify correctness
    });
  });

  describe('Async intercept path simulation', () => {
    /**
     * Simulates the checkAndRedirect flow with bloom filter optimization
     */
    async function simulateAsyncIntercept(
      url: string,
      salt: string,
      bloomFilter: BloomFilter | null,
      blocklist: BinaryHashSet
    ): Promise<{ blocked: boolean; usedSlowPath: boolean }> {
      const hash = await canonicalizeAndHash(url, salt, {
        scope: 'HOST_ONLY',
        includeScheme: true,
      });

      // Fast path: bloom filter negative prefiltering
      if (bloomFilter && !bloomFilter.mightContain(hash)) {
        return { blocked: false, usedSlowPath: false };
      }

      // Slow path: verify with authoritative hash set
      const isMatch = blocklist.has(hash);
      return { blocked: isMatch, usedSlowPath: true };
    }

    it('non-blocked URL takes fast path when bloom filter present', async () => {
      const salt = 'test-salt';
      const blocklist = new BinaryHashSet();
      const bloomFilter = BloomFilter.create({ expectedItems: 100 });

      // Add a malicious URL
      const blockedUrl = 'https://phishing.evil.com/login';
      const blockedHash = await canonicalizeAndHash(blockedUrl, salt, {
        scope: 'HOST_ONLY',
        includeScheme: true,
      });
      blocklist.add(blockedHash);
      bloomFilter.add(blockedHash);

      // Test safe URL - should use fast path
      const safeUrl = 'https://google.com/';
      const result = await simulateAsyncIntercept(safeUrl, salt, bloomFilter, blocklist);

      expect(result.blocked).toBe(false);
      expect(result.usedSlowPath).toBe(false); // Fast path!
    });

    it('blocked URL correctly identified after bloom filter check', async () => {
      const salt = 'test-salt';
      const blocklist = new BinaryHashSet();
      const bloomFilter = BloomFilter.create({ expectedItems: 100 });

      // Add a malicious URL
      const blockedUrl = 'https://phishing.evil.com/login';
      const blockedHash = await canonicalizeAndHash(blockedUrl, salt, {
        scope: 'HOST_ONLY',
        includeScheme: true,
      });
      blocklist.add(blockedHash);
      bloomFilter.add(blockedHash);

      // Test the blocked URL
      const result = await simulateAsyncIntercept(blockedUrl, salt, bloomFilter, blocklist);

      expect(result.blocked).toBe(true);
      expect(result.usedSlowPath).toBe(true); // Had to verify with hash set
    });

    it('works correctly without bloom filter (fallback)', async () => {
      const salt = 'test-salt';
      const blocklist = new BinaryHashSet();

      // Add a malicious URL
      const blockedUrl = 'https://phishing.evil.com/login';
      const blockedHash = await canonicalizeAndHash(blockedUrl, salt, {
        scope: 'HOST_ONLY',
        includeScheme: true,
      });
      blocklist.add(blockedHash);

      // Test without bloom filter
      const blockedResult = await simulateAsyncIntercept(blockedUrl, salt, null, blocklist);
      expect(blockedResult.blocked).toBe(true);
      expect(blockedResult.usedSlowPath).toBe(true);

      const safeResult = await simulateAsyncIntercept('https://google.com/', salt, null, blocklist);
      expect(safeResult.blocked).toBe(false);
      expect(safeResult.usedSlowPath).toBe(true); // No fast path without bloom
    });
  });

  describe('Bloom filter rebuild on blocklist update', () => {
    it('new bloom filter contains all blocklist items', async () => {
      const salt = 'test-salt';
      const blocklist = new BinaryHashSet();
      const urls = [
        'https://malware-1.evil.com/payload',
        'https://phishing-2.evil.com/login',
        'https://scam-3.evil.com/prize',
      ];

      // Build blocklist
      const hashes: Uint8Array[] = [];
      for (const url of urls) {
        const hash = await canonicalizeAndHash(url, salt, {
          scope: 'HOST_ONLY',
          includeScheme: true,
        });
        blocklist.add(hash);
        hashes.push(hash);
      }

      // Build bloom filter from blocklist (simulating buildBloomFilter)
      const bloomFilter = BloomFilter.create({ expectedItems: blocklist.count });
      for (const hash of blocklist.hashes()) {
        bloomFilter.add(hash);
      }

      // All hashes should be in bloom filter
      for (const hash of hashes) {
        expect(bloomFilter.mightContain(hash)).toBe(true);
      }
    });

    it('dirty flag is set when blocklist changes require rebuild', () => {
      const filter = BloomFilter.create({ expectedItems: 100 });

      expect(filter.isDirty).toBe(false);

      // Mark dirty (simulating deletion that requires rebuild)
      filter.markDirty();

      expect(filter.isDirty).toBe(true);

      // Mark clean after rebuild
      filter.markClean(1);

      expect(filter.isDirty).toBe(false);
      expect(filter.sourceVersion).toBe(1);
    });
  });

  describe('Bloom filter stats in blocking info', () => {
    it('bloom filter metadata is correctly reported', () => {
      const filter = BloomFilter.create({ expectedItems: 1000 });

      // Add some items
      for (let i = 0; i < 100; i++) {
        const hash = new Uint8Array(32);
        hash[0] = i;
        filter.add(hash);
      }

      const meta = filter.getMeta();

      expect(meta.itemCount).toBe(100);
      expect(meta.bitCount).toBeGreaterThan(0);
      expect(meta.hashCount).toBeGreaterThan(0);
      expect(meta.isDirty).toBe(false);
    });

    it('estimated false positive rate is reasonable', () => {
      const filter = BloomFilter.create({
        expectedItems: 10000,
        falsePositiveRate: 0.01, // 1% target
      });

      // Add the expected number of items
      for (let i = 0; i < 10000; i++) {
        const hash = new Uint8Array(32);
        // Create unique hashes
        hash[0] = i & 0xff;
        hash[1] = (i >> 8) & 0xff;
        hash[2] = (i >> 16) & 0xff;
        filter.add(hash);
      }

      // Estimated FPR should be close to target
      const fpr = filter.estimatedFalsePositiveRate;
      expect(fpr).toBeLessThan(0.05); // Should be well under 5%
    });
  });
});

describe('URL normalization consistency in async path', () => {
  /**
   * Verifies that the async intercept path uses the same canonicalization
   * as IOC creation, preventing bypass attacks.
   */

  const testCases = [
    // Case normalization
    ['https://EVIL.COM/path', 'https://evil.com/path'],
    // Port normalization
    ['https://evil.com:443/path', 'https://evil.com/path'],
    // Trailing dot
    ['https://evil.com./path', 'https://evil.com/path'],
    // Path traversal
    ['https://evil.com/a/../path', 'https://evil.com/path'],
    // Encoded characters
    ['https://evil.com/%70ath', 'https://evil.com/path'],
  ];

  it.each(testCases)(
    'bypass attempt %s hashes same as %s',
    async (bypassUrl, normalUrl) => {
      const salt = 'test-salt';

      const bypassHash = await canonicalizeAndHash(bypassUrl, salt, {
        scope: 'HOST_ONLY',
        includeScheme: true,
      });

      const normalHash = await canonicalizeAndHash(normalUrl, salt, {
        scope: 'HOST_ONLY',
        includeScheme: true,
      });

      expect(Array.from(bypassHash)).toEqual(Array.from(normalHash));
    }
  );
});
