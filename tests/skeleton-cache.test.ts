/**
 * Tests for DOM Skeleton Cache module.
 *
 * Verifies:
 * - URL normalization for cache keys
 * - Skeleton hashing
 * - Cache hit/miss behavior
 * - Hash stability across reloads
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import 'fake-indexeddb/auto';

// Must import after fake-indexeddb is set up
import {
  normalizeUrlForCache,
  hashSkeleton,
  getOrComputeSkeletonHash,
  isSkeletonCached,
  saveSkeletonToCache,
  loadSkeletonFromCache,
  deleteSkeletonFromCache,
} from '../src/background/skeleton-cache';
import { closeDB } from '../src/storage/idb';
import type { DOMSkeleton } from '../src/content/dom-skeleton';

/**
 * Create a mock DOMSkeleton for testing.
 */
function createMockSkeleton(overrides: Partial<DOMSkeleton> = {}): DOMSkeleton {
  return {
    tagTree: 'html(head,body(div(form[method=post](input[type=email],input[type=password],button[type=submit]))))',
    formCount: 1,
    inputTypes: ['email', 'password'],
    actionUrls: ['/login'],
    hasLoginForm: true,
    hasPaymentForm: false,
    extractionTimeMs: 5,
    ...overrides,
  };
}

describe('Skeleton Cache', () => {
  beforeEach(async () => {
    await closeDB();
    indexedDB.deleteDatabase('browserdefense');
  });

  afterEach(async () => {
    await closeDB();
  });

  describe('normalizeUrlForCache', () => {
    it('should normalize URL to scheme + host + path', () => {
      const url = 'https://example.com/login?foo=bar#section';
      const normalized = normalizeUrlForCache(url);
      expect(normalized).toBe('https://example.com/login');
    });

    it('should lowercase scheme and host', () => {
      const url = 'HTTPS://EXAMPLE.COM/Path';
      const normalized = normalizeUrlForCache(url);
      expect(normalized).toBe('https://example.com/Path');
    });

    it('should remove trailing dot from host', () => {
      const url = 'https://example.com./path';
      const normalized = normalizeUrlForCache(url);
      expect(normalized).toBe('https://example.com/path');
    });

    it('should remove default ports', () => {
      expect(normalizeUrlForCache('https://example.com:443/path')).toBe('https://example.com/path');
      expect(normalizeUrlForCache('http://example.com:80/path')).toBe('http://example.com/path');
    });

    it('should keep non-default ports', () => {
      expect(normalizeUrlForCache('https://example.com:8443/path')).toBe('https://example.com:8443/path');
      expect(normalizeUrlForCache('http://example.com:8080/path')).toBe('http://example.com:8080/path');
    });

    it('should handle root path', () => {
      const url = 'https://example.com';
      const normalized = normalizeUrlForCache(url);
      expect(normalized).toBe('https://example.com/');
    });

    it('should normalize path encoding', () => {
      const url = 'https://example.com/path%20with%20spaces';
      const normalized = normalizeUrlForCache(url);
      expect(normalized).toBe('https://example.com/path%20with%20spaces');
    });

    it('should handle invalid URLs gracefully', () => {
      const url = 'not-a-valid-url';
      const normalized = normalizeUrlForCache(url);
      expect(normalized).toBe('not-a-valid-url');
    });
  });

  describe('hashSkeleton', () => {
    it('should return consistent hash for same skeleton', async () => {
      const skeleton = createMockSkeleton();
      const hash1 = await hashSkeleton(skeleton);
      const hash2 = await hashSkeleton(skeleton);
      expect(hash1).toBe(hash2);
    });

    it('should return 64-character hex string (SHA-256)', async () => {
      const skeleton = createMockSkeleton();
      const hash = await hashSkeleton(skeleton);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should return different hash for different skeletons', async () => {
      const skeleton1 = createMockSkeleton({ tagTree: 'html(body(div))' });
      const skeleton2 = createMockSkeleton({ tagTree: 'html(body(span))' });
      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);
      expect(hash1).not.toBe(hash2);
    });

    it('should be stable across reloads (deterministic)', async () => {
      // Same input should always produce same output
      const skeleton = createMockSkeleton({
        tagTree: 'html(body(form[method=post](input[type=text])))',
      });
      const expectedHash = await hashSkeleton(skeleton);

      // Simulate "reload" by creating identical skeleton
      const skeleton2 = createMockSkeleton({
        tagTree: 'html(body(form[method=post](input[type=text])))',
      });
      const hash2 = await hashSkeleton(skeleton2);

      expect(hash2).toBe(expectedHash);
    });
  });

  describe('getOrComputeSkeletonHash', () => {
    it('should compute hash and cache on first visit', async () => {
      const url = 'https://example.com/login';
      const skeleton = createMockSkeleton();

      const result = await getOrComputeSkeletonHash(url, skeleton);

      expect(result.cached).toBe(false);
      expect(result.hash).toMatch(/^[a-f0-9]{64}$/);
      expect(result.normalizedUrl).toBe('https://example.com/login');
      expect(result.hasLoginForm).toBe(true);
      expect(result.hasPaymentForm).toBe(false);
    });

    it('should return cached hash on repeat visit', async () => {
      const url = 'https://example.com/login';
      const skeleton = createMockSkeleton();

      // First visit
      const result1 = await getOrComputeSkeletonHash(url, skeleton);
      expect(result1.cached).toBe(false);

      // Repeat visit
      const result2 = await getOrComputeSkeletonHash(url, skeleton);
      expect(result2.cached).toBe(true);
      expect(result2.hash).toBe(result1.hash);
    });

    it('should skip hashing on repeat visit (use cached result)', async () => {
      const url = 'https://example.com/login';
      const skeleton = createMockSkeleton();

      // First visit - computes hash
      await getOrComputeSkeletonHash(url, skeleton);

      // Second visit with DIFFERENT skeleton content
      // Should still return cached hash (URL-based cache)
      const differentSkeleton = createMockSkeleton({
        tagTree: 'completely-different-structure',
      });
      const result = await getOrComputeSkeletonHash(url, differentSkeleton);

      expect(result.cached).toBe(true);
      // Hash should be from the FIRST skeleton, not the second
      expect(result.hash).toBe(await hashSkeleton(skeleton));
    });

    it('should normalize URL for cache lookup', async () => {
      const skeleton = createMockSkeleton();

      // Cache with one URL format
      await getOrComputeSkeletonHash('https://example.com/login?foo=bar', skeleton);

      // Lookup with different URL format (same normalized URL)
      const result = await getOrComputeSkeletonHash(
        'https://example.com/login?baz=qux#section',
        skeleton
      );

      expect(result.cached).toBe(true);
    });

    it('should treat different paths as different pages', async () => {
      const skeleton = createMockSkeleton();

      await getOrComputeSkeletonHash('https://example.com/login', skeleton);
      const result = await getOrComputeSkeletonHash('https://example.com/signup', skeleton);

      expect(result.cached).toBe(false);
    });
  });

  describe('isSkeletonCached', () => {
    it('should return false for uncached URL', async () => {
      const cached = await isSkeletonCached('https://example.com/new-page');
      expect(cached).toBe(false);
    });

    it('should return true for cached URL', async () => {
      const url = 'https://example.com/login';
      const skeleton = createMockSkeleton();

      await getOrComputeSkeletonHash(url, skeleton);
      const cached = await isSkeletonCached(url);

      expect(cached).toBe(true);
    });
  });

  describe('saveSkeletonToCache / loadSkeletonFromCache', () => {
    it('should save and load cache entry', async () => {
      const normalizedUrl = 'https://example.com/test';
      const entry = {
        hash: 'a'.repeat(64),
        extractedAt: Date.now(),
        hasLoginForm: true,
        hasPaymentForm: false,
      };

      await saveSkeletonToCache(normalizedUrl, entry);
      const loaded = await loadSkeletonFromCache(normalizedUrl);

      expect(loaded).toEqual(entry);
    });

    it('should return null for non-existent entry', async () => {
      const loaded = await loadSkeletonFromCache('https://nonexistent.com/page');
      expect(loaded).toBeNull();
    });
  });

  describe('deleteSkeletonFromCache', () => {
    it('should delete cache entry', async () => {
      const normalizedUrl = 'https://example.com/test';
      const entry = {
        hash: 'a'.repeat(64),
        extractedAt: Date.now(),
        hasLoginForm: false,
        hasPaymentForm: false,
      };

      await saveSkeletonToCache(normalizedUrl, entry);
      await deleteSkeletonFromCache(normalizedUrl);
      const loaded = await loadSkeletonFromCache(normalizedUrl);

      expect(loaded).toBeNull();
    });
  });

  describe('Hash Stability', () => {
    it('should produce stable hash across multiple extractions', async () => {
      // This test verifies the acceptance criteria:
      // "Hash is stable across reloads"
      const tagTree = 'html(body(div(form[method=post](input[type=email],input[type=password]))))';

      const skeleton1 = createMockSkeleton({ tagTree });
      const skeleton2 = createMockSkeleton({ tagTree });
      const skeleton3 = createMockSkeleton({ tagTree });

      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);
      const hash3 = await hashSkeleton(skeleton3);

      expect(hash1).toBe(hash2);
      expect(hash2).toBe(hash3);
    });
  });

  /**
   * Issue #201: Capture DOM Kit Hash on First-Seen Pages
   *
   * These tests verify the acceptance criteria:
   * - DOM skeleton is extracted and hashed (no IOC required)
   * - Hash is cached locally to avoid repeat work
   * - Runs only once per page (first-seen per normalized URL)
   */
  describe('Issue #201: First-Seen DOM Kit Hash (No IOC Required)', () => {
    it('should extract and hash skeleton without IOC match', async () => {
      // Acceptance: "Hash is generated even if no IOC matched"
      // The skeleton cache operates independently of IOC matching
      const url = 'https://example.com/some-page';
      const skeleton = createMockSkeleton({
        tagTree: 'html(body(div(p)))',
        hasLoginForm: false,
        hasPaymentForm: false,
      });

      // This simulates content script sending skeleton to background
      // No IOC check occurs - skeleton is processed regardless
      const result = await getOrComputeSkeletonHash(url, skeleton);

      expect(result.hash).toMatch(/^[a-f0-9]{64}$/);
      expect(result.cached).toBe(false); // First time = not cached
    });

    it('should cache hash by normalized URL to avoid repeat work', async () => {
      // Acceptance: "Hash is cached locally to avoid repeat work"
      const url = 'https://example.com/page';
      const skeleton = createMockSkeleton();

      // First visit - computes and caches
      const result1 = await getOrComputeSkeletonHash(url, skeleton);
      expect(result1.cached).toBe(false);

      // Second visit - uses cache (skips hash computation)
      const result2 = await getOrComputeSkeletonHash(url, skeleton);
      expect(result2.cached).toBe(true);
      expect(result2.hash).toBe(result1.hash);
    });

    it('should track first-seen per normalized URL only', async () => {
      // Acceptance: "Runs only once per page"
      const skeleton = createMockSkeleton();

      // Same page with different query params/fragments
      const url1 = 'https://example.com/login?utm=campaign#section';
      const url2 = 'https://example.com/login?ref=twitter';
      const url3 = 'https://example.com/login#header';

      // First visit
      const result1 = await getOrComputeSkeletonHash(url1, skeleton);
      expect(result1.cached).toBe(false);
      expect(result1.normalizedUrl).toBe('https://example.com/login');

      // Same normalized URL - should be cached
      const result2 = await getOrComputeSkeletonHash(url2, skeleton);
      expect(result2.cached).toBe(true);

      // Still same normalized URL
      const result3 = await getOrComputeSkeletonHash(url3, skeleton);
      expect(result3.cached).toBe(true);
    });

    it('should work for non-login non-payment pages', async () => {
      // Acceptance: Works for any page, not just sensitive forms
      const url = 'https://blog.example.com/article/hello-world';
      const skeleton = createMockSkeleton({
        tagTree: 'html(body(article(h1,p,p,p)))',
        formCount: 0,
        inputTypes: [],
        actionUrls: [],
        hasLoginForm: false,
        hasPaymentForm: false,
      });

      const result = await getOrComputeSkeletonHash(url, skeleton);

      // Hash is generated regardless of form presence
      expect(result.hash).toMatch(/^[a-f0-9]{64}$/);
      expect(result.hasLoginForm).toBe(false);
      expect(result.hasPaymentForm).toBe(false);
    });
  });

  /**
   * Issue #180: DOM Skeleton Hashing + Local Cache
   *
   * These tests explicitly verify the acceptance criteria for Issue #180:
   * - Hash computed only for unseen pages
   * - IndexedDB cache keyed by normalized URL
   * - Repeat visits skip hashing
   * - Hash is stable across reloads
   */
  describe('Issue #180: DOM Skeleton Hashing + Local Cache', () => {
    it('should compute hash only for unseen pages', async () => {
      // Acceptance: "Hash computed only for unseen pages"
      const url = 'https://example.com/unseen-page';
      const skeleton = createMockSkeleton();

      // First visit - hash is computed
      const result1 = await getOrComputeSkeletonHash(url, skeleton);
      expect(result1.cached).toBe(false);
      expect(result1.hash).toMatch(/^[a-f0-9]{64}$/);

      // Second visit - hash is NOT recomputed (cached)
      const result2 = await getOrComputeSkeletonHash(url, skeleton);
      expect(result2.cached).toBe(true);
      expect(result2.hash).toBe(result1.hash);
    });

    it('should use IndexedDB cache keyed by normalized URL', async () => {
      // Acceptance: "IndexedDB cache keyed by normalized URL"
      const skeleton = createMockSkeleton();

      // Store with one URL variant
      const result1 = await getOrComputeSkeletonHash(
        'https://EXAMPLE.COM/path?query=1#fragment',
        skeleton
      );

      // The normalized URL should be used as cache key
      expect(result1.normalizedUrl).toBe('https://example.com/path');

      // Verify stored in IndexedDB by loading directly
      const cached = await loadSkeletonFromCache('https://example.com/path');
      expect(cached).not.toBeNull();
      expect(cached?.hash).toBe(result1.hash);
    });

    it('should skip hashing on repeat visits', async () => {
      // Acceptance: "Repeat visits skip hashing"
      const url = 'https://example.com/repeat-test';
      const skeleton1 = createMockSkeleton({
        tagTree: 'html(body(div(form)))',
      });

      // First visit - computes hash
      const result1 = await getOrComputeSkeletonHash(url, skeleton1);
      expect(result1.cached).toBe(false);

      // Repeat visit with DIFFERENT skeleton
      // Hash should NOT be recomputed - uses cached value
      const skeleton2 = createMockSkeleton({
        tagTree: 'html(body(div(span)))', // Different structure
      });
      const result2 = await getOrComputeSkeletonHash(url, skeleton2);

      expect(result2.cached).toBe(true);
      // Returns the ORIGINAL hash, not a new one from skeleton2
      expect(result2.hash).toBe(result1.hash);
    });

    it('should produce stable hash across reloads', async () => {
      // Acceptance: "Hash is stable across reloads"
      const tagTree = 'html(body(main(form[method=post](input[type=email],input[type=password],button[type=submit]))))';

      // Simulate multiple page loads with identical DOM structure
      const skeleton1 = createMockSkeleton({ tagTree, extractionTimeMs: 5 });
      const skeleton2 = createMockSkeleton({ tagTree, extractionTimeMs: 8 });
      const skeleton3 = createMockSkeleton({ tagTree, extractionTimeMs: 3 });

      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);
      const hash3 = await hashSkeleton(skeleton3);

      // Same DOM structure = same hash regardless of extraction time
      expect(hash1).toBe(hash2);
      expect(hash2).toBe(hash3);

      // Hash format is valid SHA-256
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });
  });
});
