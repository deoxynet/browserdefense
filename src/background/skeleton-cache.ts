/**
 * DOM Skeleton Cache
 *
 * Caches SHA-256 hashes of DOM skeletons by normalized URL.
 * Repeat visits skip hashing - only unseen pages are hashed.
 *
 * This makes the phishing detection system both proactive AND efficient.
 *
 * Uses the IndexedDB meta store to persist cache entries.
 */

import { sha256 } from '../crypto/hashing';
import { saveMetaToIDB, loadMetaFromIDB, deleteMetaFromIDB } from '../storage/idb';
import type { DOMSkeleton } from '../content/dom-skeleton';

/** Prefix for skeleton cache keys in meta store */
const SKELETON_CACHE_PREFIX = 'skeleton:';

/**
 * Result of processing a skeleton.
 */
export interface SkeletonHashResult {
  /** SHA-256 hash of the skeleton */
  hash: string;
  /** Whether result came from cache */
  cached: boolean;
  /** Normalized URL used as cache key */
  normalizedUrl: string;
  /** Whether page has login form */
  hasLoginForm: boolean;
  /** Whether page has payment form */
  hasPaymentForm: boolean;
}

/**
 * Skeleton cache entry stored in IndexedDB.
 */
export interface SkeletonCacheEntry {
  /** SHA-256 hash of the skeleton */
  hash: string;
  /** When the skeleton was extracted (epoch ms) */
  extractedAt: number;
  /** Whether page had a login form */
  hasLoginForm: boolean;
  /** Whether page had a payment form */
  hasPaymentForm: boolean;
}

/**
 * Normalize URL for cache key.
 * Uses scheme + host + path (no query params or fragments).
 *
 * Examples:
 * - https://example.com/login?foo=bar#section -> https://example.com/login
 * - HTTP://Example.COM:443/Path -> https://example.com/Path
 */
export function normalizeUrlForCache(url: string): string {
  try {
    const parsed = new URL(url);

    // Lowercase scheme
    let normalized = parsed.protocol.toLowerCase() + '//';

    // Lowercase host, remove trailing dot
    normalized += parsed.hostname.toLowerCase().replace(/\.$/, '');

    // Add port only if non-default
    const isDefaultPort =
      (parsed.protocol === 'http:' && parsed.port === '80') ||
      (parsed.protocol === 'https:' && parsed.port === '443') ||
      parsed.port === '';

    if (!isDefaultPort && parsed.port) {
      normalized += ':' + parsed.port;
    }

    // Add path (decode and re-encode for consistency)
    let path = parsed.pathname;
    try {
      path = decodeURIComponent(path);
    } catch {
      // Invalid encoding, keep as-is
    }

    // Normalize path segments
    path = path
      .split('/')
      .map((segment) => encodeURIComponent(segment))
      .join('/');

    if (!path) path = '/';
    normalized += path;

    return normalized;
  } catch {
    // Invalid URL, return lowercase as-is
    return url.toLowerCase();
  }
}

/**
 * Get the cache key for a URL.
 */
function getCacheKey(normalizedUrl: string): string {
  return SKELETON_CACHE_PREFIX + normalizedUrl;
}

/**
 * Compute SHA-256 hash of a DOM skeleton.
 * The hash is computed from the deterministic tagTree string.
 *
 * @param skeleton - DOM skeleton to hash
 * @returns SHA-256 hash as hex string
 */
export async function hashSkeleton(skeleton: DOMSkeleton): Promise<string> {
  // Hash the tagTree which is the deterministic structure representation
  return sha256(skeleton.tagTree);
}

/**
 * Save skeleton hash to cache.
 * @param normalizedUrl - Normalized URL as cache key
 * @param entry - Cache entry with hash and metadata
 */
export async function saveSkeletonToCache(
  normalizedUrl: string,
  entry: SkeletonCacheEntry
): Promise<void> {
  await saveMetaToIDB(getCacheKey(normalizedUrl), entry);
}

/**
 * Load skeleton hash from cache.
 * @param normalizedUrl - Normalized URL as cache key
 * @returns Cache entry or null if not found
 */
export async function loadSkeletonFromCache(
  normalizedUrl: string
): Promise<SkeletonCacheEntry | null> {
  return loadMetaFromIDB<SkeletonCacheEntry>(getCacheKey(normalizedUrl));
}

/**
 * Delete skeleton hash from cache.
 * @param normalizedUrl - Normalized URL as cache key
 */
export async function deleteSkeletonFromCache(normalizedUrl: string): Promise<void> {
  await deleteMetaFromIDB(getCacheKey(normalizedUrl));
}

/**
 * Get or compute skeleton hash for a URL.
 *
 * If URL is in cache, returns cached hash (skips hashing).
 * If URL is new, computes hash, caches it, and returns result.
 *
 * @param url - Page URL
 * @param skeleton - DOM skeleton extracted from page
 * @returns Hash result with cache status
 */
export async function getOrComputeSkeletonHash(
  url: string,
  skeleton: DOMSkeleton
): Promise<SkeletonHashResult> {
  const normalizedUrl = normalizeUrlForCache(url);

  // Check cache first
  const cached = await loadSkeletonFromCache(normalizedUrl);
  if (cached) {
    console.log('[BrowserDefense] Skeleton cache hit:', normalizedUrl);
    return {
      hash: cached.hash,
      cached: true,
      normalizedUrl,
      hasLoginForm: cached.hasLoginForm,
      hasPaymentForm: cached.hasPaymentForm,
    };
  }

  // Cache miss - compute hash
  console.log('[BrowserDefense] Skeleton cache miss, computing hash:', normalizedUrl);
  const hash = await hashSkeleton(skeleton);

  // Store in cache
  const entry: SkeletonCacheEntry = {
    hash,
    extractedAt: Date.now(),
    hasLoginForm: skeleton.hasLoginForm,
    hasPaymentForm: skeleton.hasPaymentForm,
  };
  await saveSkeletonToCache(normalizedUrl, entry);

  return {
    hash,
    cached: false,
    normalizedUrl,
    hasLoginForm: skeleton.hasLoginForm,
    hasPaymentForm: skeleton.hasPaymentForm,
  };
}

/**
 * Check if a URL's skeleton is already cached.
 *
 * @param url - Page URL
 * @returns True if cached, false otherwise
 */
export async function isSkeletonCached(url: string): Promise<boolean> {
  const normalizedUrl = normalizeUrlForCache(url);
  const cached = await loadSkeletonFromCache(normalizedUrl);
  return cached !== null;
}

/**
 * Handle DOM_SKELETON message from content script.
 *
 * This is the main entry point for skeleton processing.
 * Computes hash only for unseen pages (cache miss).
 *
 * @param message - Message from content script
 * @returns Hash result
 */
export async function handleSkeletonMessage(
  message: {
    type: string;
    payload: DOMSkeleton;
    url: string;
    timestamp: number;
  }
): Promise<SkeletonHashResult | null> {
  if (message.type !== 'DOM_SKELETON') {
    return null;
  }

  const result = await getOrComputeSkeletonHash(message.url, message.payload);

  if (result.cached) {
    console.log(
      `[BrowserDefense] Repeat visit (cached): ${result.normalizedUrl.slice(0, 50)}...`
    );
  } else {
    console.log(
      `[BrowserDefense] New page fingerprinted: ${result.normalizedUrl.slice(0, 50)}... ` +
      `(hash: ${result.hash.slice(0, 16)}...)`
    );
  }

  return result;
}

/**
 * Clear the skeleton cache.
 * Note: This requires iterating all keys in the meta store,
 * which is not efficient. For production, consider a dedicated store.
 */
export async function clearCache(): Promise<void> {
  // Since we use the meta store with prefixed keys, we can't easily clear
  // just the skeleton cache without iterating all keys.
  // For now, this is a no-op. A dedicated store would be better.
  console.log('[BrowserDefense] Skeleton cache clear requested (no-op with meta store)');
}
