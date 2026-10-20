/**
 * DOM Signature Matcher
 *
 * Matching engine for DOM signature threat intel. Supports both exact hash
 * matching and LSH similarity matching for phishing kit variant detection.
 *
 * Flow:
 * 1. Try exact hash match first (fastest, O(log n))
 * 2. If no match and LSH sketches provided, try similarity matching
 * 3. LSH uses band index for efficient candidate finding, then full verification
 */

import {
  initDOMSignatureStore,
  hasExactMatch,
  getMetadata,
  findLSHCandidates,
  getLSHSignature,
  getDOMSignatureStats,
} from '../storage/dom-sig-store';
import { estimateSimilarity } from '../content/lsh-sketch';
import type { LSHSketches } from '../content/lsh-sketch';
import type { DOMSignatureMatchResult } from '../types/dom-sig-manifest';

// ============ State ============

/** Whether the store has been initialized */
let initialized = false;

// ============ Public API ============

/**
 * Initialize the matcher (loads store from storage).
 */
export async function initDOMSignatureMatcher(): Promise<void> {
  if (initialized) {
    return;
  }

  await initDOMSignatureStore();
  initialized = true;

  const stats = getDOMSignatureStats();
  console.log(
    `[BrowserDefense] DOM signature matcher initialized: ` +
    `${stats.exactCount} exact, ${stats.lshCount} LSH signatures`
  );
}

/**
 * Match a DOM skeleton against local threat intel.
 *
 * @param hash - SHA-256 hash of DOM skeleton (64 hex chars)
 * @param lshSketches - Optional LSH sketches for similarity matching
 * @returns Match result with action recommendation
 */
export async function matchDOMSignature(
  hash: string,
  lshSketches?: LSHSketches
): Promise<DOMSignatureMatchResult> {
  // Ensure initialized
  if (!initialized) {
    await initDOMSignatureMatcher();
  }

  const hashLower = hash.toLowerCase();

  // Step 1: Try exact hash match (O(log n))
  const exactResult = matchExact(hashLower);
  if (exactResult.matched) {
    console.log(
      `[BrowserDefense] DOM signature exact match: ${hashLower.slice(0, 16)}... ` +
      `(confidence: ${exactResult.confidence}, action: ${exactResult.action})`
    );
    return exactResult;
  }

  // Step 2: Try LSH similarity match if sketches provided
  if (lshSketches) {
    const lshResult = matchLSH(lshSketches);
    if (lshResult.matched) {
      console.log(
        `[BrowserDefense] DOM signature LSH match: ${lshResult.matchedSignature?.slice(0, 16)}... ` +
        `(similarity: ${lshResult.similarity?.toFixed(2)}, confidence: ${lshResult.confidence}, action: ${lshResult.action})`
      );
      return lshResult;
    }
  }

  // No match
  return {
    matched: false,
    matchType: 'none',
    confidence: 0,
    action: 'allow',
  };
}

/**
 * Check if any signatures are loaded.
 */
export function hasDOMSignatures(): boolean {
  const stats = getDOMSignatureStats();
  return stats.exactCount > 0 || stats.lshCount > 0;
}

/**
 * Get matcher statistics.
 */
export function getDOMMatcherStats(): {
  initialized: boolean;
  exactCount: number;
  lshCount: number;
  version: number;
} {
  const stats = getDOMSignatureStats();
  return {
    initialized,
    exactCount: stats.exactCount,
    lshCount: stats.lshCount,
    version: stats.version,
  };
}

// ============ Exact Matching ============

/**
 * Try exact hash match.
 */
function matchExact(hash: string): DOMSignatureMatchResult {
  if (!hasExactMatch(hash)) {
    return {
      matched: false,
      matchType: 'none',
      confidence: 0,
      action: 'allow',
    };
  }

  // Get metadata for matched hash
  const metadata = getMetadata(hash);
  if (!metadata) {
    // Defensive fallback: hash exists in BinaryHashSet but metadata is missing.
    // This can happen if store state becomes inconsistent (e.g., interrupted save).
    // Default to blocking with high confidence since the hash was explicitly added.
    console.warn(
      `[BrowserDefense] DOM signature metadata missing for hash: ${hash.slice(0, 16)}...`
    );
    return {
      matched: true,
      matchType: 'exact',
      confidence: 80,
      action: 'block',
      matchedSignature: hash,
    };
  }

  // Check expiration
  if (metadata.expiresAt && metadata.expiresAt <= Date.now()) {
    return {
      matched: false,
      matchType: 'none',
      confidence: 0,
      action: 'allow',
    };
  }

  return {
    matched: true,
    matchType: 'exact',
    confidence: metadata.confidence,
    action: metadata.action,
    kitId: metadata.kitId,
    matchedSignature: hash,
    captureScreenshot: metadata.captureScreenshot,
  };
}

// ============ LSH Similarity Matching ============

/**
 * Try LSH similarity match.
 * Uses band index to find candidates, then verifies with full similarity.
 */
function matchLSH(sketches: LSHSketches): DOMSignatureMatchResult {
  // Find candidate signatures using band index
  const candidates = findLSHCandidates(
    sketches.dom_layout_lsh,
    sketches.form_structure_lsh,
    sketches.script_structure_lsh
  );

  if (candidates.size === 0) {
    return {
      matched: false,
      matchType: 'none',
      confidence: 0,
      action: 'allow',
    };
  }

  // Verify candidates with full similarity computation
  let bestMatch: {
    signature: string;
    similarity: number;
    entry: NonNullable<ReturnType<typeof getLSHSignature>>;
  } | null = null;

  for (const sigId of candidates) {
    const entry = getLSHSignature(sigId);
    if (!entry) continue;

    // Check expiration
    if (entry.expiresAt && entry.expiresAt <= Date.now()) {
      continue;
    }

    // Compute similarity for each sketch type
    const domSimilarity = estimateSimilarity(
      sketches.dom_layout_lsh,
      entry.dom_layout_lsh
    );
    const formSimilarity = estimateSimilarity(
      sketches.form_structure_lsh,
      entry.form_structure_lsh
    );
    const scriptSimilarity = estimateSimilarity(
      sketches.script_structure_lsh,
      entry.script_structure_lsh
    );

    // Use weighted average (DOM layout is most important)
    const combinedSimilarity =
      domSimilarity * 0.5 + formSimilarity * 0.3 + scriptSimilarity * 0.2;

    // Check threshold
    if (combinedSimilarity >= entry.similarityThreshold) {
      if (!bestMatch || combinedSimilarity > bestMatch.similarity) {
        bestMatch = {
          signature: sigId,
          similarity: combinedSimilarity,
          entry,
        };
      }
    }
  }

  if (!bestMatch) {
    return {
      matched: false,
      matchType: 'none',
      confidence: 0,
      action: 'allow',
    };
  }

  return {
    matched: true,
    matchType: 'lsh',
    confidence: bestMatch.entry.confidence,
    action: bestMatch.entry.action,
    kitId: bestMatch.entry.kitId,
    similarity: bestMatch.similarity,
    matchedSignature: bestMatch.signature,
  };
}

// ============ Singleton Instance ============

let matcherInstance: DOMSignatureMatcher | null = null;

/**
 * DOM Signature Matcher class for OOP-style usage.
 */
export class DOMSignatureMatcher {
  private initialized = false;

  async init(): Promise<void> {
    if (this.initialized) return;
    await initDOMSignatureMatcher();
    this.initialized = true;
  }

  async match(
    hash: string,
    lshSketches?: LSHSketches
  ): Promise<DOMSignatureMatchResult> {
    await this.init();
    return matchDOMSignature(hash, lshSketches);
  }

  hasSignatures(): boolean {
    return hasDOMSignatures();
  }

  getStats(): ReturnType<typeof getDOMMatcherStats> {
    return getDOMMatcherStats();
  }
}

/**
 * Get singleton matcher instance.
 */
export function getDOMSignatureMatcher(): DOMSignatureMatcher {
  if (!matcherInstance) {
    matcherInstance = new DOMSignatureMatcher();
  }
  return matcherInstance;
}

// ============ Exports for Testing ============

export {
  matchExact as _matchExact,
  matchLSH as _matchLSH,
};
