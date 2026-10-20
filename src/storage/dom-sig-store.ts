/**
 * DOM Signature Store
 *
 * Storage layer for DOM signature threat intel. Supports both exact hash
 * matching (using BinaryHashSet) and LSH similarity matching (using band index).
 *
 * Architecture:
 * - Exact matches: BinaryHashSet for O(log n) lookup
 * - Metadata: Map indexed by hex hash for O(1) after match
 * - LSH band index: Map from band hash to candidate signature IDs
 * - LSH signatures: Full signature data indexed by ID
 */

import { BinaryHashSet, hexToBytes } from './binary-set';
import {
  DOM_SIG_STORE_KEY,
  DOM_SIG_META_KEY,
} from '../config/storage-keys';
import type {
  DOMSignatureEntry,
  DOMSignatureMetadata,
  LSHSignatureEntry,
  DOMSignatureUpdateMeta,
} from '../types/dom-sig-manifest';

// ============ Constants ============

/** Number of bands for LSH indexing */
const NUM_BANDS = 8;

/** Number of hash values per band (64 total / 8 bands = 8 per band) */
const ROWS_PER_BAND = 8;

/** Hex chars per hash value in LSH signature */
const HEX_PER_HASH = 8;

/** Default similarity threshold */
const DEFAULT_SIMILARITY_THRESHOLD = 0.85;

/** Expected sketch length in hex chars (64 hashes * 8 hex chars each) */
const EXPECTED_SKETCH_LENGTH = NUM_BANDS * ROWS_PER_BAND * HEX_PER_HASH;

// ============ Store State ============

/** In-memory exact match hash set */
let exactHashSet: BinaryHashSet | null = null;

/** In-memory metadata indexed by hex hash */
let metadataMap: Map<string, DOMSignatureMetadata> = new Map();

/** In-memory LSH band index: band hash -> signature IDs */
let lshBandIndex: Map<string, Set<string>> = new Map();

/** In-memory LSH signatures: ID -> full signature data */
let lshSignatures: Map<string, LSHSignatureEntry> = new Map();

/** Store version */
let storeVersion = 0;

// ============ Serialization Types ============

interface SerializedDOMSigStore {
  exactHashes: string; // base64 from BinaryHashSet
  metadata: [string, DOMSignatureMetadata][]; // Map entries
  lshBandIndex: [string, string[]][]; // Map entries (Set -> array)
  lshSignatures: [string, LSHSignatureEntry][]; // Map entries
  version: number;
}

// ============ Core Functions ============

/**
 * Initialize the store from storage.
 */
export async function initDOMSignatureStore(): Promise<void> {
  const result = await chrome.storage.local.get(DOM_SIG_STORE_KEY);
  const data = result[DOM_SIG_STORE_KEY] as SerializedDOMSigStore | undefined;

  if (!data) {
    // Initialize empty store
    exactHashSet = new BinaryHashSet();
    metadataMap = new Map();
    lshBandIndex = new Map();
    lshSignatures = new Map();
    storeVersion = 0;
    return;
  }

  // Deserialize
  exactHashSet = data.exactHashes
    ? BinaryHashSet.deserialize(data.exactHashes)
    : new BinaryHashSet();
  metadataMap = new Map(data.metadata || []);
  lshBandIndex = new Map(
    (data.lshBandIndex || []).map(([k, v]) => [k, new Set(v)])
  );
  lshSignatures = new Map(data.lshSignatures || []);
  storeVersion = data.version || 0;

  console.log(
    `[BrowserDefense] DOM signature store loaded: ${exactHashSet.count} exact, ` +
    `${lshSignatures.size} LSH signatures, version ${storeVersion}`
  );
}

/**
 * Save the store to storage.
 */
export async function saveDOMSignatureStore(): Promise<void> {
  if (!exactHashSet) {
    exactHashSet = new BinaryHashSet();
  }

  const data: SerializedDOMSigStore = {
    exactHashes: exactHashSet.serialize(),
    metadata: Array.from(metadataMap.entries()),
    lshBandIndex: Array.from(lshBandIndex.entries()).map(([k, v]) => [k, Array.from(v)]),
    lshSignatures: Array.from(lshSignatures.entries()),
    version: storeVersion,
  };

  await chrome.storage.local.set({ [DOM_SIG_STORE_KEY]: data });
}

/**
 * Add a DOM signature entry to the store.
 */
export function addDOMSignature(entry: DOMSignatureEntry): void {
  if (!exactHashSet) {
    exactHashSet = new BinaryHashSet();
  }

  // Add to exact match set
  const hashBytes = hexToBytes(entry.hash);
  exactHashSet.add(hashBytes);

  // Add metadata
  metadataMap.set(entry.hash.toLowerCase(), {
    confidence: entry.confidence,
    action: entry.action,
    kitId: entry.kitId,
    expiresAt: entry.expiresAt,
    captureScreenshot: entry.captureScreenshot,
  });

  // Add to LSH index if LSH sketches provided
  if (entry.lsh) {
    const sigId = entry.hash.toLowerCase();
    const lshEntry: LSHSignatureEntry = {
      id: sigId,
      dom_layout_lsh: entry.lsh.dom_layout,
      form_structure_lsh: entry.lsh.form_structure,
      script_structure_lsh: entry.lsh.script_structure,
      confidence: entry.confidence,
      action: entry.action,
      similarityThreshold: entry.similarityThreshold ?? DEFAULT_SIMILARITY_THRESHOLD,
      kitId: entry.kitId,
      expiresAt: entry.expiresAt,
    };

    lshSignatures.set(sigId, lshEntry);

    // Index by bands for each sketch type
    indexLSHBands(sigId, entry.lsh.dom_layout, 'dom');
    indexLSHBands(sigId, entry.lsh.form_structure, 'form');
    indexLSHBands(sigId, entry.lsh.script_structure, 'script');
  }
}

/**
 * Remove a DOM signature from the store.
 */
export function removeDOMSignature(hash: string): boolean {
  if (!exactHashSet) {
    return false;
  }

  const hashLower = hash.toLowerCase();

  // Remove from exact match set
  try {
    const hashBytes = hexToBytes(hash);
    const deleted = exactHashSet.delete(hashBytes);
    if (!deleted) {
      return false;
    }
  } catch {
    return false;
  }

  // Remove metadata
  metadataMap.delete(hashLower);

  // Remove from LSH index
  const lshEntry = lshSignatures.get(hashLower);
  if (lshEntry) {
    removeLSHBands(hashLower, lshEntry.dom_layout_lsh, 'dom');
    removeLSHBands(hashLower, lshEntry.form_structure_lsh, 'form');
    removeLSHBands(hashLower, lshEntry.script_structure_lsh, 'script');
    lshSignatures.delete(hashLower);
  }

  return true;
}

/**
 * Check if an exact hash match exists.
 */
export function hasExactMatch(hash: string): boolean {
  if (!exactHashSet) {
    return false;
  }

  try {
    const hashBytes = hexToBytes(hash);
    return exactHashSet.has(hashBytes);
  } catch {
    return false;
  }
}

/**
 * Get metadata for a hash.
 */
export function getMetadata(hash: string): DOMSignatureMetadata | undefined {
  return metadataMap.get(hash.toLowerCase());
}

/**
 * Find candidate LSH signatures that may match the given sketches.
 * Uses band hashing to find potential matches efficiently.
 */
export function findLSHCandidates(
  domLayoutLsh: string,
  formStructureLsh: string,
  scriptStructureLsh: string
): Set<string> {
  const candidates = new Set<string>();

  // Find candidates from each sketch type
  const domCandidates = findCandidatesForSketch(domLayoutLsh, 'dom');
  const formCandidates = findCandidatesForSketch(formStructureLsh, 'form');
  const scriptCandidates = findCandidatesForSketch(scriptStructureLsh, 'script');

  // Union all candidates
  for (const c of domCandidates) candidates.add(c);
  for (const c of formCandidates) candidates.add(c);
  for (const c of scriptCandidates) candidates.add(c);

  return candidates;
}

/**
 * Get LSH signature by ID.
 */
export function getLSHSignature(id: string): LSHSignatureEntry | undefined {
  return lshSignatures.get(id.toLowerCase());
}

/**
 * Clear all signatures from the store.
 */
export function clearDOMSignatureStore(): void {
  exactHashSet = new BinaryHashSet();
  metadataMap = new Map();
  lshBandIndex = new Map();
  lshSignatures = new Map();
  storeVersion = 0;
}

/**
 * Bulk load signatures (more efficient than individual adds).
 */
export function bulkLoadSignatures(entries: DOMSignatureEntry[]): void {
  // Clear existing data
  clearDOMSignatureStore();

  // Sort entries by hash for efficient bulk insert
  const sorted = [...entries].sort((a, b) => a.hash.localeCompare(b.hash));

  for (const entry of sorted) {
    addDOMSignature(entry);
  }
}

/**
 * Get store statistics.
 */
export function getDOMSignatureStats(): {
  exactCount: number;
  lshCount: number;
  version: number;
  bandIndexSize: number;
} {
  return {
    exactCount: exactHashSet?.count ?? 0,
    lshCount: lshSignatures.size,
    version: storeVersion,
    bandIndexSize: lshBandIndex.size,
  };
}

/**
 * Set store version.
 */
export function setStoreVersion(version: number): void {
  storeVersion = version;
}

/**
 * Get store version.
 */
export function getStoreVersion(): number {
  return storeVersion;
}

/**
 * Remove expired signatures.
 */
export function pruneExpiredSignatures(): number {
  const now = Date.now();
  let pruned = 0;

  // Find expired hashes
  const expiredHashes: string[] = [];
  for (const [hash, meta] of metadataMap) {
    if (meta.expiresAt && meta.expiresAt <= now) {
      expiredHashes.push(hash);
    }
  }

  // Remove them
  for (const hash of expiredHashes) {
    if (removeDOMSignature(hash)) {
      pruned++;
    }
  }

  return pruned;
}

// ============ Update Metadata Functions ============

/**
 * Save update metadata.
 */
export async function saveDOMSignatureUpdateMeta(
  meta: DOMSignatureUpdateMeta
): Promise<void> {
  await chrome.storage.local.set({ [DOM_SIG_META_KEY]: meta });
}

/**
 * Load update metadata.
 */
export async function loadDOMSignatureUpdateMeta(): Promise<DOMSignatureUpdateMeta | null> {
  const result = await chrome.storage.local.get(DOM_SIG_META_KEY);
  return result[DOM_SIG_META_KEY] ?? null;
}

// ============ LSH Band Indexing Helpers ============

/**
 * Extract bands from an LSH sketch.
 * Sketch is 512 hex chars = 64 hash values (8 chars each).
 * Split into NUM_BANDS bands of ROWS_PER_BAND values each.
 *
 * @throws Error if sketch length is invalid
 */
function extractBands(sketch: string): string[] {
  if (sketch.length !== EXPECTED_SKETCH_LENGTH) {
    throw new Error(
      `Invalid LSH sketch length: expected ${EXPECTED_SKETCH_LENGTH}, got ${sketch.length}`
    );
  }

  const bands: string[] = [];
  const bandSize = ROWS_PER_BAND * HEX_PER_HASH; // 64 hex chars per band

  for (let i = 0; i < NUM_BANDS; i++) {
    const start = i * bandSize;
    const band = sketch.slice(start, start + bandSize);
    bands.push(band);
  }

  return bands;
}

/**
 * Index a signature's LSH bands.
 * Skips empty or invalid sketches to avoid polluting the band index.
 */
function indexLSHBands(sigId: string, sketch: string, sketchType: string): void {
  // Skip empty or invalid sketches
  if (!sketch || sketch.length !== EXPECTED_SKETCH_LENGTH) {
    return;
  }

  try {
    const bands = extractBands(sketch);

    for (let i = 0; i < bands.length; i++) {
      const bandKey = `${sketchType}:${i}:${bands[i]}`;
      let sigSet = lshBandIndex.get(bandKey);
      if (!sigSet) {
        sigSet = new Set();
        lshBandIndex.set(bandKey, sigSet);
      }
      sigSet.add(sigId);
    }
  } catch {
    // extractBands throws on invalid sketch length - skip indexing
  }
}

/**
 * Remove a signature from LSH band index.
 * Handles invalid sketches gracefully.
 */
function removeLSHBands(sigId: string, sketch: string, sketchType: string): void {
  // Skip empty or invalid sketches
  if (!sketch || sketch.length !== EXPECTED_SKETCH_LENGTH) {
    return;
  }

  try {
    const bands = extractBands(sketch);

    for (let i = 0; i < bands.length; i++) {
      const bandKey = `${sketchType}:${i}:${bands[i]}`;
      const sigSet = lshBandIndex.get(bandKey);
      if (sigSet) {
        sigSet.delete(sigId);
        if (sigSet.size === 0) {
          lshBandIndex.delete(bandKey);
        }
      }
    }
  } catch {
    // extractBands throws on invalid sketch length - nothing to remove
  }
}

/**
 * Find candidate signatures for a sketch using band lookup.
 * Returns empty set for invalid sketches.
 */
function findCandidatesForSketch(sketch: string, sketchType: string): Set<string> {
  const candidates = new Set<string>();

  // Skip empty or invalid sketches
  if (!sketch || sketch.length !== EXPECTED_SKETCH_LENGTH) {
    return candidates;
  }

  try {
    const bands = extractBands(sketch);

    for (let i = 0; i < bands.length; i++) {
      const bandKey = `${sketchType}:${i}:${bands[i]}`;
      const sigSet = lshBandIndex.get(bandKey);
      if (sigSet) {
        for (const sigId of sigSet) {
          candidates.add(sigId);
        }
      }
    }
  } catch {
    // extractBands throws on invalid sketch length - return empty candidates
  }

  return candidates;
}

// ============ Exports for Testing ============

export {
  extractBands as _extractBands,
  indexLSHBands as _indexLSHBands,
  removeLSHBands as _removeLSHBands,
  findCandidatesForSketch as _findCandidatesForSketch,
  NUM_BANDS as _NUM_BANDS,
  ROWS_PER_BAND as _ROWS_PER_BAND,
  EXPECTED_SKETCH_LENGTH as _EXPECTED_SKETCH_LENGTH,
};
