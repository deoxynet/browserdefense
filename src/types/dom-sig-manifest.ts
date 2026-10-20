/**
 * DOM Signature Threat Intel Types
 *
 * Type definitions for receiving and matching DOM signatures from threat intel feeds.
 * Enables blocking based on phishing kit detection (structural similarity) in addition
 * to URL/domain hash matching.
 *
 * Issue #XXX
 */

// ============ Signature Entry Types ============

/**
 * LSH sketches for similarity matching.
 * Each sketch is a MinHash signature (64 hash values = 512 hex chars).
 */
export interface DOMSignatureLSH {
  /** DOM layout structure sketch */
  dom_layout: string;
  /** Form structure sketch */
  form_structure: string;
  /** Script/resource structure sketch */
  script_structure: string;
}

/**
 * Single DOM signature entry in the threat feed.
 * Supports both exact hash matching and LSH similarity matching.
 */
export interface DOMSignatureEntry {
  /** DOM skeleton hash (SHA-256, 64 hex chars) */
  hash: string;

  /** Confidence score (0-100) for blocking decision */
  confidence: number;

  /** Known phishing kit ID if recognized */
  kitId?: string;

  /** Enforcement action */
  action: 'block' | 'shadow' | 'alert';

  /** LSH sketches for similarity matching (optional) */
  lsh?: DOMSignatureLSH;

  /** Similarity threshold for LSH matching (0-1, default 0.85) */
  similarityThreshold?: number;

  /** Source of the signature (for attribution) */
  source?: string;

  /** When this signature expires (Unix timestamp ms) */
  expiresAt?: number;

  /** Whether to capture screenshot on match */
  captureScreenshot?: boolean;

  /** Human-readable notes about this signature */
  notes?: string;
}

// ============ Manifest Types ============

/**
 * Delta update info for incremental signature updates.
 */
export interface DOMSignatureDeltaInfo {
  /** Source version */
  from: number;
  /** Target version */
  to: number;
  /** Relative URL to delta file */
  url: string;
  /** Size in bytes */
  size: number;
}

/**
 * DOM Signature manifest format.
 * Parallel structure to BlocklistManifest for consistency.
 */
export interface DOMSignatureManifest {
  /** Manifest version (monotonically increasing) */
  version: number;

  /** Total number of signatures */
  total_signatures: number;

  /** Number of exact-match only signatures */
  exact_count: number;

  /** Number of LSH-enabled signatures */
  lsh_count: number;

  /** SHA-256 hash of the signature data file */
  sha256_root: string;

  /** Ed25519 or P-256 signature over canonical manifest */
  signature: string;

  /** Algorithm version for future compatibility */
  algorithm_version?: string;

  /** When manifest was created (ISO 8601) */
  created_at?: string;

  /** Relative URL to full signature data file */
  data_url?: string;

  /** Available delta updates */
  deltas?: DOMSignatureDeltaInfo[];
}

// ============ Storage Types ============

/**
 * Metadata stored alongside exact-match hashes.
 * Indexed by hash for O(1) lookup after binary search confirms match.
 */
export interface DOMSignatureMetadata {
  /** Confidence score (0-100) */
  confidence: number;
  /** Enforcement action */
  action: 'block' | 'shadow' | 'alert';
  /** Known kit ID */
  kitId?: string;
  /** Expiration timestamp */
  expiresAt?: number;
  /** Whether to capture screenshot */
  captureScreenshot?: boolean;
}

/**
 * LSH signature entry with full MinHash sketches.
 * Stored separately from exact-match hashes due to different access patterns.
 */
export interface LSHSignatureEntry {
  /** Unique signature ID (hash or generated) */
  id: string;
  /** DOM layout LSH sketch */
  dom_layout_lsh: string;
  /** Form structure LSH sketch */
  form_structure_lsh: string;
  /** Script structure LSH sketch */
  script_structure_lsh: string;
  /** Confidence score */
  confidence: number;
  /** Enforcement action */
  action: 'block' | 'shadow' | 'alert';
  /** Similarity threshold (0-1) */
  similarityThreshold: number;
  /** Known kit ID */
  kitId?: string;
  /** Expiration timestamp */
  expiresAt?: number;
}

// ============ Match Result Types ============

/**
 * Result of DOM signature matching.
 */
export interface DOMSignatureMatchResult {
  /** Whether any match was found */
  matched: boolean;

  /** Match type: exact hash or LSH similarity */
  matchType: 'exact' | 'lsh' | 'none';

  /** Confidence score of the match */
  confidence: number;

  /** Recommended action */
  action: 'block' | 'shadow' | 'alert' | 'allow';

  /** Kit ID if recognized */
  kitId?: string;

  /** For LSH matches: similarity score (0-1) */
  similarity?: number;

  /** Hash that matched (for exact) or closest signature ID (for LSH) */
  matchedSignature?: string;

  /** Whether to capture screenshot */
  captureScreenshot?: boolean;
}

// ============ Update Types ============

/**
 * Configuration for DOM signature updates.
 */
export interface DOMSignatureUpdateConfig {
  /** Base endpoint URL for manifest and data */
  endpoint: string;

  /** Public key for signature verification (JWK format) */
  publicKey: JsonWebKey;

  /** Maximum retries on failure */
  maxRetries?: number;

  /** Base delay for exponential backoff (ms) */
  baseDelayMs?: number;

  /** Maximum delay cap (ms) */
  maxDelayMs?: number;

  /** Request timeout (ms) */
  timeoutMs?: number;
}

/**
 * Update metadata stored locally.
 */
export interface DOMSignatureUpdateMeta {
  /** Current version */
  version: number;
  /** When data was published */
  timestamp: string;
  /** When extension last updated */
  updatedAt: number;
  /** Number of exact-match signatures */
  exactCount: number;
  /** Number of LSH signatures */
  lshCount: number;
}

/**
 * Result of a DOM signature update attempt.
 */
export interface DOMSignatureUpdateResult {
  /** Whether update succeeded */
  success: boolean;
  /** New version (if updated) */
  version?: number;
  /** Number of exact-match signatures */
  exactCount?: number;
  /** Number of LSH signatures */
  lshCount?: number;
  /** Update type: full snapshot or delta */
  type?: 'snapshot' | 'delta';
  /** Error message if failed */
  error?: string;
}

// ============ FCM Message Types ============

/**
 * FCM message to add a DOM signature block.
 */
export interface FCMDOMSigBlockMessage {
  type: 'DOM_SIG_BLOCK';
  /** DOM skeleton hash */
  hash: string;
  /** Operation ID for acknowledgement */
  op_id: string;
  /** Confidence score */
  confidence: number;
  /** Kit ID if known */
  kitId?: string;
  /** LSH sketches for similarity blocking (optional) */
  lsh?: DOMSignatureLSH;
  /** Similarity threshold (for LSH) */
  similarityThreshold?: number;
}

/**
 * FCM message to remove a DOM signature block.
 */
export interface FCMDOMSigUnblockMessage {
  type: 'DOM_SIG_UNBLOCK';
  /** DOM skeleton hash to remove */
  hash: string;
  /** Operation ID for acknowledgement */
  op_id: string;
}

/**
 * FCM message to add a DOM signature to shadow mode.
 */
export interface FCMDOMSigShadowMessage {
  type: 'DOM_SIG_SHADOW';
  /** DOM skeleton hash */
  hash: string;
  /** Operation ID for acknowledgement */
  op_id: string;
  /** Confidence score */
  confidence: number;
  /** Kit ID if known */
  kitId?: string;
}
