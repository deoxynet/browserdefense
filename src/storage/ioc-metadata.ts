/**
 * IOC Metadata Storage
 *
 * Stores per-IOC metadata (like captureScreenshot flag) separately from
 * the hash set. This allows looking up IOC flags when a match is found.
 *
 * Storage: Uses chrome.storage.local for simplicity since metadata is small.
 * The binary hash set stores hashes only; this module adds the metadata layer.
 *
 * Reference: Issue #183 - Screenshot Capture on Block
 */

// ============ Types ============

/**
 * Metadata stored for each IOC that has special flags.
 * Only IOCs with non-default metadata are stored.
 */
export interface IOCMetadata {
  /** Whether to capture screenshot when this IOC is blocked */
  captureScreenshot?: boolean;
  /** IOC source (for analytics/filtering) */
  source?: string;
  /** When this IOC expires (ISO 8601) */
  expiresAt?: string;
}

/**
 * Map of hash (hex string) to metadata.
 */
export type IOCMetadataMap = Record<string, IOCMetadata>;

// ============ Constants ============

const STORAGE_KEY = 'blockioc_ioc_metadata';

// ============ Storage Functions ============

/**
 * Save IOC metadata map to storage.
 * Only stores IOCs that have at least one non-default flag.
 *
 * @param metadata - Map of hash to metadata
 */
export async function saveIOCMetadata(metadata: IOCMetadataMap): Promise<void> {
  // Filter out entries with no meaningful data
  const filtered: IOCMetadataMap = {};
  for (const [hash, data] of Object.entries(metadata)) {
    if (hasNonDefaultMetadata(data)) {
      filtered[hash] = data;
    }
  }

  await chrome.storage.local.set({ [STORAGE_KEY]: filtered });
  console.log(`[BlockIOC] Saved metadata for ${Object.keys(filtered).length} IOCs`);
}

/**
 * Load IOC metadata map from storage.
 *
 * @returns Map of hash to metadata, or empty object if none stored
 */
export async function loadIOCMetadata(): Promise<IOCMetadataMap> {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  return (result[STORAGE_KEY] as IOCMetadataMap) ?? {};
}

/**
 * Get metadata for a specific IOC hash.
 *
 * @param hash - SHA-256 hash (hex string)
 * @returns Metadata if found, undefined otherwise
 */
export async function getIOCMetadata(hash: string): Promise<IOCMetadata | undefined> {
  const metadata = await loadIOCMetadata();
  return metadata[hash.toLowerCase()];
}

/**
 * Set metadata for a specific IOC hash.
 *
 * @param hash - SHA-256 hash (hex string, 64 characters)
 * @param data - Metadata to set
 * @throws Error if hash is not a valid 64-character hex string
 */
export async function setIOCMetadata(hash: string, data: IOCMetadata): Promise<void> {
  // Validate hash format (64 hex chars for SHA-256)
  if (!/^[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error(`Invalid IOC hash format: expected 64 hex characters, got ${hash.length}`);
  }

  const metadata = await loadIOCMetadata();
  metadata[hash.toLowerCase()] = data;
  await saveIOCMetadata(metadata);
}

/**
 * Remove metadata for a specific IOC hash.
 *
 * @param hash - SHA-256 hash (hex string)
 */
export async function removeIOCMetadata(hash: string): Promise<void> {
  const metadata = await loadIOCMetadata();
  delete metadata[hash.toLowerCase()];
  await saveIOCMetadata(metadata);
}

/**
 * Clear all IOC metadata.
 */
export async function clearIOCMetadata(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY);
  console.log('[BlockIOC] IOC metadata cleared');
}

/**
 * Check if an IOC has screenshot capture enabled.
 * Convenience function for the common case.
 *
 * @param hash - SHA-256 hash (hex string)
 * @returns true if screenshot should be captured for this IOC
 */
export async function shouldCaptureScreenshotForIOC(hash: string): Promise<boolean> {
  const metadata = await getIOCMetadata(hash);
  return metadata?.captureScreenshot === true;
}

/**
 * Get all IOC hashes that have screenshot capture enabled.
 *
 * @returns Set of hashes with captureScreenshot: true
 */
export async function getScreenshotEnabledHashes(): Promise<Set<string>> {
  const metadata = await loadIOCMetadata();
  const hashes = new Set<string>();

  for (const [hash, data] of Object.entries(metadata)) {
    if (data.captureScreenshot === true) {
      hashes.add(hash);
    }
  }

  return hashes;
}

/**
 * Get metadata statistics.
 */
export async function getMetadataStats(): Promise<{
  totalCount: number;
  withScreenshot: number;
  withSource: number;
  withExpiration: number;
}> {
  const metadata = await loadIOCMetadata();
  let withScreenshot = 0;
  let withSource = 0;
  let withExpiration = 0;

  for (const data of Object.values(metadata)) {
    if (data.captureScreenshot) withScreenshot++;
    if (data.source) withSource++;
    if (data.expiresAt) withExpiration++;
  }

  return {
    totalCount: Object.keys(metadata).length,
    withScreenshot,
    withSource,
    withExpiration,
  };
}

// ============ Helpers ============

/**
 * Check if metadata has any non-default values worth storing.
 */
function hasNonDefaultMetadata(data: IOCMetadata): boolean {
  return (
    data.captureScreenshot === true ||
    (data.source !== undefined && data.source !== '') ||
    (data.expiresAt !== undefined && data.expiresAt !== '')
  );
}
