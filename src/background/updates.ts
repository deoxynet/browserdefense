/**
 * Blocklist update client for BrowserDefense.
 *
 * Fetches signed blocklist updates from a configured endpoint,
 * verifies signatures, and applies updates to the local blocklist.
 *
 * Features:
 * - P-256 ECDSA / Ed25519 signature verification
 * - Version tracking (rejects old updates)
 * - Delta updates (fetches delta if available, falls back to snapshot)
 * - Binary blocklist format with SHA-256 integrity verification
 * - Exponential backoff retry
 * - Stale-protect: continues with old list on failure
 */

import { BinaryHashSet, saveBlocklist, loadBlocklist } from '../storage';
import { verifyBlocklistSignature } from '../crypto/signing';
import { sha256Bytes, bytesToHex } from '../crypto/hashing';
import { reloadBlocklist } from './blocking';
import {
  UPDATE_META_KEY,
  UPDATE_CONFIG_KEY,
  BLOCKLIST_UPDATE_ALARM,
} from '../config/storage-keys';

// Re-export for test access
export { UPDATE_META_KEY, UPDATE_CONFIG_KEY, BLOCKLIST_UPDATE_ALARM } from '../config/storage-keys';

/** Default retry configuration */
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_BASE_DELAY_MS = 1000;
const DEFAULT_MAX_DELAY_MS = 30000;

/**
 * Delta info from manifest.
 */
export interface DeltaInfo {
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
 * Manifest format from blocklist endpoint.
 * Compatible with CLI output and distribution worker.
 */
export interface BlocklistManifest {
  version: number;
  total_iocs: number;
  bucket_count: number;
  sha256_root: string;
  signature: string;
  created_at?: string;
  algorithm_version?: string;
  /** Relative URL to snapshot (new format) */
  snapshot_url?: string;
  /** Available deltas (new format) */
  deltas?: DeltaInfo[];
}

/** Stored metadata about the current blocklist */
export interface UpdateMetadata {
  version: number;
  timestamp: string;
  updatedAt: number;
  hashCount: number;
}

/** Configuration for the update client */
export interface UpdateConfig {
  /** Base URL for the blocklist endpoint (e.g., https://cdn.example.com/org-slug) */
  endpoint: string;
  /** @deprecated Use snapshot_url from manifest instead */
  blocklistEndpoint?: string;
  /** P-256 or Ed25519 public key in JWK format for signature verification */
  publicKey: JsonWebKey;
  /** Maximum retry attempts (default: 3) */
  maxRetries?: number;
  /** Base delay for exponential backoff in ms (default: 1000) */
  baseDelayMs?: number;
  /** Maximum delay between retries in ms (default: 30000) */
  maxDelayMs?: number;
  /** Maximum delta size to attempt (bytes). Larger deltas will fall back to snapshot. */
  maxDeltaSize?: number;
}

/** Result of an update attempt */
export type UpdateResult =
  | { success: true; version: number; hashCount: number; type: 'full' | 'delta' | 'unchanged' }
  | { success: false; error: string; code: UpdateErrorCode };

/** Error codes for update failures */
export type UpdateErrorCode =
  | 'NETWORK_ERROR'
  | 'INVALID_SIGNATURE'
  | 'INTEGRITY_ERROR'
  | 'PARSE_ERROR'
  | 'VERSION_ERROR'
  | 'STORAGE_ERROR';

/** Default max delta size: 1MB */
const DEFAULT_MAX_DELTA_SIZE = 1024 * 1024;

/**
 * Fetch and apply a blocklist update.
 *
 * @param config - Update configuration
 * @returns Result of the update attempt
 */
export async function fetchBlocklistUpdate(config: UpdateConfig): Promise<UpdateResult> {
  const maxRetries = config.maxRetries ?? DEFAULT_MAX_RETRIES;
  const baseDelayMs = config.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  const maxDelayMs = config.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
  const maxDeltaSize = config.maxDeltaSize ?? DEFAULT_MAX_DELTA_SIZE;

  let lastError: string = 'Unknown error';

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      // Fetch manifest from endpoint
      const manifestUrl = resolveUrl(config.endpoint, 'manifest.json');
      const manifest = await fetchManifest(manifestUrl);

      // Verify signature using the unified signing module
      const isValid = await verifyBlocklistSignature(
        manifest as unknown as Record<string, unknown>,
        manifest.signature,
        config.publicKey
      );
      if (!isValid) {
        console.error('[BrowserDefense] Invalid signature on blocklist update');
        return { success: false, error: 'Invalid signature', code: 'INVALID_SIGNATURE' };
      }

      // Check version
      const meta = await getUpdateMetadata();
      if (meta && manifest.version <= meta.version) {
        console.log(`[BrowserDefense] Update version ${manifest.version} <= current ${meta.version}, skipping`);
        return { success: true, version: meta.version, hashCount: meta.hashCount, type: 'unchanged' };
      }

      // Try delta update if available and we have a previous version
      if (meta && manifest.deltas && manifest.deltas.length > 0) {
        const applicableDelta = findApplicableDelta(manifest.deltas, meta.version, maxDeltaSize);

        if (applicableDelta) {
          try {
            const deltaResult = await applyDeltaUpdate(
              config.endpoint,
              applicableDelta,
              manifest,
              meta
            );

            if (deltaResult.success) {
              // Save metadata
              await saveUpdateMetadata({
                version: manifest.version,
                timestamp: manifest.created_at || new Date().toISOString(),
                updatedAt: Date.now(),
                hashCount: deltaResult.hashCount,
              });

              // Reload in-memory blocklist
              await reloadBlocklist();

              console.log(
                `[BlockIOC] Blocklist delta updated: ${meta.version} -> ${manifest.version} ` +
                  `(${deltaResult.hashCount} hashes, +${deltaResult.added}/-${deltaResult.removed})`
              );

              return {
                success: true,
                version: manifest.version,
                hashCount: deltaResult.hashCount,
                type: 'delta',
              };
            }
          } catch (err) {
            console.warn('[BlockIOC] Delta update failed, falling back to full update:', err);
          }
        }
      }

      // Full snapshot update
      const snapshotUrl = manifest.snapshot_url
        ? resolveUrl(config.endpoint, manifest.snapshot_url)
        : config.blocklistEndpoint || deriveBlocklistUrl(manifestUrl);

      const blocklistData = await fetchBlocklistData(snapshotUrl);
      const dataHash = await computeBlocklistHash(blocklistData);

      // Verify integrity: sha256_root must match
      if (dataHash !== manifest.sha256_root) {
        console.error(`[BrowserDefense] Integrity check failed: expected ${manifest.sha256_root}, got ${dataHash}`);
        return { success: false, error: 'Blocklist integrity check failed', code: 'INTEGRITY_ERROR' };
      }

      // Apply update
      const result = await applyFullUpdate(blocklistData, manifest.total_iocs);

      // Save metadata
      await saveUpdateMetadata({
        version: manifest.version,
        timestamp: manifest.created_at || new Date().toISOString(),
        updatedAt: Date.now(),
        hashCount: result.hashCount,
      });

      // Reload in-memory blocklist so new IOCs take effect immediately
      await reloadBlocklist();

      console.log(`[BrowserDefense] Blocklist updated to version ${manifest.version} (${result.hashCount} hashes)`);

      return {
        success: true,
        version: manifest.version,
        hashCount: result.hashCount,
        type: 'full',
      };
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
      console.warn(`[BrowserDefense] Update attempt ${attempt + 1}/${maxRetries} failed: ${lastError}`);

      // Don't retry on non-retriable errors
      if (isNonRetriableError(err)) {
        break;
      }

      // Exponential backoff before retry
      if (attempt < maxRetries - 1) {
        const delay = Math.min(baseDelayMs * Math.pow(2, attempt), maxDelayMs);
        await sleep(delay);
      }
    }
  }

  // All retries exhausted - stale-protect by keeping old list
  console.error(`[BrowserDefense] Update failed after ${maxRetries} attempts, keeping old blocklist`);

  return {
    success: false,
    error: lastError,
    code: categorizeError(lastError),
  };
}

/**
 * Find an applicable delta for the current version.
 */
function findApplicableDelta(
  deltas: DeltaInfo[],
  currentVersion: number,
  maxSize: number
): DeltaInfo | null {
  // Find delta that starts from our current version
  const applicable = deltas.find((d) => d.from === currentVersion);

  if (!applicable) {
    return null;
  }

  // Check size limit
  if (applicable.size > maxSize) {
    console.log(
      `[BlockIOC] Delta size ${applicable.size} exceeds max ${maxSize}, will use snapshot`
    );
    return null;
  }

  return applicable;
}

/**
 * Apply a delta update.
 */
async function applyDeltaUpdate(
  baseUrl: string,
  delta: DeltaInfo,
  manifest: BlocklistManifest,
  _meta: UpdateMetadata
): Promise<{ success: true; hashCount: number; added: number; removed: number }> {
  // Fetch delta binary
  const deltaUrl = resolveUrl(baseUrl, delta.url);
  const response = await fetch(deltaUrl);

  if (!response.ok) {
    throw new Error(`Failed to fetch delta: HTTP ${response.status}`);
  }

  const deltaBuffer = await response.arrayBuffer();

  // Parse delta format:
  // [4 bytes: added_count (uint32 LE)]
  // [4 bytes: removed_count (uint32 LE)]
  // [added_count * 32 bytes: added hashes]
  // [removed_count * 32 bytes: removed hashes]
  const view = new DataView(deltaBuffer);
  const addedCount = view.getUint32(0, true);
  const removedCount = view.getUint32(4, true);

  const expectedSize = 8 + addedCount * 32 + removedCount * 32;
  if (deltaBuffer.byteLength !== expectedSize) {
    throw new Error(`Invalid delta size: expected ${expectedSize}, got ${deltaBuffer.byteLength}`);
  }

  const bytes = new Uint8Array(deltaBuffer);

  // Extract added hashes
  const addedHashes: Uint8Array[] = [];
  let offset = 8;
  for (let i = 0; i < addedCount; i++) {
    addedHashes.push(bytes.slice(offset, offset + 32));
    offset += 32;
  }

  // Extract removed hashes
  const removedHashes: Uint8Array[] = [];
  for (let i = 0; i < removedCount; i++) {
    removedHashes.push(bytes.slice(offset, offset + 32));
    offset += 32;
  }

  // Load current blocklist
  const blocklist = await loadBlocklist();

  // Apply removals
  for (const hash of removedHashes) {
    blocklist.delete(hash);
  }

  // Apply additions
  for (const hash of addedHashes) {
    blocklist.add(hash);
  }

  // Verify the result matches expected state
  if (blocklist.count !== manifest.total_iocs) {
    throw new Error(
      `Delta application resulted in ${blocklist.count} IOCs, expected ${manifest.total_iocs}`
    );
  }

  // Verify integrity by computing hash of resulting blocklist
  const resultHash = await computeBlocklistHashFromSet(blocklist);
  if (resultHash !== manifest.sha256_root) {
    throw new Error(
      `Delta application integrity check failed: expected ${manifest.sha256_root}, got ${resultHash}`
    );
  }

  // Save updated blocklist
  await saveBlocklist(blocklist);

  return {
    success: true,
    hashCount: blocklist.count,
    added: addedCount,
    removed: removedCount,
  };
}

/**
 * Compute SHA-256 hash of a BinaryHashSet for integrity verification.
 */
async function computeBlocklistHashFromSet(blocklist: BinaryHashSet): Promise<string> {
  const serialized = blocklist.serialize();
  const binary = atob(serialized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  const hashBytes = await sha256Bytes(bytes);
  return bytesToHex(hashBytes);
}

/**
 * Fetch the manifest from the update endpoint.
 */
async function fetchManifest(url: string): Promise<BlocklistManifest> {
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const data = await response.json();

  // Validate manifest structure
  if (!isValidManifest(data)) {
    throw new Error('Invalid manifest format');
  }

  return data as BlocklistManifest;
}

/**
 * Validate manifest structure.
 * Compatible with both old format (blocklist.b64 sibling) and new format (snapshot_url).
 */
function isValidManifest(data: unknown): data is BlocklistManifest {
  if (typeof data !== 'object' || data === null) {
    return false;
  }

  const manifest = data as Record<string, unknown>;

  return (
    typeof manifest.version === 'number' &&
    typeof manifest.total_iocs === 'number' &&
    typeof manifest.bucket_count === 'number' &&
    typeof manifest.sha256_root === 'string' &&
    typeof manifest.signature === 'string'
  );
}

/**
 * Resolve a relative URL against a base URL.
 */
function resolveUrl(base: string, relative: string): string {
  // If relative is already absolute, return it
  if (relative.startsWith('http://') || relative.startsWith('https://')) {
    return relative;
  }

  // Remove trailing filename from base if present
  let baseDir = base;
  if (!base.endsWith('/')) {
    const lastSlash = base.lastIndexOf('/');
    if (lastSlash > base.indexOf('://') + 2) {
      baseDir = base.substring(0, lastSlash + 1);
    } else {
      baseDir = base + '/';
    }
  }

  return baseDir + relative;
}

/**
 * Derive blocklist URL from manifest URL (legacy format).
 * manifest.json -> blocklist.b64
 */
function deriveBlocklistUrl(manifestUrl: string): string {
  if (manifestUrl.endsWith('/manifest.json')) {
    return manifestUrl.replace('/manifest.json', '/blocklist.b64');
  }
  if (manifestUrl.endsWith('/manifest')) {
    return manifestUrl.replace('/manifest', '/blocklist.b64');
  }
  // Append blocklist.b64 to base URL
  const base = manifestUrl.replace(/\/[^/]*$/, '');
  return `${base}/blocklist.b64`;
}

/**
 * Fetch blocklist binary data (base64 encoded).
 */
async function fetchBlocklistData(url: string): Promise<string> {
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      Accept: 'text/plain',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch blocklist: HTTP ${response.status}`);
  }

  return response.text();
}

/**
 * Compute SHA-256 hash of blocklist data for integrity verification.
 */
async function computeBlocklistHash(base64Data: string): Promise<string> {
  // Decode base64 to binary
  const binary = atob(base64Data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  // Compute SHA-256
  const hashBytes = await sha256Bytes(bytes);
  return bytesToHex(hashBytes);
}

/**
 * Apply full blocklist update from binary data.
 */
async function applyFullUpdate(
  base64Data: string,
  expectedCount: number
): Promise<{ hashCount: number }> {
  // Deserialize directly from base64
  const blocklist = BinaryHashSet.deserialize(base64Data);

  // Verify count matches expected
  if (blocklist.count !== expectedCount) {
    console.warn(`[BrowserDefense] Hash count mismatch: expected ${expectedCount}, got ${blocklist.count}`);
  }

  // Persist to storage
  await saveBlocklist(blocklist);

  return { hashCount: blocklist.count };
}

/**
 * Get stored update metadata.
 */
export async function getUpdateMetadata(): Promise<UpdateMetadata | null> {
  const result = await chrome.storage.local.get(UPDATE_META_KEY);
  const data = result[UPDATE_META_KEY];

  if (!data) {
    return null;
  }

  return data as UpdateMetadata;
}

/**
 * Save update metadata.
 */
async function saveUpdateMetadata(meta: UpdateMetadata): Promise<void> {
  await chrome.storage.local.set({ [UPDATE_META_KEY]: meta });
}

/**
 * Check if an error is non-retriable (signature/parse/integrity errors).
 */
function isNonRetriableError(err: unknown): boolean {
  if (err instanceof Error) {
    const message = err.message.toLowerCase();
    return (
      message.includes('invalid manifest') ||
      message.includes('invalid signature') ||
      message.includes('integrity') ||
      message.includes('parse')
    );
  }
  return false;
}

/**
 * Categorize an error for reporting.
 */
function categorizeError(errorMessage: string): UpdateErrorCode {
  const lower = errorMessage.toLowerCase();

  if (lower.includes('signature')) {
    return 'INVALID_SIGNATURE';
  }
  if (lower.includes('integrity')) {
    return 'INTEGRITY_ERROR';
  }
  if (lower.includes('parse') || lower.includes('format') || lower.includes('invalid manifest')) {
    return 'PARSE_ERROR';
  }
  if (lower.includes('version')) {
    return 'VERSION_ERROR';
  }
  if (lower.includes('storage')) {
    return 'STORAGE_ERROR';
  }

  return 'NETWORK_ERROR';
}

/**
 * Sleep for a given duration.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Schedule periodic blocklist updates using Chrome alarms.
 *
 * @param config - Update configuration
 * @param intervalMinutes - Update interval in minutes (default: 60)
 */
export async function scheduleUpdates(
  config: UpdateConfig,
  intervalMinutes: number = 60
): Promise<void> {
  // Store config for alarm handler
  await chrome.storage.local.set({
    [UPDATE_CONFIG_KEY]: {
      endpoint: config.endpoint,
      blocklistEndpoint: config.blocklistEndpoint,
      publicKey: config.publicKey,
      maxRetries: config.maxRetries,
      baseDelayMs: config.baseDelayMs,
      maxDelayMs: config.maxDelayMs,
      maxDeltaSize: config.maxDeltaSize,
    },
  });

  // Clear existing alarm
  await chrome.alarms.clear(BLOCKLIST_UPDATE_ALARM);

  // Create periodic alarm
  await chrome.alarms.create(BLOCKLIST_UPDATE_ALARM, {
    periodInMinutes: intervalMinutes,
    delayInMinutes: 0, // Run immediately first time
  });

  console.log(`[BrowserDefense] Scheduled blocklist updates every ${intervalMinutes} minutes`);
}

/**
 * Handle the blocklist update alarm.
 * Should be called from the alarm listener in the service worker.
 */
export async function handleUpdateAlarm(): Promise<UpdateResult | null> {
  const result = await chrome.storage.local.get(UPDATE_CONFIG_KEY);
  const config = result[UPDATE_CONFIG_KEY] as UpdateConfig | undefined;

  if (!config) {
    console.warn('[BrowserDefense] Update alarm fired but no config found');
    return null;
  }

  return fetchBlocklistUpdate(config);
}

/**
 * Force an immediate blocklist update check.
 *
 * @param config - Update configuration (if not provided, uses stored config)
 */
export async function forceUpdate(config?: UpdateConfig): Promise<UpdateResult> {
  if (!config) {
    const result = await chrome.storage.local.get(UPDATE_CONFIG_KEY);
    config = result[UPDATE_CONFIG_KEY] as UpdateConfig | undefined;

    if (!config) {
      return {
        success: false,
        error: 'No update configuration found',
        code: 'STORAGE_ERROR',
      };
    }
  }

  return fetchBlocklistUpdate(config);
}
