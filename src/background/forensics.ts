/**
 * Forensics capture and queue for BrowserDefense.
 *
 * Captures forensic data on block events and queues for encrypted upload.
 * Implements fail-safe queue with offline recovery.
 *
 * Reference: docs/Architecture_Hardening_Specification.md Section 2
 */

import type { FormSchema } from '../content/form-schema';
import type { TLSMetadata } from '../types/tls-metadata';
import { encryptForensics, type RSAPublicKeyJWK } from '../crypto/encryption';
import {
  CONFIG_STORAGE_KEY,
  FORENSICS_QUEUE_KEY,
  REDIRECT_CHAINS_KEY,
} from '../config/storage-keys';

// Re-export for test access
export { FORENSICS_QUEUE_KEY, REDIRECT_CHAINS_KEY } from '../config/storage-keys';

// ============ Types ============

export interface ForensicsPayload {
  /** The blocked URL */
  blockedUrl: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Redirect chain leading to the blocked URL (if captured) */
  redirectChain?: string[];
  /** Chrome tab ID */
  tabId: number;
  /** Frame ID (0 = main frame) */
  frameId: number;
  /** What triggered the navigation (e.g., link click, typed URL) */
  initiator?: string;
  /** Normalized URL that was matched */
  normalizedUrl?: string;
  /** Block reason */
  reason: string;
  /**
   * Whether this is a demo block (Issue #571).
   * Demo blocks are tagged so SOC teams can filter them out.
   */
  isDemo?: boolean;
  /**
   * Screenshot data (opt-in, encrypted separately).
   * Only present if:
   * 1. Global screenshot feature is enabled
   * 2. IOC has captureScreenshot: true
   */
  screenshot?: {
    /** SHA-256 hash of the screenshot image (for reference) */
    imageHash: string;
    /** Image dimensions */
    dimensions: { width: number; height: number };
    /** Capture timestamp (may differ slightly from block timestamp) */
    capturedAt: string;
  };
  /**
   * Form schemas from the blocked page (structure only, no values).
   * PRIVACY: Contains only field names, types, and attributes - never user input.
   * Reference: Issue #167 - P1: Form Schema Capture
   */
  formSchemas?: FormSchema[];
  /**
   * TLS & certificate metadata from the blocked page.
   * PRIVACY: Contains only public certificate and connection metadata - no keys or session data.
   * NOTE: Certificate details require server-side enrichment (Chrome API limitation).
   * Reference: Issue #168 - P2: TLS & Certificate Metadata Capture
   */
  tlsMetadata?: TLSMetadata;
}

export interface EncryptedForensics {
  /** Organization ID */
  orgId: string;
  /** Key version used for encryption */
  keyVersion: number;
  /** Base64-encoded IV */
  iv: string;
  /** Base64-encoded wrapped AES key */
  wrappedKey: string;
  /** Base64-encoded ciphertext */
  ciphertext: string;
}

export interface QueuedForensics {
  /** Unique ID for this queued item */
  id: string;
  /** Original forensics payload (for debugging) */
  payload: ForensicsPayload;
  /** Encrypted payload ready for upload */
  encrypted?: EncryptedForensics;
  /** Number of upload attempts */
  attempts: number;
  /** ISO 8601 timestamp of last attempt */
  lastAttempt?: string;
  /** ISO 8601 timestamp when queued */
  queuedAt: string;
}

// ============ Constants ============

const STORAGE_KEY = FORENSICS_QUEUE_KEY;
const MAX_QUEUE_SIZE = 1000;
const MAX_RETRY_ATTEMPTS = 10;
const BASE_RETRY_DELAY_MS = 5000;

// Rate limiting constants (Issue #603)
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute window
const RATE_LIMIT_MAX_EVENTS = 10; // Max 10 events per window
const QUEUE_WARNING_THRESHOLD = 0.8; // Warn at 80% capacity

// ============ Rate Limiter (Issue #603) ============

/**
 * Sliding window rate limiter for forensics capture.
 * Prevents abuse by limiting events to RATE_LIMIT_MAX_EVENTS per minute.
 */
const rateLimitTimestamps: number[] = [];
let rateLimitExceededCount = 0;

/**
 * Check if a new event should be allowed under rate limiting.
 * @returns true if allowed, false if rate limited
 */
export function checkRateLimit(): boolean {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW_MS;

  // Remove timestamps outside the window
  while (rateLimitTimestamps.length > 0 && rateLimitTimestamps[0] < windowStart) {
    rateLimitTimestamps.shift();
  }

  // Check if at limit
  if (rateLimitTimestamps.length >= RATE_LIMIT_MAX_EVENTS) {
    rateLimitExceededCount++;
    // Log warning on first occurrence and every 10th after
    if (rateLimitExceededCount === 1 || rateLimitExceededCount % 10 === 0) {
      console.warn(
        `[BrowserDefense] Rate limit exceeded: ${rateLimitTimestamps.length}/${RATE_LIMIT_MAX_EVENTS} events in last minute ` +
          `(total exceeded: ${rateLimitExceededCount})`
      );
    }
    return false;
  }

  // Record this event
  rateLimitTimestamps.push(now);
  return true;
}

/**
 * Get rate limiter statistics.
 */
export function getRateLimitStats(): {
  eventsInWindow: number;
  maxEvents: number;
  windowMs: number;
  exceededCount: number;
} {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW_MS;

  // Count events in current window
  let count = 0;
  for (const ts of rateLimitTimestamps) {
    if (ts >= windowStart) count++;
  }

  return {
    eventsInWindow: count,
    maxEvents: RATE_LIMIT_MAX_EVENTS,
    windowMs: RATE_LIMIT_WINDOW_MS,
    exceededCount: rateLimitExceededCount,
  };
}

/**
 * Reset rate limiter state (for testing).
 */
export function _resetRateLimiter(): void {
  rateLimitTimestamps.length = 0;
  rateLimitExceededCount = 0;
}

// ============ Queue Lock (Mutex) ============

/**
 * Promise-based mutex for serializing queue operations.
 * Prevents read-modify-write race conditions when multiple
 * concurrent calls try to modify the queue.
 */
let queueLock: Promise<void> = Promise.resolve();

/**
 * Execute a function while holding the queue lock.
 * Operations are serialized - each waits for the previous to complete.
 */
async function withQueueLock<T>(fn: () => Promise<T>): Promise<T> {
  // Capture current lock - we'll wait for it
  const previousLock = queueLock;

  // Create resolver for our lock
  let releaseLock: () => void;
  queueLock = new Promise<void>((resolve) => {
    releaseLock = resolve;
  });

  try {
    // Wait for any pending operations to complete
    await previousLock;
    // Execute our operation
    return await fn();
  } finally {
    // Release lock for next operation
    releaseLock!();
  }
}

// ============ Redirect Chain Tracking (Persistent) ============
//
// Redirect chains are persisted to chrome.storage.session to survive
// MV3 service worker suspension. The session storage clears on browser
// restart which is appropriate for per-session redirect tracking.
//
// Reference: Issue #234 - Redirect chain lost on SW suspend

const REDIRECT_STORAGE_KEY = REDIRECT_CHAINS_KEY;
const MAX_CHAIN_LENGTH = 20;
const PERSIST_DEBOUNCE_MS = 100;

/** In-memory cache for fast synchronous access */
const redirectChains = new Map<number, string[]>();

/** Whether we've restored from storage */
let redirectChainsRestored = false;

/** Pending persist timeout for debouncing */
let persistTimeout: ReturnType<typeof setTimeout> | null = null;

/** Timestamp tracking for chain expiry (24 hours) */
const chainTimestamps = new Map<number, number>();
const CHAIN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Restore redirect chains from session storage.
 * Call this on service worker startup.
 */
export async function restoreRedirectChains(): Promise<void> {
  if (redirectChainsRestored) return;

  try {
    // Try session storage first (survives SW suspension)
    const storage = chrome.storage.session ?? chrome.storage.local;
    const result = await storage.get(REDIRECT_STORAGE_KEY);
    const stored = result[REDIRECT_STORAGE_KEY] as
      | {
          chains: Record<string, string[]>;
          timestamps: Record<string, number>;
        }
      | undefined;

    if (stored?.chains) {
      const now = Date.now();
      let expiredCount = 0;

      for (const [tabIdStr, chain] of Object.entries(stored.chains)) {
        const tabId = parseInt(tabIdStr, 10);
        const timestamp = stored.timestamps?.[tabIdStr] ?? now;

        // Skip expired chains (older than 24 hours)
        if (now - timestamp > CHAIN_TTL_MS) {
          expiredCount++;
          continue;
        }

        redirectChains.set(tabId, chain);
        chainTimestamps.set(tabId, timestamp);
      }

      console.log(
        `[BrowserDefense] Restored ${redirectChains.size} redirect chains from storage` +
          (expiredCount > 0 ? ` (${expiredCount} expired)` : '')
      );
    }
  } catch (err) {
    console.warn('[BrowserDefense] Failed to restore redirect chains:', err);
  }

  redirectChainsRestored = true;
}

/**
 * Persist redirect chains to session storage.
 * Debounced to batch rapid updates.
 */
function persistRedirectChains(): void {
  if (persistTimeout) {
    clearTimeout(persistTimeout);
  }

  persistTimeout = setTimeout(async () => {
    persistTimeout = null;

    try {
      const chains: Record<string, string[]> = {};
      const timestamps: Record<string, number> = {};

      for (const [tabId, chain] of redirectChains) {
        chains[tabId.toString()] = chain;
        timestamps[tabId.toString()] = chainTimestamps.get(tabId) ?? Date.now();
      }

      const storage = chrome.storage.session ?? chrome.storage.local;
      await storage.set({
        [REDIRECT_STORAGE_KEY]: { chains, timestamps },
      });
    } catch (err) {
      console.warn('[BrowserDefense] Failed to persist redirect chains:', err);
    }
  }, PERSIST_DEBOUNCE_MS);
}

/**
 * Track a URL in the redirect chain for a tab.
 * Call this on webNavigation events to build the chain.
 * Persists to storage to survive SW suspension.
 */
export function trackRedirect(tabId: number, url: string): void {
  if (!redirectChains.has(tabId)) {
    redirectChains.set(tabId, []);
    chainTimestamps.set(tabId, Date.now());
  }
  const chain = redirectChains.get(tabId)!;

  // Avoid duplicates
  if (chain[chain.length - 1] !== url) {
    chain.push(url);
  }

  // Limit chain length
  if (chain.length > MAX_CHAIN_LENGTH) {
    chain.shift();
  }

  // Persist to storage (debounced)
  persistRedirectChains();
}

/**
 * Get and clear the redirect chain for a tab.
 * Removes from both memory and storage.
 */
export function getRedirectChain(tabId: number): string[] | undefined {
  const chain = redirectChains.get(tabId);
  redirectChains.delete(tabId);
  chainTimestamps.delete(tabId);

  // Persist removal to storage
  persistRedirectChains();

  return chain && chain.length > 1 ? chain : undefined;
}

/**
 * Clear redirect tracking for a tab (e.g., on tab close).
 * Removes from both memory and storage.
 */
export function clearRedirectChain(tabId: number): void {
  redirectChains.delete(tabId);
  chainTimestamps.delete(tabId);

  // Persist removal to storage
  persistRedirectChains();
}

/**
 * Clear all redirect chains (for testing or reset).
 */
export async function clearAllRedirectChains(): Promise<void> {
  redirectChains.clear();
  chainTimestamps.clear();

  try {
    const storage = chrome.storage.session ?? chrome.storage.local;
    await storage.remove(REDIRECT_STORAGE_KEY);
    console.log('[BrowserDefense] All redirect chains cleared');
  } catch (err) {
    console.warn('[BrowserDefense] Failed to clear redirect chains from storage:', err);
  }
}

/**
 * Get redirect chain statistics.
 */
export function getRedirectChainStats(): {
  activeChains: number;
  totalUrls: number;
  oldestChainAge?: number;
} {
  let totalUrls = 0;
  let oldestTimestamp: number | undefined;
  const now = Date.now();

  for (const [tabId, chain] of redirectChains) {
    totalUrls += chain.length;
    const timestamp = chainTimestamps.get(tabId);
    if (timestamp && (!oldestTimestamp || timestamp < oldestTimestamp)) {
      oldestTimestamp = timestamp;
    }
  }

  return {
    activeChains: redirectChains.size,
    totalUrls,
    oldestChainAge: oldestTimestamp ? now - oldestTimestamp : undefined,
  };
}

// ============ Forensics Capture ============

/**
 * Options for capturing forensics.
 */
export interface CaptureForensicsOptions {
  /** Reason for the block */
  reason?: string;
  /** Form schemas from the page (structure only, no values) */
  formSchemas?: FormSchema[];
  /** TLS & certificate metadata (no private data) */
  tlsMetadata?: TLSMetadata;
  /** Whether this is a demo block (Issue #571) */
  isDemo?: boolean;
}

/**
 * Capture forensics data for a blocked navigation.
 *
 * Supports two signatures for backward compatibility:
 * - captureForensics(details, normalizedUrl, options)       // New signature
 * - captureForensics(details, normalizedUrl, reason, formSchemas, tlsMetadata)  // Old signature
 *
 * @param details - Navigation details from Chrome
 * @param normalizedUrl - Normalized URL that was matched
 * @param reasonOrOptions - Either reason string (old) or CaptureForensicsOptions (new)
 * @param formSchemas - Form schemas (only used with old signature)
 * @param tlsMetadataArg - TLS metadata (only used with old signature)
 */
export function captureForensics(
  details: chrome.webNavigation.WebNavigationParentedCallbackDetails,
  normalizedUrl: string,
  reasonOrOptions?: string | CaptureForensicsOptions,
  formSchemas?: FormSchema[],
  tlsMetadataArg?: TLSMetadata
): ForensicsPayload {
  // Parse arguments - support both old and new signatures
  let reason: string;
  let schemas: FormSchema[] | undefined;
  let tls: TLSMetadata | undefined;
  let isDemo: boolean | undefined;

  if (typeof reasonOrOptions === 'object') {
    // New signature: options object
    reason = reasonOrOptions.reason ?? 'ioc_match';
    schemas = reasonOrOptions.formSchemas;
    tls = reasonOrOptions.tlsMetadata;
    isDemo = reasonOrOptions.isDemo;
  } else {
    // Old signature: positional arguments
    reason = reasonOrOptions ?? 'ioc_match';
    schemas = formSchemas;
    tls = tlsMetadataArg;
  }

  const redirectChain = getRedirectChain(details.tabId);

  return {
    blockedUrl: details.url,
    timestamp: new Date().toISOString(),
    redirectChain,
    tabId: details.tabId,
    frameId: details.frameId,
    initiator: (details as { initiator?: string }).initiator,
    normalizedUrl,
    reason,
    isDemo: isDemo || undefined, // Only include if true
    formSchemas: schemas && schemas.length > 0 ? schemas : undefined,
    tlsMetadata: tls,
  };
}

// ============ Queue Management ============

/**
 * Add forensics to the upload queue.
 * Uses mutex to prevent race conditions on concurrent calls.
 *
 * @param payload - Forensics payload to queue
 * @param encrypted - Optional pre-encrypted payload
 * @returns true if queued successfully, false if rate limited
 */
export async function queueForensics(
  payload: ForensicsPayload,
  encrypted?: EncryptedForensics
): Promise<boolean> {
  // Rate limiting check (Issue #603) - before acquiring lock
  if (!checkRateLimit()) {
    console.warn(`[BrowserDefense] Forensics dropped due to rate limit: ${payload.blockedUrl}`);
    return false;
  }

  return withQueueLock(async () => {
    const queue = await getQueue();

    // Queue depth warning at 80% capacity (Issue #603)
    const warningThreshold = Math.floor(MAX_QUEUE_SIZE * QUEUE_WARNING_THRESHOLD);
    if (queue.length >= warningThreshold && queue.length % 50 === 0) {
      console.warn(
        `[BrowserDefense] Queue depth warning: ${queue.length}/${MAX_QUEUE_SIZE} (${Math.round((queue.length / MAX_QUEUE_SIZE) * 100)}% full)`
      );
    }

    // Prevent unbounded queue growth
    if (queue.length >= MAX_QUEUE_SIZE) {
      console.warn('[BrowserDefense] Forensics queue full, dropping oldest entry');
      queue.shift();
    }

    const item: QueuedForensics = {
      id: crypto.randomUUID(),
      payload,
      encrypted,
      attempts: 0,
      queuedAt: new Date().toISOString(),
    };

    queue.push(item);
    await saveQueue(queue);
    await updateBadge(queue.length);

    console.log(`[BrowserDefense] Forensics queued: ${item.id}`);
    return true;
  });
}

/**
 * Get the current forensics queue.
 */
export async function getQueue(): Promise<QueuedForensics[]> {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  return result[STORAGE_KEY] ?? [];
}

/**
 * Save the forensics queue.
 */
async function saveQueue(queue: QueuedForensics[]): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: queue });
}

/**
 * Remove an item from the queue by ID.
 * Uses mutex to prevent race conditions.
 */
export async function removeFromQueue(id: string): Promise<void> {
  return withQueueLock(async () => {
    const queue = await getQueue();
    const filtered = queue.filter((item) => item.id !== id);
    await saveQueue(filtered);
    await updateBadge(filtered.length);
  });
}

/**
 * Clear the entire queue.
 * Uses mutex to prevent race conditions.
 */
export async function clearQueue(): Promise<void> {
  return withQueueLock(async () => {
    await chrome.storage.local.remove(STORAGE_KEY);
    await updateBadge(0);
  });
}

// ============ Upload & Retry ============

/**
 * Attempt to upload forensics immediately.
 * If upload fails, queues for later retry.
 *
 * SECURITY: Zero-knowledge policy - encryption is REQUIRED.
 * This function will NOT send plaintext data under any circumstances.
 * If encryption fails, the payload is queued for later retry but never sent unencrypted.
 *
 * @param payload - Forensics payload to upload
 * @param uploadUrl - URL to POST encrypted forensics
 * @param encryptFn - REQUIRED function to encrypt the payload (enforces zero-knowledge)
 * @returns true if upload succeeded, false if queued
 */
export async function uploadForensics(
  payload: ForensicsPayload,
  uploadUrl: string,
  encryptFn: (payload: ForensicsPayload) => Promise<EncryptedForensics>
): Promise<boolean> {
  let encrypted: EncryptedForensics;

  // SECURITY: Encryption is mandatory - no plaintext fallback
  try {
    encrypted = await encryptFn(payload);
  } catch (err) {
    console.error('[BrowserDefense] Encryption failed, queueing for retry (no plaintext upload):', err);
    // Queue WITHOUT encrypted field - retry will attempt encryption again
    await queueForensics(payload);
    return false;
  }

  // Attempt upload with encrypted data only
  try {
    const response = await fetch(uploadUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(encrypted),
      signal: AbortSignal.timeout(10000), // 10s timeout
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    console.log('[BrowserDefense] Forensics uploaded successfully');
    return true;
  } catch (err) {
    console.warn('[BrowserDefense] Upload failed, queueing:', (err as Error).message);
    // Queue WITH encrypted data for retry
    await queueForensics(payload, encrypted);
    return false;
  }
}

/**
 * Retry uploading pending forensics from the queue.
 * Called by heartbeat alarm and online event.
 *
 * SECURITY: Zero-knowledge policy - only uploads items with encrypted data.
 * Items without encryption are kept in queue for later encryption attempt
 * but are NEVER sent as plaintext.
 *
 * Uses mutex to prevent race conditions with concurrent queue operations.
 * The lock is held during the entire read-process-write cycle to ensure
 * items added during processing aren't lost.
 *
 * @param uploadUrl - Optional URL to POST forensics (uses config if not provided)
 * @param encryptFn - Optional function to encrypt unencrypted items
 * @returns Number of successfully uploaded items
 */
export async function retryPendingUploads(
  uploadUrl?: string,
  encryptFn?: (payload: ForensicsPayload) => Promise<EncryptedForensics>
): Promise<number> {
  // Check if online (in service worker context, navigator may not be available)
  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    console.log('[BrowserDefense] Offline, skipping retry');
    return 0;
  }

  // Get upload endpoint from config if not provided (outside lock)
  const endpoint = uploadUrl || (await getUploadEndpoint());
  if (!endpoint) {
    console.warn('[BrowserDefense] No upload endpoint configured, skipping retry');
    return 0;
  }

  // Lock the entire read-process-write cycle to prevent race conditions
  return withQueueLock(async () => {
    const queue = await getQueue();
    if (queue.length === 0) {
      return 0;
    }

    console.log(`[BrowserDefense] Retrying ${queue.length} pending forensics uploads`);

    const remaining: QueuedForensics[] = [];
    let successCount = 0;
    let skippedUnencrypted = 0;

    for (const item of queue) {
      // Check max retries
      if (item.attempts >= MAX_RETRY_ATTEMPTS) {
        console.warn(`[BrowserDefense] Max retries exceeded, dropping: ${item.id}`);
        continue;
      }

      // Exponential backoff check
      if (item.lastAttempt) {
        const lastAttempt = new Date(item.lastAttempt).getTime();
        const backoffMs = BASE_RETRY_DELAY_MS * Math.pow(2, item.attempts);
        if (Date.now() - lastAttempt < backoffMs) {
          remaining.push(item);
          continue;
        }
      }

      // SECURITY: Zero-knowledge policy - refuse to send unencrypted data
      if (!item.encrypted) {
        // If we have an encryption function, try to encrypt now
        if (encryptFn) {
          try {
            item.encrypted = await encryptFn(item.payload);
            console.log(`[BrowserDefense] Encrypted previously unencrypted item: ${item.id}`);
          } catch (err) {
            console.warn(
              `[BrowserDefense] Encryption failed for ${item.id}, keeping in queue:`,
              (err as Error).message
            );
            item.attempts++;
            item.lastAttempt = new Date().toISOString();
            remaining.push(item);
            skippedUnencrypted++;
            continue;
          }
        } else {
          // No encryption function available - keep in queue, don't send plaintext
          console.warn(
            `[BrowserDefense] Skipping unencrypted item ${item.id} (no encrypt function, zero-knowledge policy)`
          );
          remaining.push(item);
          skippedUnencrypted++;
          continue;
        }
      }

      // Attempt upload with encrypted data only
      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(item.encrypted),
          signal: AbortSignal.timeout(10000),
        });

        if (response.ok) {
          console.log(`[BrowserDefense] Queued forensics uploaded: ${item.id}`);
          successCount++;
          // Success - don't add to remaining
        } else {
          throw new Error(`HTTP ${response.status}`);
        }
      } catch (err) {
        console.warn(`[BrowserDefense] Retry failed for ${item.id}:`, (err as Error).message);
        item.attempts++;
        item.lastAttempt = new Date().toISOString();
        remaining.push(item);
      }
    }

    await saveQueue(remaining);
    await updateBadge(remaining.length);

    if (successCount > 0) {
      console.log(`[BrowserDefense] Uploaded ${successCount} queued forensics, ${remaining.length} remaining`);
    }
    if (skippedUnencrypted > 0) {
      console.warn(`[BrowserDefense] ${skippedUnencrypted} items skipped (awaiting encryption)`);
    }
    if (remaining.length === 0) {
      console.log('[BrowserDefense] Forensics queue cleared');
    } else if (successCount === 0 && skippedUnencrypted === 0) {
      console.log(`[BrowserDefense] ${remaining.length} items still pending`);
    }

    return successCount;
  });
}

// ============ Badge ============

/**
 * Update the extension badge to show pending upload count.
 */
export async function updateBadge(pendingCount: number): Promise<void> {
  try {
    if (pendingCount > 0) {
      await chrome.action.setBadgeText({ text: pendingCount.toString() });
      await chrome.action.setBadgeBackgroundColor({ color: '#FFA500' }); // Orange
    } else {
      await chrome.action.setBadgeText({ text: '' });
    }
  } catch {
    // Badge API may not be available in all contexts
  }
}

/**
 * Initialize badge from current queue state.
 */
export async function initBadge(): Promise<void> {
  const queue = await getQueue();
  await updateBadge(queue.length);
}

// ============ Stats & Initialization ============

/**
 * Get forensics queue statistics.
 */
export async function getQueueStats(): Promise<{
  queueLength: number;
  oldestItem?: string;
  totalAttempts: number;
}> {
  const queue = await getQueue();

  return {
    queueLength: queue.length,
    oldestItem: queue[0]?.queuedAt,
    totalAttempts: queue.reduce((sum, item) => sum + item.attempts, 0),
  };
}

/**
 * Get the count of pending forensics items.
 */
export async function getPendingCount(): Promise<number> {
  const queue = await getQueue();
  return queue.length;
}

/**
 * Check if there are pending forensics and attempt retry if online.
 * Called on heartbeat to maintain visibility and ensure uploads.
 */
export async function checkPendingForensics(): Promise<void> {
  const queue = await getQueue();
  if (queue.length > 0) {
    console.log(`[BrowserDefense] ${queue.length} pending forensics in queue`);

    // If we're online, attempt retry
    if (typeof navigator !== 'undefined' && navigator.onLine) {
      const endpoint = await getUploadEndpoint();
      if (endpoint) {
        // Issue #232: Always pass encryption function to ensure zero-knowledge policy
        const encryptFn = await getEncryptionFunction();
        if (encryptFn) {
          await retryPendingUploads(endpoint, encryptFn);
        } else {
          // No encryption key - log warning but don't retry (zero-knowledge policy)
          console.warn('[BrowserDefense] Cannot retry uploads: no encryption key configured');
        }
      }
    }
  }
}

/**
 * Get the forensics upload endpoint from config.
 * Uses the correct config field name (forensics_endpoint, snake_case).
 */
async function getUploadEndpoint(): Promise<string | null> {
  const result = await chrome.storage.local.get(CONFIG_STORAGE_KEY);
  const config = result[CONFIG_STORAGE_KEY];
  // Note: Config uses snake_case (forensics_endpoint), not camelCase
  return config?.forensics_endpoint || null;
}

/**
 * Get the encryption public key from config.
 */
async function getEncryptionPublicKey(): Promise<RSAPublicKeyJWK | null> {
  const result = await chrome.storage.local.get(CONFIG_STORAGE_KEY);
  const config = result[CONFIG_STORAGE_KEY];
  return config?.encryption_public_key || null;
}

/**
 * Create an encryption function from config.
 * Returns null if encryption is not configured.
 *
 * Issue #232: This function is used to ensure forensics are encrypted before upload.
 */
export async function getEncryptionFunction(): Promise<
  ((payload: ForensicsPayload) => Promise<EncryptedForensics>) | null
> {
  const publicKey = await getEncryptionPublicKey();
  if (!publicKey) {
    console.warn('[BrowserDefense] No encryption_public_key configured, cannot create encryption function');
    return null;
  }

  const configResult = await chrome.storage.local.get(CONFIG_STORAGE_KEY);
  const configData = configResult[CONFIG_STORAGE_KEY];
  const orgId = configData?.org_id;
  const keyVersion = configData?.key_version ?? 1;

  if (!orgId) {
    console.warn('[BrowserDefense] No org_id configured, cannot create encryption function');
    return null;
  }

  return async (payload: ForensicsPayload): Promise<EncryptedForensics> => {
    const encrypted = await encryptForensics(payload, publicKey);
    return {
      orgId,
      keyVersion,
      iv: encrypted.iv,
      wrappedKey: encrypted.wrappedKey,
      ciphertext: encrypted.ciphertext,
    };
  };
}

/**
 * Initialize the forensics queue system.
 * Restores badge state and redirect chains from storage on startup.
 */
export async function initForensicsQueue(): Promise<void> {
  // Restore redirect chains from session storage (Issue #234)
  await restoreRedirectChains();

  const count = await getPendingCount();
  await updateBadge(count);

  if (count > 0) {
    console.log(`[BrowserDefense] Restored ${count} pending forensics from storage`);
  }
}

// ============ Export for Testing ============

/**
 * Reset redirect chain state for testing.
 */
export function _resetRedirectChainState(): void {
  redirectChains.clear();
  chainTimestamps.clear();
  redirectChainsRestored = false;
}

export { redirectChains as _redirectChains, chainTimestamps as _chainTimestamps };
