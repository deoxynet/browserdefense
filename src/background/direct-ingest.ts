/**
 * Browser-Side Direct Ingest for BlockIOC.
 *
 * Issue #398 - Send logs directly from the browser to on-prem SIEM endpoints
 * with runtime permissions and an off-VPN retry queue.
 *
 * Features:
 * - Runtime host permissions when users add a new SIEM origin
 * - Persistent queue in chrome.storage.local.ingest_queue
 * - Smart retry: NetworkError (DNS/timeout) retries, 401/403 fail-fast
 * - Background worker flushes queue on connectivity restoration
 */

import type {
  DirectIngestConfig,
  IngestErrorCategory,
  IngestQueueItem,
  IngestQueueStats,
  PermissionResult,
  SendResult,
  SiemEndpoint,
} from '../types/direct-ingest';

// ============ Constants ============

const QUEUE_STORAGE_KEY = 'blockioc_ingest_queue';
const CONFIG_STORAGE_KEY = 'blockioc_ingest_config';

const DEFAULT_CONFIG: DirectIngestConfig = {
  endpoints: [],
  maxQueueSize: 500,
  maxRetries: 10,
  baseRetryDelayMs: 5000,
  maxRetryDelayMs: 300000, // 5 minutes
};

// ============ Queue Lock (Mutex) ============

/**
 * Promise-based mutex for serializing queue operations.
 * Prevents read-modify-write race conditions.
 */
let queueLock: Promise<void> = Promise.resolve();

async function withQueueLock<T>(fn: () => Promise<T>): Promise<T> {
  const previousLock = queueLock;
  let releaseLock: () => void;
  queueLock = new Promise<void>((resolve) => {
    releaseLock = resolve;
  });

  try {
    await previousLock;
    return await fn();
  } finally {
    releaseLock!();
  }
}

// ============ Permission Management ============

/**
 * Extract origin from a URL.
 */
export function extractOrigin(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.origin;
  } catch {
    throw new Error(`Invalid URL: ${url}`);
  }
}

/**
 * Check if we have permission to access a given origin.
 */
export async function hasPermission(origin: string): Promise<boolean> {
  try {
    // Chrome requires patterns, not just origins
    const pattern = `${origin}/*`;
    return await chrome.permissions.contains({
      origins: [pattern],
    });
  } catch (err) {
    console.error('[BlockIOC] Permission check failed:', err);
    return false;
  }
}

/**
 * Request runtime permission for a SIEM origin.
 * This triggers a permission prompt for the user.
 *
 * Note: Must be called from a user gesture (e.g., button click).
 */
export async function requestSiemPermission(origin: string): Promise<PermissionResult> {
  try {
    // Validate origin format
    const url = new URL(origin);
    if (url.pathname !== '/' || url.search || url.hash) {
      throw new Error('Origin must not include path, query, or hash');
    }

    const pattern = `${origin}/*`;
    const granted = await chrome.permissions.request({
      origins: [pattern],
    });

    if (granted) {
      console.log(`[BlockIOC] Permission granted for: ${origin}`);
    } else {
      console.log(`[BlockIOC] Permission denied for: ${origin}`);
    }

    return { granted, origin };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    console.error(`[BlockIOC] Permission request failed for ${origin}:`, error);
    return { granted: false, origin, error };
  }
}

/**
 * Remove permission for a SIEM origin.
 */
export async function removeSiemPermission(origin: string): Promise<boolean> {
  try {
    const pattern = `${origin}/*`;
    const removed = await chrome.permissions.remove({
      origins: [pattern],
    });

    if (removed) {
      console.log(`[BlockIOC] Permission removed for: ${origin}`);
    }

    return removed;
  } catch (err) {
    console.error(`[BlockIOC] Failed to remove permission for ${origin}:`, err);
    return false;
  }
}

// ============ Endpoint Management ============

/**
 * Load the direct ingest configuration.
 */
export async function loadIngestConfig(): Promise<DirectIngestConfig> {
  const result = await chrome.storage.local.get(CONFIG_STORAGE_KEY);
  return result[CONFIG_STORAGE_KEY] ?? { ...DEFAULT_CONFIG };
}

/**
 * Save the direct ingest configuration.
 */
export async function saveIngestConfig(config: DirectIngestConfig): Promise<void> {
  await chrome.storage.local.set({ [CONFIG_STORAGE_KEY]: config });
}

/**
 * Add a new SIEM endpoint.
 * Validates the URL and requests permission for the origin.
 *
 * Note: Permission request must be triggered from a user gesture.
 */
export async function addSiemEndpoint(
  name: string,
  url: string,
  options?: {
    method?: 'POST' | 'PUT';
    headers?: Record<string, string>;
  }
): Promise<{ endpoint?: SiemEndpoint; error?: string }> {
  try {
    // Validate URL
    const origin = extractOrigin(url);

    // Check if we already have an endpoint with this URL
    const config = await loadIngestConfig();
    const existing = config.endpoints.find((e) => e.url === url);
    if (existing) {
      return { error: 'Endpoint with this URL already exists' };
    }

    // Request permission for the origin
    const permResult = await requestSiemPermission(origin);
    if (!permResult.granted) {
      return {
        error: permResult.error || 'Permission denied for SIEM origin',
      };
    }

    // Create the endpoint
    const endpoint: SiemEndpoint = {
      id: crypto.randomUUID(),
      name,
      url,
      origin,
      method: options?.method ?? 'POST',
      headers: options?.headers,
      enabled: true,
      addedAt: new Date().toISOString(),
    };

    // Save to config
    config.endpoints.push(endpoint);
    await saveIngestConfig(config);

    console.log(`[BlockIOC] SIEM endpoint added: ${name} (${origin})`);
    return { endpoint };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    console.error('[BlockIOC] Failed to add SIEM endpoint:', error);
    return { error };
  }
}

/**
 * Remove a SIEM endpoint.
 */
export async function removeSiemEndpoint(endpointId: string): Promise<boolean> {
  const config = await loadIngestConfig();
  const endpointIndex = config.endpoints.findIndex((e) => e.id === endpointId);

  if (endpointIndex === -1) {
    return false;
  }

  const endpoint = config.endpoints[endpointIndex];

  // Remove the endpoint
  config.endpoints.splice(endpointIndex, 1);
  await saveIngestConfig(config);

  // Check if any other endpoints use the same origin
  const otherEndpointsWithOrigin = config.endpoints.filter(
    (e) => e.origin === endpoint.origin
  );

  // If no other endpoints use this origin, offer to remove permission
  if (otherEndpointsWithOrigin.length === 0) {
    await removeSiemPermission(endpoint.origin);
  }

  console.log(`[BlockIOC] SIEM endpoint removed: ${endpoint.name}`);
  return true;
}

/**
 * Update a SIEM endpoint.
 */
export async function updateSiemEndpoint(
  endpointId: string,
  updates: Partial<Pick<SiemEndpoint, 'name' | 'enabled' | 'headers'>>
): Promise<SiemEndpoint | null> {
  const config = await loadIngestConfig();
  const endpoint = config.endpoints.find((e) => e.id === endpointId);

  if (!endpoint) {
    return null;
  }

  if (updates.name !== undefined) endpoint.name = updates.name;
  if (updates.enabled !== undefined) endpoint.enabled = updates.enabled;
  if (updates.headers !== undefined) endpoint.headers = updates.headers;

  await saveIngestConfig(config);
  return endpoint;
}

/**
 * Get all configured SIEM endpoints.
 */
export async function getSiemEndpoints(): Promise<SiemEndpoint[]> {
  const config = await loadIngestConfig();
  return config.endpoints;
}

/**
 * Get a specific SIEM endpoint by ID.
 */
export async function getSiemEndpoint(endpointId: string): Promise<SiemEndpoint | null> {
  const config = await loadIngestConfig();
  return config.endpoints.find((e) => e.id === endpointId) ?? null;
}

// ============ Error Classification ============

/**
 * Classify an error for smart retry logic.
 */
function classifyError(
  error: Error | TypeError,
  statusCode?: number
): { category: IngestErrorCategory; retryable: boolean } {
  // Network errors (DNS failure, timeout, connection refused)
  if (error instanceof TypeError && error.message.includes('fetch')) {
    return { category: 'network', retryable: true };
  }

  if (error.name === 'AbortError' || error.message.includes('timeout')) {
    return { category: 'network', retryable: true };
  }

  if (error.message.includes('NetworkError') || error.message.includes('network')) {
    return { category: 'network', retryable: true };
  }

  if (error.message.includes('Failed to fetch') || error.message.includes('ERR_')) {
    return { category: 'network', retryable: true };
  }

  // HTTP status code based classification
  if (statusCode) {
    // Auth errors - DO NOT RETRY, surface to user
    if (statusCode === 401 || statusCode === 403) {
      return { category: 'auth', retryable: false };
    }

    // Server errors - RETRY with backoff
    if (statusCode >= 500 && statusCode < 600) {
      return { category: 'server', retryable: true };
    }

    // Other client errors - DO NOT RETRY
    if (statusCode >= 400 && statusCode < 500) {
      return { category: 'client', retryable: false };
    }
  }

  // Default to network error (retryable)
  return { category: 'network', retryable: true };
}

// ============ Queue Management ============

/**
 * Get the current ingest queue.
 */
export async function getIngestQueue(): Promise<IngestQueueItem[]> {
  const result = await chrome.storage.local.get(QUEUE_STORAGE_KEY);
  return result[QUEUE_STORAGE_KEY] ?? [];
}

/**
 * Save the ingest queue.
 */
async function saveIngestQueue(queue: IngestQueueItem[]): Promise<void> {
  await chrome.storage.local.set({ [QUEUE_STORAGE_KEY]: queue });
}

/**
 * Add an item to the ingest queue.
 */
async function queueIngestItem(
  endpointId: string,
  payload: unknown,
  error: string,
  errorCategory: IngestErrorCategory
): Promise<string> {
  return withQueueLock(async () => {
    const config = await loadIngestConfig();
    const queue = await getIngestQueue();

    // Drop oldest items if queue is full
    while (queue.length >= config.maxQueueSize) {
      const dropped = queue.shift();
      console.warn(`[BlockIOC] Ingest queue full, dropped: ${dropped?.id}`);
    }

    const item: IngestQueueItem = {
      id: crypto.randomUUID(),
      endpointId,
      payload,
      attempts: 1,
      queuedAt: new Date().toISOString(),
      lastAttempt: new Date().toISOString(),
      lastError: error,
      errorCategory,
    };

    queue.push(item);
    await saveIngestQueue(queue);

    console.log(`[BlockIOC] Ingest item queued: ${item.id} (${errorCategory})`);
    return item.id;
  });
}

/**
 * Remove an item from the ingest queue.
 */
export async function removeFromIngestQueue(id: string): Promise<void> {
  return withQueueLock(async () => {
    const queue = await getIngestQueue();
    const filtered = queue.filter((item) => item.id !== id);
    await saveIngestQueue(filtered);
  });
}

/**
 * Clear all items from the ingest queue.
 */
export async function clearIngestQueue(): Promise<void> {
  return withQueueLock(async () => {
    await chrome.storage.local.remove(QUEUE_STORAGE_KEY);
    console.log('[BlockIOC] Ingest queue cleared');
  });
}

/**
 * Get ingest queue statistics.
 */
export async function getIngestQueueStats(): Promise<IngestQueueStats> {
  const queue = await getIngestQueue();

  let pendingRetry = 0;
  let authErrors = 0;
  let clientErrors = 0;
  let totalAttempts = 0;

  for (const item of queue) {
    totalAttempts += item.attempts;

    switch (item.errorCategory) {
      case 'network':
      case 'server':
        pendingRetry++;
        break;
      case 'auth':
        authErrors++;
        break;
      case 'client':
        clientErrors++;
        break;
    }
  }

  return {
    queueLength: queue.length,
    pendingRetry,
    authErrors,
    clientErrors,
    oldestItem: queue[0]?.queuedAt,
    totalAttempts,
  };
}

// ============ Send Logic ============

/**
 * Send data to a SIEM endpoint.
 * On failure, queues for retry based on error type.
 */
export async function sendToSiem(
  endpointId: string,
  payload: unknown
): Promise<SendResult> {
  const endpoint = await getSiemEndpoint(endpointId);

  if (!endpoint) {
    return {
      success: false,
      error: 'Endpoint not found',
      retryable: false,
    };
  }

  if (!endpoint.enabled) {
    return {
      success: false,
      error: 'Endpoint is disabled',
      retryable: false,
    };
  }

  // Check permission
  const hasAccess = await hasPermission(endpoint.origin);
  if (!hasAccess) {
    return {
      success: false,
      error: 'Permission not granted for endpoint origin',
      errorCategory: 'auth',
      retryable: false,
    };
  }

  try {
    const response = await fetch(endpoint.url, {
      method: endpoint.method ?? 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...endpoint.headers,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(30000), // 30s timeout
    });

    if (response.ok) {
      // Update endpoint success status
      await updateEndpointStatus(endpointId, true);
      console.log(`[BlockIOC] SIEM delivery success: ${endpoint.name}`);

      return { success: true };
    }

    // HTTP error response
    const { category, retryable } = classifyError(
      new Error(`HTTP ${response.status}`),
      response.status
    );

    const errorMsg = `HTTP ${response.status}: ${response.statusText}`;

    // Update endpoint error status
    await updateEndpointStatus(endpointId, false, errorMsg);

    if (retryable) {
      const queuedId = await queueIngestItem(endpointId, payload, errorMsg, category);
      return {
        success: false,
        queuedId,
        error: errorMsg,
        errorCategory: category,
        retryable: true,
        statusCode: response.status,
      };
    }

    // Non-retryable error (auth or client error)
    console.warn(`[BlockIOC] SIEM delivery failed (not retryable): ${errorMsg}`);
    return {
      success: false,
      error: errorMsg,
      errorCategory: category,
      retryable: false,
      statusCode: response.status,
    };
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    const { category, retryable } = classifyError(error);
    const errorMsg = error.message;

    // Update endpoint error status
    await updateEndpointStatus(endpointId, false, errorMsg);

    if (retryable) {
      const queuedId = await queueIngestItem(endpointId, payload, errorMsg, category);
      console.warn(`[BlockIOC] SIEM delivery failed (queued): ${errorMsg}`);
      return {
        success: false,
        queuedId,
        error: errorMsg,
        errorCategory: category,
        retryable: true,
      };
    }

    console.warn(`[BlockIOC] SIEM delivery failed (not retryable): ${errorMsg}`);
    return {
      success: false,
      error: errorMsg,
      errorCategory: category,
      retryable: false,
    };
  }
}

/**
 * Send data to all enabled SIEM endpoints.
 */
export async function sendToAllSiems(payload: unknown): Promise<Map<string, SendResult>> {
  const config = await loadIngestConfig();
  const results = new Map<string, SendResult>();

  const enabledEndpoints = config.endpoints.filter((e) => e.enabled);

  // Send to all endpoints in parallel
  await Promise.all(
    enabledEndpoints.map(async (endpoint) => {
      const result = await sendToSiem(endpoint.id, payload);
      results.set(endpoint.id, result);
    })
  );

  return results;
}

/**
 * Update endpoint status after send attempt.
 */
async function updateEndpointStatus(
  endpointId: string,
  success: boolean,
  errorMsg?: string
): Promise<void> {
  const config = await loadIngestConfig();
  const endpoint = config.endpoints.find((e) => e.id === endpointId);

  if (!endpoint) return;

  if (success) {
    endpoint.lastSuccess = new Date().toISOString();
    endpoint.lastError = undefined;
  } else {
    endpoint.lastError = errorMsg;
  }

  await saveIngestConfig(config);
}

// ============ Retry Logic ============

/**
 * Calculate exponential backoff delay.
 */
function calculateBackoffDelay(
  attempts: number,
  baseDelayMs: number,
  maxDelayMs: number
): number {
  const delay = baseDelayMs * Math.pow(2, attempts - 1);
  return Math.min(delay, maxDelayMs);
}

/**
 * Retry pending ingest items.
 * Called by the background worker on connectivity restoration.
 *
 * Only retries items with retryable error categories (network, server).
 * Auth and client errors are kept in queue for user review but not retried.
 */
export async function retryPendingIngest(): Promise<{
  succeeded: number;
  failed: number;
  skipped: number;
}> {
  // Check if online
  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    console.log('[BlockIOC] Offline, skipping ingest retry');
    return { succeeded: 0, failed: 0, skipped: 0 };
  }

  return withQueueLock(async () => {
    const config = await loadIngestConfig();
    const queue = await getIngestQueue();

    if (queue.length === 0) {
      return { succeeded: 0, failed: 0, skipped: 0 };
    }

    console.log(`[BlockIOC] Retrying ${queue.length} pending ingest items`);

    const remaining: IngestQueueItem[] = [];
    let succeeded = 0;
    let failed = 0;
    let skipped = 0;

    for (const item of queue) {
      // Skip items that are not retryable (auth, client errors)
      if (item.errorCategory === 'auth' || item.errorCategory === 'client') {
        remaining.push(item);
        skipped++;
        continue;
      }

      // Check max retries
      if (item.attempts >= config.maxRetries) {
        console.warn(`[BlockIOC] Max retries exceeded, dropping: ${item.id}`);
        failed++;
        continue;
      }

      // Check backoff delay
      if (item.lastAttempt) {
        const lastAttempt = new Date(item.lastAttempt).getTime();
        const backoffMs = calculateBackoffDelay(
          item.attempts,
          config.baseRetryDelayMs,
          config.maxRetryDelayMs
        );
        if (Date.now() - lastAttempt < backoffMs) {
          remaining.push(item);
          skipped++;
          continue;
        }
      }

      // Get endpoint
      const endpoint = config.endpoints.find((e) => e.id === item.endpointId);
      if (!endpoint || !endpoint.enabled) {
        console.warn(`[BlockIOC] Endpoint not found or disabled: ${item.endpointId}`);
        remaining.push(item);
        skipped++;
        continue;
      }

      // Check permission
      const hasAccess = await hasPermission(endpoint.origin);
      if (!hasAccess) {
        item.errorCategory = 'auth';
        item.lastError = 'Permission revoked';
        remaining.push(item);
        skipped++;
        continue;
      }

      // Attempt send
      try {
        const response = await fetch(endpoint.url, {
          method: endpoint.method ?? 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...endpoint.headers,
          },
          body: JSON.stringify(item.payload),
          signal: AbortSignal.timeout(30000),
        });

        if (response.ok) {
          console.log(`[BlockIOC] Queued ingest delivered: ${item.id}`);
          await updateEndpointStatus(item.endpointId, true);
          succeeded++;
          continue;
        }

        // HTTP error
        const { category, retryable } = classifyError(
          new Error(`HTTP ${response.status}`),
          response.status
        );

        item.attempts++;
        item.lastAttempt = new Date().toISOString();
        item.lastError = `HTTP ${response.status}`;
        item.errorCategory = category;

        await updateEndpointStatus(item.endpointId, false, item.lastError);

        if (!retryable) {
          console.warn(`[BlockIOC] Ingest retry failed (not retryable): ${item.id}`);
        }

        remaining.push(item);
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        const { category } = classifyError(error);

        item.attempts++;
        item.lastAttempt = new Date().toISOString();
        item.lastError = error.message;
        item.errorCategory = category;

        await updateEndpointStatus(item.endpointId, false, error.message);
        remaining.push(item);
        console.warn(`[BlockIOC] Ingest retry failed: ${item.id} - ${error.message}`);
      }
    }

    await saveIngestQueue(remaining);

    console.log(
      `[BlockIOC] Ingest retry complete: ${succeeded} succeeded, ${failed} dropped, ${remaining.length} remaining`
    );

    return { succeeded, failed, skipped };
  });
}

// ============ Connectivity Monitoring ============

let connectivityListenerRegistered = false;

/**
 * Setup connectivity monitoring for queue flush.
 * Listens for online events to trigger retry.
 */
export function setupConnectivityMonitoring(): void {
  if (connectivityListenerRegistered) return;

  // Listen for online events in service worker
  if (typeof self !== 'undefined' && 'addEventListener' in self) {
    self.addEventListener('online', () => {
      console.log('[BlockIOC] Connectivity restored, retrying ingest queue');
      retryPendingIngest().catch((err) => {
        console.error('[BlockIOC] Ingest retry failed:', err);
      });
    });
    connectivityListenerRegistered = true;
    console.log('[BlockIOC] Connectivity monitoring enabled');
  }
}

/**
 * Heartbeat function to check and retry pending ingest.
 * Called periodically by the main heartbeat system.
 */
export async function checkPendingIngest(): Promise<void> {
  const stats = await getIngestQueueStats();

  if (stats.pendingRetry > 0) {
    console.log(`[BlockIOC] ${stats.pendingRetry} ingest items pending retry`);

    if (typeof navigator !== 'undefined' && navigator.onLine) {
      await retryPendingIngest();
    }
  }

  if (stats.authErrors > 0) {
    console.warn(
      `[BlockIOC] ${stats.authErrors} ingest items have auth errors (need user attention)`
    );
  }
}

// ============ Initialization ============

/**
 * Initialize the direct ingest system.
 * Sets up connectivity monitoring and checks for pending items.
 */
export async function initDirectIngest(): Promise<void> {
  setupConnectivityMonitoring();

  const stats = await getIngestQueueStats();
  if (stats.queueLength > 0) {
    console.log(
      `[BlockIOC] Restored ${stats.queueLength} pending ingest items from storage`
    );

    // Attempt immediate retry if online
    if (typeof navigator !== 'undefined' && navigator.onLine) {
      await retryPendingIngest();
    }
  }

  console.log('[BlockIOC] Direct ingest system initialized');
}
