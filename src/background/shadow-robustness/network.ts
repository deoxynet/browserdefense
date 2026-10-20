/**
 * Network Robustness for Shadow Detection (Issue #251)
 *
 * Provides:
 * - Retry with exponential backoff for telemetry failures
 * - Circuit breaker to prevent telemetry spam during outages
 * - Offline queue with bounded size
 * - Deduplication of queued events
 *
 * Design: Network failures must NEVER affect core blocking or UX.
 * Shadow telemetry is fire-and-forget with best-effort delivery.
 */

import type {
  CircuitBreakerConfig,
  CircuitBreakerState,
  CircuitBreakerStatus,
  RetryConfig,
  QueuedTelemetryEvent,
  OfflineQueueConfig,
  OfflineQueueStatus,
} from '../../types/shadow-robustness';
import { DEFAULT_SHADOW_ROBUSTNESS_CONFIG } from '../../types/shadow-robustness';

// ============ Constants ============

const CIRCUIT_BREAKER_KEY = 'browserdefense_shadow_circuit_breaker';
const OFFLINE_QUEUE_KEY = 'browserdefense_shadow_offline_queue';

// ============ Circuit Breaker Implementation ============

interface CircuitBreakerState_Internal {
  state: CircuitBreakerState;
  failureCount: number;
  failureTimestamps: number[];
  successCount: number;
  openedAt?: number;
  lastStateChange: number;
}

/**
 * Circuit breaker for shadow telemetry.
 *
 * States:
 * - closed: Normal operation, requests go through
 * - open: Requests blocked, waiting for reset timeout
 * - half-open: Testing if service recovered
 */
export class CircuitBreaker {
  private config: CircuitBreakerConfig;
  private state: CircuitBreakerState_Internal;

  constructor(config: Partial<CircuitBreakerConfig> = {}) {
    this.config = {
      ...DEFAULT_SHADOW_ROBUSTNESS_CONFIG.circuitBreaker,
      ...config,
    };
    this.state = {
      state: 'closed',
      failureCount: 0,
      failureTimestamps: [],
      successCount: 0,
      lastStateChange: Date.now(),
    };
  }

  /**
   * Load circuit breaker state from storage.
   */
  async load(): Promise<void> {
    try {
      const result = await chrome.storage.local.get(CIRCUIT_BREAKER_KEY);
      const stored = result[CIRCUIT_BREAKER_KEY] as CircuitBreakerState_Internal | undefined;
      if (stored) {
        this.state = stored;
        // Check if we should transition from open to half-open
        if (this.state.state === 'open' && this.shouldTransitionToHalfOpen()) {
          this.transitionToHalfOpen();
        }
      }
    } catch (err) {
      console.warn('[BrowserDefense] Failed to load circuit breaker state:', err);
    }
  }

  /**
   * Save circuit breaker state to storage.
   */
  private async save(): Promise<void> {
    try {
      await chrome.storage.local.set({ [CIRCUIT_BREAKER_KEY]: this.state });
    } catch (err) {
      console.warn('[BrowserDefense] Failed to save circuit breaker state:', err);
    }
  }

  /**
   * Check if a request is allowed.
   */
  isAllowed(): boolean {
    switch (this.state.state) {
      case 'closed':
        return true;
      case 'open':
        // Check if we should transition to half-open
        if (this.shouldTransitionToHalfOpen()) {
          this.transitionToHalfOpen();
          return true; // Allow one request in half-open
        }
        return false;
      case 'half-open':
        // Allow requests in half-open to test recovery
        return true;
      default:
        return true;
    }
  }

  /**
   * Check if we should transition from open to half-open.
   */
  private shouldTransitionToHalfOpen(): boolean {
    if (this.state.state !== 'open' || !this.state.openedAt) {
      return false;
    }
    return Date.now() - this.state.openedAt >= this.config.resetTimeoutMs;
  }

  /**
   * Transition to half-open state.
   */
  private transitionToHalfOpen(): void {
    this.state.state = 'half-open';
    this.state.successCount = 0;
    this.state.lastStateChange = Date.now();
    console.log('[BrowserDefense] Circuit breaker: open -> half-open');
    this.save().catch((err) => console.warn('[Shadow] Circuit breaker save failed:', err));
  }

  /**
   * Record a successful request.
   */
  async recordSuccess(): Promise<void> {
    switch (this.state.state) {
      case 'closed':
        // Stay closed, reset failure count
        this.state.failureCount = 0;
        this.state.failureTimestamps = [];
        break;
      case 'half-open':
        this.state.successCount++;
        if (this.state.successCount >= this.config.successThreshold) {
          // Recovered, close the circuit
          this.state.state = 'closed';
          this.state.failureCount = 0;
          this.state.failureTimestamps = [];
          this.state.successCount = 0;
          this.state.openedAt = undefined;
          this.state.lastStateChange = Date.now();
          console.log('[BrowserDefense] Circuit breaker: half-open -> closed (recovered)');
        }
        break;
      case 'open':
        // Shouldn't happen, but reset to closed if it does
        this.state.state = 'closed';
        this.state.failureCount = 0;
        this.state.failureTimestamps = [];
        break;
    }
    await this.save();
  }

  /**
   * Record a failed request.
   */
  async recordFailure(): Promise<void> {
    const now = Date.now();

    switch (this.state.state) {
      case 'closed': {
        // Add failure timestamp
        this.state.failureTimestamps.push(now);

        // Remove old failures outside window
        const cutoff = now - this.config.failureWindowMs;
        this.state.failureTimestamps = this.state.failureTimestamps.filter((t) => t > cutoff);
        this.state.failureCount = this.state.failureTimestamps.length;

        // Check if we should open the circuit
        if (this.state.failureCount >= this.config.failureThreshold) {
          this.state.state = 'open';
          this.state.openedAt = now;
          this.state.lastStateChange = now;
          console.log('[BrowserDefense] Circuit breaker: closed -> open (failures:', this.state.failureCount, ')');
        }
        break;
      }
      case 'half-open':
        // Failed during recovery, reopen
        this.state.state = 'open';
        this.state.openedAt = now;
        this.state.successCount = 0;
        this.state.lastStateChange = now;
        console.log('[BrowserDefense] Circuit breaker: half-open -> open (recovery failed)');
        break;
      case 'open':
        // Already open, just update timestamp
        this.state.openedAt = now;
        break;
    }
    await this.save();
  }

  /**
   * Get circuit breaker status.
   */
  getStatus(): CircuitBreakerStatus {
    return {
      state: this.state.state,
      failureCount: this.state.failureCount,
      successCount: this.state.successCount,
      openedAt: this.state.openedAt,
      nextResetAt: this.state.openedAt
        ? this.state.openedAt + this.config.resetTimeoutMs
        : undefined,
    };
  }

  /**
   * Force reset to closed state.
   */
  async reset(): Promise<void> {
    this.state = {
      state: 'closed',
      failureCount: 0,
      failureTimestamps: [],
      successCount: 0,
      lastStateChange: Date.now(),
    };
    await this.save();
    console.log('[BrowserDefense] Circuit breaker reset');
  }
}

// ============ Retry Logic Implementation ============

/**
 * Calculate delay for retry attempt with exponential backoff.
 */
export function calculateRetryDelay(
  attempt: number,
  config: RetryConfig = DEFAULT_SHADOW_ROBUSTNESS_CONFIG.retry
): number {
  // Exponential backoff: initialDelay * multiplier^attempt
  let delay = config.initialDelayMs * Math.pow(config.backoffMultiplier, attempt);

  // Cap at max delay
  delay = Math.min(delay, config.maxDelayMs);

  // Add jitter
  if (config.jitterFactor > 0) {
    const jitter = delay * config.jitterFactor * Math.random();
    delay += jitter;
  }

  return Math.round(delay);
}

/**
 * Execute a function with retry logic.
 * Returns the result or throws after all retries exhausted.
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  config: Partial<RetryConfig> = {}
): Promise<T> {
  const mergedConfig: RetryConfig = {
    ...DEFAULT_SHADOW_ROBUSTNESS_CONFIG.retry,
    ...config,
  };

  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= mergedConfig.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err as Error;

      if (attempt < mergedConfig.maxRetries) {
        const delay = calculateRetryDelay(attempt, mergedConfig);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }

  throw lastError;
}

// ============ Offline Queue Implementation ============

interface StoredQueue {
  events: QueuedTelemetryEvent[];
  version: number;
  lastProcessed: number;
}

/**
 * Bounded offline queue for shadow telemetry events.
 * Events are queued when network is unavailable or circuit is open.
 */
export class OfflineQueue {
  private config: OfflineQueueConfig;
  private processing: boolean = false;
  private lastBatchSize: number = 0;
  private seenHashes: Set<string> = new Set();

  constructor(config: Partial<OfflineQueueConfig> = {}) {
    this.config = {
      ...DEFAULT_SHADOW_ROBUSTNESS_CONFIG.offlineQueue,
      ...config,
    };
  }

  /**
   * Load queue from storage.
   */
  private async loadQueue(): Promise<StoredQueue> {
    try {
      const result = await chrome.storage.local.get(OFFLINE_QUEUE_KEY);
      const stored = result[OFFLINE_QUEUE_KEY] as StoredQueue | undefined;

      if (stored?.events) {
        // Rebuild dedup set
        this.seenHashes.clear();
        for (const event of stored.events) {
          this.seenHashes.add(event.hash);
        }
        return stored;
      }

      return {
        events: [],
        version: 1,
        lastProcessed: 0,
      };
    } catch (err) {
      console.warn('[BrowserDefense] Failed to load offline queue:', err);
      return { events: [], version: 1, lastProcessed: 0 };
    }
  }

  /**
   * Save queue to storage.
   */
  private async saveQueue(queue: StoredQueue): Promise<void> {
    try {
      await chrome.storage.local.set({ [OFFLINE_QUEUE_KEY]: queue });
    } catch (err) {
      console.warn('[BrowserDefense] Failed to save offline queue:', err);
    }
  }

  /**
   * Enqueue an event.
   * Returns true if queued, false if dropped (duplicate, full, or expired).
   */
  async enqueue(event: Omit<QueuedTelemetryEvent, 'id' | 'queuedAt' | 'nextRetryAt' | 'retryCount'>): Promise<boolean> {
    // Check for duplicate
    if (this.seenHashes.has(event.hash)) {
      return false; // Deduplicated
    }

    const queue = await this.loadQueue();
    const now = Date.now();

    // Check queue size
    if (queue.events.length >= this.config.maxSize) {
      // Remove oldest events to make room
      const toRemove = queue.events.length - this.config.maxSize + 1;
      const removed = queue.events.splice(0, toRemove);
      for (const evt of removed) {
        this.seenHashes.delete(evt.hash);
      }
      console.log('[BrowserDefense] Offline queue: evicted', toRemove, 'old events');
    }

    // Create queue entry
    const queuedEvent: QueuedTelemetryEvent = {
      id: generateEventId(),
      hash: event.hash,
      timestamp: event.timestamp,
      firstSeenLocally: event.firstSeenLocally,
      lshSketches: event.lshSketches,
      retryCount: 0,
      nextRetryAt: now,
      queuedAt: now,
    };

    queue.events.push(queuedEvent);
    this.seenHashes.add(event.hash);
    await this.saveQueue(queue);

    return true;
  }

  /**
   * Process queued events.
   * Calls the processor function for each event.
   * Returns number of successfully processed events.
   */
  async process(
    processor: (event: QueuedTelemetryEvent) => Promise<boolean>,
    circuitBreaker?: CircuitBreaker
  ): Promise<number> {
    if (this.processing) {
      return 0; // Already processing
    }

    this.processing = true;
    let processed = 0;

    try {
      const queue = await this.loadQueue();
      const now = Date.now();
      const toRemove: number[] = [];

      // Process up to batchSize events
      let processedInBatch = 0;

      for (let i = 0; i < queue.events.length && processedInBatch < this.config.batchSize; i++) {
        const event = queue.events[i];

        // Skip if not ready for retry
        if (event.nextRetryAt > now) {
          continue;
        }

        // Check if expired
        if (now - event.queuedAt > this.config.maxAgeMs) {
          toRemove.push(i);
          continue;
        }

        // Check circuit breaker
        if (circuitBreaker && !circuitBreaker.isAllowed()) {
          break; // Circuit is open, stop processing
        }

        try {
          const success = await processor(event);

          if (success) {
            toRemove.push(i);
            processed++;
            circuitBreaker?.recordSuccess();
          } else {
            // Update retry count and next retry time
            event.retryCount++;
            event.nextRetryAt = now + calculateRetryDelay(event.retryCount);

            // If too many retries, remove
            if (event.retryCount >= DEFAULT_SHADOW_ROBUSTNESS_CONFIG.retry.maxRetries) {
              toRemove.push(i);
            }

            circuitBreaker?.recordFailure();
          }
        } catch {
          // Update retry count
          event.retryCount++;
          event.nextRetryAt = now + calculateRetryDelay(event.retryCount);

          if (event.retryCount >= DEFAULT_SHADOW_ROBUSTNESS_CONFIG.retry.maxRetries) {
            toRemove.push(i);
          }

          circuitBreaker?.recordFailure();
        }

        processedInBatch++;
      }

      // Remove processed/expired events (in reverse order to preserve indices)
      toRemove.sort((a, b) => b - a);
      for (const idx of toRemove) {
        const removed = queue.events[idx];
        this.seenHashes.delete(removed.hash);
        queue.events.splice(idx, 1);
      }

      queue.lastProcessed = now;
      await this.saveQueue(queue);
      this.lastBatchSize = processedInBatch;
    } finally {
      this.processing = false;
    }

    return processed;
  }

  /**
   * Get queue status.
   */
  async getStatus(): Promise<OfflineQueueStatus> {
    const queue = await this.loadQueue();
    const now = Date.now();

    let oldestAgeMs: number | undefined;
    if (queue.events.length > 0) {
      oldestAgeMs = now - queue.events[0].queuedAt;
    }

    return {
      size: queue.events.length,
      oldestAgeMs,
      processing: this.processing,
      lastProcessedAt: queue.lastProcessed || undefined,
      lastBatchSize: this.lastBatchSize,
    };
  }

  /**
   * Clear the queue.
   */
  async clear(): Promise<void> {
    this.seenHashes.clear();
    await chrome.storage.local.remove(OFFLINE_QUEUE_KEY);
    console.log('[BrowserDefense] Offline queue cleared');
  }

  /**
   * Get queue size.
   */
  async size(): Promise<number> {
    const queue = await this.loadQueue();
    return queue.events.length;
  }
}

// ============ Helper Functions ============

/**
 * Generate a unique event ID.
 */
function generateEventId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return 'evt_' + timestamp + '_' + random;
}

/**
 * Check if browser is online.
 */
export function isOnline(): boolean {
  return navigator.onLine;
}

/**
 * Wait for network to come online.
 * Returns immediately if already online.
 * Times out after maxWaitMs.
 */
export function waitForOnline(maxWaitMs: number = 30000): Promise<boolean> {
  return new Promise((resolve) => {
    if (navigator.onLine) {
      resolve(true);
      return;
    }

    const timeout = setTimeout(() => {
      window.removeEventListener('online', onOnline);
      resolve(false);
    }, maxWaitMs);

    const onOnline = () => {
      clearTimeout(timeout);
      window.removeEventListener('online', onOnline);
      resolve(true);
    };

    window.addEventListener('online', onOnline);
  });
}

// ============ Singleton Instances ============

let defaultCircuitBreaker: CircuitBreaker | null = null;
let defaultOfflineQueue: OfflineQueue | null = null;

/**
 * Get the default circuit breaker instance.
 */
export function getDefaultCircuitBreaker(): CircuitBreaker {
  if (!defaultCircuitBreaker) {
    defaultCircuitBreaker = new CircuitBreaker();
  }
  return defaultCircuitBreaker;
}

/**
 * Get the default offline queue instance.
 */
export function getDefaultOfflineQueue(): OfflineQueue {
  if (!defaultOfflineQueue) {
    defaultOfflineQueue = new OfflineQueue();
  }
  return defaultOfflineQueue;
}

/**
 * Initialize network robustness (load state from storage).
 */
export async function initNetworkRobustness(): Promise<void> {
  const cb = getDefaultCircuitBreaker();
  await cb.load();

  // Set up online/offline listeners
  if (typeof window !== 'undefined') {
    window.addEventListener('online', () => {
      console.log('[BrowserDefense] Network: online');
      // Process queue when coming online
      const queue = getDefaultOfflineQueue();
      queue.process(async () => true, cb).catch((err) => console.warn('[Shadow] Queue processing failed:', err));
    });

    window.addEventListener('offline', () => {
      console.log('[BrowserDefense] Network: offline');
    });
  }
}

// ============ Exports for Testing ============

export {
  generateEventId as _generateEventId,
  CIRCUIT_BREAKER_KEY as _CIRCUIT_BREAKER_KEY,
  OFFLINE_QUEUE_KEY as _OFFLINE_QUEUE_KEY,
};
