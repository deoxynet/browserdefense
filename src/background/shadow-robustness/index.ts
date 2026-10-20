/**
 * Shadow Detection Robustness Module (Issue #251)
 *
 * Main entry point for shadow detection hardening.
 * Provides production-ready robustness for:
 * - Storage (LRU eviction, quota handling, corruption recovery)
 * - Network (retry, circuit breaker, offline queue)
 * - Processing (timeouts, rate limiting, DOM limits)
 * - Observability (metrics, error tracking, latency)
 *
 * CRITICAL DESIGN PRINCIPLE:
 * Shadow detection failures must NEVER affect:
 * - Core blocking functionality
 * - User experience
 * - Browser performance
 *
 * All operations fail silently with graceful degradation.
 */

// Re-export types
export type {
  LRUCacheEntry,
  LRUCacheConfig,
  StorageQuotaStatus,
  StorageHealthStatus,
  CircuitBreakerConfig,
  CircuitBreakerState,
  CircuitBreakerStatus,
  RetryConfig,
  QueuedTelemetryEvent,
  OfflineQueueConfig,
  OfflineQueueStatus,
  RateLimiterConfig,
  RateLimiterStatus,
  DOMProcessingLimits,
  SafeDOMProcessingResult,
  ShadowDetectionMetrics,
  LatencyPercentiles,
  ErrorTrackingEntry,
  ObservabilitySnapshot,
  ShadowRobustnessConfig,
} from '../../types/shadow-robustness';

export { DEFAULT_SHADOW_ROBUSTNESS_CONFIG } from '../../types/shadow-robustness';

// Re-export storage
export {
  ShadowLRUCache,
  getDefaultCache,
  getStorageHealth,
  getQuotaStatus,
  attemptStorageRecovery,
  validateCacheIntegrity,
  repairCache,
} from './storage';

// Re-export network
export {
  CircuitBreaker,
  OfflineQueue,
  getDefaultCircuitBreaker,
  getDefaultOfflineQueue,
  initNetworkRobustness,
  calculateRetryDelay,
  withRetry,
  isOnline,
  waitForOnline,
} from './network';

// Re-export processing
export {
  RateLimiter,
  getDefaultRateLimiter,
  initProcessingRobustness,
  createSafeDOMExtractor,
  withTimeout,
  safeAsync,
  validateSkeletonMessage,
} from './processing';

// Re-export metrics
export {
  getMetrics,
  incrementMetric,
  updateQueueDepth,
  recordProcessingLatency,
  recordTelemetryLatency,
  getProcessingLatency,
  getTelemetryLatency,
  recordError,
  getRecentErrors,
  getErrorRate,
  saveMetrics,
  loadMetrics,
  resetMetrics,
  getObservabilitySnapshot,
  recordTelemetrySuccess,
  recordTelemetryFailure,
  recordProcessingComplete,
  recordProcessingTimeout,
  recordRateLimitHit,
  recordEventDropped,
  recordCircuitBreakerTrip,
  recordStorageError,
  startPeriodicSave,
  stopPeriodicSave,
} from './metrics';

// ============ Initialization ============

import { initNetworkRobustness } from './network';
import { initProcessingRobustness } from './processing';
import { loadMetrics, startPeriodicSave } from './metrics';
import { validateCacheIntegrity, repairCache } from './storage';

let initialized = false;

/**
 * Initialize all shadow robustness modules.
 * Call this once during service worker startup.
 */
export async function initShadowRobustness(): Promise<void> {
  if (initialized) {
    return;
  }

  console.log('[BrowserDefense] Initializing shadow robustness...');

  try {
    // Initialize all modules in parallel
    await Promise.all([
      initNetworkRobustness(),
      initProcessingRobustness(),
      loadMetrics(),
    ]);

    // Start periodic metrics saving
    startPeriodicSave(60000); // Save every minute

    // Validate storage integrity (non-blocking)
    validateCacheIntegrity().then((result) => {
      if (!result.valid) {
        console.warn('[BrowserDefense] Cache integrity issues detected:', result.errors);
        // Attempt repair in background
        repairCache().catch((err) => console.warn('[Shadow] Cache repair failed:', err));
      }
    }).catch((err) => console.warn('[Shadow] Cache validation failed:', err));

    initialized = true;
    console.log('[BrowserDefense] Shadow robustness initialized');
  } catch (err) {
    console.error('[BrowserDefense] Shadow robustness initialization failed:', err);
    // Continue anyway - robustness features are optional
    initialized = true;
  }
}

/**
 * Check if shadow robustness is initialized.
 */
export function isInitialized(): boolean {
  return initialized;
}

// ============ Safe Wrapper for Shadow Telemetry ============

import { getDefaultCircuitBreaker, getDefaultOfflineQueue, isOnline as checkOnline } from './network';
import { getDefaultRateLimiter } from './processing';
import {
  recordTelemetrySuccess,
  recordTelemetryFailure,
  recordRateLimitHit,
  recordEventDropped,
  recordCircuitBreakerTrip,
  updateQueueDepth,
} from './metrics';

/**
 * Options for safe telemetry send.
 */
export interface SafeTelemetrySendOptions {
  /** DOM kit hash */
  hash: string;
  /** Event timestamp */
  timestamp: number;
  /** First seen locally flag */
  firstSeenLocally: boolean;
  /** LSH sketches (optional) */
  lshSketches?: {
    layout?: string;
    form?: string;
    script?: string;
  };
  /** Tab ID for rate limiting */
  tabId?: number;
  /** Actual send function */
  sendFn: () => Promise<boolean>;
}

/**
 * Send telemetry with all robustness protections.
 *
 * Applies:
 * - Rate limiting
 * - Circuit breaker
 * - Offline queueing
 * - Error tracking
 *
 * Returns true if sent successfully, false if queued or dropped.
 */
export async function safeTelemetrySend(options: SafeTelemetrySendOptions): Promise<boolean> {
  const startTime = Date.now();

  // Check rate limit first
  const rateLimiter = getDefaultRateLimiter();
  if (!rateLimiter.tryAcquire(options.tabId)) {
    recordRateLimitHit(options.tabId);
    return false;
  }

  // Check circuit breaker
  const circuitBreaker = getDefaultCircuitBreaker();
  if (!circuitBreaker.isAllowed()) {
    // Circuit is open, queue for later
    const queue = getDefaultOfflineQueue();
    const queued = await queue.enqueue({
      hash: options.hash,
      timestamp: options.timestamp,
      firstSeenLocally: options.firstSeenLocally,
      lshSketches: options.lshSketches,
    });

    if (queued) {
      const status = await queue.getStatus();
      updateQueueDepth(status.size);
    } else {
      recordEventDropped('dedup_or_full');
    }

    return false;
  }

  // Check if online
  if (!checkOnline()) {
    // Offline, queue for later
    const queue = getDefaultOfflineQueue();
    const queued = await queue.enqueue({
      hash: options.hash,
      timestamp: options.timestamp,
      firstSeenLocally: options.firstSeenLocally,
      lshSketches: options.lshSketches,
    });

    if (queued) {
      const status = await queue.getStatus();
      updateQueueDepth(status.size);
    } else {
      recordEventDropped('dedup_or_full');
    }

    return false;
  }

  // Try to send
  try {
    const success = await options.sendFn();
    const latencyMs = Date.now() - startTime;

    if (success) {
      recordTelemetrySuccess(latencyMs);
      await circuitBreaker.recordSuccess();
      return true;
    } else {
      recordTelemetryFailure('send_failed', 'Telemetry send returned false');
      await circuitBreaker.recordFailure();

      // Check if circuit opened
      if (!circuitBreaker.isAllowed()) {
        recordCircuitBreakerTrip();
      }

      return false;
    }
  } catch (err) {
    const _latencyMs = Date.now() - startTime;
    recordTelemetryFailure('send_error', (err as Error).message);
    await circuitBreaker.recordFailure();

    // Check if circuit opened
    if (!circuitBreaker.isAllowed()) {
      recordCircuitBreakerTrip();
    }

    // Queue for retry
    const queue = getDefaultOfflineQueue();
    await queue.enqueue({
      hash: options.hash,
      timestamp: options.timestamp,
      firstSeenLocally: options.firstSeenLocally,
      lshSketches: options.lshSketches,
    });

    const status = await queue.getStatus();
    updateQueueDepth(status.size);

    return false;
  }
}

/**
 * Process the offline queue.
 * Call this periodically (e.g., on heartbeat) or when coming online.
 */
export async function processOfflineQueue(
  processor: (event: { hash: string; timestamp: number; firstSeenLocally: boolean }) => Promise<boolean>
): Promise<number> {
  const queue = getDefaultOfflineQueue();
  const circuitBreaker = getDefaultCircuitBreaker();

  const processed = await queue.process(async (event) => {
    const success = await processor({
      hash: event.hash,
      timestamp: event.timestamp,
      firstSeenLocally: event.firstSeenLocally,
    });

    if (success) {
      recordTelemetrySuccess(0); // Latency not meaningful for queued
    } else {
      recordTelemetryFailure('queue_retry_failed', 'Queued telemetry retry failed');
    }

    return success;
  }, circuitBreaker);

  // Update queue depth
  const status = await queue.getStatus();
  updateQueueDepth(status.size);

  return processed;
}

// ============ Health Check ============

import { getStorageHealth, getQuotaStatus } from './storage';

/**
 * Perform a health check on shadow detection subsystem.
 */
export async function healthCheck(): Promise<{
  healthy: boolean;
  storage: { healthy: boolean; message: string };
  network: { healthy: boolean; message: string };
  queue: { healthy: boolean; message: string };
  rateLimit: { healthy: boolean; message: string };
}> {
  const storageHealth = getStorageHealth();
  const quotaStatus = await getQuotaStatus();
  const circuitBreaker = getDefaultCircuitBreaker();
  const queue = getDefaultOfflineQueue();
  const queueStatus = await queue.getStatus();
  const rateLimiter = getDefaultRateLimiter();
  const rateLimiterStatus = rateLimiter.getStatus();

  const storageHealthy = !storageHealth.degraded && !quotaStatus.isAtQuota;
  const networkHealthy = circuitBreaker.getStatus().state !== 'open';
  const queueHealthy = queueStatus.size < 500; // Warning if queue getting large
  const rateLimitHealthy = !rateLimiterStatus.isLimited;

  return {
    healthy: storageHealthy && networkHealthy && queueHealthy && rateLimitHealthy,
    storage: {
      healthy: storageHealthy,
      message: storageHealth.degraded
        ? 'Storage in degraded mode'
        : quotaStatus.isAtQuota
        ? 'Storage quota exceeded'
        : 'OK',
    },
    network: {
      healthy: networkHealthy,
      message: networkHealthy ? 'OK' : 'Circuit breaker open',
    },
    queue: {
      healthy: queueHealthy,
      message: queueHealthy ? 'OK' : 'Queue size high: ' + queueStatus.size,
    },
    rateLimit: {
      healthy: rateLimitHealthy,
      message: rateLimitHealthy ? 'OK' : 'Rate limited',
    },
  };
}
