/**
 * Shadow Detection Robustness Types (Issue #251)
 *
 * Types for hardening shadow detection against edge cases,
 * failure modes, and adversarial conditions.
 *
 * Design Principle: Shadow detection must NEVER impact:
 * - Core blocking functionality
 * - User experience (no visible errors)
 * - System stability
 */

// ============ Storage Robustness Types ============

/**
 * LRU cache entry with access tracking.
 */
export interface LRUCacheEntry<T> {
  /** The cached value */
  value: T;
  /** Last access timestamp (Unix ms) */
  lastAccess: number;
  /** Creation timestamp (Unix ms) */
  createdAt: number;
  /** Size in bytes (estimated) */
  sizeBytes: number;
}

/**
 * LRU cache configuration.
 */
export interface LRUCacheConfig {
  /** Maximum number of entries */
  maxEntries: number;
  /** Maximum total size in bytes */
  maxSizeBytes: number;
  /** Entry TTL in milliseconds (0 = no expiry) */
  ttlMs: number;
  /** How many entries to evict when at capacity (batch eviction) */
  evictionBatchSize: number;
}

/**
 * Storage quota status.
 */
export interface StorageQuotaStatus {
  /** Estimated used bytes */
  usedBytes: number;
  /** Estimated quota bytes */
  quotaBytes: number;
  /** Usage percentage (0-100) */
  usagePercent: number;
  /** Whether approaching quota (>80%) */
  isNearQuota: boolean;
  /** Whether at quota (>95%) */
  isAtQuota: boolean;
}

/**
 * Storage health status.
 */
export interface StorageHealthStatus {
  /** Whether storage is accessible */
  accessible: boolean;
  /** Last successful access timestamp */
  lastSuccessfulAccess?: number;
  /** Last error message */
  lastError?: string;
  /** Consecutive error count */
  errorCount: number;
  /** Whether in degraded mode */
  degraded: boolean;
}

// ============ Network Robustness Types ============

/**
 * Circuit breaker states.
 */
export type CircuitBreakerState = 'closed' | 'open' | 'half-open';

/**
 * Circuit breaker configuration.
 */
export interface CircuitBreakerConfig {
  /** Number of failures before opening circuit */
  failureThreshold: number;
  /** Time to wait before trying half-open (ms) */
  resetTimeoutMs: number;
  /** Number of successes needed to close from half-open */
  successThreshold: number;
  /** Time window for counting failures (ms) */
  failureWindowMs: number;
}

/**
 * Circuit breaker status.
 */
export interface CircuitBreakerStatus {
  /** Current state */
  state: CircuitBreakerState;
  /** Failure count in current window */
  failureCount: number;
  /** Success count (in half-open state) */
  successCount: number;
  /** When circuit was opened (if open/half-open) */
  openedAt?: number;
  /** Next reset attempt time (if open) */
  nextResetAt?: number;
}

/**
 * Retry configuration with exponential backoff.
 */
export interface RetryConfig {
  /** Maximum number of retry attempts */
  maxRetries: number;
  /** Initial delay in milliseconds */
  initialDelayMs: number;
  /** Maximum delay in milliseconds */
  maxDelayMs: number;
  /** Backoff multiplier (e.g., 2 for doubling) */
  backoffMultiplier: number;
  /** Add random jitter (0-1, percentage of delay) */
  jitterFactor: number;
}

/**
 * Queued telemetry event.
 */
export interface QueuedTelemetryEvent {
  /** Unique event ID */
  id: string;
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
  /** Number of retry attempts */
  retryCount: number;
  /** Next retry timestamp */
  nextRetryAt: number;
  /** Queue entry time */
  queuedAt: number;
}

/**
 * Offline queue configuration.
 */
export interface OfflineQueueConfig {
  /** Maximum queue size */
  maxSize: number;
  /** Maximum age of queued items (ms) */
  maxAgeMs: number;
  /** Batch size for processing */
  batchSize: number;
  /** Minimum interval between batches (ms) */
  batchIntervalMs: number;
}

/**
 * Offline queue status.
 */
export interface OfflineQueueStatus {
  /** Current queue size */
  size: number;
  /** Oldest item age (ms) */
  oldestAgeMs?: number;
  /** Processing in progress */
  processing: boolean;
  /** Last process time */
  lastProcessedAt?: number;
  /** Items processed in last batch */
  lastBatchSize: number;
}

// ============ Processing Robustness Types ============

/**
 * Rate limiter configuration.
 */
export interface RateLimiterConfig {
  /** Maximum requests per window */
  maxRequests: number;
  /** Window duration in milliseconds */
  windowMs: number;
  /** Per-tab limit (0 = no per-tab limit) */
  perTabLimit: number;
  /** Per-tab window (ms) */
  perTabWindowMs: number;
}

/**
 * Rate limiter status.
 */
export interface RateLimiterStatus {
  /** Current request count in window */
  currentCount: number;
  /** Remaining requests in window */
  remaining: number;
  /** Window reset time */
  resetAt: number;
  /** Whether currently rate limited */
  isLimited: boolean;
  /** Per-tab counts */
  perTabCounts: Map<number, number>;
}

/**
 * DOM processing limits.
 */
export interface DOMProcessingLimits {
  /** Maximum DOM depth to traverse */
  maxDepth: number;
  /** Maximum number of nodes to process */
  maxNodes: number;
  /** Maximum tag tree string length */
  maxTagTreeLength: number;
  /** Processing timeout in milliseconds */
  timeoutMs: number;
}

/**
 * DOM processing result with safety info.
 */
export interface SafeDOMProcessingResult {
  /** Whether processing completed successfully */
  success: boolean;
  /** Whether processing was truncated due to limits */
  truncated: boolean;
  /** Truncation reason if applicable */
  truncationReason?: 'max_depth' | 'max_nodes' | 'max_length' | 'timeout';
  /** Actual depth processed */
  processedDepth: number;
  /** Actual nodes processed */
  processedNodes: number;
  /** Processing time in milliseconds */
  processingTimeMs: number;
}

// ============ Observability Types ============

/**
 * Shadow detection metrics.
 */
export interface ShadowDetectionMetrics {
  /** Total events processed */
  totalProcessed: number;
  /** Successful telemetry sends */
  telemetrySuccesses: number;
  /** Failed telemetry sends */
  telemetryFailures: number;
  /** Events dropped (rate limited, queue full, etc.) */
  eventsDropped: number;
  /** Events currently queued */
  queueDepth: number;
  /** Circuit breaker trips */
  circuitBreakerTrips: number;
  /** Storage errors */
  storageErrors: number;
  /** Processing timeouts */
  processingTimeouts: number;
  /** Rate limit hits */
  rateLimitHits: number;
  /** Last reset timestamp */
  lastResetAt: number;
}

/**
 * Latency percentile tracking.
 */
export interface LatencyPercentiles {
  /** P50 (median) in milliseconds */
  p50: number;
  /** P90 in milliseconds */
  p90: number;
  /** P95 in milliseconds */
  p95: number;
  /** P99 in milliseconds */
  p99: number;
  /** Maximum observed */
  max: number;
  /** Sample count */
  sampleCount: number;
}

/**
 * Error tracking entry.
 */
export interface ErrorTrackingEntry {
  /** Error type/code */
  errorType: string;
  /** Error message */
  message: string;
  /** First occurrence */
  firstOccurrence: number;
  /** Last occurrence */
  lastOccurrence: number;
  /** Total count */
  count: number;
}

/**
 * Observability snapshot.
 */
export interface ObservabilitySnapshot {
  /** Current metrics */
  metrics: ShadowDetectionMetrics;
  /** Processing latency percentiles */
  processingLatency: LatencyPercentiles;
  /** Telemetry latency percentiles */
  telemetryLatency: LatencyPercentiles;
  /** Recent errors (last hour) */
  recentErrors: ErrorTrackingEntry[];
  /** Storage health */
  storageHealth: StorageHealthStatus;
  /** Circuit breaker status */
  circuitBreaker: CircuitBreakerStatus;
  /** Queue status */
  queueStatus: OfflineQueueStatus;
  /** Rate limiter status */
  rateLimiter: RateLimiterStatus;
  /** Snapshot timestamp */
  timestamp: number;
}

// ============ Configuration Types ============

/**
 * Complete shadow robustness configuration.
 */
export interface ShadowRobustnessConfig {
  /** LRU cache settings */
  cache: LRUCacheConfig;
  /** Circuit breaker settings */
  circuitBreaker: CircuitBreakerConfig;
  /** Retry settings */
  retry: RetryConfig;
  /** Offline queue settings */
  offlineQueue: OfflineQueueConfig;
  /** Rate limiter settings */
  rateLimiter: RateLimiterConfig;
  /** DOM processing limits */
  domLimits: DOMProcessingLimits;
  /** Whether to log debug info */
  debug: boolean;
}

/**
 * Default configuration values.
 */
export const DEFAULT_SHADOW_ROBUSTNESS_CONFIG: ShadowRobustnessConfig = {
  cache: {
    maxEntries: 10000,
    maxSizeBytes: 5 * 1024 * 1024, // 5MB
    ttlMs: 24 * 60 * 60 * 1000, // 24 hours
    evictionBatchSize: 100,
  },
  circuitBreaker: {
    failureThreshold: 5,
    resetTimeoutMs: 60 * 1000, // 1 minute
    successThreshold: 2,
    failureWindowMs: 60 * 1000, // 1 minute
  },
  retry: {
    maxRetries: 3,
    initialDelayMs: 1000,
    maxDelayMs: 30 * 1000, // 30 seconds
    backoffMultiplier: 2,
    jitterFactor: 0.1,
  },
  offlineQueue: {
    maxSize: 1000,
    maxAgeMs: 24 * 60 * 60 * 1000, // 24 hours
    batchSize: 10,
    batchIntervalMs: 5000,
  },
  rateLimiter: {
    maxRequests: 100,
    windowMs: 60 * 1000, // 1 minute
    perTabLimit: 10,
    perTabWindowMs: 60 * 1000, // 1 minute
  },
  domLimits: {
    maxDepth: 50,
    maxNodes: 10000,
    maxTagTreeLength: 100000,
    timeoutMs: 5000,
  },
  debug: false,
};
