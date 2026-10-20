/**
 * Observability for Shadow Detection (Issue #251)
 *
 * Provides:
 * - Metrics for shadow detection volume
 * - Error rate tracking
 * - Queue depth monitoring
 * - Processing latency percentiles
 *
 * Design: Observability must be lightweight and not affect performance.
 * Metrics are for debugging and monitoring, not user-facing.
 */

import type {
  ShadowDetectionMetrics,
  LatencyPercentiles,
  ErrorTrackingEntry,
  ObservabilitySnapshot,
  StorageHealthStatus,
  CircuitBreakerStatus,
  OfflineQueueStatus,
  RateLimiterStatus,
} from '../../types/shadow-robustness';

// ============ Constants ============

const METRICS_KEY = 'browserdefense_shadow_metrics';
const ERROR_LOG_KEY = 'browserdefense_shadow_errors';
const LATENCY_SAMPLES_KEY = 'browserdefense_shadow_latency';

const MAX_ERROR_ENTRIES = 100;
const MAX_LATENCY_SAMPLES = 1000;
const ERROR_RETENTION_MS = 60 * 60 * 1000; // 1 hour

// ============ Metrics Tracking ============

/**
 * Current metrics state (in-memory for performance).
 */
let metrics: ShadowDetectionMetrics = {
  totalProcessed: 0,
  telemetrySuccesses: 0,
  telemetryFailures: 0,
  eventsDropped: 0,
  queueDepth: 0,
  circuitBreakerTrips: 0,
  storageErrors: 0,
  processingTimeouts: 0,
  rateLimitHits: 0,
  lastResetAt: Date.now(),
};

/**
 * Latency samples for percentile calculation.
 */
interface LatencySamples {
  processing: number[];
  telemetry: number[];
}

let latencySamples: LatencySamples = {
  processing: [],
  telemetry: [],
};

/**
 * Error tracking entries.
 */
let errorEntries: ErrorTrackingEntry[] = [];

/**
 * Get current metrics.
 */
export function getMetrics(): ShadowDetectionMetrics {
  return { ...metrics };
}

/**
 * Increment a metric counter.
 */
export function incrementMetric(
  metric: keyof Pick<
    ShadowDetectionMetrics,
    | 'totalProcessed'
    | 'telemetrySuccesses'
    | 'telemetryFailures'
    | 'eventsDropped'
    | 'circuitBreakerTrips'
    | 'storageErrors'
    | 'processingTimeouts'
    | 'rateLimitHits'
  >
): void {
  metrics[metric]++;
}

/**
 * Update queue depth metric.
 */
export function updateQueueDepth(depth: number): void {
  metrics.queueDepth = depth;
}

/**
 * Record processing latency sample.
 */
export function recordProcessingLatency(latencyMs: number): void {
  latencySamples.processing.push(latencyMs);

  // Keep samples bounded
  if (latencySamples.processing.length > MAX_LATENCY_SAMPLES) {
    latencySamples.processing = latencySamples.processing.slice(-MAX_LATENCY_SAMPLES);
  }
}

/**
 * Record telemetry latency sample.
 */
export function recordTelemetryLatency(latencyMs: number): void {
  latencySamples.telemetry.push(latencyMs);

  // Keep samples bounded
  if (latencySamples.telemetry.length > MAX_LATENCY_SAMPLES) {
    latencySamples.telemetry = latencySamples.telemetry.slice(-MAX_LATENCY_SAMPLES);
  }
}

/**
 * Calculate percentiles from samples.
 */
function calculatePercentiles(samples: number[]): LatencyPercentiles {
  if (samples.length === 0) {
    return {
      p50: 0,
      p90: 0,
      p95: 0,
      p99: 0,
      max: 0,
      sampleCount: 0,
    };
  }

  // Sort samples for percentile calculation
  const sorted = [...samples].sort((a, b) => a - b);
  const len = sorted.length;

  return {
    p50: sorted[Math.floor(len * 0.5)] ?? 0,
    p90: sorted[Math.floor(len * 0.9)] ?? 0,
    p95: sorted[Math.floor(len * 0.95)] ?? 0,
    p99: sorted[Math.floor(len * 0.99)] ?? 0,
    max: sorted[len - 1] ?? 0,
    sampleCount: len,
  };
}

/**
 * Get processing latency percentiles.
 */
export function getProcessingLatency(): LatencyPercentiles {
  return calculatePercentiles(latencySamples.processing);
}

/**
 * Get telemetry latency percentiles.
 */
export function getTelemetryLatency(): LatencyPercentiles {
  return calculatePercentiles(latencySamples.telemetry);
}

// ============ Error Tracking ============

/**
 * Record an error.
 */
export function recordError(errorType: string, message: string): void {
  const now = Date.now();

  // Look for existing entry of same type
  const existing = errorEntries.find((e) => e.errorType === errorType);

  if (existing) {
    existing.count++;
    existing.lastOccurrence = now;
    existing.message = message; // Update to latest message
  } else {
    errorEntries.push({
      errorType,
      message,
      firstOccurrence: now,
      lastOccurrence: now,
      count: 1,
    });
  }

  // Prune old entries
  const cutoff = now - ERROR_RETENTION_MS;
  errorEntries = errorEntries.filter((e) => e.lastOccurrence > cutoff);

  // Keep bounded
  if (errorEntries.length > MAX_ERROR_ENTRIES) {
    // Sort by count (keep most frequent) and recency
    errorEntries.sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      return b.lastOccurrence - a.lastOccurrence;
    });
    errorEntries = errorEntries.slice(0, MAX_ERROR_ENTRIES);
  }
}

/**
 * Get recent errors.
 */
export function getRecentErrors(): ErrorTrackingEntry[] {
  const now = Date.now();
  const cutoff = now - ERROR_RETENTION_MS;
  return errorEntries
    .filter((e) => e.lastOccurrence > cutoff)
    .sort((a, b) => b.lastOccurrence - a.lastOccurrence);
}

/**
 * Get error rate (errors per minute).
 */
export function getErrorRate(): number {
  const windowMs = 60 * 1000;
  const now = Date.now();
  const cutoff = now - windowMs;

  let totalErrors = 0;
  for (const entry of errorEntries) {
    if (entry.lastOccurrence > cutoff) {
      // Estimate errors in window based on rate
      const entryWindowMs = Math.min(windowMs, entry.lastOccurrence - entry.firstOccurrence);
      if (entryWindowMs > 0) {
        totalErrors += Math.min(entry.count, entry.count * (windowMs / entryWindowMs));
      } else {
        totalErrors += entry.count;
      }
    }
  }

  return totalErrors;
}

// ============ Persistence ============

/**
 * Save metrics to storage.
 */
export async function saveMetrics(): Promise<void> {
  try {
    await chrome.storage.local.set({
      [METRICS_KEY]: metrics,
      [ERROR_LOG_KEY]: errorEntries,
      [LATENCY_SAMPLES_KEY]: latencySamples,
    });
  } catch (err) {
    console.warn('[BrowserDefense] Failed to save metrics:', err);
  }
}

/**
 * Load metrics from storage.
 */
export async function loadMetrics(): Promise<void> {
  try {
    const result = await chrome.storage.local.get([
      METRICS_KEY,
      ERROR_LOG_KEY,
      LATENCY_SAMPLES_KEY,
    ]);

    if (result[METRICS_KEY]) {
      metrics = result[METRICS_KEY] as ShadowDetectionMetrics;
    }

    if (result[ERROR_LOG_KEY]) {
      errorEntries = result[ERROR_LOG_KEY] as ErrorTrackingEntry[];
    }

    if (result[LATENCY_SAMPLES_KEY]) {
      latencySamples = result[LATENCY_SAMPLES_KEY] as LatencySamples;
    }
  } catch (err) {
    console.warn('[BrowserDefense] Failed to load metrics:', err);
  }
}

/**
 * Reset all metrics.
 */
export async function resetMetrics(): Promise<void> {
  metrics = {
    totalProcessed: 0,
    telemetrySuccesses: 0,
    telemetryFailures: 0,
    eventsDropped: 0,
    queueDepth: 0,
    circuitBreakerTrips: 0,
    storageErrors: 0,
    processingTimeouts: 0,
    rateLimitHits: 0,
    lastResetAt: Date.now(),
  };
  latencySamples = {
    processing: [],
    telemetry: [],
  };
  errorEntries = [];

  await saveMetrics();
  console.log('[BrowserDefense] Metrics reset');
}

// ============ Observability Snapshot ============

/**
 * Get a complete observability snapshot.
 * Requires external status providers.
 */
export function getObservabilitySnapshot(
  storageHealth: StorageHealthStatus,
  circuitBreaker: CircuitBreakerStatus,
  queueStatus: OfflineQueueStatus,
  rateLimiter: RateLimiterStatus
): ObservabilitySnapshot {
  return {
    metrics: getMetrics(),
    processingLatency: getProcessingLatency(),
    telemetryLatency: getTelemetryLatency(),
    recentErrors: getRecentErrors(),
    storageHealth,
    circuitBreaker,
    queueStatus,
    rateLimiter,
    timestamp: Date.now(),
  };
}

// ============ Convenience Recording Functions ============

/**
 * Record a successful telemetry send.
 */
export function recordTelemetrySuccess(latencyMs: number): void {
  incrementMetric('telemetrySuccesses');
  recordTelemetryLatency(latencyMs);
}

/**
 * Record a failed telemetry send.
 */
export function recordTelemetryFailure(errorType: string, message: string): void {
  incrementMetric('telemetryFailures');
  recordError(errorType, message);
}

/**
 * Record a processing completion.
 */
export function recordProcessingComplete(latencyMs: number): void {
  incrementMetric('totalProcessed');
  recordProcessingLatency(latencyMs);
}

/**
 * Record a processing timeout.
 */
export function recordProcessingTimeout(): void {
  incrementMetric('processingTimeouts');
  recordError('processing_timeout', 'DOM processing timed out');
}

/**
 * Record a rate limit hit.
 */
export function recordRateLimitHit(tabId?: number): void {
  incrementMetric('rateLimitHits');
  recordError('rate_limit', 'Rate limit exceeded' + (tabId ? ' for tab ' + tabId : ''));
}

/**
 * Record an event being dropped.
 */
export function recordEventDropped(reason: string): void {
  incrementMetric('eventsDropped');
  recordError('event_dropped', 'Event dropped: ' + reason);
}

/**
 * Record a circuit breaker trip.
 */
export function recordCircuitBreakerTrip(): void {
  incrementMetric('circuitBreakerTrips');
  recordError('circuit_breaker_trip', 'Circuit breaker opened');
}

/**
 * Record a storage error.
 */
export function recordStorageError(message: string): void {
  incrementMetric('storageErrors');
  recordError('storage_error', message);
}

// ============ Periodic Save ============

let saveInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Start periodic metrics saving.
 */
export function startPeriodicSave(intervalMs: number = 60000): void {
  if (saveInterval) {
    clearInterval(saveInterval);
  }
  saveInterval = setInterval(() => {
    saveMetrics().catch((err) => console.warn('[Shadow] Metrics save failed:', err));
  }, intervalMs);
}

/**
 * Stop periodic metrics saving.
 */
export function stopPeriodicSave(): void {
  if (saveInterval) {
    clearInterval(saveInterval);
    saveInterval = null;
  }
}

// ============ Exports for Testing ============

export {
  METRICS_KEY as _METRICS_KEY,
  ERROR_LOG_KEY as _ERROR_LOG_KEY,
  LATENCY_SAMPLES_KEY as _LATENCY_SAMPLES_KEY,
  calculatePercentiles as _calculatePercentiles,
};
