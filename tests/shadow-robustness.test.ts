/**
 * Tests for Shadow Detection Robustness (Issue #251)
 *
 * Tests cover:
 * - Storage robustness (LRU eviction, quota handling)
 * - Network robustness (circuit breaker, retry, offline queue)
 * - Processing robustness (rate limiting, timeouts, DOM limits)
 * - Observability (metrics, error tracking)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock chrome.storage.local
const mockStorage = new Map<string, unknown>();
const mockChrome = {
  storage: {
    local: {
      get: vi.fn(async (keys: string | string[] | null) => {
        if (keys === null) {
          return Object.fromEntries(mockStorage);
        }
        const keyList = Array.isArray(keys) ? keys : [keys];
        const result: Record<string, unknown> = {};
        for (const key of keyList) {
          if (mockStorage.has(key)) {
            result[key] = mockStorage.get(key);
          }
        }
        return result;
      }),
      set: vi.fn(async (items: Record<string, unknown>) => {
        for (const [key, value] of Object.entries(items)) {
          mockStorage.set(key, value);
        }
      }),
      remove: vi.fn(async (keys: string | string[]) => {
        const keyList = Array.isArray(keys) ? keys : [keys];
        for (const key of keyList) {
          mockStorage.delete(key);
        }
      }),
      getBytesInUse: vi.fn(async () => 1000),
    },
  },
  tabs: {
    onRemoved: {
      addListener: vi.fn(),
    },
  },
};

vi.stubGlobal('chrome', mockChrome);

// Mock navigator
vi.stubGlobal('navigator', {
  onLine: true,
  storage: {
    estimate: vi.fn(async () => ({
      usage: 1000000,
      quota: 10000000,
    })),
  },
});

// Import after mocks
import {
  DEFAULT_SHADOW_ROBUSTNESS_CONFIG,
  calculateRetryDelay,
  withRetry,
  validateSkeletonMessage,
  createSafeDOMExtractor,
  withTimeout,
  safeAsync,
} from '../src/background/shadow-robustness';
import { CircuitBreaker, OfflineQueue } from '../src/background/shadow-robustness/network';
import { RateLimiter } from '../src/background/shadow-robustness/processing';
import { ShadowLRUCache, getQuotaStatus, getStorageHealth } from '../src/background/shadow-robustness/storage';
import {
  getMetrics,
  incrementMetric,
  recordError,
  getRecentErrors,
  recordProcessingLatency,
  getProcessingLatency,
  resetMetrics,
  _calculatePercentiles,
} from '../src/background/shadow-robustness/metrics';

describe('Shadow Robustness', () => {
  beforeEach(() => {
    mockStorage.clear();
    vi.clearAllMocks();
  });

  // ============ Storage Robustness Tests ============

  describe('ShadowLRUCache', () => {
    it('should store and retrieve values', async () => {
      const cache = new ShadowLRUCache<string>();
      await cache.set('key1', 'value1');
      const result = await cache.get('key1');
      expect(result).toBe('value1');
    });

    it('should return null for missing keys', async () => {
      const cache = new ShadowLRUCache<string>();
      const result = await cache.get('nonexistent');
      expect(result).toBeNull();
    });

    it('should delete values', async () => {
      const cache = new ShadowLRUCache<string>();
      await cache.set('key1', 'value1');
      await cache.delete('key1');
      const result = await cache.get('key1');
      expect(result).toBeNull();
    });

    it('should evict oldest entries when at capacity', async () => {
      const cache = new ShadowLRUCache<string>({ maxEntries: 3, evictionBatchSize: 1 });

      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');
      await cache.set('key3', 'value3');

      // Access key1 to make it recent
      await cache.get('key1');

      // Add key4, should evict key2 (oldest unaccessed)
      await cache.set('key4', 'value4');

      const stats = await cache.getStats();
      expect(stats.entryCount).toBeLessThanOrEqual(3);
    });

    it('should report stats correctly', async () => {
      const cache = new ShadowLRUCache<string>();
      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');

      const stats = await cache.getStats();
      expect(stats.entryCount).toBe(2);
      expect(stats.totalSize).toBeGreaterThan(0);
    });

    it('should clear cache', async () => {
      const cache = new ShadowLRUCache<string>();
      await cache.set('key1', 'value1');
      await cache.clear();

      const result = await cache.get('key1');
      expect(result).toBeNull();
    });
  });

  describe('Storage Health', () => {
    it('should return healthy status by default', () => {
      const health = getStorageHealth();
      expect(health.accessible).toBe(true);
      expect(health.degraded).toBe(false);
    });

    it('should get quota status', async () => {
      const quota = await getQuotaStatus();
      expect(quota.usedBytes).toBeGreaterThanOrEqual(0);
      expect(quota.quotaBytes).toBeGreaterThan(0);
      expect(typeof quota.usagePercent).toBe('number');
      expect(typeof quota.isNearQuota).toBe('boolean');
      expect(typeof quota.isAtQuota).toBe('boolean');
    });
  });

  // ============ Network Robustness Tests ============

  describe('CircuitBreaker', () => {
    it('should start in closed state', () => {
      const cb = new CircuitBreaker();
      expect(cb.isAllowed()).toBe(true);
      expect(cb.getStatus().state).toBe('closed');
    });

    it('should open after failure threshold', async () => {
      const cb = new CircuitBreaker({ failureThreshold: 3 });

      await cb.recordFailure();
      await cb.recordFailure();
      expect(cb.isAllowed()).toBe(true);

      await cb.recordFailure();
      expect(cb.getStatus().state).toBe('open');
      expect(cb.isAllowed()).toBe(false);
    });

    it('should transition to half-open after timeout', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        resetTimeoutMs: 100,
      });

      await cb.recordFailure();
      expect(cb.getStatus().state).toBe('open');

      // Wait for reset timeout
      await new Promise((resolve) => setTimeout(resolve, 150));

      expect(cb.isAllowed()).toBe(true);
      expect(cb.getStatus().state).toBe('half-open');
    });

    it('should close after success in half-open', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        resetTimeoutMs: 50,
        successThreshold: 1,
      });

      await cb.recordFailure();
      await new Promise((resolve) => setTimeout(resolve, 100));

      cb.isAllowed(); // Trigger half-open
      await cb.recordSuccess();

      expect(cb.getStatus().state).toBe('closed');
    });

    it('should reopen on failure in half-open', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        resetTimeoutMs: 50,
      });

      await cb.recordFailure();
      await new Promise((resolve) => setTimeout(resolve, 100));

      cb.isAllowed(); // Trigger half-open
      await cb.recordFailure();

      expect(cb.getStatus().state).toBe('open');
    });

    it('should reset to closed state', async () => {
      const cb = new CircuitBreaker({ failureThreshold: 1 });
      await cb.recordFailure();
      await cb.reset();

      expect(cb.getStatus().state).toBe('closed');
      expect(cb.isAllowed()).toBe(true);
    });
  });

  describe('Retry Logic', () => {
    it('should calculate exponential backoff', () => {
      const config = {
        initialDelayMs: 100,
        maxDelayMs: 10000,
        backoffMultiplier: 2,
        jitterFactor: 0,
        maxRetries: 5,
      };

      expect(calculateRetryDelay(0, config)).toBe(100);
      expect(calculateRetryDelay(1, config)).toBe(200);
      expect(calculateRetryDelay(2, config)).toBe(400);
      expect(calculateRetryDelay(3, config)).toBe(800);
    });

    it('should cap at max delay', () => {
      const config = {
        initialDelayMs: 100,
        maxDelayMs: 500,
        backoffMultiplier: 2,
        jitterFactor: 0,
        maxRetries: 5,
      };

      expect(calculateRetryDelay(10, config)).toBe(500);
    });

    it('should retry on failure', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        if (attempts < 3) {
          throw new Error('fail');
        }
        return 'success';
      };

      const result = await withRetry(fn, {
        maxRetries: 5,
        initialDelayMs: 10,
        maxDelayMs: 100,
        backoffMultiplier: 2,
        jitterFactor: 0,
      });

      expect(result).toBe('success');
      expect(attempts).toBe(3);
    });

    it('should throw after max retries', async () => {
      const fn = async () => {
        throw new Error('always fail');
      };

      await expect(
        withRetry(fn, {
          maxRetries: 2,
          initialDelayMs: 10,
          maxDelayMs: 100,
          backoffMultiplier: 2,
          jitterFactor: 0,
        })
      ).rejects.toThrow('always fail');
    });
  });

  describe('OfflineQueue', () => {
    it('should enqueue events', async () => {
      const queue = new OfflineQueue();
      const result = await queue.enqueue({
        hash: 'abc123',
        timestamp: Date.now(),
        firstSeenLocally: true,
      });

      expect(result).toBe(true);
      expect(await queue.size()).toBe(1);
    });

    it('should deduplicate by hash', async () => {
      const queue = new OfflineQueue();

      await queue.enqueue({
        hash: 'abc123',
        timestamp: Date.now(),
        firstSeenLocally: true,
      });

      const result = await queue.enqueue({
        hash: 'abc123',
        timestamp: Date.now(),
        firstSeenLocally: false,
      });

      expect(result).toBe(false);
      expect(await queue.size()).toBe(1);
    });

    it('should process events', async () => {
      const queue = new OfflineQueue();
      await queue.enqueue({
        hash: 'abc123',
        timestamp: Date.now(),
        firstSeenLocally: true,
      });

      const processed = await queue.process(async () => true);

      expect(processed).toBe(1);
      expect(await queue.size()).toBe(0);
    });

    it('should respect max size and evict old events', async () => {
      const queue = new OfflineQueue({ maxSize: 3 });

      await queue.enqueue({ hash: 'hash1', timestamp: Date.now(), firstSeenLocally: true });
      await queue.enqueue({ hash: 'hash2', timestamp: Date.now(), firstSeenLocally: true });
      await queue.enqueue({ hash: 'hash3', timestamp: Date.now(), firstSeenLocally: true });
      await queue.enqueue({ hash: 'hash4', timestamp: Date.now(), firstSeenLocally: true });

      expect(await queue.size()).toBeLessThanOrEqual(3);
    });

    it('should clear queue', async () => {
      const queue = new OfflineQueue();
      await queue.enqueue({
        hash: 'abc123',
        timestamp: Date.now(),
        firstSeenLocally: true,
      });

      await queue.clear();
      expect(await queue.size()).toBe(0);
    });
  });

  // ============ Processing Robustness Tests ============

  describe('RateLimiter', () => {
    it('should allow requests under limit', () => {
      const limiter = new RateLimiter({ maxRequests: 10, windowMs: 1000 });

      expect(limiter.isAllowed()).toBe(true);
      expect(limiter.tryAcquire()).toBe(true);
    });

    it('should block requests over limit', () => {
      const limiter = new RateLimiter({ maxRequests: 2, windowMs: 60000 });

      expect(limiter.tryAcquire()).toBe(true);
      expect(limiter.tryAcquire()).toBe(true);
      expect(limiter.tryAcquire()).toBe(false);
      expect(limiter.isAllowed()).toBe(false);
    });

    it('should track per-tab limits', () => {
      const limiter = new RateLimiter({
        maxRequests: 100,
        windowMs: 60000,
        perTabLimit: 2,
        perTabWindowMs: 60000,
      });

      expect(limiter.tryAcquire(1)).toBe(true);
      expect(limiter.tryAcquire(1)).toBe(true);
      expect(limiter.tryAcquire(1)).toBe(false);

      // Different tab should still work
      expect(limiter.tryAcquire(2)).toBe(true);
    });

    it('should report status correctly', () => {
      const limiter = new RateLimiter({ maxRequests: 10, windowMs: 60000 });

      limiter.tryAcquire();
      limiter.tryAcquire();

      const status = limiter.getStatus();
      expect(status.currentCount).toBe(2);
      expect(status.remaining).toBe(8);
      expect(status.isLimited).toBe(false);
    });
  });

  describe('DOM Processing Safety', () => {
    it('should extract skeleton safely', () => {
      const extractor = createSafeDOMExtractor();

      // Create a mock document
      const doc = {
        documentElement: {
          tagName: 'HTML',
          children: [
            {
              tagName: 'BODY',
              children: [
                {
                  tagName: 'DIV',
                  children: [],
                  getAttribute: () => null,
                },
              ],
              getAttribute: () => null,
            },
          ],
          getAttribute: () => null,
        },
      } as unknown as Document;

      const result = extractor.extractSkeleton(doc);

      expect(result.tagTree).toContain('html');
      expect(result.meta.success).toBe(true);
      expect(result.meta.truncated).toBe(false);
    });

    it('should truncate at max length', () => {
      const extractor = createSafeDOMExtractor({ maxTagTreeLength: 10 });

      const doc = {
        documentElement: {
          tagName: 'HTML',
          children: [
            {
              tagName: 'BODY',
              children: [
                { tagName: 'DIV', children: [], getAttribute: () => null },
                { tagName: 'DIV', children: [], getAttribute: () => null },
                { tagName: 'DIV', children: [], getAttribute: () => null },
              ],
              getAttribute: () => null,
            },
          ],
          getAttribute: () => null,
        },
      } as unknown as Document;

      const result = extractor.extractSkeleton(doc);

      expect(result.tagTree.length).toBeLessThanOrEqual(10);
      expect(result.meta.truncated).toBe(true);
      expect(result.meta.truncationReason).toBe('max_length');
    });
  });

  describe('Message Validation', () => {
    it('should validate valid skeleton message', () => {
      const message = {
        type: 'DOM_SKELETON',
        url: 'https://example.com',
        payload: {
          tagTree: 'html(body(div))',
          formCount: 1,
          inputTypes: ['text', 'password'],
          actionUrls: ['/login'],
          hasLoginForm: true,
          hasPaymentForm: false,
          extractionTimeMs: 5,
        },
      };

      const result = validateSkeletonMessage(message);

      expect(result.valid).toBe(true);
      expect(result.payload).toBeDefined();
      expect(result.url).toBe('https://example.com');
    });

    it('should reject invalid message type', () => {
      const message = {
        type: 'INVALID',
        url: 'https://example.com',
        payload: {},
      };

      const result = validateSkeletonMessage(message);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid message type');
    });

    it('should reject missing payload', () => {
      const message = {
        type: 'DOM_SKELETON',
        url: 'https://example.com',
      };

      const result = validateSkeletonMessage(message);
      expect(result.valid).toBe(false);
    });

    it('should truncate oversized tag tree', () => {
      const limits = DEFAULT_SHADOW_ROBUSTNESS_CONFIG.domLimits;
      const message = {
        type: 'DOM_SKELETON',
        url: 'https://example.com',
        payload: {
          tagTree: 'x'.repeat(limits.maxTagTreeLength + 1000),
          formCount: 0,
          inputTypes: [],
          actionUrls: [],
          hasLoginForm: false,
          hasPaymentForm: false,
          extractionTimeMs: 0,
        },
      };

      const result = validateSkeletonMessage(message);

      expect(result.valid).toBe(true);
      expect(result.payload?.tagTree.length).toBeLessThanOrEqual(limits.maxTagTreeLength);
    });
  });

  describe('Timeout Helper', () => {
    it('should return result before timeout', async () => {
      const result = await withTimeout(
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 10));
          return 'success';
        },
        100
      );

      expect(result).toBe('success');
    });

    it('should throw on timeout', async () => {
      await expect(
        withTimeout(
          async () => {
            await new Promise((resolve) => setTimeout(resolve, 200));
            return 'success';
          },
          50,
          'Test timeout'
        )
      ).rejects.toThrow('Test timeout');
    });
  });

  describe('Safe Async Helper', () => {
    it('should return result on success', async () => {
      const result = await safeAsync(async () => 'success');
      expect(result).toBe('success');
    });

    it('should return fallback on error', async () => {
      const result = await safeAsync(
        async () => {
          throw new Error('fail');
        },
        'fallback'
      );

      expect(result).toBe('fallback');
    });

    it('should call error handler on error', async () => {
      const errorHandler = vi.fn();

      await safeAsync(
        async () => {
          throw new Error('fail');
        },
        null,
        errorHandler
      );

      expect(errorHandler).toHaveBeenCalled();
    });
  });

  // ============ Observability Tests ============

  describe('Metrics', () => {
    beforeEach(async () => {
      await resetMetrics();
    });

    it('should track metrics', () => {
      incrementMetric('totalProcessed');
      incrementMetric('totalProcessed');
      incrementMetric('telemetrySuccesses');

      const metrics = getMetrics();

      expect(metrics.totalProcessed).toBe(2);
      expect(metrics.telemetrySuccesses).toBe(1);
    });

    it('should track errors', () => {
      recordError('test_error', 'Test error message');
      recordError('test_error', 'Test error message 2');
      recordError('other_error', 'Other error');

      const errors = getRecentErrors();

      expect(errors.length).toBe(2);

      const testError = errors.find((e) => e.errorType === 'test_error');
      expect(testError?.count).toBe(2);
    });

    it('should calculate latency percentiles', () => {
      recordProcessingLatency(10);
      recordProcessingLatency(20);
      recordProcessingLatency(30);
      recordProcessingLatency(40);
      recordProcessingLatency(50);

      const latency = getProcessingLatency();

      expect(latency.sampleCount).toBe(5);
      expect(latency.p50).toBeGreaterThanOrEqual(20);
      expect(latency.max).toBe(50);
    });

    it('should calculate percentiles correctly', () => {
      const samples = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      const percentiles = _calculatePercentiles(samples);

      expect(percentiles.p50).toBe(6); // 50th percentile
      expect(percentiles.p90).toBe(10); // 90th percentile
      expect(percentiles.max).toBe(10);
      expect(percentiles.sampleCount).toBe(10);
    });

    it('should handle empty samples', () => {
      const percentiles = _calculatePercentiles([]);

      expect(percentiles.p50).toBe(0);
      expect(percentiles.max).toBe(0);
      expect(percentiles.sampleCount).toBe(0);
    });
  });

  // ============ Configuration Tests ============

  describe('Configuration', () => {
    it('should have valid default config', () => {
      expect(DEFAULT_SHADOW_ROBUSTNESS_CONFIG.cache.maxEntries).toBeGreaterThan(0);
      expect(DEFAULT_SHADOW_ROBUSTNESS_CONFIG.circuitBreaker.failureThreshold).toBeGreaterThan(0);
      expect(DEFAULT_SHADOW_ROBUSTNESS_CONFIG.retry.maxRetries).toBeGreaterThan(0);
      expect(DEFAULT_SHADOW_ROBUSTNESS_CONFIG.offlineQueue.maxSize).toBeGreaterThan(0);
      expect(DEFAULT_SHADOW_ROBUSTNESS_CONFIG.rateLimiter.maxRequests).toBeGreaterThan(0);
      expect(DEFAULT_SHADOW_ROBUSTNESS_CONFIG.domLimits.maxDepth).toBeGreaterThan(0);
    });
  });

  // ============ Issue #251 Acceptance Criteria Tests ============

  describe('Issue #251 Acceptance Criteria', () => {
    it('should have LRU eviction for shadow detection cache', async () => {
      const cache = new ShadowLRUCache<string>({ maxEntries: 2 });

      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');
      await cache.set('key3', 'value3');

      // Should have evicted oldest
      const stats = await cache.getStats();
      expect(stats.entryCount).toBeLessThanOrEqual(2);
    });

    it('should have circuit breaker for telemetry', async () => {
      const cb = new CircuitBreaker({ failureThreshold: 3 });

      // Simulate failures
      await cb.recordFailure();
      await cb.recordFailure();
      await cb.recordFailure();

      // Circuit should be open
      expect(cb.isAllowed()).toBe(false);
    });

    it('should have offline queue with bounded size', async () => {
      const queue = new OfflineQueue({ maxSize: 5 });

      for (let i = 0; i < 10; i++) {
        await queue.enqueue({
          hash: 'hash' + i,
          timestamp: Date.now(),
          firstSeenLocally: true,
        });
      }

      // Should not exceed max size
      expect(await queue.size()).toBeLessThanOrEqual(5);
    });

    it('should have rate limiting', () => {
      const limiter = new RateLimiter({ maxRequests: 5, windowMs: 60000 });

      for (let i = 0; i < 5; i++) {
        expect(limiter.tryAcquire()).toBe(true);
      }

      // Should be rate limited
      expect(limiter.tryAcquire()).toBe(false);
    });

    it('should have DOM processing limits', () => {
      const extractor = createSafeDOMExtractor({
        maxDepth: 3,
        maxNodes: 10,
      });

      // Create deep nested structure
      const createDeep = (depth: number): unknown => {
        if (depth === 0) {
          return {
            tagName: 'DIV',
            children: [],
            getAttribute: () => null,
          };
        }
        return {
          tagName: 'DIV',
          children: [createDeep(depth - 1)],
          getAttribute: () => null,
        };
      };

      const doc = {
        documentElement: {
          tagName: 'HTML',
          children: [createDeep(10)],
          getAttribute: () => null,
        },
      } as unknown as Document;

      const result = extractor.extractSkeleton(doc);

      // Should have truncated due to depth or node limit
      expect(result.meta.processedDepth).toBeLessThanOrEqual(3);
    });

    it('should track metrics for observability', () => {
      incrementMetric('totalProcessed');
      incrementMetric('telemetryFailures');
      recordError('test_error', 'Test message');

      const metrics = getMetrics();
      const errors = getRecentErrors();

      expect(metrics.totalProcessed).toBeGreaterThan(0);
      expect(metrics.telemetryFailures).toBeGreaterThan(0);
      expect(errors.length).toBeGreaterThan(0);
    });

    it('should deduplicate queued events', async () => {
      const queue = new OfflineQueue();

      // Try to enqueue same hash twice
      const first = await queue.enqueue({
        hash: 'duplicate_hash',
        timestamp: Date.now(),
        firstSeenLocally: true,
      });

      const second = await queue.enqueue({
        hash: 'duplicate_hash',
        timestamp: Date.now(),
        firstSeenLocally: false,
      });

      expect(first).toBe(true);
      expect(second).toBe(false); // Deduplicated
      expect(await queue.size()).toBe(1);
    });
  });
});
