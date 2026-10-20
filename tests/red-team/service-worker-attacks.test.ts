/**
 * Red Team: Service Worker Lifecycle Attacks
 *
 * Tests service worker behavior under adversarial conditions:
 * - Wake timing attacks
 * - Storage race conditions
 * - Message handling exploits
 * - Data loss scenarios
 *
 * Issue #30: Verify forensics queue survives failures
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

// ============================================================================
// Mock Setup
// ============================================================================

const mockStorage: Record<string, unknown> = {};
let storageQuotaExceeded = false;
let storageWriteDelay = 0;
let storageReadDelay = 0;
let storageFailOnWrite = false;

const STORAGE_KEY = 'browserdefense_forensics_queue';

const mockChrome = {
  storage: {
    local: {
      get: vi.fn(async (key: string) => {
        if (storageReadDelay > 0) {
          await sleep(storageReadDelay);
        }
        if (typeof key === 'string') {
          return { [key]: mockStorage[key] };
        }
        return mockStorage;
      }),
      set: vi.fn(async (items: Record<string, unknown>) => {
        if (storageWriteDelay > 0) {
          await sleep(storageWriteDelay);
        }
        if (storageQuotaExceeded) {
          throw new Error('QUOTA_BYTES_PER_ITEM quota exceeded');
        }
        if (storageFailOnWrite) {
          throw new Error('Storage write failed');
        }
        Object.assign(mockStorage, items);
      }),
      remove: vi.fn(async (key: string) => {
        delete mockStorage[key];
      }),
      getBytesInUse: vi.fn(async () => {
        return JSON.stringify(mockStorage).length;
      }),
    },
  },
  action: {
    setBadgeText: vi.fn(),
    setBadgeBackgroundColor: vi.fn(),
  },
  alarms: {
    create: vi.fn(),
    clear: vi.fn(async () => true),
    get: vi.fn(async () => null),
    getAll: vi.fn(async () => []),
    onAlarm: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
    },
  },
  tabs: {
    update: vi.fn(async () => ({})),
    onRemoved: {
      addListener: vi.fn(),
    },
  },
  webNavigation: {
    onBeforeNavigate: {
      addListener: vi.fn(),
    },
  },
  runtime: {
    getURL: (path: string) => `chrome-extension://test-id/${path}`,
  },
};

// @ts-expect-error - mocking global chrome
globalThis.chrome = mockChrome;

// Mock navigator.onLine
Object.defineProperty(globalThis, 'navigator', {
  value: { onLine: true },
  writable: true,
  configurable: true,
});

// Helper to sleep
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Helper to create ForensicsPayload
function createPayload(id: number | string, url?: string) {
  return {
    blockedUrl: url || `https://evil-${id}.com`,
    timestamp: new Date().toISOString(),
    tabId: typeof id === 'number' ? id : 1,
    frameId: 0,
    reason: 'ioc_match',
  };
}

// Import modules after mocking
import {
  getQueue,
  queueForensics,
  getPendingCount,
  clearQueue,
  retryPendingUploads,
  _resetRateLimiter,
  type QueuedForensics,
  type ForensicsPayload,
  type EncryptedForensics,
} from '../../src/background/forensics';
import { initHeartbeat, handleHeartbeat, getHeartbeatStats } from '../../src/background/heartbeat';

describe('Red Team: Service Worker Lifecycle Attacks', () => {
  beforeEach(() => {
    // Reset state
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    storageQuotaExceeded = false;
    storageWriteDelay = 0;
    storageReadDelay = 0;
    storageFailOnWrite = false;
    vi.clearAllMocks();

    // Reset rate limiter for each test (Issue #603)
    _resetRateLimiter();

    // Reset navigator.onLine
    Object.defineProperty(globalThis, 'navigator', {
      value: { onLine: true },
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ==========================================================================
  // Attack Scenario: Rapid Tab Open/Close During Blocking
  // ==========================================================================
  describe('Rapid Tab Open/Close During Blocking', () => {
    /**
     * FIX VERIFIED: Concurrent queueForensics calls now work correctly.
     * Mutex pattern prevents read-modify-write race conditions.
     * Note: Test uses 10 events to stay within rate limit (Issue #603).
     */
    it('concurrent queuing works correctly with mutex', async () => {
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(queueForensics(createPayload(i)));
      }

      await Promise.all(promises);

      const queue = await getQueue();

      // FIX VERIFIED: All items survive with mutex protection
      expect(queue.length).toBe(10);
      console.log(`[RED TEAM] Mutex fix verified: all ${queue.length}/10 items survived`);
    });

    it('sequential queuing works correctly', async () => {
      for (let i = 0; i < 10; i++) {
        await queueForensics(createPayload(i));
      }

      const queue = await getQueue();
      expect(queue).toHaveLength(10);

      // Verify no data corruption
      const urls = queue.map((item) => item.payload.blockedUrl);
      const uniqueUrls = new Set(urls);
      expect(uniqueUrls.size).toBe(10);
    });
  });

  // ==========================================================================
  // Attack Scenario: Service Worker Killed Mid-Forensics Upload
  // ==========================================================================
  describe('Service Worker Killed Mid-Forensics Upload', () => {
    it('preserves queue when upload is interrupted', async () => {
      // Pre-populate queue with items
      const items: QueuedForensics[] = [];
      for (let i = 0; i < 5; i++) {
        items.push({
          id: `item-${i}`,
          payload: createPayload(i),
          queuedAt: new Date().toISOString(),
          attempts: 0,
        });
      }
      mockStorage[STORAGE_KEY] = items;

      // Simulate slow network that would be interrupted
      global.fetch = vi.fn().mockImplementation(
        () =>
          new Promise((resolve) => {
            setTimeout(() => resolve({ ok: true }), 60000);
          })
      );

      // Start upload but don't await (simulates SW kill)
      retryPendingUploads('https://forensics.example.com');

      // Simulate SW termination by giving minimal time
      await sleep(10);

      // Queue should still have items
      const queue = await getQueue();
      expect(queue.length).toBe(5);
    });

    it('increments attempt count on failed upload', async () => {
      // Item must have encrypted data to be uploaded (zero-knowledge policy)
      const items: QueuedForensics[] = [
        {
          id: 'test-item',
          payload: createPayload('test'),
          encrypted: {
            orgId: 'test-org',
            keyVersion: 1,
            iv: 'test-iv',
            wrappedKey: 'test-wrapped-key',
            ciphertext: 'test-ciphertext',
          },
          queuedAt: new Date().toISOString(),
          attempts: 0,
        },
      ];
      mockStorage[STORAGE_KEY] = items;

      // Mock failed fetch
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

      await retryPendingUploads('https://forensics.example.com');

      const queue = await getQueue();
      expect(queue[0].attempts).toBe(1);
      expect(queue[0].lastAttempt).toBeDefined();
    });

    it('skips unencrypted items without incrementing attempts (zero-knowledge policy)', async () => {
      // Item WITHOUT encrypted data should be skipped, not uploaded
      const items: QueuedForensics[] = [
        {
          id: 'unencrypted-item',
          payload: createPayload('test'),
          queuedAt: new Date().toISOString(),
          attempts: 0,
        },
      ];
      mockStorage[STORAGE_KEY] = items;

      global.fetch = vi.fn();

      await retryPendingUploads('https://forensics.example.com');

      const queue = await getQueue();
      // Item stays in queue but fetch was never called (zero-knowledge policy)
      expect(queue).toHaveLength(1);
      expect(queue[0].attempts).toBe(0);
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it('drops items after max retry attempts', async () => {
      const items: QueuedForensics[] = [
        {
          id: 'exhausted-item',
          payload: createPayload('exhausted'),
          queuedAt: new Date().toISOString(),
          attempts: 10, // MAX_RETRY_ATTEMPTS
          lastAttempt: '2020-01-01T00:00:00.000Z', // Bypass backoff
        },
      ];
      mockStorage[STORAGE_KEY] = items;

      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

      await retryPendingUploads('https://forensics.example.com');

      const queue = await getQueue();
      expect(queue).toHaveLength(0);
    });
  });

  // ==========================================================================
  // Attack Scenario: Storage Quota Exceeded During Write
  // ==========================================================================
  describe('Storage Quota Exceeded During Write', () => {
    it('handles quota exceeded error gracefully', async () => {
      storageQuotaExceeded = true;

      await expect(queueForensics(createPayload('test'))).rejects.toThrow('QUOTA_BYTES_PER_ITEM');
    });

    it('logs warning when approaching queue limit', async () => {
      const consoleSpy = vi.spyOn(console, 'warn');

      // Fill queue to max
      const fullQueue: QueuedForensics[] = [];
      for (let i = 0; i < 1000; i++) {
        fullQueue.push({
          id: `item-${i}`,
          payload: createPayload(i),
          queuedAt: new Date().toISOString(),
          attempts: 0,
        });
      }
      mockStorage[STORAGE_KEY] = fullQueue;

      // Add one more - should drop oldest
      await queueForensics(createPayload('new'));

      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Forensics queue full'));
    });
  });

  // ==========================================================================
  // Attack Scenario: Alarm Not Firing (Heartbeat Failure)
  // ==========================================================================
  describe('Alarm Not Firing (Heartbeat Failure)', () => {
    it('initializes heartbeat alarm correctly', async () => {
      await initHeartbeat();

      expect(mockChrome.alarms.clear).toHaveBeenCalledWith('keepAlive');
      expect(mockChrome.alarms.create).toHaveBeenCalledWith(
        'keepAlive',
        expect.objectContaining({
          periodInMinutes: 4.9,
        })
      );
    });

    it('handles heartbeat when forensics pending', async () => {
      // Pre-populate queue
      mockStorage[STORAGE_KEY] = [
        {
          id: 'pending',
          payload: createPayload('pending'),
          queuedAt: new Date().toISOString(),
          attempts: 0,
        },
      ];

      const consoleSpy = vi.spyOn(console, 'log');

      await handleHeartbeat();

      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Heartbeat'));
    });

    it('tracks heartbeat count for diagnostics', async () => {
      const initialStats = getHeartbeatStats();
      const initialCount = initialStats.count;

      await handleHeartbeat();
      await handleHeartbeat();

      const stats = getHeartbeatStats();
      expect(stats.count).toBe(initialCount + 2);
      expect(stats.intervalMinutes).toBe(4.9);
    });
  });

  // ==========================================================================
  // Attack Scenario: Browser Crash Recovery
  // ==========================================================================
  describe('Browser Crash Recovery', () => {
    it('restores queue from storage on startup', async () => {
      // Simulate pre-crash state
      const crashState: QueuedForensics[] = [
        {
          id: 'pre-crash-1',
          payload: createPayload('crash1'),
          queuedAt: new Date(Date.now() - 3600000).toISOString(),
          attempts: 2,
          lastAttempt: new Date(Date.now() - 300000).toISOString(),
        },
        {
          id: 'pre-crash-2',
          payload: createPayload('crash2'),
          queuedAt: new Date(Date.now() - 1800000).toISOString(),
          attempts: 0,
        },
      ];
      mockStorage[STORAGE_KEY] = crashState;

      // Simulate SW restart - read queue
      const queue = await getQueue();

      expect(queue).toHaveLength(2);
      expect(queue[0].id).toBe('pre-crash-1');
      expect(queue[0].attempts).toBe(2); // Attempt count preserved
    });
  });

  // ==========================================================================
  // Forensics Queue Survival Tests
  // ==========================================================================
  describe('Forensics Queue Survival', () => {
    it('queue survives service worker restart', async () => {
      // Queue items
      for (let i = 0; i < 5; i++) {
        await queueForensics(createPayload(i));
      }

      // Simulate SW restart - just verify storage persists
      const queue = await getQueue();
      expect(queue).toHaveLength(5);
    });

    it('queue survives offline period', async () => {
      // Go offline
      Object.defineProperty(globalThis, 'navigator', {
        value: { onLine: false },
        writable: true,
        configurable: true,
      });

      // Queue items while offline
      await queueForensics(createPayload('offline'));

      // Retry should skip (offline)
      const uploadCount = await retryPendingUploads('https://forensics.example.com');
      expect(uploadCount).toBe(0);

      // Items should still be queued
      const queue = await getQueue();
      expect(queue).toHaveLength(1);
    });

    it('queue cleared only on explicit request', async () => {
      await queueForensics(createPayload('test'));

      // Simulate various operations that should NOT clear queue
      await handleHeartbeat();
      await getQueue();
      await getPendingCount();

      let queue = await getQueue();
      expect(queue).toHaveLength(1);

      // Only explicit clear removes items
      await clearQueue();
      queue = await getQueue();
      expect(queue).toHaveLength(0);
    });
  });

  // ==========================================================================
  // Stress Tests
  // ==========================================================================
  describe('Stress Tests', () => {
    /**
     * FIX VERIFIED: Burst traffic now works correctly with mutex protection.
     * Note: Test uses 10 events to stay within rate limit (Issue #603).
     */
    it('burst of 10 events handled correctly with mutex', async () => {
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(queueForensics(createPayload(i)));
      }

      await Promise.all(promises);

      const queue = await getQueue();
      // FIX VERIFIED: All items survive with mutex protection
      expect(queue.length).toBe(10);
      console.log(`[RED TEAM] Mutex fix verified: all ${queue.length}/10 items survived under burst load`);
    });

    it('handles sequential burst of 10 events', async () => {
      for (let i = 0; i < 10; i++) {
        await queueForensics(createPayload(i));
      }

      const queue = await getQueue();
      expect(queue).toHaveLength(10);
    });

    /**
     * RATE LIMITING (Issue #603): Verify events beyond rate limit are dropped.
     */
    it('rate limits events beyond 10 per minute', async () => {
      const results = [];
      // Queue 15 events - first 10 should succeed, last 5 should be rate limited
      for (let i = 0; i < 15; i++) {
        results.push(await queueForensics(createPayload(i)));
      }

      const queue = await getQueue();
      expect(queue.length).toBe(10);
      // First 10 should return true, last 5 should return false
      expect(results.slice(0, 10).every((r) => r === true)).toBe(true);
      expect(results.slice(10).every((r) => r === false)).toBe(true);
      console.log(`[RED TEAM] Rate limiting verified: 10 accepted, 5 dropped`);
    });
  });

  // ==========================================================================
  // Summary: Identified Vulnerabilities
  // ==========================================================================
  describe('SUMMARY: Security Status', () => {
    it('documents vulnerability fixes and remaining issues', () => {
      const fixed = [
        {
          id: 'RACE-001',
          title: 'Concurrent queueForensics data loss',
          status: 'FIXED',
          fix: 'Implemented promise-based mutex pattern to serialize queue operations',
        },
        {
          id: 'RACE-002',
          title: 'Multi-tab forensics collision',
          status: 'FIXED',
          fix: 'Mutex prevents concurrent read-modify-write race conditions',
        },
        {
          id: 'PLAINTEXT-001',
          title: 'Zero-knowledge violation via plaintext fallback',
          status: 'FIXED',
          fix: 'uploadForensics requires encryptFn, retryPendingUploads skips unencrypted items',
        },
        {
          id: 'ABUSE-001',
          title: 'Forensics upload abuse/DoS',
          status: 'FIXED',
          fix: 'Sliding window rate limiter (10 events/min) + queue depth warnings at 80%',
        },
      ];

      const remaining = [
        {
          id: 'QUOTA-001',
          title: 'Unhandled quota exhaustion',
          severity: 'MEDIUM',
          description: 'Storage quota errors cause forensics to be lost with no recovery mechanism',
          recommendation: 'Implement quota monitoring and alert before hitting limits',
        },
      ];

      console.log('\n[RED TEAM] Security Status:');
      console.log('\n  FIXED:');
      for (const item of fixed) {
        console.log(`    ${item.id}: ${item.title}`);
        console.log(`      Fix: ${item.fix}`);
      }
      console.log('\n  REMAINING:');
      for (const item of remaining) {
        console.log(`    ${item.id} [${item.severity}]: ${item.title}`);
      }

      expect(fixed.length).toBe(4);
      expect(remaining.length).toBe(1);
    });
  });
});
