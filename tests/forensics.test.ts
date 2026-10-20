import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  captureForensics,
  queueForensics,
  getQueue,
  removeFromQueue,
  clearQueue,
  trackRedirect,
  getRedirectChain,
  clearRedirectChain,
  getQueueStats,
  ForensicsPayload,
  _resetRateLimiter,
} from '../src/background/forensics';

// Mock chrome APIs
const mockStorage: Record<string, unknown> = {};

const mockChrome = {
  storage: {
    local: {
      get: vi.fn((key: string) => Promise.resolve({ [key]: mockStorage[key] })),
      set: vi.fn((items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
        return Promise.resolve();
      }),
      remove: vi.fn((key: string) => {
        delete mockStorage[key];
        return Promise.resolve();
      }),
    },
  },
  action: {
    setBadgeText: vi.fn(() => Promise.resolve()),
    setBadgeBackgroundColor: vi.fn(() => Promise.resolve()),
  },
  runtime: {
    getURL: (path: string) => `chrome-extension://test/${path}`,
  },
};

// @ts-expect-error - Mocking chrome global
globalThis.chrome = mockChrome;

describe('Forensics Module', () => {
  beforeEach(() => {
    // Clear mock storage
    Object.keys(mockStorage).forEach(key => delete mockStorage[key]);
    vi.clearAllMocks();
    // Reset rate limiter for each test (Issue #603)
    _resetRateLimiter();
  });

  describe('captureForensics', () => {
    it('should capture basic forensics data', () => {
      const details = {
        tabId: 123,
        url: 'https://evil.com/phishing',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const payload = captureForensics(details, 'evil.com/phishing', 'ioc_match');

      expect(payload.blockedUrl).toBe('https://evil.com/phishing');
      expect(payload.tabId).toBe(123);
      expect(payload.frameId).toBe(0);
      expect(payload.normalizedUrl).toBe('evil.com/phishing');
      expect(payload.reason).toBe('ioc_match');
      expect(payload.timestamp).toBeDefined();
    });

    it('should include redirect chain if available', () => {
      const tabId = 456;

      // Track some redirects
      trackRedirect(tabId, 'https://original.com');
      trackRedirect(tabId, 'https://redirect1.com');
      trackRedirect(tabId, 'https://evil.com');

      const details = {
        tabId,
        url: 'https://evil.com',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const payload = captureForensics(details, 'evil.com/', 'ioc_match');

      expect(payload.redirectChain).toEqual([
        'https://original.com',
        'https://redirect1.com',
        'https://evil.com',
      ]);
    });
  });

  describe('redirect chain tracking', () => {
    it('should track redirects per tab', () => {
      trackRedirect(1, 'https://a.com');
      trackRedirect(1, 'https://b.com');
      trackRedirect(2, 'https://c.com');

      const chain1 = getRedirectChain(1);
      const chain2 = getRedirectChain(2);

      expect(chain1).toEqual(['https://a.com', 'https://b.com']);
      expect(chain2).toBeUndefined(); // Single URL doesn't count as chain
    });

    it('should clear chain after getting it', () => {
      trackRedirect(1, 'https://a.com');
      trackRedirect(1, 'https://b.com');

      getRedirectChain(1);
      const chain = getRedirectChain(1);

      expect(chain).toBeUndefined();
    });

    it('should not duplicate URLs', () => {
      trackRedirect(1, 'https://a.com');
      trackRedirect(1, 'https://a.com');
      trackRedirect(1, 'https://b.com');

      const chain = getRedirectChain(1);

      expect(chain).toEqual(['https://a.com', 'https://b.com']);
    });

    it('should limit chain length', () => {
      for (let i = 0; i < 30; i++) {
        trackRedirect(1, `https://redirect${i}.com`);
      }

      const chain = getRedirectChain(1);

      expect(chain!.length).toBe(20);
      expect(chain![0]).toBe('https://redirect10.com');
    });

    it('should clear chain for a tab', () => {
      trackRedirect(1, 'https://a.com');
      trackRedirect(1, 'https://b.com');

      clearRedirectChain(1);
      const chain = getRedirectChain(1);

      expect(chain).toBeUndefined();
    });
  });

  describe('queueForensics', () => {
    it('should add item to queue', async () => {
      const payload: ForensicsPayload = {
        blockedUrl: 'https://evil.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      await queueForensics(payload);

      const queue = await getQueue();
      expect(queue.length).toBe(1);
      expect(queue[0].payload.blockedUrl).toBe('https://evil.com');
      expect(queue[0].attempts).toBe(0);
      expect(queue[0].id).toBeDefined();
    });

    it('should update badge when queueing', async () => {
      const payload: ForensicsPayload = {
        blockedUrl: 'https://evil.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      await queueForensics(payload);

      expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '1' });
      expect(mockChrome.action.setBadgeBackgroundColor).toHaveBeenCalledWith({ color: '#FFA500' });
    });

    it('should limit queue size', async () => {
      // Pre-populate queue with 999 items to bypass rate limiting (Issue #603)
      const prePopulated = Array.from({ length: 999 }, (_, i) => ({
        id: `pre-${i}`,
        payload: {
          blockedUrl: `https://evil${i}.com`,
          timestamp: new Date().toISOString(),
          tabId: i,
          frameId: 0,
          reason: 'ioc_match',
        },
        attempts: 0,
        queuedAt: new Date().toISOString(),
      }));
      mockStorage['browserdefense_forensics_queue'] = prePopulated;

      // Queue 2 more items - this should trigger overflow and drop item 0
      await queueForensics({
        blockedUrl: 'https://evil999.com',
        timestamp: new Date().toISOString(),
        tabId: 999,
        frameId: 0,
        reason: 'ioc_match',
      });

      await queueForensics({
        blockedUrl: 'https://evil1000.com',
        timestamp: new Date().toISOString(),
        tabId: 1000,
        frameId: 0,
        reason: 'ioc_match',
      });

      const queue = await getQueue();
      expect(queue.length).toBe(1000);
      // First item should have been dropped (evil0), now evil1 is first
      expect(queue[0].payload.blockedUrl).toBe('https://evil1.com');
    });
  });

  describe('removeFromQueue', () => {
    it('should remove item by ID', async () => {
      await queueForensics({
        blockedUrl: 'https://evil1.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      });

      await queueForensics({
        blockedUrl: 'https://evil2.com',
        timestamp: new Date().toISOString(),
        tabId: 2,
        frameId: 0,
        reason: 'ioc_match',
      });

      const queue = await getQueue();
      const idToRemove = queue[0].id;

      await removeFromQueue(idToRemove);

      const updatedQueue = await getQueue();
      expect(updatedQueue.length).toBe(1);
      expect(updatedQueue[0].payload.blockedUrl).toBe('https://evil2.com');
    });
  });

  describe('clearQueue', () => {
    it('should clear all items', async () => {
      await queueForensics({
        blockedUrl: 'https://evil1.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      });

      await queueForensics({
        blockedUrl: 'https://evil2.com',
        timestamp: new Date().toISOString(),
        tabId: 2,
        frameId: 0,
        reason: 'ioc_match',
      });

      await clearQueue();

      const queue = await getQueue();
      expect(queue.length).toBe(0);
    });

    it('should clear badge', async () => {
      await queueForensics({
        blockedUrl: 'https://evil.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      });

      vi.clearAllMocks();
      await clearQueue();

      expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
    });
  });

  describe('getQueueStats', () => {
    it('should return stats for empty queue', async () => {
      const stats = await getQueueStats();

      expect(stats.queueLength).toBe(0);
      expect(stats.oldestItem).toBeUndefined();
      expect(stats.totalAttempts).toBe(0);
    });

    it('should return stats for populated queue', async () => {
      await queueForensics({
        blockedUrl: 'https://evil1.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      });

      await queueForensics({
        blockedUrl: 'https://evil2.com',
        timestamp: new Date().toISOString(),
        tabId: 2,
        frameId: 0,
        reason: 'ioc_match',
      });

      const stats = await getQueueStats();

      expect(stats.queueLength).toBe(2);
      expect(stats.oldestItem).toBeDefined();
      expect(stats.totalAttempts).toBe(0);
    });
  });
});
