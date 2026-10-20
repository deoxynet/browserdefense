/**
 * Unit tests for BrowserDefense forensics queue module.
 * Tests the consolidated forensics.ts implementation.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock chrome APIs
const mockStorage: Record<string, unknown> = {};

const mockChrome = {
  storage: {
    local: {
      get: vi.fn(async (key: string) => {
        if (typeof key === 'string') {
          return { [key]: mockStorage[key] };
        }
        return mockStorage;
      }),
      set: vi.fn(async (items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
      }),
      remove: vi.fn(async (key: string) => {
        delete mockStorage[key];
      }),
    },
  },
  action: {
    setBadgeText: vi.fn(),
    setBadgeBackgroundColor: vi.fn(),
  },
};

// @ts-expect-error - mocking global chrome
globalThis.chrome = mockChrome;

// Import after mocking
import {
  getQueue,
  queueForensics,
  getPendingCount,
  clearQueue,
  updateBadge,
  type QueuedForensics,
  type ForensicsPayload,
} from '../src/background/forensics';

const STORAGE_KEY = 'browserdefense_forensics_queue';

describe('forensics-queue', () => {
  beforeEach(() => {
    // Clear storage and mocks before each test
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    vi.clearAllMocks();
  });

  describe('getQueue', () => {
    it('returns empty array when no queue exists', async () => {
      const queue = await getQueue();
      expect(queue).toEqual([]);
    });

    it('returns existing queue items', async () => {
      const items: QueuedForensics[] = [
        {
          id: 'test-1',
          payload: {
            blockedUrl: 'https://evil.com',
            timestamp: '2024-01-01T00:00:00.000Z',
            tabId: 1,
            frameId: 0,
            reason: 'ioc_match',
          },
          queuedAt: '2024-01-01T00:00:00.000Z',
          attempts: 0,
        },
      ];
      mockStorage[STORAGE_KEY] = items;

      const queue = await getQueue();
      expect(queue).toEqual(items);
    });
  });

  describe('queueForensics', () => {
    it('adds item to empty queue', async () => {
      const payload: ForensicsPayload = {
        blockedUrl: 'https://evil.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      await queueForensics(payload);

      const queue = await getQueue();
      expect(queue).toHaveLength(1);
      expect(queue[0].payload).toEqual(payload);
      expect(queue[0].attempts).toBe(0);
    });

    it('appends to existing queue', async () => {
      // Pre-populate queue
      mockStorage[STORAGE_KEY] = [
        {
          id: 'existing',
          payload: {
            blockedUrl: 'https://old.com',
            timestamp: '2024-01-01T00:00:00.000Z',
            tabId: 1,
            frameId: 0,
            reason: 'ioc_match',
          },
          queuedAt: '2024-01-01T00:00:00.000Z',
          attempts: 0,
        },
      ];

      await queueForensics({
        blockedUrl: 'https://new.com',
        timestamp: new Date().toISOString(),
        tabId: 2,
        frameId: 0,
        reason: 'ioc_match',
      });

      const queue = await getQueue();
      expect(queue).toHaveLength(2);
      expect(queue[1].payload.blockedUrl).toBe('https://new.com');
    });

    it('updates badge with queue count', async () => {
      await queueForensics({
        blockedUrl: 'https://test.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      });

      expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '1' });
      expect(mockChrome.action.setBadgeBackgroundColor).toHaveBeenCalledWith({ color: '#FFA500' });
    });

    it('drops oldest when queue is full', async () => {
      // Fill queue to max (1000 items)
      const fullQueue: QueuedForensics[] = [];
      for (let i = 0; i < 1000; i++) {
        fullQueue.push({
          id: `item-${i}`,
          payload: {
            blockedUrl: `https://blocked${i}.com`,
            timestamp: '2024-01-01T00:00:00.000Z',
            tabId: 1,
            frameId: 0,
            reason: 'ioc_match',
          },
          queuedAt: '2024-01-01T00:00:00.000Z',
          attempts: 0,
        });
      }
      mockStorage[STORAGE_KEY] = fullQueue;

      // Add one more
      await queueForensics({
        blockedUrl: 'https://new.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      });

      const queue = await getQueue();
      expect(queue).toHaveLength(1000);
      // Oldest (item-0) should be dropped
      expect(queue[0].id).toBe('item-1');
      // New item should be at the end
      expect(queue[999].payload.blockedUrl).toBe('https://new.com');
    });
  });

  describe('getPendingCount', () => {
    it('returns 0 for empty queue', async () => {
      const count = await getPendingCount();
      expect(count).toBe(0);
    });

    it('returns correct count', async () => {
      mockStorage[STORAGE_KEY] = [
        { id: '1', payload: {}, queuedAt: '', attempts: 0 },
        { id: '2', payload: {}, queuedAt: '', attempts: 0 },
        { id: '3', payload: {}, queuedAt: '', attempts: 0 },
      ];

      const count = await getPendingCount();
      expect(count).toBe(3);
    });
  });

  describe('clearQueue', () => {
    it('clears all items', async () => {
      mockStorage[STORAGE_KEY] = [{ id: '1' }, { id: '2' }];

      await clearQueue();

      const queue = await getQueue();
      expect(queue).toEqual([]);
    });

    it('clears badge', async () => {
      await clearQueue();

      expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
    });
  });

  describe('updateBadge', () => {
    it('shows count when pending > 0', async () => {
      await updateBadge(5);

      expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '5' });
      expect(mockChrome.action.setBadgeBackgroundColor).toHaveBeenCalledWith({ color: '#FFA500' });
    });

    it('clears badge when pending = 0', async () => {
      await updateBadge(0);

      expect(mockChrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
    });
  });
});
