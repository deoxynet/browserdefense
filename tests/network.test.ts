/**
 * Tests for the Network Status & Stale-Protect Module
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock chrome.storage.local
const mockStorage: Record<string, unknown> = {};

const mockChrome = {
  storage: {
    local: {
      get: vi.fn((key: string) => Promise.resolve({ [key]: mockStorage[key] })),
      set: vi.fn((items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
        return Promise.resolve();
      }),
    },
  },
};

// @ts-expect-error - Mocking chrome global
globalThis.chrome = mockChrome;

// Mock navigator.onLine using Object.defineProperty
let mockOnLine = true;
Object.defineProperty(globalThis, 'navigator', {
  value: {
    get onLine() {
      return mockOnLine;
    },
  },
  writable: true,
  configurable: true,
});

// Helper to set online status
function setOnlineStatus(online: boolean) {
  mockOnLine = online;
}

// Import after mocking
import {
  getNetworkState,
  updateNetworkStatus,
  recordUpdateSuccess,
  recordUpdateFailure,
  getFreshnessStatus,
  performHealthCheck,
  formatBlocklistAge,
  initNetworkMonitoring,
  STALE_WARNING_MS,
  STALE_CRITICAL_MS,
} from '../src/background/network';

describe('Network Status Module', () => {
  beforeEach(() => {
    // Clear storage between tests
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    setOnlineStatus(true);
  });

  describe('getNetworkState', () => {
    it('should return default state when no state is stored', async () => {
      const state = await getNetworkState();

      expect(state.networkStatus).toBe('online');
      expect(state.consecutiveFailures).toBe(0);
      expect(state.lastError).toBeNull();
    });

    it('should return stored state', async () => {
      mockStorage['browserdefense_network_state'] = {
        networkStatus: 'offline',
        consecutiveFailures: 3,
        lastError: 'Test error',
        lastStatusChange: 12345,
        lastSuccessfulUpdate: null,
        lastFailedUpdate: 12345,
      };

      const state = await getNetworkState();

      expect(state.networkStatus).toBe('offline');
      expect(state.consecutiveFailures).toBe(3);
      expect(state.lastError).toBe('Test error');
    });
  });

  describe('updateNetworkStatus', () => {
    it('should update status when navigator.onLine is true', async () => {
      setOnlineStatus(true);
      const status = await updateNetworkStatus();

      expect(status).toBe('online');
    });

    it('should update status when navigator.onLine is false', async () => {
      setOnlineStatus(false);
      const status = await updateNetworkStatus();

      expect(status).toBe('offline');
    });

    it('should persist status change', async () => {
      setOnlineStatus(false);
      await updateNetworkStatus();

      const state = await getNetworkState();
      expect(state.networkStatus).toBe('offline');
    });
  });

  describe('recordUpdateSuccess', () => {
    it('should reset failure count and error', async () => {
      // Set up initial failure state
      mockStorage['browserdefense_network_state'] = {
        networkStatus: 'online',
        consecutiveFailures: 5,
        lastError: 'Previous error',
        lastStatusChange: Date.now(),
        lastSuccessfulUpdate: null,
        lastFailedUpdate: Date.now(),
      };

      await recordUpdateSuccess();

      const state = await getNetworkState();
      expect(state.consecutiveFailures).toBe(0);
      expect(state.lastError).toBeNull();
      expect(state.lastSuccessfulUpdate).toBeGreaterThan(0);
    });
  });

  describe('recordUpdateFailure', () => {
    it('should increment failure count and record error', async () => {
      await recordUpdateFailure('Network timeout');

      const state = await getNetworkState();
      expect(state.consecutiveFailures).toBe(1);
      expect(state.lastError).toBe('Network timeout');
      expect(state.lastFailedUpdate).toBeGreaterThan(0);
    });

    it('should increment failure count on subsequent failures', async () => {
      await recordUpdateFailure('Error 1');
      await recordUpdateFailure('Error 2');
      await recordUpdateFailure('Error 3');

      const state = await getNetworkState();
      expect(state.consecutiveFailures).toBe(3);
      expect(state.lastError).toBe('Error 3');
    });
  });

  describe('getFreshnessStatus', () => {
    it('should return fresh for null age', () => {
      expect(getFreshnessStatus(null)).toBe('fresh');
    });

    it('should return fresh for age < 24 hours', () => {
      const age = 23 * 60 * 60 * 1000; // 23 hours
      expect(getFreshnessStatus(age)).toBe('fresh');
    });

    it('should return stale for age >= 24 hours', () => {
      const age = 25 * 60 * 60 * 1000; // 25 hours
      expect(getFreshnessStatus(age)).toBe('stale');
    });

    it('should return critical for age >= 7 days', () => {
      const age = 8 * 24 * 60 * 60 * 1000; // 8 days
      expect(getFreshnessStatus(age)).toBe('critical');
    });

    it('should respect custom critical threshold', () => {
      const age = 3 * 24 * 60 * 60 * 1000; // 3 days
      const customCritical = 2 * 24 * 60 * 60 * 1000; // 2 days
      expect(getFreshnessStatus(age, customCritical)).toBe('critical');
    });
  });

  describe('formatBlocklistAge', () => {
    it('should return "Never updated" for null', () => {
      expect(formatBlocklistAge(null)).toBe('Never updated');
    });

    it('should format seconds correctly', () => {
      expect(formatBlocklistAge(30 * 1000)).toBe('Just now');
    });

    it('should format minutes correctly', () => {
      expect(formatBlocklistAge(5 * 60 * 1000)).toBe('5m ago');
    });

    it('should format hours correctly', () => {
      expect(formatBlocklistAge(3 * 60 * 60 * 1000)).toBe('3h ago');
    });

    it('should format days correctly', () => {
      expect(formatBlocklistAge(1 * 24 * 60 * 60 * 1000)).toBe('1 day ago');
      expect(formatBlocklistAge(5 * 24 * 60 * 60 * 1000)).toBe('5 days ago');
    });
  });

  describe('performHealthCheck', () => {
    it('should return online status when fresh and online', async () => {
      setOnlineStatus(true);
      mockStorage['browserdefense_update_meta'] = {
        version: 1,
        timestamp: new Date().toISOString(),
        updatedAt: Date.now() - 60 * 1000, // 1 minute ago
        hashCount: 100,
      };

      const result = await performHealthCheck();

      expect(result.status).toBe('online');
      expect(result.isOnline).toBe(true);
      expect(result.isStale).toBe(false);
      expect(result.isCritical).toBe(false);
      expect(result.message).toBe('Protected');
    });

    it('should return offline status when offline', async () => {
      setOnlineStatus(false);

      const result = await performHealthCheck();

      expect(result.status).toBe('offline');
      expect(result.isOnline).toBe(false);
      expect(result.message).toBe('Offline - using cached blocklist');
    });

    it('should return stale status when blocklist is old', async () => {
      setOnlineStatus(true);
      mockStorage['browserdefense_update_meta'] = {
        version: 1,
        timestamp: new Date().toISOString(),
        updatedAt: Date.now() - 30 * 60 * 60 * 1000, // 30 hours ago
        hashCount: 100,
      };

      const result = await performHealthCheck();

      expect(result.status).toBe('stale');
      expect(result.isStale).toBe(true);
      expect(result.isCritical).toBe(false);
      expect(result.message).toBe('Blocklist outdated (>24 hours)');
    });

    it('should return critical status when blocklist is very old', async () => {
      setOnlineStatus(true);
      mockStorage['browserdefense_update_meta'] = {
        version: 1,
        timestamp: new Date().toISOString(),
        updatedAt: Date.now() - 10 * 24 * 60 * 60 * 1000, // 10 days ago
        hashCount: 100,
      };

      const result = await performHealthCheck();

      expect(result.status).toBe('critical');
      expect(result.isStale).toBe(true);
      expect(result.isCritical).toBe(true);
      expect(result.message).toBe('Blocklist critically outdated (>7 days)');
    });

    it('should include failure info', async () => {
      mockStorage['browserdefense_network_state'] = {
        networkStatus: 'online',
        consecutiveFailures: 3,
        lastError: 'Network error',
        lastStatusChange: Date.now(),
        lastSuccessfulUpdate: null,
        lastFailedUpdate: Date.now(),
      };

      const result = await performHealthCheck();

      expect(result.consecutiveFailures).toBe(3);
      expect(result.lastError).toBe('Network error');
    });
  });

  describe('initNetworkMonitoring', () => {
    it('should not throw', () => {
      expect(() => initNetworkMonitoring()).not.toThrow();
    });
  });

  describe('Constants', () => {
    it('should have correct stale warning threshold (24 hours)', () => {
      expect(STALE_WARNING_MS).toBe(24 * 60 * 60 * 1000);
    });

    it('should have correct critical threshold (7 days)', () => {
      expect(STALE_CRITICAL_MS).toBe(7 * 24 * 60 * 60 * 1000);
    });
  });
});
