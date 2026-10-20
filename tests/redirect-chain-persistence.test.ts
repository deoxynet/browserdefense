/**
 * Tests for Redirect Chain Persistence
 *
 * Tests for persisting redirect chains across MV3 service worker suspension.
 * Uses chrome.storage.session to survive SW lifecycle events.
 *
 * Reference: Issue #234 - Redirect chain lost on SW suspend
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

// ============ Mock Chrome APIs ============

const mockSessionStorage: Record<string, unknown> = {};
const mockLocalStorage: Record<string, unknown> = {};

const mockChrome = {
  storage: {
    session: {
      get: vi.fn((key: string | string[]) => {
        if (typeof key === 'string') {
          return Promise.resolve({ [key]: mockSessionStorage[key] });
        }
        const result: Record<string, unknown> = {};
        for (const k of key) {
          result[k] = mockSessionStorage[k];
        }
        return Promise.resolve(result);
      }),
      set: vi.fn((items: Record<string, unknown>) => {
        Object.assign(mockSessionStorage, items);
        return Promise.resolve();
      }),
      remove: vi.fn((key: string | string[]) => {
        if (typeof key === 'string') {
          delete mockSessionStorage[key];
        } else {
          for (const k of key) {
            delete mockSessionStorage[k];
          }
        }
        return Promise.resolve();
      }),
    },
    local: {
      get: vi.fn((key: string | string[]) => {
        if (typeof key === 'string') {
          return Promise.resolve({ [key]: mockLocalStorage[key] });
        }
        const result: Record<string, unknown> = {};
        for (const k of key) {
          result[k] = mockLocalStorage[k];
        }
        return Promise.resolve(result);
      }),
      set: vi.fn((items: Record<string, unknown>) => {
        Object.assign(mockLocalStorage, items);
        return Promise.resolve();
      }),
      remove: vi.fn((key: string | string[]) => {
        if (typeof key === 'string') {
          delete mockLocalStorage[key];
        } else {
          for (const k of key) {
            delete mockLocalStorage[k];
          }
        }
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

describe('Redirect Chain Persistence', () => {
  let forensicsModule: typeof import('../src/background/forensics');

  beforeEach(async () => {
    // Clear mock storage
    Object.keys(mockSessionStorage).forEach((key) => delete mockSessionStorage[key]);
    Object.keys(mockLocalStorage).forEach((key) => delete mockLocalStorage[key]);
    vi.clearAllMocks();

    // Fresh import to reset module state
    vi.resetModules();
    forensicsModule = await import('../src/background/forensics');

    // Reset internal state
    forensicsModule._resetRedirectChainState();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('trackRedirect', () => {
    it('should persist redirect chain to session storage', async () => {
      const tabId = 123;

      forensicsModule.trackRedirect(tabId, 'https://first.com');
      forensicsModule.trackRedirect(tabId, 'https://second.com');

      // Wait for debounced persist (100ms + buffer)
      await new Promise((resolve) => setTimeout(resolve, 150));

      expect(mockChrome.storage.session.set).toHaveBeenCalled();

      const stored = mockSessionStorage['browserdefense_redirect_chains'] as {
        chains: Record<string, string[]>;
        timestamps: Record<string, number>;
      };

      expect(stored).toBeDefined();
      expect(stored.chains['123']).toEqual(['https://first.com', 'https://second.com']);
      expect(stored.timestamps['123']).toBeDefined();
    });

    it('should debounce multiple rapid updates', async () => {
      const tabId = 456;

      // Rapid-fire updates
      forensicsModule.trackRedirect(tabId, 'https://url1.com');
      forensicsModule.trackRedirect(tabId, 'https://url2.com');
      forensicsModule.trackRedirect(tabId, 'https://url3.com');
      forensicsModule.trackRedirect(tabId, 'https://url4.com');
      forensicsModule.trackRedirect(tabId, 'https://url5.com');

      // Wait for debounce
      await new Promise((resolve) => setTimeout(resolve, 150));

      // Should only have called set once due to debouncing
      expect(mockChrome.storage.session.set).toHaveBeenCalledTimes(1);

      const stored = mockSessionStorage['browserdefense_redirect_chains'] as {
        chains: Record<string, string[]>;
      };
      expect(stored.chains['456']).toHaveLength(5);
    });

    it('should avoid duplicate URLs in chain', () => {
      const tabId = 789;

      forensicsModule.trackRedirect(tabId, 'https://same.com');
      forensicsModule.trackRedirect(tabId, 'https://same.com');
      forensicsModule.trackRedirect(tabId, 'https://same.com');

      const chain = forensicsModule._redirectChains.get(tabId);
      expect(chain).toHaveLength(1);
    });

    it('should limit chain length to 20', () => {
      const tabId = 100;

      // Add 25 unique URLs
      for (let i = 0; i < 25; i++) {
        forensicsModule.trackRedirect(tabId, `https://url${i}.com`);
      }

      const chain = forensicsModule._redirectChains.get(tabId);
      expect(chain).toHaveLength(20);
      // Should have dropped the first 5
      expect(chain?.[0]).toBe('https://url5.com');
    });
  });

  describe('restoreRedirectChains', () => {
    it('should restore chains from session storage', async () => {
      // Pre-populate session storage
      mockSessionStorage['browserdefense_redirect_chains'] = {
        chains: {
          '123': ['https://a.com', 'https://b.com'],
          '456': ['https://c.com', 'https://d.com', 'https://e.com'],
        },
        timestamps: {
          '123': Date.now(),
          '456': Date.now(),
        },
      };

      await forensicsModule.restoreRedirectChains();

      expect(forensicsModule._redirectChains.size).toBe(2);
      expect(forensicsModule._redirectChains.get(123)).toEqual(['https://a.com', 'https://b.com']);
      expect(forensicsModule._redirectChains.get(456)).toHaveLength(3);
    });

    it('should skip expired chains (older than 24 hours)', async () => {
      const now = Date.now();
      const expiredTimestamp = now - 25 * 60 * 60 * 1000; // 25 hours ago

      mockSessionStorage['browserdefense_redirect_chains'] = {
        chains: {
          '100': ['https://fresh.com'],
          '200': ['https://expired.com'],
        },
        timestamps: {
          '100': now,
          '200': expiredTimestamp,
        },
      };

      await forensicsModule.restoreRedirectChains();

      expect(forensicsModule._redirectChains.size).toBe(1);
      expect(forensicsModule._redirectChains.has(100)).toBe(true);
      expect(forensicsModule._redirectChains.has(200)).toBe(false);
    });

    it('should only restore once', async () => {
      mockSessionStorage['browserdefense_redirect_chains'] = {
        chains: { '123': ['https://test.com'] },
        timestamps: { '123': Date.now() },
      };

      await forensicsModule.restoreRedirectChains();
      forensicsModule._redirectChains.clear();
      await forensicsModule.restoreRedirectChains();

      // Should not restore again
      expect(forensicsModule._redirectChains.size).toBe(0);
    });

    it('should handle missing storage gracefully', async () => {
      // No data in storage
      await forensicsModule.restoreRedirectChains();

      expect(forensicsModule._redirectChains.size).toBe(0);
    });
  });

  describe('getRedirectChain', () => {
    it('should return and remove chain from storage', async () => {
      forensicsModule.trackRedirect(100, 'https://a.com');
      forensicsModule.trackRedirect(100, 'https://b.com');

      const chain = forensicsModule.getRedirectChain(100);

      expect(chain).toEqual(['https://a.com', 'https://b.com']);
      expect(forensicsModule._redirectChains.has(100)).toBe(false);

      // Wait for persist
      await new Promise((resolve) => setTimeout(resolve, 150));

      const stored = mockSessionStorage['browserdefense_redirect_chains'] as {
        chains: Record<string, string[]>;
      };
      expect(stored.chains['100']).toBeUndefined();
    });

    it('should return undefined for single-URL chains', () => {
      forensicsModule.trackRedirect(200, 'https://single.com');

      const chain = forensicsModule.getRedirectChain(200);

      expect(chain).toBeUndefined();
    });

    it('should return undefined for unknown tab', () => {
      const chain = forensicsModule.getRedirectChain(999);
      expect(chain).toBeUndefined();
    });
  });

  describe('clearRedirectChain', () => {
    it('should remove chain from memory and storage', async () => {
      forensicsModule.trackRedirect(300, 'https://a.com');
      forensicsModule.trackRedirect(300, 'https://b.com');

      forensicsModule.clearRedirectChain(300);

      expect(forensicsModule._redirectChains.has(300)).toBe(false);

      // Wait for persist
      await new Promise((resolve) => setTimeout(resolve, 150));

      const stored = mockSessionStorage['browserdefense_redirect_chains'] as {
        chains: Record<string, string[]>;
      };
      expect(stored.chains['300']).toBeUndefined();
    });
  });

  describe('clearAllRedirectChains', () => {
    it('should clear all chains from memory and storage', async () => {
      forensicsModule.trackRedirect(1, 'https://a.com');
      forensicsModule.trackRedirect(2, 'https://b.com');
      forensicsModule.trackRedirect(3, 'https://c.com');

      await forensicsModule.clearAllRedirectChains();

      expect(forensicsModule._redirectChains.size).toBe(0);
      expect(mockChrome.storage.session.remove).toHaveBeenCalledWith('browserdefense_redirect_chains');
    });
  });

  describe('getRedirectChainStats', () => {
    it('should return accurate statistics', () => {
      forensicsModule.trackRedirect(1, 'https://a.com');
      forensicsModule.trackRedirect(1, 'https://b.com');
      forensicsModule.trackRedirect(2, 'https://c.com');
      forensicsModule.trackRedirect(2, 'https://d.com');
      forensicsModule.trackRedirect(2, 'https://e.com');

      const stats = forensicsModule.getRedirectChainStats();

      expect(stats.activeChains).toBe(2);
      expect(stats.totalUrls).toBe(5);
      expect(stats.oldestChainAge).toBeDefined();
      expect(stats.oldestChainAge).toBeLessThan(1000); // Should be very recent
    });

    it('should return empty stats when no chains', () => {
      const stats = forensicsModule.getRedirectChainStats();

      expect(stats.activeChains).toBe(0);
      expect(stats.totalUrls).toBe(0);
      expect(stats.oldestChainAge).toBeUndefined();
    });
  });

  describe('Fallback to local storage', () => {
    it('should use local storage when session storage unavailable', async () => {
      // Temporarily remove session storage
      const originalSession = mockChrome.storage.session;
      // @ts-expect-error - Testing fallback
      mockChrome.storage.session = undefined;

      // Need fresh module import
      vi.resetModules();
      const fallbackModule = await import('../src/background/forensics');
      fallbackModule._resetRedirectChainState();

      fallbackModule.trackRedirect(500, 'https://fallback.com');

      // Wait for persist
      await new Promise((resolve) => setTimeout(resolve, 150));

      expect(mockChrome.storage.local.set).toHaveBeenCalled();

      // Restore
      mockChrome.storage.session = originalSession;
    });
  });

  describe('Integration with forensics capture', () => {
    it('should include persisted redirect chain in forensics payload', async () => {
      const tabId = 999;

      // Simulate redirect chain
      forensicsModule.trackRedirect(tabId, 'https://start.com');
      forensicsModule.trackRedirect(tabId, 'https://redirect.com');
      forensicsModule.trackRedirect(tabId, 'https://blocked.com');

      // Capture forensics
      const details = {
        tabId,
        url: 'https://blocked.com',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const payload = forensicsModule.captureForensics(details, 'blocked.com', 'ioc_match');

      expect(payload.redirectChain).toEqual([
        'https://start.com',
        'https://redirect.com',
        'https://blocked.com',
      ]);
    });
  });
});

describe('SW Suspension Simulation', () => {
  it('should survive simulated SW restart', async () => {
    // Clear storage
    Object.keys(mockSessionStorage).forEach((key) => delete mockSessionStorage[key]);

    // First "session" - track some redirects
    vi.resetModules();
    const module1 = await import('../src/background/forensics');
    module1._resetRedirectChainState();

    module1.trackRedirect(100, 'https://before-suspend-1.com');
    module1.trackRedirect(100, 'https://before-suspend-2.com');

    // Wait for persist
    await new Promise((resolve) => setTimeout(resolve, 150));

    // Verify data is in storage
    expect(mockSessionStorage['browserdefense_redirect_chains']).toBeDefined();

    // Simulate SW restart - fresh module import
    vi.resetModules();
    const module2 = await import('../src/background/forensics');
    module2._resetRedirectChainState();

    // Restore from storage (simulating initForensicsQueue)
    await module2.restoreRedirectChains();

    // Should have the chain
    expect(module2._redirectChains.get(100)).toEqual([
      'https://before-suspend-1.com',
      'https://before-suspend-2.com',
    ]);

    // Continue tracking
    module2.trackRedirect(100, 'https://after-suspend.com');

    const chain = module2._redirectChains.get(100);
    expect(chain).toEqual([
      'https://before-suspend-1.com',
      'https://before-suspend-2.com',
      'https://after-suspend.com',
    ]);
  });
});
