/**
 * Tests for Auth Module (Issue #399)
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock chrome.storage.local
const mockStorage: Record<string, unknown> = {};
const mockListeners: ((changes: Record<string, { newValue?: unknown }>, areaName: string) => void)[] = [];

vi.mock('chrome', () => ({
  default: {
    storage: {
      local: {
        get: vi.fn(async (keys: string | string[]) => {
          const result: Record<string, unknown> = {};
          const keyList = typeof keys === 'string' ? [keys] : keys;
          for (const key of keyList) {
            if (key in mockStorage) {
              result[key] = mockStorage[key];
            }
          }
          return result;
        }),
        set: vi.fn(async (items: Record<string, unknown>) => {
          Object.assign(mockStorage, items);
        }),
      },
      onChanged: {
        addListener: vi.fn((listener) => {
          mockListeners.push(listener);
        }),
      },
    },
  },
}));

// Need to assign to global for the module
(globalThis as Record<string, unknown>).chrome = {
  storage: {
    local: {
      get: async (keys: string | string[]) => {
        const result: Record<string, unknown> = {};
        const keyList = typeof keys === 'string' ? [keys] : keys;
        for (const key of keyList) {
          if (key in mockStorage) {
            result[key] = mockStorage[key];
          }
        }
        return result;
      },
      set: async (items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
      },
    },
    onChanged: {
      addListener: (listener: (changes: Record<string, { newValue?: unknown }>, areaName: string) => void) => {
        mockListeners.push(listener);
      },
    },
  },
};

import { getAuthState, onAuthStateChange, initAuthMonitoring, isHunterMode, getAuthToken } from '../../src/background/auth';

describe('Auth Module', () => {
  beforeEach(() => {
    // Clear storage
    Object.keys(mockStorage).forEach((k) => delete mockStorage[k]);
  });

  describe('getAuthState', () => {
    it('returns sensor mode when no token', async () => {
      const state = await getAuthState();
      expect(state.mode).toBe('sensor');
      expect(state.token).toBeNull();
      expect(state.isValid).toBe(false);
    });

    it('returns sensor mode for empty token', async () => {
      mockStorage.auth_token = '';
      const state = await getAuthState();
      expect(state.mode).toBe('sensor');
      expect(state.isValid).toBe(false);
    });

    it('returns sensor mode for short token', async () => {
      mockStorage.auth_token = 'short';
      const state = await getAuthState();
      expect(state.mode).toBe('sensor');
      expect(state.isValid).toBe(false);
    });

    it('returns hunter mode for valid JWT-like token', async () => {
      // JWT format: header.payload.signature
      mockStorage.auth_token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';
      const state = await getAuthState();
      expect(state.mode).toBe('hunter');
      expect(state.isValid).toBe(true);
    });

    it('returns hunter mode for valid API key token', async () => {
      // 32+ char alphanumeric with dashes/underscores
      mockStorage.auth_token = 'test_key_abcdefghijklmnopqrstuvwxyz123456';
      const state = await getAuthState();
      expect(state.mode).toBe('hunter');
      expect(state.isValid).toBe(true);
    });
  });

  describe('isHunterMode', () => {
    it('reflects current auth state', async () => {
      // Clear any existing token
      delete mockStorage.auth_token;
      await getAuthState();
      expect(isHunterMode()).toBe(false);

      // Set valid token
      mockStorage.auth_token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';
      await getAuthState();
      expect(isHunterMode()).toBe(true);
    });
  });

  describe('getAuthToken', () => {
    it('returns current token from state', async () => {
      // Clear any existing token
      delete mockStorage.auth_token;
      await getAuthState();
      expect(getAuthToken()).toBeNull();

      // Set token
      const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';
      mockStorage.auth_token = token;
      await getAuthState();
      expect(getAuthToken()).toBe(token);
    });
  });

  describe('onAuthStateChange', () => {
    it('returns unsubscribe function', () => {
      const unsubscribe = onAuthStateChange(() => {});
      expect(typeof unsubscribe).toBe('function');
      unsubscribe();
    });
  });
});
