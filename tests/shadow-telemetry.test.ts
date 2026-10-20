/**
 * Tests for Shadow Telemetry
 *
 * Reference: Issue #202
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  sendShadowTelemetry,
  getShadowTelemetryConfig,
  checkAndMarkFirstSeen,
  clearSeenCache,
  getSeenCacheStats,
  _assertMinimalPayload,
  _getSeenCache,
  type ShadowTelemetryPayload,
  type ShadowTelemetryConfig,
} from '../src/background/shadow-telemetry';
import { CONFIG_STORAGE_KEY } from '../src/config/storage-keys';

// Mock chrome.storage.local
const mockStorage: Record<string, unknown> = {};

vi.stubGlobal('chrome', {
  storage: {
    local: {
      get: vi.fn(async (keys: string | string[]) => {
        if (typeof keys === 'string') {
          return { [keys]: mockStorage[keys] };
        }
        const result: Record<string, unknown> = {};
        for (const key of keys) {
          if (key in mockStorage) {
            result[key] = mockStorage[key];
          }
        }
        return result;
      }),
      set: vi.fn(async (items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
      }),
      remove: vi.fn(async (keys: string | string[]) => {
        const keysToRemove = typeof keys === 'string' ? [keys] : keys;
        for (const key of keysToRemove) {
          delete mockStorage[key];
        }
      }),
    },
  },
});

// Mock fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('Shadow Telemetry', () => {
  beforeEach(() => {
    // Clear storage
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('ShadowTelemetryPayload', () => {
    it('should have correct structure', () => {
      const payload: ShadowTelemetryPayload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: Date.now(),
        first_seen_locally: true,
      };

      expect(payload).toHaveProperty('dom_kit_hash');
      expect(payload).toHaveProperty('event_ts');
      expect(payload).toHaveProperty('first_seen_locally');
    });
  });

  describe('assertMinimalPayload', () => {
    it('should accept valid payload', () => {
      const payload: ShadowTelemetryPayload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: Date.now(),
        first_seen_locally: true,
      };

      expect(() => _assertMinimalPayload(payload)).not.toThrow();
    });

    it('should reject payload with extra fields', () => {
      const payload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: Date.now(),
        first_seen_locally: true,
        url: 'https://example.com', // Extra field
      } as ShadowTelemetryPayload;

      expect(() => _assertMinimalPayload(payload)).toThrow(/PRIVACY VIOLATION/);
    });

    it('should reject invalid hash format', () => {
      const payload: ShadowTelemetryPayload = {
        dom_kit_hash: 'invalid-hash',
        event_ts: Date.now(),
        first_seen_locally: true,
      };

      expect(() => _assertMinimalPayload(payload)).toThrow(/Invalid hash format/);
    });

    it('should reject hash without sha256: prefix', () => {
      const payload: ShadowTelemetryPayload = {
        dom_kit_hash: 'a'.repeat(64), // Missing prefix
        event_ts: Date.now(),
        first_seen_locally: true,
      };

      expect(() => _assertMinimalPayload(payload)).toThrow(/Invalid hash format/);
    });

    it('should reject invalid timestamp', () => {
      const payload: ShadowTelemetryPayload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: -1,
        first_seen_locally: true,
      };

      expect(() => _assertMinimalPayload(payload)).toThrow(/Invalid timestamp/);
    });

    it('should reject non-boolean first_seen_locally', () => {
      const payload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: Date.now(),
        first_seen_locally: 'true', // String instead of boolean
      } as unknown as ShadowTelemetryPayload;

      expect(() => _assertMinimalPayload(payload)).toThrow(/Invalid first_seen_locally/);
    });
  });

  describe('checkAndMarkFirstSeen', () => {
    it('should return true for first seen hash', async () => {
      const hash = 'a'.repeat(64);

      const result = await checkAndMarkFirstSeen(hash);

      expect(result).toBe(true);
    });

    it('should return false for previously seen hash', async () => {
      const hash = 'b'.repeat(64);

      // First call - should be first seen
      await checkAndMarkFirstSeen(hash);

      // Second call - should not be first seen
      const result = await checkAndMarkFirstSeen(hash);

      expect(result).toBe(false);
    });

    it('should track multiple hashes independently', async () => {
      const hash1 = 'c'.repeat(64);
      const hash2 = 'd'.repeat(64);

      const first1 = await checkAndMarkFirstSeen(hash1);
      const first2 = await checkAndMarkFirstSeen(hash2);
      const second1 = await checkAndMarkFirstSeen(hash1);
      const second2 = await checkAndMarkFirstSeen(hash2);

      expect(first1).toBe(true);
      expect(first2).toBe(true);
      expect(second1).toBe(false);
      expect(second2).toBe(false);
    });
  });

  describe('clearSeenCache', () => {
    it('should clear the cache', async () => {
      const hash = 'e'.repeat(64);

      // Add a hash
      await checkAndMarkFirstSeen(hash);
      expect(await checkAndMarkFirstSeen(hash)).toBe(false);

      // Clear cache
      await clearSeenCache();

      // Should be first seen again
      expect(await checkAndMarkFirstSeen(hash)).toBe(true);
    });
  });

  describe('getSeenCacheStats', () => {
    it('should return empty stats for empty cache', async () => {
      const stats = await getSeenCacheStats();

      expect(stats.size).toBe(0);
      expect(stats.oldestEntry).toBeUndefined();
      expect(stats.newestEntry).toBeUndefined();
      expect(stats.firstSeenCount).toBe(0);
    });

    it('should return correct stats', async () => {
      const hash1 = 'f'.repeat(64);
      const hash2 = '0'.repeat(64);

      await checkAndMarkFirstSeen(hash1);
      await checkAndMarkFirstSeen(hash2);

      const stats = await getSeenCacheStats();

      expect(stats.size).toBe(2);
      expect(stats.oldestEntry).toBeDefined();
      expect(stats.newestEntry).toBeDefined();
      expect(stats.firstSeenCount).toBe(2); // Both are first seen only
    });
  });

  describe('sendShadowTelemetry', () => {
    const testConfig: ShadowTelemetryConfig = {
      endpoint: 'https://telemetry.example.com/shadow',
      timeoutMs: 5000,
      enabled: true,
    };

    beforeEach(() => {
      mockFetch.mockReset();
    });

    it('should send correct payload format', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      const hash = 'a'.repeat(64);
      await sendShadowTelemetry(hash, testConfig);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0];

      expect(url).toBe(testConfig.endpoint);
      expect(options.method).toBe('POST');
      expect(options.headers).toEqual({ 'Content-Type': 'application/json' });

      const body = JSON.parse(options.body);
      expect(body).toHaveProperty('dom_kit_hash');
      expect(body).toHaveProperty('event_ts');
      expect(body).toHaveProperty('first_seen_locally');

      // Verify hash has sha256: prefix
      expect(body.dom_kit_hash).toBe(`sha256:${hash}`);
    });

    it('should NOT include URL in payload', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      const hash = '1'.repeat(64);
      await sendShadowTelemetry(hash, testConfig);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);

      // Verify no URL-related fields
      expect(body).not.toHaveProperty('url');
      expect(body).not.toHaveProperty('page_url');
      expect(body).not.toHaveProperty('domain');
      expect(body).not.toHaveProperty('normalizedUrl');
    });

    it('should NOT include DOM content in payload', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      const hash = '2'.repeat(64);
      await sendShadowTelemetry(hash, testConfig);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);

      // Verify no content-related fields
      expect(body).not.toHaveProperty('content');
      expect(body).not.toHaveProperty('skeleton');
      expect(body).not.toHaveProperty('tagTree');
      expect(body).not.toHaveProperty('formSchema');
    });

    it('should NOT include screenshot in payload', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      const hash = '3'.repeat(64);
      await sendShadowTelemetry(hash, testConfig);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);

      // Verify no screenshot-related fields
      expect(body).not.toHaveProperty('screenshot');
      expect(body).not.toHaveProperty('image');
      expect(body).not.toHaveProperty('imageData');
    });

    it('should return true on success', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      const hash = '4'.repeat(64);
      const result = await sendShadowTelemetry(hash, testConfig);

      expect(result).toBe(true);
    });

    it('should return false on HTTP error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const hash = '5'.repeat(64);
      const result = await sendShadowTelemetry(hash, testConfig);

      expect(result).toBe(false);
    });

    it('should return false on network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const hash = '6'.repeat(64);
      const result = await sendShadowTelemetry(hash, testConfig);

      expect(result).toBe(false);
    });

    it('should set first_seen_locally to true for new hash', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      // Clear cache to ensure this is a new hash
      await clearSeenCache();

      const hash = '7'.repeat(64);
      await sendShadowTelemetry(hash, testConfig);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.first_seen_locally).toBe(true);
    });

    it('should set first_seen_locally to false for seen hash', async () => {
      // First call to mark hash as seen
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      const hash = '8'.repeat(64);
      await sendShadowTelemetry(hash, testConfig);

      // Second call
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      await sendShadowTelemetry(hash, testConfig);

      const body = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(body.first_seen_locally).toBe(false);
    });
  });

  describe('getShadowTelemetryConfig', () => {
    it('should return null if not configured', async () => {
      const result = await getShadowTelemetryConfig();
      expect(result).toBeNull();
    });

    it('should return null if endpoint exists but not enabled', async () => {
      mockStorage[CONFIG_STORAGE_KEY] = {
        shadow_telemetry_endpoint: 'https://telemetry.example.com/shadow',
        shadow_telemetry_enabled: false,
      };

      const result = await getShadowTelemetryConfig();
      expect(result).toBeNull();
    });

    it('should return null if enabled but no endpoint', async () => {
      mockStorage[CONFIG_STORAGE_KEY] = {
        shadow_telemetry_enabled: true,
      };

      const result = await getShadowTelemetryConfig();
      expect(result).toBeNull();
    });

    it('should return config if enabled and endpoint configured', async () => {
      mockStorage[CONFIG_STORAGE_KEY] = {
        shadow_telemetry_endpoint: 'https://telemetry.example.com/shadow',
        shadow_telemetry_enabled: true,
      };

      const result = await getShadowTelemetryConfig();
      expect(result).not.toBeNull();
      expect(result?.endpoint).toBe('https://telemetry.example.com/shadow');
      expect(result?.enabled).toBe(true);
    });

    it('should use custom timeout if provided', async () => {
      mockStorage[CONFIG_STORAGE_KEY] = {
        shadow_telemetry_endpoint: 'https://telemetry.example.com/shadow',
        shadow_telemetry_enabled: true,
        shadow_telemetry_timeout_ms: 10000,
      };

      const result = await getShadowTelemetryConfig();
      expect(result?.timeoutMs).toBe(10000);
    });
  });

  describe('Privacy guarantees', () => {
    it('should ONLY send dom_kit_hash, event_ts, and first_seen_locally', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      const testConfig: ShadowTelemetryConfig = {
        endpoint: 'https://telemetry.example.com/shadow',
        enabled: true,
      };

      const hash = '9'.repeat(64);
      await sendShadowTelemetry(hash, testConfig);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      const keys = Object.keys(body);

      // Must have EXACTLY these three keys
      expect(keys).toHaveLength(3);
      expect(keys).toContain('dom_kit_hash');
      expect(keys).toContain('event_ts');
      expect(keys).toContain('first_seen_locally');
    });
  });
});
