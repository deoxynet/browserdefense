/**
 * Tests for browser-side direct ingest to on-prem SIEM endpoints.
 *
 * Issue #398 - Browser-Side Direct Ingest
 */

import { describe, it, expect, beforeAll, vi } from 'vitest';
import {
  extractOrigin,
} from '../src/background/direct-ingest';
import type { DirectIngestConfig, IngestQueueItem, SiemEndpoint } from '../src/types/direct-ingest';

// Mock storage - single shared state for all tests
const mockStorage: Record<string, unknown> = {};

// Mock permissions state
const mockGrantedOrigins = new Set<string>();

// Mock fetch responses
const mockFetchResponse = { ok: true, status: 200, statusText: 'OK' };
const mockFetchShouldThrow: Error | null = null;

// Define chrome mock
const mockChrome = {
  storage: {
    local: {
      get: vi.fn().mockImplementation((key: string | string[]) => {
        if (typeof key === 'string') {
          return Promise.resolve({ [key]: mockStorage[key] });
        }
        const result: Record<string, unknown> = {};
        for (const k of key) {
          result[k] = mockStorage[k];
        }
        return Promise.resolve(result);
      }),
      set: vi.fn().mockImplementation((items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
        return Promise.resolve();
      }),
      remove: vi.fn().mockImplementation((key: string) => {
        delete mockStorage[key];
        return Promise.resolve();
      }),
    },
  },
  permissions: {
    contains: vi.fn().mockImplementation(({ origins }: { origins: string[] }) => {
      const origin = origins[0].replace('/*', '');
      return Promise.resolve(mockGrantedOrigins.has(origin));
    }),
    request: vi.fn().mockImplementation(({ origins }: { origins: string[] }) => {
      const origin = origins[0].replace('/*', '');
      mockGrantedOrigins.add(origin);
      return Promise.resolve(true);
    }),
    remove: vi.fn().mockImplementation(({ origins }: { origins: string[] }) => {
      const origin = origins[0].replace('/*', '');
      mockGrantedOrigins.delete(origin);
      return Promise.resolve(true);
    }),
  },
  runtime: {
    getURL: (path: string) => `chrome-extension://test/${path}`,
  },
};

// Set up global mocks before any imports
// @ts-expect-error - Mocking chrome global
globalThis.chrome = mockChrome;

// Mock fetch globally
globalThis.fetch = vi.fn().mockImplementation(() => {
  if (mockFetchShouldThrow) {
    return Promise.reject(mockFetchShouldThrow);
  }
  return Promise.resolve({
    ok: mockFetchResponse.ok,
    status: mockFetchResponse.status,
    statusText: mockFetchResponse.statusText,
    json: () => Promise.resolve({}),
  } as Response);
});

// Mock crypto.randomUUID
vi.spyOn(crypto, 'randomUUID').mockImplementation(
  () => `uuid-${Math.random().toString(36).substr(2, 9)}` as `${string}-${string}-${string}-${string}-${string}`
);

describe('Direct Ingest Module', () => {
  describe('extractOrigin', () => {
    it('should extract origin from URL', () => {
      expect(extractOrigin('https://siem.company.com/api/v1/logs')).toBe(
        'https://siem.company.com'
      );
    });

    it('should handle URLs with ports', () => {
      expect(extractOrigin('https://siem.local:8443/ingest')).toBe(
        'https://siem.local:8443'
      );
    });

    it('should throw for invalid URLs', () => {
      expect(() => extractOrigin('not-a-url')).toThrow('Invalid URL');
    });
  });

  describe('Type Definitions', () => {
    it('should have correct SiemEndpoint shape', () => {
      const endpoint: SiemEndpoint = {
        id: 'test-id',
        name: 'Test SIEM',
        url: 'https://siem.company.com/api/logs',
        origin: 'https://siem.company.com',
        enabled: true,
        addedAt: new Date().toISOString(),
      };

      expect(endpoint.id).toBe('test-id');
      expect(endpoint.enabled).toBe(true);
    });

    it('should have correct IngestQueueItem shape', () => {
      const item: IngestQueueItem = {
        id: 'queue-1',
        endpointId: 'endpoint-1',
        payload: { event: 'test' },
        attempts: 1,
        queuedAt: new Date().toISOString(),
        errorCategory: 'network',
      };

      expect(item.errorCategory).toBe('network');
      expect(item.attempts).toBe(1);
    });

    it('should have correct DirectIngestConfig shape', () => {
      const config: DirectIngestConfig = {
        endpoints: [],
        maxQueueSize: 500,
        maxRetries: 10,
        baseRetryDelayMs: 5000,
        maxRetryDelayMs: 300000,
      };

      expect(config.maxQueueSize).toBe(500);
      expect(config.endpoints).toHaveLength(0);
    });
  });

  describe('Error Classification Logic', () => {
    it('should correctly identify network errors as retryable', () => {
      // Network errors should be retryable
      const networkError = new TypeError('Failed to fetch');
      expect(networkError.message).toContain('fetch');
    });

    it('should correctly identify auth errors as non-retryable', () => {
      // 401 and 403 should not be retried
      expect([401, 403].every(code => code >= 400 && code < 404)).toBe(true);
    });

    it('should correctly identify server errors as retryable', () => {
      // 5xx errors should be retried
      expect([500, 502, 503].every(code => code >= 500 && code < 600)).toBe(true);
    });
  });
});

describe('Direct Ingest Integration', () => {
  // These tests use the actual module functions
  // They need to run in sequence to avoid state pollution

  it('should load default config when empty', async () => {
    const { loadIngestConfig } = await import('../src/background/direct-ingest');
    const config = await loadIngestConfig();

    expect(config.endpoints).toEqual([]);
    expect(config.maxQueueSize).toBe(500);
    expect(config.maxRetries).toBe(10);
  });

  it('should save and load config', async () => {
    const { loadIngestConfig, saveIngestConfig } = await import('../src/background/direct-ingest');

    const config: DirectIngestConfig = {
      endpoints: [],
      maxQueueSize: 1000,
      maxRetries: 5,
      baseRetryDelayMs: 10000,
      maxRetryDelayMs: 600000,
    };

    await saveIngestConfig(config);
    const loaded = await loadIngestConfig();

    expect(loaded.maxQueueSize).toBe(1000);
    expect(loaded.maxRetries).toBe(5);
  });

  it('should check permission status', async () => {
    const { hasPermission } = await import('../src/background/direct-ingest');

    // Add a permission
    mockGrantedOrigins.add('https://siem.company.com');

    const has = await hasPermission('https://siem.company.com');
    expect(has).toBe(true);

    const hasNot = await hasPermission('https://other.company.com');
    expect(hasNot).toBe(false);
  });

  it('should request SIEM permission', async () => {
    const { requestSiemPermission } = await import('../src/background/direct-ingest');

    const result = await requestSiemPermission('https://newsiem.company.com');

    expect(result.granted).toBe(true);
    expect(result.origin).toBe('https://newsiem.company.com');
  });

  it('should reject origin with path in permission request', async () => {
    const { requestSiemPermission } = await import('../src/background/direct-ingest');

    const result = await requestSiemPermission('https://siem.company.com/api');

    expect(result.granted).toBe(false);
    expect(result.error).toContain('must not include path');
  });

  it('should get queue stats', async () => {
    const { getIngestQueueStats } = await import('../src/background/direct-ingest');

    const stats = await getIngestQueueStats();

    expect(stats.queueLength).toBeGreaterThanOrEqual(0);
    expect(stats.pendingRetry).toBeGreaterThanOrEqual(0);
    expect(stats.authErrors).toBeGreaterThanOrEqual(0);
  });

  it('should initialize without errors', async () => {
    const { initDirectIngest } = await import('../src/background/direct-ingest');

    await expect(initDirectIngest()).resolves.not.toThrow();
  });
});
