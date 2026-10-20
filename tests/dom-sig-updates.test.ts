/**
 * DOM Signature Update Client Tests
 *
 * Tests for the DOM signature update functionality including:
 * - Manifest fetching and signature verification
 * - Version checking and delta updates
 * - Retry logic with exponential backoff
 * - Alarm scheduling
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock fetch
const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

// Mock chrome APIs
const mockStorage = {
  local: {
    get: vi.fn(),
    set: vi.fn(),
    remove: vi.fn(),
  },
};

const mockAlarms = {
  create: vi.fn(),
  clear: vi.fn(),
};

globalThis.chrome = {
  storage: mockStorage,
  alarms: mockAlarms,
} as unknown as typeof chrome;

// Mock crypto verification
vi.mock('../src/crypto/signing', () => ({
  verifyDOMSignatureManifest: vi.fn(),
}));

vi.mock('../src/crypto/hashing', () => ({
  sha256: vi.fn(),
}));

// Import after mocking
import {
  fetchDOMSignatureUpdate,
  scheduleDOMSignatureUpdates,
  handleDOMSignatureUpdateAlarm,
  cancelDOMSignatureUpdates,
  getDOMSignatureUpdateMeta,
  _resolveUrl,
  _findApplicableDelta,
  DOM_SIG_UPDATE_CONFIG_KEY,
  DOM_SIG_UPDATE_ALARM,
} from '../src/background/dom-sig-updates';

import { verifyDOMSignatureManifest } from '../src/crypto/signing';
import { sha256 } from '../src/crypto/hashing';

import type {
  DOMSignatureManifest,
  DOMSignatureEntry,
  DOMSignatureUpdateConfig,
  DOMSignatureDeltaInfo,
} from '../src/types/dom-sig-manifest';

// Helper to generate valid 64-char hex hash
function generateHash(seed: number = 0): string {
  const hex = '0123456789abcdef';
  let hash = '';
  for (let i = 0; i < 64; i++) {
    hash += hex[(seed + i) % 16];
  }
  return hash;
}

// Test fixtures
function createTestManifest(version: number = 1): DOMSignatureManifest {
  return {
    version,
    total_signatures: 2,
    exact_count: 2,
    lsh_count: 0,
    sha256_root: generateHash(100),
    signature: 'test-signature',
    created_at: new Date().toISOString(),
    data_url: 'dom-signatures.json',
  };
}

function createTestConfig(): DOMSignatureUpdateConfig {
  return {
    endpoint: 'https://api.example.com/dom-sigs/',
    publicKey: {
      kty: 'EC',
      crv: 'P-256',
      x: 'test-x',
      y: 'test-y',
    },
    maxRetries: 2,
    baseDelayMs: 10,
    maxDelayMs: 100,
    timeoutMs: 1000,
  };
}

function createTestEntries(): DOMSignatureEntry[] {
  return [
    { hash: generateHash(1), confidence: 90, action: 'block' },
    { hash: generateHash(2), confidence: 85, action: 'shadow' },
  ];
}

describe('DOM Signature Updates', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockStorage.local.get.mockResolvedValue({});
    mockStorage.local.set.mockResolvedValue(undefined);
    mockStorage.local.remove.mockResolvedValue(undefined);
    mockAlarms.create.mockResolvedValue(undefined);
    mockAlarms.clear.mockResolvedValue(undefined);
    (verifyDOMSignatureManifest as ReturnType<typeof vi.fn>).mockResolvedValue(true);
    (sha256 as ReturnType<typeof vi.fn>).mockResolvedValue(generateHash(100));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('_resolveUrl', () => {
    it('should resolve relative URLs', () => {
      expect(_resolveUrl('https://api.example.com/', 'manifest.json'))
        .toBe('https://api.example.com/manifest.json');

      expect(_resolveUrl('https://api.example.com', 'manifest.json'))
        .toBe('https://api.example.com/manifest.json');
    });

    it('should return absolute URLs unchanged', () => {
      expect(_resolveUrl('https://api.example.com/', 'https://cdn.example.com/data.json'))
        .toBe('https://cdn.example.com/data.json');

      expect(_resolveUrl('https://api.example.com/', 'http://other.com/data.json'))
        .toBe('http://other.com/data.json');
    });
  });

  describe('_findApplicableDelta', () => {
    it('should find matching delta', () => {
      const deltas: DOMSignatureDeltaInfo[] = [
        { from: 1, to: 2, url: 'delta-1-2.json', size: 1000 },
        { from: 2, to: 3, url: 'delta-2-3.json', size: 2000 },
      ];

      const result = _findApplicableDelta(deltas, 1, 2, 10000);
      expect(result).toEqual(deltas[0]);
    });

    it('should return null when no matching delta', () => {
      const deltas: DOMSignatureDeltaInfo[] = [
        { from: 2, to: 3, url: 'delta-2-3.json', size: 1000 },
      ];

      const result = _findApplicableDelta(deltas, 1, 3, 10000);
      expect(result).toBeNull();
    });

    it('should skip delta larger than maxSize', () => {
      const deltas: DOMSignatureDeltaInfo[] = [
        { from: 1, to: 2, url: 'delta-1-2.json', size: 100000 },
      ];

      const result = _findApplicableDelta(deltas, 1, 2, 1000);
      expect(result).toBeNull();
    });
  });

  describe('fetchDOMSignatureUpdate', () => {
    it('should successfully fetch and apply update', async () => {
      const manifest = createTestManifest(1);
      const entries = createTestEntries();
      const config = createTestConfig();
      const entriesJson = JSON.stringify(entries);

      // Mock manifest fetch
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(manifest),
        })
        // Mock data fetch - uses text() for integrity verification
        .mockResolvedValueOnce({
          ok: true,
          text: () => Promise.resolve(entriesJson),
        });

      const result = await fetchDOMSignatureUpdate(config);

      expect(result.success).toBe(true);
      expect(result.version).toBe(1);
      expect(result.exactCount).toBe(2);
      expect(result.type).toBe('snapshot');
    });

    it('should skip update when current version is same or newer', async () => {
      const manifest = createTestManifest(5);
      const config = createTestConfig();

      // Return existing metadata with same version
      mockStorage.local.get.mockResolvedValue({
        browserdefense_dom_sig_meta: {
          version: 5,
          exactCount: 2,
          lshCount: 0,
        },
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(manifest),
      });

      const result = await fetchDOMSignatureUpdate(config);

      expect(result.success).toBe(true);
      expect(result.version).toBe(5);
      // Should not fetch data
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should fail on invalid signature', async () => {
      const manifest = createTestManifest(1);
      const config = createTestConfig();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(manifest),
      });

      (verifyDOMSignatureManifest as ReturnType<typeof vi.fn>).mockResolvedValue(false);

      const result = await fetchDOMSignatureUpdate(config);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid signature');
    });

    it('should fail on integrity check failure', async () => {
      const manifest = createTestManifest(1);
      const entries = createTestEntries();
      const config = createTestConfig();
      const entriesJson = JSON.stringify(entries);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(manifest),
        })
        // Mock data fetch - uses text() for integrity verification
        .mockResolvedValueOnce({
          ok: true,
          text: () => Promise.resolve(entriesJson),
        });

      // Return different hash (integrity failure)
      (sha256 as ReturnType<typeof vi.fn>).mockResolvedValue(generateHash(999));

      const result = await fetchDOMSignatureUpdate(config);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Integrity check failed');
    });

    it('should retry on network failure', async () => {
      const manifest = createTestManifest(1);
      const entries = createTestEntries();
      const config = createTestConfig();
      const entriesJson = JSON.stringify(entries);

      // First manifest fetch fails, second succeeds
      mockFetch
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(manifest),
        })
        // Mock data fetch - uses text() for integrity verification
        .mockResolvedValueOnce({
          ok: true,
          text: () => Promise.resolve(entriesJson),
        });

      const result = await fetchDOMSignatureUpdate(config);

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should fail after max retries', async () => {
      const config = createTestConfig();

      mockFetch.mockRejectedValue(new Error('Network error'));

      const result = await fetchDOMSignatureUpdate(config);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Network error');
      expect(mockFetch).toHaveBeenCalledTimes(config.maxRetries ?? 3);
    });
  });

  describe('scheduleDOMSignatureUpdates', () => {
    it('should store config and create alarm', async () => {
      const config = createTestConfig();

      await scheduleDOMSignatureUpdates(config, 60);

      expect(mockStorage.local.set).toHaveBeenCalledWith({
        [DOM_SIG_UPDATE_CONFIG_KEY]: config,
      });

      expect(mockAlarms.create).toHaveBeenCalledWith(
        DOM_SIG_UPDATE_ALARM,
        {
          periodInMinutes: 60,
          delayInMinutes: 0,
        }
      );
    });

    it('should use default interval', async () => {
      const config = createTestConfig();

      await scheduleDOMSignatureUpdates(config);

      expect(mockAlarms.create).toHaveBeenCalledWith(
        DOM_SIG_UPDATE_ALARM,
        expect.objectContaining({
          periodInMinutes: 60,
        })
      );
    });
  });

  describe('handleDOMSignatureUpdateAlarm', () => {
    it('should fetch update when config exists', async () => {
      const config = createTestConfig();
      const manifest = createTestManifest(1);
      const entries = createTestEntries();
      const entriesJson = JSON.stringify(entries);

      mockStorage.local.get.mockResolvedValue({
        [DOM_SIG_UPDATE_CONFIG_KEY]: config,
      });

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(manifest),
        })
        // Mock data fetch - uses text() for integrity verification
        .mockResolvedValueOnce({
          ok: true,
          text: () => Promise.resolve(entriesJson),
        });

      await handleDOMSignatureUpdateAlarm();

      expect(mockFetch).toHaveBeenCalled();
    });

    it('should do nothing when no config exists', async () => {
      mockStorage.local.get.mockResolvedValue({});

      await handleDOMSignatureUpdateAlarm();

      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('cancelDOMSignatureUpdates', () => {
    it('should clear alarm and remove config', async () => {
      await cancelDOMSignatureUpdates();

      expect(mockAlarms.clear).toHaveBeenCalledWith(DOM_SIG_UPDATE_ALARM);
      expect(mockStorage.local.remove).toHaveBeenCalledWith(DOM_SIG_UPDATE_CONFIG_KEY);
    });
  });

  describe('getDOMSignatureUpdateMeta', () => {
    it('should return metadata when exists', async () => {
      const meta = {
        version: 5,
        timestamp: '2024-01-01T00:00:00Z',
        updatedAt: Date.now(),
        exactCount: 100,
        lshCount: 50,
      };

      mockStorage.local.get.mockResolvedValue({
        browserdefense_dom_sig_meta: meta,
      });

      const result = await getDOMSignatureUpdateMeta();

      expect(result).toEqual(meta);
    });

    it('should return null when no metadata', async () => {
      mockStorage.local.get.mockResolvedValue({});

      const result = await getDOMSignatureUpdateMeta();

      expect(result).toBeNull();
    });
  });

  describe('storage keys', () => {
    it('should export correct storage key constants', () => {
      expect(DOM_SIG_UPDATE_CONFIG_KEY).toBe('browserdefense_dom_sig_update_config');
      expect(DOM_SIG_UPDATE_ALARM).toBe('browserdefense_dom_sig_update');
    });
  });
});
