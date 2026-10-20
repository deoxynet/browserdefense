/**
 * IOC Metadata Storage Tests
 *
 * Tests for per-IOC metadata storage (Issue #183).
 * Used for storing flags like captureScreenshot.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  saveIOCMetadata,
  loadIOCMetadata,
  getIOCMetadata,
  setIOCMetadata,
  removeIOCMetadata,
  clearIOCMetadata,
  shouldCaptureScreenshotForIOC,
  getScreenshotEnabledHashes,
  getMetadataStats,
  type IOCMetadata,
  type IOCMetadataMap,
} from '../src/storage/ioc-metadata';

// ============ Test Hash Constants ============
// Valid 64-character hex strings for SHA-256 hashes
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);
const HASH_D = 'd'.repeat(64);
const HASH_E = 'e'.repeat(64);
const HASH_F = 'f'.repeat(64);
const HASH_UPPER = 'ABCDEF1234567890'.repeat(4); // Mixed case for normalization tests

// ============ Mock Setup ============

let mockStorage: Record<string, unknown> = {};

const mockChrome = {
  storage: {
    local: {
      get: vi.fn().mockImplementation((key: string) => {
        return Promise.resolve({ [key]: mockStorage[key] });
      }),
      set: vi.fn().mockImplementation((data: Record<string, unknown>) => {
        Object.assign(mockStorage, data);
        return Promise.resolve();
      }),
      remove: vi.fn().mockImplementation((key: string) => {
        delete mockStorage[key];
        return Promise.resolve();
      }),
    },
  },
};

beforeEach(() => {
  mockStorage = {};
  vi.stubGlobal('chrome', mockChrome);
  mockChrome.storage.local.get.mockClear();
  mockChrome.storage.local.set.mockClear();
  mockChrome.storage.local.remove.mockClear();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ============ Basic CRUD Tests ============

describe('IOC Metadata CRUD Operations', () => {
  it('should save and load metadata', async () => {
    const metadata: IOCMetadataMap = {
      [HASH_A]: { captureScreenshot: true },
    };

    await saveIOCMetadata(metadata);
    const loaded = await loadIOCMetadata();

    expect(loaded).toEqual(metadata);
  });

  it('should return empty object when no metadata stored', async () => {
    const loaded = await loadIOCMetadata();
    expect(loaded).toEqual({});
  });

  it('should get metadata for specific hash', async () => {
    const metadata: IOCMetadataMap = {
      [HASH_A]: { captureScreenshot: true, source: 'analyst' },
      [HASH_B]: { captureScreenshot: false },
    };
    mockStorage['blockioc_ioc_metadata'] = metadata;

    const result = await getIOCMetadata(HASH_A);
    expect(result).toEqual({ captureScreenshot: true, source: 'analyst' });
  });

  it('should return undefined for unknown hash', async () => {
    const result = await getIOCMetadata(HASH_E);
    expect(result).toBeUndefined();
  });

  it('should set metadata for a hash', async () => {
    await setIOCMetadata(HASH_A, { captureScreenshot: true });
    const loaded = await loadIOCMetadata();

    expect(loaded[HASH_A]).toEqual({ captureScreenshot: true });
  });

  it('should remove metadata for a hash', async () => {
    mockStorage['blockioc_ioc_metadata'] = {
      [HASH_A]: { captureScreenshot: true },
      [HASH_B]: { captureScreenshot: true },
    };

    await removeIOCMetadata(HASH_A);
    const loaded = await loadIOCMetadata();

    expect(loaded[HASH_A]).toBeUndefined();
    expect(loaded[HASH_B]).toEqual({ captureScreenshot: true });
  });

  it('should clear all metadata', async () => {
    mockStorage['blockioc_ioc_metadata'] = {
      [HASH_A]: { captureScreenshot: true },
    };

    await clearIOCMetadata();

    expect(mockChrome.storage.local.remove).toHaveBeenCalledWith('blockioc_ioc_metadata');
  });
});

// ============ Hash Normalization Tests ============

describe('Hash Normalization', () => {
  it('should normalize hashes to lowercase', async () => {
    await setIOCMetadata(HASH_UPPER, { captureScreenshot: true });

    // Should be stored as lowercase
    const loaded = await loadIOCMetadata();
    expect(loaded[HASH_UPPER.toLowerCase()]).toBeDefined();
  });

  it('should lookup with case-insensitive hash', async () => {
    mockStorage['blockioc_ioc_metadata'] = {
      [HASH_A]: { captureScreenshot: true },
    };

    // Uppercase lookup should work
    const result = await getIOCMetadata(HASH_A.toUpperCase());
    expect(result).toEqual({ captureScreenshot: true });
  });
});

// ============ Screenshot Flag Tests ============

describe('Screenshot Flag Helpers', () => {
  it('shouldCaptureScreenshotForIOC returns true when flag is set', async () => {
    mockStorage['blockioc_ioc_metadata'] = {
      [HASH_A]: { captureScreenshot: true },
    };

    const result = await shouldCaptureScreenshotForIOC(HASH_A);
    expect(result).toBe(true);
  });

  it('shouldCaptureScreenshotForIOC returns false when flag is not set', async () => {
    mockStorage['blockioc_ioc_metadata'] = {
      [HASH_A]: { source: 'analyst' }, // No captureScreenshot flag
    };

    const result = await shouldCaptureScreenshotForIOC(HASH_A);
    expect(result).toBe(false);
  });

  it('shouldCaptureScreenshotForIOC returns false for unknown hash', async () => {
    const result = await shouldCaptureScreenshotForIOC(HASH_E);
    expect(result).toBe(false);
  });

  it('getScreenshotEnabledHashes returns all hashes with flag', async () => {
    mockStorage['blockioc_ioc_metadata'] = {
      [HASH_A]: { captureScreenshot: true },
      [HASH_B]: { captureScreenshot: false },
      [HASH_C]: { captureScreenshot: true },
      [HASH_D]: { source: 'analyst' }, // No flag
    };

    const hashes = await getScreenshotEnabledHashes();
    expect(hashes.size).toBe(2);
    expect(hashes.has(HASH_A)).toBe(true);
    expect(hashes.has(HASH_C)).toBe(true);
    expect(hashes.has(HASH_B)).toBe(false);
    expect(hashes.has(HASH_D)).toBe(false);
  });
});

// ============ Statistics Tests ============

describe('Metadata Statistics', () => {
  it('should return correct stats', async () => {
    mockStorage['blockioc_ioc_metadata'] = {
      [HASH_A]: { captureScreenshot: true, source: 'analyst' },
      [HASH_B]: { captureScreenshot: true },
      [HASH_C]: { source: 'feed', expiresAt: '2025-12-31' },
      [HASH_D]: { expiresAt: '2025-06-30' },
    };

    const stats = await getMetadataStats();

    expect(stats.totalCount).toBe(4);
    expect(stats.withScreenshot).toBe(2);
    expect(stats.withSource).toBe(2);
    expect(stats.withExpiration).toBe(2);
  });

  it('should return zeros for empty metadata', async () => {
    const stats = await getMetadataStats();

    expect(stats.totalCount).toBe(0);
    expect(stats.withScreenshot).toBe(0);
    expect(stats.withSource).toBe(0);
    expect(stats.withExpiration).toBe(0);
  });
});

// ============ Filtering Tests ============

describe('Metadata Filtering', () => {
  it('should filter out entries with no meaningful data on save', async () => {
    const metadata: IOCMetadataMap = {
      [HASH_A]: { captureScreenshot: true }, // Should be kept
      [HASH_B]: { captureScreenshot: false }, // Should be filtered (default value)
      [HASH_C]: {}, // Should be filtered (empty)
      [HASH_D]: { source: '' }, // Should be filtered (empty string)
    };

    await saveIOCMetadata(metadata);
    const loaded = await loadIOCMetadata();

    expect(loaded[HASH_A]).toBeDefined();
    expect(loaded[HASH_B]).toBeUndefined();
    expect(loaded[HASH_C]).toBeUndefined();
    expect(loaded[HASH_D]).toBeUndefined();
  });

  it('should keep entries with source or expiresAt', async () => {
    const metadata: IOCMetadataMap = {
      [HASH_A]: { source: 'analyst' },
      [HASH_B]: { expiresAt: '2025-12-31' },
    };

    await saveIOCMetadata(metadata);
    const loaded = await loadIOCMetadata();

    expect(loaded[HASH_A]).toBeDefined();
    expect(loaded[HASH_B]).toBeDefined();
  });
});

// ============ Hash Validation Tests ============

describe('Hash Validation', () => {
  it('should reject invalid hash format in setIOCMetadata', async () => {
    await expect(setIOCMetadata('abc123', { captureScreenshot: true }))
      .rejects.toThrow('Invalid IOC hash format');
  });

  it('should reject hash with wrong length', async () => {
    await expect(setIOCMetadata('a'.repeat(32), { captureScreenshot: true }))
      .rejects.toThrow('Invalid IOC hash format');
  });

  it('should reject hash with non-hex characters', async () => {
    await expect(setIOCMetadata('g'.repeat(64), { captureScreenshot: true }))
      .rejects.toThrow('Invalid IOC hash format');
  });

  it('should accept valid 64-character hex hash', async () => {
    await expect(setIOCMetadata(HASH_A, { captureScreenshot: true }))
      .resolves.not.toThrow();
  });
});

// ============ Integration with PrioritizedIOC ============

describe('Integration with PrioritizedIOC', () => {
  it('should store metadata from PrioritizedIOC with captureScreenshot', async () => {
    // Simulate what blocking.ts does
    const ioc = {
      hash: HASH_F,
      priority: 'sync' as const,
      captureScreenshot: true,
      source: 'analyst',
      expiresAt: '2025-12-31',
    };

    if (ioc.captureScreenshot) {
      await setIOCMetadata(ioc.hash, {
        captureScreenshot: true,
        source: ioc.source,
        expiresAt: ioc.expiresAt,
      });
    }

    const shouldCapture = await shouldCaptureScreenshotForIOC(ioc.hash);
    expect(shouldCapture).toBe(true);
  });

  it('should not store metadata for IOC without captureScreenshot', async () => {
    const ioc: { hash: string; priority: 'sync'; captureScreenshot?: boolean } = {
      hash: HASH_F,
      priority: 'sync',
      // No captureScreenshot flag
    };

    // Simulate blocking.ts logic
    if (ioc.captureScreenshot) {
      await setIOCMetadata(ioc.hash, { captureScreenshot: true });
    }

    const shouldCapture = await shouldCaptureScreenshotForIOC(ioc.hash);
    expect(shouldCapture).toBe(false);
  });
});
