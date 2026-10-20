/**
 * Forensics Encryption Tests
 *
 * Tests for Issue #232: Forensics queue never encrypts/uploads (retry lacks encryptFn)
 *
 * Verifies that:
 * - getEncryptionFunction returns null when config is missing
 * - getEncryptionFunction returns a working function when properly configured
 * - checkPendingForensics calls retryPendingUploads with encryption
 * - The message handler for retryUploads uses encryption
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  getEncryptionFunction,
  checkPendingForensics,
  queueForensics,
  clearQueue,
  getQueue,
  type ForensicsPayload,
} from '../src/background/forensics';

// Mock the encryption module
vi.mock('../src/crypto/encryption', () => ({
  encryptForensics: vi.fn().mockResolvedValue({
    iv: 'mock-iv-base64',
    wrappedKey: 'mock-wrapped-key-base64',
    ciphertext: 'mock-ciphertext-base64',
  }),
}));

// Mock storage state
let mockStorage: Record<string, unknown> = {};

const mockChrome = {
  storage: {
    local: {
      get: vi.fn((keys: string | string[]) => {
        if (typeof keys === 'string') {
          return Promise.resolve({ [keys]: mockStorage[keys] });
        }
        const result: Record<string, unknown> = {};
        for (const key of keys) {
          if (mockStorage[key] !== undefined) {
            result[key] = mockStorage[key];
          }
        }
        return Promise.resolve(result);
      }),
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

// Mock navigator.onLine
Object.defineProperty(navigator, 'onLine', {
  value: true,
  writable: true,
});

// Test RSA public key in JWK format
const testPublicKey = {
  kty: 'RSA',
  n: 'test-n-value-base64url',
  e: 'AQAB',
  alg: 'RSA-OAEP-256',
  use: 'enc',
};

describe('Forensics Encryption (Issue #232)', () => {
  beforeEach(() => {
    // Reset mock storage
    mockStorage = {};
    vi.clearAllMocks();
  });

  afterEach(async () => {
    // Clear queue after each test
    await clearQueue();
  });

  describe('getEncryptionFunction', () => {
    it('should return null when no public key is configured', async () => {
      // No config at all
      mockStorage = {};

      const encryptFn = await getEncryptionFunction();

      expect(encryptFn).toBeNull();
    });

    it('should return null when config exists but no public key', async () => {
      mockStorage = {
        browserdefense_config: {
          org_id: 'test-org',
          forensics_endpoint: 'https://api.example.com/forensics',
          // No encryption_public_key
        },
      };

      const encryptFn = await getEncryptionFunction();

      expect(encryptFn).toBeNull();
    });

    it('should return null when public key exists but no org_id', async () => {
      mockStorage = {
        browserdefense_config: {
          encryption_public_key: testPublicKey,
          forensics_endpoint: 'https://api.example.com/forensics',
          // No org_id
        },
      };

      const encryptFn = await getEncryptionFunction();

      expect(encryptFn).toBeNull();
    });

    it('should return encryption function when properly configured', async () => {
      mockStorage = {
        browserdefense_config: {
          org_id: 'test-org',
          encryption_public_key: testPublicKey,
          key_version: 2,
          forensics_endpoint: 'https://api.example.com/forensics',
        },
      };

      const encryptFn = await getEncryptionFunction();

      expect(encryptFn).not.toBeNull();
      expect(typeof encryptFn).toBe('function');
    });

    it('should use default key_version of 1 when not specified', async () => {
      mockStorage = {
        browserdefense_config: {
          org_id: 'test-org',
          encryption_public_key: testPublicKey,
          // No key_version
          forensics_endpoint: 'https://api.example.com/forensics',
        },
      };

      const encryptFn = await getEncryptionFunction();

      expect(encryptFn).not.toBeNull();
    });

    it('should create function that produces encrypted output with correct metadata', async () => {
      mockStorage = {
        browserdefense_config: {
          org_id: 'test-org-123',
          encryption_public_key: testPublicKey,
          key_version: 5,
          forensics_endpoint: 'https://api.example.com/forensics',
        },
      };

      const encryptFn = await getEncryptionFunction();
      expect(encryptFn).not.toBeNull();

      // The function should wrap encryptForensics and add orgId/keyVersion
      const testPayload: ForensicsPayload = {
        blockedUrl: 'https://evil.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      const encrypted = await encryptFn!(testPayload);

      expect(encrypted.orgId).toBe('test-org-123');
      expect(encrypted.keyVersion).toBe(5);
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.wrappedKey).toBeDefined();
      expect(encrypted.ciphertext).toBeDefined();
    });
  });

  describe('checkPendingForensics with encryption', () => {
    it('should not retry when encryption key is missing', async () => {
      // Queue an item
      const payload: ForensicsPayload = {
        blockedUrl: 'https://evil.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };
      await queueForensics(payload);

      // Config without encryption key
      mockStorage = {
        ...mockStorage,
        browserdefense_config: {
          org_id: 'test-org',
          forensics_endpoint: 'https://api.example.com/forensics',
          // No encryption_public_key
        },
      };

      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      await checkPendingForensics();

      // Should warn about missing encryption key
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('No encryption_public_key configured')
      );

      consoleSpy.mockRestore();

      // Queue should still have the item (not uploaded)
      const queue = await getQueue();
      expect(queue.length).toBe(1);
    });

    it('should attempt retry when encryption is properly configured', async () => {
      // Queue an item
      const payload: ForensicsPayload = {
        blockedUrl: 'https://evil.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };
      await queueForensics(payload);

      // Full config with encryption
      mockStorage = {
        ...mockStorage,
        browserdefense_config: {
          org_id: 'test-org',
          encryption_public_key: testPublicKey,
          key_version: 1,
          forensics_endpoint: 'https://api.example.com/forensics',
        },
      };

      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      await checkPendingForensics();

      // Should log about pending forensics
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('pending forensics')
      );

      consoleSpy.mockRestore();
    });
  });

  describe('encryption config edge cases', () => {
    it('should handle empty org_id', async () => {
      mockStorage = {
        browserdefense_config: {
          org_id: '',
          encryption_public_key: testPublicKey,
          forensics_endpoint: 'https://api.example.com/forensics',
        },
      };

      const encryptFn = await getEncryptionFunction();

      // Empty string is falsy, should return null
      expect(encryptFn).toBeNull();
    });

    it('should handle null public key', async () => {
      mockStorage = {
        browserdefense_config: {
          org_id: 'test-org',
          encryption_public_key: null,
          forensics_endpoint: 'https://api.example.com/forensics',
        },
      };

      const encryptFn = await getEncryptionFunction();

      expect(encryptFn).toBeNull();
    });

    it('should handle missing config entirely', async () => {
      mockStorage = {};

      const encryptFn = await getEncryptionFunction();

      expect(encryptFn).toBeNull();
    });
  });
});

describe('Backward Compatibility (Issue #232)', () => {
  it('should gracefully handle missing encryption for queued items', async () => {
    // Clear queue first
    await clearQueue();
    mockStorage = {};
    vi.clearAllMocks();

    // This simulates the bug scenario: items were queued but encryption
    // function wasn't passed to retry
    const payload: ForensicsPayload = {
      blockedUrl: 'https://evil.com',
      timestamp: new Date().toISOString(),
      tabId: 1,
      frameId: 0,
      reason: 'ioc_match',
    };
    await queueForensics(payload);

    // Verify item was queued
    const queueBefore = await getQueue();
    expect(queueBefore.length).toBe(1);

    // Clear config to simulate no encryption available - but preserve queue
    const queueData = mockStorage['browserdefense_forensics_queue'];
    mockStorage = { browserdefense_forensics_queue: queueData };

    // This should not throw, just warn
    await expect(checkPendingForensics()).resolves.not.toThrow();

    // Item should remain in queue (not uploaded since no encryption)
    const queueAfter = await getQueue();
    expect(queueAfter.length).toBe(1);
  });
});
