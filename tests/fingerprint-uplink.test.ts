/**
 * Fingerprint Uplink Tests
 *
 * Tests for phishing kit fingerprint uplink functionality.
 * Issue #164: P0 - Phishing Kit Fingerprint Uplink
 *
 * CRITICAL: Privacy guarantees must be verified.
 * The payload must contain ONLY hash + timestamp.
 * No URLs, no DOM content, no user data.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  hashSkeleton,
  uploadFingerprint,
  _assertMinimalPayload,
  type FingerprintPayload,
  type FingerprintUplinkConfig,
} from '../src/background/fingerprint-uplink';
import type { DOMSkeleton } from '../src/content/dom-skeleton';

// Mock chrome.storage.local
const mockStorage: Record<string, unknown> = {};
vi.stubGlobal('chrome', {
  storage: {
    local: {
      get: vi.fn((keys) => {
        if (typeof keys === 'string') {
          return Promise.resolve({ [keys]: mockStorage[keys] });
        }
        return Promise.resolve(mockStorage);
      }),
      set: vi.fn((items) => {
        Object.assign(mockStorage, items);
        return Promise.resolve();
      }),
      remove: vi.fn((keys) => {
        if (typeof keys === 'string') {
          delete mockStorage[keys];
        } else {
          for (const key of keys) {
            delete mockStorage[key];
          }
        }
        return Promise.resolve();
      }),
    },
  },
});

// Sample DOM skeleton for testing
const createSampleSkeleton = (overrides: Partial<DOMSkeleton> = {}): DOMSkeleton => ({
  tagTree: 'html(body(div(form[method=post](button[type=submit],input[type=email],input[type=password]))))',
  formCount: 1,
  inputTypes: ['email', 'password'],
  actionUrls: ['/login'],
  hasLoginForm: true,
  hasPaymentForm: false,
  extractionTimeMs: 2.5,
  ...overrides,
});

describe('Fingerprint Uplink - Privacy Guarantees', () => {
  /**
   * CRITICAL SECURITY TESTS
   * These tests verify that we never send sensitive data to the server.
   */

  describe('assertMinimalPayload', () => {
    it('should accept valid payload with only hash and timestamp', () => {
      const payload: FingerprintPayload = {
        hash: 'a'.repeat(64), // Valid SHA-256 hex
        timestamp: Date.now(),
      };

      expect(() => _assertMinimalPayload(payload)).not.toThrow();
    });

    it('should reject payload with URL field', () => {
      const payload = {
        hash: 'a'.repeat(64),
        timestamp: Date.now(),
        url: 'https://phishing.com/login',
      } as unknown as FingerprintPayload;

      expect(() => _assertMinimalPayload(payload)).toThrow('PRIVACY VIOLATION');
      expect(() => _assertMinimalPayload(payload)).toThrow('url');
    });

    it('should reject payload with DOM content', () => {
      const payload = {
        hash: 'a'.repeat(64),
        timestamp: Date.now(),
        tagTree: 'html(body(...))',
      } as unknown as FingerprintPayload;

      expect(() => _assertMinimalPayload(payload)).toThrow('PRIVACY VIOLATION');
      expect(() => _assertMinimalPayload(payload)).toThrow('tagTree');
    });

    it('should reject payload with user data', () => {
      const payload = {
        hash: 'a'.repeat(64),
        timestamp: Date.now(),
        userData: { email: 'user@example.com' },
      } as unknown as FingerprintPayload;

      expect(() => _assertMinimalPayload(payload)).toThrow('PRIVACY VIOLATION');
      expect(() => _assertMinimalPayload(payload)).toThrow('userData');
    });

    it('should reject payload with screenshot', () => {
      const payload = {
        hash: 'a'.repeat(64),
        timestamp: Date.now(),
        screenshot: 'base64data...',
      } as unknown as FingerprintPayload;

      expect(() => _assertMinimalPayload(payload)).toThrow('PRIVACY VIOLATION');
      expect(() => _assertMinimalPayload(payload)).toThrow('screenshot');
    });

    it('should reject payload with formValues', () => {
      const payload = {
        hash: 'a'.repeat(64),
        timestamp: Date.now(),
        formValues: { username: 'admin', password: 'secret' },
      } as unknown as FingerprintPayload;

      expect(() => _assertMinimalPayload(payload)).toThrow('PRIVACY VIOLATION');
      expect(() => _assertMinimalPayload(payload)).toThrow('formValues');
    });

    it('should reject invalid hash format (too short)', () => {
      const payload: FingerprintPayload = {
        hash: 'abc123',
        timestamp: Date.now(),
      };

      expect(() => _assertMinimalPayload(payload)).toThrow('Invalid hash format');
    });

    it('should reject invalid hash format (non-hex)', () => {
      const payload: FingerprintPayload = {
        hash: 'g'.repeat(64), // 'g' is not a hex character
        timestamp: Date.now(),
      };

      expect(() => _assertMinimalPayload(payload)).toThrow('Invalid hash format');
    });

    it('should reject invalid timestamp (zero)', () => {
      const payload: FingerprintPayload = {
        hash: 'a'.repeat(64),
        timestamp: 0,
      };

      expect(() => _assertMinimalPayload(payload)).toThrow('Invalid timestamp');
    });

    it('should reject invalid timestamp (negative)', () => {
      const payload: FingerprintPayload = {
        hash: 'a'.repeat(64),
        timestamp: -1000,
      };

      expect(() => _assertMinimalPayload(payload)).toThrow('Invalid timestamp');
    });
  });

  describe('hashSkeleton - No sensitive data in hash input', () => {
    it('should hash skeleton deterministically', async () => {
      const skeleton = createSampleSkeleton();

      const hash1 = await hashSkeleton(skeleton);
      const hash2 = await hashSkeleton(skeleton);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce different hashes for different structures', async () => {
      const skeleton1 = createSampleSkeleton({ formCount: 1 });
      const skeleton2 = createSampleSkeleton({ formCount: 2 });

      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);

      expect(hash1).not.toBe(hash2);
    });

    it('should NOT include actionUrls in hash (may leak path info)', async () => {
      // Two skeletons with same structure but different action URLs
      // should produce the SAME hash (actionUrls excluded for privacy)
      const skeleton1 = createSampleSkeleton({ actionUrls: ['/login'] });
      const skeleton2 = createSampleSkeleton({ actionUrls: ['/api/auth'] });

      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);

      // Same hash because actionUrls are excluded
      expect(hash1).toBe(hash2);
    });

    it('should NOT include extractionTimeMs in hash', async () => {
      const skeleton1 = createSampleSkeleton({ extractionTimeMs: 1.0 });
      const skeleton2 = createSampleSkeleton({ extractionTimeMs: 100.0 });

      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);

      // Same hash because extractionTimeMs is not fingerprint-relevant
      expect(hash1).toBe(hash2);
    });
  });
});

describe('Fingerprint Uplink - Functionality', () => {
  beforeEach(() => {
    // Clear mock storage
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    vi.clearAllMocks();
  });

  describe('hashSkeleton', () => {
    it('should include tagTree in hash', async () => {
      const skeleton1 = createSampleSkeleton({ tagTree: 'html(body(div))' });
      const skeleton2 = createSampleSkeleton({ tagTree: 'html(body(span))' });

      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);

      expect(hash1).not.toBe(hash2);
    });

    it('should include formCount in hash', async () => {
      const skeleton1 = createSampleSkeleton({ formCount: 1 });
      const skeleton2 = createSampleSkeleton({ formCount: 3 });

      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);

      expect(hash1).not.toBe(hash2);
    });

    it('should include inputTypes in hash', async () => {
      const skeleton1 = createSampleSkeleton({ inputTypes: ['email', 'password'] });
      const skeleton2 = createSampleSkeleton({ inputTypes: ['text', 'tel'] });

      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);

      expect(hash1).not.toBe(hash2);
    });

    it('should include hasLoginForm in hash', async () => {
      const skeleton1 = createSampleSkeleton({ hasLoginForm: true });
      const skeleton2 = createSampleSkeleton({ hasLoginForm: false });

      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);

      expect(hash1).not.toBe(hash2);
    });

    it('should include hasPaymentForm in hash', async () => {
      const skeleton1 = createSampleSkeleton({ hasPaymentForm: true });
      const skeleton2 = createSampleSkeleton({ hasPaymentForm: false });

      const hash1 = await hashSkeleton(skeleton1);
      const hash2 = await hashSkeleton(skeleton2);

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('uploadFingerprint', () => {
    let fetchMock: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      fetchMock = vi.fn();
      vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
      vi.unstubAllGlobals();
      // Re-stub chrome
      vi.stubGlobal('chrome', {
        storage: {
          local: {
            get: vi.fn((keys) => {
              if (typeof keys === 'string') {
                return Promise.resolve({ [keys]: mockStorage[keys] });
              }
              return Promise.resolve(mockStorage);
            }),
            set: vi.fn((items) => {
              Object.assign(mockStorage, items);
              return Promise.resolve();
            }),
            remove: vi.fn((keys) => {
              if (typeof keys === 'string') {
                delete mockStorage[keys];
              } else {
                for (const key of keys) {
                  delete mockStorage[key];
                }
              }
              return Promise.resolve();
            }),
          },
        },
      });
    });

    it('should send only hash and timestamp to server', async () => {
      const skeleton = createSampleSkeleton();
      const config: FingerprintUplinkConfig = {
        endpoint: 'https://api.example.com/fingerprint',
        enableLocalCache: false,
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          confidence: 75,
          action: 'shadow',
          isNovel: true,
        }),
      });

      await uploadFingerprint(skeleton, config);

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, options] = fetchMock.mock.calls[0];

      expect(url).toBe('https://api.example.com/fingerprint');

      // Parse the sent body and verify it contains ONLY hash and timestamp
      const sentBody = JSON.parse(options.body);
      const keys = Object.keys(sentBody);

      expect(keys).toHaveLength(2);
      expect(keys).toContain('hash');
      expect(keys).toContain('timestamp');

      // Verify hash format
      expect(sentBody.hash).toMatch(/^[a-f0-9]{64}$/);

      // Verify timestamp is a number
      expect(typeof sentBody.timestamp).toBe('number');
      expect(sentBody.timestamp).toBeGreaterThan(0);

      // Verify NO other data is sent
      expect(sentBody.url).toBeUndefined();
      expect(sentBody.tagTree).toBeUndefined();
      expect(sentBody.skeleton).toBeUndefined();
      expect(sentBody.formCount).toBeUndefined();
      expect(sentBody.inputTypes).toBeUndefined();
    });

    it('should return server response on success', async () => {
      const skeleton = createSampleSkeleton();
      const config: FingerprintUplinkConfig = {
        endpoint: 'https://api.example.com/fingerprint',
        enableLocalCache: false,
      };

      const serverResponse = {
        confidence: 85,
        kitId: 'microsoft-login-v2',
        action: 'block',
        isNovel: false,
        occurrenceCount: 1500,
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(serverResponse),
      });

      const result = await uploadFingerprint(skeleton, config);

      expect(result).toEqual(serverResponse);
    });

    it('should return null on network error', async () => {
      const skeleton = createSampleSkeleton();
      const config: FingerprintUplinkConfig = {
        endpoint: 'https://api.example.com/fingerprint',
        enableLocalCache: false,
      };

      fetchMock.mockRejectedValueOnce(new Error('Network error'));

      const result = await uploadFingerprint(skeleton, config);

      expect(result).toBeNull();
    });

    it('should return null on HTTP error', async () => {
      const skeleton = createSampleSkeleton();
      const config: FingerprintUplinkConfig = {
        endpoint: 'https://api.example.com/fingerprint',
        enableLocalCache: false,
      };

      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const result = await uploadFingerprint(skeleton, config);

      expect(result).toBeNull();
    });
  });
});

describe('Fingerprint Uplink - Determinism', () => {
  it('should produce same hash for identical login forms', async () => {
    // Two login forms with same structure should have same hash
    // This is key for phishing kit detection
    const skeleton1 = createSampleSkeleton({
      tagTree: 'html(body(div(form[method=post](input[type=email],input[type=password],button[type=submit]))))',
      formCount: 1,
      inputTypes: ['email', 'password'],
      hasLoginForm: true,
      hasPaymentForm: false,
    });

    const skeleton2 = createSampleSkeleton({
      tagTree: 'html(body(div(form[method=post](input[type=email],input[type=password],button[type=submit]))))',
      formCount: 1,
      inputTypes: ['email', 'password'],
      hasLoginForm: true,
      hasPaymentForm: false,
    });

    const hash1 = await hashSkeleton(skeleton1);
    const hash2 = await hashSkeleton(skeleton2);

    expect(hash1).toBe(hash2);
  });

  it('should produce same hash regardless of actionUrl differences', async () => {
    // Same phishing kit on different domains should have same hash
    // actionUrls are excluded because they would differ by domain
    const skeleton1 = createSampleSkeleton({
      actionUrls: ['/login'],
    });

    const skeleton2 = createSampleSkeleton({
      actionUrls: ['/api/v1/authenticate'],
    });

    const hash1 = await hashSkeleton(skeleton1);
    const hash2 = await hashSkeleton(skeleton2);

    expect(hash1).toBe(hash2);
  });
});

describe('Fingerprint Uplink - Zero-Knowledge Compliance', () => {
  /**
   * These tests verify compliance with the zero-knowledge architecture.
   * Server learns ONLY: "fingerprint X was seen at time T"
   * Server does NOT learn: what site, what user, what content
   */

  it('hash should not be reversible to reveal page content', async () => {
    const skeleton = createSampleSkeleton({
      tagTree: 'html(body(div(h1,form[method=post](input[type=email],input[type=password]))))',
    });

    const hash = await hashSkeleton(skeleton);

    // Hash should be a SHA-256 hex string
    expect(hash).toMatch(/^[a-f0-9]{64}$/);

    // Hash should not contain any readable structure
    expect(hash).not.toContain('html');
    expect(hash).not.toContain('body');
    expect(hash).not.toContain('form');
    expect(hash).not.toContain('input');
  });

  it('payload should be minimal and privacy-preserving', () => {
    const validPayload: FingerprintPayload = {
      hash: 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
      timestamp: 1704067200000,
    };

    // Should not throw for valid minimal payload
    expect(() => _assertMinimalPayload(validPayload)).not.toThrow();

    // Verify the payload is truly minimal
    const payloadJson = JSON.stringify(validPayload);
    const parsed = JSON.parse(payloadJson);

    expect(Object.keys(parsed)).toEqual(['hash', 'timestamp']);
  });
});
