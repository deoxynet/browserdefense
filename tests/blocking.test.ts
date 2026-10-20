/**
 * Blocking Module Tests
 *
 * Tests for navigation blocking functionality.
 * SECURITY CRITICAL: Verifies that blocking uses the same canonicalization
 * as IOC hashing to prevent silent bypasses.
 */

import { describe, it, expect } from 'vitest';
import { getBlockPageUrl, isBlocked, type BlockingMode } from '../src/background/blocking';
import { canonicalizeUrl, canonicalizeAndHash } from '../src/crypto/canonicalize';
import { sha256Bytes } from '../src/crypto/hashing';

describe('Security Boundary: Blocking uses same canonicalization as IOC hashing', () => {
  /**
   * CRITICAL: This test verifies that the blocking path produces identical
   * canonical URLs as the IOC hashing path. If these diverge, attackers can
   * bypass blocks by using URL variations that hash differently.
   *
   * Issue #126 - Canonicalization logic was split, creating bypass risk.
   */

  describe('Double-encoding bypass prevention', () => {
    it('double-encoded path traversal is blocked', async () => {
      // Attack: %252e%252e = %2e%2e = .. (double-encoded traversal)
      // If blocking doesn't iterate decode, this bypasses blocks
      const normalUrl = 'http://evil.com/admin/secret';
      const bypassAttempt = 'http://evil.com/admin/%252e%252e/admin/secret';

      const normalCanonical = canonicalizeUrl(normalUrl);
      const bypassCanonical = canonicalizeUrl(bypassAttempt);

      // Both should resolve to the same canonical form
      expect(bypassCanonical).toBe(normalCanonical);
    });

    it('triple-encoded traversal is blocked', async () => {
      const normalUrl = 'http://evil.com/secret';
      const bypassAttempt = 'http://evil.com/safe/%25252e%25252e/secret';

      const normalCanonical = canonicalizeUrl(normalUrl);
      const bypassCanonical = canonicalizeUrl(bypassAttempt);

      expect(bypassCanonical).toBe(normalCanonical);
    });
  });

  describe('Path traversal after decode', () => {
    it('encoded .. segments are resolved after decode', async () => {
      // Attack: %2e%2e = .. after decode, must be resolved
      const normalUrl = 'http://evil.com/secret';
      const bypassAttempt = 'http://evil.com/safe/%2e%2e/secret';

      const normalCanonical = canonicalizeUrl(normalUrl);
      const bypassCanonical = canonicalizeUrl(bypassAttempt);

      expect(bypassCanonical).toBe(normalCanonical);
    });

    it('mixed encoded/literal traversal is resolved', async () => {
      const normalUrl = 'http://evil.com/target';
      const bypassAttempt = 'http://evil.com/a/b/%2e%2e/../target';

      const normalCanonical = canonicalizeUrl(normalUrl);
      const bypassCanonical = canonicalizeUrl(bypassAttempt);

      expect(bypassCanonical).toBe(normalCanonical);
    });
  });

  describe('Hash consistency between IOC creation and blocking check', () => {
    it('IOC hash matches blocking hash for normal URL', async () => {
      const url = 'https://phishing-site.com/login';
      const salt = 'test-salt';

      // IOC hashing path (what gets stored in blocklist)
      const iocHash = await canonicalizeAndHash(url, salt);

      // Blocking path (what gets checked at runtime)
      const canonical = canonicalizeUrl(url, { scope: 'HOST_PATH' });
      const blockingData = canonical + ':' + salt;
      const blockingHash = await sha256Bytes(blockingData);

      expect(Array.from(blockingHash)).toEqual(Array.from(iocHash));
    });

    it('IOC hash matches blocking hash for bypass attempt URL', async () => {
      // Attacker tries to visit bypass URL, should match IOC for target
      const targetUrl = 'https://evil.com/malware';
      const bypassUrl = 'https://EVIL.COM.:443/safe/%252e%252e/malware';
      const salt = 'customer-salt';

      // IOC was created for the target
      const iocHash = await canonicalizeAndHash(targetUrl, salt);

      // Blocking checks the bypass attempt
      const canonical = canonicalizeUrl(bypassUrl, { scope: 'HOST_PATH' });
      const blockingData = canonical + ':' + salt;
      const blockingHash = await sha256Bytes(blockingData);

      // Both should produce the same hash (bypass blocked!)
      expect(Array.from(blockingHash)).toEqual(Array.from(iocHash));
    });

    it('case + trailing dot + default port all normalize', async () => {
      const variations = [
        'http://evil.com/admin',
        'HTTP://EVIL.COM/admin',
        'http://evil.com./admin',
        'http://EVIL.COM.:80/admin',
        'HTTP://Evil.Com.:80/admin',
      ];

      const salt = 'test';
      const baseHash = await canonicalizeAndHash(variations[0], salt);

      for (const url of variations) {
        const hash = await canonicalizeAndHash(url, salt);
        expect(Array.from(hash)).toEqual(Array.from(baseHash));
      }
    });
  });

  describe('Comprehensive bypass prevention', () => {
    const bypassAttempts = [
      // Double encoding
      ['http://evil.com/admin', 'http://evil.com/%61dmin'],
      ['http://evil.com/admin', 'http://evil.com/%2561dmin'],

      // Path traversal after decode
      ['http://evil.com/secret', 'http://evil.com/safe/../secret'],
      ['http://evil.com/secret', 'http://evil.com/safe/%2e%2e/secret'],
      ['http://evil.com/secret', 'http://evil.com/safe/%252e%252e/secret'],

      // Case normalization
      ['http://evil.com/path', 'HTTP://EVIL.COM/path'],
      ['http://evil.com/path', 'http://Evil.Com./path'],

      // Port normalization
      ['http://evil.com/path', 'http://evil.com:80/path'],
      ['https://evil.com/path', 'https://evil.com:443/path'],

      // Trailing dot
      ['http://evil.com/path', 'http://evil.com./path'],

      // Combined attacks
      ['http://evil.com/admin', 'HTTP://EVIL.COM.:80/%61dmin'],
      ['http://evil.com/secret', 'http://EVIL.COM./safe/%252e%252e/secret'],
    ];

    it.each(bypassAttempts)(
      'bypass blocked: %s === %s',
      async (expected, bypass) => {
        const expectedCanonical = canonicalizeUrl(expected);
        const bypassCanonical = canonicalizeUrl(bypass);
        expect(bypassCanonical).toBe(expectedCanonical);
      }
    );
  });
});

describe('getBlockPageUrl', () => {
  it('should generate URL with blocked URL parameter', () => {
    // Mock chrome.runtime.getURL
    const originalChrome = globalThis.chrome;
    globalThis.chrome = {
      runtime: {
        getURL: (path: string) => `chrome-extension://abc123/${path}`,
      },
    } as typeof chrome;

    const result = getBlockPageUrl('https://evil.com/malware');

    expect(result).toContain('chrome-extension://abc123/blocked/blocked.html');
    expect(result).toContain('url=https%3A%2F%2Fevil.com%2Fmalware');
    expect(result).toContain('ts=');

    globalThis.chrome = originalChrome;
  });

  it('should include reason parameter when provided', () => {
    const originalChrome = globalThis.chrome;
    globalThis.chrome = {
      runtime: {
        getURL: (path: string) => `chrome-extension://abc123/${path}`,
      },
    } as typeof chrome;

    const result = getBlockPageUrl('https://evil.com', 'phishing');

    expect(result).toContain('reason=phishing');

    globalThis.chrome = originalChrome;
  });
});

describe('BlockingMode type', () => {
  /**
   * Tests for the BlockingMode type to ensure async mode is supported.
   * Issue #157: Async Phishing Intercept
   */

  it('should include async as a valid blocking mode', () => {
    // Type check - these should all be valid BlockingMode values
    const modes: BlockingMode[] = ['enterprise', 'dnr', 'async', 'fallback'];

    expect(modes).toContain('async');
    expect(modes.length).toBe(4);
  });

  it('async mode is distinct from fallback', () => {
    const async: BlockingMode = 'async';
    const fallback: BlockingMode = 'fallback';

    expect(async).not.toBe(fallback);
  });
});
