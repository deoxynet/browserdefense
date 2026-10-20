/**
 * Tests for URL canonicalization.
 * Test vectors based on docs/Canonicalization_Specification.md
 */

import { describe, it, expect } from 'vitest';
import {
  canonicalizeUrl,
  extractRegistrableDomain,
  validateUrl,
  canonicalizeAndHash,
} from '../src/crypto/canonicalize';

describe('canonicalizeUrl', () => {
  describe('hostname normalization', () => {
    it('lowercases hostname', () => {
      expect(canonicalizeUrl('HTTP://EVIL.COM/path')).toBe('evil.com/path');
      expect(canonicalizeUrl('http://Evil.Com/path')).toBe('evil.com/path');
    });

    it('strips trailing dot', () => {
      expect(canonicalizeUrl('http://evil.com./path')).toBe('evil.com/path');
    });

    it('removes default HTTP port 80', () => {
      expect(canonicalizeUrl('http://evil.com:80/path')).toBe('evil.com/path');
    });

    it('removes default HTTPS port 443', () => {
      expect(canonicalizeUrl('https://evil.com:443/path')).toBe('evil.com/path');
    });

    it('keeps non-default ports', () => {
      expect(canonicalizeUrl('http://evil.com:8080/path')).toBe('evil.com:8080/path');
      expect(canonicalizeUrl('https://evil.com:8443/path')).toBe('evil.com:8443/path');
    });

    it('handles IPv4 addresses', () => {
      expect(canonicalizeUrl('http://192.168.1.1/path')).toBe('192.168.1.1/path');
    });

    it('handles IPv6 addresses', () => {
      expect(canonicalizeUrl('http://[::1]/path')).toBe('[::1]/path');
    });
  });

  describe('path normalization', () => {
    it('normalizes empty path to /', () => {
      expect(canonicalizeUrl('http://evil.com')).toBe('evil.com/');
    });

    it('keeps root path as /', () => {
      expect(canonicalizeUrl('http://evil.com/')).toBe('evil.com/');
    });

    it('removes trailing slash except for root', () => {
      expect(canonicalizeUrl('http://evil.com/path/')).toBe('evil.com/path');
      expect(canonicalizeUrl('http://evil.com/a/b/')).toBe('evil.com/a/b');
    });

    it('resolves .. in path', () => {
      expect(canonicalizeUrl('http://evil.com/a/../b')).toBe('evil.com/b');
    });

    it('resolves . in path', () => {
      expect(canonicalizeUrl('http://evil.com/a/./b')).toBe('evil.com/a/b');
    });

    it('preserves path case (paths are case-sensitive)', () => {
      expect(canonicalizeUrl('http://evil.com/ADMIN')).toBe('evil.com/ADMIN');
      expect(canonicalizeUrl('http://EVIL.COM/ADMIN')).toBe('evil.com/ADMIN');
    });

    it('preserves double slashes in path', () => {
      expect(canonicalizeUrl('http://evil.com//double//slash')).toBe('evil.com//double//slash');
    });
  });

  describe('percent-encoding attacks', () => {
    it('decodes percent-encoded characters', () => {
      expect(canonicalizeUrl('http://evil.com/%61dmin')).toBe('evil.com/admin');
    });

    it('handles double-encoded characters', () => {
      // %252e = %2e = .
      expect(canonicalizeUrl('http://evil.com/%252e%252e/')).toBe('evil.com/');
    });

    it('re-encodes spaces consistently', () => {
      expect(canonicalizeUrl('http://evil.com/hello%20world')).toBe('evil.com/hello%20world');
    });

    it('handles mixed encoding', () => {
      // %2e%2e = ..
      expect(canonicalizeUrl('http://evil.com/%2e%2e/secret')).toBe('evil.com/secret');
    });
  });

  describe('query string handling', () => {
    it('ignores query string in HOST_PATH mode (default)', () => {
      expect(canonicalizeUrl('http://evil.com/path?query=value')).toBe('evil.com/path');
    });

    it('includes sorted query string in FULL_URL mode', () => {
      expect(canonicalizeUrl('http://evil.com/path?b=2&a=1', { scope: 'FULL_URL' }))
        .toBe('evil.com/path?a=1&b=2');
    });

    it('sorts duplicate keys by value', () => {
      expect(canonicalizeUrl('http://evil.com/?a=2&a=1', { scope: 'FULL_URL' }))
        .toBe('evil.com/?a=1&a=2');
    });

    it('handles empty query string', () => {
      expect(canonicalizeUrl('http://evil.com/path?', { scope: 'FULL_URL' }))
        .toBe('evil.com/path');
    });
  });

  describe('scope modes', () => {
    it('HOST_ONLY returns just hostname', () => {
      expect(canonicalizeUrl('http://evil.com/path?query', { scope: 'HOST_ONLY' }))
        .toBe('evil.com');
    });

    it('HOST_PATH returns hostname + path', () => {
      expect(canonicalizeUrl('http://evil.com/path?query', { scope: 'HOST_PATH' }))
        .toBe('evil.com/path');
    });

    it('FULL_URL returns hostname + path + query', () => {
      expect(canonicalizeUrl('http://evil.com/path?query=1', { scope: 'FULL_URL' }))
        .toBe('evil.com/path?query=1');
    });
  });

  describe('scheme handling', () => {
    it('includes scheme when requested', () => {
      expect(canonicalizeUrl('http://evil.com/path', { includeScheme: true }))
        .toBe('http://evil.com/path');
      expect(canonicalizeUrl('https://evil.com/path', { includeScheme: true }))
        .toBe('https://evil.com/path');
    });

    it('rejects non-http(s) schemes', () => {
      expect(() => canonicalizeUrl('ftp://evil.com/path')).toThrow('Unsupported scheme');
      expect(() => canonicalizeUrl('javascript:alert(1)')).toThrow('Unsupported scheme');
      expect(() => canonicalizeUrl('file:///etc/passwd')).toThrow('Unsupported scheme');
    });
  });

  describe('edge cases', () => {
    it('ignores fragment', () => {
      expect(canonicalizeUrl('http://evil.com/path#fragment')).toBe('evil.com/path');
    });

    it('ignores credentials', () => {
      expect(canonicalizeUrl('http://user:pass@evil.com/path')).toBe('evil.com/path');
    });

    it('throws on invalid URL', () => {
      expect(() => canonicalizeUrl('not-a-url')).toThrow('Invalid URL');
    });

    it('accepts URL object', () => {
      const url = new URL('http://evil.com/path');
      expect(canonicalizeUrl(url)).toBe('evil.com/path');
    });
  });
});

describe('extractRegistrableDomain', () => {
  it('returns hostname for IP addresses', () => {
    expect(extractRegistrableDomain('192.168.1.1')).toBe('192.168.1.1');
    expect(extractRegistrableDomain('[::1]')).toBe('[::1]');
  });

  it('returns hostname for two-part domains', () => {
    expect(extractRegistrableDomain('example.com')).toBe('example.com');
  });

  it('extracts registrable domain from subdomains', () => {
    expect(extractRegistrableDomain('sub.example.com')).toBe('example.com');
    expect(extractRegistrableDomain('deep.sub.example.com')).toBe('example.com');
  });

  it('handles common two-part TLDs', () => {
    expect(extractRegistrableDomain('sub.example.co.uk')).toBe('example.co.uk');
    expect(extractRegistrableDomain('sub.example.com.au')).toBe('example.com.au');
  });

  it('lowercases and strips trailing dot', () => {
    expect(extractRegistrableDomain('SUB.EXAMPLE.COM.')).toBe('example.com');
  });

  // Issue #127: Public Suffix List edge cases
  describe('PSL edge cases (Issue #127)', () => {
    it('handles country-specific TLDs not in hardcoded list', () => {
      // These would fail with a hardcoded list
      expect(extractRegistrableDomain('evil.co.jp')).toBe('evil.co.jp');
      expect(extractRegistrableDomain('sub.evil.co.jp')).toBe('evil.co.jp');
      expect(extractRegistrableDomain('evil.co.kr')).toBe('evil.co.kr');
      expect(extractRegistrableDomain('evil.com.sg')).toBe('evil.com.sg');
      expect(extractRegistrableDomain('evil.co.za')).toBe('evil.co.za');
    });

    it('handles private suffixes (github.io)', () => {
      // github.io is a private suffix - each subdomain is a registrable domain
      expect(extractRegistrableDomain('user.github.io')).toBe('user.github.io');
      expect(extractRegistrableDomain('project.user.github.io')).toBe('user.github.io');
    });

    it('handles private suffixes (s3.amazonaws.com)', () => {
      // s3.amazonaws.com is a private suffix
      expect(extractRegistrableDomain('bucket.s3.amazonaws.com')).toBe('bucket.s3.amazonaws.com');
    });

    it('handles private suffixes (herokuapp.com)', () => {
      expect(extractRegistrableDomain('myapp.herokuapp.com')).toBe('myapp.herokuapp.com');
    });

    it('handles new gTLDs', () => {
      expect(extractRegistrableDomain('example.app')).toBe('example.app');
      expect(extractRegistrableDomain('sub.example.app')).toBe('example.app');
      expect(extractRegistrableDomain('example.dev')).toBe('example.dev');
      expect(extractRegistrableDomain('example.security')).toBe('example.security');
    });

    it('handles complex multi-part TLDs', () => {
      expect(extractRegistrableDomain('sub.example.gov.uk')).toBe('example.gov.uk');
      expect(extractRegistrableDomain('sub.example.ac.uk')).toBe('example.ac.uk');
      expect(extractRegistrableDomain('sub.example.net.au')).toBe('example.net.au');
    });
  });
});

describe('validateUrl', () => {
  it('returns null for valid http URLs', () => {
    expect(validateUrl('http://example.com')).toBeNull();
  });

  it('returns null for valid https URLs', () => {
    expect(validateUrl('https://example.com/path')).toBeNull();
  });

  it('returns error for unsupported schemes', () => {
    expect(validateUrl('ftp://example.com')).toBe('Unsupported scheme: ftp:');
    expect(validateUrl('javascript:alert(1)')).toBe('Unsupported scheme: javascript:');
  });

  it('returns error for invalid URL format', () => {
    expect(validateUrl('not-a-url')).toBe('Invalid URL format');
  });
});

describe('canonicalizeAndHash', () => {
  it('returns consistent hash for same URL', async () => {
    const hash1 = await canonicalizeAndHash('http://evil.com/path', 'salt123');
    const hash2 = await canonicalizeAndHash('http://evil.com/path', 'salt123');
    expect(hash1).toEqual(hash2);
  });

  it('returns different hash for different URLs', async () => {
    const hash1 = await canonicalizeAndHash('http://evil.com/path1', 'salt123');
    const hash2 = await canonicalizeAndHash('http://evil.com/path2', 'salt123');
    expect(hash1).not.toEqual(hash2);
  });

  it('returns different hash for different salts', async () => {
    const hash1 = await canonicalizeAndHash('http://evil.com/path', 'salt1');
    const hash2 = await canonicalizeAndHash('http://evil.com/path', 'salt2');
    expect(hash1).not.toEqual(hash2);
  });

  it('normalizes URL before hashing', async () => {
    // These should produce the same hash
    const hash1 = await canonicalizeAndHash('http://EVIL.COM/path', 'salt');
    const hash2 = await canonicalizeAndHash('http://evil.com/path', 'salt');
    expect(hash1).toEqual(hash2);
  });

  it('returns Uint8Array of 32 bytes (SHA-256)', async () => {
    const hash = await canonicalizeAndHash('http://evil.com', 'salt');
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });

  it('respects scope option', async () => {
    // HOST_ONLY ignores path, so these should be the same
    const hash1 = await canonicalizeAndHash('http://evil.com/path1', 'salt', { scope: 'HOST_ONLY' });
    const hash2 = await canonicalizeAndHash('http://evil.com/path2', 'salt', { scope: 'HOST_ONLY' });
    expect(hash1).toEqual(hash2);
  });
});

// Test vectors from specification
describe('specification test vectors', () => {
  describe('hostname normalization vectors', () => {
    const vectors: [string, string][] = [
      ['HTTP://EVIL.COM/path', 'evil.com/path'],
      ['http://evil.com./path', 'evil.com/path'],
      ['http://evil.com:80/path', 'evil.com/path'],
      ['https://evil.com:443/path', 'evil.com/path'],
      ['http://evil.com:8080/path', 'evil.com:8080/path'],
      ['http://192.168.1.1/path', '192.168.1.1/path'],
      ['http://[::1]/path', '[::1]/path'],
    ];

    for (const [input, expected] of vectors) {
      it(`${input} → ${expected}`, () => {
        expect(canonicalizeUrl(input)).toBe(expected);
      });
    }
  });

  describe('path normalization vectors', () => {
    const vectors: [string, string][] = [
      ['http://evil.com', 'evil.com/'],
      ['http://evil.com/', 'evil.com/'],
      ['http://evil.com/path/', 'evil.com/path'],
      ['http://evil.com/a/../b', 'evil.com/b'],
      ['http://evil.com/a/./b', 'evil.com/a/b'],
      ['http://evil.com/%2e%2e/secret', 'evil.com/secret'],
      ['http://evil.com/hello%20world', 'evil.com/hello%20world'],
      ['http://evil.com/%61dmin', 'evil.com/admin'],
    ];

    for (const [input, expected] of vectors) {
      it(`${input} → ${expected}`, () => {
        expect(canonicalizeUrl(input)).toBe(expected);
      });
    }
  });

  describe('encoding attack vectors', () => {
    const vectors: [string, string, string][] = [
      ['Case bypass', 'http://EVIL.COM/ADMIN', 'evil.com/ADMIN'],
      ['Trailing dot', 'http://evil.com./', 'evil.com/'],
      ['Percent-encode', 'http://evil.com/%61dmin', 'evil.com/admin'],
      ['Double-encode', 'http://evil.com/%252e%252e/', 'evil.com/'],
      ['Default port', 'http://evil.com:80/', 'evil.com/'],
    ];

    for (const [name, input, expected] of vectors) {
      it(`${name}: ${input} → ${expected}`, () => {
        expect(canonicalizeUrl(input)).toBe(expected);
      });
    }
  });

  describe('edge case vectors', () => {
    it('Query ignored in HOST_PATH scope', () => {
      expect(canonicalizeUrl('http://evil.com?query')).toBe('evil.com/');
    });

    it('Fragment always ignored', () => {
      expect(canonicalizeUrl('http://evil.com#fragment')).toBe('evil.com/');
    });

    it('Query ignored with path in HOST_PATH scope', () => {
      expect(canonicalizeUrl('http://evil.com/path?a=1&b=2')).toBe('evil.com/path');
    });

    it('Double slashes preserved', () => {
      expect(canonicalizeUrl('http://evil.com//double//slash')).toBe('evil.com//double//slash');
    });

    it('Credentials ignored', () => {
      expect(canonicalizeUrl('http://user:pass@evil.com/')).toBe('evil.com/');
    });
  });
});
