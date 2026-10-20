/**
 * Unit tests for BrowserDefense SHA-256 hashing module.
 */

import { describe, it, expect } from 'vitest';
import {
  sha256,
  sha256Bytes,
  hexToBytes,
  bytesToHex,
  canonicalizeUrl,
  hashIOC,
  hashIOCBytes,
  hashIOCBatch,
  TEST_SALT,
  TEST_SALT_ALT,
} from '../helpers/hashing';

describe('hexToBytes', () => {
  it('converts hex string to bytes', () => {
    const bytes = hexToBytes('deadbeef');
    expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it('handles empty string', () => {
    const bytes = hexToBytes('');
    expect(bytes).toEqual(new Uint8Array([]));
  });

  it('handles lowercase hex', () => {
    const bytes = hexToBytes('abcdef');
    expect(bytes).toEqual(new Uint8Array([0xab, 0xcd, 0xef]));
  });

  it('handles uppercase hex', () => {
    const bytes = hexToBytes('ABCDEF');
    expect(bytes).toEqual(new Uint8Array([0xab, 0xcd, 0xef]));
  });
});

describe('bytesToHex', () => {
  it('converts bytes to hex string', () => {
    const hex = bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    expect(hex).toBe('deadbeef');
  });

  it('handles empty array', () => {
    const hex = bytesToHex(new Uint8Array([]));
    expect(hex).toBe('');
  });

  it('pads single-digit hex values', () => {
    const hex = bytesToHex(new Uint8Array([0x00, 0x01, 0x0f]));
    expect(hex).toBe('00010f');
  });
});

describe('sha256', () => {
  it('hashes empty string correctly', async () => {
    const hash = await sha256('');
    // SHA-256 of empty string is well-known
    expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('hashes "hello" correctly', async () => {
    const hash = await sha256('hello');
    expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });

  it('hashes Uint8Array correctly', async () => {
    const hash = await sha256(new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f])); // "hello"
    expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });

  it('returns 64-character hex string', async () => {
    const hash = await sha256('test');
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]+$/);
  });
});

describe('sha256Bytes', () => {
  it('returns 32-byte Uint8Array', async () => {
    const bytes = await sha256Bytes('hello');
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes).toHaveLength(32);
  });

  it('matches sha256 hex output', async () => {
    const bytes = await sha256Bytes('hello');
    const hex = bytesToHex(bytes);
    const directHex = await sha256('hello');
    expect(hex).toBe(directHex);
  });
});

describe('canonicalizeUrl', () => {
  describe('HOST_ONLY scope', () => {
    it('lowercases host', () => {
      expect(canonicalizeUrl('https://EXAMPLE.COM/path', 'HOST_ONLY')).toBe('https://example.com');
    });

    it('removes trailing dot', () => {
      expect(canonicalizeUrl('https://example.com./', 'HOST_ONLY')).toBe('https://example.com');
    });

    it('removes default HTTPS port', () => {
      expect(canonicalizeUrl('https://example.com:443/path', 'HOST_ONLY')).toBe(
        'https://example.com'
      );
    });

    it('removes default HTTP port', () => {
      expect(canonicalizeUrl('http://example.com:80/path', 'HOST_ONLY')).toBe('http://example.com');
    });

    it('preserves non-default port', () => {
      expect(canonicalizeUrl('https://example.com:8443/path', 'HOST_ONLY')).toBe(
        'https://example.com:8443'
      );
    });

    it('handles subdomains', () => {
      expect(canonicalizeUrl('https://WWW.EXAMPLE.COM/path', 'HOST_ONLY')).toBe(
        'https://www.example.com'
      );
    });
  });

  describe('HOST_PATH scope', () => {
    it('includes normalized path', () => {
      expect(canonicalizeUrl('https://example.com/foo/bar', 'HOST_PATH')).toBe(
        'https://example.com/foo/bar'
      );
    });

    it('normalizes path encoding', () => {
      expect(canonicalizeUrl('https://example.com/foo%20bar', 'HOST_PATH')).toBe(
        'https://example.com/foo%20bar'
      );
    });

    it('adds trailing slash for root', () => {
      expect(canonicalizeUrl('https://example.com', 'HOST_PATH')).toBe('https://example.com/');
    });

    it('excludes query string', () => {
      expect(canonicalizeUrl('https://example.com/path?foo=bar', 'HOST_PATH')).toBe(
        'https://example.com/path'
      );
    });
  });

  describe('FULL_URL scope', () => {
    it('includes sorted query params', () => {
      expect(canonicalizeUrl('https://example.com/path?z=1&a=2', 'FULL_URL')).toBe(
        'https://example.com/path?a=2&z=1'
      );
    });

    it('excludes fragment', () => {
      expect(canonicalizeUrl('https://example.com/path?a=1#section', 'FULL_URL')).toBe(
        'https://example.com/path?a=1'
      );
    });

    it('handles no query params', () => {
      expect(canonicalizeUrl('https://example.com/path', 'FULL_URL')).toBe(
        'https://example.com/path'
      );
    });
  });

  describe('edge cases', () => {
    it('handles invalid URL by returning lowercase', () => {
      expect(canonicalizeUrl('not-a-url', 'HOST_ONLY')).toBe('not-a-url');
    });

    it('handles IP addresses', () => {
      expect(canonicalizeUrl('http://192.168.1.1/path', 'HOST_ONLY')).toBe('http://192.168.1.1');
    });
  });
});

describe('hashIOC', () => {
  // Use shared TEST_SALT constant from helpers

  it('produces consistent hashes', async () => {
    const hash1 = await hashIOC('https://example.com', TEST_SALT);
    const hash2 = await hashIOC('https://example.com', TEST_SALT);
    expect(hash1).toBe(hash2);
  });

  it('produces different hashes for different IOCs', async () => {
    const hash1 = await hashIOC('https://example.com', TEST_SALT);
    const hash2 = await hashIOC('https://different.com', TEST_SALT);
    expect(hash1).not.toBe(hash2);
  });

  it('produces different hashes for different salts', async () => {
    const hash1 = await hashIOC('https://example.com', TEST_SALT);
    const hash2 = await hashIOC('https://example.com', TEST_SALT_ALT);
    expect(hash1).not.toBe(hash2);
  });

  it('normalizes URLs before hashing', async () => {
    const hash1 = await hashIOC('https://EXAMPLE.COM', TEST_SALT);
    const hash2 = await hashIOC('https://example.com', TEST_SALT);
    expect(hash1).toBe(hash2);
  });

  it('respects scope parameter', async () => {
    const hashHost = await hashIOC('https://example.com/path', TEST_SALT, 'HOST_ONLY');
    const hashPath = await hashIOC('https://example.com/path', TEST_SALT, 'HOST_PATH');
    expect(hashHost).not.toBe(hashPath);
  });

  it('returns 64-character hex string', async () => {
    const hash = await hashIOC('https://example.com', TEST_SALT);
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]+$/);
  });
});

describe('hashIOCBytes', () => {
  // Use shared TEST_SALT constant from helpers

  it('returns 32-byte Uint8Array', async () => {
    const bytes = await hashIOCBytes('https://example.com', TEST_SALT);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes).toHaveLength(32);
  });

  it('matches hashIOC hex output', async () => {
    const bytes = await hashIOCBytes('https://example.com', TEST_SALT);
    const hex = bytesToHex(bytes);
    const directHex = await hashIOC('https://example.com', TEST_SALT);
    expect(hex).toBe(directHex);
  });
});

describe('hashIOCBatch', () => {
  // Use shared TEST_SALT constant from helpers

  it('hashes multiple IOCs', async () => {
    const iocs = ['https://example.com', 'https://evil.com', 'https://test.com'];
    const results = await hashIOCBatch(iocs, TEST_SALT);

    expect(results.size).toBe(3);
    expect(results.has('https://example.com')).toBe(true);
    expect(results.has('https://evil.com')).toBe(true);
    expect(results.has('https://test.com')).toBe(true);
  });

  it('produces same hashes as individual hashIOC calls', async () => {
    const iocs = ['https://example.com', 'https://evil.com'];
    const batchResults = await hashIOCBatch(iocs, TEST_SALT);

    for (const ioc of iocs) {
      const individualHash = await hashIOC(ioc, TEST_SALT);
      expect(batchResults.get(ioc)).toBe(individualHash);
    }
  });

  it('handles empty array', async () => {
    const results = await hashIOCBatch([], TEST_SALT);
    expect(results.size).toBe(0);
  });
});
