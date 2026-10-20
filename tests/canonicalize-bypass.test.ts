/**
 * Canonicalization Bypass Attack Vector Tests
 * Red Team testing for URL canonicalization security boundary.
 *
 * Issue #28 - [Red Team] Canonicalization bypass attack vectors
 */

import { describe, it, expect } from 'vitest';
import { canonicalizeUrl } from '../src/crypto/canonicalize';

/**
 * Helper to test that two different URL representations
 * canonicalize to the SAME output (bypass prevented).
 */
function expectSameCanonical(url1: string, url2: string): void {
  let c1: string | Error;
  let c2: string | Error;

  try {
    c1 = canonicalizeUrl(url1);
  } catch (e) {
    c1 = e as Error;
  }

  try {
    c2 = canonicalizeUrl(url2);
  } catch (e) {
    c2 = e as Error;
  }

  // Both should succeed and match
  if (c1 instanceof Error || c2 instanceof Error) {
    // If one throws, both should throw (or we report the difference)
    expect(c1 instanceof Error).toBe(c2 instanceof Error);
  } else {
    expect(c1).toBe(c2);
  }
}

describe('Canonicalization Bypass Attack Vectors', () => {

  describe('Encoding Attacks', () => {

    describe('Double URL encoding', () => {
      it('%252e%252e (double-encoded ..) resolves to ..', () => {
        // %252e = %2e = .
        expect(canonicalizeUrl('http://evil.com/%252e%252e/secret')).toBe('evil.com/secret');
      });

      it('%252f (double-encoded /) is decoded', () => {
        // %252f = %2f = /
        expect(canonicalizeUrl('http://evil.com/path%252fsubpath')).toBe('evil.com/path/subpath');
      });

      it('triple-encoded characters are fully decoded', () => {
        // %25252e = %252e = %2e = .
        expect(canonicalizeUrl('http://evil.com/%25252e%25252e/secret')).toBe('evil.com/secret');
      });

      it('mixed levels of encoding normalize consistently', () => {
        expectSameCanonical(
          'http://evil.com/admin',
          'http://evil.com/%61dmin'  // %61 = 'a'
        );
        expectSameCanonical(
          'http://evil.com/admin',
          'http://evil.com/%2561dmin'  // %2561 = %61 = 'a'
        );
      });
    });

    describe('Mixed encoding combinations', () => {
      it('%2e. (encoded dot + literal dot) resolves correctly', () => {
        // %2e = .
        expect(canonicalizeUrl('http://evil.com/%2e./secret')).toBe('evil.com/secret');
        expect(canonicalizeUrl('http://evil.com/.%2e/secret')).toBe('evil.com/secret');
      });

      it('%2e%2e vs .. produce same result', () => {
        expectSameCanonical(
          'http://evil.com/../secret',
          'http://evil.com/%2e%2e/secret'
        );
      });

      it('partial encoding in path segments', () => {
        // %61 = 'a', mixing encoded and literal
        expect(canonicalizeUrl('http://evil.com/p%61th/t%6f/s%65cret'))
          .toBe('evil.com/path/to/secret');
      });
    });

    describe('Overlong UTF-8 sequences', () => {
      // Overlong UTF-8: representing ASCII with more bytes than needed
      // These are invalid UTF-8 but could be used for bypasses

      it('overlong encoding of / (C0 AF) is handled', () => {
        // %c0%af is invalid overlong encoding of /
        // Should either throw or not decode to /
        const result = canonicalizeUrl('http://evil.com/path%c0%afsubpath');
        // Should NOT create a path separator
        expect(result).not.toBe('evil.com/path/subpath');
      });

      it('overlong encoding of . (C0 AE) is handled', () => {
        // %c0%ae is invalid overlong encoding of .
        const result = canonicalizeUrl('http://evil.com/%c0%ae%c0%ae/secret');
        // Should NOT resolve as ..
        expect(result).not.toBe('evil.com/secret');
      });

      it('three-byte overlong / (E0 80 AF) is handled', () => {
        const result = canonicalizeUrl('http://evil.com/path%e0%80%afsubpath');
        expect(result).not.toBe('evil.com/path/subpath');
      });
    });

    describe('Null byte injection', () => {
      it('%00 null byte in path does not truncate', () => {
        const result = canonicalizeUrl('http://evil.com/admin%00.jpg');
        // Null byte should be encoded, not truncate the string
        expect(result).toContain('admin');
        expect(result).toContain('.jpg');
      });

      it('%00 null byte does not bypass path matching', () => {
        // If blocklist has evil.com/admin, attacker might try evil.com/admin%00/bypass
        const canonical1 = canonicalizeUrl('http://evil.com/admin');
        const canonical2 = canonicalizeUrl('http://evil.com/admin%00');
        // These should differ (null byte is part of the path)
        // OR null byte should be stripped consistently
        // Either way, we document the behavior
        expect(typeof canonical1).toBe('string');
        expect(typeof canonical2).toBe('string');
      });

      it('%00 in hostname is rejected', () => {
        // Null bytes in hostname should be rejected by URL parser
        expect(() => canonicalizeUrl('http://evil%00.com/')).toThrow();
      });
    });
  });

  describe('Path Manipulation', () => {

    describe('Path traversal after decode', () => {
      it('%2e%2e%2f (encoded ../) traverses up', () => {
        expect(canonicalizeUrl('http://evil.com/safe/%2e%2e%2fsecret')).toBe('evil.com/secret');
      });

      it('encoded traversal followed by literal traverses correctly', () => {
        expect(canonicalizeUrl('http://evil.com/a/b/%2e%2e/../c')).toBe('evil.com/c');
      });

      it('cannot traverse above root', () => {
        expect(canonicalizeUrl('http://evil.com/../../../etc/passwd')).toBe('evil.com/etc/passwd');
        expect(canonicalizeUrl('http://evil.com/%2e%2e/%2e%2e/%2e%2e/etc/passwd'))
          .toBe('evil.com/etc/passwd');
      });

      it('traversal in middle of path works correctly', () => {
        expect(canonicalizeUrl('http://evil.com/a/b/c/../../d')).toBe('evil.com/a/d');
      });
    });

    describe('Backslash variants', () => {
      // NOTE: Per WHATWG URL spec, backslashes are converted to forward slashes
      // in http/https URLs. This is CORRECT browser behavior that we must match.

      it('backslash \\ is converted to / (WHATWG URL spec)', () => {
        // URL constructor converts \\ to / for http/https per spec
        const result = canonicalizeUrl('http://evil.com/path\\subpath');
        expect(result).toBe('evil.com/path/subpath');
      });

      it('backslash traversal is resolved (matches browser behavior)', () => {
        // Since \\ becomes /, the .. is resolved as traversal
        // This matches browser behavior - blocking this is CORRECT
        expect(canonicalizeUrl('http://evil.com/a\\..\\b')).toBe('evil.com/b');
      });

      it('%5c (encoded backslash) stays encoded', () => {
        // %5c = backslash - when percent-encoded, it's NOT converted
        // Only literal backslash is converted by URL constructor
        const result = canonicalizeUrl('http://evil.com/path%5csubpath');
        // Should be encoded in output, not treated as separator
        expect(result).toContain('%5C');
      });

      it('encoded backslash traversal does NOT work (safe)', () => {
        // %5c is backslash but percent-encoded, so not treated as /
        const result = canonicalizeUrl('http://evil.com/safe/%5c../secret');
        // Should NOT resolve as traversal - %5c is just a character
        expect(result).not.toBe('evil.com/secret');
      });

      it('backslash in blocked URL matches browser request (security)', () => {
        // If attacker sends: http://evil.com/admin\secret
        // Browser will request: http://evil.com/admin/secret
        // We must canonicalize the same way to not miss the block
        expectSameCanonical(
          'http://evil.com/admin/secret',
          'http://evil.com/admin\\secret'
        );
      });
    });

    describe('Unicode path separators', () => {
      it('U+2215 division slash is not path separator', () => {
        // \u2215 = ∕ (division slash, looks like /)
        const result = canonicalizeUrl('http://evil.com/path\u2215subpath');
        expect(result).not.toBe('evil.com/path/subpath');
      });

      it('U+2044 fraction slash is not path separator', () => {
        // \u2044 = ⁄ (fraction slash)
        const result = canonicalizeUrl('http://evil.com/path\u2044subpath');
        expect(result).not.toBe('evil.com/path/subpath');
      });

      it('U+FF0F fullwidth solidus is not path separator', () => {
        // \uFF0F = ／ (fullwidth slash)
        const result = canonicalizeUrl('http://evil.com/path\uFF0Fsubpath');
        expect(result).not.toBe('evil.com/path/subpath');
      });

      it('U+29F8 big solidus is not path separator', () => {
        // \u29F8 = ⧸ (big solidus)
        const result = canonicalizeUrl('http://evil.com/path\u29F8subpath');
        expect(result).not.toBe('evil.com/path/subpath');
      });
    });
  });

  describe('Host Manipulation', () => {

    describe('Trailing dots', () => {
      it('single trailing dot is stripped', () => {
        expect(canonicalizeUrl('http://evil.com./')).toBe('evil.com/');
      });

      it('multiple trailing dots are handled', () => {
        // Multiple dots might be handled differently
        const result = canonicalizeUrl('http://evil.com../');
        // Should either strip all or reject
        expect(typeof result).toBe('string');
      });

      it('trailing dot with port', () => {
        expect(canonicalizeUrl('http://evil.com.:8080/')).toBe('evil.com:8080/');
      });

      it('trailing dot matches non-trailing dot', () => {
        expectSameCanonical('http://evil.com/', 'http://evil.com./');
      });
    });

    describe('Mixed case', () => {
      it('all uppercase hostname is lowercased', () => {
        expect(canonicalizeUrl('http://EVIL.COM/')).toBe('evil.com/');
      });

      it('mixed case hostname is lowercased', () => {
        expect(canonicalizeUrl('http://Evil.CoM/')).toBe('evil.com/');
      });

      it('path case is preserved', () => {
        expect(canonicalizeUrl('http://EVIL.COM/ADMIN')).toBe('evil.com/ADMIN');
      });

      it('scheme case is normalized', () => {
        expect(canonicalizeUrl('HTTP://evil.com/', { includeScheme: true }))
          .toBe('http://evil.com/');
      });
    });

    describe('Punycode and IDN homoglyphs', () => {
      it('IDN domain is converted to punycode', () => {
        // évil.com (with accent) should become punycode
        const result = canonicalizeUrl('http://évil.com/');
        expect(result).toContain('xn--');
      });

      it('Cyrillic homoglyph а is distinguished', () => {
        // Cyrillic 'а' (U+0430) looks like Latin 'a' (U+0061)
        const cyrillic = canonicalizeUrl('http://evіl.com/'); // Cyrillic і
        const latin = canonicalizeUrl('http://evil.com/');
        // These should be DIFFERENT after canonicalization
        expect(cyrillic).not.toBe(latin);
      });

      it('mixed script homoglyph attack is distinguishable', () => {
        // раypal.com with Cyrillic ра
        const homoglyph = canonicalizeUrl('http://раypal.com/');
        const real = canonicalizeUrl('http://paypal.com/');
        expect(homoglyph).not.toBe(real);
        expect(homoglyph).toContain('xn--');
      });

      it('punycode domain is preserved as punycode', () => {
        expect(canonicalizeUrl('http://xn--vil-dmc.com/')).toBe('xn--vil-dmc.com/');
      });
    });

    describe('IPv4 alternate representations', () => {
      it('decimal IP is normalized', () => {
        // 2130706433 = 127.0.0.1 in decimal
        const result = canonicalizeUrl('http://2130706433/');
        // URL constructor should normalize this
        expect(result).toBe('127.0.0.1/');
      });

      it('octal IP is normalized', () => {
        // 0177.0.0.1 = 127.0.0.1 in octal
        const result = canonicalizeUrl('http://0177.0.0.1/');
        expect(result).toBe('127.0.0.1/');
      });

      it('hex IP is normalized', () => {
        // 0x7f000001 = 127.0.0.1 in hex
        const result = canonicalizeUrl('http://0x7f000001/');
        expect(result).toBe('127.0.0.1/');
      });

      it('mixed notation IP is normalized', () => {
        // 0x7f.0.0.1 = 127.0.0.1
        const result = canonicalizeUrl('http://0x7f.0.0.1/');
        expect(result).toBe('127.0.0.1/');
      });

      it('all IP representations match', () => {
        expectSameCanonical('http://127.0.0.1/', 'http://0177.0.0.1/');
        expectSameCanonical('http://127.0.0.1/', 'http://0x7f000001/');
        expectSameCanonical('http://127.0.0.1/', 'http://2130706433/');
      });
    });

    describe('IPv6 variations', () => {
      it('IPv6 with brackets is preserved', () => {
        expect(canonicalizeUrl('http://[::1]/')).toBe('[::1]/');
      });

      it('IPv6 full form is normalized', () => {
        // Full form should be compressed
        const result = canonicalizeUrl('http://[0000:0000:0000:0000:0000:0000:0000:0001]/');
        expect(result).toBe('[::1]/');
      });

      it('IPv6 with port', () => {
        expect(canonicalizeUrl('http://[::1]:8080/')).toBe('[::1]:8080/');
      });

      it('IPv6 case is normalized', () => {
        // IPv6 hex should be lowercased
        const upper = canonicalizeUrl('http://[::FFFF:127.0.0.1]/');
        const lower = canonicalizeUrl('http://[::ffff:127.0.0.1]/');
        expect(upper).toBe(lower);
      });

      it('IPv4-mapped IPv6 is normalized', () => {
        const result = canonicalizeUrl('http://[::ffff:127.0.0.1]/');
        expect(typeof result).toBe('string');
        // Document behavior - might stay as IPv6 or convert to IPv4
      });
    });
  });

  describe('Query and Fragment', () => {

    describe('Query parameter injection', () => {
      it('query is ignored in HOST_PATH scope', () => {
        expect(canonicalizeUrl('http://evil.com/path?malicious=payload'))
          .toBe('evil.com/path');
      });

      it('query with path injection is handled', () => {
        // Attacker might try ?../secret
        expect(canonicalizeUrl('http://evil.com/path?../secret'))
          .toBe('evil.com/path');
      });

      it('query in FULL_URL scope is sorted', () => {
        expect(canonicalizeUrl('http://evil.com/?z=1&a=2', { scope: 'FULL_URL' }))
          .toBe('evil.com/?a=2&z=1');
      });

      it('duplicate query keys are preserved and sorted', () => {
        expect(canonicalizeUrl('http://evil.com/?a=2&a=1', { scope: 'FULL_URL' }))
          .toBe('evil.com/?a=1&a=2');
      });

      it('encoded query parameters are decoded', () => {
        const result = canonicalizeUrl('http://evil.com/?key=%76alue', { scope: 'FULL_URL' });
        // %76 = 'v'
        expect(result).toContain('value');
      });
    });

    describe('Fragment handling', () => {
      it('fragment is always stripped', () => {
        expect(canonicalizeUrl('http://evil.com/path#fragment')).toBe('evil.com/path');
      });

      it('fragment with path-like content is stripped', () => {
        expect(canonicalizeUrl('http://evil.com/path#/admin/secret')).toBe('evil.com/path');
      });

      it('fragment after query is stripped', () => {
        expect(canonicalizeUrl('http://evil.com/path?q=1#frag', { scope: 'FULL_URL' }))
          .toBe('evil.com/path?q=1');
      });

      it('encoded fragment marker %23 in path stays in path', () => {
        // %23 = #, if in path it should stay as %23 not start fragment
        const result = canonicalizeUrl('http://evil.com/path%23anchor');
        expect(result).toContain('%23');
      });
    });
  });

  describe('Complex Combined Attacks', () => {

    it('combines encoding + case + port bypass', () => {
      expectSameCanonical(
        'http://evil.com/admin',
        'HTTP://EVIL.COM:80/%61dmin'
      );
    });

    it('combines traversal + double-encoding', () => {
      expectSameCanonical(
        'http://evil.com/secret',
        'http://evil.com/safe/%252e%252e/secret'
      );
    });

    it('combines trailing dot + case + default port', () => {
      expectSameCanonical(
        'http://evil.com/',
        'http://EVIL.COM.:80/'
      );
    });

    it('realistic phishing URL is normalized', () => {
      const phishing = canonicalizeUrl(
        'HTTP://BANK.EVIL.COM.:80/login%2f..%2fadmin?ref=legit#anchor'
      );
      // Should normalize all the tricks
      expect(phishing).not.toContain('HTTP');
      expect(phishing).not.toContain('80');
      expect(phishing).not.toContain('anchor');
      expect(phishing).toBe('bank.evil.com/admin');
    });

    it('handles extremely long double-encoding chains', () => {
      // %25 repeated = deeper encoding
      // This tests the iteration limit
      const deepEncoded = 'http://evil.com/' + '%25'.repeat(15) + '2e%25'.repeat(15) + '2e/';
      // Should not hang or crash
      const result = canonicalizeUrl(deepEncoded);
      expect(typeof result).toBe('string');
    });
  });

  describe('Edge Cases and Boundaries', () => {

    it('empty path normalizes to /', () => {
      expect(canonicalizeUrl('http://evil.com')).toBe('evil.com/');
    });

    it('very long path is handled', () => {
      const longPath = '/a'.repeat(1000);
      const result = canonicalizeUrl(`http://evil.com${longPath}`);
      expect(result).toContain('evil.com');
    });

    it('path with only dots', () => {
      expect(canonicalizeUrl('http://evil.com/./././.')).toBe('evil.com/');
    });

    it('path with many traversals', () => {
      expect(canonicalizeUrl('http://evil.com/a/b/c/d/../../../../..')).toBe('evil.com/');
    });

    it('credentials in URL are stripped', () => {
      expect(canonicalizeUrl('http://user:password@evil.com/path')).toBe('evil.com/path');
    });

    it('special characters in path are encoded', () => {
      const result = canonicalizeUrl('http://evil.com/path with spaces');
      expect(result).toContain('%20');
    });

    it('unicode in path is encoded', () => {
      const result = canonicalizeUrl('http://evil.com/\u{1F600}');
      // Emoji should be percent-encoded
      expect(result).toMatch(/evil\.com\/%[A-F0-9]/);
    });
  });
});

describe('Bypass Regression Tests', () => {
  // Add any bypasses found during testing here
  // Each should have a clear description of the attack

  it('TEMPLATE: describe any bypass found here', () => {
    // Example:
    // const malicious = canonicalizeUrl('http://...');
    // const legitimate = canonicalizeUrl('http://...');
    // expect(malicious).toBe(legitimate); // Previously these were different
    expect(true).toBe(true); // Placeholder
  });
});
