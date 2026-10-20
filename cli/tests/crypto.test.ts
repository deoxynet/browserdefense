import { describe, it, expect } from 'vitest';
import {
  generateSigningKeypair,
  generateSigningKeypairEd25519,
  generateEncryptionKeypair,
  generateSalt,
  generateOrgId,
  sign,
  verify,
  signEd25519,
  verifyEd25519,
  signP256,
  verifyP256,
  signManifest,
  verifyManifest,
  detectAlgorithm,
  sha256,
  canonicalizeUrl,
  hashIOC,
  hexToBytes,
  bytesToHex,
  encryptForensics,
  decryptForensics,
  type BlocklistManifest,
  type EncryptedPayload,
  type Ed25519PublicKeyJWK,
  type Ed25519PrivateKeyJWK,
  type ECPublicKeyJWK,
  type ECPrivateKeyJWK,
} from '../src/crypto.js';

describe('Key Generation', () => {
  describe('P-256 ECDSA (default)', () => {
    it('should generate P-256 signing keypair', async () => {
      const { publicKey, privateKey } = await generateSigningKeypair();

      expect(publicKey.kty).toBe('EC');
      expect(publicKey.crv).toBe('P-256');
      expect(publicKey.x).toBeDefined();
      expect(publicKey.y).toBeDefined();

      expect(privateKey.kty).toBe('EC');
      expect(privateKey.crv).toBe('P-256');
      expect(privateKey.d).toBeDefined();
    });

    it('should detect P-256 algorithm', async () => {
      const { publicKey } = await generateSigningKeypair();
      expect(detectAlgorithm(publicKey)).toBe('p256-v1');
    });
  });

  describe('Ed25519 (experimental)', () => {
    it('should generate Ed25519 signing keypair', async () => {
      const { publicKey, privateKey } = await generateSigningKeypairEd25519();

      expect(publicKey.kty).toBe('OKP');
      expect(publicKey.crv).toBe('Ed25519');
      expect(publicKey.x).toBeDefined();

      expect(privateKey.kty).toBe('OKP');
      expect(privateKey.crv).toBe('Ed25519');
      expect(privateKey.d).toBeDefined();
    });

    it('should detect Ed25519 algorithm', async () => {
      const { publicKey } = await generateSigningKeypairEd25519();
      expect(detectAlgorithm(publicKey)).toBe('ed25519-v2');
    });
  });

  it('should generate RSA-OAEP encryption keypair', async () => {
    const { publicKey, privateKey } = await generateEncryptionKeypair();

    expect(publicKey.kty).toBe('RSA');
    expect(publicKey.n).toBeDefined();
    expect(publicKey.e).toBeDefined();

    expect(privateKey.kty).toBe('RSA');
    expect(privateKey.d).toBeDefined();
    expect(privateKey.p).toBeDefined();
    expect(privateKey.q).toBeDefined();
  });

  it('should generate random salt', () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();

    expect(salt1).toBeDefined();
    expect(salt1.length).toBeGreaterThan(0);
    expect(salt1).not.toBe(salt2);
  });

  it('should generate random org ID (UUID)', () => {
    const orgId = generateOrgId();

    // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    expect(orgId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });
});

describe('Signing and Verification', () => {
  describe('Ed25519', () => {
    it('should sign and verify data', async () => {
      const { publicKey, privateKey } = await generateSigningKeypairEd25519();
      const data = 'Hello, BrowserDefense!';

      const signature = await signEd25519(data, privateKey);
      const isValid = await verifyEd25519(data, signature, publicKey);

      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong data', async () => {
      const { publicKey, privateKey } = await generateSigningKeypairEd25519();
      const data = 'Hello, BrowserDefense!';

      const signature = await signEd25519(data, privateKey);
      const isValid = await verifyEd25519('Different data', signature, publicKey);

      expect(isValid).toBe(false);
    });

    it('should fail verification with wrong key', async () => {
      const keypair1 = await generateSigningKeypairEd25519();
      const keypair2 = await generateSigningKeypairEd25519();
      const data = 'Hello, BrowserDefense!';

      const signature = await signEd25519(data, keypair1.privateKey);
      const isValid = await verifyEd25519(data, signature, keypair2.publicKey);

      expect(isValid).toBe(false);
    });
  });

  describe('P-256', () => {
    it('should sign and verify data', async () => {
      const { publicKey, privateKey } = await generateSigningKeypair();
      const data = 'Hello, BrowserDefense!';

      const signature = await signP256(data, privateKey);
      const isValid = await verifyP256(data, signature, publicKey);

      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong data', async () => {
      const { publicKey, privateKey } = await generateSigningKeypair();
      const data = 'Hello, BrowserDefense!';

      const signature = await signP256(data, privateKey);
      const isValid = await verifyP256('Different data', signature, publicKey);

      expect(isValid).toBe(false);
    });

    it('should fail verification with wrong key', async () => {
      const keypair1 = await generateSigningKeypair();
      const keypair2 = await generateSigningKeypair();
      const data = 'Hello, BrowserDefense!';

      const signature = await signP256(data, keypair1.privateKey);
      const isValid = await verifyP256(data, signature, keypair2.publicKey);

      expect(isValid).toBe(false);
    });
  });

  describe('Unified sign/verify (auto-detect)', () => {
    it('should sign and verify P-256 data', async () => {
      const { publicKey, privateKey } = await generateSigningKeypair();
      const data = 'Hello, BrowserDefense!';

      const signature = await sign(data, privateKey);
      const isValid = await verify(data, signature, publicKey);

      expect(isValid).toBe(true);
    });

    it('should sign and verify Ed25519 data', async () => {
      const { publicKey, privateKey } = await generateSigningKeypairEd25519();
      const data = 'Hello, BrowserDefense!';

      const signature = await sign(data, privateKey);
      const isValid = await verify(data, signature, publicKey);

      expect(isValid).toBe(true);
    });
  });

  describe('Manifest signing', () => {
    it('should sign and verify manifest with P-256', async () => {
      const { publicKey, privateKey } = await generateSigningKeypair();

      const manifest: Omit<BlocklistManifest, 'signature'> = {
        version: 1,
        total_iocs: 100,
        bucket_count: 1,
        sha256_root: 'abc123',
      };

      const signedManifest = await signManifest(manifest, privateKey);
      expect(signedManifest.signature).toBeDefined();
      expect(signedManifest.algorithm_version).toBe('p256-v1');

      const isValid = await verifyManifest(signedManifest, publicKey);
      expect(isValid).toBe(true);
    });

    it('should sign and verify manifest with Ed25519', async () => {
      const { publicKey, privateKey } = await generateSigningKeypairEd25519();

      const manifest: Omit<BlocklistManifest, 'signature'> = {
        version: 1,
        total_iocs: 100,
        bucket_count: 1,
        sha256_root: 'abc123',
      };

      const signedManifest = await signManifest(manifest, privateKey);
      expect(signedManifest.signature).toBeDefined();
      expect(signedManifest.algorithm_version).toBe('ed25519-v2');

      const isValid = await verifyManifest(signedManifest, publicKey);
      expect(isValid).toBe(true);
    });

    it('should fail manifest verification if tampered', async () => {
      const { publicKey, privateKey } = await generateSigningKeypair();

      const manifest: Omit<BlocklistManifest, 'signature'> = {
        version: 1,
        total_iocs: 100,
        bucket_count: 1,
        sha256_root: 'abc123',
      };

      const signedManifest = await signManifest(manifest, privateKey);

      // Tamper with the manifest
      signedManifest.total_iocs = 200;

      const isValid = await verifyManifest(signedManifest, publicKey);
      expect(isValid).toBe(false);
    });
  });
});

describe('Hashing', () => {
  it('should compute SHA-256 hash', () => {
    const hash = sha256('test');
    expect(hash).toBe('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
  });

  it('should convert hex to bytes and back', () => {
    const hex = 'deadbeef';
    const bytes = hexToBytes(hex);
    const backToHex = bytesToHex(bytes);

    expect(backToHex).toBe(hex);
    expect(bytes).toEqual(Buffer.from([0xde, 0xad, 0xbe, 0xef]));
  });
});

describe('URL Canonicalization', () => {
  describe('hostname normalization', () => {
    it('should lowercase host', () => {
      // Default: no scheme in output
      expect(canonicalizeUrl('https://EXAMPLE.COM')).toBe('example.com');
    });

    it('should remove trailing dot', () => {
      expect(canonicalizeUrl('https://example.com.')).toBe('example.com');
    });

    it('should remove default ports', () => {
      expect(canonicalizeUrl('https://example.com:443')).toBe('example.com');
      expect(canonicalizeUrl('http://example.com:80')).toBe('example.com');
    });

    it('should keep non-default ports', () => {
      expect(canonicalizeUrl('https://example.com:8443')).toBe('example.com:8443');
    });
  });

  describe('path normalization', () => {
    it('should include path for HOST_PATH scope', () => {
      expect(canonicalizeUrl('https://example.com/path/to/resource', 'HOST_PATH')).toBe(
        'example.com/path/to/resource'
      );
    });

    it('should remove trailing slash for non-root paths', () => {
      expect(canonicalizeUrl('https://example.com/path/', 'HOST_PATH')).toBe('example.com/path');
    });

    it('should keep trailing slash for root path', () => {
      expect(canonicalizeUrl('https://example.com/', 'HOST_PATH')).toBe('example.com/');
    });

    it('should add slash for empty path', () => {
      expect(canonicalizeUrl('https://example.com', 'HOST_PATH')).toBe('example.com/');
    });

    it('should resolve dot segments', () => {
      expect(canonicalizeUrl('https://example.com/a/../b', 'HOST_PATH')).toBe('example.com/b');
      expect(canonicalizeUrl('https://example.com/a/./b', 'HOST_PATH')).toBe('example.com/a/b');
    });

    it('should resolve encoded dot segments', () => {
      // %2e = .
      expect(canonicalizeUrl('https://example.com/%2e%2e/secret', 'HOST_PATH')).toBe(
        'example.com/secret'
      );
    });
  });

  describe('iterative decoding (double-encoding protection)', () => {
    it('should decode double-encoded paths', () => {
      // %252e = %2e (after first decode) = . (after second decode)
      expect(canonicalizeUrl('https://example.com/%252e%252e/', 'HOST_PATH')).toBe('example.com/');
    });

    it('should decode triple-encoded paths', () => {
      // %25252e = %252e = %2e = .
      expect(canonicalizeUrl('https://example.com/%25252e%25252e/', 'HOST_PATH')).toBe(
        'example.com/'
      );
    });

    it('should decode percent-encoded characters', () => {
      // %61 = 'a'
      expect(canonicalizeUrl('https://example.com/%61dmin', 'HOST_PATH')).toBe('example.com/admin');
    });
  });

  describe('query string normalization', () => {
    it('should sort query params for FULL_URL scope', () => {
      expect(canonicalizeUrl('https://example.com/path?z=1&a=2', 'FULL_URL')).toBe(
        'example.com/path?a=2&z=1'
      );
    });

    it('should ignore query for HOST_PATH scope', () => {
      expect(canonicalizeUrl('https://example.com/path?query=1', 'HOST_PATH')).toBe(
        'example.com/path'
      );
    });
  });

  describe('includeScheme option', () => {
    it('should exclude scheme by default', () => {
      expect(canonicalizeUrl('https://example.com')).toBe('example.com');
    });

    it('should include scheme when requested', () => {
      expect(
        canonicalizeUrl('https://example.com', { scope: 'HOST_ONLY', includeScheme: true })
      ).toBe('https://example.com');
      expect(
        canonicalizeUrl('https://example.com/path', { scope: 'HOST_PATH', includeScheme: true })
      ).toBe('https://example.com/path');
    });
  });

  describe('spec test vectors', () => {
    // From docs/Canonicalization_Specification.md
    it('should handle hostname test vectors', () => {
      expect(canonicalizeUrl('HTTP://EVIL.COM/path', 'HOST_PATH')).toBe('evil.com/path');
      expect(canonicalizeUrl('http://evil.com./path', 'HOST_PATH')).toBe('evil.com/path');
      expect(canonicalizeUrl('http://evil.com:80/path', 'HOST_PATH')).toBe('evil.com/path');
      expect(canonicalizeUrl('https://evil.com:443/path', 'HOST_PATH')).toBe('evil.com/path');
      expect(canonicalizeUrl('http://evil.com:8080/path', 'HOST_PATH')).toBe('evil.com:8080/path');
    });

    it('should handle path test vectors', () => {
      expect(canonicalizeUrl('http://evil.com', 'HOST_PATH')).toBe('evil.com/');
      expect(canonicalizeUrl('http://evil.com/', 'HOST_PATH')).toBe('evil.com/');
      expect(canonicalizeUrl('http://evil.com/path/', 'HOST_PATH')).toBe('evil.com/path');
      expect(canonicalizeUrl('http://evil.com/a/../b', 'HOST_PATH')).toBe('evil.com/b');
      expect(canonicalizeUrl('http://evil.com/a/./b', 'HOST_PATH')).toBe('evil.com/a/b');
      expect(canonicalizeUrl('http://evil.com/%2e%2e/secret', 'HOST_PATH')).toBe('evil.com/secret');
      expect(canonicalizeUrl('http://evil.com/%61dmin', 'HOST_PATH')).toBe('evil.com/admin');
    });

    it('should handle encoding attack test vectors', () => {
      // Case bypass
      expect(canonicalizeUrl('http://EVIL.COM/ADMIN', 'HOST_PATH')).toBe('evil.com/ADMIN');
      // Trailing dot
      expect(canonicalizeUrl('http://evil.com./', 'HOST_PATH')).toBe('evil.com/');
      // Percent-encode
      expect(canonicalizeUrl('http://evil.com/%61dmin', 'HOST_PATH')).toBe('evil.com/admin');
      // Double-encode
      expect(canonicalizeUrl('http://evil.com/%252e%252e/', 'HOST_PATH')).toBe('evil.com/');
      // Default port
      expect(canonicalizeUrl('http://evil.com:80/', 'HOST_PATH')).toBe('evil.com/');
    });
  });
});

describe('IOC Hashing', () => {
  it('should hash IOC with salt', () => {
    const salt = 'test-salt';
    const hash = hashIOC('https://evil.com', salt);

    expect(hash).toHaveLength(64); // SHA-256 hex = 64 chars
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('should produce same hash for equivalent URLs', () => {
    const salt = 'test-salt';
    const hash1 = hashIOC('https://EVIL.COM', salt);
    const hash2 = hashIOC('https://evil.com.', salt);

    expect(hash1).toBe(hash2);
  });

  it('should produce different hashes with different salts', () => {
    const hash1 = hashIOC('https://evil.com', 'salt1');
    const hash2 = hashIOC('https://evil.com', 'salt2');

    expect(hash1).not.toBe(hash2);
  });

  it('should produce same hash for double-encoded bypass attempts', () => {
    const salt = 'test-salt';
    // These should all canonicalize to the same URL
    const hash1 = hashIOC('https://evil.com/', salt, 'HOST_PATH');
    const hash2 = hashIOC('https://evil.com/%2e%2e/', salt, 'HOST_PATH'); // encoded ..
    const hash3 = hashIOC('https://evil.com/%252e%252e/', salt, 'HOST_PATH'); // double-encoded ..

    expect(hash1).toBe(hash2);
    expect(hash1).toBe(hash3);
  });
});

describe('CLI/Extension canonicalization parity', () => {
  // These tests verify CLI canonicalization matches the extension's spec-compliant
  // canonicalize.ts module (docs/Canonicalization_Specification.md)
  // This prevents hash mismatches between compile-time (CLI) and runtime (extension)

  const testCases = [
    // Format: [input, scope, expected_output]
    // Basic hostname normalization
    ['https://EXAMPLE.COM', 'HOST_ONLY', 'example.com'],
    ['https://example.com.', 'HOST_ONLY', 'example.com'],
    ['https://example.com:443', 'HOST_ONLY', 'example.com'],
    ['http://example.com:80', 'HOST_ONLY', 'example.com'],
    ['https://example.com:8443', 'HOST_ONLY', 'example.com:8443'],

    // Path normalization
    ['https://example.com', 'HOST_PATH', 'example.com/'],
    ['https://example.com/', 'HOST_PATH', 'example.com/'],
    ['https://example.com/path/', 'HOST_PATH', 'example.com/path'],
    ['https://example.com/a/../b', 'HOST_PATH', 'example.com/b'],
    ['https://example.com/a/./b', 'HOST_PATH', 'example.com/a/b'],

    // Encoding bypass attempts (CRITICAL for security)
    ['https://example.com/%2e%2e/secret', 'HOST_PATH', 'example.com/secret'],
    ['https://example.com/%252e%252e/secret', 'HOST_PATH', 'example.com/secret'],
    ['https://example.com/%61dmin', 'HOST_PATH', 'example.com/admin'],

    // Query string
    ['https://example.com/path?z=1&a=2', 'FULL_URL', 'example.com/path?a=2&z=1'],
    ['https://example.com/path?query=1', 'HOST_PATH', 'example.com/path'],
  ] as const;

  it.each(testCases)('canonicalizeUrl(%s, %s) should equal %s', (input, scope, expected) => {
    expect(canonicalizeUrl(input, scope)).toBe(expected);
  });
});

describe('Forensics Encryption/Decryption', () => {
  it('should encrypt and decrypt forensics payload', async () => {
    const { publicKey, privateKey } = await generateEncryptionKeypair();

    const payload = {
      event: 'block',
      url: 'https://evil.com/phishing',
      timestamp: Date.now(),
      details: {
        reason: 'IOC match',
        hash: 'abc123',
      },
    };

    const encrypted = await encryptForensics(payload, publicKey);

    // Verify encrypted structure
    expect(encrypted.iv).toBeDefined();
    expect(encrypted.wrappedKey).toBeDefined();
    expect(encrypted.ciphertext).toBeDefined();

    // Verify it's base64 encoded
    expect(() => Buffer.from(encrypted.iv, 'base64')).not.toThrow();
    expect(() => Buffer.from(encrypted.wrappedKey, 'base64')).not.toThrow();
    expect(() => Buffer.from(encrypted.ciphertext, 'base64')).not.toThrow();

    // Decrypt and verify
    const decrypted = await decryptForensics<typeof payload>(encrypted, privateKey);

    expect(decrypted).toEqual(payload);
  });

  it('should fail decryption with wrong key', async () => {
    const keypair1 = await generateEncryptionKeypair();
    const keypair2 = await generateEncryptionKeypair();

    const payload = { secret: 'data' };
    const encrypted = await encryptForensics(payload, keypair1.publicKey);

    // Try to decrypt with wrong private key
    await expect(decryptForensics(encrypted, keypair2.privateKey)).rejects.toThrow();
  });

  it('should fail decryption with corrupted ciphertext', async () => {
    const { publicKey, privateKey } = await generateEncryptionKeypair();

    const payload = { data: 'test' };
    const encrypted = await encryptForensics(payload, publicKey);

    // Corrupt the ciphertext
    const corrupted: EncryptedPayload = {
      ...encrypted,
      ciphertext: encrypted.ciphertext.slice(0, -10) + 'xxxxxxxxxx',
    };

    await expect(decryptForensics(corrupted, privateKey)).rejects.toThrow();
  });

  it('should fail decryption with corrupted IV', async () => {
    const { publicKey, privateKey } = await generateEncryptionKeypair();

    const payload = { data: 'test' };
    const encrypted = await encryptForensics(payload, publicKey);

    // Corrupt the IV
    const corrupted: EncryptedPayload = {
      ...encrypted,
      iv: Buffer.from('wrongivvalue').toString('base64'),
    };

    await expect(decryptForensics(corrupted, privateKey)).rejects.toThrow();
  });

  it('should handle large payloads', async () => {
    const { publicKey, privateKey } = await generateEncryptionKeypair();

    // Create a large payload
    const payload = {
      events: Array.from({ length: 100 }, (_, i) => ({
        id: i,
        url: `https://example${i}.com/path/to/resource`,
        timestamp: Date.now() + i,
        data: 'x'.repeat(1000),
      })),
    };

    const encrypted = await encryptForensics(payload, publicKey);
    const decrypted = await decryptForensics<typeof payload>(encrypted, privateKey);

    expect(decrypted).toEqual(payload);
  });
});
