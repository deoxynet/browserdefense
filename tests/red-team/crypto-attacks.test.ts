/**
 * Red Team: Crypto Implementation Edge Cases
 *
 * Attack-oriented tests for cryptographic implementations.
 * Tests invalid inputs, boundary conditions, and malformed data
 * to ensure graceful error handling (no crashes).
 *
 * Issue: #29
 */

import { describe, it, expect, beforeAll } from 'vitest';

// Signature verification imports
import {
  importPublicKeySpki,
  importPublicKeyJwk,
  verifySignature,
  verifyBlocklistSignature,
  base64ToArrayBuffer,
  arrayBufferToBase64,
  hexToArrayBuffer,
} from '../../src/crypto/signing';

// Encryption imports
import {
  generateAESKey,
  generateIV,
  encryptAESGCM,
  decryptAESGCM,
  generateRSAKeyPair,
  importRSAPublicKey,
  importRSAPrivateKey,
  wrapAESKey,
  unwrapAESKey,
  encryptForensics,
  decryptForensics,
  base64ToArrayBuffer as encBase64ToArrayBuffer,
  type RSAPublicKeyJWK,
  type RSAPrivateKeyJWK,
  type EncryptedPayload,
} from '../../src/crypto/encryption';

// Hashing imports
import {
  sha256,
  sha256Bytes,
  hexToBytes,
  bytesToHex,
  hashIOC,
  canonicalizeUrl,
} from '../../src/crypto/hashing';

// ============================================================================
// SIGNATURE VERIFICATION ATTACKS
// ============================================================================

describe('Red Team: Signature Verification Attacks', () => {
  let validKeyPair: CryptoKeyPair;
  let validPublicKeyJwk: JsonWebKey;
  let validPublicKeySpki: ArrayBuffer;

  beforeAll(async () => {
    validKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    validPublicKeyJwk = await crypto.subtle.exportKey('jwk', validKeyPair.publicKey);
    validPublicKeySpki = await crypto.subtle.exportKey('spki', validKeyPair.publicKey);
  });

  async function signData(privateKey: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
    return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);
  }

  describe('Empty signature attacks', () => {
    it('should reject empty ArrayBuffer signature', async () => {
      const data = new TextEncoder().encode('test data');
      const emptySignature = new ArrayBuffer(0);

      const isValid = await verifySignature(validKeyPair.publicKey, emptySignature, data);
      expect(isValid).toBe(false);
    });

    it('should reject empty Uint8Array signature', async () => {
      const data = new TextEncoder().encode('test data');
      const emptySignature = new Uint8Array(0);

      const isValid = await verifySignature(validKeyPair.publicKey, emptySignature, data);
      expect(isValid).toBe(false);
    });

    it('should handle empty signature in base64 for blocklist verification', async () => {
      const manifest = { version: '1.0.0', total_iocs: 100, bucket_count: 10, sha256_root: 'abc' };
      const emptySignatureBase64 = '';

      const isValid = await verifyBlocklistSignature(manifest, emptySignatureBase64, validPublicKeyJwk);
      expect(isValid).toBe(false);
    });
  });

  describe('Truncated signature attacks', () => {
    it('should reject signature truncated to 1 byte', async () => {
      const data = new TextEncoder().encode('test data');
      const validSignature = await signData(validKeyPair.privateKey, data);
      const truncated = new Uint8Array(validSignature).slice(0, 1);

      const isValid = await verifySignature(validKeyPair.publicKey, truncated, data);
      expect(isValid).toBe(false);
    });

    it('should reject signature truncated to half length', async () => {
      const data = new TextEncoder().encode('test data');
      const validSignature = await signData(validKeyPair.privateKey, data);
      const truncated = new Uint8Array(validSignature).slice(0, validSignature.byteLength / 2);

      const isValid = await verifySignature(validKeyPair.publicKey, truncated, data);
      expect(isValid).toBe(false);
    });

    it('should reject signature missing last byte', async () => {
      const data = new TextEncoder().encode('test data');
      const validSignature = await signData(validKeyPair.privateKey, data);
      const truncated = new Uint8Array(validSignature).slice(0, -1);

      const isValid = await verifySignature(validKeyPair.publicKey, truncated, data);
      expect(isValid).toBe(false);
    });

    it('should reject signature with extra bytes appended', async () => {
      const data = new TextEncoder().encode('test data');
      const validSignature = await signData(validKeyPair.privateKey, data);
      const extended = new Uint8Array(validSignature.byteLength + 10);
      extended.set(new Uint8Array(validSignature));
      extended.set(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), validSignature.byteLength);

      const isValid = await verifySignature(validKeyPair.publicKey, extended, data);
      expect(isValid).toBe(false);
    });
  });

  describe('Wrong curve public key attacks', () => {
    it('should reject P-384 public key in JWK import', async () => {
      const p384Key = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign', 'verify']
      );
      const p384Jwk = await crypto.subtle.exportKey('jwk', p384Key.publicKey);

      await expect(importPublicKeyJwk(p384Jwk)).rejects.toThrow();
    });

    it('should reject P-521 public key in JWK import', async () => {
      const p521Key = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-521' },
        true,
        ['sign', 'verify']
      );
      const p521Jwk = await crypto.subtle.exportKey('jwk', p521Key.publicKey);

      await expect(importPublicKeyJwk(p521Jwk)).rejects.toThrow();
    });

    it('should reject signature made with P-384 key', async () => {
      const p384Key = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign', 'verify']
      );
      const data = new TextEncoder().encode('test data');
      const p384Signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-384' },
        p384Key.privateKey,
        data
      );

      // Try to verify P-384 signature with P-256 key
      const isValid = await verifySignature(validKeyPair.publicKey, p384Signature, data);
      expect(isValid).toBe(false);
    });
  });

  describe('Malformed JWK attacks', () => {
    it('should reject JWK with missing kty', async () => {
      const malformed = { crv: 'P-256', x: 'test', y: 'test' } as unknown as JsonWebKey;
      await expect(importPublicKeyJwk(malformed)).rejects.toThrow();
    });

    it('should reject JWK with missing crv', async () => {
      const malformed = { kty: 'EC', x: 'test', y: 'test' } as unknown as JsonWebKey;
      await expect(importPublicKeyJwk(malformed)).rejects.toThrow();
    });

    it('should reject JWK with missing x coordinate', async () => {
      const malformed = { kty: 'EC', crv: 'P-256', y: 'test' } as JsonWebKey;
      await expect(importPublicKeyJwk(malformed)).rejects.toThrow();
    });

    it('should reject JWK with missing y coordinate', async () => {
      const malformed = { kty: 'EC', crv: 'P-256', x: 'test' } as JsonWebKey;
      await expect(importPublicKeyJwk(malformed)).rejects.toThrow();
    });

    it('should reject JWK with RSA key type', async () => {
      const rsaJwk: JsonWebKey = { kty: 'RSA', n: 'test', e: 'AQAB' };
      await expect(importPublicKeyJwk(rsaJwk)).rejects.toThrow();
    });

    it('should reject JWK with invalid x coordinate (wrong length)', async () => {
      const malformed: JsonWebKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'dG9vLXNob3J0', // "too-short" in base64
        y: validPublicKeyJwk.y,
      };
      await expect(importPublicKeyJwk(malformed)).rejects.toThrow();
    });

    it('should reject JWK with point not on curve', async () => {
      const malformed: JsonWebKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', // Invalid point
        y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      };
      await expect(importPublicKeyJwk(malformed)).rejects.toThrow();
    });

    it('should reject empty JWK object', async () => {
      const empty = {} as JsonWebKey;
      await expect(importPublicKeyJwk(empty)).rejects.toThrow();
    });
  });

  describe('Valid signature, wrong data attacks', () => {
    it('should reject when verifying with completely different data', async () => {
      const originalData = new TextEncoder().encode('original message');
      const differentData = new TextEncoder().encode('different message');
      const signature = await signData(validKeyPair.privateKey, originalData);

      const isValid = await verifySignature(validKeyPair.publicKey, signature, differentData);
      expect(isValid).toBe(false);
    });

    it('should reject when data has single bit flip', async () => {
      const originalData = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
      const modifiedData = new Uint8Array([0x00, 0x01, 0x02, 0x02]); // Last bit flipped
      const signature = await signData(validKeyPair.privateKey, originalData);

      const isValid = await verifySignature(validKeyPair.publicKey, signature, modifiedData);
      expect(isValid).toBe(false);
    });

    it('should reject when data has single byte prepended', async () => {
      const originalData = new TextEncoder().encode('message');
      const modifiedData = new Uint8Array([0x00, ...originalData]);
      const signature = await signData(validKeyPair.privateKey, originalData);

      const isValid = await verifySignature(validKeyPair.publicKey, signature, modifiedData);
      expect(isValid).toBe(false);
    });

    it('should reject when data has single byte appended', async () => {
      const originalData = new TextEncoder().encode('message');
      const modifiedData = new Uint8Array([...originalData, 0x00]);
      const signature = await signData(validKeyPair.privateKey, originalData);

      const isValid = await verifySignature(validKeyPair.publicKey, signature, modifiedData);
      expect(isValid).toBe(false);
    });
  });

  describe('Replay attacks (old valid signature)', () => {
    it('should not accept signature from different manifest version', async () => {
      const manifest1 = { version: '1.0.0', total_iocs: 100, bucket_count: 10, sha256_root: 'abc' };
      const manifest2 = { version: '2.0.0', total_iocs: 100, bucket_count: 10, sha256_root: 'abc' };

      // Sign manifest1
      const signedFields1 = {
        bucket_count: manifest1.bucket_count,
        sha256_root: manifest1.sha256_root,
        total_iocs: manifest1.total_iocs,
        version: manifest1.version,
      };
      const manifestBody1 = JSON.stringify(signedFields1, Object.keys(signedFields1).sort());
      const data1 = new TextEncoder().encode(manifestBody1);
      const signature1 = await signData(validKeyPair.privateKey, data1);
      const signatureBase64 = arrayBufferToBase64(signature1);

      // Try to verify manifest2 with manifest1's signature
      const isValid = await verifyBlocklistSignature(manifest2, signatureBase64, validPublicKeyJwk);
      expect(isValid).toBe(false);
    });

    it('should not accept signature if sha256_root changed', async () => {
      const manifest1 = { version: '1.0.0', total_iocs: 100, bucket_count: 10, sha256_root: 'originalroot' };
      const manifest2 = { version: '1.0.0', total_iocs: 100, bucket_count: 10, sha256_root: 'tamperedroot' };

      const signedFields1 = {
        bucket_count: manifest1.bucket_count,
        sha256_root: manifest1.sha256_root,
        total_iocs: manifest1.total_iocs,
        version: manifest1.version,
      };
      const manifestBody1 = JSON.stringify(signedFields1, Object.keys(signedFields1).sort());
      const data1 = new TextEncoder().encode(manifestBody1);
      const signature1 = await signData(validKeyPair.privateKey, data1);
      const signatureBase64 = arrayBufferToBase64(signature1);

      const isValid = await verifyBlocklistSignature(manifest2, signatureBase64, validPublicKeyJwk);
      expect(isValid).toBe(false);
    });

    it('should not accept signature from different key', async () => {
      const attackerKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );

      const manifest = { version: '1.0.0', total_iocs: 100, bucket_count: 10, sha256_root: 'abc' };
      const signedFields = {
        bucket_count: manifest.bucket_count,
        sha256_root: manifest.sha256_root,
        total_iocs: manifest.total_iocs,
        version: manifest.version,
      };
      const manifestBody = JSON.stringify(signedFields, Object.keys(signedFields).sort());
      const data = new TextEncoder().encode(manifestBody);
      const attackerSignature = await signData(attackerKeyPair.privateKey, data);
      const signatureBase64 = arrayBufferToBase64(attackerSignature);

      // Verify with legitimate public key - should fail
      const isValid = await verifyBlocklistSignature(manifest, signatureBase64, validPublicKeyJwk);
      expect(isValid).toBe(false);
    });
  });

  describe('SPKI import attacks', () => {
    it('should reject empty SPKI', async () => {
      await expect(importPublicKeySpki(new ArrayBuffer(0))).rejects.toThrow();
    });

    it('should reject truncated SPKI', async () => {
      const truncated = validPublicKeySpki.slice(0, 10);
      await expect(importPublicKeySpki(truncated)).rejects.toThrow();
    });

    it('should reject garbage SPKI data', async () => {
      const garbage = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8]);
      await expect(importPublicKeySpki(garbage.buffer)).rejects.toThrow();
    });

    it('should reject SPKI with corrupted DER encoding', async () => {
      const corrupted = new Uint8Array(validPublicKeySpki);
      corrupted[0] = 0xff; // Corrupt the DER header
      await expect(importPublicKeySpki(corrupted.buffer)).rejects.toThrow();
    });
  });
});

// ============================================================================
// ENCRYPTION ATTACKS
// ============================================================================

describe('Red Team: Encryption Attacks', () => {
  let rsaKeyPair: { publicKey: RSAPublicKeyJWK; privateKey: RSAPrivateKeyJWK };

  beforeAll(async () => {
    rsaKeyPair = await generateRSAKeyPair();
  });

  describe('Empty plaintext handling', () => {
    it('should handle empty string payload', async () => {
      const encrypted = await encryptForensics('', rsaKeyPair.publicKey);
      const decrypted = await decryptForensics<string>(encrypted, rsaKeyPair.privateKey);
      expect(decrypted).toBe('');
    });

    it('should handle null payload', async () => {
      const encrypted = await encryptForensics(null, rsaKeyPair.publicKey);
      const decrypted = await decryptForensics<null>(encrypted, rsaKeyPair.privateKey);
      expect(decrypted).toBeNull();
    });

    it('should handle empty object payload', async () => {
      const encrypted = await encryptForensics({}, rsaKeyPair.publicKey);
      const decrypted = await decryptForensics<object>(encrypted, rsaKeyPair.privateKey);
      expect(decrypted).toEqual({});
    });

    it('should handle empty array payload', async () => {
      const encrypted = await encryptForensics([], rsaKeyPair.publicKey);
      const decrypted = await decryptForensics<unknown[]>(encrypted, rsaKeyPair.privateKey);
      expect(decrypted).toEqual([]);
    });
  });

  describe('Very large plaintext (stress test)', () => {
    it('should handle 1MB payload', async () => {
      const largeData = { data: 'x'.repeat(1024 * 1024) }; // 1MB
      const encrypted = await encryptForensics(largeData, rsaKeyPair.publicKey);
      const decrypted = await decryptForensics<typeof largeData>(encrypted, rsaKeyPair.privateKey);
      expect(decrypted.data.length).toBe(1024 * 1024);
    });

    it('should handle 5MB payload', async () => {
      const largeData = { data: 'x'.repeat(5 * 1024 * 1024) }; // 5MB
      const encrypted = await encryptForensics(largeData, rsaKeyPair.publicKey);
      const decrypted = await decryptForensics<typeof largeData>(encrypted, rsaKeyPair.privateKey);
      expect(decrypted.data.length).toBe(5 * 1024 * 1024);
    });

    // Note: 10MB+ test commented out as it may be too slow for CI
    // it('should handle 10MB+ payload', async () => {
    //   const largeData = { data: 'x'.repeat(10 * 1024 * 1024) };
    //   const encrypted = await encryptForensics(largeData, rsaKeyPair.publicKey);
    //   const decrypted = await decryptForensics<typeof largeData>(encrypted, rsaKeyPair.privateKey);
    //   expect(decrypted.data.length).toBe(10 * 1024 * 1024);
    // });
  });

  describe('Invalid RSA public key attacks', () => {
    it('should reject RSA key with missing modulus (n)', async () => {
      const invalidKey = { kty: 'RSA', e: 'AQAB' } as RSAPublicKeyJWK;
      await expect(importRSAPublicKey(invalidKey)).rejects.toThrow();
    });

    it('should reject RSA key with missing exponent (e)', async () => {
      const invalidKey = { kty: 'RSA', n: rsaKeyPair.publicKey.n } as RSAPublicKeyJWK;
      await expect(importRSAPublicKey(invalidKey)).rejects.toThrow();
    });

    it('documents: Web Crypto parses unusual modulus strings but fails at encryption', async () => {
      // FINDING: Web Crypto API is very permissive with JWK parsing
      // Even strings with special chars get decoded somehow
      const weirdKey: RSAPublicKeyJWK = {
        kty: 'RSA',
        n: '___this-is-weird-but-decoded___',
        e: 'AQAB',
      };

      // Import may succeed with some mangled interpretation
      const imported = await importRSAPublicKey(weirdKey);
      expect(imported).toBeDefined();

      // But encryption will fail with malformed key data
      const data = new TextEncoder().encode('test');
      await expect(crypto.subtle.encrypt({ name: 'RSA-OAEP' }, imported, data)).rejects.toThrow();
    });

    it('documents: Web Crypto imports tiny RSA keys but they fail at use time', async () => {
      // FINDING: Web Crypto API does NOT reject small modulus at import time
      // It will fail during actual encrypt/decrypt operations
      const tinyKey: RSAPublicKeyJWK = {
        kty: 'RSA',
        n: 'AQAB', // Way too small - 17 bits
        e: 'AQAB',
      };

      // Import succeeds (this is a Web Crypto quirk)
      const imported = await importRSAPublicKey(tinyKey);
      expect(imported).toBeDefined();

      // But encryption will fail because RSA-OAEP needs minimum key size
      const data = new TextEncoder().encode('test');
      await expect(crypto.subtle.encrypt({ name: 'RSA-OAEP' }, imported, data)).rejects.toThrow();
    });

    it('should reject empty RSA public key JWK', async () => {
      const emptyKey = {} as RSAPublicKeyJWK;
      await expect(importRSAPublicKey(emptyKey)).rejects.toThrow();
    });

    it('should reject EC key when RSA expected', async () => {
      const ecKey = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );
      const ecJwk = await crypto.subtle.exportKey('jwk', ecKey.publicKey);
      await expect(importRSAPublicKey(ecJwk as unknown as RSAPublicKeyJWK)).rejects.toThrow();
    });
  });

  describe('Malformed ciphertext attacks', () => {
    it('should reject encrypted payload with invalid IV (wrong length)', async () => {
      const payload = { test: 'data' };
      const encrypted = await encryptForensics(payload, rsaKeyPair.publicKey);

      // Corrupt IV to wrong length
      encrypted.iv = btoa('short'); // Only 5 bytes instead of 12

      await expect(decryptForensics(encrypted, rsaKeyPair.privateKey)).rejects.toThrow();
    });

    it('should reject encrypted payload with empty IV', async () => {
      const payload = { test: 'data' };
      const encrypted = await encryptForensics(payload, rsaKeyPair.publicKey);
      encrypted.iv = '';

      await expect(decryptForensics(encrypted, rsaKeyPair.privateKey)).rejects.toThrow();
    });

    it('should reject encrypted payload with invalid base64 IV', async () => {
      const payload = { test: 'data' };
      const encrypted = await encryptForensics(payload, rsaKeyPair.publicKey);
      encrypted.iv = '!!!invalid-base64!!!';

      await expect(decryptForensics(encrypted, rsaKeyPair.privateKey)).rejects.toThrow();
    });

    it('should reject encrypted payload with corrupted ciphertext', async () => {
      const payload = { test: 'data' };
      const encrypted = await encryptForensics(payload, rsaKeyPair.publicKey);

      // Corrupt the ciphertext
      const ciphertextBytes = new Uint8Array(encBase64ToArrayBuffer(encrypted.ciphertext));
      ciphertextBytes[0] ^= 0xff;
      ciphertextBytes[10] ^= 0xff;
      encrypted.ciphertext = btoa(String.fromCharCode(...ciphertextBytes));

      await expect(decryptForensics(encrypted, rsaKeyPair.privateKey)).rejects.toThrow();
    });

    it('should reject encrypted payload with empty ciphertext', async () => {
      const payload = { test: 'data' };
      const encrypted = await encryptForensics(payload, rsaKeyPair.publicKey);
      encrypted.ciphertext = '';

      await expect(decryptForensics(encrypted, rsaKeyPair.privateKey)).rejects.toThrow();
    });

    it('should reject encrypted payload with corrupted wrapped key', async () => {
      const payload = { test: 'data' };
      const encrypted = await encryptForensics(payload, rsaKeyPair.publicKey);

      // Corrupt the wrapped key
      const wrappedKeyBytes = new Uint8Array(encBase64ToArrayBuffer(encrypted.wrappedKey));
      wrappedKeyBytes[0] ^= 0xff;
      encrypted.wrappedKey = btoa(String.fromCharCode(...wrappedKeyBytes));

      await expect(decryptForensics(encrypted, rsaKeyPair.privateKey)).rejects.toThrow();
    });

    it('should reject encrypted payload with truncated wrapped key', async () => {
      const payload = { test: 'data' };
      const encrypted = await encryptForensics(payload, rsaKeyPair.publicKey);

      // Truncate wrapped key
      const wrappedKeyBytes = new Uint8Array(encBase64ToArrayBuffer(encrypted.wrappedKey));
      const truncated = wrappedKeyBytes.slice(0, 10);
      encrypted.wrappedKey = btoa(String.fromCharCode(...truncated));

      await expect(decryptForensics(encrypted, rsaKeyPair.privateKey)).rejects.toThrow();
    });
  });

  describe('Truncated AES-GCM tag attacks', () => {
    it('should reject ciphertext with truncated auth tag (missing 1 byte)', async () => {
      const key = await generateAESKey();
      const iv = generateIV();
      const plaintext = new TextEncoder().encode('test data');
      const ciphertext = await encryptAESGCM(key, iv, plaintext);

      // AES-GCM auth tag is 16 bytes at the end. Truncate it.
      const truncated = ciphertext.slice(0, ciphertext.byteLength - 1);

      await expect(decryptAESGCM(key, iv, truncated)).rejects.toThrow();
    });

    it('should reject ciphertext with truncated auth tag (missing 8 bytes)', async () => {
      const key = await generateAESKey();
      const iv = generateIV();
      const plaintext = new TextEncoder().encode('test data');
      const ciphertext = await encryptAESGCM(key, iv, plaintext);

      const truncated = ciphertext.slice(0, ciphertext.byteLength - 8);

      await expect(decryptAESGCM(key, iv, truncated)).rejects.toThrow();
    });

    it('should reject ciphertext with completely removed auth tag', async () => {
      const key = await generateAESKey();
      const iv = generateIV();
      const plaintext = new TextEncoder().encode('test data');
      const ciphertext = await encryptAESGCM(key, iv, plaintext);

      // Remove entire 16-byte auth tag
      const truncated = ciphertext.slice(0, ciphertext.byteLength - 16);

      await expect(decryptAESGCM(key, iv, truncated)).rejects.toThrow();
    });

    it('should reject ciphertext with flipped bit in auth tag', async () => {
      const key = await generateAESKey();
      const iv = generateIV();
      const plaintext = new TextEncoder().encode('test data');
      const ciphertext = await encryptAESGCM(key, iv, plaintext);

      // Flip a bit in the auth tag (last 16 bytes)
      const corrupted = new Uint8Array(ciphertext);
      corrupted[corrupted.length - 1] ^= 0x01;

      await expect(decryptAESGCM(key, iv, corrupted.buffer)).rejects.toThrow();
    });
  });

  describe('Wrong key decryption attempts', () => {
    it('should fail to decrypt with wrong RSA private key', async () => {
      const payload = { secret: 'classified data' };
      const encrypted = await encryptForensics(payload, rsaKeyPair.publicKey);

      const attackerKeyPair = await generateRSAKeyPair();

      await expect(decryptForensics(encrypted, attackerKeyPair.privateKey)).rejects.toThrow();
    });

    it('should fail to unwrap AES key with wrong RSA private key', async () => {
      const aesKey = await generateAESKey();
      const rsaPublic = await importRSAPublicKey(rsaKeyPair.publicKey);
      const wrapped = await wrapAESKey(aesKey, rsaPublic);

      const attackerKeyPair = await generateRSAKeyPair();
      const attackerPrivate = await importRSAPrivateKey(attackerKeyPair.privateKey);

      await expect(unwrapAESKey(wrapped, attackerPrivate)).rejects.toThrow();
    });

    it('should fail AES-GCM decryption with wrong key', async () => {
      const key1 = await generateAESKey();
      const key2 = await generateAESKey();
      const iv = generateIV();
      const plaintext = new TextEncoder().encode('secret');

      const ciphertext = await encryptAESGCM(key1, iv, plaintext);

      await expect(decryptAESGCM(key2, iv, ciphertext)).rejects.toThrow();
    });

    it('should fail AES-GCM decryption with wrong IV', async () => {
      const key = await generateAESKey();
      const iv1 = generateIV();
      const iv2 = generateIV();
      const plaintext = new TextEncoder().encode('secret');

      const ciphertext = await encryptAESGCM(key, iv1, plaintext);

      await expect(decryptAESGCM(key, iv2, ciphertext)).rejects.toThrow();
    });
  });

  describe('Key confusion attacks', () => {
    it('should not allow using encryption key for signing', async () => {
      // RSA-OAEP key should not work for ECDSA
      const rsaPublicCryptoKey = await importRSAPublicKey(rsaKeyPair.publicKey);

      // Attempt to use RSA key for ECDSA verification should fail
      const data = new TextEncoder().encode('test');
      const fakeSignature = new Uint8Array(64); // ECDSA P-256 signature size

      // This should either throw or return false
      try {
        const result = await crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          rsaPublicCryptoKey,
          fakeSignature,
          data
        );
        expect(result).toBe(false);
      } catch {
        // Expected - key type mismatch
        expect(true).toBe(true);
      }
    });
  });
});

// ============================================================================
// HASHING ATTACKS
// ============================================================================

describe('Red Team: Hashing Attacks', () => {
  describe('Empty input handling', () => {
    it('should hash empty string', async () => {
      const hash = await sha256('');
      // SHA-256 of empty string is well-known
      expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should hash empty Uint8Array', async () => {
      const hash = await sha256(new Uint8Array(0));
      expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should handle empty IOC with salt', async () => {
      const hash = await hashIOC('', 'test-salt');
      expect(hash).toBeDefined();
      expect(hash.length).toBe(64); // SHA-256 hex length
    });
  });

  describe('Binary data (non-UTF8) handling', () => {
    it('should hash binary data with null bytes', async () => {
      const binary = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
      const hash = await sha256(binary);
      expect(hash.length).toBe(64);
    });

    it('should hash binary data with high bytes', async () => {
      const binary = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc]);
      const hash = await sha256(binary);
      expect(hash.length).toBe(64);
    });

    it('should hash binary data with all byte values', async () => {
      const binary = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        binary[i] = i;
      }
      const hash = await sha256(binary);
      expect(hash.length).toBe(64);
    });

    it('should hash invalid UTF-8 sequences as binary', async () => {
      // These bytes are invalid UTF-8
      const invalid = new Uint8Array([0x80, 0x81, 0x82, 0xfe, 0xff]);
      const hash = await sha256(invalid);
      expect(hash.length).toBe(64);
    });

    it('should produce consistent hash for same binary', async () => {
      const binary = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const hash1 = await sha256(binary);
      const hash2 = await sha256(binary);
      expect(hash1).toBe(hash2);
    });
  });

  describe('Very long input (stress test)', () => {
    it('should hash 1MB input', async () => {
      const largeInput = 'x'.repeat(1024 * 1024);
      const hash = await sha256(largeInput);
      expect(hash.length).toBe(64);
    });

    it('should hash 5MB input', async () => {
      const largeInput = 'x'.repeat(5 * 1024 * 1024);
      const hash = await sha256(largeInput);
      expect(hash.length).toBe(64);
    });

    it('should hash 1MB Uint8Array', async () => {
      const largeInput = new Uint8Array(1024 * 1024);
      for (let i = 0; i < largeInput.length; i++) {
        largeInput[i] = i % 256;
      }
      const hash = await sha256(largeInput);
      expect(hash.length).toBe(64);
    });

    it('should return bytes for large input', async () => {
      const largeInput = 'x'.repeat(1024 * 1024);
      const hashBytes = await sha256Bytes(largeInput);
      expect(hashBytes.length).toBe(32); // SHA-256 produces 32 bytes
    });
  });

  describe('Hex conversion edge cases', () => {
    it('should handle hex with leading zeros', () => {
      const bytes = hexToBytes('00000000');
      expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0]));
    });

    it('should roundtrip bytes with leading zeros', () => {
      const original = new Uint8Array([0x00, 0x00, 0xff, 0x00]);
      const hex = bytesToHex(original);
      const roundtrip = hexToBytes(hex);
      expect(roundtrip).toEqual(original);
    });

    it('should handle empty hex string', () => {
      const bytes = hexToBytes('');
      expect(bytes.length).toBe(0);
    });

    it('should handle single byte', () => {
      const bytes = hexToBytes('ff');
      expect(bytes).toEqual(new Uint8Array([0xff]));
    });

    it('should handle lowercase hex', () => {
      const bytes = hexToBytes('abcdef');
      expect(bytes).toEqual(new Uint8Array([0xab, 0xcd, 0xef]));
    });

    it('should handle uppercase hex', () => {
      const bytes = hexToBytes('ABCDEF');
      expect(bytes).toEqual(new Uint8Array([0xab, 0xcd, 0xef]));
    });

    it('should handle mixed case hex', () => {
      const bytes = hexToBytes('AbCdEf');
      expect(bytes).toEqual(new Uint8Array([0xab, 0xcd, 0xef]));
    });
  });

  describe('URL canonicalization edge cases', () => {
    it('should handle malformed URLs gracefully', () => {
      const result = canonicalizeUrl('not-a-url');
      expect(result).toBe('not-a-url'); // Returns lowercase as-is
    });

    it('should handle URL with only scheme', () => {
      const result = canonicalizeUrl('http://');
      // URL constructor may reject this or handle it
      expect(typeof result).toBe('string');
    });

    it('should handle URL with unicode in path', () => {
      const result = canonicalizeUrl('https://example.com/path/\u0000');
      expect(typeof result).toBe('string');
    });

    it('should handle URL with percent-encoded null', () => {
      const result = canonicalizeUrl('https://example.com/path/%00');
      expect(typeof result).toBe('string');
    });

    it('should handle very long URL', () => {
      const longPath = 'a'.repeat(10000);
      const result = canonicalizeUrl(`https://example.com/${longPath}`);
      expect(result).toContain('example.com');
    });

    it('should handle URL with international domain', () => {
      const result = canonicalizeUrl('https://xn--n3h.com/'); // emoji domain
      expect(result).toContain('xn--n3h.com');
    });
  });

  describe('IOC hashing edge cases', () => {
    it('should produce different hashes for same URL with different salts', async () => {
      const url = 'https://evil.com';
      const hash1 = await hashIOC(url, 'salt1');
      const hash2 = await hashIOC(url, 'salt2');
      expect(hash1).not.toBe(hash2);
    });

    it('should produce same hash for equivalent URLs', async () => {
      const url1 = 'https://EVIL.COM';
      const url2 = 'https://evil.com';
      const hash1 = await hashIOC(url1, 'salt');
      const hash2 = await hashIOC(url2, 'salt');
      expect(hash1).toBe(hash2);
    });

    it('should handle URL with empty salt', async () => {
      const hash = await hashIOC('https://evil.com', '');
      expect(hash.length).toBe(64);
    });

    it('should handle URL with very long salt', async () => {
      const longSalt = 'x'.repeat(100000);
      const hash = await hashIOC('https://evil.com', longSalt);
      expect(hash.length).toBe(64);
    });

    it('should handle URL with special characters in salt', async () => {
      const specialSalt = '!@#$%^&*()_+-=[]{}|;:,.<>?\'"\\`~';
      const hash = await hashIOC('https://evil.com', specialSalt);
      expect(hash.length).toBe(64);
    });
  });
});

// ============================================================================
// TIMING ATTACK CONSIDERATIONS
// ============================================================================

describe('Red Team: Timing Attack Awareness', () => {
  // Note: These tests don't verify constant-time behavior (which is hard in JS),
  // but document that the implementation should be reviewed for timing leaks.

  it('documents: signature verification should not leak timing info', async () => {
    // Web Crypto API's verify() should be constant-time internally,
    // but we wrap it with try/catch which may have timing differences.
    // This is a known limitation of the JS environment.
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const data = new TextEncoder().encode('test');
    const validSig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.privateKey,
      data
    );

    // Time valid signature
    const validStart = performance.now();
    for (let i = 0; i < 100; i++) {
      await verifySignature(keyPair.publicKey, validSig, data);
    }
    const validTime = performance.now() - validStart;

    // Time invalid signature
    const invalidSig = new Uint8Array(validSig.byteLength);
    const invalidStart = performance.now();
    for (let i = 0; i < 100; i++) {
      await verifySignature(keyPair.publicKey, invalidSig, data);
    }
    const invalidTime = performance.now() - invalidStart;

    // We just document that both complete without error
    // Actual timing analysis would require statistical methods
    expect(validTime).toBeGreaterThan(0);
    expect(invalidTime).toBeGreaterThan(0);

    // Log for manual review
    console.log(`[Timing] Valid sig: ${validTime.toFixed(2)}ms, Invalid sig: ${invalidTime.toFixed(2)}ms`);
  });

  it('documents: string comparison in error paths may leak timing', () => {
    // This is a documentation test - JS string comparison is not constant-time
    // If any error messages include user-controlled data, there could be timing leaks
    // Current implementation catches errors and returns false/throws, which is safer
    expect(true).toBe(true);
  });
});
