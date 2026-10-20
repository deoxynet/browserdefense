/**
 * Unit tests for BrowserDefense hybrid encryption module.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
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
  type RSAPublicKeyJWK,
  type RSAPrivateKeyJWK,
} from '../../src/crypto/encryption';

describe('arrayBufferToBase64', () => {
  it('converts ArrayBuffer to base64', () => {
    const buffer = new Uint8Array([72, 101, 108, 108, 111]).buffer; // "Hello"
    const base64 = arrayBufferToBase64(buffer as ArrayBuffer);
    expect(base64).toBe('SGVsbG8=');
  });

  it('handles empty buffer', () => {
    const buffer = new ArrayBuffer(0);
    const base64 = arrayBufferToBase64(buffer);
    expect(base64).toBe('');
  });

  it('handles binary data', () => {
    const buffer = new Uint8Array([0x00, 0xff, 0x80, 0x7f]).buffer;
    const base64 = arrayBufferToBase64(buffer as ArrayBuffer);
    expect(base64).toBe('AP+Afw==');
  });
});

describe('base64ToArrayBuffer', () => {
  it('converts base64 to ArrayBuffer', () => {
    const buffer = base64ToArrayBuffer('SGVsbG8=');
    const bytes = new Uint8Array(buffer);
    expect(bytes).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
  });

  it('handles empty string', () => {
    const buffer = base64ToArrayBuffer('');
    expect(buffer.byteLength).toBe(0);
  });

  it('roundtrips with arrayBufferToBase64', () => {
    const original = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);
    const base64 = arrayBufferToBase64(original.buffer as ArrayBuffer);
    const roundtrip = new Uint8Array(base64ToArrayBuffer(base64));
    expect(roundtrip).toEqual(original);
  });
});

describe('generateAESKey', () => {
  it('generates an AES-256-GCM key', async () => {
    const key = await generateAESKey();
    expect(key).toBeDefined();
    expect(key.algorithm.name).toBe('AES-GCM');
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
  });

  it('generates extractable key', async () => {
    const key = await generateAESKey();
    expect(key.extractable).toBe(true);
  });

  it('generates unique keys', async () => {
    const key1 = await generateAESKey();
    const key2 = await generateAESKey();
    const raw1 = await crypto.subtle.exportKey('raw', key1);
    const raw2 = await crypto.subtle.exportKey('raw', key2);
    expect(arrayBufferToBase64(raw1)).not.toBe(arrayBufferToBase64(raw2));
  });
});

describe('generateIV', () => {
  it('generates 12-byte IV', () => {
    const iv = generateIV();
    expect(iv).toBeInstanceOf(Uint8Array);
    expect(iv.length).toBe(12);
  });

  it('generates unique IVs', () => {
    const iv1 = generateIV();
    const iv2 = generateIV();
    expect(arrayBufferToBase64(iv1.buffer as ArrayBuffer)).not.toBe(
      arrayBufferToBase64(iv2.buffer as ArrayBuffer)
    );
  });
});

describe('AES-GCM encryption/decryption', () => {
  it('encrypts and decrypts data', async () => {
    const key = await generateAESKey();
    const iv = generateIV();
    const plaintext = new TextEncoder().encode('Hello, World!');

    const ciphertext = await encryptAESGCM(key, iv, plaintext);
    expect(ciphertext.byteLength).toBeGreaterThan(plaintext.length); // Includes auth tag

    const decrypted = await decryptAESGCM(key, iv, ciphertext);
    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe('Hello, World!');
  });

  it('fails with wrong key', async () => {
    const key1 = await generateAESKey();
    const key2 = await generateAESKey();
    const iv = generateIV();
    const plaintext = new TextEncoder().encode('Secret data');

    const ciphertext = await encryptAESGCM(key1, iv, plaintext);

    await expect(decryptAESGCM(key2, iv, ciphertext)).rejects.toThrow();
  });

  it('fails with wrong IV', async () => {
    const key = await generateAESKey();
    const iv1 = generateIV();
    const iv2 = generateIV();
    const plaintext = new TextEncoder().encode('Secret data');

    const ciphertext = await encryptAESGCM(key, iv1, plaintext);

    await expect(decryptAESGCM(key, iv2, ciphertext)).rejects.toThrow();
  });

  it('handles empty plaintext', async () => {
    const key = await generateAESKey();
    const iv = generateIV();
    const plaintext = new Uint8Array(0);

    const ciphertext = await encryptAESGCM(key, iv, plaintext);
    const decrypted = await decryptAESGCM(key, iv, ciphertext);
    expect(decrypted.byteLength).toBe(0);
  });

  it('handles large plaintext', async () => {
    const key = await generateAESKey();
    const iv = generateIV();
    // Create large plaintext by filling with pattern (getRandomValues has 65536 limit)
    const plaintext = new Uint8Array(50000);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i % 256;
    }

    const ciphertext = await encryptAESGCM(key, iv, plaintext);
    const decrypted = await decryptAESGCM(key, iv, ciphertext);
    expect(new Uint8Array(decrypted)).toEqual(plaintext);
  });
});

describe('RSA key generation and import', () => {
  let keyPair: { publicKey: RSAPublicKeyJWK; privateKey: RSAPrivateKeyJWK };

  beforeAll(async () => {
    keyPair = await generateRSAKeyPair();
  });

  it('generates valid RSA keypair', () => {
    expect(keyPair.publicKey.kty).toBe('RSA');
    expect(keyPair.publicKey.n).toBeDefined();
    expect(keyPair.publicKey.e).toBeDefined();
    expect(keyPair.privateKey.d).toBeDefined();
    expect(keyPair.privateKey.p).toBeDefined();
    expect(keyPair.privateKey.q).toBeDefined();
  });

  it('imports public key', async () => {
    const key = await importRSAPublicKey(keyPair.publicKey);
    expect(key.algorithm.name).toBe('RSA-OAEP');
    expect(key.usages).toContain('encrypt');
  });

  it('imports private key', async () => {
    const key = await importRSAPrivateKey(keyPair.privateKey);
    expect(key.algorithm.name).toBe('RSA-OAEP');
    expect(key.usages).toContain('decrypt');
  });
});

describe('RSA key wrapping', () => {
  let rsaKeyPair: { publicKey: RSAPublicKeyJWK; privateKey: RSAPrivateKeyJWK };

  beforeAll(async () => {
    rsaKeyPair = await generateRSAKeyPair();
  });

  it('wraps and unwraps AES key', async () => {
    const aesKey = await generateAESKey();
    const rsaPublic = await importRSAPublicKey(rsaKeyPair.publicKey);
    const rsaPrivate = await importRSAPrivateKey(rsaKeyPair.privateKey);

    // Wrap and unwrap
    const wrapped = await wrapAESKey(aesKey, rsaPublic);
    const unwrapped = await unwrapAESKey(wrapped, rsaPrivate);

    // Verify by encrypting with original and decrypting with unwrapped
    const iv = generateIV();
    const plaintext = new TextEncoder().encode('Test message');
    const ciphertext = await encryptAESGCM(aesKey, iv, plaintext);
    const decrypted = await decryptAESGCM(unwrapped, iv, ciphertext);

    expect(new TextDecoder().decode(decrypted)).toBe('Test message');
  });

  it('produces different wrapped keys for same AES key', async () => {
    // RSA-OAEP is randomized (uses padding with random bytes)
    const aesKey = await generateAESKey();
    const rsaPublic = await importRSAPublicKey(rsaKeyPair.publicKey);

    const wrapped1 = await wrapAESKey(aesKey, rsaPublic);
    const wrapped2 = await wrapAESKey(aesKey, rsaPublic);

    // Should be different due to random padding
    expect(arrayBufferToBase64(wrapped1)).not.toBe(arrayBufferToBase64(wrapped2));
  });

  it('fails to unwrap with wrong private key', async () => {
    const aesKey = await generateAESKey();
    const rsaPublic = await importRSAPublicKey(rsaKeyPair.publicKey);

    // Generate different keypair
    const otherKeyPair = await generateRSAKeyPair();
    const otherPrivate = await importRSAPrivateKey(otherKeyPair.privateKey);

    const wrapped = await wrapAESKey(aesKey, rsaPublic);

    await expect(unwrapAESKey(wrapped, otherPrivate)).rejects.toThrow();
  });
});

describe('encryptForensics / decryptForensics', () => {
  let keyPair: { publicKey: RSAPublicKeyJWK; privateKey: RSAPrivateKeyJWK };

  beforeAll(async () => {
    keyPair = await generateRSAKeyPair();
  });

  it('encrypts and decrypts forensics payload', async () => {
    const payload = {
      url: 'https://evil.com/phishing',
      timestamp: Date.now(),
      redirectChain: ['https://legit.com', 'https://redirect.com', 'https://evil.com/phishing'],
      userId: 'user-123',
    };

    const encrypted = await encryptForensics(payload, keyPair.publicKey);

    expect(encrypted.iv).toBeDefined();
    expect(encrypted.wrappedKey).toBeDefined();
    expect(encrypted.ciphertext).toBeDefined();

    const decrypted = await decryptForensics<typeof payload>(encrypted, keyPair.privateKey);

    expect(decrypted).toEqual(payload);
  });

  it('encrypted payload is base64 encoded', async () => {
    const payload = { test: 'data' };
    const encrypted = await encryptForensics(payload, keyPair.publicKey);

    // Should be valid base64
    expect(() => atob(encrypted.iv)).not.toThrow();
    expect(() => atob(encrypted.wrappedKey)).not.toThrow();
    expect(() => atob(encrypted.ciphertext)).not.toThrow();
  });

  it('IV is 12 bytes (16 chars base64)', async () => {
    const payload = { test: 'data' };
    const encrypted = await encryptForensics(payload, keyPair.publicKey);

    const ivBytes = base64ToArrayBuffer(encrypted.iv);
    expect(ivBytes.byteLength).toBe(12);
  });

  it('different encryptions produce different ciphertext', async () => {
    const payload = { test: 'same data' };

    const encrypted1 = await encryptForensics(payload, keyPair.publicKey);
    const encrypted2 = await encryptForensics(payload, keyPair.publicKey);

    // IV should be different
    expect(encrypted1.iv).not.toBe(encrypted2.iv);
    // Ciphertext should be different (different IV)
    expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
    // Wrapped key should be different (RSA-OAEP is randomized)
    expect(encrypted1.wrappedKey).not.toBe(encrypted2.wrappedKey);
  });

  it('fails to decrypt with wrong private key', async () => {
    const payload = { secret: 'data' };
    const encrypted = await encryptForensics(payload, keyPair.publicKey);

    const otherKeyPair = await generateRSAKeyPair();

    await expect(decryptForensics(encrypted, otherKeyPair.privateKey)).rejects.toThrow();
  });

  it('handles complex nested objects', async () => {
    const payload = {
      url: 'https://test.com',
      metadata: {
        nested: {
          deeply: {
            value: [1, 2, 3],
          },
        },
      },
      array: ['a', 'b', 'c'],
      nullValue: null,
      boolValue: true,
    };

    const encrypted = await encryptForensics(payload, keyPair.publicKey);
    const decrypted = await decryptForensics<typeof payload>(encrypted, keyPair.privateKey);

    expect(decrypted).toEqual(payload);
  });

  it('handles empty object', async () => {
    const payload = {};
    const encrypted = await encryptForensics(payload, keyPair.publicKey);
    const decrypted = await decryptForensics<typeof payload>(encrypted, keyPair.privateKey);
    expect(decrypted).toEqual(payload);
  });

  it('handles string payload', async () => {
    const payload = 'just a string';
    const encrypted = await encryptForensics(payload, keyPair.publicKey);
    const decrypted = await decryptForensics<string>(encrypted, keyPair.privateKey);
    expect(decrypted).toBe(payload);
  });

  it('handles unicode in payload', async () => {
    const payload = {
      url: 'https://例え.jp/パス',
      emoji: '🔒🛡️',
      chinese: '安全',
    };

    const encrypted = await encryptForensics(payload, keyPair.publicKey);
    const decrypted = await decryptForensics<typeof payload>(encrypted, keyPair.privateKey);

    expect(decrypted).toEqual(payload);
  });
});
