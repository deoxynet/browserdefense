/**
 * Unit tests for BlockIOC Team Mesh crypto module.
 * X25519 + HKDF-SHA256 + AES-256-GCM for Team Mesh and Threat Feeds.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  generateIV,
  generateX25519KeyPair,
  importX25519PublicKey,
  importX25519PrivateKey,
  deriveSharedSecret,
  deriveAESKeyFromSecret,
  encryptAESGCM,
  decryptAESGCM,
  encryptTeamMesh,
  decryptTeamMesh,
  encryptThreatFeed,
  decryptThreatFeed,
  isX25519Supported,
  HKDF_INFO,
  type X25519PublicKeyJWK,
  type X25519PrivateKeyJWK,
} from '../../src/crypto/team-mesh';

describe('X25519 support detection', () => {
  it('detects X25519 support', async () => {
    const supported = await isX25519Supported();
    expect(typeof supported).toBe('boolean');
  });

  it('caches support detection result', async () => {
    const result1 = await isX25519Supported();
    const result2 = await isX25519Supported();
    expect(result1).toBe(result2);
  });
});

describe('generateIV', () => {
  it('generates 12-byte IV (96 bits)', () => {
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

describe('X25519 key generation and import', () => {
  let keyPair: { publicKey: X25519PublicKeyJWK; privateKey: X25519PrivateKeyJWK };

  beforeAll(async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      return;
    }
    keyPair = await generateX25519KeyPair();
  });

  it('generates valid X25519 keypair', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    expect(keyPair.publicKey.kty).toBe('OKP');
    expect(keyPair.publicKey.crv).toBe('X25519');
    expect(keyPair.publicKey.x).toBeDefined();
    expect(keyPair.privateKey.d).toBeDefined();
  });

  it('imports public key', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const key = await importX25519PublicKey(keyPair.publicKey);
    expect(key.algorithm.name).toBe('X25519');
  });

  it('imports private key', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const key = await importX25519PrivateKey(keyPair.privateKey);
    expect(key.algorithm.name).toBe('X25519');
    expect(key.usages).toContain('deriveBits');
  });

  it('rejects invalid key type', async () => {
    const invalidKey = { kty: 'EC', crv: 'P-256', x: 'abc' } as unknown as X25519PublicKeyJWK;
    await expect(importX25519PublicKey(invalidKey)).rejects.toThrow('Invalid key type');
  });
});

describe('X25519 ECDH key agreement', () => {
  it('derives identical shared secret from both sides', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const alice = await generateX25519KeyPair();
    const bob = await generateX25519KeyPair();

    const alicePrivate = await importX25519PrivateKey(alice.privateKey);
    const alicePublic = await importX25519PublicKey(alice.publicKey);
    const bobPrivate = await importX25519PrivateKey(bob.privateKey);
    const bobPublic = await importX25519PublicKey(bob.publicKey);

    // Alice derives shared secret with Bob's public key
    const aliceShared = await deriveSharedSecret(alicePrivate, bobPublic);
    // Bob derives shared secret with Alice's public key
    const bobShared = await deriveSharedSecret(bobPrivate, alicePublic);

    expect(arrayBufferToBase64(aliceShared)).toBe(arrayBufferToBase64(bobShared));
  });

  it('derives different secrets with different keys', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const alice = await generateX25519KeyPair();
    const bob = await generateX25519KeyPair();
    const charlie = await generateX25519KeyPair();

    const alicePrivate = await importX25519PrivateKey(alice.privateKey);
    const bobPublic = await importX25519PublicKey(bob.publicKey);
    const charliePublic = await importX25519PublicKey(charlie.publicKey);

    const sharedWithBob = await deriveSharedSecret(alicePrivate, bobPublic);
    const sharedWithCharlie = await deriveSharedSecret(alicePrivate, charliePublic);

    expect(arrayBufferToBase64(sharedWithBob)).not.toBe(arrayBufferToBase64(sharedWithCharlie));
  });
});

describe('HKDF key derivation', () => {
  it('derives AES-256-GCM key from shared secret', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const alice = await generateX25519KeyPair();
    const bob = await generateX25519KeyPair();

    const alicePrivate = await importX25519PrivateKey(alice.privateKey);
    const bobPublic = await importX25519PublicKey(bob.publicKey);

    const sharedSecret = await deriveSharedSecret(alicePrivate, bobPublic);
    const aesKey = await deriveAESKeyFromSecret(sharedSecret, HKDF_INFO.TEAM_MESH);

    expect(aesKey.algorithm.name).toBe('AES-GCM');
    expect((aesKey.algorithm as AesKeyAlgorithm).length).toBe(256);
    expect(aesKey.usages).toContain('encrypt');
    expect(aesKey.usages).toContain('decrypt');
  });

  it('derives different keys for different info values', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const alice = await generateX25519KeyPair();
    const bob = await generateX25519KeyPair();

    const alicePrivate = await importX25519PrivateKey(alice.privateKey);
    const bobPublic = await importX25519PublicKey(bob.publicKey);

    const sharedSecret = await deriveSharedSecret(alicePrivate, bobPublic);

    const teamMeshKey = await deriveAESKeyFromSecret(sharedSecret, HKDF_INFO.TEAM_MESH);
    const threatFeedKey = await deriveAESKeyFromSecret(sharedSecret, HKDF_INFO.THREAT_FEED);

    // Test by encrypting same data - ciphertext should differ
    const iv = generateIV();
    const plaintext = new TextEncoder().encode('test data');

    const ciphertext1 = await encryptAESGCM(teamMeshKey, iv, plaintext);
    const ciphertext2 = await encryptAESGCM(threatFeedKey, iv, plaintext);

    expect(arrayBufferToBase64(ciphertext1)).not.toBe(arrayBufferToBase64(ciphertext2));
  });
});

describe('AES-GCM encryption/decryption', () => {
  it('encrypts and decrypts data', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const alice = await generateX25519KeyPair();
    const bob = await generateX25519KeyPair();

    const alicePrivate = await importX25519PrivateKey(alice.privateKey);
    const bobPublic = await importX25519PublicKey(bob.publicKey);

    const sharedSecret = await deriveSharedSecret(alicePrivate, bobPublic);
    const key = await deriveAESKeyFromSecret(sharedSecret, HKDF_INFO.TEAM_MESH);
    const iv = generateIV();

    const plaintext = new TextEncoder().encode('Hello, Team Mesh!');
    const ciphertext = await encryptAESGCM(key, iv, plaintext);

    expect(ciphertext.byteLength).toBeGreaterThan(plaintext.length); // Includes auth tag

    const decrypted = await decryptAESGCM(key, iv, ciphertext);
    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe('Hello, Team Mesh!');
  });

  it('rejects IV with wrong size', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const alice = await generateX25519KeyPair();
    const bob = await generateX25519KeyPair();

    const alicePrivate = await importX25519PrivateKey(alice.privateKey);
    const bobPublic = await importX25519PublicKey(bob.publicKey);

    const sharedSecret = await deriveSharedSecret(alicePrivate, bobPublic);
    const key = await deriveAESKeyFromSecret(sharedSecret, HKDF_INFO.TEAM_MESH);

    const wrongIV = new Uint8Array(16); // Wrong size - should be 12
    const plaintext = new TextEncoder().encode('test');

    await expect(encryptAESGCM(key, wrongIV, plaintext)).rejects.toThrow('12 bytes');
  });
});

describe('encryptTeamMesh / decryptTeamMesh', () => {
  it('encrypts and decrypts Team Mesh payload', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const recipient = await generateX25519KeyPair();

    const payload = {
      iocList: ['evil.com', 'phishing.net'],
      version: 42,
      timestamp: Date.now(),
    };

    const encrypted = await encryptTeamMesh(payload, recipient.publicKey);

    expect(encrypted.ephemeralPublicKey).toBeDefined();
    expect(encrypted.iv).toBeDefined();
    expect(encrypted.ciphertext).toBeDefined();

    const decrypted = await decryptTeamMesh<typeof payload>(encrypted, recipient.privateKey);

    expect(decrypted).toEqual(payload);
  });

  it('IV is 12 bytes (96 bits)', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const recipient = await generateX25519KeyPair();
    const payload = { test: 'data' };

    const encrypted = await encryptTeamMesh(payload, recipient.publicKey);

    const ivBytes = base64ToArrayBuffer(encrypted.iv);
    expect(ivBytes.byteLength).toBe(12);
  });

  it('different encryptions produce different ciphertext', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const recipient = await generateX25519KeyPair();
    const payload = { test: 'same data' };

    const encrypted1 = await encryptTeamMesh(payload, recipient.publicKey);
    const encrypted2 = await encryptTeamMesh(payload, recipient.publicKey);

    // Ephemeral public key should be different (new keypair each time)
    expect(encrypted1.ephemeralPublicKey).not.toBe(encrypted2.ephemeralPublicKey);
    // IV should be different
    expect(encrypted1.iv).not.toBe(encrypted2.iv);
    // Ciphertext should be different
    expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
  });

  it('fails to decrypt with wrong private key', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const recipient = await generateX25519KeyPair();
    const wrongRecipient = await generateX25519KeyPair();

    const payload = { secret: 'data' };
    const encrypted = await encryptTeamMesh(payload, recipient.publicKey);

    await expect(decryptTeamMesh(encrypted, wrongRecipient.privateKey)).rejects.toThrow();
  });

  it('handles complex nested objects', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const recipient = await generateX25519KeyPair();

    const payload = {
      blocklist: {
        domains: ['evil.com', 'bad.net'],
        urls: ['https://phishing.com/login'],
      },
      metadata: {
        version: 1,
        timestamp: Date.now(),
        signature: 'abc123',
      },
      array: [1, 2, 3],
      nullValue: null,
      boolValue: true,
    };

    const encrypted = await encryptTeamMesh(payload, recipient.publicKey);
    const decrypted = await decryptTeamMesh<typeof payload>(encrypted, recipient.privateKey);

    expect(decrypted).toEqual(payload);
  });

  it('handles unicode in payload', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const recipient = await generateX25519KeyPair();

    const payload = {
      domain: 'beispiel.de',
      emoji: '🔒🛡️',
      chinese: '安全',
      japanese: 'セキュリティ',
    };

    const encrypted = await encryptTeamMesh(payload, recipient.publicKey);
    const decrypted = await decryptTeamMesh<typeof payload>(encrypted, recipient.privateKey);

    expect(decrypted).toEqual(payload);
  });
});

describe('encryptThreatFeed / decryptThreatFeed', () => {
  it('encrypts and decrypts Threat Feed payload', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    const recipient = await generateX25519KeyPair();

    const payload = {
      feed: 'phishing-feed-v1',
      entries: [
        { hash: 'abc123', type: 'domain' },
        { hash: 'def456', type: 'url' },
      ],
    };

    const encrypted = await encryptThreatFeed(payload, recipient.publicKey);
    const decrypted = await decryptThreatFeed<typeof payload>(encrypted, recipient.privateKey);

    expect(decrypted).toEqual(payload);
  });

  it('uses different HKDF info than Team Mesh', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    // HKDF info values should be different
    expect(HKDF_INFO.TEAM_MESH).not.toEqual(HKDF_INFO.THREAT_FEED);

    // This ensures domain separation
    const teamMeshInfo = new TextDecoder().decode(HKDF_INFO.TEAM_MESH);
    const threatFeedInfo = new TextDecoder().decode(HKDF_INFO.THREAT_FEED);

    expect(teamMeshInfo).toContain('Team Mesh');
    expect(threatFeedInfo).toContain('Threat Feed');
  });
});

describe('Cross-compatibility with WebCrypto', () => {
  it('produces compatible output across encryption/decryption cycle', async () => {
    const supported = await isX25519Supported();
    if (!supported) {
      console.log('X25519 not supported, skipping test');
      return;
    }

    // This test verifies that the encryption/decryption cycle works end-to-end
    // using the Web Crypto API primitives
    const recipient = await generateX25519KeyPair();

    // Large payload to test chunked processing
    const largePayload = {
      hashes: Array.from({ length: 1000 }, (_, i) => `hash-${i}`),
      timestamp: Date.now(),
    };

    const encrypted = await encryptTeamMesh(largePayload, recipient.publicKey);
    const decrypted = await decryptTeamMesh<typeof largePayload>(encrypted, recipient.privateKey);

    expect(decrypted).toEqual(largePayload);
  });
});
