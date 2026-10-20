import { describe, it, expect, beforeAll } from 'vitest';
import {
  importPublicKeySpki,
  importPublicKeyJwk,
  importPublicKeyP256Jwk,
  importPublicKeyEd25519Jwk,
  verifySignature,
  verifySignatureP256,
  verifySignatureEd25519,
  verifyBlocklistSignature,
  importSigningPublicKey,
  verifySignatureAuto,
  isEd25519Supported,
  base64ToArrayBuffer,
  arrayBufferToBase64,
  hexToArrayBuffer,
  arrayBufferToHex,
  type AlgorithmVersion,
} from '../src/crypto/signing';

// Generate a test P-256 keypair for use in tests
async function generateTestKeyPairP256(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

// Generate a test Ed25519 keypair for use in tests
async function generateTestKeyPairEd25519(): Promise<CryptoKeyPair | null> {
  try {
    return await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  } catch {
    // Ed25519 not supported
    return null;
  }
}

// Sign data with a P-256 private key (for test purposes)
async function signDataP256(privateKey: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
  return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);
}

// Sign data with an Ed25519 private key (for test purposes)
async function signDataEd25519(privateKey: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
  return crypto.subtle.sign('Ed25519', privateKey, data);
}

describe('P-256 ECDSA Signature Verification', () => {
  let testKeyPair: CryptoKeyPair;
  let publicKeyJwk: JsonWebKey;
  let publicKeySpki: ArrayBuffer;

  beforeAll(async () => {
    // Generate test keypair
    testKeyPair = await generateTestKeyPairP256();

    // Export public key in both formats
    publicKeyJwk = await crypto.subtle.exportKey('jwk', testKeyPair.publicKey);
    publicKeySpki = await crypto.subtle.exportKey('spki', testKeyPair.publicKey);
  });

  describe('importPublicKeyJwk (P-256)', () => {
    it('should import a valid P-256 JWK public key', async () => {
      const key = await importPublicKeyJwk(publicKeyJwk);
      expect(key).toBeDefined();
      expect(key.type).toBe('public');
      expect(key.algorithm.name).toBe('ECDSA');
    });

    it('should reject non-P-256 keys', async () => {
      const invalidJwk: JsonWebKey = {
        kty: 'RSA',
        crv: undefined,
        n: 'test',
        e: 'AQAB',
      };

      await expect(importPublicKeyJwk(invalidJwk)).rejects.toThrow('Invalid key type');
    });

    it('should reject P-384 keys', async () => {
      const p384Jwk: JsonWebKey = {
        kty: 'EC',
        crv: 'P-384',
        x: 'test',
        y: 'test',
      };

      await expect(importPublicKeyJwk(p384Jwk)).rejects.toThrow('Invalid key type');
    });
  });

  describe('importPublicKeySpki', () => {
    it('should import a valid SPKI-encoded public key', async () => {
      const key = await importPublicKeySpki(publicKeySpki);
      expect(key).toBeDefined();
      expect(key.type).toBe('public');
    });
  });

  describe('verifySignature (P-256)', () => {
    it('should verify a valid signature', async () => {
      const data = new TextEncoder().encode('Hello, BrowserDefense!');
      const signature = await signDataP256(testKeyPair.privateKey, data);

      const isValid = await verifySignature(testKeyPair.publicKey, signature, data);
      expect(isValid).toBe(true);
    });

    it('should reject an invalid signature', async () => {
      const data = new TextEncoder().encode('Hello, BrowserDefense!');
      const signature = await signDataP256(testKeyPair.privateKey, data);

      // Tamper with the signature
      const tamperedSig = new Uint8Array(signature);
      tamperedSig[0] ^= 0xff;

      const isValid = await verifySignature(testKeyPair.publicKey, tamperedSig.buffer, data);
      expect(isValid).toBe(false);
    });

    it('should reject signature for different data', async () => {
      const data1 = new TextEncoder().encode('Original data');
      const data2 = new TextEncoder().encode('Different data');

      const signature = await signDataP256(testKeyPair.privateKey, data1);

      const isValid = await verifySignature(testKeyPair.publicKey, signature, data2);
      expect(isValid).toBe(false);
    });

    it('should handle empty data', async () => {
      const data = new TextEncoder().encode('');
      const signature = await signDataP256(testKeyPair.privateKey, data);

      const isValid = await verifySignature(testKeyPair.publicKey, signature, data);
      expect(isValid).toBe(true);
    });

    it('should handle large data', async () => {
      const data = new TextEncoder().encode('x'.repeat(100000));
      const signature = await signDataP256(testKeyPair.privateKey, data);

      const isValid = await verifySignature(testKeyPair.publicKey, signature, data);
      expect(isValid).toBe(true);
    });
  });

  describe('verifyBlocklistSignature (P-256)', () => {
    it('should verify a valid blocklist manifest signature', async () => {
      const manifest = {
        version: '1.0.0',
        total_iocs: 1000,
        bucket_count: 10,
        sha256_root: 'abc123',
      };

      // Create canonical JSON (sorted keys)
      const signedFields = {
        bucket_count: manifest.bucket_count,
        sha256_root: manifest.sha256_root,
        total_iocs: manifest.total_iocs,
        version: manifest.version,
      };
      const manifestBody = JSON.stringify(signedFields, Object.keys(signedFields).sort());
      const data = new TextEncoder().encode(manifestBody);

      // Sign with test key
      const signature = await signDataP256(testKeyPair.privateKey, data);
      const signatureBase64 = arrayBufferToBase64(signature);

      // Verify
      const isValid = await verifyBlocklistSignature(manifest, signatureBase64, publicKeyJwk);
      expect(isValid).toBe(true);
    });

    it('should reject tampered manifest', async () => {
      const manifest = {
        version: '1.0.0',
        total_iocs: 1000,
        bucket_count: 10,
        sha256_root: 'abc123',
      };

      // Sign original
      const signedFields = {
        bucket_count: manifest.bucket_count,
        sha256_root: manifest.sha256_root,
        total_iocs: manifest.total_iocs,
        version: manifest.version,
      };
      const manifestBody = JSON.stringify(signedFields, Object.keys(signedFields).sort());
      const data = new TextEncoder().encode(manifestBody);
      const signature = await signDataP256(testKeyPair.privateKey, data);
      const signatureBase64 = arrayBufferToBase64(signature);

      // Tamper with manifest
      const tamperedManifest = { ...manifest, total_iocs: 2000 };

      const isValid = await verifyBlocklistSignature(tamperedManifest, signatureBase64, publicKeyJwk);
      expect(isValid).toBe(false);
    });

    it('should reject invalid signature format', async () => {
      const manifest = {
        version: '1.0.0',
        total_iocs: 1000,
        bucket_count: 10,
        sha256_root: 'abc123',
      };

      const isValid = await verifyBlocklistSignature(manifest, 'invalid-base64!!!', publicKeyJwk);
      expect(isValid).toBe(false);
    });
  });
});

// Only run Ed25519 tests if supported
describe('Ed25519 Signature Verification', () => {
  let testKeyPair: CryptoKeyPair | null;
  let publicKeyJwk: JsonWebKey | null;
  let ed25519Supported: boolean;

  beforeAll(async () => {
    ed25519Supported = await isEd25519Supported();
    if (ed25519Supported) {
      testKeyPair = await generateTestKeyPairEd25519();
      if (testKeyPair) {
        publicKeyJwk = await crypto.subtle.exportKey('jwk', testKeyPair.publicKey);
      }
    }
  });

  describe('isEd25519Supported', () => {
    it('should return a boolean', async () => {
      const supported = await isEd25519Supported();
      expect(typeof supported).toBe('boolean');
    });
  });

  describe('importPublicKeyEd25519Jwk', () => {
    it('should import a valid Ed25519 JWK public key', async () => {
      if (!ed25519Supported || !publicKeyJwk) {
        console.log('Skipping Ed25519 test - not supported in this environment');
        return;
      }

      const key = await importPublicKeyEd25519Jwk(publicKeyJwk);
      expect(key).toBeDefined();
      expect(key.type).toBe('public');
      expect(key.algorithm.name).toBe('Ed25519');
    });

    it('should reject non-Ed25519 keys', async () => {
      if (!ed25519Supported) {
        console.log('Skipping Ed25519 test - not supported in this environment');
        return;
      }

      const invalidJwk: JsonWebKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'test',
        y: 'test',
      };

      await expect(importPublicKeyEd25519Jwk(invalidJwk)).rejects.toThrow('Invalid key type');
    });
  });

  describe('verifySignatureEd25519', () => {
    it('should verify a valid signature', async () => {
      if (!ed25519Supported || !testKeyPair) {
        console.log('Skipping Ed25519 test - not supported in this environment');
        return;
      }

      const data = new TextEncoder().encode('Hello, BrowserDefense!');
      const signature = await signDataEd25519(testKeyPair.privateKey, data);

      const isValid = await verifySignatureEd25519(testKeyPair.publicKey, signature, data);
      expect(isValid).toBe(true);
    });

    it('should reject an invalid signature', async () => {
      if (!ed25519Supported || !testKeyPair) {
        console.log('Skipping Ed25519 test - not supported in this environment');
        return;
      }

      const data = new TextEncoder().encode('Hello, BrowserDefense!');
      const signature = await signDataEd25519(testKeyPair.privateKey, data);

      // Tamper with the signature
      const tamperedSig = new Uint8Array(signature);
      tamperedSig[0] ^= 0xff;

      const isValid = await verifySignatureEd25519(testKeyPair.publicKey, tamperedSig.buffer, data);
      expect(isValid).toBe(false);
    });

    it('should reject signature for different data', async () => {
      if (!ed25519Supported || !testKeyPair) {
        console.log('Skipping Ed25519 test - not supported in this environment');
        return;
      }

      const data1 = new TextEncoder().encode('Original data');
      const data2 = new TextEncoder().encode('Different data');

      const signature = await signDataEd25519(testKeyPair.privateKey, data1);

      const isValid = await verifySignatureEd25519(testKeyPair.publicKey, signature, data2);
      expect(isValid).toBe(false);
    });
  });

  describe('verifyBlocklistSignature (Ed25519)', () => {
    it('should verify a valid blocklist manifest signature', async () => {
      if (!ed25519Supported || !testKeyPair || !publicKeyJwk) {
        console.log('Skipping Ed25519 test - not supported in this environment');
        return;
      }

      const manifest = {
        version: '1.0.0',
        total_iocs: 1000,
        bucket_count: 10,
        sha256_root: 'abc123',
      };

      // Create canonical JSON (sorted keys)
      const signedFields = {
        bucket_count: manifest.bucket_count,
        sha256_root: manifest.sha256_root,
        total_iocs: manifest.total_iocs,
        version: manifest.version,
      };
      const manifestBody = JSON.stringify(signedFields, Object.keys(signedFields).sort());
      const data = new TextEncoder().encode(manifestBody);

      // Sign with test key
      const signature = await signDataEd25519(testKeyPair.privateKey, data);
      const signatureBase64 = arrayBufferToBase64(signature);

      // Verify
      const isValid = await verifyBlocklistSignature(manifest, signatureBase64, publicKeyJwk);
      expect(isValid).toBe(true);
    });
  });
});

describe('importSigningPublicKey (auto-detect)', () => {
  let p256KeyPair: CryptoKeyPair;
  let p256PublicKeyJwk: JsonWebKey;

  beforeAll(async () => {
    p256KeyPair = await generateTestKeyPairP256();
    p256PublicKeyJwk = await crypto.subtle.exportKey('jwk', p256KeyPair.publicKey);
  });

  it('should detect and import P-256 key', async () => {
    const { key, algorithm } = await importSigningPublicKey(p256PublicKeyJwk);
    expect(key).toBeDefined();
    expect(algorithm).toBe('p256-v1');
  });

  it('should detect and import Ed25519 key if supported', async () => {
    const ed25519Supported = await isEd25519Supported();
    if (!ed25519Supported) {
      console.log('Skipping Ed25519 test - not supported in this environment');
      return;
    }

    const ed25519KeyPair = await generateTestKeyPairEd25519();
    if (!ed25519KeyPair) return;

    const ed25519PublicKeyJwk = await crypto.subtle.exportKey('jwk', ed25519KeyPair.publicKey);
    const { key, algorithm } = await importSigningPublicKey(ed25519PublicKeyJwk);

    expect(key).toBeDefined();
    expect(algorithm).toBe('ed25519-v2');
  });

  it('should reject unsupported key types', async () => {
    const rsaJwk: JsonWebKey = {
      kty: 'RSA',
      n: 'test',
      e: 'AQAB',
    };

    await expect(importSigningPublicKey(rsaJwk)).rejects.toThrow('Unsupported signing key type');
  });
});

describe('verifySignatureAuto', () => {
  let p256KeyPair: CryptoKeyPair;

  beforeAll(async () => {
    p256KeyPair = await generateTestKeyPairP256();
  });

  it('should verify P-256 signature with correct algorithm', async () => {
    const data = new TextEncoder().encode('Test data');
    const signature = await signDataP256(p256KeyPair.privateKey, data);

    const isValid = await verifySignatureAuto(p256KeyPair.publicKey, 'p256-v1', signature, data);
    expect(isValid).toBe(true);
  });

  it('should verify Ed25519 signature with correct algorithm if supported', async () => {
    const ed25519Supported = await isEd25519Supported();
    if (!ed25519Supported) {
      console.log('Skipping Ed25519 test - not supported in this environment');
      return;
    }

    const ed25519KeyPair = await generateTestKeyPairEd25519();
    if (!ed25519KeyPair) return;

    const data = new TextEncoder().encode('Test data');
    const signature = await signDataEd25519(ed25519KeyPair.privateKey, data);

    const isValid = await verifySignatureAuto(
      ed25519KeyPair.publicKey,
      'ed25519-v2',
      signature,
      data
    );
    expect(isValid).toBe(true);
  });
});

describe('Helper Functions', () => {
  describe('base64ToArrayBuffer / arrayBufferToBase64', () => {
    it('should roundtrip correctly', () => {
      const original = new Uint8Array([0, 1, 2, 255, 128, 64]);
      const base64 = arrayBufferToBase64(original.buffer);
      const result = new Uint8Array(base64ToArrayBuffer(base64));

      expect(Array.from(result)).toEqual(Array.from(original));
    });

    it('should handle empty buffer', () => {
      const original = new Uint8Array([]);
      const base64 = arrayBufferToBase64(original.buffer);
      const result = new Uint8Array(base64ToArrayBuffer(base64));

      expect(result.length).toBe(0);
    });

    it('should handle large buffers', () => {
      const original = new Uint8Array(100000);
      // Fill with pattern (crypto.getRandomValues has a 65536 byte limit)
      for (let i = 0; i < original.length; i++) {
        original[i] = i % 256;
      }

      const base64 = arrayBufferToBase64(original.buffer);
      const result = new Uint8Array(base64ToArrayBuffer(base64));

      expect(Array.from(result)).toEqual(Array.from(original));
    });
  });

  describe('hexToArrayBuffer / arrayBufferToHex', () => {
    it('should roundtrip correctly', () => {
      const original = new Uint8Array([0x00, 0x01, 0xff, 0xab, 0xcd]);
      const hex = arrayBufferToHex(original.buffer);
      const result = new Uint8Array(hexToArrayBuffer(hex));

      expect(Array.from(result)).toEqual(Array.from(original));
    });

    it('should produce lowercase hex', () => {
      const buffer = new Uint8Array([0xab, 0xcd, 0xef]).buffer;
      const hex = arrayBufferToHex(buffer);

      expect(hex).toBe('abcdef');
    });

    it('should handle 0x prefix', () => {
      const result = new Uint8Array(hexToArrayBuffer('0xaabbcc'));
      expect(Array.from(result)).toEqual([0xaa, 0xbb, 0xcc]);
    });

    it('should reject odd-length hex strings', () => {
      expect(() => hexToArrayBuffer('abc')).toThrow('even length');
    });

    it('should handle empty hex string', () => {
      const result = new Uint8Array(hexToArrayBuffer(''));
      expect(result.length).toBe(0);
    });
  });
});
