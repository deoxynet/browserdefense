/**
 * Threat Feed Distribution Tests
 *
 * Tests for Issue #395: Threat Feed Distribution (Broadcast)
 *
 * Verifies that:
 * - Server can generate multi-header envelopes for active keys
 * - Extension can decrypt payload using matching kid
 * - Rotation works by adding/removing headers without re-encrypting payload
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  createThreatFeedEnvelope,
  decryptThreatFeed,
  addEnvelopeHeader,
  removeEnvelopeHeader,
  generateGpoKeyPair,
  generateX25519KeyPair,
  importX25519PublicKey,
  importX25519PrivateKey,
  deriveSharedSecret,
  deriveAesKeyFromHkdf,
  isX25519Supported,
  type X25519PrivateKeyJWK,
  type X25519PublicKeyJWK,
  type ActiveKey,
  type ThreatFeedEnvelope,
} from '../src/crypto/threat-feed';

describe('Threat Feed Distribution (Issue #395)', () => {
  // Skip tests if X25519 is not supported
  let x25519Available = false;

  beforeAll(async () => {
    x25519Available = await isX25519Supported();
    if (!x25519Available) {
      console.warn('X25519 is not supported in this environment, skipping tests');
    }
  });

  describe('X25519 Key Operations', () => {
    it.skipIf(!true)('should generate X25519 keypair', async () => {
      if (!x25519Available) return;

      const keyPair = await generateX25519KeyPair();

      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
    });

    it('should generate GPO keypair with kid', async () => {
      if (!x25519Available) return;

      const { publicKey, privateKey } = await generateGpoKeyPair('2026_test');

      expect(publicKey.kty).toBe('OKP');
      expect(publicKey.crv).toBe('X25519');
      expect(publicKey.kid).toMatch(/^2026_test_v\d+$/);
      expect(publicKey.x).toBeDefined();

      expect(privateKey.kty).toBe('OKP');
      expect(privateKey.crv).toBe('X25519');
      expect(privateKey.kid).toBe(publicKey.kid);
      expect(privateKey.x).toBeDefined();
      expect(privateKey.d).toBeDefined();
    });

    it('should import and export X25519 public key', async () => {
      if (!x25519Available) return;

      const { publicKey } = await generateGpoKeyPair();

      const imported = await importX25519PublicKey(publicKey);
      expect(imported).toBeDefined();
    });

    it('should import X25519 private key', async () => {
      if (!x25519Available) return;

      const { privateKey } = await generateGpoKeyPair();

      const imported = await importX25519PrivateKey(privateKey);
      expect(imported).toBeDefined();
    });

    it('should derive shared secret', async () => {
      if (!x25519Available) return;

      const keyPair1 = await generateGpoKeyPair('alice');
      const keyPair2 = await generateGpoKeyPair('bob');

      const alicePrivate = await importX25519PrivateKey(keyPair1.privateKey);
      const bobPublic = await importX25519PublicKey(keyPair2.publicKey);

      const bobPrivate = await importX25519PrivateKey(keyPair2.privateKey);
      const alicePublic = await importX25519PublicKey(keyPair1.publicKey);

      const secret1 = await deriveSharedSecret(alicePrivate, bobPublic);
      const secret2 = await deriveSharedSecret(bobPrivate, alicePublic);

      // Shared secrets should be identical
      expect(new Uint8Array(secret1)).toEqual(new Uint8Array(secret2));
    });

    it('should derive AES key from shared secret', async () => {
      if (!x25519Available) return;

      const sharedSecret = crypto.getRandomValues(new Uint8Array(32)).buffer;

      const aesKey = await deriveAesKeyFromHkdf(sharedSecret);

      expect(aesKey).toBeDefined();
      expect(aesKey.type).toBe('secret');
    });
  });

  describe('Envelope Creation', () => {
    it('should create envelope for single key', async () => {
      if (!x25519Available) return;

      const { publicKey, privateKey } = await generateGpoKeyPair('single_key');
      const activeKeys: ActiveKey[] = [{ kid: publicKey.kid!, publicKey }];

      const payload = { iocs: ['evil.com', 'bad.org'] };
      const { envelope } = await createThreatFeedEnvelope(payload, activeKeys);

      expect(envelope.meta.version).toBe('2026-01-09');
      expect(envelope.meta.generated_at).toBeDefined();
      expect(envelope.headers.length).toBe(1);
      expect(envelope.headers[0].kid).toBe(publicKey.kid);
      expect(envelope.headers[0].ephemeral_pub).toBeDefined();
      expect(envelope.headers[0].encrypted_session_key).toBeDefined();
      expect(envelope.headers[0].wrap_iv).toBeDefined();
      expect(envelope.iv).toBeDefined();
      expect(envelope.ciphertext).toBeDefined();
    });

    it('should create envelope for multiple keys', async () => {
      if (!x25519Available) return;

      const key1 = await generateGpoKeyPair('2025_key');
      const key2 = await generateGpoKeyPair('2026_key');

      const activeKeys: ActiveKey[] = [
        { kid: key1.publicKey.kid!, publicKey: key1.publicKey },
        { kid: key2.publicKey.kid!, publicKey: key2.publicKey },
      ];

      const payload = { iocs: ['evil.com'] };
      const { envelope } = await createThreatFeedEnvelope(payload, activeKeys);

      expect(envelope.headers.length).toBe(2);
      expect(envelope.headers.map((h) => h.kid)).toContain(key1.publicKey.kid);
      expect(envelope.headers.map((h) => h.kid)).toContain(key2.publicKey.kid);
    });

    it('should reject empty active keys', async () => {
      if (!x25519Available) return;

      const payload = { iocs: ['evil.com'] };

      await expect(createThreatFeedEnvelope(payload, [])).rejects.toThrow(
        'At least one active key is required'
      );
    });

    it('should include session key when requested', async () => {
      if (!x25519Available) return;

      const { publicKey } = await generateGpoKeyPair('test');
      const activeKeys: ActiveKey[] = [{ kid: publicKey.kid!, publicKey }];

      const payload = { test: 'data' };
      const { envelope, sessionKeyBytes } = await createThreatFeedEnvelope(payload, activeKeys, {
        includeSessionKey: true,
      });

      expect(envelope).toBeDefined();
      expect(sessionKeyBytes).toBeDefined();
      expect(sessionKeyBytes!.length).toBe(32); // 256-bit AES key
    });

    it('should use custom version', async () => {
      if (!x25519Available) return;

      const { publicKey } = await generateGpoKeyPair('test');
      const activeKeys: ActiveKey[] = [{ kid: publicKey.kid!, publicKey }];

      const payload = { test: 'data' };
      const { envelope } = await createThreatFeedEnvelope(payload, activeKeys, {
        version: 'custom-v1',
      });

      expect(envelope.meta.version).toBe('custom-v1');
    });
  });

  describe('Envelope Decryption', () => {
    it('should decrypt envelope with matching key', async () => {
      if (!x25519Available) return;

      const { publicKey, privateKey } = await generateGpoKeyPair('decrypt_test');
      const activeKeys: ActiveKey[] = [{ kid: publicKey.kid!, publicKey }];

      const originalPayload = {
        iocs: ['evil.com', 'bad.org', 'phishing.net'],
        version: 1,
      };
      const { envelope } = await createThreatFeedEnvelope(originalPayload, activeKeys);

      const decrypted = await decryptThreatFeed<typeof originalPayload>(envelope, privateKey);

      expect(decrypted).toEqual(originalPayload);
    });

    it('should decrypt with correct key from multi-key envelope', async () => {
      if (!x25519Available) return;

      const key1 = await generateGpoKeyPair('2025_key');
      const key2 = await generateGpoKeyPair('2026_key');
      const key3 = await generateGpoKeyPair('2027_key');

      const activeKeys: ActiveKey[] = [
        { kid: key1.publicKey.kid!, publicKey: key1.publicKey },
        { kid: key2.publicKey.kid!, publicKey: key2.publicKey },
        { kid: key3.publicKey.kid!, publicKey: key3.publicKey },
      ];

      const originalPayload = { iocs: ['evil.com'], count: 42 };
      const { envelope } = await createThreatFeedEnvelope(originalPayload, activeKeys);

      // Decrypt with each key - all should work
      const decrypted1 = await decryptThreatFeed<typeof originalPayload>(
        envelope,
        key1.privateKey
      );
      const decrypted2 = await decryptThreatFeed<typeof originalPayload>(
        envelope,
        key2.privateKey
      );
      const decrypted3 = await decryptThreatFeed<typeof originalPayload>(
        envelope,
        key3.privateKey
      );

      expect(decrypted1).toEqual(originalPayload);
      expect(decrypted2).toEqual(originalPayload);
      expect(decrypted3).toEqual(originalPayload);
    });

    it('should reject private key without kid', async () => {
      if (!x25519Available) return;

      const { publicKey, privateKey } = await generateGpoKeyPair('test');
      const activeKeys: ActiveKey[] = [{ kid: publicKey.kid!, publicKey }];

      const { envelope } = await createThreatFeedEnvelope({ test: 'data' }, activeKeys);

      // Remove kid from private key
      const keyWithoutKid = { ...privateKey };
      delete (keyWithoutKid as Partial<X25519PrivateKeyJWK>).kid;

      await expect(
        decryptThreatFeed(envelope, keyWithoutKid as X25519PrivateKeyJWK)
      ).rejects.toThrow('Private key must have a kid');
    });

    it('should reject non-matching kid', async () => {
      if (!x25519Available) return;

      const key1 = await generateGpoKeyPair('key1');
      const key2 = await generateGpoKeyPair('key2');

      const activeKeys: ActiveKey[] = [{ kid: key1.publicKey.kid!, publicKey: key1.publicKey }];

      const { envelope } = await createThreatFeedEnvelope({ test: 'data' }, activeKeys);

      // Try to decrypt with key2 (not in envelope)
      await expect(decryptThreatFeed(envelope, key2.privateKey)).rejects.toThrow(
        /No matching header for kid/
      );
    });

    it('should handle large payloads', async () => {
      if (!x25519Available) return;

      const { publicKey, privateKey } = await generateGpoKeyPair('large_payload');
      const activeKeys: ActiveKey[] = [{ kid: publicKey.kid!, publicKey }];

      // Create large payload (100KB+)
      const largeIocs = Array.from({ length: 5000 }, (_, i) => `evil${i}.example.com`);
      const originalPayload = { iocs: largeIocs, version: 1 };

      const { envelope } = await createThreatFeedEnvelope(originalPayload, activeKeys);

      const decrypted = await decryptThreatFeed<typeof originalPayload>(envelope, privateKey);

      expect(decrypted.iocs.length).toBe(5000);
      expect(decrypted).toEqual(originalPayload);
    });

    it('should handle complex nested payloads', async () => {
      if (!x25519Available) return;

      const { publicKey, privateKey } = await generateGpoKeyPair('complex');
      const activeKeys: ActiveKey[] = [{ kid: publicKey.kid!, publicKey }];

      const originalPayload = {
        iocs: [
          { domain: 'evil.com', type: 'phishing', severity: 'high' },
          { domain: 'bad.org', type: 'malware', severity: 'critical' },
        ],
        metadata: {
          source: 'threat-intel',
          timestamp: new Date().toISOString(),
          nested: {
            level2: {
              level3: ['a', 'b', 'c'],
            },
          },
        },
      };

      const { envelope } = await createThreatFeedEnvelope(originalPayload, activeKeys);
      const decrypted = await decryptThreatFeed<typeof originalPayload>(envelope, privateKey);

      expect(decrypted).toEqual(originalPayload);
    });
  });

  describe('Key Rotation', () => {
    it('should add new header without re-encrypting payload', async () => {
      if (!x25519Available) return;

      const key1 = await generateGpoKeyPair('original');
      const key2 = await generateGpoKeyPair('rotated');

      const activeKeys: ActiveKey[] = [{ kid: key1.publicKey.kid!, publicKey: key1.publicKey }];

      const originalPayload = { iocs: ['evil.com'] };
      const { envelope, sessionKeyBytes } = await createThreatFeedEnvelope(
        originalPayload,
        activeKeys,
        {
          includeSessionKey: true,
        }
      );

      expect(envelope.headers.length).toBe(1);

      // Add new key header
      const updatedEnvelope = await addEnvelopeHeader(
        envelope,
        { kid: key2.publicKey.kid!, publicKey: key2.publicKey },
        sessionKeyBytes!
      );

      expect(updatedEnvelope.headers.length).toBe(2);
      // Payload ciphertext should be unchanged
      expect(updatedEnvelope.ciphertext).toBe(envelope.ciphertext);
      expect(updatedEnvelope.iv).toBe(envelope.iv);

      // Both keys should be able to decrypt
      const decrypted1 = await decryptThreatFeed<typeof originalPayload>(
        updatedEnvelope,
        key1.privateKey
      );
      const decrypted2 = await decryptThreatFeed<typeof originalPayload>(
        updatedEnvelope,
        key2.privateKey
      );

      expect(decrypted1).toEqual(originalPayload);
      expect(decrypted2).toEqual(originalPayload);
    });

    it('should remove header by kid', async () => {
      if (!x25519Available) return;

      const key1 = await generateGpoKeyPair('keep');
      const key2 = await generateGpoKeyPair('remove');

      const activeKeys: ActiveKey[] = [
        { kid: key1.publicKey.kid!, publicKey: key1.publicKey },
        { kid: key2.publicKey.kid!, publicKey: key2.publicKey },
      ];

      const originalPayload = { iocs: ['evil.com'] };
      const { envelope } = await createThreatFeedEnvelope(originalPayload, activeKeys);

      expect(envelope.headers.length).toBe(2);

      // Remove key2
      const updatedEnvelope = removeEnvelopeHeader(envelope, key2.publicKey.kid!);

      expect(updatedEnvelope.headers.length).toBe(1);
      expect(updatedEnvelope.headers[0].kid).toBe(key1.publicKey.kid);

      // key1 should still work
      const decrypted = await decryptThreatFeed<typeof originalPayload>(
        updatedEnvelope,
        key1.privateKey
      );
      expect(decrypted).toEqual(originalPayload);

      // key2 should fail
      await expect(decryptThreatFeed(updatedEnvelope, key2.privateKey)).rejects.toThrow(
        /No matching header for kid/
      );
    });

    it('should handle full key rotation (add new, remove old)', async () => {
      if (!x25519Available) return;

      const oldKey = await generateGpoKeyPair('2025_key');
      const newKey = await generateGpoKeyPair('2026_key');

      // Start with old key only
      const activeKeys: ActiveKey[] = [
        { kid: oldKey.publicKey.kid!, publicKey: oldKey.publicKey },
      ];

      const originalPayload = { iocs: ['evil.com'], version: 1 };
      const { envelope, sessionKeyBytes } = await createThreatFeedEnvelope(
        originalPayload,
        activeKeys,
        { includeSessionKey: true }
      );

      // Step 1: Add new key (both keys work during transition)
      let currentEnvelope = await addEnvelopeHeader(
        envelope,
        { kid: newKey.publicKey.kid!, publicKey: newKey.publicKey },
        sessionKeyBytes!
      );

      expect(currentEnvelope.headers.length).toBe(2);

      // Both keys work
      expect(
        await decryptThreatFeed<typeof originalPayload>(currentEnvelope, oldKey.privateKey)
      ).toEqual(originalPayload);
      expect(
        await decryptThreatFeed<typeof originalPayload>(currentEnvelope, newKey.privateKey)
      ).toEqual(originalPayload);

      // Step 2: Remove old key (only new key works)
      currentEnvelope = removeEnvelopeHeader(currentEnvelope, oldKey.publicKey.kid!);

      expect(currentEnvelope.headers.length).toBe(1);

      // New key works
      expect(
        await decryptThreatFeed<typeof originalPayload>(currentEnvelope, newKey.privateKey)
      ).toEqual(originalPayload);

      // Old key fails
      await expect(decryptThreatFeed(currentEnvelope, oldKey.privateKey)).rejects.toThrow(
        /No matching header for kid/
      );
    });
  });

  describe('Extension Key Priority', () => {
    it('should document key priority (GPO > local)', async () => {
      if (!x25519Available) return;

      // This test documents the expected key priority behavior
      // In production:
      // - Priority 1 (Prod): chrome.storage.managed.gpo_private_key
      // - Priority 2 (Demo): chrome.storage.local.manual_private_key

      const gpoKey = await generateGpoKeyPair('gpo');
      const localKey = await generateGpoKeyPair('local');

      // Simulate: GPO key takes precedence when both are present
      const activeGpoKey = gpoKey.privateKey;
      const activeLocalKey = localKey.privateKey;

      // The extension should prefer GPO key over local
      expect(activeGpoKey.kid).toContain('gpo');
      expect(activeLocalKey.kid).toContain('local');

      // Both should be valid keys that can decrypt envelopes
      const activeKeys: ActiveKey[] = [
        { kid: gpoKey.publicKey.kid!, publicKey: gpoKey.publicKey },
        { kid: localKey.publicKey.kid!, publicKey: localKey.publicKey },
      ];

      const { envelope } = await createThreatFeedEnvelope({ test: 'priority' }, activeKeys);

      // Both can decrypt
      const decrypted1 = await decryptThreatFeed(envelope, activeGpoKey);
      const decrypted2 = await decryptThreatFeed(envelope, activeLocalKey);

      expect(decrypted1).toEqual({ test: 'priority' });
      expect(decrypted2).toEqual({ test: 'priority' });
    });
  });

  describe('Error Handling', () => {
    it('should fail gracefully with tampered ciphertext', async () => {
      if (!x25519Available) return;

      const { publicKey, privateKey } = await generateGpoKeyPair('tamper');
      const activeKeys: ActiveKey[] = [{ kid: publicKey.kid!, publicKey }];

      const { envelope } = await createThreatFeedEnvelope({ test: 'data' }, activeKeys);

      // Tamper with ciphertext
      const tamperedEnvelope: ThreatFeedEnvelope = {
        ...envelope,
        ciphertext: envelope.ciphertext.slice(0, -4) + 'XXXX',
      };

      await expect(decryptThreatFeed(tamperedEnvelope, privateKey)).rejects.toThrow();
    });

    it('should fail with tampered wrapped session key', async () => {
      if (!x25519Available) return;

      const { publicKey, privateKey } = await generateGpoKeyPair('tamper_key');
      const activeKeys: ActiveKey[] = [{ kid: publicKey.kid!, publicKey }];

      const { envelope } = await createThreatFeedEnvelope({ test: 'data' }, activeKeys);

      // Tamper with encrypted session key
      const tamperedEnvelope: ThreatFeedEnvelope = {
        ...envelope,
        headers: envelope.headers.map((h) => ({
          ...h,
          encrypted_session_key: h.encrypted_session_key.slice(0, -4) + 'XXXX',
        })),
      };

      await expect(decryptThreatFeed(tamperedEnvelope, privateKey)).rejects.toThrow();
    });

    it('should fail with wrong IV', async () => {
      if (!x25519Available) return;

      const { publicKey, privateKey } = await generateGpoKeyPair('wrong_iv');
      const activeKeys: ActiveKey[] = [{ kid: publicKey.kid!, publicKey }];

      const { envelope } = await createThreatFeedEnvelope({ test: 'data' }, activeKeys);

      // Generate different IV (base64 of 12 bytes)
      const wrongIv = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(12))));

      const tamperedEnvelope: ThreatFeedEnvelope = {
        ...envelope,
        iv: wrongIv,
      };

      await expect(decryptThreatFeed(tamperedEnvelope, privateKey)).rejects.toThrow();
    });
  });
});
