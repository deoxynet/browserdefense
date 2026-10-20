/**
 * BlockIOC Threat Feed Distribution Module
 *
 * X25519 + HKDF + AES-GCM envelope encryption for broadcast threat feeds.
 * Supports multiple active keys for key rotation without re-encrypting payload.
 *
 * Server Flow:
 * 1. Generate ephemeral X25519 keypair per recipient key
 * 2. Derive shared secret with each active GPO public key
 * 3. Derive AES key-encryption-key via HKDF-SHA256
 * 4. Encrypt payload once with AES-256-GCM (96-bit IV)
 * 5. Wrap session key per kid with AES-256-GCM, add header entry
 *
 * Client Flow:
 * 1. Find matching header by kid
 * 2. Derive shared secret from ephemeral_pub + private key
 * 3. Derive AES key-encryption-key via HKDF-SHA256
 * 4. Unwrap session key
 * 5. Decrypt payload
 *
 * Reference: docs/Cryptographic_Specification_v3.md Section 4
 */

import { arrayBufferToBase64, base64ToArrayBuffer, generateIV } from './encryption';

/**
 * X25519 private key in JWK format.
 */
export interface X25519PrivateKeyJWK {
  kty: 'OKP';
  crv: 'X25519';
  x: string;
  d: string;
  kid?: string;
}

/**
 * X25519 public key in JWK format.
 */
export interface X25519PublicKeyJWK {
  kty: 'OKP';
  crv: 'X25519';
  x: string;
  kid?: string;
}

/**
 * Envelope header for a single recipient key.
 */
export interface ThreatFeedHeader {
  /** Key identifier for matching */
  kid: string;
  /** Base64-encoded ephemeral X25519 public key */
  ephemeral_pub: string;
  /** Base64-encoded AES-GCM wrapped session key */
  encrypted_session_key: string;
  /** Base64-encoded 12-byte IV for session key wrapping */
  wrap_iv: string;
}

/**
 * Envelope metadata.
 */
export interface ThreatFeedMeta {
  /** Envelope format version */
  version: string;
  /** Unix timestamp when envelope was generated */
  generated_at: number;
}

/**
 * Complete threat feed envelope with multi-key support.
 */
export interface ThreatFeedEnvelope {
  /** Envelope metadata */
  meta: ThreatFeedMeta;
  /** Headers for each supported key */
  headers: ThreatFeedHeader[];
  /** Base64-encoded 12-byte IV for payload encryption */
  iv: string;
  /** Base64-encoded AES-GCM encrypted payload */
  ciphertext: string;
}

/**
 * Active key for envelope generation (server-side).
 */
export interface ActiveKey {
  /** Key identifier */
  kid: string;
  /** X25519 public key in JWK format */
  publicKey: X25519PublicKeyJWK;
}

/**
 * Result of envelope creation (server-side).
 */
export interface EnvelopeCreationResult {
  envelope: ThreatFeedEnvelope;
  /** Session key for debugging/testing (should not be stored) */
  sessionKeyBytes?: Uint8Array;
}

/**
 * Configuration for envelope creation.
 */
export interface EnvelopeConfig {
  /** Version string for envelope metadata */
  version?: string;
  /** Include session key in result (for testing only) */
  includeSessionKey?: boolean;
}

// ============ HKDF Key Derivation ============

/**
 * Derive an AES-256-GCM key from shared secret using HKDF-SHA256.
 * Uses fixed salt and info for deterministic key derivation.
 */
export async function deriveAesKeyFromHkdf(sharedSecret: ArrayBuffer): Promise<CryptoKey> {
  // Import shared secret as HKDF key material
  const keyMaterial = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, [
    'deriveKey',
  ]);

  // Fixed salt and info for deterministic derivation
  const salt = new TextEncoder().encode('BlockIOC-ThreatFeed-v1');
  const info = new TextEncoder().encode('session-key');

  // Derive AES-256-GCM key
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      salt,
      info,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// ============ X25519 Key Operations ============

/**
 * Generate an X25519 keypair.
 */
export async function generateX25519KeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']) as Promise<CryptoKeyPair>;
}

/**
 * Import an X25519 public key from JWK format.
 */
export async function importX25519PublicKey(jwk: X25519PublicKeyJWK): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, { name: 'X25519' }, true, []);
}

/**
 * Import an X25519 private key from JWK format.
 */
export async function importX25519PrivateKey(jwk: X25519PrivateKeyJWK): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, { name: 'X25519' }, false, ['deriveBits']);
}

/**
 * Import an X25519 public key from raw bytes.
 */
export async function importX25519PublicKeyRaw(raw: ArrayBuffer): Promise<CryptoKey> {
  if (raw.byteLength !== 32) {
    throw new Error(`X25519 public key must be 32 bytes, got ${raw.byteLength}`);
  }
  return crypto.subtle.importKey('raw', raw, { name: 'X25519' }, true, []);
}

/**
 * Export an X25519 public key to raw bytes.
 */
export async function exportX25519PublicKeyRaw(publicKey: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.exportKey('raw', publicKey);
}

/**
 * Derive shared secret from X25519 key agreement.
 */
export async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256);
}

// ============ Server-Side Envelope Creation ============

/**
 * Create a threat feed envelope for multiple active keys.
 *
 * This encrypts the payload once with a random session key,
 * then wraps the session key for each active recipient key.
 * Key rotation is achieved by adding/removing headers without re-encrypting payload.
 *
 * @param payload - The data to encrypt (will be JSON stringified)
 * @param activeKeys - Array of active recipient keys with their kid and public key
 * @param config - Optional configuration
 * @returns Envelope ready for distribution
 */
export async function createThreatFeedEnvelope<T>(
  payload: T,
  activeKeys: ActiveKey[],
  config: EnvelopeConfig = {}
): Promise<EnvelopeCreationResult> {
  if (activeKeys.length === 0) {
    throw new Error('At least one active key is required');
  }

  // 1. Generate session key for payload encryption
  const sessionKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
  const sessionKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', sessionKey));

  // 2. Encrypt payload with session key
  const payloadIv = generateIV();
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: payloadIv as BufferSource },
    sessionKey,
    plaintext
  );

  // 3. Create header for each active key
  const headers: ThreatFeedHeader[] = [];

  for (const activeKey of activeKeys) {
    // Generate ephemeral keypair for this recipient
    const ephemeralKeyPair = await generateX25519KeyPair();
    const ephemeralPubRaw = await exportX25519PublicKeyRaw(ephemeralKeyPair.publicKey);

    // Import recipient's public key
    const recipientPublicKey = await importX25519PublicKey(activeKey.publicKey);

    // Derive shared secret
    const sharedSecret = await deriveSharedSecret(ephemeralKeyPair.privateKey, recipientPublicKey);

    // Derive key-encryption-key from shared secret
    const kek = await deriveAesKeyFromHkdf(sharedSecret);

    // Wrap session key with KEK
    const wrapIv = generateIV();
    const wrappedSessionKey = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: wrapIv as BufferSource },
      kek,
      sessionKeyBytes
    );

    headers.push({
      kid: activeKey.kid,
      ephemeral_pub: arrayBufferToBase64(ephemeralPubRaw),
      encrypted_session_key: arrayBufferToBase64(wrappedSessionKey),
      wrap_iv: arrayBufferToBase64(wrapIv.buffer as ArrayBuffer),
    });
  }

  const envelope: ThreatFeedEnvelope = {
    meta: {
      version: config.version ?? '2026-01-09',
      generated_at: Math.floor(Date.now() / 1000),
    },
    headers,
    iv: arrayBufferToBase64(payloadIv.buffer as ArrayBuffer),
    ciphertext: arrayBufferToBase64(ciphertext),
  };

  const result: EnvelopeCreationResult = { envelope };
  if (config.includeSessionKey) {
    result.sessionKeyBytes = sessionKeyBytes;
  }

  return result;
}

// ============ Client-Side Envelope Decryption ============

/**
 * Decrypt a threat feed envelope using the provided private key.
 *
 * This finds the matching header by kid, derives the shared secret,
 * unwraps the session key, and decrypts the payload.
 *
 * @param envelope - The encrypted envelope
 * @param privateKeyJwk - X25519 private key with kid for matching
 * @returns Decrypted and parsed payload
 */
export async function decryptThreatFeed<T>(
  envelope: ThreatFeedEnvelope,
  privateKeyJwk: X25519PrivateKeyJWK
): Promise<T> {
  // 1. Find matching header by kid
  const kid = privateKeyJwk.kid;
  if (!kid) {
    throw new Error('Private key must have a kid for header matching');
  }

  const header = envelope.headers.find((h) => h.kid === kid);
  if (!header) {
    const availableKids = envelope.headers.map((h) => h.kid).join(', ');
    throw new Error(
      `No matching header for kid "${kid}". Available: ${availableKids || 'none'}`
    );
  }

  // 2. Import private key
  const privateKey = await importX25519PrivateKey(privateKeyJwk);

  // 3. Import ephemeral public key from header
  const ephemeralPubRaw = base64ToArrayBuffer(header.ephemeral_pub);
  const ephemeralPub = await importX25519PublicKeyRaw(ephemeralPubRaw);

  // 4. Derive shared secret
  const sharedSecret = await deriveSharedSecret(privateKey, ephemeralPub);

  // 5. Derive key-encryption-key
  const kek = await deriveAesKeyFromHkdf(sharedSecret);

  // 6. Unwrap session key
  const wrapIv = new Uint8Array(base64ToArrayBuffer(header.wrap_iv));
  const wrappedSessionKey = base64ToArrayBuffer(header.encrypted_session_key);

  const sessionKeyBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: wrapIv },
    kek,
    wrappedSessionKey
  );

  // 7. Import session key
  const sessionKey = await crypto.subtle.importKey(
    'raw',
    sessionKeyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // 8. Decrypt payload
  const iv = new Uint8Array(base64ToArrayBuffer(envelope.iv));
  const ciphertext = base64ToArrayBuffer(envelope.ciphertext);

  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, sessionKey, ciphertext);

  // 9. Parse and return
  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json) as T;
}

/**
 * Check if X25519 is supported in the current environment.
 * Caches the result after first check.
 */
let x25519Supported: boolean | null = null;

export async function isX25519Supported(): Promise<boolean> {
  if (x25519Supported !== null) {
    return x25519Supported;
  }

  try {
    await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    x25519Supported = true;
  } catch {
    x25519Supported = false;
  }

  return x25519Supported;
}

// ============ Key Management Utilities ============

/**
 * Generate a new X25519 keypair with kid for GPO/MDM deployment.
 *
 * @param kidPrefix - Prefix for the key identifier (e.g., "2026_key")
 * @returns Object with publicKey and privateKey in JWK format
 */
export async function generateGpoKeyPair(kidPrefix?: string): Promise<{
  publicKey: X25519PublicKeyJWK;
  privateKey: X25519PrivateKeyJWK;
}> {
  const keyPair = await generateX25519KeyPair();

  const publicKey = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as X25519PublicKeyJWK;
  const privateKey = (await crypto.subtle.exportKey(
    'jwk',
    keyPair.privateKey
  )) as X25519PrivateKeyJWK;

  // Generate kid
  const kid = kidPrefix
    ? `${kidPrefix}_v${Date.now()}`
    : `key_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  publicKey.kid = kid;
  privateKey.kid = kid;

  return { publicKey, privateKey };
}

/**
 * Add a new key header to an existing envelope without re-encrypting payload.
 * This enables key rotation by adding a header for a new key.
 *
 * Note: This requires access to the session key, which is normally discarded
 * after envelope creation. Use createThreatFeedEnvelope with includeSessionKey
 * if you need this capability.
 *
 * @param envelope - Existing envelope to extend
 * @param newKey - New recipient key to add
 * @param sessionKeyBytes - The session key used for payload encryption
 * @returns Updated envelope with new header
 */
export async function addEnvelopeHeader(
  envelope: ThreatFeedEnvelope,
  newKey: ActiveKey,
  sessionKeyBytes: Uint8Array
): Promise<ThreatFeedEnvelope> {
  // Generate ephemeral keypair for this recipient
  const ephemeralKeyPair = await generateX25519KeyPair();
  const ephemeralPubRaw = await exportX25519PublicKeyRaw(ephemeralKeyPair.publicKey);

  // Import recipient's public key
  const recipientPublicKey = await importX25519PublicKey(newKey.publicKey);

  // Derive shared secret
  const sharedSecret = await deriveSharedSecret(ephemeralKeyPair.privateKey, recipientPublicKey);

  // Derive key-encryption-key from shared secret
  const kek = await deriveAesKeyFromHkdf(sharedSecret);

  // Wrap session key with KEK
  const wrapIv = generateIV();
  const wrappedSessionKey = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: wrapIv as BufferSource },
    kek,
    sessionKeyBytes as BufferSource
  );

  const newHeader: ThreatFeedHeader = {
    kid: newKey.kid,
    ephemeral_pub: arrayBufferToBase64(ephemeralPubRaw),
    encrypted_session_key: arrayBufferToBase64(wrappedSessionKey),
    wrap_iv: arrayBufferToBase64(wrapIv.buffer as ArrayBuffer),
  };

  return {
    ...envelope,
    headers: [...envelope.headers, newHeader],
  };
}

/**
 * Remove a key header from an envelope by kid.
 * This enables key rotation by removing old keys.
 *
 * @param envelope - Existing envelope
 * @param kid - Key identifier to remove
 * @returns Updated envelope without the specified header
 */
export function removeEnvelopeHeader(envelope: ThreatFeedEnvelope, kid: string): ThreatFeedEnvelope {
  return {
    ...envelope,
    headers: envelope.headers.filter((h) => h.kid !== kid),
  };
}
