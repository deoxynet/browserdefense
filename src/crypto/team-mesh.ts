/**
 * BlockIOC Team Mesh Crypto Module
 *
 * X25519 + HKDF-SHA256 + AES-256-GCM for Team Mesh and Threat Feeds.
 * Uses Web Crypto API exclusively - no external dependencies.
 *
 * This is part of the dual-stack crypto standard:
 * - Team Mesh/Threat Feeds: X25519 + HKDF-SHA256 + AES-256-GCM (this module)
 * - Forensics: RSA-OAEP-2048 + AES-256-GCM (see encryption.ts)
 *
 * Flow (Encryption):
 * 1. Generate ephemeral X25519 keypair
 * 2. Perform ECDH with recipient's public key to get shared secret
 * 3. Derive AES-256-GCM key via HKDF-SHA256
 * 4. Encrypt payload with AES-GCM (96-bit IV)
 * 5. Bundle: { ephemeralPublicKey, iv, ciphertext }
 *
 * Flow (Decryption):
 * 1. Perform ECDH with ephemeral public key and recipient's private key
 * 2. Derive AES-256-GCM key via HKDF-SHA256
 * 3. Decrypt payload with AES-GCM
 *
 * Algorithm Parameters:
 * - X25519: Curve25519 for ECDH (32-byte keys)
 * - HKDF: SHA-256 hash, 256-bit derived key, context-specific info
 * - AES-GCM: 256-bit key, 96-bit (12-byte) IV, 128-bit auth tag
 *
 * Key Formats:
 * - JWK: { kty: "OKP", crv: "X25519", x: base64url, d?: base64url }
 * - Raw: 32 bytes for public key, 32 bytes for private key
 *
 * Reference: docs/Cryptographic_Specification_v3.md Section 3
 */

/**
 * Encrypted Team Mesh payload ready for transmission.
 */
export interface TeamMeshPayload {
  /** Base64-encoded ephemeral X25519 public key (32 bytes) */
  ephemeralPublicKey: string;
  /** Base64-encoded 96-bit IV for AES-GCM */
  iv: string;
  /** Base64-encoded AES-GCM ciphertext (includes 128-bit auth tag) */
  ciphertext: string;
}

/**
 * JWK format for X25519 public key.
 */
export interface X25519PublicKeyJWK {
  kty: 'OKP';
  crv: 'X25519';
  x: string; // base64url-encoded public key
}

/**
 * JWK format for X25519 private key.
 */
export interface X25519PrivateKeyJWK extends X25519PublicKeyJWK {
  d: string; // base64url-encoded private key
}

/**
 * HKDF context info for different use cases.
 * Using distinct info strings ensures domain separation.
 */
export const HKDF_INFO = {
  TEAM_MESH: new TextEncoder().encode('BlockIOC Team Mesh v1'),
  THREAT_FEED: new TextEncoder().encode('BlockIOC Threat Feed v1'),
} as const;

/**
 * Check if X25519 is supported in this environment.
 * Caches the result after first check.
 */
let x25519Supported: boolean | null = null;

export async function isX25519Supported(): Promise<boolean> {
  if (x25519Supported !== null) {
    return x25519Supported;
  }

  try {
    // Try to generate a test keypair to verify support
    const testKey = await crypto.subtle.generateKey('X25519', false, ['deriveBits']);
    x25519Supported = testKey !== null;
    return x25519Supported;
  } catch {
    x25519Supported = false;
    return false;
  }
}

/**
 * Convert ArrayBuffer to base64 string.
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to ArrayBuffer.
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer as ArrayBuffer;
}

/**
 * Convert base64url to standard base64.
 * JWK uses base64url encoding (RFC 7515).
 */
function base64urlToBase64(base64url: string): string {
  return base64url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (base64url.length % 4)) % 4);
}

/**
 * Convert standard base64 to base64url.
 * JWK uses base64url encoding (RFC 7515).
 */
function base64ToBase64url(base64: string): string {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Generate a random 96-bit IV for AES-GCM.
 * 96 bits (12 bytes) is the required IV size for this module.
 * This is enforced per the dual-stack crypto standard.
 */
export function generateIV(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Generate an X25519 keypair for Team Mesh encryption.
 *
 * @returns Object with publicKey and privateKey in JWK format
 */
export async function generateX25519KeyPair(): Promise<{
  publicKey: X25519PublicKeyJWK;
  privateKey: X25519PrivateKeyJWK;
}> {
  const supported = await isX25519Supported();
  if (!supported) {
    throw new Error(
      'X25519 is not supported in this environment. ' +
        'Please upgrade to Chrome 133+ or Node.js 18+.'
    );
  }

  const keyPair = (await crypto.subtle.generateKey('X25519', true, [
    'deriveBits',
  ])) as CryptoKeyPair;

  const publicKey = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as X25519PublicKeyJWK;
  const privateKey = (await crypto.subtle.exportKey(
    'jwk',
    keyPair.privateKey
  )) as X25519PrivateKeyJWK;

  return { publicKey, privateKey };
}

/**
 * Import an X25519 public key from JWK format.
 *
 * @param jwk - JSON Web Key object
 * @returns CryptoKey for ECDH derivation
 */
export async function importX25519PublicKey(jwk: X25519PublicKeyJWK): Promise<CryptoKey> {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'X25519') {
    throw new Error(`Invalid key type: expected OKP X25519, got ${jwk.kty} ${jwk.crv}`);
  }

  return crypto.subtle.importKey('jwk', jwk, { name: 'X25519' }, false, []);
}

/**
 * Import an X25519 private key from JWK format.
 *
 * @param jwk - JSON Web Key object with private key component
 * @returns CryptoKey for ECDH derivation
 */
export async function importX25519PrivateKey(jwk: X25519PrivateKeyJWK): Promise<CryptoKey> {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'X25519') {
    throw new Error(`Invalid key type: expected OKP X25519, got ${jwk.kty} ${jwk.crv}`);
  }

  return crypto.subtle.importKey('jwk', jwk, { name: 'X25519' }, false, ['deriveBits']);
}

/**
 * Derive a shared secret using X25519 ECDH.
 *
 * @param privateKey - Local private key
 * @param publicKey - Remote public key
 * @returns 32-byte shared secret as ArrayBuffer
 */
export async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256);
}

/**
 * Derive an AES-256-GCM key from a shared secret using HKDF-SHA256.
 *
 * @param sharedSecret - 32-byte shared secret from X25519 ECDH
 * @param info - Context-specific info for domain separation (use HKDF_INFO constants)
 * @param salt - Optional salt (defaults to empty, which uses HKDF's default)
 * @returns CryptoKey for AES-GCM encryption/decryption
 */
export async function deriveAESKeyFromSecret(
  sharedSecret: ArrayBuffer,
  info: Uint8Array,
  salt?: Uint8Array
): Promise<CryptoKey> {
  // Import shared secret as HKDF key material
  const keyMaterial = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, [
    'deriveKey',
  ]);

  // Derive AES-256-GCM key using HKDF-SHA256
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: (salt ?? new Uint8Array(0)) as BufferSource,
      info: info as BufferSource,
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data with AES-256-GCM.
 *
 * @param key - AES-GCM CryptoKey
 * @param iv - 96-bit (12-byte) initialization vector
 * @param plaintext - Data to encrypt
 * @returns Ciphertext with 128-bit auth tag appended
 */
export async function encryptAESGCM(
  key: CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<ArrayBuffer> {
  if (iv.length !== 12) {
    throw new Error(`AES-GCM IV must be 12 bytes (96 bits), got ${iv.length} bytes`);
  }
  return crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    plaintext as BufferSource
  );
}

/**
 * Decrypt data with AES-256-GCM.
 *
 * @param key - AES-GCM CryptoKey
 * @param iv - 96-bit (12-byte) initialization vector
 * @param ciphertext - Encrypted data with auth tag
 * @returns Decrypted plaintext
 */
export async function decryptAESGCM(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: ArrayBuffer
): Promise<ArrayBuffer> {
  if (iv.length !== 12) {
    throw new Error(`AES-GCM IV must be 12 bytes (96 bits), got ${iv.length} bytes`);
  }
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ciphertext);
}

/**
 * Encrypt a Team Mesh payload using X25519 + HKDF + AES-GCM.
 *
 * This is the main encryption function for Team Mesh broadcasts.
 * Each encryption uses a fresh ephemeral keypair for forward secrecy.
 *
 * @param payload - Data to encrypt (will be JSON stringified)
 * @param recipientPublicKeyJwk - Recipient's X25519 public key in JWK format
 * @param info - HKDF info for domain separation (default: TEAM_MESH)
 * @returns Encrypted payload with ephemeralPublicKey, iv, and ciphertext
 */
export async function encryptTeamMesh<T>(
  payload: T,
  recipientPublicKeyJwk: X25519PublicKeyJWK,
  info: Uint8Array = HKDF_INFO.TEAM_MESH
): Promise<TeamMeshPayload> {
  // 1. Generate ephemeral X25519 keypair
  const ephemeral = await generateX25519KeyPair();
  const ephemeralPrivateKey = await importX25519PrivateKey(ephemeral.privateKey);
  const recipientPublicKey = await importX25519PublicKey(recipientPublicKeyJwk);

  // 2. Derive shared secret via X25519 ECDH
  const sharedSecret = await deriveSharedSecret(ephemeralPrivateKey, recipientPublicKey);

  // 3. Derive AES-256-GCM key via HKDF-SHA256
  const aesKey = await deriveAESKeyFromSecret(sharedSecret, info);

  // 4. Generate random 96-bit IV
  const iv = generateIV();

  // 5. Encrypt payload with AES-GCM
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await encryptAESGCM(aesKey, iv, plaintext);

  // 6. Export ephemeral public key as raw bytes for compact transmission
  // JWK uses base64url encoding, so we convert to standard base64 first
  const ephemeralPublicKeyRaw = base64ToArrayBuffer(base64urlToBase64(ephemeral.publicKey.x));

  // 7. Return base64-encoded bundle
  return {
    ephemeralPublicKey: arrayBufferToBase64(ephemeralPublicKeyRaw),
    iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
    ciphertext: arrayBufferToBase64(ciphertext),
  };
}

/**
 * Decrypt a Team Mesh payload using X25519 + HKDF + AES-GCM.
 *
 * @param encrypted - Encrypted payload from encryptTeamMesh
 * @param recipientPrivateKeyJwk - Recipient's X25519 private key in JWK format
 * @param info - HKDF info for domain separation (must match encryption)
 * @returns Decrypted and parsed payload
 */
export async function decryptTeamMesh<T>(
  encrypted: TeamMeshPayload,
  recipientPrivateKeyJwk: X25519PrivateKeyJWK,
  info: Uint8Array = HKDF_INFO.TEAM_MESH
): Promise<T> {
  // 1. Decode base64 values
  const ephemeralPublicKeyRaw = base64ToArrayBuffer(encrypted.ephemeralPublicKey);
  const iv = new Uint8Array(base64ToArrayBuffer(encrypted.iv));
  const ciphertext = base64ToArrayBuffer(encrypted.ciphertext);

  // Validate IV size
  if (iv.length !== 12) {
    throw new Error(`Invalid IV size: expected 12 bytes, got ${iv.length}`);
  }

  // 2. Reconstruct ephemeral public key JWK from raw bytes
  // Convert standard base64 to base64url for JWK format
  const ephemeralPublicKeyJwk: X25519PublicKeyJWK = {
    kty: 'OKP',
    crv: 'X25519',
    x: base64ToBase64url(arrayBufferToBase64(ephemeralPublicKeyRaw)),
  };

  // 3. Import keys
  const ephemeralPublicKey = await importX25519PublicKey(ephemeralPublicKeyJwk);
  const recipientPrivateKey = await importX25519PrivateKey(recipientPrivateKeyJwk);

  // 4. Derive shared secret via X25519 ECDH
  const sharedSecret = await deriveSharedSecret(recipientPrivateKey, ephemeralPublicKey);

  // 5. Derive AES-256-GCM key via HKDF-SHA256
  const aesKey = await deriveAESKeyFromSecret(sharedSecret, info);

  // 6. Decrypt payload with AES-GCM
  const plaintext = await decryptAESGCM(aesKey, iv, ciphertext);

  // 7. Parse JSON
  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json) as T;
}

/**
 * Encrypt a Threat Feed payload using X25519 + HKDF + AES-GCM.
 *
 * Same as encryptTeamMesh but uses THREAT_FEED info for domain separation.
 *
 * @param payload - Data to encrypt
 * @param recipientPublicKeyJwk - Recipient's X25519 public key
 * @returns Encrypted payload
 */
export async function encryptThreatFeed<T>(
  payload: T,
  recipientPublicKeyJwk: X25519PublicKeyJWK
): Promise<TeamMeshPayload> {
  return encryptTeamMesh(payload, recipientPublicKeyJwk, HKDF_INFO.THREAT_FEED);
}

/**
 * Decrypt a Threat Feed payload using X25519 + HKDF + AES-GCM.
 *
 * @param encrypted - Encrypted payload
 * @param recipientPrivateKeyJwk - Recipient's X25519 private key
 * @returns Decrypted payload
 */
export async function decryptThreatFeed<T>(
  encrypted: TeamMeshPayload,
  recipientPrivateKeyJwk: X25519PrivateKeyJWK
): Promise<T> {
  return decryptTeamMesh(encrypted, recipientPrivateKeyJwk, HKDF_INFO.THREAT_FEED);
}
