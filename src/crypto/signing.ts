/**
 * Ed25519 and P-256 ECDSA signature verification for blocklist updates.
 *
 * Ed25519 is the preferred algorithm (faster, simpler, more secure).
 * P-256 ECDSA is supported for backwards compatibility with v1 deployments.
 *
 * Reference: docs/Cryptographic_Specification_v3.md Section 4
 */

/**
 * Signature algorithm version for tracking.
 */
export type AlgorithmVersion = 'ed25519-v2' | 'p256-v1';

/**
 * Check if Ed25519 is supported in this browser.
 * Caches the result after first check.
 */
let ed25519Supported: boolean | null = null;

export async function isEd25519Supported(): Promise<boolean> {
  if (ed25519Supported !== null) {
    return ed25519Supported;
  }

  try {
    // Try to generate a test keypair to verify support
    const testKey = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
    ed25519Supported = testKey !== null;
    return ed25519Supported;
  } catch {
    ed25519Supported = false;
    return false;
  }
}

/**
 * Import an Ed25519 public key from raw 32-byte format.
 * @param raw - ArrayBuffer containing the 32-byte public key
 * @returns CryptoKey for verification
 */
export async function importPublicKeyEd25519Raw(raw: ArrayBuffer): Promise<CryptoKey> {
  if (raw.byteLength !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${raw.byteLength}`);
  }

  return crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
}

/**
 * Import an Ed25519 public key from JWK format.
 * @param jwk - JSON Web Key object
 * @returns CryptoKey for verification
 */
export async function importPublicKeyEd25519Jwk(jwk: JsonWebKey): Promise<CryptoKey> {
  // Validate it's an Ed25519 key
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    throw new Error(`Invalid key type: expected OKP Ed25519, got ${jwk.kty} ${jwk.crv}`);
  }

  return crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['verify']);
}

/**
 * Verify an Ed25519 signature.
 * @param publicKey - CryptoKey for verification
 * @param signature - The 64-byte signature to verify
 * @param data - The data that was signed
 * @returns true if signature is valid, false otherwise
 */
export async function verifySignatureEd25519(
  publicKey: CryptoKey,
  signature: BufferSource,
  data: BufferSource
): Promise<boolean> {
  try {
    return await crypto.subtle.verify('Ed25519', publicKey, signature, data);
  } catch {
    // Invalid signature format or other crypto error
    return false;
  }
}

/**
 * Import a P-256 public key from SPKI format (DER-encoded).
 * @param spki - ArrayBuffer containing the SPKI-encoded public key
 * @returns CryptoKey for verification
 */
export async function importPublicKeySpki(spki: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'spki',
    spki,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
}

/**
 * Import a P-256 public key from JWK format.
 * @param jwk - JSON Web Key object
 * @returns CryptoKey for verification
 */
export async function importPublicKeyP256Jwk(jwk: JsonWebKey): Promise<CryptoKey> {
  // Validate it's a P-256 key
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error(`Invalid key type: expected EC P-256, got ${jwk.kty} ${jwk.crv}`);
  }

  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
}

/**
 * Verify a P-256 ECDSA signature.
 * @param publicKey - CryptoKey for verification (from importPublicKey*)
 * @param signature - The signature to verify (DER or raw format)
 * @param data - The data that was signed
 * @returns true if signature is valid, false otherwise
 */
export async function verifySignatureP256(
  publicKey: CryptoKey,
  signature: BufferSource,
  data: BufferSource
): Promise<boolean> {
  try {
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      signature,
      data
    );
  } catch {
    // Invalid signature format or other crypto error
    return false;
  }
}

// Legacy aliases for backwards compatibility
export const importPublicKeyJwk = importPublicKeyP256Jwk;
export const verifySignature = verifySignatureP256;

/**
 * Detect algorithm from JWK and import appropriately.
 * @param jwk - JSON Web Key object (Ed25519 or P-256)
 * @returns CryptoKey for verification and algorithm version
 */
export async function importSigningPublicKey(
  jwk: JsonWebKey
): Promise<{ key: CryptoKey; algorithm: AlgorithmVersion }> {
  // Ed25519 keys use OKP key type
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    const supported = await isEd25519Supported();
    if (!supported) {
      throw new Error(
        'Ed25519 is not supported in this browser. ' +
          'Please upgrade to Chrome 113+ or use P-256 keys for compatibility.'
      );
    }
    const key = await importPublicKeyEd25519Jwk(jwk);
    return { key, algorithm: 'ed25519-v2' };
  }

  // P-256 keys use EC key type
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
    const key = await importPublicKeyP256Jwk(jwk);
    return { key, algorithm: 'p256-v1' };
  }

  throw new Error(
    `Unsupported signing key type: ${jwk.kty} ${jwk.crv}. ` +
      'Expected Ed25519 (OKP/Ed25519) or P-256 (EC/P-256).'
  );
}

/**
 * Verify a signature using the appropriate algorithm based on key type.
 * @param publicKey - CryptoKey for verification
 * @param algorithm - Algorithm version
 * @param signature - The signature to verify
 * @param data - The data that was signed
 * @returns true if signature is valid
 */
export async function verifySignatureAuto(
  publicKey: CryptoKey,
  algorithm: AlgorithmVersion,
  signature: BufferSource,
  data: BufferSource
): Promise<boolean> {
  if (algorithm === 'ed25519-v2') {
    return verifySignatureEd25519(publicKey, signature, data);
  }
  return verifySignatureP256(publicKey, signature, data);
}

/**
 * Verify a blocklist manifest signature.
 * Automatically detects Ed25519 vs P-256 based on key format.
 * Convenience function that handles the full verification flow.
 *
 * @param manifest - The manifest object to verify
 * @param signatureBase64 - Base64-encoded signature
 * @param publicKeyJwk - Public key in JWK format (Ed25519 or P-256)
 * @returns true if signature is valid
 */
export async function verifyBlocklistSignature(
  manifest: Record<string, unknown>,
  signatureBase64: string,
  publicKeyJwk: JsonWebKey
): Promise<boolean> {
  try {
    // Import key and detect algorithm
    const { key, algorithm } = await importSigningPublicKey(publicKeyJwk);

    // Canonical JSON for signing (sorted keys, no whitespace)
    // Only include the fields that should be signed
    const signedFields = {
      bucket_count: manifest.bucket_count,
      sha256_root: manifest.sha256_root,
      total_iocs: manifest.total_iocs,
      version: manifest.version,
    };
    const manifestBody = JSON.stringify(signedFields, Object.keys(signedFields).sort());

    // Decode signature
    const signature = base64ToArrayBuffer(signatureBase64);

    // Encode manifest for verification
    const data = new TextEncoder().encode(manifestBody);

    // Verify using appropriate algorithm
    return await verifySignatureAuto(key, algorithm, signature, data);
  } catch (err) {
    console.error('[BrowserDefense] Signature verification failed:', err);
    return false;
  }
}

/**
 * Verify a DOM signature manifest signature.
 * Uses DOM-signature-specific canonical fields.
 *
 * @param manifest - The DOM signature manifest object to verify
 * @param signatureBase64 - Base64-encoded signature
 * @param publicKeyJwk - Public key in JWK format (Ed25519 or P-256)
 * @returns true if signature is valid
 */
export async function verifyDOMSignatureManifest(
  manifest: Record<string, unknown>,
  signatureBase64: string,
  publicKeyJwk: JsonWebKey
): Promise<boolean> {
  try {
    // Import key and detect algorithm
    const { key, algorithm } = await importSigningPublicKey(publicKeyJwk);

    // Canonical JSON for signing (sorted keys, no whitespace)
    // Only include the fields that should be signed for DOM signatures
    const signedFields = {
      exact_count: manifest.exact_count,
      lsh_count: manifest.lsh_count,
      sha256_root: manifest.sha256_root,
      total_signatures: manifest.total_signatures,
      version: manifest.version,
    };
    const manifestBody = JSON.stringify(signedFields, Object.keys(signedFields).sort());

    // Decode signature
    const signature = base64ToArrayBuffer(signatureBase64);

    // Encode manifest for verification
    const data = new TextEncoder().encode(manifestBody);

    // Verify using appropriate algorithm
    return await verifySignatureAuto(key, algorithm, signature, data);
  } catch (err) {
    console.error('[BrowserDefense] DOM signature manifest verification failed:', err);
    return false;
  }
}

// ============ Helper Functions ============

/**
 * Convert base64 string to ArrayBuffer.
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

/**
 * Convert ArrayBuffer to base64 string.
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const CHUNK_SIZE = 0x8000; // 32KB chunks to avoid stack overflow
  let binary = '';

  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

/**
 * Convert hex string to ArrayBuffer.
 */
export function hexToArrayBuffer(hex: string): ArrayBuffer {
  const normalized = hex.replace(/^0x/, '');

  if (normalized.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }

  const bytes = new Uint8Array(normalized.length / 2);

  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = parseInt(normalized.slice(i, i + 2), 16);
  }

  return bytes.buffer;
}

/**
 * Convert ArrayBuffer to hex string.
 */
export function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
