/**
 * BrowserDefense Hybrid Encryption Module
 *
 * RSA-OAEP + AES-GCM hybrid encryption for zero-knowledge forensics.
 * Uses Web Crypto API exclusively - no external dependencies.
 *
 * Flow:
 * 1. Generate ephemeral AES-256-GCM key
 * 2. Encrypt payload with AES-GCM
 * 3. Wrap AES key with RSA-OAEP (customer's public key)
 * 4. Bundle: { iv, wrappedKey, ciphertext }
 *
 * The customer decrypts with their private key. BrowserDefense never sees plaintext.
 */

/**
 * Encrypted forensics payload ready for upload.
 */
export interface EncryptedPayload {
  /** Base64-encoded 96-bit IV for AES-GCM */
  iv: string;
  /** Base64-encoded RSA-OAEP wrapped AES key */
  wrappedKey: string;
  /** Base64-encoded AES-GCM ciphertext */
  ciphertext: string;
}

/**
 * JWK format for RSA public key.
 */
export interface RSAPublicKeyJWK {
  kty: 'RSA';
  n: string;
  e: string;
  alg?: string;
  use?: string;
}

/**
 * JWK format for RSA private key (for decryption).
 */
export interface RSAPrivateKeyJWK extends RSAPublicKeyJWK {
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
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
 * Generate an ephemeral AES-256-GCM key.
 */
export async function generateAESKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

/**
 * Generate a random 96-bit IV for AES-GCM.
 * 96 bits (12 bytes) is the recommended IV size for AES-GCM.
 */
export function generateIV(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Encrypt data with AES-GCM.
 */
export async function encryptAESGCM(
  key: CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, plaintext as BufferSource);
}

/**
 * Decrypt data with AES-GCM.
 */
export async function decryptAESGCM(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: ArrayBuffer
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ciphertext);
}

/**
 * Import an RSA-OAEP public key from JWK format.
 */
export async function importRSAPublicKey(jwk: RSAPublicKeyJWK): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, [
    'encrypt',
  ]);
}

/**
 * Import an RSA-OAEP private key from JWK format.
 */
export async function importRSAPrivateKey(jwk: RSAPrivateKeyJWK): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, [
    'decrypt',
  ]);
}

/**
 * Wrap (encrypt) an AES key with RSA-OAEP.
 */
export async function wrapAESKey(aesKey: CryptoKey, rsaPublicKey: CryptoKey): Promise<ArrayBuffer> {
  // Export AES key to raw bytes, then encrypt with RSA
  const rawKey = await crypto.subtle.exportKey('raw', aesKey);
  return crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPublicKey, rawKey);
}

/**
 * Unwrap (decrypt) an AES key with RSA-OAEP.
 */
export async function unwrapAESKey(
  wrappedKey: ArrayBuffer,
  rsaPrivateKey: CryptoKey
): Promise<CryptoKey> {
  // Decrypt the wrapped key with RSA
  const rawKey = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaPrivateKey, wrappedKey);

  // Import as AES-GCM key
  return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM', length: 256 }, false, [
    'decrypt',
  ]);
}

/**
 * Encrypt forensics payload using hybrid RSA-OAEP + AES-GCM encryption.
 *
 * This is the main function for zero-knowledge forensics:
 * 1. Generates ephemeral AES-256-GCM key
 * 2. Encrypts payload with AES-GCM
 * 3. Wraps AES key with customer's RSA public key
 *
 * BrowserDefense stores the encrypted result but cannot decrypt it.
 *
 * @param payload - The forensics data to encrypt (will be JSON stringified)
 * @param publicKeyJwk - Customer's RSA-OAEP public key in JWK format
 * @returns Encrypted payload with iv, wrappedKey, and ciphertext (all base64)
 */
export async function encryptForensics<T>(
  payload: T,
  publicKeyJwk: RSAPublicKeyJWK
): Promise<EncryptedPayload> {
  // 1. Generate ephemeral AES key
  const aesKey = await generateAESKey();

  // 2. Generate random IV
  const iv = generateIV();

  // 3. Encrypt payload with AES-GCM
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await encryptAESGCM(aesKey, iv, plaintext);

  // 4. Import RSA public key and wrap AES key
  const rsaPublicKey = await importRSAPublicKey(publicKeyJwk);
  const wrappedKey = await wrapAESKey(aesKey, rsaPublicKey);

  // 5. Return base64-encoded bundle
  return {
    iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
    wrappedKey: arrayBufferToBase64(wrappedKey),
    ciphertext: arrayBufferToBase64(ciphertext),
  };
}

/**
 * Decrypt forensics payload using hybrid RSA-OAEP + AES-GCM decryption.
 *
 * This runs on the customer's side with their private key.
 *
 * @param encrypted - The encrypted payload from encryptForensics
 * @param privateKeyJwk - Customer's RSA-OAEP private key in JWK format
 * @returns Decrypted and parsed payload
 */
export async function decryptForensics<T>(
  encrypted: EncryptedPayload,
  privateKeyJwk: RSAPrivateKeyJWK
): Promise<T> {
  // 1. Decode base64 values
  const iv = new Uint8Array(base64ToArrayBuffer(encrypted.iv));
  const wrappedKey = base64ToArrayBuffer(encrypted.wrappedKey);
  const ciphertext = base64ToArrayBuffer(encrypted.ciphertext);

  // 2. Import RSA private key and unwrap AES key
  const rsaPrivateKey = await importRSAPrivateKey(privateKeyJwk);
  const aesKey = await unwrapAESKey(wrappedKey, rsaPrivateKey);

  // 3. Decrypt payload with AES-GCM
  const plaintext = await decryptAESGCM(aesKey, iv, ciphertext);

  // 4. Parse JSON
  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json) as T;
}

/**
 * Generate an RSA-OAEP keypair for forensics encryption.
 * This is used by the admin tool to generate customer keys.
 *
 * @returns Object with publicKey and privateKey in JWK format
 */
export async function generateRSAKeyPair(): Promise<{
  publicKey: RSAPublicKeyJWK;
  privateKey: RSAPrivateKeyJWK;
}> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );

  const publicKey = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as RSAPublicKeyJWK;
  const privateKey = (await crypto.subtle.exportKey('jwk', keyPair.privateKey)) as RSAPrivateKeyJWK;

  return { publicKey, privateKey };
}
