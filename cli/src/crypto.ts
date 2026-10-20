/**
 * BrowserDefense CLI Crypto Module
 * Uses Node.js crypto module for Ed25519 and P-256 ECDSA signing, and RSA-OAEP encryption.
 * Compatible with Web Crypto API used in the browser extension.
 */

import * as crypto from 'node:crypto';

// ============ Types ============

/**
 * Ed25519 public key in JWK format.
 * Use --ed25519 flag for this algorithm (requires Chrome 113+).
 */
export interface Ed25519PublicKeyJWK {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  [key: string]: unknown;
}

/**
 * Ed25519 private key in JWK format.
 */
export interface Ed25519PrivateKeyJWK extends Ed25519PublicKeyJWK {
  d: string;
}

/**
 * P-256 ECDSA public key in JWK format.
 * This is the default algorithm for maximum enterprise Chrome compatibility.
 */
export interface ECPublicKeyJWK {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  [key: string]: unknown;
}

/**
 * P-256 ECDSA private key in JWK format.
 */
export interface ECPrivateKeyJWK extends ECPublicKeyJWK {
  d: string;
}

/**
 * Union type for all signing public keys.
 */
export type SigningPublicKeyJWK = Ed25519PublicKeyJWK | ECPublicKeyJWK;

/**
 * Union type for all signing private keys.
 */
export type SigningPrivateKeyJWK = Ed25519PrivateKeyJWK | ECPrivateKeyJWK;

export interface RSAPublicKeyJWK {
  kty: 'RSA';
  n: string;
  e: string;
  alg?: string;
  [key: string]: unknown;
}

export interface RSAPrivateKeyJWK extends RSAPublicKeyJWK {
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
}

export interface BlocklistManifest {
  version: number;
  total_iocs: number;
  bucket_count: number;
  sha256_root: string;
  signature?: string;
  created_at?: string;
  algorithm_version?: string;
}

/**
 * Signature algorithm version.
 */
export type AlgorithmVersion = 'ed25519-v2' | 'p256-v1';

// ============ Key Generation ============

/**
 * Generate P-256 ECDSA keypair for blocklist signing.
 * This is the default algorithm for maximum enterprise Chrome compatibility.
 */
export async function generateSigningKeypair(): Promise<{
  publicKey: ECPublicKeyJWK;
  privateKey: ECPrivateKeyJWK;
}> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  const publicJwk = publicKey.export({ format: 'jwk' }) as ECPublicKeyJWK;
  const privateJwk = privateKey.export({ format: 'jwk' }) as ECPrivateKeyJWK;

  return { publicKey: publicJwk, privateKey: privateJwk };
}

/**
 * Generate Ed25519 keypair for blocklist signing.
 * Use --ed25519 flag for this algorithm (requires Chrome 113+).
 */
export async function generateSigningKeypairEd25519(): Promise<{
  publicKey: Ed25519PublicKeyJWK;
  privateKey: Ed25519PrivateKeyJWK;
}> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

  const publicJwk = publicKey.export({ format: 'jwk' }) as Ed25519PublicKeyJWK;
  const privateJwk = privateKey.export({ format: 'jwk' }) as Ed25519PrivateKeyJWK;

  return { publicKey: publicJwk, privateKey: privateJwk };
}

/**
 * Generate RSA-OAEP keypair for forensics encryption.
 */
export async function generateEncryptionKeypair(): Promise<{
  publicKey: RSAPublicKeyJWK;
  privateKey: RSAPrivateKeyJWK;
}> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });

  const publicJwk = publicKey.export({ format: 'jwk' }) as RSAPublicKeyJWK;
  const privateJwk = privateKey.export({ format: 'jwk' }) as RSAPrivateKeyJWK;

  // Add algorithm hint for Web Crypto compatibility
  publicJwk.alg = 'RSA-OAEP-256';
  privateJwk.alg = 'RSA-OAEP-256';

  return { publicKey: publicJwk, privateKey: privateJwk };
}

/**
 * Generate random salt for IOC hashing.
 */
export function generateSalt(): string {
  const saltBytes = crypto.randomBytes(32);
  return saltBytes.toString('base64');
}

/**
 * Generate a random UUID for org_id.
 */
export function generateOrgId(): string {
  return crypto.randomUUID();
}

// ============ Algorithm Detection ============

/**
 * Detect the algorithm from a signing key JWK.
 */
export function detectAlgorithm(keyJwk: SigningPublicKeyJWK | SigningPrivateKeyJWK): AlgorithmVersion {
  // Capture values before type narrowing to use in error message
  const kty = keyJwk.kty;
  const crv = keyJwk.crv;
  if (kty === 'OKP' && crv === 'Ed25519') {
    return 'ed25519-v2';
  }
  if (kty === 'EC' && crv === 'P-256') {
    return 'p256-v1';
  }
  throw new Error(`Unsupported key type: ${kty} ${crv}`);
}

// ============ Ed25519 Signing ============

/**
 * Sign data with Ed25519 private key.
 * Returns 64-byte signature, base64 encoded.
 */
export async function signEd25519(
  data: Buffer | string,
  privateKeyJwk: Ed25519PrivateKeyJWK
): Promise<string> {
  const privateKey = crypto.createPrivateKey({ key: privateKeyJwk, format: 'jwk' });
  const dataBuffer = typeof data === 'string' ? Buffer.from(data) : data;
  const signature = crypto.sign(null, dataBuffer, privateKey);
  return signature.toString('base64');
}

/**
 * Verify Ed25519 signature.
 */
export async function verifyEd25519(
  data: Buffer | string,
  signatureBase64: string,
  publicKeyJwk: Ed25519PublicKeyJWK
): Promise<boolean> {
  try {
    const publicKey = crypto.createPublicKey({ key: publicKeyJwk, format: 'jwk' });
    const dataBuffer = typeof data === 'string' ? Buffer.from(data) : data;
    const signature = Buffer.from(signatureBase64, 'base64');
    return crypto.verify(null, dataBuffer, publicKey, signature);
  } catch (err) {
    console.error('Ed25519 verification error:', err);
    return false;
  }
}

// ============ P-256 Signing ============

/**
 * Sign data with P-256 ECDSA private key.
 * Returns signature in raw format (r||s, 64 bytes), base64 encoded.
 */
export async function signP256(
  data: Buffer | string,
  privateKeyJwk: ECPrivateKeyJWK
): Promise<string> {
  const privateKey = crypto.createPrivateKey({ key: privateKeyJwk, format: 'jwk' });

  // Sign with SHA-256
  const signer = crypto.createSign('SHA256');
  signer.update(data);
  const derSignature = signer.sign(privateKey);

  // Convert DER to raw format (r||s) for Web Crypto compatibility
  const rawSignature = derToRaw(derSignature);

  return rawSignature.toString('base64');
}

/**
 * Verify P-256 ECDSA signature.
 */
export async function verifyP256(
  data: Buffer | string,
  signatureBase64: string,
  publicKeyJwk: ECPublicKeyJWK
): Promise<boolean> {
  try {
    const publicKey = crypto.createPublicKey({ key: publicKeyJwk, format: 'jwk' });

    // Convert raw signature back to DER format
    const rawSignature = Buffer.from(signatureBase64, 'base64');
    const derSignature = rawToDer(rawSignature);

    const verifier = crypto.createVerify('SHA256');
    verifier.update(data);

    return verifier.verify(publicKey, derSignature);
  } catch (err) {
    console.error('P-256 verification error:', err);
    return false;
  }
}

// ============ Unified Signing ============

/**
 * Sign data with a private key (auto-detects algorithm).
 */
export async function sign(
  data: Buffer | string,
  privateKeyJwk: SigningPrivateKeyJWK
): Promise<string> {
  const algorithm = detectAlgorithm(privateKeyJwk);
  if (algorithm === 'ed25519-v2') {
    return signEd25519(data, privateKeyJwk as Ed25519PrivateKeyJWK);
  }
  return signP256(data, privateKeyJwk as ECPrivateKeyJWK);
}

/**
 * Verify signature (auto-detects algorithm from key).
 */
export async function verify(
  data: Buffer | string,
  signatureBase64: string,
  publicKeyJwk: SigningPublicKeyJWK
): Promise<boolean> {
  const algorithm = detectAlgorithm(publicKeyJwk);
  if (algorithm === 'ed25519-v2') {
    return verifyEd25519(data, signatureBase64, publicKeyJwk as Ed25519PublicKeyJWK);
  }
  return verifyP256(data, signatureBase64, publicKeyJwk as ECPublicKeyJWK);
}

/**
 * Sign a blocklist manifest.
 * Creates canonical JSON and signs it.
 */
export async function signManifest(
  manifest: Omit<BlocklistManifest, 'signature'>,
  privateKeyJwk: SigningPrivateKeyJWK
): Promise<BlocklistManifest> {
  // Create canonical JSON (sorted keys, no whitespace)
  const signedFields = {
    bucket_count: manifest.bucket_count,
    sha256_root: manifest.sha256_root,
    total_iocs: manifest.total_iocs,
    version: manifest.version,
  };

  const sortedKeys = Object.keys(signedFields).sort() as (keyof typeof signedFields)[];
  const canonicalObj: Record<string, unknown> = {};
  for (const key of sortedKeys) {
    canonicalObj[key] = signedFields[key];
  }
  const canonicalJson = JSON.stringify(canonicalObj);

  const signature = await sign(canonicalJson, privateKeyJwk);
  const algorithm = detectAlgorithm(privateKeyJwk);

  return {
    ...manifest,
    signature,
    algorithm_version: algorithm,
  };
}

/**
 * Verify a blocklist manifest signature.
 */
export async function verifyManifest(
  manifest: BlocklistManifest,
  publicKeyJwk: SigningPublicKeyJWK
): Promise<boolean> {
  if (!manifest.signature) {
    return false;
  }

  // Recreate canonical JSON (same as signing)
  const signedFields = {
    bucket_count: manifest.bucket_count,
    sha256_root: manifest.sha256_root,
    total_iocs: manifest.total_iocs,
    version: manifest.version,
  };

  const sortedKeys = Object.keys(signedFields).sort() as (keyof typeof signedFields)[];
  const canonicalObj: Record<string, unknown> = {};
  for (const key of sortedKeys) {
    canonicalObj[key] = signedFields[key];
  }
  const canonicalJson = JSON.stringify(canonicalObj);

  return verify(canonicalJson, manifest.signature, publicKeyJwk);
}

// ============ Hashing ============

/**
 * SHA-256 hash of a string, returns hex.
 */
export function sha256(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * SHA-256 hash returning raw bytes.
 */
export function sha256Bytes(data: string | Buffer): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

export type CanonicalizationScope = 'HOST_ONLY' | 'HOST_PATH' | 'FULL_URL';

export interface CanonicalizationOptions {
  /** What parts of the URL to include */
  scope?: CanonicalizationScope;
  /** Include scheme in output (default: false for hash comparison) */
  includeScheme?: boolean;
}

/**
 * Canonicalize a URL for consistent IOC hashing.
 * Matches the extension's canonicalization exactly to ensure hash alignment.
 * See docs/Canonicalization_Specification.md for the full specification.
 */
export function canonicalizeUrl(
  url: string,
  scopeOrOptions: CanonicalizationScope | CanonicalizationOptions = 'HOST_ONLY'
): string {
  // Handle legacy scope-only argument or new options object
  const options: CanonicalizationOptions =
    typeof scopeOrOptions === 'string' ? { scope: scopeOrOptions } : scopeOrOptions;
  const scope = options.scope ?? 'HOST_ONLY';
  const includeScheme = options.includeScheme ?? false;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // Invalid URL - return lowercase as-is
    return url.toLowerCase();
  }

  // Validate scheme
  const scheme = parsed.protocol.toLowerCase();
  if (scheme !== 'http:' && scheme !== 'https:') {
    throw new Error(`Unsupported scheme: ${scheme}`);
  }

  // Normalize hostname: lowercase and strip trailing dot
  let hostname = parsed.hostname.toLowerCase();
  if (hostname.endsWith('.')) {
    hostname = hostname.slice(0, -1);
  }

  // Handle port: remove default ports
  let port = '';
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    // Only keep non-default ports
    const isDefaultPort =
      (scheme === 'http:' && parsed.port === '80') ||
      (scheme === 'https:' && parsed.port === '443');
    if (!isDefaultPort) {
      port = parsed.port;
    }
  }

  // Build host (hostname + optional port)
  const host = port ? `${hostname}:${port}` : hostname;

  // HOST_ONLY scope - return just the host
  if (scope === 'HOST_ONLY') {
    return includeScheme ? `${scheme}//${host}` : host;
  }

  // Normalize path with iterative decoding and dot-segment resolution
  const path = normalizePath(parsed.pathname);

  // HOST_PATH scope - return host + path
  if (scope === 'HOST_PATH') {
    const result = host + path;
    return includeScheme ? `${scheme}//${result}` : result;
  }

  // FULL_URL scope - include sorted query string
  const query = normalizeQueryString(parsed.search);
  const result = host + path + query;
  return includeScheme ? `${scheme}//${result}` : result;
}

/**
 * Normalize path.
 * - Handle percent-encoding consistently
 * - Protect against double-encoding attacks (iterative decode)
 * - Resolve . and .. segments after decoding
 * - Normalize trailing slashes
 * - Empty path becomes /
 */
function normalizePath(pathname: string): string {
  // Decode iteratively until stable (handles double-encoding)
  const decoded = decodeIteratively(pathname);

  // Resolve . and .. segments after decoding
  // (URL constructor resolved them at parse time, but decoded .. needs resolution)
  const segments = decoded.split('/');
  const resolved: string[] = [];

  for (const segment of segments) {
    if (segment === '..') {
      // Go up one level (but not above root)
      if (resolved.length > 0 && resolved[resolved.length - 1] !== '') {
        resolved.pop();
      }
    } else if (segment === '.') {
      // Skip current directory marker
      continue;
    } else {
      resolved.push(segment);
    }
  }

  // Re-encode consistently
  let path = resolved
    .map((segment) => {
      // Don't encode empty segments (preserves // in paths)
      if (!segment) return segment;
      return encodeURIComponent(segment);
    })
    .join('/');

  // Normalize empty path to /
  if (!path) {
    path = '/';
  }

  // Ensure path starts with /
  if (!path.startsWith('/')) {
    path = '/' + path;
  }

  // Remove trailing slash except for root
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }

  return path;
}

/**
 * Decode percent-encoding iteratively until stable.
 * Protects against double-encoding attacks (%252e = %2e = .)
 */
function decodeIteratively(str: string): string {
  let decoded = str;
  let prev = '';
  let iterations = 0;
  const maxIterations = 10; // Prevent infinite loops

  while (decoded !== prev && iterations < maxIterations) {
    prev = decoded;
    try {
      decoded = decodeURIComponent(decoded);
    } catch {
      // Malformed encoding, stop decoding
      break;
    }
    iterations++;
  }

  return decoded;
}

/**
 * Normalize query string.
 * - Sort parameters alphabetically for consistency
 * - Re-encode values
 */
function normalizeQueryString(search: string): string {
  if (!search || search === '?') {
    return '';
  }

  const params = new URLSearchParams(search);

  // Sort parameters alphabetically
  const sorted = [...params.entries()].sort((a, b) => {
    // Sort by key first, then by value
    const keyCompare = a[0].localeCompare(b[0]);
    if (keyCompare !== 0) return keyCompare;
    return a[1].localeCompare(b[1]);
  });

  if (sorted.length === 0) {
    return '';
  }

  const normalized = new URLSearchParams(sorted);
  return '?' + normalized.toString();
}

/**
 * Hash an IOC with salt.
 */
export function hashIOC(
  ioc: string,
  salt: string,
  scope: 'HOST_ONLY' | 'HOST_PATH' | 'FULL_URL' = 'HOST_ONLY'
): string {
  const canonical = canonicalizeUrl(ioc, scope);
  const data = canonical + ':' + salt;
  return sha256(data);
}

/**
 * Hash IOC returning raw bytes.
 */
export function hashIOCBytes(
  ioc: string,
  salt: string,
  scope: 'HOST_ONLY' | 'HOST_PATH' | 'FULL_URL' = 'HOST_ONLY'
): Buffer {
  const canonical = canonicalizeUrl(ioc, scope);
  const data = canonical + ':' + salt;
  return sha256Bytes(data);
}

// ============ DER/Raw Conversion (P-256 only) ============

/**
 * Convert DER-encoded ECDSA signature to raw format (r||s).
 * DER: 0x30 || len || 0x02 || rLen || r || 0x02 || sLen || s
 * Raw: r (32 bytes) || s (32 bytes)
 */
function derToRaw(der: Buffer): Buffer {
  // Skip sequence tag and length
  let offset = 2;

  // Read r
  if (der[offset] !== 0x02) throw new Error('Invalid DER signature');
  offset++;
  const rLen = der[offset];
  offset++;
  let r = der.subarray(offset, offset + rLen);
  offset += rLen;

  // Read s
  if (der[offset] !== 0x02) throw new Error('Invalid DER signature');
  offset++;
  const sLen = der[offset];
  offset++;
  let s = der.subarray(offset, offset + sLen);

  // Remove leading zeros and pad to 32 bytes
  r = padTo32(r);
  s = padTo32(s);

  return Buffer.concat([r, s]);
}

/**
 * Convert raw format signature (r||s) to DER.
 */
function rawToDer(raw: Buffer): Buffer {
  if (raw.length !== 64) {
    throw new Error(`Invalid raw signature length: ${raw.length}, expected 64`);
  }

  let r = raw.subarray(0, 32);
  let s = raw.subarray(32, 64);

  // Remove leading zeros (but keep at least one byte)
  r = trimLeadingZeros(r);
  s = trimLeadingZeros(s);

  // Add leading zero if high bit is set (to keep positive)
  if (r[0] & 0x80) r = Buffer.concat([Buffer.from([0x00]), r]);
  if (s[0] & 0x80) s = Buffer.concat([Buffer.from([0x00]), s]);

  const rEncoded = Buffer.concat([Buffer.from([0x02, r.length]), r]);
  const sEncoded = Buffer.concat([Buffer.from([0x02, s.length]), s]);

  const content = Buffer.concat([rEncoded, sEncoded]);
  return Buffer.concat([Buffer.from([0x30, content.length]), content]);
}

function padTo32(buf: Buffer): Buffer {
  // Remove leading zeros
  while (buf.length > 32 && buf[0] === 0x00) {
    buf = buf.subarray(1);
  }

  // Pad to 32 bytes
  if (buf.length < 32) {
    const padding = Buffer.alloc(32 - buf.length);
    buf = Buffer.concat([padding, buf]);
  }

  return buf;
}

function trimLeadingZeros(buf: Buffer): Buffer {
  let start = 0;
  while (start < buf.length - 1 && buf[start] === 0x00) {
    start++;
  }
  return buf.subarray(start);
}

// ============ Binary Format ============

/**
 * Convert hex hash to bytes.
 */
export function hexToBytes(hex: string): Buffer {
  return Buffer.from(hex, 'hex');
}

/**
 * Convert bytes to hex string.
 */
export function bytesToHex(buf: Buffer): string {
  return buf.toString('hex');
}

/**
 * Convert binary hash buffer to base64.
 */
export function binaryToBase64(buf: Buffer): string {
  return buf.toString('base64');
}

/**
 * Convert base64 to binary buffer.
 */
export function base64ToBinary(b64: string): Buffer {
  return Buffer.from(b64, 'base64');
}

// ============ RSA-OAEP Decryption ============

/**
 * Encrypted forensics payload format (from extension).
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
 * Decrypt a wrapped AES key using RSA-OAEP.
 */
function unwrapAESKey(wrappedKey: Buffer, privateKey: crypto.KeyObject): Buffer {
  return crypto.privateDecrypt(
    {
      key: privateKey,
      oaepHash: 'sha256',
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    wrappedKey
  );
}

/**
 * Decrypt ciphertext using AES-256-GCM.
 */
function decryptAESGCM(ciphertext: Buffer, key: Buffer, iv: Buffer): Buffer {
  // AES-GCM includes a 16-byte auth tag at the end of ciphertext
  const authTagLength = 16;
  const authTag = ciphertext.subarray(ciphertext.length - authTagLength);
  const encryptedData = ciphertext.subarray(0, ciphertext.length - authTagLength);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

  return decrypted;
}

/**
 * Decrypt forensics payload using hybrid RSA-OAEP + AES-GCM decryption.
 *
 * @param encrypted - The encrypted payload from the extension
 * @param privateKeyJwk - Customer's RSA-OAEP private key in JWK format
 * @returns Decrypted payload as parsed JSON
 */
export async function decryptForensics<T>(
  encrypted: EncryptedPayload,
  privateKeyJwk: RSAPrivateKeyJWK
): Promise<T> {
  // 1. Decode base64 values
  const iv = Buffer.from(encrypted.iv, 'base64');
  const wrappedKey = Buffer.from(encrypted.wrappedKey, 'base64');
  const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');

  // 2. Import RSA private key
  const privateKey = crypto.createPrivateKey({ key: privateKeyJwk, format: 'jwk' });

  // 3. Unwrap AES key using RSA-OAEP
  const aesKey = unwrapAESKey(wrappedKey, privateKey);

  // 4. Decrypt payload with AES-GCM
  const plaintext = decryptAESGCM(ciphertext, aesKey, iv);

  // 5. Parse JSON
  return JSON.parse(plaintext.toString('utf-8')) as T;
}

/**
 * Encrypt forensics payload using hybrid RSA-OAEP + AES-GCM encryption.
 * This is primarily for testing - the extension uses Web Crypto API for actual encryption.
 *
 * @param payload - The data to encrypt (will be JSON stringified)
 * @param publicKeyJwk - RSA-OAEP public key in JWK format
 * @returns Encrypted payload
 */
export async function encryptForensics<T>(
  payload: T,
  publicKeyJwk: RSAPublicKeyJWK
): Promise<EncryptedPayload> {
  // 1. Generate random AES-256 key and IV
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12); // 96-bit IV for AES-GCM

  // 2. Encrypt payload with AES-GCM
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf-8');
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([encrypted, authTag]);

  // 3. Wrap AES key with RSA-OAEP
  const publicKey = crypto.createPublicKey({ key: publicKeyJwk, format: 'jwk' });
  const wrappedKey = crypto.publicEncrypt(
    {
      key: publicKey,
      oaepHash: 'sha256',
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    aesKey
  );

  // 4. Return base64-encoded bundle
  return {
    iv: iv.toString('base64'),
    wrappedKey: wrappedKey.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}
