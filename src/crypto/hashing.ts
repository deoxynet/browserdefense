/**
 * BrowserDefense SHA-256 Hashing Module
 *
 * Uses Web Crypto API for all hashing operations.
 * No external dependencies.
 */

/**
 * IOC scope levels for URL canonicalization.
 * - HOST_ONLY: Just the scheme + host (recommended for phishing)
 * - HOST_PATH: Scheme + host + path (recommended for malware)
 * - FULL_URL: Scheme + host + path + sorted query params
 */
export type IOCScope = 'HOST_ONLY' | 'HOST_PATH' | 'FULL_URL';

/**
 * Convert a hex string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert a Uint8Array to hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Compute SHA-256 hash of arbitrary data.
 * Returns hex string.
 */
export async function sha256(data: string | Uint8Array): Promise<string> {
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', input as BufferSource);
  return bytesToHex(new Uint8Array(hashBuffer));
}

/**
 * Compute SHA-256 hash and return raw bytes.
 */
export async function sha256Bytes(data: string | Uint8Array): Promise<Uint8Array> {
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', input as BufferSource);
  return new Uint8Array(hashBuffer);
}

/**
 * Compute SHA-256 hash and return as ArrayBuffer (for compatibility).
 */
export async function sha256ArrayBuffer(input: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  return crypto.subtle.digest('SHA-256', data);
}

/**
 * Compute SHA-256 hash of a string and return as hex string.
 * Alias for sha256() when called with a string.
 */
export async function sha256Hex(input: string): Promise<string> {
  return sha256(input);
}

/**
 * Canonicalize a URL for consistent IOC hashing.
 *
 * Rules:
 * 1. Lowercase scheme and host
 * 2. Convert IDN to punycode (browser handles this)
 * 3. Remove trailing dot from host
 * 4. Remove default ports (80 for http, 443 for https)
 * 5. Normalize path encoding
 * 6. Sort query parameters alphabetically
 * 7. Never include fragment
 */
export function canonicalizeUrl(url: string, scope: IOCScope = 'HOST_ONLY'): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // Invalid URL - return lowercase as-is (will likely not match any IOC)
    return url.toLowerCase();
  }

  // 1. Lowercase scheme
  let canonical = parsed.protocol.toLowerCase() + '//';

  // 2-3. Lowercase host and remove trailing dot
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  canonical += host;

  // 4. Add port only if non-default
  const isDefaultPort =
    (parsed.protocol === 'http:' && parsed.port === '80') ||
    (parsed.protocol === 'https:' && parsed.port === '443') ||
    parsed.port === '';

  if (!isDefaultPort) {
    canonical += ':' + parsed.port;
  }

  if (scope === 'HOST_ONLY') {
    return canonical;
  }

  // 5. Normalize path
  let path = parsed.pathname;
  try {
    // Decode then re-encode for consistency
    path = decodeURIComponent(path);
  } catch {
    // Invalid encoding, keep as-is
  }
  // Re-encode each segment
  path = path
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
  // Empty path becomes /
  if (!path) path = '/';

  canonical += path;

  if (scope === 'HOST_PATH') {
    return canonical;
  }

  // 6. Sort and normalize query parameters
  if (parsed.search) {
    const params = new URLSearchParams(parsed.search);
    const sortedParams = new URLSearchParams([...params.entries()].sort());
    canonical += '?' + sortedParams.toString();
  }

  // Fragment is never included
  return canonical;
}

/**
 * Hash an IOC (Indicator of Compromise) with salt.
 *
 * The salt ensures that even if an attacker knows a URL is blocked,
 * they can't compute the hash without the customer's salt.
 *
 * @param ioc - The URL/domain to hash
 * @param salt - Customer-specific salt (base64 encoded)
 * @param scope - How much of the URL to include
 * @returns SHA-256 hash as hex string
 */
export async function hashIOC(
  ioc: string,
  salt: string,
  scope: IOCScope = 'HOST_ONLY'
): Promise<string> {
  // 1. Canonicalize the URL
  const canonical = canonicalizeUrl(ioc, scope);

  // 2. Combine with salt (using colon as separator)
  const data = canonical + ':' + salt;

  // 3. Hash with SHA-256
  return sha256(data);
}

/**
 * Hash an IOC and return raw bytes (for binary storage).
 */
export async function hashIOCBytes(
  ioc: string,
  salt: string,
  scope: IOCScope = 'HOST_ONLY'
): Promise<Uint8Array> {
  const canonical = canonicalizeUrl(ioc, scope);
  const data = canonical + ':' + salt;
  return sha256Bytes(data);
}

/**
 * Batch hash multiple IOCs efficiently.
 */
export async function hashIOCBatch(
  iocs: string[],
  salt: string,
  scope: IOCScope = 'HOST_ONLY'
): Promise<Map<string, string>> {
  const results = new Map<string, string>();
  await Promise.all(
    iocs.map(async (ioc) => {
      const hash = await hashIOC(ioc, salt, scope);
      results.set(ioc, hash);
    })
  );
  return results;
}
