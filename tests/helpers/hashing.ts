/**
 * Shared Test Utilities for Hashing
 *
 * Issue #489: Consolidate hashing test utilities to prevent salt mismatches
 * between tests and production code.
 *
 * This module provides:
 * - Consistent test salt constants
 * - Re-exports of production hashing functions
 * - Helper utilities for creating test blocklists
 */

// Re-export all production hashing functions for test use
export {
  sha256,
  sha256Bytes,
  sha256ArrayBuffer,
  sha256Hex,
  hexToBytes,
  bytesToHex,
  canonicalizeUrl,
  hashIOC,
  hashIOCBytes,
  hashIOCBatch,
  type IOCScope,
} from '../../src/crypto/hashing';

/**
 * Standard test salt for all tests.
 * Using base64-encoded "test-salt" for consistency.
 */
export const TEST_SALT = 'dGVzdC1zYWx0'; // base64 of "test-salt"

/**
 * Alternative test salt for multi-salt scenarios.
 */
export const TEST_SALT_ALT = 'YWx0LXRlc3Qtc2FsdA=='; // base64 of "alt-test-salt"

/**
 * Salt specifically for E2E tests that need browser-compatible hashing.
 */
export const E2E_TEST_SALT = 'e2e-test-salt';

/**
 * Hash a URL using the same algorithm as the extension's blocking logic.
 * Uses HOST_PATH scope with scheme included.
 *
 * @param url - The URL to hash
 * @param salt - The salt to use (defaults to TEST_SALT)
 * @returns SHA-256 hash as Uint8Array
 */
export async function hashUrl(url: string, salt: string = TEST_SALT): Promise<Uint8Array> {
  // Parse URL
  const parsed = new URL(url);

  // Get scheme (includes colon: "http:")
  const scheme = parsed.protocol;

  // Normalize hostname (lowercase, no trailing dot)
  let hostname = parsed.hostname.toLowerCase();
  if (hostname.endsWith('.')) {
    hostname = hostname.slice(0, -1);
  }

  // Normalize port (remove default ports)
  let port = parsed.port;
  if (scheme === 'http:' && port === '80') port = '';
  if (scheme === 'https:' && port === '443') port = '';

  // Build host
  const host = port ? `${hostname}:${port}` : hostname;

  // Normalize path (no trailing slash except for root)
  let path = parsed.pathname;
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }
  if (!path) {
    path = '/';
  }

  // Build canonical form: scheme://host/path (with scheme)
  const canonical = `${scheme}//${host}${path}`;

  // Hash: SHA-256(canonical + ':' + salt)
  const data = canonical + ':' + salt;
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return new Uint8Array(hashBuffer);
}

/**
 * Hash a URL using HOST_PATH scope (same as hashUrl but matches extension naming).
 */
export async function hashUrlForHostPath(
  url: string,
  salt: string = TEST_SALT
): Promise<Uint8Array> {
  return hashUrl(url, salt);
}

/**
 * Create a binary blocklist from an array of hashes.
 * Each hash is 32 bytes, sorted and concatenated.
 *
 * @param hashes - Array of 32-byte hashes
 * @returns Base64-encoded binary blocklist
 */
export function createBinaryBlocklist(hashes: Uint8Array[]): string {
  // Sort hashes for binary search
  hashes.sort((a, b) => {
    for (let i = 0; i < 32; i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return 0;
  });

  // Concatenate into single buffer
  const buffer = new Uint8Array(hashes.length * 32);
  for (let i = 0; i < hashes.length; i++) {
    buffer.set(hashes[i], i * 32);
  }

  // Base64 encode
  let binary = '';
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary);
}

/**
 * Create a test configuration object with the given salt.
 *
 * @param salt - The IOC salt to use
 * @returns Configuration object matching BrowserDefenseConfig
 */
export function createTestConfig(salt: string = TEST_SALT) {
  return {
    ioc_salt: salt,
    ioc_scope: 'HOST_PATH' as const,
    forensics_enabled: true,
    forensics_endpoint: 'https://test.example.com/forensics',
    forensics_public_key: 'test-public-key',
  };
}

/**
 * Create a minimal test configuration (just salt).
 */
export function createMinimalTestConfig(salt: string = TEST_SALT) {
  return {
    ioc_salt: salt,
  };
}
