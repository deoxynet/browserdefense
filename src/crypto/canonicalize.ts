/**
 * URL Canonicalization for BrowserDefense.
 *
 * Normalizes URLs consistently before hashing to prevent bypass attacks.
 * See docs/Canonicalization_Specification.md for full specification.
 */

import { parse as parseDomain } from 'tldts';

/**
 * Canonicalization scope - determines what parts of the URL are included.
 */
export type CanonicalizationScope = 'HOST_ONLY' | 'HOST_PATH' | 'FULL_URL';

/**
 * Options for URL canonicalization.
 */
export interface CanonicalizationOptions {
  /** What parts of the URL to include */
  scope?: CanonicalizationScope;
  /** Include scheme in output (default: false for hash comparison) */
  includeScheme?: boolean;
}

const DEFAULT_OPTIONS: Required<CanonicalizationOptions> = {
  scope: 'HOST_PATH',
  includeScheme: false,
};

/**
 * Canonicalize a URL for consistent hashing.
 *
 * @param input - URL string or URL object to canonicalize
 * @param options - Canonicalization options
 * @returns Canonicalized URL string
 * @throws Error if URL is invalid or uses unsupported scheme
 */
export function canonicalizeUrl(
  input: string | URL,
  options: CanonicalizationOptions = {}
): string {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  // Parse URL if string
  let url: URL;
  try {
    url = typeof input === 'string' ? new URL(input) : input;
  } catch {
    throw new Error(`Invalid URL: ${input}`);
  }

  // Validate scheme
  const scheme = url.protocol.toLowerCase();
  if (scheme !== 'http:' && scheme !== 'https:') {
    throw new Error(`Unsupported scheme: ${scheme}`);
  }

  // Normalize hostname
  const hostname = normalizeHostname(url.hostname);

  // Handle port
  const port = normalizePort(url.port, scheme);

  // Build host (hostname + optional port)
  const host = port ? `${hostname}:${port}` : hostname;

  // HOST_ONLY scope - return just the host
  if (opts.scope === 'HOST_ONLY') {
    return opts.includeScheme ? `${scheme}//${host}` : host;
  }

  // Normalize path
  const path = normalizePath(url.pathname);

  // HOST_PATH scope - return host + path
  if (opts.scope === 'HOST_PATH') {
    const result = host + path;
    return opts.includeScheme ? `${scheme}//${result}` : result;
  }

  // FULL_URL scope - include sorted query string
  const query = normalizeQueryString(url.search);
  const result = host + path + query;
  return opts.includeScheme ? `${scheme}//${result}` : result;
}

/**
 * Normalize hostname.
 * - Lowercase
 * - Strip trailing dot
 * - IDN/IPv4/IPv6 handled by URL constructor
 */
function normalizeHostname(hostname: string): string {
  let normalized = hostname.toLowerCase();

  // Strip trailing dot (DNS root)
  if (normalized.endsWith('.')) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

/**
 * Normalize port.
 * - Remove default ports (80 for http, 443 for https)
 * - Return empty string if default or not specified
 */
function normalizePort(port: string, scheme: string): string {
  if (!port) return '';

  // Remove default ports
  if (scheme === 'http:' && port === '80') return '';
  if (scheme === 'https:' && port === '443') return '';

  return port;
}

/**
 * Normalize path.
 * - Handle percent-encoding consistently
 * - Protect against double-encoding attacks
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
    .map(segment => {
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
 * Extract the registrable domain (eTLD+1) from a hostname.
 * For example: sub.example.co.uk → example.co.uk
 *
 * Uses the Public Suffix List via tldts for accurate domain extraction.
 * Handles:
 * - Multi-part TLDs (co.uk, com.au, co.jp, etc.)
 * - Private suffixes (github.io, s3.amazonaws.com, etc.)
 * - New gTLDs (.app, .dev, .security, etc.)
 */
export function extractRegistrableDomain(hostname: string): string {
  // Normalize first
  hostname = normalizeHostname(hostname);

  // Handle IP addresses (no registrable domain concept)
  if (isIPAddress(hostname)) {
    return hostname;
  }

  // Use tldts for accurate PSL-based domain extraction
  const parsed = parseDomain(hostname, {
    // Include private suffixes like github.io, s3.amazonaws.com
    allowPrivateDomains: true,
  });

  // If tldts found a registrable domain, use it
  if (parsed.domain) {
    return parsed.domain.toLowerCase();
  }

  // Fallback: return the hostname as-is if PSL lookup fails
  // (e.g., for localhost or custom TLDs)
  return hostname;
}

/**
 * Check if a string is an IP address (v4 or v6).
 */
function isIPAddress(hostname: string): boolean {
  // IPv6 (bracketed)
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    return true;
  }

  // IPv4 - simple check for four numbers separated by dots
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(hostname)) {
    return true;
  }

  // IPv6 without brackets (rare in URLs)
  if (hostname.includes(':') && !hostname.includes('.')) {
    return true;
  }

  return false;
}

/**
 * Validate that a URL can be canonicalized.
 * Returns null if valid, error message if invalid.
 */
export function validateUrl(input: string): string | null {
  try {
    const url = new URL(input);
    const scheme = url.protocol.toLowerCase();

    if (scheme !== 'http:' && scheme !== 'https:') {
      return `Unsupported scheme: ${scheme}`;
    }

    return null;
  } catch {
    return `Invalid URL format`;
  }
}

/**
 * Canonicalize and hash a URL with a salt.
 * Convenience function combining canonicalization with hashing.
 */
export async function canonicalizeAndHash(
  url: string,
  salt: string,
  options: CanonicalizationOptions = {}
): Promise<Uint8Array> {
  const canonical = canonicalizeUrl(url, options);
  const data = canonical + ':' + salt;

  const hashBuffer = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(data)
  );

  return new Uint8Array(hashBuffer);
}
