/**
 * TLS & Certificate Metadata Types
 *
 * Types for capturing TLS connection and certificate metadata on blocked pages.
 * This metadata helps analysts understand the security context of blocked URLs.
 *
 * PRIVACY GUARANTEES:
 * - NO private key material
 * - NO session keys
 * - NO user credentials
 * - Only public certificate and connection metadata
 *
 * NOTE: Chrome extensions cannot directly access SSL certificates.
 * Certificate details (issuer, SANs, fingerprint) require server-side enrichment.
 * Local capture is limited to protocol and security headers.
 *
 * Reference: Issue #168
 */

/**
 * TLS connection metadata.
 * Captured locally from security headers and URL analysis.
 */
export interface TLSConnectionMetadata {
  /** Whether the connection uses HTTPS */
  isSecure: boolean;
  /** URL scheme (http, https) */
  scheme: 'http' | 'https';
  /** TLS/SSL protocol version if detectable (e.g., 'TLSv1.2', 'TLSv1.3') */
  protocolVersion?: string;
  /** Whether HSTS header was present */
  hasHSTS: boolean;
  /** HSTS max-age value in seconds (if present) */
  hstsMaxAge?: number;
  /** Whether HSTS includes subdomains */
  hstsIncludeSubdomains?: boolean;
  /** Whether HSTS has preload directive */
  hstsPreload?: boolean;
  /** Whether connection used HTTP/2 or HTTP/3 */
  httpVersion?: 'HTTP/1.1' | 'HTTP/2' | 'HTTP/3';
}

/**
 * Certificate metadata.
 * Obtained via server-side enrichment (not directly accessible in Chrome).
 */
export interface CertificateMetadata {
  /** Certificate issuer Common Name (CN) */
  issuerCN?: string;
  /** Certificate issuer Organization (O) */
  issuerOrg?: string;
  /** Full issuer distinguished name */
  issuerDN?: string;
  /** Subject Common Name (CN) */
  subjectCN?: string;
  /** Subject Organization (O) */
  subjectOrg?: string;
  /** Subject Alternative Names (SANs) - domain names */
  subjectAltNames?: string[];
  /** SHA-256 fingerprint of the certificate (hex, lowercase) */
  fingerprintSHA256?: string;
  /** SHA-1 fingerprint for legacy reference (hex, lowercase) */
  fingerprintSHA1?: string;
  /** Certificate serial number (hex) */
  serialNumber?: string;
  /** Certificate validity start (ISO 8601) */
  validFrom?: string;
  /** Certificate validity end (ISO 8601) */
  validUntil?: string;
  /** Days until certificate expires */
  daysUntilExpiry?: number;
  /** Whether certificate is expired */
  isExpired?: boolean;
  /** Public key algorithm (RSA, ECDSA, Ed25519) */
  publicKeyAlgorithm?: string;
  /** Public key size in bits */
  publicKeySize?: number;
  /** Signature algorithm (e.g., SHA256withRSA) */
  signatureAlgorithm?: string;
  /** Whether certificate is self-signed */
  isSelfSigned?: boolean;
  /** Certificate chain length (1 = end entity only) */
  chainLength?: number;
  /** Extended Validation (EV) certificate */
  isEV?: boolean;
  /** Organization Validated (OV) certificate */
  isOV?: boolean;
  /** Domain Validated (DV) certificate */
  isDV?: boolean;
}

/**
 * Complete TLS metadata combining connection and certificate info.
 */
export interface TLSMetadata {
  /** Hostname from the URL */
  hostname: string;
  /** Port number (443 for HTTPS, 80 for HTTP, or custom) */
  port: number;
  /** Connection-level TLS metadata (captured locally) */
  connection: TLSConnectionMetadata;
  /** Certificate metadata (requires server-side enrichment) */
  certificate?: CertificateMetadata;
  /** When the metadata was captured (Unix timestamp ms) */
  capturedAt: number;
  /** Source of certificate data */
  certificateSource?: 'local' | 'enrichment_server' | 'unavailable';
  /** Error message if certificate lookup failed */
  certificateError?: string;
}

/**
 * Security headers captured from response.
 */
export interface SecurityHeaders {
  /** Strict-Transport-Security header value */
  strictTransportSecurity?: string;
  /** Content-Security-Policy header value (truncated for privacy) */
  contentSecurityPolicy?: string;
  /** X-Content-Type-Options header value */
  xContentTypeOptions?: string;
  /** X-Frame-Options header value */
  xFrameOptions?: string;
  /** X-XSS-Protection header value */
  xXSSProtection?: string;
  /** Referrer-Policy header value */
  referrerPolicy?: string;
  /** Permissions-Policy header value (truncated) */
  permissionsPolicy?: string;
}

/**
 * Configuration for TLS metadata capture.
 */
export interface TLSCaptureConfig {
  /** Whether TLS metadata capture is enabled */
  enabled: boolean;
  /** Server endpoint for certificate enrichment (optional) */
  enrichmentEndpoint?: string;
  /** Timeout for enrichment requests in milliseconds */
  enrichmentTimeoutMs?: number;
  /** Whether to cache enrichment results */
  cacheEnrichment?: boolean;
  /** Maximum security header value length to capture */
  maxHeaderLength?: number;
}

/**
 * Default TLS capture configuration.
 */
export const DEFAULT_TLS_CAPTURE_CONFIG: TLSCaptureConfig = {
  enabled: true,
  enrichmentTimeoutMs: 3000,
  cacheEnrichment: true,
  maxHeaderLength: 500, // Truncate long CSP headers
};

/**
 * Request payload for certificate enrichment server.
 * Sends only hostname - no URLs or user data.
 */
export interface CertificateEnrichmentRequest {
  /** Hostname to lookup */
  hostname: string;
  /** Port number (usually 443) */
  port: number;
}

/**
 * Response from certificate enrichment server.
 */
export interface CertificateEnrichmentResponse {
  /** Whether lookup succeeded */
  success: boolean;
  /** Certificate metadata if successful */
  certificate?: CertificateMetadata;
  /** Error message if lookup failed */
  error?: string;
  /** Connection metadata from server's perspective */
  connection?: {
    protocolVersion?: string;
    cipherSuite?: string;
  };
}

/**
 * Parse HSTS header into structured data.
 *
 * @param headerValue - Strict-Transport-Security header value
 * @returns Parsed HSTS data
 */
export function parseHSTSHeader(headerValue: string): {
  maxAge?: number;
  includeSubdomains: boolean;
  preload: boolean;
} {
  const result = {
    maxAge: undefined as number | undefined,
    includeSubdomains: false,
    preload: false,
  };

  if (!headerValue) {
    return result;
  }

  // Parse max-age
  const maxAgeMatch = headerValue.match(/max-age=(\d+)/i);
  if (maxAgeMatch) {
    result.maxAge = parseInt(maxAgeMatch[1], 10);
  }

  // Check for includeSubDomains (case-insensitive)
  result.includeSubdomains = /includeSubDomains/i.test(headerValue);

  // Check for preload
  result.preload = /preload/i.test(headerValue);

  return result;
}

/**
 * Extract hostname and port from URL.
 *
 * @param url - Full URL
 * @returns Hostname and port
 */
export function extractHostPort(url: string): { hostname: string; port: number } {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    let port: number;

    if (parsed.port) {
      port = parseInt(parsed.port, 10);
    } else if (parsed.protocol === 'https:') {
      port = 443;
    } else {
      port = 80;
    }

    return { hostname, port };
  } catch {
    return { hostname: '', port: 0 };
  }
}

/**
 * Truncate a header value to maximum length for privacy.
 *
 * @param value - Header value
 * @param maxLength - Maximum length
 * @returns Truncated value
 */
export function truncateHeader(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }
  return value.slice(0, maxLength) + '...[truncated]';
}
