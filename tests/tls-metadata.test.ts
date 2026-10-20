/**
 * Tests for TLS & Certificate Metadata Capture Module
 *
 * Tests for TLS connection metadata capture, security headers extraction,
 * and optional certificate enrichment via server-side lookup.
 *
 * Reference: Issue #168
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  parseHSTSHeader,
  extractHostPort,
  truncateHeader,
  DEFAULT_TLS_CAPTURE_CONFIG,
  type TLSMetadata,
  type TLSConnectionMetadata,
  type CertificateMetadata,
  type SecurityHeaders,
  type TLSCaptureConfig,
} from '../src/types/tls-metadata';
import { TLS_CAPTURE_CONFIG_KEY } from '../src/config/storage-keys';

// ============ Mock Chrome APIs ============

const mockStorage: Record<string, unknown> = {};

const mockChrome = {
  storage: {
    local: {
      get: vi.fn((key: string | string[]) => {
        if (typeof key === 'string') {
          return Promise.resolve({ [key]: mockStorage[key] });
        }
        const result: Record<string, unknown> = {};
        for (const k of key) {
          result[k] = mockStorage[k];
        }
        return Promise.resolve(result);
      }),
      set: vi.fn((items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
        return Promise.resolve();
      }),
      remove: vi.fn((key: string | string[]) => {
        if (typeof key === 'string') {
          delete mockStorage[key];
        } else {
          for (const k of key) {
            delete mockStorage[k];
          }
        }
        return Promise.resolve();
      }),
    },
  },
  webRequest: {
    onHeadersReceived: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
    },
  },
  tabs: {
    onRemoved: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
    },
  },
};

// @ts-expect-error - Mocking chrome global
globalThis.chrome = mockChrome;

// Mock fetch for enrichment tests
const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

describe('TLS Metadata Types', () => {
  describe('parseHSTSHeader', () => {
    it('should parse empty header', () => {
      const result = parseHSTSHeader('');
      expect(result.maxAge).toBeUndefined();
      expect(result.includeSubdomains).toBe(false);
      expect(result.preload).toBe(false);
    });

    it('should parse max-age only', () => {
      const result = parseHSTSHeader('max-age=31536000');
      expect(result.maxAge).toBe(31536000);
      expect(result.includeSubdomains).toBe(false);
      expect(result.preload).toBe(false);
    });

    it('should parse max-age with includeSubDomains', () => {
      const result = parseHSTSHeader('max-age=31536000; includeSubDomains');
      expect(result.maxAge).toBe(31536000);
      expect(result.includeSubdomains).toBe(true);
      expect(result.preload).toBe(false);
    });

    it('should parse full HSTS header with preload', () => {
      const result = parseHSTSHeader('max-age=31536000; includeSubDomains; preload');
      expect(result.maxAge).toBe(31536000);
      expect(result.includeSubdomains).toBe(true);
      expect(result.preload).toBe(true);
    });

    it('should handle case-insensitive directives', () => {
      const result = parseHSTSHeader('Max-Age=63072000; INCLUDESUBDOMAINS; PRELOAD');
      expect(result.maxAge).toBe(63072000);
      expect(result.includeSubdomains).toBe(true);
      expect(result.preload).toBe(true);
    });

    it('should handle variations in spacing', () => {
      const result = parseHSTSHeader('max-age=3600;includeSubDomains;preload');
      expect(result.maxAge).toBe(3600);
      expect(result.includeSubdomains).toBe(true);
      expect(result.preload).toBe(true);
    });
  });

  describe('extractHostPort', () => {
    it('should extract hostname and default HTTPS port', () => {
      const result = extractHostPort('https://example.com/path');
      expect(result.hostname).toBe('example.com');
      expect(result.port).toBe(443);
    });

    it('should extract hostname and default HTTP port', () => {
      const result = extractHostPort('http://example.com/path');
      expect(result.hostname).toBe('example.com');
      expect(result.port).toBe(80);
    });

    it('should extract custom port', () => {
      const result = extractHostPort('https://example.com:8443/path');
      expect(result.hostname).toBe('example.com');
      expect(result.port).toBe(8443);
    });

    it('should handle URL with query string', () => {
      const result = extractHostPort('https://example.com:9000/path?query=1');
      expect(result.hostname).toBe('example.com');
      expect(result.port).toBe(9000);
    });

    it('should handle invalid URL gracefully', () => {
      const result = extractHostPort('not-a-valid-url');
      expect(result.hostname).toBe('');
      expect(result.port).toBe(0);
    });

    it('should handle subdomain', () => {
      const result = extractHostPort('https://www.sub.example.com/');
      expect(result.hostname).toBe('www.sub.example.com');
      expect(result.port).toBe(443);
    });
  });

  describe('truncateHeader', () => {
    it('should not truncate short headers', () => {
      const result = truncateHeader('short value', 100);
      expect(result).toBe('short value');
    });

    it('should truncate long headers', () => {
      const longValue = 'a'.repeat(200);
      const result = truncateHeader(longValue, 100);
      expect(result).toBe('a'.repeat(100) + '...[truncated]');
    });

    it('should handle exact length', () => {
      const exactValue = 'a'.repeat(100);
      const result = truncateHeader(exactValue, 100);
      expect(result).toBe(exactValue);
    });

    it('should handle empty string', () => {
      const result = truncateHeader('', 100);
      expect(result).toBe('');
    });
  });

  describe('DEFAULT_TLS_CAPTURE_CONFIG', () => {
    it('should have expected default values', () => {
      expect(DEFAULT_TLS_CAPTURE_CONFIG.enabled).toBe(true);
      expect(DEFAULT_TLS_CAPTURE_CONFIG.enrichmentTimeoutMs).toBe(3000);
      expect(DEFAULT_TLS_CAPTURE_CONFIG.cacheEnrichment).toBe(true);
      expect(DEFAULT_TLS_CAPTURE_CONFIG.maxHeaderLength).toBe(500);
    });
  });
});

describe('TLS Metadata Module', () => {
  // Dynamic import to get fresh module state
  let tlsModule: typeof import('../src/background/tls-metadata');

  beforeEach(async () => {
    // Clear mock storage
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    vi.clearAllMocks();
    mockFetch.mockReset();

    // Fresh import to reset module state
    vi.resetModules();
    tlsModule = await import('../src/background/tls-metadata');
  });

  describe('getTLSCaptureConfig', () => {
    it('should return default config when none stored', async () => {
      const config = await tlsModule.getTLSCaptureConfig();
      expect(config.enabled).toBe(true);
      expect(config.enrichmentTimeoutMs).toBe(3000);
      expect(config.cacheEnrichment).toBe(true);
    });

    it('should merge stored config with defaults', async () => {
      mockStorage[TLS_CAPTURE_CONFIG_KEY] = {
        enabled: false,
        enrichmentEndpoint: 'https://api.example.com/cert',
      };

      const config = await tlsModule.getTLSCaptureConfig();
      expect(config.enabled).toBe(false);
      expect(config.enrichmentEndpoint).toBe('https://api.example.com/cert');
      expect(config.enrichmentTimeoutMs).toBe(3000); // Default preserved
    });
  });

  describe('updateTLSCaptureConfig', () => {
    it('should update and return merged config', async () => {
      const updated = await tlsModule.updateTLSCaptureConfig({
        enabled: false,
        enrichmentEndpoint: 'https://cert-api.example.com',
      });

      expect(updated.enabled).toBe(false);
      expect(updated.enrichmentEndpoint).toBe('https://cert-api.example.com');
      expect(mockChrome.storage.local.set).toHaveBeenCalled();
    });

    it('should preserve existing config when updating', async () => {
      mockStorage[TLS_CAPTURE_CONFIG_KEY] = {
        enrichmentEndpoint: 'https://existing.com',
      };

      const updated = await tlsModule.updateTLSCaptureConfig({
        cacheEnrichment: false,
      });

      expect(updated.enrichmentEndpoint).toBe('https://existing.com');
      expect(updated.cacheEnrichment).toBe(false);
    });
  });

  describe('initTLSCapture', () => {
    it('should register webRequest listener', () => {
      tlsModule.initTLSCapture();

      expect(mockChrome.webRequest.onHeadersReceived.addListener).toHaveBeenCalled();
      const call = mockChrome.webRequest.onHeadersReceived.addListener.mock.calls[0];
      expect(call[1]).toEqual({
        urls: ['http://*/*', 'https://*/*'],
        types: ['main_frame'],
      });
      expect(call[2]).toEqual(['responseHeaders']);
    });
  });

  describe('TLS metadata storage', () => {
    it('should store and retrieve metadata by tab', () => {
      const tabId = 123;

      // Manually store metadata via internal map
      const metadata: TLSMetadata = {
        hostname: 'example.com',
        port: 443,
        connection: {
          isSecure: true,
          scheme: 'https',
          hasHSTS: true,
          hstsMaxAge: 31536000,
        },
        capturedAt: Date.now(),
        certificateSource: 'unavailable',
      };

      tlsModule._tlsMetadataByTab.set(tabId, metadata);

      const retrieved = tlsModule.getTLSMetadata(tabId);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.hostname).toBe('example.com');
      expect(retrieved?.connection.hasHSTS).toBe(true);
    });

    it('should return null for unknown tab', () => {
      const retrieved = tlsModule.getTLSMetadata(999);
      expect(retrieved).toBeNull();
    });

    it('should consume and remove metadata', () => {
      const tabId = 456;

      const metadata: TLSMetadata = {
        hostname: 'test.com',
        port: 443,
        connection: {
          isSecure: true,
          scheme: 'https',
          hasHSTS: false,
        },
        capturedAt: Date.now(),
        certificateSource: 'unavailable',
      };

      tlsModule._tlsMetadataByTab.set(tabId, metadata);

      const consumed = tlsModule.consumeTLSMetadata(tabId);
      expect(consumed).not.toBeNull();
      expect(consumed?.hostname).toBe('test.com');

      // Should be removed after consumption
      const second = tlsModule.getTLSMetadata(tabId);
      expect(second).toBeNull();
    });

    it('should clear metadata for tab', () => {
      const tabId = 789;

      tlsModule._tlsMetadataByTab.set(tabId, {
        hostname: 'clear.com',
        port: 443,
        connection: { isSecure: true, scheme: 'https', hasHSTS: false },
        capturedAt: Date.now(),
        certificateSource: 'unavailable',
      });

      tlsModule._securityHeadersByTab.set(tabId, {
        strictTransportSecurity: 'max-age=3600',
      });

      tlsModule.clearTLSMetadata(tabId);

      expect(tlsModule.getTLSMetadata(tabId)).toBeNull();
      expect(tlsModule.getSecurityHeaders(tabId)).toBeNull();
    });
  });

  describe('Security headers storage', () => {
    it('should store and retrieve security headers', () => {
      const tabId = 100;

      const headers: SecurityHeaders = {
        strictTransportSecurity: 'max-age=31536000',
        contentSecurityPolicy: "default-src 'self'",
        xContentTypeOptions: 'nosniff',
        xFrameOptions: 'DENY',
      };

      tlsModule._securityHeadersByTab.set(tabId, headers);

      const retrieved = tlsModule.getSecurityHeaders(tabId);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.strictTransportSecurity).toBe('max-age=31536000');
      expect(retrieved?.xContentTypeOptions).toBe('nosniff');
    });
  });

  describe('enrichWithCertificate', () => {
    const baseMetadata: TLSMetadata = {
      hostname: 'secure.example.com',
      port: 443,
      connection: {
        isSecure: true,
        scheme: 'https',
        hasHSTS: true,
      },
      capturedAt: Date.now(),
      certificateSource: 'unavailable',
    };

    it('should return unchanged if no enrichment endpoint', async () => {
      const config: TLSCaptureConfig = {
        enabled: true,
        cacheEnrichment: false,
      };

      const result = await tlsModule.enrichWithCertificate(baseMetadata, config);

      expect(result.certificateSource).toBe('unavailable');
      expect(result.certificateError).toBe('No enrichment endpoint configured');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should fetch and merge certificate data', async () => {
      const config: TLSCaptureConfig = {
        enabled: true,
        enrichmentEndpoint: 'https://cert-api.example.com/lookup',
        enrichmentTimeoutMs: 3000,
        cacheEnrichment: false,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            success: true,
            certificate: {
              issuerCN: 'DigiCert Global CA',
              issuerOrg: 'DigiCert Inc',
              subjectCN: 'secure.example.com',
              subjectAltNames: ['secure.example.com', 'www.example.com'],
              fingerprintSHA256: 'abc123def456',
              validFrom: '2024-01-01T00:00:00Z',
              validUntil: '2025-01-01T00:00:00Z',
              publicKeyAlgorithm: 'RSA',
              publicKeySize: 2048,
            },
            connection: {
              protocolVersion: 'TLSv1.3',
            },
          }),
      });

      const result = await tlsModule.enrichWithCertificate(baseMetadata, config);

      expect(result.certificateSource).toBe('enrichment_server');
      expect(result.certificate?.issuerCN).toBe('DigiCert Global CA');
      expect(result.certificate?.subjectAltNames).toEqual(['secure.example.com', 'www.example.com']);
      expect(result.connection.protocolVersion).toBe('TLSv1.3');

      // Check fetch was called correctly
      expect(mockFetch).toHaveBeenCalledWith(
        'https://cert-api.example.com/lookup',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hostname: 'secure.example.com', port: 443 }),
        })
      );
    });

    it('should handle enrichment failure gracefully', async () => {
      const config: TLSCaptureConfig = {
        enabled: true,
        enrichmentEndpoint: 'https://cert-api.example.com/lookup',
        cacheEnrichment: false,
      };

      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const result = await tlsModule.enrichWithCertificate(baseMetadata, config);

      expect(result.certificateSource).toBe('unavailable');
      expect(result.certificateError).toBe('Network error');
    });

    it('should handle HTTP error response', async () => {
      const config: TLSCaptureConfig = {
        enabled: true,
        enrichmentEndpoint: 'https://cert-api.example.com/lookup',
        cacheEnrichment: false,
      };

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      const result = await tlsModule.enrichWithCertificate(baseMetadata, config);

      expect(result.certificateSource).toBe('unavailable');
      expect(result.certificateError).toBe('HTTP 500: Internal Server Error');
    });

    it('should use cache for repeated lookups', async () => {
      const config: TLSCaptureConfig = {
        enabled: true,
        enrichmentEndpoint: 'https://cert-api.example.com/lookup',
        cacheEnrichment: true,
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            success: true,
            certificate: {
              issuerCN: 'Cached CA',
            },
          }),
      });

      // First call
      const result1 = await tlsModule.enrichWithCertificate(baseMetadata, config);
      expect(result1.certificate?.issuerCN).toBe('Cached CA');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second call - should use cache
      const result2 = await tlsModule.enrichWithCertificate(baseMetadata, config);
      expect(result2.certificate?.issuerCN).toBe('Cached CA');
      expect(mockFetch).toHaveBeenCalledTimes(1); // No additional fetch
    });
  });

  describe('captureTLSMetadata', () => {
    it('should capture basic HTTPS metadata', async () => {
      const result = await tlsModule.captureTLSMetadata('https://secure.example.com/path');

      expect(result.hostname).toBe('secure.example.com');
      expect(result.port).toBe(443);
      expect(result.connection.isSecure).toBe(true);
      expect(result.connection.scheme).toBe('https');
      expect(result.capturedAt).toBeGreaterThan(0);
      expect(result.certificateSource).toBe('unavailable');
    });

    it('should capture HTTP metadata', async () => {
      const result = await tlsModule.captureTLSMetadata('http://insecure.example.com/path');

      expect(result.hostname).toBe('insecure.example.com');
      expect(result.port).toBe(80);
      expect(result.connection.isSecure).toBe(false);
      expect(result.connection.scheme).toBe('http');
    });

    it('should store metadata by tab if provided', async () => {
      const tabId = 555;
      await tlsModule.captureTLSMetadata('https://example.com', tabId);

      const stored = tlsModule.getTLSMetadata(tabId);
      expect(stored).not.toBeNull();
      expect(stored?.hostname).toBe('example.com');
    });
  });

  describe('Enrichment cache', () => {
    it('should track cache statistics', () => {
      const stats = tlsModule.getEnrichmentCacheStats();

      expect(stats.size).toBe(0);
      expect(stats.oldestEntry).toBeUndefined();
      expect(stats.newestEntry).toBeUndefined();
    });

    it('should clear cache', async () => {
      // Add something to cache
      tlsModule._enrichmentCache.set('test.com:443', {
        response: { success: true },
        cachedAt: Date.now(),
      });

      await tlsModule.clearEnrichmentCache();

      expect(tlsModule._enrichmentCache.size).toBe(0);
    });
  });

  describe('clearAllTLSMetadata', () => {
    it('should clear all stored metadata', () => {
      // Add some data
      tlsModule._tlsMetadataByTab.set(1, {
        hostname: 'a.com',
        port: 443,
        connection: { isSecure: true, scheme: 'https', hasHSTS: false },
        capturedAt: Date.now(),
        certificateSource: 'unavailable',
      });
      tlsModule._tlsMetadataByTab.set(2, {
        hostname: 'b.com',
        port: 443,
        connection: { isSecure: true, scheme: 'https', hasHSTS: false },
        capturedAt: Date.now(),
        certificateSource: 'unavailable',
      });
      tlsModule._securityHeadersByTab.set(1, { xContentTypeOptions: 'nosniff' });

      tlsModule.clearAllTLSMetadata();

      expect(tlsModule._tlsMetadataByTab.size).toBe(0);
      expect(tlsModule._securityHeadersByTab.size).toBe(0);
    });
  });

  describe('setupTLSCleanup', () => {
    it('should register tab removal listener', () => {
      tlsModule.setupTLSCleanup();

      expect(mockChrome.tabs.onRemoved.addListener).toHaveBeenCalled();
    });
  });
});

describe('TLS Metadata Type Structure', () => {
  it('should have correct CertificateMetadata structure', () => {
    const cert: CertificateMetadata = {
      issuerCN: 'Test CA',
      issuerOrg: 'Test Org',
      issuerDN: 'CN=Test CA, O=Test Org',
      subjectCN: 'example.com',
      subjectOrg: 'Example Inc',
      subjectAltNames: ['example.com', '*.example.com'],
      fingerprintSHA256: 'a'.repeat(64),
      fingerprintSHA1: 'b'.repeat(40),
      serialNumber: '0123456789ABCDEF',
      validFrom: '2024-01-01T00:00:00Z',
      validUntil: '2025-01-01T00:00:00Z',
      daysUntilExpiry: 365,
      isExpired: false,
      publicKeyAlgorithm: 'RSA',
      publicKeySize: 2048,
      signatureAlgorithm: 'SHA256withRSA',
      isSelfSigned: false,
      chainLength: 3,
      isEV: false,
      isOV: true,
      isDV: false,
    };

    expect(cert.issuerCN).toBe('Test CA');
    expect(cert.subjectAltNames?.length).toBe(2);
    expect(cert.fingerprintSHA256?.length).toBe(64);
  });

  it('should have correct TLSConnectionMetadata structure', () => {
    const conn: TLSConnectionMetadata = {
      isSecure: true,
      scheme: 'https',
      protocolVersion: 'TLSv1.3',
      hasHSTS: true,
      hstsMaxAge: 31536000,
      hstsIncludeSubdomains: true,
      hstsPreload: true,
      httpVersion: 'HTTP/2',
    };

    expect(conn.isSecure).toBe(true);
    expect(conn.protocolVersion).toBe('TLSv1.3');
    expect(conn.httpVersion).toBe('HTTP/2');
  });
});
