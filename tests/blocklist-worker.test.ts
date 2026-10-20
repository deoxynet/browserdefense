import { describe, it, expect, beforeEach, vi } from 'vitest';
import blocklist from '../functions/blocklist';
import type { Env } from '../functions/blocklist';

// =============================================================================
// Test Fixtures
// =============================================================================

function createValidManifest(overrides: Partial<{
  version: number;
  timestamp: string;
  type: 'delta' | 'full';
  hashes: string[];
  removed: string[];
  signature: string;
}> = {}) {
  return {
    version: 1,
    timestamp: new Date().toISOString(),
    type: 'full' as const,
    hashes: [
      'a'.repeat(64),
      'b'.repeat(64),
    ],
    signature: 'valid-signature-string',
    ...overrides,
  };
}

function createMockR2Object(data: unknown, etag = 'test-etag'): R2ObjectBody {
  const jsonStr = JSON.stringify(data);
  return {
    key: 'test-key',
    version: 'v1',
    size: jsonStr.length,
    etag,
    httpEtag: `"${etag}"`,
    uploaded: new Date(),
    httpMetadata: {},
    customMetadata: {},
    checksums: {},
    writeHttpMetadata: vi.fn(),
    body: new ReadableStream(),
    bodyUsed: false,
    arrayBuffer: vi.fn().mockResolvedValue(new TextEncoder().encode(jsonStr).buffer),
    text: vi.fn().mockResolvedValue(jsonStr),
    json: vi.fn().mockResolvedValue(data),
    blob: vi.fn().mockResolvedValue(new Blob([jsonStr])),
  } as unknown as R2ObjectBody;
}

function createMockEnv(overrides: Partial<Env> = {}): Env {
  return {
    BLOCKLIST_BUCKET: {
      get: vi.fn(),
      put: vi.fn(),
      delete: vi.fn(),
      list: vi.fn(),
      head: vi.fn(),
    } as unknown as R2Bucket,
    UPLOAD_API_KEY: 'test-api-key',
    CORS_ORIGIN: '*',
    SUPABASE_URL: 'https://test.supabase.co',
    SUPABASE_SERVICE_ROLE_KEY: 'test-service-role-key',
    ...overrides,
  };
}

function createRequest(
  path: string,
  method = 'GET',
  body?: string,
  headers: Record<string, string> = {}
): Request {
  const url = `https://blocklist.example.com${path}`;
  const init: RequestInit = { method, headers };
  if (body) {
    init.body = body;
  }
  return new Request(url, init);
}

// =============================================================================
// Tests
// =============================================================================

describe('Blocklist Worker', () => {
  let mockEnv: Env;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEnv = createMockEnv();
    // Mock global fetch for Supabase calls
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(''),
    });
  });

  // ===========================================================================
  // CORS Handling
  // ===========================================================================

  describe('CORS Handling', () => {
    it('should return CORS headers on OPTIONS request', async () => {
      const request = createRequest('/blocklist/test-org', 'OPTIONS');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('GET');
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('PUT');
    });

    it('should use custom CORS_ORIGIN when set', async () => {
      mockEnv.CORS_ORIGIN = 'https://app.example.com';
      const request = createRequest('/blocklist/test-org', 'OPTIONS');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://app.example.com');
    });

    it('should include CORS headers in all responses', async () => {
      const request = createRequest('/health');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    });
  });

  // ===========================================================================
  // Health Check
  // ===========================================================================

  describe('Health Check', () => {
    it('should return health status on /health', async () => {
      const request = createRequest('/health');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      const body = await response.json() as { status: string; timestamp: string };
      expect(body.status).toBe('ok');
      expect(body.timestamp).toBeDefined();
    });
  });

  // ===========================================================================
  // GET /blocklist/{org_id}
  // ===========================================================================

  describe('GET /blocklist/{org_id}', () => {
    it('should return blocklist manifest for valid org', async () => {
      const manifest = createValidManifest();
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
        createMockR2Object(manifest)
      );

      const request = createRequest('/blocklist/test-org');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      const body = await response.json() as typeof manifest;
      expect(body.version).toBe(manifest.version);
      expect(body.hashes).toEqual(manifest.hashes);
    });

    it('should return 404 when blocklist not found', async () => {
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

      const request = createRequest('/blocklist/unknown-org');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(404);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('not found');
    });

    it('should include Cache-Control header', async () => {
      const manifest = createValidManifest();
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
        createMockR2Object(manifest)
      );

      const request = createRequest('/blocklist/test-org');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.headers.get('Cache-Control')).toContain('max-age=300');
    });

    it('should include ETag header', async () => {
      const manifest = createValidManifest();
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
        createMockR2Object(manifest, 'custom-etag')
      );

      const request = createRequest('/blocklist/test-org');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.headers.get('ETag')).toBe('custom-etag');
    });

    it('should handle org IDs with valid characters', async () => {
      const manifest = createValidManifest();
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
        createMockR2Object(manifest)
      );

      const request = createRequest('/blocklist/org-123_ABC');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(200);
    });
  });

  // ===========================================================================
  // PUT /blocklist/{org_id}
  // ===========================================================================

  describe('PUT /blocklist/{org_id}', () => {
    it('should reject request without API key', async () => {
      const request = createRequest('/blocklist/test-org', 'PUT', JSON.stringify(createValidManifest()));
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(401);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Unauthorized');
    });

    it('should reject request with invalid API key', async () => {
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(createValidManifest()),
        { 'X-API-Key': 'wrong-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(401);
    });

    it('should accept request with valid X-API-Key header', async () => {
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);
      (mockEnv.BLOCKLIST_BUCKET.put as ReturnType<typeof vi.fn>).mockResolvedValueOnce(undefined);

      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(createValidManifest()),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(201);
    });

    it('should accept request with Bearer token', async () => {
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);
      (mockEnv.BLOCKLIST_BUCKET.put as ReturnType<typeof vi.fn>).mockResolvedValueOnce(undefined);

      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(createValidManifest()),
        { 'Authorization': 'Bearer test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(201);
    });

    it('should reject invalid JSON body', async () => {
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        'not-valid-json',
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Invalid JSON');
    });

    it('should reject manifest with invalid version', async () => {
      const manifest = createValidManifest({ version: -1 });
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(manifest),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('version');
    });

    it('should reject manifest with invalid timestamp', async () => {
      const manifest = createValidManifest({ timestamp: 'not-a-date' });
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(manifest),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('timestamp');
    });

    it('should reject manifest with invalid type', async () => {
      const manifest = { ...createValidManifest(), type: 'invalid' };
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(manifest),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('type');
    });

    it('should reject manifest with invalid hash format', async () => {
      const manifest = createValidManifest({ hashes: ['invalid-hash', 'a'.repeat(64)] });
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(manifest),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('hash');
    });

    it('should reject manifest with empty signature', async () => {
      const manifest = createValidManifest({ signature: '' });
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(manifest),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('signature');
    });

    it('should reject version conflict (version not greater)', async () => {
      const existingManifest = createValidManifest({ version: 5 });
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
        createMockR2Object(existingManifest)
      );

      const newManifest = createValidManifest({ version: 3 });
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(newManifest),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(409);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Version conflict');
    });

    it('should store manifest in R2 bucket', async () => {
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);
      (mockEnv.BLOCKLIST_BUCKET.put as ReturnType<typeof vi.fn>).mockResolvedValueOnce(undefined);

      const manifest = createValidManifest();
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(manifest),
        { 'X-API-Key': 'test-api-key' }
      );
      await blocklist.fetch(request, mockEnv);

      expect(mockEnv.BLOCKLIST_BUCKET.put).toHaveBeenCalled();
    });

    it('should return success response with version info', async () => {
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);
      (mockEnv.BLOCKLIST_BUCKET.put as ReturnType<typeof vi.fn>).mockResolvedValueOnce(undefined);

      const manifest = createValidManifest({ version: 42 });
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(manifest),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(201);
      const body = await response.json() as { success: boolean; version: number; hashCount: number };
      expect(body.success).toBe(true);
      expect(body.version).toBe(42);
      expect(body.hashCount).toBe(manifest.hashes.length);
    });
  });

  // ===========================================================================
  // GET /blocklist/{org_id}/delta
  // ===========================================================================

  describe('GET /blocklist/{org_id}/delta', () => {
    it('should require since parameter', async () => {
      const request = createRequest('/blocklist/test-org/delta');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('since');
    });

    it('should reject invalid since parameter', async () => {
      const request = createRequest('/blocklist/test-org/delta?since=invalid');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Invalid version');
    });

    it('should reject negative since parameter', async () => {
      const request = createRequest('/blocklist/test-org/delta?since=-1');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(400);
    });

    it('should return 404 when blocklist not found', async () => {
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

      const request = createRequest('/blocklist/test-org/delta?since=1');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(404);
    });

    it('should return unchanged response when client is up to date', async () => {
      const manifest = createValidManifest({ version: 5 });
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
        createMockR2Object(manifest)
      );

      const request = createRequest('/blocklist/test-org/delta?since=5');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      const body = await response.json() as { unchanged: boolean; hashes: string[]; removed: string[] };
      expect(body.unchanged).toBe(true);
      expect(body.hashes).toEqual([]);
      expect(body.removed).toEqual([]);
    });

    it('should return full update when old version not available', async () => {
      const currentManifest = createValidManifest({ version: 5 });
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>)
        .mockResolvedValueOnce(createMockR2Object(currentManifest))  // current
        .mockResolvedValueOnce(null);  // old version not found

      const request = createRequest('/blocklist/test-org/delta?since=1');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      expect(response.headers.get('X-Delta-Fallback')).toBe('full');
    });

    it('should compute delta between versions', async () => {
      const oldManifest = createValidManifest({
        version: 1,
        hashes: ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)],
      });
      const currentManifest = createValidManifest({
        version: 2,
        hashes: ['a'.repeat(64), 'd'.repeat(64), 'e'.repeat(64)],
      });

      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>)
        .mockResolvedValueOnce(createMockR2Object(currentManifest))  // current
        .mockResolvedValueOnce(createMockR2Object(oldManifest));  // old version

      const request = createRequest('/blocklist/test-org/delta?since=1');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      const body = await response.json() as {
        version: number;
        type: string;
        hashes: string[];
        removed: string[];
      };

      expect(body.version).toBe(2);
      expect(body.type).toBe('delta');
      // Added: d, e (b, c removed; a unchanged)
      expect(body.hashes).toContain('d'.repeat(64));
      expect(body.hashes).toContain('e'.repeat(64));
      expect(body.hashes).not.toContain('a'.repeat(64));
      // Removed: b, c
      expect(body.removed).toContain('b'.repeat(64));
      expect(body.removed).toContain('c'.repeat(64));
    });

    it('should include shorter cache headers for deltas', async () => {
      const oldManifest = createValidManifest({ version: 1 });
      const currentManifest = createValidManifest({ version: 2 });

      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>)
        .mockResolvedValueOnce(createMockR2Object(currentManifest))
        .mockResolvedValueOnce(createMockR2Object(oldManifest));

      const request = createRequest('/blocklist/test-org/delta?since=1');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.headers.get('Cache-Control')).toContain('max-age=60');
    });
  });

  // ===========================================================================
  // 404 Not Found
  // ===========================================================================

  describe('404 Not Found', () => {
    it('should return 404 for unknown routes', async () => {
      const request = createRequest('/unknown/path');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(404);
      const body = await response.json() as { error: string };
      expect(body.error).toBe('Not found');
    });

    it('should return 404 for /blocklist without org_id', async () => {
      const request = createRequest('/blocklist');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(404);
    });

    it('should return 404 for /blocklist/ without org_id', async () => {
      const request = createRequest('/blocklist/');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(404);
    });
  });

  // ===========================================================================
  // Error Handling
  // ===========================================================================

  describe('Error Handling', () => {
    it('should return 500 on internal error', async () => {
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('R2 connection failed')
      );
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const request = createRequest('/blocklist/test-org');
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(500);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Internal server error');
      expect(consoleSpy).toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // Manifest Validation
  // ===========================================================================

  describe('Manifest Validation', () => {
    it('should accept manifest with removed array', async () => {
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);
      (mockEnv.BLOCKLIST_BUCKET.put as ReturnType<typeof vi.fn>).mockResolvedValueOnce(undefined);

      const manifest = createValidManifest({
        type: 'delta',
        removed: ['f'.repeat(64)],
      });
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(manifest),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(201);
    });

    it('should reject invalid removed hash format', async () => {
      const manifest = createValidManifest({
        type: 'delta',
        removed: ['invalid-removed-hash'],
      });
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(manifest),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('removed hash');
    });

    it('should accept uppercase hex hashes', async () => {
      (mockEnv.BLOCKLIST_BUCKET.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);
      (mockEnv.BLOCKLIST_BUCKET.put as ReturnType<typeof vi.fn>).mockResolvedValueOnce(undefined);

      const manifest = createValidManifest({
        hashes: ['A'.repeat(64), 'B'.repeat(64)],
      });
      const request = createRequest(
        '/blocklist/test-org',
        'PUT',
        JSON.stringify(manifest),
        { 'X-API-Key': 'test-api-key' }
      );
      const response = await blocklist.fetch(request, mockEnv);

      expect(response.status).toBe(201);
    });
  });
});
