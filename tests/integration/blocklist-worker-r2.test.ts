/**
 * Integration tests for BlockIOC Blocklist Worker R2 endpoints
 *
 * Issue #134: Tests the blocklist worker with real R2 bindings using wrangler's
 * unstable_dev API which handles TypeScript compilation automatically.
 *
 * Tests cover:
 * - PUT /blocklist/{org} stores manifest and updates index
 * - GET /blocklist/{org} returns manifest with ETag + cache headers
 * - Version conflict returns 409
 * - GET /blocklist/{org}/delta?since= returns delta or full fallback
 * - CORS preflight responds with expected headers
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

// Test manifest structure (matches functions/blocklist.ts)
interface BlocklistManifest {
  version: number;
  timestamp: string;
  type: 'delta' | 'full';
  hashes: string[];
  removed?: string[];
  signature: string;
}

// Helper to create a valid test manifest
function createTestManifest(
  version: number,
  hashes: string[] = [],
  type: 'delta' | 'full' = 'full'
): BlocklistManifest {
  return {
    version,
    timestamp: new Date().toISOString(),
    type,
    hashes,
    signature: 'test-signature-' + version,
  };
}

// Helper to generate a valid SHA-256 hash (64 hex chars)
function generateTestHash(seed: number): string {
  const hex = seed.toString(16).padStart(8, '0');
  return hex.repeat(8);
}

describe('Blocklist Worker R2 Integration', () => {
  let worker: Unstable_DevWorker;
  const TEST_API_KEY = 'test-api-key-12345';
  const TEST_CORS_ORIGIN = 'https://example.com';
  const TEST_ORG_ID = 'test-org';

  // Track uploaded orgs for cleanup
  let uploadedOrgs: string[] = [];

  beforeAll(async () => {
    // Start the worker using wrangler's unstable_dev which handles TS compilation
    worker = await unstable_dev('functions/blocklist.ts', {
      experimental: { disableExperimentalWarning: true },
      local: true,
      persist: false, // Don't persist R2 data between tests
      vars: {
        UPLOAD_API_KEY: TEST_API_KEY,
        CORS_ORIGIN: TEST_CORS_ORIGIN,
      },
      r2: [{ binding: 'BLOCKLIST_BUCKET', bucket_name: 'blockioc-blocklists-test' }],
    });
  }, 60000); // Increase timeout for worker startup

  afterAll(async () => {
    await worker?.stop();
  });

  beforeEach(() => {
    // Reset tracking
    uploadedOrgs = [];
  });

  // Helper to make requests to the worker
   
  async function fetch(path: string, init?: RequestInit): Promise<any> {
    return worker.fetch(path, init as any);
  }

  describe('CORS Preflight', () => {
    it('should respond to OPTIONS with CORS headers', async () => {
      const response = await fetch(`/blocklist/${TEST_ORG_ID}`, {
        method: 'OPTIONS',
      });

      expect(response.status).toBe(200);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe(TEST_CORS_ORIGIN);
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('GET');
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('PUT');
      expect(response.headers.get('Access-Control-Allow-Headers')).toContain('X-API-Key');
    });
  });

  describe('PUT /blocklist/{org}', () => {
    it('should store manifest with API key authentication', async () => {
      const orgId = `put-test-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1), generateTestHash(2)]);

      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': TEST_API_KEY,
        },
        body: JSON.stringify(manifest),
      });

      expect(response.status).toBe(201);

      const body = (await response.json()) as { success: boolean; version: number; hashCount: number };
      expect(body.success).toBe(true);
      expect(body.version).toBe(1);
      expect(body.hashCount).toBe(2);
    });

    it('should accept Bearer token authentication', async () => {
      const orgId = `bearer-test-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);

      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${TEST_API_KEY}`,
        },
        body: JSON.stringify(manifest),
      });

      expect(response.status).toBe(201);
    });

    it('should reject request without API key', async () => {
      const manifest = createTestManifest(1);

      const response = await fetch(`/blocklist/${TEST_ORG_ID}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(manifest),
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain('Unauthorized');
    });

    it('should reject invalid API key', async () => {
      const manifest = createTestManifest(1);

      const response = await fetch(`/blocklist/${TEST_ORG_ID}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'wrong-key',
        },
        body: JSON.stringify(manifest),
      });

      expect(response.status).toBe(401);
    });

    it('should update versions index on upload', async () => {
      const orgId = `index-test-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);

      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': TEST_API_KEY,
        },
        body: JSON.stringify(manifest),
      });

      // Verify by fetching the manifest back
      const getResponse = await fetch(`/blocklist/${orgId}`, { method: 'GET' });
      expect(getResponse.status).toBe(200);

      const body = (await getResponse.json()) as BlocklistManifest;
      expect(body.version).toBe(1);
      expect(body.hashes.length).toBe(1);
    });

    it('should archive previous version on new upload', async () => {
      const orgId = `archive-test-${Date.now()}`;
      uploadedOrgs.push(orgId);

      // Upload version 1
      const manifest1 = createTestManifest(1, [generateTestHash(1)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest1),
      });

      // Upload version 2
      const manifest2 = createTestManifest(2, [generateTestHash(1), generateTestHash(2)]);
      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest2),
      });

      expect(response.status).toBe(201);

      // Verify current manifest is version 2
      const getResponse = await fetch(`/blocklist/${orgId}`, { method: 'GET' });
      const body = (await getResponse.json()) as BlocklistManifest;
      expect(body.version).toBe(2);
    });

    describe('Validation', () => {
      it('should reject invalid JSON body', async () => {
        const response = await fetch(`/blocklist/${TEST_ORG_ID}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Key': TEST_API_KEY,
          },
          body: 'not json',
        });

        expect(response.status).toBe(400);
        const body = (await response.json()) as { error: string };
        expect(body.error).toContain('Invalid JSON');
      });

      it('should reject manifest with missing version', async () => {
        const response = await fetch(`/blocklist/${TEST_ORG_ID}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Key': TEST_API_KEY,
          },
          body: JSON.stringify({
            timestamp: new Date().toISOString(),
            type: 'full',
            hashes: [],
            signature: 'test',
          }),
        });

        expect(response.status).toBe(400);
      });

      it('should reject manifest with invalid hash format', async () => {
        const response = await fetch(`/blocklist/${TEST_ORG_ID}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Key': TEST_API_KEY,
          },
          body: JSON.stringify({
            version: 1,
            timestamp: new Date().toISOString(),
            type: 'full',
            hashes: ['invalid-hash'],
            signature: 'test',
          }),
        });

        expect(response.status).toBe(400);
        const body = (await response.json()) as { error: string };
        expect(body.error).toContain('Invalid hash');
      });

      it('should reject manifest with empty signature', async () => {
        const response = await fetch(`/blocklist/${TEST_ORG_ID}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Key': TEST_API_KEY,
          },
          body: JSON.stringify({
            version: 1,
            timestamp: new Date().toISOString(),
            type: 'full',
            hashes: [],
            signature: '',
          }),
        });

        expect(response.status).toBe(400);
        const body = (await response.json()) as { error: string };
        expect(body.error).toContain('signature');
      });
    });
  });

  describe('Version Conflict (409)', () => {
    it('should return 409 when uploading same version', async () => {
      const orgId = `conflict-same-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);

      // First upload
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      // Second upload with same version
      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      expect(response.status).toBe(409);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain('Version conflict');
    });

    it('should return 409 when uploading older version', async () => {
      const orgId = `conflict-older-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest2 = createTestManifest(2, [generateTestHash(1)]);
      const manifest1 = createTestManifest(1, [generateTestHash(1)]);

      // Upload version 2
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest2),
      });

      // Try to upload version 1
      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest1),
      });

      expect(response.status).toBe(409);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain('must be greater');
    });

    it('should accept newer version', async () => {
      const orgId = `conflict-newer-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest1 = createTestManifest(1, [generateTestHash(1)]);
      const manifest2 = createTestManifest(2, [generateTestHash(2)]);

      // Upload version 1
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest1),
      });

      // Upload version 2
      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest2),
      });

      expect(response.status).toBe(201);
    });
  });

  describe('GET /blocklist/{org}', () => {
    it('should return manifest with ETag header', async () => {
      const orgId = `get-etag-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);

      // Upload manifest
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      // Fetch manifest
      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'GET',
      });

      expect(response.status).toBe(200);
      expect(response.headers.get('ETag')).toBeTruthy();
      expect(response.headers.get('Content-Type')).toBe('application/json');
    });

    it('should return manifest with cache headers', async () => {
      const orgId = `get-cache-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);

      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'GET',
      });

      expect(response.headers.get('Cache-Control')).toContain('max-age');
    });

    it('should return 404 for non-existent org', async () => {
      const response = await fetch('/blocklist/non-existent-org-xyz', {
        method: 'GET',
      });

      expect(response.status).toBe(404);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain('not found');
    });

    it('should return correct manifest data', async () => {
      const orgId = `get-data-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const hashes = [generateTestHash(1), generateTestHash(2), generateTestHash(3)];
      const manifest = createTestManifest(5, hashes);

      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'GET',
      });

      const body = (await response.json()) as BlocklistManifest;
      expect(body.version).toBe(5);
      expect(body.hashes).toEqual(hashes);
      expect(body.type).toBe('full');
    });

    it('should include CORS headers in response', async () => {
      const orgId = `get-cors-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);

      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'GET',
      });

      expect(response.headers.get('Access-Control-Allow-Origin')).toBe(TEST_CORS_ORIGIN);
    });
  });

  describe('GET /blocklist/{org}/delta', () => {
    it('should return delta with added and removed hashes', async () => {
      const orgId = `delta-changes-${Date.now()}`;
      uploadedOrgs.push(orgId);

      // Upload version 1 with hashes 1, 2, 3
      const manifest1 = createTestManifest(1, [generateTestHash(1), generateTestHash(2), generateTestHash(3)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest1),
      });

      // Upload version 2 with hashes 2, 3, 4 (1 removed, 4 added)
      const manifest2 = createTestManifest(2, [generateTestHash(2), generateTestHash(3), generateTestHash(4)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest2),
      });

      // Request delta from version 1
      const response = await fetch(`/blocklist/${orgId}/delta?since=1`, {
        method: 'GET',
      });

      expect(response.status).toBe(200);
      const body = (await response.json()) as BlocklistManifest & { unchanged?: boolean };
      expect(body.version).toBe(2);
      expect(body.type).toBe('delta');
      expect(body.hashes).toContain(generateTestHash(4)); // Added
      expect(body.removed).toContain(generateTestHash(1)); // Removed
    });

    it('should return full update when old version not archived', async () => {
      const orgId = `delta-fallback-${Date.now()}`;
      uploadedOrgs.push(orgId);

      // Upload only version 5 (no version 1 archived)
      const manifest5 = createTestManifest(5, [generateTestHash(1), generateTestHash(2)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest5),
      });

      // Request delta from non-existent version 1
      const response = await fetch(`/blocklist/${orgId}/delta?since=1`, {
        method: 'GET',
      });

      expect(response.status).toBe(200);
      expect(response.headers.get('X-Delta-Fallback')).toBe('full');

      const body = (await response.json()) as BlocklistManifest;
      expect(body.version).toBe(5);
      expect(body.type).toBe('full');
    });

    it('should return unchanged when client is up to date', async () => {
      const orgId = `delta-uptodate-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(3, [generateTestHash(1)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      // Request delta from same version
      const response = await fetch(`/blocklist/${orgId}/delta?since=3`, {
        method: 'GET',
      });

      expect(response.status).toBe(200);
      const body = (await response.json()) as BlocklistManifest & { unchanged?: boolean };
      expect(body.unchanged).toBe(true);
      expect(body.hashes).toEqual([]);
      expect(body.removed).toEqual([]);
    });

    it('should return unchanged when client has newer version', async () => {
      const orgId = `delta-newer-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(3, [generateTestHash(1)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      // Request delta from future version
      const response = await fetch(`/blocklist/${orgId}/delta?since=10`, {
        method: 'GET',
      });

      expect(response.status).toBe(200);
      const body = (await response.json()) as BlocklistManifest & { unchanged?: boolean };
      expect(body.unchanged).toBe(true);
    });

    it('should return 400 for missing since parameter', async () => {
      const orgId = `delta-missing-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      const response = await fetch(`/blocklist/${orgId}/delta`, {
        method: 'GET',
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain('since');
    });

    it('should return 400 for invalid since parameter', async () => {
      const orgId = `delta-invalid-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      const response = await fetch(`/blocklist/${orgId}/delta?since=abc`, {
        method: 'GET',
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain('Invalid version');
    });

    it('should return 400 for negative since parameter', async () => {
      const orgId = `delta-negative-${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      const response = await fetch(`/blocklist/${orgId}/delta?since=-1`, {
        method: 'GET',
      });

      expect(response.status).toBe(400);
    });

    it('should return 404 for non-existent org', async () => {
      const response = await fetch('/blocklist/non-existent-org-xyz/delta?since=1', {
        method: 'GET',
      });

      expect(response.status).toBe(404);
    });

    it('should include shorter cache header for deltas', async () => {
      const orgId = `delta-cache-${Date.now()}`;
      uploadedOrgs.push(orgId);

      // Upload versions 1 and 2
      const manifest1 = createTestManifest(1, [generateTestHash(1)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest1),
      });

      const manifest2 = createTestManifest(2, [generateTestHash(2)]);
      await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest2),
      });

      const response = await fetch(`/blocklist/${orgId}/delta?since=1`, {
        method: 'GET',
      });

      const cacheControl = response.headers.get('Cache-Control');
      expect(cacheControl).toContain('max-age=60'); // Shorter than full manifest
    });
  });

  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const response = await fetch('/health', {
        method: 'GET',
      });

      expect(response.status).toBe(200);
      const body = (await response.json()) as { status: string; timestamp: string };
      expect(body.status).toBe('ok');
      expect(body.timestamp).toBeTruthy();
    });
  });

  describe('Error Handling', () => {
    it('should return 404 for unknown routes', async () => {
      const response = await fetch('/unknown/path', {
        method: 'GET',
      });

      expect(response.status).toBe(404);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain('Not found');
    });

    it('should include CORS headers in error responses', async () => {
      const response = await fetch('/blocklist/non-existent-org-xyz', {
        method: 'GET',
      });

      expect(response.status).toBe(404);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe(TEST_CORS_ORIGIN);
    });
  });

  describe('Version Index Cleanup', () => {
    it('should limit versions index to 10 entries', async () => {
      const orgId = `cleanup-${Date.now()}`;
      uploadedOrgs.push(orgId);

      // Upload 12 versions
      for (let v = 1; v <= 12; v++) {
        const manifest = createTestManifest(v, [generateTestHash(v)]);
        await fetch(`/blocklist/${orgId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
          body: JSON.stringify(manifest),
        });
      }

      // The index is internal to R2, but we can verify delta requests
      // for old versions fall back to full (because version 1 was cleaned up)
      const response = await fetch(`/blocklist/${orgId}/delta?since=1`, {
        method: 'GET',
      });

      expect(response.status).toBe(200);
      // Version 1 should be deleted, so it falls back to full
      expect(response.headers.get('X-Delta-Fallback')).toBe('full');
    });
  });

  describe('Org ID Validation', () => {
    it('should accept alphanumeric org IDs', async () => {
      const orgId = `abc123${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);

      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      expect(response.status).toBe(201);
    });

    it('should accept org IDs with hyphens and underscores', async () => {
      const orgId = `my-org_${Date.now()}`;
      uploadedOrgs.push(orgId);
      const manifest = createTestManifest(1, [generateTestHash(1)]);

      const response = await fetch(`/blocklist/${orgId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      expect(response.status).toBe(201);
    });

    it('should reject org IDs with invalid characters', async () => {
      const manifest = createTestManifest(1, [generateTestHash(1)]);

      const response = await fetch('/blocklist/org@123', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': TEST_API_KEY },
        body: JSON.stringify(manifest),
      });

      // Route won't match, so 404
      expect(response.status).toBe(404);
    });
  });
});
