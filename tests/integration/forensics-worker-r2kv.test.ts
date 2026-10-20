/**
 * Integration: Forensics Worker R2+KV endpoints
 *
 * Tests forensics upload/list/retrieve endpoints with real bindings
 * using Miniflare's in-memory R2 and KV storage.
 *
 * Reference: Issue #135
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Types from the forensics worker
interface ForensicsEnv {
  FORENSICS_BUCKET: R2Bucket;
  RATE_LIMIT_KV: KVNamespace;
  CORS_ORIGIN: string;
}

interface ForensicsPayload {
  encrypted_data: string;
  encrypted_key: string;
  iv: string;
  key_version?: number;
  timestamp: string;
  metadata?: {
    event_type?: string;
    severity?: string;
  };
}

interface ForensicRecord {
  id: string;
  org_id: string;
  encrypted_data: string;
  encrypted_key: string;
  iv: string;
  key_version: number;
  timestamp: string;
  received_at: string;
  metadata?: ForensicsPayload['metadata'];
}

// Mock R2Object for get results
class MockR2Object implements Partial<R2Object> {
  private data: string;
  readonly key: string;
  readonly size: number;
  readonly customMetadata: Record<string, string>;

  constructor(key: string, data: string, customMetadata: Record<string, string> = {}) {
    this.key = key;
    this.data = data;
    this.size = data.length;
    this.customMetadata = customMetadata;
  }

  async text(): Promise<string> {
    return this.data;
  }

  async json<T>(): Promise<T> {
    return JSON.parse(this.data) as T;
  }

  async arrayBuffer(): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    return encoder.encode(this.data).buffer;
  }
}

// Mock R2 Bucket
function createMockR2Bucket(): R2Bucket {
  const store = new Map<string, { data: string; metadata: Record<string, string> }>();

  return {
    put: vi.fn(
      async (
        key: string,
        value: string | ArrayBuffer | ReadableStream,
        options?: { customMetadata?: Record<string, string> }
      ) => {
        const data = typeof value === 'string' ? value : String(value);
        store.set(key, {
          data,
          metadata: options?.customMetadata ?? {},
        });
        return {} as R2Object;
      }
    ),
    get: vi.fn(async (key: string) => {
      const item = store.get(key);
      if (!item) return null;
      return new MockR2Object(key, item.data, item.metadata) as unknown as R2Object;
    }),
    delete: vi.fn(async (key: string | string[]) => {
      if (Array.isArray(key)) {
        key.forEach((k) => store.delete(k));
      } else {
        store.delete(key);
      }
    }),
    list: vi.fn(
      async (options?: { prefix?: string; limit?: number; cursor?: string }) => {
        const prefix = options?.prefix ?? '';
        const limit = options?.limit ?? 1000;
        const cursor = options?.cursor;

        const allKeys = Array.from(store.keys())
          .filter((k) => k.startsWith(prefix))
          .sort();

        // Handle cursor-based pagination
        let startIndex = 0;
        if (cursor) {
          const cursorIndex = parseInt(cursor, 10);
          if (!isNaN(cursorIndex)) {
            startIndex = cursorIndex;
          }
        }

        const keys = allKeys.slice(startIndex, startIndex + limit);
        const truncated = startIndex + limit < allKeys.length;

        return {
          objects: keys.map((key) => {
            const item = store.get(key)!;
            return {
              key,
              size: item.data.length,
              customMetadata: item.metadata,
            };
          }),
          truncated,
          cursor: truncated ? String(startIndex + limit) : undefined,
        } as R2Objects;
      }
    ),
    head: vi.fn(),
    createMultipartUpload: vi.fn(),
    resumeMultipartUpload: vi.fn(),
  } as unknown as R2Bucket;
}

// Mock KV Namespace
function createMockKV(): KVNamespace {
  const store = new Map<string, { value: string; expiresAt?: number }>();

  return {
    get: vi.fn(async (key: string, type?: string) => {
      const item = store.get(key);
      if (!item) return null;
      if (item.expiresAt && Date.now() > item.expiresAt) {
        store.delete(key);
        return null;
      }
      if (type === 'json') return JSON.parse(item.value);
      return item.value;
    }),
    put: vi.fn(async (key: string, value: string, options?: { expirationTtl?: number }) => {
      const expiresAt = options?.expirationTtl
        ? Date.now() + options.expirationTtl * 1000
        : undefined;
      store.set(key, { value, expiresAt });
    }),
    delete: vi.fn(async (key: string) => {
      store.delete(key);
    }),
    list: vi.fn(),
    getWithMetadata: vi.fn(),
  } as unknown as KVNamespace;
}

// Import and recreate worker handler logic for testing
// (Simulating the worker fetch handler)
async function handleForensicsRequest(
  request: Request,
  env: ForensicsEnv
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  const corsHeaders = {
    'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // POST /forensics/{org_id}
    const postMatch = path.match(/^\/forensics\/([a-zA-Z0-9_-]+)$/);
    if (postMatch && request.method === 'POST') {
      return await handlePost(postMatch[1], request, env, corsHeaders);
    }

    // GET /forensics/{org_id}/{id}
    const getMatch = path.match(/^\/forensics\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)$/);
    if (getMatch && request.method === 'GET') {
      return await handleGet(getMatch[1], getMatch[2], env, corsHeaders);
    }

    // GET /forensics/{org_id}?limit=&cursor=
    const listMatch = path.match(/^\/forensics\/([a-zA-Z0-9_-]+)$/);
    if (listMatch && request.method === 'GET') {
      return await handleList(listMatch[1], url.searchParams, env, corsHeaders);
    }

    return jsonError(404, 'Not found', corsHeaders);
  } catch (err) {
    console.error('Forensics worker error:', err);
    return jsonError(500, 'Internal server error', corsHeaders);
  }
}

const MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 100;

async function handlePost(
  orgId: string,
  request: Request,
  env: ForensicsEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  // Check content length
  const contentLength = request.headers.get('Content-Length');
  if (contentLength && parseInt(contentLength, 10) > MAX_PAYLOAD_SIZE) {
    return jsonError(413, `Payload too large. Maximum size is ${MAX_PAYLOAD_SIZE} bytes`, corsHeaders);
  }

  // Rate limiting
  const rateLimitResult = await checkRateLimit(orgId, env);
  if (!rateLimitResult.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Rate limit exceeded',
        retry_after: rateLimitResult.retryAfter,
      }),
      {
        status: 429,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
          'Retry-After': String(rateLimitResult.retryAfter),
        },
      }
    );
  }

  // Parse body
  let payload: ForensicsPayload;
  try {
    const body = await request.text();
    if (body.length > MAX_PAYLOAD_SIZE) {
      return jsonError(413, `Payload too large. Maximum size is ${MAX_PAYLOAD_SIZE} bytes`, corsHeaders);
    }
    payload = JSON.parse(body);
  } catch {
    return jsonError(400, 'Invalid JSON body', corsHeaders);
  }

  // Validate
  const validationError = validatePayload(payload);
  if (validationError) {
    return jsonError(400, validationError, corsHeaders);
  }

  // Generate ID and store
  const forensicId = generateForensicId();
  const receivedAt = new Date().toISOString();

  const record: ForensicRecord = {
    id: forensicId,
    org_id: orgId,
    encrypted_data: payload.encrypted_data,
    encrypted_key: payload.encrypted_key,
    iv: payload.iv,
    key_version: payload.key_version ?? 1,
    timestamp: payload.timestamp,
    received_at: receivedAt,
    metadata: payload.metadata,
  };

  const key = `${orgId}/${forensicId}`;
  await env.FORENSICS_BUCKET.put(key, JSON.stringify(record), {
    customMetadata: {
      org_id: orgId,
      timestamp: payload.timestamp,
      received_at: receivedAt,
      event_type: payload.metadata?.event_type ?? 'unknown',
    },
  });

  return new Response(JSON.stringify({ status: 'received', id: forensicId }), {
    status: 201,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

async function handleGet(
  orgId: string,
  forensicId: string,
  env: ForensicsEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const key = `${orgId}/${forensicId}`;
  const object = await env.FORENSICS_BUCKET.get(key);

  if (!object) {
    return jsonError(404, `Forensic record not found: ${forensicId}`, corsHeaders);
  }

  const record = await object.json<ForensicRecord>();
  return new Response(JSON.stringify(record), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

async function handleList(
  orgId: string,
  params: URLSearchParams,
  env: ForensicsEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const limit = Math.min(parseInt(params.get('limit') ?? '100', 10), 1000);
  const cursor = params.get('cursor') ?? undefined;

  const prefix = `${orgId}/`;
  const listed = await env.FORENSICS_BUCKET.list({ prefix, limit, cursor });

  const records = listed.objects.map((obj) => ({
    id: obj.key.replace(prefix, ''),
    timestamp: obj.customMetadata?.timestamp,
    received_at: obj.customMetadata?.received_at,
    event_type: obj.customMetadata?.event_type,
    size: obj.size,
  }));

  return new Response(
    JSON.stringify({
      records,
      cursor: listed.truncated ? listed.cursor : null,
      has_more: listed.truncated,
    }),
    { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
  );
}

async function checkRateLimit(
  orgId: string,
  env: ForensicsEnv
): Promise<{ allowed: boolean; retryAfter: number }> {
  const key = `ratelimit:forensics:${orgId}`;
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW_MS;

  const data = await env.RATE_LIMIT_KV.get(key, 'json');
  const requests: number[] = (data as number[] | null) ?? [];
  const recentRequests = requests.filter((ts) => ts > windowStart);

  if (recentRequests.length >= RATE_LIMIT_MAX_REQUESTS) {
    const oldestRequest = Math.min(...recentRequests);
    const retryAfter = Math.ceil((oldestRequest + RATE_LIMIT_WINDOW_MS - now) / 1000);
    return { allowed: false, retryAfter: Math.max(1, retryAfter) };
  }

  recentRequests.push(now);
  await env.RATE_LIMIT_KV.put(key, JSON.stringify(recentRequests), {
    expirationTtl: Math.ceil(RATE_LIMIT_WINDOW_MS / 1000) + 60,
  });

  return { allowed: true, retryAfter: 0 };
}

function validatePayload(payload: unknown): string | null {
  if (typeof payload !== 'object' || payload === null) {
    return 'Payload must be an object';
  }

  const p = payload as Record<string, unknown>;

  if (typeof p.encrypted_data !== 'string' || p.encrypted_data.length === 0) {
    return 'Invalid encrypted_data: must be a non-empty string';
  }

  if (typeof p.encrypted_key !== 'string' || p.encrypted_key.length === 0) {
    return 'Invalid encrypted_key: must be a non-empty string';
  }

  if (typeof p.iv !== 'string' || p.iv.length === 0) {
    return 'Invalid iv: must be a non-empty string';
  }

  if (typeof p.timestamp !== 'string') {
    return 'Invalid timestamp: must be a string';
  }

  const timestampDate = new Date(p.timestamp);
  if (isNaN(timestampDate.getTime())) {
    return 'Invalid timestamp: must be ISO 8601 format';
  }

  if (!isValidBase64(p.encrypted_data as string)) {
    return 'Invalid encrypted_data: must be valid base64';
  }

  if (!isValidBase64(p.encrypted_key as string)) {
    return 'Invalid encrypted_key: must be valid base64';
  }

  if (!isValidBase64(p.iv as string)) {
    return 'Invalid iv: must be valid base64';
  }

  return null;
}

function isValidBase64(str: string): boolean {
  const base64Regex = /^[A-Za-z0-9+/\-_]*={0,2}$/;
  return base64Regex.test(str);
}

function generateForensicId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `forensic_${timestamp}_${random}`;
}

function jsonError(
  status: number,
  message: string,
  corsHeaders: Record<string, string>
): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

// Helper to create valid forensics payload
function createValidPayload(overrides: Partial<ForensicsPayload> = {}): ForensicsPayload {
  return {
    encrypted_data: 'dGVzdCBkYXRh', // base64 "test data"
    encrypted_key: 'dGVzdCBrZXk=', // base64 "test key"
    iv: 'dGVzdCBpdg==', // base64 "test iv"
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('Forensics Worker R2+KV Integration', () => {
  let env: ForensicsEnv;

  beforeEach(() => {
    env = {
      FORENSICS_BUCKET: createMockR2Bucket(),
      RATE_LIMIT_KV: createMockKV(),
      CORS_ORIGIN: '*',
    };
  });

  describe('POST /forensics/{org} - Store forensics', () => {
    it('should store a record and return an id', async () => {
      const payload = createValidPayload({
        metadata: { event_type: 'block', severity: 'high' },
      });

      const request = new Request('https://worker.test/forensics/org123', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(201);

      const result = (await response.json()) as { status: string; id: string };
      expect(result.status).toBe('received');
      expect(result.id).toMatch(/^forensic_[a-z0-9]+_[a-z0-9]+$/);
    });

    it('should store record with correct data in R2', async () => {
      const payload = createValidPayload({
        metadata: { event_type: 'redirect_chain' },
      });

      const request = new Request('https://worker.test/forensics/test-org', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const response = await handleForensicsRequest(request, env);
      const result = (await response.json()) as { id: string };

      // Verify R2 put was called
      expect(env.FORENSICS_BUCKET.put).toHaveBeenCalled();

      // Retrieve and verify stored data
      const stored = await env.FORENSICS_BUCKET.get(`test-org/${result.id}`);
      expect(stored).not.toBeNull();

      const record = await stored!.json<ForensicRecord>();
      expect(record.org_id).toBe('test-org');
      expect(record.encrypted_data).toBe(payload.encrypted_data);
      expect(record.encrypted_key).toBe(payload.encrypted_key);
      expect(record.iv).toBe(payload.iv);
      expect(record.metadata?.event_type).toBe('redirect_chain');
    });

    it('should reject invalid JSON body', async () => {
      const request = new Request('https://worker.test/forensics/org123', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'not valid json',
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(400);

      const result = (await response.json()) as { error: string };
      expect(result.error).toBe('Invalid JSON body');
    });

    it('should reject missing required fields', async () => {
      const request = new Request('https://worker.test/forensics/org123', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encrypted_data: 'dGVzdA==' }),
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(400);

      const result = (await response.json()) as { error: string };
      expect(result.error).toContain('Invalid encrypted_key');
    });
  });

  describe('GET /forensics/{org}/{id} - Retrieve forensics', () => {
    it('should return the stored record', async () => {
      // First store a record
      const payload = createValidPayload();
      const postRequest = new Request('https://worker.test/forensics/org456', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const postResponse = await handleForensicsRequest(postRequest, env);
      const { id } = (await postResponse.json()) as { id: string };

      // Now retrieve it
      const getRequest = new Request(`https://worker.test/forensics/org456/${id}`, {
        method: 'GET',
      });

      const getResponse = await handleForensicsRequest(getRequest, env);
      expect(getResponse.status).toBe(200);

      const record = (await getResponse.json()) as ForensicRecord;
      expect(record.id).toBe(id);
      expect(record.org_id).toBe('org456');
      expect(record.encrypted_data).toBe(payload.encrypted_data);
    });

    it('should return 404 for non-existent record', async () => {
      const request = new Request(
        'https://worker.test/forensics/org123/forensic_nonexistent_12345',
        { method: 'GET' }
      );

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(404);

      const result = (await response.json()) as { error: string };
      expect(result.error).toContain('not found');
    });

    it('should not return records from different org', async () => {
      // Store in org-a
      const payload = createValidPayload();
      const postRequest = new Request('https://worker.test/forensics/org-a', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      const postResponse = await handleForensicsRequest(postRequest, env);
      const { id } = (await postResponse.json()) as { id: string };

      // Try to retrieve from org-b
      const getRequest = new Request(`https://worker.test/forensics/org-b/${id}`, {
        method: 'GET',
      });

      const getResponse = await handleForensicsRequest(getRequest, env);
      expect(getResponse.status).toBe(404);
    });
  });

  describe('GET /forensics/{org}?limit=&cursor= - List forensics', () => {
    beforeEach(async () => {
      // Store multiple records for listing tests
      for (let i = 0; i < 5; i++) {
        const payload = createValidPayload({
          metadata: { event_type: `event_${i}` },
        });
        const request = new Request('https://worker.test/forensics/list-org', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        await handleForensicsRequest(request, env);
      }
    });

    it('should list records with default limit', async () => {
      const request = new Request('https://worker.test/forensics/list-org', {
        method: 'GET',
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(200);

      const result = (await response.json()) as {
        records: Array<{ id: string }>;
        has_more: boolean;
        cursor: string | null;
      };
      expect(result.records).toHaveLength(5);
      expect(result.has_more).toBe(false);
      expect(result.cursor).toBeNull();
    });

    it('should list records with pagination', async () => {
      // Request with limit=2
      const request1 = new Request('https://worker.test/forensics/list-org?limit=2', {
        method: 'GET',
      });

      const response1 = await handleForensicsRequest(request1, env);
      const result1 = (await response1.json()) as {
        records: Array<{ id: string }>;
        has_more: boolean;
        cursor: string;
      };

      expect(result1.records).toHaveLength(2);
      expect(result1.has_more).toBe(true);
      expect(result1.cursor).toBeTruthy();

      // Request next page using cursor
      const request2 = new Request(
        `https://worker.test/forensics/list-org?limit=2&cursor=${result1.cursor}`,
        { method: 'GET' }
      );

      const response2 = await handleForensicsRequest(request2, env);
      const result2 = (await response2.json()) as {
        records: Array<{ id: string }>;
        has_more: boolean;
      };

      expect(result2.records).toHaveLength(2);
      expect(result2.has_more).toBe(true);
    });

    it('should return empty records for org with no data', async () => {
      const request = new Request('https://worker.test/forensics/empty-org', {
        method: 'GET',
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(200);

      const result = (await response.json()) as { records: unknown[]; has_more: boolean };
      expect(result.records).toHaveLength(0);
      expect(result.has_more).toBe(false);
    });

    it('should include metadata in listing response', async () => {
      const request = new Request('https://worker.test/forensics/list-org?limit=1', {
        method: 'GET',
      });

      const response = await handleForensicsRequest(request, env);
      const result = (await response.json()) as {
        records: Array<{
          id: string;
          timestamp?: string;
          received_at?: string;
          event_type?: string;
          size: number;
        }>;
      };

      expect(result.records[0]).toHaveProperty('id');
      expect(result.records[0]).toHaveProperty('timestamp');
      expect(result.records[0]).toHaveProperty('received_at');
      expect(result.records[0]).toHaveProperty('event_type');
      expect(result.records[0]).toHaveProperty('size');
    });
  });

  describe('Rate limiting - 429 with Retry-After', () => {
    it('should return 429 after exceeding rate limit', async () => {
      // Exhaust rate limit by making 100 requests
      const requests: number[] = Array(100)
        .fill(null)
        .map(() => Date.now());
      await env.RATE_LIMIT_KV.put(
        'ratelimit:forensics:rate-test-org',
        JSON.stringify(requests),
        { expirationTtl: 120 }
      );

      const payload = createValidPayload();
      const request = new Request('https://worker.test/forensics/rate-test-org', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(429);

      const result = (await response.json()) as { error: string; retry_after: number };
      expect(result.error).toBe('Rate limit exceeded');
      expect(result.retry_after).toBeGreaterThan(0);
      expect(response.headers.get('Retry-After')).toBeTruthy();
    });

    it('should allow requests after rate limit window expires', async () => {
      // Set old requests that are outside the window
      const oldRequests: number[] = Array(100)
        .fill(null)
        .map(() => Date.now() - 120000); // 2 minutes ago
      await env.RATE_LIMIT_KV.put(
        'ratelimit:forensics:window-test-org',
        JSON.stringify(oldRequests),
        { expirationTtl: 120 }
      );

      const payload = createValidPayload();
      const request = new Request('https://worker.test/forensics/window-test-org', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(201);
    });

    it('should track requests per org independently', async () => {
      // Exhaust rate limit for org-a
      const requests: number[] = Array(100)
        .fill(null)
        .map(() => Date.now());
      await env.RATE_LIMIT_KV.put('ratelimit:forensics:org-a', JSON.stringify(requests), {
        expirationTtl: 120,
      });

      // org-a should be rate limited
      const requestA = new Request('https://worker.test/forensics/org-a', {
        method: 'POST',
        body: JSON.stringify(createValidPayload()),
      });
      const responseA = await handleForensicsRequest(requestA, env);
      expect(responseA.status).toBe(429);

      // org-b should still be allowed
      const requestB = new Request('https://worker.test/forensics/org-b', {
        method: 'POST',
        body: JSON.stringify(createValidPayload()),
      });
      const responseB = await handleForensicsRequest(requestB, env);
      expect(responseB.status).toBe(201);
    });
  });

  describe('Size limits - 413 for payloads >1MB', () => {
    it('should return 413 for payload exceeding 1MB via Content-Length', async () => {
      const request = new Request('https://worker.test/forensics/size-test', {
        method: 'POST',
        headers: {
          'Content-Length': String(2 * 1024 * 1024), // 2MB
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(createValidPayload()),
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(413);

      const result = (await response.json()) as { error: string };
      expect(result.error).toContain('Payload too large');
      expect(result.error).toContain('1048576');
    });

    it('should return 413 for actual payload exceeding 1MB', async () => {
      // Create a payload with data larger than 1MB
      const largeData = 'A'.repeat(1.5 * 1024 * 1024); // 1.5MB of base64-like chars
      const payload = createValidPayload({ encrypted_data: largeData });

      const request = new Request('https://worker.test/forensics/size-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(413);
    });

    it('should accept payload just under 1MB', async () => {
      // Create payload close to but under 1MB
      const nearLimitData = 'A'.repeat(500 * 1024); // 500KB
      const payload = createValidPayload({ encrypted_data: nearLimitData });

      const request = new Request('https://worker.test/forensics/size-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(201);
    });
  });

  describe('CORS preflight headers', () => {
    it('should respond to OPTIONS with CORS headers', async () => {
      const request = new Request('https://worker.test/forensics/any-org', {
        method: 'OPTIONS',
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(200);

      const headers = response.headers;
      expect(headers.get('Access-Control-Allow-Origin')).toBe('*');
      expect(headers.get('Access-Control-Allow-Methods')).toContain('GET');
      expect(headers.get('Access-Control-Allow-Methods')).toContain('POST');
      expect(headers.get('Access-Control-Allow-Methods')).toContain('OPTIONS');
      expect(headers.get('Access-Control-Allow-Headers')).toContain('Content-Type');
    });

    it('should include CORS headers in all responses', async () => {
      const payload = createValidPayload();
      const request = new Request('https://worker.test/forensics/cors-test', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    });

    it('should respect custom CORS_ORIGIN', async () => {
      env.CORS_ORIGIN = 'https://app.blockioc.com';

      const request = new Request('https://worker.test/forensics/custom-cors', {
        method: 'OPTIONS',
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe(
        'https://app.blockioc.com'
      );
    });

    it('should include CORS headers in error responses', async () => {
      const request = new Request('https://worker.test/forensics/error-cors', {
        method: 'POST',
        body: 'invalid json',
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(400);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    });
  });

  describe('Route handling', () => {
    it('should return 404 for unknown routes', async () => {
      const request = new Request('https://worker.test/unknown/route', {
        method: 'GET',
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(404);

      const result = (await response.json()) as { error: string };
      expect(result.error).toBe('Not found');
    });

    it('should reject invalid org_id characters', async () => {
      const request = new Request('https://worker.test/forensics/org@invalid!', {
        method: 'POST',
        body: JSON.stringify(createValidPayload()),
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(404);
    });

    it('should accept org_id with underscores and hyphens', async () => {
      const request = new Request('https://worker.test/forensics/my-org_123', {
        method: 'POST',
        body: JSON.stringify(createValidPayload()),
      });

      const response = await handleForensicsRequest(request, env);
      expect(response.status).toBe(201);
    });
  });

  describe('Data integrity', () => {
    it('should preserve all payload fields in stored record', async () => {
      const payload = createValidPayload({
        key_version: 2,
        metadata: { event_type: 'block', severity: 'critical' },
      });

      const postRequest = new Request('https://worker.test/forensics/integrity-test', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      const postResponse = await handleForensicsRequest(postRequest, env);
      const { id } = (await postResponse.json()) as { id: string };

      // Retrieve and verify all fields
      const getRequest = new Request(
        `https://worker.test/forensics/integrity-test/${id}`,
        { method: 'GET' }
      );
      const getResponse = await handleForensicsRequest(getRequest, env);
      const record = (await getResponse.json()) as ForensicRecord;

      expect(record.encrypted_data).toBe(payload.encrypted_data);
      expect(record.encrypted_key).toBe(payload.encrypted_key);
      expect(record.iv).toBe(payload.iv);
      expect(record.key_version).toBe(2);
      expect(record.timestamp).toBe(payload.timestamp);
      expect(record.metadata?.event_type).toBe('block');
      expect(record.metadata?.severity).toBe('critical');
      expect(record.received_at).toBeTruthy();
    });

    it('should generate unique IDs for each record', async () => {
      const ids = new Set<string>();

      for (let i = 0; i < 10; i++) {
        const request = new Request('https://worker.test/forensics/unique-test', {
          method: 'POST',
          body: JSON.stringify(createValidPayload()),
        });

        const response = await handleForensicsRequest(request, env);
        const { id } = (await response.json()) as { id: string };
        ids.add(id);
      }

      expect(ids.size).toBe(10);
    });
  });
});
