/**
 * BrowserDefense Forensics Upload Worker
 *
 * Serverless endpoint for receiving encrypted forensics from extensions.
 * Zero-knowledge: Worker stores encrypted blobs it cannot read.
 *
 * Architecture:
 *   Extension → Cloudflare Worker → R2 Storage (or customer endpoint)
 *                     ↓
 *               Rate limiting (100/min per org)
 *                     ↓
 *               Size validation (1MB max)
 *                     ↓
 *               Forward/store
 *
 * Endpoints:
 *   POST /forensics/{org_id}     - Receive encrypted forensics
 *   GET  /forensics/{org_id}/{id} - Retrieve stored forensic (for customer pull)
 */

export interface ForensicsEnv {
  FORENSICS_BUCKET: R2Bucket;
  RATE_LIMIT_KV: KVNamespace;
  CORS_ORIGIN: string;
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
}

/** Encrypted forensics payload from extension */
interface ForensicsPayload {
  encrypted_data: string; // Base64 AES-GCM ciphertext
  encrypted_key: string; // Base64 RSA-OAEP wrapped AES key
  iv: string; // Base64 96-bit IV
  key_version?: number; // For multi-key support
  timestamp: string; // ISO 8601 timestamp
  extension_id?: string; // Chrome extension ID
  metadata_encrypted?: string; // Encrypted metadata (redirect chain, referrer, etc)
  metadata?: {
    // Optional metadata (unencrypted, for routing/filtering)
    event_type?: string; // "block" | "redirect_chain" | etc.
    severity?: string; // "low" | "medium" | "high" | "critical"
    blocked_url_hash?: string; // SHA-256 hash of blocked URL
  };
}

/** Stored forensic record */
interface ForensicRecord {
  id: string;
  org_id: string;
  encrypted_data: string;
  encrypted_key: string;
  iv: string;
  key_version: number;
  timestamp: string;
  received_at: string;
  extension_id?: string;
  metadata_encrypted?: string;
  metadata?: ForensicsPayload['metadata'];
}

// Rate limiting configuration
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 100; // 100 requests per minute per org

// Size limits
const MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB

export default {
  async fetch(request: Request, env: ForensicsEnv): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Route: POST /forensics/{org_id}
      const postMatch = path.match(/^\/forensics\/([a-zA-Z0-9_-]+)$/);
      if (postMatch && request.method === 'POST') {
        return await handlePostForensics(postMatch[1], request, env, corsHeaders);
      }

      // Route: GET /forensics/{org_id}/{id}
      const getMatch = path.match(/^\/forensics\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)$/);
      if (getMatch && request.method === 'GET') {
        return await handleGetForensic(getMatch[1], getMatch[2], env, corsHeaders);
      }

      // Route: GET /forensics/{org_id} - List forensics for org
      const listMatch = path.match(/^\/forensics\/([a-zA-Z0-9_-]+)$/);
      if (listMatch && request.method === 'GET') {
        return await handleListForensics(listMatch[1], url.searchParams, env, corsHeaders);
      }

      return jsonError(404, 'Not found', corsHeaders);
    } catch (err) {
      console.error('Forensics worker error:', err);
      return jsonError(500, 'Internal server error', corsHeaders);
    }
  },
};

/**
 * POST /forensics/{org_id}
 * Receive and store encrypted forensics from extension.
 */
async function handlePostForensics(
  orgId: string,
  request: Request,
  env: ForensicsEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  // Check content length before reading body
  const contentLength = request.headers.get('Content-Length');
  if (contentLength && parseInt(contentLength, 10) > MAX_PAYLOAD_SIZE) {
    return jsonError(413, `Payload too large. Maximum size is ${MAX_PAYLOAD_SIZE} bytes`, corsHeaders);
  }

  // Rate limiting check
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

  // Parse request body
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

  // Validate payload structure
  const validationError = validateForensicsPayload(payload);
  if (validationError) {
    return jsonError(400, validationError, corsHeaders);
  }

  // Generate unique ID for this forensic record
  const forensicId = generateForensicId();
  const receivedAt = new Date().toISOString();

  // Create the record to store
  const record: ForensicRecord = {
    id: forensicId,
    org_id: orgId,
    encrypted_data: payload.encrypted_data,
    encrypted_key: payload.encrypted_key,
    iv: payload.iv,
    key_version: payload.key_version ?? 1,
    timestamp: payload.timestamp,
    received_at: receivedAt,
    extension_id: payload.extension_id,
    metadata_encrypted: payload.metadata_encrypted,
    metadata: payload.metadata,
  };

  // Store in R2
  const key = getForensicKey(orgId, forensicId);
  const recordJson = JSON.stringify(record);
  await env.FORENSICS_BUCKET.put(key, recordJson, {
    customMetadata: {
      org_id: orgId,
      timestamp: payload.timestamp,
      received_at: receivedAt,
      event_type: payload.metadata?.event_type ?? 'unknown',
    },
  });

  // Insert metadata into Supabase forensics_index
  const blobId = crypto.randomUUID();
  const indexRow = {
    org_id: orgId,
    blob_id: blobId,
    encrypted_key: payload.encrypted_key,
    key_version: payload.key_version ?? 1,
    storage_path: key,
    size_bytes: recordJson.length,
    status: 'uploaded',
    blocked_url_hash: payload.metadata?.blocked_url_hash ?? null,
    block_timestamp: payload.timestamp,
    extension_id: payload.extension_id ?? null,
    metadata_encrypted: payload.metadata_encrypted ?? null,
  };

  const supabaseResponse = await fetch(
    `${env.SUPABASE_URL}/rest/v1/forensics_index`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        Prefer: 'return=minimal',
      },
      body: JSON.stringify(indexRow),
    }
  );

  if (!supabaseResponse.ok) {
    // Log error but don't fail the request - R2 storage succeeded
    console.error(
      'Failed to insert forensics_index row:',
      supabaseResponse.status,
      await supabaseResponse.text()
    );
  }

  return new Response(
    JSON.stringify({
      status: 'received',
      id: forensicId,
      blob_id: blobId,
    }),
    {
      status: 201,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    }
  );
}

/**
 * GET /forensics/{org_id}/{id}
 * Retrieve a specific forensic record.
 */
async function handleGetForensic(
  orgId: string,
  forensicId: string,
  env: ForensicsEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const key = getForensicKey(orgId, forensicId);
  const object = await env.FORENSICS_BUCKET.get(key);

  if (!object) {
    return jsonError(404, `Forensic record not found: ${forensicId}`, corsHeaders);
  }

  const record = await object.json<ForensicRecord>();

  return new Response(JSON.stringify(record), {
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
    },
  });
}

/**
 * GET /forensics/{org_id}?limit=100&cursor=xxx
 * List forensic records for an organization.
 */
async function handleListForensics(
  orgId: string,
  params: URLSearchParams,
  env: ForensicsEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const limit = Math.min(parseInt(params.get('limit') ?? '100', 10), 1000);
  const cursor = params.get('cursor') ?? undefined;

  const prefix = `${orgId}/`;
  const listed = await env.FORENSICS_BUCKET.list({
    prefix,
    limit,
    cursor,
  });

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
    {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    }
  );
}

/**
 * Rate limiting using KV storage.
 * Uses a sliding window counter approach.
 */
async function checkRateLimit(
  orgId: string,
  env: ForensicsEnv
): Promise<{ allowed: boolean; retryAfter: number }> {
  const key = `ratelimit:forensics:${orgId}`;
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW_MS;

  // Get current rate limit data
  const data = await env.RATE_LIMIT_KV.get(key, 'json');
  const requests: number[] = (data as number[] | null) ?? [];

  // Filter to only requests within the current window
  const recentRequests = requests.filter((ts) => ts > windowStart);

  if (recentRequests.length >= RATE_LIMIT_MAX_REQUESTS) {
    // Calculate when the oldest request will expire
    const oldestRequest = Math.min(...recentRequests);
    const retryAfter = Math.ceil((oldestRequest + RATE_LIMIT_WINDOW_MS - now) / 1000);
    return { allowed: false, retryAfter: Math.max(1, retryAfter) };
  }

  // Add current request timestamp
  recentRequests.push(now);

  // Store updated rate limit data (expire after window + buffer)
  await env.RATE_LIMIT_KV.put(key, JSON.stringify(recentRequests), {
    expirationTtl: Math.ceil(RATE_LIMIT_WINDOW_MS / 1000) + 60,
  });

  return { allowed: true, retryAfter: 0 };
}

/**
 * Validate the forensics payload structure.
 */
function validateForensicsPayload(payload: unknown): string | null {
  if (typeof payload !== 'object' || payload === null) {
    return 'Payload must be an object';
  }

  const p = payload as Record<string, unknown>;

  // Required fields
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

  // Validate timestamp format (ISO 8601)
  const timestampDate = new Date(p.timestamp);
  if (isNaN(timestampDate.getTime())) {
    return 'Invalid timestamp: must be ISO 8601 format';
  }

  // Validate base64 encoding (basic check)
  if (!isValidBase64(p.encrypted_data as string)) {
    return 'Invalid encrypted_data: must be valid base64';
  }

  if (!isValidBase64(p.encrypted_key as string)) {
    return 'Invalid encrypted_key: must be valid base64';
  }

  if (!isValidBase64(p.iv as string)) {
    return 'Invalid iv: must be valid base64';
  }

  // Optional fields validation
  if (p.key_version !== undefined) {
    if (typeof p.key_version !== 'number' || !Number.isInteger(p.key_version) || p.key_version < 1) {
      return 'Invalid key_version: must be a positive integer';
    }
  }

  if (p.metadata !== undefined) {
    if (typeof p.metadata !== 'object' || p.metadata === null) {
      return 'Invalid metadata: must be an object';
    }
  }

  return null;
}

/**
 * Check if a string is valid base64.
 */
function isValidBase64(str: string): boolean {
  // Base64 can contain A-Z, a-z, 0-9, +, /, and = for padding
  // Also allow URL-safe base64 with - and _
  const base64Regex = /^[A-Za-z0-9+/\-_]*={0,2}$/;
  return base64Regex.test(str);
}

/**
 * Generate a unique forensic ID.
 */
function generateForensicId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `forensic_${timestamp}_${random}`;
}

/**
 * Get R2 key for a forensic record.
 */
function getForensicKey(orgId: string, forensicId: string): string {
  return `${orgId}/${forensicId}`;
}

/**
 * Return a JSON error response.
 */
function jsonError(status: number, message: string, corsHeaders: Record<string, string>): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}
