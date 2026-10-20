/**
 * BrowserDefense Shadow Telemetry Worker
 *
 * Server-side global first-seen tracking for DOM kit hashes.
 * Internal analytics only - no client feedback, no enforcement.
 *
 * Architecture:
 *   Extension → Cloudflare Worker → KV Storage
 *                     ↓
 *               Rate limiting (1000/min)
 *                     ↓
 *               Global first-seen tracking
 *
 * Endpoints:
 *   POST /telemetry  - Receive shadow telemetry
 *   GET  /health     - Health check
 *
 * Stored data per hash:
 *   - dom_kit_hash: The SHA-256 hash (sha256:...)
 *   - first_seen_ts: Unix timestamp when first seen globally
 *   - total_seen_count: Number of times this hash has been reported
 *
 * Reference: Issue #203
 */

export interface ShadowTelemetryEnv {
  /** KV namespace for storing hash tracking data */
  HASH_TRACKING_KV: KVNamespace;
  /** KV namespace for rate limiting */
  RATE_LIMIT_KV: KVNamespace;
  /** CORS origin configuration */
  CORS_ORIGIN: string;
}

/** Shadow telemetry payload from extension */
interface ShadowTelemetryPayload {
  /** SHA-256 hash of DOM skeleton (prefixed with sha256:) */
  dom_kit_hash: string;
  /** Unix timestamp in milliseconds */
  event_ts: number;
  /** Whether this is the first time this hash was seen locally */
  first_seen_locally: boolean;
}

/** Stored hash tracking record */
interface HashTrackingRecord {
  /** The DOM kit hash (sha256:...) */
  dom_kit_hash: string;
  /** Unix timestamp (ms) when first seen globally */
  first_seen_ts: number;
  /** Total number of times this hash has been reported */
  total_seen_count: number;
  /** Last seen timestamp (ms) */
  last_seen_ts: number;
}

// Rate limiting configuration
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 1000; // 1000 requests per minute (global)

// Validation
const MAX_PAYLOAD_SIZE = 1024; // 1KB max for telemetry payloads
const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/i;

export default {
  async fetch(request: Request, env: ShadowTelemetryEnv): Promise<Response> {
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
      // Route: POST /telemetry
      if (path === '/telemetry' && request.method === 'POST') {
        return await handlePostTelemetry(request, env, corsHeaders);
      }

      // Route: GET /health
      if (path === '/health' && request.method === 'GET') {
        return new Response(JSON.stringify({ status: 'ok', service: 'shadow-telemetry' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      return jsonError(404, 'Not found', corsHeaders);
    } catch (err) {
      console.error('Shadow telemetry worker error:', err);
      return jsonError(500, 'Internal server error', corsHeaders);
    }
  },
};

/**
 * POST /telemetry
 * Receive shadow telemetry and update global first-seen tracking.
 *
 * IMPORTANT: This endpoint does NOT return any "first seen globally" signal.
 * This is internal analytics only.
 */
async function handlePostTelemetry(
  request: Request,
  env: ShadowTelemetryEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  // Check content length before reading body
  const contentLength = request.headers.get('Content-Length');
  if (contentLength && parseInt(contentLength, 10) > MAX_PAYLOAD_SIZE) {
    return jsonError(413, `Payload too large. Maximum size is ${MAX_PAYLOAD_SIZE} bytes`, corsHeaders);
  }

  // Rate limiting check (global, not per-org)
  const rateLimitResult = await checkRateLimit(env);
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
  let payload: ShadowTelemetryPayload;
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
  const validationError = validatePayload(payload);
  if (validationError) {
    return jsonError(400, validationError, corsHeaders);
  }

  // Update global first-seen tracking
  await updateHashTracking(payload.dom_kit_hash, payload.event_ts, env);

  // Return minimal acknowledgment (no "first seen" signal to client)
  return new Response(
    JSON.stringify({ status: 'received' }),
    {
      status: 202, // Accepted
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    }
  );
}

/**
 * Update global first-seen tracking for a hash.
 *
 * Atomically updates:
 * - first_seen_ts: Set only if this is the first time seeing this hash
 * - total_seen_count: Incremented on every report
 * - last_seen_ts: Updated on every report
 */
async function updateHashTracking(
  domKitHash: string,
  eventTs: number,
  env: ShadowTelemetryEnv
): Promise<void> {
  const key = `hash:${domKitHash}`;
  const now = Date.now();

  // Get existing record
  const existingData = await env.HASH_TRACKING_KV.get(key, 'json');
  const existing = existingData as HashTrackingRecord | null;

  if (existing) {
    // Update existing record
    const updated: HashTrackingRecord = {
      dom_kit_hash: domKitHash,
      first_seen_ts: existing.first_seen_ts, // Keep original first seen time
      total_seen_count: existing.total_seen_count + 1,
      last_seen_ts: now,
    };

    await env.HASH_TRACKING_KV.put(key, JSON.stringify(updated));

    console.log(
      `[ShadowTelemetry] Updated hash ${domKitHash.slice(0, 24)}... ` +
        `(count: ${updated.total_seen_count})`
    );
  } else {
    // Create new record (first time seen globally!)
    const record: HashTrackingRecord = {
      dom_kit_hash: domKitHash,
      first_seen_ts: eventTs, // Use client timestamp as first seen
      total_seen_count: 1,
      last_seen_ts: now,
    };

    await env.HASH_TRACKING_KV.put(key, JSON.stringify(record));

    console.log(
      `[ShadowTelemetry] First global sighting: ${domKitHash.slice(0, 24)}... ` +
        `(ts: ${new Date(eventTs).toISOString()})`
    );
  }
}

/**
 * Rate limiting using KV storage.
 * Uses a sliding window counter approach.
 * This is global rate limiting (not per-client) for DoS protection.
 */
async function checkRateLimit(
  env: ShadowTelemetryEnv
): Promise<{ allowed: boolean; retryAfter: number }> {
  const key = 'ratelimit:shadow-telemetry:global';
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
 * Validate the shadow telemetry payload structure.
 */
function validatePayload(payload: unknown): string | null {
  if (typeof payload !== 'object' || payload === null) {
    return 'Payload must be an object';
  }

  const p = payload as Record<string, unknown>;

  // Required: dom_kit_hash (sha256:... format)
  if (typeof p.dom_kit_hash !== 'string') {
    return 'Invalid dom_kit_hash: must be a string';
  }

  if (!HASH_PATTERN.test(p.dom_kit_hash)) {
    return 'Invalid dom_kit_hash: must be sha256: followed by 64 hex characters';
  }

  // Required: event_ts (positive number)
  if (typeof p.event_ts !== 'number' || p.event_ts <= 0) {
    return 'Invalid event_ts: must be a positive number';
  }

  // Validate timestamp is reasonable (not in the future, not too old)
  const now = Date.now();
  const oneYearMs = 365 * 24 * 60 * 60 * 1000;

  if (p.event_ts > now + 60000) {
    // Allow 1 minute clock skew
    return 'Invalid event_ts: timestamp is in the future';
  }

  if (p.event_ts < now - oneYearMs) {
    return 'Invalid event_ts: timestamp is too old';
  }

  // Required: first_seen_locally (boolean)
  if (typeof p.first_seen_locally !== 'boolean') {
    return 'Invalid first_seen_locally: must be a boolean';
  }

  // Verify no extra fields (defense in depth)
  const allowedKeys = new Set(['dom_kit_hash', 'event_ts', 'first_seen_locally']);
  for (const key of Object.keys(p)) {
    if (!allowedKeys.has(key)) {
      return `Unexpected field: ${key}`;
    }
  }

  return null;
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
