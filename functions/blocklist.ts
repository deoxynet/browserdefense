/**
 * BrowserDefense Blocklist Cloudflare Worker
 *
 * Serverless endpoint for hosting signed blocklists.
 *
 * Architecture:
 *   Client (Extension) → Cloudflare Worker → R2 Storage
 *                              ↓
 *                        Signature validation
 *                              ↓
 *                        Response caching
 *
 * Endpoints:
 *   GET  /blocklist/{org_id}              - Get current signed blocklist
 *   PUT  /blocklist/{org_id}              - Upload new signed blocklist (authenticated)
 *   GET  /blocklist/{org_id}/delta?since={version} - Get delta update
 */

export interface Env {
  BLOCKLIST_BUCKET: R2Bucket;
  UPLOAD_API_KEY: string;
  CORS_ORIGIN: string;
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
}

/** Manifest format matching the client's BlocklistManifest */
interface BlocklistManifest {
  version: number;
  timestamp: string;
  type: 'delta' | 'full';
  hashes: string[];
  removed?: string[];
  signature: string;
}

/** Stored version metadata for delta generation */
interface VersionMetadata {
  version: number;
  timestamp: string;
  hashCount: number;
}

// R2 object keys
const getManifestKey = (orgId: string) => `${orgId}/manifest.json`;
const getVersionKey = (orgId: string, version: number) => `${orgId}/versions/${version}.json`;
const getVersionsIndexKey = (orgId: string) => `${orgId}/versions/index.json`;

/**
 * Compute SHA-256 hash of data and return as hex string.
 */
async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const buffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  const hashArray = Array.from(new Uint8Array(buffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Insert manifest metadata into Supabase.
 */
async function insertManifestMetadata(
  env: Env,
  orgId: string,
  manifest: BlocklistManifest,
  manifestJson: string,
  signingKeyId: string
): Promise<void> {
  const contentHash = await sha256(manifestJson);

  const response = await fetch(`${env.SUPABASE_URL}/rest/v1/update_manifests`, {
    method: 'POST',
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      'Content-Type': 'application/json',
      Prefer: 'return=minimal',
    },
    body: JSON.stringify({
      org_id: orgId,
      version: manifest.version,
      content_hash: contentHash,
      signature: manifest.signature,
      signing_key_id: signingKeyId,
      total_hashes: manifest.hashes.length,
      size_bytes: manifestJson.length,
      published_at: new Date().toISOString(),
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error('Failed to insert manifest metadata:', response.status, errorText);
    throw new Error(`Supabase insert failed: ${response.status}`);
  }
}

/**
 * Insert delta metadata into Supabase.
 */
async function insertDeltaMetadata(
  env: Env,
  orgId: string,
  fromVersion: number,
  toVersion: number,
  addedHashes: string[],
  removedHashes: string[],
  signature: string,
  signingKeyId: string
): Promise<void> {
  // Insert added hashes delta if any
  if (addedHashes.length > 0) {
    const hashesData = hexHashesToBytea(addedHashes);

    const response = await fetch(`${env.SUPABASE_URL}/rest/v1/update_deltas`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        org_id: orgId,
        from_version: fromVersion,
        to_version: toVersion,
        delta_type: 'add',
        hashes_data: hashesData,
        hashes_count: addedHashes.length,
        signature: signature,
        signing_key_id: signingKeyId,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Failed to insert add delta:', response.status, errorText);
      throw new Error(`Supabase delta insert failed: ${response.status}`);
    }
  }

  // Insert removed hashes delta if any
  if (removedHashes.length > 0) {
    const hashesData = hexHashesToBytea(removedHashes);

    const response = await fetch(`${env.SUPABASE_URL}/rest/v1/update_deltas`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        org_id: orgId,
        from_version: fromVersion,
        to_version: toVersion,
        delta_type: 'remove',
        hashes_data: hashesData,
        hashes_count: removedHashes.length,
        signature: signature,
        signing_key_id: signingKeyId,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Failed to insert remove delta:', response.status, errorText);
      throw new Error(`Supabase delta insert failed: ${response.status}`);
    }
  }
}

/**
 * Convert hex hash strings to base64-encoded bytea format for Postgres.
 */
function hexHashesToBytea(hashes: string[]): string {
  // Each hash is 64 hex chars = 32 bytes
  const buffer = new Uint8Array(hashes.length * 32);
  for (let i = 0; i < hashes.length; i++) {
    const hash = hashes[i];
    for (let j = 0; j < 32; j++) {
      buffer[i * 32 + j] = parseInt(hash.substring(j * 2, j * 2 + 2), 16);
    }
  }
  // Postgres bytea expects \\x prefix with hex encoding, but Supabase REST API accepts base64
  return btoa(String.fromCharCode(...buffer));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key, X-Signing-Key-Id',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Route: GET /blocklist/{org_id}
      const getMatch = path.match(/^\/blocklist\/([a-zA-Z0-9_-]+)$/);
      if (getMatch && request.method === 'GET') {
        return await handleGetBlocklist(getMatch[1], env, corsHeaders);
      }

      // Route: PUT /blocklist/{org_id}
      const putMatch = path.match(/^\/blocklist\/([a-zA-Z0-9_-]+)$/);
      if (putMatch && request.method === 'PUT') {
        return await handlePutBlocklist(putMatch[1], request, env, corsHeaders);
      }

      // Route: GET /blocklist/{org_id}/delta?since={version}
      const deltaMatch = path.match(/^\/blocklist\/([a-zA-Z0-9_-]+)\/delta$/);
      if (deltaMatch && request.method === 'GET') {
        const sinceParam = url.searchParams.get('since');
        if (!sinceParam) {
          return jsonError(400, 'Missing required parameter: since', corsHeaders);
        }
        const sinceVersion = parseInt(sinceParam, 10);
        if (isNaN(sinceVersion) || sinceVersion < 0) {
          return jsonError(400, 'Invalid version parameter', corsHeaders);
        }
        return await handleGetDelta(deltaMatch[1], sinceVersion, env, corsHeaders);
      }

      // Health check
      if (path === '/health' && request.method === 'GET') {
        return new Response(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      return jsonError(404, 'Not found', corsHeaders);
    } catch (err) {
      console.error('Worker error:', err);
      return jsonError(500, 'Internal server error', corsHeaders);
    }
  },
};

/**
 * GET /blocklist/{org_id}
 * Returns the current signed blocklist manifest for an organization.
 */
async function handleGetBlocklist(
  orgId: string,
  env: Env,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const key = getManifestKey(orgId);
  const object = await env.BLOCKLIST_BUCKET.get(key);

  if (!object) {
    return jsonError(404, `Blocklist not found for organization: ${orgId}`, corsHeaders);
  }

  const manifest = await object.json<BlocklistManifest>();

  return new Response(JSON.stringify(manifest), {
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300', // 5 minute cache
      'ETag': object.etag,
    },
  });
}

/**
 * PUT /blocklist/{org_id}
 * Upload a new signed blocklist (requires API key authentication).
 */
async function handlePutBlocklist(
  orgId: string,
  request: Request,
  env: Env,
  corsHeaders: Record<string, string>
): Promise<Response> {
  // Authenticate request
  const apiKey = request.headers.get('X-API-Key') || request.headers.get('Authorization')?.replace('Bearer ', '');

  if (!apiKey || apiKey !== env.UPLOAD_API_KEY) {
    return jsonError(401, 'Unauthorized: Invalid or missing API key', corsHeaders);
  }

  // Get signing key ID from header (required for Supabase metadata)
  const signingKeyId = request.headers.get('X-Signing-Key-Id') || 'default';

  // Parse request body
  let manifest: BlocklistManifest;
  let rawBody: string;
  try {
    rawBody = await request.text();
    manifest = JSON.parse(rawBody) as BlocklistManifest;
  } catch {
    return jsonError(400, 'Invalid JSON body', corsHeaders);
  }

  // Validate manifest structure
  const validationError = validateManifest(manifest);
  if (validationError) {
    return jsonError(400, validationError, corsHeaders);
  }

  // Get current manifest to check version
  const currentKey = getManifestKey(orgId);
  const currentObject = await env.BLOCKLIST_BUCKET.get(currentKey);
  let previousVersion: number | null = null;
  let previousHashes: Set<string> | null = null;

  if (currentObject) {
    const current = await currentObject.json<BlocklistManifest>();
    if (manifest.version <= current.version) {
      return jsonError(
        409,
        `Version conflict: new version ${manifest.version} must be greater than current ${current.version}`,
        corsHeaders
      );
    }

    previousVersion = current.version;
    previousHashes = new Set(current.hashes);

    // Archive current version for delta generation
    await archiveVersion(orgId, current, env);
  }

  // Store new manifest in R2
  const manifestJson = JSON.stringify(manifest);
  await env.BLOCKLIST_BUCKET.put(currentKey, manifestJson, {
    customMetadata: {
      version: String(manifest.version),
      timestamp: manifest.timestamp,
      hashCount: String(manifest.hashes.length),
    },
  });

  // Update versions index
  await updateVersionsIndex(orgId, manifest, env);

  // Insert manifest metadata into Supabase
  if (env.SUPABASE_URL && env.SUPABASE_SERVICE_ROLE_KEY) {
    try {
      await insertManifestMetadata(env, orgId, manifest, manifestJson, signingKeyId);

      // If this is an update (not first version), also insert delta metadata
      if (previousVersion !== null && previousHashes !== null) {
        const currentHashes = new Set(manifest.hashes);

        // Compute added and removed hashes
        const addedHashes: string[] = [];
        const removedHashes: string[] = [];

        for (const hash of currentHashes) {
          if (!previousHashes.has(hash)) {
            addedHashes.push(hash);
          }
        }

        for (const hash of previousHashes) {
          if (!currentHashes.has(hash)) {
            removedHashes.push(hash);
          }
        }

        // Insert delta metadata if there are changes
        if (addedHashes.length > 0 || removedHashes.length > 0) {
          await insertDeltaMetadata(
            env,
            orgId,
            previousVersion,
            manifest.version,
            addedHashes,
            removedHashes,
            manifest.signature,
            signingKeyId
          );
        }
      }
    } catch (err) {
      // Log error but don't fail the request - R2 upload already succeeded
      console.error('Failed to insert Supabase metadata:', err);
    }
  }

  return new Response(
    JSON.stringify({
      success: true,
      version: manifest.version,
      hashCount: manifest.hashes.length,
    }),
    {
      status: 201,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    }
  );
}

/**
 * GET /blocklist/{org_id}/delta?since={version}
 * Returns a delta update from the specified version to current.
 */
async function handleGetDelta(
  orgId: string,
  sinceVersion: number,
  env: Env,
  corsHeaders: Record<string, string>
): Promise<Response> {
  // Get current manifest
  const currentObject = await env.BLOCKLIST_BUCKET.get(getManifestKey(orgId));
  if (!currentObject) {
    return jsonError(404, `Blocklist not found for organization: ${orgId}`, corsHeaders);
  }

  const current = await currentObject.json<BlocklistManifest>();

  // If client is already up to date
  if (sinceVersion >= current.version) {
    return new Response(
      JSON.stringify({
        version: current.version,
        timestamp: current.timestamp,
        type: 'delta' as const,
        hashes: [],
        removed: [],
        signature: '', // No changes, no signature needed
        unchanged: true,
      }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }

  // Try to get the old version for delta computation
  const oldObject = await env.BLOCKLIST_BUCKET.get(getVersionKey(orgId, sinceVersion));

  if (!oldObject) {
    // Old version not available, return full update
    return new Response(JSON.stringify(current), {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'X-Delta-Fallback': 'full', // Indicate we returned a full update
      },
    });
  }

  const oldManifest = await oldObject.json<BlocklistManifest>();

  // Compute delta
  const oldHashes = new Set(oldManifest.hashes);
  const currentHashes = new Set(current.hashes);

  const added: string[] = [];
  const removed: string[] = [];

  // Find added hashes
  for (const hash of currentHashes) {
    if (!oldHashes.has(hash)) {
      added.push(hash);
    }
  }

  // Find removed hashes
  for (const hash of oldHashes) {
    if (!currentHashes.has(hash)) {
      removed.push(hash);
    }
  }

  // Note: The delta is NOT signed - clients should verify the full blocklist
  // periodically and use deltas only for incremental updates between full syncs.
  // For production, you would want to sign delta updates as well.
  const delta: BlocklistManifest = {
    version: current.version,
    timestamp: current.timestamp,
    type: 'delta',
    hashes: added,
    removed: removed,
    signature: current.signature, // Use current signature (covers the resulting state)
  };

  return new Response(JSON.stringify(delta), {
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=60', // Shorter cache for deltas
    },
  });
}

/**
 * Validate manifest structure.
 */
function validateManifest(manifest: unknown): string | null {
  if (typeof manifest !== 'object' || manifest === null) {
    return 'Manifest must be an object';
  }

  const m = manifest as Record<string, unknown>;

  if (typeof m.version !== 'number' || !Number.isInteger(m.version) || m.version < 0) {
    return 'Invalid version: must be a non-negative integer';
  }

  if (typeof m.timestamp !== 'string') {
    return 'Invalid timestamp: must be a string';
  }

  // Validate timestamp format (ISO 8601)
  const timestampDate = new Date(m.timestamp);
  if (isNaN(timestampDate.getTime())) {
    return 'Invalid timestamp: must be ISO 8601 format';
  }

  if (m.type !== 'delta' && m.type !== 'full') {
    return 'Invalid type: must be "delta" or "full"';
  }

  if (!Array.isArray(m.hashes)) {
    return 'Invalid hashes: must be an array';
  }

  // Validate hash format (64 hex chars = SHA-256)
  for (const hash of m.hashes) {
    if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/i.test(hash)) {
      return `Invalid hash format: ${hash}`;
    }
  }

  if (m.removed !== undefined) {
    if (!Array.isArray(m.removed)) {
      return 'Invalid removed: must be an array';
    }
    for (const hash of m.removed) {
      if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/i.test(hash)) {
        return `Invalid removed hash format: ${hash}`;
      }
    }
  }

  if (typeof m.signature !== 'string' || m.signature.length === 0) {
    return 'Invalid signature: must be a non-empty string';
  }

  return null;
}

/**
 * Archive a version for delta generation.
 */
async function archiveVersion(orgId: string, manifest: BlocklistManifest, env: Env): Promise<void> {
  const key = getVersionKey(orgId, manifest.version);
  await env.BLOCKLIST_BUCKET.put(key, JSON.stringify(manifest), {
    customMetadata: {
      version: String(manifest.version),
      timestamp: manifest.timestamp,
    },
  });
}

/**
 * Update the versions index to track available versions.
 */
async function updateVersionsIndex(orgId: string, manifest: BlocklistManifest, env: Env): Promise<void> {
  const indexKey = getVersionsIndexKey(orgId);
  let versions: VersionMetadata[] = [];

  // Get existing index
  const indexObject = await env.BLOCKLIST_BUCKET.get(indexKey);
  if (indexObject) {
    versions = await indexObject.json<VersionMetadata[]>();
  }

  // Add new version
  versions.push({
    version: manifest.version,
    timestamp: manifest.timestamp,
    hashCount: manifest.hashes.length,
  });

  // Keep only last 10 versions to limit storage
  if (versions.length > 10) {
    const toRemove = versions.slice(0, versions.length - 10);
    versions = versions.slice(-10);

    // Clean up old version files
    for (const old of toRemove) {
      await env.BLOCKLIST_BUCKET.delete(getVersionKey(orgId, old.version));
    }
  }

  // Save updated index
  await env.BLOCKLIST_BUCKET.put(indexKey, JSON.stringify(versions));
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
