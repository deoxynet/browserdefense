/**
 * BlockIOC Blocklist Distribution Worker
 *
 * Extension-compatible blocklist distribution via Cloudflare R2.
 * Serves pre-computed snapshots and deltas from immutable R2 objects.
 *
 * R2 Layout per account:
 *   /{account}/manifest.json           - Current version manifest (CDN cached)
 *   /{account}/snapshots/{version}.b64 - Immutable base64 blocklist snapshots
 *   /{account}/deltas/{from}-{to}.bin  - Pre-computed binary deltas
 *   /{account}/meta/versions.json      - Version history for cleanup
 *
 * Read Endpoints (public, CDN-cacheable):
 *   GET  /{account}/manifest.json
 *   GET  /{account}/snapshots/{version}.b64
 *   GET  /{account}/deltas/{from}-{to}.bin
 *
 * Write Endpoints (authenticated):
 *   POST /api/publish/{account}        - Upload new snapshot + update manifest
 */

export interface Env {
  BLOCKLIST_BUCKET: R2Bucket;
  PUBLISH_API_KEY: string;
  CORS_ORIGIN?: string;
}

/**
 * Manifest format - compatible with extension's BlocklistManifest
 * (src/background/updates.ts)
 */
export interface BlocklistManifest {
  /** Monotonically increasing version number (typically timestamp) */
  version: number;
  /** Total number of IOC hashes in the blocklist */
  total_iocs: number;
  /** Number of buckets (1 for single-file, >1 for sharded) */
  bucket_count: number;
  /** SHA-256 hash of the binary blocklist content */
  sha256_root: string;
  /** P-256 ECDSA or Ed25519 signature over canonical fields */
  signature: string;
  /** ISO 8601 creation timestamp */
  created_at: string;
  /** Signing algorithm version: 'p256-v1' or 'ed25519-v2' */
  algorithm_version: string;
  /** Relative URL to the snapshot file */
  snapshot_url: string;
  /** Available deltas from previous versions */
  deltas: DeltaInfo[];
}

export interface DeltaInfo {
  /** Source version */
  from: number;
  /** Target version (should match manifest.version) */
  to: number;
  /** Relative URL to the delta file */
  url: string;
  /** Size in bytes (for client to decide if delta is worth it) */
  size: number;
}

/**
 * Version metadata stored in meta/versions.json
 */
interface VersionEntry {
  version: number;
  created_at: string;
  total_iocs: number;
  sha256_root: string;
}

/**
 * Publish request body
 */
interface PublishRequest {
  /** Base64-encoded blocklist binary */
  blocklist_b64: string;
  /** Manifest fields (signature required) */
  manifest: {
    version: number;
    total_iocs: number;
    bucket_count: number;
    sha256_root: string;
    signature: string;
    created_at: string;
    algorithm_version: string;
  };
}

// R2 key helpers
const getManifestKey = (account: string) => `${account}/manifest.json`;
const getSnapshotKey = (account: string, version: number) =>
  `${account}/snapshots/${version}.b64`;
const getDeltaKey = (account: string, from: number, to: number) =>
  `${account}/deltas/${from}-${to}.bin`;
const getVersionsKey = (account: string) => `${account}/meta/versions.json`;

// Keep last N versions for delta generation
const MAX_VERSIONS_KEPT = 5;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    const corsHeaders: Record<string, string> = {
      'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    };

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Health check
      if (path === '/health') {
        return jsonResponse({ status: 'ok', timestamp: new Date().toISOString() }, corsHeaders);
      }

      // POST /api/publish/{account} - Publish new blocklist
      const publishMatch = path.match(/^\/api\/publish\/([a-zA-Z0-9_-]+)$/);
      if (publishMatch && request.method === 'POST') {
        return handlePublish(publishMatch[1], request, env, corsHeaders);
      }

      // GET /{account}/manifest.json - Get current manifest
      const manifestMatch = path.match(/^\/([a-zA-Z0-9_-]+)\/manifest\.json$/);
      if (manifestMatch && request.method === 'GET') {
        return handleGetManifest(manifestMatch[1], env, corsHeaders);
      }

      // GET /{account}/snapshots/{version}.b64 - Get snapshot
      const snapshotMatch = path.match(/^\/([a-zA-Z0-9_-]+)\/snapshots\/(\d+)\.b64$/);
      if (snapshotMatch && request.method === 'GET') {
        return handleGetSnapshot(snapshotMatch[1], parseInt(snapshotMatch[2], 10), env, corsHeaders);
      }

      // GET /{account}/deltas/{from}-{to}.bin - Get delta
      const deltaMatch = path.match(/^\/([a-zA-Z0-9_-]+)\/deltas\/(\d+)-(\d+)\.bin$/);
      if (deltaMatch && request.method === 'GET') {
        return handleGetDelta(
          deltaMatch[1],
          parseInt(deltaMatch[2], 10),
          parseInt(deltaMatch[3], 10),
          env,
          corsHeaders
        );
      }

      return jsonError(404, 'Not found', corsHeaders);
    } catch (err) {
      console.error('Worker error:', err);
      return jsonError(500, 'Internal server error', corsHeaders);
    }
  },
};

/**
 * GET /{account}/manifest.json
 * Returns the current blocklist manifest (CDN-cacheable).
 */
async function handleGetManifest(
  account: string,
  env: Env,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const key = getManifestKey(account);
  const object = await env.BLOCKLIST_BUCKET.get(key);

  if (!object) {
    return jsonError(404, `Blocklist not found for account: ${account}`, corsHeaders);
  }

  const manifest = await object.json<BlocklistManifest>();

  return new Response(JSON.stringify(manifest), {
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300, stale-while-revalidate=60',
      ETag: object.etag,
    },
  });
}

/**
 * GET /{account}/snapshots/{version}.b64
 * Returns the base64-encoded blocklist snapshot (immutable, long cache).
 */
async function handleGetSnapshot(
  account: string,
  version: number,
  env: Env,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const key = getSnapshotKey(account, version);
  const object = await env.BLOCKLIST_BUCKET.get(key);

  if (!object) {
    return jsonError(404, `Snapshot not found: version ${version}`, corsHeaders);
  }

  const body = await object.text();

  return new Response(body, {
    headers: {
      ...corsHeaders,
      'Content-Type': 'text/plain',
      // Immutable content - cache forever
      'Cache-Control': 'public, max-age=31536000, immutable',
      ETag: object.etag,
    },
  });
}

/**
 * GET /{account}/deltas/{from}-{to}.bin
 * Returns the binary delta file (immutable, long cache).
 */
async function handleGetDelta(
  account: string,
  from: number,
  to: number,
  env: Env,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const key = getDeltaKey(account, from, to);
  const object = await env.BLOCKLIST_BUCKET.get(key);

  if (!object) {
    return jsonError(404, `Delta not found: ${from} -> ${to}`, corsHeaders);
  }

  const body = await object.arrayBuffer();

  return new Response(body, {
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/octet-stream',
      // Immutable content - cache forever
      'Cache-Control': 'public, max-age=31536000, immutable',
      ETag: object.etag,
    },
  });
}

/**
 * POST /api/publish/{account}
 * Upload a new blocklist snapshot and update the manifest.
 * Authenticated via API key.
 */
async function handlePublish(
  account: string,
  request: Request,
  env: Env,
  corsHeaders: Record<string, string>
): Promise<Response> {
  // Authenticate
  const apiKey =
    request.headers.get('X-API-Key') || request.headers.get('Authorization')?.replace('Bearer ', '');

  if (!apiKey || apiKey !== env.PUBLISH_API_KEY) {
    return jsonError(401, 'Unauthorized: Invalid or missing API key', corsHeaders);
  }

  // Parse request
  let body: PublishRequest;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'Invalid JSON body', corsHeaders);
  }

  // Validate request
  const validationError = validatePublishRequest(body);
  if (validationError) {
    return jsonError(400, validationError, corsHeaders);
  }

  // Get current manifest to check version
  const currentManifestKey = getManifestKey(account);
  const currentObject = await env.BLOCKLIST_BUCKET.get(currentManifestKey);
  let previousManifest: BlocklistManifest | null = null;

  if (currentObject) {
    previousManifest = await currentObject.json<BlocklistManifest>();
    if (body.manifest.version <= previousManifest.version) {
      return jsonError(
        409,
        `Version conflict: ${body.manifest.version} <= current ${previousManifest.version}`,
        corsHeaders
      );
    }
  }

  // Upload snapshot
  const snapshotKey = getSnapshotKey(account, body.manifest.version);
  await env.BLOCKLIST_BUCKET.put(snapshotKey, body.blocklist_b64, {
    customMetadata: {
      version: String(body.manifest.version),
      total_iocs: String(body.manifest.total_iocs),
    },
  });

  // Compute and upload deltas from recent versions
  const deltas: DeltaInfo[] = [];

  if (previousManifest) {
    // Get version history
    const versions = await getVersionHistory(account, env);

    // Compute deltas from each recent version
    for (const prevVersion of versions.slice(-MAX_VERSIONS_KEPT)) {
      try {
        const delta = await computeAndStoreDelta(
          account,
          prevVersion.version,
          body.manifest.version,
          body.blocklist_b64,
          env
        );
        if (delta) {
          deltas.push(delta);
        }
      } catch (err) {
        console.warn(`Failed to compute delta ${prevVersion.version} -> ${body.manifest.version}:`, err);
      }
    }
  }

  // Build new manifest
  const newManifest: BlocklistManifest = {
    version: body.manifest.version,
    total_iocs: body.manifest.total_iocs,
    bucket_count: body.manifest.bucket_count,
    sha256_root: body.manifest.sha256_root,
    signature: body.manifest.signature,
    created_at: body.manifest.created_at,
    algorithm_version: body.manifest.algorithm_version,
    snapshot_url: `snapshots/${body.manifest.version}.b64`,
    deltas,
  };

  // Upload manifest (atomic update)
  await env.BLOCKLIST_BUCKET.put(currentManifestKey, JSON.stringify(newManifest), {
    customMetadata: {
      version: String(newManifest.version),
    },
  });

  // Update version history
  await updateVersionHistory(account, body.manifest, env);

  return jsonResponse(
    {
      success: true,
      version: newManifest.version,
      snapshot_url: newManifest.snapshot_url,
      deltas_created: deltas.length,
    },
    corsHeaders,
    201
  );
}

/**
 * Compute delta between two versions and store it in R2.
 */
async function computeAndStoreDelta(
  account: string,
  fromVersion: number,
  toVersion: number,
  newBlocklistB64: string,
  env: Env
): Promise<DeltaInfo | null> {
  // Get old snapshot
  const oldSnapshotKey = getSnapshotKey(account, fromVersion);
  const oldObject = await env.BLOCKLIST_BUCKET.get(oldSnapshotKey);

  if (!oldObject) {
    console.warn(`Old snapshot not found: ${fromVersion}`);
    return null;
  }

  const oldBlocklistB64 = await oldObject.text();

  // Decode both blocklists
  const oldHashes = decodeBlocklist(oldBlocklistB64);
  const newHashes = decodeBlocklist(newBlocklistB64);

  // Compute diff
  const oldSet = new Set(oldHashes.map((h) => bufferToHex(h)));
  const newSet = new Set(newHashes.map((h) => bufferToHex(h)));

  const added: Uint8Array[] = [];
  const removed: Uint8Array[] = [];

  for (const hash of newHashes) {
    const hex = bufferToHex(hash);
    if (!oldSet.has(hex)) {
      added.push(hash);
    }
  }

  for (const hash of oldHashes) {
    const hex = bufferToHex(hash);
    if (!newSet.has(hex)) {
      removed.push(hash);
    }
  }

  // If no changes, skip delta
  if (added.length === 0 && removed.length === 0) {
    return null;
  }

  // Encode delta in binary format:
  // [4 bytes: added_count (uint32 LE)]
  // [4 bytes: removed_count (uint32 LE)]
  // [added_count * 32 bytes: added hashes]
  // [removed_count * 32 bytes: removed hashes]
  const deltaBuffer = encodeDelta(added, removed);

  // Store delta
  const deltaKey = getDeltaKey(account, fromVersion, toVersion);
  await env.BLOCKLIST_BUCKET.put(deltaKey, deltaBuffer, {
    customMetadata: {
      from_version: String(fromVersion),
      to_version: String(toVersion),
      added_count: String(added.length),
      removed_count: String(removed.length),
    },
  });

  return {
    from: fromVersion,
    to: toVersion,
    url: `deltas/${fromVersion}-${toVersion}.bin`,
    size: deltaBuffer.byteLength,
  };
}

/**
 * Decode base64 blocklist to array of 32-byte hashes.
 */
function decodeBlocklist(b64: string): Uint8Array[] {
  const binary = base64ToUint8Array(b64);
  const hashes: Uint8Array[] = [];

  for (let i = 0; i < binary.length; i += 32) {
    hashes.push(binary.slice(i, i + 32));
  }

  return hashes;
}

/**
 * Encode delta as binary buffer.
 */
function encodeDelta(added: Uint8Array[], removed: Uint8Array[]): ArrayBuffer {
  const headerSize = 8;
  const totalSize = headerSize + added.length * 32 + removed.length * 32;
  const buffer = new ArrayBuffer(totalSize);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  // Header
  view.setUint32(0, added.length, true); // little-endian
  view.setUint32(4, removed.length, true);

  // Added hashes
  let offset = headerSize;
  for (const hash of added) {
    bytes.set(hash, offset);
    offset += 32;
  }

  // Removed hashes
  for (const hash of removed) {
    bytes.set(hash, offset);
    offset += 32;
  }

  return buffer;
}

/**
 * Get version history for an account.
 */
async function getVersionHistory(account: string, env: Env): Promise<VersionEntry[]> {
  const key = getVersionsKey(account);
  const object = await env.BLOCKLIST_BUCKET.get(key);

  if (!object) {
    return [];
  }

  return object.json<VersionEntry[]>();
}

/**
 * Update version history after publishing.
 */
async function updateVersionHistory(
  account: string,
  manifest: PublishRequest['manifest'],
  env: Env
): Promise<void> {
  const key = getVersionsKey(account);
  let versions = await getVersionHistory(account, env);

  // Add new version
  versions.push({
    version: manifest.version,
    created_at: manifest.created_at,
    total_iocs: manifest.total_iocs,
    sha256_root: manifest.sha256_root,
  });

  // Keep only recent versions
  const maxVersions = MAX_VERSIONS_KEPT + 1; // +1 for current
  if (versions.length > maxVersions) {
    const toRemove = versions.slice(0, versions.length - maxVersions);
    versions = versions.slice(-maxVersions);

    // Clean up old snapshots and deltas
    for (const old of toRemove) {
      await env.BLOCKLIST_BUCKET.delete(getSnapshotKey(account, old.version));
      // Note: deltas referencing this version will become orphaned but that's OK
      // They'll be unreachable and can be cleaned up in a separate process
    }
  }

  await env.BLOCKLIST_BUCKET.put(key, JSON.stringify(versions));
}

/**
 * Validate publish request.
 */
function validatePublishRequest(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) {
    return 'Request body must be an object';
  }

  const req = body as Record<string, unknown>;

  if (typeof req.blocklist_b64 !== 'string' || req.blocklist_b64.length === 0) {
    return 'blocklist_b64 is required and must be a non-empty string';
  }

  if (typeof req.manifest !== 'object' || req.manifest === null) {
    return 'manifest is required and must be an object';
  }

  const m = req.manifest as Record<string, unknown>;

  if (typeof m.version !== 'number' || !Number.isInteger(m.version) || m.version < 0) {
    return 'manifest.version must be a non-negative integer';
  }

  if (typeof m.total_iocs !== 'number' || !Number.isInteger(m.total_iocs) || m.total_iocs < 0) {
    return 'manifest.total_iocs must be a non-negative integer';
  }

  if (typeof m.bucket_count !== 'number' || !Number.isInteger(m.bucket_count) || m.bucket_count < 1) {
    return 'manifest.bucket_count must be a positive integer';
  }

  if (typeof m.sha256_root !== 'string' || !/^[a-f0-9]{64}$/i.test(m.sha256_root)) {
    return 'manifest.sha256_root must be a 64-character hex string';
  }

  if (typeof m.signature !== 'string' || m.signature.length === 0) {
    return 'manifest.signature is required';
  }

  if (typeof m.created_at !== 'string') {
    return 'manifest.created_at must be a string';
  }

  if (typeof m.algorithm_version !== 'string') {
    return 'manifest.algorithm_version must be a string';
  }

  return null;
}

// Utility functions

function jsonResponse(
  data: unknown,
  corsHeaders: Record<string, string>,
  status = 200
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
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

function base64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bufferToHex(buf: Uint8Array): string {
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
