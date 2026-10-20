/**
 * BrowserDefense Hash Labels Worker
 *
 * Server-side storage for analyst TP/FP labels on DOM kit hashes.
 * Labels are for incident review and research ONLY - NO automatic enforcement.
 *
 * Endpoints:
 *   POST   /labels              - Create or update a label
 *   GET    /labels/{hash}       - Get label for a specific hash
 *   DELETE /labels/{hash}       - Remove a label
 *   GET    /labels              - List labels with optional filters
 *
 * Reference: Issue #205
 */

export interface HashLabelsEnv {
  /** KV namespace for label storage */
  HASH_LABELS_KV: KVNamespace;
  /** CORS origin */
  CORS_ORIGIN: string;
}

/** Label classification types */
type HashLabelType = 'TP' | 'FP' | 'UNKNOWN';

/** Stored label record */
interface HashLabel {
  dom_kit_hash: string;
  label: HashLabelType;
  analyst?: string;
  notes?: string;
  created_at: number;
  updated_at: number;
}

/** Request payload for creating/updating labels */
interface LabelRequest {
  dom_kit_hash: string;
  label: HashLabelType;
  analyst?: string;
  notes?: string;
}

// Validation patterns
const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/i;
const VALID_LABELS: HashLabelType[] = ['TP', 'FP', 'UNKNOWN'];

export default {
  async fetch(request: Request, env: HashLabelsEnv): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Health check
      if (path === '/health') {
        return jsonResponse({ status: 'ok', service: 'hash-labels' }, corsHeaders);
      }

      // POST /labels - Create or update a label
      if (path === '/labels' && request.method === 'POST') {
        return await handleCreateLabel(request, env, corsHeaders);
      }

      // GET /labels - List labels
      if (path === '/labels' && request.method === 'GET') {
        return await handleListLabels(url.searchParams, env, corsHeaders);
      }

      // GET /labels/{hash} - Get specific label
      const getMatch = path.match(/^\/labels\/(.+)$/);
      if (getMatch && request.method === 'GET') {
        const hash = decodeURIComponent(getMatch[1]);
        return await handleGetLabel(hash, env, corsHeaders);
      }

      // DELETE /labels/{hash} - Delete a label
      if (getMatch && request.method === 'DELETE') {
        const hash = decodeURIComponent(getMatch[1]);
        return await handleDeleteLabel(hash, env, corsHeaders);
      }

      return jsonResponse({ error: 'Not found' }, corsHeaders, 404);
    } catch (err) {
      console.error('[HashLabels] Error:', err);
      return jsonResponse({ error: 'Internal server error' }, corsHeaders, 500);
    }
  },
};

/**
 * POST /labels - Create or update a label.
 */
async function handleCreateLabel(
  request: Request,
  env: HashLabelsEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, corsHeaders, 400);
  }

  // Validate request
  const validationError = validateLabelRequest(body);
  if (validationError) {
    return jsonResponse({ error: validationError }, corsHeaders, 400);
  }

  const req = body as LabelRequest;
  const now = Date.now();

  // Check if label already exists
  const key = getLabelKey(req.dom_kit_hash);
  const existing = await env.HASH_LABELS_KV.get(key, 'json') as HashLabel | null;

  const label: HashLabel = {
    dom_kit_hash: req.dom_kit_hash,
    label: req.label,
    analyst: req.analyst,
    notes: req.notes,
    created_at: existing?.created_at ?? now,
    updated_at: now,
  };

  // Store in KV
  await env.HASH_LABELS_KV.put(key, JSON.stringify(label));

  // Also store in a secondary index by label type for filtering
  await updateLabelIndex(env, label, existing);

  const status = existing ? 'updated' : 'created';
  console.log(`[HashLabels] Label ${status}: ${req.dom_kit_hash.slice(0, 20)}... => ${req.label}`);

  return jsonResponse({ status, label }, corsHeaders, existing ? 200 : 201);
}

/**
 * GET /labels/{hash} - Get a specific label.
 */
async function handleGetLabel(
  hash: string,
  env: HashLabelsEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (!HASH_PATTERN.test(hash)) {
    return jsonResponse({ error: 'Invalid hash format' }, corsHeaders, 400);
  }

  const key = getLabelKey(hash);
  const label = await env.HASH_LABELS_KV.get(key, 'json') as HashLabel | null;

  if (!label) {
    return jsonResponse({ status: 'not_found' }, corsHeaders, 404);
  }

  return jsonResponse({ status: 'found', label }, corsHeaders);
}

/**
 * DELETE /labels/{hash} - Delete a label.
 */
async function handleDeleteLabel(
  hash: string,
  env: HashLabelsEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (!HASH_PATTERN.test(hash)) {
    return jsonResponse({ error: 'Invalid hash format' }, corsHeaders, 400);
  }

  const key = getLabelKey(hash);
  const existing = await env.HASH_LABELS_KV.get(key, 'json') as HashLabel | null;

  if (!existing) {
    return jsonResponse({ status: 'not_found' }, corsHeaders, 404);
  }

  // Delete from main storage
  await env.HASH_LABELS_KV.delete(key);

  // Remove from index
  await removeFromLabelIndex(env, existing);

  console.log(`[HashLabels] Label deleted: ${hash.slice(0, 20)}...`);

  return jsonResponse({ status: 'deleted' }, corsHeaders);
}

/**
 * GET /labels - List labels with optional filters.
 */
async function handleListLabels(
  params: URLSearchParams,
  env: HashLabelsEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const labelFilter = params.get('label') as HashLabelType | null;
  const analystFilter = params.get('analyst');
  const limit = Math.min(parseInt(params.get('limit') ?? '100', 10), 1000);
  const cursor = params.get('cursor') ?? undefined;

  // If filtering by label type, use the index
  let prefix = 'label:';
  if (labelFilter && VALID_LABELS.includes(labelFilter)) {
    prefix = `idx:${labelFilter}:`;
  }

  const listed = await env.HASH_LABELS_KV.list({
    prefix,
    limit: limit + 1, // +1 to check for more
    cursor,
  });

  const labels: HashLabel[] = [];
  for (const key of listed.keys) {
    // Skip index entries when listing all
    if (key.name.startsWith('idx:')) continue;

    const label = await env.HASH_LABELS_KV.get(key.name, 'json') as HashLabel | null;
    if (label) {
      // Apply analyst filter if specified
      if (analystFilter && label.analyst !== analystFilter) continue;
      labels.push(label);
      if (labels.length >= limit) break;
    }
  }

  // If using label index, fetch the actual labels
  if (labelFilter) {
    labels.length = 0;
    for (const key of listed.keys) {
      if (labels.length >= limit) break;
      // Index key format: idx:{label}:{hash}
      const hash = key.name.replace(`idx:${labelFilter}:`, '');
      const labelKey = getLabelKey(hash);
      const label = await env.HASH_LABELS_KV.get(labelKey, 'json') as HashLabel | null;
      if (label) {
        if (analystFilter && label.analyst !== analystFilter) continue;
        labels.push(label);
      }
    }
  }

  return jsonResponse(
    {
      labels,
      cursor: listed.list_complete ? undefined : listed.cursor,
      has_more: !listed.list_complete,
    },
    corsHeaders
  );
}

/**
 * Validate label request payload.
 */
function validateLabelRequest(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) {
    return 'Request body must be an object';
  }

  const req = body as Record<string, unknown>;

  // Validate dom_kit_hash
  if (typeof req.dom_kit_hash !== 'string') {
    return 'dom_kit_hash must be a string';
  }
  if (!HASH_PATTERN.test(req.dom_kit_hash)) {
    return 'dom_kit_hash must be sha256: followed by 64 hex characters';
  }

  // Validate label
  if (!VALID_LABELS.includes(req.label as HashLabelType)) {
    return `label must be one of: ${VALID_LABELS.join(', ')}`;
  }

  // Validate optional fields
  if (req.analyst !== undefined && typeof req.analyst !== 'string') {
    return 'analyst must be a string';
  }
  if (req.notes !== undefined && typeof req.notes !== 'string') {
    return 'notes must be a string';
  }

  // Limit notes length
  if (req.notes && (req.notes as string).length > 10000) {
    return 'notes must be 10000 characters or less';
  }

  return null;
}

/**
 * Get KV key for a label.
 */
function getLabelKey(hash: string): string {
  return `label:${hash}`;
}

/**
 * Update the label type index.
 */
async function updateLabelIndex(
  env: HashLabelsEnv,
  label: HashLabel,
  existing: HashLabel | null
): Promise<void> {
  // Remove from old index if label type changed
  if (existing && existing.label !== label.label) {
    const oldIndexKey = `idx:${existing.label}:${existing.dom_kit_hash}`;
    await env.HASH_LABELS_KV.delete(oldIndexKey);
  }

  // Add to new index
  const indexKey = `idx:${label.label}:${label.dom_kit_hash}`;
  await env.HASH_LABELS_KV.put(indexKey, '1'); // Value doesn't matter, just existence
}

/**
 * Remove from label type index.
 */
async function removeFromLabelIndex(env: HashLabelsEnv, label: HashLabel): Promise<void> {
  const indexKey = `idx:${label.label}:${label.dom_kit_hash}`;
  await env.HASH_LABELS_KV.delete(indexKey);
}

/**
 * Return a JSON response.
 */
function jsonResponse(
  data: unknown,
  corsHeaders: Record<string, string>,
  status: number = 200
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}
