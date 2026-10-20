/**
 * Shadow Telemetry for DOM Hash Events
 *
 * Sends hash-only telemetry for DOM kit hashes to server for aggregation and research.
 * This is "shadow mode" telemetry - it does NOT affect blocking or alerts.
 *
 * PRIVACY GUARANTEES (CRITICAL):
 * - NO URLs transmitted
 * - NO DOM content transmitted
 * - NO screenshots
 * - NO user data
 * - ONLY hash + timestamp + first_seen_locally flag
 *
 * Reference: Issue #202
 */

// ============ Types ============

/**
 * Shadow telemetry payload - MINIMAL by design.
 * Contains ONLY hash, timestamp, and first-seen flag.
 */
export interface ShadowTelemetryPayload {
  /** SHA-256 hash of DOM skeleton (prefixed with sha256:) */
  dom_kit_hash: string;
  /** Unix timestamp in milliseconds */
  event_ts: number;
  /** Whether this is the first time this hash was seen locally */
  first_seen_locally: boolean;
}

/**
 * Configuration for shadow telemetry.
 */
export interface ShadowTelemetryConfig {
  /** Server endpoint URL for shadow telemetry */
  endpoint: string;
  /** Request timeout in milliseconds */
  timeoutMs?: number;
  /** Whether shadow telemetry is enabled */
  enabled?: boolean;
  /** Whether LSH sketches should be included (Issue #200) */
  lshEnabled?: boolean;
}

/**
 * LSH sketches for shadow telemetry (Issue #200).
 * Used for kit variant discovery via structural similarity.
 */
export interface LSHSketchesForTelemetry {
  /** DOM layout structure sketch */
  dom_layout_lsh: string;
  /** Form structure sketch */
  form_structure_lsh: string;
  /** Script/resource structure sketch */
  script_structure_lsh: string;
}

/**
 * Extended shadow telemetry payload with LSH sketches.
 * Extends base payload with optional LSH fields.
 */
export interface ShadowTelemetryPayloadWithLSH extends ShadowTelemetryPayload {
  /** DOM layout LSH sketch (optional) */
  lsh_layout?: string;
  /** Form structure LSH sketch (optional) */
  lsh_form?: string;
  /** Script structure LSH sketch (optional) */
  lsh_script?: string;
}

// ============ Constants ============

const DEFAULT_TIMEOUT_MS = 5000;
const LOCAL_SEEN_CACHE_KEY = 'browserdefense_shadow_seen_hashes';
const MAX_SEEN_CACHE_SIZE = 50000;
const SEEN_CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// ============ Local Seen Cache ============

interface SeenHashEntry {
  /** First seen timestamp (Unix ms) */
  firstSeen: number;
  /** Last seen timestamp (Unix ms) */
  lastSeen: number;
}

/**
 * Get the local seen-hashes cache.
 */
async function getSeenCache(): Promise<Map<string, SeenHashEntry>> {
  const result = await chrome.storage.local.get(LOCAL_SEEN_CACHE_KEY);
  const data = result[LOCAL_SEEN_CACHE_KEY] as [string, SeenHashEntry][] | undefined;
  return new Map(data ?? []);
}

/**
 * Save the local seen-hashes cache.
 */
async function saveSeenCache(cache: Map<string, SeenHashEntry>): Promise<void> {
  // Prune old entries if cache is too large
  if (cache.size > MAX_SEEN_CACHE_SIZE) {
    const entries = Array.from(cache.entries());
    // Sort by last seen time, keep most recent
    entries.sort((a, b) => b[1].lastSeen - a[1].lastSeen);
    const toKeep = entries.slice(0, MAX_SEEN_CACHE_SIZE);
    cache.clear();
    for (const [key, value] of toKeep) {
      cache.set(key, value);
    }
  }

  // Prune expired entries
  const now = Date.now();
  for (const [key, value] of cache) {
    if (now - value.lastSeen > SEEN_CACHE_TTL_MS) {
      cache.delete(key);
    }
  }

  await chrome.storage.local.set({
    [LOCAL_SEEN_CACHE_KEY]: Array.from(cache.entries()),
  });
}

/**
 * Check if a hash has been seen locally before.
 * Also marks it as seen for future checks.
 *
 * @param hash - The DOM skeleton hash (without prefix)
 * @returns true if this is the first time seeing this hash locally
 */
export async function checkAndMarkFirstSeen(hash: string): Promise<boolean> {
  const cache = await getSeenCache();
  const now = Date.now();

  const existing = cache.get(hash);

  if (existing) {
    // Update last seen time
    existing.lastSeen = now;
    await saveSeenCache(cache);
    return false; // Not first seen
  }

  // First time seeing this hash
  cache.set(hash, {
    firstSeen: now,
    lastSeen: now,
  });
  await saveSeenCache(cache);
  return true;
}

// ============ Telemetry ============

/**
 * Send shadow telemetry for a DOM hash.
 *
 * PRIVACY: This function sends ONLY hash + timestamp + first_seen_locally.
 * It does NOT send URLs, DOM content, or any user data.
 *
 * @param hash - SHA-256 hash of DOM skeleton (hex string, no prefix)
 * @param config - Telemetry configuration
 * @returns true if telemetry was sent successfully, false otherwise
 */
export async function sendShadowTelemetry(
  hash: string,
  config: ShadowTelemetryConfig
): Promise<boolean> {
  // Check if this is first time seeing this hash locally
  const firstSeenLocally = await checkAndMarkFirstSeen(hash);

  const timestamp = Date.now();

  // Build minimal payload - ONLY hash, timestamp, and first_seen flag
  const payload: ShadowTelemetryPayload = {
    dom_kit_hash: `sha256:${hash}`,
    event_ts: timestamp,
    first_seen_locally: firstSeenLocally,
  };

  // Validate payload before sending (defense in depth)
  assertMinimalPayload(payload);

  try {
    const response = await fetch(config.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(config.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });

    if (!response.ok) {
      console.warn(`[BrowserDefense] Shadow telemetry failed: HTTP ${response.status}`);
      return false;
    }

    console.log(
      `[BrowserDefense] Shadow telemetry sent: ${hash.slice(0, 16)}... ` +
        `(first_seen_locally: ${firstSeenLocally})`
    );

    return true;
  } catch (err) {
    console.warn('[BrowserDefense] Shadow telemetry error:', (err as Error).message);
    return false;
  }
}

/**
 * Send shadow telemetry with LSH sketches for a DOM hash.
 *
 * PRIVACY: This function sends ONLY hash + timestamp + first_seen_locally + LSH sketches.
 * LSH sketches are non-reversible structural fingerprints, NOT content.
 *
 * @param hash - SHA-256 hash of DOM skeleton (hex string, no prefix)
 * @param config - Telemetry configuration
 * @param lshSketches - LSH sketches to include (optional)
 * @returns true if telemetry was sent successfully, false otherwise
 */
export async function sendShadowTelemetryWithLSH(
  hash: string,
  config: ShadowTelemetryConfig,
  lshSketches?: LSHSketchesForTelemetry
): Promise<boolean> {
  // Check if this is first time seeing this hash locally
  const firstSeenLocally = await checkAndMarkFirstSeen(hash);

  const timestamp = Date.now();

  // Build payload with optional LSH sketches
  const payload: ShadowTelemetryPayloadWithLSH = {
    dom_kit_hash: `sha256:${hash}`,
    event_ts: timestamp,
    first_seen_locally: firstSeenLocally,
  };

  // Add LSH sketches if enabled and provided
  if (config.lshEnabled && lshSketches) {
    payload.lsh_layout = lshSketches.dom_layout_lsh;
    payload.lsh_form = lshSketches.form_structure_lsh;
    payload.lsh_script = lshSketches.script_structure_lsh;
  }

  // Validate payload before sending (defense in depth)
  assertLSHPayload(payload);

  try {
    const response = await fetch(config.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(config.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });

    if (!response.ok) {
      console.warn(`[BrowserDefense] Shadow telemetry (LSH) failed: HTTP ${response.status}`);
      return false;
    }

    const lshInfo = config.lshEnabled && lshSketches ? ' +LSH' : '';
    console.log(
      `[BrowserDefense] Shadow telemetry sent: ${hash.slice(0, 16)}...${lshInfo} ` +
        `(first_seen_locally: ${firstSeenLocally})`
    );

    return true;
  } catch (err) {
    console.warn('[BrowserDefense] Shadow telemetry (LSH) error:', (err as Error).message);
    return false;
  }
}

/**
 * Assert that payload contains ONLY the expected fields.
 * This is a defense-in-depth check to ensure we never accidentally
 * send more data than intended.
 *
 * @throws Error if payload contains unexpected fields
 */
function assertMinimalPayload(payload: ShadowTelemetryPayload): void {
  const allowedKeys = new Set(['dom_kit_hash', 'event_ts', 'first_seen_locally']);
  const actualKeys = Object.keys(payload);

  for (const key of actualKeys) {
    if (!allowedKeys.has(key)) {
      throw new Error(
        `[BrowserDefense] PRIVACY VIOLATION: Shadow telemetry payload contains unexpected field: ${key}`
      );
    }
  }

  // Validate hash format (should be sha256: prefixed, followed by 64 hex chars)
  if (
    typeof payload.dom_kit_hash !== 'string' ||
    !/^sha256:[a-f0-9]{64}$/i.test(payload.dom_kit_hash)
  ) {
    throw new Error('[BrowserDefense] Invalid hash format in shadow telemetry payload');
  }

  // Validate timestamp (should be positive number)
  if (typeof payload.event_ts !== 'number' || payload.event_ts <= 0) {
    throw new Error('[BrowserDefense] Invalid timestamp in shadow telemetry payload');
  }

  // Validate first_seen_locally (should be boolean)
  if (typeof payload.first_seen_locally !== 'boolean') {
    throw new Error('[BrowserDefense] Invalid first_seen_locally in shadow telemetry payload');
  }
}

/**
 * Assert that LSH payload contains ONLY the expected fields.
 * Extends minimal payload validation with LSH fields.
 *
 * @throws Error if payload contains unexpected fields
 */
function assertLSHPayload(payload: ShadowTelemetryPayloadWithLSH): void {
  const allowedKeys = new Set([
    'dom_kit_hash',
    'event_ts',
    'first_seen_locally',
    'lsh_layout',
    'lsh_form',
    'lsh_script',
  ]);
  const actualKeys = Object.keys(payload);

  for (const key of actualKeys) {
    if (!allowedKeys.has(key)) {
      throw new Error(
        `[BrowserDefense] PRIVACY VIOLATION: Shadow telemetry LSH payload contains unexpected field: ${key}`
      );
    }
  }

  // Validate hash format (should be sha256: prefixed, followed by 64 hex chars)
  if (
    typeof payload.dom_kit_hash !== 'string' ||
    !/^sha256:[a-f0-9]{64}$/i.test(payload.dom_kit_hash)
  ) {
    throw new Error('[BrowserDefense] Invalid hash format in shadow telemetry LSH payload');
  }

  // Validate timestamp (should be positive number)
  if (typeof payload.event_ts !== 'number' || payload.event_ts <= 0) {
    throw new Error('[BrowserDefense] Invalid timestamp in shadow telemetry LSH payload');
  }

  // Validate first_seen_locally (should be boolean)
  if (typeof payload.first_seen_locally !== 'boolean') {
    throw new Error('[BrowserDefense] Invalid first_seen_locally in shadow telemetry LSH payload');
  }

  // Validate LSH sketch formats if present (512 hex chars = 64 hashes * 8 chars each)
  const lshPattern = /^[a-f0-9]{512}$/i;

  if (payload.lsh_layout !== undefined) {
    if (typeof payload.lsh_layout !== 'string' || !lshPattern.test(payload.lsh_layout)) {
      throw new Error('[BrowserDefense] Invalid lsh_layout format in shadow telemetry LSH payload');
    }
  }

  if (payload.lsh_form !== undefined) {
    if (typeof payload.lsh_form !== 'string' || !lshPattern.test(payload.lsh_form)) {
      throw new Error('[BrowserDefense] Invalid lsh_form format in shadow telemetry LSH payload');
    }
  }

  if (payload.lsh_script !== undefined) {
    if (typeof payload.lsh_script !== 'string' || !lshPattern.test(payload.lsh_script)) {
      throw new Error('[BrowserDefense] Invalid lsh_script format in shadow telemetry LSH payload');
    }
  }
}

// ============ Configuration ============

/**
 * Get shadow telemetry configuration from storage.
 */
export async function getShadowTelemetryConfig(): Promise<ShadowTelemetryConfig | null> {
  const { browserdefense_config } = await chrome.storage.local.get('browserdefense_config');

  // Check if shadow telemetry is explicitly enabled and has an endpoint
  if (!browserdefense_config?.shadow_telemetry_endpoint) {
    return null;
  }

  // Shadow telemetry must be explicitly enabled
  if (browserdefense_config.shadow_telemetry_enabled !== true) {
    return null;
  }

  return {
    endpoint: browserdefense_config.shadow_telemetry_endpoint,
    timeoutMs: browserdefense_config.shadow_telemetry_timeout_ms ?? DEFAULT_TIMEOUT_MS,
    enabled: true,
    lshEnabled: browserdefense_config.shadow_telemetry_lsh_enabled === true,
  };
}

// ============ Cache Management ============

/**
 * Clear the local seen-hashes cache.
 * Useful for testing or when privacy reset is needed.
 */
export async function clearSeenCache(): Promise<void> {
  await chrome.storage.local.remove(LOCAL_SEEN_CACHE_KEY);
  console.log('[BrowserDefense] Shadow telemetry seen cache cleared');
}

/**
 * Get seen-hashes cache statistics.
 */
export async function getSeenCacheStats(): Promise<{
  size: number;
  oldestEntry?: number;
  newestEntry?: number;
  firstSeenCount: number;
}> {
  const cache = await getSeenCache();
  const entries = Array.from(cache.values());

  const firstSeenTimes = entries.map((v) => v.firstSeen);
  const lastSeenTimes = entries.map((v) => v.lastSeen);

  return {
    size: cache.size,
    oldestEntry: firstSeenTimes.length > 0 ? Math.min(...firstSeenTimes) : undefined,
    newestEntry: lastSeenTimes.length > 0 ? Math.max(...lastSeenTimes) : undefined,
    firstSeenCount: entries.filter((v) => v.firstSeen === v.lastSeen).length,
  };
}

// ============ Exports for Testing ============

export {
  assertMinimalPayload as _assertMinimalPayload,
  assertLSHPayload as _assertLSHPayload,
  getSeenCache as _getSeenCache,
  saveSeenCache as _saveSeenCache,
};
