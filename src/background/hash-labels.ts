/**
 * Hash Labels Client API
 *
 * Client-side functions for interacting with the hash labels service.
 * Allows analysts to attach TP/FP labels to DOM kit hashes.
 *
 * IMPORTANT: Labels do NOT trigger automatic enforcement actions.
 * They are for incident review and research ONLY.
 *
 * Reference: Issue #205
 */

import type {
  HashLabel,
  HashLabelType,
  LabelRequest,
  LabelResponse,
  LabelListQuery,
  LabelListResponse,
} from '../types/hash-labels';

// Re-export types for convenience
export type { HashLabel, HashLabelType, LabelRequest, LabelResponse, LabelListQuery, LabelListResponse };

// ============ Configuration ============

const DEFAULT_TIMEOUT_MS = 10000;
const _LABELS_ENDPOINT_KEY = 'browserdefense_hash_labels_endpoint';

/**
 * Configuration for the hash labels client.
 */
export interface HashLabelsConfig {
  /** Server endpoint URL for hash labels API */
  endpoint: string;
  /** Request timeout in milliseconds */
  timeoutMs?: number;
}

/**
 * Get hash labels configuration from storage.
 */
export async function getHashLabelsConfig(): Promise<HashLabelsConfig | null> {
  const { browserdefense_config } = await chrome.storage.local.get('browserdefense_config');

  if (!browserdefense_config?.hash_labels_endpoint) {
    return null;
  }

  return {
    endpoint: browserdefense_config.hash_labels_endpoint,
    timeoutMs: browserdefense_config.hash_labels_timeout_ms ?? DEFAULT_TIMEOUT_MS,
  };
}

// ============ API Functions ============

/**
 * Create or update a label for a DOM kit hash.
 *
 * @param request - Label request with hash, label type, and optional metadata
 * @param config - API configuration (or uses stored config if not provided)
 * @returns Label response with created/updated status
 */
export async function setLabel(
  request: LabelRequest,
  config?: HashLabelsConfig
): Promise<LabelResponse> {
  const cfg = config ?? (await getHashLabelsConfig());
  if (!cfg) {
    throw new Error('Hash labels endpoint not configured');
  }

  // Validate hash format
  if (!/^sha256:[a-f0-9]{64}$/i.test(request.dom_kit_hash)) {
    throw new Error('Invalid dom_kit_hash format');
  }

  // Validate label type
  if (!['TP', 'FP', 'UNKNOWN'].includes(request.label)) {
    throw new Error('Invalid label type');
  }

  const response = await fetch(`${cfg.endpoint}/labels`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
    signal: AbortSignal.timeout(cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' })) as { error?: string };
    throw new Error(`Failed to set label: ${errorData.error || response.statusText}`);
  }

  return response.json();
}

/**
 * Get the label for a specific DOM kit hash.
 *
 * @param hash - DOM kit hash (format: sha256:xxx)
 * @param config - API configuration (or uses stored config if not provided)
 * @returns Label response with found/not_found status
 */
export async function getLabel(
  hash: string,
  config?: HashLabelsConfig
): Promise<LabelResponse> {
  const cfg = config ?? (await getHashLabelsConfig());
  if (!cfg) {
    throw new Error('Hash labels endpoint not configured');
  }

  // Validate hash format
  if (!/^sha256:[a-f0-9]{64}$/i.test(hash)) {
    throw new Error('Invalid dom_kit_hash format');
  }

  const encodedHash = encodeURIComponent(hash);
  const response = await fetch(`${cfg.endpoint}/labels/${encodedHash}`, {
    method: 'GET',
    signal: AbortSignal.timeout(cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  });

  if (response.status === 404) {
    return { status: 'not_found' };
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' })) as { error?: string };
    throw new Error(`Failed to get label: ${errorData.error || response.statusText}`);
  }

  return response.json();
}

/**
 * Delete a label for a DOM kit hash.
 *
 * @param hash - DOM kit hash (format: sha256:xxx)
 * @param config - API configuration (or uses stored config if not provided)
 * @returns Label response with deleted/not_found status
 */
export async function deleteLabel(
  hash: string,
  config?: HashLabelsConfig
): Promise<LabelResponse> {
  const cfg = config ?? (await getHashLabelsConfig());
  if (!cfg) {
    throw new Error('Hash labels endpoint not configured');
  }

  // Validate hash format
  if (!/^sha256:[a-f0-9]{64}$/i.test(hash)) {
    throw new Error('Invalid dom_kit_hash format');
  }

  const encodedHash = encodeURIComponent(hash);
  const response = await fetch(`${cfg.endpoint}/labels/${encodedHash}`, {
    method: 'DELETE',
    signal: AbortSignal.timeout(cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  });

  if (response.status === 404) {
    return { status: 'not_found' };
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' })) as { error?: string };
    throw new Error(`Failed to delete label: ${errorData.error || response.statusText}`);
  }

  return response.json();
}

/**
 * List labels with optional filters.
 *
 * @param query - Optional filters (label type, analyst, limit, cursor)
 * @param config - API configuration (or uses stored config if not provided)
 * @returns List of labels with pagination info
 */
export async function listLabels(
  query?: LabelListQuery,
  config?: HashLabelsConfig
): Promise<LabelListResponse> {
  const cfg = config ?? (await getHashLabelsConfig());
  if (!cfg) {
    throw new Error('Hash labels endpoint not configured');
  }

  const params = new URLSearchParams();
  if (query?.label) params.set('label', query.label);
  if (query?.analyst) params.set('analyst', query.analyst);
  if (query?.limit) params.set('limit', String(query.limit));
  if (query?.cursor) params.set('cursor', query.cursor);

  const url = `${cfg.endpoint}/labels${params.toString() ? '?' + params.toString() : ''}`;
  const response = await fetch(url, {
    method: 'GET',
    signal: AbortSignal.timeout(cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' })) as { error?: string };
    throw new Error(`Failed to list labels: ${errorData.error || response.statusText}`);
  }

  return response.json();
}

// ============ Convenience Functions ============

/**
 * Mark a DOM kit hash as True Positive.
 *
 * @param hash - DOM kit hash (format: sha256:xxx)
 * @param analyst - Analyst identifier
 * @param notes - Optional notes
 */
export async function markAsTP(
  hash: string,
  analyst?: string,
  notes?: string
): Promise<LabelResponse> {
  return setLabel({
    dom_kit_hash: hash,
    label: 'TP',
    analyst,
    notes,
  });
}

/**
 * Mark a DOM kit hash as False Positive.
 *
 * @param hash - DOM kit hash (format: sha256:xxx)
 * @param analyst - Analyst identifier
 * @param notes - Optional notes
 */
export async function markAsFP(
  hash: string,
  analyst?: string,
  notes?: string
): Promise<LabelResponse> {
  return setLabel({
    dom_kit_hash: hash,
    label: 'FP',
    analyst,
    notes,
  });
}

/**
 * Get all True Positive labels.
 *
 * @param limit - Maximum number of results (default 100)
 */
export async function getTruePositives(limit?: number): Promise<LabelListResponse> {
  return listLabels({ label: 'TP', limit });
}

/**
 * Get all False Positive labels.
 *
 * @param limit - Maximum number of results (default 100)
 */
export async function getFalsePositives(limit?: number): Promise<LabelListResponse> {
  return listLabels({ label: 'FP', limit });
}

// ============ Local Cache (Optional) ============

const LOCAL_LABELS_CACHE_KEY = 'browserdefense_labels_cache';
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface _LabelCache {
  labels: Map<string, HashLabel>;
  lastUpdated: number;
}

/**
 * Get cached labels from local storage.
 * Returns null if cache is stale or doesn't exist.
 */
export async function getCachedLabels(): Promise<Map<string, HashLabel> | null> {
  const result = await chrome.storage.local.get(LOCAL_LABELS_CACHE_KEY);
  const cache = result[LOCAL_LABELS_CACHE_KEY] as { entries: [string, HashLabel][]; lastUpdated: number } | undefined;

  if (!cache) return null;
  if (Date.now() - cache.lastUpdated > CACHE_TTL_MS) return null;

  return new Map(cache.entries);
}

/**
 * Update the local labels cache.
 */
export async function updateLabelsCache(labels: HashLabel[]): Promise<void> {
  const entries: [string, HashLabel][] = labels.map((l) => [l.dom_kit_hash, l]);
  await chrome.storage.local.set({
    [LOCAL_LABELS_CACHE_KEY]: {
      entries,
      lastUpdated: Date.now(),
    },
  });
}

/**
 * Clear the local labels cache.
 */
export async function clearLabelsCache(): Promise<void> {
  await chrome.storage.local.remove(LOCAL_LABELS_CACHE_KEY);
}
