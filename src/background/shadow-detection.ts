/**
 * Shadow Detection Module
 *
 * Detects and logs new DOM kit fingerprints without blocking until
 * confidence threshold is met. This is "alert-only" mode that requires
 * analyst review before any enforcement action.
 *
 * Purpose:
 * - Prevent false positives by not auto-blocking uncertain detections
 * - Allow analysts to review novel kit fingerprints before enforcement
 * - Build confidence through analyst feedback (TP/FP labels)
 *
 * Flow:
 * 1. Fingerprint response received with confidence score
 * 2. If novel + low confidence, log as shadow detection (no block)
 * 3. Send alert to analysts if configured
 * 4. Analyst reviews and promotes to blocking or dismisses
 *
 * Reference: Issue #171
 */

import type { FingerprintResponse } from './fingerprint-uplink';
import type { ConfidenceScore } from '../types/confidence';
import type {
  ShadowDetection,
  ShadowDetectionConfig,
  ShadowDetectionResult,
  ShadowDetectionQuery,
  ShadowDetectionListResponse,
  ShadowDetectionStats,
  ShadowDetectionStatus,
  ShadowDetectionAlert,
} from '../types/shadow-detection';
import {
  DEFAULT_SHADOW_DETECTION_CONFIG,
  generateDetectionId,
  generateAlertId,
  getSeverityFromConfidence,
} from '../types/shadow-detection';

// Re-export types for convenience
export type {
  ShadowDetection,
  ShadowDetectionConfig,
  ShadowDetectionResult,
  ShadowDetectionQuery,
  ShadowDetectionListResponse,
  ShadowDetectionStats,
  ShadowDetectionAlert,
};
export { DEFAULT_SHADOW_DETECTION_CONFIG };

// ============ Constants ============

const STORAGE_KEY = 'browserdefense_shadow_detections';
const CONFIG_KEY = 'browserdefense_shadow_detection_config';
const ALERT_COOLDOWN_KEY = 'browserdefense_shadow_alert_cooldowns';

// ============ Storage ============

interface StoredDetections {
  detections: ShadowDetection[];
  version: number;
}

/**
 * Load shadow detections from storage.
 */
async function loadDetections(): Promise<Map<string, ShadowDetection>> {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  const data = result[STORAGE_KEY] as StoredDetections | undefined;

  if (!data?.detections) {
    return new Map();
  }

  // Index by hash for fast lookup
  const map = new Map<string, ShadowDetection>();
  for (const detection of data.detections) {
    map.set(detection.dom_kit_hash, detection);
  }
  return map;
}

/**
 * Save shadow detections to storage.
 */
async function saveDetections(
  detections: Map<string, ShadowDetection>,
  config: ShadowDetectionConfig
): Promise<void> {
  // Convert to array and prune if needed
  let detectionsArray = Array.from(detections.values());

  // Prune oldest entries if over limit
  if (detectionsArray.length > config.maxDetections) {
    detectionsArray.sort((a, b) => a.detectedAt - b.detectedAt);
    detectionsArray = detectionsArray.slice(detectionsArray.length - config.maxDetections);
  }

  // Mark expired entries
  const now = Date.now();
  for (const detection of detectionsArray) {
    if (
      detection.status === 'pending' &&
      now - detection.detectedAt > config.detectionTTLMs
    ) {
      detection.status = 'expired';
    }
  }

  const stored: StoredDetections = {
    detections: detectionsArray,
    version: 1,
  };

  await chrome.storage.local.set({ [STORAGE_KEY]: stored });
}

/**
 * Load alert cooldowns from storage.
 * Maps hash -> last alert timestamp.
 */
async function loadAlertCooldowns(): Promise<Map<string, number>> {
  const result = await chrome.storage.local.get(ALERT_COOLDOWN_KEY);
  const data = result[ALERT_COOLDOWN_KEY] as [string, number][] | undefined;
  return new Map(data ?? []);
}

/**
 * Save alert cooldowns to storage.
 */
async function saveAlertCooldowns(cooldowns: Map<string, number>): Promise<void> {
  // Prune old cooldowns (older than 7 days)
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  for (const [hash, timestamp] of cooldowns) {
    if (timestamp < cutoff) {
      cooldowns.delete(hash);
    }
  }

  await chrome.storage.local.set({
    [ALERT_COOLDOWN_KEY]: Array.from(cooldowns.entries()),
  });
}

// ============ Configuration ============

/**
 * Get shadow detection configuration from storage.
 */
export async function getShadowDetectionConfig(): Promise<ShadowDetectionConfig> {
  const result = await chrome.storage.local.get(CONFIG_KEY);
  const stored = result[CONFIG_KEY] as Partial<ShadowDetectionConfig> | undefined;

  return {
    ...DEFAULT_SHADOW_DETECTION_CONFIG,
    ...stored,
  };
}

/**
 * Update shadow detection configuration.
 */
export async function updateShadowDetectionConfig(
  config: Partial<ShadowDetectionConfig>
): Promise<ShadowDetectionConfig> {
  const current = await getShadowDetectionConfig();
  const updated = { ...current, ...config };

  await chrome.storage.local.set({ [CONFIG_KEY]: updated });
  console.log('[BrowserDefense] Shadow detection config updated:', updated);

  return updated;
}

// ============ Core Processing ============

/**
 * Process a fingerprint response through shadow detection.
 *
 * This is the main entry point for shadow detection processing.
 * Call this after receiving a FingerprintResponse from the server.
 *
 * @param hash - DOM kit hash (hex string without sha256: prefix)
 * @param response - Server fingerprint response
 * @param confidenceScore - Optional confidence score with analyst adjustments
 * @returns Shadow detection result
 */
export async function processShadowDetection(
  hash: string,
  response: FingerprintResponse,
  confidenceScore?: ConfidenceScore
): Promise<ShadowDetectionResult> {
  const config = await getShadowDetectionConfig();

  // Format hash with prefix
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;

  // Check if shadow detection is enabled
  if (!config.enabled) {
    return {
      shadowMode: false,
      isNewDetection: false,
      reason: 'shadow_disabled',
      alertSent: false,
    };
  }

  // Use adjusted confidence if available, otherwise server confidence
  const effectiveConfidence = confidenceScore?.finalConfidence ?? response.confidence;

  // Check if confidence meets threshold (no shadow mode needed)
  if (effectiveConfidence >= config.confidenceThreshold) {
    return {
      shadowMode: false,
      isNewDetection: false,
      reason: 'confidence_above_threshold',
      alertSent: false,
    };
  }

  // Check if we only shadow novel fingerprints
  if (config.novelOnly && !response.isNovel) {
    return {
      shadowMode: false,
      isNewDetection: false,
      reason: 'not_novel',
      alertSent: false,
    };
  }

  // Load existing detections
  const detections = await loadDetections();
  const existing = detections.get(formattedHash);

  // Check if already promoted or dismissed
  if (existing) {
    if (existing.status === 'promoted') {
      return {
        shadowMode: false,
        isNewDetection: false,
        detection: existing,
        reason: 'already_promoted',
        alertSent: false,
      };
    }

    if (existing.status === 'dismissed') {
      return {
        shadowMode: true,
        isNewDetection: false,
        detection: existing,
        reason: 'already_dismissed',
        alertSent: false,
      };
    }

    // Update existing detection (repeat hit)
    existing.hitCount++;
    existing.lastSeenAt = Date.now();
    existing.serverConfidence = response.confidence;
    existing.adjustedConfidence = effectiveConfidence;
    existing.confidenceScore = confidenceScore;
    existing.occurrenceCount = response.occurrenceCount;

    await saveDetections(detections, config);

    // Check alert cooldown
    let alertSent = false;
    if (config.alertsEnabled) {
      alertSent = await sendAlertIfNeeded(existing, config);
    }

    return {
      shadowMode: true,
      isNewDetection: false,
      detection: existing,
      reason: 'repeat_shadow_hit',
      alertSent,
    };
  }

  // Create new shadow detection
  const detection: ShadowDetection = {
    id: generateDetectionId(),
    dom_kit_hash: formattedHash,
    serverConfidence: response.confidence,
    adjustedConfidence: effectiveConfidence,
    confidenceScore,
    kitId: response.kitId,
    isNovel: response.isNovel,
    occurrenceCount: response.occurrenceCount,
    status: 'pending',
    detectedAt: Date.now(),
    hitCount: 1,
    lastSeenAt: Date.now(),
  };

  detections.set(formattedHash, detection);
  await saveDetections(detections, config);

  // Send alert for new detection
  let alertSent = false;
  if (config.alertsEnabled) {
    alertSent = await sendAlertIfNeeded(detection, config);
  }

  console.log(
    `[BrowserDefense] Shadow detection: ${formattedHash.slice(0, 24)}... ` +
    `(confidence: ${effectiveConfidence}, novel: ${response.isNovel})`
  );

  return {
    shadowMode: true,
    isNewDetection: true,
    detection,
    reason: 'new_shadow_detection',
    alertSent,
  };
}

/**
 * Check if a fingerprint should be in shadow mode.
 *
 * Quick check that doesn't create/update detections.
 * Use this for fast decision-making in the blocking flow.
 *
 * @param hash - DOM kit hash
 * @param response - Server fingerprint response
 * @returns true if shadow mode should be applied (no blocking)
 */
export async function shouldShadowMode(
  hash: string,
  response: FingerprintResponse
): Promise<boolean> {
  const config = await getShadowDetectionConfig();

  if (!config.enabled) {
    return false;
  }

  // Check confidence threshold
  if (response.confidence >= config.confidenceThreshold) {
    return false;
  }

  // Check novel-only setting
  if (config.novelOnly && !response.isNovel) {
    return false;
  }

  // Check if already promoted
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;
  const detections = await loadDetections();
  const existing = detections.get(formattedHash);

  if (existing?.status === 'promoted') {
    return false; // Promoted detections are enforced
  }

  return true;
}

// ============ Alert Sending ============

/**
 * Send alert if cooldown has passed.
 */
async function sendAlertIfNeeded(
  detection: ShadowDetection,
  config: ShadowDetectionConfig
): Promise<boolean> {
  const cooldowns = await loadAlertCooldowns();
  const lastAlert = cooldowns.get(detection.dom_kit_hash);
  const now = Date.now();

  // Check cooldown
  if (lastAlert && now - lastAlert < config.alertIntervalMs) {
    return false; // Still in cooldown
  }

  // Build and send alert
  const alert: ShadowDetectionAlert = {
    type: 'shadow_detection',
    severity: getSeverityFromConfidence(detection.adjustedConfidence),
    title: `Shadow Detection: ${detection.isNovel ? 'Novel' : 'Known'} DOM Kit`,
    description: buildAlertDescription(detection),
    detection,
    timestamp: now,
    alertId: generateAlertId(),
  };

  try {
    await sendAlert(alert);

    // Update cooldown
    cooldowns.set(detection.dom_kit_hash, now);
    await saveAlertCooldowns(cooldowns);

    console.log(`[BrowserDefense] Shadow detection alert sent: ${alert.alertId}`);
    return true;
  } catch (err) {
    console.warn('[BrowserDefense] Failed to send shadow detection alert:', err);
    return false;
  }
}

/**
 * Build alert description.
 */
function buildAlertDescription(detection: ShadowDetection): string {
  const parts: string[] = [];

  parts.push(`DOM Kit Hash: ${detection.dom_kit_hash}`);
  parts.push(`Confidence: ${detection.adjustedConfidence}%`);

  if (detection.isNovel) {
    parts.push('Status: Novel fingerprint (first time seen globally)');
  }

  if (detection.kitId) {
    parts.push(`Known Kit: ${detection.kitId}`);
  }

  if (detection.occurrenceCount !== undefined) {
    parts.push(`Global Occurrences: ${detection.occurrenceCount}`);
  }

  parts.push(`Hit Count: ${detection.hitCount}`);
  parts.push('Action: Logged only (shadow mode) - requires analyst review');

  return parts.join('\n');
}

/**
 * Send alert via configured connectors.
 * This is a simplified implementation - in production, this would
 * integrate with the connector system.
 */
async function sendAlert(alert: ShadowDetectionAlert): Promise<void> {
  // Get alert configuration
  const { browserdefense_config } = await chrome.storage.local.get('browserdefense_config');

  if (!browserdefense_config?.shadow_detection_alert_endpoint) {
    // No endpoint configured, log to console only
    console.log('[BrowserDefense] Shadow detection alert (no endpoint configured):', alert);
    return;
  }

  // Send to configured endpoint
  const response = await fetch(browserdefense_config.shadow_detection_alert_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(alert),
    signal: AbortSignal.timeout(5000),
  });

  if (!response.ok) {
    throw new Error(`Alert endpoint returned ${response.status}`);
  }
}

// ============ Analyst Review Actions ============

/**
 * Promote a shadow detection to blocking.
 *
 * Called when an analyst confirms this is a true positive.
 * The hash will be added to the blocklist.
 *
 * @param hash - DOM kit hash
 * @param analyst - Analyst identifier
 * @param notes - Optional notes
 * @returns Updated detection or null if not found
 */
export async function promoteDetection(
  hash: string,
  analyst: string,
  notes?: string
): Promise<ShadowDetection | null> {
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;
  const config = await getShadowDetectionConfig();
  const detections = await loadDetections();
  const detection = detections.get(formattedHash);

  if (!detection) {
    return null;
  }

  detection.status = 'promoted';
  detection.reviewedAt = Date.now();
  detection.reviewedBy = analyst;
  detection.appliedLabel = 'TP';
  if (notes) {
    detection.notes = notes;
  }

  await saveDetections(detections, config);

  console.log(`[BrowserDefense] Shadow detection promoted: ${formattedHash} by ${analyst}`);
  return detection;
}

/**
 * Dismiss a shadow detection.
 *
 * Called when an analyst confirms this is a false positive.
 * The hash will be ignored in future detections.
 *
 * @param hash - DOM kit hash
 * @param analyst - Analyst identifier
 * @param notes - Optional notes
 * @returns Updated detection or null if not found
 */
export async function dismissDetection(
  hash: string,
  analyst: string,
  notes?: string
): Promise<ShadowDetection | null> {
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;
  const config = await getShadowDetectionConfig();
  const detections = await loadDetections();
  const detection = detections.get(formattedHash);

  if (!detection) {
    return null;
  }

  detection.status = 'dismissed';
  detection.reviewedAt = Date.now();
  detection.reviewedBy = analyst;
  detection.appliedLabel = 'FP';
  if (notes) {
    detection.notes = notes;
  }

  await saveDetections(detections, config);

  console.log(`[BrowserDefense] Shadow detection dismissed: ${formattedHash} by ${analyst}`);
  return detection;
}

/**
 * Get a single shadow detection by hash.
 */
export async function getDetection(hash: string): Promise<ShadowDetection | null> {
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;
  const detections = await loadDetections();
  return detections.get(formattedHash) ?? null;
}

/**
 * Delete a shadow detection.
 */
export async function deleteDetection(hash: string): Promise<boolean> {
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;
  const config = await getShadowDetectionConfig();
  const detections = await loadDetections();

  if (!detections.has(formattedHash)) {
    return false;
  }

  detections.delete(formattedHash);
  await saveDetections(detections, config);

  console.log(`[BrowserDefense] Shadow detection deleted: ${formattedHash}`);
  return true;
}

// ============ Querying ============

/**
 * List shadow detections with optional filtering.
 */
export async function listDetections(
  query: ShadowDetectionQuery = {}
): Promise<ShadowDetectionListResponse> {
  const detections = await loadDetections();
  let results = Array.from(detections.values());

  // Apply filters
  if (query.status) {
    results = results.filter((d) => d.status === query.status);
  }

  if (query.minConfidence !== undefined) {
    results = results.filter((d) => d.adjustedConfidence >= query.minConfidence!);
  }

  if (query.maxConfidence !== undefined) {
    results = results.filter((d) => d.adjustedConfidence <= query.maxConfidence!);
  }

  if (query.novelOnly) {
    results = results.filter((d) => d.isNovel);
  }

  if (query.minHitCount !== undefined) {
    results = results.filter((d) => d.hitCount >= query.minHitCount!);
  }

  if (query.detectedAfter !== undefined) {
    results = results.filter((d) => d.detectedAt >= query.detectedAfter!);
  }

  if (query.detectedBefore !== undefined) {
    results = results.filter((d) => d.detectedAt <= query.detectedBefore!);
  }

  // Sort
  const sortBy = query.sortBy ?? 'detectedAt';
  const sortDir = query.sortDir ?? 'desc';
  const sortMultiplier = sortDir === 'asc' ? 1 : -1;

  results.sort((a, b) => {
    let aVal: number;
    let bVal: number;

    switch (sortBy) {
      case 'lastSeenAt':
        aVal = a.lastSeenAt;
        bVal = b.lastSeenAt;
        break;
      case 'hitCount':
        aVal = a.hitCount;
        bVal = b.hitCount;
        break;
      case 'confidence':
        aVal = a.adjustedConfidence;
        bVal = b.adjustedConfidence;
        break;
      case 'detectedAt':
      default:
        aVal = a.detectedAt;
        bVal = b.detectedAt;
        break;
    }

    return (aVal - bVal) * sortMultiplier;
  });

  // Calculate total before pagination
  const total = results.length;

  // Apply pagination
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  results = results.slice(offset, offset + limit);

  return {
    detections: results,
    total,
    hasMore: offset + results.length < total,
  };
}

/**
 * Get shadow detection statistics.
 */
export async function getDetectionStats(): Promise<ShadowDetectionStats> {
  const detections = await loadDetections();
  const all = Array.from(detections.values());

  const byStatus: Record<ShadowDetectionStatus, number> = {
    pending: 0,
    promoted: 0,
    dismissed: 0,
    expired: 0,
  };

  let totalConfidence = 0;
  let pendingCount = 0;
  let totalHits = 0;
  let novelCount = 0;
  let oldestPending: number | undefined;

  for (const detection of all) {
    byStatus[detection.status]++;
    totalHits += detection.hitCount;

    if (detection.isNovel) {
      novelCount++;
    }

    if (detection.status === 'pending') {
      pendingCount++;
      totalConfidence += detection.adjustedConfidence;

      if (oldestPending === undefined || detection.detectedAt < oldestPending) {
        oldestPending = detection.detectedAt;
      }
    }
  }

  return {
    total: all.length,
    byStatus,
    pendingReview: byStatus.pending,
    promoted: byStatus.promoted,
    dismissed: byStatus.dismissed,
    expired: byStatus.expired,
    avgPendingConfidence: pendingCount > 0 ? Math.round(totalConfidence / pendingCount) : 0,
    totalHits,
    novelCount,
    oldestPending,
  };
}

// ============ Maintenance ============

/**
 * Clean up expired and old detections.
 * Should be called periodically (e.g., on service worker startup).
 */
export async function cleanupDetections(): Promise<{
  expired: number;
  pruned: number;
}> {
  const config = await getShadowDetectionConfig();
  const detections = await loadDetections();
  const now = Date.now();

  let expired = 0;
  let pruned = 0;

  // Mark expired pending detections
  for (const detection of detections.values()) {
    if (
      detection.status === 'pending' &&
      now - detection.detectedAt > config.detectionTTLMs
    ) {
      detection.status = 'expired';
      expired++;
    }
  }

  // Prune old expired/dismissed detections (keep for 7 days after expiry)
  const pruneCutoff = now - 7 * 24 * 60 * 60 * 1000;
  for (const [hash, detection] of detections) {
    if (
      (detection.status === 'expired' || detection.status === 'dismissed') &&
      detection.detectedAt < pruneCutoff
    ) {
      detections.delete(hash);
      pruned++;
    }
  }

  await saveDetections(detections, config);

  if (expired > 0 || pruned > 0) {
    console.log(`[BrowserDefense] Shadow detection cleanup: ${expired} expired, ${pruned} pruned`);
  }

  return { expired, pruned };
}

/**
 * Clear all shadow detections.
 * Useful for testing or reset.
 */
export async function clearAllDetections(): Promise<void> {
  await chrome.storage.local.remove([STORAGE_KEY, ALERT_COOLDOWN_KEY]);
  console.log('[BrowserDefense] All shadow detections cleared');
}

// ============ Exports for Testing ============

export {
  loadDetections as _loadDetections,
  saveDetections as _saveDetections,
  loadAlertCooldowns as _loadAlertCooldowns,
  saveAlertCooldowns as _saveAlertCooldowns,
  sendAlertIfNeeded as _sendAlertIfNeeded,
  buildAlertDescription as _buildAlertDescription,
};
