/**
 * Confidence Scoring Module
 *
 * Calculates adjusted confidence scores for DOM kit fingerprints
 * based on analyst TP/FP labels from Issue #205.
 *
 * IMPORTANT: Analyst labels affect CONFIDENCE SCORES ONLY.
 * They do NOT trigger auto-blocking or change enforcement actions.
 *
 * Confidence flow:
 *   Server confidence (0-100)
 *     + TP labels (boost)
 *     - FP labels (penalty)
 *   = Adjusted confidence (0-100)
 *
 * Reference: Issue #165
 */

import type { HashLabel } from '../types/hash-labels';
import type {
  ConfidenceScore,
  ConfidenceConfig,
  LabelBreakdown,
  LabelWithConfidenceImpact,
  ConfidenceEnhancedResponse,
} from '../types/confidence';
import {
  DEFAULT_CONFIDENCE_CONFIG,
  getLabelImpact,
  clamp,
} from '../types/confidence';
import type { FingerprintResponse } from './fingerprint-uplink';
import { getLabel, listLabels, type HashLabelsConfig } from './hash-labels';

// Re-export types for convenience
export type {
  ConfidenceScore,
  ConfidenceConfig,
  LabelBreakdown,
  LabelWithConfidenceImpact,
  ConfidenceEnhancedResponse,
};
export { DEFAULT_CONFIDENCE_CONFIG };

// ============ Core Confidence Calculation ============

/**
 * Calculate confidence score with analyst label adjustments.
 *
 * @param baseConfidence - Server-provided confidence (0-100)
 * @param labels - Analyst labels for this fingerprint
 * @param config - Confidence calculation config
 * @returns Confidence score with breakdown
 */
export function calculateConfidenceScore(
  baseConfidence: number,
  labels: HashLabel[],
  config: ConfidenceConfig = DEFAULT_CONFIDENCE_CONFIG
): ConfidenceScore {
  // Count labels by type
  const breakdown: LabelBreakdown = {
    tp: 0,
    fp: 0,
    unknown: 0,
  };

  let totalAdjustment = 0;
  const labelsWithImpact: LabelWithConfidenceImpact[] = [];

  for (const label of labels) {
    const impact = getLabelImpact(label.label, config);
    totalAdjustment += impact;

    // Track breakdown
    switch (label.label) {
      case 'TP':
        breakdown.tp++;
        break;
      case 'FP':
        breakdown.fp++;
        break;
      case 'UNKNOWN':
        breakdown.unknown++;
        break;
    }

    labelsWithImpact.push({
      dom_kit_hash: label.dom_kit_hash,
      label: label.label,
      analyst: label.analyst,
      confidenceImpact: impact,
      created_at: label.created_at,
    });
  }

  // Clamp total adjustment to max
  const clampedAdjustment = clamp(
    totalAdjustment,
    -config.maxAdjustment,
    config.maxAdjustment
  );

  // Calculate final confidence
  const finalConfidence = clamp(
    baseConfidence + clampedAdjustment,
    config.minConfidence,
    config.maxConfidence
  );

  return {
    baseConfidence,
    labelAdjustment: clampedAdjustment,
    finalConfidence: Math.round(finalConfidence),
    labelCount: labels.length,
    labelBreakdown: breakdown,
    hasAnalystFeedback: labels.length > 0,
  };
}

/**
 * Calculate confidence adjustment from label counts.
 *
 * This is a simplified version that works with counts instead of full labels.
 *
 * @param tpCount - Number of True Positive labels
 * @param fpCount - Number of False Positive labels
 * @param config - Confidence calculation config
 * @returns Net adjustment value
 */
export function calculateAdjustmentFromCounts(
  tpCount: number,
  fpCount: number,
  config: ConfidenceConfig = DEFAULT_CONFIDENCE_CONFIG
): number {
  const rawAdjustment = (tpCount * config.tpBoost) + (fpCount * config.fpPenalty);
  return clamp(rawAdjustment, -config.maxAdjustment, config.maxAdjustment);
}

// ============ Integration with Hash Labels API ============

/**
 * Get confidence-enhanced fingerprint response.
 *
 * Fetches analyst labels for the fingerprint hash and calculates
 * adjusted confidence score. The action field is NOT modified.
 *
 * @param hash - DOM kit hash (hex string without sha256: prefix)
 * @param serverResponse - Original server response
 * @param labelsConfig - Hash labels API config (optional)
 * @returns Enhanced response with adjusted confidence
 */
export async function getConfidenceEnhancedResponse(
  hash: string,
  serverResponse: FingerprintResponse,
  labelsConfig?: HashLabelsConfig
): Promise<ConfidenceEnhancedResponse> {
  // Format hash for label lookup (add sha256: prefix if not present)
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;

  // Fetch label for this hash
  let labels: HashLabel[] = [];
  try {
    const labelResponse = await getLabel(formattedHash, labelsConfig);
    if (labelResponse.status === 'found' && labelResponse.label) {
      labels = [labelResponse.label];
    }
  } catch (err) {
    // Label fetch failed, continue with base confidence
    console.warn('[BrowserDefense] Failed to fetch label for confidence:', (err as Error).message);
  }

  // Calculate adjusted confidence
  const confidenceScore = calculateConfidenceScore(serverResponse.confidence, labels);

  // Build applied labels list
  const appliedLabels: LabelWithConfidenceImpact[] = labels.map((label) => ({
    dom_kit_hash: label.dom_kit_hash,
    label: label.label,
    analyst: label.analyst,
    confidenceImpact: getLabelImpact(label.label),
    created_at: label.created_at,
  }));

  return {
    hash: formattedHash,
    serverConfidence: serverResponse.confidence,
    adjustedConfidence: confidenceScore.finalConfidence,
    confidenceScore,
    kitId: serverResponse.kitId,
    // IMPORTANT: Action is NOT modified by analyst labels
    // This ensures no auto-blocking from label feedback
    action: serverResponse.action,
    isNovel: serverResponse.isNovel,
    occurrenceCount: serverResponse.occurrenceCount,
    appliedLabels,
  };
}

/**
 * Batch calculate confidence for multiple hashes.
 *
 * Efficiently fetches labels for multiple hashes in one call
 * and calculates adjusted confidence for each.
 *
 * @param hashes - Array of DOM kit hashes (hex strings)
 * @param serverConfidences - Map of hash to server confidence
 * @param labelsConfig - Hash labels API config (optional)
 * @returns Map of hash to confidence score
 */
export async function batchCalculateConfidence(
  hashes: string[],
  serverConfidences: Map<string, number>,
  labelsConfig?: HashLabelsConfig
): Promise<Map<string, ConfidenceScore>> {
  const results = new Map<string, ConfidenceScore>();

  // Fetch all TP and FP labels
  let allLabels: HashLabel[] = [];
  try {
    const [tpResponse, fpResponse] = await Promise.all([
      listLabels({ label: 'TP', limit: 1000 }, labelsConfig),
      listLabels({ label: 'FP', limit: 1000 }, labelsConfig),
    ]);
    allLabels = [...tpResponse.labels, ...fpResponse.labels];
  } catch (err) {
    console.warn('[BrowserDefense] Failed to fetch labels for batch confidence:', (err as Error).message);
  }

  // Index labels by hash
  const labelsByHash = new Map<string, HashLabel[]>();
  for (const label of allLabels) {
    const existing = labelsByHash.get(label.dom_kit_hash) ?? [];
    existing.push(label);
    labelsByHash.set(label.dom_kit_hash, existing);
  }

  // Calculate confidence for each hash
  for (const hash of hashes) {
    const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;
    const baseConfidence = serverConfidences.get(hash) ?? serverConfidences.get(formattedHash) ?? 50;
    const labels = labelsByHash.get(formattedHash) ?? [];

    const score = calculateConfidenceScore(baseConfidence, labels);
    results.set(formattedHash, score);
  }

  return results;
}

// ============ Confidence Thresholds ============

/**
 * Confidence threshold levels.
 * These are informational only - they do NOT determine enforcement.
 */
export const CONFIDENCE_THRESHOLDS = {
  /** Very high confidence - likely malicious */
  VERY_HIGH: 85,
  /** High confidence - suspicious */
  HIGH: 70,
  /** Medium confidence - needs review */
  MEDIUM: 50,
  /** Low confidence - probably benign */
  LOW: 30,
} as const;

/**
 * Get confidence level description.
 *
 * @param confidence - Confidence score (0-100)
 * @returns Human-readable level description
 */
export function getConfidenceLevel(confidence: number): string {
  if (confidence >= CONFIDENCE_THRESHOLDS.VERY_HIGH) {
    return 'Very High';
  } else if (confidence >= CONFIDENCE_THRESHOLDS.HIGH) {
    return 'High';
  } else if (confidence >= CONFIDENCE_THRESHOLDS.MEDIUM) {
    return 'Medium';
  } else if (confidence >= CONFIDENCE_THRESHOLDS.LOW) {
    return 'Low';
  } else {
    return 'Very Low';
  }
}

/**
 * Check if confidence meets a threshold.
 *
 * @param confidence - Confidence score (0-100)
 * @param threshold - Threshold to check against
 * @returns true if confidence meets or exceeds threshold
 */
export function meetsThreshold(
  confidence: number,
  threshold: number
): boolean {
  return confidence >= threshold;
}

// ============ Stats & Reporting ============

/**
 * Get aggregate statistics for confidence scores.
 *
 * @param scores - Array of confidence scores
 * @returns Aggregate statistics
 */
export function getConfidenceStats(scores: ConfidenceScore[]): {
  count: number;
  avgBaseConfidence: number;
  avgFinalConfidence: number;
  avgAdjustment: number;
  withFeedback: number;
  withoutFeedback: number;
  totalTpLabels: number;
  totalFpLabels: number;
} {
  if (scores.length === 0) {
    return {
      count: 0,
      avgBaseConfidence: 0,
      avgFinalConfidence: 0,
      avgAdjustment: 0,
      withFeedback: 0,
      withoutFeedback: 0,
      totalTpLabels: 0,
      totalFpLabels: 0,
    };
  }

  const sumBase = scores.reduce((sum, s) => sum + s.baseConfidence, 0);
  const sumFinal = scores.reduce((sum, s) => sum + s.finalConfidence, 0);
  const sumAdjustment = scores.reduce((sum, s) => sum + s.labelAdjustment, 0);
  const withFeedback = scores.filter((s) => s.hasAnalystFeedback).length;
  const totalTp = scores.reduce((sum, s) => sum + s.labelBreakdown.tp, 0);
  const totalFp = scores.reduce((sum, s) => sum + s.labelBreakdown.fp, 0);

  return {
    count: scores.length,
    avgBaseConfidence: Math.round(sumBase / scores.length),
    avgFinalConfidence: Math.round(sumFinal / scores.length),
    avgAdjustment: Math.round(sumAdjustment / scores.length),
    withFeedback,
    withoutFeedback: scores.length - withFeedback,
    totalTpLabels: totalTp,
    totalFpLabels: totalFp,
  };
}
