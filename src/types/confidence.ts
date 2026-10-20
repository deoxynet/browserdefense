/**
 * Confidence Score Types
 *
 * Types for confidence-based scoring of DOM kit fingerprints.
 * Analyst labels (TP/FP) affect confidence scores but do NOT trigger auto-blocking.
 *
 * Reference: Issue #165
 */

import type { HashLabelType } from './hash-labels';

/**
 * Confidence score with adjustment metadata.
 * Tracks base score, adjustments, and final score.
 */
export interface ConfidenceScore {
  /** Base confidence from server (0-100) */
  baseConfidence: number;
  /** Adjustment from analyst labels (-100 to +100) */
  labelAdjustment: number;
  /** Final confidence score (0-100, clamped) */
  finalConfidence: number;
  /** Number of analyst labels considered */
  labelCount: number;
  /** Breakdown by label type */
  labelBreakdown: LabelBreakdown;
  /** Whether score was adjusted by analyst feedback */
  hasAnalystFeedback: boolean;
}

/**
 * Breakdown of labels by type.
 */
export interface LabelBreakdown {
  /** Number of True Positive labels */
  tp: number;
  /** Number of False Positive labels */
  fp: number;
  /** Number of Unknown labels */
  unknown: number;
}

/**
 * Configuration for confidence calculation.
 */
export interface ConfidenceConfig {
  /** Points to add per TP label (default: 15) */
  tpBoost: number;
  /** Points to subtract per FP label (default: -25) */
  fpPenalty: number;
  /** Maximum total adjustment from labels (default: 50) */
  maxAdjustment: number;
  /** Minimum confidence floor (default: 0) */
  minConfidence: number;
  /** Maximum confidence ceiling (default: 100) */
  maxConfidence: number;
}

/**
 * Default confidence configuration.
 *
 * Design rationale:
 * - FP penalty is higher than TP boost (false positives are more costly to users)
 * - Max adjustment caps influence of labels to prevent gaming
 * - No auto-blocking: confidence only affects score, not enforcement
 */
export const DEFAULT_CONFIDENCE_CONFIG: ConfidenceConfig = {
  tpBoost: 15,      // Each TP label adds 15 points
  fpPenalty: -25,   // Each FP label subtracts 25 points
  maxAdjustment: 50, // Labels can adjust score by at most ±50 points
  minConfidence: 0,
  maxConfidence: 100,
};

/**
 * Analyst label with confidence impact.
 * Extends base label with scoring metadata.
 */
export interface LabelWithConfidenceImpact {
  /** DOM kit hash (format: sha256:xxx) */
  dom_kit_hash: string;
  /** Label classification */
  label: HashLabelType;
  /** Analyst identifier */
  analyst?: string;
  /** Impact on confidence score */
  confidenceImpact: number;
  /** When the label was created */
  created_at: number;
}

/**
 * Response from confidence-enhanced fingerprint lookup.
 */
export interface ConfidenceEnhancedResponse {
  /** DOM kit hash */
  hash: string;
  /** Original server confidence (0-100) */
  serverConfidence: number;
  /** Adjusted confidence with analyst feedback (0-100) */
  adjustedConfidence: number;
  /** Full confidence score breakdown */
  confidenceScore: ConfidenceScore;
  /** Known phishing kit ID if recognized */
  kitId?: string;
  /** Recommended action (NOT affected by confidence adjustment) */
  action: 'block' | 'shadow' | 'allow';
  /** Whether this is a novel fingerprint */
  isNovel: boolean;
  /** Global occurrence count */
  occurrenceCount?: number;
  /** Labels that affected the score */
  appliedLabels: LabelWithConfidenceImpact[];
}

/**
 * Calculate confidence impact for a label type.
 */
export function getLabelImpact(
  label: HashLabelType,
  config: ConfidenceConfig = DEFAULT_CONFIDENCE_CONFIG
): number {
  switch (label) {
    case 'TP':
      return config.tpBoost;
    case 'FP':
      return config.fpPenalty;
    case 'UNKNOWN':
      return 0;
  }
}

/**
 * Clamp a value between min and max.
 */
export function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}
