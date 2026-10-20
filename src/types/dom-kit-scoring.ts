/**
 * DOM Kit Confidence Scoring Types (Issue #170)
 *
 * Types for rules-based confidence scoring of DOM kit fingerprints.
 * Scores are computed from multiple factors:
 * - Global novelty (is hash new globally?)
 * - Local novelty (is hash new to this user?)
 * - Analyst labels (TP/FP feedback)
 * - Temporal burstiness (sudden spike in occurrences)
 *
 * IMPORTANT: Confidence scores are for PRIORITIZATION only.
 * They do NOT trigger auto-blocking or change enforcement actions.
 */

import type { HashLabel } from './hash-labels';

// ============ Scoring Factor Types ============

/**
 * Global novelty factor - is this hash new globally?
 */
export interface GlobalNoveltyFactor {
  /** Whether the hash is novel (first occurrence globally) */
  isNovel: boolean;
  /** Global occurrence count if available */
  occurrenceCount?: number;
}

/**
 * Local novelty factor - is this hash new to this user?
 */
export interface LocalNoveltyFactor {
  /** Whether this is the first time seeing this hash locally */
  firstSeenLocally: boolean;
  /** Local first seen timestamp (Unix ms) if available */
  localFirstSeen?: number;
  /** Number of times seen locally */
  localOccurrenceCount?: number;
}

/**
 * Analyst labels factor - TP/FP feedback.
 */
export interface AnalystLabelsFactor {
  /** True Positive label count */
  tpCount: number;
  /** False Positive label count */
  fpCount: number;
  /** Unknown label count */
  unknownCount: number;
  /** Full labels if available */
  labels?: HashLabel[];
}

/**
 * Temporal burstiness factor - sudden spike in occurrences.
 */
export interface TemporalBurstinessFactor {
  /** Occurrences in the last hour */
  recentOccurrences: number;
  /** Occurrences in the last 24 hours */
  dailyOccurrences: number;
  /** Whether a burst was detected */
  isBursty: boolean;
}

/**
 * All scoring factors combined.
 */
export interface ScoringFactors {
  globalNovelty?: GlobalNoveltyFactor;
  localNovelty?: LocalNoveltyFactor;
  analystLabels?: AnalystLabelsFactor;
  temporalBurstiness?: TemporalBurstinessFactor;
}

// ============ Score Adjustment Types ============

/**
 * Individual score adjustment with source tracking.
 */
export interface ScoreAdjustment {
  /** The factor that produced this adjustment */
  factor: 'globalNovelty' | 'localNovelty' | 'analystLabels' | 'temporalBurstiness';
  /** Adjustment value (+/-) */
  adjustment: number;
  /** Human-readable reason for the adjustment */
  reason: string;
}

/**
 * Complete confidence score with breakdown.
 */
export interface DOMKitConfidenceScore {
  /** Base confidence score (default: 50) */
  baseScore: number;
  /** Final computed confidence score (0-100) */
  finalScore: number;
  /** Individual adjustments that were applied */
  adjustments: ScoreAdjustment[];
  /** Total adjustment from all factors */
  totalAdjustment: number;
  /** The factors used in scoring */
  factors: ScoringFactors;
  /** When this score was computed (Unix ms) */
  computedAt: number;
}

// ============ Scoring Configuration ============

/**
 * Weights for each scoring factor.
 */
export interface ScoringWeights {
  /** Boost for globally novel hashes (default: +20) */
  globalNoveltyBoost: number;
  /** Boost for locally novel hashes (default: +15) */
  localNoveltyBoost: number;
  /** Boost per True Positive label (default: +15) */
  tpLabelBoost: number;
  /** Penalty per False Positive label (default: -25) */
  fpLabelPenalty: number;
  /** Maximum total adjustment from analyst labels (default: ±50) */
  maxLabelAdjustment: number;
  /** Boost per recent occurrence for burstiness (default: +3) */
  burstinessPerOccurrence: number;
  /** Maximum burstiness boost (default: +20) */
  maxBurstinessBoost: number;
  /** Threshold for recent occurrences to trigger burstiness (default: 3) */
  burstinessThreshold: number;
}

/**
 * Complete scoring configuration.
 */
export interface DOMKitScoringConfig {
  /** Base score when no factors present (default: 50) */
  baseScore: number;
  /** Minimum score (floor, default: 0) */
  minScore: number;
  /** Maximum score (ceiling, default: 100) */
  maxScore: number;
  /** Scoring weights for each factor */
  weights: ScoringWeights;
}

/**
 * Default scoring configuration.
 */
export const DEFAULT_SCORING_CONFIG: DOMKitScoringConfig = {
  baseScore: 50,
  minScore: 0,
  maxScore: 100,
  weights: {
    globalNoveltyBoost: 20,
    localNoveltyBoost: 15,
    tpLabelBoost: 15,
    fpLabelPenalty: -25,
    maxLabelAdjustment: 50,
    burstinessPerOccurrence: 3,
    maxBurstinessBoost: 20,
    burstinessThreshold: 3,
  },
};

// ============ Temporal Tracking Types ============

/**
 * Entry in the temporal occurrence tracker.
 */
export interface TemporalOccurrence {
  /** DOM kit hash (sha256:xxx format) */
  hash: string;
  /** Occurrence timestamp (Unix ms) */
  timestamp: number;
}

/**
 * Storage format for temporal tracking data.
 */
export interface TemporalTrackingData {
  /** List of recent occurrences (kept for 24h) */
  occurrences: TemporalOccurrence[];
  /** Last cleanup timestamp */
  lastCleanup: number;
}

// ============ Priority Level Types ============

/**
 * Priority levels for triaging.
 */
export type PriorityLevel = 'critical' | 'high' | 'medium' | 'low' | 'minimal';

/**
 * Priority thresholds.
 */
export const PRIORITY_THRESHOLDS = {
  CRITICAL: 85,
  HIGH: 70,
  MEDIUM: 50,
  LOW: 30,
  MINIMAL: 0,
} as const;
