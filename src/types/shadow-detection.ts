/**
 * Shadow Detection Types
 *
 * Types for shadow detection mode - detecting and logging new DOM kits
 * without blocking until confidence threshold is met.
 *
 * Shadow mode is "alert-only" - it requires analyst review before
 * any enforcement action is taken. This prevents false positives.
 *
 * Reference: Issue #171
 */

import type { HashLabelType } from './hash-labels';
import type { ConfidenceScore } from './confidence';

/**
 * Shadow detection status.
 * - pending: Awaiting analyst review
 * - promoted: Analyst confirmed TP, moved to blocking
 * - dismissed: Analyst confirmed FP, dismissed
 * - expired: TTL exceeded without review
 */
export type ShadowDetectionStatus = 'pending' | 'promoted' | 'dismissed' | 'expired';

/**
 * A shadow detection record.
 * Represents a novel DOM kit fingerprint that was detected but not blocked.
 */
export interface ShadowDetection {
  /** Unique detection ID */
  id: string;
  /** DOM kit hash (format: sha256:xxx) */
  dom_kit_hash: string;
  /** Server-reported confidence score (0-100) */
  serverConfidence: number;
  /** Adjusted confidence with analyst labels (0-100) */
  adjustedConfidence: number;
  /** Full confidence score breakdown */
  confidenceScore?: ConfidenceScore;
  /** Known phishing kit ID if recognized */
  kitId?: string;
  /** Whether this was a novel fingerprint (first time seen globally) */
  isNovel: boolean;
  /** Global occurrence count at time of detection */
  occurrenceCount?: number;
  /** Current status */
  status: ShadowDetectionStatus;
  /** When the detection occurred (Unix timestamp ms) */
  detectedAt: number;
  /** When the detection was reviewed (Unix timestamp ms) */
  reviewedAt?: number;
  /** Analyst who reviewed (if reviewed) */
  reviewedBy?: string;
  /** Label applied after review */
  appliedLabel?: HashLabelType;
  /** Analyst notes */
  notes?: string;
  /** Number of times this hash was seen in shadow mode */
  hitCount: number;
  /** Last time this hash was seen (Unix timestamp ms) */
  lastSeenAt: number;
}

/**
 * Configuration for shadow detection mode.
 */
export interface ShadowDetectionConfig {
  /** Whether shadow detection is enabled */
  enabled: boolean;
  /**
   * Confidence threshold for shadow mode.
   * Novel fingerprints with confidence BELOW this threshold are shadow-logged.
   * Above this threshold, normal enforcement applies.
   * Default: 70 (matches CONFIDENCE_THRESHOLDS.HIGH)
   */
  confidenceThreshold: number;
  /**
   * Whether to apply shadow mode only to novel fingerprints.
   * If true, only isNovel=true fingerprints are shadow-logged.
   * If false, any fingerprint below threshold is shadow-logged.
   * Default: true
   */
  novelOnly: boolean;
  /**
   * Maximum number of shadow detections to store.
   * Oldest entries are pruned when limit is exceeded.
   * Default: 10000
   */
  maxDetections: number;
  /**
   * TTL for shadow detections in milliseconds.
   * Detections older than this are marked as expired.
   * Default: 30 days
   */
  detectionTTLMs: number;
  /**
   * Whether to send alerts for new shadow detections.
   * Alerts are sent via configured connectors.
   * Default: true
   */
  alertsEnabled: boolean;
  /**
   * Minimum interval between alerts for the same hash (ms).
   * Prevents alert fatigue for frequently-seen hashes.
   * Default: 1 hour
   */
  alertIntervalMs: number;
}

/**
 * Default shadow detection configuration.
 */
export const DEFAULT_SHADOW_DETECTION_CONFIG: ShadowDetectionConfig = {
  enabled: true,
  confidenceThreshold: 70,
  novelOnly: true,
  maxDetections: 10000,
  detectionTTLMs: 30 * 24 * 60 * 60 * 1000, // 30 days
  alertsEnabled: true,
  alertIntervalMs: 60 * 60 * 1000, // 1 hour
};

/**
 * Result of processing a fingerprint through shadow detection.
 */
export interface ShadowDetectionResult {
  /** Whether shadow mode was applied (detection logged, no block) */
  shadowMode: boolean;
  /** Whether this is a new shadow detection (vs. repeat hit) */
  isNewDetection: boolean;
  /** The shadow detection record (if shadow mode applied) */
  detection?: ShadowDetection;
  /** Reason for shadow mode (or why not applied) */
  reason: ShadowDetectionReason;
  /** Whether an alert was sent */
  alertSent: boolean;
}

/**
 * Reason codes for shadow detection decisions.
 */
export type ShadowDetectionReason =
  | 'shadow_disabled'           // Shadow mode is disabled
  | 'confidence_above_threshold' // Confidence meets threshold, normal enforcement
  | 'not_novel'                  // Not a novel fingerprint (and novelOnly=true)
  | 'new_shadow_detection'       // New shadow detection created
  | 'repeat_shadow_hit'          // Repeat hit on existing shadow detection
  | 'already_promoted'           // Detection was already promoted to blocking
  | 'already_dismissed';         // Detection was already dismissed

/**
 * Query parameters for listing shadow detections.
 */
export interface ShadowDetectionQuery {
  /** Filter by status */
  status?: ShadowDetectionStatus;
  /** Filter by minimum confidence */
  minConfidence?: number;
  /** Filter by maximum confidence */
  maxConfidence?: number;
  /** Filter by novel only */
  novelOnly?: boolean;
  /** Filter by minimum hit count */
  minHitCount?: number;
  /** Filter by detected after (Unix timestamp ms) */
  detectedAfter?: number;
  /** Filter by detected before (Unix timestamp ms) */
  detectedBefore?: number;
  /** Maximum number of results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
  /** Sort field */
  sortBy?: 'detectedAt' | 'lastSeenAt' | 'hitCount' | 'confidence';
  /** Sort direction */
  sortDir?: 'asc' | 'desc';
}

/**
 * Response from listing shadow detections.
 */
export interface ShadowDetectionListResponse {
  /** List of shadow detections */
  detections: ShadowDetection[];
  /** Total count (before pagination) */
  total: number;
  /** Whether there are more results */
  hasMore: boolean;
}

/**
 * Shadow detection statistics.
 */
export interface ShadowDetectionStats {
  /** Total shadow detections */
  total: number;
  /** Detections by status */
  byStatus: Record<ShadowDetectionStatus, number>;
  /** Detections pending review */
  pendingReview: number;
  /** Detections promoted to blocking */
  promoted: number;
  /** Detections dismissed */
  dismissed: number;
  /** Detections expired without review */
  expired: number;
  /** Average confidence of pending detections */
  avgPendingConfidence: number;
  /** Total hit count across all detections */
  totalHits: number;
  /** Novel detections (isNovel=true) */
  novelCount: number;
  /** Oldest pending detection (Unix timestamp ms) */
  oldestPending?: number;
}

/**
 * Alert payload for shadow detection.
 * Sent to connectors when a new shadow detection occurs.
 */
export interface ShadowDetectionAlert {
  /** Alert type identifier */
  type: 'shadow_detection';
  /** Alert severity (informational for shadow detections) */
  severity: 'info' | 'low' | 'medium';
  /** Alert title */
  title: string;
  /** Alert description */
  description: string;
  /** The shadow detection record */
  detection: ShadowDetection;
  /** When the alert was generated (Unix timestamp ms) */
  timestamp: number;
  /** Unique alert ID */
  alertId: string;
}

/**
 * Generate a unique detection ID.
 */
export function generateDetectionId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `sd_${timestamp}_${random}`;
}

/**
 * Generate a unique alert ID.
 */
export function generateAlertId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `alert_${timestamp}_${random}`;
}

/**
 * Determine severity based on confidence score.
 * Lower confidence = higher severity (more suspicious).
 */
export function getSeverityFromConfidence(confidence: number): 'info' | 'low' | 'medium' {
  if (confidence >= 50) {
    return 'medium'; // Higher confidence = more likely malicious
  } else if (confidence >= 30) {
    return 'low';
  } else {
    return 'info'; // Very low confidence = probably benign
  }
}
