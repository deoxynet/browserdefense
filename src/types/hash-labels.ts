/**
 * Hash Label Types
 *
 * Types for analyst TP/FP labels attached to DOM kit hashes.
 * Labels are for incident review and research - NO automatic enforcement action.
 *
 * Reference: Issue #205
 */

/**
 * Label classification for DOM kit hash.
 * - TP: True Positive - confirmed malicious/phishing
 * - FP: False Positive - confirmed benign
 * - UNKNOWN: Not yet classified
 */
export type HashLabelType = 'TP' | 'FP' | 'UNKNOWN';

/**
 * A label attached to a DOM kit hash by an analyst.
 * Labels do NOT trigger automatic enforcement actions.
 */
export interface HashLabel {
  /** DOM kit hash (format: sha256:xxx) */
  dom_kit_hash: string;
  /** Label classification */
  label: HashLabelType;
  /** Analyst identifier (email or username) */
  analyst?: string;
  /** Optional notes from the analyst */
  notes?: string;
  /** When the label was created (Unix timestamp ms) */
  created_at: number;
  /** When the label was last updated (Unix timestamp ms) */
  updated_at: number;
}

/**
 * Request payload for creating or updating a label.
 */
export interface LabelRequest {
  /** DOM kit hash (format: sha256:xxx) */
  dom_kit_hash: string;
  /** Label classification */
  label: HashLabelType;
  /** Analyst identifier (optional, can be inferred from auth) */
  analyst?: string;
  /** Optional notes */
  notes?: string;
}

/**
 * Response from the label API.
 */
export interface LabelResponse {
  /** Status of the operation */
  status: 'created' | 'updated' | 'deleted' | 'found' | 'not_found';
  /** The label record (if applicable) */
  label?: HashLabel;
}

/**
 * Query parameters for listing labels.
 */
export interface LabelListQuery {
  /** Filter by label type */
  label?: HashLabelType;
  /** Filter by analyst */
  analyst?: string;
  /** Maximum number of results */
  limit?: number;
  /** Cursor for pagination */
  cursor?: string;
}

/**
 * Response from listing labels.
 */
export interface LabelListResponse {
  /** List of labels */
  labels: HashLabel[];
  /** Pagination cursor for next page */
  cursor?: string;
  /** Whether there are more results */
  has_more: boolean;
  /** Total count (if available) */
  total?: number;
}

/**
 * Validate a DOM kit hash format.
 * Must be sha256: followed by 64 hex characters.
 */
export function isValidDomKitHash(hash: string): boolean {
  return /^sha256:[a-f0-9]{64}$/i.test(hash);
}

/**
 * Validate a label type.
 */
export function isValidLabelType(label: unknown): label is HashLabelType {
  return label === 'TP' || label === 'FP' || label === 'UNKNOWN';
}

/**
 * Get the confidence impact direction for a label type.
 * - TP: positive (increases confidence)
 * - FP: negative (decreases confidence)
 * - UNKNOWN: neutral (no impact)
 *
 * Note: Actual impact values are defined in confidence.ts
 * Reference: Issue #165
 */
export function getLabelConfidenceDirection(label: HashLabelType): 'positive' | 'negative' | 'neutral' {
  switch (label) {
    case 'TP':
      return 'positive';
    case 'FP':
      return 'negative';
    case 'UNKNOWN':
      return 'neutral';
  }
}
