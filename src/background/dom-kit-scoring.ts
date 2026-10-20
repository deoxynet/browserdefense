/**
 * DOM Kit Confidence Scoring (Issue #170)
 *
 * Rules-based confidence scoring for DOM kit fingerprints.
 * Computes confidence from multiple deterministic factors:
 * - Global novelty (is hash new globally?)
 * - Local novelty (is hash new to this user?)
 * - Analyst labels (TP/FP feedback)
 * - Temporal burstiness (sudden spike in occurrences)
 *
 * IMPORTANT: Confidence scores are for PRIORITIZATION only.
 * They do NOT trigger auto-blocking or change enforcement actions.
 *
 * Reference: Issue #170
 */

import type { HashLabel } from '../types/hash-labels';
import type {
  ScoringFactors,
  GlobalNoveltyFactor,
  LocalNoveltyFactor,
  AnalystLabelsFactor,
  TemporalBurstinessFactor,
  ScoreAdjustment,
  DOMKitConfidenceScore,
  DOMKitScoringConfig,
  PriorityLevel,
  TemporalTrackingData,
} from '../types/dom-kit-scoring';
import { DEFAULT_SCORING_CONFIG, PRIORITY_THRESHOLDS } from '../types/dom-kit-scoring';

// Re-export types and constants
export type {
  ScoringFactors,
  GlobalNoveltyFactor,
  LocalNoveltyFactor,
  AnalystLabelsFactor,
  TemporalBurstinessFactor,
  ScoreAdjustment,
  DOMKitConfidenceScore,
  DOMKitScoringConfig,
  PriorityLevel,
};
export { DEFAULT_SCORING_CONFIG, PRIORITY_THRESHOLDS };

// ============ Constants ============

const TEMPORAL_TRACKING_KEY = 'browserdefense_temporal_tracking';
const TEMPORAL_DATA_TTL_MS = 24 * 60 * 60 * 1000;
const RECENT_WINDOW_MS = 60 * 60 * 1000;
const MAX_OCCURRENCES_PER_HASH = 100;
const MAX_TOTAL_OCCURRENCES = 10000;

// ============ Core Scoring Function ============

export function calculateDOMKitScore(
  factors: ScoringFactors,
  config: DOMKitScoringConfig = DEFAULT_SCORING_CONFIG
): DOMKitConfidenceScore {
  const adjustments: ScoreAdjustment[] = [];
  let totalAdjustment = 0;

  if (factors.globalNovelty) {
    const adj = calculateGlobalNoveltyAdjustment(factors.globalNovelty, config);
    if (adj.adjustment !== 0) {
      adjustments.push(adj);
      totalAdjustment += adj.adjustment;
    }
  }

  if (factors.localNovelty) {
    const adj = calculateLocalNoveltyAdjustment(factors.localNovelty, config);
    if (adj.adjustment !== 0) {
      adjustments.push(adj);
      totalAdjustment += adj.adjustment;
    }
  }

  if (factors.analystLabels) {
    const adj = calculateAnalystLabelsAdjustment(factors.analystLabels, config);
    if (adj.adjustment !== 0) {
      adjustments.push(adj);
      totalAdjustment += adj.adjustment;
    }
  }

  if (factors.temporalBurstiness) {
    const adj = calculateBurstinessAdjustment(factors.temporalBurstiness, config);
    if (adj.adjustment !== 0) {
      adjustments.push(adj);
      totalAdjustment += adj.adjustment;
    }
  }

  const rawScore = config.baseScore + totalAdjustment;
  const finalScore = Math.round(
    Math.max(config.minScore, Math.min(config.maxScore, rawScore))
  );

  return {
    baseScore: config.baseScore,
    finalScore,
    adjustments,
    totalAdjustment,
    factors,
    computedAt: Date.now(),
  };
}

// ============ Individual Factor Calculations ============

function calculateGlobalNoveltyAdjustment(
  factor: GlobalNoveltyFactor,
  config: DOMKitScoringConfig
): ScoreAdjustment {
  if (factor.isNovel) {
    return {
      factor: 'globalNovelty',
      adjustment: config.weights.globalNoveltyBoost,
      reason: 'Hash is globally novel (first occurrence)',
    };
  }
  return {
    factor: 'globalNovelty',
    adjustment: 0,
    reason: 'Hash is known globally',
  };
}

function calculateLocalNoveltyAdjustment(
  factor: LocalNoveltyFactor,
  config: DOMKitScoringConfig
): ScoreAdjustment {
  if (factor.firstSeenLocally) {
    return {
      factor: 'localNovelty',
      adjustment: config.weights.localNoveltyBoost,
      reason: 'Hash is locally novel (first seen by this user)',
    };
  }
  return {
    factor: 'localNovelty',
    adjustment: 0,
    reason: 'Hash was previously seen locally',
  };
}

function calculateAnalystLabelsAdjustment(
  factor: AnalystLabelsFactor,
  config: DOMKitScoringConfig
): ScoreAdjustment {
  const tpAdjustment = factor.tpCount * config.weights.tpLabelBoost;
  const fpAdjustment = factor.fpCount * config.weights.fpLabelPenalty;
  const rawAdjustment = tpAdjustment + fpAdjustment;

  const clampedAdjustment = Math.max(
    -config.weights.maxLabelAdjustment,
    Math.min(config.weights.maxLabelAdjustment, rawAdjustment)
  );

  if (clampedAdjustment === 0) {
    return {
      factor: 'analystLabels',
      adjustment: 0,
      reason: factor.tpCount + factor.fpCount === 0
        ? 'No analyst labels'
        : 'TP and FP labels balanced',
    };
  }

  const direction = clampedAdjustment > 0 ? 'boost' : 'penalty';
  const reason = factor.tpCount + ' TP labels (+' + tpAdjustment + '), ' + factor.fpCount + ' FP labels (' + fpAdjustment + ')';

  return {
    factor: 'analystLabels',
    adjustment: clampedAdjustment,
    reason: 'Analyst feedback ' + direction + ': ' + reason,
  };
}

function calculateBurstinessAdjustment(
  factor: TemporalBurstinessFactor,
  config: DOMKitScoringConfig
): ScoreAdjustment {
  if (!factor.isBursty || factor.recentOccurrences < config.weights.burstinessThreshold) {
    return {
      factor: 'temporalBurstiness',
      adjustment: 0,
      reason: factor.recentOccurrences + ' recent occurrences (below threshold of ' + config.weights.burstinessThreshold + ')',
    };
  }

  const rawBoost = factor.recentOccurrences * config.weights.burstinessPerOccurrence;
  const clampedBoost = Math.min(rawBoost, config.weights.maxBurstinessBoost);

  return {
    factor: 'temporalBurstiness',
    adjustment: clampedBoost,
    reason: 'Temporal burst detected: ' + factor.recentOccurrences + ' occurrences in last hour',
  };
}

// ============ Temporal Tracking ============

export async function recordOccurrence(hash: string): Promise<void> {
  const data = await getTemporalTrackingData();
  const now = Date.now();

  data.occurrences.push({
    hash: hash.startsWith('sha256:') ? hash : 'sha256:' + hash,
    timestamp: now,
  });

  if (now - data.lastCleanup > TEMPORAL_DATA_TTL_MS / 24) {
    await cleanupTemporalData(data, now);
  } else {
    await saveTemporalTrackingData(data);
  }
}

export async function getTemporalBurstinessFactor(
  hash: string,
  config: DOMKitScoringConfig = DEFAULT_SCORING_CONFIG
): Promise<TemporalBurstinessFactor> {
  const data = await getTemporalTrackingData();
  const now = Date.now();
  const formattedHash = hash.startsWith('sha256:') ? hash : 'sha256:' + hash;

  let recentOccurrences = 0;
  let dailyOccurrences = 0;

  for (const occ of data.occurrences) {
    if (occ.hash !== formattedHash) continue;

    const age = now - occ.timestamp;

    if (age <= RECENT_WINDOW_MS) {
      recentOccurrences++;
    }
    if (age <= TEMPORAL_DATA_TTL_MS) {
      dailyOccurrences++;
    }
  }

  return {
    recentOccurrences,
    dailyOccurrences,
    isBursty: recentOccurrences >= config.weights.burstinessThreshold,
  };
}

async function getTemporalTrackingData(): Promise<TemporalTrackingData> {
  const result = await chrome.storage.local.get(TEMPORAL_TRACKING_KEY);
  const data = result[TEMPORAL_TRACKING_KEY] as TemporalTrackingData | undefined;

  return data ?? {
    occurrences: [],
    lastCleanup: Date.now(),
  };
}

async function saveTemporalTrackingData(data: TemporalTrackingData): Promise<void> {
  await chrome.storage.local.set({ [TEMPORAL_TRACKING_KEY]: data });
}

async function cleanupTemporalData(data: TemporalTrackingData, now: number): Promise<void> {
  data.occurrences = data.occurrences.filter(
    (occ) => now - occ.timestamp <= TEMPORAL_DATA_TTL_MS
  );

  const hashCounts = new Map<string, number>();
  data.occurrences = data.occurrences.filter((occ) => {
    const count = hashCounts.get(occ.hash) ?? 0;
    if (count >= MAX_OCCURRENCES_PER_HASH) {
      return false;
    }
    hashCounts.set(occ.hash, count + 1);
    return true;
  });

  if (data.occurrences.length > MAX_TOTAL_OCCURRENCES) {
    data.occurrences.sort((a, b) => b.timestamp - a.timestamp);
    data.occurrences = data.occurrences.slice(0, MAX_TOTAL_OCCURRENCES);
  }

  data.lastCleanup = now;
  await saveTemporalTrackingData(data);
}

export async function clearTemporalTracking(): Promise<void> {
  await chrome.storage.local.remove(TEMPORAL_TRACKING_KEY);
}

// ============ Priority Level ============

export function getPriorityLevel(score: number): PriorityLevel {
  if (score >= PRIORITY_THRESHOLDS.CRITICAL) {
    return 'critical';
  } else if (score >= PRIORITY_THRESHOLDS.HIGH) {
    return 'high';
  } else if (score >= PRIORITY_THRESHOLDS.MEDIUM) {
    return 'medium';
  } else if (score >= PRIORITY_THRESHOLDS.LOW) {
    return 'low';
  } else {
    return 'minimal';
  }
}

export function getPriorityDescription(level: PriorityLevel): string {
  switch (level) {
    case 'critical':
      return 'Critical - Immediate investigation recommended';
    case 'high':
      return 'High - Prioritize for review';
    case 'medium':
      return 'Medium - Standard review queue';
    case 'low':
      return 'Low - Review when time permits';
    case 'minimal':
      return 'Minimal - Likely benign';
  }
}

// ============ Convenience Functions ============

export function buildScoringFactors(options: {
  isNovel?: boolean;
  occurrenceCount?: number;
  firstSeenLocally?: boolean;
  localFirstSeen?: number;
  localOccurrenceCount?: number;
  labels?: HashLabel[];
  recentOccurrences?: number;
  dailyOccurrences?: number;
  burstinessThreshold?: number;
}): ScoringFactors {
  const factors: ScoringFactors = {};

  if (options.isNovel !== undefined) {
    factors.globalNovelty = {
      isNovel: options.isNovel,
      occurrenceCount: options.occurrenceCount,
    };
  }

  if (options.firstSeenLocally !== undefined) {
    factors.localNovelty = {
      firstSeenLocally: options.firstSeenLocally,
      localFirstSeen: options.localFirstSeen,
      localOccurrenceCount: options.localOccurrenceCount,
    };
  }

  if (options.labels !== undefined) {
    factors.analystLabels = buildAnalystLabelsFactor(options.labels);
  }

  if (options.recentOccurrences !== undefined) {
    const threshold = options.burstinessThreshold ?? DEFAULT_SCORING_CONFIG.weights.burstinessThreshold;
    factors.temporalBurstiness = {
      recentOccurrences: options.recentOccurrences,
      dailyOccurrences: options.dailyOccurrences ?? options.recentOccurrences,
      isBursty: options.recentOccurrences >= threshold,
    };
  }

  return factors;
}

export function buildAnalystLabelsFactor(labels: HashLabel[]): AnalystLabelsFactor {
  let tpCount = 0;
  let fpCount = 0;
  let unknownCount = 0;

  for (const label of labels) {
    switch (label.label) {
      case 'TP':
        tpCount++;
        break;
      case 'FP':
        fpCount++;
        break;
      case 'UNKNOWN':
        unknownCount++;
        break;
    }
  }

  return {
    tpCount,
    fpCount,
    unknownCount,
    labels,
  };
}

export function quickScore(
  isNovel: boolean,
  firstSeenLocally: boolean,
  tpCount: number = 0,
  fpCount: number = 0,
  config: DOMKitScoringConfig = DEFAULT_SCORING_CONFIG
): number {
  const factors = buildScoringFactors({
    isNovel,
    firstSeenLocally,
    labels: [
      ...Array(tpCount).fill({ label: 'TP' }),
      ...Array(fpCount).fill({ label: 'FP' }),
    ] as HashLabel[],
  });

  return calculateDOMKitScore(factors, config).finalScore;
}

// ============ Exports for Testing ============

export {
  getTemporalTrackingData as _getTemporalTrackingData,
  saveTemporalTrackingData as _saveTemporalTrackingData,
  cleanupTemporalData as _cleanupTemporalData,
  TEMPORAL_TRACKING_KEY as _TEMPORAL_TRACKING_KEY,
  TEMPORAL_DATA_TTL_MS as _TEMPORAL_DATA_TTL_MS,
  RECENT_WINDOW_MS as _RECENT_WINDOW_MS,
};
