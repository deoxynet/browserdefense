/**
 * Tests for DOM Kit Confidence Scoring (Issue #170)
 *
 * Verifies:
 * - Deterministic rules-based scoring
 * - Global novelty factor
 * - Local novelty factor
 * - Analyst labels factor
 * - Temporal burstiness factor
 * - Priority level assignment
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock chrome APIs before importing the module
const mockStorage: Record<string, unknown> = {};

vi.stubGlobal('chrome', {
  storage: {
    local: {
      get: vi.fn((keys: string | string[]) => {
        const keyList = Array.isArray(keys) ? keys : [keys];
        const result: Record<string, unknown> = {};
        for (const key of keyList) {
          if (mockStorage[key] !== undefined) {
            result[key] = mockStorage[key];
          }
        }
        return Promise.resolve(result);
      }),
      set: vi.fn((items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
        return Promise.resolve();
      }),
      remove: vi.fn((keys: string | string[]) => {
        const keyList = Array.isArray(keys) ? keys : [keys];
        for (const key of keyList) {
          delete mockStorage[key];
        }
        return Promise.resolve();
      }),
    },
  },
});

// Import module after mocking
import {
  calculateDOMKitScore,
  buildScoringFactors,
  buildAnalystLabelsFactor,
  quickScore,
  getPriorityLevel,
  getPriorityDescription,
  recordOccurrence,
  getTemporalBurstinessFactor,
  clearTemporalTracking,
  DEFAULT_SCORING_CONFIG,
  PRIORITY_THRESHOLDS,
} from '../src/background/dom-kit-scoring';
import type { HashLabel } from '../src/types/hash-labels';

describe('DOM Kit Confidence Scoring', () => {
  beforeEach(() => {
    // Clear storage
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    vi.clearAllMocks();
  });

  describe('Core Scoring Function', () => {
    it('should return base score with no factors', () => {
      const score = calculateDOMKitScore({});
      expect(score.baseScore).toBe(50);
      expect(score.finalScore).toBe(50);
      expect(score.totalAdjustment).toBe(0);
      expect(score.adjustments).toHaveLength(0);
    });

    it('should be deterministic (same input = same output)', () => {
      const factors = buildScoringFactors({
        isNovel: true,
        firstSeenLocally: true,
        labels: [{ label: 'TP' } as HashLabel],
        recentOccurrences: 5,
      });

      const score1 = calculateDOMKitScore(factors);
      const score2 = calculateDOMKitScore(factors);

      expect(score1.finalScore).toBe(score2.finalScore);
      expect(score1.adjustments).toEqual(score2.adjustments);
    });

    it('should clamp score to [0, 100]', () => {
      // Test upper bound
      const highFactors = buildScoringFactors({
        isNovel: true,
        firstSeenLocally: true,
        labels: [
          { label: 'TP' } as HashLabel,
          { label: 'TP' } as HashLabel,
          { label: 'TP' } as HashLabel,
          { label: 'TP' } as HashLabel,
        ],
        recentOccurrences: 10,
      });
      const highScore = calculateDOMKitScore(highFactors);
      expect(highScore.finalScore).toBeLessThanOrEqual(100);

      // Test lower bound
      const lowFactors = buildScoringFactors({
        isNovel: false,
        firstSeenLocally: false,
        labels: [
          { label: 'FP' } as HashLabel,
          { label: 'FP' } as HashLabel,
          { label: 'FP' } as HashLabel,
          { label: 'FP' } as HashLabel,
        ],
      });
      const lowScore = calculateDOMKitScore(lowFactors);
      expect(lowScore.finalScore).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Global Novelty Factor', () => {
    it('should boost score when hash is globally novel', () => {
      const novelScore = calculateDOMKitScore({
        globalNovelty: { isNovel: true },
      });

      expect(novelScore.finalScore).toBe(50 + DEFAULT_SCORING_CONFIG.weights.globalNoveltyBoost);
      expect(novelScore.adjustments).toHaveLength(1);
      expect(novelScore.adjustments[0].factor).toBe('globalNovelty');
      expect(novelScore.adjustments[0].adjustment).toBe(20);
    });

    it('should not adjust score when hash is known globally', () => {
      const knownScore = calculateDOMKitScore({
        globalNovelty: { isNovel: false },
      });

      expect(knownScore.finalScore).toBe(50);
      expect(knownScore.totalAdjustment).toBe(0);
    });
  });

  describe('Local Novelty Factor', () => {
    it('should boost score when hash is first seen locally', () => {
      const localNovelScore = calculateDOMKitScore({
        localNovelty: { firstSeenLocally: true },
      });

      expect(localNovelScore.finalScore).toBe(50 + DEFAULT_SCORING_CONFIG.weights.localNoveltyBoost);
      expect(localNovelScore.adjustments).toHaveLength(1);
      expect(localNovelScore.adjustments[0].factor).toBe('localNovelty');
      expect(localNovelScore.adjustments[0].adjustment).toBe(15);
    });

    it('should not adjust score when hash was previously seen locally', () => {
      const seenScore = calculateDOMKitScore({
        localNovelty: { firstSeenLocally: false },
      });

      expect(seenScore.finalScore).toBe(50);
      expect(seenScore.totalAdjustment).toBe(0);
    });
  });

  describe('Analyst Labels Factor', () => {
    it('should boost score for TP labels', () => {
      const tpScore = calculateDOMKitScore({
        analystLabels: { tpCount: 2, fpCount: 0, unknownCount: 0 },
      });

      const expectedBoost = 2 * DEFAULT_SCORING_CONFIG.weights.tpLabelBoost;
      expect(tpScore.finalScore).toBe(50 + expectedBoost);
      expect(tpScore.adjustments[0].factor).toBe('analystLabels');
    });

    it('should penalize score for FP labels', () => {
      const fpScore = calculateDOMKitScore({
        analystLabels: { tpCount: 0, fpCount: 2, unknownCount: 0 },
      });

      const expectedPenalty = 2 * DEFAULT_SCORING_CONFIG.weights.fpLabelPenalty;
      expect(fpScore.finalScore).toBe(50 + expectedPenalty);
    });

    it('should balance TP and FP labels', () => {
      const mixedScore = calculateDOMKitScore({
        analystLabels: { tpCount: 1, fpCount: 1, unknownCount: 0 },
      });

      const expectedAdjustment =
        DEFAULT_SCORING_CONFIG.weights.tpLabelBoost +
        DEFAULT_SCORING_CONFIG.weights.fpLabelPenalty;
      expect(mixedScore.finalScore).toBe(50 + expectedAdjustment);
    });

    it('should clamp label adjustment to maxLabelAdjustment', () => {
      // Many TP labels should not exceed max adjustment
      const manyTpScore = calculateDOMKitScore({
        analystLabels: { tpCount: 10, fpCount: 0, unknownCount: 0 },
      });

      const maxAdjustment = DEFAULT_SCORING_CONFIG.weights.maxLabelAdjustment;
      expect(manyTpScore.adjustments[0].adjustment).toBeLessThanOrEqual(maxAdjustment);

      // Many FP labels should not exceed negative max adjustment
      const manyFpScore = calculateDOMKitScore({
        analystLabels: { tpCount: 0, fpCount: 10, unknownCount: 0 },
      });

      expect(manyFpScore.adjustments[0].adjustment).toBeGreaterThanOrEqual(-maxAdjustment);
    });

    it('should not adjust for UNKNOWN labels', () => {
      const unknownScore = calculateDOMKitScore({
        analystLabels: { tpCount: 0, fpCount: 0, unknownCount: 5 },
      });

      expect(unknownScore.finalScore).toBe(50);
    });
  });

  describe('Temporal Burstiness Factor', () => {
    it('should boost score when burstiness detected', () => {
      const burstyScore = calculateDOMKitScore({
        temporalBurstiness: {
          recentOccurrences: 5,
          dailyOccurrences: 10,
          isBursty: true,
        },
      });

      const expectedBoost = Math.min(
        5 * DEFAULT_SCORING_CONFIG.weights.burstinessPerOccurrence,
        DEFAULT_SCORING_CONFIG.weights.maxBurstinessBoost
      );
      expect(burstyScore.finalScore).toBe(50 + expectedBoost);
      expect(burstyScore.adjustments[0].factor).toBe('temporalBurstiness');
    });

    it('should not boost when below threshold', () => {
      const notBurstyScore = calculateDOMKitScore({
        temporalBurstiness: {
          recentOccurrences: 2,
          dailyOccurrences: 5,
          isBursty: false,
        },
      });

      expect(notBurstyScore.finalScore).toBe(50);
    });

    it('should cap burstiness boost at maxBurstinessBoost', () => {
      const veryBurstyScore = calculateDOMKitScore({
        temporalBurstiness: {
          recentOccurrences: 100,
          dailyOccurrences: 500,
          isBursty: true,
        },
      });

      const maxBoost = DEFAULT_SCORING_CONFIG.weights.maxBurstinessBoost;
      expect(veryBurstyScore.adjustments[0].adjustment).toBeLessThanOrEqual(maxBoost);
    });
  });

  describe('Combined Factors', () => {
    it('should combine all factors additively', () => {
      const combinedScore = calculateDOMKitScore({
        globalNovelty: { isNovel: true },
        localNovelty: { firstSeenLocally: true },
        analystLabels: { tpCount: 1, fpCount: 0, unknownCount: 0 },
        temporalBurstiness: { recentOccurrences: 5, dailyOccurrences: 10, isBursty: true },
      });

      expect(combinedScore.adjustments).toHaveLength(4);

      // Verify each adjustment is tracked
      const factorNames = combinedScore.adjustments.map((a) => a.factor);
      expect(factorNames).toContain('globalNovelty');
      expect(factorNames).toContain('localNovelty');
      expect(factorNames).toContain('analystLabels');
      expect(factorNames).toContain('temporalBurstiness');
    });

    it('should produce high score for highly suspicious hash', () => {
      const suspiciousScore = calculateDOMKitScore({
        globalNovelty: { isNovel: true },
        localNovelty: { firstSeenLocally: true },
        analystLabels: { tpCount: 2, fpCount: 0, unknownCount: 0 },
        temporalBurstiness: { recentOccurrences: 5, dailyOccurrences: 10, isBursty: true },
      });

      expect(suspiciousScore.finalScore).toBeGreaterThanOrEqual(PRIORITY_THRESHOLDS.HIGH);
    });

    it('should produce low score for likely benign hash', () => {
      const benignScore = calculateDOMKitScore({
        globalNovelty: { isNovel: false },
        localNovelty: { firstSeenLocally: false },
        analystLabels: { tpCount: 0, fpCount: 2, unknownCount: 0 },
      });

      expect(benignScore.finalScore).toBeLessThan(PRIORITY_THRESHOLDS.MEDIUM);
    });
  });

  describe('Priority Levels', () => {
    it('should assign critical priority for scores >= 85', () => {
      expect(getPriorityLevel(85)).toBe('critical');
      expect(getPriorityLevel(100)).toBe('critical');
    });

    it('should assign high priority for scores >= 70', () => {
      expect(getPriorityLevel(70)).toBe('high');
      expect(getPriorityLevel(84)).toBe('high');
    });

    it('should assign medium priority for scores >= 50', () => {
      expect(getPriorityLevel(50)).toBe('medium');
      expect(getPriorityLevel(69)).toBe('medium');
    });

    it('should assign low priority for scores >= 30', () => {
      expect(getPriorityLevel(30)).toBe('low');
      expect(getPriorityLevel(49)).toBe('low');
    });

    it('should assign minimal priority for scores < 30', () => {
      expect(getPriorityLevel(0)).toBe('minimal');
      expect(getPriorityLevel(29)).toBe('minimal');
    });

    it('should provide descriptions for each priority level', () => {
      expect(getPriorityDescription('critical')).toContain('Immediate');
      expect(getPriorityDescription('high')).toContain('Prioritize');
      expect(getPriorityDescription('medium')).toContain('Standard');
      expect(getPriorityDescription('low')).toContain('time permits');
      expect(getPriorityDescription('minimal')).toContain('benign');
    });
  });

  describe('Helper Functions', () => {
    describe('buildScoringFactors', () => {
      it('should build factors from options', () => {
        const factors = buildScoringFactors({
          isNovel: true,
          firstSeenLocally: false,
          labels: [{ label: 'TP' } as HashLabel],
          recentOccurrences: 5,
        });

        expect(factors.globalNovelty?.isNovel).toBe(true);
        expect(factors.localNovelty?.firstSeenLocally).toBe(false);
        expect(factors.analystLabels?.tpCount).toBe(1);
        expect(factors.temporalBurstiness?.recentOccurrences).toBe(5);
      });

      it('should only include defined factors', () => {
        const factors = buildScoringFactors({ isNovel: true });

        expect(factors.globalNovelty).toBeDefined();
        expect(factors.localNovelty).toBeUndefined();
        expect(factors.analystLabels).toBeUndefined();
        expect(factors.temporalBurstiness).toBeUndefined();
      });
    });

    describe('buildAnalystLabelsFactor', () => {
      it('should count labels by type', () => {
        const labels: HashLabel[] = [
          { dom_kit_hash: 'sha256:abc', label: 'TP', created_at: 1, updated_at: 1 },
          { dom_kit_hash: 'sha256:abc', label: 'TP', created_at: 2, updated_at: 2 },
          { dom_kit_hash: 'sha256:abc', label: 'FP', created_at: 3, updated_at: 3 },
          { dom_kit_hash: 'sha256:abc', label: 'UNKNOWN', created_at: 4, updated_at: 4 },
        ];

        const factor = buildAnalystLabelsFactor(labels);

        expect(factor.tpCount).toBe(2);
        expect(factor.fpCount).toBe(1);
        expect(factor.unknownCount).toBe(1);
        expect(factor.labels).toBe(labels);
      });
    });

    describe('quickScore', () => {
      it('should calculate score from minimal inputs', () => {
        const score = quickScore(true, true, 1, 0);

        // Novel (+20) + Local novel (+15) + 1 TP (+15) = 50 + 50 = 100
        expect(score).toBe(100);
      });

      it('should handle all false/zero inputs', () => {
        const score = quickScore(false, false, 0, 0);
        expect(score).toBe(50); // Base score only
      });
    });
  });

  describe('Temporal Tracking', () => {
    beforeEach(async () => {
      await clearTemporalTracking();
    });

    it('should record occurrences', async () => {
      await recordOccurrence('abc123');
      await recordOccurrence('abc123');
      await recordOccurrence('abc123');

      const factor = await getTemporalBurstinessFactor('abc123');
      expect(factor.recentOccurrences).toBe(3);
      expect(factor.isBursty).toBe(true);
    });

    it('should detect burstiness when threshold exceeded', async () => {
      // Add occurrences
      for (let i = 0; i < 5; i++) {
        await recordOccurrence('bursty_hash');
      }

      const factor = await getTemporalBurstinessFactor('bursty_hash');
      expect(factor.isBursty).toBe(true);
      expect(factor.recentOccurrences).toBe(5);
    });

    it('should not detect burstiness below threshold', async () => {
      await recordOccurrence('single_hash');

      const factor = await getTemporalBurstinessFactor('single_hash');
      expect(factor.isBursty).toBe(false);
      expect(factor.recentOccurrences).toBe(1);
    });

    it('should handle hash with sha256: prefix', async () => {
      await recordOccurrence('sha256:abc123');
      await recordOccurrence('abc123'); // Without prefix

      // Both should count toward same hash
      const factor = await getTemporalBurstinessFactor('sha256:abc123');
      expect(factor.recentOccurrences).toBe(2);
    });

    it('should clear temporal tracking', async () => {
      await recordOccurrence('to_clear');
      await clearTemporalTracking();

      const factor = await getTemporalBurstinessFactor('to_clear');
      expect(factor.recentOccurrences).toBe(0);
    });
  });

  describe('Issue #170 Acceptance Criteria', () => {
    it('should be deterministic (no ML)', () => {
      // Run the same calculation multiple times
      const results = new Set<number>();

      for (let i = 0; i < 10; i++) {
        const score = calculateDOMKitScore({
          globalNovelty: { isNovel: true },
          localNovelty: { firstSeenLocally: true },
          analystLabels: { tpCount: 1, fpCount: 0, unknownCount: 0 },
        });
        results.add(score.finalScore);
      }

      // Should always produce the same result
      expect(results.size).toBe(1);
    });

    it('should include all required factors', () => {
      const score = calculateDOMKitScore({
        globalNovelty: { isNovel: true },
        localNovelty: { firstSeenLocally: true },
        analystLabels: { tpCount: 1, fpCount: 1, unknownCount: 0 },
        temporalBurstiness: { recentOccurrences: 5, dailyOccurrences: 10, isBursty: true },
      });

      // Verify all factors are tracked
      expect(score.factors.globalNovelty).toBeDefined();
      expect(score.factors.localNovelty).toBeDefined();
      expect(score.factors.analystLabels).toBeDefined();
      expect(score.factors.temporalBurstiness).toBeDefined();
    });

    it('should be usable for prioritization', () => {
      // High-risk scenario
      const highRisk = calculateDOMKitScore({
        globalNovelty: { isNovel: true },
        localNovelty: { firstSeenLocally: true },
        analystLabels: { tpCount: 2, fpCount: 0, unknownCount: 0 },
        temporalBurstiness: { recentOccurrences: 10, dailyOccurrences: 50, isBursty: true },
      });

      // Low-risk scenario
      const lowRisk = calculateDOMKitScore({
        globalNovelty: { isNovel: false },
        localNovelty: { firstSeenLocally: false },
        analystLabels: { tpCount: 0, fpCount: 2, unknownCount: 0 },
      });

      // Should be able to differentiate for prioritization
      expect(highRisk.finalScore).toBeGreaterThan(lowRisk.finalScore);
      expect(getPriorityLevel(highRisk.finalScore)).not.toBe(getPriorityLevel(lowRisk.finalScore));
    });

    it('should NOT affect enforcement (scores are informational)', () => {
      const score = calculateDOMKitScore({
        globalNovelty: { isNovel: true },
        analystLabels: { tpCount: 5, fpCount: 0, unknownCount: 0 },
      });

      // Score object should not contain any "action" or "block" field
      expect(score).not.toHaveProperty('action');
      expect(score).not.toHaveProperty('block');
      expect(score).not.toHaveProperty('shouldBlock');
    });
  });
});
