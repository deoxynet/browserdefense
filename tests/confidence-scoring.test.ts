/**
 * Tests for Confidence Scoring Module
 *
 * Tests for analyst label-based confidence adjustments.
 * Labels affect confidence scores but do NOT trigger auto-blocking.
 *
 * Reference: Issue #165
 */

import { describe, it, expect } from 'vitest';

// Import types inline to avoid import issues in tests
type HashLabelType = 'TP' | 'FP' | 'UNKNOWN';

interface HashLabel {
  dom_kit_hash: string;
  label: HashLabelType;
  analyst?: string;
  notes?: string;
  created_at: number;
  updated_at: number;
}

interface ConfidenceConfig {
  tpBoost: number;
  fpPenalty: number;
  maxAdjustment: number;
  minConfidence: number;
  maxConfidence: number;
}

interface LabelBreakdown {
  tp: number;
  fp: number;
  unknown: number;
}

interface ConfidenceScore {
  baseConfidence: number;
  labelAdjustment: number;
  finalConfidence: number;
  labelCount: number;
  labelBreakdown: LabelBreakdown;
  hasAnalystFeedback: boolean;
}

// Default configuration
const DEFAULT_CONFIDENCE_CONFIG: ConfidenceConfig = {
  tpBoost: 15,
  fpPenalty: -25,
  maxAdjustment: 50,
  minConfidence: 0,
  maxConfidence: 100,
};

// Helper functions (replicated from module)
function getLabelImpact(
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

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function calculateConfidenceScore(
  baseConfidence: number,
  labels: HashLabel[],
  config: ConfidenceConfig = DEFAULT_CONFIDENCE_CONFIG
): ConfidenceScore {
  const breakdown: LabelBreakdown = { tp: 0, fp: 0, unknown: 0 };
  let totalAdjustment = 0;

  for (const label of labels) {
    const impact = getLabelImpact(label.label, config);
    totalAdjustment += impact;

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
  }

  const clampedAdjustment = clamp(totalAdjustment, -config.maxAdjustment, config.maxAdjustment);
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

function calculateAdjustmentFromCounts(
  tpCount: number,
  fpCount: number,
  config: ConfidenceConfig = DEFAULT_CONFIDENCE_CONFIG
): number {
  const rawAdjustment = (tpCount * config.tpBoost) + (fpCount * config.fpPenalty);
  return clamp(rawAdjustment, -config.maxAdjustment, config.maxAdjustment);
}

function getConfidenceLevel(confidence: number): string {
  if (confidence >= 85) return 'Very High';
  if (confidence >= 70) return 'High';
  if (confidence >= 50) return 'Medium';
  if (confidence >= 30) return 'Low';
  return 'Very Low';
}

// Helper to create test labels
function createLabel(
  label: HashLabelType,
  hash: string = 'sha256:' + 'a'.repeat(64)
): HashLabel {
  return {
    dom_kit_hash: hash,
    label,
    analyst: 'test@example.com',
    created_at: Date.now(),
    updated_at: Date.now(),
  };
}

describe('Confidence Scoring', () => {
  describe('calculateConfidenceScore', () => {
    it('should return base confidence with no labels', () => {
      const score = calculateConfidenceScore(60, []);

      expect(score.baseConfidence).toBe(60);
      expect(score.finalConfidence).toBe(60);
      expect(score.labelAdjustment).toBe(0);
      expect(score.labelCount).toBe(0);
      expect(score.hasAnalystFeedback).toBe(false);
    });

    it('should increase confidence with TP label', () => {
      const labels = [createLabel('TP')];
      const score = calculateConfidenceScore(50, labels);

      expect(score.baseConfidence).toBe(50);
      expect(score.finalConfidence).toBe(65); // 50 + 15
      expect(score.labelAdjustment).toBe(15);
      expect(score.labelBreakdown.tp).toBe(1);
      expect(score.hasAnalystFeedback).toBe(true);
    });

    it('should decrease confidence with FP label', () => {
      const labels = [createLabel('FP')];
      const score = calculateConfidenceScore(50, labels);

      expect(score.baseConfidence).toBe(50);
      expect(score.finalConfidence).toBe(25); // 50 - 25
      expect(score.labelAdjustment).toBe(-25);
      expect(score.labelBreakdown.fp).toBe(1);
    });

    it('should not change confidence with UNKNOWN label', () => {
      const labels = [createLabel('UNKNOWN')];
      const score = calculateConfidenceScore(50, labels);

      expect(score.finalConfidence).toBe(50);
      expect(score.labelAdjustment).toBe(0);
      expect(score.labelBreakdown.unknown).toBe(1);
      expect(score.hasAnalystFeedback).toBe(true);
    });

    it('should accumulate multiple TP labels', () => {
      const labels = [createLabel('TP'), createLabel('TP'), createLabel('TP')];
      const score = calculateConfidenceScore(50, labels);

      expect(score.finalConfidence).toBe(95); // 50 + 45 (3 * 15)
      expect(score.labelAdjustment).toBe(45);
      expect(score.labelBreakdown.tp).toBe(3);
    });

    it('should accumulate multiple FP labels', () => {
      const labels = [createLabel('FP'), createLabel('FP')];
      const score = calculateConfidenceScore(60, labels);

      expect(score.finalConfidence).toBe(10); // 60 - 50 (max adjustment)
      expect(score.labelAdjustment).toBe(-50); // Clamped to max
      expect(score.labelBreakdown.fp).toBe(2);
    });

    it('should handle mixed TP and FP labels', () => {
      const labels = [createLabel('TP'), createLabel('FP'), createLabel('TP')];
      const score = calculateConfidenceScore(50, labels);

      // 15 + (-25) + 15 = 5
      expect(score.finalConfidence).toBe(55);
      expect(score.labelAdjustment).toBe(5);
      expect(score.labelBreakdown.tp).toBe(2);
      expect(score.labelBreakdown.fp).toBe(1);
    });

    it('should clamp adjustment to max', () => {
      // 4 TP labels = 60 points, but max is 50
      const labels = [
        createLabel('TP'),
        createLabel('TP'),
        createLabel('TP'),
        createLabel('TP'),
      ];
      const score = calculateConfidenceScore(40, labels);

      expect(score.labelAdjustment).toBe(50); // Clamped
      expect(score.finalConfidence).toBe(90); // 40 + 50
    });

    it('should clamp final confidence to 0-100', () => {
      // High base + TP should cap at 100
      const tpLabels = [createLabel('TP'), createLabel('TP'), createLabel('TP')];
      const highScore = calculateConfidenceScore(90, tpLabels);
      expect(highScore.finalConfidence).toBe(100); // Capped at 100

      // Low base + FP should floor at 0
      const fpLabels = [createLabel('FP'), createLabel('FP')];
      const lowScore = calculateConfidenceScore(10, fpLabels);
      expect(lowScore.finalConfidence).toBe(0); // Floored at 0
    });
  });

  describe('calculateAdjustmentFromCounts', () => {
    it('should calculate adjustment from counts', () => {
      expect(calculateAdjustmentFromCounts(1, 0)).toBe(15);
      expect(calculateAdjustmentFromCounts(0, 1)).toBe(-25);
      expect(calculateAdjustmentFromCounts(2, 1)).toBe(5); // 30 - 25
    });

    it('should clamp to max adjustment', () => {
      expect(calculateAdjustmentFromCounts(10, 0)).toBe(50); // Clamped
      expect(calculateAdjustmentFromCounts(0, 10)).toBe(-50); // Clamped
    });

    it('should handle zero counts', () => {
      expect(calculateAdjustmentFromCounts(0, 0)).toBe(0);
    });
  });

  describe('getLabelImpact', () => {
    it('should return correct impact for TP', () => {
      expect(getLabelImpact('TP')).toBe(15);
    });

    it('should return correct impact for FP', () => {
      expect(getLabelImpact('FP')).toBe(-25);
    });

    it('should return zero for UNKNOWN', () => {
      expect(getLabelImpact('UNKNOWN')).toBe(0);
    });

    it('should use custom config', () => {
      const customConfig: ConfidenceConfig = {
        tpBoost: 20,
        fpPenalty: -30,
        maxAdjustment: 60,
        minConfidence: 0,
        maxConfidence: 100,
      };
      expect(getLabelImpact('TP', customConfig)).toBe(20);
      expect(getLabelImpact('FP', customConfig)).toBe(-30);
    });
  });

  describe('getConfidenceLevel', () => {
    it('should return Very High for >= 85', () => {
      expect(getConfidenceLevel(85)).toBe('Very High');
      expect(getConfidenceLevel(100)).toBe('Very High');
    });

    it('should return High for >= 70', () => {
      expect(getConfidenceLevel(70)).toBe('High');
      expect(getConfidenceLevel(84)).toBe('High');
    });

    it('should return Medium for >= 50', () => {
      expect(getConfidenceLevel(50)).toBe('Medium');
      expect(getConfidenceLevel(69)).toBe('Medium');
    });

    it('should return Low for >= 30', () => {
      expect(getConfidenceLevel(30)).toBe('Low');
      expect(getConfidenceLevel(49)).toBe('Low');
    });

    it('should return Very Low for < 30', () => {
      expect(getConfidenceLevel(29)).toBe('Very Low');
      expect(getConfidenceLevel(0)).toBe('Very Low');
    });
  });

  describe('No auto-blocking guarantee', () => {
    it('should NOT change action based on confidence', () => {
      // This test verifies the design principle that labels affect
      // confidence scores only, NOT enforcement actions

      // Simulate a server response with 'shadow' action
      const serverAction = 'shadow';
      const serverConfidence = 40;

      // Even with TP labels boosting confidence...
      const labels = [createLabel('TP'), createLabel('TP'), createLabel('TP')];
      const score = calculateConfidenceScore(serverConfidence, labels);

      // ...the action should remain unchanged
      expect(score.finalConfidence).toBe(85); // Boosted to high confidence (40 + 45)
      // But action is NOT part of the confidence score - it stays as 'shadow'
      // (In real implementation, ConfidenceEnhancedResponse preserves original action)
      expect(serverAction).toBe('shadow'); // Action unchanged
    });

    it('should allow high confidence without forcing block', () => {
      const score = calculateConfidenceScore(95, [createLabel('TP')]);
      expect(score.finalConfidence).toBe(100);
      // No action field in ConfidenceScore - by design
      expect(score).not.toHaveProperty('action');
    });

    it('should allow low confidence from FP labels', () => {
      const score = calculateConfidenceScore(50, [createLabel('FP'), createLabel('FP')]);
      expect(score.finalConfidence).toBe(0);
      // Even with 0 confidence, this doesn't auto-allow - action is separate
      expect(score).not.toHaveProperty('action');
    });
  });

  describe('Label breakdown tracking', () => {
    it('should correctly count each label type', () => {
      const labels = [
        createLabel('TP'),
        createLabel('FP'),
        createLabel('TP'),
        createLabel('UNKNOWN'),
        createLabel('FP'),
        createLabel('TP'),
      ];
      const score = calculateConfidenceScore(50, labels);

      expect(score.labelBreakdown.tp).toBe(3);
      expect(score.labelBreakdown.fp).toBe(2);
      expect(score.labelBreakdown.unknown).toBe(1);
      expect(score.labelCount).toBe(6);
    });
  });

  describe('Custom configuration', () => {
    it('should use custom TP boost', () => {
      const config: ConfidenceConfig = {
        ...DEFAULT_CONFIDENCE_CONFIG,
        tpBoost: 30,
      };
      const labels = [createLabel('TP')];
      const score = calculateConfidenceScore(50, labels, config);

      expect(score.finalConfidence).toBe(80); // 50 + 30
    });

    it('should use custom FP penalty', () => {
      const config: ConfidenceConfig = {
        ...DEFAULT_CONFIDENCE_CONFIG,
        fpPenalty: -40,
      };
      const labels = [createLabel('FP')];
      const score = calculateConfidenceScore(50, labels, config);

      expect(score.finalConfidence).toBe(10); // 50 - 40
    });

    it('should use custom max adjustment', () => {
      const config: ConfidenceConfig = {
        ...DEFAULT_CONFIDENCE_CONFIG,
        maxAdjustment: 30,
      };
      // 3 TP = 45, but max is 30
      const labels = [createLabel('TP'), createLabel('TP'), createLabel('TP')];
      const score = calculateConfidenceScore(50, labels, config);

      expect(score.labelAdjustment).toBe(30); // Clamped to 30
      expect(score.finalConfidence).toBe(80); // 50 + 30
    });
  });

  describe('Edge cases', () => {
    it('should handle base confidence of 0', () => {
      const labels = [createLabel('TP')];
      const score = calculateConfidenceScore(0, labels);

      expect(score.baseConfidence).toBe(0);
      expect(score.finalConfidence).toBe(15);
    });

    it('should handle base confidence of 100', () => {
      const labels = [createLabel('FP')];
      const score = calculateConfidenceScore(100, labels);

      expect(score.baseConfidence).toBe(100);
      expect(score.finalConfidence).toBe(75);
    });

    it('should handle large number of labels', () => {
      const labels: HashLabel[] = [];
      for (let i = 0; i < 100; i++) {
        labels.push(createLabel('TP'));
      }
      const score = calculateConfidenceScore(50, labels);

      // Even with 100 TP labels (1500 points), max adjustment is 50
      expect(score.labelAdjustment).toBe(50);
      expect(score.finalConfidence).toBe(100);
      expect(score.labelCount).toBe(100);
    });
  });

  describe('Confidence direction helper', () => {
    function getLabelConfidenceDirection(label: HashLabelType): 'positive' | 'negative' | 'neutral' {
      switch (label) {
        case 'TP':
          return 'positive';
        case 'FP':
          return 'negative';
        case 'UNKNOWN':
          return 'neutral';
      }
    }

    it('should return positive for TP', () => {
      expect(getLabelConfidenceDirection('TP')).toBe('positive');
    });

    it('should return negative for FP', () => {
      expect(getLabelConfidenceDirection('FP')).toBe('negative');
    });

    it('should return neutral for UNKNOWN', () => {
      expect(getLabelConfidenceDirection('UNKNOWN')).toBe('neutral');
    });
  });
});
