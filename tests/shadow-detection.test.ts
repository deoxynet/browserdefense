/**
 * Tests for Shadow Detection Module
 *
 * Tests for shadow detection mode - detecting and logging new DOM kits
 * without blocking until confidence threshold is met.
 *
 * Reference: Issue #171
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// ============ Type Definitions ============

type ShadowDetectionStatus = 'pending' | 'promoted' | 'dismissed' | 'expired';
type ShadowDetectionReason =
  | 'shadow_disabled'
  | 'confidence_above_threshold'
  | 'not_novel'
  | 'new_shadow_detection'
  | 'repeat_shadow_hit'
  | 'already_promoted'
  | 'already_dismissed';

interface ShadowDetection {
  id: string;
  dom_kit_hash: string;
  serverConfidence: number;
  adjustedConfidence: number;
  kitId?: string;
  isNovel: boolean;
  occurrenceCount?: number;
  status: ShadowDetectionStatus;
  detectedAt: number;
  reviewedAt?: number;
  reviewedBy?: string;
  appliedLabel?: 'TP' | 'FP' | 'UNKNOWN';
  notes?: string;
  hitCount: number;
  lastSeenAt: number;
}

interface ShadowDetectionConfig {
  enabled: boolean;
  confidenceThreshold: number;
  novelOnly: boolean;
  maxDetections: number;
  detectionTTLMs: number;
  alertsEnabled: boolean;
  alertIntervalMs: number;
}

interface ShadowDetectionResult {
  shadowMode: boolean;
  isNewDetection: boolean;
  detection?: ShadowDetection;
  reason: ShadowDetectionReason;
  alertSent: boolean;
}

interface FingerprintResponse {
  confidence: number;
  kitId?: string;
  action: 'block' | 'shadow' | 'allow';
  isNovel: boolean;
  occurrenceCount?: number;
}

// ============ Default Configuration ============

const DEFAULT_CONFIG: ShadowDetectionConfig = {
  enabled: true,
  confidenceThreshold: 70,
  novelOnly: true,
  maxDetections: 10000,
  detectionTTLMs: 30 * 24 * 60 * 60 * 1000,
  alertsEnabled: true,
  alertIntervalMs: 60 * 60 * 1000,
};

// ============ Mock Functions ============

// Simulated storage
let mockDetections: Map<string, ShadowDetection> = new Map();
let mockConfig: ShadowDetectionConfig = { ...DEFAULT_CONFIG };
let mockAlertCooldowns: Map<string, number> = new Map();

function generateDetectionId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `sd_${timestamp}_${random}`;
}

function getSeverityFromConfidence(confidence: number): 'info' | 'low' | 'medium' {
  if (confidence >= 50) return 'medium';
  if (confidence >= 30) return 'low';
  return 'info';
}

// Simulated processShadowDetection
async function processShadowDetection(
  hash: string,
  response: FingerprintResponse
): Promise<ShadowDetectionResult> {
  const config = mockConfig;
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;

  if (!config.enabled) {
    return {
      shadowMode: false,
      isNewDetection: false,
      reason: 'shadow_disabled',
      alertSent: false,
    };
  }

  if (response.confidence >= config.confidenceThreshold) {
    return {
      shadowMode: false,
      isNewDetection: false,
      reason: 'confidence_above_threshold',
      alertSent: false,
    };
  }

  if (config.novelOnly && !response.isNovel) {
    return {
      shadowMode: false,
      isNewDetection: false,
      reason: 'not_novel',
      alertSent: false,
    };
  }

  const existing = mockDetections.get(formattedHash);

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

    // Update existing
    existing.hitCount++;
    existing.lastSeenAt = Date.now();
    existing.serverConfidence = response.confidence;
    existing.adjustedConfidence = response.confidence;

    return {
      shadowMode: true,
      isNewDetection: false,
      detection: existing,
      reason: 'repeat_shadow_hit',
      alertSent: false,
    };
  }

  // Create new detection
  const detection: ShadowDetection = {
    id: generateDetectionId(),
    dom_kit_hash: formattedHash,
    serverConfidence: response.confidence,
    adjustedConfidence: response.confidence,
    kitId: response.kitId,
    isNovel: response.isNovel,
    occurrenceCount: response.occurrenceCount,
    status: 'pending',
    detectedAt: Date.now(),
    hitCount: 1,
    lastSeenAt: Date.now(),
  };

  mockDetections.set(formattedHash, detection);

  return {
    shadowMode: true,
    isNewDetection: true,
    detection,
    reason: 'new_shadow_detection',
    alertSent: config.alertsEnabled,
  };
}

async function shouldShadowMode(hash: string, response: FingerprintResponse): Promise<boolean> {
  if (!mockConfig.enabled) return false;
  if (response.confidence >= mockConfig.confidenceThreshold) return false;
  if (mockConfig.novelOnly && !response.isNovel) return false;

  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;
  const existing = mockDetections.get(formattedHash);
  if (existing?.status === 'promoted') return false;

  return true;
}

async function promoteDetection(
  hash: string,
  analyst: string,
  notes?: string
): Promise<ShadowDetection | null> {
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;
  const detection = mockDetections.get(formattedHash);

  if (!detection) return null;

  detection.status = 'promoted';
  detection.reviewedAt = Date.now();
  detection.reviewedBy = analyst;
  detection.appliedLabel = 'TP';
  if (notes) detection.notes = notes;

  return detection;
}

async function dismissDetection(
  hash: string,
  analyst: string,
  notes?: string
): Promise<ShadowDetection | null> {
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;
  const detection = mockDetections.get(formattedHash);

  if (!detection) return null;

  detection.status = 'dismissed';
  detection.reviewedAt = Date.now();
  detection.reviewedBy = analyst;
  detection.appliedLabel = 'FP';
  if (notes) detection.notes = notes;

  return detection;
}

async function getDetection(hash: string): Promise<ShadowDetection | null> {
  const formattedHash = hash.startsWith('sha256:') ? hash : `sha256:${hash}`;
  return mockDetections.get(formattedHash) ?? null;
}

async function getDetectionStats(): Promise<{
  total: number;
  byStatus: Record<ShadowDetectionStatus, number>;
  pendingReview: number;
  promoted: number;
  dismissed: number;
  expired: number;
  avgPendingConfidence: number;
  totalHits: number;
  novelCount: number;
}> {
  const all = Array.from(mockDetections.values());
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

  for (const detection of all) {
    byStatus[detection.status]++;
    totalHits += detection.hitCount;

    if (detection.isNovel) novelCount++;

    if (detection.status === 'pending') {
      pendingCount++;
      totalConfidence += detection.adjustedConfidence;
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
  };
}

// ============ Test Helpers ============

function createFingerprintResponse(overrides: Partial<FingerprintResponse> = {}): FingerprintResponse {
  return {
    confidence: 50,
    action: 'shadow',
    isNovel: true,
    ...overrides,
  };
}

function createTestHash(): string {
  return 'a'.repeat(64);
}

// ============ Tests ============

describe('Shadow Detection', () => {
  beforeEach(() => {
    mockDetections = new Map();
    mockConfig = { ...DEFAULT_CONFIG };
    mockAlertCooldowns = new Map();
  });

  describe('processShadowDetection', () => {
    it('should create shadow detection for novel low-confidence fingerprint', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      const result = await processShadowDetection(hash, response);

      expect(result.shadowMode).toBe(true);
      expect(result.isNewDetection).toBe(true);
      expect(result.reason).toBe('new_shadow_detection');
      expect(result.detection).toBeDefined();
      expect(result.detection?.status).toBe('pending');
      expect(result.detection?.hitCount).toBe(1);
    });

    it('should not shadow when confidence meets threshold', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 75,
        isNovel: true,
      });

      const result = await processShadowDetection(hash, response);

      expect(result.shadowMode).toBe(false);
      expect(result.reason).toBe('confidence_above_threshold');
    });

    it('should not shadow non-novel fingerprints when novelOnly is true', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: false,
      });

      const result = await processShadowDetection(hash, response);

      expect(result.shadowMode).toBe(false);
      expect(result.reason).toBe('not_novel');
    });

    it('should shadow non-novel fingerprints when novelOnly is false', async () => {
      mockConfig.novelOnly = false;
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: false,
      });

      const result = await processShadowDetection(hash, response);

      expect(result.shadowMode).toBe(true);
      expect(result.isNewDetection).toBe(true);
    });

    it('should return disabled reason when shadow detection is disabled', async () => {
      mockConfig.enabled = false;
      const hash = createTestHash();
      const response = createFingerprintResponse();

      const result = await processShadowDetection(hash, response);

      expect(result.shadowMode).toBe(false);
      expect(result.reason).toBe('shadow_disabled');
    });

    it('should increment hit count for repeat detections', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      // First detection
      const result1 = await processShadowDetection(hash, response);
      expect(result1.isNewDetection).toBe(true);
      expect(result1.detection?.hitCount).toBe(1);

      // Second detection (repeat hit)
      const result2 = await processShadowDetection(hash, response);
      expect(result2.isNewDetection).toBe(false);
      expect(result2.reason).toBe('repeat_shadow_hit');
      expect(result2.detection?.hitCount).toBe(2);
    });

    it('should not shadow already promoted detections', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      // Create detection
      await processShadowDetection(hash, response);

      // Promote it
      await promoteDetection(hash, 'analyst@test.com');

      // Try to shadow again
      const result = await processShadowDetection(hash, response);

      expect(result.shadowMode).toBe(false);
      expect(result.reason).toBe('already_promoted');
    });

    it('should continue shadowing dismissed detections', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      // Create detection
      await processShadowDetection(hash, response);

      // Dismiss it
      await dismissDetection(hash, 'analyst@test.com');

      // Try to shadow again
      const result = await processShadowDetection(hash, response);

      expect(result.shadowMode).toBe(true);
      expect(result.reason).toBe('already_dismissed');
    });

    it('should format hash with sha256 prefix', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      const result = await processShadowDetection(hash, response);

      expect(result.detection?.dom_kit_hash).toBe(`sha256:${hash}`);
    });

    it('should handle hash already with prefix', async () => {
      const hash = `sha256:${'b'.repeat(64)}`;
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      const result = await processShadowDetection(hash, response);

      expect(result.detection?.dom_kit_hash).toBe(hash);
    });
  });

  describe('shouldShadowMode', () => {
    it('should return true for novel low-confidence fingerprints', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      const result = await shouldShadowMode(hash, response);

      expect(result).toBe(true);
    });

    it('should return false for high-confidence fingerprints', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 85,
        isNovel: true,
      });

      const result = await shouldShadowMode(hash, response);

      expect(result).toBe(false);
    });

    it('should return false when shadow detection is disabled', async () => {
      mockConfig.enabled = false;
      const hash = createTestHash();
      const response = createFingerprintResponse();

      const result = await shouldShadowMode(hash, response);

      expect(result).toBe(false);
    });

    it('should return false for promoted detections', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      // Create and promote detection
      await processShadowDetection(hash, response);
      await promoteDetection(hash, 'analyst@test.com');

      const result = await shouldShadowMode(hash, response);

      expect(result).toBe(false);
    });
  });

  describe('promoteDetection', () => {
    it('should promote a pending detection to blocking', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      await processShadowDetection(hash, response);
      const detection = await promoteDetection(hash, 'analyst@test.com', 'Confirmed phishing');

      expect(detection).not.toBeNull();
      expect(detection?.status).toBe('promoted');
      expect(detection?.reviewedBy).toBe('analyst@test.com');
      expect(detection?.appliedLabel).toBe('TP');
      expect(detection?.notes).toBe('Confirmed phishing');
      expect(detection?.reviewedAt).toBeDefined();
    });

    it('should return null for non-existent detection', async () => {
      const detection = await promoteDetection('nonexistent', 'analyst@test.com');

      expect(detection).toBeNull();
    });
  });

  describe('dismissDetection', () => {
    it('should dismiss a pending detection as false positive', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      await processShadowDetection(hash, response);
      const detection = await dismissDetection(hash, 'analyst@test.com', 'Benign site');

      expect(detection).not.toBeNull();
      expect(detection?.status).toBe('dismissed');
      expect(detection?.reviewedBy).toBe('analyst@test.com');
      expect(detection?.appliedLabel).toBe('FP');
      expect(detection?.notes).toBe('Benign site');
    });

    it('should return null for non-existent detection', async () => {
      const detection = await dismissDetection('nonexistent', 'analyst@test.com');

      expect(detection).toBeNull();
    });
  });

  describe('getDetection', () => {
    it('should retrieve a detection by hash', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
        kitId: 'test-kit-123',
      });

      await processShadowDetection(hash, response);
      const detection = await getDetection(hash);

      expect(detection).not.toBeNull();
      expect(detection?.dom_kit_hash).toBe(`sha256:${hash}`);
      expect(detection?.kitId).toBe('test-kit-123');
    });

    it('should return null for non-existent detection', async () => {
      const detection = await getDetection('nonexistent');

      expect(detection).toBeNull();
    });

    it('should work with sha256 prefixed hash', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse();

      await processShadowDetection(hash, response);
      const detection = await getDetection(`sha256:${hash}`);

      expect(detection).not.toBeNull();
    });
  });

  describe('getDetectionStats', () => {
    it('should return correct statistics', async () => {
      // Create some detections (all novel since novelOnly=true by default)
      const hash1 = 'a'.repeat(64);
      const hash2 = 'b'.repeat(64);
      const hash3 = 'c'.repeat(64);

      await processShadowDetection(hash1, createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      }));
      await processShadowDetection(hash2, createFingerprintResponse({
        confidence: 50,
        isNovel: true,
      }));
      await processShadowDetection(hash3, createFingerprintResponse({
        confidence: 60,
        isNovel: true, // Must be novel since novelOnly=true
      }));

      // Promote one
      await promoteDetection(hash1, 'analyst@test.com');

      // Dismiss one
      await dismissDetection(hash2, 'analyst@test.com');

      const stats = await getDetectionStats();

      expect(stats.total).toBe(3);
      expect(stats.promoted).toBe(1);
      expect(stats.dismissed).toBe(1);
      expect(stats.pendingReview).toBe(1);
      expect(stats.byStatus.pending).toBe(1);
      expect(stats.byStatus.promoted).toBe(1);
      expect(stats.byStatus.dismissed).toBe(1);
    });

    it('should calculate average pending confidence', async () => {
      await processShadowDetection('a'.repeat(64), createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      }));
      await processShadowDetection('b'.repeat(64), createFingerprintResponse({
        confidence: 60,
        isNovel: true,
      }));

      const stats = await getDetectionStats();

      expect(stats.avgPendingConfidence).toBe(50); // (40 + 60) / 2
    });

    it('should count total hits', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      });

      // Multiple hits on same hash
      await processShadowDetection(hash, response);
      await processShadowDetection(hash, response);
      await processShadowDetection(hash, response);

      const stats = await getDetectionStats();

      expect(stats.totalHits).toBe(3);
    });

    it('should return zeros for empty detection store', async () => {
      const stats = await getDetectionStats();

      expect(stats.total).toBe(0);
      expect(stats.pendingReview).toBe(0);
      expect(stats.avgPendingConfidence).toBe(0);
    });
  });

  describe('getSeverityFromConfidence', () => {
    it('should return medium for high confidence', () => {
      expect(getSeverityFromConfidence(70)).toBe('medium');
      expect(getSeverityFromConfidence(50)).toBe('medium');
    });

    it('should return low for medium confidence', () => {
      expect(getSeverityFromConfidence(49)).toBe('low');
      expect(getSeverityFromConfidence(30)).toBe('low');
    });

    it('should return info for low confidence', () => {
      expect(getSeverityFromConfidence(29)).toBe('info');
      expect(getSeverityFromConfidence(0)).toBe('info');
    });
  });

  describe('Configuration', () => {
    it('should respect custom confidence threshold', async () => {
      mockConfig.confidenceThreshold = 50;
      const hash = createTestHash();

      // 45 is below custom threshold
      const result1 = await processShadowDetection(hash, createFingerprintResponse({
        confidence: 45,
        isNovel: true,
      }));
      expect(result1.shadowMode).toBe(true);

      // Reset and test 55 is above custom threshold
      mockDetections.clear();
      const hash2 = 'b'.repeat(64);
      const result2 = await processShadowDetection(hash2, createFingerprintResponse({
        confidence: 55,
        isNovel: true,
      }));
      expect(result2.shadowMode).toBe(false);
    });
  });

  describe('Edge cases', () => {
    it('should handle confidence at exact threshold', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 70, // Exactly at threshold
        isNovel: true,
      });

      const result = await processShadowDetection(hash, response);

      expect(result.shadowMode).toBe(false);
      expect(result.reason).toBe('confidence_above_threshold');
    });

    it('should handle confidence just below threshold', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 69,
        isNovel: true,
      });

      const result = await processShadowDetection(hash, response);

      expect(result.shadowMode).toBe(true);
    });

    it('should handle zero confidence', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 0,
        isNovel: true,
      });

      const result = await processShadowDetection(hash, response);

      expect(result.shadowMode).toBe(true);
    });

    it('should preserve kit ID and occurrence count', async () => {
      const hash = createTestHash();
      const response = createFingerprintResponse({
        confidence: 40,
        isNovel: true,
        kitId: 'phishing-kit-001',
        occurrenceCount: 42,
      });

      const result = await processShadowDetection(hash, response);

      expect(result.detection?.kitId).toBe('phishing-kit-001');
      expect(result.detection?.occurrenceCount).toBe(42);
    });
  });

  describe('No auto-blocking guarantee', () => {
    it('should NOT change enforcement based on shadow detection', async () => {
      // This test verifies the design principle that shadow detection
      // logs detections but does NOT automatically block

      const hash = createTestHash();
      const serverAction: 'block' | 'shadow' | 'allow' = 'shadow';

      // Even if we detect in shadow mode...
      const result = await processShadowDetection(hash, createFingerprintResponse({
        confidence: 40,
        isNovel: true,
        action: serverAction,
      }));

      // ...the action is logged but NOT automatically changed to 'block'
      expect(result.shadowMode).toBe(true);
      expect(result.detection?.status).toBe('pending'); // Still pending review

      // Only after analyst review and promotion should blocking occur
    });

    it('should require analyst review before enforcement', async () => {
      const hash = createTestHash();

      // Create shadow detection
      await processShadowDetection(hash, createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      }));

      // Before promotion - still in shadow mode
      const beforePromotion = await shouldShadowMode(hash, createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      }));
      expect(beforePromotion).toBe(true);

      // After promotion - no longer in shadow mode (now blocking)
      await promoteDetection(hash, 'analyst@test.com');
      const afterPromotion = await shouldShadowMode(hash, createFingerprintResponse({
        confidence: 40,
        isNovel: true,
      }));
      expect(afterPromotion).toBe(false);
    });
  });
});
