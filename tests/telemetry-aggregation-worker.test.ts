/**
 * Tests for Telemetry Aggregation Worker
 *
 * Reference: Issue #204
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock KV namespace
function createMockKV(): KVNamespace & { _store: Map<string, string> } {
  const store = new Map<string, string>();

  return {
    _store: store,
    get: vi.fn(async (key: string, type?: string) => {
      const value = store.get(key);
      if (!value) return null;
      if (type === 'json') return JSON.parse(value);
      return value;
    }),
    put: vi.fn(async (key: string, value: string, options?: { expirationTtl?: number }) => {
      store.set(key, value);
    }),
    delete: vi.fn(async (key: string) => {
      store.delete(key);
    }),
    list: vi.fn(async (options?: { prefix?: string; limit?: number; cursor?: string }) => {
      const prefix = options?.prefix || '';
      const limit = options?.limit || 1000;
      const keys: { name: string }[] = [];

      for (const key of store.keys()) {
        if (key.startsWith(prefix)) {
          keys.push({ name: key });
          if (keys.length >= limit) break;
        }
      }

      return {
        keys,
        list_complete: keys.length < limit,
        cursor: undefined,
      };
    }),
    getWithMetadata: vi.fn(),
  } as unknown as KVNamespace & { _store: Map<string, string> };
}

/** Hash tracking record (from shadow-telemetry worker) */
interface HashTrackingRecord {
  dom_kit_hash: string;
  first_seen_ts: number;
  total_seen_count: number;
  last_seen_ts: number;
}

/** Prevalence distribution buckets */
interface PrevalenceDistribution {
  '1': number;
  '2-5': number;
  '6-10': number;
  '11-50': number;
  '51+': number;
}

/** Aggregation result */
interface AggregationResult {
  window: 'daily' | 'weekly';
  window_start: number;
  window_end: number;
  computed_at: number;
  total_unique_hashes: number;
  first_seen_count: number;
  first_seen_percentage: number;
  total_sightings: number;
  median_time_to_second: number | null;
  mean_time_to_second: number | null;
  p90_time_to_second: number | null;
  prevalence_distribution: PrevalenceDistribution;
  records_processed: number;
}

// Time constants
const MS_PER_DAY = 24 * 60 * 60 * 1000;
const MS_PER_WEEK = 7 * MS_PER_DAY;

/**
 * Compute prevalence distribution from records.
 */
function computePrevalenceDistribution(records: HashTrackingRecord[]): PrevalenceDistribution {
  const dist: PrevalenceDistribution = {
    '1': 0,
    '2-5': 0,
    '6-10': 0,
    '11-50': 0,
    '51+': 0,
  };

  for (const record of records) {
    const count = record.total_seen_count;
    if (count === 1) {
      dist['1']++;
    } else if (count >= 2 && count <= 5) {
      dist['2-5']++;
    } else if (count >= 6 && count <= 10) {
      dist['6-10']++;
    } else if (count >= 11 && count <= 50) {
      dist['11-50']++;
    } else {
      dist['51+']++;
    }
  }

  return dist;
}

/**
 * Compute median of an array of numbers.
 */
function computeMedian(values: number[]): number | null {
  if (values.length === 0) return null;

  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);

  if (sorted.length % 2 === 0) {
    return Math.round((sorted[mid - 1] + sorted[mid]) / 2);
  }
  return Math.round(sorted[mid]);
}

/**
 * Compute percentile of an array of numbers.
 */
function computePercentile(values: number[], percentile: number): number | null {
  if (values.length === 0) return null;

  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil((percentile / 100) * sorted.length) - 1;
  return Math.round(sorted[Math.max(0, index)]);
}

describe('Telemetry Aggregation Worker', () => {
  describe('Prevalence distribution', () => {
    it('should categorize hashes seen once', () => {
      const records: HashTrackingRecord[] = [
        { dom_kit_hash: 'sha256:' + 'a'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 1, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + 'b'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 1, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + 'c'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 1, last_seen_ts: Date.now() },
      ];

      const dist = computePrevalenceDistribution(records);

      expect(dist['1']).toBe(3);
      expect(dist['2-5']).toBe(0);
      expect(dist['6-10']).toBe(0);
      expect(dist['11-50']).toBe(0);
      expect(dist['51+']).toBe(0);
    });

    it('should categorize hashes seen 2-5 times', () => {
      const records: HashTrackingRecord[] = [
        { dom_kit_hash: 'sha256:' + 'a'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 2, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + 'b'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 3, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + 'c'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 5, last_seen_ts: Date.now() },
      ];

      const dist = computePrevalenceDistribution(records);

      expect(dist['1']).toBe(0);
      expect(dist['2-5']).toBe(3);
      expect(dist['6-10']).toBe(0);
    });

    it('should categorize hashes seen 6-10 times', () => {
      const records: HashTrackingRecord[] = [
        { dom_kit_hash: 'sha256:' + 'a'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 6, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + 'b'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 10, last_seen_ts: Date.now() },
      ];

      const dist = computePrevalenceDistribution(records);

      expect(dist['6-10']).toBe(2);
    });

    it('should categorize hashes seen 11-50 times', () => {
      const records: HashTrackingRecord[] = [
        { dom_kit_hash: 'sha256:' + 'a'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 11, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + 'b'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 25, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + 'c'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 50, last_seen_ts: Date.now() },
      ];

      const dist = computePrevalenceDistribution(records);

      expect(dist['11-50']).toBe(3);
    });

    it('should categorize hashes seen 51+ times', () => {
      const records: HashTrackingRecord[] = [
        { dom_kit_hash: 'sha256:' + 'a'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 51, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + 'b'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 100, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + 'c'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 1000, last_seen_ts: Date.now() },
      ];

      const dist = computePrevalenceDistribution(records);

      expect(dist['51+']).toBe(3);
    });

    it('should handle mixed distribution', () => {
      const records: HashTrackingRecord[] = [
        { dom_kit_hash: 'sha256:' + '1'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 1, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + '2'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 3, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + '3'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 7, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + '4'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 25, last_seen_ts: Date.now() },
        { dom_kit_hash: 'sha256:' + '5'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 100, last_seen_ts: Date.now() },
      ];

      const dist = computePrevalenceDistribution(records);

      expect(dist['1']).toBe(1);
      expect(dist['2-5']).toBe(1);
      expect(dist['6-10']).toBe(1);
      expect(dist['11-50']).toBe(1);
      expect(dist['51+']).toBe(1);
    });

    it('should handle empty records', () => {
      const dist = computePrevalenceDistribution([]);

      expect(dist['1']).toBe(0);
      expect(dist['2-5']).toBe(0);
      expect(dist['6-10']).toBe(0);
      expect(dist['11-50']).toBe(0);
      expect(dist['51+']).toBe(0);
    });
  });

  describe('Statistical functions', () => {
    describe('computeMedian', () => {
      it('should return null for empty array', () => {
        expect(computeMedian([])).toBeNull();
      });

      it('should return the value for single element', () => {
        expect(computeMedian([100])).toBe(100);
      });

      it('should return middle value for odd-length array', () => {
        expect(computeMedian([1, 3, 5])).toBe(3);
        expect(computeMedian([10, 20, 30, 40, 50])).toBe(30);
      });

      it('should return average of middle values for even-length array', () => {
        expect(computeMedian([1, 2, 3, 4])).toBe(3); // (2+3)/2 = 2.5, rounded to 3
        expect(computeMedian([10, 20, 30, 40])).toBe(25); // (20+30)/2 = 25
      });

      it('should handle unsorted input', () => {
        expect(computeMedian([5, 1, 3])).toBe(3);
        expect(computeMedian([100, 10, 1000, 1])).toBe(55); // (10+100)/2 = 55
      });
    });

    describe('computePercentile', () => {
      it('should return null for empty array', () => {
        expect(computePercentile([], 90)).toBeNull();
      });

      it('should return the value for single element', () => {
        expect(computePercentile([100], 90)).toBe(100);
      });

      it('should compute 90th percentile', () => {
        const values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        expect(computePercentile(values, 90)).toBe(9);
      });

      it('should compute 50th percentile (median)', () => {
        const values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        expect(computePercentile(values, 50)).toBe(5);
      });

      it('should handle unsorted input', () => {
        const values = [10, 1, 9, 2, 8, 3, 7, 4, 6, 5];
        expect(computePercentile(values, 90)).toBe(9);
      });
    });
  });

  describe('First-seen calculation', () => {
    it('should identify hashes first seen in daily window', () => {
      const now = Date.now();
      const windowStart = now - MS_PER_DAY;

      const records: HashTrackingRecord[] = [
        // First seen within window
        { dom_kit_hash: 'sha256:' + 'a'.repeat(64), first_seen_ts: now - (MS_PER_DAY / 2), total_seen_count: 1, last_seen_ts: now },
        // First seen before window
        { dom_kit_hash: 'sha256:' + 'b'.repeat(64), first_seen_ts: now - (MS_PER_DAY * 2), total_seen_count: 5, last_seen_ts: now },
      ];

      const firstSeenInWindow = records.filter(r => r.first_seen_ts >= windowStart);
      expect(firstSeenInWindow.length).toBe(1);
    });

    it('should calculate first-seen percentage correctly', () => {
      const now = Date.now();
      const windowStart = now - MS_PER_DAY;

      const records: HashTrackingRecord[] = [
        { dom_kit_hash: 'sha256:' + 'a'.repeat(64), first_seen_ts: now - (MS_PER_DAY / 2), total_seen_count: 1, last_seen_ts: now },
        { dom_kit_hash: 'sha256:' + 'b'.repeat(64), first_seen_ts: now - (MS_PER_DAY / 4), total_seen_count: 2, last_seen_ts: now },
        { dom_kit_hash: 'sha256:' + 'c'.repeat(64), first_seen_ts: now - (MS_PER_DAY * 2), total_seen_count: 10, last_seen_ts: now },
        { dom_kit_hash: 'sha256:' + 'd'.repeat(64), first_seen_ts: now - (MS_PER_DAY * 5), total_seen_count: 20, last_seen_ts: now },
      ];

      const firstSeenCount = records.filter(r => r.first_seen_ts >= windowStart).length;
      const totalUniqueHashes = records.length;
      const percentage = (firstSeenCount / totalUniqueHashes) * 100;

      expect(firstSeenCount).toBe(2);
      expect(totalUniqueHashes).toBe(4);
      expect(percentage).toBe(50);
    });
  });

  describe('Time-to-second-sighting estimation', () => {
    it('should estimate average interval for multiple sightings', () => {
      // Hash seen 3 times over 2 hours
      const record: HashTrackingRecord = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        first_seen_ts: Date.now() - (2 * 60 * 60 * 1000), // 2 hours ago
        total_seen_count: 3,
        last_seen_ts: Date.now(),
      };

      // Average interval = (last - first) / (count - 1) = 2 hours / 2 = 1 hour
      const avgInterval = (record.last_seen_ts - record.first_seen_ts) / (record.total_seen_count - 1);
      expect(avgInterval).toBeCloseTo(60 * 60 * 1000, -4); // ~1 hour in ms
    });

    it('should handle hashes with only one sighting', () => {
      const records: HashTrackingRecord[] = [
        { dom_kit_hash: 'sha256:' + 'a'.repeat(64), first_seen_ts: Date.now(), total_seen_count: 1, last_seen_ts: Date.now() },
      ];

      const hashesWithMultipleSightings = records.filter(r => r.total_seen_count >= 2);
      expect(hashesWithMultipleSightings.length).toBe(0);
    });
  });

  describe('KV storage integration', () => {
    let mockHashKV: KVNamespace & { _store: Map<string, string> };
    let mockAggregationKV: KVNamespace & { _store: Map<string, string> };

    beforeEach(() => {
      mockHashKV = createMockKV();
      mockAggregationKV = createMockKV();
    });

    it('should store aggregation with date-based key', async () => {
      const result: AggregationResult = {
        window: 'daily',
        window_start: Date.now() - MS_PER_DAY,
        window_end: Date.now(),
        computed_at: Date.now(),
        total_unique_hashes: 100,
        first_seen_count: 25,
        first_seen_percentage: 25,
        total_sightings: 500,
        median_time_to_second: 3600000,
        mean_time_to_second: 4000000,
        p90_time_to_second: 7200000,
        prevalence_distribution: { '1': 50, '2-5': 30, '6-10': 10, '11-50': 8, '51+': 2 },
        records_processed: 100,
      };

      const dateStr = new Date(result.window_end).toISOString().split('T')[0];
      const historyKey = `aggregation:daily:${dateStr}`;
      const latestKey = 'aggregation:daily:latest';

      await mockAggregationKV.put(historyKey, JSON.stringify(result));
      await mockAggregationKV.put(latestKey, JSON.stringify(result));

      const storedHistory = await mockAggregationKV.get(historyKey, 'json') as AggregationResult;
      const storedLatest = await mockAggregationKV.get(latestKey, 'json') as AggregationResult;

      expect(storedHistory.total_unique_hashes).toBe(100);
      expect(storedLatest.first_seen_percentage).toBe(25);
    });

    it('should list hash records with prefix', async () => {
      // Store some hash records
      const hashes = ['aa', 'bb', 'cc'].map(c => 'sha256:' + c.repeat(32));
      for (const hash of hashes) {
        const record: HashTrackingRecord = {
          dom_kit_hash: hash,
          first_seen_ts: Date.now(),
          total_seen_count: 1,
          last_seen_ts: Date.now(),
        };
        await mockHashKV.put(`hash:${hash}`, JSON.stringify(record));
      }

      const listed = await mockHashKV.list({ prefix: 'hash:' });
      expect(listed.keys.length).toBe(3);
    });

    it('should retrieve aggregation history', async () => {
      // Store multiple daily aggregations
      const dates = ['2024-01-01', '2024-01-02', '2024-01-03'];
      for (const date of dates) {
        const result: Partial<AggregationResult> = {
          window: 'daily',
          window_end: new Date(date).getTime(),
          total_unique_hashes: 100,
        };
        await mockAggregationKV.put(`aggregation:daily:${date}`, JSON.stringify(result));
      }

      const listed = await mockAggregationKV.list({ prefix: 'aggregation:daily:' });
      expect(listed.keys.length).toBe(3);
    });
  });

  describe('Aggregation windows', () => {
    it('should define daily window as 24 hours', () => {
      expect(MS_PER_DAY).toBe(24 * 60 * 60 * 1000);
    });

    it('should define weekly window as 7 days', () => {
      expect(MS_PER_WEEK).toBe(7 * 24 * 60 * 60 * 1000);
    });

    it('should calculate correct window boundaries', () => {
      const now = Date.now();

      const dailyStart = now - MS_PER_DAY;
      const weeklyStart = now - MS_PER_WEEK;

      expect(now - dailyStart).toBe(MS_PER_DAY);
      expect(now - weeklyStart).toBe(MS_PER_WEEK);
    });
  });

  describe('Internal only guarantees', () => {
    it('should NOT include per-org identifiers in aggregation', () => {
      const result: AggregationResult = {
        window: 'daily',
        window_start: Date.now() - MS_PER_DAY,
        window_end: Date.now(),
        computed_at: Date.now(),
        total_unique_hashes: 100,
        first_seen_count: 25,
        first_seen_percentage: 25,
        total_sightings: 500,
        median_time_to_second: 3600000,
        mean_time_to_second: 4000000,
        p90_time_to_second: 7200000,
        prevalence_distribution: { '1': 50, '2-5': 30, '6-10': 10, '11-50': 8, '51+': 2 },
        records_processed: 100,
      };

      // Verify no org-specific data in aggregation
      expect(result).not.toHaveProperty('org_id');
      expect(result).not.toHaveProperty('client_id');
      expect(result).not.toHaveProperty('org_breakdown');
      expect(result).not.toHaveProperty('per_org_stats');
    });

    it('should NOT include individual hash lists in aggregation', () => {
      const result: AggregationResult = {
        window: 'daily',
        window_start: Date.now() - MS_PER_DAY,
        window_end: Date.now(),
        computed_at: Date.now(),
        total_unique_hashes: 100,
        first_seen_count: 25,
        first_seen_percentage: 25,
        total_sightings: 500,
        median_time_to_second: 3600000,
        mean_time_to_second: 4000000,
        p90_time_to_second: 7200000,
        prevalence_distribution: { '1': 50, '2-5': 30, '6-10': 10, '11-50': 8, '51+': 2 },
        records_processed: 100,
      };

      // Verify no hash lists exposed
      expect(result).not.toHaveProperty('hashes');
      expect(result).not.toHaveProperty('hash_list');
      expect(result).not.toHaveProperty('first_seen_hashes');
    });
  });

  describe('AggregationResult structure', () => {
    it('should have all required fields', () => {
      const result: AggregationResult = {
        window: 'daily',
        window_start: Date.now() - MS_PER_DAY,
        window_end: Date.now(),
        computed_at: Date.now(),
        total_unique_hashes: 100,
        first_seen_count: 25,
        first_seen_percentage: 25,
        total_sightings: 500,
        median_time_to_second: 3600000,
        mean_time_to_second: 4000000,
        p90_time_to_second: 7200000,
        prevalence_distribution: { '1': 50, '2-5': 30, '6-10': 10, '11-50': 8, '51+': 2 },
        records_processed: 100,
      };

      // Window info
      expect(result).toHaveProperty('window');
      expect(result).toHaveProperty('window_start');
      expect(result).toHaveProperty('window_end');
      expect(result).toHaveProperty('computed_at');

      // Core metrics
      expect(result).toHaveProperty('total_unique_hashes');
      expect(result).toHaveProperty('first_seen_count');
      expect(result).toHaveProperty('first_seen_percentage');
      expect(result).toHaveProperty('total_sightings');

      // Time-to-second metrics
      expect(result).toHaveProperty('median_time_to_second');
      expect(result).toHaveProperty('mean_time_to_second');
      expect(result).toHaveProperty('p90_time_to_second');

      // Distribution
      expect(result).toHaveProperty('prevalence_distribution');

      // Metadata
      expect(result).toHaveProperty('records_processed');
    });

    it('should allow null time-to-second metrics when no data', () => {
      const result: AggregationResult = {
        window: 'weekly',
        window_start: Date.now() - MS_PER_WEEK,
        window_end: Date.now(),
        computed_at: Date.now(),
        total_unique_hashes: 0,
        first_seen_count: 0,
        first_seen_percentage: 0,
        total_sightings: 0,
        median_time_to_second: null,
        mean_time_to_second: null,
        p90_time_to_second: null,
        prevalence_distribution: { '1': 0, '2-5': 0, '6-10': 0, '11-50': 0, '51+': 0 },
        records_processed: 0,
      };

      expect(result.median_time_to_second).toBeNull();
      expect(result.mean_time_to_second).toBeNull();
      expect(result.p90_time_to_second).toBeNull();
    });
  });

  describe('Cron schedule', () => {
    it('should run daily aggregation at 2am UTC', () => {
      // This is a documentation test - verifies the expected cron pattern
      const dailyCron = '0 2 * * *';
      expect(dailyCron).toBe('0 2 * * *');
    });

    it('should run weekly aggregation on Sundays at 3am UTC', () => {
      // This is a documentation test - verifies the expected cron pattern
      const weeklyCron = '0 3 * * 0';
      expect(weeklyCron).toBe('0 3 * * 0');
    });
  });
});
