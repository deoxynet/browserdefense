/**
 * BrowserDefense Telemetry Aggregation Worker
 *
 * Batch-based aggregation of DOM kit hash sightings for research.
 * Runs on a schedule (daily/weekly) to compute aggregate statistics.
 *
 * INTERNAL ONLY - No client feedback, no per-org data exposed.
 *
 * Aggregation windows:
 *   - Daily: 24-hour rolling windows
 *   - Weekly: 7-day rolling windows
 *
 * Metrics computed:
 *   - total_unique_hashes: Count of unique DOM kit hashes seen
 *   - first_seen_count: Hashes seen for the first time in this window
 *   - first_seen_percentage: % of sightings that were first-seen
 *   - median_time_to_second: Median time between first and second sighting
 *   - prevalence_distribution: Distribution of sighting counts
 *
 * Reference: Issue #204
 */

export interface AggregationEnv {
  /** KV namespace containing hash tracking data */
  HASH_TRACKING_KV: KVNamespace;
  /** KV namespace for storing aggregation results */
  AGGREGATION_KV: KVNamespace;
}

/** Hash tracking record (from shadow-telemetry worker) */
interface HashTrackingRecord {
  dom_kit_hash: string;
  first_seen_ts: number;
  total_seen_count: number;
  last_seen_ts: number;
}

/** Time window for aggregation */
type AggregationWindow = 'daily' | 'weekly';

/** Aggregation result for a time window */
export interface AggregationResult {
  /** Aggregation window type */
  window: AggregationWindow;
  /** Window start timestamp (Unix ms) */
  window_start: number;
  /** Window end timestamp (Unix ms) */
  window_end: number;
  /** When this aggregation was computed */
  computed_at: number;

  // Core metrics
  /** Total unique hashes in the dataset */
  total_unique_hashes: number;
  /** Hashes first seen during this window */
  first_seen_count: number;
  /** Percentage of first-seen hashes (0-100) */
  first_seen_percentage: number;
  /** Total sightings during this window */
  total_sightings: number;

  // Time-to-second-sighting metrics
  /** Median time (ms) from first to second sighting */
  median_time_to_second: number | null;
  /** Mean time (ms) from first to second sighting */
  mean_time_to_second: number | null;
  /** P90 time (ms) from first to second sighting */
  p90_time_to_second: number | null;

  // Prevalence distribution (count of hashes with N sightings)
  /** Distribution: { "1": count, "2-5": count, "6-10": count, "11-50": count, "51+": count } */
  prevalence_distribution: PrevalenceDistribution;

  // Metadata
  /** Number of records processed */
  records_processed: number;
}

/** Prevalence distribution buckets */
interface PrevalenceDistribution {
  /** Hashes seen exactly once */
  '1': number;
  /** Hashes seen 2-5 times */
  '2-5': number;
  /** Hashes seen 6-10 times */
  '6-10': number;
  /** Hashes seen 11-50 times */
  '11-50': number;
  /** Hashes seen 51+ times */
  '51+': number;
}

// Time constants
const MS_PER_DAY = 24 * 60 * 60 * 1000;
const MS_PER_WEEK = 7 * MS_PER_DAY;

export default {
  /**
   * Scheduled handler - runs on cron trigger.
   * Configured in wrangler.toml with cron triggers.
   */
  async scheduled(
    controller: ScheduledController,
    env: AggregationEnv,
    _ctx: ExecutionContext
  ): Promise<void> {
    console.log('[Aggregation] Scheduled run started');

    try {
      // Run daily aggregation
      const dailyResult = await computeAggregation(env, 'daily');
      await storeAggregation(env, dailyResult);
      console.log(`[Aggregation] Daily: ${dailyResult.total_unique_hashes} hashes, ${dailyResult.first_seen_percentage.toFixed(1)}% first-seen`);

      // Run weekly aggregation (only on specific days or always)
      const weeklyResult = await computeAggregation(env, 'weekly');
      await storeAggregation(env, weeklyResult);
      console.log(`[Aggregation] Weekly: ${weeklyResult.total_unique_hashes} hashes, ${weeklyResult.first_seen_percentage.toFixed(1)}% first-seen`);
    } catch (err) {
      console.error('[Aggregation] Error:', err);
      throw err;
    }
  },

  /**
   * HTTP handler - for manual triggers and health checks.
   */
  async fetch(request: Request, env: AggregationEnv): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers (internal only, but useful for admin tools)
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Health check
      if (path === '/health') {
        return jsonResponse({ status: 'ok', service: 'telemetry-aggregation' }, corsHeaders);
      }

      // Manual trigger (requires auth in production)
      if (path === '/aggregate' && request.method === 'POST') {
        const window = url.searchParams.get('window') as AggregationWindow || 'daily';
        const result = await computeAggregation(env, window);
        await storeAggregation(env, result);
        return jsonResponse({ status: 'completed', result }, corsHeaders);
      }

      // Get latest aggregation
      if (path === '/latest' && request.method === 'GET') {
        const window = url.searchParams.get('window') as AggregationWindow || 'daily';
        const result = await getLatestAggregation(env, window);
        if (!result) {
          return jsonResponse({ error: 'No aggregation found' }, corsHeaders, 404);
        }
        return jsonResponse(result, corsHeaders);
      }

      // Get aggregation history
      if (path === '/history' && request.method === 'GET') {
        const window = url.searchParams.get('window') as AggregationWindow || 'daily';
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '30', 10), 100);
        const history = await getAggregationHistory(env, window, limit);
        return jsonResponse({ window, count: history.length, results: history }, corsHeaders);
      }

      return jsonResponse({ error: 'Not found' }, corsHeaders, 404);
    } catch (err) {
      console.error('[Aggregation] HTTP error:', err);
      return jsonResponse({ error: 'Internal server error' }, corsHeaders, 500);
    }
  },
};

/**
 * Compute aggregation for a time window.
 */
async function computeAggregation(
  env: AggregationEnv,
  window: AggregationWindow
): Promise<AggregationResult> {
  const now = Date.now();
  const windowMs = window === 'daily' ? MS_PER_DAY : MS_PER_WEEK;
  const windowStart = now - windowMs;
  const windowEnd = now;

  // Fetch all hash tracking records
  // Note: In production with large datasets, this would need pagination
  const records = await fetchAllHashRecords(env);

  // Compute metrics
  const totalUniqueHashes = records.length;

  // First-seen in this window
  const firstSeenInWindow = records.filter(r => r.first_seen_ts >= windowStart && r.first_seen_ts <= windowEnd);
  const firstSeenCount = firstSeenInWindow.length;
  const firstSeenPercentage = totalUniqueHashes > 0 ? (firstSeenCount / totalUniqueHashes) * 100 : 0;

  // Total sightings (sum of all counts for records active in window)
  const activeInWindow = records.filter(r => r.last_seen_ts >= windowStart);
  const totalSightings = activeInWindow.reduce((sum, r) => sum + r.total_seen_count, 0);

  // Time-to-second-sighting (for hashes seen more than once)
  const hashesWithMultipleSightings = records.filter(r => r.total_seen_count >= 2);
  const timesToSecond = hashesWithMultipleSightings.map(r => {
    // Estimate time to second sighting based on average interval
    // This is an approximation since we don't store individual sighting times
    const avgInterval = (r.last_seen_ts - r.first_seen_ts) / (r.total_seen_count - 1);
    return avgInterval;
  }).filter(t => t > 0 && isFinite(t));

  const medianTimeToSecond = computeMedian(timesToSecond);
  const meanTimeToSecond = timesToSecond.length > 0 ? timesToSecond.reduce((a, b) => a + b, 0) / timesToSecond.length : null;
  const p90TimeToSecond = computePercentile(timesToSecond, 90);

  // Prevalence distribution
  const prevalenceDistribution = computePrevalenceDistribution(records);

  return {
    window,
    window_start: windowStart,
    window_end: windowEnd,
    computed_at: now,
    total_unique_hashes: totalUniqueHashes,
    first_seen_count: firstSeenCount,
    first_seen_percentage: Math.round(firstSeenPercentage * 100) / 100,
    total_sightings: totalSightings,
    median_time_to_second: medianTimeToSecond,
    mean_time_to_second: meanTimeToSecond ? Math.round(meanTimeToSecond) : null,
    p90_time_to_second: p90TimeToSecond,
    prevalence_distribution: prevalenceDistribution,
    records_processed: records.length,
  };
}

/**
 * Fetch all hash tracking records from KV.
 * Note: In production, this would need to handle pagination for large datasets.
 */
async function fetchAllHashRecords(env: AggregationEnv): Promise<HashTrackingRecord[]> {
  const records: HashTrackingRecord[] = [];
  let cursor: string | undefined;

  do {
    const listed = await env.HASH_TRACKING_KV.list({
      prefix: 'hash:',
      limit: 1000,
      cursor,
    });

    // Fetch each record
    for (const key of listed.keys) {
      const data = await env.HASH_TRACKING_KV.get(key.name, 'json');
      if (data) {
        records.push(data as HashTrackingRecord);
      }
    }

    cursor = listed.list_complete ? undefined : listed.cursor;
  } while (cursor);

  return records;
}

/**
 * Store aggregation result in KV.
 */
async function storeAggregation(env: AggregationEnv, result: AggregationResult): Promise<void> {
  // Store with timestamp-based key for history
  const dateStr = new Date(result.window_end).toISOString().split('T')[0]; // YYYY-MM-DD
  const historyKey = `aggregation:${result.window}:${dateStr}`;
  await env.AGGREGATION_KV.put(historyKey, JSON.stringify(result), {
    expirationTtl: 90 * 24 * 60 * 60, // Keep 90 days of history
  });

  // Store as latest
  const latestKey = `aggregation:${result.window}:latest`;
  await env.AGGREGATION_KV.put(latestKey, JSON.stringify(result));

  console.log(`[Aggregation] Stored ${result.window} aggregation for ${dateStr}`);
}

/**
 * Get the latest aggregation result.
 */
async function getLatestAggregation(
  env: AggregationEnv,
  window: AggregationWindow
): Promise<AggregationResult | null> {
  const key = `aggregation:${window}:latest`;
  return env.AGGREGATION_KV.get(key, 'json');
}

/**
 * Get aggregation history.
 */
async function getAggregationHistory(
  env: AggregationEnv,
  window: AggregationWindow,
  limit: number
): Promise<AggregationResult[]> {
  const results: AggregationResult[] = [];
  const listed = await env.AGGREGATION_KV.list({
    prefix: `aggregation:${window}:`,
    limit: limit + 1, // +1 to skip 'latest'
  });

  for (const key of listed.keys) {
    if (key.name.endsWith(':latest')) continue;

    const data = await env.AGGREGATION_KV.get(key.name, 'json');
    if (data) {
      results.push(data as AggregationResult);
    }

    if (results.length >= limit) break;
  }

  // Sort by window_end descending (most recent first)
  results.sort((a, b) => b.window_end - a.window_end);

  return results;
}

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

/**
 * Return a JSON response.
 */
function jsonResponse(
  data: unknown,
  corsHeaders: Record<string, string>,
  status: number = 200
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}
