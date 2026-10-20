/**
 * Performance benchmark tests for BinaryHashSet at scale.
 *
 * Tests storage and performance characteristics at:
 * - 10,000 hashes
 * - 100,000 hashes
 * - 300,000 hashes
 * - 1,000,000 hashes
 *
 * Metrics measured:
 * - Cold start time (deserialization to ready-to-block)
 * - Memory/storage size
 * - Delta update time (adding 1k new hashes)
 * - Lookup time (binary search)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { BinaryHashSet, hexToBytes } from '../src/storage/binary-set';

// Test scales
const SCALES = [10_000, 100_000, 300_000, 1_000_000] as const;

// Helper to generate deterministic hash from seed
function hashFromSeed(seed: number): string {
  // Create a deterministic 64-char hex string from seed
  const seedHex = seed.toString(16).padStart(16, '0');
  // Repeat and truncate to get 64 chars
  return (seedHex.repeat(4)).slice(0, 64);
}

// Helper to generate array of hex strings
function generateHexStrings(count: number, startSeed: number = 0): string[] {
  const strings: string[] = [];
  for (let i = 0; i < count; i++) {
    strings.push(hashFromSeed(startSeed + i));
  }
  return strings;
}

// Store precomputed sets for lookup tests
const precomputedSets: Map<number, { set: BinaryHashSet; serialized: string }> = new Map();

// Precompute sets at each scale (run once before all tests)
beforeAll(() => {
  console.log('\n=== Precomputing hash sets for benchmarks ===\n');

  for (const scale of SCALES) {
    const hexStrings = generateHexStrings(scale);
    const set = BinaryHashSet.fromHexStrings(hexStrings);
    const serialized = set.serialize();
    precomputedSets.set(scale, { set, serialized });

    const sizeKB = Math.round(serialized.length / 1024);
    const sizeMB = (serialized.length / (1024 * 1024)).toFixed(2);
    console.log(`  ${scale.toLocaleString()} hashes: ${sizeKB} KB (${sizeMB} MB)`);
  }

  console.log('\n');
}, 120_000); // Allow 2 minutes for precomputation

describe('Performance Benchmarks', () => {
  describe('Storage Size', () => {
    it.each(SCALES)('should calculate storage size for %d hashes', (scale) => {
      const { serialized } = precomputedSets.get(scale)!;

      const sizeBytes = serialized.length;
      const rawBinarySize = scale * 32; // 32 bytes per hash
      const base64Overhead = ((sizeBytes - rawBinarySize * 4 / 3) / sizeBytes) * 100;

      // Report storage metrics
      console.log(`\n${scale.toLocaleString()} hashes storage:`);
      console.log(`  Raw binary: ${(rawBinarySize / 1024).toFixed(1)} KB`);
      console.log(`  Base64 serialized: ${(sizeBytes / 1024).toFixed(1)} KB`);
      console.log(`  Base64 overhead: ~33%`);

      // Verify base64 encoding adds ~33% overhead
      expect(sizeBytes).toBeGreaterThan(rawBinarySize);
      expect(sizeBytes).toBeLessThan(rawBinarySize * 1.4); // <40% overhead

      // Verify under chrome.storage.local limit (10MB without unlimitedStorage)
      if (scale <= 100_000) {
        expect(sizeBytes).toBeLessThan(10 * 1024 * 1024);
      }
    });

    it('should fit 100k hashes under 10MB default limit', () => {
      const { serialized } = precomputedSets.get(100_000)!;
      const sizeBytes = serialized.length;
      const sizeMB = sizeBytes / (1024 * 1024);

      console.log(`\n100k hashes: ${sizeMB.toFixed(2)} MB`);
      expect(sizeMB).toBeLessThan(10);
    });

    it('should document that 300k hashes exceeds 10MB default limit', () => {
      const { serialized } = precomputedSets.get(300_000)!;
      const sizeMB = serialized.length / (1024 * 1024);

      console.log(`\n300k hashes: ${sizeMB.toFixed(2)} MB (EXCEEDS 10MB default)`);
      console.log('  -> Requires unlimitedStorage permission for 300k+ hashes');

      // 300k hashes is ~12.2 MB, exceeding the 10MB default
      expect(sizeMB).toBeGreaterThan(10);
      expect(sizeMB).toBeLessThan(15); // But still reasonable
    });

    it('should calculate max hashes for 10MB limit', () => {
      // Each hash: 32 bytes raw, ~42.67 bytes base64 encoded
      const bytesPerHash = 32 * 4 / 3; // base64 expansion
      const maxHashes = Math.floor((10 * 1024 * 1024) / bytesPerHash);

      console.log(`\nMax hashes for 10MB limit: ~${maxHashes.toLocaleString()}`);
      console.log('  Recommended safe limit: 230,000 hashes');

      expect(maxHashes).toBeGreaterThan(230_000);
      expect(maxHashes).toBeLessThan(250_000);
    });
  });

  describe('Cold Start Time (Deserialization)', () => {
    // Target: <3 seconds at 100k hashes
    it.each(SCALES)('should measure cold start time for %d hashes', (scale) => {
      const { serialized } = precomputedSets.get(scale)!;

      // Measure deserialization time (cold start)
      const iterations = 3;
      const times: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        const set = BinaryHashSet.deserialize(serialized);
        const elapsed = performance.now() - start;
        times.push(elapsed);

        // Verify set is usable
        expect(set.count).toBe(scale);
      }

      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const minTime = Math.min(...times);
      const maxTime = Math.max(...times);

      console.log(`\n${scale.toLocaleString()} hashes cold start:`);
      console.log(`  Average: ${avgTime.toFixed(2)} ms`);
      console.log(`  Min: ${minTime.toFixed(2)} ms`);
      console.log(`  Max: ${maxTime.toFixed(2)} ms`);

      // Target: <3 seconds at 100k
      if (scale === 100_000) {
        expect(avgTime).toBeLessThan(3000);
      }
    });

    it('should start in <3 seconds at 100k hashes (target)', () => {
      const { serialized } = precomputedSets.get(100_000)!;

      const start = performance.now();
      const set = BinaryHashSet.deserialize(serialized);
      const elapsed = performance.now() - start;

      console.log(`\n100k cold start: ${elapsed.toFixed(2)} ms`);
      expect(elapsed).toBeLessThan(3000);
      expect(set.count).toBe(100_000);
    });
  });

  describe('Delta Update Time', () => {
    // Target: <10 seconds to apply 1k delta update
    it.each(SCALES)('should measure 1k delta update time for %d existing hashes', (scale) => {
      const { serialized } = precomputedSets.get(scale)!;

      // Deserialize to get a fresh set
      const set = BinaryHashSet.deserialize(serialized);

      // Generate 1k new hashes (with seeds that don't overlap)
      const newHashes = generateHexStrings(1000, scale + 1000);

      // Measure time to add 1k new hashes
      const start = performance.now();
      for (const hex of newHashes) {
        set.add(hexToBytes(hex));
      }
      const elapsed = performance.now() - start;

      console.log(`\n1k delta update on ${scale.toLocaleString()} hashes: ${elapsed.toFixed(2)} ms`);

      // Verify hashes were added
      expect(set.count).toBe(scale + 1000);

      // Target: <10 seconds
      expect(elapsed).toBeLessThan(10_000);
    });

    it('should apply 1k delta in <10 seconds at 100k (target)', () => {
      const { serialized } = precomputedSets.get(100_000)!;
      const set = BinaryHashSet.deserialize(serialized);

      const newHashes = generateHexStrings(1000, 200_000);

      const start = performance.now();
      for (const hex of newHashes) {
        set.add(hexToBytes(hex));
      }
      const elapsed = performance.now() - start;

      console.log(`\n100k + 1k delta: ${elapsed.toFixed(2)} ms`);
      expect(elapsed).toBeLessThan(10_000);
    });
  });

  describe('Lookup Time (Binary Search)', () => {
    // Should be O(log n) - very fast
    it.each(SCALES)('should measure lookup time for %d hashes', (scale) => {
      const { set } = precomputedSets.get(scale)!;

      const queriesPerRound = 1000;
      const rounds = 5;
      const times: number[] = [];

      for (let r = 0; r < rounds; r++) {
        const start = performance.now();

        // Mix of hits and misses
        for (let i = 0; i < queriesPerRound; i++) {
          // Half hits (existing hashes)
          if (i % 2 === 0) {
            const idx = Math.floor(Math.random() * scale);
            set.has(hexToBytes(hashFromSeed(idx)));
          } else {
            // Half misses (non-existent hashes)
            set.has(hexToBytes(hashFromSeed(scale + i)));
          }
        }

        const elapsed = performance.now() - start;
        times.push(elapsed);
      }

      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const avgPerLookup = avgTime / queriesPerRound;
      const lookupsPerSecond = Math.round(1000 / avgPerLookup);

      console.log(`\n${scale.toLocaleString()} hashes lookup performance:`);
      console.log(`  ${queriesPerRound} lookups: ${avgTime.toFixed(2)} ms`);
      console.log(`  Per lookup: ${(avgPerLookup * 1000).toFixed(2)} μs`);
      console.log(`  Throughput: ${lookupsPerSecond.toLocaleString()} lookups/sec`);
      console.log(`  Expected comparisons (log2): ${Math.ceil(Math.log2(scale))}`);

      // Binary search should be very fast - less than 1ms per lookup even at 1M
      expect(avgPerLookup).toBeLessThan(1);
    });

    it('should demonstrate O(log n) scaling', () => {
      // Compare lookup times across scales
      // Time should grow logarithmically, not linearly

      const results: { scale: number; avgLookupMs: number }[] = [];

      for (const scale of SCALES) {
        const { set } = precomputedSets.get(scale)!;

        const queries = 10_000;
        const start = performance.now();

        for (let i = 0; i < queries; i++) {
          const idx = Math.floor(Math.random() * scale);
          set.has(hexToBytes(hashFromSeed(idx)));
        }

        const elapsed = performance.now() - start;
        results.push({ scale, avgLookupMs: elapsed / queries });
      }

      console.log('\nO(log n) scaling analysis:');
      for (const { scale, avgLookupMs } of results) {
        const log2 = Math.ceil(Math.log2(scale));
        console.log(`  ${scale.toLocaleString()} hashes: ${(avgLookupMs * 1000).toFixed(2)} μs (log2=${log2})`);
      }

      // 1M should be no more than 3x slower than 10k (not 100x)
      const time10k = results.find(r => r.scale === 10_000)!.avgLookupMs;
      const time1M = results.find(r => r.scale === 1_000_000)!.avgLookupMs;

      // log2(1M) / log2(10k) = 20/14 = ~1.43x theoretical
      // Allow 5x margin for overhead
      expect(time1M / time10k).toBeLessThan(5);
    });
  });

  describe('Memory Usage', () => {
    it.each(SCALES)('should report memory usage for %d hashes', (scale) => {
      const { set, serialized } = precomputedSets.get(scale)!;

      // In-memory size (ArrayBuffer)
      const inMemoryBytes = set.byteLength;

      // Serialized size (base64)
      const serializedBytes = serialized.length;

      // Estimated total memory footprint (buffer + overhead)
      // Actual JS overhead is hard to measure, but buffer is the main cost
      const estimatedOverhead = 1.1; // ~10% for JS object overhead
      const estimatedTotalBytes = Math.round(inMemoryBytes * estimatedOverhead);

      console.log(`\n${scale.toLocaleString()} hashes memory:`);
      console.log(`  In-memory buffer: ${(inMemoryBytes / 1024).toFixed(1)} KB`);
      console.log(`  Serialized (base64): ${(serializedBytes / 1024).toFixed(1)} KB`);
      console.log(`  Estimated total: ${(estimatedTotalBytes / 1024).toFixed(1)} KB`);
      console.log(`  Per hash (in-memory): 32 bytes`);
      console.log(`  Per hash (serialized): ${(serializedBytes / scale).toFixed(1)} bytes`);

      // Verify efficient storage
      expect(inMemoryBytes).toBe(scale * 32);
    });
  });

  describe('Bulk Load Performance', () => {
    it.each(SCALES)('should measure bulk load time for %d hashes', (scale) => {
      const hexStrings = generateHexStrings(scale);

      const start = performance.now();
      const set = BinaryHashSet.fromHexStrings(hexStrings);
      const elapsed = performance.now() - start;

      console.log(`\n${scale.toLocaleString()} hashes bulk load: ${elapsed.toFixed(2)} ms`);

      expect(set.count).toBe(scale);

      // Bulk load should be reasonably fast
      // At 100k, should be under 5 seconds
      if (scale === 100_000) {
        expect(elapsed).toBeLessThan(5000);
      }
    }, 60_000); // Allow 60s for 1M test
  });
});

describe('Benchmark Summary', () => {
  it('should generate benchmark results table', () => {
    console.log('\n');
    console.log('='.repeat(80));
    console.log('BENCHMARK RESULTS SUMMARY');
    console.log('='.repeat(80));

    console.log('\n| Hash Count | Storage Size | Cold Start | 1k Delta | Lookup/sec |');
    console.log('|------------|--------------|------------|----------|------------|');

    for (const scale of SCALES) {
      const { set, serialized } = precomputedSets.get(scale)!;

      // Storage
      const storageMB = (serialized.length / (1024 * 1024)).toFixed(2);

      // Cold start
      const start1 = performance.now();
      BinaryHashSet.deserialize(serialized);
      const coldStartMs = (performance.now() - start1).toFixed(0);

      // Delta update
      const testSet = BinaryHashSet.deserialize(serialized);
      const newHashes = generateHexStrings(1000, scale + 10000);
      const start2 = performance.now();
      for (const hex of newHashes) {
        testSet.add(hexToBytes(hex));
      }
      const deltaMs = (performance.now() - start2).toFixed(0);

      // Lookup
      const queries = 10_000;
      const start3 = performance.now();
      for (let i = 0; i < queries; i++) {
        set.has(hexToBytes(hashFromSeed(Math.floor(Math.random() * scale))));
      }
      const lookupTotal = performance.now() - start3;
      const lookupsPerSec = Math.round((queries / lookupTotal) * 1000);

      console.log(
        `| ${scale.toLocaleString().padStart(10)} | ${(storageMB + ' MB').padStart(12)} | ${(coldStartMs + ' ms').padStart(10)} | ${(deltaMs + ' ms').padStart(8)} | ${lookupsPerSec.toLocaleString().padStart(10)} |`
      );
    }

    console.log('\n');
    console.log('Targets:');
    console.log('  - Cold start at 100k: <3,000 ms');
    console.log('  - 1k delta update: <10,000 ms');
    console.log('  - Lookup: O(log n) complexity');
    console.log('\n');
    console.log('Storage limits:');
    console.log('  - chrome.storage.local: 10 MB (default)');
    console.log('  - With unlimitedStorage permission: ~unlimited');
    console.log('\n');

    // Pass if we got here
    expect(true).toBe(true);
  });
});
