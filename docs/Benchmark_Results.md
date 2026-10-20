# BrowserDefense Performance Benchmark Results

Performance measurements for BinaryHashSet storage at scale.

## Summary

| Hash Count | Storage Size | Cold Start | 1k Delta | Lookup/sec |
|------------|--------------|------------|----------|------------|
| 10,000     | 0.41 MB      | ~1 ms      | ~1 ms    | ~1,000,000 |
| 100,000    | 4.07 MB      | ~4 ms      | ~1 ms    | ~700,000   |
| 300,000    | 12.21 MB     | ~12 ms     | ~3 ms    | ~600,000   |
| 1,000,000  | 40.69 MB     | ~41 ms     | ~6 ms    | ~750,000   |

## Targets vs Actual

| Metric | Target | Actual (100k) | Status |
|--------|--------|---------------|--------|
| Cold start to ready-to-block | < 3 seconds | ~4-5 ms | PASS (600x margin) |
| 1k delta update | < 10 seconds | ~1-2 ms | PASS (5000x margin) |
| Lookup complexity | O(log n) | ~1 microsecond | PASS |

## Storage Limits

### Default chrome.storage.local (10 MB)

- **Safe limit**: ~230,000 hashes
- **Maximum theoretical**: ~245,760 hashes
- 100,000 hashes uses 4.07 MB (safe margin)

### With unlimitedStorage permission

- 300,000 hashes: 12.21 MB
- 1,000,000 hashes: 40.69 MB
- Practical limit depends on device memory

## Recommended Tier Limits

| Tier | Max Hashes | Storage Required | Permission Needed |
|------|------------|------------------|-------------------|
| Free | 100,000    | ~4 MB            | None              |
| Pro  | 300,000    | ~12 MB           | unlimitedStorage  |
| Enterprise | 1,000,000 | ~41 MB      | unlimitedStorage  |

## Detailed Metrics

### Storage Efficiency

- **Binary format**: 32 bytes per hash (raw)
- **Base64 encoded**: ~42.7 bytes per hash (33% overhead)
- **Compared to JSON hex strings**: ~70 bytes per hash (40% savings)

### Cold Start (Deserialization)

Time to deserialize from base64 storage to ready-to-block state:

| Hash Count | Average | Min | Max |
|------------|---------|-----|-----|
| 10,000     | 1.0 ms  | 0.5 ms | 1.9 ms |
| 100,000    | 5.3 ms  | 3.5 ms | 9.4 ms |
| 300,000    | 11.3 ms | 10.7 ms | 12.2 ms |
| 1,000,000  | 44.2 ms | 42.8 ms | 45.4 ms |

### Delta Updates (Adding 1k Hashes)

Time to add 1,000 new hashes to existing set:

| Existing Hashes | Time |
|-----------------|------|
| 10,000          | ~1.1 ms |
| 100,000         | ~1.3 ms |
| 300,000         | ~1.8 ms |
| 1,000,000       | ~4.5 ms |

The binary set maintains sorted order using insertion sort. Performance degrades slightly at scale but remains well under targets.

### Lookup Performance (Binary Search)

| Hash Count | Time/Lookup | Expected Comparisons (log2) |
|------------|-------------|----------------------------|
| 10,000     | ~1.0 microsecond | 14 |
| 100,000    | ~1.1 microsecond | 17 |
| 300,000    | ~1.2 microsecond | 19 |
| 1,000,000  | ~1.3 microsecond | 20 |

Lookup time scales logarithmically as expected. Even at 1M hashes, each lookup completes in ~1.3 microseconds.

### Bulk Load Performance

Time to create BinaryHashSet from hex string array (fromHexStrings):

| Hash Count | Time |
|------------|------|
| 10,000     | ~8 ms |
| 100,000    | ~90 ms |
| 300,000    | ~270 ms |
| 1,000,000  | ~880 ms |

Bulk load includes sorting, which is O(n log n).

## Recommendations

1. **Default tier (no special permissions)**: Limit to 100k hashes
   - Plenty of headroom under 10MB limit
   - Sub-5ms cold start

2. **For 300k+ hashes**: Add `unlimitedStorage` permission to manifest.json
   ```json
   {
     "permissions": ["unlimitedStorage"]
   }
   ```

3. **Memory considerations**: Each hash uses 32 bytes in-memory
   - 100k hashes: ~3.1 MB RAM
   - 300k hashes: ~9.4 MB RAM
   - 1M hashes: ~31.3 MB RAM

4. **Update strategy**: Delta updates are fast enough (~1-5ms for 1k hashes) to apply incrementally rather than full replacement

## Test Environment

- Node.js (via Vitest)
- M-series Mac
- Tests run in `tests/benchmark.test.ts`

Run benchmarks:
```bash
npm test -- tests/benchmark.test.ts
```
