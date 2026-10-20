# Geometric Compaction Specification

This document describes the geometric compaction (logarithmic tiering) strategy for IOC delta storage in BrowserDefense. This approach balances read performance against storage costs, inspired by LevelDB and Cassandra's tiered compaction.

**Related:** [Blocklist Distribution Specification](./Blocklist_Distribution_Specification.md), Issue #376 (Realtime IOC Sync)

## Overview

Instead of retaining individual deltas indefinitely or expiring them too quickly, organize data into exponentially growing tiers:

| Level | Name | Granularity | TTL | Cache-Control |
|-------|------|-------------|-----|---------------|
| 0 | Deltas | 1 update | 24 hours | `immutable` |
| 1 | Deca-Bundles | 10 deltas | 7 days | `immutable` |
| 2 | Hecto-Bundles | 100 deltas | 30 days | `immutable` |
| 3 | Snapshots | 1000 deltas | Forever | `immutable` |

**Key insight:** All payloads are immutable. CDN caches them forever. R2 reads approach zero in steady state.

## Design Goals

1. **Minimize R2 storage costs** - TTL-based cleanup removes old granular data
2. **Low cold-start latency** - Parallel fetch of bundles instead of N individual deltas
3. **CDN-first architecture** - Immutable files cached at edge, R2 rarely touched
4. **Race-condition-free** - TTL-based deletion prevents 404s during compaction

## R2 Storage Layout

```
https://{org-slug}.browserdefense.net/
├── manifest_ent.json           # Enterprise tier (60s TTL)
├── manifest_free.json          # Free tier (3600s TTL)
├── deltas/
│   ├── 2451.bin                # Individual delta (24h TTL)
│   ├── 2452.bin
│   └── ...
├── bundles/
│   ├── deca/
│   │   ├── 2401_2410.bin       # 10-delta bundles (7d TTL)
│   │   └── 2411_2420.bin
│   └── hecto/
│       ├── 2001_2100.bin       # 100-delta bundles (30d TTL)
│       └── 2101_2200.bin
└── snapshots/
    ├── 1000.bin                # Full snapshots (forever)
    └── 2000.bin
```

### File Types

| Path Pattern | Content-Type | Cache-Control | TTL |
|--------------|--------------|---------------|-----|
| `manifest_*.json` | `application/json` | `max-age=60` or `max-age=3600` | - |
| `deltas/{id}.bin` | `application/octet-stream` | `max-age=31536000, immutable` | 24h |
| `bundles/deca/{start}_{end}.bin` | `application/octet-stream` | `max-age=31536000, immutable` | 7d |
| `bundles/hecto/{start}_{end}.bin` | `application/octet-stream` | `max-age=31536000, immutable` | 30d |
| `snapshots/{id}.bin` | `application/octet-stream` | `max-age=31536000, immutable` | Forever |

## Write Path (Publisher)

### The 1-10-100-1000 Algorithm

Every delta publication triggers compaction checks at geometric boundaries:

```typescript
async function publishDelta(id: number, delta: ArrayBuffer): Promise<void> {
  // 1. Always upload individual delta
  await r2.put(`deltas/${id}.bin`, delta, {
    httpMetadata: { cacheControl: 'public, max-age=31536000, immutable' }
  });

  // 2. Compaction triggers at geometric boundaries
  if (id % 10 === 0) {
    await compactDecaBundle(id - 9, id);
  }
  if (id % 100 === 0) {
    await compactHectoBundle(id - 99, id);
  }
  if (id % 1000 === 0) {
    await createSnapshot(id);
  }

  // 3. Update manifests for both pricing tiers
  await updateManifests(id);

  // 4. Send FCM push notification (see Issue #376)
  await sendFCM(id, delta);
}
```

### Bundle Creation

```typescript
async function compactDecaBundle(startId: number, endId: number): Promise<void> {
  // Fetch the 10 individual deltas
  const deltas = await Promise.all(
    range(startId, endId + 1).map(id => r2.get(`deltas/${id}.bin`))
  );

  // Create length-prefixed bundle
  const bundle = createBundle(deltas, startId);

  await r2.put(`bundles/deca/${startId}_${endId}.bin`, bundle, {
    httpMetadata: { cacheControl: 'public, max-age=31536000, immutable' }
  });

  // DON'T delete individual deltas - TTL handles cleanup
  // This prevents race conditions with in-flight requests
}

async function compactHectoBundle(startId: number, endId: number): Promise<void> {
  // Fetch 10 deca-bundles (not individual deltas)
  const decaBundles = await Promise.all(
    range(startId, endId + 1, 10).map(start =>
      r2.get(`bundles/deca/${start}_${start + 9}.bin`)
    )
  );

  // Merge into hecto-bundle (or fetch from individual deltas as fallback)
  const bundle = mergeDecaBundles(decaBundles);

  await r2.put(`bundles/hecto/${startId}_${endId}.bin`, bundle, {
    httpMetadata: { cacheControl: 'public, max-age=31536000, immutable' }
  });
}
```

### Snapshot Creation

Every 1000 deltas, create a full snapshot for cold-start baseline:

```typescript
async function createSnapshot(id: number): Promise<void> {
  // Build full blocklist by applying all deltas since last snapshot
  const previousSnapshotId = id - 1000;
  const baseBlocklist = await loadSnapshot(previousSnapshotId);

  // Apply the 10 hecto-bundles (or fetch from R2)
  const hectoBundles = await fetchHectoBundles(previousSnapshotId + 1, id);
  const finalBlocklist = applyBundles(baseBlocklist, hectoBundles);

  await r2.put(`snapshots/${id}.bin`, finalBlocklist, {
    httpMetadata: { cacheControl: 'public, max-age=31536000, immutable' }
  });
}
```

## Bundle Binary Format

All bundles use a length-prefixed framing format:

```
┌──────────────┬──────────────────────────────────────────┐
│ Entry Count  │ Entries...                               │
│ (4 bytes LE) │                                          │
└──────────────┴──────────────────────────────────────────┘

Each Entry:
┌──────────────┬──────────────┬────────────────────────────┐
│ Delta ID     │ Length       │ Encrypted Delta            │
│ (4 bytes LE) │ (4 bytes LE) │ [IV 12b][Ciphertext]       │
└──────────────┴──────────────┴────────────────────────────┘
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| Entry Count | uint32 LE | Number of deltas in bundle (10 for deca, 100 for hecto) |
| Delta ID | uint32 LE | Monotonic delta identifier |
| Length | uint32 LE | Size of encrypted delta payload |
| Encrypted Delta | bytes | AES-GCM encrypted delta (12-byte IV prefix) |

### Bundle Parsing

```typescript
interface DeltaEntry {
  id: number;
  payload: Uint8Array;
}

function parseBundle(buffer: ArrayBuffer): DeltaEntry[] {
  const view = new DataView(buffer);
  const count = view.getUint32(0, true); // little-endian
  const entries: DeltaEntry[] = [];

  let offset = 4;
  for (let i = 0; i < count; i++) {
    const id = view.getUint32(offset, true);
    const length = view.getUint32(offset + 4, true);
    const payload = new Uint8Array(buffer, offset + 8, length);

    entries.push({ id, payload });
    offset += 8 + length;
  }

  return entries;
}
```

## Read Path (Extension Cold Start)

### Gap Threshold Decision

When extension starts or reconnects, it checks the gap between local and remote versions:

```typescript
async function recover(localId: number, remoteId: number): Promise<void> {
  const gap = remoteId - localId;

  if (gap <= 0) {
    return; // Already up to date
  }

  if (gap <= 50) {
    // Small gap - parallel fetch individual deltas
    await fetchDeltasParallel(localId + 1, remoteId);
  } else {
    // Large gap - use geometric compaction
    await coldStartWithCompaction(localId, remoteId);
  }
}
```

### Greedy Descent Algorithm

For large gaps, use the largest possible bundles first:

```typescript
interface FetchPlan {
  type: 'snapshot' | 'hecto' | 'deca' | 'delta';
  id?: number;
  start?: number;
  end?: number;
}

async function coldStartWithCompaction(
  localId: number,
  remoteId: number
): Promise<void> {
  const fetches: FetchPlan[] = [];
  let covered = localId;

  // 1. Find largest snapshot <= remoteId that's > localId
  const snapshotId = Math.floor(remoteId / 1000) * 1000;
  if (snapshotId > covered) {
    fetches.push({ type: 'snapshot', id: snapshotId });
    covered = snapshotId;
  }

  // 2. Fill with hecto-bundles (100s)
  while (covered + 100 <= remoteId) {
    const start = Math.ceil((covered + 1) / 100) * 100 - 99;
    const end = start + 99;
    if (end <= remoteId && start > covered) {
      fetches.push({ type: 'hecto', start, end });
      covered = end;
    } else {
      break;
    }
  }

  // 3. Fill with deca-bundles (10s)
  while (covered + 10 <= remoteId) {
    const start = Math.ceil((covered + 1) / 10) * 10 - 9;
    const end = start + 9;
    if (end <= remoteId && start > covered) {
      fetches.push({ type: 'deca', start, end });
      covered = end;
    } else {
      break;
    }
  }

  // 4. Fill remaining with individual deltas
  for (let id = covered + 1; id <= remoteId; id++) {
    fetches.push({ type: 'delta', id });
  }

  // Execute with concurrency limit, apply sequentially
  const results = await executeFetchPlan(fetches, { concurrency: 5 });
  await applyInOrder(results);
}
```

### Example: Cold Start from 0 to 2456

| Step | Fetch | Covers | Requests |
|------|-------|--------|----------|
| 1 | `snapshots/2000.bin` | 0-2000 | 1 |
| 2-5 | `bundles/hecto/2001_2100.bin` ... `2301_2400.bin` | 2001-2400 | 4 |
| 6-10 | `bundles/deca/2401_2410.bin` ... `2441_2450.bin` | 2401-2450 | 5 |
| 11-16 | `deltas/2451.bin` ... `deltas/2456.bin` | 2451-2456 | 6 |

**Total: 16 parallel requests, ~1-2s latency**

Without geometric compaction, this would require 2456 individual requests.

## TTL-Based Deletion

### The Race Condition Problem

If we delete `deltas/9.bin` immediately after publishing `deltas/10.bin` and creating the deca-bundle, users still syncing to version 9 will 404.

### The Solution: R2 Object Lifecycle Rules

```json
{
  "rules": [
    {
      "id": "expire-deltas",
      "filter": { "prefix": "deltas/" },
      "expiration": { "days": 1 }
    },
    {
      "id": "expire-deca-bundles",
      "filter": { "prefix": "bundles/deca/" },
      "expiration": { "days": 7 }
    },
    {
      "id": "expire-hecto-bundles",
      "filter": { "prefix": "bundles/hecto/" },
      "expiration": { "days": 30 }
    }
  ]
}
```

### Sliding Window Visualization

```
NOW ←── 24h ──←── 7d ──←── 30d ──← OLD
[Deltas]  [Deca]   [Hecto]   [Snapshots]
  Fine     Medium   Coarse    Full state
```

- **Deltas**: Fine-grained, recent updates
- **Deca-bundles**: Medium granularity, past week
- **Hecto-bundles**: Coarse granularity, past month
- **Snapshots**: Full state, kept forever

## Manifest Schema

The manifest includes compaction state so clients know what files exist:

```typescript
interface GeometricManifest {
  /** Current latest delta ID */
  latest_id: number;

  /** Unix timestamp (seconds) */
  timestamp: number;

  /** Minimum extension version required */
  min_client_version: string;

  /** Compaction state for intelligent fetching */
  compaction: {
    /** Most recent snapshot ID */
    latest_snapshot: number;

    /** Oldest available hecto-bundle start ID */
    hecto_available_from: number;

    /** Oldest available deca-bundle start ID */
    deca_available_from: number;

    /** Oldest available individual delta ID */
    deltas_available_from: number;
  };

  /** Signature over canonical fields */
  signature: string;

  /** Signing key ID */
  signing_key_id: string;
}
```

### Example Manifest

```json
{
  "latest_id": 2456,
  "timestamp": 1778439200,
  "min_client_version": "1.4.0",
  "compaction": {
    "latest_snapshot": 2000,
    "hecto_available_from": 2001,
    "deca_available_from": 2401,
    "deltas_available_from": 2451
  },
  "signature": "MEUCIQC...",
  "signing_key_id": "key-2026-01"
}
```

The client uses `compaction` to know exactly what files exist without 404 probing.

## Fallback Chain

If a file 404s (expired TTL or missing), fall back to coarser granularity:

| If this 404s... | Fall back to... |
|-----------------|-----------------|
| `deltas/2451.bin` | `bundles/deca/2441_2450.bin` + remaining deltas |
| `bundles/deca/*` | `bundles/hecto/*` |
| `bundles/hecto/*` | `snapshots/*` |
| Everything | Latest snapshot only (full cold start) |

```typescript
async function fetchWithFallback(
  type: 'delta' | 'deca' | 'hecto',
  id: number
): Promise<Uint8Array> {
  try {
    return await fetchDirect(type, id);
  } catch (e) {
    if (e instanceof NotFoundError) {
      // Fall back to coarser granularity
      switch (type) {
        case 'delta':
          return extractFromDecaBundle(id);
        case 'deca':
          return extractFromHectoBundle(id);
        case 'hecto':
          return fetchSnapshot(Math.floor(id / 1000) * 1000);
      }
    }
    throw e;
  }
}
```

## Economic Analysis

| Metric | Individual Deltas Only | Geometric Compaction | Improvement |
|--------|------------------------|----------------------|-------------|
| Storage | O(N) | ~1.11x O(N) | 11% overhead |
| Cold Start Requests | N | ~15-20 | **99% fewer** |
| CDN Cache Hit Rate | Low (many files) | **99%+** (immutable) | Massive |
| R2 Reads (steady state) | Many | **~0** | CDN serves |

### Monthly Cost Estimate

For a typical deployment with ~10 updates/day:

| Component | Cost |
|-----------|------|
| R2 Storage Writes | ~$5/mo (compaction reduces 1000 writes to ~1) |
| R2 Storage Reads | ~$1/mo (CDN 99%+ hit rate) |
| R2 Storage | ~$0.50/mo (small blob sizes) |
| **Total** | **~$6.50/mo** |

Cost remains nearly constant regardless of client count due to CDN caching.

## Implementation Checklist

### Publisher (Admin Dashboard)

- [ ] Delta publication with immutable cache headers
- [ ] Deca-bundle compaction trigger (every 10 deltas)
- [ ] Hecto-bundle compaction trigger (every 100 deltas)
- [ ] Snapshot creation trigger (every 1000 deltas)
- [ ] Length-prefixed bundle format encoder
- [ ] Manifest includes compaction state
- [ ] R2 lifecycle rules configured in Wrangler

### Extension (Chrome MV3)

- [ ] Gap threshold check (>50 triggers geometric fetch)
- [ ] Greedy descent algorithm implementation
- [ ] Bundle parser (extract individual deltas)
- [ ] Parallel fetch with concurrency limit (5)
- [ ] Sequential apply after fetch
- [ ] Fallback chain for 404s
- [ ] Manifest parsing with compaction state

### Testing

- [ ] Cold start 0 -> N for various N values
- [ ] Race condition simulation during compaction
- [ ] TTL expiration behavior verification
- [ ] CDN cache hit rate monitoring
- [ ] Bundle corruption/truncation handling
- [ ] Fallback chain verification
- [ ] Performance benchmarks (latency, bandwidth)

## Security Considerations

1. **Immutable artifacts** - Once published, bundles and snapshots never change
2. **Signature covers manifest** - Clients verify compaction state is authentic
3. **No inline deltas in manifest** - Prevents manifest bloat attacks
4. **TTL prevents infinite storage growth** - Old data automatically cleaned
5. **Fallback to snapshot** - Worst case is full cold start, not failure

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `COMPACTION_DECA_THRESHOLD` | Deltas per deca-bundle | 10 |
| `COMPACTION_HECTO_THRESHOLD` | Deltas per hecto-bundle | 100 |
| `COMPACTION_SNAPSHOT_THRESHOLD` | Deltas per snapshot | 1000 |
| `DELTA_TTL_HOURS` | Individual delta TTL | 24 |
| `DECA_TTL_DAYS` | Deca-bundle TTL | 7 |
| `HECTO_TTL_DAYS` | Hecto-bundle TTL | 30 |
| `COLD_START_GAP_THRESHOLD` | Gap triggering geometric fetch | 50 |

### R2 Lifecycle Configuration (wrangler.toml)

```toml
[[r2_buckets]]
binding = "IOC_BUCKET"
bucket_name = "browserdefense-iocs"

# Note: Lifecycle rules are configured via R2 dashboard or API
# See docs/ops/r2-lifecycle-setup.md
```

## References

- [LevelDB Compaction](https://github.com/google/leveldb/blob/main/doc/impl.md)
- [Cassandra Tiered Compaction](https://cassandra.apache.org/doc/latest/cassandra/operating/compaction/)
- [R2 Object Lifecycles](https://developers.cloudflare.com/r2/buckets/object-lifecycles/)
- Issue #376 - Realtime IOC Sync System
- [Blocklist Distribution Specification](./Blocklist_Distribution_Specification.md)
