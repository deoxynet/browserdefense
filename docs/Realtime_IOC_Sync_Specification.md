# Realtime IOC Sync System Specification

**Version:** 1.0
**Status:** DESIGN COMPLETE
**Purpose:** Technical specification for push/pull IOC synchronization with binary encrypted deltas

---

## Executive Summary

This specification defines the **BlockIOC Realtime IOC Sync System** - an architecture achieving extremely low latency, infinite scalability, resilience to downtime, and cost efficiency through edge caching.

**Key Properties:**
- **Hot Path:** Server → FCM → Extension (< 1 second latency)
- **Cold Path:** Extension → CDN Edge → R2 (~ 1 second latency)
- **Binary encrypted deltas** - AES-256-GCM, bandwidth efficient
- **Inline small deltas** - Skip R2 roundtrip for payloads < 2.8KB
- **Tiered polling** - Enterprise (5 min) vs Free (60 min)
- **Geometric compaction** - Reduces recovery costs by 100x

**Related Specifications:**
- Geometric Compaction Strategy (Issue #382)
- Cryptographic Specification v3

---

## I. System Architecture

### High-Level Data Flow

```
┌─────────────┐    1. Upload Delta     ┌─────────────┐
│   Backend   │ ───────────────────────│  R2 + CDN   │
│  Publisher  │    2. Update Manifest  │  (99% hit)  │
└──────┬──────┘                        └──────┬──────┘
       │                                      │
       │ 3. FCM Push                          │ 4. Cold Path
       │    (inline if <2.8KB)                │    (bundle/snapshot)
       ▼                                      ▼
┌─────────────────────────────────────────────────────┐
│                Chrome Extension                      │
│  ┌───────────┐  ┌───────────┐  ┌─────────────────┐  │
│  │ FCM       │  │ Watchdog  │  │ Delta Applier   │  │
│  │ Listener  │  │ (tiered)  │  │ (Sequential)    │  │
│  └─────┬─────┘  └─────┬─────┘  └────────┬────────┘  │
│        │              │                  │          │
│        └──────────────┴──────────────────┘          │
│                       ▼                             │
│              ┌─────────────────┐                    │
│              │  IOC Hash Set   │                    │
│              │  (In Memory)    │                    │
│              └─────────────────┘                    │
└─────────────────────────────────────────────────────┘
```

### Design Principles

1. **Push-First, Pull-Fallback:** FCM delivers immediate updates; polling catches missed messages
2. **Edge-Heavy:** CDN handles 99%+ of reads; R2 serves only cache misses
3. **Immutable Assets:** Deltas and bundles are write-once, cache-forever
4. **Fail-Safe:** Local state is source of truth; network failures degrade gracefully
5. **Tier-Aware:** Enterprise gets realtime; Free tier gets hourly updates

---

## II. Storage Architecture

### R2 Object Layout

**Base URL:** `https://{org-slug}.blockioc.net/`

| Path | Purpose | Cache-Control | Notes |
|------|---------|---------------|-------|
| `/manifest_ent.json` | Enterprise manifest | `max-age=60` | Short TTL for freshness |
| `/manifest_free.json` | Free tier manifest | `max-age=3600` | Hourly updates acceptable |
| `/deltas/{ID}.bin` | Individual delta | `max-age=31536000, immutable` | Never changes |
| `/bundles/deca/{start}_{end}.bin` | 10-delta bundle | `max-age=31536000, immutable` | Compacted |
| `/bundles/hecto/{start}_{end}.bin` | 100-delta bundle | `max-age=31536000, immutable` | Compacted |
| `/snapshots/{ID}.bin` | Full snapshot | `max-age=31536000, immutable` | Cold start recovery |

**Cost Impact:** Immutable caching means you pay for **1 R2 read per CDN edge location**, not per client request.

### Manifest Schema

```typescript
interface SyncManifest {
  // Current state
  latest_id: number;           // e.g., 2456
  timestamp: number;           // Unix epoch seconds

  // Client compatibility
  min_client_version: string;  // e.g., "1.4.0"

  // Compaction metadata (for recovery optimization)
  compaction: {
    latest_snapshot: number;      // e.g., 2000 - most recent full snapshot
    hecto_available_from: number; // e.g., 2001 - 100-delta bundles start here
    deca_available_from: number;  // e.g., 2401 - 10-delta bundles start here
    deltas_available_from: number; // e.g., 2451 - individual deltas start here
  };

  // Optional: key rotation
  key_version?: number;
}
```

**Example Manifest:**
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
  }
}
```

---

## III. Delta Binary Format

### Wire Format

All deltas, bundles, and snapshots use the same binary envelope:

```
┌────────────────┬─────────────────────────────────────┐
│ IV             │ Ciphertext                          │
│ (12 bytes)     │ AES-256-GCM encrypted payload       │
│                │ (variable length)                   │
└────────────────┴─────────────────────────────────────┘
Offset:  0          12                                 EOF
```

**Design Rationale:**
- **No header/version byte:** Simplicity; version changes handled via manifest
- **No salt/keyID:** Key rotation communicated out-of-band via manifest
- **12-byte IV:** Standard for AES-GCM, randomly generated per delta
- **Authentication:** GCM tag (16 bytes) appended to ciphertext by WebCrypto

### Decrypted Payload Schema

```typescript
interface DeltaPayload {
  id: number;                    // Sequential delta ID
  timestamp: number;             // Unix epoch seconds

  // IOC changes
  add: Uint8Array[];             // SHA-256 hashes to add (32 bytes each)
  remove: Uint8Array[];          // SHA-256 hashes to remove (32 bytes each)

  // Optional metadata
  source?: string;               // e.g., "threatfeed-xyz"
  ttl?: number;                  // Auto-expire after N seconds (optional)
}
```

### Bundle Payload Schema

Bundles concatenate multiple deltas for efficient recovery:

```typescript
interface BundlePayload {
  start_id: number;              // First delta ID in bundle
  end_id: number;                // Last delta ID in bundle
  deltas: DeltaPayload[];        // Ordered array of deltas
}
```

### Snapshot Payload Schema

Full state for cold start:

```typescript
interface SnapshotPayload {
  id: number;                    // Snapshot ID (matches delta ID at time of creation)
  timestamp: number;
  hashes: Uint8Array[];          // All active IOC hashes
  metadata?: {
    total_count: number;
    source_breakdown?: Record<string, number>;
  };
}
```

---

## IV. Push Channel (FCM)

### FCM Payload Structure

**Size Constraint:** FCM data messages have a **4KB total limit**. After JSON encoding overhead, approximately **2.8KB** is available for the payload.

#### Decision Logic (Publisher)

```typescript
const INLINE_THRESHOLD = 2800; // bytes

function shouldInline(delta: ArrayBuffer): boolean {
  // Base64 encoding adds ~33% overhead
  const encodedSize = Math.ceil(delta.byteLength * 4 / 3);
  return encodedSize < INLINE_THRESHOLD;
}
```

#### Small Delta (< 2.8KB) - Inline Mode

```json
{
  "data": {
    "type": "SYNC_DELTA",
    "id": "1050",
    "payload": "base64-encoded-binary-delta..."
  }
}
```

**Benefit:** Zero R2 reads required. Extension applies delta directly from push payload.

#### Large Delta (>= 2.8KB) - Fetch Mode

```json
{
  "data": {
    "type": "SYNC_TICKLE",
    "strategy": "fetch",
    "latest_id": "1050"
  }
}
```

**Behavior:** Extension compares `latest_id` to local state, fetches missing deltas from CDN.

### FCM Registration

```typescript
// Extension registers for FCM on install/startup
async function registerFCM(): Promise<string> {
  return new Promise((resolve, reject) => {
    chrome.gcm.register([FCM_SENDER_ID], (registrationId) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(registrationId);
      }
    });
  });
}

// Send registration ID to backend for targeting
async function reportRegistration(registrationId: string, orgId: string) {
  await fetch(`${API_BASE}/register-fcm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ registration_id: registrationId, org_id: orgId })
  });
}
```

---

## V. Tier Differentiation

### Feature Matrix

| Feature | Enterprise | Free |
|---------|------------|------|
| FCM Push | Real-time delivery | Not available |
| Watchdog Poll Interval | 5 minutes | 60 minutes |
| Manifest Cache TTL | 60 seconds | 3600 seconds |
| Manifest Endpoint | `/manifest_ent.json` | `/manifest_free.json` |
| Expected Latency | < 1 second | < 60 minutes |
| SLA | 99.9% uptime | Best effort |

### Tier Detection

```typescript
interface SyncConfig {
  tier: 'enterprise' | 'free';
  org_id: string;
  cdn_base: string;
}

function getManifestUrl(config: SyncConfig): string {
  const filename = config.tier === 'enterprise'
    ? 'manifest_ent.json'
    : 'manifest_free.json';
  return `${config.cdn_base}/${filename}`;
}

function getPollInterval(config: SyncConfig): number {
  return config.tier === 'enterprise' ? 5 : 60; // minutes
}
```

---

## VI. Client Implementation

### State Management

```typescript
interface SyncState {
  current_id: number;           // Last successfully applied delta
  last_check_ts: number;        // Unix timestamp of last manifest check
  last_fcm_ts: number;          // Unix timestamp of last FCM message
  tier: 'enterprise' | 'free';
  recovery_in_progress: boolean;
}

// Persist to chrome.storage.local
async function saveSyncState(state: SyncState): Promise<void> {
  await chrome.storage.local.set({ sync_state: state });
}

async function loadSyncState(): Promise<SyncState | null> {
  const { sync_state } = await chrome.storage.local.get('sync_state');
  return sync_state ?? null;
}
```

### Watchdog (Tiered Polling)

```typescript
function initializeWatchdog(config: SyncConfig): void {
  const interval = getPollInterval(config);

  chrome.alarms.create('sync_watchdog', {
    periodInMinutes: interval
  });

  console.log(`[BlockIOC] Watchdog initialized: ${interval} min interval`);
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'sync_watchdog') return;

  const config = await loadSyncConfig();
  const state = await loadSyncState();

  try {
    const manifest = await fetchManifest(config);

    if (manifest.latest_id > state.current_id) {
      console.log(`[BlockIOC] Watchdog: gap detected, recovering...`);
      await recover(state.current_id, manifest.latest_id, config);
    } else {
      console.log(`[BlockIOC] Watchdog: up to date at ${state.current_id}`);
    }

    await saveSyncState({ ...state, last_check_ts: Date.now() });
  } catch (err) {
    console.error(`[BlockIOC] Watchdog failed:`, err);
    // Don't update last_check_ts on failure - will retry next interval
  }
});
```

### FCM Message Handler

```typescript
chrome.gcm.onMessage.addListener(async (message) => {
  const state = await loadSyncState();
  const config = await loadSyncConfig();

  const { type, id, payload, latest_id, strategy } = message.data;

  // Reset watchdog timer on any valid push
  chrome.alarms.clear('sync_watchdog');
  chrome.alarms.create('sync_watchdog', {
    periodInMinutes: getPollInterval(config)
  });

  await saveSyncState({ ...state, last_fcm_ts: Date.now() });

  if (type === 'SYNC_DELTA' && payload) {
    // Inline mode - apply directly from payload
    const targetId = parseInt(id, 10);

    if (targetId === state.current_id + 1) {
      // Sequential - apply immediately
      const binary = base64ToArrayBuffer(payload);
      await decryptAndApplyDelta(binary, config);
      await saveSyncState({ ...state, current_id: targetId });
      console.log(`[BlockIOC] Applied inline delta ${targetId}`);

    } else if (targetId > state.current_id + 1) {
      // Gap detected - need recovery
      console.log(`[BlockIOC] Gap: have ${state.current_id}, received ${targetId}`);
      await recover(state.current_id, targetId, config);
    }
    // targetId <= current_id: duplicate, ignore

  } else if (type === 'SYNC_TICKLE' && strategy === 'fetch') {
    // Fetch mode - large delta or batch
    const targetId = parseInt(latest_id, 10);

    if (targetId > state.current_id) {
      await recover(state.current_id, targetId, config);
    }
  }
});
```

### Recovery Logic (Smart Fetch)

**Key Optimization:** Never fetch hundreds of individual deltas. Use geometric compaction.

```typescript
const GAP_THRESHOLD = 50; // Switch to bundles above this gap

async function recover(
  localId: number,
  remoteId: number,
  config: SyncConfig
): Promise<void> {
  const state = await loadSyncState();

  if (state.recovery_in_progress) {
    console.log(`[BlockIOC] Recovery already in progress, skipping`);
    return;
  }

  await saveSyncState({ ...state, recovery_in_progress: true });

  try {
    const gap = remoteId - localId;

    if (gap > GAP_THRESHOLD) {
      // Large gap: use geometric compaction (bundles/snapshots)
      console.log(`[BlockIOC] Large gap (${gap}), using compaction`);
      await recoverWithCompaction(localId, remoteId, config);
    } else {
      // Small gap: parallel fetch individual deltas
      console.log(`[BlockIOC] Small gap (${gap}), fetching deltas`);
      await fetchDeltasParallel(localId + 1, remoteId, config);
    }

    await saveSyncState({
      ...state,
      current_id: remoteId,
      recovery_in_progress: false
    });

  } catch (err) {
    await saveSyncState({ ...state, recovery_in_progress: false });
    throw err;
  }
}
```

### Parallel Delta Fetch

```typescript
const MAX_CONCURRENT_FETCHES = 6;

async function fetchDeltasParallel(
  startId: number,
  endId: number,
  config: SyncConfig
): Promise<void> {
  const ids = Array.from(
    { length: endId - startId + 1 },
    (_, i) => startId + i
  );

  // Fetch in batches to limit concurrency
  for (let i = 0; i < ids.length; i += MAX_CONCURRENT_FETCHES) {
    const batch = ids.slice(i, i + MAX_CONCURRENT_FETCHES);

    const deltas = await Promise.all(
      batch.map(id => fetchDelta(id, config))
    );

    // Apply sequentially to maintain order
    for (const delta of deltas) {
      await decryptAndApplyDelta(delta, config);
    }
  }
}

async function fetchDelta(id: number, config: SyncConfig): Promise<ArrayBuffer> {
  const url = `${config.cdn_base}/deltas/${id}.bin`;
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Failed to fetch delta ${id}: ${response.status}`);
  }

  return response.arrayBuffer();
}
```

### Compaction-Based Recovery

See Issue #382 for the full greedy descent algorithm. Summary:

```typescript
async function recoverWithCompaction(
  localId: number,
  remoteId: number,
  config: SyncConfig
): Promise<void> {
  const manifest = await fetchManifest(config);
  const { compaction } = manifest;

  let currentId = localId;

  // 1. If very far behind, start from snapshot
  if (currentId < compaction.latest_snapshot) {
    const snapshot = await fetchSnapshot(compaction.latest_snapshot, config);
    await applySnapshot(snapshot);
    currentId = compaction.latest_snapshot;
  }

  // 2. Apply hecto bundles (100-delta)
  while (currentId + 100 <= remoteId &&
         currentId < compaction.deca_available_from - 100) {
    const bundleStart = currentId + 1;
    const bundleEnd = currentId + 100;
    const bundle = await fetchHectoBundle(bundleStart, bundleEnd, config);
    await applyBundle(bundle);
    currentId = bundleEnd;
  }

  // 3. Apply deca bundles (10-delta)
  while (currentId + 10 <= remoteId &&
         currentId < compaction.deltas_available_from - 10) {
    const bundleStart = currentId + 1;
    const bundleEnd = currentId + 10;
    const bundle = await fetchDecaBundle(bundleStart, bundleEnd, config);
    await applyBundle(bundle);
    currentId = bundleEnd;
  }

  // 4. Apply remaining individual deltas
  if (currentId < remoteId) {
    await fetchDeltasParallel(currentId + 1, remoteId, config);
  }
}
```

---

## VII. Cryptography

### Key Management

```typescript
interface SyncKeys {
  delta_key: CryptoKey;    // AES-256-GCM for delta decryption
  key_version: number;     // Matches manifest.key_version
}

// Derive delta key from org master key
async function deriveDeltaKey(masterKey: CryptoKey): Promise<CryptoKey> {
  // Use HKDF to derive purpose-specific key
  const info = new TextEncoder().encode('blockioc-delta-encryption-v1');

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32), // Fixed salt for deterministic derivation
      info
    },
    masterKey,
    256
  );

  return crypto.subtle.importKey(
    'raw',
    derivedBits,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
}
```

### Decryption

```typescript
async function decryptDelta(
  buffer: ArrayBuffer,
  key: CryptoKey
): Promise<ArrayBuffer> {
  // Extract IV (first 12 bytes)
  const iv = new Uint8Array(buffer.slice(0, 12));

  // Extract ciphertext (remaining bytes)
  const ciphertext = buffer.slice(12);

  // Decrypt with AES-GCM
  return crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv
    },
    key,
    ciphertext
  );
}

async function decryptAndApplyDelta(
  buffer: ArrayBuffer,
  config: SyncConfig
): Promise<void> {
  const keys = await loadSyncKeys();
  const plaintext = await decryptDelta(buffer, keys.delta_key);
  const delta = decodeDeltaPayload(plaintext);
  await applyDeltaToHashSet(delta);
}
```

### Delta Application

```typescript
async function applyDeltaToHashSet(delta: DeltaPayload): Promise<void> {
  const hashSet = await loadIOCHashSet();

  // Remove before add (handles updates)
  for (const hash of delta.remove) {
    hashSet.delete(hash);
  }

  for (const hash of delta.add) {
    hashSet.add(hash);
  }

  await saveIOCHashSet(hashSet);

  console.log(`[BlockIOC] Applied delta ${delta.id}: +${delta.add.length} -${delta.remove.length}`);
}
```

---

## VIII. Publisher Implementation

### Delta Publication Flow

```typescript
async function publishDelta(delta: DeltaPayload, config: PublisherConfig): Promise<void> {
  // 1. Encrypt delta
  const encrypted = await encryptDelta(delta, config.delta_key);

  // 2. Upload to R2
  const deltaPath = `deltas/${delta.id}.bin`;
  await uploadToR2(deltaPath, encrypted, {
    'Cache-Control': 'max-age=31536000, immutable'
  });

  // 3. Update manifests
  await updateManifests(delta.id, config);

  // 4. Send FCM notification
  if (shouldInline(encrypted)) {
    // Small delta - embed in FCM
    await sendFCMInline(delta.id, encrypted, config);
  } else {
    // Large delta - send tickle
    await sendFCMTickle(delta.id, config);
  }

  // 5. Trigger compaction if needed
  await maybeCompact(delta.id, config);
}

async function encryptDelta(
  delta: DeltaPayload,
  key: CryptoKey
): Promise<ArrayBuffer> {
  const plaintext = encodeDeltaPayload(delta);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );

  // Concatenate IV + ciphertext
  const result = new Uint8Array(12 + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), 12);

  return result.buffer;
}
```

### FCM Notification

```typescript
async function sendFCMInline(
  deltaId: number,
  encrypted: ArrayBuffer,
  config: PublisherConfig
): Promise<void> {
  const payload = {
    data: {
      type: 'SYNC_DELTA',
      id: String(deltaId),
      payload: arrayBufferToBase64(encrypted)
    }
  };

  await sendFCMToTopic(`org-${config.org_id}-enterprise`, payload);
}

async function sendFCMTickle(
  deltaId: number,
  config: PublisherConfig
): Promise<void> {
  const payload = {
    data: {
      type: 'SYNC_TICKLE',
      strategy: 'fetch',
      latest_id: String(deltaId)
    }
  };

  await sendFCMToTopic(`org-${config.org_id}-enterprise`, payload);
}
```

---

## IX. Economic Analysis

### Cost Model

| Component | Cost Driver | Optimization | Monthly Estimate |
|-----------|-------------|--------------|------------------|
| **FCM Messages** | Per-message pricing | Topic messaging (1 msg → N devices) | **$0** (free tier sufficient) |
| **R2 Storage** | Per-GB stored | Compaction reduces storage 100x | **~$0.50** |
| **R2 Reads (Class B)** | Per 1M requests | CDN 99%+ hit rate | **~$1** |
| **R2 Writes (Class A)** | Per 1M requests | Compaction (1000 deltas → 1 bundle) | **~$5** |
| **CDN Bandwidth** | Egress | Cloudflare = free egress | **$0** |

**Total Estimated Cost:** ~$6.50/month for typical deployment

### Scaling Characteristics

- **Horizontal:** Each org gets isolated R2 prefix, FCM topic
- **Delta Size:** ~100-500 bytes per IOC change (hash + metadata)
- **Compaction:** 1000 deltas → 1 hecto bundle, 100x read reduction
- **CDN Efficiency:** Immutable files cached indefinitely at edge

---

## X. Test Scenarios

| Scenario | Input | Expected Behavior |
|----------|-------|-------------------|
| Small delta via FCM | Delta < 2.8KB | Apply directly from payload, no R2 fetch |
| Large delta via FCM | Delta >= 2.8KB | Receive tickle, fetch from R2, apply |
| Sequential deltas | ID matches current+1 | Apply immediately |
| Gap <= 50 | e.g., have 100, receive 130 | Parallel fetch 30 individual deltas |
| Gap > 50 | e.g., have 100, receive 500 | Use bundles/snapshots per compaction |
| Enterprise watchdog | Every 5 min | Check manifest, recover if behind |
| Free tier watchdog | Every 60 min | Check manifest, recover if behind |
| FCM received | Any valid push | Reset watchdog timer |
| Manifest cache hit | Within TTL | CDN serves, no R2 read |
| Cold start (new install) | No local state | Fetch latest snapshot, then deltas |
| Network failure | Fetch fails | Retry on next watchdog, maintain local state |

---

## XI. Implementation Checklist

### Publisher (Node.js/Go/Rust)

- [ ] Delta encoding with CBOR or MessagePack
- [ ] AES-256-GCM encryption with random IV
- [ ] 2.8KB threshold check for inline vs fetch
- [ ] R2 upload with `immutable` cache headers
- [ ] Manifest update (separate enterprise/free files)
- [ ] FCM send via topic messaging
- [ ] Compaction trigger (per Issue #382)

### Extension (TypeScript)

- [ ] FCM registration on install
- [ ] FCM message handler (inline + tickle modes)
- [ ] Tier-based watchdog alarm (5 min / 60 min)
- [ ] Manifest fetching with tier-appropriate URL
- [ ] Gap threshold logic (>50 → bundles)
- [ ] Parallel delta fetch with concurrency limit
- [ ] AES-GCM decryption via WebCrypto
- [ ] Sequential delta application
- [ ] State persistence in chrome.storage.local
- [ ] Error handling and retry logic

### Infrastructure

- [ ] R2 bucket with appropriate lifecycle rules
- [ ] CDN caching rules (honor Cache-Control)
- [ ] Separate manifest files for tiers
- [ ] FCM project with topic support
- [ ] Monitoring for sync latency and error rates

---

## XII. Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Delta tampering | AES-GCM authentication (AEAD) |
| Replay attacks | Sequential delta IDs, state tracking |
| Key compromise | Key rotation via manifest, HKDF derivation |
| Man-in-the-middle | TLS for all fetches, FCM encryption |
| DoS via large deltas | Size limits, rate limiting at publisher |

### Privacy

- Delta payloads contain only IOC hashes, not URLs
- No PII in FCM payloads
- Org isolation via separate R2 prefixes and FCM topics

---

## References

- [Chrome GCM API](https://developer.chrome.com/docs/extensions/reference/gcm/)
- [Firebase Cloud Messaging](https://firebase.google.com/docs/cloud-messaging)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
- [Cloudflare R2 Pricing](https://developers.cloudflare.com/r2/pricing/)
- [AES-GCM Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- Related: Issue #382 (Geometric Compaction Strategy)
