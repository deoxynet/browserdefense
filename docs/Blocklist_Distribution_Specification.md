# Blocklist Distribution Specification

This document describes the R2 storage layout, manifest schema, and API for distributing blocklist updates to BlockIOC browser extensions.

## Overview

The blocklist distribution system uses Cloudflare R2 for storage and a Cloudflare Worker for the API layer. Updates are served as:

1. **Full snapshots** - Complete base64-encoded blocklists (immutable)
2. **Delta updates** - Binary diffs between versions (immutable)
3. **Manifest** - JSON file pointing to current snapshot and available deltas

## R2 Storage Layout

```
/{account}/
├── manifest.json                    # Current version manifest (mutable, CDN-cached 5min)
├── snapshots/
│   ├── {version}.b64               # Immutable base64 blocklist snapshot
│   └── ...
├── deltas/
│   ├── {from}-{to}.bin             # Binary delta from version {from} to {to}
│   └── ...
└── meta/
    └── versions.json               # Version history for cleanup (internal)
```

### File Types

| Path Pattern | Content-Type | Cache-Control | Description |
|--------------|--------------|---------------|-------------|
| `manifest.json` | `application/json` | `max-age=300, stale-while-revalidate=60` | Current version info |
| `snapshots/{version}.b64` | `text/plain` | `max-age=31536000, immutable` | Base64-encoded blocklist |
| `deltas/{from}-{to}.bin` | `application/octet-stream` | `max-age=31536000, immutable` | Binary delta |

## Manifest Schema

```typescript
interface BlocklistManifest {
  /** Monotonically increasing version number (typically Unix timestamp in ms) */
  version: number;

  /** Total number of IOC hashes in the blocklist */
  total_iocs: number;

  /** Number of buckets (1 for single-file, >1 for sharded) */
  bucket_count: number;

  /** SHA-256 hash of the raw binary blocklist content (hex, lowercase) */
  sha256_root: string;

  /** Base64-encoded signature over canonical manifest fields */
  signature: string;

  /** ISO 8601 timestamp when this version was created */
  created_at: string;

  /** Signing algorithm: 'p256-v1' or 'ed25519-v2' */
  algorithm_version: string;

  /** Relative URL to the snapshot file */
  snapshot_url: string;

  /** Available deltas from previous versions */
  deltas: DeltaInfo[];
}

interface DeltaInfo {
  /** Source version */
  from: number;

  /** Target version (should match manifest.version) */
  to: number;

  /** Relative URL to the delta file */
  url: string;

  /** Size in bytes */
  size: number;
}
```

### Example Manifest

```json
{
  "version": 1736451234567,
  "total_iocs": 5000,
  "bucket_count": 1,
  "sha256_root": "a1b2c3d4e5f6...",
  "signature": "MEUCIQC...",
  "created_at": "2026-01-09T15:00:34.567Z",
  "algorithm_version": "p256-v1",
  "snapshot_url": "snapshots/1736451234567.b64",
  "deltas": [
    {
      "from": 1736447634567,
      "to": 1736451234567,
      "url": "deltas/1736447634567-1736451234567.bin",
      "size": 1024
    }
  ]
}
```

### Signature Verification

The signature covers a canonical JSON object with sorted keys:

```json
{"bucket_count":1,"sha256_root":"a1b2c3...","total_iocs":5000,"version":1736451234567}
```

**Algorithm-specific signing:**
- **P-256 ECDSA (`p256-v1`)**: SHA-256 hash of canonical JSON, signature in raw (r||s) format, base64-encoded
- **Ed25519 (`ed25519-v2`)**: Direct signature of canonical JSON bytes, base64-encoded

## Snapshot Format

Snapshots are base64-encoded binary files containing sorted 32-byte SHA-256 hashes:

```
[hash_1: 32 bytes]
[hash_2: 32 bytes]
...
[hash_n: 32 bytes]
```

**Properties:**
- Hashes are sorted in lexicographic (binary) order
- Total size = `total_iocs * 32` bytes (before base64 encoding)
- SHA-256 hash of the raw binary = `sha256_root`

## Delta Format

Deltas are binary files with the following structure:

```
[4 bytes: added_count (uint32 little-endian)]
[4 bytes: removed_count (uint32 little-endian)]
[added_count * 32 bytes: added hashes]
[removed_count * 32 bytes: removed hashes]
```

**Properties:**
- Total size = `8 + (added_count + removed_count) * 32` bytes
- Applied by: (1) removing `removed` hashes, (2) adding `added` hashes
- After application, the resulting blocklist should match `sha256_root`

## API Endpoints

### Read Endpoints (Public, CDN-cacheable)

#### GET `/{account}/manifest.json`

Returns the current blocklist manifest.

**Response:** `200 OK` with `BlocklistManifest` JSON

**Cache:** `max-age=300, stale-while-revalidate=60`

#### GET `/{account}/snapshots/{version}.b64`

Returns a specific snapshot version.

**Response:** `200 OK` with base64-encoded blocklist

**Cache:** `max-age=31536000, immutable`

#### GET `/{account}/deltas/{from}-{to}.bin`

Returns a specific delta file.

**Response:** `200 OK` with binary delta

**Cache:** `max-age=31536000, immutable`

### Write Endpoint (Authenticated)

#### POST `/api/publish/{account}`

Publishes a new blocklist version.

**Headers:**
- `Authorization: Bearer {API_KEY}` or `X-API-Key: {API_KEY}`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "blocklist_b64": "base64-encoded binary blocklist",
  "manifest": {
    "version": 1736451234567,
    "total_iocs": 5000,
    "bucket_count": 1,
    "sha256_root": "a1b2c3...",
    "signature": "MEUCIQC...",
    "created_at": "2026-01-09T15:00:34.567Z",
    "algorithm_version": "p256-v1"
  }
}
```

**Response:** `201 Created`
```json
{
  "success": true,
  "version": 1736451234567,
  "snapshot_url": "snapshots/1736451234567.b64",
  "deltas_created": 1
}
```

**Errors:**
- `400 Bad Request` - Invalid request body or manifest
- `401 Unauthorized` - Missing or invalid API key
- `409 Conflict` - Version number not greater than current

### Health Check

#### GET `/health`

Returns worker health status.

**Response:** `200 OK`
```json
{
  "status": "ok",
  "timestamp": "2026-01-09T15:00:00.000Z"
}
```

## Extension Update Flow

1. **Fetch manifest** from `{endpoint}/manifest.json`
2. **Verify signature** using configured public key
3. **Check version** - skip if manifest version <= current version
4. **Try delta** (if available and size < threshold):
   - Find delta where `from` matches current version
   - Fetch delta, apply to local blocklist
   - Verify result matches `sha256_root`
5. **Fall back to snapshot** (if delta unavailable or fails):
   - Fetch full snapshot from `snapshot_url`
   - Verify hash matches `sha256_root`
   - Replace local blocklist
6. **Save metadata** - version, timestamp, hash count
7. **Reload in-memory blocklist** for immediate effect

## Version Retention

The distribution worker retains the last 5 versions:
- Current version manifest
- 5 most recent snapshots
- Deltas from those 5 versions to current

Older snapshots are automatically deleted during publish.

## Security Considerations

1. **Signature verification** - All manifests must be signed; extensions reject unsigned updates
2. **Integrity verification** - `sha256_root` ensures blocklist wasn't tampered with
3. **Version monotonicity** - Prevents rollback attacks (version must increase)
4. **Delta validation** - After applying delta, verify result matches expected hash
5. **Authenticated publish** - Only authorized clients can publish new versions
6. **Immutable artifacts** - Snapshots and deltas are never modified after creation

## Environment Variables

| Variable | Description |
|----------|-------------|
| `BLOCKLIST_BUCKET` | R2 bucket binding name |
| `PUBLISH_API_KEY` | API key for publish endpoint |
| `CORS_ORIGIN` | Allowed CORS origin (default: `*`) |

## Migration from Legacy Format

The legacy worker (`functions/blocklist.ts`) uses a different format:
- Manifest contains inline `hashes[]` array
- Deltas computed on-demand (not immutable)

To migrate:
1. Deploy new worker alongside legacy
2. Use CLI to compile and sign blocklist
3. Publish to new endpoint using `/api/publish/{account}`
4. Update extension configuration to new endpoint
5. Deprecate legacy worker after transition

## CLI Integration

The BlockIOC CLI produces compatible output:

```bash
# Compile IOCs to binary format
blockioc compile --input blocklist.txt --salt config.json

# Sign the manifest
blockioc sign --key signing-private.jwk

# Output files:
# - blocklist.b64  (snapshot)
# - manifest.json  (manifest)
```

To publish:
```bash
curl -X POST "https://blocklist.example.com/api/publish/my-org" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "blocklist_b64": "$(cat blocklist.b64)",
  "manifest": $(cat manifest.json)
}
EOF
```
