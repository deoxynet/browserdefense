/**
 * Binary Bloom Filter for IOC Lookup Acceleration
 *
 * An append-only Bloom filter that acts as a fast negative prefilter
 * for IOC lookups. This is a PERFORMANCE OPTIMIZATION, not a security primitive.
 *
 * Key properties:
 * - False positives possible ("possibly in set")
 * - False negatives NEVER occur ("definitely not in set" is always accurate)
 * - Append-only: insertions only, no deletions
 * - Deletes mark filter "dirty" for deferred rebuild
 * - Stored as binary blob in IndexedDB
 *
 * Usage:
 * 1. Check bloom filter first (fast)
 * 2. If bloom says "not in set" -> skip expensive hash lookup
 * 3. If bloom says "possibly in set" -> do the actual lookup
 *
 * IMPORTANT: Bloom filter NEVER causes enforcement decisions.
 * A positive bloom result must ALWAYS be verified against the authoritative set.
 *
 * Reference: Issue #160
 */

// ============ Constants ============

/** Default number of bits per item (controls false positive rate) */
const BITS_PER_ITEM = 10;

/** Default number of hash functions */
const DEFAULT_K = 7;

/** Minimum filter size in bits */
const MIN_BITS = 1024;

/** Maximum filter size in bits (128 MB) */
const MAX_BITS = 1024 * 1024 * 1024;

// ============ Types ============

/**
 * Bloom filter metadata for storage and rebuild tracking.
 */
export interface BloomFilterMeta {
  /** Number of items inserted */
  itemCount: number;
  /** Number of bits in the filter */
  bitCount: number;
  /** Number of hash functions used */
  hashCount: number;
  /** Whether the filter needs rebuild (due to deletes) */
  isDirty: boolean;
  /** Timestamp of last rebuild (ISO 8601) */
  lastRebuild?: string;
  /** Version of the source blocklist when bloom was built */
  sourceVersion?: number;
}

/**
 * Configuration for creating a new Bloom filter.
 */
export interface BloomFilterConfig {
  /** Expected number of items */
  expectedItems: number;
  /** Target false positive rate (0-1, default 0.01 = 1%) */
  falsePositiveRate?: number;
  /** Number of hash functions (auto-calculated if not provided) */
  hashCount?: number;
}

// ============ BloomFilter Class ============

/**
 * Binary Bloom filter implementation.
 *
 * Uses double hashing technique for generating multiple hash values.
 */
export class BloomFilter {
  private bits: Uint8Array;
  private _itemCount: number;
  private _hashCount: number;
  private _isDirty: boolean;
  private _lastRebuild?: string;
  private _sourceVersion?: number;

  constructor(bitCount: number, hashCount: number = DEFAULT_K) {
    if (bitCount < MIN_BITS) {
      bitCount = MIN_BITS;
    }
    if (bitCount > MAX_BITS) {
      throw new Error(`Bloom filter too large: ${bitCount} bits exceeds max ${MAX_BITS}`);
    }

    const byteCount = Math.ceil(bitCount / 8);
    this.bits = new Uint8Array(byteCount);
    this._itemCount = 0;
    this._hashCount = hashCount;
    this._isDirty = false;
  }

  get itemCount(): number {
    return this._itemCount;
  }

  get bitCount(): number {
    return this.bits.length * 8;
  }

  get hashCount(): number {
    return this._hashCount;
  }

  get byteLength(): number {
    return this.bits.length;
  }

  get isDirty(): boolean {
    return this._isDirty;
  }

  get lastRebuild(): string | undefined {
    return this._lastRebuild;
  }

  get sourceVersion(): number | undefined {
    return this._sourceVersion;
  }

  get estimatedFalsePositiveRate(): number {
    const k = this._hashCount;
    const n = this._itemCount;
    const m = this.bitCount;
    if (n === 0) return 0;
    const exp = Math.exp((-k * n) / m);
    return Math.pow(1 - exp, k);
  }

  get fillRatio(): number {
    let setBits = 0;
    for (let i = 0; i < this.bits.length; i++) {
      setBits += popCount(this.bits[i]);
    }
    return setBits / this.bitCount;
  }

  add(hash: Uint8Array | ArrayBuffer): void {
    const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);
    const positions = this.getHashPositions(hashBytes);
    for (const pos of positions) {
      this.setBit(pos);
    }
    this._itemCount++;
  }

  addHex(hexHash: string): void {
    this.add(hexToBytes(hexHash));
  }

  mightContain(hash: Uint8Array | ArrayBuffer): boolean {
    const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);
    const positions = this.getHashPositions(hashBytes);
    for (const pos of positions) {
      if (!this.getBit(pos)) {
        return false;
      }
    }
    return true;
  }

  mightContainHex(hexHash: string): boolean {
    return this.mightContain(hexToBytes(hexHash));
  }

  markDirty(): void {
    this._isDirty = true;
  }

  markClean(sourceVersion?: number): void {
    this._isDirty = false;
    this._lastRebuild = new Date().toISOString();
    this._sourceVersion = sourceVersion;
  }

  reset(): void {
    this.bits.fill(0);
    this._itemCount = 0;
    this._isDirty = false;
    this._lastRebuild = undefined;
    this._sourceVersion = undefined;
  }

  serialize(): Uint8Array {
    return this.bits.slice();
  }

  serializeToBase64(): string {
    return uint8ArrayToBase64(this.bits);
  }

  getMeta(): BloomFilterMeta {
    return {
      itemCount: this._itemCount,
      bitCount: this.bitCount,
      hashCount: this._hashCount,
      isDirty: this._isDirty,
      lastRebuild: this._lastRebuild,
      sourceVersion: this._sourceVersion,
    };
  }

  static deserialize(data: Uint8Array, meta: BloomFilterMeta): BloomFilter {
    const filter = new BloomFilter(meta.bitCount, meta.hashCount);
    filter.bits.set(data);
    filter._itemCount = meta.itemCount;
    filter._isDirty = meta.isDirty;
    filter._lastRebuild = meta.lastRebuild;
    filter._sourceVersion = meta.sourceVersion;
    return filter;
  }

  static deserializeFromBase64(base64: string, meta: BloomFilterMeta): BloomFilter {
    const data = base64ToUint8Array(base64);
    return BloomFilter.deserialize(data, meta);
  }

  static create(config: BloomFilterConfig): BloomFilter {
    const { expectedItems, falsePositiveRate = 0.01 } = config;
    const n = Math.max(1, expectedItems);
    const p = Math.max(0.0001, Math.min(0.5, falsePositiveRate));
    const ln2Sq = Math.LN2 * Math.LN2;
    const m = Math.ceil((-n * Math.log(p)) / ln2Sq);
    const optimalK = config.hashCount ?? Math.round((m / n) * Math.LN2);
    const k = Math.max(1, Math.min(20, optimalK));
    return new BloomFilter(m, k);
  }

  static fromHashes(
    hashes: Iterable<Uint8Array | ArrayBuffer>,
    expectedCount: number,
    sourceVersion?: number
  ): BloomFilter {
    const filter = BloomFilter.create({ expectedItems: expectedCount });
    for (const hash of hashes) {
      filter.add(hash);
    }
    filter.markClean(sourceVersion);
    return filter;
  }

  static fromHexHashes(
    hexHashes: Iterable<string>,
    expectedCount: number,
    sourceVersion?: number
  ): BloomFilter {
    const filter = BloomFilter.create({ expectedItems: expectedCount });
    for (const hex of hexHashes) {
      filter.addHex(hex);
    }
    filter.markClean(sourceVersion);
    return filter;
  }

  private getHashPositions(hash: Uint8Array): number[] {
    const h1 = readUint64(hash, 0);
    const h2 = readUint64(hash, 8);
    const m = this.bitCount;
    const positions: number[] = [];
    for (let i = 0; i < this._hashCount; i++) {
      const pos = Number((h1 + BigInt(i) * h2) % BigInt(m));
      positions.push(pos);
    }
    return positions;
  }

  private setBit(position: number): void {
    const byteIndex = Math.floor(position / 8);
    const bitIndex = position % 8;
    this.bits[byteIndex] |= 1 << bitIndex;
  }

  private getBit(position: number): boolean {
    const byteIndex = Math.floor(position / 8);
    const bitIndex = position % 8;
    return (this.bits[byteIndex] & (1 << bitIndex)) !== 0;
  }
}

// ============ Utility Functions ============

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.toLowerCase().replace(/^0x/, '');
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function readUint64(bytes: Uint8Array, offset: number): bigint {
  let result = BigInt(0);
  for (let i = 7; i >= 0; i--) {
    result = (result << BigInt(8)) | BigInt(bytes[offset + i]);
  }
  return result;
}

function popCount(n: number): number {
  n = n - ((n >>> 1) & 0x55);
  n = (n & 0x33) + ((n >>> 2) & 0x33);
  return (n + (n >>> 4)) & 0x0f;
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ============ Storage Integration ============

export const BLOOM_STORAGE_KEYS = {
  DATA: 'bloom_data',
  META: 'bloom_meta',
} as const;

export function needsRebuild(
  meta: BloomFilterMeta,
  currentSourceVersion?: number,
  fillThreshold: number = 0.5
): boolean {
  if (meta.isDirty) {
    return true;
  }
  if (meta.sourceVersion !== undefined && currentSourceVersion !== undefined) {
    if (currentSourceVersion !== meta.sourceVersion) {
      return true;
    }
  }
  const optimalBits = meta.itemCount * BITS_PER_ITEM;
  const estimatedFill = Math.min(1, optimalBits / meta.bitCount);
  if (estimatedFill > fillThreshold) {
    return true;
  }
  return false;
}
