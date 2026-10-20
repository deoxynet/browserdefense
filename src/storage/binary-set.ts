/**
 * Binary compact hash storage for IOC blocklists.
 *
 * Stores SHA-256 hashes (32 bytes each) in a contiguous ArrayBuffer,
 * sorted for O(log n) lookup via binary search.
 *
 * Why not JSON arrays?
 * - JSON hex strings: 64 chars + quotes + commas = ~70 bytes per hash
 * - Binary format: 32 bytes per hash (2x+ more compact)
 * - chrome.storage.local has 10MB limit - binary lets us fit 300k+ hashes
 */

const HASH_SIZE = 32; // SHA-256 = 32 bytes
const DEFAULT_CAPACITY = 100_000;
const GROWTH_FACTOR = 1.5;

export class BinaryHashSet {
  private buffer: ArrayBuffer;
  private view: Uint8Array;
  private _count: number;
  private capacity: number;

  constructor(capacity: number = DEFAULT_CAPACITY) {
    this.capacity = capacity;
    this.buffer = new ArrayBuffer(capacity * HASH_SIZE);
    this.view = new Uint8Array(this.buffer);
    this._count = 0;
  }

  /**
   * Number of hashes in the set.
   */
  get count(): number {
    return this._count;
  }

  /**
   * Size in bytes of the used portion.
   */
  get byteLength(): number {
    return this._count * HASH_SIZE;
  }

  /**
   * Add a hash to the set. Maintains sorted order for binary search.
   * @param hash - 32-byte ArrayBuffer or Uint8Array
   */
  add(hash: ArrayBuffer | Uint8Array): void {
    const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);

    if (hashBytes.length !== HASH_SIZE) {
      throw new Error(`Hash must be ${HASH_SIZE} bytes, got ${hashBytes.length}`);
    }

    // Find insertion point using binary search
    const insertIdx = this.findInsertionPoint(hashBytes);

    // Check if already exists (exact match at insertIdx)
    if (insertIdx < this._count && this.compareAt(insertIdx, hashBytes) === 0) {
      return; // Duplicate, skip
    }

    // Grow buffer if needed
    if (this._count >= this.capacity) {
      this.grow();
    }

    // Shift elements to make room
    if (insertIdx < this._count) {
      // Move everything from insertIdx to end, one slot forward
      const shiftStart = insertIdx * HASH_SIZE;
      const shiftEnd = this._count * HASH_SIZE;
      // Copy backwards to avoid overwriting
      for (let i = shiftEnd - 1; i >= shiftStart; i--) {
        this.view[i + HASH_SIZE] = this.view[i];
      }
    }

    // Insert the new hash
    this.view.set(hashBytes, insertIdx * HASH_SIZE);
    this._count++;
  }

  /**
   * Check if a hash exists in the set. O(log n) binary search.
   * @param hash - 32-byte ArrayBuffer or Uint8Array
   */
  has(hash: ArrayBuffer | Uint8Array): boolean {
    const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);

    if (hashBytes.length !== HASH_SIZE) {
      return false;
    }

    return this.binarySearch(hashBytes) !== -1;
  }

  /**
   * Remove all hashes from the set.
   */
  clear(): void {
    this._count = 0;
  }

  /**
   * Iterate over all hashes in the set.
   * Yields 32-byte Uint8Array views (not copies).
   */
  *hashes(): Generator<Uint8Array> {
    for (let i = 0; i < this._count; i++) {
      const offset = i * HASH_SIZE;
      yield this.view.subarray(offset, offset + HASH_SIZE);
    }
  }

  /**
   * Remove a hash from the set.
   * @param hash - 32-byte ArrayBuffer or Uint8Array
   * @returns true if the hash was found and removed, false if not found
   */
  delete(hash: ArrayBuffer | Uint8Array): boolean {
    const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);

    if (hashBytes.length !== HASH_SIZE) {
      return false;
    }

    // Find the hash using binary search
    const index = this.binarySearch(hashBytes);

    if (index === -1) {
      return false; // Not found
    }

    // Shift elements left to fill the gap
    const shiftStart = (index + 1) * HASH_SIZE;
    const shiftEnd = this._count * HASH_SIZE;

    for (let i = shiftStart; i < shiftEnd; i++) {
      this.view[i - HASH_SIZE] = this.view[i];
    }

    this._count--;
    return true;
  }

  /**
   * Serialize to base64 string for storage.
   * Only serializes the used portion of the buffer.
   */
  serialize(): string {
    const usedBytes = this.view.slice(0, this._count * HASH_SIZE);
    return uint8ArrayToBase64(usedBytes);
  }

  /**
   * Deserialize from base64 string.
   * Assumes the data is already sorted (as produced by serialize).
   */
  static deserialize(data: string): BinaryHashSet {
    const bytes = base64ToUint8Array(data);

    if (bytes.length % HASH_SIZE !== 0) {
      throw new Error(`Invalid data length: ${bytes.length} is not a multiple of ${HASH_SIZE}`);
    }

    const count = bytes.length / HASH_SIZE;
    const set = new BinaryHashSet(Math.max(count, DEFAULT_CAPACITY));
    set.view.set(bytes);
    set._count = count;

    return set;
  }

  /**
   * Create a BinaryHashSet from an iterable of hex strings.
   * Useful for bulk loading.
   */
  static fromHexStrings(hexStrings: Iterable<string>): BinaryHashSet {
    const hashes: Uint8Array[] = [];

    for (const hex of hexStrings) {
      hashes.push(hexToBytes(hex));
    }

    // Sort before inserting for efficiency
    hashes.sort(compareUint8Arrays);

    const set = new BinaryHashSet(Math.max(hashes.length, DEFAULT_CAPACITY));

    // Bulk insert (already sorted, no shifting needed)
    for (const hash of hashes) {
      // Skip duplicates
      if (set._count > 0 && set.compareAt(set._count - 1, hash) === 0) {
        continue;
      }
      set.view.set(hash, set._count * HASH_SIZE);
      set._count++;
    }

    return set;
  }

  /**
   * Binary search for exact match.
   * @returns index if found, -1 if not found
   */
  private binarySearch(target: Uint8Array): number {
    let left = 0;
    let right = this._count - 1;

    while (left <= right) {
      const mid = (left + right) >>> 1;
      const cmp = this.compareAt(mid, target);

      if (cmp === 0) {
        return mid;
      } else if (cmp < 0) {
        left = mid + 1;
      } else {
        right = mid - 1;
      }
    }

    return -1;
  }

  /**
   * Find insertion point for maintaining sorted order.
   * @returns index where the hash should be inserted
   */
  private findInsertionPoint(target: Uint8Array): number {
    let left = 0;
    let right = this._count;

    while (left < right) {
      const mid = (left + right) >>> 1;
      const cmp = this.compareAt(mid, target);

      if (cmp < 0) {
        left = mid + 1;
      } else {
        right = mid;
      }
    }

    return left;
  }

  /**
   * Compare hash at index with target.
   * @returns negative if index < target, 0 if equal, positive if index > target
   */
  private compareAt(index: number, target: Uint8Array): number {
    const offset = index * HASH_SIZE;

    for (let i = 0; i < HASH_SIZE; i++) {
      const diff = this.view[offset + i] - target[i];
      if (diff !== 0) {
        return diff;
      }
    }

    return 0;
  }

  /**
   * Grow the buffer when capacity is exceeded.
   */
  private grow(): void {
    const newCapacity = Math.floor(this.capacity * GROWTH_FACTOR);
    const newBuffer = new ArrayBuffer(newCapacity * HASH_SIZE);
    const newView = new Uint8Array(newBuffer);

    // Copy existing data
    newView.set(this.view.slice(0, this._count * HASH_SIZE));

    this.buffer = newBuffer;
    this.view = newView;
    this.capacity = newCapacity;
  }
}

// ============ Utility Functions ============

/**
 * Convert hex string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.toLowerCase().replace(/^0x/, '');

  if (normalized.length !== HASH_SIZE * 2) {
    throw new Error(`Hex string must be ${HASH_SIZE * 2} characters, got ${normalized.length}`);
  }

  const bytes = new Uint8Array(HASH_SIZE);

  for (let i = 0; i < HASH_SIZE; i++) {
    bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

/**
 * Convert Uint8Array to hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Compare two Uint8Arrays lexicographically.
 */
function compareUint8Arrays(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);

  for (let i = 0; i < len; i++) {
    const diff = a[i] - b[i];
    if (diff !== 0) {
      return diff;
    }
  }

  return a.length - b.length;
}

/**
 * Convert Uint8Array to base64 string.
 * Handles large arrays without stack overflow.
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  // Use chunks to avoid stack overflow on large arrays
  const CHUNK_SIZE = 0x8000; // 32KB chunks
  let binary = '';

  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array.
 */
function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}
