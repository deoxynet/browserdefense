import { describe, it, expect, beforeEach } from 'vitest';
import { BinaryHashSet, hexToBytes, bytesToHex } from '../src/storage/binary-set';

// Helper to generate random SHA-256 hash (32 bytes)
function randomHash(): Uint8Array {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}

// Helper to generate deterministic hash from seed
function hashFromSeed(seed: number): string {
  const hex = seed.toString(16).padStart(64, '0');
  return hex;
}

describe('BinaryHashSet', () => {
  let hashSet: BinaryHashSet;

  beforeEach(() => {
    hashSet = new BinaryHashSet();
  });

  describe('basic operations', () => {
    it('should start empty', () => {
      expect(hashSet.count).toBe(0);
      expect(hashSet.byteLength).toBe(0);
    });

    it('should add and find a hash', () => {
      const hash = randomHash();
      hashSet.add(hash);

      expect(hashSet.count).toBe(1);
      expect(hashSet.has(hash)).toBe(true);
    });

    it('should not find a hash that was not added', () => {
      const hash1 = randomHash();
      const hash2 = randomHash();

      hashSet.add(hash1);

      expect(hashSet.has(hash1)).toBe(true);
      expect(hashSet.has(hash2)).toBe(false);
    });

    it('should handle duplicate adds', () => {
      const hash = randomHash();

      hashSet.add(hash);
      hashSet.add(hash);
      hashSet.add(hash);

      expect(hashSet.count).toBe(1);
    });

    it('should clear all hashes', () => {
      hashSet.add(randomHash());
      hashSet.add(randomHash());
      hashSet.add(randomHash());

      expect(hashSet.count).toBe(3);

      hashSet.clear();

      expect(hashSet.count).toBe(0);
    });
  });

  describe('hex conversion', () => {
    it('should convert hex string to bytes', () => {
      const hex = '0'.repeat(64);
      const bytes = hexToBytes(hex);

      expect(bytes.length).toBe(32);
      expect(bytes.every(b => b === 0)).toBe(true);
    });

    it('should convert bytes to hex string', () => {
      const bytes = new Uint8Array(32);
      bytes[0] = 0xff;
      bytes[31] = 0xab;

      const hex = bytesToHex(bytes);

      expect(hex).toBe('ff' + '00'.repeat(30) + 'ab');
    });

    it('should roundtrip hex conversion', () => {
      const original = 'a1b2c3d4e5f6'.padEnd(64, '0');
      const bytes = hexToBytes(original);
      const result = bytesToHex(bytes);

      expect(result).toBe(original);
    });

    it('should reject invalid hex length', () => {
      expect(() => hexToBytes('abc')).toThrow();
      expect(() => hexToBytes('0'.repeat(63))).toThrow();
      expect(() => hexToBytes('0'.repeat(65))).toThrow();
    });

    it('should handle 0x prefix', () => {
      const hex = '0x' + '0'.repeat(64);
      const bytes = hexToBytes(hex);

      expect(bytes.length).toBe(32);
    });
  });

  describe('fromHexStrings', () => {
    it('should bulk load hex strings', () => {
      const hexStrings = [
        hashFromSeed(100),
        hashFromSeed(50),
        hashFromSeed(200),
      ];

      const set = BinaryHashSet.fromHexStrings(hexStrings);

      expect(set.count).toBe(3);

      for (const hex of hexStrings) {
        expect(set.has(hexToBytes(hex))).toBe(true);
      }
    });

    it('should deduplicate during bulk load', () => {
      const hex = hashFromSeed(42);
      const hexStrings = [hex, hex, hex];

      const set = BinaryHashSet.fromHexStrings(hexStrings);

      expect(set.count).toBe(1);
    });
  });

  describe('serialization', () => {
    it('should serialize empty set', () => {
      const serialized = hashSet.serialize();

      expect(serialized).toBe('');
    });

    it('should serialize and deserialize single hash', () => {
      const hash = randomHash();
      hashSet.add(hash);

      const serialized = hashSet.serialize();
      const restored = BinaryHashSet.deserialize(serialized);

      expect(restored.count).toBe(1);
      expect(restored.has(hash)).toBe(true);
    });

    it('should roundtrip multiple hashes', () => {
      const hashes = Array.from({ length: 100 }, () => randomHash());

      for (const hash of hashes) {
        hashSet.add(hash);
      }

      const serialized = hashSet.serialize();
      const restored = BinaryHashSet.deserialize(serialized);

      expect(restored.count).toBe(100);

      for (const hash of hashes) {
        expect(restored.has(hash)).toBe(true);
      }
    });

    it('should reject invalid data length', () => {
      // Create base64 that decodes to non-multiple of 32 bytes
      const invalidData = btoa('x'.repeat(33));

      expect(() => BinaryHashSet.deserialize(invalidData)).toThrow();
    });
  });

  describe('sorted order', () => {
    it('should maintain sorted order after adds', () => {
      // Add hashes in reverse order
      for (let i = 100; i >= 0; i--) {
        hashSet.add(hexToBytes(hashFromSeed(i)));
      }

      // Verify all can be found
      for (let i = 0; i <= 100; i++) {
        expect(hashSet.has(hexToBytes(hashFromSeed(i)))).toBe(true);
      }
    });

    it('should find hashes added in random order', () => {
      const seeds = Array.from({ length: 50 }, (_, i) => i);

      // Shuffle
      for (let i = seeds.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [seeds[i], seeds[j]] = [seeds[j], seeds[i]];
      }

      // Add in random order
      for (const seed of seeds) {
        hashSet.add(hexToBytes(hashFromSeed(seed)));
      }

      // All should be findable
      for (let i = 0; i < 50; i++) {
        expect(hashSet.has(hexToBytes(hashFromSeed(i)))).toBe(true);
      }
    });
  });

  describe('large sets (10k+ hashes)', () => {
    it('should handle 10,000 hashes', () => {
      const count = 10_000;
      const hashes: Uint8Array[] = [];

      for (let i = 0; i < count; i++) {
        const hash = hexToBytes(hashFromSeed(i));
        hashes.push(hash);
        hashSet.add(hash);
      }

      expect(hashSet.count).toBe(count);

      // Verify random samples
      for (let i = 0; i < 100; i++) {
        const idx = Math.floor(Math.random() * count);
        expect(hashSet.has(hashes[idx])).toBe(true);
      }

      // Verify non-existent hashes
      for (let i = count; i < count + 100; i++) {
        expect(hashSet.has(hexToBytes(hashFromSeed(i)))).toBe(false);
      }
    });

    it('should serialize/deserialize 10,000 hashes', () => {
      const count = 10_000;

      for (let i = 0; i < count; i++) {
        hashSet.add(hexToBytes(hashFromSeed(i)));
      }

      const serialized = hashSet.serialize();
      const restored = BinaryHashSet.deserialize(serialized);

      expect(restored.count).toBe(count);

      // Verify random samples
      for (let i = 0; i < 100; i++) {
        const idx = Math.floor(Math.random() * count);
        expect(restored.has(hexToBytes(hashFromSeed(idx)))).toBe(true);
      }
    });

    it('should handle 50,000 hashes via bulk load', () => {
      const count = 50_000;
      const hexStrings: string[] = [];

      for (let i = 0; i < count; i++) {
        hexStrings.push(hashFromSeed(i));
      }

      const set = BinaryHashSet.fromHexStrings(hexStrings);

      expect(set.count).toBe(count);

      // Verify random samples
      for (let i = 0; i < 100; i++) {
        const idx = Math.floor(Math.random() * count);
        expect(set.has(hexToBytes(hashFromSeed(idx)))).toBe(true);
      }
    });

    it('should have compact serialization (32 bytes per hash + base64 overhead)', () => {
      const count = 10_000;

      for (let i = 0; i < count; i++) {
        hashSet.add(hexToBytes(hashFromSeed(i)));
      }

      const serialized = hashSet.serialize();

      // Binary: 32 bytes * 10,000 = 320,000 bytes
      // Base64 overhead: ~33% -> ~426,667 bytes
      // Compare to JSON hex: ~70 bytes * 10,000 = 700,000 bytes

      expect(serialized.length).toBeLessThan(450_000); // Well under JSON approach
      expect(serialized.length).toBeLessThan(700_000 * 0.7); // At least 30% savings
    });
  });

  describe('edge cases', () => {
    it('should reject hash with wrong size', () => {
      expect(() => hashSet.add(new Uint8Array(31))).toThrow();
      expect(() => hashSet.add(new Uint8Array(33))).toThrow();
    });

    it('should return false for wrong-sized hash in has()', () => {
      hashSet.add(randomHash());

      expect(hashSet.has(new Uint8Array(31))).toBe(false);
      expect(hashSet.has(new Uint8Array(0))).toBe(false);
    });

    it('should handle ArrayBuffer input', () => {
      const buffer = new ArrayBuffer(32);
      const view = new Uint8Array(buffer);
      view[0] = 0xff;

      hashSet.add(buffer);

      expect(hashSet.has(buffer)).toBe(true);
      expect(hashSet.has(view)).toBe(true);
    });

    it('should grow buffer when capacity exceeded', () => {
      const smallSet = new BinaryHashSet(10);

      // Add more than initial capacity
      for (let i = 0; i < 20; i++) {
        smallSet.add(hexToBytes(hashFromSeed(i)));
      }

      expect(smallSet.count).toBe(20);

      // All should still be findable
      for (let i = 0; i < 20; i++) {
        expect(smallSet.has(hexToBytes(hashFromSeed(i)))).toBe(true);
      }
    });
  });

  describe('performance', () => {
    it('should have O(log n) lookup time', () => {
      const count = 100_000;
      const set = new BinaryHashSet(count);

      // Bulk add using fromHexStrings for speed
      const hexStrings: string[] = [];
      for (let i = 0; i < count; i++) {
        hexStrings.push(hashFromSeed(i));
      }
      const loadedSet = BinaryHashSet.fromHexStrings(hexStrings);

      // Measure lookup time for 1000 queries
      const queries = 1000;
      const start = performance.now();

      for (let i = 0; i < queries; i++) {
        const idx = Math.floor(Math.random() * count);
        loadedSet.has(hexToBytes(hashFromSeed(idx)));
      }

      const elapsed = performance.now() - start;

      // 1000 lookups in 100k set should be fast (< 100ms)
      // O(log n) = ~17 comparisons per lookup
      expect(elapsed).toBeLessThan(100);
    });
  });
});
