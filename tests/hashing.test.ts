import { describe, it, expect } from 'vitest';
import { sha256, sha256Bytes, sha256Hex, sha256ArrayBuffer } from '../src/crypto/hashing';

describe('SHA-256 Hashing', () => {
  describe('sha256ArrayBuffer', () => {
    it('should return ArrayBuffer of correct size', async () => {
      const result = await sha256ArrayBuffer('test');
      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(result.byteLength).toBe(32);
    });

    it('should produce consistent hashes', async () => {
      const hash1 = await sha256ArrayBuffer('hello');
      const hash2 = await sha256ArrayBuffer('hello');

      const view1 = new Uint8Array(hash1);
      const view2 = new Uint8Array(hash2);

      expect(Array.from(view1)).toEqual(Array.from(view2));
    });

    it('should produce different hashes for different inputs', async () => {
      const hash1 = await sha256ArrayBuffer('hello');
      const hash2 = await sha256ArrayBuffer('world');

      const view1 = new Uint8Array(hash1);
      const view2 = new Uint8Array(hash2);

      expect(Array.from(view1)).not.toEqual(Array.from(view2));
    });
  });

  describe('sha256', () => {
    it('should return 64-character hex string', async () => {
      const result = await sha256('test');
      expect(typeof result).toBe('string');
      expect(result.length).toBe(64);
      expect(/^[0-9a-f]+$/.test(result)).toBe(true);
    });

    it('should match known SHA-256 values', async () => {
      // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
      const result = await sha256('hello');
      expect(result).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });

    it('should handle empty string', async () => {
      // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const result = await sha256('');
      expect(result).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should handle Uint8Array input', async () => {
      const bytes = new TextEncoder().encode('hello');
      const result = await sha256(bytes);
      expect(result).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });
  });

  describe('sha256Bytes', () => {
    it('should return Uint8Array of correct size', async () => {
      const result = await sha256Bytes('test');
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });

    it('should handle Uint8Array input', async () => {
      const bytes = new TextEncoder().encode('test');
      const result = await sha256Bytes(bytes);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });
  });

  describe('sha256Hex', () => {
    it('should return 64-character hex string', async () => {
      const result = await sha256Hex('test');
      expect(typeof result).toBe('string');
      expect(result.length).toBe(64);
      expect(/^[0-9a-f]+$/.test(result)).toBe(true);
    });

    it('should match known SHA-256 values', async () => {
      // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
      const result = await sha256Hex('hello');
      expect(result).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });

    it('should handle empty string', async () => {
      // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const result = await sha256Hex('');
      expect(result).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should handle unicode', async () => {
      const result = await sha256Hex('日本語');
      expect(result.length).toBe(64);
    });

    it('should handle long strings', async () => {
      const longString = 'a'.repeat(10000);
      const result = await sha256Hex(longString);
      expect(result.length).toBe(64);
    });
  });
});
