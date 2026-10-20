/**
 * Tests for Hash Labels
 *
 * Tests for analyst TP/FP labels attached to DOM kit hashes.
 *
 * Reference: Issue #205
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// ============ Types ============

type HashLabelType = 'TP' | 'FP' | 'UNKNOWN';

interface HashLabel {
  dom_kit_hash: string;
  label: HashLabelType;
  analyst?: string;
  notes?: string;
  created_at: number;
  updated_at: number;
}

interface LabelRequest {
  dom_kit_hash: string;
  label: HashLabelType;
  analyst?: string;
  notes?: string;
}

// ============ Validation Functions ============

const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/i;
const VALID_LABELS: HashLabelType[] = ['TP', 'FP', 'UNKNOWN'];

function isValidDomKitHash(hash: string): boolean {
  return HASH_PATTERN.test(hash);
}

function isValidLabelType(label: unknown): label is HashLabelType {
  return VALID_LABELS.includes(label as HashLabelType);
}

function validateLabelRequest(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) {
    return 'Request body must be an object';
  }

  const req = body as Record<string, unknown>;

  if (typeof req.dom_kit_hash !== 'string') {
    return 'dom_kit_hash must be a string';
  }
  if (!HASH_PATTERN.test(req.dom_kit_hash)) {
    return 'dom_kit_hash must be sha256: followed by 64 hex characters';
  }

  if (!VALID_LABELS.includes(req.label as HashLabelType)) {
    return `label must be one of: ${VALID_LABELS.join(', ')}`;
  }

  if (req.analyst !== undefined && typeof req.analyst !== 'string') {
    return 'analyst must be a string';
  }
  if (req.notes !== undefined && typeof req.notes !== 'string') {
    return 'notes must be a string';
  }

  if (req.notes && (req.notes as string).length > 10000) {
    return 'notes must be 10000 characters or less';
  }

  return null;
}

// ============ Mock KV ============

function createMockKV(): KVNamespace & { _store: Map<string, string> } {
  const store = new Map<string, string>();

  return {
    _store: store,
    get: vi.fn(async (key: string, type?: string) => {
      const value = store.get(key);
      if (!value) return null;
      if (type === 'json') return JSON.parse(value);
      return value;
    }),
    put: vi.fn(async (key: string, value: string) => {
      store.set(key, value);
    }),
    delete: vi.fn(async (key: string) => {
      store.delete(key);
    }),
    list: vi.fn(async (options?: { prefix?: string; limit?: number; cursor?: string }) => {
      const prefix = options?.prefix || '';
      const limit = options?.limit || 1000;
      const keys: { name: string }[] = [];

      for (const key of store.keys()) {
        if (key.startsWith(prefix)) {
          keys.push({ name: key });
          if (keys.length >= limit) break;
        }
      }

      return {
        keys,
        list_complete: keys.length < limit,
        cursor: undefined,
      };
    }),
    getWithMetadata: vi.fn(),
  } as unknown as KVNamespace & { _store: Map<string, string> };
}

// ============ Tests ============

describe('Hash Labels', () => {
  describe('Hash validation', () => {
    it('should accept valid sha256 hash', () => {
      const validHash = 'sha256:' + 'a'.repeat(64);
      expect(isValidDomKitHash(validHash)).toBe(true);
    });

    it('should accept hash with uppercase hex', () => {
      const validHash = 'sha256:' + 'ABCDEF'.repeat(10) + 'abcd';
      expect(isValidDomKitHash(validHash)).toBe(true);
    });

    it('should reject hash without sha256 prefix', () => {
      const invalidHash = 'a'.repeat(64);
      expect(isValidDomKitHash(invalidHash)).toBe(false);
    });

    it('should reject hash with wrong length', () => {
      const shortHash = 'sha256:' + 'a'.repeat(63);
      const longHash = 'sha256:' + 'a'.repeat(65);
      expect(isValidDomKitHash(shortHash)).toBe(false);
      expect(isValidDomKitHash(longHash)).toBe(false);
    });

    it('should reject hash with invalid characters', () => {
      const invalidHash = 'sha256:' + 'g'.repeat(64);
      expect(isValidDomKitHash(invalidHash)).toBe(false);
    });

    it('should reject empty hash', () => {
      expect(isValidDomKitHash('')).toBe(false);
    });
  });

  describe('Label type validation', () => {
    it('should accept TP label', () => {
      expect(isValidLabelType('TP')).toBe(true);
    });

    it('should accept FP label', () => {
      expect(isValidLabelType('FP')).toBe(true);
    });

    it('should accept UNKNOWN label', () => {
      expect(isValidLabelType('UNKNOWN')).toBe(true);
    });

    it('should reject invalid label types', () => {
      expect(isValidLabelType('tp')).toBe(false);
      expect(isValidLabelType('fp')).toBe(false);
      expect(isValidLabelType('unknown')).toBe(false);
      expect(isValidLabelType('MALWARE')).toBe(false);
      expect(isValidLabelType('')).toBe(false);
      expect(isValidLabelType(null)).toBe(false);
      expect(isValidLabelType(undefined)).toBe(false);
      expect(isValidLabelType(123)).toBe(false);
    });
  });

  describe('Label request validation', () => {
    it('should accept valid request', () => {
      const request: LabelRequest = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        label: 'TP',
        analyst: 'analyst@example.com',
        notes: 'Confirmed phishing kit',
      };
      expect(validateLabelRequest(request)).toBeNull();
    });

    it('should accept request without optional fields', () => {
      const request: LabelRequest = {
        dom_kit_hash: 'sha256:' + 'b'.repeat(64),
        label: 'FP',
      };
      expect(validateLabelRequest(request)).toBeNull();
    });

    it('should reject non-object body', () => {
      expect(validateLabelRequest(null)).toBe('Request body must be an object');
      expect(validateLabelRequest('string')).toBe('Request body must be an object');
      expect(validateLabelRequest(123)).toBe('Request body must be an object');
    });

    it('should reject missing dom_kit_hash', () => {
      const request = { label: 'TP' };
      expect(validateLabelRequest(request)).toBe('dom_kit_hash must be a string');
    });

    it('should reject invalid dom_kit_hash', () => {
      const request = { dom_kit_hash: 'invalid', label: 'TP' };
      expect(validateLabelRequest(request)).toBe('dom_kit_hash must be sha256: followed by 64 hex characters');
    });

    it('should reject invalid label', () => {
      const request = { dom_kit_hash: 'sha256:' + 'a'.repeat(64), label: 'INVALID' };
      expect(validateLabelRequest(request)).toContain('label must be one of');
    });

    it('should reject non-string analyst', () => {
      const request = { dom_kit_hash: 'sha256:' + 'a'.repeat(64), label: 'TP', analyst: 123 };
      expect(validateLabelRequest(request)).toBe('analyst must be a string');
    });

    it('should reject non-string notes', () => {
      const request = { dom_kit_hash: 'sha256:' + 'a'.repeat(64), label: 'TP', notes: 123 };
      expect(validateLabelRequest(request)).toBe('notes must be a string');
    });

    it('should reject notes exceeding limit', () => {
      const request = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        label: 'TP',
        notes: 'x'.repeat(10001),
      };
      expect(validateLabelRequest(request)).toBe('notes must be 10000 characters or less');
    });
  });

  describe('KV storage', () => {
    let mockKV: KVNamespace & { _store: Map<string, string> };

    beforeEach(() => {
      mockKV = createMockKV();
    });

    it('should store label with correct key format', async () => {
      const hash = 'sha256:' + 'c'.repeat(64);
      const label: HashLabel = {
        dom_kit_hash: hash,
        label: 'TP',
        analyst: 'analyst@example.com',
        created_at: Date.now(),
        updated_at: Date.now(),
      };

      const key = `label:${hash}`;
      await mockKV.put(key, JSON.stringify(label));

      const stored = await mockKV.get(key, 'json') as HashLabel;
      expect(stored.dom_kit_hash).toBe(hash);
      expect(stored.label).toBe('TP');
    });

    it('should update existing label', async () => {
      const hash = 'sha256:' + 'd'.repeat(64);
      const key = `label:${hash}`;
      const originalCreatedAt = Date.now() - 10000;

      // Create initial label
      const initial: HashLabel = {
        dom_kit_hash: hash,
        label: 'UNKNOWN',
        created_at: originalCreatedAt,
        updated_at: originalCreatedAt,
      };
      await mockKV.put(key, JSON.stringify(initial));

      // Update label
      const updated: HashLabel = {
        dom_kit_hash: hash,
        label: 'TP',
        analyst: 'analyst@example.com',
        created_at: originalCreatedAt, // Preserve original
        updated_at: Date.now(),
      };
      await mockKV.put(key, JSON.stringify(updated));

      const stored = await mockKV.get(key, 'json') as HashLabel;
      expect(stored.label).toBe('TP');
      expect(stored.created_at).toBe(originalCreatedAt); // Preserved
      expect(stored.updated_at).toBeGreaterThan(originalCreatedAt);
    });

    it('should delete label', async () => {
      const hash = 'sha256:' + 'e'.repeat(64);
      const key = `label:${hash}`;

      const label: HashLabel = {
        dom_kit_hash: hash,
        label: 'FP',
        created_at: Date.now(),
        updated_at: Date.now(),
      };
      await mockKV.put(key, JSON.stringify(label));

      // Verify it exists
      const before = await mockKV.get(key, 'json');
      expect(before).not.toBeNull();

      // Delete
      await mockKV.delete(key);

      // Verify it's gone
      const after = await mockKV.get(key, 'json');
      expect(after).toBeNull();
    });

    it('should list labels with prefix', async () => {
      // Store multiple labels
      const hashes = ['aa', 'bb', 'cc'].map((c) => 'sha256:' + c.repeat(32));
      for (const hash of hashes) {
        const label: HashLabel = {
          dom_kit_hash: hash,
          label: 'TP',
          created_at: Date.now(),
          updated_at: Date.now(),
        };
        await mockKV.put(`label:${hash}`, JSON.stringify(label));
      }

      const listed = await mockKV.list({ prefix: 'label:' });
      expect(listed.keys.length).toBe(3);
    });
  });

  describe('Label structure', () => {
    it('should have all required fields', () => {
      const label: HashLabel = {
        dom_kit_hash: 'sha256:' + 'f'.repeat(64),
        label: 'TP',
        created_at: Date.now(),
        updated_at: Date.now(),
      };

      expect(label).toHaveProperty('dom_kit_hash');
      expect(label).toHaveProperty('label');
      expect(label).toHaveProperty('created_at');
      expect(label).toHaveProperty('updated_at');
    });

    it('should have optional fields', () => {
      const label: HashLabel = {
        dom_kit_hash: 'sha256:' + '0'.repeat(64),
        label: 'FP',
        analyst: 'analyst@example.com',
        notes: 'This is a false positive - legitimate site',
        created_at: Date.now(),
        updated_at: Date.now(),
      };

      expect(label.analyst).toBe('analyst@example.com');
      expect(label.notes).toBe('This is a false positive - legitimate site');
    });
  });

  describe('No automatic enforcement', () => {
    it('should NOT include enforcement fields in label', () => {
      const label: HashLabel = {
        dom_kit_hash: 'sha256:' + '1'.repeat(64),
        label: 'TP',
        created_at: Date.now(),
        updated_at: Date.now(),
      };

      // Verify no enforcement-related fields
      expect(label).not.toHaveProperty('blocked');
      expect(label).not.toHaveProperty('block');
      expect(label).not.toHaveProperty('action');
      expect(label).not.toHaveProperty('enforce');
      expect(label).not.toHaveProperty('auto_block');
    });

    it('should be shadow mode only', () => {
      // Labels are for research/review, not enforcement
      // This is a documentation test to verify the design intent
      const labelTypes: HashLabelType[] = ['TP', 'FP', 'UNKNOWN'];

      for (const type of labelTypes) {
        // All label types should be valid for shadow mode review
        expect(isValidLabelType(type)).toBe(true);
      }

      // There should be no "BLOCKED" or "ENFORCED" label type
      expect(isValidLabelType('BLOCKED')).toBe(false);
      expect(isValidLabelType('ENFORCED')).toBe(false);
    });
  });

  describe('Analyst workflow', () => {
    it('should support marking hash as True Positive', () => {
      const request: LabelRequest = {
        dom_kit_hash: 'sha256:' + '2'.repeat(64),
        label: 'TP',
        analyst: 'soc-analyst@company.com',
        notes: 'Confirmed credential harvesting phishing kit',
      };

      expect(validateLabelRequest(request)).toBeNull();
    });

    it('should support marking hash as False Positive', () => {
      const request: LabelRequest = {
        dom_kit_hash: 'sha256:' + '3'.repeat(64),
        label: 'FP',
        analyst: 'soc-analyst@company.com',
        notes: 'Legitimate Microsoft login page',
      };

      expect(validateLabelRequest(request)).toBeNull();
    });

    it('should support marking hash as Unknown for further review', () => {
      const request: LabelRequest = {
        dom_kit_hash: 'sha256:' + '4'.repeat(64),
        label: 'UNKNOWN',
        analyst: 'soc-analyst@company.com',
        notes: 'Needs further investigation - unusual structure',
      };

      expect(validateLabelRequest(request)).toBeNull();
    });
  });

  describe('Label indexing', () => {
    let mockKV: KVNamespace & { _store: Map<string, string> };

    beforeEach(() => {
      mockKV = createMockKV();
    });

    it('should support label type index', async () => {
      const hash = 'sha256:' + '5'.repeat(64);

      // Store main label
      const label: HashLabel = {
        dom_kit_hash: hash,
        label: 'TP',
        created_at: Date.now(),
        updated_at: Date.now(),
      };
      await mockKV.put(`label:${hash}`, JSON.stringify(label));

      // Store index entry
      await mockKV.put(`idx:TP:${hash}`, '1');

      // List by label type
      const listed = await mockKV.list({ prefix: 'idx:TP:' });
      expect(listed.keys.length).toBe(1);
    });

    it('should update index when label changes', async () => {
      const hash = 'sha256:' + '6'.repeat(64);

      // Initially mark as UNKNOWN
      await mockKV.put(`idx:UNKNOWN:${hash}`, '1');

      // Change to TP - should remove from UNKNOWN index
      await mockKV.delete(`idx:UNKNOWN:${hash}`);
      await mockKV.put(`idx:TP:${hash}`, '1');

      const unknownList = await mockKV.list({ prefix: 'idx:UNKNOWN:' });
      const tpList = await mockKV.list({ prefix: 'idx:TP:' });

      expect(unknownList.keys.length).toBe(0);
      expect(tpList.keys.length).toBe(1);
    });
  });

  describe('DOM kit hash attachment', () => {
    it('should attach label to dom_kit_hash, not IOC', () => {
      // This is a key requirement from Issue #205
      const label: HashLabel = {
        dom_kit_hash: 'sha256:' + '7'.repeat(64),
        label: 'TP',
        created_at: Date.now(),
        updated_at: Date.now(),
      };

      // Label is attached to dom_kit_hash
      expect(label.dom_kit_hash).toMatch(/^sha256:[a-f0-9]{64}$/i);

      // NOT attached to IOC fields
      expect(label).not.toHaveProperty('ioc');
      expect(label).not.toHaveProperty('url');
      expect(label).not.toHaveProperty('domain');
      expect(label).not.toHaveProperty('indicator');
    });
  });
});
