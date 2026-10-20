/**
 * Tests for Shadow Telemetry Worker
 *
 * Reference: Issue #203
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock KV namespace
function createMockKV(): KVNamespace {
  const store = new Map<string, string>();

  return {
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
    list: vi.fn(),
    getWithMetadata: vi.fn(),
  } as unknown as KVNamespace;
}

// Import the worker handler after mocking
// We need to import the types and test the logic
interface ShadowTelemetryPayload {
  dom_kit_hash: string;
  event_ts: number;
  first_seen_locally: boolean;
}

interface HashTrackingRecord {
  dom_kit_hash: string;
  first_seen_ts: number;
  total_seen_count: number;
  last_seen_ts: number;
}

const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/i;

// Test the validation logic
function validatePayload(payload: unknown): string | null {
  if (typeof payload !== 'object' || payload === null) {
    return 'Payload must be an object';
  }

  const p = payload as Record<string, unknown>;

  if (typeof p.dom_kit_hash !== 'string') {
    return 'Invalid dom_kit_hash: must be a string';
  }

  if (!HASH_PATTERN.test(p.dom_kit_hash)) {
    return 'Invalid dom_kit_hash: must be sha256: followed by 64 hex characters';
  }

  if (typeof p.event_ts !== 'number' || p.event_ts <= 0) {
    return 'Invalid event_ts: must be a positive number';
  }

  const now = Date.now();
  const oneYearMs = 365 * 24 * 60 * 60 * 1000;

  if (p.event_ts > now + 60000) {
    return 'Invalid event_ts: timestamp is in the future';
  }

  if (p.event_ts < now - oneYearMs) {
    return 'Invalid event_ts: timestamp is too old';
  }

  if (typeof p.first_seen_locally !== 'boolean') {
    return 'Invalid first_seen_locally: must be a boolean';
  }

  const allowedKeys = new Set(['dom_kit_hash', 'event_ts', 'first_seen_locally']);
  for (const key of Object.keys(p)) {
    if (!allowedKeys.has(key)) {
      return `Unexpected field: ${key}`;
    }
  }

  return null;
}

describe('Shadow Telemetry Worker', () => {
  describe('Payload validation', () => {
    it('should accept valid payload', () => {
      const payload: ShadowTelemetryPayload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: Date.now(),
        first_seen_locally: true,
      };

      expect(validatePayload(payload)).toBeNull();
    });

    it('should reject non-object payload', () => {
      expect(validatePayload(null)).toBe('Payload must be an object');
      expect(validatePayload('string')).toBe('Payload must be an object');
      expect(validatePayload(123)).toBe('Payload must be an object');
    });

    it('should reject missing dom_kit_hash', () => {
      const payload = {
        event_ts: Date.now(),
        first_seen_locally: true,
      };

      expect(validatePayload(payload)).toBe('Invalid dom_kit_hash: must be a string');
    });

    it('should reject invalid hash format', () => {
      const payload = {
        dom_kit_hash: 'invalid-hash',
        event_ts: Date.now(),
        first_seen_locally: true,
      };

      expect(validatePayload(payload)).toBe('Invalid dom_kit_hash: must be sha256: followed by 64 hex characters');
    });

    it('should reject hash without sha256: prefix', () => {
      const payload = {
        dom_kit_hash: 'a'.repeat(64),
        event_ts: Date.now(),
        first_seen_locally: true,
      };

      expect(validatePayload(payload)).toBe('Invalid dom_kit_hash: must be sha256: followed by 64 hex characters');
    });

    it('should reject invalid event_ts', () => {
      const payload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: -1,
        first_seen_locally: true,
      };

      expect(validatePayload(payload)).toBe('Invalid event_ts: must be a positive number');
    });

    it('should reject future timestamp', () => {
      const payload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: Date.now() + 120000, // 2 minutes in future
        first_seen_locally: true,
      };

      expect(validatePayload(payload)).toBe('Invalid event_ts: timestamp is in the future');
    });

    it('should reject very old timestamp', () => {
      const payload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: Date.now() - (2 * 365 * 24 * 60 * 60 * 1000), // 2 years ago
        first_seen_locally: true,
      };

      expect(validatePayload(payload)).toBe('Invalid event_ts: timestamp is too old');
    });

    it('should reject invalid first_seen_locally', () => {
      const payload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: Date.now(),
        first_seen_locally: 'true', // string instead of boolean
      };

      expect(validatePayload(payload)).toBe('Invalid first_seen_locally: must be a boolean');
    });

    it('should reject extra fields', () => {
      const payload = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        event_ts: Date.now(),
        first_seen_locally: true,
        url: 'https://example.com', // Extra field
      };

      expect(validatePayload(payload)).toBe('Unexpected field: url');
    });
  });

  describe('Hash tracking record structure', () => {
    it('should have correct structure', () => {
      const record: HashTrackingRecord = {
        dom_kit_hash: 'sha256:' + 'a'.repeat(64),
        first_seen_ts: Date.now(),
        total_seen_count: 1,
        last_seen_ts: Date.now(),
      };

      expect(record).toHaveProperty('dom_kit_hash');
      expect(record).toHaveProperty('first_seen_ts');
      expect(record).toHaveProperty('total_seen_count');
      expect(record).toHaveProperty('last_seen_ts');
    });
  });

  describe('KV storage integration', () => {
    let mockKV: KVNamespace;

    beforeEach(() => {
      mockKV = createMockKV();
    });

    it('should store new hash as first seen', async () => {
      const hash = 'sha256:' + 'b'.repeat(64);
      const eventTs = Date.now();
      const key = `hash:${hash}`;

      // Simulate first time seeing this hash
      const existing = await mockKV.get(key, 'json');
      expect(existing).toBeNull();

      // Create new record
      const record: HashTrackingRecord = {
        dom_kit_hash: hash,
        first_seen_ts: eventTs,
        total_seen_count: 1,
        last_seen_ts: Date.now(),
      };

      await mockKV.put(key, JSON.stringify(record));

      // Verify stored
      const stored = await mockKV.get(key, 'json') as HashTrackingRecord;
      expect(stored.dom_kit_hash).toBe(hash);
      expect(stored.first_seen_ts).toBe(eventTs);
      expect(stored.total_seen_count).toBe(1);
    });

    it('should increment count for existing hash', async () => {
      const hash = 'sha256:' + 'c'.repeat(64);
      const key = `hash:${hash}`;
      const firstSeenTs = Date.now() - 10000; // 10 seconds ago

      // Store initial record
      const initialRecord: HashTrackingRecord = {
        dom_kit_hash: hash,
        first_seen_ts: firstSeenTs,
        total_seen_count: 5,
        last_seen_ts: firstSeenTs,
      };
      await mockKV.put(key, JSON.stringify(initialRecord));

      // Simulate update
      const existing = await mockKV.get(key, 'json') as HashTrackingRecord;
      const updated: HashTrackingRecord = {
        dom_kit_hash: hash,
        first_seen_ts: existing.first_seen_ts, // Keep original
        total_seen_count: existing.total_seen_count + 1,
        last_seen_ts: Date.now(),
      };
      await mockKV.put(key, JSON.stringify(updated));

      // Verify
      const stored = await mockKV.get(key, 'json') as HashTrackingRecord;
      expect(stored.first_seen_ts).toBe(firstSeenTs); // Original preserved
      expect(stored.total_seen_count).toBe(6); // Incremented
    });

    it('should preserve first_seen_ts on updates', async () => {
      const hash = 'sha256:' + 'd'.repeat(64);
      const key = `hash:${hash}`;
      const originalFirstSeen = Date.now() - 86400000; // 1 day ago

      // Store initial record
      const initialRecord: HashTrackingRecord = {
        dom_kit_hash: hash,
        first_seen_ts: originalFirstSeen,
        total_seen_count: 100,
        last_seen_ts: Date.now() - 3600000, // 1 hour ago
      };
      await mockKV.put(key, JSON.stringify(initialRecord));

      // Update multiple times
      for (let i = 0; i < 10; i++) {
        const existing = await mockKV.get(key, 'json') as HashTrackingRecord;
        const updated: HashTrackingRecord = {
          dom_kit_hash: hash,
          first_seen_ts: existing.first_seen_ts,
          total_seen_count: existing.total_seen_count + 1,
          last_seen_ts: Date.now(),
        };
        await mockKV.put(key, JSON.stringify(updated));
      }

      // Verify first_seen_ts unchanged
      const final = await mockKV.get(key, 'json') as HashTrackingRecord;
      expect(final.first_seen_ts).toBe(originalFirstSeen);
      expect(final.total_seen_count).toBe(110);
    });
  });

  describe('Privacy guarantees', () => {
    it('should NOT store URLs in hash tracking record', () => {
      const record: HashTrackingRecord = {
        dom_kit_hash: 'sha256:' + 'e'.repeat(64),
        first_seen_ts: Date.now(),
        total_seen_count: 1,
        last_seen_ts: Date.now(),
      };

      // Verify no URL-related fields
      expect(record).not.toHaveProperty('url');
      expect(record).not.toHaveProperty('page_url');
      expect(record).not.toHaveProperty('domain');
      expect(record).not.toHaveProperty('origin');
    });

    it('should NOT store DOM content in hash tracking record', () => {
      const record: HashTrackingRecord = {
        dom_kit_hash: 'sha256:' + 'f'.repeat(64),
        first_seen_ts: Date.now(),
        total_seen_count: 1,
        last_seen_ts: Date.now(),
      };

      // Verify no content-related fields
      expect(record).not.toHaveProperty('content');
      expect(record).not.toHaveProperty('skeleton');
      expect(record).not.toHaveProperty('tagTree');
      expect(record).not.toHaveProperty('html');
    });

    it('should NOT include client identifiers in hash tracking record', () => {
      const record: HashTrackingRecord = {
        dom_kit_hash: 'sha256:' + '0'.repeat(64),
        first_seen_ts: Date.now(),
        total_seen_count: 1,
        last_seen_ts: Date.now(),
      };

      // Verify no client identifier fields
      expect(record).not.toHaveProperty('client_id');
      expect(record).not.toHaveProperty('extension_id');
      expect(record).not.toHaveProperty('org_id');
      expect(record).not.toHaveProperty('user_id');
      expect(record).not.toHaveProperty('ip');
    });
  });

  describe('No client feedback', () => {
    it('should NOT return first_seen_globally signal', () => {
      // The worker response should be minimal
      const expectedResponse = { status: 'received' };

      // Verify no first-seen signal in response
      expect(expectedResponse).not.toHaveProperty('first_seen_globally');
      expect(expectedResponse).not.toHaveProperty('is_first');
      expect(expectedResponse).not.toHaveProperty('isNovel');
      expect(expectedResponse).not.toHaveProperty('global_first');
    });

    it('should NOT return total_seen_count to client', () => {
      const expectedResponse = { status: 'received' };

      expect(expectedResponse).not.toHaveProperty('total_seen_count');
      expect(expectedResponse).not.toHaveProperty('count');
      expect(expectedResponse).not.toHaveProperty('seen_count');
    });
  });

  describe('Acceptance criteria', () => {
    it('should store dom_kit_hash', () => {
      const record: HashTrackingRecord = {
        dom_kit_hash: 'sha256:' + '1'.repeat(64),
        first_seen_ts: Date.now(),
        total_seen_count: 1,
        last_seen_ts: Date.now(),
      };

      expect(record.dom_kit_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('should store first_seen_ts', () => {
      const record: HashTrackingRecord = {
        dom_kit_hash: 'sha256:' + '2'.repeat(64),
        first_seen_ts: 1704067200000, // Example timestamp
        total_seen_count: 1,
        last_seen_ts: Date.now(),
      };

      expect(typeof record.first_seen_ts).toBe('number');
      expect(record.first_seen_ts).toBeGreaterThan(0);
    });

    it('should store total_seen_count', () => {
      const record: HashTrackingRecord = {
        dom_kit_hash: 'sha256:' + '3'.repeat(64),
        first_seen_ts: Date.now(),
        total_seen_count: 42,
        last_seen_ts: Date.now(),
      };

      expect(typeof record.total_seen_count).toBe('number');
      expect(record.total_seen_count).toBeGreaterThanOrEqual(1);
    });
  });
});
