import { describe, it, expect, beforeAll, beforeEach, vi, afterEach } from 'vitest';
import { BinaryHashSet, hexToBytes } from '../src/storage/binary-set';
import { arrayBufferToBase64 } from '../src/crypto/signing';
import { sha256 } from '../src/crypto/hashing';

// Mock reloadBlocklist to verify it's called after updates
vi.mock('../src/background/blocking', () => ({
  reloadBlocklist: vi.fn().mockResolvedValue(undefined),
}));

// Import after mock is set up
import {
  fetchBlocklistUpdate,
  getUpdateMetadata,
  BlocklistManifest,
  UpdateConfig,
} from '../src/background/updates';
import { reloadBlocklist } from '../src/background/blocking';

// Mock chrome APIs
const mockStorage: Record<string, unknown> = {};
const mockAlarms: Record<string, chrome.alarms.Alarm> = {};

vi.stubGlobal('chrome', {
  storage: {
    local: {
      get: vi.fn(async (keys: string | string[]) => {
        if (typeof keys === 'string') {
          return { [keys]: mockStorage[keys] };
        }
        const result: Record<string, unknown> = {};
        for (const key of keys) {
          result[key] = mockStorage[key];
        }
        return result;
      }),
      set: vi.fn(async (items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
      }),
      remove: vi.fn(async (keys: string | string[]) => {
        const keyList = typeof keys === 'string' ? [keys] : keys;
        for (const key of keyList) {
          delete mockStorage[key];
        }
      }),
    },
  },
  alarms: {
    create: vi.fn(async (name: string, info: chrome.alarms.AlarmCreateInfo) => {
      mockAlarms[name] = {
        name,
        scheduledTime: Date.now() + (info.delayInMinutes || 0) * 60000,
        periodInMinutes: info.periodInMinutes,
      };
    }),
    clear: vi.fn(async (name: string) => {
      delete mockAlarms[name];
      return true;
    }),
  },
});

// Test key generation helpers
async function generateTestKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

async function signData(privateKey: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
  return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);
}

/**
 * Create a signed manifest matching CLI format.
 * Signs: {bucket_count, sha256_root, total_iocs, version} (sorted keys)
 */
async function createSignedManifest(
  manifest: Omit<BlocklistManifest, 'signature'>,
  privateKey: CryptoKey
): Promise<BlocklistManifest> {
  // Build signed payload (sorted keys, matching CLI format)
  const signedFields = {
    bucket_count: manifest.bucket_count,
    sha256_root: manifest.sha256_root,
    total_iocs: manifest.total_iocs,
    version: manifest.version,
  };

  const canonicalJson = JSON.stringify(signedFields, Object.keys(signedFields).sort());
  const data = new TextEncoder().encode(canonicalJson);
  const signature = await signData(privateKey, data);

  return {
    ...manifest,
    signature: arrayBufferToBase64(signature),
  };
}

/**
 * Create test blocklist data (base64 encoded binary hashes).
 */
function createBlocklistData(hexHashes: string[]): string {
  const set = BinaryHashSet.fromHexStrings(hexHashes);
  return set.serialize();
}

/**
 * Compute SHA-256 hash of blocklist data.
 */
async function computeBlocklistHash(base64Data: string): Promise<string> {
  const binary = atob(base64Data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return sha256(bytes);
}

describe('Blocklist Update Client', () => {
  let testKeyPair: CryptoKeyPair;
  let publicKeyJwk: JsonWebKey;

  beforeAll(async () => {
    testKeyPair = await generateTestKeyPair();
    publicKeyJwk = await crypto.subtle.exportKey('jwk', testKeyPair.publicKey);
  });

  beforeEach(() => {
    // Clear mock storage
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    vi.clearAllMocks();
    vi.mocked(reloadBlocklist).mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('fetchBlocklistUpdate', () => {
    it('should apply a full update with valid signature', async () => {
      // Create blocklist data
      const hashes = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      ];
      const blocklistData = createBlocklistData(hashes);
      const sha256Root = await computeBlocklistHash(blocklistData);

      const manifest = await createSignedManifest(
        {
          version: 1,
          total_iocs: hashes.length,
          bucket_count: 1,
          sha256_root: sha256Root,
          created_at: '2026-01-09T00:00:00Z',
        },
        testKeyPair.privateKey
      );

      // Mock fetch: first call for manifest, second for blocklist
      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => manifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistData,
        });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.version).toBe(1);
        expect(result.hashCount).toBe(2);
        expect(result.type).toBe('full');
      }

      // Verify storage was updated
      expect(mockStorage['browserdefense_blocklist']).toBeDefined();
      expect(mockStorage['browserdefense_update_meta']).toBeDefined();
    });

    it('should reload in-memory blocklist after successful update', async () => {
      // Create blocklist data
      const hashes = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ];
      const blocklistData = createBlocklistData(hashes);
      const sha256Root = await computeBlocklistHash(blocklistData);

      const manifest = await createSignedManifest(
        {
          version: 1,
          total_iocs: hashes.length,
          bucket_count: 1,
          sha256_root: sha256Root,
          created_at: '2026-01-09T00:00:00Z',
        },
        testKeyPair.privateKey
      );

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => manifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistData,
        });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(true);
      // Critical: reloadBlocklist must be called after successful update
      // This ensures new IOCs take effect immediately (Issue #260)
      expect(reloadBlocklist).toHaveBeenCalledTimes(1);
    });

    it('should not reload blocklist when update is unchanged', async () => {
      // Set up existing metadata with version 5
      mockStorage['browserdefense_update_meta'] = {
        version: 5,
        timestamp: '2026-01-08T00:00:00Z',
        updatedAt: Date.now(),
        hashCount: 100,
      };

      const hashes = ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'];
      const blocklistData = createBlocklistData(hashes);
      const sha256Root = await computeBlocklistHash(blocklistData);

      // Try to apply same version
      const manifest = await createSignedManifest(
        {
          version: 5,
          total_iocs: 1,
          bucket_count: 1,
          sha256_root: sha256Root,
        },
        testKeyPair.privateKey
      );

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => manifest,
      });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.type).toBe('unchanged');
      }
      // Should NOT reload blocklist when no update was applied
      expect(reloadBlocklist).not.toHaveBeenCalled();
    });

    it('should not reload blocklist on update failure', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
        maxRetries: 1,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(false);
      // Should NOT reload blocklist on failure
      expect(reloadBlocklist).not.toHaveBeenCalled();
    });

    it('should reject invalid signature', async () => {
      const hashes = ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'];
      const blocklistData = createBlocklistData(hashes);
      const sha256Root = await computeBlocklistHash(blocklistData);

      const manifest: BlocklistManifest = {
        version: 1,
        total_iocs: 1,
        bucket_count: 1,
        sha256_root: sha256Root,
        signature: 'invalid-signature-not-real',
      };

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => manifest,
      });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe('INVALID_SIGNATURE');
      }
    });

    it('should reject integrity check failure', async () => {
      // Create blocklist data with different hash than manifest claims
      const hashes = ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'];
      const blocklistData = createBlocklistData(hashes);

      // Use wrong sha256_root
      const wrongRoot = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

      const manifest = await createSignedManifest(
        {
          version: 1,
          total_iocs: 1,
          bucket_count: 1,
          sha256_root: wrongRoot,  // Wrong hash!
        },
        testKeyPair.privateKey
      );

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => manifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistData,
        });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe('INTEGRITY_ERROR');
      }
    });

    it('should reject old version updates', async () => {
      // Set up existing metadata with version 5
      mockStorage['browserdefense_update_meta'] = {
        version: 5,
        timestamp: '2026-01-08T00:00:00Z',
        updatedAt: Date.now(),
        hashCount: 100,
      };

      const hashes = ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'];
      const blocklistData = createBlocklistData(hashes);
      const sha256Root = await computeBlocklistHash(blocklistData);

      // Try to apply version 3
      const manifest = await createSignedManifest(
        {
          version: 3,  // Old version
          total_iocs: 1,
          bucket_count: 1,
          sha256_root: sha256Root,
        },
        testKeyPair.privateKey
      );

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => manifest,
      });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.type).toBe('unchanged');
        expect(result.version).toBe(5); // Should report current version
      }
    });

    it('should retry on network errors with exponential backoff', async () => {
      const hashes = ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'];
      const blocklistData = createBlocklistData(hashes);
      const sha256Root = await computeBlocklistHash(blocklistData);

      const manifest = await createSignedManifest(
        {
          version: 1,
          total_iocs: 1,
          bucket_count: 1,
          sha256_root: sha256Root,
        },
        testKeyPair.privateKey
      );

      // Fail twice for manifest, then succeed with manifest and blocklist
      global.fetch = vi
        .fn()
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          json: async () => manifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistData,
        });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
        maxRetries: 3,
        baseDelayMs: 10, // Speed up tests
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(true);
      expect(global.fetch).toHaveBeenCalledTimes(4); // 2 failures + 1 manifest + 1 blocklist
    });

    it('should fail after max retries and keep old blocklist', async () => {
      // Set up existing blocklist
      const existingSet = BinaryHashSet.fromHexStrings([
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ]);
      const existingData = existingSet.serialize();
      mockStorage['browserdefense_blocklist'] = existingData;

      // All retries fail
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
        maxRetries: 3,
        baseDelayMs: 10,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe('NETWORK_ERROR');
      }

      // Blocklist should be unchanged (stale-protect)
      expect(mockStorage['browserdefense_blocklist']).toBe(existingData);
    });

    it('should not retry on signature errors', async () => {
      const manifest: BlocklistManifest = {
        version: 1,
        total_iocs: 1,
        bucket_count: 1,
        sha256_root: 'test',
        signature: 'invalid',
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => manifest,
      });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
        maxRetries: 3,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(false);
      // Should only try once for signature errors
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('should handle HTTP errors', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
        maxRetries: 1,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe('NETWORK_ERROR');
      }
    });

    it('should handle invalid manifest format', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          version: 'not-a-number', // Invalid
          total_iocs: 1,
          bucket_count: 1,
          sha256_root: 'test',
          signature: 'test',
        }),
      });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        publicKey: publicKeyJwk,
        maxRetries: 1,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe('PARSE_ERROR');
      }
    });

    it('should use custom blocklistEndpoint if provided', async () => {
      const hashes = ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'];
      const blocklistData = createBlocklistData(hashes);
      const sha256Root = await computeBlocklistHash(blocklistData);

      const manifest = await createSignedManifest(
        {
          version: 1,
          total_iocs: 1,
          bucket_count: 1,
          sha256_root: sha256Root,
        },
        testKeyPair.privateKey
      );

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => manifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistData,
        });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/manifest.json',
        blocklistEndpoint: 'https://cdn.example.com/blocklist.b64', // Custom endpoint
        publicKey: publicKeyJwk,
      };

      await fetchBlocklistUpdate(config);

      // Verify the custom blocklist endpoint was used
      expect(global.fetch).toHaveBeenCalledTimes(2);
      expect(global.fetch).toHaveBeenCalledWith(
        'https://cdn.example.com/blocklist.b64',
        expect.any(Object)
      );
    });
  });

  describe('delta updates', () => {
    it('should apply delta update when available', async () => {
      // Set up existing blocklist with 2 hashes
      const existingHashes = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      ];
      const existingSet = BinaryHashSet.fromHexStrings(existingHashes);
      const existingData = existingSet.serialize();
      mockStorage['browserdefense_blocklist'] = existingData;

      // Set up metadata
      mockStorage['browserdefense_update_meta'] = {
        version: 1,
        timestamp: '2026-01-08T00:00:00Z',
        updatedAt: Date.now(),
        hashCount: 2,
      };

      // New blocklist: remove one hash, add one hash
      const newHashes = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
      ];
      const newSet = BinaryHashSet.fromHexStrings(newHashes);
      const newData = newSet.serialize();
      const sha256Root = await computeBlocklistHash(newData);

      // Create delta binary: 1 added, 1 removed
      const addedHash = hexToBytes('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
      const removedHash = hexToBytes('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
      const deltaBuffer = new ArrayBuffer(8 + 64);
      const deltaView = new DataView(deltaBuffer);
      const deltaBytes = new Uint8Array(deltaBuffer);
      deltaView.setUint32(0, 1, true); // 1 added
      deltaView.setUint32(4, 1, true); // 1 removed
      deltaBytes.set(addedHash, 8);
      deltaBytes.set(removedHash, 40);

      const manifest = await createSignedManifest(
        {
          version: 2,
          total_iocs: 2,
          bucket_count: 1,
          sha256_root: sha256Root,
          created_at: '2026-01-09T00:00:00Z',
        },
        testKeyPair.privateKey
      );

      // Add snapshot_url and deltas to manifest
      const manifestWithDeltas = {
        ...manifest,
        snapshot_url: 'snapshots/2.b64',
        deltas: [{ from: 1, to: 2, url: 'deltas/1-2.bin', size: 72 }],
      };

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => manifestWithDeltas,
        })
        .mockResolvedValueOnce({
          ok: true,
          arrayBuffer: async () => deltaBuffer,
        });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/org1',
        publicKey: publicKeyJwk,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.type).toBe('delta');
        expect(result.version).toBe(2);
        expect(result.hashCount).toBe(2);
      }

      expect(reloadBlocklist).toHaveBeenCalledTimes(1);
    });

    it('should fall back to snapshot when delta fails', async () => {
      // Set up existing blocklist
      const existingHashes = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ];
      const existingSet = BinaryHashSet.fromHexStrings(existingHashes);
      mockStorage['browserdefense_blocklist'] = existingSet.serialize();
      mockStorage['browserdefense_update_meta'] = {
        version: 1,
        timestamp: '2026-01-08T00:00:00Z',
        updatedAt: Date.now(),
        hashCount: 1,
      };

      // New blocklist
      const newHashes = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      ];
      const newSet = BinaryHashSet.fromHexStrings(newHashes);
      const newData = newSet.serialize();
      const sha256Root = await computeBlocklistHash(newData);

      const manifest = await createSignedManifest(
        {
          version: 2,
          total_iocs: 2,
          bucket_count: 1,
          sha256_root: sha256Root,
          created_at: '2026-01-09T00:00:00Z',
        },
        testKeyPair.privateKey
      );

      const manifestWithDeltas = {
        ...manifest,
        snapshot_url: 'snapshots/2.b64',
        deltas: [{ from: 1, to: 2, url: 'deltas/1-2.bin', size: 72 }],
      };

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => manifestWithDeltas,
        })
        .mockResolvedValueOnce({
          // Delta fetch fails
          ok: false,
          status: 404,
        })
        .mockResolvedValueOnce({
          // Falls back to snapshot
          ok: true,
          text: async () => newData,
        });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/org1',
        publicKey: publicKeyJwk,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.type).toBe('full');
        expect(result.hashCount).toBe(2);
      }
    });

    it('should skip delta if size exceeds maxDeltaSize', async () => {
      mockStorage['browserdefense_update_meta'] = {
        version: 1,
        timestamp: '2026-01-08T00:00:00Z',
        updatedAt: Date.now(),
        hashCount: 1,
      };

      const newHashes = ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'];
      const newSet = BinaryHashSet.fromHexStrings(newHashes);
      const newData = newSet.serialize();
      const sha256Root = await computeBlocklistHash(newData);

      const manifest = await createSignedManifest(
        {
          version: 2,
          total_iocs: 1,
          bucket_count: 1,
          sha256_root: sha256Root,
        },
        testKeyPair.privateKey
      );

      const manifestWithDeltas = {
        ...manifest,
        snapshot_url: 'snapshots/2.b64',
        deltas: [{ from: 1, to: 2, url: 'deltas/1-2.bin', size: 10000000 }], // 10MB - too big
      };

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => manifestWithDeltas,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => newData,
        });

      const config: UpdateConfig = {
        endpoint: 'https://example.com/org1',
        publicKey: publicKeyJwk,
        maxDeltaSize: 1000, // Only allow 1KB deltas
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(true);
      if (result.success) {
        // Should use full snapshot, not delta
        expect(result.type).toBe('full');
      }

      // Should have fetched manifest and snapshot (not delta)
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    it('should use snapshot_url from manifest', async () => {
      const hashes = ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'];
      const blocklistData = createBlocklistData(hashes);
      const sha256Root = await computeBlocklistHash(blocklistData);

      const manifest = await createSignedManifest(
        {
          version: 1,
          total_iocs: 1,
          bucket_count: 1,
          sha256_root: sha256Root,
        },
        testKeyPair.privateKey
      );

      const manifestWithSnapshot = {
        ...manifest,
        snapshot_url: 'snapshots/1.b64',
        deltas: [],
      };

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => manifestWithSnapshot,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistData,
        });

      const config: UpdateConfig = {
        endpoint: 'https://cdn.example.com/org1/', // Trailing slash indicates directory
        publicKey: publicKeyJwk,
      };

      await fetchBlocklistUpdate(config);

      // Should fetch from snapshot_url relative to endpoint
      expect(global.fetch).toHaveBeenCalledWith(
        'https://cdn.example.com/org1/snapshots/1.b64',
        expect.any(Object)
      );
    });
  });

  describe('getUpdateMetadata', () => {
    it('should return null when no metadata exists', async () => {
      const meta = await getUpdateMetadata();
      expect(meta).toBeNull();
    });

    it('should return stored metadata', async () => {
      const expected = {
        version: 42,
        timestamp: '2026-01-09T00:00:00Z',
        updatedAt: Date.now(),
        hashCount: 1000,
      };
      mockStorage['browserdefense_update_meta'] = expected;

      const meta = await getUpdateMetadata();
      expect(meta).toEqual(expected);
    });
  });

  describe('BinaryHashSet.delete', () => {
    it('should delete an existing hash', () => {
      const set = BinaryHashSet.fromHexStrings([
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
      ]);

      expect(set.count).toBe(3);

      const hashToDelete = hexToBytes(
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
      );
      const deleted = set.delete(hashToDelete);

      expect(deleted).toBe(true);
      expect(set.count).toBe(2);
      expect(set.has(hashToDelete)).toBe(false);
    });

    it('should return false when hash does not exist', () => {
      const set = BinaryHashSet.fromHexStrings([
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ]);

      const nonExistent = hexToBytes(
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
      );
      const deleted = set.delete(nonExistent);

      expect(deleted).toBe(false);
      expect(set.count).toBe(1);
    });

    it('should handle deleting the first hash', () => {
      const hashes = [
        '0000000000000000000000000000000000000000000000000000000000000001',
        '0000000000000000000000000000000000000000000000000000000000000002',
        '0000000000000000000000000000000000000000000000000000000000000003',
      ];
      const set = BinaryHashSet.fromHexStrings(hashes);

      const deleted = set.delete(hexToBytes(hashes[0]));

      expect(deleted).toBe(true);
      expect(set.count).toBe(2);
      expect(set.has(hexToBytes(hashes[0]))).toBe(false);
      expect(set.has(hexToBytes(hashes[1]))).toBe(true);
      expect(set.has(hexToBytes(hashes[2]))).toBe(true);
    });

    it('should handle deleting the last hash', () => {
      const hashes = [
        '0000000000000000000000000000000000000000000000000000000000000001',
        '0000000000000000000000000000000000000000000000000000000000000002',
        '0000000000000000000000000000000000000000000000000000000000000003',
      ];
      const set = BinaryHashSet.fromHexStrings(hashes);

      const deleted = set.delete(hexToBytes(hashes[2]));

      expect(deleted).toBe(true);
      expect(set.count).toBe(2);
      expect(set.has(hexToBytes(hashes[0]))).toBe(true);
      expect(set.has(hexToBytes(hashes[1]))).toBe(true);
      expect(set.has(hexToBytes(hashes[2]))).toBe(false);
    });

    it('should handle deleting from single-element set', () => {
      const set = BinaryHashSet.fromHexStrings([
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ]);

      const deleted = set.delete(
        hexToBytes('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
      );

      expect(deleted).toBe(true);
      expect(set.count).toBe(0);
    });

    it('should return false for wrong-sized hash', () => {
      const set = BinaryHashSet.fromHexStrings([
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ]);

      const wrongSize = new Uint8Array(16); // Should be 32
      const deleted = set.delete(wrongSize);

      expect(deleted).toBe(false);
    });
  });
});
