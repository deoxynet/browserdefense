/**
 * Integration Test: CLI Manifest Update Pipeline
 *
 * Issue #225: Tests the end-to-end flow where CLI-generated `manifest.json`
 * and `blocklist.b64` are served and consumed by the production update path.
 *
 * This test catches:
 * - Field mismatches between CLI output and extension expectations
 * - Signing/integrity regressions
 * - Canonicalization mismatches that would cause silent blocking failures
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// CLI crypto functions (use directly instead of spawning CLI process)
import {
  generateSigningKeypair,
  generateSalt,
  hashIOCBytes,
  signManifest,
  sha256,
  binaryToBase64,
  type SigningPublicKeyJWK,
  type SigningPrivateKeyJWK,
  type BlocklistManifest,
} from '../../cli/src/crypto';

// Extension update functions
import {
  fetchBlocklistUpdate,
  getUpdateMetadata,
  type UpdateConfig,
} from '../../src/background/updates';

// Extension blocking functions
import { BinaryHashSet } from '../../src/storage/binary-set';
import { loadBlocklistFromIDB, closeDB } from '../../src/storage/idb';

// Mock storage
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
    managed: {
      get: vi.fn(async () => ({})),
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
  runtime: {
    getURL: (path: string) => `chrome-extension://test/${path}`,
  },
});

/**
 * Simulates CLI compile command output.
 * Matches cli/src/commands/compile.ts logic exactly.
 */
function compileIOCsLikeCLI(
  iocs: string[],
  salt: string,
  scope: 'HOST_ONLY' | 'HOST_PATH' | 'FULL_URL' = 'HOST_ONLY'
): { binaryData: Buffer; manifest: Omit<BlocklistManifest, 'signature'> } {
  // Hash all IOCs (matching CLI compile.ts:70-73)
  const hashes: Buffer[] = [];
  for (const ioc of iocs) {
    const hash = hashIOCBytes(ioc, salt, scope);
    hashes.push(hash);
  }

  // Sort hashes for consistent ordering (matching CLI compile.ts:76)
  hashes.sort(Buffer.compare);

  // Remove duplicates (matching CLI compile.ts:79-84)
  const uniqueHashes: Buffer[] = [];
  for (let i = 0; i < hashes.length; i++) {
    if (i === 0 || !hashes[i].equals(hashes[i - 1])) {
      uniqueHashes.push(hashes[i]);
    }
  }

  // Create binary buffer (matching CLI compile.ts:92)
  const binaryBuffer = Buffer.concat(uniqueHashes);

  // Calculate root hash (matching CLI compile.ts:95)
  const rootHash = sha256(binaryBuffer);

  // Create manifest (matching CLI compile.ts:113-121)
  const manifest: Omit<BlocklistManifest, 'signature'> = {
    version: Date.now(),
    total_iocs: uniqueHashes.length,
    bucket_count: 1,
    sha256_root: rootHash,
    created_at: new Date().toISOString(),
    algorithm_version: 'p256-v1',
  };

  return { binaryData: binaryBuffer, manifest };
}

describe('CLI Manifest Update Pipeline Integration', () => {
  let signingKeyPair: { publicKey: SigningPublicKeyJWK; privateKey: SigningPrivateKeyJWK };
  let testSalt: string;

  beforeAll(async () => {
    // Generate test signing keypair (matching CLI keygen command)
    // Uses Ed25519 by default (preferred algorithm)
    signingKeyPair = await generateSigningKeypair();
    testSalt = generateSalt();
  });

  beforeEach(async () => {
    // Clear mock storage before each test
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    // Clear IndexedDB
    await closeDB();
    indexedDB.deleteDatabase('browserdefense');
    vi.clearAllMocks();
  });

  afterEach(async () => {
    await closeDB();
    vi.restoreAllMocks();
  });

  describe('Full Update Pipeline', () => {
    it('should successfully apply update from CLI-generated blocklist', async () => {
      // Test IOCs - using domains that would be in a real blocklist
      const testIOCs = [
        'https://evil-phishing.com',
        'https://malware-download.net',
        'https://credential-theft.org',
      ];

      // Step 1: Compile IOCs like CLI does
      const { binaryData, manifest } = compileIOCsLikeCLI(testIOCs, testSalt, 'HOST_ONLY');

      // Step 2: Sign manifest like CLI sign command
      const signedManifest = await signManifest(manifest, signingKeyPair.privateKey);

      // Step 3: Convert to base64 (matching CLI compile.ts:111)
      const blocklistBase64 = binaryToBase64(binaryData);

      // Step 4: Mock fetch to serve CLI-generated files
      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => signedManifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistBase64,
        });

      // Step 5: Configure and run update
      const config: UpdateConfig = {
        endpoint: 'https://blocklist.example.com/manifest.json',
        publicKey: signingKeyPair.publicKey as unknown as JsonWebKey,
      };

      const result = await fetchBlocklistUpdate(config);

      // Verify update succeeded
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.type).toBe('full');
        expect(result.hashCount).toBe(testIOCs.length);
        expect(result.version).toBe(signedManifest.version);
      }

      // Verify metadata was stored
      const metadata = await getUpdateMetadata();
      expect(metadata).not.toBeNull();
      expect(metadata?.version).toBe(signedManifest.version);
      expect(metadata?.hashCount).toBe(testIOCs.length);

      // Verify blocklist was stored
      expect(await loadBlocklistFromIDB()).toBeDefined();
    });

    it('should correctly block URLs that match CLI-compiled IOCs', async () => {
      // Test IOC - specific domain to block
      const blockedDomain = 'https://phishing-site.example.com';
      const allowedDomain = 'https://safe-site.example.com';

      // Compile just the blocked domain
      const { binaryData, manifest } = compileIOCsLikeCLI([blockedDomain], testSalt, 'HOST_ONLY');
      const signedManifest = await signManifest(manifest, signingKeyPair.privateKey);
      const blocklistBase64 = binaryToBase64(binaryData);

      // Mock fetch
      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => signedManifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistBase64,
        });

      // Apply update
      const config: UpdateConfig = {
        endpoint: 'https://blocklist.example.com/manifest.json',
        publicKey: signingKeyPair.publicKey as unknown as JsonWebKey,
      };
      await fetchBlocklistUpdate(config);

      // Load the blocklist that was stored
      const storedBlocklist = await loadBlocklistFromIDB() as string;
      const blocklist = BinaryHashSet.deserialize(storedBlocklist);

      // Compute hash for blocked domain (using CLI's exact hashing logic)
      const blockedHash = hashIOCBytes(blockedDomain, testSalt, 'HOST_ONLY');
      const allowedHash = hashIOCBytes(allowedDomain, testSalt, 'HOST_ONLY');

      // Verify blocking behavior
      expect(blocklist.has(blockedHash)).toBe(true);
      expect(blocklist.has(allowedHash)).toBe(false);
    });

    it('should reject manifest with invalid signature', async () => {
      const testIOCs = ['https://evil.com'];
      const { binaryData, manifest } = compileIOCsLikeCLI(testIOCs, testSalt, 'HOST_ONLY');

      // Sign with correct key, then tamper
      const signedManifest = await signManifest(manifest, signingKeyPair.privateKey);
      const tamperedManifest = {
        ...signedManifest,
        total_iocs: 999, // Tampered field
      };

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => tamperedManifest,
      });

      const config: UpdateConfig = {
        endpoint: 'https://blocklist.example.com/manifest.json',
        publicKey: signingKeyPair.publicKey as unknown as JsonWebKey,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe('INVALID_SIGNATURE');
      }
    });

    it('should reject blocklist with integrity mismatch', async () => {
      const testIOCs = ['https://evil.com'];
      const { binaryData, manifest } = compileIOCsLikeCLI(testIOCs, testSalt, 'HOST_ONLY');
      const signedManifest = await signManifest(manifest, signingKeyPair.privateKey);

      // Create different blocklist data that doesn't match sha256_root
      const wrongData = Buffer.alloc(32, 0xff);
      const wrongBase64 = binaryToBase64(wrongData);

      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => signedManifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => wrongBase64,
        });

      const config: UpdateConfig = {
        endpoint: 'https://blocklist.example.com/manifest.json',
        publicKey: signingKeyPair.publicKey as unknown as JsonWebKey,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe('INTEGRITY_ERROR');
      }
    });

    it('should handle HOST_PATH scope correctly', async () => {
      const testIOC = 'https://evil.com/phishing/login';
      const differentPath = 'https://evil.com/safe/page';

      // Compile with HOST_PATH scope
      const { binaryData, manifest } = compileIOCsLikeCLI([testIOC], testSalt, 'HOST_PATH');
      const signedManifest = await signManifest(manifest, signingKeyPair.privateKey);
      const blocklistBase64 = binaryToBase64(binaryData);

      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => signedManifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistBase64,
        });

      const config: UpdateConfig = {
        endpoint: 'https://blocklist.example.com/manifest.json',
        publicKey: signingKeyPair.publicKey as unknown as JsonWebKey,
      };
      await fetchBlocklistUpdate(config);

      const storedBlocklist = await loadBlocklistFromIDB() as string;
      const blocklist = BinaryHashSet.deserialize(storedBlocklist);

      // Should match exact path
      const exactHash = hashIOCBytes(testIOC, testSalt, 'HOST_PATH');
      expect(blocklist.has(exactHash)).toBe(true);

      // Should NOT match different path on same host
      const differentHash = hashIOCBytes(differentPath, testSalt, 'HOST_PATH');
      expect(blocklist.has(differentHash)).toBe(false);
    });

    it('should handle FULL_URL scope with query params', async () => {
      const testIOC = 'https://evil.com/track?id=123&campaign=phish';
      const differentQuery = 'https://evil.com/track?id=456&campaign=safe';

      // Compile with FULL_URL scope
      const { binaryData, manifest } = compileIOCsLikeCLI([testIOC], testSalt, 'FULL_URL');
      const signedManifest = await signManifest(manifest, signingKeyPair.privateKey);
      const blocklistBase64 = binaryToBase64(binaryData);

      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => signedManifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistBase64,
        });

      const config: UpdateConfig = {
        endpoint: 'https://blocklist.example.com/manifest.json',
        publicKey: signingKeyPair.publicKey as unknown as JsonWebKey,
      };
      await fetchBlocklistUpdate(config);

      const storedBlocklist = await loadBlocklistFromIDB() as string;
      const blocklist = BinaryHashSet.deserialize(storedBlocklist);

      // Should match exact URL with query
      const exactHash = hashIOCBytes(testIOC, testSalt, 'FULL_URL');
      expect(blocklist.has(exactHash)).toBe(true);

      // Should NOT match different query params
      const differentHash = hashIOCBytes(differentQuery, testSalt, 'FULL_URL');
      expect(blocklist.has(differentHash)).toBe(false);
    });
  });

  describe('Manifest Format Compatibility', () => {
    it('should accept all required manifest fields from CLI', async () => {
      const testIOCs = ['https://test.com'];
      const { binaryData, manifest } = compileIOCsLikeCLI(testIOCs, testSalt);
      const signedManifest = await signManifest(manifest, signingKeyPair.privateKey);

      // Verify manifest has all required fields
      expect(signedManifest.version).toBeDefined();
      expect(typeof signedManifest.version).toBe('number');
      expect(signedManifest.total_iocs).toBeDefined();
      expect(typeof signedManifest.total_iocs).toBe('number');
      expect(signedManifest.bucket_count).toBeDefined();
      expect(typeof signedManifest.bucket_count).toBe('number');
      expect(signedManifest.sha256_root).toBeDefined();
      expect(typeof signedManifest.sha256_root).toBe('string');
      expect(signedManifest.signature).toBeDefined();
      expect(typeof signedManifest.signature).toBe('string');

      // Optional fields
      expect(signedManifest.created_at).toBeDefined();
      // Algorithm version depends on key type (ed25519-v2 or p256-v1)
      expect(['ed25519-v2', 'p256-v1']).toContain(signedManifest.algorithm_version);
    });

    it('should handle large blocklists efficiently', async () => {
      // Generate a larger blocklist (1000 IOCs)
      const testIOCs = Array.from({ length: 1000 }, (_, i) => `https://evil${i}.example.com`);

      const startTime = Date.now();
      const { binaryData, manifest } = compileIOCsLikeCLI(testIOCs, testSalt);
      const compileTime = Date.now() - startTime;

      const signedManifest = await signManifest(manifest, signingKeyPair.privateKey);
      const blocklistBase64 = binaryToBase64(binaryData);

      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => signedManifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistBase64,
        });

      const config: UpdateConfig = {
        endpoint: 'https://blocklist.example.com/manifest.json',
        publicKey: signingKeyPair.publicKey as unknown as JsonWebKey,
      };

      const updateStartTime = Date.now();
      const result = await fetchBlocklistUpdate(config);
      const updateTime = Date.now() - updateStartTime;

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.hashCount).toBe(1000);
      }

      // Performance sanity check - should complete in reasonable time
      expect(compileTime).toBeLessThan(5000); // 5 seconds for compile
      expect(updateTime).toBeLessThan(5000); // 5 seconds for update
    });

    it('should deduplicate IOCs during compile', async () => {
      // Include duplicates
      const testIOCs = [
        'https://evil.com',
        'https://evil.com', // Exact duplicate
        'https://EVIL.COM', // Case variation (should normalize to same hash)
        'https://other.com',
      ];

      const { binaryData, manifest } = compileIOCsLikeCLI(testIOCs, testSalt);

      // Should have deduplicated to 2 unique IOCs
      expect(manifest.total_iocs).toBe(2);
    });
  });

  describe('Version Management', () => {
    it('should skip update when version is not newer', async () => {
      const testIOCs = ['https://evil.com'];
      const { binaryData, manifest } = compileIOCsLikeCLI(testIOCs, testSalt);

      // Force a specific version
      const oldManifest = { ...manifest, version: 100 };
      const signedManifest = await signManifest(oldManifest, signingKeyPair.privateKey);
      const blocklistBase64 = binaryToBase64(binaryData);

      // Set existing metadata with newer version
      mockStorage['browserdefense_update_meta'] = {
        version: 200, // Newer than manifest
        timestamp: new Date().toISOString(),
        updatedAt: Date.now(),
        hashCount: 1,
      };

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => signedManifest,
      });

      const config: UpdateConfig = {
        endpoint: 'https://blocklist.example.com/manifest.json',
        publicKey: signingKeyPair.publicKey as unknown as JsonWebKey,
      };

      const result = await fetchBlocklistUpdate(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.type).toBe('unchanged');
        expect(result.version).toBe(200); // Reports current version
      }

      // Should not have fetched blocklist
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('Canonicalization Alignment', () => {
    it('should handle URL normalization consistently between CLI and extension', async () => {
      // Test various URL formats that should normalize to the same hash
      const canonicalUrl = 'https://example.com';
      const variations = [
        'https://example.com', // Base
        'https://example.com/', // Trailing slash
        'https://EXAMPLE.COM', // Uppercase
        'https://example.com:443', // Default port
        'https://example.com.', // Trailing dot
      ];

      // Compile with the canonical URL
      const { binaryData, manifest } = compileIOCsLikeCLI([canonicalUrl], testSalt, 'HOST_ONLY');
      const signedManifest = await signManifest(manifest, signingKeyPair.privateKey);
      const blocklistBase64 = binaryToBase64(binaryData);

      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => signedManifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistBase64,
        });

      const config: UpdateConfig = {
        endpoint: 'https://blocklist.example.com/manifest.json',
        publicKey: signingKeyPair.publicKey as unknown as JsonWebKey,
      };
      await fetchBlocklistUpdate(config);

      const storedBlocklist = await loadBlocklistFromIDB() as string;
      const blocklist = BinaryHashSet.deserialize(storedBlocklist);

      // All variations should match (normalized to same hash)
      for (const variant of variations) {
        const hash = hashIOCBytes(variant, testSalt, 'HOST_ONLY');
        expect(blocklist.has(hash)).toBe(true);
      }
    });

    it('should handle path normalization consistently', async () => {
      // Test path normalization cases
      const basePath = 'https://example.com/path/to/page';

      const { binaryData, manifest } = compileIOCsLikeCLI([basePath], testSalt, 'HOST_PATH');
      const signedManifest = await signManifest(manifest, signingKeyPair.privateKey);
      const blocklistBase64 = binaryToBase64(binaryData);

      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => signedManifest,
        })
        .mockResolvedValueOnce({
          ok: true,
          text: async () => blocklistBase64,
        });

      const config: UpdateConfig = {
        endpoint: 'https://blocklist.example.com/manifest.json',
        publicKey: signingKeyPair.publicKey as unknown as JsonWebKey,
      };
      await fetchBlocklistUpdate(config);

      const storedBlocklist = await loadBlocklistFromIDB() as string;
      const blocklist = BinaryHashSet.deserialize(storedBlocklist);

      // Base path should match
      const baseHash = hashIOCBytes(basePath, testSalt, 'HOST_PATH');
      expect(blocklist.has(baseHash)).toBe(true);

      // With trailing slash should also match (after normalization)
      const trailingSlash = 'https://example.com/path/to/page/';
      const trailingHash = hashIOCBytes(trailingSlash, testSalt, 'HOST_PATH');
      expect(blocklist.has(trailingHash)).toBe(true);
    });
  });
});
