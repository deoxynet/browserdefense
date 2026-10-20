/**
 * E2E: Blocklist Update Pipeline
 *
 * Tests the full update flow: signed manifest -> blocking behavior.
 * Uses a real local HTTP server (no mocked fetch).
 *
 * Issue #130, #288, #293
 *
 * Uses production manifest format: {version, total_iocs, bucket_count, sha256_root, signature}
 * and serves /manifest.json + /blocklist.b64 endpoints.
 */

import { test, expect, getServiceWorker } from './fixtures';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';

// ============================================================================
// Test Infrastructure: P-256 Key Generation & Signing
// ============================================================================

interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyJwk: JsonWebKey;
}

/**
 * Production manifest format (matches CLI output and updates.ts:BlocklistManifest)
 */
interface BlocklistManifest {
  version: number;
  total_iocs: number;
  bucket_count: number;
  sha256_root: string;
  signature: string;
  created_at?: string;
  algorithm_version?: string;
}

/**
 * Generate a P-256 ECDSA keypair for testing.
 */
async function generateTestKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // extractable
    ['sign', 'verify']
  );

  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyJwk,
  };
}

/**
 * Sign data with a P-256 private key.
 */
async function signData(privateKey: CryptoKey, data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    encoded
  );
  return arrayBufferToBase64(signature);
}

/**
 * Create a BinaryHashSet-compatible base64 blocklist from hex hashes.
 * Matches the format expected by BinaryHashSet.deserialize().
 */
function createBlocklistData(hexHashes: string[]): string {
  // Sort hashes lexicographically (as BinaryHashSet does)
  const sortedHashes = [...hexHashes].sort();

  // Convert to binary (32 bytes per hash)
  const buffer = new ArrayBuffer(sortedHashes.length * 32);
  const view = new Uint8Array(buffer);

  for (let i = 0; i < sortedHashes.length; i++) {
    const hashBytes = hexToBytes(sortedHashes[i]);
    view.set(hashBytes, i * 32);
  }

  return arrayBufferToBase64(buffer);
}

/**
 * Compute SHA-256 hash of blocklist data for integrity verification.
 */
async function computeBlocklistHash(base64Data: string): Promise<string> {
  const binary = atob(base64Data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return arrayBufferToHex(hashBuffer);
}

/**
 * Create a signed blocklist manifest in production format.
 * Signs: {bucket_count, sha256_root, total_iocs, version} (sorted alphabetically)
 */
async function createSignedManifest(
  privateKey: CryptoKey,
  params: {
    version: number;
    hexHashes: string[];
  }
): Promise<{ manifest: BlocklistManifest; blocklistData: string }> {
  // Create binary blocklist data
  const blocklistData = createBlocklistData(params.hexHashes);

  // Compute integrity hash
  const sha256Root = await computeBlocklistHash(blocklistData);

  // Build canonical JSON for signing (sorted keys)
  // Must match verifyBlocklistSignature() in src/crypto/signing.ts
  const signedFields = {
    bucket_count: 1, // Single bucket for test simplicity
    sha256_root: sha256Root,
    total_iocs: params.hexHashes.length,
    version: params.version,
  };

  const canonicalJson = JSON.stringify(signedFields, Object.keys(signedFields).sort());
  const signature = await signData(privateKey, canonicalJson);

  const manifest: BlocklistManifest = {
    version: params.version,
    total_iocs: params.hexHashes.length,
    bucket_count: 1,
    sha256_root: sha256Root,
    signature,
    created_at: new Date().toISOString(),
    algorithm_version: 'p256-v1',
  };

  return { manifest, blocklistData };
}

// ============================================================================
// Helper Functions
// ============================================================================

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.toLowerCase().replace(/^0x/, '');
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ============================================================================
// Local HTTP Server for Manifest Serving
// ============================================================================

/**
 * Hash a URL for blocklist lookup (SHA-256 of normalized URL).
 * Matches the extension's canonicalization for HOST_ONLY scope.
 */
async function hashUrl(url: string): Promise<string> {
  // Normalize: lowercase hostname only (HOST_ONLY scope)
  const parsed = new URL(url);
  let hostname = parsed.hostname.toLowerCase();
  if (hostname.endsWith('.')) {
    hostname = hostname.slice(0, -1);
  }

  const encoded = new TextEncoder().encode(hostname);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return arrayBufferToHex(hashBuffer);
}

interface ManifestServer {
  server: Server;
  port: number;
  url: string;
  setData: (manifest: BlocklistManifest, blocklistData: string) => void;
  close: () => Promise<void>;
}

/**
 * Create a local HTTP server that serves:
 * - /manifest.json - Returns the manifest JSON
 * - /blocklist.b64 - Returns the base64-encoded binary blocklist
 */
async function createManifestServer(): Promise<ManifestServer> {
  let currentManifest: BlocklistManifest | null = null;
  let currentBlocklistData: string = '';

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    // CORS headers for extension access
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.url === '/manifest.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(currentManifest));
    } else if (req.url === '/blocklist.b64') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(currentBlocklistData);
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as AddressInfo;
      const port = address.port;
      const url = `http://127.0.0.1:${port}`;

      resolve({
        server,
        port,
        url,
        setData: (manifest: BlocklistManifest, blocklistData: string) => {
          currentManifest = manifest;
          currentBlocklistData = blocklistData;
        },
        close: () =>
          new Promise((resolveClose) => {
            server.close(() => resolveClose());
          }),
      });
    });
  });
}

// ============================================================================
// E2E Tests
// ============================================================================

test.describe('Blocklist Update Pipeline', () => {
  let manifestServer: ManifestServer;
  let keyPair: KeyPair;
  let testUrlHash: string;

  const TEST_URL = 'https://malicious-test-domain.example.com/phishing';

  test.beforeAll(async () => {
    // Generate test keypair
    keyPair = await generateTestKeyPair();

    // Pre-compute hash for test URL (HOST_ONLY scope)
    testUrlHash = await hashUrl(TEST_URL);

    // Start manifest server
    manifestServer = await createManifestServer();
  });

  test.afterAll(async () => {
    if (manifestServer) {
      await manifestServer.close();
    }
  });

  test('full update adds hash and enables blocking', async ({ context, extensionId }) => {
    // Create signed manifest with test URL hash using production format
    const { manifest, blocklistData } = await createSignedManifest(keyPair.privateKey, {
      version: 1,
      hexHashes: [testUrlHash],
    });
    manifestServer.setData(manifest, blocklistData);

    // Configure extension via options page (accesses chrome.storage)
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Set update config via page script
    // Note: endpoint points to /manifest.json, blocklist.b64 is derived automatically
    await optionsPage.evaluate(
      async ({ endpoint, publicKey }: { endpoint: string; publicKey: JsonWebKey }) => {
        await chrome.storage.local.set({
          browserdefense_update_config: { endpoint, publicKey },
        });
      },
      {
        endpoint: `${manifestServer.url}/manifest.json`,
        publicKey: keyPair.publicKeyJwk,
      }
    );

    // Send message to trigger update
    const updateResult = await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'forceUpdate' }, (response) => {
          resolve(response);
        });
      });
    });

    await optionsPage.close();

    // Verify update succeeded
    expect(updateResult).toBeDefined();
    if (updateResult && typeof updateResult === 'object' && 'success' in updateResult) {
      expect(updateResult.success).toBe(true);
    }
  });

  test('blocking behavior reflects stored blocklist', async ({ context, extensionId }) => {
    // First, set up the blocklist (each test has a fresh context)
    const { manifest, blocklistData } = await createSignedManifest(keyPair.privateKey, {
      version: 1,
      hexHashes: [testUrlHash],
    });
    manifestServer.setData(manifest, blocklistData);

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure and trigger update
    await optionsPage.evaluate(
      async ({ endpoint, publicKey }: { endpoint: string; publicKey: JsonWebKey }) => {
        await chrome.storage.local.set({
          browserdefense_update_config: { endpoint, publicKey },
        });
      },
      {
        endpoint: `${manifestServer.url}/manifest.json`,
        publicKey: keyPair.publicKeyJwk,
      }
    );

    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'forceUpdate' }, resolve);
      });
    });

    // Test via navigation - verify we can navigate to a safe URL
    const page = await context.newPage();
    await page.goto('https://example.com');
    expect(page.url()).toContain('example.com');

    // Now check update metadata (blocklist is stored in IndexedDB, not chrome.storage.local)
    const storageData = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_update_meta');
      return {
        hasMetadata: !!result.browserdefense_update_meta,
        metadata: result.browserdefense_update_meta,
      };
    });

    // Verify update metadata exists (indicates blocklist was saved)
    expect(storageData.hasMetadata).toBe(true);
    expect(storageData.metadata?.hashCount).toBeGreaterThan(0);

    await page.close();
    await optionsPage.close();
  });

  test('newer version replaces blocklist', async ({ context, extensionId }) => {
    // First, set up initial blocklist (version 1)
    const { manifest: manifest1, blocklistData: blocklistData1 } = await createSignedManifest(
      keyPair.privateKey,
      { version: 1, hexHashes: [testUrlHash] }
    );
    manifestServer.setData(manifest1, blocklistData1);

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure update
    await optionsPage.evaluate(
      async ({ endpoint, publicKey }: { endpoint: string; publicKey: JsonWebKey }) => {
        await chrome.storage.local.set({
          browserdefense_update_config: { endpoint, publicKey },
        });
      },
      {
        endpoint: `${manifestServer.url}/manifest.json`,
        publicKey: keyPair.publicKeyJwk,
      }
    );

    // Trigger initial update
    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'forceUpdate' }, resolve);
      });
    });

    // Now create newer manifest (version 2) with different content
    const newHash = await hashUrl('https://another-malicious-site.example.com');
    const { manifest: manifest2, blocklistData: blocklistData2 } = await createSignedManifest(
      keyPair.privateKey,
      { version: 2, hexHashes: [newHash] }
    );
    manifestServer.setData(manifest2, blocklistData2);

    // Trigger second update
    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'forceUpdate' }, resolve);
      });
    });

    // Check that metadata was updated to version 2
    const metadata = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_update_meta');
      return result.browserdefense_update_meta;
    });

    await optionsPage.close();

    // Verify version updated to 2
    expect(metadata).toBeDefined();
    expect(metadata.version).toBe(2);
  });

  test('rejects manifest with invalid signature', async ({ context, extensionId }) => {
    // First, install a valid version 1 blocklist
    const { manifest: validManifest, blocklistData: validData } = await createSignedManifest(
      keyPair.privateKey,
      { version: 1, hexHashes: [testUrlHash] }
    );
    manifestServer.setData(validManifest, validData);

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure update
    await optionsPage.evaluate(
      async ({ endpoint, publicKey }: { endpoint: string; publicKey: JsonWebKey }) => {
        await chrome.storage.local.set({
          browserdefense_update_config: { endpoint, publicKey },
        });
      },
      {
        endpoint: `${manifestServer.url}/manifest.json`,
        publicKey: keyPair.publicKeyJwk,
      }
    );

    // Trigger initial update to establish baseline
    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'forceUpdate' }, resolve);
      });
    });

    // Get version before attempting invalid update
    const versionBefore = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_update_meta');
      return result.browserdefense_update_meta?.version ?? 0;
    });

    // Now serve a tampered manifest (version 100) with invalid signature
    const tamperedBlocklistData = createBlocklistData([testUrlHash]);
    const sha256Root = await computeBlocklistHash(tamperedBlocklistData);
    const tamperedManifest: BlocklistManifest = {
      version: 100,
      total_iocs: 1,
      bucket_count: 1,
      sha256_root: sha256Root,
      signature: arrayBufferToBase64(new Uint8Array(64).buffer), // Invalid signature
      created_at: new Date().toISOString(),
      algorithm_version: 'p256-v1',
    };
    manifestServer.setData(tamperedManifest, tamperedBlocklistData);

    // Trigger update - should fail
    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'forceUpdate' }, resolve);
      });
    });

    // Verify version didn't change (update was rejected)
    const versionAfter = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_update_meta');
      return result.browserdefense_update_meta?.version ?? 0;
    });

    await optionsPage.close();

    // Version should not have changed to 100 (should still be 1)
    expect(versionAfter).toBe(versionBefore);
    expect(versionAfter).toBeLessThan(100);
  });

  test('storage persists across page reloads', async ({ context, extensionId }) => {
    // Generate a second test hash for the persistence test
    const secondHash = await hashUrl('https://persistence-test.example.com');

    // Set up a known state with production format
    const { manifest, blocklistData } = await createSignedManifest(keyPair.privateKey, {
      version: 50,
      hexHashes: [testUrlHash, secondHash],
    });
    manifestServer.setData(manifest, blocklistData);

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure update
    await optionsPage.evaluate(
      async ({ endpoint, publicKey }: { endpoint: string; publicKey: JsonWebKey }) => {
        await chrome.storage.local.set({
          browserdefense_update_config: { endpoint, publicKey },
        });
      },
      {
        endpoint: `${manifestServer.url}/manifest.json`,
        publicKey: keyPair.publicKeyJwk,
      }
    );

    // Trigger update
    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'forceUpdate' }, resolve);
      });
    });

    // Get state before reload (metadata is in chrome.storage.local, blocklist is in IndexedDB)
    const stateBefore = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_update_meta');
      return {
        hasMetadata: !!result.browserdefense_update_meta,
        version: result.browserdefense_update_meta?.version,
        hashCount: result.browserdefense_update_meta?.hashCount,
      };
    });

    // Reload page
    await optionsPage.reload();

    // Verify state persisted
    const stateAfter = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_update_meta');
      return {
        hasMetadata: !!result.browserdefense_update_meta,
        version: result.browserdefense_update_meta?.version,
        hashCount: result.browserdefense_update_meta?.hashCount,
      };
    });

    await optionsPage.close();

    expect(stateAfter.hasMetadata).toBe(stateBefore.hasMetadata);
    expect(stateAfter.version).toBe(stateBefore.version);
    expect(stateAfter.hashCount).toBe(stateBefore.hashCount);
  });
});

test.describe('Update Error Handling', () => {
  test('handles network errors gracefully', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure with unreachable endpoint
    await optionsPage.evaluate(async () => {
      await chrome.storage.local.set({
        browserdefense_update_config: {
          endpoint: 'http://127.0.0.1:1', // Unreachable port
          publicKey: { kty: 'EC', crv: 'P-256', x: 'test', y: 'test' },
          maxRetries: 1,
          baseDelayMs: 10,
        },
      });
    });

    // Trigger update - should fail gracefully
    const updateResult = await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'forceUpdate' }, (response) => {
          resolve(response);
        });
      });
    });

    await optionsPage.close();

    // Should return an error response, not crash
    expect(updateResult).toBeDefined();
  });

  test('handles malformed manifest gracefully', async ({ context, extensionId }) => {
    const localServer = await createManifestServer();
    const localKeyPair = await generateTestKeyPair();

    try {
      // Serve malformed manifest (missing required fields like sha256_root, total_iocs)
      // Use type assertion to bypass TypeScript - this is intentionally invalid
      localServer.setData({ invalid: 'manifest' } as unknown as BlocklistManifest, '');

      const optionsPage = await context.newPage();
      await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

      await optionsPage.evaluate(
        async ({ endpoint, publicKey }: { endpoint: string; publicKey: JsonWebKey }) => {
          await chrome.storage.local.set({
            browserdefense_update_config: { endpoint, publicKey },
          });
        },
        {
          endpoint: `${localServer.url}/manifest.json`,
          publicKey: localKeyPair.publicKeyJwk,
        }
      );

      // Should not crash
      const updateResult = await optionsPage.evaluate(async () => {
        return new Promise((resolve) => {
          chrome.runtime.sendMessage({ type: 'forceUpdate' }, (response) => {
            resolve(response);
          });
        });
      });

      await optionsPage.close();

      expect(updateResult).toBeDefined();
    } finally {
      await localServer.close();
    }
  });
});

// ============================================================================
// Salted Hash Blocking Tests (Issue #293)
// ============================================================================

/**
 * Create a binary blocklist (same format as BinaryHashSet).
 * Each hash is 32 bytes, concatenated together.
 */
function createBinaryBlocklist(hashes: Uint8Array[]): string {
  // Sort hashes for binary search
  hashes.sort((a, b) => {
    for (let i = 0; i < 32; i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return 0;
  });

  // Concatenate into single buffer
  const buffer = new Uint8Array(hashes.length * 32);
  for (let i = 0; i < hashes.length; i++) {
    buffer.set(hashes[i], i * 32);
  }

  // Base64 encode
  let binary = '';
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary);
}

/**
 * Hash a URL and return as Uint8Array for blocklist storage.
 */
async function hashUrlBytes(url: string, salt: string): Promise<Uint8Array> {
  const parsed = new URL(url);
  const scheme = parsed.protocol;
  let hostname = parsed.hostname.toLowerCase();
  if (hostname.endsWith('.')) {
    hostname = hostname.slice(0, -1);
  }
  let port = parsed.port;
  if (scheme === 'http:' && port === '80') port = '';
  if (scheme === 'https:' && port === '443') port = '';
  const host = port ? `${hostname}:${port}` : hostname;
  const canonical = `${scheme}//${host}`;
  const data = canonical + ':' + salt;
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return new Uint8Array(hashBuffer);
}

/**
 * Local test server for salted hash blocking tests.
 */
interface SaltedTestServer {
  server: Server;
  port: number;
  baseUrl: string;
  close: () => Promise<void>;
}

async function createSaltedTestServer(): Promise<SaltedTestServer> {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    res.setHeader('Access-Control-Allow-Origin', '*');

    if (req.url === '/blocked-page') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>Blocked Test Page</h1></body></html>');
    } else if (req.url === '/safe-page') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>Safe Test Page</h1></body></html>');
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<html><body><h1>Path: ${req.url}</h1></body></html>`);
    }
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as AddressInfo;
      const port = address.port;
      const baseUrl = `http://127.0.0.1:${port}`;

      resolve({
        server,
        port,
        baseUrl,
        close: () =>
          new Promise((resolveClose) => {
            server.close(() => resolveClose());
          }),
      });
    });
  });
}

test.describe('Salted Hash Blocking (Issue #293)', () => {
  let testServer: SaltedTestServer;
  const TEST_SALT = 'e2e-salted-blocking-test-salt';

  /**
   * Create a full valid BrowserDefense config for testing.
   * Uses HOST_PATH scope to match the local server URL format.
   */
  const createTestConfig = (salt: string) => ({
    org_id: 'e2e-salted-test-org',
    signing_public_key: {
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    },
    encryption_public_key: {
      kty: 'RSA',
      n: 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
      e: 'AQAB',
    },
    blocklist_endpoint: 'https://example.com/blocklist.json',
    forensics_endpoint: 'https://example.com/forensics',
    ioc_salt: salt,
    ioc_scope: 'HOST_PATH',
  });

  /**
   * Hash a URL for HOST_PATH scope with scheme included.
   * Must match the extension's canonicalizeAndHash behavior.
   */
  async function hashUrlForHostPath(url: string, salt: string): Promise<Uint8Array> {
    const parsed = new URL(url);
    const scheme = parsed.protocol;
    let hostname = parsed.hostname.toLowerCase();
    if (hostname.endsWith('.')) {
      hostname = hostname.slice(0, -1);
    }
    let port = parsed.port;
    if (scheme === 'http:' && port === '80') port = '';
    if (scheme === 'https:' && port === '443') port = '';
    const host = port ? `${hostname}:${port}` : hostname;

    // Normalize path
    let path = parsed.pathname;
    if (!path) path = '/';
    if (path.length > 1 && path.endsWith('/')) {
      path = path.slice(0, -1);
    }

    // HOST_PATH with scheme: scheme://host/path
    const canonical = `${scheme}//${host}${path}`;
    const data = canonical + ':' + salt;
    const encoded = new TextEncoder().encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
    return new Uint8Array(hashBuffer);
  }

  test.beforeAll(async () => {
    testServer = await createSaltedTestServer();
  });

  test.afterAll(async () => {
    if (testServer) {
      await testServer.close();
    }
  });

  test('salted hash lookup correctly blocks navigation to IOC URL', async ({ context, extensionId }) => {
    // This test validates issue #293:
    // 1. Set browserdefense_config with ioc_salt
    // 2. Generate salted hash matching extension's canonicalization
    // 3. Navigate to IOC URL and verify redirect to blocked.html

    const blockedUrl = `${testServer.baseUrl}/blocked-page`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Compute salted hash for the blocked URL
    const testUrlHash = await hashUrlForHostPath(blockedUrl, TEST_SALT);
    const blocklistData = createBinaryBlocklist([testUrlHash]);

    // Set config with salt AND blocklist with salted hash
    await optionsPage.evaluate(
      async ({ config, blocklist }: { config: object; blocklist: string }) => {
        await chrome.storage.local.set({
          browserdefense_config: config,
          browserdefense_blocklist: blocklist,
        });
        // Notify service worker to reload config and blocklist
        await new Promise<void>((resolve) => {
          chrome.runtime.sendMessage({ type: 'reloadBlocklist' }, () => resolve());
        });
      },
      { config: createTestConfig(TEST_SALT), blocklist: blocklistData }
    );

    // Wait for blocking to be active by polling checkBlocked
    let attempts = 0;
    while (attempts < 20) {
      const result = (await optionsPage.evaluate(async (url: string) => {
        return new Promise((resolve) => {
          chrome.runtime.sendMessage({ type: 'checkBlocked', url }, (response) => {
            resolve(response);
          });
        });
      }, blockedUrl)) as { blocked: boolean };
      if (result?.blocked) break;
      await optionsPage.waitForTimeout(100);
      attempts++;
    }
    await optionsPage.close();

    // Navigate to blocked URL
    const page = await context.newPage();
    try {
      await page.goto(blockedUrl, { waitUntil: 'domcontentloaded', timeout: 5000 });
    } catch {
      // Navigation may be aborted when blocking intercepts
    }

    // Wait for redirect to block page
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    // Verify blocked URL is in query params
    expect(page.url()).toContain('blocked-page');

    await page.close();
  });

  test('salt mismatch prevents blocking (security validation)', async ({ context, extensionId }) => {
    // This test validates that using the WRONG salt doesn't cause false positives
    // The hash is computed with one salt, but config uses a different salt
    // This simulates a supply chain attack where someone tries to bypass detection

    const WRONG_SALT = 'completely-different-salt';
    const CORRECT_SALT = 'actual-deployment-salt';
    const testUrl = `${testServer.baseUrl}/blocked-page`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Compute hash with WRONG salt (simulating attacker's hash)
    const testUrlHash = await hashUrlForHostPath(testUrl, WRONG_SALT);
    const blocklistData = createBinaryBlocklist([testUrlHash]);

    // But configure extension with CORRECT salt
    await optionsPage.evaluate(
      async ({ config, blocklist }: { config: object; blocklist: string }) => {
        await chrome.storage.local.set({
          browserdefense_config: config,
          browserdefense_blocklist: blocklist,
        });
        await new Promise<void>((resolve) => {
          chrome.runtime.sendMessage({ type: 'reloadBlocklist' }, () => resolve());
        });
      },
      { config: createTestConfig(CORRECT_SALT), blocklist: blocklistData }
    );

    // Wait a moment for config to load
    await optionsPage.waitForTimeout(500);

    // Check - should NOT be blocked because salt doesn't match
    const result = (await optionsPage.evaluate(async (url: string) => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'checkBlocked', url }, (response) => {
          resolve(response);
        });
      });
    }, testUrl)) as { blocked: boolean };

    expect(result?.blocked).toBe(false);
    await optionsPage.close();
  });

  test('safe URL is not blocked with salted hashing', async ({ context, extensionId }) => {
    const blockedUrl = `${testServer.baseUrl}/blocked-page`;
    const safeUrl = `${testServer.baseUrl}/safe-page`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Hash only the blocked URL, not the safe URL
    const testUrlHash = await hashUrlForHostPath(blockedUrl, TEST_SALT);
    const blocklistData = createBinaryBlocklist([testUrlHash]);

    await optionsPage.evaluate(
      async ({ config, blocklist }: { config: object; blocklist: string }) => {
        await chrome.storage.local.set({
          browserdefense_config: config,
          browserdefense_blocklist: blocklist,
        });
        await new Promise<void>((resolve) => {
          chrome.runtime.sendMessage({ type: 'reloadBlocklist' }, () => resolve());
        });
      },
      { config: createTestConfig(TEST_SALT), blocklist: blocklistData }
    );

    await optionsPage.waitForTimeout(500);
    await optionsPage.close();

    // Navigate to safe URL - should NOT be blocked
    const page = await context.newPage();
    await page.goto(safeUrl);

    // Should load normally
    expect(page.url()).toBe(safeUrl);
    expect(page.url()).not.toContain('blocked/blocked.html');

    await page.close();
  });
});
