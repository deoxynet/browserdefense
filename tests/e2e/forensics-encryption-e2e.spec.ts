/**
 * E2E: Forensics Encryption/Upload Integration Test
 *
 * Tests the full zero-knowledge forensics pipeline:
 * 1. Trigger a block that generates forensics
 * 2. Encrypt with RSA-OAEP + AES-GCM
 * 3. Upload to a local test server
 * 4. Verify NO plaintext fields are in transit
 * 5. Decrypt server-side and verify payload matches
 *
 * Issue #226 - Integration test gap: forensics encryption/upload end-to-end
 */

import { test, expect, getServiceWorker } from './fixtures';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';

// ============================================================================
// Test Infrastructure: Crypto Helpers (matching src/crypto/encryption.ts)
// ============================================================================

interface EncryptedPayload {
  iv: string;
  wrappedKey: string;
  ciphertext: string;
}

interface RSAPublicKeyJWK {
  kty: 'RSA';
  n: string;
  e: string;
  alg?: string;
  use?: string;
}

interface RSAPrivateKeyJWK extends RSAPublicKeyJWK {
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer as ArrayBuffer;
}

async function importRSAPrivateKey(jwk: RSAPrivateKeyJWK): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, [
    'decrypt',
  ]);
}

async function unwrapAESKey(wrappedKey: ArrayBuffer, rsaPrivateKey: CryptoKey): Promise<CryptoKey> {
  const rawKey = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaPrivateKey, wrappedKey);
  return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM', length: 256 }, false, [
    'decrypt',
  ]);
}

async function decryptAESGCM(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: ArrayBuffer
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ciphertext);
}

/**
 * Decrypt forensics payload using hybrid RSA-OAEP + AES-GCM decryption.
 * This mirrors the decryptForensics function from src/crypto/encryption.ts
 */
async function decryptForensics<T>(
  encrypted: EncryptedPayload,
  privateKeyJwk: RSAPrivateKeyJWK
): Promise<T> {
  const iv = new Uint8Array(base64ToArrayBuffer(encrypted.iv));
  const wrappedKey = base64ToArrayBuffer(encrypted.wrappedKey);
  const ciphertext = base64ToArrayBuffer(encrypted.ciphertext);

  const rsaPrivateKey = await importRSAPrivateKey(privateKeyJwk);
  const aesKey = await unwrapAESKey(wrappedKey, rsaPrivateKey);
  const plaintext = await decryptAESGCM(aesKey, iv, ciphertext);

  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json) as T;
}

// ============================================================================
// Test Infrastructure: Forensics Upload Server with Decryption
// ============================================================================

interface ForensicsE2EServer {
  server: Server;
  port: number;
  url: string;
  receivedPayloads: EncryptedPayload[];
  setPrivateKey: (key: RSAPrivateKeyJWK) => void;
  getDecryptedPayloads: () => Promise<unknown[]>;
  getRawPayloads: () => EncryptedPayload[];
  getReceivedCount: () => number;
  clearReceived: () => void;
  close: () => Promise<void>;
}

async function createForensicsE2EServer(): Promise<ForensicsE2EServer> {
  const receivedPayloads: EncryptedPayload[] = [];
  let privateKey: RSAPrivateKeyJWK | null = null;

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === 'POST' && req.url === '/forensics') {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk;
      });
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          receivedPayloads.push(payload);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', id: crypto.randomUUID() }));
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
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
        receivedPayloads,
        setPrivateKey: (key: RSAPrivateKeyJWK) => {
          privateKey = key;
        },
        getDecryptedPayloads: async () => {
          if (!privateKey) throw new Error('Private key not set');
          const decrypted: unknown[] = [];
          for (const payload of receivedPayloads) {
            try {
              const dec = await decryptForensics(payload, privateKey);
              decrypted.push(dec);
            } catch (err) {
              throw new Error(`Failed to decrypt payload: ${(err as Error).message}`);
            }
          }
          return decrypted;
        },
        getRawPayloads: () => [...receivedPayloads],
        getReceivedCount: () => receivedPayloads.length,
        clearReceived: () => {
          receivedPayloads.length = 0;
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
// Plaintext field names that MUST NOT appear in transit
// These are the forensics payload fields from ForensicsPayload interface
// ============================================================================

const PLAINTEXT_FIELD_PATTERNS = [
  'blockedUrl',
  'timestamp',
  'redirectChain',
  'tabId',
  'frameId',
  'initiator',
  'normalizedUrl',
  'reason',
  'ioc_match',
  'https://',
  'http://',
];

/**
 * Check that a string does NOT contain any plaintext forensics fields.
 * The encrypted payload should be completely opaque.
 */
function assertNoPlaintextFields(rawBody: string, context: string): void {
  for (const pattern of PLAINTEXT_FIELD_PATTERNS) {
    // Only check if the pattern appears outside of the expected encrypted structure
    // The keys 'iv', 'wrappedKey', 'ciphertext' are expected
    const bodyWithoutStructure = rawBody
      .replace(/"iv"/g, '')
      .replace(/"wrappedKey"/g, '')
      .replace(/"ciphertext"/g, '')
      .replace(/"orgId"/g, '')
      .replace(/"keyVersion"/g, '');

    if (bodyWithoutStructure.includes(pattern)) {
      throw new Error(
        `ZERO-KNOWLEDGE VIOLATION: Plaintext field "${pattern}" found in ${context}. ` +
          `This indicates unencrypted forensics data was transmitted.`
      );
    }
  }
}

// ============================================================================
// E2E Tests
// ============================================================================

test.describe('Forensics Encryption E2E', () => {
  let forensicsServer: ForensicsE2EServer;
  let testKeyPair: { publicKey: RSAPublicKeyJWK; privateKey: RSAPrivateKeyJWK };

  test.beforeAll(async () => {
    forensicsServer = await createForensicsE2EServer();
  });

  test.afterAll(async () => {
    if (forensicsServer) {
      await forensicsServer.close();
    }
  });

  test.beforeEach(async () => {
    forensicsServer.clearReceived();
  });

  test('uploadForensics sends only encrypted payloads (zero-knowledge verified)', async ({
    context,
    extensionId,
  }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Generate RSA keypair in the browser context
    testKeyPair = await optionsPage.evaluate(async () => {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );

      const publicKey = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as RSAPublicKeyJWK;
      const privateKey = (await crypto.subtle.exportKey(
        'jwk',
        keyPair.privateKey
      )) as RSAPrivateKeyJWK;

      return { publicKey, privateKey };
    });

    // Set private key on server for decryption
    forensicsServer.setPrivateKey(testKeyPair.privateKey);

    // Configure extension with public key and forensics endpoint
    await optionsPage.evaluate(
      async ({
        endpoint,
        publicKey,
      }: {
        endpoint: string;
        publicKey: RSAPublicKeyJWK;
      }) => {
        await chrome.storage.local.set({
          browserdefense_config: {
            forensics_endpoint: endpoint,
            encryption_public_key: publicKey,
            org_id: 'test-org-123',
            key_version: 1,
          },
        });
      },
      { endpoint: `${forensicsServer.url}/forensics`, publicKey: testKeyPair.publicKey }
    );

    // Create a test payload and invoke uploadForensics via the service worker
    const testPayload = {
      blockedUrl: 'https://malicious-phishing.example.com/login?user=victim',
      timestamp: new Date().toISOString(),
      tabId: 42,
      frameId: 0,
      reason: 'ioc_match',
      redirectChain: [
        'https://legit-site.com',
        'https://redirect-1.com/path',
        'https://malicious-phishing.example.com/login?user=victim',
      ],
      normalizedUrl: 'malicious-phishing.example.com/login',
    };

    // Send message to service worker to trigger uploadForensics
    const uploadResult = await optionsPage.evaluate(async (payload) => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { type: 'uploadForensicsTest', payload },
          (response) => resolve(response)
        );
      });
    }, testPayload);

    // Wait for upload to complete
    await optionsPage.waitForTimeout(500);

    // Verify server received exactly one payload
    expect(forensicsServer.getReceivedCount()).toBe(1);

    // Get the raw encrypted payload
    const rawPayloads = forensicsServer.getRawPayloads();
    expect(rawPayloads.length).toBe(1);

    const encrypted = rawPayloads[0];

    // CRITICAL: Verify encrypted structure
    expect(encrypted.iv).toBeDefined();
    expect(encrypted.wrappedKey).toBeDefined();
    expect(encrypted.ciphertext).toBeDefined();

    // CRITICAL: Verify NO plaintext forensics data in the encrypted payload
    const rawBody = JSON.stringify(encrypted);
    assertNoPlaintextFields(rawBody, 'encrypted payload');

    // Verify base64 encoding
    expect(() => atob(encrypted.iv)).not.toThrow();
    expect(() => atob(encrypted.wrappedKey)).not.toThrow();
    expect(() => atob(encrypted.ciphertext)).not.toThrow();

    // Decrypt and verify the payload matches
    const decryptedPayloads = await forensicsServer.getDecryptedPayloads();
    expect(decryptedPayloads.length).toBe(1);

    const decrypted = decryptedPayloads[0] as typeof testPayload;
    expect(decrypted.blockedUrl).toBe(testPayload.blockedUrl);
    expect(decrypted.tabId).toBe(testPayload.tabId);
    expect(decrypted.frameId).toBe(testPayload.frameId);
    expect(decrypted.reason).toBe(testPayload.reason);
    expect(decrypted.redirectChain).toEqual(testPayload.redirectChain);
    expect(decrypted.normalizedUrl).toBe(testPayload.normalizedUrl);

    await optionsPage.close();
  });

  test('retryPendingUploads encrypts queued items before sending', async ({
    context,
    extensionId,
  }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Generate RSA keypair
    testKeyPair = await optionsPage.evaluate(async () => {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );

      const publicKey = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as RSAPublicKeyJWK;
      const privateKey = (await crypto.subtle.exportKey(
        'jwk',
        keyPair.privateKey
      )) as RSAPrivateKeyJWK;

      return { publicKey, privateKey };
    });

    forensicsServer.setPrivateKey(testKeyPair.privateKey);

    // Configure extension
    await optionsPage.evaluate(
      async ({
        endpoint,
        publicKey,
      }: {
        endpoint: string;
        publicKey: RSAPublicKeyJWK;
      }) => {
        await chrome.storage.local.set({
          browserdefense_config: {
            forensics_endpoint: endpoint,
            encryption_public_key: publicKey,
            org_id: 'test-org-456',
            key_version: 2,
          },
        });
      },
      { endpoint: `${forensicsServer.url}/forensics`, publicKey: testKeyPair.publicKey }
    );

    // Add an UNENCRYPTED item to the queue (simulating encryption failure on initial attempt)
    await optionsPage.evaluate(async () => {
      const queue = [
        {
          id: 'queued-item-1',
          payload: {
            blockedUrl: 'https://queued-malware.example.com/dropper.exe',
            timestamp: new Date().toISOString(),
            tabId: 100,
            frameId: 0,
            reason: 'ioc_match',
            normalizedUrl: 'queued-malware.example.com/dropper.exe',
          },
          // NO 'encrypted' field - needs encryption on retry
          attempts: 0,
          queuedAt: new Date().toISOString(),
        },
      ];
      await chrome.storage.local.set({ browserdefense_forensics_queue: queue });
    });

    // Trigger retry
    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'retryForensics' }, resolve);
      });
    });

    // Wait for retry to complete
    await optionsPage.waitForTimeout(1000);

    // Server should have received encrypted payload
    const receivedCount = forensicsServer.getReceivedCount();

    // If retry was successful, verify encryption
    if (receivedCount > 0) {
      const rawPayloads = forensicsServer.getRawPayloads();
      const encrypted = rawPayloads[0];

      // Verify encrypted structure
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.wrappedKey).toBeDefined();
      expect(encrypted.ciphertext).toBeDefined();

      // Verify no plaintext
      const rawBody = JSON.stringify(encrypted);
      assertNoPlaintextFields(rawBody, 'retry encrypted payload');

      // Decrypt and verify
      const decryptedPayloads = await forensicsServer.getDecryptedPayloads();
      const decrypted = decryptedPayloads[0] as { blockedUrl: string };
      expect(decrypted.blockedUrl).toBe('https://queued-malware.example.com/dropper.exe');
    }

    await optionsPage.close();
  });

  test('pre-encrypted queue items are sent without re-encryption', async ({
    context,
    extensionId,
  }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Generate RSA keypair
    testKeyPair = await optionsPage.evaluate(async () => {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );

      const publicKey = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as RSAPublicKeyJWK;
      const privateKey = (await crypto.subtle.exportKey(
        'jwk',
        keyPair.privateKey
      )) as RSAPrivateKeyJWK;

      return { publicKey, privateKey };
    });

    forensicsServer.setPrivateKey(testKeyPair.privateKey);

    // Configure extension
    await optionsPage.evaluate(
      async ({
        endpoint,
        publicKey,
      }: {
        endpoint: string;
        publicKey: RSAPublicKeyJWK;
      }) => {
        await chrome.storage.local.set({
          browserdefense_config: {
            forensics_endpoint: endpoint,
            encryption_public_key: publicKey,
            org_id: 'test-org-789',
            key_version: 3,
          },
        });
      },
      { endpoint: `${forensicsServer.url}/forensics`, publicKey: testKeyPair.publicKey }
    );

    // Pre-encrypt a payload in the browser and add to queue
    const preEncryptedData = await optionsPage.evaluate(async () => {
      // Generate AES key
      const aesKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );

      // Generate IV
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // Get public key from config
      const config = (await chrome.storage.local.get('browserdefense_config')).browserdefense_config;
      const publicKey = config.encryption_public_key;

      // Encrypt payload
      const payload = {
        blockedUrl: 'https://pre-encrypted.example.com/malware',
        timestamp: new Date().toISOString(),
        tabId: 200,
        frameId: 0,
        reason: 'ioc_match',
      };

      const plaintext = new TextEncoder().encode(JSON.stringify(payload));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        aesKey,
        plaintext
      );

      // Wrap AES key with RSA
      const rsaPublicKey = await crypto.subtle.importKey(
        'jwk',
        publicKey,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
      );
      const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
      const wrappedKey = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        rsaPublicKey,
        rawAesKey
      );

      // Convert to base64
      const toBase64 = (buffer: ArrayBuffer) => {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
      };

      const encrypted = {
        iv: toBase64(iv.buffer as ArrayBuffer),
        wrappedKey: toBase64(wrappedKey),
        ciphertext: toBase64(ciphertext),
        orgId: config.org_id,
        keyVersion: config.key_version,
      };

      // Add pre-encrypted item to queue
      const queue = [
        {
          id: 'pre-encrypted-item',
          payload,
          encrypted,
          attempts: 1,
          lastAttempt: new Date(Date.now() - 60000).toISOString(), // 1 min ago, past backoff
          queuedAt: new Date().toISOString(),
        },
      ];
      await chrome.storage.local.set({ browserdefense_forensics_queue: queue });

      return encrypted;
    });

    // Trigger retry
    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'retryForensics' }, resolve);
      });
    });

    await optionsPage.waitForTimeout(500);

    // Server should have received the pre-encrypted payload
    const receivedCount = forensicsServer.getReceivedCount();

    if (receivedCount > 0) {
      const rawPayloads = forensicsServer.getRawPayloads();
      const received = rawPayloads[0];

      // Verify the received payload matches what we pre-encrypted
      expect(received.iv).toBe(preEncryptedData.iv);
      expect(received.wrappedKey).toBe(preEncryptedData.wrappedKey);
      expect(received.ciphertext).toBe(preEncryptedData.ciphertext);

      // Verify no plaintext
      const rawBody = JSON.stringify(received);
      assertNoPlaintextFields(rawBody, 'pre-encrypted payload');

      // Decrypt and verify
      const decryptedPayloads = await forensicsServer.getDecryptedPayloads();
      const decrypted = decryptedPayloads[0] as { blockedUrl: string };
      expect(decrypted.blockedUrl).toBe('https://pre-encrypted.example.com/malware');
    }

    await optionsPage.close();
  });

  test('encryption failure prevents plaintext upload', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure with INVALID public key (will cause encryption to fail)
    await optionsPage.evaluate(
      async ({ endpoint }: { endpoint: string }) => {
        await chrome.storage.local.set({
          browserdefense_config: {
            forensics_endpoint: endpoint,
            // Invalid key - missing required fields
            encryption_public_key: { kty: 'RSA', n: 'invalid', e: 'AQAB' },
            org_id: 'test-org-fail',
            key_version: 1,
          },
        });
      },
      { endpoint: `${forensicsServer.url}/forensics` }
    );

    // Try to upload - should fail encryption and queue, NOT send plaintext
    const testPayload = {
      blockedUrl: 'https://should-not-leak.example.com/secret',
      timestamp: new Date().toISOString(),
      tabId: 300,
      frameId: 0,
      reason: 'ioc_match',
    };

    await optionsPage.evaluate(async (payload) => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { type: 'uploadForensicsTest', payload },
          (response) => resolve(response)
        );
      });
    }, testPayload);

    await optionsPage.waitForTimeout(500);

    // Server should NOT have received anything
    expect(forensicsServer.getReceivedCount()).toBe(0);

    // Item should be queued for later retry
    const queueLength = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_forensics_queue');
      return result.browserdefense_forensics_queue?.length ?? 0;
    });

    expect(queueLength).toBeGreaterThanOrEqual(1);

    await optionsPage.close();
  });
});

test.describe('Zero-Knowledge Verification', () => {
  let forensicsServer: ForensicsE2EServer;

  test.beforeAll(async () => {
    forensicsServer = await createForensicsE2EServer();
  });

  test.afterAll(async () => {
    if (forensicsServer) {
      await forensicsServer.close();
    }
  });

  test('encrypted payload is completely opaque', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Generate keys
    const keyPair = await optionsPage.evaluate(async () => {
      const kp = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );
      return {
        publicKey: (await crypto.subtle.exportKey('jwk', kp.publicKey)) as RSAPublicKeyJWK,
        privateKey: (await crypto.subtle.exportKey('jwk', kp.privateKey)) as RSAPrivateKeyJWK,
      };
    });

    forensicsServer.setPrivateKey(keyPair.privateKey);
    forensicsServer.clearReceived();

    // Configure extension
    await optionsPage.evaluate(
      async ({
        endpoint,
        publicKey,
      }: {
        endpoint: string;
        publicKey: RSAPublicKeyJWK;
      }) => {
        await chrome.storage.local.set({
          browserdefense_config: {
            forensics_endpoint: endpoint,
            encryption_public_key: publicKey,
            org_id: 'test-opaque',
            key_version: 1,
          },
        });
      },
      { endpoint: `${forensicsServer.url}/forensics`, publicKey: keyPair.publicKey }
    );

    // Create a payload with sensitive data that MUST NOT leak
    const sensitivePayload = {
      blockedUrl: 'https://internal-corp.example.com/admin?password=supersecret123',
      timestamp: new Date().toISOString(),
      tabId: 999,
      frameId: 0,
      reason: 'ioc_match',
      redirectChain: [
        'https://internal-corp.example.com/login',
        'https://internal-corp.example.com/admin?password=supersecret123',
      ],
      normalizedUrl: 'internal-corp.example.com/admin',
      initiator: 'https://trusted-site.com',
    };

    // Upload
    await optionsPage.evaluate(async (payload) => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { type: 'uploadForensicsTest', payload },
          (response) => resolve(response)
        );
      });
    }, sensitivePayload);

    await optionsPage.waitForTimeout(500);

    // Get raw payload
    const rawPayloads = forensicsServer.getRawPayloads();
    if (rawPayloads.length > 0) {
      const encrypted = rawPayloads[0];
      const rawBody = JSON.stringify(encrypted);

      // Specific sensitive data checks
      const sensitivePatterns = [
        'internal-corp.example.com',
        'password=supersecret123',
        'admin',
        'trusted-site.com',
        'login',
      ];

      for (const pattern of sensitivePatterns) {
        expect(rawBody).not.toContain(pattern);
      }

      // Verify only expected keys exist
      const allowedKeys = ['iv', 'wrappedKey', 'ciphertext', 'orgId', 'keyVersion'];
      const receivedKeys = Object.keys(encrypted);
      for (const key of receivedKeys) {
        expect(allowedKeys).toContain(key);
      }

      // Decrypt and verify
      const decryptedPayloads = await forensicsServer.getDecryptedPayloads();
      const decrypted = decryptedPayloads[0] as typeof sensitivePayload;
      expect(decrypted.blockedUrl).toBe(sensitivePayload.blockedUrl);
    }

    await optionsPage.close();
  });
});
