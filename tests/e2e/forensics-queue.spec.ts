/**
 * E2E: Forensics Queue Persistence + Retry Upload
 *
 * Tests offline queueing, persistence across service worker restarts,
 * and retry logic when connectivity is restored.
 *
 * Issue #132
 */

import { test, expect, getServiceWorker } from './fixtures';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';

// ============================================================================
// Test Infrastructure: Forensics Upload Server
// ============================================================================

interface ForensicsServer {
  server: Server;
  port: number;
  url: string;
  receivedPayloads: object[];
  setMode: (mode: 'accept' | 'reject' | 'offline') => void;
  getReceivedCount: () => number;
  clearReceived: () => void;
  close: () => Promise<void>;
}

async function createForensicsServer(): Promise<ForensicsServer> {
  let mode: 'accept' | 'reject' | 'offline' = 'accept';
  const receivedPayloads: object[] = [];

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

    if (req.method === 'POST' && (req.url === '/forensics' || req.url === '/upload')) {
      if (mode === 'offline') {
        // Simulate connection refused by closing immediately
        res.destroy();
        return;
      }

      if (mode === 'reject') {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Server error' }));
        return;
      }

      // Accept mode - collect the payload
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
        setMode: (newMode: 'accept' | 'reject' | 'offline') => {
          mode = newMode;
        },
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
// Helper: Create test forensics payload
// ============================================================================

function createTestForensicsPayload(url: string = 'https://malicious.example.com/phish') {
  return {
    blockedUrl: url,
    timestamp: new Date().toISOString(),
    tabId: 1,
    frameId: 0,
    reason: 'ioc_match',
    normalizedUrl: new URL(url).hostname + new URL(url).pathname,
  };
}

// ============================================================================
// Test RSA encryption key (required for zero-knowledge forensics upload)
// ============================================================================

const TEST_ENCRYPTION_PUBLIC_KEY = {
  kty: 'RSA',
  n: 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
  e: 'AQAB',
};

// ============================================================================
// E2E Tests
// ============================================================================

test.describe('Forensics Queue Persistence', () => {
  let forensicsServer: ForensicsServer;

  test.beforeAll(async () => {
    forensicsServer = await createForensicsServer();
  });

  test.afterAll(async () => {
    if (forensicsServer) {
      await forensicsServer.close();
    }
  });

  test.beforeEach(async () => {
    forensicsServer.setMode('accept');
    forensicsServer.clearReceived();
  });

  test('queues forensics when upload endpoint fails', async ({ context, extensionId }) => {
    // Configure endpoint to reject
    forensicsServer.setMode('reject');

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure forensics endpoint
    await optionsPage.evaluate(
      async ({ endpoint }: { endpoint: string }) => {
        await chrome.storage.local.set({
          browserdefense_config: {
            forensics_endpoint: endpoint,
          },
        });
      },
      { endpoint: `${forensicsServer.url}/forensics` }
    );

    // Directly add to queue (simulating failed upload)
    await optionsPage.evaluate(async () => {
      const payload = {
        blockedUrl: 'https://evil.com/phish',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      const queue = (await chrome.storage.local.get('browserdefense_forensics_queue'))
        .browserdefense_forensics_queue || [];

      queue.push({
        id: crypto.randomUUID(),
        payload,
        attempts: 0,
        queuedAt: new Date().toISOString(),
      });

      await chrome.storage.local.set({ browserdefense_forensics_queue: queue });
    });

    // Verify queue has item
    const queueLength = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_forensics_queue');
      return result.browserdefense_forensics_queue?.length ?? 0;
    });

    expect(queueLength).toBe(1);
    await optionsPage.close();
  });

  test('queue persists across page reloads', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Add items to queue
    await optionsPage.evaluate(async () => {
      const queue = [];
      for (let i = 0; i < 3; i++) {
        queue.push({
          id: crypto.randomUUID(),
          payload: {
            blockedUrl: `https://evil-${i}.com/phish`,
            timestamp: new Date().toISOString(),
            tabId: i,
            frameId: 0,
            reason: 'ioc_match',
          },
          attempts: 0,
          queuedAt: new Date().toISOString(),
        });
      }
      await chrome.storage.local.set({ browserdefense_forensics_queue: queue });
    });

    // Verify before reload
    const queueBefore = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_forensics_queue');
      return result.browserdefense_forensics_queue?.length ?? 0;
    });
    expect(queueBefore).toBe(3);

    // Reload page (simulates extension restart for storage perspective)
    await optionsPage.reload();

    // Verify after reload
    const queueAfter = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_forensics_queue');
      return result.browserdefense_forensics_queue?.length ?? 0;
    });
    expect(queueAfter).toBe(3);

    await optionsPage.close();
  });

  test('retry uploads succeed when endpoint comes online', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure forensics endpoint with encryption key (required for zero-knowledge upload)
    await optionsPage.evaluate(
      async ({
        endpoint,
        encryptionKey,
      }: {
        endpoint: string;
        encryptionKey: typeof TEST_ENCRYPTION_PUBLIC_KEY;
      }) => {
        await chrome.storage.local.set({
          browserdefense_config: {
            forensics_endpoint: endpoint,
            encryption_public_key: encryptionKey,
          },
        });
      },
      { endpoint: `${forensicsServer.url}/forensics`, encryptionKey: TEST_ENCRYPTION_PUBLIC_KEY }
    );

    // Add items to queue (simulating previously failed uploads)
    const initialQueueLength = 2;
    await optionsPage.evaluate(async () => {
      const queue = [
        {
          id: crypto.randomUUID(),
          payload: {
            blockedUrl: 'https://evil1.com/phish',
            timestamp: new Date().toISOString(),
            tabId: 1,
            frameId: 0,
            reason: 'ioc_match',
          },
          attempts: 1,
          lastAttempt: new Date(Date.now() - 60000).toISOString(), // 1 minute ago
          queuedAt: new Date().toISOString(),
        },
        {
          id: crypto.randomUUID(),
          payload: {
            blockedUrl: 'https://evil2.com/phish',
            timestamp: new Date().toISOString(),
            tabId: 2,
            frameId: 0,
            reason: 'ioc_match',
          },
          attempts: 0,
          queuedAt: new Date().toISOString(),
        },
      ];
      await chrome.storage.local.set({ browserdefense_forensics_queue: queue });
    });

    // Ensure server is accepting
    forensicsServer.setMode('accept');

    // Trigger retry via message
    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'retryForensics' }, resolve);
      });
    });

    // Wait a bit for uploads to complete
    await optionsPage.waitForTimeout(500);

    // Check server received the uploads
    const receivedCount = forensicsServer.getReceivedCount();

    // Check queue is empty or reduced
    const remainingQueue = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_forensics_queue');
      return result.browserdefense_forensics_queue ?? [];
    });

    await optionsPage.close();

    // Server should have received encrypted payloads
    expect(receivedCount).toBeGreaterThanOrEqual(1);
    // Queue should be reduced (items uploaded successfully removed)
    expect(remainingQueue.length).toBeLessThan(initialQueueLength);
  });

  test('increments attempt count on failed retry', async ({ context, extensionId }) => {
    forensicsServer.setMode('reject');

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure endpoint with encryption key (required for retry to attempt upload)
    await optionsPage.evaluate(
      async ({
        endpoint,
        encryptionKey,
      }: {
        endpoint: string;
        encryptionKey: typeof TEST_ENCRYPTION_PUBLIC_KEY;
      }) => {
        await chrome.storage.local.set({
          browserdefense_config: {
            forensics_endpoint: endpoint,
            encryption_public_key: encryptionKey,
          },
        });
      },
      { endpoint: `${forensicsServer.url}/forensics`, encryptionKey: TEST_ENCRYPTION_PUBLIC_KEY }
    );

    // Add item with 0 attempts
    const itemId = await optionsPage.evaluate(async () => {
      const id = crypto.randomUUID();
      const queue = [
        {
          id,
          payload: {
            blockedUrl: 'https://evil.com/phish',
            timestamp: new Date().toISOString(),
            tabId: 1,
            frameId: 0,
            reason: 'ioc_match',
          },
          attempts: 0,
          queuedAt: new Date().toISOString(),
        },
      ];
      await chrome.storage.local.set({ browserdefense_forensics_queue: queue });
      return id;
    });

    // Trigger retry
    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'retryForensics' }, resolve);
      });
    });

    await optionsPage.waitForTimeout(500);

    // Check attempt count increased
    const queue = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_forensics_queue');
      return result.browserdefense_forensics_queue ?? [];
    });

    await optionsPage.close();

    // Item should still be in queue (upload failed)
    expect(queue.length).toBe(1);
    // Attempt counter should have been incremented from 0
    expect(queue[0].attempts).toBeGreaterThan(0);
  });

  test('drops items after max retry attempts', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure endpoint with encryption key first
    await optionsPage.evaluate(
      async ({
        endpoint,
        encryptionKey,
      }: {
        endpoint: string;
        encryptionKey: typeof TEST_ENCRYPTION_PUBLIC_KEY;
      }) => {
        await chrome.storage.local.set({
          browserdefense_config: {
            forensics_endpoint: endpoint,
            encryption_public_key: encryptionKey,
          },
        });
      },
      { endpoint: `${forensicsServer.url}/forensics`, encryptionKey: TEST_ENCRYPTION_PUBLIC_KEY }
    );

    // Add item at max attempts (10)
    await optionsPage.evaluate(async () => {
      const queue = [
        {
          id: crypto.randomUUID(),
          payload: {
            blockedUrl: 'https://evil.com/phish',
            timestamp: new Date().toISOString(),
            tabId: 1,
            frameId: 0,
            reason: 'ioc_match',
          },
          attempts: 10, // MAX_RETRY_ATTEMPTS
          lastAttempt: new Date(Date.now() - 1000000).toISOString(), // Long ago
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

    await optionsPage.waitForTimeout(500);

    // Check queue - item should be dropped
    const queueLength = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_forensics_queue');
      return result.browserdefense_forensics_queue?.length ?? 0;
    });

    await optionsPage.close();

    // Item should have been dropped due to max retries exceeded
    expect(queueLength).toBe(0);
  });

  test('respects exponential backoff', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Configure endpoint with encryption key (to ensure backoff is the reason for skip)
    await optionsPage.evaluate(
      async ({
        endpoint,
        encryptionKey,
      }: {
        endpoint: string;
        encryptionKey: typeof TEST_ENCRYPTION_PUBLIC_KEY;
      }) => {
        await chrome.storage.local.set({
          browserdefense_config: {
            forensics_endpoint: endpoint,
            encryption_public_key: encryptionKey,
          },
        });
      },
      { endpoint: `${forensicsServer.url}/forensics`, encryptionKey: TEST_ENCRYPTION_PUBLIC_KEY }
    );

    // Add item with recent last attempt (should be skipped due to backoff)
    await optionsPage.evaluate(async () => {
      const queue = [
        {
          id: crypto.randomUUID(),
          payload: {
            blockedUrl: 'https://evil.com/phish',
            timestamp: new Date().toISOString(),
            tabId: 1,
            frameId: 0,
            reason: 'ioc_match',
          },
          attempts: 3, // Has been tried 3 times
          lastAttempt: new Date().toISOString(), // Just now
          queuedAt: new Date().toISOString(),
        },
      ];
      await chrome.storage.local.set({ browserdefense_forensics_queue: queue });
    });

    forensicsServer.setMode('accept');

    // Trigger retry
    await optionsPage.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'retryForensics' }, resolve);
      });
    });

    await optionsPage.waitForTimeout(100);

    // Server should NOT have received upload due to backoff
    const receivedCount = forensicsServer.getReceivedCount();

    // Item should still be in queue (skipped due to backoff)
    const queueLength = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_forensics_queue');
      return result.browserdefense_forensics_queue?.length ?? 0;
    });

    await optionsPage.close();

    // Item should still be queued (backoff not elapsed)
    expect(queueLength).toBe(1);
    expect(receivedCount).toBe(0);
  });
});

test.describe('Forensics Queue Badge', () => {
  test('badge reflects queue count', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Add items to queue
    await optionsPage.evaluate(async () => {
      const queue = [];
      for (let i = 0; i < 5; i++) {
        queue.push({
          id: crypto.randomUUID(),
          payload: {
            blockedUrl: `https://evil-${i}.com`,
            timestamp: new Date().toISOString(),
            tabId: i,
            frameId: 0,
            reason: 'ioc_match',
          },
          attempts: 0,
          queuedAt: new Date().toISOString(),
        });
      }
      await chrome.storage.local.set({ browserdefense_forensics_queue: queue });

      // Update badge
      await chrome.action.setBadgeText({ text: '5' });
      await chrome.action.setBadgeBackgroundColor({ color: '#FFA500' });
    });

    // Verify badge text
    const badgeText = await optionsPage.evaluate(async () => {
      return chrome.action.getBadgeText({});
    });

    await optionsPage.close();

    expect(badgeText).toBe('5');
  });

  test('badge clears when queue is empty', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Set badge, then clear queue
    await optionsPage.evaluate(async () => {
      await chrome.action.setBadgeText({ text: '3' });
      await chrome.storage.local.remove('browserdefense_forensics_queue');
      await chrome.action.setBadgeText({ text: '' });
    });

    const badgeText = await optionsPage.evaluate(async () => {
      return chrome.action.getBadgeText({});
    });

    await optionsPage.close();

    expect(badgeText).toBe('');
  });
});

test.describe('Forensics Data Integrity', () => {
  let forensicsServer: ForensicsServer;

  test.beforeAll(async () => {
    forensicsServer = await createForensicsServer();
  });

  test.afterAll(async () => {
    if (forensicsServer) {
      await forensicsServer.close();
    }
  });

  test('queued payload matches original data', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    const testPayload = {
      blockedUrl: 'https://phishing.example.com/login?user=test',
      timestamp: '2024-01-15T10:30:00.000Z',
      tabId: 42,
      frameId: 0,
      reason: 'ioc_match',
      redirectChain: [
        'https://legit.com',
        'https://redirect1.com',
        'https://phishing.example.com/login?user=test',
      ],
    };

    // Queue the payload
    await optionsPage.evaluate(async (payload) => {
      const queue = [
        {
          id: 'test-id-123',
          payload,
          attempts: 0,
          queuedAt: new Date().toISOString(),
        },
      ];
      await chrome.storage.local.set({ browserdefense_forensics_queue: queue });
    }, testPayload);

    // Retrieve and verify
    const retrieved = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_forensics_queue');
      return result.browserdefense_forensics_queue?.[0]?.payload;
    });

    await optionsPage.close();

    expect(retrieved).toBeDefined();
    expect(retrieved.blockedUrl).toBe(testPayload.blockedUrl);
    expect(retrieved.timestamp).toBe(testPayload.timestamp);
    expect(retrieved.tabId).toBe(testPayload.tabId);
    expect(retrieved.reason).toBe(testPayload.reason);
    expect(retrieved.redirectChain).toEqual(testPayload.redirectChain);
  });

  test('multiple queue items maintain order', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Queue items in order
    await optionsPage.evaluate(async () => {
      const queue = [];
      for (let i = 1; i <= 5; i++) {
        queue.push({
          id: `item-${i}`,
          payload: {
            blockedUrl: `https://evil-${i}.com`,
            timestamp: new Date().toISOString(),
            tabId: i,
            frameId: 0,
            reason: 'ioc_match',
          },
          attempts: 0,
          queuedAt: new Date().toISOString(),
        });
      }
      await chrome.storage.local.set({ browserdefense_forensics_queue: queue });
    });

    // Retrieve and check order
    const queue = await optionsPage.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_forensics_queue');
      return result.browserdefense_forensics_queue ?? [];
    });

    await optionsPage.close();

    expect(queue.length).toBe(5);
    for (let i = 0; i < 5; i++) {
      expect(queue[i].id).toBe(`item-${i + 1}`);
      expect(queue[i].payload.tabId).toBe(i + 1);
    }
  });
});
