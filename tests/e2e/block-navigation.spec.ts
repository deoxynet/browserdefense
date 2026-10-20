/**
 * E2E: Block/Allow Navigation
 *
 * Validates that the blocking mechanism correctly:
 * 1. Blocks navigation to URLs matching the blocklist
 * 2. Allows navigation to safe URLs
 * 3. Displays the block page with correct information
 *
 * Issue #129
 */

import { test, expect, getServiceWorker } from './fixtures';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';
import {
  hashUrl,
  bytesToHex,
  createBinaryBlocklist,
  E2E_E2E_TEST_SALT,
} from '../helpers/hashing';

// ============================================================================
// Local Test Server
// ============================================================================

interface TestServer {
  server: Server;
  port: number;
  baseUrl: string;
  close: () => Promise<void>;
}

async function createTestServer(): Promise<TestServer> {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    res.setHeader('Access-Control-Allow-Origin', '*');

    if (req.url === '/safe') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><head><title>Safe Page</title></head><body><h1>Safe Page</h1></body></html>');
    } else if (req.url === '/blocked') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(
        '<html><head><title>Blocked Page</title></head><body><h1>This should be blocked</h1></body></html>'
      );
    } else if (req.url === '/another-blocked') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><head><title>Another Blocked</title></head><body><h1>Also blocked</h1></body></html>');
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<html><head><title>Test</title></head><body><h1>Path: ${req.url}</h1></body></html>`);
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

// ============================================================================
// E2E Tests
// ============================================================================

test.describe('Block/Allow Navigation', () => {
  let testServer: TestServer;
  // Use shared salt constant from test helpers

  // Create a full valid config (config validation requires all fields)
  const createTestConfig = (salt: string) => ({
    org_id: 'e2e-test-org',
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

  test.beforeAll(async () => {
    testServer = await createTestServer();
  });

  test.afterAll(async () => {
    if (testServer) {
      await testServer.close();
    }
  });

  test.afterEach(async ({ context }) => {
    // Close all pages except the background service worker to ensure clean state
    for (const page of context.pages()) {
      if (!page.url().includes('service_worker')) {
        await page.close().catch(() => {});
      }
    }
    // Small delay to let cleanup complete
    await new Promise((resolve) => setTimeout(resolve, 100));
  });

  test.beforeEach(async ({ context, extensionId }) => {
    // Set up the extension with config and blocklist before each test
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Compute hashes for URLs we want to block
    const blockedUrl1 = `${testServer.baseUrl}/blocked`;
    const blockedUrl2 = `${testServer.baseUrl}/another-blocked`;

    const hash1 = await hashUrl(blockedUrl1, E2E_TEST_SALT);
    const hash2 = await hashUrl(blockedUrl2, E2E_TEST_SALT);

    // Create binary blocklist
    const blocklistData = createBinaryBlocklist([hash1, hash2]);

    // Set full valid config and blocklist in extension storage
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
      { config: createTestConfig(E2E_TEST_SALT), blocklist: blocklistData }
    );

    // Verify blocking is active by checking a blocked URL (with timeout)
    const blockedUrl = `${testServer.baseUrl}/blocked`;
    const startTime = Date.now();
    while (Date.now() - startTime < 2000) {
      try {
        const result = (await optionsPage.evaluate(async (url: string) => {
          return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Timeout')), 500);
            chrome.runtime.sendMessage({ type: 'checkBlocked', url }, (response) => {
              clearTimeout(timeout);
              resolve(response);
            });
          });
        }, blockedUrl)) as { blocked: boolean };

        if (result?.blocked) {
          break;
        }
      } catch {
        // Ignore timeout errors
      }
      await optionsPage.waitForTimeout(100);
    }

    await optionsPage.close();
  });

  test('blocks navigation to URL in blocklist', async ({ context, extensionId }) => {
    const page = await context.newPage();
    const blockedUrl = `${testServer.baseUrl}/blocked`;

    // Navigate to blocked URL - may throw ERR_ABORTED if blocking intercepts
    try {
      await page.goto(blockedUrl, { waitUntil: 'domcontentloaded', timeout: 5000 });
    } catch {
      // Navigation may be aborted when blocking intercepts
    }

    // Wait for redirect to block page with polling
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    // Wait for page to be fully loaded
    try {
      await page.waitForLoadState('load', { timeout: 2000 });
    } catch {
      // Ignore if page doesn't fully load
    }

    // Should be redirected to block page
    const currentUrl = page.url();
    expect(currentUrl).toContain('blocked/blocked.html');
    expect(currentUrl).toContain(`url=${encodeURIComponent(blockedUrl)}`);

    // Block page should show BrowserDefense branding
    await expect(page.locator('body')).toContainText(/block/i);

    await page.close();
  });

  test('allows navigation to URL not in blocklist', async ({ context }) => {
    const page = await context.newPage();
    const safeUrl = `${testServer.baseUrl}/safe`;

    // Navigate to safe URL
    await page.goto(safeUrl);

    // Should load normally
    expect(page.url()).toBe(safeUrl);
    await expect(page.locator('h1')).toHaveText('Safe Page');

    await page.close();
  });

  test('blocks multiple different URLs in blocklist', async ({ context }) => {
    const page = await context.newPage();

    // Test first blocked URL
    const blockedUrl1 = `${testServer.baseUrl}/blocked`;
    try {
      await page.goto(blockedUrl1, { waitUntil: 'domcontentloaded' });
    } catch {
      // Navigation may be aborted
    }
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    // Test second blocked URL
    const blockedUrl2 = `${testServer.baseUrl}/another-blocked`;
    try {
      await page.goto(blockedUrl2, { waitUntil: 'domcontentloaded' });
    } catch {
      // Navigation may be aborted
    }
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
      expect(page.url()).toContain(encodeURIComponent('another-blocked'));
    }).toPass({ timeout: 5000 });

    await page.close();
  });

  test('block page displays blocked URL', async ({ context }) => {
    const page = await context.newPage();
    const blockedUrl = `${testServer.baseUrl}/blocked`;

    try {
      await page.goto(blockedUrl, { waitUntil: 'domcontentloaded' });
    } catch {
      // Navigation may be aborted
    }

    // Wait for redirect to block page
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    // Block page should display the blocked URL (sanitized)
    // Check that it's somewhere on the page
    const bodyText = await page.locator('body').textContent();
    expect(bodyText).toContain('127.0.0.1');

    await page.close();
  });

  test('external safe sites are not blocked', async ({ context }) => {
    const page = await context.newPage();

    // Navigate to a real external site
    await page.goto('https://example.com');

    // Should load normally (not blocked)
    expect(page.url()).toContain('example.com');
    await expect(page.locator('h1')).toHaveText('Example Domain');

    await page.close();
  });
});

test.describe('Blocking Edge Cases', () => {
  let testServer: TestServer;
  // Use shared E2E_E2E_TEST_SALT from test helpers

  // Create a full valid config (config validation requires all fields)
  const createTestConfig = (salt: string) => ({
    org_id: 'e2e-test-org',
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

  test.beforeAll(async () => {
    testServer = await createTestServer();
  });

  test.afterAll(async () => {
    if (testServer) {
      await testServer.close();
    }
  });

  test('path variations are handled correctly', async ({ context, extensionId }) => {
    // Set up blocklist with specific path
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    const blockedUrl = `${testServer.baseUrl}/blocked`;
    const hash = await hashUrl(blockedUrl, E2E_TEST_SALT);
    const blocklistData = createBinaryBlocklist([hash]);

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
      { config: createTestConfig(E2E_TEST_SALT), blocklist: blocklistData }
    );

    // Wait for blocking to be active
    let attempts = 0;
    while (attempts < 10) {
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

    const page = await context.newPage();

    // Exact path should be blocked
    try {
      await page.goto(`${testServer.baseUrl}/blocked`, { waitUntil: 'domcontentloaded' });
    } catch {
      // Navigation may be aborted
    }
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    // Different path should NOT be blocked
    await page.goto(`${testServer.baseUrl}/safe`);
    expect(page.url()).toBe(`${testServer.baseUrl}/safe`);

    await page.close();
  });

  test('query parameters do not affect blocking', async ({ context, extensionId }) => {
    // Set up blocklist
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    const blockedUrl = `${testServer.baseUrl}/blocked`;
    const hash = await hashUrl(blockedUrl, E2E_TEST_SALT);
    const blocklistData = createBinaryBlocklist([hash]);

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
      { config: createTestConfig(E2E_TEST_SALT), blocklist: blocklistData }
    );

    // Wait for blocking to be active
    let attempts = 0;
    while (attempts < 10) {
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

    const page = await context.newPage();

    // URL with query params should still be blocked (query not included in hash)
    try {
      await page.goto(`${testServer.baseUrl}/blocked?foo=bar&baz=qux`, { waitUntil: 'domcontentloaded' });
    } catch {
      // Navigation may be aborted
    }
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    await page.close();
  });

  test('blocking works after page reload', async ({ context, extensionId }) => {
    // Set up blocklist
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    const blockedUrl = `${testServer.baseUrl}/blocked`;
    const hash = await hashUrl(blockedUrl, E2E_TEST_SALT);
    const blocklistData = createBinaryBlocklist([hash]);

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
      { config: createTestConfig(E2E_TEST_SALT), blocklist: blocklistData }
    );

    // Wait for blocking to be active
    let attempts = 0;
    while (attempts < 10) {
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

    const page = await context.newPage();

    // First navigation - blocked
    try {
      await page.goto(`${testServer.baseUrl}/blocked`, { waitUntil: 'domcontentloaded' });
    } catch {
      // Navigation may be aborted
    }
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    // Go to safe page
    await page.goto(`${testServer.baseUrl}/safe`);
    expect(page.url()).toBe(`${testServer.baseUrl}/safe`);

    // Navigate back to blocked URL - should still be blocked
    try {
      await page.goto(`${testServer.baseUrl}/blocked`, { waitUntil: 'domcontentloaded' });
    } catch {
      // Navigation may be aborted
    }
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    await page.close();
  });
});

test.describe('Blocking Without Config', () => {
  test('navigation allowed when no config is set', async ({ context, extensionId }) => {
    // Clear any existing config
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    await optionsPage.evaluate(async () => {
      await chrome.storage.local.remove(['browserdefense_config', 'browserdefense_blocklist']);
      await new Promise<void>((resolve) => {
        chrome.runtime.sendMessage({ type: 'reloadBlocklist' }, () => resolve());
      });
    });
    await optionsPage.waitForTimeout(500);
    await optionsPage.close();

    const page = await context.newPage();

    // Navigation should work without blocking
    await page.goto('https://example.com');
    expect(page.url()).toContain('example.com');

    await page.close();
  });

  test('navigation allowed when blocklist is empty', async ({ context, extensionId }) => {
    // Set config but empty blocklist
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    await optionsPage.evaluate(async () => {
      await chrome.storage.local.set({
        browserdefense_config: {
          ioc_salt: 'test-salt',
          ioc_scope: 'HOST_PATH',
        },
        browserdefense_blocklist: '', // Empty blocklist
      });
      await new Promise<void>((resolve) => {
        chrome.runtime.sendMessage({ type: 'reloadBlocklist' }, () => resolve());
      });
    });
    await optionsPage.waitForTimeout(500);
    await optionsPage.close();

    const page = await context.newPage();

    // Navigation should work without blocking
    await page.goto('https://example.com');
    expect(page.url()).toContain('example.com');

    await page.close();
  });
});

test.describe('Blocking Status API', () => {
  let testServer: TestServer;
  // Use shared E2E_E2E_TEST_SALT from test helpers

  // Create a full valid config (config validation requires all fields)
  const createTestConfig = (salt: string) => ({
    org_id: 'e2e-test-org',
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

  test.beforeAll(async () => {
    testServer = await createTestServer();
  });

  test.afterAll(async () => {
    if (testServer) {
      await testServer.close();
    }
  });

  test('checkBlocked API returns correct status', async ({ context, extensionId }) => {
    // Set up blocklist
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    const blockedUrl = `${testServer.baseUrl}/blocked`;
    const safeUrl = `${testServer.baseUrl}/safe`;
    const hash = await hashUrl(blockedUrl, E2E_TEST_SALT);
    const blocklistData = createBinaryBlocklist([hash]);

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
      { config: createTestConfig(E2E_TEST_SALT), blocklist: blocklistData }
    );
    await optionsPage.waitForTimeout(500);

    // Test checkBlocked API for blocked URL
    const blockedResult = await optionsPage.evaluate(async (url: string) => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'checkBlocked', url }, (response) => {
          resolve(response);
        });
      });
    }, blockedUrl);

    expect(blockedResult).toEqual({ blocked: true });

    // Test checkBlocked API for safe URL
    const safeResult = await optionsPage.evaluate(async (url: string) => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'checkBlocked', url }, (response) => {
          resolve(response);
        });
      });
    }, safeUrl);

    expect(safeResult).toEqual({ blocked: false });

    await optionsPage.close();
  });
});
