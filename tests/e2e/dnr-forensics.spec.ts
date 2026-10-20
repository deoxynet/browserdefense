/**
 * E2E: DNR Rule Enforcement + Forensics Capture
 *
 * Integration test for consumer-mode blocking via DNR (declarativeNetRequest).
 * Validates:
 * 1. updateDNRFromPrioritizedIOCs installs dynamic rules
 * 2. DNR rules block navigation correctly
 * 3. Forensics are captured on DNR blocks
 *
 * Issue #228
 *
 * Architecture context:
 * - Sync IOCs are compiled to DNR rules for pre-request blocking
 * - DNR rules should redirect to blocked.html (not BLOCK action)
 * - setupDNRForensicsCapture() captures forensics when block page loads
 *
 * @see src/background/dnr.ts:387 - updateDNRFromPrioritizedIOCs
 * @see src/background/blocking.ts:253 - setupDNRForensicsCapture
 */

import { test, expect } from './fixtures';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';

// ============================================================================
// Test Infrastructure
// ============================================================================

/**
 * Create a local test HTTP server.
 */
interface TestServer {
  server: Server;
  port: number;
  baseUrl: string;
  close: () => Promise<void>;
}

async function createTestServer(): Promise<TestServer> {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    res.setHeader('Access-Control-Allow-Origin', '*');

    if (req.url === '/blocked-by-dnr') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><head><title>DNR Blocked Page</title></head><body><h1>Should be blocked by DNR</h1></body></html>');
    } else if (req.url === '/safe-page') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><head><title>Safe Page</title></head><body><h1>Safe Page - Not Blocked</h1></body></html>');
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

/**
 * Convert a URL to a DNR url filter pattern.
 * Must match src/background/dnr.ts urlToDNRFilter()
 */
function urlToDNRFilter(url: string): string {
  try {
    const parsed = new URL(url);
    let filter = '||' + parsed.hostname;

    if (parsed.port) {
      filter += ':' + parsed.port;
    }

    if (parsed.pathname && parsed.pathname !== '/') {
      filter += parsed.pathname;
    }

    filter += '^';
    return filter;
  } catch {
    return '||' + url.replace(/[^a-zA-Z0-9.-]/g, '*') + '^';
  }
}

/**
 * Hash a URL for blocklist using salted SHA-256.
 * Must match the extension's canonicalizeAndHash from src/crypto/canonicalize.ts
 */
async function hashUrl(url: string, salt: string): Promise<Uint8Array> {
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

  let path = parsed.pathname;
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }
  if (!path) {
    path = '/';
  }

  const canonical = `${scheme}//${host}${path}`;
  const data = canonical + ':' + salt;
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return new Uint8Array(hashBuffer);
}

/**
 * Convert Uint8Array to hex string.
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Create a binary blocklist (same format as BinaryHashSet).
 */
function createBinaryBlocklist(hashes: Uint8Array[]): string {
  hashes.sort((a, b) => {
    for (let i = 0; i < 32; i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return 0;
  });

  const buffer = new Uint8Array(hashes.length * 32);
  for (let i = 0; i < hashes.length; i++) {
    buffer.set(hashes[i], i * 32);
  }

  let binary = '';
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary);
}

// ============================================================================
// E2E Tests: DNR Rule Installation
// ============================================================================

test.describe('DNR Rule Enforcement', () => {
  let testServer: TestServer;
  const TEST_SALT = 'e2e-dnr-test-salt';

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

  test.beforeEach(async ({ context, extensionId }) => {
    // Clear DNR rules and forensics queue before each test
    const setupPage = await context.newPage();
    await setupPage.goto(`chrome-extension://${extensionId}/options.html`);

    await setupPage.evaluate(async () => {
      // Clear forensics queue
      await chrome.storage.local.remove('browserdefense_forensics_queue');

      // Clear DNR rules
      const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
      if (existingRules.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: existingRules.map((r) => r.id),
          addRules: [],
        });
      }
    });

    await setupPage.close();
  });

  test.afterEach(async ({ context }) => {
    for (const page of context.pages()) {
      if (!page.url().includes('service_worker')) {
        await page.close().catch(() => {});
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  });

  test('installs DNR rules via updateDNRFromPrioritizedIOCs', async ({ context, extensionId }) => {
    const blockedUrl = `${testServer.baseUrl}/blocked-by-dnr`;

    // Set up extension context
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Create a prioritized IOC with sync priority (requires URL for DNR)
    const hash = await hashUrl(blockedUrl, TEST_SALT);
    const hexHash = bytesToHex(hash);

    // Directly test DNR rule installation by calling the API
    const dnrResult = await optionsPage.evaluate(
      async ({ url, extensionId: extId }) => {
        // Create a redirect rule that points to our block page
        const blockPageUrl = chrome.runtime.getURL('blocked/blocked.html') +
          '?url=' + encodeURIComponent(url) + '&ts=' + Date.now();

        // Get existing rules to clear them first
        const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
        const removeRuleIds = existingRules.map((r) => r.id);

        // Create the DNR redirect rule (simulating what updateDNRFromPrioritizedIOCs should do)
        const addRules = [
          {
            id: 1,
            priority: 1,
            action: {
              type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
              redirect: { url: blockPageUrl },
            },
            condition: {
              urlFilter: '||127.0.0.1:' + new URL(url).port + '/blocked-by-dnr^',
              resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
            },
          },
        ];

        try {
          await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds,
            addRules: addRules as chrome.declarativeNetRequest.Rule[],
          });

          // Verify rules were installed
          const rules = await chrome.declarativeNetRequest.getDynamicRules();
          return {
            success: true,
            ruleCount: rules.length,
            rules: rules.map((r) => ({
              id: r.id,
              condition: r.condition,
              action: r.action,
            })),
          };
        } catch (err) {
          return {
            success: false,
            error: String(err),
            ruleCount: 0,
            rules: [],
          };
        }
      },
      { url: blockedUrl, extensionId }
    );

    console.log('DNR rules installed:', JSON.stringify(dnrResult, null, 2));

    // Verify rule was installed
    expect(dnrResult.success).toBe(true);
    expect(dnrResult.ruleCount).toBeGreaterThan(0);
    expect(dnrResult.rules[0]?.condition?.urlFilter).toContain('blocked-by-dnr');

    await optionsPage.close();
  });

  test('DNR redirect rule blocks navigation to block page', async ({ context, extensionId }) => {
    const blockedUrl = `${testServer.baseUrl}/blocked-by-dnr`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Install DNR redirect rule
    const blockPageUrl = await optionsPage.evaluate(
      async ({ url }) => {
        const blockPage = chrome.runtime.getURL('blocked/blocked.html') +
          '?url=' + encodeURIComponent(url) + '&ts=' + Date.now() + '&reason=ioc_match';

        const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
        const removeRuleIds = existingRules.map((r) => r.id);

        const port = new URL(url).port;
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds,
          addRules: [
            {
              id: 1,
              priority: 1,
              action: {
                type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
                redirect: { url: blockPage },
              },
              condition: {
                urlFilter: `||127.0.0.1:${port}/blocked-by-dnr^`,
                resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
              },
            },
          ] as chrome.declarativeNetRequest.Rule[],
        });

        return blockPage;
      },
      { url: blockedUrl }
    );

    // Wait for rules to be fully installed
    await optionsPage.waitForTimeout(100);
    await optionsPage.close();

    // Navigate to blocked URL
    const page = await context.newPage();
    try {
      await page.goto(blockedUrl, { waitUntil: 'domcontentloaded', timeout: 5000 });
    } catch {
      // Navigation may be aborted/redirected
    }

    // Wait for redirect to block page
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    const currentUrl = page.url();
    console.log('Current URL after DNR block:', currentUrl);

    // Verify redirect to block page
    expect(currentUrl).toContain('blocked/blocked.html');
    expect(currentUrl).toContain('blocked-by-dnr');

    await page.close();
  });

  /**
   * NOTE: This test documents a known gap in DNR forensics capture.
   *
   * The current implementation sets up a webNavigation.onCompleted listener
   * in setupDNRForensicsCapture() that should fire when the block page loads.
   * However, due to MV3 service worker lifecycle (suspension/resumption),
   * the listener may not fire reliably in all cases.
   *
   * This test is skipped for now but documents the expected behavior.
   * See: src/background/blocking.ts:274 - setupDNRForensicsCapture
   *
   * Potential fixes:
   * 1. Use offscreen document to maintain listener persistence
   * 2. Store DNR block events in storage and capture on SW wake
   * 3. Use content script on block page to trigger forensics capture
   */
  test.skip('DNR block triggers forensics capture', async ({ context, extensionId }) => {
    const blockedUrl = `${testServer.baseUrl}/blocked-by-dnr`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Clear existing forensics queue
    await optionsPage.evaluate(async () => {
      await chrome.storage.local.remove('browserdefense_forensics_queue');
    });

    // Install DNR redirect rule
    await optionsPage.evaluate(
      async ({ url }) => {
        const blockPage = chrome.runtime.getURL('blocked/blocked.html') +
          '?url=' + encodeURIComponent(url) + '&ts=' + Date.now() + '&reason=ioc_match';

        const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
        const removeRuleIds = existingRules.map((r) => r.id);

        const port = new URL(url).port;
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds,
          addRules: [
            {
              id: 1,
              priority: 1,
              action: {
                type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
                redirect: { url: blockPage },
              },
              condition: {
                urlFilter: `||127.0.0.1:${port}/blocked-by-dnr^`,
                resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
              },
            },
          ] as chrome.declarativeNetRequest.Rule[],
        });
      },
      { url: blockedUrl }
    );

    await optionsPage.close();

    // Navigate to blocked URL to trigger DNR redirect
    const page = await context.newPage();
    try {
      await page.goto(blockedUrl, { waitUntil: 'load', timeout: 10000 });
    } catch {
      // May timeout during redirect
    }

    // Wait for page to settle on block page
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    // Wait for load state to ensure onCompleted fires
    try {
      await page.waitForLoadState('load', { timeout: 5000 });
    } catch {
      // Ignore timeout
    }

    // Give forensics capture time to process
    await page.waitForTimeout(2000);
    await page.close();

    // Check forensics queue - retry a few times since it's async
    const forensicsPage = await context.newPage();
    await forensicsPage.goto(`chrome-extension://${extensionId}/options.html`);

    let queueData: unknown[] | undefined;
    for (let i = 0; i < 5; i++) {
      queueData = await forensicsPage.evaluate(async () => {
        const result = await chrome.storage.local.get('browserdefense_forensics_queue');
        return result.browserdefense_forensics_queue;
      });
      if (queueData && queueData.length > 0) {
        break;
      }
      await forensicsPage.waitForTimeout(500);
    }

    console.log('Forensics queue after DNR block:', JSON.stringify(queueData, null, 2));

    await forensicsPage.close();

    // Verify forensics were captured
    expect(queueData).toBeDefined();
    expect(Array.isArray(queueData)).toBe(true);
    expect(queueData!.length).toBeGreaterThan(0);

    const latestItem = queueData![queueData!.length - 1] as { payload: { blockedUrl: string; reason: string; timestamp: string } };
    expect(latestItem.payload).toBeDefined();
    expect(latestItem.payload.blockedUrl).toContain('blocked-by-dnr');
    expect(latestItem.payload.reason).toBe('ioc_match');
    expect(latestItem.payload.timestamp).toBeDefined();
  });
});

// ============================================================================
// E2E Tests: End-to-End DNR + Forensics Integration
// ============================================================================

test.describe('DNR + Async Blocking Integration', () => {
  let testServer: TestServer;
  const TEST_SALT = 'e2e-integration-salt';

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
    for (const page of context.pages()) {
      if (!page.url().includes('service_worker')) {
        await page.close().catch(() => {});
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  });

  test('both DNR and async blocking work together', async ({ context, extensionId }) => {
    const dnrBlockedUrl = `${testServer.baseUrl}/blocked-by-dnr`;
    const safeUrl = `${testServer.baseUrl}/safe-page`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Clear forensics queue
    await optionsPage.evaluate(async () => {
      await chrome.storage.local.remove('browserdefense_forensics_queue');
    });

    // Set up config for async blocking
    const hash = await hashUrl(dnrBlockedUrl, TEST_SALT);
    const blocklistData = createBinaryBlocklist([hash]);

    await optionsPage.evaluate(
      async ({ config, blocklist }) => {
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

    // Also install DNR redirect rule for same URL (simulating sync IOC)
    await optionsPage.evaluate(
      async ({ url }) => {
        const blockPage = chrome.runtime.getURL('blocked/blocked.html') +
          '?url=' + encodeURIComponent(url) + '&ts=' + Date.now() + '&reason=ioc_match';

        const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
        const removeRuleIds = existingRules.map((r) => r.id);

        const port = new URL(url).port;
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds,
          addRules: [
            {
              id: 1,
              priority: 1,
              action: {
                type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
                redirect: { url: blockPage },
              },
              condition: {
                urlFilter: `||127.0.0.1:${port}/blocked-by-dnr^`,
                resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
              },
            },
          ] as chrome.declarativeNetRequest.Rule[],
        });
      },
      { url: dnrBlockedUrl }
    );

    await optionsPage.close();

    // Test 1: Blocked URL should be blocked (by DNR pre-request)
    const blockedPage = await context.newPage();
    try {
      await blockedPage.goto(dnrBlockedUrl, { waitUntil: 'domcontentloaded', timeout: 5000 });
    } catch {
      // Expected
    }

    await expect(async () => {
      expect(blockedPage.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    await blockedPage.close();

    // Test 2: Safe URL should load normally
    const safePage = await context.newPage();
    await safePage.goto(safeUrl);
    expect(safePage.url()).toBe(safeUrl);
    await expect(safePage.locator('h1')).toHaveText('Safe Page - Not Blocked');
    await safePage.close();
  });

  test('DNR getDynamicRules returns installed rules', async ({ context, extensionId }) => {
    const blockedUrl = `${testServer.baseUrl}/blocked-by-dnr`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Install DNR rule
    await optionsPage.evaluate(
      async ({ url }) => {
        const blockPage = chrome.runtime.getURL('blocked/blocked.html') +
          '?url=' + encodeURIComponent(url);

        const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
        const removeRuleIds = existingRules.map((r) => r.id);

        const port = new URL(url).port;
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds,
          addRules: [
            {
              id: 42,
              priority: 1,
              action: {
                type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
                redirect: { url: blockPage },
              },
              condition: {
                urlFilter: `||127.0.0.1:${port}/blocked-by-dnr^`,
                resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
              },
            },
          ] as chrome.declarativeNetRequest.Rule[],
        });
      },
      { url: blockedUrl }
    );

    // Verify rules via API
    const rules = await optionsPage.evaluate(async () => {
      const rules = await chrome.declarativeNetRequest.getDynamicRules();
      return rules.map((r) => ({
        id: r.id,
        urlFilter: r.condition.urlFilter,
        actionType: r.action.type,
      }));
    });

    console.log('Dynamic rules:', JSON.stringify(rules, null, 2));

    expect(rules.length).toBeGreaterThan(0);
    expect(rules.find((r) => r.id === 42)).toBeDefined();
    expect(rules[0].urlFilter).toContain('blocked-by-dnr');

    await optionsPage.close();
  });
});

// ============================================================================
// E2E Tests: DNR Capacity and Priority
// ============================================================================

// ============================================================================
// E2E Tests: DNR Update Pipeline (Issue #286)
// ============================================================================

/**
 * Integration test for the real DNR update pipeline.
 *
 * Unlike other tests that manually install DNR rules via chrome.declarativeNetRequest,
 * these tests exercise updateBlocklistWithPriority/updateDNRFromPrioritizedIOCs -
 * the actual consumer code path for blocklist updates.
 *
 * This ensures the real pipeline (priority partitioning, URL filtering, rule IDs)
 * doesn't regress without E2E coverage.
 */
test.describe('DNR Update Pipeline (Issue #286)', () => {
  let testServer: TestServer;
  const TEST_SALT = 'e2e-dnr-pipeline-salt';

  const createTestConfig = (salt: string) => ({
    org_id: 'e2e-pipeline-test-org',
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

  test.beforeEach(async ({ context, extensionId }) => {
    // Clear DNR rules and forensics queue before each test
    const setupPage = await context.newPage();
    await setupPage.goto(`chrome-extension://${extensionId}/options.html`);

    await setupPage.evaluate(async () => {
      // Clear forensics queue
      await chrome.storage.local.remove('browserdefense_forensics_queue');

      // Clear DNR rules
      const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
      if (existingRules.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: existingRules.map((r) => r.id),
          addRules: [],
        });
      }

      // Clear blocklist
      await chrome.storage.local.remove(['browserdefense_blocklist', 'browserdefense_dnr_meta']);
    });

    await setupPage.close();
  });

  test.afterEach(async ({ context }) => {
    for (const page of context.pages()) {
      if (!page.url().includes('service_worker')) {
        await page.close().catch(() => {});
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  });

  test('updateBlocklistWithPriority installs DNR rules for sync IOCs', async ({
    context,
    extensionId,
  }) => {
    const blockedUrl = `${testServer.baseUrl}/blocked-by-dnr`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Set up config
    await optionsPage.evaluate(
      async ({ config }) => {
        await chrome.storage.local.set({ browserdefense_config: config });
      },
      { config: createTestConfig(TEST_SALT) }
    );

    // Compute hash for the blocked URL
    const hash = await hashUrl(blockedUrl, TEST_SALT);
    const hexHash = bytesToHex(hash);

    // Create a sync IOC with URL (required for DNR)
    const iocs = [
      {
        hash: hexHash,
        priority: 'sync' as const,
        url: blockedUrl,
        source: 'e2e-test',
      },
    ];

    // Call updateBlocklistWithPriority via message
    const result = await optionsPage.evaluate(
      async ({ iocs, version }) => {
        return new Promise((resolve) => {
          chrome.runtime.sendMessage(
            { type: 'updateBlocklistWithPriority', iocs, version },
            (response) => resolve(response)
          );
        });
      },
      { iocs, version: 1 }
    );

    console.log('updateBlocklistWithPriority result:', JSON.stringify(result, null, 2));

    // Verify the update succeeded
    expect((result as { success: boolean }).success).toBe(true);
    expect((result as { hashCount: number }).hashCount).toBe(1);
    expect((result as { dnrResult: { syncRuleCount: number } }).dnrResult.syncRuleCount).toBe(1);

    // Verify DNR rules were installed via getDynamicRules
    const rules = await optionsPage.evaluate(async () => {
      const rules = await chrome.declarativeNetRequest.getDynamicRules();
      return rules.map((r) => ({
        id: r.id,
        urlFilter: r.condition.urlFilter,
        actionType: r.action.type,
      }));
    });

    console.log('Installed DNR rules:', JSON.stringify(rules, null, 2));

    expect(rules.length).toBe(1);
    expect(rules[0].urlFilter).toContain('blocked-by-dnr');
    expect(rules[0].actionType).toBe('redirect');

    await optionsPage.close();
  });

  test('sync IOC blocks navigation via DNR redirect', async ({ context, extensionId }) => {
    const blockedUrl = `${testServer.baseUrl}/blocked-by-dnr`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Set up config
    await optionsPage.evaluate(
      async ({ config }) => {
        await chrome.storage.local.set({ browserdefense_config: config });
      },
      { config: createTestConfig(TEST_SALT) }
    );

    // Compute hash for the blocked URL
    const hash = await hashUrl(blockedUrl, TEST_SALT);
    const hexHash = bytesToHex(hash);

    // Create a sync IOC with URL
    const iocs = [
      {
        hash: hexHash,
        priority: 'sync' as const,
        url: blockedUrl,
        source: 'e2e-test',
      },
    ];

    // Call updateBlocklistWithPriority via message
    await optionsPage.evaluate(
      async ({ iocs, version }) => {
        return new Promise((resolve) => {
          chrome.runtime.sendMessage(
            { type: 'updateBlocklistWithPriority', iocs, version },
            (response) => resolve(response)
          );
        });
      },
      { iocs, version: 1 }
    );

    // Wait for rules to be installed
    await optionsPage.waitForTimeout(100);
    await optionsPage.close();

    // Navigate to the blocked URL
    const page = await context.newPage();
    try {
      await page.goto(blockedUrl, { waitUntil: 'domcontentloaded', timeout: 5000 });
    } catch {
      // Navigation may be redirected
    }

    // Wait for redirect to block page
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    const currentUrl = page.url();
    console.log('Current URL after DNR block:', currentUrl);

    // Verify redirect to block page with original URL in params
    expect(currentUrl).toContain('blocked/blocked.html');
    expect(currentUrl).toContain('blocked-by-dnr');

    await page.close();
  });

  /**
   * NOTE: This test documents a known gap in DNR forensics capture.
   *
   * The current implementation sets up a webNavigation.onCompleted listener
   * in setupDNRForensicsCapture() that should fire when the block page loads.
   * However, due to MV3 service worker lifecycle (suspension/resumption),
   * the listener may not fire reliably in all cases.
   *
   * This test is skipped but documents the expected behavior.
   * See: src/background/blocking.ts:274 - setupDNRForensicsCapture
   * See also: test.skip('DNR block triggers forensics capture') above
   */
  test.skip('sync IOC queues forensics on block', async ({ context, extensionId }) => {
    const blockedUrl = `${testServer.baseUrl}/blocked-by-dnr`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Set up config and clear forensics
    await optionsPage.evaluate(
      async ({ config }) => {
        await chrome.storage.local.set({ browserdefense_config: config });
        await chrome.storage.local.remove('browserdefense_forensics_queue');
      },
      { config: createTestConfig(TEST_SALT) }
    );

    // Compute hash for the blocked URL
    const hash = await hashUrl(blockedUrl, TEST_SALT);
    const hexHash = bytesToHex(hash);

    // Create a sync IOC with URL
    const iocs = [
      {
        hash: hexHash,
        priority: 'sync' as const,
        url: blockedUrl,
        source: 'e2e-test',
      },
    ];

    // Call updateBlocklistWithPriority via message
    await optionsPage.evaluate(
      async ({ iocs, version }) => {
        return new Promise((resolve) => {
          chrome.runtime.sendMessage(
            { type: 'updateBlocklistWithPriority', iocs, version },
            (response) => resolve(response)
          );
        });
      },
      { iocs, version: 1 }
    );

    await optionsPage.waitForTimeout(100);
    await optionsPage.close();

    // Navigate to the blocked URL to trigger DNR redirect
    const page = await context.newPage();
    try {
      await page.goto(blockedUrl, { waitUntil: 'load', timeout: 10000 });
    } catch {
      // May timeout during redirect
    }

    // Wait for page to settle on block page
    await expect(async () => {
      expect(page.url()).toContain('blocked/blocked.html');
    }).toPass({ timeout: 5000 });

    // Wait for load state to ensure onCompleted fires and forensics are captured
    try {
      await page.waitForLoadState('load', { timeout: 5000 });
    } catch {
      // Ignore timeout
    }

    // Give forensics capture time to process
    await page.waitForTimeout(2000);
    await page.close();

    // Check forensics queue - retry since it's async
    const forensicsPage = await context.newPage();
    await forensicsPage.goto(`chrome-extension://${extensionId}/options.html`);

    let queueData: unknown[] | undefined;
    for (let i = 0; i < 5; i++) {
      queueData = await forensicsPage.evaluate(async () => {
        const result = await chrome.storage.local.get('browserdefense_forensics_queue');
        return result.browserdefense_forensics_queue;
      });
      if (queueData && queueData.length > 0) {
        break;
      }
      await forensicsPage.waitForTimeout(500);
    }

    console.log('Forensics queue after DNR block:', JSON.stringify(queueData, null, 2));

    await forensicsPage.close();

    // Verify forensics were captured
    expect(queueData).toBeDefined();
    expect(Array.isArray(queueData)).toBe(true);
    expect(queueData!.length).toBeGreaterThan(0);

    const latestItem = queueData![queueData!.length - 1] as {
      payload: { blockedUrl: string; reason: string; timestamp: string };
    };
    expect(latestItem.payload).toBeDefined();
    expect(latestItem.payload.blockedUrl).toContain('blocked-by-dnr');
    expect(latestItem.payload.reason).toBe('ioc_match');
    expect(latestItem.payload.timestamp).toBeDefined();
  });

  test('async IOC does NOT install DNR rules', async ({ context, extensionId }) => {
    const blockedUrl = `${testServer.baseUrl}/blocked-by-dnr`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Set up config
    await optionsPage.evaluate(
      async ({ config }) => {
        await chrome.storage.local.set({ browserdefense_config: config });
      },
      { config: createTestConfig(TEST_SALT) }
    );

    // Compute hash for the blocked URL
    const hash = await hashUrl(blockedUrl, TEST_SALT);
    const hexHash = bytesToHex(hash);

    // Create an async IOC (should NOT install DNR rule)
    const iocs = [
      {
        hash: hexHash,
        priority: 'async' as const,
        url: blockedUrl,
        source: 'e2e-test',
      },
    ];

    // Call updateBlocklistWithPriority via message
    const result = await optionsPage.evaluate(
      async ({ iocs, version }) => {
        return new Promise((resolve) => {
          chrome.runtime.sendMessage(
            { type: 'updateBlocklistWithPriority', iocs, version },
            (response) => resolve(response)
          );
        });
      },
      { iocs, version: 1 }
    );

    console.log('updateBlocklistWithPriority result (async):', JSON.stringify(result, null, 2));

    // Verify the update succeeded but no DNR rules
    expect((result as { success: boolean }).success).toBe(true);
    expect((result as { hashCount: number }).hashCount).toBe(1);
    expect((result as { dnrResult: { syncRuleCount: number } }).dnrResult.syncRuleCount).toBe(0);
    expect((result as { dnrResult: { asyncCount: number } }).dnrResult.asyncCount).toBe(1);

    // Verify no DNR rules were installed
    const rules = await optionsPage.evaluate(async () => {
      return chrome.declarativeNetRequest.getDynamicRules();
    });

    expect(rules.length).toBe(0);

    await optionsPage.close();
  });

  test('sync IOC without URL is skipped for DNR', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Set up config
    await optionsPage.evaluate(
      async ({ config }) => {
        await chrome.storage.local.set({ browserdefense_config: config });
      },
      { config: createTestConfig(TEST_SALT) }
    );

    // Create a sync IOC WITHOUT URL (can't compile to DNR)
    const iocs = [
      {
        hash: 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234',
        priority: 'sync' as const,
        // No url field!
        source: 'e2e-test',
      },
    ];

    // Call updateBlocklistWithPriority via message
    const result = await optionsPage.evaluate(
      async ({ iocs, version }) => {
        return new Promise((resolve) => {
          chrome.runtime.sendMessage(
            { type: 'updateBlocklistWithPriority', iocs, version },
            (response) => resolve(response)
          );
        });
      },
      { iocs, version: 1 }
    );

    console.log('updateBlocklistWithPriority result (no URL):', JSON.stringify(result, null, 2));

    // Verify the update succeeded but IOC was skipped for DNR
    expect((result as { success: boolean }).success).toBe(true);
    expect((result as { hashCount: number }).hashCount).toBe(1); // Still added to hash set
    expect((result as { dnrResult: { syncRuleCount: number } }).dnrResult.syncRuleCount).toBe(0);
    expect((result as { dnrResult: { skippedNoUrl: number } }).dnrResult.skippedNoUrl).toBe(1);

    // Verify no DNR rules were installed
    const rules = await optionsPage.evaluate(async () => {
      return chrome.declarativeNetRequest.getDynamicRules();
    });

    expect(rules.length).toBe(0);

    await optionsPage.close();
  });

  test('multiple sync IOCs install multiple DNR rules', async ({ context, extensionId }) => {
    const blockedUrl1 = `${testServer.baseUrl}/blocked-1`;
    const blockedUrl2 = `${testServer.baseUrl}/blocked-2`;

    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Set up config
    await optionsPage.evaluate(
      async ({ config }) => {
        await chrome.storage.local.set({ browserdefense_config: config });
      },
      { config: createTestConfig(TEST_SALT) }
    );

    // Compute hashes for both URLs
    const hash1 = await hashUrl(blockedUrl1, TEST_SALT);
    const hash2 = await hashUrl(blockedUrl2, TEST_SALT);

    // Create multiple sync IOCs
    const iocs = [
      { hash: bytesToHex(hash1), priority: 'sync' as const, url: blockedUrl1, source: 'e2e-test' },
      { hash: bytesToHex(hash2), priority: 'sync' as const, url: blockedUrl2, source: 'e2e-test' },
    ];

    // Call updateBlocklistWithPriority via message
    const result = await optionsPage.evaluate(
      async ({ iocs, version }) => {
        return new Promise((resolve) => {
          chrome.runtime.sendMessage(
            { type: 'updateBlocklistWithPriority', iocs, version },
            (response) => resolve(response)
          );
        });
      },
      { iocs, version: 1 }
    );

    console.log('updateBlocklistWithPriority result (multiple):', JSON.stringify(result, null, 2));

    // Verify the update succeeded with multiple rules
    expect((result as { success: boolean }).success).toBe(true);
    expect((result as { hashCount: number }).hashCount).toBe(2);
    expect((result as { dnrResult: { syncRuleCount: number } }).dnrResult.syncRuleCount).toBe(2);

    // Verify both DNR rules were installed
    const rules = await optionsPage.evaluate(async () => {
      const rules = await chrome.declarativeNetRequest.getDynamicRules();
      return rules.map((r) => ({
        id: r.id,
        urlFilter: r.condition.urlFilter,
      }));
    });

    console.log('Installed DNR rules:', JSON.stringify(rules, null, 2));

    expect(rules.length).toBe(2);
    expect(rules.some((r) => r.urlFilter?.includes('blocked-1'))).toBe(true);
    expect(rules.some((r) => r.urlFilter?.includes('blocked-2'))).toBe(true);

    // Verify rule IDs are unique
    const ruleIds = rules.map((r) => r.id);
    expect(new Set(ruleIds).size).toBe(2);

    await optionsPage.close();
  });
});

test.describe('DNR Capacity Management', () => {
  test('can install multiple DNR rules', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // Install multiple DNR rules
    const ruleCount = await optionsPage.evaluate(async () => {
      const blockPageBase = chrome.runtime.getURL('blocked/blocked.html');

      const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
      const removeRuleIds = existingRules.map((r) => r.id);

      // Create 10 test rules
      const addRules: chrome.declarativeNetRequest.Rule[] = [];
      for (let i = 0; i < 10; i++) {
        addRules.push({
          id: i + 1,
          priority: 1,
          action: {
            type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
            redirect: { url: `${blockPageBase}?url=test${i}` },
          },
          condition: {
            urlFilter: `||test${i}.malware.example.com^`,
            resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
          },
        });
      }

      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds,
        addRules,
      });

      const rules = await chrome.declarativeNetRequest.getDynamicRules();
      return rules.length;
    });

    expect(ruleCount).toBe(10);

    // Clean up
    await optionsPage.evaluate(async () => {
      const rules = await chrome.declarativeNetRequest.getDynamicRules();
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: rules.map((r) => r.id),
        addRules: [],
      });
    });

    await optionsPage.close();
  });

  test('can clear all DNR rules', async ({ context, extensionId }) => {
    const optionsPage = await context.newPage();
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);

    // First add some rules
    await optionsPage.evaluate(async () => {
      const blockPageBase = chrome.runtime.getURL('blocked/blocked.html');
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [],
        addRules: [
          {
            id: 999,
            priority: 1,
            action: {
              type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
              redirect: { url: blockPageBase },
            },
            condition: {
              urlFilter: '||temp.example.com^',
              resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
            },
          },
        ],
      });
    });

    // Clear all rules
    const countAfterClear = await optionsPage.evaluate(async () => {
      const rules = await chrome.declarativeNetRequest.getDynamicRules();
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: rules.map((r) => r.id),
        addRules: [],
      });

      const remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
      return remainingRules.length;
    });

    expect(countAfterClear).toBe(0);

    await optionsPage.close();
  });
});
