/**
 * E2E Smoke Test: Manifest Packaging Verification
 *
 * Issue #247: Validates that the built extension has the correct
 * manifest and reports the expected blocking mode.
 *
 * Consumer Build (dist/):
 * - Should load successfully
 * - Should NOT have webRequestBlocking permission
 * - Should report DNR blocking mode
 *
 * Enterprise Build (dist-enterprise/):
 * - Requires separate test with policy-installed extension
 * - See tests/e2e/enterprise-blocking.spec.ts
 *
 * Run tests: npm run test:e2e -- --grep 'Manifest Packaging'
 */

import { test as base, chromium, type BrowserContext, expect } from '@playwright/test';
import path from 'path';
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Paths to built extensions
const CONSUMER_EXTENSION_PATH = path.join(__dirname, '../../dist');
const ENTERPRISE_EXTENSION_PATH = path.join(__dirname, '../../dist-enterprise');

interface ChromeManifest {
  manifest_version: number;
  name: string;
  version: string;
  permissions: string[];
}

type ExtensionFixtures = {
  context: BrowserContext;
  extensionId: string;
};

// ============================================================================
// Consumer Extension Tests
// ============================================================================

const consumerTest = base.extend<ExtensionFixtures>({
  context: async (_, use) => {
    if (!existsSync(CONSUMER_EXTENSION_PATH)) {
      console.error('Consumer extension not built. Run: npm run build');
      throw new Error('Consumer extension not found at dist/');
    }

    const context = await chromium.launchPersistentContext('', {
      headless: false,
      args: [
        `--disable-extensions-except=${CONSUMER_EXTENSION_PATH}`,
        `--load-extension=${CONSUMER_EXTENSION_PATH}`,
        '--no-first-run',
        '--no-default-browser-check',
      ],
    });

    await use(context);
    await context.close();
  },

  extensionId: async ({ context }, use) => {
    let extensionId = '';

    const serviceWorkers = context.serviceWorkers();
    if (serviceWorkers.length > 0) {
      const url = serviceWorkers[0].url();
      const match = url.match(/chrome-extension:\/\/([^/]+)/);
      if (match) {
        extensionId = match[1];
      }
    }

    if (!extensionId) {
      const sw = await context.waitForEvent('serviceworker', { timeout: 5000 }).catch(() => null);
      if (sw) {
        const url = sw.url();
        const match = url.match(/chrome-extension:\/\/([^/]+)/);
        if (match) {
          extensionId = match[1];
        }
      }
    }

    await use(extensionId);
  },
});

consumerTest.describe('Manifest Packaging: Consumer Build', () => {
  consumerTest('should load consumer extension from dist/', async ({ extensionId }) => {
    expect(extensionId).toBeTruthy();
    expect(extensionId.length).toBe(32); // Extension IDs are 32 chars
  });

  consumerTest('consumer manifest should have correct name', async () => {
    const manifestPath = path.join(CONSUMER_EXTENSION_PATH, 'manifest.json');
    expect(existsSync(manifestPath)).toBe(true);

    const manifest: ChromeManifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    expect(manifest.name).toBe('BrowserDefense');
  });

  consumerTest('consumer manifest should have DNR permissions', async () => {
    const manifestPath = path.join(CONSUMER_EXTENSION_PATH, 'manifest.json');
    const manifest: ChromeManifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));

    expect(manifest.permissions).toContain('declarativeNetRequest');
    expect(manifest.permissions).toContain('declarativeNetRequestWithHostAccess');
  });

  consumerTest('consumer manifest should NOT have webRequestBlocking', async () => {
    const manifestPath = path.join(CONSUMER_EXTENSION_PATH, 'manifest.json');
    const manifest: ChromeManifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));

    expect(manifest.permissions).not.toContain('webRequestBlocking');
  });

  consumerTest('consumer extension should report DNR mode', async ({ context, extensionId }) => {
    // Get the service worker to check permissions
    const workers = context.serviceWorkers();
    expect(workers.length).toBeGreaterThan(0);

    const sw = workers[0];

    // Evaluate in service worker context to check permissions
    const hasWebRequestBlocking = await sw.evaluate(async () => {
      // @ts-expect-error Chrome extension API
      const result = await chrome.permissions.contains({
        permissions: ['webRequestBlocking'],
      });
      return result;
    });

    // Consumer extension should NOT have webRequestBlocking
    expect(hasWebRequestBlocking).toBe(false);
  });

  consumerTest('consumer popup should be accessible', async ({ context, extensionId }) => {
    const popupUrl = `chrome-extension://${extensionId}/popup.html`;
    const page = await context.newPage();
    await page.goto(popupUrl);

    // Should load without errors
    await expect(page).toHaveTitle(/BlockIOC/);
    await page.close();
  });
});

// ============================================================================
// Enterprise Extension Tests (requires policy installation)
// ============================================================================

const enterpriseTest = base.extend<ExtensionFixtures>({
  context: async (_, use) => {
    if (!existsSync(ENTERPRISE_EXTENSION_PATH)) {
      console.log('Enterprise extension not built. Run: npm run build:enterprise');
      // Skip enterprise tests if not built
      await use(null as unknown as BrowserContext);
      return;
    }

    const context = await chromium.launchPersistentContext('', {
      headless: false,
      args: [
        `--disable-extensions-except=${ENTERPRISE_EXTENSION_PATH}`,
        `--load-extension=${ENTERPRISE_EXTENSION_PATH}`,
        '--no-first-run',
        '--no-default-browser-check',
      ],
    });

    await use(context);
    await context.close();
  },

  extensionId: async ({ context }, use) => {
    if (!context) {
      await use('');
      return;
    }

    let extensionId = '';

    const serviceWorkers = context.serviceWorkers();
    if (serviceWorkers.length > 0) {
      const url = serviceWorkers[0].url();
      const match = url.match(/chrome-extension:\/\/([^/]+)/);
      if (match) {
        extensionId = match[1];
      }
    }

    if (!extensionId) {
      const sw = await context.waitForEvent('serviceworker', { timeout: 5000 }).catch(() => null);
      if (sw) {
        const url = sw.url();
        const match = url.match(/chrome-extension:\/\/([^/]+)/);
        if (match) {
          extensionId = match[1];
        }
      }
    }

    await use(extensionId);
  },
});

enterpriseTest.describe('Manifest Packaging: Enterprise Build', () => {
  enterpriseTest.skip(({ context }) => !context, 'Enterprise extension not built');

  enterpriseTest('should load enterprise extension from dist-enterprise/', async ({ extensionId }) => {
    expect(extensionId).toBeTruthy();
    expect(extensionId.length).toBe(32);
  });

  enterpriseTest('enterprise manifest should have correct name', async () => {
    const manifestPath = path.join(ENTERPRISE_EXTENSION_PATH, 'manifest.json');
    expect(existsSync(manifestPath)).toBe(true);

    const manifest: ChromeManifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    expect(manifest.name).toBe('BrowserDefense Enterprise');
  });

  enterpriseTest('enterprise manifest should have webRequestBlocking permission', async () => {
    const manifestPath = path.join(ENTERPRISE_EXTENSION_PATH, 'manifest.json');
    const manifest: ChromeManifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));

    expect(manifest.permissions).toContain('webRequestBlocking');
    expect(manifest.permissions).toContain('webRequest');
  });

  enterpriseTest('enterprise manifest should NOT have DNR permissions', async () => {
    const manifestPath = path.join(ENTERPRISE_EXTENSION_PATH, 'manifest.json');
    const manifest: ChromeManifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));

    expect(manifest.permissions).not.toContain('declarativeNetRequest');
    expect(manifest.permissions).not.toContain('declarativeNetRequestWithHostAccess');
  });

  enterpriseTest('enterprise popup should be accessible', async ({ context, extensionId }) => {
    if (!context) return;

    const popupUrl = `chrome-extension://${extensionId}/popup.html`;
    const page = await context.newPage();
    await page.goto(popupUrl);

    // Should load without errors
    await expect(page).toHaveTitle(/BlockIOC/);
    await page.close();
  });

  /**
   * NOTE: webRequestBlocking permission check will fail for non-policy-installed extensions.
   *
   * For enterprise extension to report hasWebRequestBlocking = true, it must be:
   * 1. Installed via enterprise policy (GPO/MDM)
   * 2. Chrome must recognize it as policy-installed
   *
   * This test documents the expected behavior but will pass even when
   * webRequestBlocking returns false (since Playwright loads it manually).
   */
  enterpriseTest('enterprise extension requests webRequestBlocking (policy-dependent)', async ({
    context,
  }) => {
    if (!context) return;

    // Note: This test verifies the manifest requests the permission.
    // Actual permission grant requires policy installation.
    const manifestPath = path.join(ENTERPRISE_EXTENSION_PATH, 'manifest.json');
    const manifest: ChromeManifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));

    expect(manifest.permissions).toContain('webRequestBlocking');

    // When testing in Playwright (not policy-installed), webRequestBlocking
    // will NOT be available. This is expected behavior.
    // For actual enterprise mode testing, see tests/e2e/enterprise-blocking.spec.ts
  });
});

// ============================================================================
// Build Artifact Validation
// ============================================================================

base.describe('Manifest Packaging: Build Artifacts', () => {
  base('consumer build should include all required files', async () => {
    if (!existsSync(CONSUMER_EXTENSION_PATH)) {
      console.log('Consumer extension not built. Run: npm run build');
      return;
    }

    const requiredFiles = [
      'manifest.json',
      'background.js',
      'content.js',
      'popup.html',
      'popup.css',
      'options.html',
      'options.css',
      'blocked/blocked.html',
      'blocked/blocked.css',
      'icons/icon16.png',
      'icons/icon48.png',
      'icons/icon128.png',
    ];

    for (const file of requiredFiles) {
      const filePath = path.join(CONSUMER_EXTENSION_PATH, file);
      expect(existsSync(filePath), `Missing file: ${file}`).toBe(true);
    }
  });

  base('enterprise build should include all required files', async () => {
    if (!existsSync(ENTERPRISE_EXTENSION_PATH)) {
      console.log('Enterprise extension not built. Run: npm run build:enterprise');
      return;
    }

    const requiredFiles = [
      'manifest.json',
      'background.js',
      'content.js',
      'popup.html',
      'popup.css',
      'options.html',
      'options.css',
      'blocked/blocked.html',
      'blocked/blocked.css',
      'icons/icon16.png',
      'icons/icon48.png',
      'icons/icon128.png',
    ];

    for (const file of requiredFiles) {
      const filePath = path.join(ENTERPRISE_EXTENSION_PATH, file);
      expect(existsSync(filePath), `Missing file: ${file}`).toBe(true);
    }
  });

  base('manifests should differ between consumer and enterprise builds', async () => {
    if (!existsSync(CONSUMER_EXTENSION_PATH) || !existsSync(ENTERPRISE_EXTENSION_PATH)) {
      console.log('Both builds required. Run: npm run build:all');
      return;
    }

    const consumerManifest: ChromeManifest = JSON.parse(
      readFileSync(path.join(CONSUMER_EXTENSION_PATH, 'manifest.json'), 'utf-8')
    );
    const enterpriseManifest: ChromeManifest = JSON.parse(
      readFileSync(path.join(ENTERPRISE_EXTENSION_PATH, 'manifest.json'), 'utf-8')
    );

    // Names should differ
    expect(consumerManifest.name).not.toBe(enterpriseManifest.name);

    // Permissions should differ
    const consumerHasDNR = consumerManifest.permissions.includes('declarativeNetRequest');
    const enterpriseHasWRB = enterpriseManifest.permissions.includes('webRequestBlocking');

    expect(consumerHasDNR).toBe(true);
    expect(enterpriseHasWRB).toBe(true);

    // Mutually exclusive
    expect(consumerManifest.permissions).not.toContain('webRequestBlocking');
    expect(enterpriseManifest.permissions).not.toContain('declarativeNetRequest');
  });
});
