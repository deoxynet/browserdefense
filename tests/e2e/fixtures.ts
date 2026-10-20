import { test as base, chromium, type BrowserContext } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Custom Playwright fixtures for Chrome extension testing.
 *
 * Chrome extensions require special handling:
 * 1. Must use chromium.launchPersistentContext() (not browser.newContext())
 * 2. Extension path passed via --load-extension flag
 * 3. Extensions CANNOT run in headless mode - this is a Chrome limitation
 *
 * For CI, use xvfb-run to provide a virtual display:
 *   xvfb-run npx playwright test
 */

// Path to built extension
const EXTENSION_PATH = path.join(__dirname, '../../dist');

/**
 * Check if running in headless mode and fail fast with helpful error.
 * Chrome extensions cannot be loaded in headless mode - tests will silently
 * pass/fail incorrectly if we don't catch this early.
 */
function checkHeadlessMode(): void {
  // Check common headless indicators
  const isHeadless =
    process.env.PLAYWRIGHT_HEADLESS === '1' ||
    process.env.HEADLESS === 'true' ||
    process.env.HEADLESS === '1';

  // Also check if DISPLAY is missing (Linux without xvfb)
  const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;

  if (isHeadless) {
    throw new Error(
      '\n\n' +
      '='.repeat(70) + '\n' +
      'ERROR: Chrome extensions cannot run in headless mode!\n' +
      '='.repeat(70) + '\n\n' +
      'Chrome/Chromium ignores --load-extension in headless mode.\n' +
      'Tests will silently fail because the extension is not loaded.\n\n' +
      'Solutions:\n' +
      '  1. Run with visible browser: npx playwright test --headed\n' +
      '  2. Use virtual display (CI): xvfb-run npx playwright test\n' +
      '  3. Use Docker with Xvfb pre-configured\n\n' +
      'See tests/e2e/README.md for detailed instructions.\n' +
      '='.repeat(70) + '\n'
    );
  }

  if (noDisplay) {
    console.warn(
      '\n' +
      'WARNING: No DISPLAY environment variable detected on Linux.\n' +
      'Chrome extension tests require a display. Use xvfb-run:\n' +
      '  xvfb-run npx playwright test\n'
    );
  }
}

// Run check immediately when fixtures are loaded
checkHeadlessMode();

export type ExtensionFixtures = {
  context: BrowserContext;
  extensionId: string;
};

/**
 * Custom test fixture that launches Chrome with the extension loaded.
 */
export const test = base.extend<ExtensionFixtures>({
  // Override context to use persistent context with extension
  context: async (_, use) => {
    const context = await chromium.launchPersistentContext('', {
      headless: false,  // REQUIRED: Chrome ignores --load-extension in headless mode
      args: [
        `--disable-extensions-except=${EXTENSION_PATH}`,
        `--load-extension=${EXTENSION_PATH}`,
        '--no-first-run',
        '--no-default-browser-check',
      ],
    });

    await use(context);
    await context.close();
  },

  // Get the extension ID from the loaded extension
  extensionId: async ({ context }, use) => {
    // Service workers are registered as special pages
    // Wait for the service worker to be registered
    let extensionId = '';

    // Method 1: Get from service worker URL
    const serviceWorkers = context.serviceWorkers();
    if (serviceWorkers.length > 0) {
      const url = serviceWorkers[0].url();
      const match = url.match(/chrome-extension:\/\/([^/]+)/);
      if (match) {
        extensionId = match[1];
      }
    }

    // Method 2: Wait for service worker if not immediately available
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

export { expect } from '@playwright/test';

/**
 * Helper to navigate to the extension popup.
 */
export async function openExtensionPopup(context: BrowserContext, extensionId: string) {
  const popupUrl = `chrome-extension://${extensionId}/popup.html`;
  const page = await context.newPage();
  await page.goto(popupUrl);
  return page;
}

/**
 * Helper to get the extension's service worker.
 */
export async function getServiceWorker(context: BrowserContext) {
  const workers = context.serviceWorkers();
  if (workers.length > 0) {
    return workers[0];
  }
  return context.waitForEvent('serviceworker', { timeout: 5000 });
}
