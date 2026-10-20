import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for Chrome extension and UI testing.
 *
 * Chrome extensions require:
 * 1. Using 'chromium' channel (not webkit/firefox)
 * 2. Loading extension via --load-extension flag
 * 3. Using persistent context (extensions don't work in incognito by default)
 *
 * Note: Extension tests use a custom fixture (see tests/e2e/fixtures.ts)
 * that launches Chrome with the extension pre-loaded.
 */
export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,  // Extensions need sequential tests per worker
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,  // Extension context must be single-threaded
  reporter: 'html',

  // Screenshot comparison settings
  expect: {
    toHaveScreenshot: {
      // Allow small differences due to font rendering, etc.
      maxDiffPixelRatio: 0.01,
      // Snapshot output directory
      // Baseline screenshots stored in tests/e2e/screenshots/*.spec.ts-snapshots/
    },
  },

  // Snapshot configuration
  snapshotDir: './tests/e2e/screenshots',
  snapshotPathTemplate: '{testDir}/{testFileDir}/{testFileName}-snapshots/{arg}{ext}',

  use: {
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    // Extension tests (popup, blocked page)
    {
      name: 'chrome-extension',
      testMatch: ['extension.spec.ts', 'blocklist-update.spec.ts', 'forensics-capture.spec.ts', 'forensics-queue.spec.ts', 'forensics-encryption-e2e.spec.ts', 'block-navigation.spec.ts', 'options-config.spec.ts', 'dnr-forensics.spec.ts', 'manifest-packaging.spec.ts', 'screenshots/popup.spec.ts', 'screenshots/blocked.spec.ts'],
      use: {
        // Uses custom fixtures for extension loading
        // See tests/e2e/fixtures.ts
      },
    },
    // Standalone page tests (no extension needed)
    {
      name: 'standalone-pages',
      testMatch: ['screenshots/website.spec.ts', 'screenshots/keygen.spec.ts', 'screenshots/forensics-viewer.spec.ts'],
      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],

  globalSetup: './tests/e2e/global-setup.ts',
});
