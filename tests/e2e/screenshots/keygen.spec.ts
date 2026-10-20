/**
 * BrowserDefense Key Generator Screenshot Tests
 *
 * Visual regression tests for the key generation tool.
 */

import { test as base, expect } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Standalone test configuration (no extension needed)
const test = base.extend({});

test.describe('Key Generator Screenshots', () => {
  test('initial state', async ({ page }) => {
    const keygenPath = path.resolve(__dirname, '../../../tools/keygen/index.html');
    await page.goto(`file://${keygenPath}`);

    await page.waitForSelector('.container');
    await page.waitForTimeout(300);

    await expect(page).toHaveScreenshot('keygen-initial.png', {
      maxDiffPixels: 100,
    });
  });

  test('header and warning banner', async ({ page }) => {
    const keygenPath = path.resolve(__dirname, '../../../tools/keygen/index.html');
    await page.goto(`file://${keygenPath}`);

    await page.waitForSelector('.warning-banner');

    // Screenshot just header area
    const header = page.locator('h1');
    const subtitle = page.locator('.subtitle');
    const warning = page.locator('.warning-banner');

    await expect(warning).toHaveScreenshot('keygen-warning-banner.png', {
      maxDiffPixels: 50,
    });
  });

  test('generate button initial', async ({ page }) => {
    const keygenPath = path.resolve(__dirname, '../../../tools/keygen/index.html');
    await page.goto(`file://${keygenPath}`);

    await page.waitForSelector('.generate-section');

    const generateSection = page.locator('.generate-section');
    await expect(generateSection).toHaveScreenshot('keygen-generate-button.png', {
      maxDiffPixels: 50,
    });
  });

  test('keys generated - full view', async ({ page }) => {
    const keygenPath = path.resolve(__dirname, '../../../tools/keygen/index.html');
    await page.goto(`file://${keygenPath}`);

    // Click generate button
    const generateBtn = page.locator('#generateBtn');
    await generateBtn.click();

    // Wait for key generation to complete
    await page.waitForSelector('.results.visible');
    await page.waitForTimeout(500);

    // Mask dynamic key content (key previews contain random data)
    const keyPreviews = page.locator('.key-preview');
    const configPreview = page.locator('.config-preview');

    // Full page screenshot with masked dynamic content
    await expect(page).toHaveScreenshot('keygen-keys-generated.png', {
      fullPage: true,
      maxDiffPixels: 500,
      mask: [keyPreviews, configPreview],
    });
  });

  test('keys generated - signing section', async ({ page }) => {
    const keygenPath = path.resolve(__dirname, '../../../tools/keygen/index.html');
    await page.goto(`file://${keygenPath}`);

    await page.locator('#generateBtn').click();
    await page.waitForSelector('.results.visible');
    await page.waitForTimeout(300);

    // Screenshot signing keys section with masked key content
    const signingKeys = page.locator('.key-section').first();
    const keyPreview = signingKeys.locator('.key-preview');

    await expect(signingKeys).toHaveScreenshot('keygen-signing-public.png', {
      maxDiffPixels: 200,
      mask: [keyPreview],
    });
  });

  test('keys generated - encryption section', async ({ page }) => {
    const keygenPath = path.resolve(__dirname, '../../../tools/keygen/index.html');
    await page.goto(`file://${keygenPath}`);

    await page.locator('#generateBtn').click();
    await page.waitForSelector('.results.visible');
    await page.waitForTimeout(300);

    // Scroll to encryption section
    const encryptionTitle = page.locator('.section-title:has-text("Encryption Keys")');
    await encryptionTitle.scrollIntoViewIfNeeded();

    const encryptionKey = page.locator('.key-section').nth(2); // Third key section
    const keyPreview = encryptionKey.locator('.key-preview');

    await expect(encryptionKey).toHaveScreenshot('keygen-encryption-public.png', {
      maxDiffPixels: 200,
      mask: [keyPreview],
    });
  });

  test('keys generated - config section', async ({ page }) => {
    const keygenPath = path.resolve(__dirname, '../../../tools/keygen/index.html');
    await page.goto(`file://${keygenPath}`);

    await page.locator('#generateBtn').click();
    await page.waitForSelector('.results.visible');
    await page.waitForTimeout(300);

    // Scroll to config section
    const configSection = page.locator('.config-section');
    await configSection.scrollIntoViewIfNeeded();
    await page.waitForTimeout(200);

    // Mask the config preview which contains random keys
    const configPreview = configSection.locator('.config-preview');

    await expect(configSection).toHaveScreenshot('keygen-config.png', {
      maxDiffPixels: 200,
      mask: [configPreview],
    });
  });

  test('keys generated - storage tips', async ({ page }) => {
    const keygenPath = path.resolve(__dirname, '../../../tools/keygen/index.html');
    await page.goto(`file://${keygenPath}`);

    await page.locator('#generateBtn').click();
    await page.waitForSelector('.results.visible');
    await page.waitForTimeout(300);

    const storageTips = page.locator('.storage-tips');
    await storageTips.scrollIntoViewIfNeeded();
    await page.waitForTimeout(200);

    await expect(storageTips).toHaveScreenshot('keygen-storage-tips.png', {
      maxDiffPixels: 50,
    });
  });

  test('success status after generation', async ({ page }) => {
    const keygenPath = path.resolve(__dirname, '../../../tools/keygen/index.html');
    await page.goto(`file://${keygenPath}`);

    await page.locator('#generateBtn').click();
    await page.waitForSelector('#status.visible');

    const status = page.locator('#status');
    await expect(status).toHaveScreenshot('keygen-success-status.png', {
      maxDiffPixels: 50,
    });
  });

  test('key badge styles', async ({ page }) => {
    const keygenPath = path.resolve(__dirname, '../../../tools/keygen/index.html');
    await page.goto(`file://${keygenPath}`);

    await page.locator('#generateBtn').click();
    await page.waitForSelector('.results.visible');

    // Screenshot showing public (DISTRIBUTE) and private (KEEP SECRET) badges
    const publicBadge = page.locator('.badge-public').first();
    const privateBadge = page.locator('.badge-private').first();

    // Get parent key-header containing both badge types
    const keyHeaders = page.locator('.key-header');
    await expect(keyHeaders.first()).toHaveScreenshot('keygen-badge-public.png', {
      maxDiffPixels: 50,
    });
    await expect(keyHeaders.nth(1)).toHaveScreenshot('keygen-badge-private.png', {
      maxDiffPixels: 50,
    });
  });
});
