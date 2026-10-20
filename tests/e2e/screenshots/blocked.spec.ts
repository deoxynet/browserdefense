/**
 * BrowserDefense Block Page Screenshot Tests
 *
 * Visual regression tests for the block page shown when navigation is blocked.
 */

import { test, expect } from '../fixtures';

test.describe('Block Page Screenshots', () => {
  test('block page with all fields', async ({ context, extensionId }) => {
    const page = await context.newPage();

    // Navigate to block page with sample parameters
    const blockedUrl = `chrome-extension://${extensionId}/blocked/blocked.html`;
    const params = new URLSearchParams({
      url: 'https://malware.example.com/phishing/login.html',
      category: 'phishing',
      timestamp: new Date().toISOString(),
    });

    await page.goto(`${blockedUrl}?${params.toString()}`);

    // Wait for page to load and display values
    await page.waitForSelector('.container');
    await page.waitForTimeout(300);

    // Mask the timestamp which varies between runs
    const timestamp = page.locator('#timestamp');

    await expect(page).toHaveScreenshot('blocked-full.png', {
      maxDiffPixels: 100,
      mask: [timestamp],
    });

    await page.close();
  });

  test('block page logo and header', async ({ context, extensionId }) => {
    const page = await context.newPage();

    const blockedUrl = `chrome-extension://${extensionId}/blocked/blocked.html`;
    await page.goto(blockedUrl);

    await page.waitForSelector('.logo');

    // Screenshot the logo and title section
    const header = page.locator('.logo, h1').first();
    await expect(page.locator('.logo')).toHaveScreenshot('blocked-logo.png', {
      maxDiffPixels: 50,
    });

    await page.close();
  });

  test('block page details section', async ({ context, extensionId }) => {
    const page = await context.newPage();

    const blockedUrl = `chrome-extension://${extensionId}/blocked/blocked.html`;
    const params = new URLSearchParams({
      url: 'https://suspicious-domain.xyz/payload.js',
      category: 'malware',
    });

    await page.goto(`${blockedUrl}?${params.toString()}`);

    await page.waitForSelector('.details');

    // Screenshot the details section - mask the timestamp which varies
    const details = page.locator('.details');
    const timestamp = page.locator('#timestamp');

    await expect(details).toHaveScreenshot('blocked-details.png', {
      maxDiffPixels: 50,
      mask: [timestamp],
    });

    await page.close();
  });

  test('block page actions', async ({ context, extensionId }) => {
    const page = await context.newPage();

    const blockedUrl = `chrome-extension://${extensionId}/blocked/blocked.html`;
    await page.goto(blockedUrl);

    await page.waitForSelector('.actions');

    const actions = page.locator('.actions');
    await expect(actions).toHaveScreenshot('blocked-actions.png', {
      maxDiffPixels: 50,
    });

    await page.close();
  });

  test('block page footer', async ({ context, extensionId }) => {
    const page = await context.newPage();

    const blockedUrl = `chrome-extension://${extensionId}/blocked/blocked.html`;
    await page.goto(blockedUrl);

    await page.waitForSelector('.footer');

    const footer = page.locator('.footer');
    await expect(footer).toHaveScreenshot('blocked-footer.png', {
      maxDiffPixels: 50,
    });

    await page.close();
  });

  test('block page mobile view', async ({ context, extensionId }) => {
    const page = await context.newPage();

    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    const blockedUrl = `chrome-extension://${extensionId}/blocked/blocked.html`;
    const params = new URLSearchParams({
      url: 'https://malware.example.com/attack',
      category: 'malware',
    });

    await page.goto(`${blockedUrl}?${params.toString()}`);

    await page.waitForSelector('.container');
    await page.waitForTimeout(300);

    await expect(page).toHaveScreenshot('blocked-mobile.png', {
      maxDiffPixels: 100,
    });

    await page.close();
  });
});
