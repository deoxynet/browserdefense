/**
 * BrowserDefense Extension Popup Screenshot Tests
 *
 * Visual regression tests for the extension popup UI.
 * Uses Playwright screenshot comparison to detect UI changes.
 */

import { test, expect, openExtensionPopup } from '../fixtures';

test.describe('Extension Popup Screenshots', () => {
  test('popup initial state', async ({ context, extensionId }) => {
    const popup = await openExtensionPopup(context, extensionId);

    // Wait for popup to fully load
    await popup.waitForSelector('.popup');
    await popup.waitForSelector('#status-text');

    // Wait for any loading states to resolve
    await popup.waitForTimeout(500);

    // Take screenshot
    await expect(popup).toHaveScreenshot('popup-initial.png', {
      maxDiffPixels: 100,
    });

    await popup.close();
  });

  test('popup with blocklist loaded', async ({ context, extensionId }) => {
    const popup = await openExtensionPopup(context, extensionId);

    // Wait for blocklist stats to load
    await popup.waitForSelector('.popup');
    await popup.waitForFunction(() => {
      const countEl = document.getElementById('ioc-count');
      return countEl && !countEl.textContent?.includes('Loading');
    }, { timeout: 5000 }).catch(() => {
      // Stats may not load if blocklist isn't configured - that's OK
    });

    await popup.waitForTimeout(300);

    await expect(popup).toHaveScreenshot('popup-with-blocklist.png', {
      maxDiffPixels: 100,
    });

    await popup.close();
  });

  test('popup status indicator variations', async ({ context, extensionId }) => {
    const popup = await openExtensionPopup(context, extensionId);

    await popup.waitForSelector('.popup');

    // Verify status dot is visible
    const statusDot = popup.locator('#status-dot');
    await expect(statusDot).toBeVisible();

    // Take screenshot focusing on header with status
    const header = popup.locator('.header');
    await expect(header).toHaveScreenshot('popup-header-status.png', {
      maxDiffPixels: 50,
    });

    await popup.close();
  });

  test('popup recent blocks section', async ({ context, extensionId }) => {
    const popup = await openExtensionPopup(context, extensionId);

    await popup.waitForSelector('.popup');
    await popup.waitForSelector('#recent-section');

    // Recent section should show "No recent blocks" initially
    const recentSection = popup.locator('#recent-section');
    await expect(recentSection).toHaveScreenshot('popup-recent-empty.png', {
      maxDiffPixels: 50,
    });

    await popup.close();
  });

  test('popup actions buttons', async ({ context, extensionId }) => {
    const popup = await openExtensionPopup(context, extensionId);

    await popup.waitForSelector('.popup');

    // Screenshot the action buttons
    const actions = popup.locator('.actions');
    await expect(actions).toHaveScreenshot('popup-actions.png', {
      maxDiffPixels: 50,
    });

    await popup.close();
  });

  test('popup stats section', async ({ context, extensionId }) => {
    const popup = await openExtensionPopup(context, extensionId);

    await popup.waitForSelector('.popup');
    await popup.waitForSelector('.stats');

    // Wait for stats to stabilize
    await popup.waitForTimeout(500);

    const stats = popup.locator('.stats');
    await expect(stats).toHaveScreenshot('popup-stats.png', {
      maxDiffPixels: 50,
    });

    await popup.close();
  });
});
