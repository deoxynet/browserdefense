/**
 * BrowserDefense Chrome Extension Integration Tests
 *
 * These tests verify the extension loads correctly and basic functionality works.
 * Uses custom fixtures from ./fixtures.ts to load Chrome with the extension.
 */

import { test, expect, openExtensionPopup, getServiceWorker } from './fixtures';

test.describe('Extension Loading', () => {
  test('extension loads and service worker starts', async ({ context, extensionId }) => {
    // Extension should be loaded with a valid ID
    expect(extensionId).toBeTruthy();
    expect(extensionId).toMatch(/^[a-z]{32}$/);

    // Service worker should be running
    const sw = await getServiceWorker(context);
    expect(sw).toBeTruthy();
    expect(sw.url()).toContain('chrome-extension://');
  });

  test('popup opens and displays status', async ({ context, extensionId }) => {
    const popup = await openExtensionPopup(context, extensionId);

    // Popup should show BrowserDefense title
    await expect(popup.locator('h1')).toHaveText('BrowserDefense');

    await popup.close();
  });
});

test.describe('Service Worker Heartbeat', () => {
  test('heartbeat alarm is registered with correct period', async ({ context, extensionId }) => {
    // Open popup page to have an extension context for messaging
    const popup = await openExtensionPopup(context, extensionId);

    // Query the keepAlive alarm via message passing from extension page
    const alarmResult = await popup.evaluate(async () => {
      return new Promise<{ success: boolean; alarm?: { name: string; periodInMinutes?: number; scheduledTime: number }; error?: string }>((resolve) => {
        chrome.runtime.sendMessage({ type: 'heartbeat_getAlarm' }, (response) => {
          resolve(response);
        });
      });
    });

    expect(alarmResult.success).toBe(true);
    expect(alarmResult.alarm).toBeDefined();
    expect(alarmResult.alarm!.name).toBe('keepAlive');
    // Verify period is approximately 4.9 minutes (allow small tolerance)
    expect(alarmResult.alarm!.periodInMinutes).toBeCloseTo(4.9, 1);

    await popup.close();
  });

  test('forceHeartbeat increments heartbeat count', async ({ context, extensionId }) => {
    // Open popup page to have an extension context for messaging
    const popup = await openExtensionPopup(context, extensionId);

    // Get initial stats
    const initialStats = await popup.evaluate(async () => {
      return new Promise<{ success: boolean; stats?: { count: number; intervalMinutes: number }; error?: string }>((resolve) => {
        chrome.runtime.sendMessage({ type: 'heartbeat_getStats' }, (response) => {
          resolve(response);
        });
      });
    });

    expect(initialStats.success).toBe(true);
    const initialCount = initialStats.stats!.count;

    // Force a heartbeat
    const forceResult = await popup.evaluate(async () => {
      return new Promise<{ success: boolean; error?: string }>((resolve) => {
        chrome.runtime.sendMessage({ type: 'heartbeat_forceHeartbeat' }, (response) => {
          resolve(response);
        });
      });
    });

    expect(forceResult.success).toBe(true);

    // Get updated stats
    const updatedStats = await popup.evaluate(async () => {
      return new Promise<{ success: boolean; stats?: { count: number; intervalMinutes: number }; error?: string }>((resolve) => {
        chrome.runtime.sendMessage({ type: 'heartbeat_getStats' }, (response) => {
          resolve(response);
        });
      });
    });

    expect(updatedStats.success).toBe(true);
    // Count should have incremented by 1
    expect(updatedStats.stats!.count).toBe(initialCount + 1);
    // Verify the interval is correct
    expect(updatedStats.stats!.intervalMinutes).toBe(4.9);

    await popup.close();
  });
});

/**
 * Blocking tests have been moved to dedicated test files:
 * - block-navigation.spec.ts - Core block/allow navigation tests
 * - forensics-capture.spec.ts - Forensics capture on block events
 * - forensics-queue.spec.ts - Offline forensics queue tests
 *
 * These files provide comprehensive coverage of:
 * - Blocking known-bad URLs
 * - Allowing safe URLs
 * - Block page display with original URL
 * - Path variations and query parameters
 * - Redirect chain capture
 */
