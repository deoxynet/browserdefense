/**
 * E2E: Options Config Import/Export and Background Wiring
 *
 * Tests the complete config lifecycle:
 * - Import config via paste
 * - Export config
 * - Clear config
 * - Verify config changes propagate to background service worker
 *
 * Note: Tests consolidated into single describe blocks to avoid
 * Chrome extension context reuse timing issues in Playwright.
 *
 * Issue #133
 */

import { test, expect, getServiceWorker } from './fixtures';
import fs from 'fs/promises';

// ============================================================================
// Test Data: Valid Configuration
// ============================================================================

/**
 * Generate a valid test configuration with real cryptographic keys.
 * Uses the example config structure from schema.ts.
 */
function createTestConfig(orgId: string = 'test-org') {
  return {
    org_id: orgId,
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
    blocklist_endpoint: 'https://cdn.example.com/blocklist.json',
    forensics_endpoint: 'https://forensics.example.com/upload',
    ioc_salt: 'test-salt-for-e2e-testing',
    ioc_scope: 'HOST_ONLY',
    update_interval_minutes: 30,
  };
}

/**
 * Helper to open the options page.
 */
async function openOptionsPage(context: any, extensionId: string) {
  const optionsUrl = `chrome-extension://${extensionId}/options.html`;
  const page = await context.newPage();
  await page.goto(optionsUrl);
  return page;
}

// ============================================================================
// Config Import, Export, and Clear Tests
// ============================================================================

test.describe('Options Page: Config Lifecycle', () => {
  test('imports valid config and validates input', async ({ context, extensionId }) => {
    const page = await openOptionsPage(context, extensionId);

    // Clear any existing config first
    await page.evaluate(async () => {
      await chrome.storage.local.remove('browserdefense_config');
    });
    await page.reload();

    // === Test 1: Valid config import via JSON paste ===
    const testConfig = createTestConfig('paste-test-org');

    // Initially should show not configured
    await expect(page.locator('#status-text')).toHaveText('Not configured');

    // Show the textarea
    await page.click('#btn-toggle-textarea');
    await expect(page.locator('#textarea-area')).toBeVisible();

    // Paste the JSON config
    await page.fill('#config-textarea', JSON.stringify(testConfig, null, 2));

    // Click import button
    await page.click('#btn-import-text');

    // Should show success message
    await expect(page.locator('#import-success')).toBeVisible();
    await expect(page.locator('#import-success')).toContainText('paste-test-org');

    // Status should update to configured
    await expect(page.locator('#status-text')).toHaveText('Configured');
    await expect(page.locator('#config-org-id')).toHaveText('paste-test-org');

    // Verify stored in chrome.storage
    const storedConfig = await page.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_config');
      return result.browserdefense_config;
    });

    expect(storedConfig).toBeDefined();
    expect(storedConfig.org_id).toBe('paste-test-org');
    expect(storedConfig.update_interval_minutes).toBe(30);

    // === Test 2: Validation errors for invalid config ===
    // Clear config and reload
    await page.evaluate(async () => {
      await chrome.storage.local.remove('browserdefense_config');
    });
    await page.reload();

    // Show the textarea
    await page.click('#btn-toggle-textarea');

    // Paste invalid JSON (missing required fields)
    const invalidConfig = {
      org_id: 'test-org',
      // Missing all required fields
    };
    await page.fill('#config-textarea', JSON.stringify(invalidConfig));
    await page.click('#btn-import-text');

    // Should show error message
    await expect(page.locator('#import-error')).toBeVisible();
    await expect(page.locator('#import-error')).toContainText('signing_public_key');

    // Status should remain not configured
    await expect(page.locator('#status-text')).toHaveText('Not configured');

    // === Test 3: Malformed JSON ===
    // Clear textarea and try malformed JSON
    await page.fill('#config-textarea', '{ invalid json }');
    await page.click('#btn-import-text');

    // Should show error message
    await expect(page.locator('#import-error')).toBeVisible();

    // === Test 4: HTTP endpoints rejected (requires HTTPS) ===
    const httpConfig = createTestConfig('http-test-org');
    httpConfig.blocklist_endpoint = 'http://insecure.example.com/blocklist.json'; // HTTP not HTTPS

    await page.fill('#config-textarea', JSON.stringify(httpConfig));
    await page.click('#btn-import-text');

    // Should show error about HTTPS
    await expect(page.locator('#import-error')).toBeVisible();
    await expect(page.locator('#import-error')).toContainText('HTTPS');

    await page.close();
  });

  test('exports and clears config correctly', async ({ context, extensionId }) => {
    const page = await openOptionsPage(context, extensionId);
    const testConfig = createTestConfig('export-test-org');

    // Import a config first
    await page.evaluate(async (config) => {
      await chrome.storage.local.set({ browserdefense_config: config });
    }, testConfig);

    // Reload to pick up the config
    await page.reload();

    // === Test Export ===
    // Export section should be visible
    await expect(page.locator('#export-section')).toBeVisible();

    // Set up download listener
    const downloadPromise = page.waitForEvent('download');

    // Click export button
    await page.click('#btn-export');

    // Wait for download
    const download = await downloadPromise;

    // Verify filename contains org_id and has .json extension
    expect(download.suggestedFilename()).toContain('export-test-org');
    expect(download.suggestedFilename()).toMatch(/\.json$/);

    // Verify content
    const downloadPath = await download.path();
    if (downloadPath) {
      const content = await fs.readFile(downloadPath, 'utf-8');
      const exportedConfig = JSON.parse(content);
      expect(exportedConfig.org_id).toBe('export-test-org');
      expect(exportedConfig.blocklist_endpoint).toBe(testConfig.blocklist_endpoint);
    }

    // === Test Clear ===
    // Set up dialog handler to accept confirmation
    page.on('dialog', async (dialog) => {
      await dialog.accept();
    });

    // Click clear button
    await page.click('#btn-clear');

    // Should show success message
    await expect(page.locator('#import-success')).toBeVisible();
    await expect(page.locator('#import-success')).toContainText('cleared');

    // Status should update to not configured
    await expect(page.locator('#status-text')).toHaveText('Not configured');

    // Verify removed from storage
    const storedConfig = await page.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_config');
      return result.browserdefense_config;
    });

    expect(storedConfig).toBeUndefined();

    // Export section should be hidden when no config
    await expect(page.locator('#export-section')).toBeHidden();

    await page.close();
  });
});

// ============================================================================
// Background Wiring Tests
// ============================================================================

test.describe('Background Wiring', () => {
  test('configUpdated triggers update scheduling and configCleared cancels it', async ({ context, extensionId }) => {
    const page = await openOptionsPage(context, extensionId);
    const testConfig = createTestConfig('wiring-test-org');
    testConfig.update_interval_minutes = 45;

    // Clear any existing state first
    await page.evaluate(async () => {
      await chrome.storage.local.remove(['browserdefense_config', 'browserdefense_update_config']);
      await chrome.alarms.clear('browserdefense_blocklist_update');
    });

    // Import config via storage then send configUpdated message
    await page.evaluate(async (config) => {
      await chrome.storage.local.set({ browserdefense_config: config });
    }, testConfig);

    // Send configUpdated message directly and check response
    const response = await page.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'configUpdated' }, (response) => {
          resolve(response);
        });
      });
    });

    expect(response).toBeDefined();
    expect((response as any).success).toBe(true);

    // Give background time to process the message
    await page.waitForTimeout(500);

    // Check that update config was stored (used by scheduleUpdates)
    const updateConfig = await page.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_update_config');
      return result.browserdefense_update_config;
    });

    // Update config should be set from main config
    expect(updateConfig).toBeDefined();
    expect(updateConfig.endpoint).toBe(testConfig.blocklist_endpoint);

    // Check that alarm was created
    let alarms = await page.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.alarms.getAll((alarms) => {
          resolve(alarms);
        });
      });
    });

    // Should have blocklist update alarm
    let updateAlarm = (alarms as any[]).find(
      (a) => a.name === 'browserdefense_blocklist_update'
    );
    expect(updateAlarm).toBeDefined();

    // === Now test configCleared ===
    // Clear config and send configCleared message
    await page.evaluate(async () => {
      await chrome.storage.local.remove('browserdefense_config');
    });

    const clearResponse = await page.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'configCleared' }, resolve);
      });
    });

    expect((clearResponse as any).success).toBe(true);

    // Alarm should be cleared
    alarms = await page.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.alarms.getAll((alarms) => resolve(alarms));
      });
    });

    updateAlarm = (alarms as any[]).find(
      (a) => a.name === 'browserdefense_blocklist_update'
    );
    expect(updateAlarm).toBeUndefined();

    await page.close();
  });
});

// ============================================================================
// Config Persistence Tests
// ============================================================================

test.describe('Config Persistence', () => {
  test('config persists across page reloads', async ({ context, extensionId }) => {
    const page = await openOptionsPage(context, extensionId);
    const testConfig = createTestConfig('persist-test-org');

    // Clear any existing config first
    await page.evaluate(async () => {
      await chrome.storage.local.remove('browserdefense_config');
    });
    await page.reload();

    // Import config via paste
    await page.click('#btn-toggle-textarea');
    await page.fill('#config-textarea', JSON.stringify(testConfig));
    await page.click('#btn-import-text');
    await expect(page.locator('#import-success')).toBeVisible();

    // Reload page
    await page.reload();

    // Config should still be displayed
    await expect(page.locator('#status-text')).toHaveText('Configured');
    await expect(page.locator('#config-org-id')).toHaveText('persist-test-org');

    // Verify storage persistence directly
    const storedConfig = await page.evaluate(async () => {
      const result = await chrome.storage.local.get('browserdefense_config');
      return result.browserdefense_config;
    });

    expect(storedConfig).toBeDefined();
    expect(storedConfig.org_id).toBe('persist-test-org');

    await page.close();
  });
});
