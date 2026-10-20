/**
 * BrowserDefense Forensics Viewer Screenshot Tests
 *
 * Visual regression tests for the forensics decryption tool.
 */

import { test as base, expect } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Standalone test configuration (no extension needed)
const test = base.extend({});

test.describe('Forensics Viewer Screenshots', () => {
  test('empty state', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    await page.waitForSelector('.container');
    await page.waitForTimeout(300);

    await expect(page).toHaveScreenshot('forensics-empty.png', {
      maxDiffPixels: 100,
    });
  });

  test('header and subtitle', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    await page.waitForSelector('h1');

    const header = page.locator('h1, .subtitle').first();
    await expect(page.locator('h1')).toHaveScreenshot('forensics-header.png', {
      maxDiffPixels: 50,
    });
  });

  test('input panels layout', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    await page.waitForSelector('.panels');

    const panels = page.locator('.panels');
    await expect(panels).toHaveScreenshot('forensics-panels.png', {
      maxDiffPixels: 100,
    });
  });

  test('private key panel', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    await page.waitForSelector('.panel');

    const keyPanel = page.locator('.panel').first();
    await expect(keyPanel).toHaveScreenshot('forensics-key-panel.png', {
      maxDiffPixels: 50,
    });
  });

  test('encrypted data panel', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    await page.waitForSelector('.panel');

    const dataPanel = page.locator('.panel').nth(1);
    await expect(dataPanel).toHaveScreenshot('forensics-data-panel.png', {
      maxDiffPixels: 50,
    });
  });

  test('action buttons', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    await page.waitForSelector('.actions');

    const actions = page.locator('.actions');
    await expect(actions).toHaveScreenshot('forensics-actions.png', {
      maxDiffPixels: 50,
    });
  });

  test('error state - missing key', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    // Click decrypt without providing data
    await page.locator('#decryptBtn').click();
    await page.waitForSelector('.status:not(.hidden)');

    const status = page.locator('#status');
    await expect(status).toHaveScreenshot('forensics-error-missing-key.png', {
      maxDiffPixels: 50,
    });
  });

  test('error state - missing data', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    // Enter some key but no data
    await page.locator('#keyInput').fill('{"kty":"RSA","d":"test"}');
    await page.locator('#decryptBtn').click();
    await page.waitForSelector('.status:not(.hidden)');

    const status = page.locator('#status');
    await expect(status).toHaveScreenshot('forensics-error-missing-data.png', {
      maxDiffPixels: 50,
    });
  });

  test('drop zones hover state', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    await page.waitForSelector('.drop-zone');

    // Hover over drop zone to show hover state
    const keyDropZone = page.locator('#keyDropZone');
    await keyDropZone.hover();
    await page.waitForTimeout(200);

    await expect(keyDropZone).toHaveScreenshot('forensics-dropzone-hover.png', {
      maxDiffPixels: 50,
    });
  });

  test('empty results state text', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    await page.waitForSelector('#emptyState');

    const emptyState = page.locator('#emptyState');
    await expect(emptyState).toHaveScreenshot('forensics-empty-state-text.png', {
      maxDiffPixels: 50,
    });
  });

  test('mobile layout', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');

    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto(`file://${viewerPath}`);
    await page.waitForTimeout(300);

    await expect(page).toHaveScreenshot('forensics-mobile.png', {
      maxDiffPixels: 100,
    });
  });

  test('with decrypted data - mock', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    // Inject mock decrypted data directly into the page to test results rendering
    await page.evaluate(() => {
      // @ts-ignore - accessing global state
      window.decryptedRecords = [
        {
          timestamp: '2024-01-15T10:30:00Z',
          blockedUrl: 'https://malware.example.com/payload.exe',
          normalizedUrl: 'malware.example.com/payload.exe',
          redirectChain: ['https://legit.com', 'https://redirect.co', 'https://malware.example.com/payload.exe'],
          initiator: 'user_navigation',
          reason: 'hash_match',
        },
        {
          timestamp: '2024-01-15T11:45:00Z',
          blockedUrl: 'https://phishing.bad/login',
          normalizedUrl: 'phishing.bad/login',
          redirectChain: [],
          initiator: 'link_click',
          reason: 'domain_match',
        },
      ];

      // Manually trigger render
      const resultsSection = document.getElementById('resultsSection');
      const emptyState = document.getElementById('emptyState');
      const resultsCount = document.getElementById('resultsCount');
      const resultsBody = document.getElementById('resultsBody');

      if (resultsSection && emptyState && resultsCount && resultsBody) {
        emptyState.classList.add('hidden');
        resultsSection.classList.remove('hidden');
        resultsCount.textContent = '2 records';

        // @ts-ignore
        const records = window.decryptedRecords;
        resultsBody.innerHTML = records.map((record: any) => `
          <tr>
            <td class="timestamp">${record.timestamp}</td>
            <td class="url-cell">${record.blockedUrl}</td>
            <td class="url-cell">${record.normalizedUrl || '-'}</td>
            <td class="chain-cell">${record.redirectChain?.length || 0} hops</td>
            <td><code>${record.initiator || '-'}</code></td>
            <td><code>${record.reason || '-'}</code></td>
          </tr>
        `).join('');
      }
    });

    await page.waitForTimeout(300);

    await expect(page).toHaveScreenshot('forensics-with-data.png', {
      maxDiffPixels: 150,
    });
  });

  test('results table header', async ({ page }) => {
    const viewerPath = path.resolve(__dirname, '../../../tools/forensics-viewer/index.html');
    await page.goto(`file://${viewerPath}`);

    // Show results section
    await page.evaluate(() => {
      const resultsSection = document.getElementById('resultsSection');
      const emptyState = document.getElementById('emptyState');
      if (resultsSection && emptyState) {
        emptyState.classList.add('hidden');
        resultsSection.classList.remove('hidden');
      }
    });

    await page.waitForTimeout(200);

    const resultsHeader = page.locator('.results-header');
    await expect(resultsHeader).toHaveScreenshot('forensics-results-header.png', {
      maxDiffPixels: 50,
    });
  });
});
