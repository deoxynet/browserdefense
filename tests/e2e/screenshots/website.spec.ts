/**
 * BrowserDefense Landing Page Screenshot Tests
 *
 * Visual regression tests for the marketing website.
 * Tests run against the local website files.
 */

import { test as base, expect, chromium } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Standalone test configuration for website (no extension needed)
const test = base.extend({});

test.describe('Landing Page Screenshots', () => {
  test('hero section desktop', async ({ page }) => {
    const websitePath = path.resolve(__dirname, '../../../website/index.html');
    await page.goto(`file://${websitePath}`);

    // Wait for Tailwind to load
    await page.waitForTimeout(1000);

    // Set desktop viewport
    await page.setViewportSize({ width: 1280, height: 800 });

    // Screenshot hero section
    await page.waitForSelector('section');
    await expect(page).toHaveScreenshot('website-hero-desktop.png', {
      maxDiffPixels: 200,
      fullPage: false,
    });
  });

  test('hero section mobile', async ({ page }) => {
    const websitePath = path.resolve(__dirname, '../../../website/index.html');

    // Set mobile viewport before navigating
    await page.setViewportSize({ width: 375, height: 667 });

    await page.goto(`file://${websitePath}`);
    await page.waitForTimeout(1000);

    await expect(page).toHaveScreenshot('website-hero-mobile.png', {
      maxDiffPixels: 200,
      fullPage: false,
    });
  });

  test('navigation bar', async ({ page }) => {
    const websitePath = path.resolve(__dirname, '../../../website/index.html');
    await page.goto(`file://${websitePath}`);
    await page.waitForTimeout(500);

    const nav = page.locator('nav');
    await expect(nav).toHaveScreenshot('website-nav.png', {
      maxDiffPixels: 50,
    });
  });

  test('features section', async ({ page }) => {
    const websitePath = path.resolve(__dirname, '../../../website/index.html');
    await page.goto(`file://${websitePath}`);
    await page.waitForTimeout(500);

    await page.setViewportSize({ width: 1280, height: 900 });

    // Scroll to features section
    await page.locator('#features').scrollIntoViewIfNeeded();
    await page.waitForTimeout(300);

    const features = page.locator('#features');
    await expect(features).toHaveScreenshot('website-features.png', {
      maxDiffPixels: 150,
    });
  });

  test('pricing table desktop', async ({ page }) => {
    const websitePath = path.resolve(__dirname, '../../../website/index.html');
    await page.goto(`file://${websitePath}`);
    await page.waitForTimeout(500);

    await page.setViewportSize({ width: 1280, height: 1000 });

    // Scroll to pricing section
    await page.locator('#pricing').scrollIntoViewIfNeeded();
    await page.waitForTimeout(300);

    const pricing = page.locator('#pricing');
    await expect(pricing).toHaveScreenshot('website-pricing-desktop.png', {
      maxDiffPixels: 150,
    });
  });

  test('pricing table mobile', async ({ page }) => {
    const websitePath = path.resolve(__dirname, '../../../website/index.html');

    await page.setViewportSize({ width: 375, height: 800 });
    await page.goto(`file://${websitePath}`);
    await page.waitForTimeout(500);

    // Scroll to pricing
    await page.locator('#pricing').scrollIntoViewIfNeeded();
    await page.waitForTimeout(300);

    const pricing = page.locator('#pricing');
    await expect(pricing).toHaveScreenshot('website-pricing-mobile.png', {
      maxDiffPixels: 150,
    });
  });

  test('trust section', async ({ page }) => {
    const websitePath = path.resolve(__dirname, '../../../website/index.html');
    await page.goto(`file://${websitePath}`);
    await page.waitForTimeout(500);

    await page.setViewportSize({ width: 1280, height: 600 });

    // Find the trust section (dark bg with "Built for Trust")
    const trustSection = page.locator('section.bg-slate-900').first();
    await trustSection.scrollIntoViewIfNeeded();
    await page.waitForTimeout(300);

    await expect(trustSection).toHaveScreenshot('website-trust.png', {
      maxDiffPixels: 100,
    });
  });

  test('footer', async ({ page }) => {
    const websitePath = path.resolve(__dirname, '../../../website/index.html');
    await page.goto(`file://${websitePath}`);
    await page.waitForTimeout(500);

    await page.setViewportSize({ width: 1280, height: 400 });

    const footer = page.locator('footer');
    await footer.scrollIntoViewIfNeeded();
    await page.waitForTimeout(300);

    await expect(footer).toHaveScreenshot('website-footer.png', {
      maxDiffPixels: 100,
    });
  });

  test('full page scroll (desktop)', async ({ page }) => {
    const websitePath = path.resolve(__dirname, '../../../website/index.html');
    await page.goto(`file://${websitePath}`);
    await page.waitForTimeout(1000);

    await page.setViewportSize({ width: 1280, height: 800 });

    // Full page screenshot
    await expect(page).toHaveScreenshot('website-full-desktop.png', {
      fullPage: true,
      maxDiffPixels: 500,
    });
  });

  test('mobile menu toggle', async ({ page }) => {
    const websitePath = path.resolve(__dirname, '../../../website/index.html');

    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto(`file://${websitePath}`);
    await page.waitForTimeout(500);

    // Click mobile menu button
    const menuBtn = page.locator('#mobile-menu-btn');
    await menuBtn.click();
    await page.waitForTimeout(300);

    // Screenshot with mobile menu open
    const mobileMenu = page.locator('#mobile-menu');
    await expect(mobileMenu).toBeVisible();
    await expect(page.locator('nav')).toHaveScreenshot('website-mobile-menu-open.png', {
      maxDiffPixels: 100,
    });
  });
});
