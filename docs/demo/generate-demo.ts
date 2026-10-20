/**
 * BrowserDefense Demo GIF Generator
 *
 * Captures screenshots of the extension workflow and converts to animated GIF.
 *
 * Usage: npx tsx docs/demo/generate-demo.ts
 *
 * Requirements:
 * - Built extension in dist/
 * - ffmpeg installed (brew install ffmpeg)
 */

import { chromium, type BrowserContext, type Page } from '@playwright/test';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import sharp from 'sharp';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.join(__dirname, '../..');
const EXTENSION_PATH = path.join(PROJECT_ROOT, 'dist');
const OUTPUT_DIR = path.join(__dirname, 'frames');
const NORMALIZED_DIR = path.join(__dirname, 'frames-normalized');
const FINAL_GIF = path.join(PROJECT_ROOT, 'website/assets/demo.gif');

// Demo configuration
const DEMO_CONFIG = {
  viewport: { width: 1200, height: 800 },
  popupSize: { width: 360, height: 500 },
  frameDelay: 2000, // ms between frames in GIF
  phishingUrl: 'https://secure-login.malicious-site.com/auth/microsoft365',
  category: 'phishing',
};

// Test IOC that matches the phishing URL
const TEST_BLOCKLIST_URL = 'secure-login.malicious-site.com';

interface FrameCapture {
  name: string;
  description: string;
  capture: (context: BrowserContext, extensionId: string) => Promise<void>;
}

/**
 * Helper to open extension popup
 */
async function openPopup(context: BrowserContext, extensionId: string): Promise<Page> {
  const popupUrl = `chrome-extension://${extensionId}/popup.html`;
  const page = await context.newPage();
  await page.setViewportSize(DEMO_CONFIG.popupSize);
  await page.goto(popupUrl);
  await page.waitForSelector('.popup');
  await page.waitForTimeout(300);
  return page;
}

/**
 * Helper to capture blocked page
 */
async function openBlockedPage(context: BrowserContext, extensionId: string, url: string, reason: string): Promise<Page> {
  const ts = Date.now();
  const blockedUrl = `chrome-extension://${extensionId}/blocked/blocked.html?url=${encodeURIComponent(url)}&reason=${reason}&ts=${ts}`;
  const page = await context.newPage();
  await page.setViewportSize(DEMO_CONFIG.viewport);
  await page.goto(blockedUrl);
  await page.waitForSelector('.container');
  await page.waitForTimeout(300);
  return page;
}

/**
 * Create a mock threat intel report page
 */
async function createThreatReportPage(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.setViewportSize(DEMO_CONFIG.viewport);

  // Create a mock threat intel report
  await page.setContent(`
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #f8fafc;
          padding: 40px;
        }
        .report {
          max-width: 800px;
          margin: 0 auto;
          background: white;
          border-radius: 12px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.1);
          overflow: hidden;
        }
        .header {
          background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
          color: white;
          padding: 24px 32px;
        }
        .header h1 { font-size: 24px; margin-bottom: 8px; }
        .header p { opacity: 0.9; font-size: 14px; }
        .content { padding: 32px; }
        .alert {
          background: #fef2f2;
          border: 1px solid #fecaca;
          border-radius: 8px;
          padding: 16px 20px;
          margin-bottom: 24px;
        }
        .alert-title {
          color: #991b1b;
          font-weight: 600;
          font-size: 16px;
          margin-bottom: 8px;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .alert-title::before {
          content: '⚠️';
        }
        .ioc-box {
          background: #1e293b;
          color: #e2e8f0;
          padding: 16px 20px;
          border-radius: 8px;
          font-family: 'SF Mono', Monaco, monospace;
          font-size: 14px;
          margin: 16px 0;
          word-break: break-all;
        }
        .ioc-label {
          color: #94a3b8;
          font-size: 12px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          margin-bottom: 8px;
        }
        .meta {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 16px;
          margin-top: 24px;
          padding-top: 24px;
          border-top: 1px solid #e2e8f0;
        }
        .meta-item label {
          display: block;
          color: #64748b;
          font-size: 12px;
          text-transform: uppercase;
          margin-bottom: 4px;
        }
        .meta-item span {
          font-weight: 600;
          color: #1e293b;
        }
        .badge {
          display: inline-block;
          background: #dc2626;
          color: white;
          padding: 4px 12px;
          border-radius: 12px;
          font-size: 12px;
          font-weight: 600;
        }
        .action-hint {
          background: #eff6ff;
          border: 1px solid #bfdbfe;
          border-radius: 8px;
          padding: 16px;
          margin-top: 24px;
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .action-hint svg {
          flex-shrink: 0;
        }
        .action-hint p {
          color: #1e40af;
          font-size: 14px;
        }
      </style>
    </head>
    <body>
      <div class="report">
        <div class="header">
          <h1>Threat Intelligence Report</h1>
          <p>Automated detection from email security gateway</p>
        </div>
        <div class="content">
          <div class="alert">
            <div class="alert-title">Active Phishing Campaign Detected</div>
            <p>This credential harvesting page was found in 12 emails targeting your organization in the last hour.</p>
          </div>

          <div class="ioc-label">Malicious URL (IOC)</div>
          <div class="ioc-box">${DEMO_CONFIG.phishingUrl}</div>

          <div class="meta">
            <div class="meta-item">
              <label>Threat Type</label>
              <span class="badge">Phishing</span>
            </div>
            <div class="meta-item">
              <label>Confidence</label>
              <span>High (98%)</span>
            </div>
            <div class="meta-item">
              <label>First Seen</label>
              <span>${new Date().toLocaleDateString()}</span>
            </div>
          </div>

          <div class="action-hint">
            <svg width="24" height="24" fill="none" stroke="#1e40af" stroke-width="2">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
            </svg>
            <p><strong>BrowserDefense:</strong> Add this IOC to your blocklist to protect all browsers across your organization.</p>
          </div>
        </div>
      </div>
    </body>
    </html>
  `);

  await page.waitForTimeout(200);
  return page;
}

/**
 * Create a mock "IOC Added" confirmation page
 */
async function createAddedConfirmationPage(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.setViewportSize(DEMO_CONFIG.viewport);

  await page.setContent(`
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #f8fafc;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .card {
          background: white;
          border-radius: 16px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.1);
          padding: 48px;
          text-align: center;
          max-width: 500px;
        }
        .success-icon {
          width: 80px;
          height: 80px;
          background: #dcfce7;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0 auto 24px;
        }
        .success-icon svg {
          width: 40px;
          height: 40px;
          stroke: #16a34a;
        }
        h1 {
          color: #1e293b;
          font-size: 24px;
          margin-bottom: 12px;
        }
        p {
          color: #64748b;
          font-size: 16px;
          line-height: 1.6;
        }
        .ioc-added {
          background: #f1f5f9;
          border-radius: 8px;
          padding: 16px;
          margin: 24px 0;
          font-family: 'SF Mono', Monaco, monospace;
          font-size: 13px;
          color: #475569;
          word-break: break-all;
        }
        .stats {
          display: flex;
          justify-content: center;
          gap: 32px;
          margin-top: 24px;
          padding-top: 24px;
          border-top: 1px solid #e2e8f0;
        }
        .stat {
          text-align: center;
        }
        .stat-value {
          font-size: 28px;
          font-weight: 700;
          color: #1e40af;
        }
        .stat-label {
          font-size: 12px;
          color: #64748b;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="success-icon">
          <svg fill="none" stroke="currentColor" stroke-width="3">
            <path d="M20 6L9 17l-5-5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <h1>IOC Added Successfully</h1>
        <p>This threat indicator is now blocked across your entire organization.</p>
        <div class="ioc-added">${TEST_BLOCKLIST_URL}</div>
        <div class="stats">
          <div class="stat">
            <div class="stat-value">247</div>
            <div class="stat-label">Browsers Protected</div>
          </div>
          <div class="stat">
            <div class="stat-value">&lt;1s</div>
            <div class="stat-label">Propagation Time</div>
          </div>
        </div>
      </div>
    </body>
    </html>
  `);

  await page.waitForTimeout(200);
  return page;
}

/**
 * Frame capture definitions
 */
const frames: FrameCapture[] = [
  {
    name: '01-threat-report',
    description: 'SOC analyst reviews threat intel report with phishing URL',
    capture: async (context) => {
      const page = await createThreatReportPage(context);
      await page.screenshot({ path: path.join(OUTPUT_DIR, '01-threat-report.png') });
      await page.close();
    },
  },
  {
    name: '02-popup-active',
    description: 'BrowserDefense popup shows extension is active',
    capture: async (context, extensionId) => {
      const page = await openPopup(context, extensionId);

      // Inject mock data for the demo
      await page.evaluate(() => {
        const statusDot = document.getElementById('status-dot');
        const statusText = document.getElementById('status-text');
        const iocCount = document.getElementById('ioc-count');
        const lastUpdate = document.getElementById('last-update');
        const blocksCount = document.getElementById('blocks-count');

        if (statusDot) statusDot.classList.add('active');
        if (statusText) statusText.textContent = 'Active';
        if (iocCount) iocCount.textContent = '12,847 IOCs';
        if (lastUpdate) lastUpdate.textContent = '2 minutes ago';
        if (blocksCount) blocksCount.textContent = '3';
      });

      await page.waitForTimeout(200);
      await page.screenshot({ path: path.join(OUTPUT_DIR, '02-popup-active.png') });
      await page.close();
    },
  },
  {
    name: '03-ioc-added',
    description: 'Confirmation that IOC was added to blocklist',
    capture: async (context) => {
      const page = await createAddedConfirmationPage(context);
      await page.screenshot({ path: path.join(OUTPUT_DIR, '03-ioc-added.png') });
      await page.close();
    },
  },
  {
    name: '04-blocked-page',
    description: 'User tries to visit URL and sees block page',
    capture: async (context, extensionId) => {
      const page = await openBlockedPage(
        context,
        extensionId,
        DEMO_CONFIG.phishingUrl,
        DEMO_CONFIG.category
      );
      await page.screenshot({ path: path.join(OUTPUT_DIR, '04-blocked-page.png') });
      await page.close();
    },
  },
  {
    name: '05-popup-with-block',
    description: 'Popup shows the recent block event',
    capture: async (context, extensionId) => {
      const page = await openPopup(context, extensionId);

      // Inject mock data with recent block
      await page.evaluate((blockedDomain: string) => {
        const statusDot = document.getElementById('status-dot');
        const statusText = document.getElementById('status-text');
        const iocCount = document.getElementById('ioc-count');
        const lastUpdate = document.getElementById('last-update');
        const blocksCount = document.getElementById('blocks-count');
        const recentList = document.getElementById('recent-list');

        if (statusDot) statusDot.classList.add('active');
        if (statusText) statusText.textContent = 'Active';
        if (iocCount) iocCount.textContent = '12,848 IOCs';
        if (lastUpdate) lastUpdate.textContent = 'Just now';
        if (blocksCount) blocksCount.textContent = '4';

        if (recentList) {
          recentList.innerHTML = `
            <div class="recent-item" style="
              display: flex;
              align-items: center;
              gap: 12px;
              padding: 12px;
              background: #fef2f2;
              border-radius: 8px;
              border-left: 3px solid #dc2626;
            ">
              <div style="
                width: 8px;
                height: 8px;
                background: #dc2626;
                border-radius: 50%;
                flex-shrink: 0;
              "></div>
              <div style="flex: 1; min-width: 0;">
                <div style="
                  font-size: 13px;
                  font-weight: 500;
                  color: #1e293b;
                  white-space: nowrap;
                  overflow: hidden;
                  text-overflow: ellipsis;
                ">${blockedDomain}</div>
                <div style="font-size: 11px; color: #64748b;">Phishing - Just now</div>
              </div>
            </div>
          `;
        }
      }, TEST_BLOCKLIST_URL);

      await page.waitForTimeout(200);
      await page.screenshot({ path: path.join(OUTPUT_DIR, '05-popup-with-block.png') });
      await page.close();
    },
  },
];

/**
 * Get extension ID from browser context
 */
async function getExtensionId(context: BrowserContext): Promise<string> {
  // Wait for service worker
  let extensionId = '';
  const serviceWorkers = context.serviceWorkers();

  if (serviceWorkers.length > 0) {
    const url = serviceWorkers[0].url();
    const match = url.match(/chrome-extension:\/\/([^/]+)/);
    if (match) extensionId = match[1];
  }

  if (!extensionId) {
    const sw = await context.waitForEvent('serviceworker', { timeout: 10000 });
    const url = sw.url();
    const match = url.match(/chrome-extension:\/\/([^/]+)/);
    if (match) extensionId = match[1];
  }

  return extensionId;
}

/**
 * Normalize all frames to consistent dimensions using sharp
 */
async function normalizeFrames(): Promise<void> {
  console.log('\n🔧 Normalizing frames...');

  // Clean/create normalized directory
  if (fs.existsSync(NORMALIZED_DIR)) {
    fs.rmSync(NORMALIZED_DIR, { recursive: true });
  }
  fs.mkdirSync(NORMALIZED_DIR, { recursive: true });

  const frameFiles = fs.readdirSync(OUTPUT_DIR)
    .filter(f => f.endsWith('.png'))
    .sort();

  const targetWidth = 800;
  const targetHeight = 600;
  const bgColor = { r: 15, g: 23, b: 42, alpha: 1 }; // #0f172a (dark blue)

  for (const file of frameFiles) {
    const inputPath = path.join(OUTPUT_DIR, file);
    const outputPath = path.join(NORMALIZED_DIR, file);

    // Create a background canvas and composite the frame on top
    const background = sharp({
      create: {
        width: targetWidth,
        height: targetHeight,
        channels: 4,
        background: bgColor,
      },
    });

    // Resize input to fit within target with padding
    const resizedFrame = await sharp(inputPath)
      .resize(targetWidth - 40, targetHeight - 40, { fit: 'inside' })
      .toBuffer();

    // Get resized dimensions
    const resizedMeta = await sharp(resizedFrame).metadata();
    const rw = resizedMeta.width || 0;
    const rh = resizedMeta.height || 0;

    // Center the frame on the background
    const left = Math.round((targetWidth - rw) / 2);
    const top = Math.round((targetHeight - rh) / 2);

    await background
      .composite([{ input: resizedFrame, left, top }])
      .png()
      .toFile(outputPath);

    console.log(`  ✓ ${file} (${rw}x${rh} -> centered on ${targetWidth}x${targetHeight})`);
  }
}

/**
 * Convert frames to GIF using ffmpeg
 */
async function createGif(): Promise<void> {
  // First normalize all frames to same dimensions
  await normalizeFrames();

  console.log('\n📽️  Converting to GIF...');

  const frameFiles = fs.readdirSync(NORMALIZED_DIR)
    .filter(f => f.endsWith('.png'))
    .sort();

  if (frameFiles.length === 0) {
    throw new Error('No frames found to convert');
  }

  // Create concat file for ffmpeg
  const concatFile = path.join(NORMALIZED_DIR, 'concat.txt');
  const concatContent = frameFiles
    .map(f => `file '${f}'\nduration ${DEMO_CONFIG.frameDelay / 1000}`)
    .join('\n');

  // Add last frame again (ffmpeg concat demuxer quirk)
  const lastFrame = frameFiles[frameFiles.length - 1];
  fs.writeFileSync(concatFile, concatContent + `\nfile '${lastFrame}'`);

  // Ensure output directory exists
  const outputDir = path.dirname(FINAL_GIF);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Generate GIF with ffmpeg
  // Two-pass for better quality: first generate palette, then use it
  const paletteFile = path.join(NORMALIZED_DIR, 'palette.png');

  console.log('  Generating color palette...');
  execSync(
    `ffmpeg -y -f concat -safe 0 -i "${concatFile}" -vf "fps=0.5,palettegen=max_colors=128:stats_mode=diff" "${paletteFile}"`,
    { cwd: NORMALIZED_DIR, stdio: 'pipe' }
  );

  console.log('  Creating GIF...');
  execSync(
    `ffmpeg -y -f concat -safe 0 -i "${concatFile}" -i "${paletteFile}" -filter_complex "fps=0.5[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle" "${FINAL_GIF}"`,
    { cwd: NORMALIZED_DIR, stdio: 'pipe' }
  );

  // Get file size
  const stats = fs.statSync(FINAL_GIF);
  const sizeMB = (stats.size / (1024 * 1024)).toFixed(2);

  console.log(`  ✅ Created: ${FINAL_GIF}`);
  console.log(`  📦 Size: ${sizeMB} MB`);

  // Warn if too large
  if (stats.size > 5 * 1024 * 1024) {
    console.log('  ⚠️  Warning: GIF is larger than 5MB target');
  }
}

/**
 * Main execution
 */
async function main(): Promise<void> {
  console.log('🎬 BrowserDefense Demo GIF Generator\n');

  // Check ffmpeg
  try {
    execSync('which ffmpeg', { stdio: 'pipe' });
  } catch {
    console.error('❌ ffmpeg not found. Install with: brew install ffmpeg');
    process.exit(1);
  }

  // Check extension build
  if (!fs.existsSync(path.join(EXTENSION_PATH, 'manifest.json'))) {
    console.error('❌ Extension not built. Run: npm run build');
    process.exit(1);
  }

  // Clean/create output directory
  if (fs.existsSync(OUTPUT_DIR)) {
    fs.rmSync(OUTPUT_DIR, { recursive: true });
  }
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  console.log('🚀 Launching Chrome with extension...\n');

  // Launch browser with extension
  const context = await chromium.launchPersistentContext('', {
    headless: false,
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`,
      '--no-first-run',
      '--no-default-browser-check',
    ],
  });

  try {
    const extensionId = await getExtensionId(context);
    console.log(`📦 Extension loaded: ${extensionId}\n`);

    // Capture each frame
    for (const frame of frames) {
      console.log(`📸 Capturing: ${frame.name}`);
      console.log(`   ${frame.description}`);
      await frame.capture(context, extensionId);
    }

    console.log('\n✅ All frames captured');

  } finally {
    await context.close();
  }

  // Convert to GIF
  await createGif();

  console.log('\n🎉 Demo generation complete!');
}

main().catch((err) => {
  console.error('❌ Error:', err.message);
  process.exit(1);
});
