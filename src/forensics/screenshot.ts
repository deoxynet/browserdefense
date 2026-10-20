/**
 * Screenshot Capture Module (Opt-In)
 *
 * Captures screenshots of blocked pages for forensic investigation.
 * Key privacy/security properties:
 *
 * - DISABLED by default (per-IOC opt-in required)
 * - Captures AFTER block (shows block page, not malicious content)
 * - Inputs are disabled on the blocked page (visible disruption)
 * - Watermarked with logo + tier (not stealthy → not spyware)
 * - Encrypted immediately client-side (zero-knowledge)
 *
 * Reference: Issue #166
 */

import {
  encryptForensics,
  type EncryptedPayload,
  type RSAPublicKeyJWK,
} from '../crypto/encryption';

// ============ Types ============

/**
 * Watermark configuration for screenshots.
 */
export interface WatermarkConfig {
  /** Organization name or ID */
  orgId: string;
  /** Subscription tier (e.g., "Enterprise", "Pro", "Free") */
  tier?: string;
  /** Custom text to add to watermark */
  customText?: string;
}

/**
 * Screenshot capture options.
 */
export interface ScreenshotOptions {
  /** Image quality (0-100, default 80) */
  quality?: number;
  /** Watermark configuration */
  watermark?: WatermarkConfig;
  /** Delay before capture in ms (allows block page to render) */
  captureDelayMs?: number;
}

/**
 * Screenshot capture result.
 */
export interface ScreenshotResult {
  /** Whether capture succeeded */
  success: boolean;
  /** Base64-encoded PNG image data (unencrypted) */
  imageData?: string;
  /** Image dimensions */
  dimensions?: { width: number; height: number };
  /** Capture timestamp (ISO 8601) */
  timestamp: string;
  /** Error message if capture failed */
  error?: string;
}

/**
 * Encrypted screenshot ready for upload.
 */
export interface EncryptedScreenshot {
  /** Encrypted payload containing the screenshot */
  encrypted: EncryptedPayload;
  /** Capture timestamp (ISO 8601) - not encrypted for audit trail */
  timestamp: string;
  /** SHA-256 hash of the screenshot (for integrity verification) */
  imageHash: string;
  /** Image dimensions (not sensitive) */
  dimensions: { width: number; height: number };
}

// ============ Constants ============

/** Default screenshot quality (0-100) */
const DEFAULT_QUALITY = 80;

/** Default delay before capture to allow block page to render */
const DEFAULT_CAPTURE_DELAY_MS = 500;

/** Watermark font size in pixels */
const WATERMARK_FONT_SIZE = 14;

/** Watermark padding from edges */
const WATERMARK_PADDING = 10;

/** Watermark opacity (0-1) */
const WATERMARK_OPACITY = 0.7;

// ============ Screenshot Capture ============

/**
 * Capture a screenshot of the current visible tab.
 *
 * IMPORTANT: This captures the BLOCK PAGE, not the original malicious page.
 * The malicious page has already been replaced by the time this runs.
 *
 * @param tabId - Tab to capture (must be the block page tab)
 * @param options - Capture options
 * @returns Screenshot result with base64 image data
 */
export async function captureScreenshot(
  tabId: number,
  options: ScreenshotOptions = {}
): Promise<ScreenshotResult> {
  const timestamp = new Date().toISOString();
  const { quality = DEFAULT_QUALITY, captureDelayMs = DEFAULT_CAPTURE_DELAY_MS } = options;

  try {
    // Wait for block page to fully render
    if (captureDelayMs > 0) {
      await delay(captureDelayMs);
    }

    // Verify the tab still exists and is the block page
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url?.includes(chrome.runtime.id) || !tab.url?.includes('blocked')) {
      return {
        success: false,
        timestamp,
        error: 'Tab is not showing the block page',
      };
    }

    // Get the window ID for the tab
    const windowId = tab.windowId;

    // Capture the visible tab
    // Note: This captures whatever is currently visible in the tab
    const dataUrl = await chrome.tabs.captureVisibleTab(windowId, {
      format: 'png',
      quality,
    });

    // Extract base64 data from data URL
    const base64Data = dataUrl.replace(/^data:image\/png;base64,/, '');

    // Get image dimensions (we'll estimate from data size or use canvas)
    const dimensions = await getImageDimensions(dataUrl);

    // Apply watermark if configured
    let finalImageData = base64Data;
    if (options.watermark) {
      const watermarked = await applyWatermark(dataUrl, options.watermark);
      finalImageData = watermarked.replace(/^data:image\/png;base64,/, '');
    }

    return {
      success: true,
      imageData: finalImageData,
      dimensions,
      timestamp,
    };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    console.error('[BrowserDefense] Screenshot capture failed:', error);

    return {
      success: false,
      timestamp,
      error,
    };
  }
}

/**
 * Capture and immediately encrypt a screenshot.
 *
 * This is the main function for zero-knowledge screenshot capture:
 * 1. Captures the block page screenshot
 * 2. Applies watermark
 * 3. Encrypts with RSA-OAEP + AES-GCM
 *
 * BrowserDefense never sees the unencrypted screenshot.
 *
 * @param tabId - Tab to capture
 * @param publicKeyJwk - Customer's RSA public key for encryption
 * @param options - Capture options
 * @returns Encrypted screenshot or null if capture failed
 */
export async function captureAndEncryptScreenshot(
  tabId: number,
  publicKeyJwk: RSAPublicKeyJWK,
  options: ScreenshotOptions = {}
): Promise<EncryptedScreenshot | null> {
  // Capture screenshot
  const result = await captureScreenshot(tabId, options);

  if (!result.success || !result.imageData) {
    console.warn('[BrowserDefense] Screenshot capture failed:', result.error);
    return null;
  }

  try {
    // Calculate hash of image for integrity
    const imageHash = await hashImageData(result.imageData);

    // Encrypt the screenshot payload
    const payload = {
      imageData: result.imageData,
      timestamp: result.timestamp,
      dimensions: result.dimensions,
    };

    const encrypted = await encryptForensics(payload, publicKeyJwk);

    return {
      encrypted,
      timestamp: result.timestamp,
      imageHash,
      dimensions: result.dimensions!,
    };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    console.error('[BrowserDefense] Screenshot encryption failed:', error);
    return null;
  }
}

// ============ Watermarking ============

/**
 * Apply watermark to a screenshot.
 *
 * Watermark includes:
 * - Organization ID
 * - Subscription tier (if provided)
 * - Timestamp
 * - "BrowserDefense" branding
 *
 * The watermark is semi-transparent and placed in the bottom-right corner.
 * This makes the capture VISIBLE (not stealthy) → not spyware.
 *
 * @param dataUrl - Original screenshot as data URL
 * @param config - Watermark configuration
 * @returns Watermarked screenshot as data URL
 */
export async function applyWatermark(
  dataUrl: string,
  config: WatermarkConfig
): Promise<string> {
  return new Promise((resolve, reject) => {
    const img = new Image();

    img.onload = () => {
      try {
        // Create canvas with image dimensions
        const canvas = new OffscreenCanvas(img.width, img.height);
        const ctx = canvas.getContext('2d');

        if (!ctx) {
          reject(new Error('Failed to get canvas context'));
          return;
        }

        // Draw original image
        ctx.drawImage(img, 0, 0);

        // Build watermark text
        const lines: string[] = [];
        lines.push(`BrowserDefense`);
        lines.push(`Org: ${config.orgId}`);
        if (config.tier) {
          lines.push(`Tier: ${config.tier}`);
        }
        lines.push(`Captured: ${new Date().toISOString()}`);
        if (config.customText) {
          lines.push(config.customText);
        }

        // Configure watermark style
        ctx.font = `${WATERMARK_FONT_SIZE}px monospace`;
        ctx.globalAlpha = WATERMARK_OPACITY;

        // Calculate text dimensions
        const lineHeight = WATERMARK_FONT_SIZE + 4;
        const maxWidth = Math.max(
          ...lines.map((line) => ctx.measureText(line).width)
        );
        const totalHeight = lines.length * lineHeight;

        // Position in bottom-right corner
        const x = img.width - maxWidth - WATERMARK_PADDING - 10;
        const y = img.height - totalHeight - WATERMARK_PADDING;

        // Draw semi-transparent background
        ctx.fillStyle = 'rgba(0, 0, 0, 0.5)';
        ctx.fillRect(
          x - 5,
          y - lineHeight + 5,
          maxWidth + 15,
          totalHeight + 10
        );

        // Draw text
        ctx.fillStyle = 'white';
        ctx.globalAlpha = 1;
        lines.forEach((line, i) => {
          ctx.fillText(line, x, y + i * lineHeight);
        });

        // Convert back to data URL
        canvas.convertToBlob({ type: 'image/png' }).then((blob) => {
          const reader = new FileReader();
          reader.onloadend = () => {
            resolve(reader.result as string);
          };
          reader.onerror = reject;
          reader.readAsDataURL(blob);
        });
      } catch (err) {
        reject(err);
      }
    };

    img.onerror = () => reject(new Error('Failed to load image'));
    img.src = dataUrl;
  });
}

// ============ Helpers ============

/**
 * Get image dimensions from a data URL.
 */
async function getImageDimensions(
  dataUrl: string
): Promise<{ width: number; height: number }> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve({ width: img.width, height: img.height });
    img.onerror = reject;
    img.src = dataUrl;
  });
}

/**
 * Calculate SHA-256 hash of image data.
 */
async function hashImageData(base64Data: string): Promise<string> {
  const bytes = Uint8Array.from(atob(base64Data), (c) => c.charCodeAt(0));
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Simple delay helper.
 */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============ IOC Screenshot Flag ============

/**
 * Check if screenshot capture is enabled for an IOC.
 *
 * Screenshot capture requires:
 * 1. Global feature is enabled in config
 * 2. Per-IOC flag is set (captureScreenshot: true)
 *
 * This double opt-in ensures screenshots are never captured accidentally.
 */
export function shouldCaptureScreenshot(
  globalEnabled: boolean,
  iocCaptureFlag?: boolean
): boolean {
  // Both global and per-IOC flags must be true
  return globalEnabled === true && iocCaptureFlag === true;
}

/**
 * Screenshot capture settings for configuration.
 */
export interface ScreenshotConfig {
  /** Whether screenshot capture is globally enabled (default: false) */
  enabled: boolean;
  /** Default quality for captures (0-100) */
  quality?: number;
  /** Organization tier for watermark */
  tier?: string;
}

/**
 * Default screenshot configuration (everything disabled).
 */
export const DEFAULT_SCREENSHOT_CONFIG: ScreenshotConfig = {
  enabled: false,
  quality: DEFAULT_QUALITY,
};
