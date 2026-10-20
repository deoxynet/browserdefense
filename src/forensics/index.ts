/**
 * Forensics Module
 *
 * Provides forensic capture capabilities for incident investigation.
 * All forensics data is encrypted client-side (zero-knowledge).
 */

export {
  // Screenshot capture
  captureScreenshot,
  captureAndEncryptScreenshot,
  applyWatermark,
  shouldCaptureScreenshot,
  DEFAULT_SCREENSHOT_CONFIG,
  type ScreenshotOptions,
  type ScreenshotResult,
  type EncryptedScreenshot,
  type WatermarkConfig,
  type ScreenshotConfig,
} from './screenshot';
