/**
 * Configuration module exports.
 *
 * Re-exports storage keys, config loaders, and schema utilities.
 */

// Storage key constants (Issue #490)
export * from './storage-keys';

// Config loader
export {
  saveConfig,
  loadConfig,
  hasConfig,
  clearConfig,
  parseConfigJson,
  exportConfigJson,
  requireConfig,
} from './loader';

// Schema and validation
export {
  type BrowserDefenseConfig,
  type ConfigValidationResult,
  type Ed25519PublicKeyJWK,
  type P256PublicKeyJWK,
  type SigningPublicKeyJWK,
  type IOCScope,
  type ScreenshotCaptureConfig,
  validateConfig,
  createExampleConfig,
} from './schema';

// Demo mode configuration (Issue #571)
export {
  type DemoConfig,
  DEFAULT_DEMO_CONFIG,
  loadDemoConfig,
  saveDemoConfig,
  isDemoModeEnabled,
  matchesDemoUrl,
  getDemoUrlsIfEnabled,
} from './demo';
