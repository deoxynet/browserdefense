/**
 * BrowserDefense Configuration Schema
 *
 * Re-exports from shared Zod schemas for backwards compatibility.
 * All new code should import directly from '@shared/schemas'.
 *
 * @see shared/schemas/config.ts for the canonical schema definitions.
 */

// Re-export all types and functions from shared schemas
export {
  // Key schemas and types
  Ed25519PublicKeySchema,
  type Ed25519PublicKeyJWK,
  P256PublicKeySchema,
  type P256PublicKeyJWK,
  SigningPublicKeySchema,
  type SigningPublicKeyJWK,
  RSAPublicKeySchema,
  type RSAPublicKeyJWK,
  // IOC scope
  IOCScopeSchema,
  type IOCScope,
  // Screenshot config
  ScreenshotCaptureConfigSchema,
  type ScreenshotCaptureConfig,
  // Main config
  BrowserDefenseConfigSchema,
  type BrowserDefenseConfig,
  // Blocklist manifest
  BlocklistManifestSchema,
  type BlocklistManifest,
  // Validation helpers
  type ConfigValidationResult,
  validateConfig,
  parseConfig,
  validateSigningPublicKey,
  validateEncryptionPublicKey,
  // Example factories
  createExampleConfig,
  createLegacyP256ExampleConfig,
} from '../../shared/schemas/config';

// Re-export RSAPublicKeyJWK from encryption for backwards compatibility
// (some code may import it from here)
export type { RSAPublicKeyJWK as RSAEncryptionKeyJWK } from '../crypto/encryption';
