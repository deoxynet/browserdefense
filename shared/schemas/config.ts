/**
 * Shared Configuration Schema
 *
 * Zod-based schema definitions shared between CLI and extension.
 * This ensures consistent validation across all components.
 *
 * Issue #487
 */

import { z } from 'zod';

// ============================================================================
// JWK Key Schemas
// ============================================================================

/**
 * Ed25519 public key schema (OKP key type).
 * Preferred algorithm for new deployments.
 */
export const Ed25519PublicKeySchema = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  x: z
    .string()
    .min(40, 'Ed25519 public key x must be ~43 base64url chars')
    .max(50, 'Ed25519 public key x must be ~43 base64url chars')
    .regex(/^[A-Za-z0-9_-]+$/, 'x must be valid base64url'),
  alg: z.string().optional(),
  use: z.string().optional(),
  kid: z.string().optional(),
});

export type Ed25519PublicKeyJWK = z.infer<typeof Ed25519PublicKeySchema>;

/**
 * P-256 ECDSA public key schema (EC key type).
 * Supported for backwards compatibility with legacy deployments.
 */
export const P256PublicKeySchema = z.object({
  kty: z.literal('EC'),
  crv: z.literal('P-256'),
  x: z.string().min(1, 'x coordinate is required').regex(/^[A-Za-z0-9_-]+$/, 'x must be valid base64url'),
  y: z.string().min(1, 'y coordinate is required').regex(/^[A-Za-z0-9_-]+$/, 'y must be valid base64url'),
  alg: z.string().optional(),
  use: z.string().optional(),
  kid: z.string().optional(),
});

export type P256PublicKeyJWK = z.infer<typeof P256PublicKeySchema>;

/**
 * Union of all supported signing public key types.
 */
export const SigningPublicKeySchema = z.discriminatedUnion('kty', [
  Ed25519PublicKeySchema,
  P256PublicKeySchema,
]);

export type SigningPublicKeyJWK = z.infer<typeof SigningPublicKeySchema>;

/**
 * RSA-OAEP public key schema for forensics encryption.
 */
export const RSAPublicKeySchema = z.object({
  kty: z.literal('RSA'),
  n: z
    .string()
    .min(300, 'RSA modulus too short (recommend 2048-bit or larger)')
    .regex(/^[A-Za-z0-9_-]+$/, 'modulus must be valid base64url'),
  e: z.string().min(1, 'exponent is required').regex(/^[A-Za-z0-9_-]+$/, 'exponent must be valid base64url'),
  alg: z.string().optional(),
  use: z.string().optional(),
  kid: z.string().optional(),
});

export type RSAPublicKeyJWK = z.infer<typeof RSAPublicKeySchema>;

// ============================================================================
// IOC Scope
// ============================================================================

/**
 * IOC hashing scope - determines what parts of the URL are included in the hash.
 */
export const IOCScopeSchema = z.enum(['HOST_ONLY', 'HOST_PATH', 'FULL_URL']);

export type IOCScope = z.infer<typeof IOCScopeSchema>;

// ============================================================================
// HTTPS URL Validation
// ============================================================================

/**
 * HTTPS URL schema - ensures URL is valid and uses HTTPS.
 */
export const HttpsUrlSchema = z.string().url('must be a valid URL').refine(
  (url) => {
    try {
      return new URL(url).protocol === 'https:';
    } catch {
      return false;
    }
  },
  { message: 'must use HTTPS' }
);

// ============================================================================
// Screenshot Capture Config
// ============================================================================

/**
 * Screenshot capture configuration (opt-in feature).
 */
export const ScreenshotCaptureConfigSchema = z.object({
  enabled: z.boolean().default(false),
  quality: z.number().int().min(0).max(100).default(80).optional(),
  tier: z.string().optional(),
});

export type ScreenshotCaptureConfig = z.infer<typeof ScreenshotCaptureConfigSchema>;

// ============================================================================
// Main BrowserDefense Config Schema
// ============================================================================

/**
 * Complete BrowserDefense configuration schema.
 * This is what customers import via the options page.
 */
export const BrowserDefenseConfigSchema = z.object({
  /** Organization identifier (e.g., "acme-corp") */
  org_id: z
    .string()
    .transform((s) => s.trim())
    .pipe(z.string().min(1, 'org_id must be a non-empty string')),

  /** Public key for verifying blocklist signatures (Ed25519 preferred, P-256 for legacy) */
  signing_public_key: SigningPublicKeySchema,

  /** RSA-OAEP public key for encrypting forensics data */
  encryption_public_key: RSAPublicKeySchema,

  /** URL to fetch signed blocklist updates from */
  blocklist_endpoint: HttpsUrlSchema,

  /** URL to upload encrypted forensics data to */
  forensics_endpoint: HttpsUrlSchema,

  /** Salt for IOC hashing - must match CLI compile salt */
  ioc_salt: z
    .string()
    .transform((s) => s.trim())
    .pipe(z.string().min(1, 'ioc_salt must be a non-empty string')),

  /** IOC hashing scope (default: HOST_ONLY) - must match CLI compile scope */
  ioc_scope: IOCScopeSchema.optional(),

  /** How often to check for blocklist updates (default: 60 minutes) */
  update_interval_minutes: z.number().int().min(1).max(1440).optional(),

  /** Screenshot capture configuration (opt-in feature) */
  screenshot_capture: ScreenshotCaptureConfigSchema.optional(),
});

export type BrowserDefenseConfig = z.infer<typeof BrowserDefenseConfigSchema>;

// ============================================================================
// Blocklist Manifest Schema
// ============================================================================

/**
 * Blocklist manifest schema - the signed manifest served by the CDN.
 */
export const BlocklistManifestSchema = z.object({
  version: z.number().int().positive(),
  total_iocs: z.number().int().nonnegative(),
  bucket_count: z.number().int().positive(),
  sha256_root: z.string().length(64, 'sha256_root must be 64 hex characters'),
  signature: z.string().optional(),
  created_at: z.string().datetime().optional(),
  algorithm_version: z.enum(['ed25519-v2', 'p256-v1']).optional(),
  snapshot_url: z.string().optional(),
  deltas: z
    .array(
      z.object({
        from: z.number().int(),
        to: z.number().int(),
        url: z.string(),
        size: z.number().int().positive(),
      })
    )
    .optional(),
});

export type BlocklistManifest = z.infer<typeof BlocklistManifestSchema>;

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Validation result type matching the existing interface.
 */
export type ConfigValidationResult =
  | { valid: true; config: BrowserDefenseConfig }
  | { valid: false; errors: string[] };

/**
 * Validate a BrowserDefense configuration object using Zod.
 *
 * @param data - Unknown data to validate
 * @returns Validation result with parsed config or error messages
 */
export function validateConfig(data: unknown): ConfigValidationResult {
  const result = BrowserDefenseConfigSchema.safeParse(data);

  if (result.success) {
    return { valid: true, config: result.data };
  }

  // Convert Zod errors to user-friendly messages
  const errors = result.error.issues.map((issue) => {
    const path = issue.path.join('.');
    return path ? `${path}: ${issue.message}` : issue.message;
  });

  return { valid: false, errors };
}

/**
 * Parse and validate a config, throwing on error.
 * Useful for CLI where you want to fail fast.
 */
export function parseConfig(data: unknown): BrowserDefenseConfig {
  return BrowserDefenseConfigSchema.parse(data);
}

/**
 * Validate just the signing public key.
 */
export function validateSigningPublicKey(
  key: unknown
): { valid: true; key: SigningPublicKeyJWK } | { valid: false; errors: string[] } {
  const result = SigningPublicKeySchema.safeParse(key);

  if (result.success) {
    return { valid: true, key: result.data };
  }

  const errors = result.error.issues.map((issue) => {
    const path = issue.path.join('.');
    return path ? `${path}: ${issue.message}` : issue.message;
  });

  return { valid: false, errors };
}

/**
 * Validate just the encryption public key.
 */
export function validateEncryptionPublicKey(
  key: unknown
): { valid: true; key: RSAPublicKeyJWK } | { valid: false; errors: string[] } {
  const result = RSAPublicKeySchema.safeParse(key);

  if (result.success) {
    return { valid: true, key: result.data };
  }

  const errors = result.error.issues.map((issue) => {
    const path = issue.path.join('.');
    return path ? `${path}: ${issue.message}` : issue.message;
  });

  return { valid: false, errors };
}

// ============================================================================
// Example Config Factories
// ============================================================================

/**
 * Create an example configuration for documentation/testing.
 * Uses Ed25519 as the preferred algorithm.
 */
export function createExampleConfig(): BrowserDefenseConfig {
  return {
    org_id: 'example-org',
    signing_public_key: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
    },
    encryption_public_key: {
      kty: 'RSA',
      n: 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
      e: 'AQAB',
    },
    blocklist_endpoint: 'https://cdn.example.com/blocklist.json',
    forensics_endpoint: 'https://forensics.example.com/upload',
    ioc_salt: 'example-salt-do-not-use-in-production',
    ioc_scope: 'HOST_ONLY',
    update_interval_minutes: 60,
  };
}

/**
 * Create a legacy P-256 example configuration for backwards compatibility testing.
 */
export function createLegacyP256ExampleConfig(): BrowserDefenseConfig {
  return {
    org_id: 'example-org-legacy',
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
    ioc_salt: 'example-salt-do-not-use-in-production',
    ioc_scope: 'HOST_ONLY',
    update_interval_minutes: 60,
  };
}
