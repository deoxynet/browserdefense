/**
 * Test fixtures for deployment export tests
 */

import type { DeploymentConfig } from '../../src/deployment/types.js';

/**
 * Sample P-256 signing public key (test only - not a real key)
 */
export const testSigningPublicKey: JsonWebKey = {
  kty: 'EC',
  crv: 'P-256',
  x: 'WbbXwVSeNU_E5WCuJT5L9Gj4qGY3TrnvHbGvqptXvJI',
  y: 'hHGFGU_RXbxvWwWvFBJBwBwGAAkNbwVPnQMfbz3QMm0',
};

/**
 * Sample RSA encryption public key (test only - not a real key)
 */
export const testEncryptionPublicKey: JsonWebKey = {
  kty: 'RSA',
  n: 'wJENcRev-eXZKvhhWLiV3Ga5SoagXl9NK3q4O1KveJGQ3y4aKkXqL3vR7EKvLYA8h_BnQu0lGCkeGpjKGFTbzq1aHWvVPLUV3nqKLAhC6a1J3DaS_7N3F-mzxIZEqdSPJdxJUTbI3Q',
  e: 'AQAB',
};

/**
 * Standard test configuration
 */
export const testConfig: DeploymentConfig = {
  orgSlug: 'test-org',
  extensionId: 'abcdefghijklmnopqrstuvwxyzabcdef',
  signingPublicKey: testSigningPublicKey,
  encryptionPublicKey: testEncryptionPublicKey,
  iocSalt: '7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a',
  blocklistEndpoint: 'https://browserdefense.net/bl/test-org',
  forensicsEndpoint: 'https://browserdefense.net/f/test-org',
  updateIntervalMinutes: 60,
  orgDisplayName: 'Test Organization',
  enableDebugLogging: false,
};

/**
 * Config with special characters (to test XML escaping)
 */
export const testConfigWithSpecialChars: DeploymentConfig = {
  ...testConfig,
  orgSlug: 'test-org-special',
  orgDisplayName: 'Test & Org <Special> "Chars"',
};
