/**
 * Configuration for generating deployment exports
 */
export interface DeploymentConfig {
  /** Organization slug/identifier */
  orgSlug: string;

  /** Chrome extension ID */
  extensionId: string;

  /** P-256 ECDSA signing public key in JWK format */
  signingPublicKey: JsonWebKey;

  /** RSA-OAEP encryption public key in JWK format */
  encryptionPublicKey: JsonWebKey;

  /** IOC salt for hashing (hex string) */
  iocSalt: string;

  /** Blocklist update endpoint URL */
  blocklistEndpoint: string;

  /** Forensics upload endpoint URL */
  forensicsEndpoint: string;

  /** Update interval in minutes (default: 60) */
  updateIntervalMinutes?: number;

  /** Organization display name */
  orgDisplayName?: string;

  /** Enable debug logging (default: false) */
  enableDebugLogging?: boolean;
}

/**
 * Result of ADMX generation (includes both files)
 */
export interface ADMXResult {
  admx: string;
  adml: string;
}
