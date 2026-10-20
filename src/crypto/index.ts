/**
 * BrowserDefense Crypto Module
 * RSA-OAEP + AES-GCM for forensics, P-256 ECDSA for signatures, SHA-256 for hashing
 */

export {
  sha256,
  sha256Bytes,
  sha256ArrayBuffer,
  sha256Hex,
  hexToBytes,
  bytesToHex,
  hashIOC,
  hashIOCBytes,
  hashIOCBatch,
  type IOCScope,
} from './hashing';

export {
  importPublicKeySpki,
  importPublicKeyJwk,
  verifySignature,
  verifyBlocklistSignature,
  base64ToArrayBuffer,
  arrayBufferToBase64,
  hexToArrayBuffer,
  arrayBufferToHex,
} from './signing';

export {
  canonicalizeUrl,
  canonicalizeAndHash,
  extractRegistrableDomain,
  validateUrl,
  type CanonicalizationScope,
  type CanonicalizationOptions,
} from './canonicalize';

export {
  encryptForensics,
  decryptForensics,
  generateRSAKeyPair,
  generateAESKey,
  generateIV,
  encryptAESGCM,
  decryptAESGCM,
  importRSAPublicKey,
  importRSAPrivateKey,
  wrapAESKey,
  unwrapAESKey,
  type EncryptedPayload,
  type RSAPublicKeyJWK,
  type RSAPrivateKeyJWK,
} from './encryption';

export {
  // Envelope operations
  createThreatFeedEnvelope,
  decryptThreatFeed,
  addEnvelopeHeader,
  removeEnvelopeHeader,
  // X25519 key operations
  generateX25519KeyPair,
  generateGpoKeyPair,
  importX25519PublicKey,
  importX25519PrivateKey,
  importX25519PublicKeyRaw,
  exportX25519PublicKeyRaw,
  deriveSharedSecret,
  deriveAesKeyFromHkdf,
  isX25519Supported,
  // Types
  type X25519PrivateKeyJWK,
  type X25519PublicKeyJWK,
  type ThreatFeedEnvelope,
  type ThreatFeedHeader,
  type ThreatFeedMeta,
  type ActiveKey,
  type EnvelopeCreationResult,
  type EnvelopeConfig,
} from './threat-feed';

export {
  // Team Mesh encryption (X25519 + HKDF + AES-GCM)
  encryptTeamMesh,
  decryptTeamMesh,
  encryptThreatFeed as encryptThreatFeedTeamMesh,
  decryptThreatFeed as decryptThreatFeedTeamMesh,
  deriveAESKeyFromSecret,
  HKDF_INFO,
  type TeamMeshPayload,
} from './team-mesh';
