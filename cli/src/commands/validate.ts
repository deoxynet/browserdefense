/**
 * Validate command.
 * Verifies blocklist manifest signatures.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyManifest, verify, sha256, type ECPublicKeyJWK, type BlocklistManifest } from '../crypto.js';

export interface ValidateOptions {
  key: string;
  manifest?: string;
}

export async function validate(options: ValidateOptions): Promise<void> {
  // Load public key
  const keyPath = options.key;
  if (!fs.existsSync(keyPath)) {
    console.error(`Error: Key file not found: ${keyPath}`);
    process.exit(1);
  }

  let publicKey: ECPublicKeyJWK;
  try {
    publicKey = JSON.parse(fs.readFileSync(keyPath, 'utf-8'));
    if (publicKey.kty !== 'EC' || publicKey.crv !== 'P-256') {
      throw new Error('Not a P-256 key');
    }
  } catch (err) {
    console.error(`Error: Invalid public key: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  // Load manifest
  const manifestPath = options.manifest || path.join(process.cwd(), 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    console.error(`Error: Manifest file not found: ${manifestPath}`);
    process.exit(1);
  }

  let manifest: BlocklistManifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
  } catch (err) {
    console.error(`Error: Invalid manifest JSON: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  if (!manifest.signature) {
    console.error('Error: Manifest has no signature');
    process.exit(1);
  }

  console.log('Verifying manifest signature...');
  console.log(`  Version:     ${manifest.version}`);
  console.log(`  Total IOCs:  ${manifest.total_iocs}`);
  console.log(`  Buckets:     ${manifest.bucket_count}`);
  console.log(`  Root Hash:   ${manifest.sha256_root.substring(0, 16)}...`);
  console.log(`  Signature:   ${manifest.signature.substring(0, 32)}...`);

  const isValid = await verifyManifest(manifest, publicKey);

  if (isValid) {
    console.log('\nSignature is VALID');
    process.exit(0);
  } else {
    console.error('\nSignature is INVALID');
    process.exit(1);
  }
}

/**
 * Validate a file signature.
 */
export async function validateFile(
  filePath: string,
  signaturePath: string,
  keyPath: string
): Promise<void> {
  if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
  }

  if (!fs.existsSync(signaturePath)) {
    console.error(`Error: Signature file not found: ${signaturePath}`);
    process.exit(1);
  }

  if (!fs.existsSync(keyPath)) {
    console.error(`Error: Key file not found: ${keyPath}`);
    process.exit(1);
  }

  let publicKey: ECPublicKeyJWK;
  try {
    publicKey = JSON.parse(fs.readFileSync(keyPath, 'utf-8'));
    if (publicKey.kty !== 'EC' || publicKey.crv !== 'P-256') {
      throw new Error('Not a P-256 key');
    }
  } catch (err) {
    console.error(`Error: Invalid public key: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  const fileContent = fs.readFileSync(filePath);
  const signature = fs.readFileSync(signaturePath, 'utf-8').trim();
  const hash = sha256(fileContent);

  console.log(`File hash: ${hash}`);

  const isValid = await verify(fileContent, signature, publicKey);

  if (isValid) {
    console.log('Signature is VALID');
    process.exit(0);
  } else {
    console.error('Signature is INVALID');
    process.exit(1);
  }
}
