/**
 * Sign command.
 * Signs a blocklist manifest with an Ed25519 or P-256 ECDSA private key.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  signManifest,
  sha256,
  sign as signRaw,
  detectAlgorithm,
  type SigningPrivateKeyJWK,
  type BlocklistManifest,
} from '../crypto.js';

export interface SignOptions {
  key: string;
  manifest?: string;
  output?: string;
}

export async function sign(options: SignOptions): Promise<void> {
  // Load private key
  const keyPath = options.key;
  if (!fs.existsSync(keyPath)) {
    console.error(`Error: Key file not found: ${keyPath}`);
    process.exit(1);
  }

  let privateKey: SigningPrivateKeyJWK;
  let algorithmVersion: string;
  try {
    privateKey = JSON.parse(fs.readFileSync(keyPath, 'utf-8'));

    // Validate key type - support both Ed25519 and P-256
    if (privateKey.kty === 'OKP' && privateKey.crv === 'Ed25519') {
      if (!('d' in privateKey) || !privateKey.d) {
        throw new Error('Not a private key (missing d parameter)');
      }
      algorithmVersion = 'Ed25519 (ed25519-v2)';
    } else if (privateKey.kty === 'EC' && privateKey.crv === 'P-256') {
      if (!('d' in privateKey) || !privateKey.d) {
        throw new Error('Not a private key (missing d parameter)');
      }
      algorithmVersion = 'P-256 ECDSA (p256-v1)';
    } else {
      // Type cast for error message since TypeScript narrows to never
      const keyData = privateKey as { kty?: string; crv?: string };
      throw new Error(
        `Unsupported key type: ${keyData.kty} ${keyData.crv}. ` +
          'Expected Ed25519 (OKP/Ed25519) or P-256 (EC/P-256).'
      );
    }
  } catch (err) {
    console.error(`Error: Invalid signing key: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  // Load manifest
  const manifestPath = options.manifest || path.join(process.cwd(), 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    console.error(`Error: Manifest file not found: ${manifestPath}`);
    process.exit(1);
  }

  let manifest: Omit<BlocklistManifest, 'signature'>;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));

    // Validate required fields
    if (typeof manifest.version !== 'number') throw new Error('Missing version');
    if (typeof manifest.total_iocs !== 'number') throw new Error('Missing total_iocs');
    if (typeof manifest.bucket_count !== 'number') throw new Error('Missing bucket_count');
    if (typeof manifest.sha256_root !== 'string') throw new Error('Missing sha256_root');
  } catch (err) {
    console.error(`Error: Invalid manifest: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  console.log('Signing manifest...');
  console.log(`  Version:     ${manifest.version}`);
  console.log(`  Total IOCs:  ${manifest.total_iocs}`);
  console.log(`  Buckets:     ${manifest.bucket_count}`);
  console.log(`  Root Hash:   ${manifest.sha256_root.substring(0, 16)}...`);
  console.log(`  Algorithm:   ${algorithmVersion}`);

  const signedManifest = await signManifest(manifest, privateKey);

  // Write signed manifest
  const outputPath = options.output || manifestPath;
  fs.writeFileSync(outputPath, JSON.stringify(signedManifest, null, 2));

  console.log(`\nSigned manifest written to: ${outputPath}`);
  console.log(`Signature: ${signedManifest.signature?.substring(0, 32)}...`);
}

/**
 * Sign raw data (file contents).
 * Useful for signing blocklist binary files.
 */
export async function signFile(
  filePath: string,
  keyPath: string,
  outputPath?: string
): Promise<void> {
  if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
  }

  if (!fs.existsSync(keyPath)) {
    console.error(`Error: Key file not found: ${keyPath}`);
    process.exit(1);
  }

  let privateKey: SigningPrivateKeyJWK;
  try {
    privateKey = JSON.parse(fs.readFileSync(keyPath, 'utf-8'));

    // Validate key type - support both Ed25519 and P-256
    if (privateKey.kty === 'OKP' && privateKey.crv === 'Ed25519') {
      if (!('d' in privateKey) || !privateKey.d) {
        throw new Error('Not a private key (missing d parameter)');
      }
    } else if (privateKey.kty === 'EC' && privateKey.crv === 'P-256') {
      if (!('d' in privateKey) || !privateKey.d) {
        throw new Error('Not a private key (missing d parameter)');
      }
    } else {
      // Type cast for error message since TypeScript narrows to never
      const keyData = privateKey as { kty?: string; crv?: string };
      throw new Error(
        `Unsupported key type: ${keyData.kty} ${keyData.crv}. ` +
          'Expected Ed25519 (OKP/Ed25519) or P-256 (EC/P-256).'
      );
    }
  } catch (err) {
    console.error(`Error: Invalid signing key: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  const fileContent = fs.readFileSync(filePath);
  const hash = sha256(fileContent);

  const signature = await signRaw(fileContent, privateKey);

  const sigPath = outputPath || filePath + '.sig';
  fs.writeFileSync(sigPath, signature);

  const algorithm = detectAlgorithm(privateKey);
  console.log(`File hash:  ${hash}`);
  console.log(`Algorithm:  ${algorithm}`);
  console.log(`Signature:  ${sigPath}`);
}
