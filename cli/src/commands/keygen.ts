/**
 * Key generation command.
 * Generates P-256 ECDSA signing keys (default) or Ed25519 (experimental), and RSA-OAEP encryption keys.
 *
 * P-256 is the default because Ed25519 is not uniformly available in enterprise Chrome deployments.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  generateSigningKeypair,
  generateSigningKeypairEd25519,
  generateEncryptionKeypair,
  generateSalt,
  generateOrgId,
  detectAlgorithm,
} from '../crypto.js';

export interface KeygenOptions {
  type: 'signing' | 'encryption' | 'all';
  output?: string;
  /** Use Ed25519 instead of P-256 ECDSA (requires Chrome 113+) */
  ed25519?: boolean;
}

export async function keygen(options: KeygenOptions): Promise<void> {
  const outputDir = options.output || process.cwd();
  const useEd25519 = options.ed25519 ?? false;

  // Ensure output directory exists
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  if (options.type === 'signing' || options.type === 'all') {
    if (useEd25519) {
      console.log('Generating Ed25519 signing keypair (experimental)...');
      const { publicKey, privateKey } = await generateSigningKeypairEd25519();

      const publicPath = path.join(outputDir, 'signing-public.jwk');
      const privatePath = path.join(outputDir, 'signing-private.jwk');

      fs.writeFileSync(publicPath, JSON.stringify(publicKey, null, 2));
      fs.writeFileSync(privatePath, JSON.stringify(privateKey, null, 2));

      console.log(`  Public key:  ${publicPath}`);
      console.log(`  Private key: ${privatePath}`);
      console.log(`  Algorithm:   Ed25519 (ed25519-v2)`);
    } else {
      console.log('Generating P-256 ECDSA signing keypair...');
      const { publicKey, privateKey } = await generateSigningKeypair();

      const publicPath = path.join(outputDir, 'signing-public.jwk');
      const privatePath = path.join(outputDir, 'signing-private.jwk');

      fs.writeFileSync(publicPath, JSON.stringify(publicKey, null, 2));
      fs.writeFileSync(privatePath, JSON.stringify(privateKey, null, 2));

      console.log(`  Public key:  ${publicPath}`);
      console.log(`  Private key: ${privatePath}`);
      console.log(`  Algorithm:   P-256 ECDSA (p256-v1)`);
    }
  }

  if (options.type === 'encryption' || options.type === 'all') {
    console.log('Generating RSA-OAEP 2048-bit encryption keypair...');
    const { publicKey, privateKey } = await generateEncryptionKeypair();

    const publicPath = path.join(outputDir, 'encryption-public.jwk');
    const privatePath = path.join(outputDir, 'encryption-private.jwk');

    fs.writeFileSync(publicPath, JSON.stringify(publicKey, null, 2));
    fs.writeFileSync(privatePath, JSON.stringify(privateKey, null, 2));

    console.log(`  Public key:  ${publicPath}`);
    console.log(`  Private key: ${privatePath}`);
  }

  if (options.type === 'all') {
    // Also generate salt, org ID, and config
    console.log('Generating organization configuration...');

    const salt = generateSalt();
    const orgId = generateOrgId();

    // Read back the keys for config
    const signingPublic = JSON.parse(
      fs.readFileSync(path.join(outputDir, 'signing-public.jwk'), 'utf-8')
    );
    const encryptionPublic = JSON.parse(
      fs.readFileSync(path.join(outputDir, 'encryption-public.jwk'), 'utf-8')
    );

    const algorithmVersion = detectAlgorithm(signingPublic);

    const config = {
      org_id: orgId,
      signing_public_key: signingPublic,
      encryption_public_key: encryptionPublic,
      blocklist_endpoint: 'https://YOUR_CDN_HERE/blocklist.json',
      forensics_endpoint: 'https://YOUR_ENDPOINT_HERE/forensics',
      ioc_salt: salt,
      key_version: 1,
      algorithm_version: algorithmVersion,
    };

    const configPath = path.join(outputDir, 'browserdefense-config.json');
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    console.log(`  Config:      ${configPath}`);
  }

  console.log('\nDone! Remember to store private keys securely.');
  if (options.type === 'all') {
    console.log('Note: Update blocklist_endpoint and forensics_endpoint in browserdefense-config.json before importing.');
  }

  if (useEd25519 && (options.type === 'signing' || options.type === 'all')) {
    console.log('\nNote: Ed25519 requires Chrome 113+ (May 2023).');
    console.log('P-256 ECDSA is recommended for maximum enterprise compatibility.');
  }
}
