/**
 * Decrypt command for forensics files.
 * Decrypts encrypted forensics captured by the extension using RSA-OAEP + AES-GCM.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { decryptForensics, RSAPrivateKeyJWK, EncryptedPayload } from '../crypto.js';

export interface DecryptOptions {
  key: string;
  input: string;
  output?: string;
  format: 'json' | 'pretty';
}

/**
 * Decrypt forensics files.
 */
export async function decrypt(options: DecryptOptions): Promise<void> {
  // Load private key
  const privateKeyJwk = loadPrivateKey(options.key);

  // Determine if input is a file or directory
  const inputStat = fs.statSync(options.input);

  if (inputStat.isDirectory()) {
    await decryptDirectory(options.input, privateKeyJwk, options.output, options.format);
  } else {
    await decryptFile(options.input, privateKeyJwk, options.output, options.format);
  }
}

/**
 * Load RSA private key from JWK file.
 */
function loadPrivateKey(keyPath: string): RSAPrivateKeyJWK {
  if (!fs.existsSync(keyPath)) {
    console.error(`Error: Key file not found: ${keyPath}`);
    process.exit(1);
  }

  try {
    const keyData = fs.readFileSync(keyPath, 'utf-8');
    const key = JSON.parse(keyData) as RSAPrivateKeyJWK;

    // Validate it's an RSA private key
    if (key.kty !== 'RSA') {
      console.error(`Error: Expected RSA key, got ${key.kty}`);
      process.exit(1);
    }

    if (!key.d) {
      console.error('Error: Key is not a private key (missing "d" component)');
      process.exit(1);
    }

    return key;
  } catch (err) {
    console.error(`Error: Failed to parse key file: ${err}`);
    process.exit(1);
  }
}

/**
 * Load encrypted payload from file.
 */
function loadEncryptedPayload(filePath: string): EncryptedPayload {
  const data = fs.readFileSync(filePath, 'utf-8');
  const payload = JSON.parse(data) as EncryptedPayload;

  // Validate structure
  if (!payload.iv || !payload.wrappedKey || !payload.ciphertext) {
    throw new Error('Invalid encrypted payload: missing iv, wrappedKey, or ciphertext');
  }

  return payload;
}

/**
 * Decrypt a single file.
 */
async function decryptFile(
  inputPath: string,
  privateKey: RSAPrivateKeyJWK,
  outputPath: string | undefined,
  format: 'json' | 'pretty'
): Promise<void> {
  try {
    const encrypted = loadEncryptedPayload(inputPath);
    const decrypted = await decryptForensics<unknown>(encrypted, privateKey);

    const output =
      format === 'pretty' ? JSON.stringify(decrypted, null, 2) : JSON.stringify(decrypted);

    if (outputPath) {
      fs.writeFileSync(outputPath, output);
      console.log(`Decrypted: ${inputPath} -> ${outputPath}`);
    } else {
      console.log(output);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Error decrypting ${inputPath}: ${message}`);
    process.exit(1);
  }
}

/**
 * Decrypt all .enc files in a directory.
 */
async function decryptDirectory(
  inputDir: string,
  privateKey: RSAPrivateKeyJWK,
  outputDir: string | undefined,
  format: 'json' | 'pretty'
): Promise<void> {
  // Create output directory if specified
  if (outputDir && !fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Find all .enc files
  const files = fs.readdirSync(inputDir).filter((f) => f.endsWith('.enc'));

  if (files.length === 0) {
    console.log('No .enc files found in directory');
    return;
  }

  console.log(`Found ${files.length} encrypted file(s)`);

  let successCount = 0;
  let errorCount = 0;

  for (const file of files) {
    const inputPath = path.join(inputDir, file);
    const outputFileName = file.replace(/\.enc$/, '.json');
    const outputPath = outputDir ? path.join(outputDir, outputFileName) : undefined;

    try {
      const encrypted = loadEncryptedPayload(inputPath);
      const decrypted = await decryptForensics<unknown>(encrypted, privateKey);

      const output =
        format === 'pretty' ? JSON.stringify(decrypted, null, 2) : JSON.stringify(decrypted);

      if (outputPath) {
        fs.writeFileSync(outputPath, output);
        console.log(`  ✓ ${file} -> ${outputFileName}`);
      } else {
        console.log(`\n--- ${file} ---`);
        console.log(output);
      }

      successCount++;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`  ✗ ${file}: ${message}`);
      errorCount++;
    }
  }

  console.log(`\nDecrypted: ${successCount}/${files.length} files`);
  if (errorCount > 0) {
    console.log(`Failed: ${errorCount} files`);
    process.exit(1);
  }
}
