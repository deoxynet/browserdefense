/**
 * Compile command.
 * Converts plaintext IOCs to binary hash format.
 *
 * Input: Text file with one IOC per line (URLs or domains)
 * Output: Binary file with 32-byte SHA-256 hashes + manifest.json
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  hashIOCBytes,
  sha256,
  binaryToBase64,
  type BlocklistManifest,
} from '../crypto.js';

export interface CompileOptions {
  input: string;
  salt: string;
  output?: string;
  scope?: 'HOST_ONLY' | 'HOST_PATH' | 'FULL_URL';
  buckets?: number;
}

export async function compile(options: CompileOptions): Promise<void> {
  const inputPath = options.input;
  const scope = options.scope || 'HOST_ONLY';
  const bucketCount = options.buckets || 1;

  if (!fs.existsSync(inputPath)) {
    console.error(`Error: Input file not found: ${inputPath}`);
    process.exit(1);
  }

  // Read IOCs
  const content = fs.readFileSync(inputPath, 'utf-8');
  const lines = content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));

  if (lines.length === 0) {
    console.error('Error: No IOCs found in input file');
    process.exit(1);
  }

  console.log(`Compiling ${lines.length} IOCs...`);
  console.log(`  Scope:   ${scope}`);
  console.log(`  Buckets: ${bucketCount}`);

  // Load salt
  let salt: string;
  if (fs.existsSync(options.salt)) {
    // Salt is a file path (could be config file or raw salt file)
    const saltContent = fs.readFileSync(options.salt, 'utf-8');
    try {
      const config = JSON.parse(saltContent);
      salt = config.ioc_salt || config.salt;
    } catch {
      salt = saltContent.trim();
    }
  } else {
    // Salt is provided directly
    salt = options.salt;
  }

  // Hash all IOCs
  const hashes: Buffer[] = [];
  for (const ioc of lines) {
    const hash = hashIOCBytes(ioc, salt, scope);
    hashes.push(hash);
  }

  // Sort hashes for consistent ordering and binary search
  hashes.sort(Buffer.compare);

  // Remove duplicates
  const uniqueHashes: Buffer[] = [];
  for (let i = 0; i < hashes.length; i++) {
    if (i === 0 || !hashes[i].equals(hashes[i - 1])) {
      uniqueHashes.push(hashes[i]);
    }
  }

  const duplicatesRemoved = hashes.length - uniqueHashes.length;
  if (duplicatesRemoved > 0) {
    console.log(`  Removed ${duplicatesRemoved} duplicate hashes`);
  }

  // Create binary buffer
  const binaryBuffer = Buffer.concat(uniqueHashes);

  // Calculate root hash (hash of the binary content)
  const rootHash = sha256(binaryBuffer);

  // Output paths
  const outputDir = options.output || process.cwd();
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const binaryPath = path.join(outputDir, 'blocklist.bin');
  const base64Path = path.join(outputDir, 'blocklist.b64');
  const manifestPath = path.join(outputDir, 'manifest.json');

  // Write binary file
  fs.writeFileSync(binaryPath, binaryBuffer);

  // Write base64 version (for chrome.storage.local)
  fs.writeFileSync(base64Path, binaryToBase64(binaryBuffer));

  // Create manifest (unsigned)
  const manifest: Omit<BlocklistManifest, 'signature'> = {
    version: Date.now(),
    total_iocs: uniqueHashes.length,
    bucket_count: bucketCount,
    sha256_root: rootHash,
    created_at: new Date().toISOString(),
    algorithm_version: 'p256-v1',
  };

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  console.log(`\nCompiled successfully!`);
  console.log(`  Total hashes: ${uniqueHashes.length}`);
  console.log(`  Binary size:  ${binaryBuffer.length} bytes`);
  console.log(`  Root hash:    ${rootHash.substring(0, 16)}...`);
  console.log(`\nOutput files:`);
  console.log(`  ${binaryPath}`);
  console.log(`  ${base64Path}`);
  console.log(`  ${manifestPath}`);
  console.log(`\nNext: Sign the manifest with 'browserdefense sign --key signing-private.jwk'`);
}

/**
 * Compile IOCs for a multi-bucket setup.
 * Splits hashes across multiple bucket files for faster loading.
 */
export async function compileMultiBucket(options: CompileOptions): Promise<void> {
  const bucketCount = options.buckets || 16;

  // For multi-bucket, we need to distribute hashes by prefix
  // Each bucket contains hashes where hash[0] % bucketCount === bucketIndex

  const inputPath = options.input;
  const scope = options.scope || 'HOST_ONLY';

  if (!fs.existsSync(inputPath)) {
    console.error(`Error: Input file not found: ${inputPath}`);
    process.exit(1);
  }

  const content = fs.readFileSync(inputPath, 'utf-8');
  const lines = content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));

  if (lines.length === 0) {
    console.error('Error: No IOCs found in input file');
    process.exit(1);
  }

  // Load salt
  let salt: string;
  if (fs.existsSync(options.salt)) {
    const saltContent = fs.readFileSync(options.salt, 'utf-8');
    try {
      const config = JSON.parse(saltContent);
      salt = config.ioc_salt || config.salt;
    } catch {
      salt = saltContent.trim();
    }
  } else {
    salt = options.salt;
  }

  console.log(`Compiling ${lines.length} IOCs into ${bucketCount} buckets...`);

  // Initialize buckets
  const buckets: Buffer[][] = Array.from({ length: bucketCount }, () => []);

  // Hash and distribute
  for (const ioc of lines) {
    const hash = hashIOCBytes(ioc, salt, scope);
    const bucketIndex = hash[0] % bucketCount;
    buckets[bucketIndex].push(hash);
  }

  // Sort each bucket
  for (const bucket of buckets) {
    bucket.sort(Buffer.compare);
  }

  // Output
  const outputDir = options.output || process.cwd();
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const bucketHashes: string[] = [];
  let totalHashes = 0;

  for (let i = 0; i < bucketCount; i++) {
    const bucket = buckets[i];
    const binaryBuffer = Buffer.concat(bucket);
    const bucketHash = sha256(binaryBuffer);
    bucketHashes.push(bucketHash);
    totalHashes += bucket.length;

    const bucketPath = path.join(outputDir, `bucket-${i.toString().padStart(2, '0')}.bin`);
    fs.writeFileSync(bucketPath, binaryBuffer);
  }

  // Root hash is hash of all bucket hashes
  const rootHash = sha256(bucketHashes.join(''));

  // Create manifest
  const manifest: Omit<BlocklistManifest, 'signature'> = {
    version: Date.now(),
    total_iocs: totalHashes,
    bucket_count: bucketCount,
    sha256_root: rootHash,
    created_at: new Date().toISOString(),
    algorithm_version: 'p256-v1',
  };

  const manifestPath = path.join(outputDir, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  console.log(`\nCompiled successfully!`);
  console.log(`  Total hashes: ${totalHashes}`);
  console.log(`  Bucket count: ${bucketCount}`);
  console.log(`  Root hash:    ${rootHash.substring(0, 16)}...`);
  console.log(`\nOutput: ${outputDir}/bucket-*.bin`);
  console.log(`\nNext: Sign the manifest with 'browserdefense sign --key signing-private.jwk'`);
}
