/**
 * Blocklist management commands.
 * init, add, remove, stats for managing IOC lists.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { generateSalt } from '../crypto.js';

const BLOCKLIST_FILE = 'blocklist.txt';
const CONFIG_FILE = 'blocklist.config.json';

interface BlocklistConfig {
  org: string;
  salt: string;
  scope: 'HOST_ONLY' | 'HOST_PATH' | 'FULL_URL';
  created_at: string;
  last_modified: string;
}

/**
 * Initialize a new blocklist in the current directory.
 */
export async function init(options: { org: string; scope?: string }): Promise<void> {
  const blocklistPath = path.join(process.cwd(), BLOCKLIST_FILE);
  const configPath = path.join(process.cwd(), CONFIG_FILE);

  if (fs.existsSync(blocklistPath) || fs.existsSync(configPath)) {
    console.error('Error: Blocklist already exists in this directory');
    console.error('  Remove blocklist.txt and blocklist.config.json to reinitialize');
    process.exit(1);
  }

  const scope = (options.scope || 'HOST_ONLY') as BlocklistConfig['scope'];
  const now = new Date().toISOString();

  const config: BlocklistConfig = {
    org: options.org,
    salt: generateSalt(),
    scope,
    created_at: now,
    last_modified: now,
  };

  // Create empty blocklist
  fs.writeFileSync(blocklistPath, '# BrowserDefense Blocklist\n# One IOC per line\n# Lines starting with # are comments\n\n');

  // Write config
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

  console.log(`Initialized blocklist for ${options.org}`);
  console.log(`  Blocklist: ${blocklistPath}`);
  console.log(`  Config:    ${configPath}`);
  console.log(`  Scope:     ${scope}`);
  console.log(`\nNext steps:`);
  console.log(`  1. Add IOCs:    browserdefense add evil.com`);
  console.log(`  2. Compile:     browserdefense compile`);
  console.log(`  3. Sign:        browserdefense sign --key signing-private.jwk`);
}

/**
 * Add IOCs to the blocklist.
 */
export async function add(iocs: string[], options: { file?: string }): Promise<void> {
  const blocklistPath = path.join(process.cwd(), BLOCKLIST_FILE);
  const configPath = path.join(process.cwd(), CONFIG_FILE);

  if (!fs.existsSync(blocklistPath)) {
    console.error('Error: No blocklist found. Run "browserdefense init" first.');
    process.exit(1);
  }

  // Collect IOCs to add
  const toAdd: string[] = [...iocs];

  // Read from file if provided
  if (options.file) {
    if (!fs.existsSync(options.file)) {
      console.error(`Error: File not found: ${options.file}`);
      process.exit(1);
    }
    const content = fs.readFileSync(options.file, 'utf-8');
    const lines = content
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
    toAdd.push(...lines);
  }

  if (toAdd.length === 0) {
    console.error('Error: No IOCs provided');
    console.error('Usage: browserdefense add evil.com [more.com ...] [-f file.txt]');
    process.exit(1);
  }

  // Load existing blocklist
  const existing = new Set(
    fs
      .readFileSync(blocklistPath, 'utf-8')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'))
  );

  // Add new IOCs
  let added = 0;
  let skipped = 0;

  for (const ioc of toAdd) {
    // Normalize the IOC
    const normalized = normalizeIOC(ioc);
    if (existing.has(normalized)) {
      skipped++;
    } else {
      existing.add(normalized);
      added++;
    }
  }

  // Write updated blocklist
  const header = '# BrowserDefense Blocklist\n# One IOC per line\n# Lines starting with # are comments\n\n';
  const sortedIOCs = Array.from(existing).sort();
  fs.writeFileSync(blocklistPath, header + sortedIOCs.join('\n') + '\n');

  // Update config timestamp
  if (fs.existsSync(configPath)) {
    const config: BlocklistConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    config.last_modified = new Date().toISOString();
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  }

  console.log(`Added ${added} IOC(s), skipped ${skipped} duplicate(s)`);
  console.log(`Total IOCs: ${existing.size}`);
}

/**
 * Remove IOCs from the blocklist.
 */
export async function remove(iocs: string[]): Promise<void> {
  const blocklistPath = path.join(process.cwd(), BLOCKLIST_FILE);
  const configPath = path.join(process.cwd(), CONFIG_FILE);

  if (!fs.existsSync(blocklistPath)) {
    console.error('Error: No blocklist found. Run "browserdefense init" first.');
    process.exit(1);
  }

  if (iocs.length === 0) {
    console.error('Error: No IOCs provided');
    console.error('Usage: browserdefense remove evil.com [more.com ...]');
    process.exit(1);
  }

  // Load existing blocklist
  const existing = new Set(
    fs
      .readFileSync(blocklistPath, 'utf-8')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'))
  );

  // Remove IOCs
  let removed = 0;
  let notFound = 0;

  for (const ioc of iocs) {
    const normalized = normalizeIOC(ioc);
    if (existing.has(normalized)) {
      existing.delete(normalized);
      removed++;
    } else {
      notFound++;
    }
  }

  // Write updated blocklist
  const header = '# BrowserDefense Blocklist\n# One IOC per line\n# Lines starting with # are comments\n\n';
  const sortedIOCs = Array.from(existing).sort();
  fs.writeFileSync(blocklistPath, header + sortedIOCs.join('\n') + '\n');

  // Update config timestamp
  if (fs.existsSync(configPath)) {
    const config: BlocklistConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    config.last_modified = new Date().toISOString();
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  }

  console.log(`Removed ${removed} IOC(s), ${notFound} not found`);
  console.log(`Total IOCs: ${existing.size}`);
}

/**
 * Show blocklist statistics.
 */
export async function stats(): Promise<void> {
  const blocklistPath = path.join(process.cwd(), BLOCKLIST_FILE);
  const configPath = path.join(process.cwd(), CONFIG_FILE);
  const manifestPath = path.join(process.cwd(), 'manifest.json');

  if (!fs.existsSync(blocklistPath)) {
    console.error('Error: No blocklist found. Run "browserdefense init" first.');
    process.exit(1);
  }

  // Read blocklist
  const content = fs.readFileSync(blocklistPath, 'utf-8');
  const iocs = content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));

  console.log('Blocklist Statistics');
  console.log('====================');
  console.log(`Total IOCs: ${iocs.length}`);

  // Read config if exists
  if (fs.existsSync(configPath)) {
    const config: BlocklistConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    console.log(`\nConfiguration:`);
    console.log(`  Organization: ${config.org}`);
    console.log(`  Scope:        ${config.scope}`);
    console.log(`  Created:      ${config.created_at}`);
    console.log(`  Modified:     ${config.last_modified}`);
  }

  // Read manifest if exists
  if (fs.existsSync(manifestPath)) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    console.log(`\nCompiled Manifest:`);
    console.log(`  Version:      ${manifest.version}`);
    console.log(`  Total Hashes: ${manifest.total_iocs}`);
    console.log(`  Buckets:      ${manifest.bucket_count}`);
    console.log(`  Root Hash:    ${manifest.sha256_root.substring(0, 32)}...`);
    console.log(`  Signed:       ${manifest.signature ? 'Yes' : 'No'}`);
  } else {
    console.log(`\nNot compiled yet. Run 'browserdefense compile' to generate binary format.`);
  }

  // Show some IOC stats
  if (iocs.length > 0) {
    const domains = iocs.filter((ioc) => !ioc.includes('/'));
    const urls = iocs.filter((ioc) => ioc.includes('/'));
    console.log(`\nIOC Types:`);
    console.log(`  Domains: ${domains.length}`);
    console.log(`  URLs:    ${urls.length}`);
  }
}

/**
 * Normalize an IOC for consistent storage.
 */
function normalizeIOC(ioc: string): string {
  // If it looks like a domain (no protocol), add https://
  if (!ioc.includes('://')) {
    // Remove any leading dots or slashes
    ioc = ioc.replace(/^[./]+/, '');
    return ioc.toLowerCase();
  }

  // It's a URL, canonicalize it
  try {
    const url = new URL(ioc);
    // Store host only for domain IOCs
    return url.hostname.toLowerCase();
  } catch {
    return ioc.toLowerCase();
  }
}
