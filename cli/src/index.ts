#!/usr/bin/env node
/**
 * BrowserDefense CLI
 * Manage blocklists, generate keys, sign manifests.
 */

import { Command } from 'commander';
import { keygen } from './commands/keygen.js';
import { sign, signFile } from './commands/sign.js';
import { validate, validateFile } from './commands/validate.js';
import { compile, compileMultiBucket } from './commands/compile.js';
import { init, add, remove, stats } from './commands/blocklist.js';
import { decrypt } from './commands/decrypt.js';
import { serve } from './commands/serve.js';

const program = new Command();

program
  .name('browserdefense')
  .description('CLI tool for managing BrowserDefense blocklists')
  .version('0.1.0');

// ============ Key Generation ============

program
  .command('keygen')
  .description('Generate cryptographic keys')
  .option('-t, --type <type>', 'Key type: signing, encryption, or all', 'all')
  .option('-o, --output <dir>', 'Output directory', '.')
  .action(async (options) => {
    if (!['signing', 'encryption', 'all'].includes(options.type)) {
      console.error('Error: Invalid key type. Use: signing, encryption, or all');
      process.exit(1);
    }
    await keygen({ type: options.type, output: options.output });
  });

// ============ Signing ============

program
  .command('sign')
  .description('Sign a blocklist manifest')
  .requiredOption('-k, --key <path>', 'Path to signing private key (JWK)')
  .option('-m, --manifest <path>', 'Path to manifest.json', 'manifest.json')
  .option('-o, --output <path>', 'Output path for signed manifest')
  .action(async (options) => {
    await sign({
      key: options.key,
      manifest: options.manifest,
      output: options.output,
    });
  });

program
  .command('sign-file')
  .description('Sign a file (generates .sig file)')
  .argument('<file>', 'File to sign')
  .requiredOption('-k, --key <path>', 'Path to signing private key (JWK)')
  .option('-o, --output <path>', 'Output path for signature')
  .action(async (file, options) => {
    await signFile(file, options.key, options.output);
  });

// ============ Validation ============

program
  .command('validate')
  .description('Verify a blocklist manifest signature')
  .requiredOption('-k, --key <path>', 'Path to signing public key (JWK)')
  .option('-m, --manifest <path>', 'Path to manifest.json', 'manifest.json')
  .action(async (options) => {
    await validate({
      key: options.key,
      manifest: options.manifest,
    });
  });

program
  .command('validate-file')
  .description('Verify a file signature')
  .argument('<file>', 'File to verify')
  .argument('<signature>', 'Signature file (.sig)')
  .requiredOption('-k, --key <path>', 'Path to signing public key (JWK)')
  .action(async (file, signature, options) => {
    await validateFile(file, signature, options.key);
  });

// ============ Compilation ============

program
  .command('compile')
  .description('Compile IOCs to binary hash format')
  .requiredOption('-i, --input <path>', 'Input file with IOCs (one per line)')
  .requiredOption('-s, --salt <salt>', 'Salt string or path to config/salt file')
  .option('-o, --output <dir>', 'Output directory', '.')
  .option('--scope <scope>', 'URL scope: HOST_ONLY, HOST_PATH, FULL_URL', 'HOST_ONLY')
  .option('-b, --buckets <n>', 'Number of buckets (1 for single file)', '1')
  .action(async (options) => {
    const buckets = parseInt(options.buckets, 10);
    if (buckets > 1) {
      await compileMultiBucket({
        input: options.input,
        salt: options.salt,
        output: options.output,
        scope: options.scope,
        buckets,
      });
    } else {
      await compile({
        input: options.input,
        salt: options.salt,
        output: options.output,
        scope: options.scope,
      });
    }
  });

// ============ Blocklist Management ============

program
  .command('init')
  .description('Initialize a new blocklist in the current directory')
  .requiredOption('--org <name>', 'Organization name')
  .option('--scope <scope>', 'URL scope: HOST_ONLY, HOST_PATH, FULL_URL', 'HOST_ONLY')
  .action(async (options) => {
    await init({ org: options.org, scope: options.scope });
  });

program
  .command('add')
  .description('Add IOCs to the blocklist')
  .argument('[iocs...]', 'IOCs to add')
  .option('-f, --file <path>', 'Read IOCs from file')
  .action(async (iocs, options) => {
    await add(iocs || [], { file: options.file });
  });

program
  .command('remove')
  .description('Remove IOCs from the blocklist')
  .argument('<iocs...>', 'IOCs to remove')
  .action(async (iocs) => {
    await remove(iocs);
  });

program
  .command('stats')
  .description('Show blocklist statistics')
  .action(async () => {
    await stats();
  });

// ============ Forensics Decryption ============

program
  .command('decrypt')
  .description('Decrypt forensics files captured by the extension')
  .requiredOption('-k, --key <path>', 'Path to encryption private key (JWK)')
  .requiredOption('-i, --input <path>', 'Input file or directory')
  .option('-o, --output <path>', 'Output file or directory')
  .option('-f, --format <format>', 'Output format: json or pretty', 'json')
  .action(async (options) => {
    if (!['json', 'pretty'].includes(options.format)) {
      console.error('Error: Invalid format. Use: json or pretty');
      process.exit(1);
    }
    await decrypt({
      key: options.key,
      input: options.input,
      output: options.output,
      format: options.format,
    });
  });

// ============ Connector Service ============

program
  .command('serve')
  .description('Run connector daemon for continuous forensics forwarding')
  .requiredOption('-c, --config <path>', 'Path to config file (JSON)')
  .option('-v, --verbose', 'Enable verbose logging', false)
  .action(async (options) => {
    await serve({
      config: options.config,
      verbose: options.verbose,
    });
  });

// Parse arguments
program.parse();
