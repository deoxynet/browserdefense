/**
 * Serve command for continuous forensics forwarding.
 * Runs as a daemon that polls for new forensics, decrypts them,
 * and forwards to configured connectors (SIEM, webhook, etc.).
 *
 * Issue #577
 */

import * as fs from 'node:fs';
import { decryptForensics, RSAPrivateKeyJWK, EncryptedPayload } from '../crypto.js';

export interface ServeConfig {
  /** Supabase URL for forensics_index */
  supabase_url: string;
  /** Supabase service role key */
  supabase_key: string;
  /** Organization ID to poll for */
  org_id: string;
  /** Path to encryption private key */
  key_path: string;
  /** Connector configuration */
  connector: ConnectorConfig;
  /** Poll interval in seconds (default: 30) */
  poll_interval?: number;
  /** Batch size for fetching (default: 100) */
  batch_size?: number;
}

export interface ConnectorConfig {
  /** Connector type */
  type: 'webhook' | 'splunk' | 'syslog';
  /** Webhook URL for webhook type */
  url?: string;
  /** Optional headers for webhook */
  headers?: Record<string, string>;
  /** Splunk HEC token for splunk type */
  token?: string;
  /** Syslog host:port for syslog type */
  host?: string;
}

export interface ServeOptions {
  config: string;
  verbose: boolean;
}

interface ForensicsIndexRow {
  id: string;
  org_id: string;
  blob_id: string;
  storage_path: string;
  status: 'uploaded' | 'processed' | 'failed';
  block_timestamp: string;
  created_at: string;
}

interface ForensicsBlob {
  id: string;
  org_id: string;
  encrypted_data: string;
  encrypted_key: string;
  iv: string;
  timestamp: string;
}

/**
 * Start the connector daemon.
 */
export async function serve(options: ServeOptions): Promise<void> {
  // Load config
  const config = loadConfig(options.config);
  const privateKey = loadPrivateKey(config.key_path);

  console.log(`[BrowserDefense Connector] Starting...`);
  console.log(`  Org: ${config.org_id}`);
  console.log(`  Connector: ${config.connector.type}`);
  console.log(`  Poll interval: ${config.poll_interval ?? 30}s`);

  // Run poll loop
  let running = true;

  // Handle shutdown
  process.on('SIGINT', () => {
    console.log('\n[BrowserDefense Connector] Shutting down...');
    running = false;
  });

  process.on('SIGTERM', () => {
    console.log('\n[BrowserDefense Connector] Shutting down...');
    running = false;
  });

  while (running) {
    try {
      await pollAndForward(config, privateKey, options.verbose);
    } catch (err) {
      console.error('[BrowserDefense Connector] Poll error:', err);
    }

    // Wait for next poll
    await sleep((config.poll_interval ?? 30) * 1000);
  }

  console.log('[BrowserDefense Connector] Stopped.');
}

/**
 * Poll for new forensics and forward to connector.
 */
async function pollAndForward(
  config: ServeConfig,
  privateKey: RSAPrivateKeyJWK,
  verbose: boolean
): Promise<void> {
  if (verbose) {
    console.log(`[${new Date().toISOString()}] Polling for new forensics...`);
  }

  // Fetch pending forensics from Supabase
  const pending = await fetchPendingForensics(config);

  if (pending.length === 0) {
    if (verbose) {
      console.log('  No new forensics found.');
    }
    return;
  }

  console.log(`[${new Date().toISOString()}] Found ${pending.length} new forensics`);

  let processed = 0;
  let failed = 0;

  for (const row of pending) {
    try {
      // Fetch the actual blob from storage
      const blob = await fetchForensicsBlob(config, row.storage_path);

      if (!blob) {
        console.error(`  Failed to fetch blob: ${row.storage_path}`);
        await updateStatus(config, row.id, 'failed');
        failed++;
        continue;
      }

      // Convert to EncryptedPayload format
      const encrypted: EncryptedPayload = {
        iv: blob.iv,
        wrappedKey: blob.encrypted_key,
        ciphertext: blob.encrypted_data,
      };

      // Decrypt
      const decrypted = await decryptForensics<unknown>(encrypted, privateKey);

      if (verbose) {
        console.log(`  Decrypted: ${row.blob_id}`);
      }

      // Forward to connector
      await forwardToConnector(config.connector, decrypted, row);

      // Mark as processed
      await updateStatus(config, row.id, 'processed');
      processed++;
    } catch (err) {
      console.error(`  Error processing ${row.blob_id}:`, err);
      await updateStatus(config, row.id, 'failed');
      failed++;
    }
  }

  console.log(`  Processed: ${processed}, Failed: ${failed}`);
}

/**
 * Fetch pending forensics from Supabase.
 */
async function fetchPendingForensics(config: ServeConfig): Promise<ForensicsIndexRow[]> {
  const url = `${config.supabase_url}/rest/v1/forensics_index?org_id=eq.${config.org_id}&status=eq.uploaded&limit=${config.batch_size ?? 100}&order=created_at.asc`;

  const response = await fetch(url, {
    headers: {
      apikey: config.supabase_key,
      Authorization: `Bearer ${config.supabase_key}`,
    },
  });

  if (!response.ok) {
    throw new Error(`Supabase fetch failed: ${response.status}`);
  }

  return response.json() as Promise<ForensicsIndexRow[]>;
}

/**
 * Fetch forensics blob from R2 via Supabase storage or direct URL.
 */
async function fetchForensicsBlob(
  config: ServeConfig,
  storagePath: string
): Promise<ForensicsBlob | null> {
  // For now, assume storage_path is a full URL or we construct one
  // In production, this might use Supabase Storage or direct R2 access
  const url = `${config.supabase_url}/storage/v1/object/public/forensics/${storagePath}`;

  try {
    const response = await fetch(url, {
      headers: {
        apikey: config.supabase_key,
        Authorization: `Bearer ${config.supabase_key}`,
      },
    });

    if (!response.ok) {
      console.error(`Blob fetch failed: ${response.status} for ${storagePath}`);
      return null;
    }

    return response.json() as Promise<ForensicsBlob>;
  } catch (err) {
    console.error(`Blob fetch error for ${storagePath}:`, err);
    return null;
  }
}

/**
 * Update forensics status in Supabase.
 */
async function updateStatus(
  config: ServeConfig,
  id: string,
  status: 'processed' | 'failed'
): Promise<void> {
  const url = `${config.supabase_url}/rest/v1/forensics_index?id=eq.${id}`;

  await fetch(url, {
    method: 'PATCH',
    headers: {
      apikey: config.supabase_key,
      Authorization: `Bearer ${config.supabase_key}`,
      'Content-Type': 'application/json',
      Prefer: 'return=minimal',
    },
    body: JSON.stringify({
      status,
      processed_at: new Date().toISOString(),
    }),
  });
}

/**
 * Forward decrypted forensics to connector.
 */
async function forwardToConnector(
  connector: ConnectorConfig,
  data: unknown,
  metadata: ForensicsIndexRow
): Promise<void> {
  const payload = {
    forensics: data,
    metadata: {
      blob_id: metadata.blob_id,
      org_id: metadata.org_id,
      block_timestamp: metadata.block_timestamp,
      processed_at: new Date().toISOString(),
    },
  };

  switch (connector.type) {
    case 'webhook':
      await forwardToWebhook(connector, payload);
      break;
    case 'splunk':
      await forwardToSplunk(connector, payload);
      break;
    case 'syslog':
      console.warn('Syslog connector not yet implemented');
      break;
    default:
      throw new Error(`Unknown connector type: ${(connector as ConnectorConfig).type}`);
  }
}

/**
 * Forward to webhook endpoint.
 */
async function forwardToWebhook(
  connector: ConnectorConfig,
  payload: unknown
): Promise<void> {
  if (!connector.url) {
    throw new Error('Webhook URL not configured');
  }

  const response = await fetch(connector.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...connector.headers,
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`Webhook failed: ${response.status}`);
  }
}

/**
 * Forward to Splunk HEC.
 */
async function forwardToSplunk(
  connector: ConnectorConfig,
  payload: unknown
): Promise<void> {
  if (!connector.url || !connector.token) {
    throw new Error('Splunk HEC URL and token required');
  }

  // Splunk HEC format
  const hecPayload = {
    event: payload,
    sourcetype: 'browserdefense:forensics',
    source: 'browserdefense-connector',
    time: Date.now() / 1000,
  };

  const response = await fetch(connector.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Splunk ${connector.token}`,
    },
    body: JSON.stringify(hecPayload),
  });

  if (!response.ok) {
    throw new Error(`Splunk HEC failed: ${response.status}`);
  }
}

/**
 * Load config from YAML/JSON file.
 */
function loadConfig(configPath: string): ServeConfig {
  if (!fs.existsSync(configPath)) {
    console.error(`Error: Config file not found: ${configPath}`);
    process.exit(1);
  }

  try {
    const content = fs.readFileSync(configPath, 'utf-8');

    // Simple YAML-like parsing for common cases
    if (configPath.endsWith('.yaml') || configPath.endsWith('.yml')) {
      // For now, require JSON format
      console.error('Error: YAML config not yet supported. Use JSON format.');
      console.error('Example config:');
      console.error(JSON.stringify(
        {
          supabase_url: 'https://your-project.supabase.co',
          supabase_key: 'your-service-role-key',
          org_id: 'your-org-id',
          key_path: './keys/encryption-private.jwk',
          connector: {
            type: 'webhook',
            url: 'https://your-siem.example.com/api/events',
          },
          poll_interval: 30,
          batch_size: 100,
        },
        null,
        2
      ));
      process.exit(1);
    }

    return JSON.parse(content) as ServeConfig;
  } catch (err) {
    console.error(`Error parsing config: ${err}`);
    process.exit(1);
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
    console.error(`Error parsing key file: ${err}`);
    process.exit(1);
  }
}

/**
 * Sleep for specified milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
