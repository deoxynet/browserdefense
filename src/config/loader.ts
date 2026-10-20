/**
 * BrowserDefense Configuration Loader
 *
 * Handles saving and loading configuration from chrome.storage.
 * Enterprise deployments use chrome.storage.managed for policy settings,
 * which are read-only and take precedence over local settings.
 */

import { BrowserDefenseConfig, validateConfig, ConfigValidationResult } from './schema';
import { CONFIG_STORAGE_KEY } from './storage-keys';

/**
 * Save a validated configuration to storage.
 *
 * @param config - The configuration to save
 */
export async function saveConfig(config: BrowserDefenseConfig): Promise<void> {
  await chrome.storage.local.set({ [CONFIG_STORAGE_KEY]: config });
  console.log('[BrowserDefense] Configuration saved for org:', config.org_id);
}

/**
 * Load managed policy configuration from chrome.storage.managed.
 *
 * Enterprise deployments can push configuration via GPO/MDM, which
 * Chrome makes available through the managed storage area.
 *
 * @returns The managed configuration, or null if none exists or managed storage is unavailable
 */
export async function loadManagedConfig(): Promise<BrowserDefenseConfig | null> {
  // chrome.storage.managed may not be available in all contexts
  if (!chrome.storage.managed) {
    console.log('[BrowserDefense] Managed storage not available');
    return null;
  }

  try {
    const result = await chrome.storage.managed.get(null);

    // If no managed settings exist, result will be an empty object
    if (!result || Object.keys(result).length === 0) {
      return null;
    }

    // Map managed policy keys to config structure
    // Managed storage uses flat keys from enterprise policy
    const managedData: Record<string, unknown> = {
      org_id: result.org_id,
      signing_public_key: parseJsonOrPass(result.signing_public_key),
      encryption_public_key: parseJsonOrPass(result.encryption_public_key || result.forensics_public_key),
      blocklist_endpoint: result.blocklist_endpoint,
      forensics_endpoint: result.forensics_endpoint,
      ioc_salt: result.ioc_salt,
      ioc_scope: result.ioc_scope,
      update_interval_minutes: result.update_interval_minutes,
    };

    // Remove undefined keys
    Object.keys(managedData).forEach((key) => {
      if (managedData[key] === undefined) {
        delete managedData[key];
      }
    });

    // Validate the managed config
    const validation = validateConfig(managedData);

    if (!validation.valid) {
      console.warn('[BrowserDefense] Managed configuration is invalid:', validation.errors);
      return null;
    }

    console.log('[BrowserDefense] Loaded configuration from managed storage for org:', validation.config.org_id);
    return validation.config;
  } catch (error) {
    // Managed storage access can fail if not policy-installed
    console.log('[BrowserDefense] Could not read managed storage:', error);
    return null;
  }
}

/**
 * Parse a JSON string or return the value as-is if already an object.
 * Enterprise policies may store JWK keys as JSON strings.
 */
function parseJsonOrPass(value: unknown): unknown {
  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }
  return value;
}

/**
 * Load configuration from storage.
 *
 * Checks chrome.storage.managed first (enterprise policy), then falls back
 * to chrome.storage.local. Managed config takes full precedence when present.
 *
 * @returns The stored configuration, or null if none exists
 */
export async function loadConfig(): Promise<BrowserDefenseConfig | null> {
  // First, try to load from managed storage (enterprise policy)
  const managedConfig = await loadManagedConfig();
  if (managedConfig) {
    return managedConfig;
  }

  // Fall back to local storage
  const result = await chrome.storage.local.get(CONFIG_STORAGE_KEY);
  const data = result[CONFIG_STORAGE_KEY];

  if (!data) {
    return null;
  }

  // Re-validate on load in case schema has changed
  const validation = validateConfig(data);

  if (!validation.valid) {
    console.warn('[BrowserDefense] Stored configuration is invalid:', validation.errors);
    return null;
  }

  return validation.config;
}

/**
 * Check if a configuration is stored (in either managed or local storage).
 *
 * @returns true if a config exists in storage
 */
export async function hasConfig(): Promise<boolean> {
  // Check managed storage first
  const managedConfig = await loadManagedConfig();
  if (managedConfig) {
    return true;
  }

  // Check local storage
  const result = await chrome.storage.local.get(CONFIG_STORAGE_KEY);
  return result[CONFIG_STORAGE_KEY] !== undefined;
}

/**
 * Check if the current configuration comes from managed policy storage.
 *
 * This is useful for showing UI feedback like "Managed by your organization"
 * and disabling configuration editing when managed.
 *
 * @returns true if config is from chrome.storage.managed
 */
export async function isConfigManaged(): Promise<boolean> {
  const managedConfig = await loadManagedConfig();
  return managedConfig !== null;
}

/**
 * Clear the stored configuration.
 */
export async function clearConfig(): Promise<void> {
  await chrome.storage.local.remove(CONFIG_STORAGE_KEY);
  console.log('[BrowserDefense] Configuration cleared');
}

/**
 * Import configuration from a JSON string.
 *
 * @param jsonString - JSON string containing the configuration
 * @returns Validation result with the parsed config or errors
 */
export function parseConfigJson(jsonString: string): ConfigValidationResult {
  let parsed: unknown;

  try {
    parsed = JSON.parse(jsonString);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown parse error';
    return { valid: false, errors: [`Invalid JSON: ${message}`] };
  }

  return validateConfig(parsed);
}

/**
 * Export configuration to a JSON string (formatted).
 *
 * @param config - The configuration to export
 * @returns Formatted JSON string
 */
export function exportConfigJson(config: BrowserDefenseConfig): string {
  return JSON.stringify(config, null, 2);
}

/**
 * Parse managed policy configuration.
 *
 * Enterprise policies (GPO, Intune) deliver JWK keys as JSON strings,
 * but the config schema expects JWK objects. This function:
 * 1. Parses JSON string fields (signing_public_key, forensics_public_key)
 * 2. Maps forensics_public_key → encryption_public_key (enterprise naming)
 *
 * @param data - Raw managed policy data from chrome.storage.managed
 * @returns Normalized config object ready for validation
 */
export function parseManagedPolicyConfig(data: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = { ...data };

  // Parse signing_public_key if it's a JSON string
  if (typeof result.signing_public_key === 'string') {
    try {
      result.signing_public_key = JSON.parse(result.signing_public_key);
    } catch {
      // Leave as-is, validation will catch the error
    }
  }

  // Parse forensics_public_key and map to encryption_public_key
  // Enterprise templates use forensics_public_key, but schema uses encryption_public_key
  if (typeof result.forensics_public_key === 'string') {
    try {
      result.encryption_public_key = JSON.parse(result.forensics_public_key);
      delete result.forensics_public_key;
    } catch {
      // Leave as-is, validation will catch the error
    }
  } else if (typeof result.forensics_public_key === 'object' && result.forensics_public_key !== null) {
    // Already an object, just rename
    result.encryption_public_key = result.forensics_public_key;
    delete result.forensics_public_key;
  }

  // Also parse encryption_public_key if it's a string (for direct use of schema naming)
  if (typeof result.encryption_public_key === 'string') {
    try {
      result.encryption_public_key = JSON.parse(result.encryption_public_key);
    } catch {
      // Leave as-is, validation will catch the error
    }
  }

  return result;
}

/**
 * Get the current config or throw if not configured.
 * Useful for places that require a valid config.
 *
 * @throws Error if no config is stored
 */
export async function requireConfig(): Promise<BrowserDefenseConfig> {
  const config = await loadConfig();

  if (!config) {
    throw new Error('BrowserDefense is not configured. Please import a configuration file.');
  }

  return config;
}
