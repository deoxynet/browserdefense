/**
 * Demo Mode Configuration
 *
 * Demo mode allows safe testing with fake URLs that trigger blocking.
 * This is useful for:
 * - YouTube demo videos
 * - Sales demonstrations
 * - Testing the blocking flow without real malicious URLs
 *
 * Demo mode is stored separately from the main config because:
 * - Main config may be managed/read-only (enterprise policy)
 * - Demo mode is always local-only
 *
 * Issue #571
 */

import { DEMO_CONFIG_KEY } from './storage-keys';

/**
 * Demo mode configuration.
 */
export interface DemoConfig {
  /** Whether demo mode is enabled */
  demoMode: boolean;
  /** URLs that trigger blocking in demo mode (domains or full URLs) */
  demoUrls: string[];
}

/**
 * Default demo config (disabled).
 */
export const DEFAULT_DEMO_CONFIG: DemoConfig = {
  demoMode: false,
  demoUrls: [],
};

/**
 * Load demo configuration from storage.
 */
export async function loadDemoConfig(): Promise<DemoConfig> {
  try {
    const result = await chrome.storage.local.get(DEMO_CONFIG_KEY);
    const data = result[DEMO_CONFIG_KEY];

    if (!data) {
      return DEFAULT_DEMO_CONFIG;
    }

    // Validate and sanitize
    return {
      demoMode: typeof data.demoMode === 'boolean' ? data.demoMode : false,
      demoUrls: Array.isArray(data.demoUrls)
        ? data.demoUrls.filter((url: unknown) => typeof url === 'string')
        : [],
    };
  } catch (err) {
    console.warn('[BrowserDefense] Failed to load demo config:', err);
    return DEFAULT_DEMO_CONFIG;
  }
}

/**
 * Save demo configuration to storage.
 */
export async function saveDemoConfig(config: DemoConfig): Promise<void> {
  await chrome.storage.local.set({ [DEMO_CONFIG_KEY]: config });
  console.log(`[BrowserDefense] Demo mode ${config.demoMode ? 'enabled' : 'disabled'}`);
  if (config.demoMode && config.demoUrls.length > 0) {
    console.log(`[BrowserDefense] Demo URLs: ${config.demoUrls.join(', ')}`);
  }
}

/**
 * Check if demo mode is enabled.
 */
export async function isDemoModeEnabled(): Promise<boolean> {
  const config = await loadDemoConfig();
  return config.demoMode;
}

/**
 * Check if a URL matches any demo URL pattern.
 *
 * Matching rules:
 * - If demoUrl is a domain (no path), matches any URL with that domain
 * - If demoUrl includes a path, matches the full URL
 * - Comparison is case-insensitive for domains
 *
 * @param url - The URL to check
 * @param demoUrls - Array of demo URL patterns
 * @returns true if the URL matches a demo pattern
 */
export function matchesDemoUrl(url: string, demoUrls: string[]): boolean {
  if (!demoUrls || demoUrls.length === 0) {
    return false;
  }

  try {
    const parsedUrl = new URL(url);
    const urlHost = parsedUrl.hostname.toLowerCase();
    const urlPath = parsedUrl.pathname;

    for (const demoUrl of demoUrls) {
      const demoPattern = demoUrl.trim().toLowerCase();

      if (!demoPattern) continue;

      // Check if it's a domain-only pattern (no scheme, no path)
      if (!demoPattern.includes('/') && !demoPattern.includes(':')) {
        // Domain-only match
        if (urlHost === demoPattern || urlHost.endsWith('.' + demoPattern)) {
          return true;
        }
      } else {
        // Try parsing as full URL
        try {
          // Add scheme if missing
          const fullPattern = demoPattern.startsWith('http')
            ? demoPattern
            : 'https://' + demoPattern;
          const parsedPattern = new URL(fullPattern);

          // Match host
          if (urlHost !== parsedPattern.hostname.toLowerCase()) {
            continue;
          }

          // Match path (prefix match)
          if (parsedPattern.pathname !== '/' && !urlPath.startsWith(parsedPattern.pathname)) {
            continue;
          }

          return true;
        } catch {
          // If it's not a valid URL, treat as domain
          if (urlHost === demoPattern || urlHost.endsWith('.' + demoPattern)) {
            return true;
          }
        }
      }
    }

    return false;
  } catch {
    // Invalid URL
    return false;
  }
}

/**
 * Get demo URLs if demo mode is enabled.
 * Returns empty array if demo mode is disabled.
 */
export async function getDemoUrlsIfEnabled(): Promise<string[]> {
  const config = await loadDemoConfig();
  return config.demoMode ? config.demoUrls : [];
}
