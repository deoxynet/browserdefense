/**
 * Declarative Net Request (DNR) module for consumer-mode blocking.
 *
 * DNR provides true pre-request blocking without requiring enterprise
 * policy installation. However, it requires URL patterns (not hashes)
 * for blocking rules.
 *
 * Architecture:
 * - Only 'sync' priority IOCs are compiled to DNR rules
 * - 'async' priority IOCs are handled via webRequest observer (no DNR)
 * - This provides IOC QoS (Quality of Service) differentiation
 *
 * Limitations:
 * - Chrome limits dynamic rules to 30,000 per extension
 * - Rules must be URL patterns (wildcards supported)
 * - Cannot use hash-based lookup directly
 * - Sync IOCs MUST have URL field (not just hash) for DNR compilation
 *
 * @see https://developer.chrome.com/docs/extensions/reference/declarativeNetRequest/
 */

import {
  type PrioritizedIOC,
  partitionByPriority,
  MAX_DNR_RULES,
} from '../ioc/priority';

/** Maximum number of dynamic rules Chrome allows */
const MAX_DYNAMIC_RULES = 30000;

/** Rule ID offset to avoid conflicts with static rules */
const DYNAMIC_RULE_ID_START = 1;

/** Storage key for rule metadata */
const DNR_META_KEY = 'browserdefense_dnr_meta';

/**
 * DNR rule metadata stored locally.
 */
interface DNRMetadata {
  /** Number of active rules */
  ruleCount: number;
  /** Last update timestamp */
  updatedAt: number;
  /** Blocklist version these rules correspond to */
  version: number;
}

/**
 * Result of a DNR update operation.
 */
export interface DNRUpdateResult {
  success: boolean;
  ruleCount: number;
  error?: string;
}

/**
 * Check if DNR is available.
 */
export function isDNRAvailable(): boolean {
  return typeof chrome.declarativeNetRequest !== 'undefined';
}

/**
 * Get current DNR rule count.
 */
export async function getDNRRuleCount(): Promise<number> {
  if (!isDNRAvailable()) {
    return 0;
  }

  try {
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    return rules.length;
  } catch (err) {
    console.error('[BrowserDefense] Failed to get DNR rules:', err);
    return 0;
  }
}

/**
 * Get DNR metadata from storage.
 */
export async function getDNRMetadata(): Promise<DNRMetadata | null> {
  const result = await chrome.storage.local.get(DNR_META_KEY);
  return result[DNR_META_KEY] || null;
}

/**
 * Convert a URL to a DNR url filter pattern.
 *
 * Examples:
 * - https://evil.com -> ||evil.com^
 * - https://phish.com/login -> ||phish.com/login^
 * - http://malware.net:8080/dl -> ||malware.net:8080/dl^
 */
export function urlToDNRFilter(url: string): string {
  try {
    const parsed = new URL(url);

    // Build filter pattern
    // || means match any scheme
    // ^ means separator (end of host, port, path segment)
    let filter = '||' + parsed.hostname;

    // Add port if non-default
    if (parsed.port) {
      filter += ':' + parsed.port;
    }

    // Add path if not just /
    if (parsed.pathname && parsed.pathname !== '/') {
      filter += parsed.pathname;
    }

    // End with separator
    filter += '^';

    return filter;
  } catch {
    // Invalid URL, return as-is with basic escaping
    return '||' + url.replace(/[^a-zA-Z0-9.-]/g, '*') + '^';
  }
}

/**
 * Create a DNR block rule from a URL.
 *
 * @param url - URL to block
 * @param ruleId - Unique rule ID
 * @returns DNR rule object
 */
export function createBlockRule(
  url: string,
  ruleId: number
): chrome.declarativeNetRequest.Rule {
  return {
    id: ruleId,
    priority: 1,
    action: {
      type: chrome.declarativeNetRequest.RuleActionType.BLOCK,
    },
    condition: {
      urlFilter: urlToDNRFilter(url),
      resourceTypes: [
        chrome.declarativeNetRequest.ResourceType.MAIN_FRAME,
        chrome.declarativeNetRequest.ResourceType.SUB_FRAME,
      ],
    },
  };
}

/**
 * Create a DNR redirect rule from a URL.
 *
 * Instead of blocking (which shows Chrome's error page), redirect
 * to our custom block page for better user experience.
 *
 * @param url - URL to block
 * @param ruleId - Unique rule ID
 * @param blockPageUrl - URL of the block page to redirect to
 * @returns DNR rule object
 */
export function createRedirectRule(
  url: string,
  ruleId: number,
  blockPageUrl: string
): chrome.declarativeNetRequest.Rule {
  return {
    id: ruleId,
    priority: 1,
    action: {
      type: chrome.declarativeNetRequest.RuleActionType.REDIRECT,
      redirect: {
        url: blockPageUrl,
      },
    },
    condition: {
      urlFilter: urlToDNRFilter(url),
      resourceTypes: [chrome.declarativeNetRequest.ResourceType.MAIN_FRAME],
    },
  };
}

/**
 * Get the block page URL for a blocked request.
 * Used by DNR redirect rules.
 *
 * @param blockedUrl - The URL that was blocked
 * @returns Block page URL with query parameters
 */
export function getBlockPageUrl(blockedUrl: string): string {
  const params = new URLSearchParams({
    url: blockedUrl,
    ts: Date.now().toString(),
    reason: 'ioc_match',
  });

  return chrome.runtime.getURL('blocked/blocked.html') + '?' + params.toString();
}

/**
 * Update DNR rules from a list of URLs to block.
 *
 * This replaces all existing dynamic rules with new ones.
 * Rules redirect to our block page instead of using Chrome's BLOCK action,
 * ensuring users see the BrowserDefense block page and forensics are captured.
 *
 * @param urls - Array of URLs to block
 * @param version - Blocklist version number
 * @returns Result of the update operation
 */
export async function updateDNRRules(
  urls: string[],
  version: number
): Promise<DNRUpdateResult> {
  if (!isDNRAvailable()) {
    return {
      success: false,
      ruleCount: 0,
      error: 'DNR not available',
    };
  }

  // Enforce Chrome's rule limit
  const rulesToAdd = urls.slice(0, MAX_DYNAMIC_RULES);
  const truncated = urls.length > MAX_DYNAMIC_RULES;

  if (truncated) {
    console.warn(
      `[BrowserDefense] DNR rule limit reached: ${urls.length} URLs, using first ${MAX_DYNAMIC_RULES}`
    );
  }

  try {
    // Get existing rules to remove
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existingRules.map((r) => r.id);

    // Create redirect rules (not BLOCK rules) so users see BrowserDefense block page
    // and forensics can be captured via setupDNRForensicsCapture
    const addRules = rulesToAdd.map((url, index) => {
      const blockPageUrl = getBlockPageUrl(url);
      return createRedirectRule(url, DYNAMIC_RULE_ID_START + index, blockPageUrl);
    });

    // Apply update
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules,
    });

    // Save metadata
    const metadata: DNRMetadata = {
      ruleCount: addRules.length,
      updatedAt: Date.now(),
      version,
    };
    await chrome.storage.local.set({ [DNR_META_KEY]: metadata });

    console.log(`[BrowserDefense] DNR rules updated: ${addRules.length} redirect rules`);

    return {
      success: true,
      ruleCount: addRules.length,
    };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    console.error('[BrowserDefense] Failed to update DNR rules:', error);

    return {
      success: false,
      ruleCount: 0,
      error,
    };
  }
}

/**
 * Clear all DNR rules.
 */
export async function clearDNRRules(): Promise<void> {
  if (!isDNRAvailable()) {
    return;
  }

  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existingRules.map((r) => r.id);

    if (removeRuleIds.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds,
        addRules: [],
      });
    }

    // Clear metadata
    await chrome.storage.local.remove(DNR_META_KEY);

    console.log('[BrowserDefense] DNR rules cleared');
  } catch (err) {
    console.error('[BrowserDefense] Failed to clear DNR rules:', err);
  }
}

/**
 * Add a single URL to the DNR blocklist.
 *
 * @param url - URL to block
 * @returns Updated rule count
 */
export async function addDNRRule(url: string): Promise<number> {
  if (!isDNRAvailable()) {
    return 0;
  }

  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();

    // Check limit
    if (existingRules.length >= MAX_DYNAMIC_RULES) {
      console.warn('[BrowserDefense] DNR rule limit reached, cannot add more rules');
      return existingRules.length;
    }

    // Find next available ID
    const maxId = existingRules.reduce((max, r) => Math.max(max, r.id), 0);
    const blockPageUrl = getBlockPageUrl(url);
    const newRule = createRedirectRule(url, maxId + 1, blockPageUrl);

    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [newRule],
    });

    return existingRules.length + 1;
  } catch (err) {
    console.error('[BrowserDefense] Failed to add DNR rule:', err);
    return 0;
  }
}

/**
 * Remove a URL from the DNR blocklist.
 *
 * @param url - URL to unblock
 * @returns Updated rule count
 */
export async function removeDNRRule(url: string): Promise<number> {
  if (!isDNRAvailable()) {
    return 0;
  }

  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const filter = urlToDNRFilter(url);

    // Find matching rule
    const matchingRule = existingRules.find((r) => r.condition.urlFilter === filter);

    if (matchingRule) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [matchingRule.id],
      });
      return existingRules.length - 1;
    }

    return existingRules.length;
  } catch (err) {
    console.error('[BrowserDefense] Failed to remove DNR rule:', err);
    return 0;
  }
}

// ============ Priority-Based DNR Functions ============

/**
 * Result of updating DNR from prioritized IOCs.
 */
export interface PrioritizedDNRUpdateResult {
  success: boolean;
  /** Number of sync IOCs compiled to DNR rules */
  syncRuleCount: number;
  /** Number of IOCs demoted from sync to async due to capacity */
  demotedCount: number;
  /** Number of sync IOCs skipped (no URL field) */
  skippedNoUrl: number;
  /** Total async IOCs (not in DNR) */
  asyncCount: number;
  error?: string;
}

/**
 * Update DNR rules from prioritized IOCs.
 *
 * ONLY sync priority IOCs are compiled to DNR rules.
 * Async priority IOCs are NOT touched - they use webRequest path.
 *
 * This is the core of IOC QoS:
 * - Sync IOCs get instant pre-request blocking (limited to 30k)
 * - Async IOCs get post-navigation redirect (unlimited)
 *
 * @param iocs - Array of prioritized IOCs
 * @param version - Blocklist version number
 * @returns Update result with statistics
 */
export async function updateDNRFromPrioritizedIOCs(
  iocs: PrioritizedIOC[],
  version: number
): Promise<PrioritizedDNRUpdateResult> {
  if (!isDNRAvailable()) {
    return {
      success: false,
      syncRuleCount: 0,
      demotedCount: 0,
      skippedNoUrl: 0,
      asyncCount: iocs.length,
      error: 'DNR not available',
    };
  }

  // Partition IOCs by priority
  const partitioned = partitionByPriority(iocs, MAX_DNR_RULES);

  // Filter sync IOCs that have URLs (required for DNR)
  const syncWithUrls = partitioned.sync.filter((ioc) => ioc.url);
  const skippedNoUrl = partitioned.sync.length - syncWithUrls.length;

  if (skippedNoUrl > 0) {
    console.warn(
      `[BrowserDefense] ${skippedNoUrl} sync IOCs skipped - no URL for DNR rule`
    );
  }

  // Extract URLs for DNR compilation
  const syncUrls = syncWithUrls.map((ioc) => ioc.url!);

  // Update DNR rules
  const dnrResult = await updateDNRRules(syncUrls, version);

  if (!dnrResult.success) {
    return {
      success: false,
      syncRuleCount: 0,
      demotedCount: partitioned.stats.demotedCount,
      skippedNoUrl,
      asyncCount: partitioned.stats.asyncCount,
      error: dnrResult.error,
    };
  }

  console.log(
    `[BrowserDefense] Priority-based DNR update: ${dnrResult.ruleCount} sync rules, ` +
    `${partitioned.stats.asyncCount} async IOCs, ${partitioned.stats.demotedCount} demoted`
  );

  return {
    success: true,
    syncRuleCount: dnrResult.ruleCount,
    demotedCount: partitioned.stats.demotedCount,
    skippedNoUrl,
    asyncCount: partitioned.stats.asyncCount,
  };
}

/**
 * Get DNR capacity information.
 *
 * @returns Current usage and available capacity
 */
export async function getDNRCapacity(): Promise<{
  used: number;
  available: number;
  max: number;
  percentUsed: number;
}> {
  const used = await getDNRRuleCount();

  return {
    used,
    available: MAX_DNR_RULES - used,
    max: MAX_DNR_RULES,
    percentUsed: Math.round((used / MAX_DNR_RULES) * 100),
  };
}

/**
 * Check if there's capacity for more sync IOCs.
 *
 * @param count - Number of IOCs to check
 * @returns True if there's enough capacity
 */
export async function hasDNRCapacity(count: number): Promise<boolean> {
  const capacity = await getDNRCapacity();
  return capacity.available >= count;
}
