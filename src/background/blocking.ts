/**
 * Navigation blocking logic for BrowserDefense.
 *
 * Supports two blocking modes:
 *
 * 1. Enterprise Mode (webRequestBlocking):
 *    - Uses webRequest.onBeforeRequest for pre-request blocking
 *    - Requires policy-installed extension with webRequestBlocking permission
 *    - True synchronous blocking (no IOC leak)
 *
 * 2. Consumer Mode (DNR + webNavigation fallback):
 *    - Uses declarativeNetRequest for pre-request blocking (when URLs available)
 *    - Falls back to webNavigation + redirect for hash-based blocking
 *    - Hash-based blocking is reactive (IOC may leak before redirect)
 *
 * Mode is auto-detected based on available permissions.
 */

import { BinaryHashSet, bytesToHex, hexToBytes } from '../storage/binary-set';
import { loadBlocklist, loadBloomFilter, buildBloomFilter, saveBloomFilter, saveBlocklist } from '../storage';
import { BloomFilter } from '../storage/bloom-filter';
import { canonicalizeAndHash, type CanonicalizationScope } from '../crypto/canonicalize';
import { loadConfig } from '../config/loader';
import { loadDemoConfig, matchesDemoUrl, type DemoConfig } from '../config/demo';
import {
  captureForensics,
  queueForensics,
  trackRedirect,
  clearRedirectChain,
} from './forensics';
import { consumeFormSchemas } from './form-schema-store';
import { consumeTLSMetadata } from './tls-metadata';
import {
  checkEnterpriseMode,
  initEnterpriseBlocking,
  setupEnterpriseBlocking,
  updateEnterpriseConfig,
} from './enterprise-blocking';
import {
  isDNRAvailable,
  getDNRRuleCount,
  getDNRCapacity,
  updateDNRFromPrioritizedIOCs,
  type PrioritizedDNRUpdateResult,
} from './dnr';
import {
  type IOCPriority,
  type PrioritizedIOC,
  MAX_DNR_RULES,
} from '../ioc/priority';
import {
  shouldCaptureScreenshotForIOC,
  saveIOCMetadata,
  type IOCMetadataMap,
} from '../storage/ioc-metadata';
import {
  captureAndEncryptScreenshot,
  shouldCaptureScreenshot,
} from '../forensics/screenshot';

/** Blocking mode the extension is operating in */
export type BlockingMode = 'enterprise' | 'dnr' | 'async' | 'fallback';

let blocklist: BinaryHashSet | null = null;
let bloomFilter: BloomFilter | null = null;
let isInitialized = false;
let iocSalt: string | null = null;
let iocScope: CanonicalizationScope = 'HOST_ONLY';
let currentBlockingMode: BlockingMode = 'fallback';
let dnrForensicsSetUp = false;

/** Demo mode configuration (Issue #571) */
let demoConfig: DemoConfig = { demoMode: false, demoUrls: [] };

/**
 * Initialize the blocking system.
 * Must be called before any blocking can occur.
 *
 * Auto-detects and configures the best available blocking mode:
 * 1. Enterprise (webRequestBlocking) - if policy-installed
 * 2. DNR (declarativeNetRequest) - if URL patterns available
 * 3. Fallback (webNavigation) - always available but reactive
 */
export async function initBlocking(): Promise<void> {
  if (isInitialized) return;

  try {
    // Load config for salt and scope
    const config = await loadConfig();
    if (config) {
      iocSalt = config.ioc_salt;
      iocScope = config.ioc_scope ?? 'HOST_ONLY';
      console.log(`[BrowserDefense] Using IOC scope: ${iocScope}`);
    } else {
      console.warn('[BrowserDefense] No config found, blocking will not work without salt');
    }

    // Load demo config (Issue #571)
    demoConfig = await loadDemoConfig();
    if (demoConfig.demoMode) {
      console.log(`[BrowserDefense] Demo mode enabled with ${demoConfig.demoUrls.length} demo URLs`);
    }

    // Load blocklist and bloom filter
    blocklist = await loadBlocklist();
    bloomFilter = await loadBloomFilter();

    // Build bloom filter if not present but blocklist exists
    if (!bloomFilter && blocklist && blocklist.count > 0) {
      console.log('[BrowserDefense] Building bloom filter from blocklist...');
      bloomFilter = buildBloomFilter(blocklist);
      await saveBloomFilter(bloomFilter);
      console.log(`[BrowserDefense] Bloom filter built: ${bloomFilter.itemCount} items`);
    }

    // Detect blocking mode
    const isEnterprise = await checkEnterpriseMode();

    if (isEnterprise) {
      // Enterprise mode: use webRequestBlocking
      currentBlockingMode = 'enterprise';
      if (iocSalt) {
        initEnterpriseBlocking(blocklist, iocSalt, iocScope);
      }
      console.log('[BrowserDefense] Blocking mode: ENTERPRISE (webRequestBlocking)');
    } else {
      // Consumer mode: check if DNR rules are active
      // DNR provides pre-request blocking for sync IOCs with URL patterns
      if (isDNRAvailable()) {
        const dnrCount = await getDNRRuleCount();
        if (dnrCount > 0) {
          // DNR rules exist - use DNR mode for pre-request blocking
          currentBlockingMode = 'dnr';
          console.log(`[BrowserDefense] Blocking mode: DNR (${dnrCount} redirect rules)`);
        } else {
          // No DNR rules - use async intercept path
          currentBlockingMode = 'async';
          console.log('[BrowserDefense] Blocking mode: ASYNC (webRequest observer + redirect)');
        }
      } else {
        // DNR not available - use async intercept path
        currentBlockingMode = 'async';
        console.log('[BrowserDefense] Blocking mode: ASYNC (webRequest observer + redirect)');
      }
    }

    isInitialized = true;
    const bloomInfo = bloomFilter ? `, bloom filter: ${bloomFilter.itemCount} items` : '';
    console.log(`[BrowserDefense] Blocking initialized with ${blocklist.count} hashes${bloomInfo}`);
  } catch (err) {
    console.error('[BrowserDefense] Failed to initialize blocklist:', err);
    blocklist = new BinaryHashSet();
    currentBlockingMode = 'fallback';
    isInitialized = true;
  }
}

/**
 * Get the current blocking mode.
 */
export function getBlockingMode(): BlockingMode {
  return currentBlockingMode;
}

/**
 * Result of checking if a URL is blocked.
 */
export interface BlockCheckResult {
  /** Whether the URL is blocked */
  blocked: boolean;
  /** Whether this is a demo block (vs real IOC match) */
  isDemo: boolean;
  /** Hash of the IOC (only for real IOC matches) */
  hash?: Uint8Array;
}

/**
 * Check if a URL should be blocked and why.
 * @param url - URL to check
 * @returns BlockCheckResult with blocking info
 */
export async function checkBlocked(url: string): Promise<BlockCheckResult> {
  if (!blocklist) {
    await initBlocking();
  }

  // Check demo mode first (Issue #571)
  if (demoConfig.demoMode && matchesDemoUrl(url, demoConfig.demoUrls)) {
    return { blocked: true, isDemo: true };
  }

  // Cannot check blocklist without salt
  if (!iocSalt) {
    return { blocked: false, isDemo: false };
  }

  try {
    // Use salted hashing with scheme to match CLI's hashIOC function.
    // Critical: includeScheme must be true to match CLI canonicalization.
    const hash = await canonicalizeAndHash(url, iocSalt, {
      scope: iocScope,
      includeScheme: true,
    });

    const matched = blocklist!.has(hash);
    return { blocked: matched, isDemo: false, hash: matched ? hash : undefined };
  } catch {
    // Invalid URL or unsupported scheme
    return { blocked: false, isDemo: false };
  }
}

/**
 * Check if a URL should be blocked.
 * @param url - URL to check
 * @returns true if the URL matches the blocklist or demo URLs
 */
export async function isBlocked(url: string): Promise<boolean> {
  const result = await checkBlocked(url);
  return result.blocked;
}

/**
 * Get the block page URL with parameters.
 */
export function getBlockPageUrl(blockedUrl: string, reason?: string): string {
  const params = new URLSearchParams({
    url: blockedUrl,
    ts: Date.now().toString(),
  });

  if (reason) {
    params.set('reason', reason);
  }

  return chrome.runtime.getURL('blocked/blocked.html') + '?' + params.toString();
}

/**
 * Options for handling a blocked navigation.
 */
export interface HandleBlockOptions {
  /** SHA-256 hash of the IOC (for metadata lookup) */
  iocHash?: string;
  /** Whether this is a demo block (Issue #571) */
  isDemo?: boolean;
}

/**
 * Handle a blocked navigation by redirecting to the block page.
 * Also captures and queues forensics data including form schemas.
 *
 * @param details - Navigation details from Chrome
 * @param normalizedUrl - Normalized URL that was matched
 * @param options - Block handling options
 */
export async function handleBlockedNavigation(
  details: chrome.webNavigation.WebNavigationParentedCallbackDetails,
  normalizedUrl: string,
  options: HandleBlockOptions = {}
): Promise<void> {
  const { iocHash, isDemo } = options;
  const blockPageUrl = getBlockPageUrl(details.url, 'ioc_match');

  // Consume form schemas for this tab (if available from content script)
  const formSchemas = consumeFormSchemas(details.tabId);

  // Consume TLS metadata for this tab (if available from webRequest headers)
  const tlsMetadata = consumeTLSMetadata(details.tabId);

  // Check if screenshot capture should be triggered for this block
  // Requires: 1) Global feature enabled, 2) Per-IOC flag enabled
  let screenshotResult = null;
  if (iocHash) {
    try {
      const config = await loadConfig();
      const globalEnabled = config?.screenshot_capture?.enabled ?? false;
      const iocEnabled = await shouldCaptureScreenshotForIOC(iocHash);

      if (shouldCaptureScreenshot(globalEnabled, iocEnabled)) {
        console.log('[BrowserDefense] Screenshot capture enabled for this IOC');

        // Capture screenshot BEFORE redirecting to block page
        // This captures the malicious page with inputs disabled
        if (config?.encryption_public_key) {
          screenshotResult = await captureAndEncryptScreenshot(
            details.tabId,
            config.encryption_public_key,
            {
              quality: config.screenshot_capture?.quality,
              watermark: {
                orgId: config.org_id,
                tier: config.screenshot_capture?.tier,
              },
            }
          );

          if (screenshotResult) {
            console.log('[BrowserDefense] Screenshot captured and encrypted');
          }
        } else {
          console.warn('[BrowserDefense] Cannot capture screenshot: no encryption key configured');
        }
      }
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      console.error(`[BrowserDefense] Screenshot capture failed for IOC ${iocHash?.slice(0, 8)}: ${error}`);
      // Continue with blocking even if screenshot fails
    }
  }

  // Capture forensics before redirecting (includes form schemas and TLS metadata if available)
  const forensicsPayload = captureForensics(details, normalizedUrl, {
    reason: isDemo ? 'demo_block' : 'ioc_match',
    formSchemas,
    tlsMetadata: tlsMetadata ?? undefined,
    isDemo,
  });

  // Add screenshot metadata to forensics if capture was successful
  if (screenshotResult) {
    forensicsPayload.screenshot = {
      imageHash: screenshotResult.imageHash,
      dimensions: screenshotResult.dimensions,
      capturedAt: screenshotResult.timestamp,
    };
  }

  // Queue forensics for upload (encryption will be added when config is available)
  try {
    await queueForensics(forensicsPayload);
  } catch (err) {
    console.error('[BrowserDefense] Failed to queue forensics:', err);
  }

  // Redirect to block page
  try {
    await chrome.tabs.update(details.tabId, { url: blockPageUrl });
    console.log(`[BrowserDefense] Blocked navigation to: ${details.url}`);
  } catch (err) {
    console.error('[BrowserDefense] Failed to redirect to block page:', err);
  }
}

/**
 * Set up navigation blocking listeners.
 *
 * This sets up the appropriate blocking mechanism based on the detected mode:
 * - Enterprise: webRequest.onBeforeRequest (pre-request blocking)
 * - DNR: declarativeNetRequest rules handle blocking automatically
 * - Fallback: webNavigation.onBeforeNavigate + redirect (reactive)
 *
 * webNavigation listeners are always set up for forensics capture.
 */
export function setupNavigationBlocking(): void {
  // Track redirects for forensics (always enabled)
  chrome.webNavigation.onBeforeNavigate.addListener(
    (details) => {
      if (details.frameId === 0) {
        trackRedirect(details.tabId, details.url);
      }
    },
    { url: [{ schemes: ['http', 'https'] }] }
  );

  // Set up mode-specific blocking
  if (currentBlockingMode === 'enterprise') {
    // Enterprise mode: use webRequest for pre-request blocking
    setupEnterpriseBlocking();
    console.log('[BrowserDefense] Enterprise webRequest blocking registered');
  } else if (currentBlockingMode === 'dnr') {
    // DNR mode: rules handle sync IOCs, also need async intercept for hash-based IOCs
    // DNR handles URL-pattern IOCs (pre-request blocking)
    // Async intercept handles hash-only IOCs (post-request redirect)
    setupDNRForensicsCapture();
    setupAsyncInterceptBlocking();
    console.log('[BrowserDefense] DNR blocking active + async intercept for hash-based IOCs');
  } else if (currentBlockingMode === 'async') {
    // Async intercept mode: use webRequest observer + redirect
    // This is the primary consumer path - non-blocking but fast
    setupAsyncInterceptBlocking();
    console.log('[BrowserDefense] Async intercept blocking registered');

    // Also set up DNR forensics capture - DNR rules may coexist with async blocking
    // Sync IOCs use DNR for pre-request blocking while async IOCs use webRequest
    if (isDNRAvailable()) {
      setupDNRForensicsCapture();
      console.log('[BrowserDefense] DNR forensics capture also registered (coexists with async)');
    }
  } else {
    // Fallback mode: use webNavigation + redirect (reactive, leaks IOC)
    setupFallbackBlocking();
    console.log('[BrowserDefense] Fallback webNavigation blocking registered');
    console.warn('[BrowserDefense] WARNING: Fallback mode is reactive - IOCs may leak');
  }

  // Clean up redirect tracking on tab close
  chrome.tabs.onRemoved.addListener((tabId) => {
    clearRedirectChain(tabId);
  });
}

/**
 * Set up forensics capture for DNR-blocked requests.
 * When DNR redirects a request to our block page, we capture forensics.
 * This function is idempotent - safe to call multiple times.
 */
function setupDNRForensicsCapture(): void {
  // Only set up once
  if (dnrForensicsSetUp) {
    return;
  }
  dnrForensicsSetUp = true;

  // Listen for navigations to our block page to capture forensics
  // DNR redirects to block page, we capture forensics on arrival
  const blockPageBase = chrome.runtime.getURL('blocked/blocked.html');

  chrome.webNavigation.onCompleted.addListener(async (details) => {
    // Only handle main frame navigations
    if (details.frameId !== 0) return;

    // Check if this is our block page
    if (!details.url.startsWith(blockPageBase)) return;

    // Extract blocked URL from query params
    try {
      const url = new URL(details.url);
      const blockedUrl = url.searchParams.get('url');

      if (blockedUrl) {
        // Capture forensics for DNR-blocked request
        const forensicsPayload = {
          blockedUrl,
          timestamp: new Date().toISOString(),
          tabId: details.tabId,
          frameId: details.frameId,
          reason: 'ioc_match',
          normalizedUrl: blockedUrl,
        };
        await queueForensics(forensicsPayload);
        console.log(`[BrowserDefense] DNR forensics captured: ${blockedUrl}`);
      }
    } catch {
      // Ignore parsing errors
    }
  });
}

/**
 * Set up async intercept blocking using webRequest (non-blocking).
 *
 * This is the primary consumer enforcement path for phishing protection.
 * It uses webRequest.onBeforeRequest WITHOUT the blocking flag, which:
 * - Works in all MV3 extensions (no enterprise policy required)
 * - Survives service worker cold-starts (async processing)
 * - Decouples from DNR rule limits
 *
 * On match, redirects the tab to blocked.html AFTER the request starts.
 * The original request may partially complete, but the user sees the block page.
 *
 * Note: This is intentionally "leaky" - security is traded for reliability.
 * For true pre-request blocking, use enterprise mode (webRequestBlocking).
 */
function setupAsyncInterceptBlocking(): void {
  chrome.webRequest.onBeforeRequest.addListener(
    (details): chrome.webRequest.BlockingResponse | undefined => {
      // Only intercept main frame navigations
      if (details.type !== 'main_frame') return undefined;

      // Skip chrome:// and extension URLs
      if (
        details.url.startsWith('chrome://') ||
        details.url.startsWith('chrome-extension://')
      ) {
        return undefined;
      }

      // Cannot check without salt
      if (!iocSalt) {
        return undefined;
      }

      // Fire and forget - don't block the request
      // This allows the check to happen async while the request proceeds
      checkAndRedirect(details.tabId, details.url, details.frameId).catch((err) => {
        console.error('[BrowserDefense] Async intercept error:', err);
      });

      return undefined;
    },
    {
      urls: ['http://*/*', 'https://*/*'],
      types: ['main_frame'],
    }
    // NOTE: No 'blocking' option - this is intentionally non-blocking
  );
}

/**
 * Check if a URL is blocked and redirect if necessary.
 * Called asynchronously from the webRequest listener.
 *
 * Uses bloom filter for fast negative prefiltering:
 * - If bloom says "not in set" -> skip expensive hash set lookup (O(k) vs O(log n))
 * - If bloom says "possibly in set" -> verify with authoritative hash set
 *
 * Also checks demo mode URLs (Issue #571).
 *
 * This ensures no measurable delay on normal (non-blocked) browsing.
 */
async function checkAndRedirect(tabId: number, url: string, frameId: number): Promise<void> {
  // Check demo mode first (fast path, no crypto needed)
  if (demoConfig.demoMode && matchesDemoUrl(url, demoConfig.demoUrls)) {
    console.log(`[BrowserDefense] Demo mode intercept: ${url}`);

    const details: chrome.webNavigation.WebNavigationParentedCallbackDetails = {
      tabId,
      url,
      frameId,
      timeStamp: Date.now(),
      processId: -1,
      parentFrameId: -1,
      frameType: 'outermost_frame',
      documentLifecycle: 'active',
    };

    await handleBlockedNavigation(details, url, { isDemo: true });
    return;
  }

  // Check blocklist (requires salt and blocklist)
  if (!iocSalt || !blocklist) {
    return;
  }

  try {
    // Use salted hashing with scheme to match CLI's hashIOC function.
    // Critical: includeScheme must be true to match CLI canonicalization.
    const hashBytes = await canonicalizeAndHash(url, iocSalt, {
      scope: iocScope,
      includeScheme: true,
    });

    // Fast path: bloom filter negative prefiltering
    // If bloom says "definitely not in set", skip the hash set lookup
    if (bloomFilter && !bloomFilter.mightContain(hashBytes)) {
      // Bloom filter says definitely not blocked - fast exit
      return;
    }

    // Slow path: verify with authoritative hash set
    // Either no bloom filter, or bloom said "possibly in set"
    const isMatch = blocklist.has(hashBytes);

    if (isMatch) {
      console.log(`[BrowserDefense] Async intercept match: ${url}`);

      // Convert hash to hex for metadata lookup
      const hashHex = bytesToHex(hashBytes);

      // Create a synthetic details object for handleBlockedNavigation
      const details: chrome.webNavigation.WebNavigationParentedCallbackDetails = {
        tabId,
        url,
        frameId,
        timeStamp: Date.now(),
        processId: -1, // Not available from webRequest
        parentFrameId: -1,
        frameType: 'outermost_frame',
        documentLifecycle: 'active',
      };

      await handleBlockedNavigation(details, url, { iocHash: hashHex });
    }
  } catch (err) {
    // Invalid URL or unsupported scheme, skip
    console.debug('[BrowserDefense] Async intercept skip:', err);
  }
}

/**
 * Set up fallback blocking using webNavigation.
 * This is reactive - the request may be sent before we can block.
 * Also handles demo mode URLs (Issue #571).
 */
function setupFallbackBlocking(): void {
  chrome.webNavigation.onBeforeNavigate.addListener(
    async (details) => {
      // Only block main frame navigations
      if (details.frameId !== 0) return;

      // Skip chrome:// and extension URLs
      if (
        details.url.startsWith('chrome://') ||
        details.url.startsWith('chrome-extension://')
      ) {
        return;
      }

      // Check demo mode first (Issue #571)
      if (demoConfig.demoMode && matchesDemoUrl(details.url, demoConfig.demoUrls)) {
        console.log(`[BrowserDefense] Demo mode block: ${details.url}`);
        await handleBlockedNavigation(details, details.url, { isDemo: true });
        return;
      }

      // Cannot check blocklist without salt
      if (!iocSalt) {
        return;
      }

      try {
        // Use salted hashing with scheme to match CLI's hashIOC function.
        // Critical: includeScheme must be true to match CLI canonicalization.
        const hashBytes = await canonicalizeAndHash(details.url, iocSalt, {
          scope: iocScope,
          includeScheme: true,
        });
        const blocked = blocklist?.has(hashBytes) ?? false;

        if (blocked) {
          // Convert hash to hex for metadata lookup
          const hashHex = bytesToHex(hashBytes);
          await handleBlockedNavigation(details, details.url, { iocHash: hashHex });
        }
      } catch {
        // Invalid URL or unsupported scheme, skip
      }
    },
    {
      url: [{ schemes: ['http', 'https'] }],
    }
  );
}

/**
 * Reload the blocklist from storage.
 * Also reloads config, bloom filter, and demo config.
 * Call this after blocklist updates.
 */
export async function reloadBlocklist(): Promise<void> {
  // Reload config in case salt/scope changed
  const config = await loadConfig();
  if (config) {
    iocSalt = config.ioc_salt;
    iocScope = config.ioc_scope ?? 'HOST_ONLY';
  }

  // Reload demo config (Issue #571)
  demoConfig = await loadDemoConfig();

  blocklist = await loadBlocklist();
  bloomFilter = await loadBloomFilter();

  // Rebuild bloom filter if stale or missing
  if (blocklist && blocklist.count > 0) {
    if (!bloomFilter || bloomFilter.isDirty) {
      console.log('[BrowserDefense] Rebuilding bloom filter...');
      bloomFilter = buildBloomFilter(blocklist);
      await saveBloomFilter(bloomFilter);
    }
  }

  // Update enterprise blocking config if in enterprise mode
  if (currentBlockingMode === 'enterprise' && iocSalt && blocklist) {
    updateEnterpriseConfig(blocklist, iocSalt, iocScope);
  }

  const bloomInfo = bloomFilter ? `, bloom: ${bloomFilter.itemCount} items` : '';
  const demoInfo = demoConfig.demoMode ? `, demo: ${demoConfig.demoUrls.length} URLs` : '';
  console.log(`[BrowserDefense] Blocklist reloaded with ${blocklist.count} hashes${bloomInfo}${demoInfo}`);
}

/**
 * Reload just the demo configuration.
 * Call this after demo config changes.
 * Issue #571
 */
export async function reloadDemoConfig(): Promise<void> {
  demoConfig = await loadDemoConfig();
  if (demoConfig.demoMode) {
    console.log(`[BrowserDefense] Demo mode reloaded: ${demoConfig.demoUrls.length} URLs`);
  } else {
    console.log('[BrowserDefense] Demo mode disabled');
  }
}

/**
 * Get current demo mode status.
 * Issue #571
 */
export function getDemoModeStatus(): { enabled: boolean; urlCount: number } {
  return {
    enabled: demoConfig.demoMode,
    urlCount: demoConfig.demoUrls.length,
  };
}

/**
 * Get current blocklist stats.
 */
export function getBlocklistInfo(): {
  initialized: boolean;
  count: number;
  blockingMode: BlockingMode;
  bloomFilter: {
    loaded: boolean;
    itemCount: number;
    isDirty: boolean;
  };
} {
  return {
    initialized: isInitialized,
    count: blocklist?.count ?? 0,
    blockingMode: currentBlockingMode,
    bloomFilter: {
      loaded: bloomFilter !== null,
      itemCount: bloomFilter?.itemCount ?? 0,
      isDirty: bloomFilter?.isDirty ?? false,
    },
  };
}

/**
 * Get extended blocklist info including DNR capacity.
 * Useful for monitoring IOC QoS status.
 */
export async function getBlocklistInfoExtended(): Promise<{
  initialized: boolean;
  count: number;
  blockingMode: BlockingMode;
  dnr: {
    available: boolean;
    used: number;
    capacity: number;
    percentUsed: number;
  };
}> {
  const basic = getBlocklistInfo();
  const dnrCapacity = await getDNRCapacity();

  return {
    ...basic,
    dnr: {
      available: isDNRAvailable(),
      used: dnrCapacity.used,
      capacity: dnrCapacity.max,
      percentUsed: dnrCapacity.percentUsed,
    },
  };
}

/**
 * Update blocklist with prioritized IOCs.
 *
 * This is the main entry point for priority-based IOC enforcement:
 * - Sync IOCs are compiled to DNR rules (instant blocking)
 * - Async IOCs are added to the hash set (webRequest path)
 *
 * @param iocs - Array of prioritized IOCs
 * @param version - Blocklist version number
 * @returns Update result
 */
export async function updateBlocklistWithPriority(
  iocs: PrioritizedIOC[],
  version: number
): Promise<{
  success: boolean;
  hashCount: number;
  dnrResult?: PrioritizedDNRUpdateResult;
  error?: string;
}> {
  try {
    // Add all IOC hashes to the binary hash set (used for async path)
    if (!blocklist) {
      blocklist = new BinaryHashSet();
    }

    // Collect IOC metadata for those with special flags (like captureScreenshot)
    const metadata: IOCMetadataMap = {};

    let hashCount = 0;
    for (const ioc of iocs) {
      try {
        const hashBytes = hexToBytes(ioc.hash);
        blocklist.add(hashBytes);
        hashCount++;

        // Store metadata for IOCs with captureScreenshot flag
        if (ioc.captureScreenshot) {
          metadata[ioc.hash.toLowerCase()] = {
            captureScreenshot: true,
            source: ioc.source,
            expiresAt: ioc.expiresAt,
          };
        }
      } catch {
        console.warn(`[BrowserDefense] Invalid hash: ${ioc.hash.slice(0, 16)}...`);
      }
    }

    // Save blocklist and metadata to storage
    await saveBlocklist(blocklist);

    // Save IOC metadata if any IOCs have special flags
    if (Object.keys(metadata).length > 0) {
      await saveIOCMetadata(metadata);
      const screenshotCount = Object.values(metadata).filter(m => m.captureScreenshot).length;
      console.log(`[BrowserDefense] Saved metadata for ${Object.keys(metadata).length} IOCs (${screenshotCount} with captureScreenshot)`);
    }

    // Rebuild bloom filter for async intercept path optimization
    bloomFilter = buildBloomFilter(blocklist, version);
    await saveBloomFilter(bloomFilter);

    // Update DNR rules for sync IOCs only
    const dnrResult = await updateDNRFromPrioritizedIOCs(iocs, version);

    // If DNR rules were installed, switch to DNR mode and set up forensics capture
    if (dnrResult.success && dnrResult.syncRuleCount > 0) {
      if (currentBlockingMode !== 'enterprise') {
        currentBlockingMode = 'dnr';
        // Set up DNR forensics capture (idempotent, safe to call multiple times)
        setupDNRForensicsCapture();
        console.log(`[BrowserDefense] Switched to DNR mode with ${dnrResult.syncRuleCount} redirect rules`);
      }
    }

    console.log(
      `[BrowserDefense] Priority blocklist updated: ${hashCount} hashes, ` +
      `${dnrResult.syncRuleCount} DNR rules, ${dnrResult.asyncCount} async, ` +
      `bloom filter: ${bloomFilter?.itemCount ?? 0} items`
    );

    return {
      success: true,
      hashCount,
      dnrResult,
    };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    console.error('[BrowserDefense] Failed to update priority blocklist:', error);

    return {
      success: false,
      hashCount: 0,
      error,
    };
  }
}

// Re-export IOC priority types for convenience
export { type IOCPriority, type PrioritizedIOC, MAX_DNR_RULES };
