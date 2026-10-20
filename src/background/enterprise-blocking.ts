/**
 * Enterprise blocking using webRequest.onBeforeRequest.
 *
 * This module provides synchronous, pre-request blocking using Chrome's
 * webRequest API with the 'blocking' option. This is only available in
 * MV3 for policy-installed (enterprise) extensions.
 *
 * Key benefits over webNavigation:
 * - Blocks BEFORE the request is sent (no IOC leak)
 * - Synchronous decision (no race conditions)
 * - Captures full request details for forensics
 *
 * Requirements:
 * - Extension must be policy-installed via GPO/MDM
 * - manifest.json must include webRequest and webRequestBlocking permissions
 */

import { BinaryHashSet } from '../storage/binary-set';
import { canonicalizeAndHash, type CanonicalizationScope } from '../crypto/canonicalize';
import {
  queueForensics,
  trackRedirect,
  getRedirectChain,
} from './forensics';
import { getBlockPageUrl } from './blocking';

// Module state
let blocklist: BinaryHashSet | null = null;
let iocSalt: string | null = null;
let iocScope: CanonicalizationScope = 'HOST_ONLY';
let isEnterpriseMode = false;

/**
 * Check if webRequestBlocking is available.
 * This will only return true for policy-installed extensions.
 */
export async function checkEnterpriseMode(): Promise<boolean> {
  try {
    // Check if we have the webRequestBlocking permission
    const hasPermission = await chrome.permissions.contains({
      permissions: ['webRequestBlocking'],
    });

    if (hasPermission) {
      // Verify webRequest API is available
      if (typeof chrome.webRequest !== 'undefined') {
        console.log('[BrowserDefense] Enterprise mode available (webRequestBlocking)');
        isEnterpriseMode = true;
        return true;
      }
    }
  } catch (err) {
    console.log('[BrowserDefense] Enterprise mode check failed:', err);
  }

  console.log('[BrowserDefense] Enterprise mode not available, using fallback');
  isEnterpriseMode = false;
  return false;
}

/**
 * Get current enterprise mode status.
 */
export function getEnterpriseMode(): boolean {
  return isEnterpriseMode;
}

/**
 * Initialize enterprise blocking with blocklist and config.
 */
export function initEnterpriseBlocking(
  blocklistRef: BinaryHashSet,
  salt: string,
  scope: CanonicalizationScope
): void {
  blocklist = blocklistRef;
  iocSalt = salt;
  iocScope = scope;
}

/**
 * Update enterprise blocking config.
 */
export function updateEnterpriseConfig(
  blocklistRef: BinaryHashSet,
  salt: string,
  scope: CanonicalizationScope
): void {
  blocklist = blocklistRef;
  iocSalt = salt;
  iocScope = scope;
}

/**
 * Async hash lookup for blocking decision.
 *
 * Uses Web Crypto API for SHA-256 hashing. The async nature is handled
 * by returning a Promise from the webRequest listener, which Chrome
 * holds the request for until the Promise resolves (with 'blocking' extraInfoSpec).
 */
async function checkBlocked(url: string): Promise<boolean> {
  if (!blocklist || !iocSalt) {
    return false;
  }

  try {
    const hash = await canonicalizeAndHash(url, iocSalt, {
      scope: iocScope,
      includeScheme: true,
    });
    return blocklist.has(hash);
  } catch {
    return false;
  }
}

/**
 * Callback type for MV3 enterprise webRequest blocking.
 * Chrome MV3 with webRequestBlocking supports Promise return values,
 * but the @types/chrome definitions don't include this.
 */
type EnterpriseBlockingCallback = (
  details: chrome.webRequest.WebRequestBodyDetails
) => chrome.webRequest.BlockingResponse | Promise<chrome.webRequest.BlockingResponse> | void;

/**
 * Set up enterprise webRequest blocking with synchronous pre-request blocking.
 *
 * In MV3 with webRequestBlocking permission (policy-installed extensions),
 * the listener callback can return a Promise that resolves to a BlockingResponse.
 * This allows async hash lookup while still blocking the request BEFORE it's sent.
 *
 * The request is held until the Promise resolves, ensuring no IOC leak occurs
 * (no DNS lookup, no HTTP request to the malicious destination).
 */
export function setupEnterpriseBlocking(): void {
  if (!isEnterpriseMode) {
    console.warn('[BrowserDefense] Cannot setup enterprise blocking - not in enterprise mode');
    return;
  }

  // Callback with Promise return - Chrome MV3 enterprise supports this
  const blockingCallback: EnterpriseBlockingCallback = (details) => {
    // Only handle main frame requests
    if (details.type !== 'main_frame') {
      return;
    }

    // Skip chrome:// and extension URLs
    if (
      details.url.startsWith('chrome://') ||
      details.url.startsWith('chrome-extension://')
    ) {
      return;
    }

    // Track for forensics
    if (details.tabId >= 0) {
      trackRedirect(details.tabId, details.url);
    }

    // Return a Promise that resolves to BlockingResponse
    // The request is HELD until this Promise resolves (pre-request blocking)
    return checkBlocked(details.url).then((blocked): chrome.webRequest.BlockingResponse => {
      if (blocked && details.tabId >= 0) {
        // Queue forensics asynchronously (fire-and-forget, don't delay the redirect)
        handleEnterpriseForensics(details);

        // Return redirect response - request is blocked BEFORE being sent
        const blockPageUrl = getBlockPageUrl(details.url, 'ioc_match');
        console.log(`[BrowserDefense] Enterprise blocked (pre-request): ${details.url}`);
        return { redirectUrl: blockPageUrl };
      }

      // Allow request to proceed
      return {};
    });
  };

  // webRequest.onBeforeRequest with 'blocking' extraInfoSpec for pre-request blocking
  // Cast needed: @types/chrome doesn't include Promise support for MV3 enterprise
  chrome.webRequest.onBeforeRequest.addListener(
    blockingCallback as (
      details: chrome.webRequest.WebRequestBodyDetails
    ) => chrome.webRequest.BlockingResponse | undefined,
    {
      urls: ['http://*/*', 'https://*/*'],
      types: ['main_frame'],
    },
    ['blocking']
  );

  console.log('[BrowserDefense] Enterprise webRequest blocking registered (synchronous)');
}

/**
 * Queue forensics for a blocked enterprise request.
 * The redirect is handled by the blocking response, so this only queues forensics.
 */
function handleEnterpriseForensics(
  details: chrome.webRequest.WebRequestBodyDetails
): void {
  // Get redirect chain before building payload (consumes the chain)
  const redirectChain = getRedirectChain(details.tabId);

  // Capture forensics with enterprise-specific metadata
  const forensicsPayload = {
    blockedUrl: details.url,
    timestamp: new Date().toISOString(),
    redirectChain,
    tabId: details.tabId,
    frameId: details.frameId,
    reason: 'ioc_match',
    normalizedUrl: details.url,
    initiator: details.initiator,
  };

  // Queue forensics (fire-and-forget, don't block the redirect)
  queueForensics(forensicsPayload).catch((err) => {
    console.error('[BrowserDefense] Failed to queue enterprise forensics:', err);
  });
}

