/**
 * Processing Robustness for Shadow Detection (Issue #251)
 *
 * Provides:
 * - Timeout for DOM skeleton extraction (prevent hung tabs)
 * - Max DOM depth/size limits to prevent DoS
 * - Graceful handling of malformed/hostile DOM structures
 * - Rate limiting per-tab and global
 *
 * Design: Processing failures must NEVER affect core blocking or UX.
 * Large/malicious DOMs should be safely truncated, not crash.
 */

import type {
  RateLimiterConfig,
  RateLimiterStatus,
  DOMProcessingLimits,
  SafeDOMProcessingResult,
} from '../../types/shadow-robustness';
import { DEFAULT_SHADOW_ROBUSTNESS_CONFIG } from '../../types/shadow-robustness';

// ============ Constants ============

const RATE_LIMIT_KEY = 'browserdefense_shadow_rate_limits';

// ============ Rate Limiter Implementation ============

interface RateLimitState {
  /** Global request timestamps in current window */
  globalTimestamps: number[];
  /** Per-tab request timestamps */
  perTabTimestamps: Record<number, number[]>;
  /** Last cleanup time */
  lastCleanup: number;
}

/**
 * Rate limiter for shadow detection processing.
 * Prevents overwhelming the system with too many requests.
 */
export class RateLimiter {
  private config: RateLimiterConfig;
  private state: RateLimitState;

  constructor(config: Partial<RateLimiterConfig> = {}) {
    this.config = {
      ...DEFAULT_SHADOW_ROBUSTNESS_CONFIG.rateLimiter,
      ...config,
    };
    this.state = {
      globalTimestamps: [],
      perTabTimestamps: {},
      lastCleanup: Date.now(),
    };
  }

  /**
   * Load state from storage.
   */
  async load(): Promise<void> {
    try {
      const result = await chrome.storage.local.get(RATE_LIMIT_KEY);
      const stored = result[RATE_LIMIT_KEY] as RateLimitState | undefined;
      if (stored) {
        this.state = stored;
        this.cleanup(); // Clean old entries
      }
    } catch (err) {
      console.warn('[BrowserDefense] Failed to load rate limit state:', err);
    }
  }

  /**
   * Save state to storage (debounced).
   */
  private saveTimeout: ReturnType<typeof setTimeout> | null = null;
  private async save(): Promise<void> {
    // Debounce saves to reduce storage writes
    if (this.saveTimeout) {
      clearTimeout(this.saveTimeout);
    }
    this.saveTimeout = setTimeout(async () => {
      try {
        await chrome.storage.local.set({ [RATE_LIMIT_KEY]: this.state });
      } catch (err) {
        console.warn('[BrowserDefense] Failed to save rate limit state:', err);
      }
    }, 1000);
  }

  /**
   * Clean up old timestamps.
   */
  private cleanup(): void {
    const now = Date.now();
    const globalCutoff = now - this.config.windowMs;
    const tabCutoff = now - this.config.perTabWindowMs;

    // Clean global timestamps
    this.state.globalTimestamps = this.state.globalTimestamps.filter((t) => t > globalCutoff);

    // Clean per-tab timestamps
    for (const tabId of Object.keys(this.state.perTabTimestamps)) {
      const tabIdNum = parseInt(tabId, 10);
      this.state.perTabTimestamps[tabIdNum] = this.state.perTabTimestamps[tabIdNum].filter(
        (t) => t > tabCutoff
      );
      // Remove empty entries
      if (this.state.perTabTimestamps[tabIdNum].length === 0) {
        delete this.state.perTabTimestamps[tabIdNum];
      }
    }

    this.state.lastCleanup = now;
  }

  /**
   * Check if a request is allowed.
   * Does NOT consume a request slot.
   */
  isAllowed(tabId?: number): boolean {
    const now = Date.now();

    // Cleanup if needed
    if (now - this.state.lastCleanup > 10000) {
      this.cleanup();
    }

    // Check global limit
    const globalCutoff = now - this.config.windowMs;
    const recentGlobal = this.state.globalTimestamps.filter((t) => t > globalCutoff);
    if (recentGlobal.length >= this.config.maxRequests) {
      return false;
    }

    // Check per-tab limit if applicable
    if (tabId !== undefined && this.config.perTabLimit > 0) {
      const tabCutoff = now - this.config.perTabWindowMs;
      const tabTimestamps = this.state.perTabTimestamps[tabId] ?? [];
      const recentTab = tabTimestamps.filter((t) => t > tabCutoff);
      if (recentTab.length >= this.config.perTabLimit) {
        return false;
      }
    }

    return true;
  }

  /**
   * Try to acquire a request slot.
   * Returns true if allowed, false if rate limited.
   */
  tryAcquire(tabId?: number): boolean {
    if (!this.isAllowed(tabId)) {
      return false;
    }

    const now = Date.now();

    // Record global timestamp
    this.state.globalTimestamps.push(now);

    // Record per-tab timestamp
    if (tabId !== undefined) {
      if (!this.state.perTabTimestamps[tabId]) {
        this.state.perTabTimestamps[tabId] = [];
      }
      this.state.perTabTimestamps[tabId].push(now);
    }

    // Save state (debounced)
    this.save().catch((err) => console.warn('[Shadow] Save failed:', err));

    return true;
  }

  /**
   * Get rate limiter status.
   */
  getStatus(): RateLimiterStatus {
    const now = Date.now();
    const globalCutoff = now - this.config.windowMs;

    const recentGlobal = this.state.globalTimestamps.filter((t) => t > globalCutoff);
    const remaining = Math.max(0, this.config.maxRequests - recentGlobal.length);

    // Find next reset time
    let resetAt = now + this.config.windowMs;
    if (recentGlobal.length > 0) {
      resetAt = recentGlobal[0] + this.config.windowMs;
    }

    return {
      currentCount: recentGlobal.length,
      remaining,
      resetAt,
      isLimited: remaining === 0,
      perTabCounts: new Map(
        Object.entries(this.state.perTabTimestamps).map(([tabId, timestamps]) => {
          const tabCutoff = now - this.config.perTabWindowMs;
          return [parseInt(tabId, 10), timestamps.filter((t) => t > tabCutoff).length];
        })
      ),
    };
  }

  /**
   * Reset rate limiter.
   */
  async reset(): Promise<void> {
    this.state = {
      globalTimestamps: [],
      perTabTimestamps: {},
      lastCleanup: Date.now(),
    };
    try {
      await chrome.storage.local.remove(RATE_LIMIT_KEY);
    } catch {
      // Ignore
    }
    console.log('[BrowserDefense] Rate limiter reset');
  }

  /**
   * Remove tracking for a closed tab.
   */
  removeTab(tabId: number): void {
    delete this.state.perTabTimestamps[tabId];
    this.save().catch((err) => console.warn('[Shadow] Save failed:', err));
  }
}

// ============ DOM Processing Safety ============

/**
 * Result of safe DOM processing.
 */
export interface SafeSkeletonResult {
  /** Serialized tag tree (may be truncated) */
  tagTree: string;
  /** Processing metadata */
  meta: SafeDOMProcessingResult;
}

/**
 * Safe DOM skeleton extraction with limits.
 * This wraps the content script extraction with safety limits.
 */
export function createSafeDOMExtractor(
  limits: Partial<DOMProcessingLimits> = {}
): {
  extractSkeleton: (doc: Document) => SafeSkeletonResult;
} {
  const config: DOMProcessingLimits = {
    ...DEFAULT_SHADOW_ROBUSTNESS_CONFIG.domLimits,
    ...limits,
  };

  return {
    extractSkeleton: (doc: Document): SafeSkeletonResult => {
      const startTime = performance.now();
      let nodesProcessed = 0;
      let maxDepthReached = 0;
      let truncated = false;
      let truncationReason: SafeDOMProcessingResult['truncationReason'];

      const _STRUCTURAL_TAGS = new Set([
        'html', 'head', 'body',
        'header', 'footer', 'main', 'nav', 'aside', 'section', 'article',
        'div', 'span', 'p', 'a',
        'form', 'input', 'button', 'select', 'textarea', 'label', 'fieldset', 'legend',
        'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td',
        'ul', 'ol', 'li', 'dl', 'dt', 'dd',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'iframe',
      ]);

      const SKIP_TAGS = new Set([
        'script', 'style', 'noscript', 'template',
        'svg', 'canvas', 'video', 'audio',
        'img', 'picture', 'source',
      ]);

      function serializeNode(node: Element | null, depth: number): string {
        // Check timeout
        if (performance.now() - startTime > config.timeoutMs) {
          truncated = true;
          truncationReason = 'timeout';
          return '';
        }

        // Check depth limit
        if (depth > config.maxDepth) {
          truncated = true;
          truncationReason = 'max_depth';
          return '';
        }

        // Check node limit
        if (nodesProcessed >= config.maxNodes) {
          truncated = true;
          truncationReason = 'max_nodes';
          return '';
        }

        if (!node) return '';

        const tagName = node.tagName.toLowerCase();

        // Skip non-structural tags entirely
        if (SKIP_TAGS.has(tagName)) {
          return '';
        }

        nodesProcessed++;
        maxDepthReached = Math.max(maxDepthReached, depth);

        // Build attribute string (only structural attributes)
        const attrs: string[] = [];

        if (tagName === 'input') {
          const type = (node.getAttribute('type') || 'text').toLowerCase();
          attrs.push('type=' + type);
        }

        if (tagName === 'button') {
          const type = (node.getAttribute('type') || 'submit').toLowerCase();
          attrs.push('type=' + type);
        }

        if (tagName === 'form') {
          const method = (node.getAttribute('method') || 'get').toLowerCase();
          attrs.push('method=' + method);
        }

        attrs.sort();
        const attrStr = attrs.length > 0 ? '[' + attrs.join(',') + ']' : '';

        // Recursively process children
        const childStrings: string[] = [];
        const children = Array.from(node.children);

        for (const child of children) {
          // Check if we're truncated
          if (truncated) break;

          const childStr = serializeNode(child, depth + 1);
          if (childStr) {
            childStrings.push(childStr);
          }
        }

        // Sort children for determinism
        childStrings.sort();

        // Build result
        if (childStrings.length === 0) {
          return tagName + attrStr;
        }

        return tagName + attrStr + '(' + childStrings.join(',') + ')';
      }

      // Extract skeleton
      let tagTree = serializeNode(doc.documentElement, 0);

      // Check tag tree length limit
      if (tagTree.length > config.maxTagTreeLength) {
        tagTree = tagTree.substring(0, config.maxTagTreeLength);
        truncated = true;
        truncationReason = 'max_length';
      }

      const processingTimeMs = performance.now() - startTime;

      return {
        tagTree,
        meta: {
          success: !truncated || truncationReason !== 'timeout',
          truncated,
          truncationReason,
          processedDepth: maxDepthReached,
          processedNodes: nodesProcessed,
          processingTimeMs,
        },
      };
    },
  };
}

/**
 * Execute a function with a timeout.
 * Returns the result or throws TimeoutError.
 */
export async function withTimeout<T>(
  fn: () => Promise<T>,
  timeoutMs: number,
  errorMessage: string = 'Operation timed out'
): Promise<T> {
  return Promise.race([
    fn(),
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(errorMessage)), timeoutMs)
    ),
  ]);
}

/**
 * Safe wrapper for async operations that should not throw.
 * Returns null on error instead of throwing.
 */
export async function safeAsync<T>(
  fn: () => Promise<T>,
  fallback: T | null = null,
  errorHandler?: (err: Error) => void
): Promise<T | null> {
  try {
    return await fn();
  } catch (err) {
    if (errorHandler) {
      errorHandler(err as Error);
    }
    return fallback;
  }
}

// ============ Message Validation ============

/**
 * Validate a DOM_SKELETON message from content script.
 * Returns sanitized payload or null if invalid.
 */
export function validateSkeletonMessage(message: unknown): {
  valid: boolean;
  payload?: {
    tagTree: string;
    formCount: number;
    inputTypes: string[];
    actionUrls: string[];
    hasLoginForm: boolean;
    hasPaymentForm: boolean;
    extractionTimeMs: number;
  };
  url?: string;
  error?: string;
} {
  if (!message || typeof message !== 'object') {
    return { valid: false, error: 'Invalid message format' };
  }

  const msg = message as Record<string, unknown>;

  if (msg.type !== 'DOM_SKELETON') {
    return { valid: false, error: 'Invalid message type' };
  }

  if (typeof msg.url !== 'string' || msg.url.length === 0) {
    return { valid: false, error: 'Missing or invalid URL' };
  }

  const payload = msg.payload as Record<string, unknown>;
  if (!payload || typeof payload !== 'object') {
    return { valid: false, error: 'Missing or invalid payload' };
  }

  // Validate payload fields
  if (typeof payload.tagTree !== 'string') {
    return { valid: false, error: 'Invalid tagTree' };
  }

  if (typeof payload.formCount !== 'number' || payload.formCount < 0) {
    return { valid: false, error: 'Invalid formCount' };
  }

  if (!Array.isArray(payload.inputTypes)) {
    return { valid: false, error: 'Invalid inputTypes' };
  }

  if (!Array.isArray(payload.actionUrls)) {
    return { valid: false, error: 'Invalid actionUrls' };
  }

  if (typeof payload.hasLoginForm !== 'boolean') {
    return { valid: false, error: 'Invalid hasLoginForm' };
  }

  if (typeof payload.hasPaymentForm !== 'boolean') {
    return { valid: false, error: 'Invalid hasPaymentForm' };
  }

  // Sanitize tag tree length
  const limits = DEFAULT_SHADOW_ROBUSTNESS_CONFIG.domLimits;
  let tagTree = payload.tagTree as string;
  if (tagTree.length > limits.maxTagTreeLength) {
    tagTree = tagTree.substring(0, limits.maxTagTreeLength);
  }

  return {
    valid: true,
    payload: {
      tagTree,
      formCount: Math.min(payload.formCount as number, 1000),
      inputTypes: (payload.inputTypes as string[]).slice(0, 100),
      actionUrls: (payload.actionUrls as string[]).slice(0, 100),
      hasLoginForm: payload.hasLoginForm as boolean,
      hasPaymentForm: payload.hasPaymentForm as boolean,
      extractionTimeMs: typeof payload.extractionTimeMs === 'number'
        ? payload.extractionTimeMs
        : 0,
    },
    url: msg.url as string,
  };
}

// ============ Singleton Instance ============

let defaultRateLimiter: RateLimiter | null = null;

/**
 * Get the default rate limiter instance.
 */
export function getDefaultRateLimiter(): RateLimiter {
  if (!defaultRateLimiter) {
    defaultRateLimiter = new RateLimiter();
  }
  return defaultRateLimiter;
}

/**
 * Initialize processing robustness.
 */
export async function initProcessingRobustness(): Promise<void> {
  const limiter = getDefaultRateLimiter();
  await limiter.load();

  // Listen for tab close events to clean up per-tab state
  if (typeof chrome !== 'undefined' && chrome.tabs) {
    chrome.tabs.onRemoved.addListener((tabId) => {
      limiter.removeTab(tabId);
    });
  }
}

// ============ Exports for Testing ============

export {
  RATE_LIMIT_KEY as _RATE_LIMIT_KEY,
};
