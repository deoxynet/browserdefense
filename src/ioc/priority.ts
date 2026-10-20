/**
 * IOC Priority-Based Enforcement
 *
 * Defines priority levels for IOCs that determine enforcement path:
 * - `sync` → compiled into DNR rules (30k cap, instant pre-request blocking)
 * - `async` → handled via webRequest observer (unlimited, post-navigation redirect)
 *
 * This is IOC QoS (Quality of Service) - a major product differentiator.
 *
 * Reference: docs/Architecture_v2_DOM_Detection.md Section "IOC Priority System"
 */

// ============ Types ============

/**
 * IOC enforcement priority level.
 *
 * - `sync`: High priority - compiled to DNR rules for instant blocking.
 *   Limited to 30k rules. Best for high-confidence, curated IOCs.
 *
 * - `async`: Standard priority - handled via webRequest observer.
 *   Unlimited capacity. Blocking happens post-navigation via redirect.
 */
export type IOCPriority = 'sync' | 'async';

/**
 * IOC with priority metadata.
 * Extends the basic hash with priority and optional source info.
 */
export interface PrioritizedIOC {
  /** SHA-256 hash of the canonicalized IOC (hex string) */
  hash: string;
  /** Enforcement priority */
  priority: IOCPriority;
  /** Original URL (only for sync IOCs, needed for DNR rules) */
  url?: string;
  /** Source of this IOC (e.g., feed name, analyst ID) */
  source?: string;
  /** When this IOC was added (ISO 8601) */
  addedAt?: string;
  /** Expiration time (ISO 8601) - IOC is ignored after this */
  expiresAt?: string;
  /**
   * Whether to capture a screenshot when this IOC is blocked.
   * Requires global screenshot feature to also be enabled.
   * Default: false (opt-in per IOC)
   */
  captureScreenshot?: boolean;
}

/**
 * Partitioned IOC collection by priority.
 */
export interface PartitionedIOCs {
  /** Sync IOCs (for DNR) */
  sync: PrioritizedIOC[];
  /** Async IOCs (for webRequest) */
  async: PrioritizedIOC[];
  /** Stats */
  stats: {
    totalCount: number;
    syncCount: number;
    asyncCount: number;
    /** Number of sync IOCs that exceeded DNR limit and were demoted to async */
    demotedCount: number;
  };
}

/**
 * Result of IOC priority assignment.
 */
export interface PriorityAssignmentResult {
  /** IOCs successfully assigned to sync (DNR) */
  syncIOCs: PrioritizedIOC[];
  /** IOCs assigned to async (webRequest) */
  asyncIOCs: PrioritizedIOC[];
  /** IOCs that were demoted from sync to async due to capacity */
  demotedIOCs: PrioritizedIOC[];
  /** Whether DNR capacity was exceeded */
  dnrCapacityExceeded: boolean;
}

// ============ Constants ============

/** Maximum DNR rules Chrome allows */
export const MAX_DNR_RULES = 30000;

/** Default priority for IOCs without explicit priority */
export const DEFAULT_PRIORITY: IOCPriority = 'async';

// ============ Functions ============

/**
 * Partition IOCs by priority level.
 *
 * @param iocs - Array of prioritized IOCs
 * @param dnrCapacity - Maximum sync IOCs (default: MAX_DNR_RULES)
 * @returns Partitioned IOCs with stats
 */
export function partitionByPriority(
  iocs: PrioritizedIOC[],
  dnrCapacity: number = MAX_DNR_RULES
): PartitionedIOCs {
  const sync: PrioritizedIOC[] = [];
  const async: PrioritizedIOC[] = [];
  let demotedCount = 0;

  // Filter out expired IOCs
  const now = new Date().toISOString();
  const validIOCs = iocs.filter((ioc) => !ioc.expiresAt || ioc.expiresAt > now);

  for (const ioc of validIOCs) {
    if (ioc.priority === 'sync') {
      if (sync.length < dnrCapacity) {
        sync.push(ioc);
      } else {
        // Demote to async if DNR capacity exceeded
        async.push({ ...ioc, priority: 'async' });
        demotedCount++;
      }
    } else {
      async.push(ioc);
    }
  }

  return {
    sync,
    async,
    stats: {
      totalCount: validIOCs.length,
      syncCount: sync.length,
      asyncCount: async.length,
      demotedCount,
    },
  };
}

/**
 * Assign priority to IOCs based on rules.
 *
 * Priority assignment rules (in order):
 * 1. Explicit priority in IOC metadata → use as-is
 * 2. High-confidence sources → sync
 * 3. Everything else → async
 *
 * @param iocs - IOCs to assign priority
 * @param highConfidenceSources - Sources that get sync priority
 * @param dnrCapacity - Maximum sync IOCs
 * @returns Assignment result
 */
export function assignPriority(
  iocs: Array<Omit<PrioritizedIOC, 'priority'> & { priority?: IOCPriority }>,
  highConfidenceSources: Set<string> = new Set(),
  dnrCapacity: number = MAX_DNR_RULES
): PriorityAssignmentResult {
  const syncIOCs: PrioritizedIOC[] = [];
  const asyncIOCs: PrioritizedIOC[] = [];
  const demotedIOCs: PrioritizedIOC[] = [];

  for (const ioc of iocs) {
    let priority: IOCPriority;

    if (ioc.priority) {
      // Explicit priority takes precedence
      priority = ioc.priority;
    } else if (ioc.source && highConfidenceSources.has(ioc.source)) {
      // High-confidence source gets sync
      priority = 'sync';
    } else {
      // Default to async
      priority = DEFAULT_PRIORITY;
    }

    const prioritizedIOC: PrioritizedIOC = {
      ...ioc,
      priority,
    };

    if (priority === 'sync') {
      if (syncIOCs.length < dnrCapacity) {
        syncIOCs.push(prioritizedIOC);
      } else {
        // Demote to async
        const demoted = { ...prioritizedIOC, priority: 'async' as IOCPriority };
        asyncIOCs.push(demoted);
        demotedIOCs.push(demoted);
      }
    } else {
      asyncIOCs.push(prioritizedIOC);
    }
  }

  return {
    syncIOCs,
    asyncIOCs,
    demotedIOCs,
    dnrCapacityExceeded: demotedIOCs.length > 0,
  };
}

/**
 * Get priority for a single IOC.
 *
 * @param ioc - IOC to check
 * @param highConfidenceSources - Sources that get sync priority
 * @returns Priority level
 */
export function getIOCPriority(
  ioc: { priority?: IOCPriority; source?: string },
  highConfidenceSources: Set<string> = new Set()
): IOCPriority {
  if (ioc.priority) {
    return ioc.priority;
  }

  if (ioc.source && highConfidenceSources.has(ioc.source)) {
    return 'sync';
  }

  return DEFAULT_PRIORITY;
}

/**
 * Check if an IOC is expired.
 */
export function isIOCExpired(ioc: PrioritizedIOC): boolean {
  if (!ioc.expiresAt) {
    return false;
  }

  return new Date(ioc.expiresAt) < new Date();
}

/**
 * Filter out expired IOCs from a collection.
 */
export function filterExpiredIOCs(iocs: PrioritizedIOC[]): PrioritizedIOC[] {
  return iocs.filter((ioc) => !isIOCExpired(ioc));
}

/**
 * Create a prioritized IOC from basic inputs.
 *
 * @param hash - SHA-256 hash (hex string)
 * @param priority - Enforcement priority
 * @param url - Original URL (required for sync IOCs)
 * @param options - Additional metadata
 * @returns PrioritizedIOC
 */
export function createPrioritizedIOC(
  hash: string,
  priority: IOCPriority,
  url?: string,
  options: {
    source?: string;
    expiresAt?: string;
  } = {}
): PrioritizedIOC {
  // Sync IOCs should have URLs for DNR compilation
  if (priority === 'sync' && !url) {
    console.warn(
      '[BrowserDefense] Sync IOC created without URL - DNR rule cannot be created'
    );
  }

  return {
    hash,
    priority,
    url,
    source: options.source,
    addedAt: new Date().toISOString(),
    expiresAt: options.expiresAt,
  };
}

/**
 * Demote a sync IOC to async.
 * Used when DNR capacity is exceeded or IOC no longer qualifies for sync.
 */
export function demoteToAsync(ioc: PrioritizedIOC): PrioritizedIOC {
  return {
    ...ioc,
    priority: 'async',
  };
}

/**
 * Promote an async IOC to sync.
 * Only valid if the IOC has a URL (needed for DNR).
 */
export function promoteToSync(ioc: PrioritizedIOC): PrioritizedIOC | null {
  if (!ioc.url) {
    console.warn(
      '[BrowserDefense] Cannot promote to sync - IOC has no URL for DNR'
    );
    return null;
  }

  return {
    ...ioc,
    priority: 'sync',
  };
}

/**
 * Get statistics about IOC priority distribution.
 */
export function getPriorityStats(iocs: PrioritizedIOC[]): {
  total: number;
  sync: number;
  async: number;
  expired: number;
  withUrl: number;
  withoutUrl: number;
} {
  let sync = 0;
  let async = 0;
  let expired = 0;
  let withUrl = 0;
  let withoutUrl = 0;

  for (const ioc of iocs) {
    if (isIOCExpired(ioc)) {
      expired++;
    }

    if (ioc.priority === 'sync') {
      sync++;
    } else {
      async++;
    }

    if (ioc.url) {
      withUrl++;
    } else {
      withoutUrl++;
    }
  }

  return {
    total: iocs.length,
    sync,
    async,
    expired,
    withUrl,
    withoutUrl,
  };
}
