/**
 * IOC Priority Tests
 *
 * Tests for priority-based IOC enforcement.
 * Issue #158: P0 - Priority-Based IOC Enforcement
 *
 * Key requirements:
 * - IOC metadata includes priority (sync | async)
 * - Only sync IOCs consume DNR quota
 * - Async IOCs never touch DNR
 * - Backward compatible with existing IOC format
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  type IOCPriority,
  type PrioritizedIOC,
  MAX_DNR_RULES,
  DEFAULT_PRIORITY,
  partitionByPriority,
  assignPriority,
  getIOCPriority,
  isIOCExpired,
  filterExpiredIOCs,
  createPrioritizedIOC,
  demoteToAsync,
  promoteToSync,
  getPriorityStats,
} from '../src/ioc/priority';

// Helper to create test IOCs
function createTestIOC(
  hash: string,
  priority: IOCPriority,
  url?: string,
  options: {
    source?: string;
    expiresAt?: string;
  } = {}
): PrioritizedIOC {
  return {
    hash,
    priority,
    url,
    source: options.source,
    addedAt: new Date().toISOString(),
    expiresAt: options.expiresAt,
  };
}

describe('IOC Priority Types', () => {
  describe('IOCPriority type', () => {
    it('should accept sync as a valid priority', () => {
      const priority: IOCPriority = 'sync';
      expect(priority).toBe('sync');
    });

    it('should accept async as a valid priority', () => {
      const priority: IOCPriority = 'async';
      expect(priority).toBe('async');
    });
  });

  describe('PrioritizedIOC interface', () => {
    it('should create a valid sync IOC with URL', () => {
      const ioc: PrioritizedIOC = {
        hash: 'a'.repeat(64),
        priority: 'sync',
        url: 'https://evil.com/phishing',
        source: 'analyst-feed',
        addedAt: new Date().toISOString(),
      };

      expect(ioc.priority).toBe('sync');
      expect(ioc.url).toBeDefined();
    });

    it('should create a valid async IOC without URL', () => {
      const ioc: PrioritizedIOC = {
        hash: 'b'.repeat(64),
        priority: 'async',
        // No URL - async IOCs don't need URLs
      };

      expect(ioc.priority).toBe('async');
      expect(ioc.url).toBeUndefined();
    });
  });
});

describe('partitionByPriority', () => {
  it('should partition IOCs into sync and async', () => {
    const iocs: PrioritizedIOC[] = [
      createTestIOC('a'.repeat(64), 'sync', 'https://evil1.com'),
      createTestIOC('b'.repeat(64), 'sync', 'https://evil2.com'),
      createTestIOC('c'.repeat(64), 'async'),
      createTestIOC('d'.repeat(64), 'async'),
      createTestIOC('e'.repeat(64), 'async'),
    ];

    const result = partitionByPriority(iocs);

    expect(result.sync).toHaveLength(2);
    expect(result.async).toHaveLength(3);
    expect(result.stats.syncCount).toBe(2);
    expect(result.stats.asyncCount).toBe(3);
    expect(result.stats.totalCount).toBe(5);
    expect(result.stats.demotedCount).toBe(0);
  });

  it('should demote sync IOCs when DNR capacity exceeded', () => {
    const dnrCapacity = 3;
    const iocs: PrioritizedIOC[] = [
      createTestIOC('a'.repeat(64), 'sync', 'https://evil1.com'),
      createTestIOC('b'.repeat(64), 'sync', 'https://evil2.com'),
      createTestIOC('c'.repeat(64), 'sync', 'https://evil3.com'),
      createTestIOC('d'.repeat(64), 'sync', 'https://evil4.com'), // Should be demoted
      createTestIOC('e'.repeat(64), 'sync', 'https://evil5.com'), // Should be demoted
    ];

    const result = partitionByPriority(iocs, dnrCapacity);

    expect(result.sync).toHaveLength(3);
    expect(result.async).toHaveLength(2);
    expect(result.stats.demotedCount).toBe(2);
  });

  it('should filter out expired IOCs', () => {
    const pastDate = new Date(Date.now() - 1000).toISOString();
    const futureDate = new Date(Date.now() + 100000).toISOString();

    const iocs: PrioritizedIOC[] = [
      createTestIOC('a'.repeat(64), 'sync', 'https://evil1.com', { expiresAt: futureDate }),
      createTestIOC('b'.repeat(64), 'sync', 'https://evil2.com', { expiresAt: pastDate }), // Expired
      createTestIOC('c'.repeat(64), 'async'),
    ];

    const result = partitionByPriority(iocs);

    expect(result.stats.totalCount).toBe(2); // Expired IOC not counted
    expect(result.sync).toHaveLength(1);
  });

  it('should respect MAX_DNR_RULES constant', () => {
    expect(MAX_DNR_RULES).toBe(30000);
  });
});

describe('assignPriority', () => {
  it('should use explicit priority when provided', () => {
    const iocs = [
      { hash: 'a'.repeat(64), priority: 'sync' as IOCPriority, url: 'https://evil.com' },
      { hash: 'b'.repeat(64), priority: 'async' as IOCPriority },
    ];

    const result = assignPriority(iocs);

    expect(result.syncIOCs).toHaveLength(1);
    expect(result.asyncIOCs).toHaveLength(1);
  });

  it('should assign sync to high-confidence sources', () => {
    const highConfidenceSources = new Set(['curated-feed', 'analyst-verified']);
    const iocs = [
      { hash: 'a'.repeat(64), source: 'curated-feed', url: 'https://evil1.com' },
      { hash: 'b'.repeat(64), source: 'analyst-verified', url: 'https://evil2.com' },
      { hash: 'c'.repeat(64), source: 'community-feed' },
    ];

    const result = assignPriority(iocs, highConfidenceSources);

    expect(result.syncIOCs).toHaveLength(2);
    expect(result.asyncIOCs).toHaveLength(1);
    expect(result.syncIOCs.every(ioc => ioc.priority === 'sync')).toBe(true);
  });

  it('should default to async for IOCs without priority or high-confidence source', () => {
    const iocs = [
      { hash: 'a'.repeat(64) },
      { hash: 'b'.repeat(64), source: 'unknown-feed' },
    ];

    const result = assignPriority(iocs);

    expect(result.syncIOCs).toHaveLength(0);
    expect(result.asyncIOCs).toHaveLength(2);
    expect(result.asyncIOCs.every(ioc => ioc.priority === 'async')).toBe(true);
  });

  it('should demote sync IOCs when capacity exceeded', () => {
    const iocs = Array.from({ length: 5 }, (_, i) => ({
      hash: String(i).repeat(64),
      priority: 'sync' as IOCPriority,
      url: `https://evil${i}.com`,
    }));

    const result = assignPriority(iocs, new Set(), 3);

    expect(result.syncIOCs).toHaveLength(3);
    expect(result.demotedIOCs).toHaveLength(2);
    expect(result.dnrCapacityExceeded).toBe(true);
  });
});

describe('getIOCPriority', () => {
  it('should return explicit priority when set', () => {
    expect(getIOCPriority({ priority: 'sync' })).toBe('sync');
    expect(getIOCPriority({ priority: 'async' })).toBe('async');
  });

  it('should return sync for high-confidence source', () => {
    const highConfidence = new Set(['trusted']);
    expect(getIOCPriority({ source: 'trusted' }, highConfidence)).toBe('sync');
  });

  it('should return default priority when no explicit or source match', () => {
    expect(getIOCPriority({})).toBe(DEFAULT_PRIORITY);
    expect(getIOCPriority({ source: 'unknown' })).toBe(DEFAULT_PRIORITY);
  });
});

describe('isIOCExpired', () => {
  it('should return false for IOC without expiration', () => {
    const ioc = createTestIOC('a'.repeat(64), 'sync');
    expect(isIOCExpired(ioc)).toBe(false);
  });

  it('should return false for IOC with future expiration', () => {
    const futureDate = new Date(Date.now() + 100000).toISOString();
    const ioc = createTestIOC('a'.repeat(64), 'sync', undefined, { expiresAt: futureDate });
    expect(isIOCExpired(ioc)).toBe(false);
  });

  it('should return true for IOC with past expiration', () => {
    const pastDate = new Date(Date.now() - 1000).toISOString();
    const ioc = createTestIOC('a'.repeat(64), 'sync', undefined, { expiresAt: pastDate });
    expect(isIOCExpired(ioc)).toBe(true);
  });
});

describe('filterExpiredIOCs', () => {
  it('should filter out expired IOCs', () => {
    const pastDate = new Date(Date.now() - 1000).toISOString();
    const futureDate = new Date(Date.now() + 100000).toISOString();

    const iocs = [
      createTestIOC('a'.repeat(64), 'sync', undefined, { expiresAt: futureDate }),
      createTestIOC('b'.repeat(64), 'sync', undefined, { expiresAt: pastDate }),
      createTestIOC('c'.repeat(64), 'async'),
    ];

    const filtered = filterExpiredIOCs(iocs);

    expect(filtered).toHaveLength(2);
    expect(filtered.map(i => i.hash[0])).toEqual(['a', 'c']);
  });
});

describe('createPrioritizedIOC', () => {
  it('should create a sync IOC with URL', () => {
    const ioc = createPrioritizedIOC(
      'a'.repeat(64),
      'sync',
      'https://evil.com',
      { source: 'test' }
    );

    expect(ioc.hash).toBe('a'.repeat(64));
    expect(ioc.priority).toBe('sync');
    expect(ioc.url).toBe('https://evil.com');
    expect(ioc.source).toBe('test');
    expect(ioc.addedAt).toBeDefined();
  });

  it('should create an async IOC without URL', () => {
    const ioc = createPrioritizedIOC('b'.repeat(64), 'async');

    expect(ioc.priority).toBe('async');
    expect(ioc.url).toBeUndefined();
  });

  it('should warn when creating sync IOC without URL', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    createPrioritizedIOC('a'.repeat(64), 'sync'); // No URL

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('Sync IOC created without URL')
    );

    warnSpy.mockRestore();
  });
});

describe('demoteToAsync', () => {
  it('should change priority from sync to async', () => {
    const syncIOC = createTestIOC('a'.repeat(64), 'sync', 'https://evil.com');
    const demoted = demoteToAsync(syncIOC);

    expect(demoted.priority).toBe('async');
    expect(demoted.hash).toBe(syncIOC.hash);
    expect(demoted.url).toBe(syncIOC.url);
  });

  it('should preserve all other fields', () => {
    const syncIOC = createTestIOC('a'.repeat(64), 'sync', 'https://evil.com', {
      source: 'test-feed',
    });
    const demoted = demoteToAsync(syncIOC);

    expect(demoted.source).toBe('test-feed');
    expect(demoted.addedAt).toBe(syncIOC.addedAt);
  });
});

describe('promoteToSync', () => {
  it('should change priority from async to sync when URL present', () => {
    const asyncIOC = createTestIOC('a'.repeat(64), 'async', 'https://evil.com');
    const promoted = promoteToSync(asyncIOC);

    expect(promoted).not.toBeNull();
    expect(promoted!.priority).toBe('sync');
  });

  it('should return null when IOC has no URL', () => {
    const asyncIOC = createTestIOC('a'.repeat(64), 'async');
    const promoted = promoteToSync(asyncIOC);

    expect(promoted).toBeNull();
  });

  it('should warn when IOC has no URL', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const asyncIOC = createTestIOC('a'.repeat(64), 'async');
    promoteToSync(asyncIOC);

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('Cannot promote to sync - IOC has no URL')
    );

    warnSpy.mockRestore();
  });
});

describe('getPriorityStats', () => {
  it('should return correct statistics', () => {
    const pastDate = new Date(Date.now() - 1000).toISOString();

    const iocs: PrioritizedIOC[] = [
      createTestIOC('a'.repeat(64), 'sync', 'https://evil1.com'),
      createTestIOC('b'.repeat(64), 'sync', 'https://evil2.com'),
      createTestIOC('c'.repeat(64), 'async', 'https://evil3.com'),
      createTestIOC('d'.repeat(64), 'async'),
      createTestIOC('e'.repeat(64), 'sync', undefined, { expiresAt: pastDate }), // Expired
    ];

    const stats = getPriorityStats(iocs);

    expect(stats.total).toBe(5);
    expect(stats.sync).toBe(3);
    expect(stats.async).toBe(2);
    expect(stats.expired).toBe(1);
    expect(stats.withUrl).toBe(3);
    expect(stats.withoutUrl).toBe(2);
  });
});

describe('Backward Compatibility', () => {
  it('should default to async priority for IOCs without explicit priority', () => {
    // Simulate old IOC format (no priority field)
    // Cast to allow extra properties (hash) while satisfying function signature
    const legacyIOC = {
      hash: 'a'.repeat(64),
      // No priority field - cast to allow extra properties
    } as { priority?: IOCPriority; source?: string };

    const priority = getIOCPriority(legacyIOC);
    expect(priority).toBe('async');
  });

  it('should work with mixed old and new IOC formats', () => {
    const iocs = [
      // New format with explicit priority
      { hash: 'a'.repeat(64), priority: 'sync' as IOCPriority, url: 'https://evil1.com' },
      // Old format without priority
      { hash: 'b'.repeat(64) },
      { hash: 'c'.repeat(64) },
    ];

    const result = assignPriority(iocs);

    // One sync (explicit), two async (default)
    expect(result.syncIOCs).toHaveLength(1);
    expect(result.asyncIOCs).toHaveLength(2);
  });
});

describe('DNR Quota Management', () => {
  it('should never exceed MAX_DNR_RULES for sync IOCs', () => {
    // Create more IOCs than DNR limit
    const iocs = Array.from({ length: MAX_DNR_RULES + 1000 }, (_, i) => ({
      hash: String(i).padStart(64, '0'),
      priority: 'sync' as IOCPriority,
      url: `https://evil${i}.com`,
    }));

    const result = partitionByPriority(iocs);

    expect(result.sync.length).toBeLessThanOrEqual(MAX_DNR_RULES);
    expect(result.stats.demotedCount).toBe(1000);
  });

  it('async IOCs should not consume DNR quota', () => {
    const iocs: PrioritizedIOC[] = [
      createTestIOC('a'.repeat(64), 'async'),
      createTestIOC('b'.repeat(64), 'async'),
      createTestIOC('c'.repeat(64), 'async'),
    ];

    const result = partitionByPriority(iocs, 1); // Even with capacity 1

    // All async IOCs stay async, none go to sync
    expect(result.sync).toHaveLength(0);
    expect(result.async).toHaveLength(3);
    expect(result.stats.demotedCount).toBe(0);
  });
});
