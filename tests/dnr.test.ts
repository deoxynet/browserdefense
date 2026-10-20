import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// =============================================================================
// Chrome API Mocks
// =============================================================================

const mockGetDynamicRules = vi.fn();
const mockUpdateDynamicRules = vi.fn();
const mockStorageLocalGet = vi.fn();
const mockStorageLocalSet = vi.fn();
const mockStorageLocalRemove = vi.fn();
const mockRuntimeGetURL = vi.fn();

// DNR enums
const RuleActionType = {
  BLOCK: 'block',
  REDIRECT: 'redirect',
  ALLOW: 'allow',
  UPGRADE_SCHEME: 'upgradeScheme',
  MODIFY_HEADERS: 'modifyHeaders',
  ALLOW_ALL_REQUESTS: 'allowAllRequests',
} as const;

const ResourceType = {
  MAIN_FRAME: 'main_frame',
  SUB_FRAME: 'sub_frame',
  STYLESHEET: 'stylesheet',
  SCRIPT: 'script',
  IMAGE: 'image',
  FONT: 'font',
  OBJECT: 'object',
  XMLHTTPREQUEST: 'xmlhttprequest',
  PING: 'ping',
  CSP_REPORT: 'csp_report',
  MEDIA: 'media',
  WEBSOCKET: 'websocket',
  OTHER: 'other',
} as const;

vi.stubGlobal('chrome', {
  declarativeNetRequest: {
    getDynamicRules: mockGetDynamicRules,
    updateDynamicRules: mockUpdateDynamicRules,
    RuleActionType,
    ResourceType,
  },
  storage: {
    local: {
      get: mockStorageLocalGet,
      set: mockStorageLocalSet,
      remove: mockStorageLocalRemove,
    },
  },
  runtime: {
    getURL: mockRuntimeGetURL,
  },
});

// Mock the priority module
vi.mock('../src/ioc/priority', () => ({
  partitionByPriority: vi.fn(),
  MAX_DNR_RULES: 30000,
}));

// =============================================================================
// Tests
// =============================================================================

describe('DNR Module', () => {
  let dnrModule: typeof import('../src/background/dnr');
  let priorityModule: typeof import('../src/ioc/priority');

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();

    // Default mock returns
    mockGetDynamicRules.mockResolvedValue([]);
    mockUpdateDynamicRules.mockResolvedValue(undefined);
    mockStorageLocalGet.mockResolvedValue({});
    mockStorageLocalSet.mockResolvedValue(undefined);
    mockStorageLocalRemove.mockResolvedValue(undefined);
    mockRuntimeGetURL.mockImplementation((path: string) => `chrome-extension://test-id/${path}`);

    // Re-import modules
    dnrModule = await import('../src/background/dnr');
    priorityModule = await import('../src/ioc/priority');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ===========================================================================
  // isDNRAvailable
  // ===========================================================================

  describe('isDNRAvailable', () => {
    it('should return true when declarativeNetRequest is available', () => {
      expect(dnrModule.isDNRAvailable()).toBe(true);
    });

    it('should return false when declarativeNetRequest is undefined', async () => {
      // Temporarily remove DNR
      const originalDNR = chrome.declarativeNetRequest;
      (chrome as Record<string, unknown>).declarativeNetRequest = undefined;

      vi.resetModules();
      const freshModule = await import('../src/background/dnr');

      expect(freshModule.isDNRAvailable()).toBe(false);

      // Restore
      (chrome as Record<string, unknown>).declarativeNetRequest = originalDNR;
    });
  });

  // ===========================================================================
  // getDNRRuleCount
  // ===========================================================================

  describe('getDNRRuleCount', () => {
    it('should return 0 when no rules exist', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      const count = await dnrModule.getDNRRuleCount();

      expect(count).toBe(0);
    });

    it('should return correct count when rules exist', async () => {
      mockGetDynamicRules.mockResolvedValue([
        { id: 1 },
        { id: 2 },
        { id: 3 },
      ]);

      const count = await dnrModule.getDNRRuleCount();

      expect(count).toBe(3);
    });

    it('should return 0 on error', async () => {
      mockGetDynamicRules.mockRejectedValue(new Error('API error'));

      const count = await dnrModule.getDNRRuleCount();

      expect(count).toBe(0);
    });

    it('should return 0 when DNR is not available', async () => {
      const originalDNR = chrome.declarativeNetRequest;
      (chrome as Record<string, unknown>).declarativeNetRequest = undefined;

      vi.resetModules();
      const freshModule = await import('../src/background/dnr');

      const count = await freshModule.getDNRRuleCount();

      expect(count).toBe(0);

      (chrome as Record<string, unknown>).declarativeNetRequest = originalDNR;
    });
  });

  // ===========================================================================
  // getDNRMetadata
  // ===========================================================================

  describe('getDNRMetadata', () => {
    it('should return null when no metadata exists', async () => {
      mockStorageLocalGet.mockResolvedValue({});

      const metadata = await dnrModule.getDNRMetadata();

      expect(metadata).toBeNull();
    });

    it('should return metadata when it exists', async () => {
      const storedMetadata = {
        ruleCount: 100,
        updatedAt: 1234567890,
        version: 5,
      };
      mockStorageLocalGet.mockResolvedValue({
        browserdefense_dnr_meta: storedMetadata,
      });

      const metadata = await dnrModule.getDNRMetadata();

      expect(metadata).toEqual(storedMetadata);
    });

    it('should query correct storage key', async () => {
      await dnrModule.getDNRMetadata();

      expect(mockStorageLocalGet).toHaveBeenCalledWith('browserdefense_dnr_meta');
    });
  });

  // ===========================================================================
  // urlToDNRFilter
  // ===========================================================================

  describe('urlToDNRFilter', () => {
    it('should convert simple HTTPS URL', () => {
      const filter = dnrModule.urlToDNRFilter('https://evil.com');

      expect(filter).toBe('||evil.com^');
    });

    it('should convert URL with path', () => {
      const filter = dnrModule.urlToDNRFilter('https://phish.com/login');

      expect(filter).toBe('||phish.com/login^');
    });

    it('should convert URL with port', () => {
      const filter = dnrModule.urlToDNRFilter('http://malware.net:8080/dl');

      expect(filter).toBe('||malware.net:8080/dl^');
    });

    it('should handle URL with query string', () => {
      const filter = dnrModule.urlToDNRFilter('https://bad.com/page?id=123');

      expect(filter).toBe('||bad.com/page^');
    });

    it('should handle HTTP URL', () => {
      const filter = dnrModule.urlToDNRFilter('http://unsafe.org');

      expect(filter).toBe('||unsafe.org^');
    });

    it('should handle deep path', () => {
      const filter = dnrModule.urlToDNRFilter('https://evil.com/a/b/c/d');

      expect(filter).toBe('||evil.com/a/b/c/d^');
    });

    it('should handle subdomain', () => {
      const filter = dnrModule.urlToDNRFilter('https://sub.evil.com');

      expect(filter).toBe('||sub.evil.com^');
    });

    it('should handle invalid URL gracefully', () => {
      const filter = dnrModule.urlToDNRFilter('not-a-valid-url');

      // Should escape special chars and wrap with ||...^
      expect(filter).toMatch(/^\|\|.*\^$/);
    });

    it('should not include trailing slash in filter', () => {
      const filter = dnrModule.urlToDNRFilter('https://evil.com/');

      expect(filter).toBe('||evil.com^');
    });
  });

  // ===========================================================================
  // createBlockRule
  // ===========================================================================

  describe('createBlockRule', () => {
    it('should create block rule with correct structure', () => {
      const rule = dnrModule.createBlockRule('https://evil.com', 1);

      expect(rule).toEqual({
        id: 1,
        priority: 1,
        action: {
          type: RuleActionType.BLOCK,
        },
        condition: {
          urlFilter: '||evil.com^',
          resourceTypes: [ResourceType.MAIN_FRAME, ResourceType.SUB_FRAME],
        },
      });
    });

    it('should use provided rule ID', () => {
      const rule = dnrModule.createBlockRule('https://test.com', 42);

      expect(rule.id).toBe(42);
    });

    it('should include both MAIN_FRAME and SUB_FRAME resource types', () => {
      const rule = dnrModule.createBlockRule('https://test.com', 1);

      expect(rule.condition.resourceTypes).toContain(ResourceType.MAIN_FRAME);
      expect(rule.condition.resourceTypes).toContain(ResourceType.SUB_FRAME);
    });

    it('should set priority to 1', () => {
      const rule = dnrModule.createBlockRule('https://test.com', 1);

      expect(rule.priority).toBe(1);
    });
  });

  // ===========================================================================
  // createRedirectRule
  // ===========================================================================

  describe('createRedirectRule', () => {
    it('should create redirect rule with correct structure', () => {
      const rule = dnrModule.createRedirectRule(
        'https://evil.com',
        1,
        'chrome-extension://id/blocked.html'
      );

      expect(rule).toEqual({
        id: 1,
        priority: 1,
        action: {
          type: RuleActionType.REDIRECT,
          redirect: {
            url: 'chrome-extension://id/blocked.html',
          },
        },
        condition: {
          urlFilter: '||evil.com^',
          resourceTypes: [ResourceType.MAIN_FRAME],
        },
      });
    });

    it('should only include MAIN_FRAME resource type', () => {
      const rule = dnrModule.createRedirectRule('https://test.com', 1, 'chrome://blocked');

      expect(rule.condition.resourceTypes).toEqual([ResourceType.MAIN_FRAME]);
      expect(rule.condition.resourceTypes).not.toContain(ResourceType.SUB_FRAME);
    });

    it('should use provided block page URL', () => {
      const blockPageUrl = 'chrome-extension://test/custom-block.html?reason=ioc';
      const rule = dnrModule.createRedirectRule('https://test.com', 1, blockPageUrl);

      expect(rule.action.redirect?.url).toBe(blockPageUrl);
    });
  });

  // ===========================================================================
  // getBlockPageUrl
  // ===========================================================================

  describe('getBlockPageUrl', () => {
    it('should generate block page URL with parameters', () => {
      const url = dnrModule.getBlockPageUrl('https://evil.com');

      expect(url).toContain('blocked/blocked.html');
      expect(url).toContain('url=');
      expect(url).toContain('ts=');
      expect(url).toContain('reason=ioc_match');
    });

    it('should use chrome.runtime.getURL', () => {
      dnrModule.getBlockPageUrl('https://evil.com');

      expect(mockRuntimeGetURL).toHaveBeenCalledWith('blocked/blocked.html');
    });

    it('should encode blocked URL in query params', () => {
      const blockedUrl = 'https://evil.com/path?query=value';
      const url = dnrModule.getBlockPageUrl(blockedUrl);

      expect(url).toContain(encodeURIComponent(blockedUrl));
    });

    it('should include timestamp', () => {
      const beforeTs = Date.now();
      const url = dnrModule.getBlockPageUrl('https://evil.com');
      const afterTs = Date.now();

      const tsMatch = url.match(/ts=(\d+)/);
      expect(tsMatch).not.toBeNull();
      const ts = parseInt(tsMatch![1], 10);
      expect(ts).toBeGreaterThanOrEqual(beforeTs);
      expect(ts).toBeLessThanOrEqual(afterTs);
    });
  });

  // ===========================================================================
  // updateDNRRules
  // ===========================================================================

  describe('updateDNRRules', () => {
    it('should update rules successfully', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      const result = await dnrModule.updateDNRRules(['https://evil.com'], 1);

      expect(result.success).toBe(true);
      expect(result.ruleCount).toBe(1);
    });

    it('should remove existing rules before adding new ones', async () => {
      mockGetDynamicRules.mockResolvedValue([{ id: 1 }, { id: 2 }]);

      await dnrModule.updateDNRRules(['https://new.com'], 1);

      expect(mockUpdateDynamicRules).toHaveBeenCalledWith({
        removeRuleIds: [1, 2],
        addRules: expect.any(Array),
      });
    });

    it('should create redirect rules with block page URLs', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      await dnrModule.updateDNRRules(['https://evil.com'], 1);

      const call = mockUpdateDynamicRules.mock.calls[0][0];
      expect(call.addRules[0].action.type).toBe(RuleActionType.REDIRECT);
      expect(call.addRules[0].action.redirect.url).toContain('blocked/blocked.html');
    });

    it('should save metadata after successful update', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      await dnrModule.updateDNRRules(['https://evil.com'], 5);

      expect(mockStorageLocalSet).toHaveBeenCalledWith({
        browserdefense_dnr_meta: expect.objectContaining({
          ruleCount: 1,
          version: 5,
        }),
      });
    });

    it('should truncate URLs exceeding 30000 limit', async () => {
      mockGetDynamicRules.mockResolvedValue([]);
      const urls = Array.from({ length: 35000 }, (_, i) => `https://evil${i}.com`);

      const result = await dnrModule.updateDNRRules(urls, 1);

      const call = mockUpdateDynamicRules.mock.calls[0][0];
      expect(call.addRules.length).toBe(30000);
      expect(result.ruleCount).toBe(30000);
    });

    it('should return error when DNR not available', async () => {
      const originalDNR = chrome.declarativeNetRequest;
      (chrome as Record<string, unknown>).declarativeNetRequest = undefined;

      vi.resetModules();
      const freshModule = await import('../src/background/dnr');

      const result = await freshModule.updateDNRRules(['https://evil.com'], 1);

      expect(result.success).toBe(false);
      expect(result.error).toBe('DNR not available');

      (chrome as Record<string, unknown>).declarativeNetRequest = originalDNR;
    });

    it('should handle API error gracefully', async () => {
      mockGetDynamicRules.mockResolvedValue([]);
      mockUpdateDynamicRules.mockRejectedValue(new Error('Update failed'));

      const result = await dnrModule.updateDNRRules(['https://evil.com'], 1);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Update failed');
    });

    it('should assign sequential rule IDs starting from 1', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      await dnrModule.updateDNRRules(['https://a.com', 'https://b.com', 'https://c.com'], 1);

      const call = mockUpdateDynamicRules.mock.calls[0][0];
      expect(call.addRules[0].id).toBe(1);
      expect(call.addRules[1].id).toBe(2);
      expect(call.addRules[2].id).toBe(3);
    });
  });

  // ===========================================================================
  // clearDNRRules
  // ===========================================================================

  describe('clearDNRRules', () => {
    it('should remove all existing rules', async () => {
      mockGetDynamicRules.mockResolvedValue([{ id: 1 }, { id: 2 }, { id: 3 }]);

      await dnrModule.clearDNRRules();

      expect(mockUpdateDynamicRules).toHaveBeenCalledWith({
        removeRuleIds: [1, 2, 3],
        addRules: [],
      });
    });

    it('should clear metadata from storage', async () => {
      mockGetDynamicRules.mockResolvedValue([{ id: 1 }]);

      await dnrModule.clearDNRRules();

      expect(mockStorageLocalRemove).toHaveBeenCalledWith('browserdefense_dnr_meta');
    });

    it('should not call updateDynamicRules when no rules exist', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      await dnrModule.clearDNRRules();

      expect(mockUpdateDynamicRules).not.toHaveBeenCalled();
    });

    it('should still clear metadata even when no rules exist', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      await dnrModule.clearDNRRules();

      expect(mockStorageLocalRemove).toHaveBeenCalledWith('browserdefense_dnr_meta');
    });

    it('should handle errors gracefully', async () => {
      mockGetDynamicRules.mockRejectedValue(new Error('Failed'));

      // Should not throw
      await expect(dnrModule.clearDNRRules()).resolves.toBeUndefined();
    });

    it('should do nothing when DNR not available', async () => {
      const originalDNR = chrome.declarativeNetRequest;
      (chrome as Record<string, unknown>).declarativeNetRequest = undefined;

      vi.resetModules();
      const freshModule = await import('../src/background/dnr');

      await freshModule.clearDNRRules();

      expect(mockGetDynamicRules).not.toHaveBeenCalled();

      (chrome as Record<string, unknown>).declarativeNetRequest = originalDNR;
    });
  });

  // ===========================================================================
  // addDNRRule
  // ===========================================================================

  describe('addDNRRule', () => {
    it('should add a single rule', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      const count = await dnrModule.addDNRRule('https://evil.com');

      expect(count).toBe(1);
      expect(mockUpdateDynamicRules).toHaveBeenCalled();
    });

    it('should use next available ID', async () => {
      mockGetDynamicRules.mockResolvedValue([{ id: 1 }, { id: 5 }, { id: 3 }]);

      await dnrModule.addDNRRule('https://evil.com');

      const call = mockUpdateDynamicRules.mock.calls[0][0];
      expect(call.addRules[0].id).toBe(6); // max(1,5,3) + 1
    });

    it('should not add rule when at limit', async () => {
      mockGetDynamicRules.mockResolvedValue(
        Array.from({ length: 30000 }, (_, i) => ({ id: i + 1 }))
      );

      const count = await dnrModule.addDNRRule('https://evil.com');

      expect(count).toBe(30000);
      expect(mockUpdateDynamicRules).not.toHaveBeenCalled();
    });

    it('should return 0 when DNR not available', async () => {
      const originalDNR = chrome.declarativeNetRequest;
      (chrome as Record<string, unknown>).declarativeNetRequest = undefined;

      vi.resetModules();
      const freshModule = await import('../src/background/dnr');

      const count = await freshModule.addDNRRule('https://evil.com');

      expect(count).toBe(0);

      (chrome as Record<string, unknown>).declarativeNetRequest = originalDNR;
    });

    it('should return 0 on error', async () => {
      mockGetDynamicRules.mockRejectedValue(new Error('Failed'));

      const count = await dnrModule.addDNRRule('https://evil.com');

      expect(count).toBe(0);
    });

    it('should create redirect rule', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      await dnrModule.addDNRRule('https://evil.com');

      const call = mockUpdateDynamicRules.mock.calls[0][0];
      expect(call.addRules[0].action.type).toBe(RuleActionType.REDIRECT);
    });
  });

  // ===========================================================================
  // removeDNRRule
  // ===========================================================================

  describe('removeDNRRule', () => {
    it('should remove matching rule', async () => {
      mockGetDynamicRules.mockResolvedValue([
        { id: 1, condition: { urlFilter: '||evil.com^' } },
        { id: 2, condition: { urlFilter: '||other.com^' } },
      ]);

      const count = await dnrModule.removeDNRRule('https://evil.com');

      expect(count).toBe(1);
      expect(mockUpdateDynamicRules).toHaveBeenCalledWith({
        removeRuleIds: [1],
      });
    });

    it('should return same count when no matching rule found', async () => {
      mockGetDynamicRules.mockResolvedValue([
        { id: 1, condition: { urlFilter: '||other.com^' } },
      ]);

      const count = await dnrModule.removeDNRRule('https://evil.com');

      expect(count).toBe(1);
      expect(mockUpdateDynamicRules).not.toHaveBeenCalled();
    });

    it('should return 0 when DNR not available', async () => {
      const originalDNR = chrome.declarativeNetRequest;
      (chrome as Record<string, unknown>).declarativeNetRequest = undefined;

      vi.resetModules();
      const freshModule = await import('../src/background/dnr');

      const count = await freshModule.removeDNRRule('https://evil.com');

      expect(count).toBe(0);

      (chrome as Record<string, unknown>).declarativeNetRequest = originalDNR;
    });

    it('should return 0 on error', async () => {
      mockGetDynamicRules.mockRejectedValue(new Error('Failed'));

      const count = await dnrModule.removeDNRRule('https://evil.com');

      expect(count).toBe(0);
    });
  });

  // ===========================================================================
  // updateDNRFromPrioritizedIOCs
  // ===========================================================================

  describe('updateDNRFromPrioritizedIOCs', () => {
    it('should partition IOCs and update DNR', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      vi.mocked(priorityModule.partitionByPriority).mockReturnValue({
        sync: [
          { hash: 'h1', priority: 'sync', url: 'https://sync1.com' },
          { hash: 'h2', priority: 'sync', url: 'https://sync2.com' },
        ],
        async: [{ hash: 'h3', priority: 'async' }],
        stats: {
          totalCount: 3,
          syncCount: 2,
          asyncCount: 1,
          demotedCount: 0,
        },
      });

      const result = await dnrModule.updateDNRFromPrioritizedIOCs([], 1);

      expect(result.success).toBe(true);
      expect(result.syncRuleCount).toBe(2);
      expect(result.asyncCount).toBe(1);
    });

    it('should skip sync IOCs without URL', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      vi.mocked(priorityModule.partitionByPriority).mockReturnValue({
        sync: [
          { hash: 'h1', priority: 'sync', url: 'https://sync1.com' },
          { hash: 'h2', priority: 'sync' }, // No URL
          { hash: 'h3', priority: 'sync', url: undefined },
        ],
        async: [],
        stats: {
          totalCount: 3,
          syncCount: 3,
          asyncCount: 0,
          demotedCount: 0,
        },
      });

      const result = await dnrModule.updateDNRFromPrioritizedIOCs([], 1);

      expect(result.skippedNoUrl).toBe(2);
      expect(result.syncRuleCount).toBe(1);
    });

    it('should report demoted count', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      vi.mocked(priorityModule.partitionByPriority).mockReturnValue({
        sync: [],
        async: [],
        stats: {
          totalCount: 100,
          syncCount: 0,
          asyncCount: 100,
          demotedCount: 50,
        },
      });

      const result = await dnrModule.updateDNRFromPrioritizedIOCs([], 1);

      expect(result.demotedCount).toBe(50);
    });

    it('should return error when DNR not available', async () => {
      const originalDNR = chrome.declarativeNetRequest;
      (chrome as Record<string, unknown>).declarativeNetRequest = undefined;

      vi.resetModules();
      const freshModule = await import('../src/background/dnr');

      const result = await freshModule.updateDNRFromPrioritizedIOCs([], 1);

      expect(result.success).toBe(false);
      expect(result.error).toBe('DNR not available');

      (chrome as Record<string, unknown>).declarativeNetRequest = originalDNR;
    });

    it('should handle updateDNRRules failure', async () => {
      mockGetDynamicRules.mockResolvedValue([]);
      mockUpdateDynamicRules.mockRejectedValue(new Error('Update failed'));

      vi.mocked(priorityModule.partitionByPriority).mockReturnValue({
        sync: [{ hash: 'h1', priority: 'sync', url: 'https://sync1.com' }],
        async: [],
        stats: {
          totalCount: 1,
          syncCount: 1,
          asyncCount: 0,
          demotedCount: 0,
        },
      });

      const result = await dnrModule.updateDNRFromPrioritizedIOCs([], 1);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Update failed');
    });
  });

  // ===========================================================================
  // getDNRCapacity
  // ===========================================================================

  describe('getDNRCapacity', () => {
    it('should return correct capacity when empty', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      const capacity = await dnrModule.getDNRCapacity();

      expect(capacity).toEqual({
        used: 0,
        available: 30000,
        max: 30000,
        percentUsed: 0,
      });
    });

    it('should return correct capacity when partially used', async () => {
      mockGetDynamicRules.mockResolvedValue(
        Array.from({ length: 15000 }, (_, i) => ({ id: i + 1 }))
      );

      const capacity = await dnrModule.getDNRCapacity();

      expect(capacity).toEqual({
        used: 15000,
        available: 15000,
        max: 30000,
        percentUsed: 50,
      });
    });

    it('should return correct capacity when full', async () => {
      mockGetDynamicRules.mockResolvedValue(
        Array.from({ length: 30000 }, (_, i) => ({ id: i + 1 }))
      );

      const capacity = await dnrModule.getDNRCapacity();

      expect(capacity).toEqual({
        used: 30000,
        available: 0,
        max: 30000,
        percentUsed: 100,
      });
    });

    it('should round percentUsed', async () => {
      mockGetDynamicRules.mockResolvedValue(
        Array.from({ length: 10001 }, (_, i) => ({ id: i + 1 }))
      );

      const capacity = await dnrModule.getDNRCapacity();

      expect(capacity.percentUsed).toBe(33); // 10001/30000 * 100 = 33.33... -> 33
    });
  });

  // ===========================================================================
  // hasDNRCapacity
  // ===========================================================================

  describe('hasDNRCapacity', () => {
    it('should return true when there is enough capacity', async () => {
      mockGetDynamicRules.mockResolvedValue(
        Array.from({ length: 100 }, (_, i) => ({ id: i + 1 }))
      );

      const hasCapacity = await dnrModule.hasDNRCapacity(100);

      expect(hasCapacity).toBe(true);
    });

    it('should return false when not enough capacity', async () => {
      mockGetDynamicRules.mockResolvedValue(
        Array.from({ length: 29950 }, (_, i) => ({ id: i + 1 }))
      );

      const hasCapacity = await dnrModule.hasDNRCapacity(100);

      expect(hasCapacity).toBe(false);
    });

    it('should return true for exact remaining capacity', async () => {
      mockGetDynamicRules.mockResolvedValue(
        Array.from({ length: 29900 }, (_, i) => ({ id: i + 1 }))
      );

      const hasCapacity = await dnrModule.hasDNRCapacity(100);

      expect(hasCapacity).toBe(true);
    });

    it('should return true for empty rules and any count within limit', async () => {
      mockGetDynamicRules.mockResolvedValue([]);

      const hasCapacity = await dnrModule.hasDNRCapacity(30000);

      expect(hasCapacity).toBe(true);
    });

    it('should return false when already at limit', async () => {
      mockGetDynamicRules.mockResolvedValue(
        Array.from({ length: 30000 }, (_, i) => ({ id: i + 1 }))
      );

      const hasCapacity = await dnrModule.hasDNRCapacity(1);

      expect(hasCapacity).toBe(false);
    });
  });
});
