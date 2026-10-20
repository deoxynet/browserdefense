import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// =============================================================================
// Chrome API Mocks
// =============================================================================

const mockPermissionsContains = vi.fn();
const mockWebRequestOnBeforeRequestAddListener = vi.fn();

vi.stubGlobal('chrome', {
  permissions: {
    contains: mockPermissionsContains,
  },
  webRequest: {
    onBeforeRequest: {
      addListener: mockWebRequestOnBeforeRequestAddListener,
    },
  },
});

// =============================================================================
// Module Mocks
// =============================================================================

// Mock BinaryHashSet
const mockBinaryHashSetHas = vi.fn();
vi.mock('../src/storage/binary-set', () => ({
  BinaryHashSet: vi.fn().mockImplementation(() => ({
    has: mockBinaryHashSetHas,
  })),
}));

// Mock canonicalize
const mockCanonicalizeAndHash = vi.fn();
vi.mock('../src/crypto/canonicalize', () => ({
  canonicalizeAndHash: mockCanonicalizeAndHash,
}));

// Mock forensics
const mockQueueForensics = vi.fn();
const mockTrackRedirect = vi.fn();
const mockGetRedirectChain = vi.fn();
vi.mock('../src/background/forensics', () => ({
  queueForensics: mockQueueForensics,
  trackRedirect: mockTrackRedirect,
  getRedirectChain: mockGetRedirectChain,
}));

// Mock blocking
const mockGetBlockPageUrl = vi.fn();
vi.mock('../src/background/blocking', () => ({
  getBlockPageUrl: mockGetBlockPageUrl,
}));

// =============================================================================
// Test Helpers
// =============================================================================

function createMockBinaryHashSet() {
  return {
    has: mockBinaryHashSetHas,
    size: 100,
    add: vi.fn(),
    delete: vi.fn(),
    clear: vi.fn(),
  };
}

function createWebRequestDetails(
  url: string,
  tabId = 1,
  type: chrome.webRequest.ResourceType = 'main_frame'
): chrome.webRequest.WebRequestBodyDetails {
  return {
    url,
    tabId,
    frameId: 0,
    parentFrameId: -1,
    requestId: '123',
    method: 'GET',
    timeStamp: Date.now(),
    type,
    initiator: 'https://google.com',
    requestBody: null,
  };
}

// =============================================================================
// Tests
// =============================================================================

describe('Enterprise Blocking Module', () => {
  let enterpriseModule: typeof import('../src/background/enterprise-blocking');

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();

    // Default mock returns
    mockPermissionsContains.mockResolvedValue(false);
    mockCanonicalizeAndHash.mockResolvedValue('mockhash123');
    mockBinaryHashSetHas.mockReturnValue(false);
    mockQueueForensics.mockResolvedValue(undefined);
    mockTrackRedirect.mockReturnValue(undefined);
    mockGetRedirectChain.mockReturnValue(['https://redirect1.com', 'https://redirect2.com']);
    mockGetBlockPageUrl.mockReturnValue('chrome-extension://test/blocked.html');

    // Re-import module
    enterpriseModule = await import('../src/background/enterprise-blocking');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ===========================================================================
  // checkEnterpriseMode
  // ===========================================================================

  describe('checkEnterpriseMode', () => {
    it('should return true when webRequestBlocking permission is available', async () => {
      mockPermissionsContains.mockResolvedValue(true);

      const result = await enterpriseModule.checkEnterpriseMode();

      expect(result).toBe(true);
    });

    it('should check for webRequestBlocking permission', async () => {
      await enterpriseModule.checkEnterpriseMode();

      expect(mockPermissionsContains).toHaveBeenCalledWith({
        permissions: ['webRequestBlocking'],
      });
    });

    it('should return false when permission is not available', async () => {
      mockPermissionsContains.mockResolvedValue(false);

      const result = await enterpriseModule.checkEnterpriseMode();

      expect(result).toBe(false);
    });

    it('should return false on permission check error', async () => {
      mockPermissionsContains.mockRejectedValue(new Error('Permission check failed'));

      const result = await enterpriseModule.checkEnterpriseMode();

      expect(result).toBe(false);
    });

    it('should update internal enterprise mode state to true when available', async () => {
      mockPermissionsContains.mockResolvedValue(true);

      await enterpriseModule.checkEnterpriseMode();

      expect(enterpriseModule.getEnterpriseMode()).toBe(true);
    });

    it('should update internal enterprise mode state to false when not available', async () => {
      mockPermissionsContains.mockResolvedValue(false);

      await enterpriseModule.checkEnterpriseMode();

      expect(enterpriseModule.getEnterpriseMode()).toBe(false);
    });

    it('should return false when webRequest API is undefined', async () => {
      mockPermissionsContains.mockResolvedValue(true);
      const originalWebRequest = chrome.webRequest;
      (chrome as Record<string, unknown>).webRequest = undefined;

      vi.resetModules();
      const freshModule = await import('../src/background/enterprise-blocking');
      const result = await freshModule.checkEnterpriseMode();

      expect(result).toBe(false);

      (chrome as Record<string, unknown>).webRequest = originalWebRequest;
    });
  });

  // ===========================================================================
  // getEnterpriseMode
  // ===========================================================================

  describe('getEnterpriseMode', () => {
    it('should return false by default', () => {
      expect(enterpriseModule.getEnterpriseMode()).toBe(false);
    });

    it('should return true after successful checkEnterpriseMode', async () => {
      mockPermissionsContains.mockResolvedValue(true);

      await enterpriseModule.checkEnterpriseMode();

      expect(enterpriseModule.getEnterpriseMode()).toBe(true);
    });

    it('should return false after failed checkEnterpriseMode', async () => {
      mockPermissionsContains.mockResolvedValue(false);

      await enterpriseModule.checkEnterpriseMode();

      expect(enterpriseModule.getEnterpriseMode()).toBe(false);
    });
  });

  // ===========================================================================
  // initEnterpriseBlocking
  // ===========================================================================

  describe('initEnterpriseBlocking', () => {
    it('should initialize with blocklist and config', () => {
      const mockBlocklist = createMockBinaryHashSet();

      // Should not throw
      expect(() => {
        enterpriseModule.initEnterpriseBlocking(
          mockBlocklist as unknown as import('../src/storage/binary-set').BinaryHashSet,
          'test-salt',
          'HOST_ONLY'
        );
      }).not.toThrow();
    });

    it('should accept different canonicalization scopes', () => {
      const mockBlocklist = createMockBinaryHashSet();

      expect(() => {
        enterpriseModule.initEnterpriseBlocking(
          mockBlocklist as unknown as import('../src/storage/binary-set').BinaryHashSet,
          'test-salt',
          'HOST_PATH'
        );
      }).not.toThrow();
    });
  });

  // ===========================================================================
  // updateEnterpriseConfig
  // ===========================================================================

  describe('updateEnterpriseConfig', () => {
    it('should update blocklist and config', () => {
      const mockBlocklist = createMockBinaryHashSet();

      // Should not throw
      expect(() => {
        enterpriseModule.updateEnterpriseConfig(
          mockBlocklist as unknown as import('../src/storage/binary-set').BinaryHashSet,
          'new-salt',
          'HOST_ONLY'
        );
      }).not.toThrow();
    });

    it('should allow updating scope', () => {
      const mockBlocklist = createMockBinaryHashSet();

      expect(() => {
        enterpriseModule.updateEnterpriseConfig(
          mockBlocklist as unknown as import('../src/storage/binary-set').BinaryHashSet,
          'test-salt',
          'HOST_PATH'
        );
      }).not.toThrow();
    });
  });

  // ===========================================================================
  // setupEnterpriseBlocking
  // ===========================================================================

  describe('setupEnterpriseBlocking', () => {
    it('should not register listener when not in enterprise mode', () => {
      enterpriseModule.setupEnterpriseBlocking();

      expect(mockWebRequestOnBeforeRequestAddListener).not.toHaveBeenCalled();
    });

    it('should register listener when in enterprise mode', async () => {
      mockPermissionsContains.mockResolvedValue(true);
      await enterpriseModule.checkEnterpriseMode();

      enterpriseModule.setupEnterpriseBlocking();

      expect(mockWebRequestOnBeforeRequestAddListener).toHaveBeenCalled();
    });

    it('should register listener with correct URL patterns', async () => {
      mockPermissionsContains.mockResolvedValue(true);
      await enterpriseModule.checkEnterpriseMode();

      enterpriseModule.setupEnterpriseBlocking();

      const call = mockWebRequestOnBeforeRequestAddListener.mock.calls[0];
      expect(call[1]).toEqual({
        urls: ['http://*/*', 'https://*/*'],
        types: ['main_frame'],
      });
    });

    it('should register listener with blocking extraInfoSpec', async () => {
      mockPermissionsContains.mockResolvedValue(true);
      await enterpriseModule.checkEnterpriseMode();

      enterpriseModule.setupEnterpriseBlocking();

      const call = mockWebRequestOnBeforeRequestAddListener.mock.calls[0];
      expect(call[2]).toEqual(['blocking']);
    });

    it('should provide callback function to listener', async () => {
      mockPermissionsContains.mockResolvedValue(true);
      await enterpriseModule.checkEnterpriseMode();

      enterpriseModule.setupEnterpriseBlocking();

      const callback = mockWebRequestOnBeforeRequestAddListener.mock.calls[0][0];
      expect(typeof callback).toBe('function');
    });
  });

  // ===========================================================================
  // Blocking Callback Behavior
  // ===========================================================================

  describe('Blocking callback behavior', () => {
    let blockingCallback: (
      details: chrome.webRequest.WebRequestBodyDetails
    ) => chrome.webRequest.BlockingResponse | Promise<chrome.webRequest.BlockingResponse> | void;

    beforeEach(async () => {
      mockPermissionsContains.mockResolvedValue(true);
      await enterpriseModule.checkEnterpriseMode();

      // Initialize with blocklist
      const mockBlocklist = createMockBinaryHashSet();
      enterpriseModule.initEnterpriseBlocking(
        mockBlocklist as unknown as import('../src/storage/binary-set').BinaryHashSet,
        'test-salt',
        'HOST_ONLY'
      );

      enterpriseModule.setupEnterpriseBlocking();
      blockingCallback = mockWebRequestOnBeforeRequestAddListener.mock.calls[0][0];
    });

    it('should ignore non-main_frame requests', () => {
      const details = createWebRequestDetails('https://evil.com', 1, 'sub_frame');

      const result = blockingCallback(details);

      expect(result).toBeUndefined();
    });

    it('should ignore chrome:// URLs', () => {
      const details = createWebRequestDetails('chrome://settings', 1, 'main_frame');

      const result = blockingCallback(details);

      expect(result).toBeUndefined();
    });

    it('should ignore chrome-extension:// URLs', () => {
      const details = createWebRequestDetails('chrome-extension://abc/popup.html', 1, 'main_frame');

      const result = blockingCallback(details);

      expect(result).toBeUndefined();
    });

    it('should track redirect for valid main_frame requests', () => {
      const details = createWebRequestDetails('https://example.com', 5, 'main_frame');

      blockingCallback(details);

      expect(mockTrackRedirect).toHaveBeenCalledWith(5, 'https://example.com');
    });

    it('should not track redirect for negative tabId', () => {
      const details = createWebRequestDetails('https://example.com', -1, 'main_frame');

      blockingCallback(details);

      expect(mockTrackRedirect).not.toHaveBeenCalled();
    });

    it('should return Promise for blocking check', () => {
      const details = createWebRequestDetails('https://example.com', 1, 'main_frame');

      const result = blockingCallback(details);

      expect(result).toBeInstanceOf(Promise);
    });

    it('should allow non-blocked URLs', async () => {
      mockBinaryHashSetHas.mockReturnValue(false);
      const details = createWebRequestDetails('https://safe.com', 1, 'main_frame');

      const result = await blockingCallback(details);

      expect(result).toEqual({});
    });

    it('should redirect blocked URLs', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      mockGetBlockPageUrl.mockReturnValue('chrome-extension://test/blocked.html?url=evil.com');
      const details = createWebRequestDetails('https://evil.com', 1, 'main_frame');

      const result = await blockingCallback(details);

      expect(result).toEqual({
        redirectUrl: 'chrome-extension://test/blocked.html?url=evil.com',
      });
    });

    it('should call getBlockPageUrl with correct parameters for blocked URL', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      const details = createWebRequestDetails('https://evil.com', 1, 'main_frame');

      await blockingCallback(details);

      expect(mockGetBlockPageUrl).toHaveBeenCalledWith('https://evil.com', 'ioc_match');
    });

    it('should not redirect blocked URL with negative tabId', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      const details = createWebRequestDetails('https://evil.com', -1, 'main_frame');

      const result = await blockingCallback(details);

      expect(result).toEqual({});
    });
  });

  // ===========================================================================
  // Forensics Capture
  // ===========================================================================

  describe('Forensics capture', () => {
    let blockingCallback: (
      details: chrome.webRequest.WebRequestBodyDetails
    ) => chrome.webRequest.BlockingResponse | Promise<chrome.webRequest.BlockingResponse> | void;

    beforeEach(async () => {
      mockPermissionsContains.mockResolvedValue(true);
      await enterpriseModule.checkEnterpriseMode();

      const mockBlocklist = createMockBinaryHashSet();
      enterpriseModule.initEnterpriseBlocking(
        mockBlocklist as unknown as import('../src/storage/binary-set').BinaryHashSet,
        'test-salt',
        'HOST_ONLY'
      );

      enterpriseModule.setupEnterpriseBlocking();
      blockingCallback = mockWebRequestOnBeforeRequestAddListener.mock.calls[0][0];
    });

    it('should queue forensics for blocked requests', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      const details = createWebRequestDetails('https://evil.com', 1, 'main_frame');

      await blockingCallback(details);

      // Wait for fire-and-forget async call
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(mockQueueForensics).toHaveBeenCalled();
    });

    it('should include blocked URL in forensics payload', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      const details = createWebRequestDetails('https://evil.com', 1, 'main_frame');

      await blockingCallback(details);
      await new Promise((resolve) => setTimeout(resolve, 0));

      const payload = mockQueueForensics.mock.calls[0][0];
      expect(payload.blockedUrl).toBe('https://evil.com');
    });

    it('should include redirect chain in forensics payload', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      mockGetRedirectChain.mockReturnValue(['https://step1.com', 'https://step2.com']);
      const details = createWebRequestDetails('https://evil.com', 1, 'main_frame');

      await blockingCallback(details);
      await new Promise((resolve) => setTimeout(resolve, 0));

      const payload = mockQueueForensics.mock.calls[0][0];
      expect(payload.redirectChain).toEqual(['https://step1.com', 'https://step2.com']);
    });

    it('should include tabId and frameId in forensics payload', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      const details = createWebRequestDetails('https://evil.com', 42, 'main_frame');
      details.frameId = 7;

      await blockingCallback(details);
      await new Promise((resolve) => setTimeout(resolve, 0));

      const payload = mockQueueForensics.mock.calls[0][0];
      expect(payload.tabId).toBe(42);
      expect(payload.frameId).toBe(7);
    });

    it('should include reason in forensics payload', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      const details = createWebRequestDetails('https://evil.com', 1, 'main_frame');

      await blockingCallback(details);
      await new Promise((resolve) => setTimeout(resolve, 0));

      const payload = mockQueueForensics.mock.calls[0][0];
      expect(payload.reason).toBe('ioc_match');
    });

    it('should include initiator in forensics payload', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      const details = createWebRequestDetails('https://evil.com', 1, 'main_frame');
      details.initiator = 'https://search.example.com';

      await blockingCallback(details);
      await new Promise((resolve) => setTimeout(resolve, 0));

      const payload = mockQueueForensics.mock.calls[0][0];
      expect(payload.initiator).toBe('https://search.example.com');
    });

    it('should include timestamp in forensics payload', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      const details = createWebRequestDetails('https://evil.com', 1, 'main_frame');

      const beforeTime = new Date().toISOString();
      await blockingCallback(details);
      await new Promise((resolve) => setTimeout(resolve, 0));
      const afterTime = new Date().toISOString();

      const payload = mockQueueForensics.mock.calls[0][0];
      expect(payload.timestamp).toBeDefined();
      expect(payload.timestamp >= beforeTime).toBe(true);
      expect(payload.timestamp <= afterTime).toBe(true);
    });

    it('should not queue forensics for allowed requests', async () => {
      mockBinaryHashSetHas.mockReturnValue(false);
      const details = createWebRequestDetails('https://safe.com', 1, 'main_frame');

      await blockingCallback(details);
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(mockQueueForensics).not.toHaveBeenCalled();
    });

    it('should get redirect chain for correct tabId', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      const details = createWebRequestDetails('https://evil.com', 99, 'main_frame');

      await blockingCallback(details);
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(mockGetRedirectChain).toHaveBeenCalledWith(99);
    });

    it('should handle forensics queue failure gracefully', async () => {
      mockBinaryHashSetHas.mockReturnValue(true);
      mockQueueForensics.mockRejectedValue(new Error('Queue failed'));
      const details = createWebRequestDetails('https://evil.com', 1, 'main_frame');

      // Should not throw
      await expect(blockingCallback(details)).resolves.toEqual({
        redirectUrl: expect.any(String),
      });
    });
  });

  // ===========================================================================
  // Hash Lookup
  // ===========================================================================

  describe('Hash lookup', () => {
    let blockingCallback: (
      details: chrome.webRequest.WebRequestBodyDetails
    ) => chrome.webRequest.BlockingResponse | Promise<chrome.webRequest.BlockingResponse> | void;

    beforeEach(async () => {
      mockPermissionsContains.mockResolvedValue(true);
      await enterpriseModule.checkEnterpriseMode();

      const mockBlocklist = createMockBinaryHashSet();
      enterpriseModule.initEnterpriseBlocking(
        mockBlocklist as unknown as import('../src/storage/binary-set').BinaryHashSet,
        'test-salt',
        'HOST_ONLY'
      );

      enterpriseModule.setupEnterpriseBlocking();
      blockingCallback = mockWebRequestOnBeforeRequestAddListener.mock.calls[0][0];
    });

    it('should call canonicalizeAndHash with URL', async () => {
      const details = createWebRequestDetails('https://example.com/path', 1, 'main_frame');

      await blockingCallback(details);

      expect(mockCanonicalizeAndHash).toHaveBeenCalledWith(
        'https://example.com/path',
        'test-salt',
        expect.objectContaining({
          scope: 'HOST_ONLY',
          includeScheme: true,
        })
      );
    });

    it('should check hash against blocklist', async () => {
      mockCanonicalizeAndHash.mockResolvedValue('computed-hash');
      const details = createWebRequestDetails('https://example.com', 1, 'main_frame');

      await blockingCallback(details);

      expect(mockBinaryHashSetHas).toHaveBeenCalledWith('computed-hash');
    });

    it('should handle canonicalization error gracefully', async () => {
      mockCanonicalizeAndHash.mockRejectedValue(new Error('Hash failed'));
      const details = createWebRequestDetails('https://example.com', 1, 'main_frame');

      const result = await blockingCallback(details);

      // Should allow request on error
      expect(result).toEqual({});
    });

    it('should use scope from initialization', async () => {
      // Clear mocks before this specific test
      vi.clearAllMocks();
      vi.resetModules();

      // Re-initialize with different scope
      const mockBlocklist = createMockBinaryHashSet();
      const freshModule = await import('../src/background/enterprise-blocking');

      mockPermissionsContains.mockResolvedValue(true);
      await freshModule.checkEnterpriseMode();

      freshModule.initEnterpriseBlocking(
        mockBlocklist as unknown as import('../src/storage/binary-set').BinaryHashSet,
        'new-salt',
        'HOST_PATH'
      );

      freshModule.setupEnterpriseBlocking();
      const callback = mockWebRequestOnBeforeRequestAddListener.mock.calls[0][0];

      const details = createWebRequestDetails('https://example.com/path', 1, 'main_frame');
      await callback(details);

      expect(mockCanonicalizeAndHash).toHaveBeenCalledWith(
        'https://example.com/path',
        'new-salt',
        expect.objectContaining({
          scope: 'HOST_PATH',
        })
      );
    });
  });

  // ===========================================================================
  // Edge Cases
  // ===========================================================================

  describe('Edge cases', () => {
    it('should handle empty blocklist', async () => {
      mockPermissionsContains.mockResolvedValue(true);
      await enterpriseModule.checkEnterpriseMode();

      // Don't initialize blocklist
      enterpriseModule.setupEnterpriseBlocking();
      const callback = mockWebRequestOnBeforeRequestAddListener.mock.calls[0][0];

      const details = createWebRequestDetails('https://evil.com', 1, 'main_frame');
      const result = await callback(details);

      // Should allow when blocklist not initialized
      expect(result).toEqual({});
    });

    it('should handle various resource types correctly', async () => {
      mockPermissionsContains.mockResolvedValue(true);
      await enterpriseModule.checkEnterpriseMode();

      const mockBlocklist = createMockBinaryHashSet();
      enterpriseModule.initEnterpriseBlocking(
        mockBlocklist as unknown as import('../src/storage/binary-set').BinaryHashSet,
        'test-salt',
        'HOST_ONLY'
      );

      enterpriseModule.setupEnterpriseBlocking();
      const callback = mockWebRequestOnBeforeRequestAddListener.mock.calls[0][0];

      const resourceTypes: chrome.webRequest.ResourceType[] = [
        'sub_frame',
        'stylesheet',
        'script',
        'image',
        'font',
        'object',
        'xmlhttprequest',
        'ping',
        'csp_report',
        'media',
        'websocket',
        'other',
      ];

      for (const type of resourceTypes) {
        const details = createWebRequestDetails('https://evil.com', 1, type);
        const result = callback(details);
        expect(result).toBeUndefined();
      }
    });

    it('should handle tab ID 0 (prerender)', async () => {
      mockPermissionsContains.mockResolvedValue(true);
      await enterpriseModule.checkEnterpriseMode();

      const mockBlocklist = createMockBinaryHashSet();
      enterpriseModule.initEnterpriseBlocking(
        mockBlocklist as unknown as import('../src/storage/binary-set').BinaryHashSet,
        'test-salt',
        'HOST_ONLY'
      );

      enterpriseModule.setupEnterpriseBlocking();
      const callback = mockWebRequestOnBeforeRequestAddListener.mock.calls[0][0];

      mockBinaryHashSetHas.mockReturnValue(true);
      const details = createWebRequestDetails('https://evil.com', 0, 'main_frame');
      const result = await callback(details);

      // Tab ID 0 is valid (prerender), should still block
      expect(result).toEqual({
        redirectUrl: expect.any(String),
      });
    });
  });
});
