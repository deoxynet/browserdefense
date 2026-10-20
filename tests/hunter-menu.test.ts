import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock chrome API before importing module
const mockContextMenusCreate = vi.fn();
const mockContextMenusRemove = vi.fn();
const mockContextMenusOnClickedAddListener = vi.fn();
const mockTabsSendMessage = vi.fn();

vi.stubGlobal('chrome', {
  contextMenus: {
    create: mockContextMenusCreate,
    remove: mockContextMenusRemove,
    onClicked: {
      addListener: mockContextMenusOnClickedAddListener,
    },
  },
  tabs: {
    sendMessage: mockTabsSendMessage,
  },
});

// Mock dependencies
vi.mock('../src/background/auth', () => ({
  getAuthToken: vi.fn(),
}));

vi.mock('../src/config/loader', () => ({
  loadConfig: vi.fn(),
}));

vi.mock('../src/background/ioc-extractor', () => ({
  extractIOCs: vi.fn(),
}));

// Import after mocks are set up
import { getAuthToken } from '../src/background/auth';
import { loadConfig } from '../src/config/loader';
import { extractIOCs } from '../src/background/ioc-extractor';
import type { ExtractedIOC } from '../src/background/ioc-extractor';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestIOC(overrides: Partial<ExtractedIOC> = {}): ExtractedIOC {
  return {
    type: 'domain',
    value: 'malware.example.com',
    original: 'malware.example.com',
    defanged: false,
    ...overrides,
  };
}

function createTestConfig() {
  return {
    org_id: 'test-org',
    signing_public_key: {
      kty: 'OKP' as const,
      crv: 'Ed25519' as const,
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
    },
    encryption_public_key: {
      kty: 'RSA' as const,
      n: 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
      e: 'AQAB',
    },
    blocklist_endpoint: 'https://api.blockioc.com/v1/blocklist',
    forensics_endpoint: 'https://forensics.example.com/upload',
    ioc_salt: 'test-salt-for-testing',
  };
}

// =============================================================================
// Tests
// =============================================================================

describe('Hunter Menu', () => {
  let mockFetch: ReturnType<typeof vi.fn>;
  let hunterMenu: typeof import('../src/background/hunter-menu');

  beforeEach(async () => {
    vi.clearAllMocks();
    mockFetch = vi.fn();
    global.fetch = mockFetch as typeof fetch;

    // Reset module to clear menuCreated state
    vi.resetModules();

    // Re-import after reset
    hunterMenu = await import('../src/background/hunter-menu');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ===========================================================================
  // createHunterMenu
  // ===========================================================================

  describe('createHunterMenu', () => {
    it('should create context menu with correct options', async () => {
      mockContextMenusCreate.mockResolvedValueOnce(undefined);

      await hunterMenu.createHunterMenu();

      expect(mockContextMenusCreate).toHaveBeenCalledWith({
        id: 'blockioc-broadcast-iocs',
        title: 'Broadcast IOCs to Team',
        contexts: ['selection'],
      });
    });

    it('should not create menu if already created', async () => {
      mockContextMenusCreate.mockResolvedValue(undefined);

      await hunterMenu.createHunterMenu();
      await hunterMenu.createHunterMenu();

      expect(mockContextMenusCreate).toHaveBeenCalledTimes(1);
    });

    it('should handle duplicate id error gracefully', async () => {
      mockContextMenusCreate.mockRejectedValueOnce(new Error('duplicate id'));

      await expect(hunterMenu.createHunterMenu()).resolves.not.toThrow();
    });

    it('should log error for other create errors', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      mockContextMenusCreate.mockRejectedValueOnce(new Error('Some other error'));

      await hunterMenu.createHunterMenu();

      expect(consoleSpy).toHaveBeenCalledWith(
        '[BlockIOC] Failed to create context menu:',
        expect.any(Error)
      );
    });
  });

  // ===========================================================================
  // removeHunterMenu
  // ===========================================================================

  describe('removeHunterMenu', () => {
    it('should remove context menu when it exists', async () => {
      // First create the menu
      mockContextMenusCreate.mockResolvedValueOnce(undefined);
      await hunterMenu.createHunterMenu();

      // Then remove it
      mockContextMenusRemove.mockResolvedValueOnce(undefined);
      await hunterMenu.removeHunterMenu();

      expect(mockContextMenusRemove).toHaveBeenCalledWith('blockioc-broadcast-iocs');
    });

    it('should not call remove if menu not created', async () => {
      await hunterMenu.removeHunterMenu();

      expect(mockContextMenusRemove).not.toHaveBeenCalled();
    });

    it('should handle "Cannot find menu item" error gracefully', async () => {
      mockContextMenusCreate.mockResolvedValueOnce(undefined);
      await hunterMenu.createHunterMenu();

      mockContextMenusRemove.mockRejectedValueOnce(new Error('Cannot find menu item'));

      await expect(hunterMenu.removeHunterMenu()).resolves.not.toThrow();
    });

    it('should log error for other remove errors', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      mockContextMenusCreate.mockResolvedValueOnce(undefined);
      await hunterMenu.createHunterMenu();

      mockContextMenusRemove.mockRejectedValueOnce(new Error('Some other error'));

      await hunterMenu.removeHunterMenu();

      expect(consoleSpy).toHaveBeenCalledWith(
        '[BlockIOC] Failed to remove context menu:',
        expect.any(Error)
      );
    });
  });

  // ===========================================================================
  // updateHunterMenu
  // ===========================================================================

  describe('updateHunterMenu', () => {
    it('should create menu when mode is hunter', async () => {
      mockContextMenusCreate.mockResolvedValueOnce(undefined);

      await hunterMenu.updateHunterMenu({ mode: 'hunter', token: 'test-token', isValid: true });

      expect(mockContextMenusCreate).toHaveBeenCalled();
    });

    it('should remove menu when mode is sensor', async () => {
      // First create the menu
      mockContextMenusCreate.mockResolvedValueOnce(undefined);
      await hunterMenu.createHunterMenu();

      // Then update to sensor mode
      mockContextMenusRemove.mockResolvedValueOnce(undefined);
      await hunterMenu.updateHunterMenu({ mode: 'sensor', token: null, isValid: false });

      expect(mockContextMenusRemove).toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // broadcastIOCs
  // ===========================================================================

  describe('broadcastIOCs', () => {
    it('should return error when not authenticated', async () => {
      vi.mocked(getAuthToken).mockReturnValue(null);

      const iocs = [createTestIOC()];
      const result = await hunterMenu.broadcastIOCs(iocs);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Not authenticated');
      expect(result.iocs).toEqual(iocs);
    });

    it('should return error when no config found', async () => {
      vi.mocked(getAuthToken).mockReturnValue('test-token');
      vi.mocked(loadConfig).mockResolvedValue(null);

      const iocs = [createTestIOC()];
      const result = await hunterMenu.broadcastIOCs(iocs);

      expect(result.success).toBe(false);
      expect(result.error).toBe('No configuration found');
    });

    it('should broadcast IOCs to correct endpoint', async () => {
      vi.mocked(getAuthToken).mockReturnValue('test-token');
      vi.mocked(loadConfig).mockResolvedValue(createTestConfig());
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      const iocs = [
        createTestIOC({ type: 'domain', value: 'evil.com' }),
        createTestIOC({ type: 'ipv4', value: '192.168.1.1' }),
      ];
      const result = await hunterMenu.broadcastIOCs(iocs);

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.blockioc.com/api/v1/broadcast',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer test-token',
          },
        })
      );

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.iocs).toHaveLength(2);
      expect(body.source).toBe('hunter-extension');
      expect(body.timestamp).toBeDefined();
    });

    it('should return error on API failure', async () => {
      vi.mocked(getAuthToken).mockReturnValue('test-token');
      vi.mocked(loadConfig).mockResolvedValue(createTestConfig());
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        text: () => Promise.resolve('Forbidden'),
      });

      const iocs = [createTestIOC()];
      const result = await hunterMenu.broadcastIOCs(iocs);

      expect(result.success).toBe(false);
      expect(result.error).toContain('API error: 403');
    });

    it('should return error on network failure', async () => {
      vi.mocked(getAuthToken).mockReturnValue('test-token');
      vi.mocked(loadConfig).mockResolvedValue(createTestConfig());
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const iocs = [createTestIOC()];
      const result = await hunterMenu.broadcastIOCs(iocs);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Network error');
    });

    it('should include defanged flag in broadcast payload', async () => {
      vi.mocked(getAuthToken).mockReturnValue('test-token');
      vi.mocked(loadConfig).mockResolvedValue(createTestConfig());
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const iocs = [createTestIOC({ defanged: true })];
      await hunterMenu.broadcastIOCs(iocs);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.iocs[0].defanged).toBe(true);
    });
  });

  // ===========================================================================
  // setupMenuListener
  // ===========================================================================

  describe('setupMenuListener', () => {
    it('should add click listener to context menu', () => {
      hunterMenu.setupMenuListener();

      expect(mockContextMenusOnClickedAddListener).toHaveBeenCalledWith(expect.any(Function));
    });
  });

  // ===========================================================================
  // initHunterMenu
  // ===========================================================================

  describe('initHunterMenu', () => {
    it('should setup listener and create menu for hunter mode', async () => {
      mockContextMenusCreate.mockResolvedValueOnce(undefined);

      await hunterMenu.initHunterMenu({ mode: 'hunter', token: 'test-token', isValid: true });

      expect(mockContextMenusOnClickedAddListener).toHaveBeenCalled();
      expect(mockContextMenusCreate).toHaveBeenCalled();
    });

    it('should setup listener but not create menu for sensor mode', async () => {
      await hunterMenu.initHunterMenu({ mode: 'sensor', token: null, isValid: false });

      expect(mockContextMenusOnClickedAddListener).toHaveBeenCalled();
      expect(mockContextMenusCreate).not.toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // BroadcastResult type
  // ===========================================================================

  describe('BroadcastResult', () => {
    it('should have correct structure on success', async () => {
      vi.mocked(getAuthToken).mockReturnValue('test-token');
      vi.mocked(loadConfig).mockResolvedValue(createTestConfig());
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

      const iocs = [createTestIOC()];
      const result = await hunterMenu.broadcastIOCs(iocs);

      expect(result).toHaveProperty('success', true);
      expect(result).toHaveProperty('iocs');
      expect(result.error).toBeUndefined();
    });

    it('should have correct structure on failure', async () => {
      vi.mocked(getAuthToken).mockReturnValue(null);

      const iocs = [createTestIOC()];
      const result = await hunterMenu.broadcastIOCs(iocs);

      expect(result).toHaveProperty('success', false);
      expect(result).toHaveProperty('iocs');
      expect(result).toHaveProperty('error');
    });
  });
});
