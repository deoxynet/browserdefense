import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock chrome API before importing module
const mockStorageLocalGet = vi.fn();
const mockStorageLocalSet = vi.fn();
const mockStorageOnChangedAddListener = vi.fn();

vi.stubGlobal('chrome', {
  storage: {
    local: {
      get: mockStorageLocalGet,
      set: mockStorageLocalSet,
    },
    onChanged: {
      addListener: mockStorageOnChangedAddListener,
    },
  },
});

// =============================================================================
// Test Fixtures
// =============================================================================

// Valid JWT token (three dot-separated non-empty parts)
const VALID_JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test-signature';

// Valid API key (32+ chars, alphanumeric + dashes/underscores)
const VALID_API_KEY = 'test_key_abcdef1234567890abcdef1234567890';

// Invalid tokens
const INVALID_TOKENS = {
  empty: '',
  whitespaceOnly: '   ',
  tooShort: 'abc123',
  invalidChars: 'token-with-invalid@chars!',
  malformedJwt: 'not.a.valid.jwt.token',
  partialJwt: 'header.payload',
  jwtWithEmptyPart: 'header..signature',
};

// =============================================================================
// Tests
// =============================================================================

describe('Auth Module', () => {
  let authModule: typeof import('../src/background/auth');

  beforeEach(async () => {
    vi.clearAllMocks();

    // Reset module to clear internal state
    vi.resetModules();

    // Re-import after reset
    authModule = await import('../src/background/auth');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ===========================================================================
  // getAuthState
  // ===========================================================================

  describe('getAuthState', () => {
    it('should return sensor mode when no token stored', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('sensor');
      expect(state.token).toBeNull();
      expect(state.isValid).toBe(false);
    });

    it('should return sensor mode when token is null', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: null });

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('sensor');
      expect(state.token).toBeNull();
      expect(state.isValid).toBe(false);
    });

    it('should return hunter mode with valid JWT token', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: VALID_JWT_TOKEN });

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('hunter');
      expect(state.token).toBe(VALID_JWT_TOKEN);
      expect(state.isValid).toBe(true);
    });

    it('should return hunter mode with valid API key', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: VALID_API_KEY });

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('hunter');
      expect(state.token).toBe(VALID_API_KEY);
      expect(state.isValid).toBe(true);
    });

    it('should return sensor mode with empty token', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: INVALID_TOKENS.empty });

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('sensor');
      expect(state.isValid).toBe(false);
    });

    it('should return sensor mode with whitespace-only token', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: INVALID_TOKENS.whitespaceOnly });

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('sensor');
      expect(state.isValid).toBe(false);
    });

    it('should return sensor mode with too short token', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: INVALID_TOKENS.tooShort });

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('sensor');
      expect(state.isValid).toBe(false);
    });

    it('should return sensor mode with invalid characters in token', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: INVALID_TOKENS.invalidChars });

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('sensor');
      expect(state.isValid).toBe(false);
    });

    it('should return sensor mode with malformed JWT', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: INVALID_TOKENS.malformedJwt });

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('sensor');
      expect(state.isValid).toBe(false);
    });

    it('should return sensor mode with partial JWT (missing part)', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: INVALID_TOKENS.partialJwt });

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('sensor');
      expect(state.isValid).toBe(false);
    });

    it('should return sensor mode with JWT containing empty part', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: INVALID_TOKENS.jwtWithEmptyPart });

      const state = await authModule.getAuthState();

      expect(state.mode).toBe('sensor');
      expect(state.isValid).toBe(false);
    });
  });

  // ===========================================================================
  // onAuthStateChange
  // ===========================================================================

  describe('onAuthStateChange', () => {
    it('should register listener', () => {
      const listener = vi.fn();

      const unsubscribe = authModule.onAuthStateChange(listener);

      expect(typeof unsubscribe).toBe('function');
    });

    it('should return working unsubscribe function', () => {
      const listener = vi.fn();

      const unsubscribe = authModule.onAuthStateChange(listener);
      unsubscribe();

      // No way to directly verify unsubscription without triggering storage change
      // but this ensures the function doesn't throw
      expect(unsubscribe).not.toThrow;
    });

    it('should allow multiple listeners', () => {
      const listener1 = vi.fn();
      const listener2 = vi.fn();

      const unsub1 = authModule.onAuthStateChange(listener1);
      const unsub2 = authModule.onAuthStateChange(listener2);

      expect(typeof unsub1).toBe('function');
      expect(typeof unsub2).toBe('function');
    });
  });

  // ===========================================================================
  // initAuthMonitoring
  // ===========================================================================

  describe('initAuthMonitoring', () => {
    it('should get initial auth state', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      authModule.initAuthMonitoring();

      // Wait for async getAuthState to complete
      await new Promise((resolve) => setTimeout(resolve, 10));

      expect(mockStorageLocalGet).toHaveBeenCalledWith('auth_token');
      expect(consoleSpy).toHaveBeenCalledWith('[BlockIOC] Initial mode: sensor');
    });

    it('should register storage change listener', () => {
      mockStorageLocalGet.mockResolvedValueOnce({});

      authModule.initAuthMonitoring();

      expect(mockStorageOnChangedAddListener).toHaveBeenCalledWith(expect.any(Function));
    });

    it('should notify listeners when token changes', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});
      const listener = vi.fn();
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      authModule.onAuthStateChange(listener);
      authModule.initAuthMonitoring();

      // Get the storage change handler
      const storageHandler = mockStorageOnChangedAddListener.mock.calls[0][0];

      // Simulate token change
      storageHandler(
        { auth_token: { newValue: VALID_JWT_TOKEN, oldValue: undefined } },
        'local'
      );

      expect(listener).toHaveBeenCalledWith({
        mode: 'hunter',
        token: VALID_JWT_TOKEN,
        isValid: true,
      });
      expect(consoleSpy).toHaveBeenCalledWith('[BlockIOC] Mode changed to: hunter');
    });

    it('should not notify on non-auth_token storage changes', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});
      const listener = vi.fn();

      authModule.onAuthStateChange(listener);
      authModule.initAuthMonitoring();

      const storageHandler = mockStorageOnChangedAddListener.mock.calls[0][0];

      // Simulate non-auth change
      storageHandler(
        { other_key: { newValue: 'something', oldValue: undefined } },
        'local'
      );

      expect(listener).not.toHaveBeenCalled();
    });

    it('should not notify on sync storage changes', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});
      const listener = vi.fn();

      authModule.onAuthStateChange(listener);
      authModule.initAuthMonitoring();

      const storageHandler = mockStorageOnChangedAddListener.mock.calls[0][0];

      // Simulate sync area change
      storageHandler(
        { auth_token: { newValue: VALID_JWT_TOKEN, oldValue: undefined } },
        'sync'
      );

      expect(listener).not.toHaveBeenCalled();
    });

    it('should handle listener errors gracefully', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});
      const errorListener = vi.fn().mockImplementation(() => {
        throw new Error('Listener error');
      });
      const normalListener = vi.fn();
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      authModule.onAuthStateChange(errorListener);
      authModule.onAuthStateChange(normalListener);
      authModule.initAuthMonitoring();

      const storageHandler = mockStorageOnChangedAddListener.mock.calls[0][0];
      storageHandler(
        { auth_token: { newValue: VALID_JWT_TOKEN, oldValue: undefined } },
        'local'
      );

      expect(consoleSpy).toHaveBeenCalledWith(
        '[BlockIOC] Auth listener error:',
        expect.any(Error)
      );
      // Normal listener should still be called
      expect(normalListener).toHaveBeenCalled();
    });

    it('should detect mode change from sensor to hunter', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      authModule.initAuthMonitoring();

      await new Promise((resolve) => setTimeout(resolve, 10));

      const storageHandler = mockStorageOnChangedAddListener.mock.calls[0][0];
      storageHandler(
        { auth_token: { newValue: VALID_JWT_TOKEN, oldValue: undefined } },
        'local'
      );

      expect(consoleSpy).toHaveBeenCalledWith('[BlockIOC] Mode changed to: hunter');
    });

    it('should detect mode change from hunter to sensor', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: VALID_JWT_TOKEN });
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      authModule.initAuthMonitoring();

      await new Promise((resolve) => setTimeout(resolve, 10));

      const storageHandler = mockStorageOnChangedAddListener.mock.calls[0][0];
      storageHandler(
        { auth_token: { newValue: null, oldValue: VALID_JWT_TOKEN } },
        'local'
      );

      expect(consoleSpy).toHaveBeenCalledWith('[BlockIOC] Mode changed to: sensor');
    });

    it('should not log mode change when mode stays same', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: VALID_JWT_TOKEN });
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      authModule.initAuthMonitoring();

      await new Promise((resolve) => setTimeout(resolve, 10));
      consoleSpy.mockClear();

      const storageHandler = mockStorageOnChangedAddListener.mock.calls[0][0];
      // Change to another valid token (still hunter mode)
      storageHandler(
        { auth_token: { newValue: VALID_API_KEY, oldValue: VALID_JWT_TOKEN } },
        'local'
      );

      expect(consoleSpy).not.toHaveBeenCalledWith(expect.stringContaining('Mode changed'));
    });
  });

  // ===========================================================================
  // isHunterMode
  // ===========================================================================

  describe('isHunterMode', () => {
    it('should return false by default (before getAuthState)', () => {
      expect(authModule.isHunterMode()).toBe(false);
    });

    it('should return false after loading sensor mode', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});

      await authModule.getAuthState();

      expect(authModule.isHunterMode()).toBe(false);
    });

    it('should return true after loading hunter mode', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: VALID_JWT_TOKEN });

      await authModule.getAuthState();

      expect(authModule.isHunterMode()).toBe(true);
    });
  });

  // ===========================================================================
  // getAuthToken
  // ===========================================================================

  describe('getAuthToken', () => {
    it('should return null by default', () => {
      expect(authModule.getAuthToken()).toBeNull();
    });

    it('should return null after loading with no token', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});

      await authModule.getAuthState();

      expect(authModule.getAuthToken()).toBeNull();
    });

    it('should return token after loading valid token', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: VALID_JWT_TOKEN });

      await authModule.getAuthState();

      expect(authModule.getAuthToken()).toBe(VALID_JWT_TOKEN);
    });

    it('should return updated token after storage change', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});

      authModule.initAuthMonitoring();

      await new Promise((resolve) => setTimeout(resolve, 10));

      const storageHandler = mockStorageOnChangedAddListener.mock.calls[0][0];
      storageHandler(
        { auth_token: { newValue: VALID_API_KEY, oldValue: null } },
        'local'
      );

      expect(authModule.getAuthToken()).toBe(VALID_API_KEY);
    });
  });

  // ===========================================================================
  // Token Validation (tested via getAuthState)
  // ===========================================================================

  describe('Token Validation', () => {
    describe('JWT tokens', () => {
      it('should accept standard JWT format', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: VALID_JWT_TOKEN });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(true);
      });

      it('should accept minimal valid JWT (three non-empty parts)', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: 'a.b.c' });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(true);
      });

      it('should reject JWT with empty header', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: '.payload.signature' });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(false);
      });

      it('should reject JWT with empty payload', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: 'header..signature' });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(false);
      });

      it('should reject JWT with empty signature', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: 'header.payload.' });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(false);
      });

      it('should reject JWT with too many parts', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: 'a.b.c.d.e' });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(false);
      });
    });

    describe('API key tokens', () => {
      it('should accept 32-char alphanumeric API key', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: 'abcdefghijklmnopqrstuvwxyz123456' });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(true);
      });

      it('should accept API key with underscores', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: 'test_key_abcdef1234567890abcdef12' });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(true);
      });

      it('should accept API key with dashes', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: 'api-key-abcdef1234567890abcdef12' });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(true);
      });

      it('should reject API key shorter than 32 chars', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: 'short-key-123' });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(false);
      });

      it('should reject API key with special characters', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: 'api@key#with$special%chars!!!!!' });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(false);
      });
    });

    describe('edge cases', () => {
      it('should reject non-string token (number)', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: 12345 });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(false);
      });

      it('should reject non-string token (object)', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: { token: 'value' } });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(false);
      });

      it('should reject non-string token (array)', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: ['token'] });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(false);
      });

      it('should reject undefined token', async () => {
        mockStorageLocalGet.mockResolvedValueOnce({ auth_token: undefined });

        const state = await authModule.getAuthState();

        expect(state.isValid).toBe(false);
      });
    });
  });

  // ===========================================================================
  // State Persistence
  // ===========================================================================

  describe('State Persistence', () => {
    it('should persist state across getAuthState calls', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: VALID_JWT_TOKEN });

      await authModule.getAuthState();

      expect(authModule.isHunterMode()).toBe(true);
      expect(authModule.getAuthToken()).toBe(VALID_JWT_TOKEN);
    });

    it('should update persisted state on storage change', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({});

      authModule.initAuthMonitoring();
      await new Promise((resolve) => setTimeout(resolve, 10));

      // Initial state
      expect(authModule.isHunterMode()).toBe(false);
      expect(authModule.getAuthToken()).toBeNull();

      // Simulate storage change
      const storageHandler = mockStorageOnChangedAddListener.mock.calls[0][0];
      storageHandler(
        { auth_token: { newValue: VALID_JWT_TOKEN, oldValue: null } },
        'local'
      );

      // State should be updated
      expect(authModule.isHunterMode()).toBe(true);
      expect(authModule.getAuthToken()).toBe(VALID_JWT_TOKEN);
    });

    it('should clear token on logout (null token)', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: VALID_JWT_TOKEN });

      authModule.initAuthMonitoring();
      await new Promise((resolve) => setTimeout(resolve, 10));

      // Initial authenticated state
      expect(authModule.isHunterMode()).toBe(true);

      // Simulate logout
      const storageHandler = mockStorageOnChangedAddListener.mock.calls[0][0];
      storageHandler(
        { auth_token: { newValue: null, oldValue: VALID_JWT_TOKEN } },
        'local'
      );

      expect(authModule.isHunterMode()).toBe(false);
      expect(authModule.getAuthToken()).toBeNull();
    });
  });

  // ===========================================================================
  // Type exports
  // ===========================================================================

  describe('Type exports', () => {
    it('should export ExtensionMode type', () => {
      // Type checking - this will fail at compile time if types aren't exported
      const mode: import('../src/background/auth').ExtensionMode = 'hunter';
      expect(mode).toBe('hunter');
    });

    it('should export AuthState interface', async () => {
      mockStorageLocalGet.mockResolvedValueOnce({ auth_token: VALID_JWT_TOKEN });

      const state: import('../src/background/auth').AuthState = await authModule.getAuthState();

      expect(state).toHaveProperty('mode');
      expect(state).toHaveProperty('token');
      expect(state).toHaveProperty('isValid');
    });
  });
});
