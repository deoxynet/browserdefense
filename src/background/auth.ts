/**
 * Auth module for dual-mode extension (Issue #399)
 *
 * Handles auth_token storage and mode detection:
 * - Sensor mode (unauthenticated): blocking only, no UI/menus
 * - Hunter mode (authenticated): context menus, Ops Center UI
 */

export type ExtensionMode = 'sensor' | 'hunter';

export interface AuthState {
  mode: ExtensionMode;
  token: string | null;
  isValid: boolean;
}

type AuthStateListener = (state: AuthState) => void;

const listeners: AuthStateListener[] = [];
let currentState: AuthState = {
  mode: 'sensor',
  token: null,
  isValid: false,
};

/**
 * Get the current auth state from storage.
 */
export async function getAuthState(): Promise<AuthState> {
  const { auth_token } = await chrome.storage.local.get('auth_token');
  const isValid = isValidToken(auth_token);

  currentState = {
    mode: isValid ? 'hunter' : 'sensor',
    token: auth_token ?? null,
    isValid,
  };

  return currentState;
}

/**
 * Validate auth token format.
 * For now, just checks that it's a non-empty string.
 * Can be extended to check JWT format, expiry, etc.
 */
function isValidToken(token: unknown): boolean {
  if (typeof token !== 'string' || token.trim() === '') {
    return false;
  }

  // Basic JWT structure check (three dot-separated parts)
  const parts = token.split('.');
  if (parts.length === 3) {
    // Looks like a JWT
    return parts.every((part) => part.length > 0);
  }

  // Allow simple API key format (at least 32 chars, alphanumeric + dashes)
  if (token.length >= 32 && /^[a-zA-Z0-9_-]+$/.test(token)) {
    return true;
  }

  return false;
}

/**
 * Register a listener for auth state changes.
 */
export function onAuthStateChange(listener: AuthStateListener): () => void {
  listeners.push(listener);
  return () => {
    const idx = listeners.indexOf(listener);
    if (idx >= 0) listeners.splice(idx, 1);
  };
}

/**
 * Notify all listeners of auth state change.
 */
function notifyListeners(state: AuthState): void {
  for (const listener of listeners) {
    try {
      listener(state);
    } catch (err) {
      console.error('[BlockIOC] Auth listener error:', err);
    }
  }
}

/**
 * Initialize auth state monitoring.
 * Watches for storage changes and notifies listeners.
 */
export function initAuthMonitoring(): void {
  // Get initial state
  getAuthState().then((state) => {
    console.log(`[BlockIOC] Initial mode: ${state.mode}`);
  });

  // Watch for auth_token changes
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && changes.auth_token) {
      const newToken = changes.auth_token.newValue;
      const isValid = isValidToken(newToken);

      const newState: AuthState = {
        mode: isValid ? 'hunter' : 'sensor',
        token: newToken ?? null,
        isValid,
      };

      const modeChanged = currentState.mode !== newState.mode;
      currentState = newState;

      if (modeChanged) {
        console.log(`[BlockIOC] Mode changed to: ${newState.mode}`);
      }

      notifyListeners(newState);
    }
  });
}

/**
 * Check if currently in hunter mode.
 */
export function isHunterMode(): boolean {
  return currentState.mode === 'hunter';
}

/**
 * Get the current auth token (for API calls).
 */
export function getAuthToken(): string | null {
  return currentState.token;
}
