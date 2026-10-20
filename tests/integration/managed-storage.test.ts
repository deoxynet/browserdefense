/**
 * Integration Test: Managed Policy Storage
 *
 * Issue #259: Tests the chrome.storage.managed implementation for enterprise
 * policy configuration delivery via GPO/MDM.
 *
 * This test validates:
 * 1. loadManagedConfig() reads from chrome.storage.managed
 * 2. loadConfig() checks managed storage before local storage
 * 3. Managed config takes precedence over local config
 * 4. isConfigManaged() correctly identifies managed configurations
 * 5. Proper handling when managed storage is unavailable
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import {
  loadConfig,
  loadManagedConfig,
  saveConfig,
  hasConfig,
  isConfigManaged,
} from '../../src/config/loader';
import { createExampleConfig, BrowserDefenseConfig } from '../../src/config/schema';

// Mock storage state
const mockLocalStorage: Record<string, unknown> = {};
let mockManagedStorage: Record<string, unknown> | null = {};

// Mock chrome API
vi.stubGlobal('chrome', {
  storage: {
    local: {
      get: vi.fn(async (keys: string | string[] | null) => {
        if (keys === null) {
          return { ...mockLocalStorage };
        }
        if (typeof keys === 'string') {
          return { [keys]: mockLocalStorage[keys] };
        }
        const result: Record<string, unknown> = {};
        for (const key of keys) {
          result[key] = mockLocalStorage[key];
        }
        return result;
      }),
      set: vi.fn(async (items: Record<string, unknown>) => {
        Object.assign(mockLocalStorage, items);
      }),
      remove: vi.fn(async (keys: string | string[]) => {
        const keyList = typeof keys === 'string' ? [keys] : keys;
        for (const key of keyList) {
          delete mockLocalStorage[key];
        }
      }),
    },
    managed: {
      get: vi.fn(async (keys: string | string[] | null) => {
        if (mockManagedStorage === null) {
          throw new Error('Managed storage not available');
        }
        if (keys === null) {
          return { ...mockManagedStorage };
        }
        if (typeof keys === 'string') {
          return { [keys]: mockManagedStorage[keys] };
        }
        const result: Record<string, unknown> = {};
        for (const key of keys) {
          result[key] = mockManagedStorage[key];
        }
        return result;
      }),
    },
  },
});

// Helper to create valid managed policy config
function createManagedPolicyConfig(): Record<string, unknown> {
  return {
    org_id: 'enterprise-org',
    signing_public_key: JSON.stringify({
      kty: 'OKP',
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
    }),
    encryption_public_key: JSON.stringify({
      kty: 'RSA',
      n: 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
      e: 'AQAB',
    }),
    blocklist_endpoint: 'https://enterprise.example.com/blocklist.json',
    forensics_endpoint: 'https://enterprise.example.com/forensics',
    ioc_salt: 'enterprise-salt',
    ioc_scope: 'HOST_PATH',
    update_interval_minutes: 30,
  };
}

describe('Managed Policy Storage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Clear storage state
    Object.keys(mockLocalStorage).forEach((key) => delete mockLocalStorage[key]);
    mockManagedStorage = {};
  });

  // ===========================================================================
  // Test 1: loadManagedConfig reads from chrome.storage.managed
  // ===========================================================================

  describe('loadManagedConfig', () => {
    it('should return null when managed storage is empty', async () => {
      mockManagedStorage = {};

      const result = await loadManagedConfig();

      expect(chrome.storage.managed.get).toHaveBeenCalledWith(null);
      expect(result).toBeNull();
    });

    it('should load valid config from managed storage', async () => {
      mockManagedStorage = createManagedPolicyConfig();

      const result = await loadManagedConfig();

      expect(result).not.toBeNull();
      expect(result?.org_id).toBe('enterprise-org');
      expect(result?.blocklist_endpoint).toBe('https://enterprise.example.com/blocklist.json');
      expect(result?.ioc_scope).toBe('HOST_PATH');
    });

    it('should parse JWK keys stored as JSON strings', async () => {
      mockManagedStorage = createManagedPolicyConfig();

      const result = await loadManagedConfig();

      expect(result).not.toBeNull();
      expect(result?.signing_public_key.kty).toBe('OKP');
      expect(result?.encryption_public_key.kty).toBe('RSA');
    });

    it('should handle JWK keys stored as objects', async () => {
      mockManagedStorage = {
        ...createManagedPolicyConfig(),
        signing_public_key: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        },
      };

      const result = await loadManagedConfig();

      expect(result).not.toBeNull();
      expect(result?.signing_public_key.kty).toBe('OKP');
    });

    it('should return null for invalid managed config', async () => {
      mockManagedStorage = {
        org_id: '', // Invalid: empty
        blocklist_endpoint: 'http://insecure.com', // Invalid: not HTTPS
      };

      const consoleSpy = vi.spyOn(console, 'warn');
      const result = await loadManagedConfig();

      expect(result).toBeNull();
      expect(consoleSpy).toHaveBeenCalledWith(
        '[BrowserDefense] Managed configuration is invalid:',
        expect.any(Array)
      );
    });

    it('should return null when managed storage throws', async () => {
      mockManagedStorage = null; // This triggers the error path

      const consoleSpy = vi.spyOn(console, 'log');
      const result = await loadManagedConfig();

      expect(result).toBeNull();
      expect(consoleSpy).toHaveBeenCalledWith(
        '[BrowserDefense] Could not read managed storage:',
        expect.any(Error)
      );
    });

    it('should support forensics_public_key as alias for encryption_public_key', async () => {
      // Enterprise docs use forensics_public_key as the policy key name
      const policyConfig = createManagedPolicyConfig();
      const encKey = policyConfig.encryption_public_key;
      delete policyConfig.encryption_public_key;
      policyConfig.forensics_public_key = encKey;

      mockManagedStorage = policyConfig;

      const result = await loadManagedConfig();

      expect(result).not.toBeNull();
      expect(result?.encryption_public_key.kty).toBe('RSA');
    });
  });

  // ===========================================================================
  // Test 2: loadConfig checks managed storage before local storage
  // ===========================================================================

  describe('loadConfig priority', () => {
    it('should prefer managed config over local config', async () => {
      // Set up managed config
      mockManagedStorage = createManagedPolicyConfig();

      // Set up local config with different org_id
      const localConfig = createExampleConfig();
      localConfig.org_id = 'local-org';
      mockLocalStorage['browserdefense_config'] = localConfig;

      const result = await loadConfig();

      expect(result).not.toBeNull();
      expect(result?.org_id).toBe('enterprise-org'); // Managed config wins
    });

    it('should fall back to local config when managed is empty', async () => {
      mockManagedStorage = {};

      const localConfig = createExampleConfig();
      mockLocalStorage['browserdefense_config'] = localConfig;

      const result = await loadConfig();

      expect(result).not.toBeNull();
      expect(result?.org_id).toBe('example-org'); // Local config used
    });

    it('should return null when both managed and local are empty', async () => {
      mockManagedStorage = {};
      // mockLocalStorage is empty

      const result = await loadConfig();

      expect(result).toBeNull();
    });
  });

  // ===========================================================================
  // Test 3: isConfigManaged correctly identifies managed configurations
  // ===========================================================================

  describe('isConfigManaged', () => {
    it('should return true when managed config exists', async () => {
      mockManagedStorage = createManagedPolicyConfig();

      const result = await isConfigManaged();

      expect(result).toBe(true);
    });

    it('should return false when managed storage is empty', async () => {
      mockManagedStorage = {};

      const result = await isConfigManaged();

      expect(result).toBe(false);
    });

    it('should return false when managed config is invalid', async () => {
      mockManagedStorage = {
        org_id: '', // Invalid
      };

      const result = await isConfigManaged();

      expect(result).toBe(false);
    });
  });

  // ===========================================================================
  // Test 4: hasConfig checks both storage areas
  // ===========================================================================

  describe('hasConfig', () => {
    it('should return true when only managed config exists', async () => {
      mockManagedStorage = createManagedPolicyConfig();
      // mockLocalStorage is empty

      const result = await hasConfig();

      expect(result).toBe(true);
    });

    it('should return true when only local config exists', async () => {
      mockManagedStorage = {};
      mockLocalStorage['browserdefense_config'] = createExampleConfig();

      const result = await hasConfig();

      expect(result).toBe(true);
    });

    it('should return true when both exist', async () => {
      mockManagedStorage = createManagedPolicyConfig();
      mockLocalStorage['browserdefense_config'] = createExampleConfig();

      const result = await hasConfig();

      expect(result).toBe(true);
    });

    it('should return false when neither exists', async () => {
      mockManagedStorage = {};
      // mockLocalStorage is empty

      const result = await hasConfig();

      expect(result).toBe(false);
    });
  });

  // ===========================================================================
  // Test 5: Managed storage unavailable scenarios
  // ===========================================================================

  describe('Managed storage unavailable', () => {
    it('should handle chrome.storage.managed being undefined', async () => {
      // Temporarily remove managed storage
      const originalManaged = chrome.storage.managed;
      (chrome.storage as { managed?: typeof chrome.storage.managed }).managed = undefined;

      const result = await loadManagedConfig();

      expect(result).toBeNull();

      // Restore
      (chrome.storage as { managed?: typeof chrome.storage.managed }).managed = originalManaged;
    });

    it('should fall back to local config when managed throws', async () => {
      mockManagedStorage = null; // This triggers error

      const localConfig = createExampleConfig();
      mockLocalStorage['browserdefense_config'] = localConfig;

      const result = await loadConfig();

      expect(result).not.toBeNull();
      expect(result?.org_id).toBe('example-org');
    });
  });
});

// ===========================================================================
// Test 6: Enterprise deployment scenarios
// ===========================================================================

describe('Enterprise Deployment Scenarios', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.keys(mockLocalStorage).forEach((key) => delete mockLocalStorage[key]);
    mockManagedStorage = {};
  });

  it('should load config with all enterprise deployment fields', async () => {
    mockManagedStorage = {
      org_id: 'acme-corp',
      signing_public_key: JSON.stringify({
        kty: 'EC',
        crv: 'P-256',
        x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
      }),
      encryption_public_key: JSON.stringify({
        kty: 'RSA',
        n: 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
        e: 'AQAB',
      }),
      blocklist_endpoint: 'https://cdn.acme-corp.com/blocklist/v1/manifest.json',
      forensics_endpoint: 'https://siem.acme-corp.com/api/forensics',
      ioc_salt: 'acme-unique-salt-2024',
      ioc_scope: 'HOST_ONLY',
      update_interval_minutes: 15,
    };

    const config = await loadConfig();

    expect(config).not.toBeNull();
    expect(config?.org_id).toBe('acme-corp');
    expect(config?.signing_public_key.kty).toBe('EC');
    expect(config?.ioc_scope).toBe('HOST_ONLY');
    expect(config?.update_interval_minutes).toBe(15);
  });

  it('should handle partial managed config with defaults', async () => {
    // Only required fields - optional fields should be undefined
    mockManagedStorage = {
      org_id: 'minimal-org',
      signing_public_key: JSON.stringify({
        kty: 'OKP',
        crv: 'Ed25519',
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      }),
      encryption_public_key: JSON.stringify({
        kty: 'RSA',
        n: 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
        e: 'AQAB',
      }),
      blocklist_endpoint: 'https://cdn.example.com/blocklist.json',
      forensics_endpoint: 'https://forensics.example.com/upload',
      ioc_salt: 'minimal-salt',
      // No ioc_scope or update_interval_minutes
    };

    const config = await loadConfig();

    expect(config).not.toBeNull();
    expect(config?.org_id).toBe('minimal-org');
    expect(config?.ioc_scope).toBeUndefined();
    expect(config?.update_interval_minutes).toBeUndefined();
  });

  it('should correctly determine managed status for UI display', async () => {
    // Scenario: Enterprise install with managed config
    mockManagedStorage = createManagedPolicyConfig();

    const config = await loadConfig();
    const isManaged = await isConfigManaged();

    expect(config).not.toBeNull();
    expect(isManaged).toBe(true);
    // UI should show "Managed by your organization" and disable editing
  });

  it('should correctly identify non-managed config', async () => {
    // Scenario: Free/self-service install with local config only
    mockManagedStorage = {};
    mockLocalStorage['browserdefense_config'] = createExampleConfig();

    const config = await loadConfig();
    const isManaged = await isConfigManaged();

    expect(config).not.toBeNull();
    expect(isManaged).toBe(false);
    // UI should allow configuration editing
  });
});
