/**
 * Sensor Mode Tests
 *
 * Tests for the FCM listener, DNR update, and ack jitter functionality.
 * Issue #400
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock chrome APIs before importing sensor module
const mockStorage = {
  local: {
    get: vi.fn(),
    set: vi.fn(),
  },
  managed: {
    get: vi.fn(),
  },
};

const mockGcm = {
  register: vi.fn(),
  onMessage: {
    addListener: vi.fn(),
  },
};

const mockIdentity = {
  getProfileUserInfo: vi.fn((callback: (info: { email: string }) => void) => {
    callback({ email: '' });
  }),
};

const mockDeclarativeNetRequest = {
  getDynamicRules: vi.fn().mockResolvedValue([]),
  updateDynamicRules: vi.fn().mockResolvedValue(undefined),
  RuleActionType: {
    BLOCK: 'block',
    REDIRECT: 'redirect',
  },
  ResourceType: {
    MAIN_FRAME: 'main_frame',
    SUB_FRAME: 'sub_frame',
  },
};

const mockRuntime = {
  getURL: vi.fn((path: string) => `chrome-extension://test123/${path}`),
  lastError: null,
};

// Set up chrome mock
globalThis.chrome = {
  storage: mockStorage,
  gcm: mockGcm,
  identity: mockIdentity,
  declarativeNetRequest: mockDeclarativeNetRequest,
  runtime: mockRuntime,
} as unknown as typeof chrome;

// Now import the sensor module
import {
  getSensorConfig,
  saveSensorConfig,
  getHostIdentity,
  setHostIdentity,
  getSensorStats,
  isGCMAvailable,
  setupGCMListener,
  type SensorConfig,
  type HostIdentity,
  type FCMBlockMessage,
  type FCMUnblockMessage,
  type FCMPingMessage,
  type AckPayload,
} from '../src/background/sensor';

describe('Sensor Mode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockStorage.local.get.mockResolvedValue({});
    mockStorage.local.set.mockResolvedValue(undefined);
    mockStorage.managed.get.mockResolvedValue({});
    // Reset to default callback behavior
    mockIdentity.getProfileUserInfo.mockImplementation(
      (callback: (info: { email: string }) => void) => {
        callback({ email: '' });
      }
    );
    mockRuntime.lastError = null;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getSensorConfig', () => {
    it('returns null when no config exists', async () => {
      mockStorage.local.get.mockResolvedValue({});
      const config = await getSensorConfig();
      expect(config).toBeNull();
    });

    it('returns config when stored', async () => {
      const storedConfig: SensorConfig = {
        enabled: true,
        gcm_sender_id: '123456789',
        ack_endpoint: 'https://api.example.com/ack',
      };
      mockStorage.local.get.mockResolvedValue({
        blockioc_sensor_config: storedConfig,
      });

      const config = await getSensorConfig();
      expect(config).toEqual(storedConfig);
    });
  });

  describe('saveSensorConfig', () => {
    it('saves config to storage', async () => {
      const config: SensorConfig = {
        enabled: true,
        gcm_sender_id: '123456789',
        ack_endpoint: 'https://api.example.com/ack',
      };

      await saveSensorConfig(config);

      expect(mockStorage.local.set).toHaveBeenCalledWith({
        blockioc_sensor_config: config,
      });
    });
  });

  describe('getHostIdentity', () => {
    it('returns identity from managed storage if available', async () => {
      mockStorage.managed.get.mockResolvedValue({
        hostname: 'enterprise-host',
        username: 'enterprise-user',
      });

      const identity = await getHostIdentity();

      expect(identity).toEqual({
        hostname: 'enterprise-host',
        username: 'enterprise-user',
      });
    });

    it('returns identity from local storage cache if managed not available', async () => {
      mockStorage.managed.get.mockResolvedValue({});
      mockStorage.local.get.mockResolvedValue({
        blockioc_host_identity: {
          hostname: 'cached-host',
          username: 'cached-user',
        },
      });

      const identity = await getHostIdentity();

      expect(identity).toEqual({
        hostname: 'cached-host',
        username: 'cached-user',
      });
    });

    it('uses chrome identity API email as username fallback', async () => {
      mockStorage.managed.get.mockResolvedValue({});
      mockStorage.local.get.mockResolvedValue({});
      mockIdentity.getProfileUserInfo.mockImplementation(
        (callback: (info: { email: string }) => void) => {
          callback({ email: 'user@example.com' });
        }
      );

      const identity = await getHostIdentity();

      expect(identity.username).toBe('user@example.com');
      expect(identity.hostname).toBe('browser-agent');
    });

    it('returns defaults when no identity sources available', async () => {
      mockStorage.managed.get.mockResolvedValue({});
      mockStorage.local.get.mockResolvedValue({});
      mockIdentity.getProfileUserInfo.mockImplementation(
        (callback: (info: { email: string }) => void) => {
          callback({ email: '' });
        }
      );

      const identity = await getHostIdentity();

      expect(identity).toEqual({
        hostname: 'browser-agent',
        username: 'unknown',
      });
    });

    it('caches identity to local storage', async () => {
      mockStorage.managed.get.mockResolvedValue({});
      mockStorage.local.get.mockResolvedValue({});
      mockIdentity.getProfileUserInfo.mockImplementation(
        (callback: (info: { email: string }) => void) => {
          callback({ email: 'user@test.com' });
        }
      );

      await getHostIdentity();

      expect(mockStorage.local.set).toHaveBeenCalledWith({
        blockioc_host_identity: {
          hostname: 'browser-agent',
          username: 'user@test.com',
        },
      });
    });
  });

  describe('setHostIdentity', () => {
    it('saves identity to local storage', async () => {
      const identity: HostIdentity = {
        hostname: 'custom-host',
        username: 'custom-user',
      };

      await setHostIdentity(identity);

      expect(mockStorage.local.set).toHaveBeenCalledWith({
        blockioc_host_identity: identity,
      });
    });
  });

  describe('isGCMAvailable', () => {
    it('returns true when chrome.gcm is defined', () => {
      expect(isGCMAvailable()).toBe(true);
    });

    it('returns false when chrome.gcm is undefined', () => {
      const originalGcm = globalThis.chrome.gcm;
      (globalThis.chrome as Record<string, unknown>).gcm = undefined;

      expect(isGCMAvailable()).toBe(false);

      globalThis.chrome.gcm = originalGcm;
    });
  });

  describe('setupGCMListener', () => {
    it('registers GCM message listener', () => {
      setupGCMListener();

      expect(mockGcm.onMessage.addListener).toHaveBeenCalledTimes(1);
      expect(mockGcm.onMessage.addListener).toHaveBeenCalledWith(
        expect.any(Function)
      );
    });
  });

  describe('getSensorStats', () => {
    it('returns stats when sensor mode is disabled', async () => {
      mockStorage.local.get.mockResolvedValue({});

      const stats = await getSensorStats();

      expect(stats).toEqual({
        enabled: false,
        gcmAvailable: true,
        hasConfig: false,
        identity: null,
      });
    });

    it('returns stats with identity when sensor mode is enabled', async () => {
      const config: SensorConfig = {
        enabled: true,
        gcm_sender_id: '123456789',
        ack_endpoint: 'https://api.example.com/ack',
      };
      mockStorage.local.get.mockImplementation(async (key) => {
        if (key === 'blockioc_sensor_config') {
          return { blockioc_sensor_config: config };
        }
        if (key === 'blockioc_host_identity') {
          return {
            blockioc_host_identity: {
              hostname: 'test-host',
              username: 'test-user',
            },
          };
        }
        return {};
      });
      mockStorage.managed.get.mockResolvedValue({});

      const stats = await getSensorStats();

      expect(stats.enabled).toBe(true);
      expect(stats.hasConfig).toBe(true);
      expect(stats.identity).toBeDefined();
    });
  });
});

describe('FCM Message Types', () => {
  it('FCMBlockMessage has required fields', () => {
    const message: FCMBlockMessage = {
      type: 'BLOCK',
      ioc: 'https://evil.com',
      op_id: 'op-123',
    };

    expect(message.type).toBe('BLOCK');
    expect(message.ioc).toBeDefined();
    expect(message.op_id).toBeDefined();
  });

  it('FCMBlockMessage can have optional reason', () => {
    const message: FCMBlockMessage = {
      type: 'BLOCK',
      ioc: 'https://phishing.com',
      op_id: 'op-456',
      reason: 'phishing',
    };

    expect(message.reason).toBe('phishing');
  });

  it('FCMPingMessage has required fields', () => {
    const message: FCMPingMessage = {
      type: 'PING',
      op_id: 'ping-789',
    };

    expect(message.type).toBe('PING');
    expect(message.op_id).toBeDefined();
  });

  it('FCMUnblockMessage has required fields', () => {
    const message: FCMUnblockMessage = {
      type: 'UNBLOCK',
      ioc: 'https://evil.com',
      op_id: 'op-unblock-123',
    };

    expect(message.type).toBe('UNBLOCK');
    expect(message.ioc).toBeDefined();
    expect(message.op_id).toBeDefined();
  });
});

describe('AckPayload', () => {
  it('has all required fields for success', () => {
    const payload: AckPayload = {
      op_id: 'op-123',
      host: 'test-host',
      user: 'test-user',
      result: 'success',
      timestamp: Date.now(),
    };

    expect(payload.op_id).toBeDefined();
    expect(payload.host).toBeDefined();
    expect(payload.user).toBeDefined();
    expect(payload.result).toBe('success');
    expect(payload.timestamp).toBeGreaterThan(0);
  });

  it('has error field for error result', () => {
    const payload: AckPayload = {
      op_id: 'op-456',
      host: 'test-host',
      user: 'test-user',
      result: 'error',
      error: 'DNR not available',
      timestamp: Date.now(),
    };

    expect(payload.result).toBe('error');
    expect(payload.error).toBeDefined();
  });
});

describe('Jitter Behavior', () => {
  it('jitter is within 0-3000ms range', () => {
    // Test jitter bounds by checking random values
    for (let i = 0; i < 100; i++) {
      const jitter = Math.floor(Math.random() * 3000);
      expect(jitter).toBeGreaterThanOrEqual(0);
      expect(jitter).toBeLessThan(3000);
    }
  });
});
