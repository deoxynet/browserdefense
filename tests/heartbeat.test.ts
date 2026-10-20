import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// =============================================================================
// Chrome API Mocks
// =============================================================================

const mockAlarmsClear = vi.fn().mockResolvedValue(true);
const mockAlarmsCreate = vi.fn().mockResolvedValue(undefined);
const mockAlarmsOnAlarmAddListener = vi.fn();

vi.stubGlobal('chrome', {
  alarms: {
    clear: mockAlarmsClear,
    create: mockAlarmsCreate,
    onAlarm: {
      addListener: mockAlarmsOnAlarmAddListener,
    },
  },
});

// Mock forensics and direct-ingest modules
vi.mock('../src/background/forensics', () => ({
  checkPendingForensics: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../src/background/direct-ingest', () => ({
  checkPendingIngest: vi.fn().mockResolvedValue(undefined),
}));

// =============================================================================
// Tests
// =============================================================================

describe('Heartbeat Module', () => {
  let heartbeatModule: typeof import('../src/background/heartbeat');
  let forensicsModule: typeof import('../src/background/forensics');
  let directIngestModule: typeof import('../src/background/direct-ingest');

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();

    // Re-import modules after reset
    heartbeatModule = await import('../src/background/heartbeat');
    forensicsModule = await import('../src/background/forensics');
    directIngestModule = await import('../src/background/direct-ingest');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ===========================================================================
  // initHeartbeat
  // ===========================================================================

  describe('initHeartbeat', () => {
    it('should clear existing alarm before creating new one', async () => {
      await heartbeatModule.initHeartbeat();

      expect(mockAlarmsClear).toHaveBeenCalledWith('keepAlive');
      expect(mockAlarmsClear).toHaveBeenCalledTimes(1);
    });

    it('should create heartbeat alarm with correct interval', async () => {
      await heartbeatModule.initHeartbeat();

      expect(mockAlarmsCreate).toHaveBeenCalledWith('keepAlive', {
        periodInMinutes: 4.9,
      });
      expect(mockAlarmsCreate).toHaveBeenCalledTimes(1);
    });

    it('should clear alarm before creating to ensure clean state', async () => {
      await heartbeatModule.initHeartbeat();

      // Verify clear is called before create
      const clearCall = mockAlarmsClear.mock.invocationCallOrder[0];
      const createCall = mockAlarmsCreate.mock.invocationCallOrder[0];
      expect(clearCall).toBeLessThan(createCall);
    });

    it('should use 4.9 minute interval (under Chrome 5 min limit)', async () => {
      await heartbeatModule.initHeartbeat();

      const createArg = mockAlarmsCreate.mock.calls[0][1] as { periodInMinutes: number };
      expect(createArg.periodInMinutes).toBe(4.9);
      expect(createArg.periodInMinutes).toBeLessThan(5);
    });

    it('should handle alarm clear failure gracefully', async () => {
      mockAlarmsClear.mockRejectedValueOnce(new Error('Clear failed'));

      await expect(heartbeatModule.initHeartbeat()).rejects.toThrow('Clear failed');
    });

    it('should handle alarm create failure gracefully', async () => {
      mockAlarmsCreate.mockRejectedValueOnce(new Error('Create failed'));

      await expect(heartbeatModule.initHeartbeat()).rejects.toThrow('Create failed');
    });
  });

  // ===========================================================================
  // handleHeartbeat
  // ===========================================================================

  describe('handleHeartbeat', () => {
    it('should increment heartbeat count', async () => {
      const initialStats = heartbeatModule.getHeartbeatStats();
      const initialCount = initialStats.count;

      await heartbeatModule.handleHeartbeat();

      const newStats = heartbeatModule.getHeartbeatStats();
      expect(newStats.count).toBe(initialCount + 1);
    });

    it('should call checkPendingForensics', async () => {
      await heartbeatModule.handleHeartbeat();

      expect(forensicsModule.checkPendingForensics).toHaveBeenCalledTimes(1);
    });

    it('should call checkPendingIngest', async () => {
      await heartbeatModule.handleHeartbeat();

      expect(directIngestModule.checkPendingIngest).toHaveBeenCalledTimes(1);
    });

    it('should call both pending checks on each heartbeat', async () => {
      await heartbeatModule.handleHeartbeat();
      await heartbeatModule.handleHeartbeat();

      expect(forensicsModule.checkPendingForensics).toHaveBeenCalledTimes(2);
      expect(directIngestModule.checkPendingIngest).toHaveBeenCalledTimes(2);
    });

    it('should increment count on each call', async () => {
      const initialCount = heartbeatModule.getHeartbeatStats().count;

      await heartbeatModule.handleHeartbeat();
      await heartbeatModule.handleHeartbeat();
      await heartbeatModule.handleHeartbeat();

      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount + 3);
    });

    it('should handle forensics check failure gracefully', async () => {
      vi.mocked(forensicsModule.checkPendingForensics).mockRejectedValueOnce(
        new Error('Forensics failed')
      );

      // Should propagate the error
      await expect(heartbeatModule.handleHeartbeat()).rejects.toThrow('Forensics failed');
    });

    it('should handle ingest check failure gracefully', async () => {
      vi.mocked(directIngestModule.checkPendingIngest).mockRejectedValueOnce(
        new Error('Ingest failed')
      );

      // Should propagate the error
      await expect(heartbeatModule.handleHeartbeat()).rejects.toThrow('Ingest failed');
    });
  });

  // ===========================================================================
  // setupHeartbeatListener
  // ===========================================================================

  describe('setupHeartbeatListener', () => {
    it('should add alarm listener', () => {
      heartbeatModule.setupHeartbeatListener();

      expect(mockAlarmsOnAlarmAddListener).toHaveBeenCalledTimes(1);
      expect(typeof mockAlarmsOnAlarmAddListener.mock.calls[0][0]).toBe('function');
    });

    it('should call handleHeartbeat when keepAlive alarm fires', async () => {
      heartbeatModule.setupHeartbeatListener();

      const listener = mockAlarmsOnAlarmAddListener.mock.calls[0][0] as (
        alarm: chrome.alarms.Alarm
      ) => Promise<void>;

      const initialCount = heartbeatModule.getHeartbeatStats().count;

      await listener({ name: 'keepAlive', scheduledTime: Date.now() });

      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount + 1);
    });

    it('should not call handleHeartbeat for other alarms', async () => {
      heartbeatModule.setupHeartbeatListener();

      const listener = mockAlarmsOnAlarmAddListener.mock.calls[0][0] as (
        alarm: chrome.alarms.Alarm
      ) => Promise<void>;

      const initialCount = heartbeatModule.getHeartbeatStats().count;

      await listener({ name: 'otherAlarm', scheduledTime: Date.now() });

      // Count should not change for other alarms
      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount);
    });

    it('should ignore alarms with different names', async () => {
      heartbeatModule.setupHeartbeatListener();

      const listener = mockAlarmsOnAlarmAddListener.mock.calls[0][0] as (
        alarm: chrome.alarms.Alarm
      ) => Promise<void>;

      const testAlarms = ['someOther', 'anotherAlarm', 'notKeepAlive', ''];
      const initialCount = heartbeatModule.getHeartbeatStats().count;

      for (const alarmName of testAlarms) {
        await listener({ name: alarmName, scheduledTime: Date.now() });
      }

      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount);
    });

    it('should call pending checks when keepAlive alarm fires', async () => {
      heartbeatModule.setupHeartbeatListener();

      const listener = mockAlarmsOnAlarmAddListener.mock.calls[0][0] as (
        alarm: chrome.alarms.Alarm
      ) => Promise<void>;

      await listener({ name: 'keepAlive', scheduledTime: Date.now() });

      expect(forensicsModule.checkPendingForensics).toHaveBeenCalled();
      expect(directIngestModule.checkPendingIngest).toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // getHeartbeatStats
  // ===========================================================================

  describe('getHeartbeatStats', () => {
    it('should return current count', () => {
      const stats = heartbeatModule.getHeartbeatStats();

      expect(typeof stats.count).toBe('number');
      expect(stats.count).toBeGreaterThanOrEqual(0);
    });

    it('should return correct interval', () => {
      const stats = heartbeatModule.getHeartbeatStats();

      expect(stats.intervalMinutes).toBe(4.9);
    });

    it('should return object with count and intervalMinutes', () => {
      const stats = heartbeatModule.getHeartbeatStats();

      expect(stats).toHaveProperty('count');
      expect(stats).toHaveProperty('intervalMinutes');
    });

    it('should reflect incremented count after handleHeartbeat', async () => {
      const initialCount = heartbeatModule.getHeartbeatStats().count;

      await heartbeatModule.handleHeartbeat();
      await heartbeatModule.handleHeartbeat();

      const stats = heartbeatModule.getHeartbeatStats();
      expect(stats.count).toBe(initialCount + 2);
    });

    it('should have immutable interval', () => {
      const stats1 = heartbeatModule.getHeartbeatStats();
      const stats2 = heartbeatModule.getHeartbeatStats();

      expect(stats1.intervalMinutes).toBe(stats2.intervalMinutes);
    });
  });

  // ===========================================================================
  // forceHeartbeat
  // ===========================================================================

  describe('forceHeartbeat', () => {
    it('should increment heartbeat count', async () => {
      const initialCount = heartbeatModule.getHeartbeatStats().count;

      await heartbeatModule.forceHeartbeat();

      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount + 1);
    });

    it('should call checkPendingForensics', async () => {
      await heartbeatModule.forceHeartbeat();

      expect(forensicsModule.checkPendingForensics).toHaveBeenCalledTimes(1);
    });

    it('should call checkPendingIngest', async () => {
      await heartbeatModule.forceHeartbeat();

      expect(directIngestModule.checkPendingIngest).toHaveBeenCalledTimes(1);
    });

    it('should work independently of alarm system', async () => {
      // Force heartbeat without initializing alarm
      const initialCount = heartbeatModule.getHeartbeatStats().count;

      await heartbeatModule.forceHeartbeat();

      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount + 1);
      // Alarm methods should not be called
      expect(mockAlarmsCreate).not.toHaveBeenCalled();
    });

    it('should be equivalent to handleHeartbeat', async () => {
      await heartbeatModule.forceHeartbeat();
      await heartbeatModule.handleHeartbeat();

      // Both should call the same underlying checks
      expect(forensicsModule.checkPendingForensics).toHaveBeenCalledTimes(2);
      expect(directIngestModule.checkPendingIngest).toHaveBeenCalledTimes(2);
    });
  });

  // ===========================================================================
  // Integration scenarios
  // ===========================================================================

  describe('Integration scenarios', () => {
    it('should handle full lifecycle: init -> listener -> heartbeat', async () => {
      // Initialize
      await heartbeatModule.initHeartbeat();
      expect(mockAlarmsCreate).toHaveBeenCalledWith('keepAlive', { periodInMinutes: 4.9 });

      // Setup listener
      heartbeatModule.setupHeartbeatListener();
      expect(mockAlarmsOnAlarmAddListener).toHaveBeenCalled();

      // Simulate alarm firing
      const listener = mockAlarmsOnAlarmAddListener.mock.calls[0][0] as (
        alarm: chrome.alarms.Alarm
      ) => Promise<void>;
      const initialCount = heartbeatModule.getHeartbeatStats().count;

      await listener({ name: 'keepAlive', scheduledTime: Date.now() });

      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount + 1);
      expect(forensicsModule.checkPendingForensics).toHaveBeenCalled();
      expect(directIngestModule.checkPendingIngest).toHaveBeenCalled();
    });

    it('should handle multiple heartbeats over simulated time', async () => {
      await heartbeatModule.initHeartbeat();
      heartbeatModule.setupHeartbeatListener();

      const listener = mockAlarmsOnAlarmAddListener.mock.calls[0][0] as (
        alarm: chrome.alarms.Alarm
      ) => Promise<void>;
      const initialCount = heartbeatModule.getHeartbeatStats().count;

      // Simulate 5 heartbeats (like ~25 minutes of runtime)
      for (let i = 0; i < 5; i++) {
        await listener({ name: 'keepAlive', scheduledTime: Date.now() + i * 4.9 * 60 * 1000 });
      }

      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount + 5);
      expect(forensicsModule.checkPendingForensics).toHaveBeenCalledTimes(5);
      expect(directIngestModule.checkPendingIngest).toHaveBeenCalledTimes(5);
    });

    it('should not process non-keepAlive alarms in busy system', async () => {
      heartbeatModule.setupHeartbeatListener();

      const listener = mockAlarmsOnAlarmAddListener.mock.calls[0][0] as (
        alarm: chrome.alarms.Alarm
      ) => Promise<void>;
      const initialCount = heartbeatModule.getHeartbeatStats().count;

      // Mix of keepAlive and other alarms
      await listener({ name: 'updateCheck', scheduledTime: Date.now() });
      await listener({ name: 'keepAlive', scheduledTime: Date.now() });
      await listener({ name: 'syncData', scheduledTime: Date.now() });
      await listener({ name: 'keepAlive', scheduledTime: Date.now() });
      await listener({ name: 'cleanup', scheduledTime: Date.now() });

      // Only keepAlive alarms should trigger heartbeat
      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount + 2);
    });

    it('should maintain state across force and regular heartbeats', async () => {
      heartbeatModule.setupHeartbeatListener();

      const listener = mockAlarmsOnAlarmAddListener.mock.calls[0][0] as (
        alarm: chrome.alarms.Alarm
      ) => Promise<void>;
      const initialCount = heartbeatModule.getHeartbeatStats().count;

      await heartbeatModule.forceHeartbeat();
      await listener({ name: 'keepAlive', scheduledTime: Date.now() });
      await heartbeatModule.forceHeartbeat();

      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount + 3);
    });
  });

  // ===========================================================================
  // Edge cases
  // ===========================================================================

  describe('Edge cases', () => {
    it('should handle rapid successive heartbeats', async () => {
      const initialCount = heartbeatModule.getHeartbeatStats().count;

      // Fire many heartbeats rapidly
      await Promise.all([
        heartbeatModule.handleHeartbeat(),
        heartbeatModule.handleHeartbeat(),
        heartbeatModule.handleHeartbeat(),
      ]);

      expect(heartbeatModule.getHeartbeatStats().count).toBe(initialCount + 3);
    });

    it('should handle re-initialization', async () => {
      await heartbeatModule.initHeartbeat();
      await heartbeatModule.initHeartbeat();

      // Should clear and create twice
      expect(mockAlarmsClear).toHaveBeenCalledTimes(2);
      expect(mockAlarmsCreate).toHaveBeenCalledTimes(2);
    });

    it('should handle listener setup multiple times', () => {
      heartbeatModule.setupHeartbeatListener();
      heartbeatModule.setupHeartbeatListener();

      // Each call adds another listener
      expect(mockAlarmsOnAlarmAddListener).toHaveBeenCalledTimes(2);
    });
  });
});
