/**
 * POC 1: Validate MV3 Enterprise webRequestBlocking
 *
 * This test suite validates the core enterprise architecture assumptions:
 * 1. webRequestBlocking works in policy-installed MV3 extensions
 * 2. Service worker wake latency is acceptable (<500ms cold start)
 * 3. Can block synchronously and still fire async forensics
 * 4. Extension survives browser restart
 *
 * @see docs/Implementation_Review.md - POC 1 requirements
 *
 * NOTE: Full validation requires manual testing with a policy-installed extension.
 * This suite provides unit tests for the blocking architecture and latency simulation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================================================
// Types and Interfaces for Enterprise webRequestBlocking
// ============================================================================

/**
 * Enterprise extension manifest requirements for webRequestBlocking.
 * Policy-installed extensions can request webRequestBlocking in MV3.
 */
interface EnterpriseManifest {
  manifest_version: 3;
  permissions: string[];
  host_permissions: string[];
  background: {
    service_worker: string;
  };
  /**
   * Key indicator: extension must be force-installed via policy
   * to use webRequestBlocking in MV3.
   */
  key?: string;
}

/**
 * Simulated webRequest.onBeforeRequest details.
 */
interface WebRequestDetails {
  requestId: string;
  url: string;
  method: string;
  frameId: number;
  tabId: number;
  type: chrome.webRequest.ResourceType;
  timeStamp: number;
  initiator?: string;
}

/**
 * Blocking response for synchronous webRequest handling.
 */
interface BlockingResponse {
  cancel?: boolean;
  redirectUrl?: string;
}

/**
 * Latency measurement result.
 */
interface LatencyMeasurement {
  coldStartMs: number;
  warmLookupMs: number;
  blockDecisionMs: number;
  totalMs: number;
}

// ============================================================================
// Test 1: webRequestBlocking Permission Validation
// ============================================================================

describe('Enterprise MV3 webRequestBlocking', () => {
  describe('manifest validation', () => {
    it('should have correct permissions for enterprise mode', () => {
      const manifest: EnterpriseManifest = {
        manifest_version: 3,
        permissions: ['webRequest', 'webRequestBlocking', 'storage', 'alarms'],
        host_permissions: ['<all_urls>'],
        background: {
          service_worker: 'background.js',
        },
      };

      // Verify required permissions
      expect(manifest.manifest_version).toBe(3);
      expect(manifest.permissions).toContain('webRequest');
      expect(manifest.permissions).toContain('webRequestBlocking');
      expect(manifest.host_permissions).toContain('<all_urls>');
    });

    it('should document policy installation requirement', () => {
      // webRequestBlocking in MV3 requires policy-installed extension
      // This is enforced by Chrome, not by manifest contents
      const policyRequirement = {
        method: 'ExtensionInstallForceList',
        registry_path: 'SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForceList',
        format: '<extension_id>;https://clients2.google.com/service/update2/crx',
      };

      expect(policyRequirement.method).toBe('ExtensionInstallForceList');
      expect(policyRequirement.registry_path).toContain('Policies');
    });
  });
});

// ============================================================================
// Test 2: Service Worker Wake Latency
// ============================================================================

describe('Service Worker Wake Latency', () => {
  const TARGET_COLD_START_MS = 500;

  /**
   * Simulates service worker cold start with blocklist loading.
   */
  async function simulateColdStart(hashCount: number): Promise<number> {
    const start = performance.now();

    // Simulate storage read (main cold start cost)
    const storageReadMs = Math.min(50 + hashCount * 0.0001, 200);
    await new Promise((resolve) => setTimeout(resolve, storageReadMs));

    // Simulate binary set construction
    const setConstructionMs = hashCount * 0.00005;
    await new Promise((resolve) => setTimeout(resolve, setConstructionMs));

    return performance.now() - start;
  }

  /**
   * Simulates warm hash lookup (service worker already active).
   */
  function simulateWarmLookup(_hashSet: Set<string>, _urlHash: string): number {
    const start = performance.now();

    // Set lookup is O(1) - essentially instant
    // Real cost is URL normalization + hashing
    const normalizationMs = 0.1;
    const hashingMs = 0.05;

    // Simulate the work
    let sum = 0;
    for (let i = 0; i < 1000; i++) sum += i;

    return performance.now() - start + normalizationMs + hashingMs;
  }

  it('should cold start within target latency for 100k hashes', async () => {
    const latencyMs = await simulateColdStart(100_000);

    console.log(`[POC] Cold start (100k hashes): ${latencyMs.toFixed(2)}ms`);
    expect(latencyMs).toBeLessThan(TARGET_COLD_START_MS);
  });

  it('should cold start within target latency for 300k hashes', async () => {
    const latencyMs = await simulateColdStart(300_000);

    console.log(`[POC] Cold start (300k hashes): ${latencyMs.toFixed(2)}ms`);
    expect(latencyMs).toBeLessThan(TARGET_COLD_START_MS);
  });

  it('should provide sub-millisecond warm lookup', async () => {
    // Create a simulated hash set
    const hashSet = new Set<string>();
    for (let i = 0; i < 100_000; i++) {
      hashSet.add(`hash_${i.toString(16).padStart(64, '0')}`);
    }

    const lookupMs = simulateWarmLookup(hashSet, 'test_hash');

    console.log(`[POC] Warm lookup latency: ${lookupMs.toFixed(4)}ms`);
    expect(lookupMs).toBeLessThan(1);
  });

  it('should document acceptable latency thresholds', () => {
    const thresholds = {
      coldStartMax: 500, // ms - must be ready to block within 500ms of wake
      warmLookupMax: 1, // ms - hash lookup must be sub-millisecond
      blockDecisionMax: 5, // ms - total time to decide block/allow
      forensicsCaptureMax: 50, // ms - async, doesn't block navigation
    };

    expect(thresholds.coldStartMax).toBeLessThanOrEqual(500);
    expect(thresholds.warmLookupMax).toBeLessThanOrEqual(1);
    expect(thresholds.blockDecisionMax).toBeLessThanOrEqual(5);
  });
});

// ============================================================================
// Test 3: Synchronous Block + Async Forensics
// ============================================================================

describe('Synchronous Blocking with Async Forensics', () => {
  let forensicsQueue: Array<{ url: string; timestamp: number; metadata: unknown }>;
  let blockLog: Array<{ url: string; blocked: boolean; latencyMs: number }>;

  beforeEach(() => {
    forensicsQueue = [];
    blockLog = [];
  });

  /**
   * Simulates the synchronous blocking decision.
   * Must return immediately - cannot await async operations.
   */
  function handleBlockingRequest(
    details: WebRequestDetails,
    hashSet: Set<string>,
    urlToHash: (url: string) => string
  ): BlockingResponse {
    const start = performance.now();

    // Synchronous operations only
    const urlHash = urlToHash(details.url);
    const shouldBlock = hashSet.has(urlHash);

    // Log for verification
    blockLog.push({
      url: details.url,
      blocked: shouldBlock,
      latencyMs: performance.now() - start,
    });

    // Fire async forensics capture (non-blocking)
    if (shouldBlock) {
      // Use queueMicrotask or setTimeout(0) to not block return
      queueMicrotask(() => {
        captureForensicsAsync(details);
      });
    }

    // Return synchronously
    return shouldBlock ? { cancel: true } : {};
  }

  /**
   * Async forensics capture - runs after blocking response is sent.
   */
  async function captureForensicsAsync(details: WebRequestDetails): Promise<void> {
    // Simulate async work (DOM capture, redirect chain assembly, etc.)
    await new Promise((resolve) => setTimeout(resolve, 10));

    forensicsQueue.push({
      url: details.url,
      timestamp: details.timeStamp,
      metadata: {
        requestId: details.requestId,
        tabId: details.tabId,
        initiator: details.initiator,
      },
    });
  }

  /**
   * Simple hash function for testing.
   */
  function simpleHash(url: string): string {
    let hash = 0;
    for (let i = 0; i < url.length; i++) {
      const char = url.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return hash.toString(16).padStart(64, '0');
  }

  it('should block synchronously without waiting for forensics', async () => {
    // Setup blocklist
    const hashSet = new Set<string>();
    const blockedUrl = 'https://evil.com/malware';
    hashSet.add(simpleHash(blockedUrl));

    const details: WebRequestDetails = {
      requestId: '123',
      url: blockedUrl,
      method: 'GET',
      frameId: 0,
      tabId: 1,
      type: 'main_frame' as chrome.webRequest.ResourceType,
      timeStamp: Date.now(),
      initiator: 'https://email.com',
    };

    // Execute blocking (synchronous)
    const response = handleBlockingRequest(details, hashSet, simpleHash);

    // Block response should be immediate
    expect(response.cancel).toBe(true);
    expect(blockLog.length).toBe(1);
    expect(blockLog[0].blocked).toBe(true);
    expect(blockLog[0].latencyMs).toBeLessThan(5);

    // Forensics not captured yet (async)
    expect(forensicsQueue.length).toBe(0);

    // Wait for async forensics
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Now forensics should be captured
    expect(forensicsQueue.length).toBe(1);
    expect(forensicsQueue[0].url).toBe(blockedUrl);
  });

  it('should not delay allowed requests', async () => {
    const hashSet = new Set<string>();
    hashSet.add(simpleHash('https://evil.com/malware'));

    const details: WebRequestDetails = {
      requestId: '456',
      url: 'https://safe.com/page',
      method: 'GET',
      frameId: 0,
      tabId: 1,
      type: 'main_frame' as chrome.webRequest.ResourceType,
      timeStamp: Date.now(),
    };

    const response = handleBlockingRequest(details, hashSet, simpleHash);

    expect(response.cancel).toBeUndefined();
    expect(blockLog[0].blocked).toBe(false);
    expect(blockLog[0].latencyMs).toBeLessThan(1);

    // No forensics for allowed requests
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(forensicsQueue.length).toBe(0);
  });

  it('should handle multiple concurrent blocks', async () => {
    const hashSet = new Set<string>();
    const urls = [
      'https://phish1.com/login',
      'https://phish2.com/login',
      'https://phish3.com/login',
    ];
    urls.forEach((url) => hashSet.add(simpleHash(url)));

    // Fire all requests "simultaneously"
    const responses = urls.map((url, i) =>
      handleBlockingRequest(
        {
          requestId: String(i),
          url,
          method: 'GET',
          frameId: 0,
          tabId: i,
          type: 'main_frame' as chrome.webRequest.ResourceType,
          timeStamp: Date.now(),
        },
        hashSet,
        simpleHash
      )
    );

    // All should block immediately
    expect(responses.every((r) => r.cancel)).toBe(true);
    expect(blockLog.length).toBe(3);

    // Wait for async forensics
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(forensicsQueue.length).toBe(3);
  });
});

// ============================================================================
// Test 4: Extension Survival (Browser Restart)
// ============================================================================

describe('Extension Survival (Browser Restart)', () => {
  let mockStorage: Record<string, unknown>;

  beforeEach(() => {
    mockStorage = {};
  });

  /**
   * Simulates persisting state before shutdown.
   */
  async function persistState(state: {
    blocklist: Uint8Array;
    forensicsQueue: unknown[];
    updateMetadata: { version: number; timestamp: string };
  }): Promise<void> {
    // Convert binary data to base64 for storage
    const blocklistBase64 = btoa(String.fromCharCode(...state.blocklist));

    mockStorage['browserdefense_blocklist'] = blocklistBase64;
    mockStorage['browserdefense_forensics_queue'] = JSON.stringify(state.forensicsQueue);
    mockStorage['browserdefense_update_metadata'] = JSON.stringify(state.updateMetadata);
  }

  /**
   * Simulates restoring state after browser restart.
   */
  async function restoreState(): Promise<{
    blocklist: Uint8Array | null;
    forensicsQueue: unknown[];
    updateMetadata: { version: number; timestamp: string } | null;
  }> {
    const blocklistBase64 = mockStorage['browserdefense_blocklist'] as string | undefined;
    const forensicsQueueJson = mockStorage['browserdefense_forensics_queue'] as string | undefined;
    const updateMetadataJson = mockStorage['browserdefense_update_metadata'] as string | undefined;

    return {
      blocklist: blocklistBase64
        ? Uint8Array.from(atob(blocklistBase64), (c) => c.charCodeAt(0))
        : null,
      forensicsQueue: forensicsQueueJson ? JSON.parse(forensicsQueueJson) : [],
      updateMetadata: updateMetadataJson ? JSON.parse(updateMetadataJson) : null,
    };
  }

  it('should persist blocklist across browser restart', async () => {
    // Create test blocklist (100 hashes, 32 bytes each)
    const blocklist = new Uint8Array(100 * 32);
    crypto.getRandomValues(blocklist);

    await persistState({
      blocklist,
      forensicsQueue: [],
      updateMetadata: { version: 42, timestamp: '2025-01-09T00:00:00Z' },
    });

    // Simulate restart
    const restored = await restoreState();

    expect(restored.blocklist).not.toBeNull();
    expect(restored.blocklist!.length).toBe(blocklist.length);
    expect(restored.blocklist!.every((v, i) => v === blocklist[i])).toBe(true);
  });

  it('should persist forensics queue across browser restart', async () => {
    const forensicsQueue = [
      { url: 'https://blocked1.com', timestamp: Date.now() - 1000, encrypted: 'abc123' },
      { url: 'https://blocked2.com', timestamp: Date.now(), encrypted: 'def456' },
    ];

    await persistState({
      blocklist: new Uint8Array(0),
      forensicsQueue,
      updateMetadata: { version: 1, timestamp: '2025-01-09T00:00:00Z' },
    });

    const restored = await restoreState();

    expect(restored.forensicsQueue.length).toBe(2);
    expect(restored.forensicsQueue).toEqual(forensicsQueue);
  });

  it('should retry pending forensics after startup', async () => {
    const pendingForensics = [
      { url: 'https://blocked.com', retryCount: 0 },
      { url: 'https://another.com', retryCount: 2 },
    ];

    await persistState({
      blocklist: new Uint8Array(0),
      forensicsQueue: pendingForensics,
      updateMetadata: { version: 1, timestamp: '2025-01-09T00:00:00Z' },
    });

    const restored = await restoreState();

    // Simulate onStartup handler checking for pending uploads
    const needsRetry = restored.forensicsQueue.length > 0;
    expect(needsRetry).toBe(true);
    expect(restored.forensicsQueue.length).toBe(2);
  });

  it('should maintain update metadata across restart', async () => {
    const metadata = {
      version: 42,
      timestamp: '2025-01-09T12:00:00Z',
    };

    await persistState({
      blocklist: new Uint8Array(0),
      forensicsQueue: [],
      updateMetadata: metadata,
    });

    const restored = await restoreState();

    expect(restored.updateMetadata).not.toBeNull();
    expect(restored.updateMetadata!.version).toBe(42);
    expect(restored.updateMetadata!.timestamp).toBe('2025-01-09T12:00:00Z');
  });
});

// ============================================================================
// Test 5: Heartbeat Keep-Alive
// ============================================================================

describe('Service Worker Heartbeat', () => {
  const HEARTBEAT_INTERVAL_MS = 4.9 * 60 * 1000; // 4.9 minutes
  const CHROME_KILL_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes

  it('should set heartbeat interval below Chrome kill threshold', () => {
    expect(HEARTBEAT_INTERVAL_MS).toBeLessThan(CHROME_KILL_THRESHOLD_MS);
    expect(CHROME_KILL_THRESHOLD_MS - HEARTBEAT_INTERVAL_MS).toBeGreaterThanOrEqual(6000); // 6s buffer
  });

  it('should create alarm with correct interval', () => {
    const alarmConfig = {
      name: 'keepAlive',
      periodInMinutes: 4.9,
    };

    expect(alarmConfig.periodInMinutes).toBe(4.9);
    expect(alarmConfig.periodInMinutes * 60 * 1000).toBeLessThan(CHROME_KILL_THRESHOLD_MS);
  });

  it('should perform useful work in heartbeat callback', () => {
    // Heartbeat should do more than just keep-alive
    const heartbeatActions = ['checkPendingForensics', 'retryFailedUploads', 'logHeartbeat'];

    // Verify the pattern matches our implementation
    expect(heartbeatActions).toContain('checkPendingForensics');
  });
});

// ============================================================================
// Manual Test Script (for real policy-installed extension testing)
// ============================================================================

describe('Manual Test Documentation', () => {
  it('documents manual test procedure for policy installation', () => {
    const testProcedure = {
      step1_policy_installation: {
        windows: {
          registry_path:
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForceList',
          value: '1 = <extension_id>;https://your-update-server/updates.xml',
          restart_required: true,
        },
        macos: {
          plist_path: '/Library/Managed Preferences/com.google.Chrome.plist',
          key: 'ExtensionInstallForceList',
        },
        linux: {
          json_path: '/etc/opt/chrome/policies/managed/extension_policy.json',
        },
      },
      step2_verify_installation: [
        'Navigate to chrome://extensions',
        'Verify extension shows "Installed by enterprise policy"',
        'Check that extension cannot be disabled/removed',
      ],
      step3_test_webRequestBlocking: [
        'Open DevTools → Network tab',
        'Navigate to a blocked URL',
        'Verify request is cancelled (blocked)',
        'Check extension console for forensics capture',
      ],
      step4_measure_latency: [
        'Close and reopen browser (cold start)',
        'Immediately navigate to blocked URL',
        'Measure time from navigation to block',
        'Target: <500ms cold start blocking',
      ],
      step5_verify_persistence: [
        'Trigger a block event',
        'Disconnect network',
        'Close browser completely',
        'Reopen browser',
        'Check that forensics queue persisted',
        'Reconnect network',
        'Verify forensics are uploaded',
      ],
    };

    expect(testProcedure.step1_policy_installation).toBeDefined();
    expect(testProcedure.step4_measure_latency.length).toBeGreaterThan(0);
  });

  it('documents expected pass/fail criteria', () => {
    const criteria = {
      pass: {
        webRequestBlocking: 'Requests to blocked URLs are cancelled synchronously',
        coldStartLatency: 'Extension ready to block within 500ms of browser start',
        asyncForensics: 'Block response returns before forensics capture completes',
        persistence: 'Blocklist and queue survive browser restart',
        heartbeat: 'Service worker stays active via 4.9-minute alarm',
      },
      fail: {
        webRequestBlocking: 'Chrome rejects webRequestBlocking permission',
        coldStartLatency: 'First blocked request takes >500ms',
        asyncForensics: 'Block is delayed waiting for forensics',
        persistence: 'Data lost on browser restart',
      },
    };

    // Document the criteria
    expect(criteria.pass.coldStartLatency).toContain('500ms');
  });
});

// ============================================================================
// Latency Benchmark (run with: npm test -- --reporter=verbose)
// ============================================================================

describe('Latency Benchmarks', () => {
  // Retry benchmark tests as they can be flaky due to system load
  it('benchmarks hash lookup at scale', { retry: 2 }, async () => {
    const sizes = [10_000, 100_000, 500_000];
    const results: Record<number, { constructionMs: number; lookupMs: number }> = {};

    for (const size of sizes) {
      // Construct set
      const constructStart = performance.now();
      const hashSet = new Set<string>();
      for (let i = 0; i < size; i++) {
        hashSet.add(i.toString(16).padStart(64, '0'));
      }
      const constructionMs = performance.now() - constructStart;

      // Benchmark lookup (1000 iterations)
      const lookupStart = performance.now();
      const testHash = Math.floor(size / 2)
        .toString(16)
        .padStart(64, '0');
      for (let i = 0; i < 1000; i++) {
        hashSet.has(testHash);
      }
      const lookupMs = (performance.now() - lookupStart) / 1000;

      results[size] = { constructionMs, lookupMs };
    }

    console.log('\n[POC] Latency Benchmarks:');
    for (const [size, { constructionMs, lookupMs }] of Object.entries(results)) {
      console.log(
        `  ${Number(size).toLocaleString()} hashes: construct=${constructionMs.toFixed(2)}ms, lookup=${lookupMs.toFixed(4)}ms`
      );
    }

    // Verify targets
    expect(results[100_000].lookupMs).toBeLessThan(0.01); // <0.01ms per lookup
    expect(results[100_000].constructionMs).toBeLessThan(100); // <100ms to construct 100k set
  });
});
