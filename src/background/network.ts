/**
 * BrowserDefense Network Status & Stale-Protect Module
 *
 * Monitors network connectivity and blocklist freshness.
 * Provides graceful degradation when offline or stale.
 *
 * Key principles:
 * - Never fail-open: always use last-known-good blocklist
 * - Queue forensics locally when offline
 * - Visual indicators for ops visibility
 */

import { getUpdateMetadata } from './updates';

/** Storage key for network state */
const NETWORK_STATE_KEY = 'browserdefense_network_state';

/** Staleness thresholds (in milliseconds) */
export const STALE_WARNING_MS = 24 * 60 * 60 * 1000; // 24 hours
export const STALE_CRITICAL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days (configurable default)

/** Network status states */
export type NetworkStatus = 'online' | 'offline';

/** Blocklist freshness states */
export type FreshnessStatus = 'fresh' | 'stale' | 'critical';

/** Combined health status for UI */
export type HealthStatus = 'online' | 'stale' | 'offline' | 'critical';

/** Persisted network state */
export interface NetworkState {
  /** Current network status */
  networkStatus: NetworkStatus;
  /** Timestamp when status last changed */
  lastStatusChange: number;
  /** Last successful update attempt */
  lastSuccessfulUpdate: number | null;
  /** Last failed update attempt */
  lastFailedUpdate: number | null;
  /** Consecutive update failures */
  consecutiveFailures: number;
  /** Last error message */
  lastError: string | null;
}

/** Health check result for popup */
export interface HealthCheckResult {
  /** Overall health status */
  status: HealthStatus;
  /** Human-readable status message */
  message: string;
  /** Whether currently online */
  isOnline: boolean;
  /** Whether blocklist is stale (>24h old) */
  isStale: boolean;
  /** Whether blocklist is critically stale (>7d old) */
  isCritical: boolean;
  /** Blocklist age in milliseconds */
  blocklistAgeMs: number | null;
  /** Consecutive update failures */
  consecutiveFailures: number;
  /** Last error if any */
  lastError: string | null;
}

/** Default network state */
const DEFAULT_STATE: NetworkState = {
  networkStatus: 'online',
  lastStatusChange: Date.now(),
  lastSuccessfulUpdate: null,
  lastFailedUpdate: null,
  consecutiveFailures: 0,
  lastError: null,
};

/**
 * Get the current network state from storage.
 */
export async function getNetworkState(): Promise<NetworkState> {
  const result = await chrome.storage.local.get(NETWORK_STATE_KEY);
  return result[NETWORK_STATE_KEY] || { ...DEFAULT_STATE };
}

/**
 * Save network state to storage.
 */
async function saveNetworkState(state: NetworkState): Promise<void> {
  await chrome.storage.local.set({ [NETWORK_STATE_KEY]: state });
}

/**
 * Update network status based on browser's navigator.onLine.
 */
export async function updateNetworkStatus(): Promise<NetworkStatus> {
  const isOnline = typeof navigator !== 'undefined' ? navigator.onLine : true;
  const status: NetworkStatus = isOnline ? 'online' : 'offline';

  const state = await getNetworkState();

  if (state.networkStatus !== status) {
    state.networkStatus = status;
    state.lastStatusChange = Date.now();
    await saveNetworkState(state);

    console.log(`[BrowserDefense] Network status changed to: ${status}`);
  }

  return status;
}

/**
 * Record a successful update.
 */
export async function recordUpdateSuccess(): Promise<void> {
  const state = await getNetworkState();

  state.lastSuccessfulUpdate = Date.now();
  state.consecutiveFailures = 0;
  state.lastError = null;

  await saveNetworkState(state);

  console.log('[BrowserDefense] Update success recorded');
}

/**
 * Record a failed update attempt.
 */
export async function recordUpdateFailure(error: string): Promise<void> {
  const state = await getNetworkState();

  state.lastFailedUpdate = Date.now();
  state.consecutiveFailures++;
  state.lastError = error;

  await saveNetworkState(state);

  console.warn(`[BrowserDefense] Update failure recorded (${state.consecutiveFailures} consecutive): ${error}`);
}

/**
 * Get blocklist freshness status based on age.
 */
export function getFreshnessStatus(ageMs: number | null, criticalMs: number = STALE_CRITICAL_MS): FreshnessStatus {
  if (ageMs === null) {
    return 'fresh'; // No blocklist yet, not considered stale
  }

  if (ageMs >= criticalMs) {
    return 'critical';
  }

  if (ageMs >= STALE_WARNING_MS) {
    return 'stale';
  }

  return 'fresh';
}

/**
 * Perform a health check and return combined status.
 * This is the main entry point for the popup to get current status.
 */
export async function performHealthCheck(): Promise<HealthCheckResult> {
  const [_state, updateMeta] = await Promise.all([getNetworkState(), getUpdateMetadata()]);

  // Update network status first
  await updateNetworkStatus();
  const currentState = await getNetworkState();

  // Calculate blocklist age
  const blocklistAgeMs = updateMeta?.updatedAt ? Date.now() - updateMeta.updatedAt : null;

  // Determine freshness
  const freshness = getFreshnessStatus(blocklistAgeMs);
  const isStale = freshness === 'stale' || freshness === 'critical';
  const isCritical = freshness === 'critical';

  // Determine overall status
  let status: HealthStatus;
  let message: string;

  if (currentState.networkStatus === 'offline') {
    status = 'offline';
    message = 'Offline - using cached blocklist';
  } else if (isCritical) {
    status = 'critical';
    message = 'Blocklist critically outdated (>7 days)';
  } else if (isStale) {
    status = 'stale';
    message = 'Blocklist outdated (>24 hours)';
  } else {
    status = 'online';
    message = 'Protected';
  }

  // Log for ops visibility
  if (isStale) {
    const ageHours = blocklistAgeMs ? Math.floor(blocklistAgeMs / (60 * 60 * 1000)) : 0;
    console.log(`[BrowserDefense] Staleness warning: blocklist is ${ageHours} hours old`);
  }

  return {
    status,
    message,
    isOnline: currentState.networkStatus === 'online',
    isStale,
    isCritical,
    blocklistAgeMs,
    consecutiveFailures: currentState.consecutiveFailures,
    lastError: currentState.lastError,
  };
}

/**
 * Format blocklist age for display.
 */
export function formatBlocklistAge(ageMs: number | null): string {
  if (ageMs === null) {
    return 'Never updated';
  }

  const seconds = Math.floor(ageMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days === 1) return '1 day ago';
  return `${days} days ago`;
}

/**
 * Initialize network monitoring.
 * Sets up listeners for online/offline events.
 */
export function initNetworkMonitoring(): void {
  // Note: In MV3 service workers, we can't use addEventListener on self for online/offline
  // We rely on periodic health checks via heartbeat instead
  console.log('[BrowserDefense] Network monitoring initialized');

  // Do initial status check
  updateNetworkStatus().catch((err) => {
    console.error('[BrowserDefense] Initial network status check failed:', err);
  });
}
