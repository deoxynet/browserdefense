/**
 * BrowserDefense Service Worker Heartbeat
 *
 * Implements the "Warm-Keep Protocol" to minimize service worker cold starts.
 * Chrome terminates inactive service workers after 5 minutes. We use a 4.9
 * minute alarm to keep the worker alive during active browsing sessions.
 */

import { checkPendingForensics } from './forensics';
import { checkPendingIngest } from './direct-ingest';

/** Heartbeat interval - just under Chrome's 5 minute limit */
const HEARTBEAT_INTERVAL_MINUTES = 4.9;

/** Alarm name for the heartbeat */
const HEARTBEAT_ALARM_NAME = 'keepAlive';

/** Track heartbeat count for diagnostics */
let heartbeatCount = 0;

/**
 * Initialize the heartbeat alarm.
 * Should be called once when the service worker starts.
 */
export async function initHeartbeat(): Promise<void> {
  // Clear any existing alarm first
  await chrome.alarms.clear(HEARTBEAT_ALARM_NAME);

  // Create the heartbeat alarm
  await chrome.alarms.create(HEARTBEAT_ALARM_NAME, {
    periodInMinutes: HEARTBEAT_INTERVAL_MINUTES,
  });

  console.log(`[BrowserDefense] Heartbeat initialized (${HEARTBEAT_INTERVAL_MINUTES} min interval)`);
}

/**
 * Handle heartbeat alarm.
 * Performs lightweight maintenance tasks to keep the worker useful.
 */
export async function handleHeartbeat(): Promise<void> {
  heartbeatCount++;
  const now = new Date().toISOString();

  console.log(`[BrowserDefense] Heartbeat #${heartbeatCount} at ${now}`);

  // Check for pending forensics uploads
  await checkPendingForensics();

  // Check for pending direct ingest items (Issue #398)
  await checkPendingIngest();
}

/**
 * Setup the alarm listener.
 * Should be called once during service worker initialization.
 */
export function setupHeartbeatListener(): void {
  chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === HEARTBEAT_ALARM_NAME) {
      await handleHeartbeat();
    }
  });
}

/**
 * Get heartbeat diagnostics.
 */
export function getHeartbeatStats(): { count: number; intervalMinutes: number } {
  return {
    count: heartbeatCount,
    intervalMinutes: HEARTBEAT_INTERVAL_MINUTES,
  };
}

/**
 * Force an immediate heartbeat.
 * Useful for testing or manual queue flush.
 */
export async function forceHeartbeat(): Promise<void> {
  console.log('[BrowserDefense] Forcing immediate heartbeat');
  await handleHeartbeat();
}
