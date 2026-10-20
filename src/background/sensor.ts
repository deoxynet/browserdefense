/**
 * Sensor Mode - FCM Listener + DNR Update + Ack Jitter
 *
 * Implements fleet-side listener that receives BLOCK commands via FCM
 * and returns acknowledgements with jitter.
 *
 * Features:
 * - Uses chrome.gcm to listen for messages
 * - On { type: 'BLOCK', ioc: '...' }, updates DNR dynamic rules immediately
 * - Collects hostname/username from managed storage or identity
 * - Sends fire-and-forget POST to /ack with jitter 0-3000ms (keepalive: true)
 *
 * @see Issue #400
 */

import { addDNRRule, removeDNRRule, isDNRAvailable } from './dnr';
import {
  initDOMSignatureStore,
  addDOMSignature,
  removeDOMSignature,
  saveDOMSignatureStore,
} from '../storage/dom-sig-store';
import type {
  DOMSignatureEntry,
  FCMDOMSigBlockMessage,
  FCMDOMSigUnblockMessage,
  FCMDOMSigShadowMessage,
} from '../types/dom-sig-manifest';

/** Storage key for sensor mode configuration */
const SENSOR_CONFIG_KEY = 'blockioc_sensor_config';

/** Storage key for host identity */
const HOST_IDENTITY_KEY = 'blockioc_host_identity';

/** Maximum jitter in milliseconds for ack */
const MAX_ACK_JITTER_MS = 3000;

/**
 * FCM message types supported by sensor mode.
 */
export type FCMMessageType =
  | 'BLOCK'
  | 'UNBLOCK'
  | 'PING'
  | 'DOM_SIG_BLOCK'
  | 'DOM_SIG_UNBLOCK'
  | 'DOM_SIG_SHADOW';

/**
 * FCM message payload for BLOCK commands.
 */
export interface FCMBlockMessage {
  type: 'BLOCK';
  /** IOC to block (URL or domain) */
  ioc: string;
  /** Operation ID for acknowledgement */
  op_id: string;
  /** Optional reason for blocking */
  reason?: string;
}

/**
 * FCM message payload for UNBLOCK commands.
 */
export interface FCMUnblockMessage {
  type: 'UNBLOCK';
  /** IOC to unblock */
  ioc: string;
  /** Operation ID for acknowledgement */
  op_id: string;
}

/**
 * FCM message payload for PING (health check).
 */
export interface FCMPingMessage {
  type: 'PING';
  /** Operation ID for acknowledgement */
  op_id: string;
}

/**
 * Union type for all FCM messages.
 */
export type FCMMessage =
  | FCMBlockMessage
  | FCMUnblockMessage
  | FCMPingMessage
  | FCMDOMSigBlockMessage
  | FCMDOMSigUnblockMessage
  | FCMDOMSigShadowMessage;

/**
 * Sensor mode configuration.
 */
export interface SensorConfig {
  /** Whether sensor mode is enabled */
  enabled: boolean;
  /** GCM sender ID for FCM registration */
  gcm_sender_id: string;
  /** Endpoint to send ack POST requests */
  ack_endpoint: string;
}

/**
 * Host identity for ack payloads.
 */
export interface HostIdentity {
  /** Hostname of this machine */
  hostname: string;
  /** Username of the logged-in user */
  username: string;
}

/**
 * Acknowledgement payload sent to /ack endpoint.
 */
export interface AckPayload {
  /** Operation ID from FCM message */
  op_id: string;
  /** Hostname of this machine */
  host: string;
  /** Username of the logged-in user */
  user: string;
  /** Result of the operation */
  result: 'success' | 'error';
  /** Error message if result is 'error' */
  error?: string;
  /** Timestamp of the ack */
  timestamp: number;
}

/**
 * Get sensor configuration from storage.
 */
export async function getSensorConfig(): Promise<SensorConfig | null> {
  const result = await chrome.storage.local.get(SENSOR_CONFIG_KEY);
  return result[SENSOR_CONFIG_KEY] || null;
}

/**
 * Save sensor configuration to storage.
 */
export async function saveSensorConfig(config: SensorConfig): Promise<void> {
  await chrome.storage.local.set({ [SENSOR_CONFIG_KEY]: config });
  console.log('[BrowserDefense] Sensor config saved');
}

/**
 * Get host identity from managed storage, identity API, or local storage.
 *
 * Priority:
 * 1. Managed storage (enterprise GPO)
 * 2. Chrome identity API
 * 3. Local storage cache
 * 4. Default values
 */
export async function getHostIdentity(): Promise<HostIdentity> {
  // Try managed storage first (enterprise deployment)
  try {
    const managed = await chrome.storage.managed.get(['hostname', 'username']);
    if (managed.hostname && managed.username) {
      return {
        hostname: managed.hostname,
        username: managed.username,
      };
    }
  } catch {
    // Managed storage may not be available
  }

  // Try to get from local storage cache
  const cached = await chrome.storage.local.get(HOST_IDENTITY_KEY);
  if (cached[HOST_IDENTITY_KEY]) {
    return cached[HOST_IDENTITY_KEY];
  }

  // Try Chrome identity API for email as username
  let username = 'unknown';
  try {
    // Use callback-style API for better compatibility
    const userInfo = await new Promise<chrome.identity.UserInfo>((resolve, reject) => {
      chrome.identity.getProfileUserInfo((info) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve(info);
        }
      });
    });
    if (userInfo.email) {
      username = userInfo.email;
    }
  } catch {
    // Identity API may not be available
  }

  // Default hostname - in browser extension context we don't have real hostname
  // This should be provided via managed storage in enterprise deployments
  const identity: HostIdentity = {
    hostname: 'browser-agent',
    username,
  };

  // Cache for future use
  await chrome.storage.local.set({ [HOST_IDENTITY_KEY]: identity });

  return identity;
}

/**
 * Save host identity to local storage.
 */
export async function setHostIdentity(identity: HostIdentity): Promise<void> {
  await chrome.storage.local.set({ [HOST_IDENTITY_KEY]: identity });
  console.log('[BrowserDefense] Host identity saved');
}

/**
 * Apply random jitter delay (0-3000ms).
 */
function applyJitter(): Promise<void> {
  const delay = Math.floor(Math.random() * MAX_ACK_JITTER_MS);
  return new Promise((resolve) => setTimeout(resolve, delay));
}

/**
 * Send fire-and-forget ack POST with jitter.
 *
 * Uses keepalive: true to ensure request completes even if service worker terminates.
 * Does not block the main handler.
 */
async function sendAck(
  endpoint: string,
  payload: AckPayload
): Promise<void> {
  // Apply jitter (0-3000ms)
  await applyJitter();

  try {
    // Fire and forget with keepalive
    fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      keepalive: true, // Ensures request completes even if SW terminates
    }).catch((err) => {
      // Log but don't throw - this is fire-and-forget
      console.warn('[BrowserDefense] Ack POST failed:', err);
    });

    console.log(`[BrowserDefense] Ack sent for op_id=${payload.op_id}`);
  } catch (err) {
    console.warn('[BrowserDefense] Ack failed:', err);
  }
}

/**
 * Handle incoming FCM BLOCK message.
 *
 * Updates DNR rules immediately and sends ack with jitter.
 */
async function handleBlockMessage(
  message: FCMBlockMessage,
  config: SensorConfig
): Promise<void> {
  console.log(`[BrowserDefense] BLOCK command received: ioc=${message.ioc}, op_id=${message.op_id}`);

  const identity = await getHostIdentity();
  let result: 'success' | 'error' = 'success';
  let error: string | undefined;

  // Update DNR rules immediately
  if (isDNRAvailable()) {
    try {
      const ruleCount = await addDNRRule(message.ioc);
      console.log(`[BrowserDefense] DNR rule added for ${message.ioc}, total rules: ${ruleCount}`);
    } catch (err) {
      result = 'error';
      error = err instanceof Error ? err.message : String(err);
      console.error('[BrowserDefense] Failed to add DNR rule:', err);
    }
  } else {
    result = 'error';
    error = 'DNR not available';
    console.warn('[BrowserDefense] DNR not available, cannot add rule');
  }

  // Send ack with jitter (fire-and-forget, does not block)
  const ackPayload: AckPayload = {
    op_id: message.op_id,
    host: identity.hostname,
    user: identity.username,
    result,
    error,
    timestamp: Date.now(),
  };

  // Don't await - fire and forget
  sendAck(config.ack_endpoint, ackPayload);
}

/**
 * Handle incoming FCM PING message.
 *
 * Just sends an ack to confirm connectivity.
 */
async function handlePingMessage(
  message: FCMPingMessage,
  config: SensorConfig
): Promise<void> {
  console.log(`[BrowserDefense] PING received: op_id=${message.op_id}`);

  const identity = await getHostIdentity();

  const ackPayload: AckPayload = {
    op_id: message.op_id,
    host: identity.hostname,
    user: identity.username,
    result: 'success',
    timestamp: Date.now(),
  };

  // Don't await - fire and forget
  sendAck(config.ack_endpoint, ackPayload);
}

/**
 * Handle incoming FCM UNBLOCK message.
 *
 * Removes DNR rule for the specified IOC and sends ack with jitter.
 */
async function handleUnblockMessage(
  message: FCMUnblockMessage,
  config: SensorConfig
): Promise<void> {
  console.log(`[BrowserDefense] UNBLOCK command received: ioc=${message.ioc}, op_id=${message.op_id}`);

  const identity = await getHostIdentity();
  let result: 'success' | 'error' = 'success';
  let error: string | undefined;

  // Remove DNR rule immediately
  if (isDNRAvailable()) {
    try {
      const ruleCount = await removeDNRRule(message.ioc);
      console.log(`[BrowserDefense] DNR rule removed for ${message.ioc}, total rules: ${ruleCount}`);
    } catch (err) {
      result = 'error';
      error = err instanceof Error ? err.message : String(err);
      console.error('[BrowserDefense] Failed to remove DNR rule:', err);
    }
  } else {
    result = 'error';
    error = 'DNR not available';
    console.warn('[BrowserDefense] DNR not available, cannot remove rule');
  }

  // Send ack with jitter (fire-and-forget, does not block)
  const ackPayload: AckPayload = {
    op_id: message.op_id,
    host: identity.hostname,
    user: identity.username,
    result,
    error,
    timestamp: Date.now(),
  };

  // Don't await - fire and forget
  sendAck(config.ack_endpoint, ackPayload);
}

/**
 * Handle incoming FCM DOM_SIG_BLOCK message.
 *
 * Adds a DOM signature to the local threat intel store.
 */
async function handleDOMSigBlockMessage(
  message: FCMDOMSigBlockMessage,
  config: SensorConfig
): Promise<void> {
  console.log(
    `[BrowserDefense] DOM_SIG_BLOCK command received: hash=${message.hash.slice(0, 16)}..., ` +
    `op_id=${message.op_id}`
  );

  const identity = await getHostIdentity();
  let result: 'success' | 'error' = 'success';
  let error: string | undefined;

  try {
    // Initialize store if needed
    await initDOMSignatureStore();

    // Build signature entry
    const entry: DOMSignatureEntry = {
      hash: message.hash,
      confidence: message.confidence,
      action: 'block',
      kitId: message.kitId,
      lsh: message.lsh,
      similarityThreshold: message.similarityThreshold,
    };

    // Add to store
    addDOMSignature(entry);
    await saveDOMSignatureStore();

    console.log(`[BrowserDefense] DOM signature added: ${message.hash.slice(0, 16)}...`);
  } catch (err) {
    result = 'error';
    error = err instanceof Error ? err.message : String(err);
    console.error('[BrowserDefense] Failed to add DOM signature:', err);
  }

  // Send ack with jitter
  const ackPayload: AckPayload = {
    op_id: message.op_id,
    host: identity.hostname,
    user: identity.username,
    result,
    error,
    timestamp: Date.now(),
  };

  sendAck(config.ack_endpoint, ackPayload);
}

/**
 * Handle incoming FCM DOM_SIG_UNBLOCK message.
 *
 * Removes a DOM signature from the local threat intel store.
 */
async function handleDOMSigUnblockMessage(
  message: FCMDOMSigUnblockMessage,
  config: SensorConfig
): Promise<void> {
  console.log(
    `[BrowserDefense] DOM_SIG_UNBLOCK command received: hash=${message.hash.slice(0, 16)}..., ` +
    `op_id=${message.op_id}`
  );

  const identity = await getHostIdentity();
  let result: 'success' | 'error' = 'success';
  let error: string | undefined;

  try {
    // Initialize store if needed
    await initDOMSignatureStore();

    // Remove from store
    const removed = removeDOMSignature(message.hash);
    if (removed) {
      await saveDOMSignatureStore();
      console.log(`[BrowserDefense] DOM signature removed: ${message.hash.slice(0, 16)}...`);
    } else {
      console.log(`[BrowserDefense] DOM signature not found: ${message.hash.slice(0, 16)}...`);
    }
  } catch (err) {
    result = 'error';
    error = err instanceof Error ? err.message : String(err);
    console.error('[BrowserDefense] Failed to remove DOM signature:', err);
  }

  // Send ack with jitter
  const ackPayload: AckPayload = {
    op_id: message.op_id,
    host: identity.hostname,
    user: identity.username,
    result,
    error,
    timestamp: Date.now(),
  };

  sendAck(config.ack_endpoint, ackPayload);
}

/**
 * Handle incoming FCM DOM_SIG_SHADOW message.
 *
 * Adds a DOM signature to shadow mode (alert only, no blocking).
 */
async function handleDOMSigShadowMessage(
  message: FCMDOMSigShadowMessage,
  config: SensorConfig
): Promise<void> {
  console.log(
    `[BrowserDefense] DOM_SIG_SHADOW command received: hash=${message.hash.slice(0, 16)}..., ` +
    `op_id=${message.op_id}`
  );

  const identity = await getHostIdentity();
  let result: 'success' | 'error' = 'success';
  let error: string | undefined;

  try {
    // Initialize store if needed
    await initDOMSignatureStore();

    // Build signature entry with shadow action
    const entry: DOMSignatureEntry = {
      hash: message.hash,
      confidence: message.confidence,
      action: 'shadow',
      kitId: message.kitId,
    };

    // Add to store
    addDOMSignature(entry);
    await saveDOMSignatureStore();

    console.log(`[BrowserDefense] DOM signature added to shadow: ${message.hash.slice(0, 16)}...`);
  } catch (err) {
    result = 'error';
    error = err instanceof Error ? err.message : String(err);
    console.error('[BrowserDefense] Failed to add DOM signature to shadow:', err);
  }

  // Send ack with jitter
  const ackPayload: AckPayload = {
    op_id: message.op_id,
    host: identity.hostname,
    user: identity.username,
    result,
    error,
    timestamp: Date.now(),
  };

  sendAck(config.ack_endpoint, ackPayload);
}

/**
 * Parse and validate FCM message data.
 */
function parseFCMMessage(data: { [key: string]: string }): FCMMessage | null {
  const type = data.type as FCMMessageType | undefined;

  if (!type || !data.op_id) {
    console.warn('[BrowserDefense] Invalid FCM message: missing type or op_id');
    return null;
  }

  switch (type) {
    case 'BLOCK':
      if (!data.ioc) {
        console.warn('[BrowserDefense] Invalid BLOCK message: missing ioc');
        return null;
      }
      return {
        type: 'BLOCK',
        ioc: data.ioc,
        op_id: data.op_id,
        reason: data.reason,
      };

    case 'UNBLOCK':
      if (!data.ioc) {
        console.warn('[BrowserDefense] Invalid UNBLOCK message: missing ioc');
        return null;
      }
      return {
        type: 'UNBLOCK',
        ioc: data.ioc,
        op_id: data.op_id,
      };

    case 'PING':
      return {
        type: 'PING',
        op_id: data.op_id,
      };

    case 'DOM_SIG_BLOCK':
      if (!data.hash) {
        console.warn('[BrowserDefense] Invalid DOM_SIG_BLOCK message: missing hash');
        return null;
      }
      return {
        type: 'DOM_SIG_BLOCK',
        hash: data.hash,
        op_id: data.op_id,
        confidence: parseInt(data.confidence || '80', 10),
        kitId: data.kitId,
        lsh: data.lsh_dom_layout
          ? {
              dom_layout: data.lsh_dom_layout,
              form_structure: data.lsh_form_structure || '',
              script_structure: data.lsh_script_structure || '',
            }
          : undefined,
        similarityThreshold: data.similarityThreshold
          ? parseFloat(data.similarityThreshold)
          : undefined,
      };

    case 'DOM_SIG_UNBLOCK':
      if (!data.hash) {
        console.warn('[BrowserDefense] Invalid DOM_SIG_UNBLOCK message: missing hash');
        return null;
      }
      return {
        type: 'DOM_SIG_UNBLOCK',
        hash: data.hash,
        op_id: data.op_id,
      };

    case 'DOM_SIG_SHADOW':
      if (!data.hash) {
        console.warn('[BrowserDefense] Invalid DOM_SIG_SHADOW message: missing hash');
        return null;
      }
      return {
        type: 'DOM_SIG_SHADOW',
        hash: data.hash,
        op_id: data.op_id,
        confidence: parseInt(data.confidence || '50', 10),
        kitId: data.kitId,
      };

    default:
      console.warn(`[BrowserDefense] Unknown FCM message type: ${type}`);
      return null;
  }
}

/**
 * FCM message handler.
 */
async function handleFCMMessage(messageData: { [key: string]: string }): Promise<void> {
  const config = await getSensorConfig();

  if (!config?.enabled) {
    console.log('[BrowserDefense] Sensor mode not enabled, ignoring FCM message');
    return;
  }

  const message = parseFCMMessage(messageData);
  if (!message) {
    return;
  }

  switch (message.type) {
    case 'BLOCK':
      await handleBlockMessage(message, config);
      break;

    case 'PING':
      await handlePingMessage(message, config);
      break;

    case 'UNBLOCK':
      await handleUnblockMessage(message, config);
      break;

    case 'DOM_SIG_BLOCK':
      await handleDOMSigBlockMessage(message, config);
      break;

    case 'DOM_SIG_UNBLOCK':
      await handleDOMSigUnblockMessage(message, config);
      break;

    case 'DOM_SIG_SHADOW':
      await handleDOMSigShadowMessage(message, config);
      break;
  }
}

/**
 * Initialize sensor mode.
 *
 * Sets up GCM message listener if sensor mode is enabled.
 */
export async function initSensorMode(): Promise<void> {
  const config = await getSensorConfig();

  if (!config?.enabled) {
    console.log('[BrowserDefense] Sensor mode not enabled');
    return;
  }

  console.log('[BrowserDefense] Initializing sensor mode...');

  // Register for GCM
  try {
    // Note: chrome.gcm.register is deprecated but still functional
    // The sender ID should be configured via sensor config
    chrome.gcm.register([config.gcm_sender_id], (registrationId) => {
      if (chrome.runtime.lastError) {
        console.error('[BrowserDefense] GCM registration failed:', chrome.runtime.lastError);
        return;
      }
      console.log('[BrowserDefense] GCM registered, ID:', registrationId.slice(0, 20) + '...');
    });
  } catch (err) {
    console.error('[BrowserDefense] GCM registration error:', err);
  }

  console.log('[BrowserDefense] Sensor mode initialized');
}

/**
 * Set up GCM message listener.
 *
 * This should be called once during service worker initialization.
 */
export function setupGCMListener(): void {
  chrome.gcm.onMessage.addListener((message) => {
    console.log('[BrowserDefense] GCM message received');

    // Handle message asynchronously
    // Cast data to expected type - GCM messages have string key-value pairs
    const data = (message.data || {}) as { [key: string]: string };
    handleFCMMessage(data).catch((err) => {
      console.error('[BrowserDefense] Error handling FCM message:', err);
    });
  });

  console.log('[BrowserDefense] GCM listener registered');
}

/**
 * Check if GCM is available.
 */
export function isGCMAvailable(): boolean {
  return typeof chrome.gcm !== 'undefined';
}

/**
 * Get sensor mode statistics.
 */
export async function getSensorStats(): Promise<{
  enabled: boolean;
  gcmAvailable: boolean;
  hasConfig: boolean;
  identity: HostIdentity | null;
}> {
  const config = await getSensorConfig();
  let identity: HostIdentity | null = null;

  if (config?.enabled) {
    identity = await getHostIdentity();
  }

  return {
    enabled: config?.enabled ?? false,
    gcmAvailable: isGCMAvailable(),
    hasConfig: config !== null,
    identity,
  };
}
