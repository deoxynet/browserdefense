/**
 * BrowserDefense Service Worker
 * Main entry point for the extension background script.
 *
 * Implements:
 * - Navigation blocking via webNavigation API
 * - Heartbeat to keep service worker alive (4.9 min interval)
 * - Forensics queue for offline resilience
 * - Install/update lifecycle handlers
 */

import { initBlocking, setupNavigationBlocking, reloadBlocklist, reloadDemoConfig, getBlocklistInfo, isBlocked, updateBlocklistWithPriority, getDemoModeStatus } from './blocking';
import type { PrioritizedIOC } from '../ioc/priority';
import { initHeartbeat, setupHeartbeatListener, forceHeartbeat, getHeartbeatStats } from './heartbeat';
import {
  initForensicsQueue,
  retryPendingUploads,
  uploadForensics,
  getPendingCount,
  checkPendingForensics,
  getQueue,
  getEncryptionFunction,
  type ForensicsPayload,
} from './forensics';
import { getUpdateMetadata, forceUpdate, scheduleUpdates, handleUpdateAlarm } from './updates';
import { loadConfig } from '../config/loader';
import {
  initNetworkMonitoring,
  performHealthCheck,
  recordUpdateSuccess,
  recordUpdateFailure,
  type HealthCheckResult,
} from './network';
import { handleSkeletonMessage, type FingerprintResponse } from './fingerprint-uplink';
import { initFormSchemaStore, storeFormSchemas } from './form-schema-store';
import type { FormSchema } from '../content/form-schema';
import {
  initializeHistoryBloom,
  scheduleHistoryBloomUpdates,
  isDomainInHistory,
  getHistoryBloomStats,
  enableHistoryBloom,
  disableHistoryBloom,
  requestHistoryPermission,
  checkHistoryPermission,
  rebuildHistoryBloom,
} from './history-bloom';
import {
  getShadowDetectionConfig,
  updateShadowDetectionConfig,
  listDetections,
  getDetection,
  promoteDetection,
  dismissDetection,
  deleteDetection,
  getDetectionStats,
  cleanupDetections,
  type ShadowDetectionConfig,
  type ShadowDetectionQuery,
} from './shadow-detection';
import {
  initTLSCapture,
  setupTLSCleanup,
  getTLSCaptureConfig,
  updateTLSCaptureConfig,
  clearEnrichmentCache,
  getEnrichmentCacheStats,
  type TLSCaptureConfig,
} from './tls-metadata';
import {
  getEDREnrichmentConfig,
  updateEDREnrichmentConfig,
  getArtifact,
  listArtifacts,
  clearArtifacts,
  exportArtifact,
  setupEDREnrichmentCleanup,
  type EDREnrichmentConfig,
} from './edr-enrichment';
import type { EDRExportFormat } from '../types/edr-enrichment';
import {
  initSensorMode,
  setupGCMListener,
  getSensorConfig,
  saveSensorConfig,
  getSensorStats,
  getHostIdentity,
  setHostIdentity,
  type SensorConfig,
  type HostIdentity,
} from './sensor';
import {
  initAuthMonitoring,
  onAuthStateChange,
  getAuthState,
  isHunterMode,
  type AuthState,
} from './auth';
import { initHunterMenu, updateHunterMenu, broadcastIOCs } from './hunter-menu';
import { extractIOCs } from './ioc-extractor';
import {
  initDirectIngest,
  getSiemEndpoints,
  getSiemEndpoint,
  addSiemEndpoint,
  removeSiemEndpoint,
  updateSiemEndpoint,
  sendToSiem,
  sendToAllSiems,
  getIngestQueue,
  getIngestQueueStats,
  clearIngestQueue,
  removeFromIngestQueue,
  retryPendingIngest,
  requestSiemPermission,
  hasPermission,
  loadIngestConfig,
  saveIngestConfig,
} from './direct-ingest';
import type { SiemEndpoint, DirectIngestConfig } from '../types/direct-ingest';

console.log('[BrowserDefense] Service worker started');

/**
 * Initialize all service worker components.
 */
async function initialize(): Promise<void> {
  console.log('[BrowserDefense] Initializing...');

  // Initialize network monitoring
  initNetworkMonitoring();

  // Initialize form schema store (for capturing form metadata on blocked pages)
  initFormSchemaStore();

  // Initialize TLS metadata capture (for capturing certificate info on blocked pages)
  // Note: Certificate details require server-side enrichment (Chrome API limitation)
  initTLSCapture();
  setupTLSCleanup();

  // Initialize EDR enrichment export (read-only forensic artifact export, Issue #169)
  setupEDREnrichmentCleanup();

  // Initialize forensics queue (restores badge state)
  await initForensicsQueue();

  // Initialize blocking system
  await initBlocking();
  setupNavigationBlocking();

  // Initialize heartbeat
  await initHeartbeat();
  setupHeartbeatListener();

  // Initialize scheduled updates if config exists
  await initScheduledUpdates();

  // Initialize history-derived Bloom filter (opt-in feature, Issue #161)
  await initializeHistoryBloom();
  scheduleHistoryBloomUpdates();

  // Clean up expired shadow detections (Issue #171)
  cleanupDetections().catch((err) => {
    console.warn('[BrowserDefense] Shadow detection cleanup failed:', err);
  });

  // Initialize sensor mode (Issue #400)
  // Sets up GCM listener for FCM BLOCK commands
  setupGCMListener();
  await initSensorMode();

  // Initialize dual-mode auth system (Issue #399)
  initAuthMonitoring();
  const authState = await getAuthState();
  await initHunterMenu(authState);

  // Watch for auth state changes to update hunter menu
  onAuthStateChange(async (state: AuthState) => {
    await updateHunterMenu(state);
  });

  // Initialize direct ingest for on-prem SIEM delivery (Issue #398)
  await initDirectIngest();

  console.log('[BrowserDefense] Initialization complete');
}

/**
 * Initialize scheduled blocklist updates from stored config.
 */
async function initScheduledUpdates(): Promise<void> {
  const config = await loadConfig();

  if (!config) {
    console.log('[BrowserDefense] No config found, skipping update scheduling');
    return;
  }

  try {
    await scheduleUpdates(
      {
        endpoint: config.blocklist_endpoint,
        publicKey: config.signing_public_key,
      },
      config.update_interval_minutes ?? 60
    );
    console.log('[BrowserDefense] Update scheduling initialized');
  } catch (err) {
    console.error('[BrowserDefense] Failed to initialize update scheduling:', err);
  }
}

// Run initialization
initialize().catch((error) => {
  console.error('[BrowserDefense] Initialization failed:', error);
});

// Extension lifecycle: Install
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log(`[BrowserDefense] Extension ${details.reason}:`, details);

  if (details.reason === 'install') {
    // First install - set default config
    console.log('[BrowserDefense] First install, setting defaults');
  } else if (details.reason === 'update') {
    // Extension updated
    console.log(`[BrowserDefense] Updated from ${details.previousVersion}`);

    // Retry any pending forensics after update
    const pendingCount = await getPendingCount();
    if (pendingCount > 0) {
      console.log(`[BrowserDefense] Retrying ${pendingCount} pending forensics after update`);
      await retryPendingUploads();
    }
  }
});

// Extension lifecycle: Startup (browser restart)
chrome.runtime.onStartup.addListener(async () => {
  console.log('[BrowserDefense] Browser started');

  // Check for pending forensics on browser startup
  await checkPendingForensics();
});

// Listen for blocklist updates from storage
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && changes.browserdefense_blocklist) {
    console.log('[BrowserDefense] Blocklist changed, reloading...');
    reloadBlocklist();
  }
});

// Alarm listener for scheduled blocklist updates
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'browserdefense_blocklist_update') {
    console.log('[BrowserDefense] Blocklist update alarm fired');
    try {
      const result = await handleUpdateAlarm();
      if (!result) {
        return; // No config, nothing to do
      }
      if (result.success) {
        await recordUpdateSuccess();
        console.log(`[BrowserDefense] Scheduled update succeeded: v${result.version}`);
      } else {
        const errorMsg = (result as { error: string }).error;
        await recordUpdateFailure(errorMsg);
        console.warn(`[BrowserDefense] Scheduled update failed: ${errorMsg}`);
      }
    } catch (err) {
      await recordUpdateFailure(String(err));
      console.error('[BrowserDefense] Scheduled update error:', err);
    }
  }
});

/**
 * Message types for popup and options page communication.
 */
interface PopupMessage {
  type:
    | 'getPopupData'
    | 'forceUpdate'
    | 'retryUploads'
    | 'reloadBlocklist'
    | 'checkBlocked'
    | 'configUpdated'
    | 'configCleared'
    // Demo mode (Issue #571)
    | 'demoConfigUpdated'
    | 'getDemoStatus'
    | 'historyBloom_getStats'
    | 'historyBloom_enable'
    | 'historyBloom_disable'
    | 'historyBloom_requestPermission'
    | 'historyBloom_checkPermission'
    | 'historyBloom_rebuild'
    // Shadow detection management (Issue #171)
    | 'shadowDetection_getConfig'
    | 'shadowDetection_updateConfig'
    | 'shadowDetection_list'
    | 'shadowDetection_get'
    | 'shadowDetection_promote'
    | 'shadowDetection_dismiss'
    | 'shadowDetection_delete'
    | 'shadowDetection_stats'
    // TLS metadata configuration (Issue #168)
    | 'tls_getConfig'
    | 'tls_updateConfig'
    | 'tls_clearCache'
    | 'tls_getCacheStats'
    // EDR enrichment export (Issue #169)
    | 'edr_getConfig'
    | 'edr_updateConfig'
    | 'edr_getArtifact'
    | 'edr_listArtifacts'
    | 'edr_exportArtifact'
    | 'edr_clearArtifacts'
    // E2E Testing (Issue #226)
    | 'uploadForensicsTest'
    | 'retryForensics'
    // DNR update pipeline (Issue #286)
    | 'updateBlocklistWithPriority'
    // Heartbeat testing (Issue #230)
    | 'heartbeat_getAlarm'
    | 'heartbeat_forceHeartbeat'
    | 'heartbeat_getStats'
    // Dashboard (Issue #280)
    | 'getDashboardData'
    | 'getForensicsById'
    // Sensor mode (Issue #400)
    | 'sensor_getConfig'
    | 'sensor_saveConfig'
    | 'sensor_getStats'
    | 'sensor_getIdentity'
    | 'sensor_setIdentity'
    // Dual-mode auth (Issue #399)
    | 'auth_getState'
    | 'auth_setToken'
    | 'ioc_extract'
    | 'ioc_broadcast'
    // Direct ingest to on-prem SIEM (Issue #398)
    | 'directIngest_getEndpoints'
    | 'directIngest_getEndpoint'
    | 'directIngest_addEndpoint'
    | 'directIngest_removeEndpoint'
    | 'directIngest_updateEndpoint'
    | 'directIngest_sendToSiem'
    | 'directIngest_sendToAllSiems'
    | 'directIngest_getQueue'
    | 'directIngest_getQueueStats'
    | 'directIngest_clearQueue'
    | 'directIngest_removeFromQueue'
    | 'directIngest_retry'
    | 'directIngest_requestPermission'
    | 'directIngest_hasPermission'
    | 'directIngest_getConfig'
    | 'directIngest_updateConfig';
  url?: string;
  // Forensics detail ID (Issue #479)
  id?: string;
  // Auth parameters (Issue #399)
  authToken?: string;
  text?: string;
  // Test forensics payload (Issue #226)
  payload?: ForensicsPayload;
  // Shadow detection parameters
  hash?: string;
  analyst?: string;
  notes?: string;
  config?: Partial<ShadowDetectionConfig>;
  query?: ShadowDetectionQuery;
  // TLS configuration parameters
  tlsConfig?: Partial<TLSCaptureConfig>;
  // EDR enrichment parameters
  edrConfig?: Partial<EDREnrichmentConfig>;
  artifactId?: string;
  exportFormat?: EDRExportFormat;
  artifactLimit?: number;
  // DNR update pipeline parameters (Issue #286)
  iocs?: PrioritizedIOC[];
  version?: number;
  // Sensor mode parameters (Issue #400)
  sensorConfig?: SensorConfig;
  hostIdentity?: HostIdentity;
  // Direct ingest parameters (Issue #398)
  endpointId?: string;
  endpointName?: string;
  endpointUrl?: string;
  endpointMethod?: 'POST' | 'PUT';
  endpointHeaders?: Record<string, string>;
  endpointUpdates?: Partial<Pick<SiemEndpoint, 'name' | 'enabled' | 'headers'>>;
  ingestPayload?: unknown;
  ingestConfig?: Partial<DirectIngestConfig>;
  origin?: string;
  queueItemId?: string;
}

/**
 * Message from content script with DOM skeleton.
 * Used for phishing kit fingerprinting and form schema capture.
 */
interface SkeletonMessage {
  type: 'DOM_SKELETON';
  payload: {
    tagTree: string;
    formCount: number;
    inputTypes: string[];
    actionUrls: string[];
    hasLoginForm: boolean;
    hasPaymentForm: boolean;
    extractionTimeMs: number;
  };
  url: string;
  timestamp: number;
  /** Form schemas extracted from the page (structure only, no values) */
  formSchemas?: FormSchema[];
}

interface PopupData {
  blocklist: {
    initialized: boolean;
    count: number;
  };
  update: {
    version: number | null;
    timestamp: string | null;
    updatedAt: number | null;
  };
  forensics: {
    pendingCount: number;
    recentBlocks: Array<{
      url: string;
      timestamp: number;
    }>;
  };
  isOnline: boolean;
  health: HealthCheckResult;
}

/**
 * Handle test upload with encryption (Issue #226).
 * Used by E2E tests to verify the full encryption/upload pipeline.
 */
async function handleTestUpload(
  payload: ForensicsPayload
): Promise<{ success: boolean; error?: string }> {
  const { browserdefense_config } = await chrome.storage.local.get('browserdefense_config');
  const endpoint = browserdefense_config?.forensics_endpoint as string | undefined;

  if (!endpoint) {
    return { success: false, error: 'No forensics endpoint configured' };
  }

  const encryptFn = await getEncryptionFunction();
  if (!encryptFn) {
    return { success: false, error: 'No encryption key configured' };
  }

  const success = await uploadForensics(payload, endpoint, encryptFn);
  return { success };
}

/**
 * Retry pending uploads with encryption function (Issue #226).
 * Provides the encryption function to retryPendingUploads for encrypting
 * items that were queued without encryption.
 */
async function handleRetryWithEncryption(): Promise<number> {
  const { browserdefense_config } = await chrome.storage.local.get('browserdefense_config');
  const endpoint = browserdefense_config?.forensics_endpoint as string | undefined;

  const encryptFn = await getEncryptionFunction();

  return retryPendingUploads(endpoint, encryptFn ?? undefined);
}

/**
 * Handle messages from popup, options page, and content scripts.
 */
chrome.runtime.onMessage.addListener((message: PopupMessage | SkeletonMessage, sender, sendResponse) => {
  // Handle DOM skeleton from content script (fingerprint uplink + form schema capture)
  if (message.type === 'DOM_SKELETON') {
    const skeletonMsg = message as SkeletonMessage;

    // Store form schemas for this tab (for forensics capture on block)
    if (sender.tab?.id && skeletonMsg.formSchemas && skeletonMsg.formSchemas.length > 0) {
      storeFormSchemas(sender.tab.id, skeletonMsg.formSchemas, skeletonMsg.url);
    }

    // Check history Bloom filter - skip fingerprinting for known domains (Issue #161)
    isDomainInHistory(skeletonMsg.url)
      .then((inHistory) => {
        if (inHistory) {
          console.log(`[BrowserDefense] Skipping fingerprint for known domain: ${skeletonMsg.url.slice(0, 50)}...`);
          sendResponse({ success: true, result: null, skippedKnownDomain: true });
          return;
        }

        // Process new domain
        handleSkeletonMessage(skeletonMsg)
          .then((response: FingerprintResponse | null) => {
            sendResponse({ success: true, result: response });
          })
          .catch((err) => {
            console.error('[BrowserDefense] Skeleton message error:', err);
            sendResponse({ success: false, error: String(err) });
          });
      })
      .catch((err) => {
        console.error('[BrowserDefense] History check error:', err);
        // Fall back to processing on error
        handleSkeletonMessage(skeletonMsg)
          .then((response: FingerprintResponse | null) => {
            sendResponse({ success: true, result: response });
          })
          .catch((innerErr) => {
            console.error('[BrowserDefense] Skeleton message error:', innerErr);
            sendResponse({ success: false, error: String(innerErr) });
          });
      });
    return true; // Async response
  }

  if (message.type === 'getPopupData') {
    getPopupData().then(sendResponse);
    return true; // Async response
  }

  if (message.type === 'forceUpdate') {
    forceUpdate()
      .then(async (result) => {
        // Record success/failure for network monitoring
        if (result.success) {
          await recordUpdateSuccess();
          sendResponse({ success: true, error: null });
          return;
        }
        const errorMsg = (result as { error: string }).error;
        await recordUpdateFailure(errorMsg);
        sendResponse({ success: false, error: errorMsg });
      })
      .catch(async (err) => {
        await recordUpdateFailure(String(err));
        sendResponse({ success: false, error: String(err) });
      });
    return true;
  }

  if (message.type === 'retryUploads') {
    (async () => {
      const config = await loadConfig();
      const encryptFn = await getEncryptionFunction();
      if (!config?.forensics_endpoint || !encryptFn) {
        sendResponse({ success: false, error: 'Missing config or encryption key' });
        return;
      }
      const count = await retryPendingUploads(config.forensics_endpoint, encryptFn);
      sendResponse({ success: true, uploaded: count });
    })().catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  // E2E Test endpoint: Upload forensics with encryption (Issue #226)
  if (message.type === 'uploadForensicsTest') {
    if (!message.payload) {
      sendResponse({ success: false, error: 'Payload required' });
      return true;
    }
    handleTestUpload(message.payload)
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  // Alias for retryUploads (used by existing tests)
  if (message.type === 'retryForensics') {
    handleRetryWithEncryption()
      .then((count) => sendResponse({ success: true, uploaded: count }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  // E2E Test endpoint: Update blocklist with priority (Issue #286)
  // Exercises the full DNR update pipeline for integration testing
  if (message.type === 'updateBlocklistWithPriority') {
    if (!message.iocs || !Array.isArray(message.iocs)) {
      sendResponse({ success: false, error: 'iocs array required' });
      return true;
    }
    const version = message.version ?? 1;
    updateBlocklistWithPriority(message.iocs, version)
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'reloadBlocklist') {
    reloadBlocklist()
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  // Debug endpoint for testing
  if (message.type === 'checkBlocked') {
    isBlocked(message.url || '')
      .then((blocked) => sendResponse({ blocked }))
      .catch((err) => sendResponse({ blocked: false, error: String(err) }));
    return true;
  }

  // Config updated from options page - reschedule updates
  if (message.type === 'configUpdated') {
    initScheduledUpdates()
      .then(() => {
        console.log('[BrowserDefense] Config updated, rescheduled updates');
        sendResponse({ success: true });
      })
      .catch((err) => {
        console.error('[BrowserDefense] Failed to reschedule updates:', err);
        sendResponse({ success: false, error: String(err) });
      });
    return true;
  }

  // Config cleared from options page - cancel scheduled updates
  if (message.type === 'configCleared') {
    chrome.alarms.clear('browserdefense_blocklist_update')
      .then(() => {
        console.log('[BrowserDefense] Config cleared, cancelled scheduled updates');
        sendResponse({ success: true });
      })
      .catch((err) => {
        console.error('[BrowserDefense] Failed to cancel scheduled updates:', err);
        sendResponse({ success: false, error: String(err) });
      });
    return true;
  }

  // Demo mode config updated from options page (Issue #571)
  if (message.type === 'demoConfigUpdated') {
    reloadDemoConfig()
      .then(() => {
        console.log('[BrowserDefense] Demo config reloaded');
        sendResponse({ success: true });
      })
      .catch((err) => {
        console.error('[BrowserDefense] Failed to reload demo config:', err);
        sendResponse({ success: false, error: String(err) });
      });
    return true;
  }

  // Get demo mode status (Issue #571)
  if (message.type === 'getDemoStatus') {
    const status = getDemoModeStatus();
    sendResponse({ success: true, ...status });
    return true;
  }

  // History Bloom filter management (Issue #161)
  if (message.type === 'historyBloom_getStats') {
    getHistoryBloomStats()
      .then((stats) => sendResponse({ success: true, stats }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'historyBloom_enable') {
    enableHistoryBloom()
      .then((enabled) => sendResponse({ success: enabled }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'historyBloom_disable') {
    disableHistoryBloom()
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'historyBloom_requestPermission') {
    requestHistoryPermission()
      .then((granted) => sendResponse({ success: true, granted }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'historyBloom_checkPermission') {
    checkHistoryPermission()
      .then((status) => sendResponse({ success: true, ...status }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'historyBloom_rebuild') {
    rebuildHistoryBloom(true)
      .then((count) => sendResponse({ success: true, domainCount: count }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  // Shadow detection management (Issue #171)
  if (message.type === 'shadowDetection_getConfig') {
    getShadowDetectionConfig()
      .then((config) => sendResponse({ success: true, config }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'shadowDetection_updateConfig') {
    if (!message.config) {
      sendResponse({ success: false, error: 'Config required' });
      return true;
    }
    updateShadowDetectionConfig(message.config)
      .then((config) => sendResponse({ success: true, config }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'shadowDetection_list') {
    listDetections(message.query ?? {})
      .then((result) => sendResponse({ success: true, ...result }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'shadowDetection_get') {
    if (!message.hash) {
      sendResponse({ success: false, error: 'Hash required' });
      return true;
    }
    getDetection(message.hash)
      .then((detection) => sendResponse({ success: true, detection }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'shadowDetection_promote') {
    if (!message.hash || !message.analyst) {
      sendResponse({ success: false, error: 'Hash and analyst required' });
      return true;
    }
    promoteDetection(message.hash, message.analyst, message.notes)
      .then((detection) => {
        if (detection) {
          sendResponse({ success: true, detection });
        } else {
          sendResponse({ success: false, error: 'Detection not found' });
        }
      })
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'shadowDetection_dismiss') {
    if (!message.hash || !message.analyst) {
      sendResponse({ success: false, error: 'Hash and analyst required' });
      return true;
    }
    dismissDetection(message.hash, message.analyst, message.notes)
      .then((detection) => {
        if (detection) {
          sendResponse({ success: true, detection });
        } else {
          sendResponse({ success: false, error: 'Detection not found' });
        }
      })
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'shadowDetection_delete') {
    if (!message.hash) {
      sendResponse({ success: false, error: 'Hash required' });
      return true;
    }
    deleteDetection(message.hash)
      .then((deleted) => sendResponse({ success: deleted }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'shadowDetection_stats') {
    getDetectionStats()
      .then((stats) => sendResponse({ success: true, stats }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  // TLS metadata configuration (Issue #168)
  if (message.type === 'tls_getConfig') {
    getTLSCaptureConfig()
      .then((config) => sendResponse({ success: true, config }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'tls_updateConfig') {
    if (!message.tlsConfig) {
      sendResponse({ success: false, error: 'TLS config required' });
      return true;
    }
    updateTLSCaptureConfig(message.tlsConfig)
      .then((config) => sendResponse({ success: true, config }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'tls_clearCache') {
    clearEnrichmentCache()
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'tls_getCacheStats') {
    try {
      const stats = getEnrichmentCacheStats();
      sendResponse({ success: true, stats });
    } catch (err) {
      sendResponse({ success: false, error: String(err) });
    }
    return true;
  }

  // EDR enrichment export (Issue #169)
  if (message.type === 'edr_getConfig') {
    getEDREnrichmentConfig()
      .then((config) => sendResponse({ success: true, config }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'edr_updateConfig') {
    if (!message.edrConfig) {
      sendResponse({ success: false, error: 'EDR config required' });
      return true;
    }
    updateEDREnrichmentConfig(message.edrConfig)
      .then((config) => sendResponse({ success: true, config }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'edr_getArtifact') {
    if (!message.artifactId) {
      sendResponse({ success: false, error: 'Artifact ID required' });
      return true;
    }
    try {
      const artifact = getArtifact(message.artifactId);
      if (artifact) {
        sendResponse({ success: true, artifact });
      } else {
        sendResponse({ success: false, error: 'Artifact not found' });
      }
    } catch (err) {
      sendResponse({ success: false, error: String(err) });
    }
    return true;
  }

  if (message.type === 'edr_listArtifacts') {
    try {
      const artifacts = listArtifacts(message.artifactLimit ?? 20);
      sendResponse({ success: true, artifacts });
    } catch (err) {
      sendResponse({ success: false, error: String(err) });
    }
    return true;
  }

  if (message.type === 'edr_exportArtifact') {
    if (!message.artifactId) {
      sendResponse({ success: false, error: 'Artifact ID required' });
      return true;
    }
    try {
      const artifact = getArtifact(message.artifactId);
      if (!artifact) {
        sendResponse({ success: false, error: 'Artifact not found' });
        return true;
      }
      const exported = exportArtifact(artifact, message.exportFormat ?? 'json');
      sendResponse({ success: true, exported });
    } catch (err) {
      sendResponse({ success: false, error: String(err) });
    }
    return true;
  }

  if (message.type === 'edr_clearArtifacts') {
    try {
      clearArtifacts();
      sendResponse({ success: true });
    } catch (err) {
      sendResponse({ success: false, error: String(err) });
    }
    return true;
  }

  // Heartbeat testing (Issue #230)
  if (message.type === 'heartbeat_getAlarm') {
    chrome.alarms.get('keepAlive')
      .then((alarm) => {
        if (alarm) {
          sendResponse({
            success: true,
            alarm: {
              name: alarm.name,
              periodInMinutes: alarm.periodInMinutes,
              scheduledTime: alarm.scheduledTime,
            },
          });
        } else {
          sendResponse({ success: false, error: 'Alarm not found' });
        }
      })
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'heartbeat_forceHeartbeat') {
    forceHeartbeat()
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'heartbeat_getStats') {
    try {
      const stats = getHeartbeatStats();
      sendResponse({ success: true, stats });
    } catch (err) {
      sendResponse({ success: false, error: String(err) });
    }
    return true;
  }

  // Dashboard data (Issue #280)
  if (message.type === 'getDashboardData') {
    getDashboardData()
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  // Forensics detail by ID (Issue #479)
  if (message.type === 'getForensicsById') {
    const eventId = message.id as string;
    getQueue()
      .then((queue) => {
        const event = queue.find((item) => item.id === eventId);
        if (event) {
          sendResponse({ success: true, event });
        } else {
          sendResponse({ success: false, error: 'Event not found' });
        }
      })
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  // Sensor mode (Issue #400)
  if (message.type === 'sensor_getConfig') {
    getSensorConfig()
      .then((config) => sendResponse({ success: true, config }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  // Dual-mode auth (Issue #399)
  if (message.type === 'auth_getState') {
    getAuthState()
      .then((state) => sendResponse({ success: true, state }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'sensor_saveConfig') {
    if (!message.sensorConfig) {
      sendResponse({ success: false, error: 'Sensor config required' });
      return true;
    }
    saveSensorConfig(message.sensorConfig)
      .then(() => {
        // Re-initialize sensor mode with new config
        return initSensorMode();
      })
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'sensor_getStats') {
    getSensorStats()
      .then((stats) => sendResponse({ success: true, stats }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  // Direct ingest to on-prem SIEM (Issue #398)
  if (message.type === 'directIngest_getEndpoints') {
    getSiemEndpoints()
      .then((endpoints) => sendResponse({ success: true, endpoints }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_getEndpoint') {
    if (!message.endpointId) {
      sendResponse({ success: false, error: 'Endpoint ID required' });
      return true;
    }
    getSiemEndpoint(message.endpointId)
      .then((endpoint) => {
        if (endpoint) {
          sendResponse({ success: true, endpoint });
        } else {
          sendResponse({ success: false, error: 'Endpoint not found' });
        }
      })
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_addEndpoint') {
    if (!message.endpointName || !message.endpointUrl) {
      sendResponse({ success: false, error: 'Name and URL required' });
      return true;
    }
    addSiemEndpoint(message.endpointName, message.endpointUrl, {
      method: message.endpointMethod,
      headers: message.endpointHeaders,
    })
      .then((result) => {
        if (result.endpoint) {
          sendResponse({ success: true, endpoint: result.endpoint });
        } else {
          sendResponse({ success: false, error: result.error });
        }
      })
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_removeEndpoint') {
    if (!message.endpointId) {
      sendResponse({ success: false, error: 'Endpoint ID required' });
      return true;
    }
    removeSiemEndpoint(message.endpointId)
      .then((removed) => sendResponse({ success: removed }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_updateEndpoint') {
    if (!message.endpointId || !message.endpointUpdates) {
      sendResponse({ success: false, error: 'Endpoint ID and updates required' });
      return true;
    }
    updateSiemEndpoint(message.endpointId, message.endpointUpdates)
      .then((endpoint) => {
        if (endpoint) {
          sendResponse({ success: true, endpoint });
        } else {
          sendResponse({ success: false, error: 'Endpoint not found' });
        }
      })
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_sendToSiem') {
    if (!message.endpointId || message.ingestPayload === undefined) {
      sendResponse({ success: false, error: 'Endpoint ID and payload required' });
      return true;
    }
    sendToSiem(message.endpointId, message.ingestPayload)
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_sendToAllSiems') {
    if (message.ingestPayload === undefined) {
      sendResponse({ success: false, error: 'Payload required' });
      return true;
    }
    sendToAllSiems(message.ingestPayload)
      .then((results) => {
        const resultsObj: Record<string, unknown> = {};
        results.forEach((value, key) => {
          resultsObj[key] = value;
        });
        sendResponse({ success: true, results: resultsObj });
      })
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_getQueue') {
    getIngestQueue()
      .then((queue) => sendResponse({ success: true, queue }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_getQueueStats') {
    getIngestQueueStats()
      .then((stats) => sendResponse({ success: true, stats }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'sensor_getIdentity') {
    getHostIdentity()
      .then((identity) => sendResponse({ success: true, identity }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'sensor_setIdentity') {
    if (!message.hostIdentity) {
      sendResponse({ success: false, error: 'Host identity required' });
      return true;
    }
    setHostIdentity(message.hostIdentity)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'auth_setToken') {
    const token = message.authToken;
    chrome.storage.local.set({ auth_token: token ?? null })
      .then(() => getAuthState())
      .then((state) => sendResponse({ success: true, state }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'ioc_extract') {
    if (!message.text) {
      sendResponse({ success: false, error: 'Text required' });
      return true;
    }
    const result = extractIOCs(message.text);
    sendResponse({ success: true, ...result });
    return true;
  }

  // Broadcast IOCs from popup (Issue #570)
  if (message.type === 'ioc_broadcast') {
    if (!message.text) {
      sendResponse({ success: false, error: 'Text required' });
      return true;
    }
    const extractResult = extractIOCs(message.text);
    if (extractResult.iocs.length === 0) {
      sendResponse({ success: false, error: 'No IOCs found in input' });
      return true;
    }
    broadcastIOCs(extractResult.iocs)
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ success: false, iocs: [], error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_clearQueue') {
    clearIngestQueue()
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_removeFromQueue') {
    if (!message.queueItemId) {
      sendResponse({ success: false, error: 'Queue item ID required' });
      return true;
    }
    removeFromIngestQueue(message.queueItemId)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_retry') {
    retryPendingIngest()
      .then((result) => sendResponse({ success: true, ...result }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_requestPermission') {
    if (!message.origin) {
      sendResponse({ success: false, error: 'Origin required' });
      return true;
    }
    requestSiemPermission(message.origin)
      .then((result) => sendResponse({ success: result.granted, ...result }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_hasPermission') {
    if (!message.origin) {
      sendResponse({ success: false, error: 'Origin required' });
      return true;
    }
    hasPermission(message.origin)
      .then((has) => sendResponse({ success: true, hasPermission: has }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_getConfig') {
    loadIngestConfig()
      .then((config) => sendResponse({ success: true, config }))
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  if (message.type === 'directIngest_updateConfig') {
    if (!message.ingestConfig) {
      sendResponse({ success: false, error: 'Config updates required' });
      return true;
    }
    loadIngestConfig()
      .then(async (currentConfig) => {
        const newConfig = { ...currentConfig, ...message.ingestConfig };
        await saveIngestConfig(newConfig);
        sendResponse({ success: true, config: newConfig });
      })
      .catch((err) => sendResponse({ success: false, error: String(err) }));
    return true;
  }

  return false;
});

/**
 * Dashboard data structure (Issue #280)
 */
interface DashboardData {
  stats: {
    blocksToday: number;
    newKitsSeen: number;
    pendingTriage: number;
  };
  recentBlocks: Array<{
    id: string;
    url: string;
    timestamp: number;
    similarityScore: number | null;
    category?: 'phishing' | 'malware' | 'c2' | 'unknown';
  }>;
  deployment: {
    configured: number;
    unconfigured: number;
  };
  lastUpdated: number;
}

/**
 * Gather all data needed for the popup.
 */
async function getPopupData(): Promise<PopupData> {
  const [blocklistInfo, updateMeta, pendingCount, queue, health] = await Promise.all([
    Promise.resolve(getBlocklistInfo()),
    getUpdateMetadata(),
    getPendingCount(),
    getQueue(),
    performHealthCheck(),
  ]);

  // Get recent blocks from queue (last 5, sorted by queue time)
  const recentBlocks = queue
    .sort((a, b) => new Date(b.queuedAt).getTime() - new Date(a.queuedAt).getTime())
    .slice(0, 5)
    .map((item) => ({
      url: item.payload.blockedUrl || 'Unknown URL',
      timestamp: new Date(item.queuedAt).getTime(),
    }));

  return {
    blocklist: blocklistInfo,
    update: {
      version: updateMeta?.version ?? null,
      timestamp: updateMeta?.timestamp ?? null,
      updatedAt: updateMeta?.updatedAt ?? null,
    },
    forensics: {
      pendingCount,
      recentBlocks,
    },
    isOnline: health.isOnline,
    health,
  };
}

/**
 * Gather all data needed for the dashboard (Issue #280).
 */
async function getDashboardData(): Promise<DashboardData> {
  const [queue, detectionStats] = await Promise.all([
    getQueue(),
    getDetectionStats(),
  ]);

  // Calculate blocks today (from forensics queue)
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayStart = today.getTime();

  const blocksToday = queue.filter((item) => {
    const queuedTime = new Date(item.queuedAt).getTime();
    return queuedTime >= todayStart;
  }).length;

  // Get recent blocks - similarity scores would come from shadow detection
  // but forensics payloads don't currently store the DOM kit hash
  // For now, return blocks without similarity scores (marked as new)
  const recentBlocks = queue
    .sort((a, b) => new Date(b.queuedAt).getTime() - new Date(a.queuedAt).getTime())
    .slice(0, 10)
    .map((item) => ({
      id: item.id,
      url: item.payload.blockedUrl || 'Unknown URL',
      timestamp: new Date(item.queuedAt).getTime(),
      // Similarity scores require linking forensics to shadow detection
      // This will be null until that linkage is implemented
      similarityScore: null as number | null,
      category: (['phishing', 'malware', 'c2'].includes(item.payload.reason)
        ? item.payload.reason
        : 'unknown') as 'phishing' | 'malware' | 'c2' | 'unknown',
    }));

  // Pending triage = unlabeled shadow detections
  const pendingTriage = detectionStats.pendingReview;

  // New kits = shadow detections first seen today
  // For now, approximate with total pending since we don't have first_seen filtering
  const newKitsSeen = detectionStats.total > 0
    ? Math.min(detectionStats.pendingReview, Math.max(1, Math.floor(detectionStats.pendingReview * 0.3)))
    : 0;

  // Deployment status
  // For v1, we don't have real endpoint check-in data
  // Return mock data that can be replaced with real API later
  const deployment = {
    configured: 1, // At minimum, this extension instance
    unconfigured: 0,
  };

  return {
    stats: {
      blocksToday,
      newKitsSeen,
      pendingTriage,
    },
    recentBlocks,
    deployment,
    lastUpdated: Date.now(),
  };
}

// Export for testing and external access
export {
  initBlocking,
  setupNavigationBlocking,
  reloadBlocklist,
  forceHeartbeat,
  retryPendingUploads,
  getPendingCount,
  getPopupData,
  getDashboardData,
  // Dual-mode auth exports (Issue #399)
  getAuthState,
  isHunterMode,
  extractIOCs,
};
