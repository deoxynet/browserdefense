/**
 * Storage Key Constants
 *
 * Centralized storage keys for chrome.storage.local to prevent
 * test/production mismatches. All storage keys should be defined here
 * and imported by both production code and tests.
 *
 * Issue #490
 */

// ============ Core Configuration ============

/** Main extension configuration */
export const CONFIG_STORAGE_KEY = 'browserdefense_config';

/** Blocklist update configuration */
export const UPDATE_CONFIG_KEY = 'browserdefense_update_config';

/** Update metadata (version, timestamp, etc.) */
export const UPDATE_META_KEY = 'browserdefense_update_meta';

// ============ Blocklist Storage ============

/** Legacy blocklist storage (chrome.storage.local) */
export const BLOCKLIST_STORAGE_KEY = 'browserdefense_blocklist';

/** Flag indicating migration to IndexedDB is complete */
export const MIGRATION_FLAG_KEY = 'browserdefense_idb_migrated';

/** DNR rule metadata */
export const DNR_META_KEY = 'browserdefense_dnr_meta';

// ============ Forensics ============

/** Forensics event queue */
export const FORENSICS_QUEUE_KEY = 'browserdefense_forensics_queue';

/** Redirect chain tracking */
export const REDIRECT_CHAINS_KEY = 'browserdefense_redirect_chains';

// ============ Shadow Detection ============

/** Shadow detection results */
export const SHADOW_DETECTIONS_KEY = 'browserdefense_shadow_detections';

/** Shadow detection configuration */
export const SHADOW_DETECTION_CONFIG_KEY = 'browserdefense_shadow_detection_config';

/** Shadow detection alert cooldowns */
export const SHADOW_ALERT_COOLDOWNS_KEY = 'browserdefense_shadow_alert_cooldowns';

// ============ Shadow Telemetry ============

/** Seen hashes cache for shadow telemetry */
export const SHADOW_SEEN_CACHE_KEY = 'browserdefense_shadow_seen_hashes';

// ============ Shadow Robustness ============

/** Shadow processing rate limits */
export const SHADOW_RATE_LIMITS_KEY = 'browserdefense_shadow_rate_limits';

/** Shadow processing metrics */
export const SHADOW_METRICS_KEY = 'browserdefense_shadow_metrics';

/** Shadow error log */
export const SHADOW_ERRORS_KEY = 'browserdefense_shadow_errors';

/** Shadow latency samples */
export const SHADOW_LATENCY_KEY = 'browserdefense_shadow_latency';

/** Shadow robust storage prefix */
export const SHADOW_ROBUST_PREFIX = 'browserdefense_shadow_robust_';

/** Shadow circuit breaker state */
export const SHADOW_CIRCUIT_BREAKER_KEY = 'browserdefense_shadow_circuit_breaker';

/** Shadow offline queue */
export const SHADOW_OFFLINE_QUEUE_KEY = 'browserdefense_shadow_offline_queue';

// ============ Fingerprint Uplink ============

/** Fingerprint cache */
export const FINGERPRINT_CACHE_KEY = 'browserdefense_fingerprint_cache';

// ============ Hash Labels ============

/** Hash labels endpoint (legacy - use config) */
export const HASH_LABELS_ENDPOINT_KEY = 'browserdefense_hash_labels_endpoint';

/** Hash labels local cache */
export const HASH_LABELS_CACHE_KEY = 'browserdefense_labels_cache';

// ============ EDR Enrichment ============

/** EDR enrichment configuration */
export const EDR_ENRICHMENT_CONFIG_KEY = 'browserdefense_edr_enrichment_config';

/** EDR artifacts cache */
export const EDR_ARTIFACTS_KEY = 'browserdefense_edr_artifacts';

// ============ TLS Metadata ============

/** TLS capture configuration */
export const TLS_CAPTURE_CONFIG_KEY = 'browserdefense_tls_capture_config';

/** TLS enrichment cache */
export const TLS_ENRICHMENT_CACHE_KEY = 'browserdefense_tls_enrichment_cache';

// ============ DOM Kit Scoring ============

/** Temporal tracking for DOM kit scoring */
export const TEMPORAL_TRACKING_KEY = 'browserdefense_temporal_tracking';

// ============ History Bloom ============

/** History bloom filter configuration */
export const HISTORY_BLOOM_CONFIG_KEY = 'history_bloom_config';

// ============ Network State ============

/** Network connectivity state */
export const NETWORK_STATE_KEY = 'browserdefense_network_state';

// ============ Demo Mode ============

/** Demo mode configuration */
export const DEMO_CONFIG_KEY = 'browserdefense_demo_config';

// ============ DOM Signature Threat Intel ============

/** DOM signature store data */
export const DOM_SIG_STORE_KEY = 'browserdefense_dom_sig_store';

/** DOM signature update metadata */
export const DOM_SIG_META_KEY = 'browserdefense_dom_sig_meta';

/** DOM signature update configuration */
export const DOM_SIG_UPDATE_CONFIG_KEY = 'browserdefense_dom_sig_update_config';

// ============ Alarm Names ============

/** Blocklist update alarm */
export const BLOCKLIST_UPDATE_ALARM = 'browserdefense_blocklist_update';

/** DOM signature update alarm */
export const DOM_SIG_UPDATE_ALARM = 'browserdefense_dom_sig_update';
