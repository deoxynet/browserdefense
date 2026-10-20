/**
 * Types for browser-side direct ingest to on-prem SIEM endpoints.
 *
 * Issue #398 - Browser-Side Direct Ingest
 *
 * Enables sending logs directly from the browser to on-prem SIEM endpoints
 * with runtime permissions and an off-VPN retry queue.
 */

/**
 * SIEM endpoint configuration.
 */
export interface SiemEndpoint {
  /** Unique identifier for this endpoint */
  id: string;
  /** Display name for the endpoint */
  name: string;
  /** Full URL to the SIEM ingestion endpoint */
  url: string;
  /** Origin extracted from URL for permission requests */
  origin: string;
  /** HTTP method to use (defaults to POST) */
  method?: 'POST' | 'PUT';
  /** Custom headers to include */
  headers?: Record<string, string>;
  /** Whether this endpoint is enabled */
  enabled: boolean;
  /** When this endpoint was added (ISO 8601) */
  addedAt: string;
  /** Last successful delivery (ISO 8601) */
  lastSuccess?: string;
  /** Last error message */
  lastError?: string;
}

/**
 * Ingest queue item for failed deliveries.
 */
export interface IngestQueueItem {
  /** Unique identifier for this queue item */
  id: string;
  /** ID of the target SIEM endpoint */
  endpointId: string;
  /** Payload to send (already encrypted or formatted for SIEM) */
  payload: unknown;
  /** Number of delivery attempts */
  attempts: number;
  /** ISO 8601 timestamp when queued */
  queuedAt: string;
  /** ISO 8601 timestamp of last attempt */
  lastAttempt?: string;
  /** Last error message */
  lastError?: string;
  /** Error category for smart retry */
  errorCategory?: IngestErrorCategory;
}

/**
 * Error categories for smart retry logic.
 *
 * - network: DNS failures, timeouts, connection refused - RETRY
 * - auth: 401/403 responses - DO NOT RETRY (surface to user)
 * - server: 5xx responses - RETRY with backoff
 * - client: 4xx responses (non-auth) - DO NOT RETRY
 */
export type IngestErrorCategory = 'network' | 'auth' | 'server' | 'client';

/**
 * Result of a permission request.
 */
export interface PermissionResult {
  /** Whether permission was granted */
  granted: boolean;
  /** The origin that was requested */
  origin: string;
  /** Error message if the request failed */
  error?: string;
}

/**
 * Result of a send operation.
 */
export interface SendResult {
  /** Whether the send was successful */
  success: boolean;
  /** The queue item ID if queued for retry */
  queuedId?: string;
  /** Error message if failed */
  error?: string;
  /** Error category for smart retry */
  errorCategory?: IngestErrorCategory;
  /** Whether the error is retryable */
  retryable?: boolean;
  /** HTTP status code if applicable */
  statusCode?: number;
}

/**
 * Ingest queue statistics.
 */
export interface IngestQueueStats {
  /** Total items in queue */
  queueLength: number;
  /** Items pending retry (network/server errors) */
  pendingRetry: number;
  /** Items with auth errors (need user attention) */
  authErrors: number;
  /** Items with client errors (will not retry) */
  clientErrors: number;
  /** Oldest item timestamp (ISO 8601) */
  oldestItem?: string;
  /** Total delivery attempts across all items */
  totalAttempts: number;
}

/**
 * Configuration for the direct ingest system.
 */
export interface DirectIngestConfig {
  /** List of configured SIEM endpoints */
  endpoints: SiemEndpoint[];
  /** Maximum queue size before dropping oldest items */
  maxQueueSize: number;
  /** Maximum retry attempts per item */
  maxRetries: number;
  /** Base retry delay in milliseconds */
  baseRetryDelayMs: number;
  /** Maximum retry delay in milliseconds */
  maxRetryDelayMs: number;
}
