/**
 * BlockIOC Connector SDK Types
 *
 * Common types and interfaces for building connectors that forward
 * decrypted forensics events to security platforms.
 */

/**
 * IOC action type - block or unblock.
 * 'block' is the default for backwards compatibility.
 * 'unblock' indicates the IOC should be revoked/removed.
 */
export type IocAction = 'block' | 'unblock';

/**
 * Forensics event received after decryption.
 * This is the primary data structure connectors receive.
 */
export interface ForensicsEvent {
  /** Action type - block or unblock (defaults to 'block' for backwards compat) */
  action?: IocAction;

  /** The blocked URL that triggered the event */
  blockedUrl: string;

  /** ISO8601 timestamp when the block occurred */
  timestamp: string;

  /** Chain of redirects leading to the blocked URL */
  redirectChain: string[];

  /** Browser tab context at block time */
  tabContext: {
    tabId: number;
    windowId: number;
    initiatorUrl?: string;
    tabTitle?: string;
    incognito: boolean;
  };

  /** Organization identifier for multi-tenant deployments */
  orgId: string;

  /** Unique event identifier */
  eventId: string;

  /** IOC type that matched (domain, url, hash) */
  matchType: 'domain' | 'url' | 'hash';

  /** The specific IOC pattern that matched */
  matchedIndicator: string;

  /** User identifier (if available from enterprise directory) */
  userId?: string;

  /** Device identifier (if available from MDM) */
  deviceId?: string;

  /** Original raw decrypted payload for custom processing */
  raw: Record<string, unknown>;
}

/**
 * Result of sending an event to a destination.
 */
export interface SendResult {
  /** Whether the send was successful */
  success: boolean;

  /** The event ID that was processed */
  eventId: string;

  /** Error message if send failed */
  error?: string;

  /** Whether the failure is retryable (e.g., network timeout) */
  retryable?: boolean;

  /** Additional response data from the destination */
  response?: Record<string, unknown>;
}

/**
 * Result of an unblock operation.
 * Used when closing/resolving incidents created from block events.
 */
export interface UnblockResult {
  /** Whether the unblock was successful */
  success: boolean;

  /** Event ID of the original block event */
  eventId: string;

  /** Error message if failed */
  error?: string;

  /** Whether the operation should be retried */
  retryable?: boolean;

  /** Whether the incident was already closed (idempotent) */
  alreadyClosed?: boolean;

  /** Incident ID that was updated */
  incidentId?: string;
}

/**
 * Retry configuration for connector operations.
 */
export interface RetryConfig {
  /** Maximum number of retry attempts */
  maxAttempts: number;

  /** Initial delay between retries in milliseconds */
  initialDelayMs: number;

  /** Maximum delay between retries in milliseconds */
  maxDelayMs: number;

  /** Multiplier for exponential backoff */
  backoffMultiplier: number;
}

/**
 * Batch configuration for connector operations.
 */
export interface BatchConfig {
  /** Maximum number of events to batch together */
  maxSize: number;

  /** Maximum time to wait before flushing a batch */
  maxWaitMs: number;
}

/**
 * Event filtering configuration.
 */
export interface FilterConfig {
  /** Only forward events from these organization IDs */
  orgIds?: string[];

  /** Only forward events with these match types */
  matchTypes?: Array<'domain' | 'url' | 'hash'>;

  /** Regex patterns to exclude from forwarding */
  excludePatterns?: string[];
}

/**
 * Base configuration for all connectors.
 */
export interface BaseConnectorConfig {
  /** Connector type identifier */
  type: string;

  /** Human-readable name for this connector instance */
  name: string;

  /** Whether this connector is enabled */
  enabled: boolean;

  /** Retry configuration */
  retry?: RetryConfig;

  /** Batch configuration */
  batch?: BatchConfig;

  /** Event filtering */
  filter?: FilterConfig;
}

/**
 * Health check result.
 */
export interface HealthResult {
  /** Whether the connector is healthy */
  healthy: boolean;

  /** Descriptive message about health status */
  message: string;
}

/**
 * Abstract base class for all connectors.
 * Provides common functionality like retry handling and lifecycle management.
 */
export abstract class BaseConnector<
  TConfig extends BaseConnectorConfig = BaseConnectorConfig,
> {
  /** The connector type identifier */
  abstract readonly type: string;

  /**
   * Whether this connector supports unblock operations.
   * Override in subclasses that implement doUnblock().
   * Default is false - unblock() returns a skipped result.
   */
  readonly supportsUnblock: boolean = false;

  /** Whether the connector has been initialized */
  protected initialized = false;

  constructor(protected config: TConfig) {}

  /**
   * Initialize the connector (establish connections, validate credentials).
   * Called once before any send operations.
   */
  async init(): Promise<void> {
    if (this.initialized) {
      return;
    }
    await this.doInit();
    this.initialized = true;
  }

  /**
   * Send a forensics event to the destination.
   * Includes retry logic if configured.
   */
  async send(event: ForensicsEvent): Promise<SendResult> {
    if (!this.initialized) {
      throw new Error('Connector not initialized. Call init() first.');
    }

    const retryConfig = this.config.retry ?? {
      maxAttempts: 3,
      initialDelayMs: 1000,
      maxDelayMs: 30000,
      backoffMultiplier: 2,
    };

    let lastError: Error | undefined;
    let delay = retryConfig.initialDelayMs;

    for (let attempt = 1; attempt <= retryConfig.maxAttempts; attempt++) {
      try {
        const result = await this.doSend(event);
        if (result.success || !result.retryable) {
          return result;
        }
        lastError = new Error(result.error ?? 'Send failed');
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
      }

      if (attempt < retryConfig.maxAttempts) {
        await this.sleep(delay);
        delay = Math.min(
          delay * retryConfig.backoffMultiplier,
          retryConfig.maxDelayMs
        );
      }
    }

    return {
      success: false,
      eventId: event.eventId,
      error: lastError?.message ?? 'Max retries exceeded',
      retryable: false,
    };
  }

  /**
   * Unblock/revoke a previously blocked indicator.
   * Used to close incidents, remove IOCs from blocklists, etc.
   *
   * Connectors that don't support unblocking (supportsUnblock=false)
   * will return success=true without taking action.
   */
  async unblock(event: ForensicsEvent): Promise<UnblockResult> {
    if (!this.initialized) {
      throw new Error('Connector not initialized. Call init() first.');
    }

    // If connector doesn't support unblock, return success (skip)
    if (!this.supportsUnblock) {
      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: false,
      };
    }

    // Delegate to platform-specific implementation
    try {
      return await this.doUnblock(event);
    } catch (error) {
      return {
        success: false,
        eventId: event.eventId,
        error: error instanceof Error ? error.message : String(error),
        retryable: true,
      };
    }
  }

  /**
   * Check connector health.
   */
  async health(): Promise<HealthResult> {
    if (!this.initialized) {
      return { healthy: false, message: 'Not initialized' };
    }
    return this.doHealth();
  }

  /**
   * Close the connector and release resources.
   */
  async close(): Promise<void> {
    if (!this.initialized) {
      return;
    }
    await this.doClose();
    this.initialized = false;
  }

  /** Subclass implementation of initialization */
  protected abstract doInit(): Promise<void>;

  /** Subclass implementation of send */
  protected abstract doSend(event: ForensicsEvent): Promise<SendResult>;

  /** Subclass implementation of health check */
  protected abstract doHealth(): Promise<HealthResult>;

  /** Subclass implementation of close */
  protected abstract doClose(): Promise<void>;

  /**
   * Subclass implementation of unblock.
   * Override this method and set supportsUnblock=true to enable.
   * Default implementation returns an error (should not be called).
   */
  protected doUnblock(_event: ForensicsEvent): Promise<UnblockResult> {
    return Promise.resolve({
      success: false,
      eventId: _event.eventId,
      error: 'Unblock not implemented for this connector',
      retryable: false,
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
