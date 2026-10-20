/**
 * BrowserDefense Enterprise Connector Base
 *
 * Abstract base class and interface definitions for enterprise connectors.
 * Provides common functionality for retry logic, batching, filtering, and health monitoring.
 */

import {
  BaseConnectorConfig,
  BatchConfig,
  ConnectorConfig,
  ConnectorType,
  FilterConfig,
  ForensicsEvent,
  HealthMetrics,
  HealthStatus,
  RetryConfig,
  SendResult,
  UnblockResult,
} from './types';

// =============================================================================
// Connector Interface
// =============================================================================

/**
 * Core connector interface that all connector implementations must satisfy.
 *
 * Connectors are responsible for receiving decrypted forensics events and
 * forwarding them to external security platforms (SIEMs, EDRs, SOARs).
 *
 * Lifecycle:
 * 1. Constructor - Create instance with configuration
 * 2. init() - Establish connections, validate config
 * 3. send() - Called for each event (may be batched)
 * 4. unblock() - Called to revoke/close incidents (if supported)
 * 5. health() - Called periodically for monitoring
 * 6. close() - Clean shutdown, flush buffers
 */
export interface Connector {
  /** Unique identifier for this connector type */
  readonly type: ConnectorType;

  /** Human-readable name for this connector instance */
  readonly name: string;

  /**
   * Whether this connector supports unblock/revoke operations.
   * Connectors that don't support unblocking should return false.
   * When false, unblock() will return a skipped result.
   */
  readonly supportsUnblock: boolean;

  /**
   * Initialize the connector.
   * Called once after construction. Should establish connections,
   * validate credentials, and prepare for event delivery.
   *
   * @throws Error if initialization fails (invalid config, unreachable endpoint)
   */
  init(): Promise<void>;

  /**
   * Send a forensics event to the destination.
   * Implementations may buffer events for batching.
   * For action-aware connectors, check event.action to determine behavior.
   *
   * @param event - Decrypted forensics event to send
   * @returns Result indicating success/failure and retry eligibility
   */
  send(event: ForensicsEvent): Promise<SendResult>;

  /**
   * Send multiple events in a batch.
   * Default implementation calls send() for each event.
   *
   * @param events - Array of events to send
   * @returns Array of results for each event
   */
  sendBatch(events: ForensicsEvent[]): Promise<SendResult[]>;

  /**
   * Unblock/revoke a previously blocked indicator.
   * Used to close incidents, remove IOCs from blocklists, etc.
   *
   * Connectors that don't support unblocking will return a skipped result
   * with success=true and response.skipped=true.
   *
   * @param event - Forensics event with action='unblock'
   * @returns Result indicating success/failure
   */
  unblock(event: ForensicsEvent): Promise<UnblockResult>;

  /**
   * Perform a health check.
   * Called periodically by the service to monitor connector status.
   *
   * @returns Health status with metrics
   */
  health(): Promise<HealthStatus>;

  /**
   * Gracefully close the connector.
   * Should flush any buffered events and close connections.
   */
  close(): Promise<void>;

  /**
   * Check if this connector should process a given event.
   * Used for filtering based on org ID, match type, etc.
   *
   * @param event - Event to check
   * @returns true if this connector should handle the event
   */
  shouldProcess(event: ForensicsEvent): boolean;
}

// =============================================================================
// Abstract Base Connector
// =============================================================================

/**
 * Default retry configuration.
 */
const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxAttempts: 3,
  initialDelayMs: 1000,
  maxDelayMs: 30000,
  backoffMultiplier: 2,
};

/**
 * Default batch configuration.
 */
const DEFAULT_BATCH_CONFIG: BatchConfig = {
  maxSize: 100,
  maxWaitMs: 5000,
};

/**
 * Abstract base class providing common connector functionality.
 *
 * Subclasses must implement:
 * - doSend() - Actual send logic for the specific platform
 * - doHealth() - Platform-specific health check
 * - doInit() - Platform-specific initialization
 * - doClose() - Platform-specific cleanup
 *
 * Optionally implement:
 * - doUnblock() - Platform-specific unblock logic (override supportsUnblock to enable)
 */
export abstract class BaseConnector implements Connector {
  abstract readonly type: ConnectorType;

  readonly name: string;

  /**
   * Whether this connector supports unblock operations.
   * Override in subclasses that implement doUnblock().
   * Default is false - unblock() returns a skipped result.
   */
  readonly supportsUnblock: boolean = false;

  protected readonly config: BaseConnectorConfig;
  protected readonly retryConfig: RetryConfig;
  protected readonly batchConfig: BatchConfig;
  protected readonly filterConfig?: FilterConfig;

  // Metrics tracking
  protected metrics: HealthMetrics = {
    eventsSent: 0,
    eventsFailed: 0,
    eventsInRetryQueue: 0,
    avgLatencyMs: 0,
    uptimeSeconds: 0,
  };

  // Internal state
  private startTime: number = 0;
  private initialized: boolean = false;
  private closed: boolean = false;
  private latencySum: number = 0;
  private latencyCount: number = 0;
  private batchBuffer: ForensicsEvent[] = [];
  private batchTimer: ReturnType<typeof setTimeout> | null = null;
  private retryQueue: Array<{ event: ForensicsEvent; attempts: number }> = [];

  constructor(config: BaseConnectorConfig) {
    this.name = config.name;
    this.config = config;
    this.retryConfig = { ...DEFAULT_RETRY_CONFIG, ...config.retry };
    this.batchConfig = { ...DEFAULT_BATCH_CONFIG, ...config.batch };
    this.filterConfig = config.filter;
  }

  // ===========================================================================
  // Abstract methods - must be implemented by subclasses
  // ===========================================================================

  /**
   * Perform platform-specific initialization.
   * Called by init() after common setup.
   */
  protected abstract doInit(): Promise<void>;

  /**
   * Send an event to the specific platform.
   * Called by send() after filtering and before retry logic.
   */
  protected abstract doSend(event: ForensicsEvent): Promise<SendResult>;

  /**
   * Perform platform-specific health check.
   * Called by health() to gather platform-specific status.
   */
  protected abstract doHealth(): Promise<{ healthy: boolean; message: string }>;

  /**
   * Perform platform-specific cleanup.
   * Called by close() after common cleanup.
   */
  protected abstract doClose(): Promise<void>;

  /**
   * Perform platform-specific unblock operation.
   * Called by unblock() for connectors that support it.
   * Override this method and set supportsUnblock=true to enable.
   *
   * Default implementation throws - only called if supportsUnblock is true.
   *
   * @param event - Forensics event with action='unblock'
   * @returns Result of the unblock operation
   */
  protected doUnblock(_event: ForensicsEvent): Promise<UnblockResult> {
    // Default implementation - should not be called if supportsUnblock is false
    return Promise.resolve({
      success: false,
      eventId: _event.eventId,
      error: 'Unblock not implemented for this connector',
      retryable: false,
    });
  }

  // ===========================================================================
  // Public interface implementation
  // ===========================================================================

  async init(): Promise<void> {
    if (this.initialized) {
      throw new Error(`Connector ${this.name} already initialized`);
    }
    if (this.closed) {
      throw new Error(`Connector ${this.name} has been closed`);
    }

    await this.doInit();

    this.startTime = Date.now();
    this.initialized = true;
  }

  async send(event: ForensicsEvent): Promise<SendResult> {
    this.ensureInitialized();

    // Apply filtering
    if (!this.shouldProcess(event)) {
      return {
        success: true,
        eventId: event.eventId,
        response: { filtered: true },
      };
    }

    // If batching is enabled, buffer the event
    if (this.batchConfig.maxSize > 1) {
      return this.bufferEvent(event);
    }

    // Direct send with retry
    return this.sendWithRetry(event);
  }

  async sendBatch(events: ForensicsEvent[]): Promise<SendResult[]> {
    this.ensureInitialized();

    // Filter events
    const filtered = events.filter((e) => this.shouldProcess(e));

    // Send each event (subclasses can override for bulk APIs)
    const results = await Promise.all(
      filtered.map((event) => this.sendWithRetry(event))
    );

    // Add filtered results
    const filteredResults: SendResult[] = events
      .filter((e) => !this.shouldProcess(e))
      .map((e) => ({
        success: true,
        eventId: e.eventId,
        response: { filtered: true },
      }));

    return [...results, ...filteredResults];
  }

  async unblock(event: ForensicsEvent): Promise<UnblockResult> {
    this.ensureInitialized();

    // Apply filtering
    if (!this.shouldProcess(event)) {
      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: false,
      };
    }

    // If connector doesn't support unblock, return skipped result
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
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable: true,
      };
    }
  }

  async health(): Promise<HealthStatus> {
    this.ensureInitialized();

    const platformHealth = await this.doHealth();

    // Update uptime
    this.metrics.uptimeSeconds = Math.floor((Date.now() - this.startTime) / 1000);
    this.metrics.eventsInRetryQueue = this.retryQueue.length;

    // Calculate average latency
    if (this.latencyCount > 0) {
      this.metrics.avgLatencyMs = Math.round(this.latencySum / this.latencyCount);
    }

    return {
      healthy: platformHealth.healthy,
      message: platformHealth.message,
      lastSuccess: this.metrics.eventsSent > 0 ? new Date().toISOString() : undefined,
      lastError: !platformHealth.healthy ? platformHealth.message : undefined,
      metrics: { ...this.metrics },
    };
  }

  async close(): Promise<void> {
    if (this.closed) return;

    // Flush any buffered events
    if (this.batchBuffer.length > 0) {
      await this.flushBatch();
    }

    // Clear batch timer
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }

    // Process retry queue one last time
    await this.processRetryQueue();

    // Platform-specific cleanup
    await this.doClose();

    this.closed = true;
  }

  shouldProcess(event: ForensicsEvent): boolean {
    if (!this.filterConfig) return true;

    // Check org ID filter
    if (this.filterConfig.orgIds && this.filterConfig.orgIds.length > 0) {
      if (!this.filterConfig.orgIds.includes(event.orgId)) {
        return false;
      }
    }

    // Check match type filter
    if (this.filterConfig.matchTypes && this.filterConfig.matchTypes.length > 0) {
      if (!this.filterConfig.matchTypes.includes(event.matchType)) {
        return false;
      }
    }

    // Check exclude patterns
    if (this.filterConfig.excludePatterns) {
      for (const pattern of this.filterConfig.excludePatterns) {
        const regex = new RegExp(pattern);
        if (regex.test(event.blockedUrl)) {
          return false;
        }
      }
    }

    return true;
  }

  // ===========================================================================
  // Protected helper methods
  // ===========================================================================

  /**
   * Ensure the connector has been initialized.
   */
  protected ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error(`Connector ${this.name} not initialized. Call init() first.`);
    }
    if (this.closed) {
      throw new Error(`Connector ${this.name} has been closed.`);
    }
  }

  /**
   * Send an event with retry logic.
   */
  protected async sendWithRetry(
    event: ForensicsEvent,
    attemptNumber: number = 0
  ): Promise<SendResult> {
    const startTime = Date.now();

    try {
      const result = await this.doSend(event);

      // Track latency for successful sends
      if (result.success) {
        const latency = Date.now() - startTime;
        this.latencySum += latency;
        this.latencyCount++;
        this.metrics.eventsSent++;
      } else if (result.retryable && attemptNumber < this.retryConfig.maxAttempts) {
        // Queue for retry
        this.retryQueue.push({ event, attempts: attemptNumber + 1 });
        this.metrics.eventsInRetryQueue++;

        // Schedule retry processing
        this.scheduleRetryProcessing(attemptNumber);
      } else {
        this.metrics.eventsFailed++;
      }

      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Retry on transient errors
      if (attemptNumber < this.retryConfig.maxAttempts) {
        this.retryQueue.push({ event, attempts: attemptNumber + 1 });
        this.metrics.eventsInRetryQueue++;
        this.scheduleRetryProcessing(attemptNumber);

        return {
          success: false,
          eventId: event.eventId,
          error: errorMessage,
          retryable: true,
        };
      }

      this.metrics.eventsFailed++;
      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable: false,
      };
    }
  }

  /**
   * Calculate retry delay with exponential backoff.
   */
  protected calculateRetryDelay(attemptNumber: number): number {
    const delay = this.retryConfig.initialDelayMs *
      Math.pow(this.retryConfig.backoffMultiplier, attemptNumber);
    return Math.min(delay, this.retryConfig.maxDelayMs);
  }

  /**
   * Schedule retry queue processing.
   */
  private scheduleRetryProcessing(attemptNumber: number): void {
    const delay = this.calculateRetryDelay(attemptNumber);
    setTimeout(() => this.processRetryQueue(), delay);
  }

  /**
   * Process the retry queue.
   */
  private async processRetryQueue(): Promise<void> {
    const queue = [...this.retryQueue];
    this.retryQueue = [];

    for (const item of queue) {
      await this.sendWithRetry(item.event, item.attempts);
    }
  }

  /**
   * Buffer an event for batching.
   */
  private async bufferEvent(event: ForensicsEvent): Promise<SendResult> {
    this.batchBuffer.push(event);

    // Start batch timer if not running
    if (!this.batchTimer) {
      this.batchTimer = setTimeout(
        () => this.flushBatch(),
        this.batchConfig.maxWaitMs
      );
    }

    // Flush if batch is full
    if (this.batchBuffer.length >= this.batchConfig.maxSize) {
      await this.flushBatch();
    }

    return {
      success: true,
      eventId: event.eventId,
      response: { buffered: true },
    };
  }

  /**
   * Flush the batch buffer.
   */
  private async flushBatch(): Promise<void> {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }

    const events = [...this.batchBuffer];
    this.batchBuffer = [];

    if (events.length > 0) {
      await this.sendBatch(events);
    }
  }
}

// =============================================================================
// Connector Registry
// =============================================================================

/**
 * Factory function type for creating connectors.
 */
export type ConnectorFactory<T extends ConnectorConfig = ConnectorConfig> = (
  config: T
) => Connector;

/**
 * Registry for connector factories.
 * Allows dynamic registration of connector implementations.
 */
export class ConnectorRegistry {
  private factories: Map<ConnectorType, ConnectorFactory> = new Map();

  /**
   * Register a connector factory.
   *
   * @param type - Connector type identifier
   * @param factory - Factory function to create connector instances
   */
  register<T extends ConnectorConfig>(
    type: T['type'],
    factory: ConnectorFactory<T>
  ): void {
    this.factories.set(type, factory as ConnectorFactory);
  }

  /**
   * Create a connector instance from configuration.
   *
   * @param config - Connector configuration
   * @returns Connector instance
   * @throws Error if connector type is not registered
   */
  create(config: ConnectorConfig): Connector {
    const factory = this.factories.get(config.type);
    if (!factory) {
      throw new Error(`Unknown connector type: ${config.type}`);
    }
    return factory(config);
  }

  /**
   * Check if a connector type is registered.
   */
  has(type: ConnectorType): boolean {
    return this.factories.has(type);
  }

  /**
   * Get all registered connector types.
   */
  types(): ConnectorType[] {
    return Array.from(this.factories.keys());
  }
}

/**
 * Global connector registry instance.
 */
export const connectorRegistry = new ConnectorRegistry();

// =============================================================================
// Helper Types for Connector Implementations
// =============================================================================

/**
 * Type helper for extracting config type from connector type.
 */
export type ConfigForType<T extends ConnectorType> = Extract<
  ConnectorConfig,
  { type: T }
>;

/**
 * Event transformation function type.
 * Used by connectors to transform events to platform-specific formats.
 */
export type EventTransformer<T> = (event: ForensicsEvent) => T;

/**
 * Common HTTP client options for connectors.
 */
export interface HttpClientOptions {
  baseUrl: string;
  timeout?: number;
  headers?: Record<string, string>;
  tls?: {
    verify: boolean;
    caCertPath?: string;
    clientCertPath?: string;
    clientKeyPath?: string;
  };
}
