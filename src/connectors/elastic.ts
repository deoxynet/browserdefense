/**
 * BrowserDefense Elastic/ELK Stack Connector
 *
 * Sends forensics events to Elasticsearch/OpenSearch using the bulk API.
 * Supports ECS (Elastic Common Schema) field mapping for seamless integration
 * with Kibana SIEM and Elastic Security.
 *
 * Unblock Support:
 * - Indexes an unblock document with ECS fields
 * - Uses event.action='url-unblocked' for correlation
 * - Links to original block via event.id
 */

import { BaseConnector } from './base';
import {
  ElasticConnectorConfig,
  ForensicsEvent,
  SendResult,
  UnblockResult,
} from './types';

// =============================================================================
// ECS Field Mapping
// =============================================================================

/**
 * ECS-compliant document structure for Elastic SIEM integration.
 * Maps BrowserDefense forensics events to Elastic Common Schema fields.
 *
 * @see https://www.elastic.co/guide/en/ecs/current/index.html
 */
export interface EcsDocument {
  // ECS Base fields
  '@timestamp': string;
  message: string;
  tags: string[];

  // ECS Event fields
  event: {
    kind: 'alert';
    category: string[];
    type: string[];
    action: string;
    outcome: 'success';
    id: string;
    created: string;
    original?: string;
  };

  // ECS Threat fields (using enrichments pattern per ECS spec)
  threat: {
    enrichments: Array<{
      matched: {
        atomic: string;
        field: string;
        type: 'indicator_match_rule';
        id: string;
      };
      indicator: {
        type: string;
      };
    }>;
  };

  // ECS URL fields
  url: {
    full: string;
    domain?: string;
    path?: string;
    scheme?: string;
  };

  // ECS User fields (optional)
  user?: {
    id?: string;
  };

  // ECS Host/Device fields (optional)
  host?: {
    id?: string;
  };

  // ECS Organization fields
  organization: {
    id: string;
  };

  // BrowserDefense custom fields (namespaced under browserdefense.*)
  browserdefense: {
    match_type: string;
    matched_indicator: string;
    redirect_chain: string[];
    tab_context: {
      tab_id: number;
      window_id: number;
      initiator_url?: string;
      tab_title?: string;
      incognito: boolean;
    };
  };
}

/**
 * Bulk API action metadata.
 */
interface BulkIndexAction {
  index: {
    _index: string;
    _id?: string;
  };
}

/**
 * Bulk API response.
 */
interface BulkResponse {
  took: number;
  errors: boolean;
  items: Array<{
    index?: {
      _index: string;
      _id: string;
      status: number;
      error?: {
        type: string;
        reason: string;
      };
    };
  }>;
}

// =============================================================================
// Elastic Connector Implementation
// =============================================================================

/**
 * Elasticsearch/OpenSearch connector for BrowserDefense forensics events.
 *
 * Features:
 * - ECS (Elastic Common Schema) field mapping
 * - Bulk API for efficient event ingestion
 * - Date-based index pattern support (e.g., "browserdefense-%{+yyyy.MM.dd}")
 * - Multiple authentication methods (API key, basic auth, cloud ID)
 * - TLS/mTLS support
 *
 * @example
 * ```typescript
 * const connector = new ElasticConnector({
 *   name: 'production-elk',
 *   enabled: true,
 *   type: 'elastic',
 *   nodes: ['https://elasticsearch:9200'],
 *   indexPattern: 'browserdefense-%{+yyyy.MM.dd}',
 *   // API key must be base64-encoded "id:api_key"
 *   apiKey: btoa('your-id:your-api-key'),
 * });
 *
 * await connector.init();
 * await connector.send(event);
 * ```
 */
export class ElasticConnector extends BaseConnector {
  readonly type = 'elastic' as const;

  /**
   * Elastic supports unblock via indexing an unblock document.
   * The document is correlated with the original block by event.id.
   */
  readonly supportsUnblock = true;

  private readonly elasticConfig: ElasticConnectorConfig;
  private currentNodeIndex: number = 0;
  private cloudEndpoint: string | null = null;

  constructor(config: ElasticConnectorConfig) {
    super(config);
    this.elasticConfig = config;

    // Decode Cloud ID if provided
    if (config.cloudId) {
      this.cloudEndpoint = this.decodeCloudId(config.cloudId);
    }
  }

  /**
   * Decode an Elastic Cloud ID to extract the Elasticsearch endpoint URL.
   *
   * Cloud ID format: `name:base64(host$esId$kibanaId)`
   * where host is the base domain and esId is the Elasticsearch subdomain.
   *
   * @see https://github.com/elastic/beats/blob/master/libbeat/cloudid/cloudid.go
   */
  private decodeCloudId(cloudId: string): string {
    // Remove the human-readable prefix (everything before ':')
    const encoded = cloudId.includes(':') ? cloudId.split(':').pop()! : cloudId;

    // Base64 decode
    const decoded = Buffer.from(encoded, 'base64').toString('utf-8');

    // Split by '$': [host, esId, kibanaId, ...]
    const parts = decoded.split('$');
    if (parts.length < 2) {
      throw new Error(
        'Invalid Cloud ID format: expected base64-encoded "host$esId$kibanaId"'
      );
    }

    const [host, esIdWithPort] = parts;

    // Parse port if present (esId:port format), default to 443
    let esId: string;
    let port: string;
    if (esIdWithPort.includes(':')) {
      [esId, port] = esIdWithPort.split(':');
    } else {
      esId = esIdWithPort;
      port = '443';
    }

    return `https://${esId}.${host}:${port}`;
  }

  // ===========================================================================
  // BaseConnector Abstract Method Implementations
  // ===========================================================================

  protected async doInit(): Promise<void> {
    // Validate configuration - nodes required unless cloudId is provided
    const hasCloudId = !!this.cloudEndpoint;
    if (!hasCloudId && (!this.elasticConfig.nodes || this.elasticConfig.nodes.length === 0)) {
      throw new Error('At least one Elasticsearch node URL is required');
    }

    if (!this.elasticConfig.indexPattern) {
      throw new Error('Index pattern is required');
    }

    // Validate authentication - need at least one method
    const hasApiKey = !!this.elasticConfig.apiKey;
    const hasBasicAuth = !!this.elasticConfig.username && !!this.elasticConfig.password;

    if (!hasApiKey && !hasBasicAuth && !hasCloudId) {
      throw new Error(
        'Authentication required: provide apiKey, username/password, or cloudId'
      );
    }

    // Test connection to at least one node
    await this.testConnection();
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    // Transform event to ECS format
    const ecsDoc = this.transformToEcs(event);

    // Calculate index name
    const indexName = this.resolveIndexPattern(new Date(event.timestamp));

    // Build bulk request body
    const action: BulkIndexAction = {
      index: {
        _index: indexName,
        _id: event.eventId,
      },
    };

    const bulkBody = JSON.stringify(action) + '\n' + JSON.stringify(ecsDoc) + '\n';

    // Send to Elasticsearch
    const response = await this.sendBulkRequest(bulkBody);

    if (response.errors) {
      const errorItem = response.items.find((item) => item.index?.error);
      if (errorItem?.index?.error) {
        const isRetryable = this.isRetryableError(errorItem.index.status);
        return {
          success: false,
          eventId: event.eventId,
          error: `${errorItem.index.error.type}: ${errorItem.index.error.reason}`,
          retryable: isRetryable,
        };
      }
    }

    return {
      success: true,
      eventId: event.eventId,
      response: {
        took: response.took,
        index: indexName,
      },
    };
  }

  /**
   * Override sendBatch to use Elasticsearch bulk API efficiently.
   */
  async sendBatch(events: ForensicsEvent[]): Promise<SendResult[]> {
    this.ensureInitialized();

    // Filter events
    const filtered = events.filter((e) => this.shouldProcess(e));

    if (filtered.length === 0) {
      return events.map((e) => ({
        success: true,
        eventId: e.eventId,
        response: { filtered: true },
      }));
    }

    // Build bulk request body for all events
    let bulkBody = '';
    const eventMap = new Map<string, ForensicsEvent>();

    for (const event of filtered) {
      const ecsDoc = this.transformToEcs(event);
      const indexName = this.resolveIndexPattern(new Date(event.timestamp));

      const action: BulkIndexAction = {
        index: {
          _index: indexName,
          _id: event.eventId,
        },
      };

      bulkBody += JSON.stringify(action) + '\n' + JSON.stringify(ecsDoc) + '\n';
      eventMap.set(event.eventId, event);
    }

    // Send bulk request
    const response = await this.sendBulkRequest(bulkBody);

    // Process results
    const results: SendResult[] = [];

    for (const item of response.items) {
      if (item.index) {
        const eventId = item.index._id;

        if (item.index.error) {
          const isRetryable = this.isRetryableError(item.index.status);
          results.push({
            success: false,
            eventId,
            error: `${item.index.error.type}: ${item.index.error.reason}`,
            retryable: isRetryable,
          });
          this.metrics.eventsFailed++;
        } else {
          results.push({
            success: true,
            eventId,
            response: { index: item.index._index },
          });
          this.metrics.eventsSent++;
        }
      }
    }

    // Add filtered events to results
    for (const event of events) {
      if (!this.shouldProcess(event)) {
        results.push({
          success: true,
          eventId: event.eventId,
          response: { filtered: true },
        });
      }
    }

    return results;
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      const node = this.getNextNode();
      const url = `${node}/_cluster/health`;

      const response = await fetch(url, {
        method: 'GET',
        headers: this.buildHeaders(),
      });

      if (!response.ok) {
        return {
          healthy: false,
          message: `Elasticsearch cluster health check failed: ${response.status}`,
        };
      }

      const health = (await response.json()) as { status: string; cluster_name: string };

      // green = all shards assigned, yellow = replicas not assigned, red = some primary shards not assigned
      const isHealthy = health.status === 'green' || health.status === 'yellow';

      return {
        healthy: isHealthy,
        message: `Cluster ${health.cluster_name}: ${health.status}`,
      };
    } catch (error) {
      return {
        healthy: false,
        message: `Health check failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  protected async doClose(): Promise<void> {
    // No persistent connections to close with fetch API
    // In a production implementation, this would close connection pools
  }

  /**
   * Index an unblock document to Elasticsearch for correlation.
   */
  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    try {
      // Transform event to ECS unblock format
      const ecsDoc = this.transformToEcsUnblock(event);

      // Calculate index name using current time
      const indexName = this.resolveIndexPattern(new Date());

      // Build bulk request body
      const action: BulkIndexAction = {
        index: {
          _index: indexName,
          _id: `unblock-${event.eventId}`,
        },
      };

      const bulkBody = JSON.stringify(action) + '\n' + JSON.stringify(ecsDoc) + '\n';

      // Send to Elasticsearch
      const response = await this.sendBulkRequest(bulkBody);

      if (response.errors) {
        const errorItem = response.items.find((item) => item.index?.error);
        if (errorItem?.index?.error) {
          const isRetryable = this.isRetryableError(errorItem.index.status);
          return {
            success: false,
            eventId: event.eventId,
            error: `${errorItem.index.error.type}: ${errorItem.index.error.reason}`,
            retryable: isRetryable,
          };
        }
      }

      return {
        success: true,
        eventId: event.eventId,
        incidentId: `unblock-${event.eventId}`,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        eventId: event.eventId,
        error: `Elastic unblock failed: ${errorMessage}`,
        retryable: true,
      };
    }
  }

  // ===========================================================================
  // ECS Transformation
  // ===========================================================================

  /**
   * Transform a BrowserDefense forensics event to ECS format.
   */
  private transformToEcs(event: ForensicsEvent): EcsDocument {
    const url = this.parseUrl(event.blockedUrl);

    return {
      '@timestamp': event.timestamp,
      message: `BrowserDefense blocked ${event.matchType} match: ${event.matchedIndicator}`,
      tags: ['browserdefense', 'ioc-block', event.matchType],

      event: {
        kind: 'alert',
        category: ['intrusion_detection', 'web'],
        type: ['denied'],
        action: 'url-blocked',
        outcome: 'success',
        id: event.eventId,
        created: event.timestamp,
        original: JSON.stringify(event.raw),
      },

      threat: {
        enrichments: [
          {
            matched: {
              atomic: event.matchedIndicator,
              field: this.getMatchedField(event.matchType),
              type: 'indicator_match_rule',
              id: event.eventId,
            },
            indicator: {
              type: this.mapMatchTypeToEcsIndicatorType(event.matchType),
            },
          },
        ],
      },

      url: {
        full: event.blockedUrl,
        domain: url.hostname || undefined,
        path: url.pathname || undefined,
        scheme: url.protocol?.replace(':', '') || undefined,
      },

      user: event.userId ? { id: event.userId } : undefined,
      host: event.deviceId ? { id: event.deviceId } : undefined,

      organization: {
        id: event.orgId,
      },

      browserdefense: {
        match_type: event.matchType,
        matched_indicator: event.matchedIndicator,
        redirect_chain: event.redirectChain,
        tab_context: {
          tab_id: event.tabContext.tabId,
          window_id: event.tabContext.windowId,
          initiator_url: event.tabContext.initiatorUrl,
          tab_title: event.tabContext.tabTitle,
          incognito: event.tabContext.incognito,
        },
      },
    };
  }

  /**
   * Transform a BrowserDefense forensics event to ECS unblock format.
   */
  private transformToEcsUnblock(event: ForensicsEvent): Record<string, unknown> {
    const url = this.parseUrl(event.blockedUrl);
    const now = new Date().toISOString();

    return {
      '@timestamp': now,
      message: `BrowserDefense unblocked ${event.matchType} match: ${event.matchedIndicator}`,
      tags: ['browserdefense', 'ioc-unblock', event.matchType],

      event: {
        kind: 'alert',
        category: ['intrusion_detection', 'web'],
        type: ['allowed'],
        action: 'url-unblocked',
        outcome: 'success',
        id: event.eventId,
        created: now,
        original_event_id: event.eventId,
      },

      url: {
        full: event.blockedUrl,
        domain: url.hostname || undefined,
        path: url.pathname || undefined,
        scheme: url.protocol?.replace(':', '') || undefined,
      },

      user: event.userId ? { id: event.userId } : undefined,
      host: event.deviceId ? { id: event.deviceId } : undefined,

      organization: {
        id: event.orgId,
      },

      browserdefense: {
        action: 'unblock',
        match_type: event.matchType,
        matched_indicator: event.matchedIndicator,
        original_event_id: event.eventId,
      },
    };
  }

  /**
   * Map BrowserDefense match type to ECS threat indicator type.
   *
   * ECS uses STIX 2.0 cyber observable types for threat.indicator.type.
   * @see https://www.elastic.co/guide/en/ecs/current/ecs-threat.html
   */
  private mapMatchTypeToEcsIndicatorType(matchType: ForensicsEvent['matchType']): string {
    switch (matchType) {
      case 'domain':
        return 'domain-name';
      case 'url':
        return 'url';
      case 'hash':
        // ECS uses 'file' for file hash indicators (STIX 2.0 cyber observable type)
        return 'file';
      default:
        return 'unknown';
    }
  }

  /**
   * Get the ECS field name that was matched for the indicator.
   */
  private getMatchedField(matchType: ForensicsEvent['matchType']): string {
    switch (matchType) {
      case 'domain':
        return 'url.domain';
      case 'url':
        return 'url.full';
      case 'hash':
        return 'file.hash.sha256';
      default:
        return 'unknown';
    }
  }

  /**
   * Parse a URL safely, returning empty strings on failure.
   */
  private parseUrl(urlString: string): Partial<URL> {
    try {
      return new URL(urlString);
    } catch {
      return {};
    }
  }

  // ===========================================================================
  // Index Pattern Resolution
  // ===========================================================================

  /**
   * Resolve index pattern with date placeholders.
   *
   * Supports patterns like:
   * - "browserdefense" (static)
   * - "browserdefense-%{+yyyy.MM.dd}" (daily)
   * - "browserdefense-%{+yyyy.MM}" (monthly)
   * - "browserdefense-%{+yyyy-'W'ww}" (weekly)
   */
  resolveIndexPattern(date: Date): string {
    let pattern = this.elasticConfig.indexPattern;

    // Match %{+format} placeholders
    const formatRegex = /%\{\+([^}]+)\}/g;
    let match: RegExpExecArray | null;

    while ((match = formatRegex.exec(this.elasticConfig.indexPattern)) !== null) {
      const format = match[1];
      const formatted = this.formatDate(date, format);
      pattern = pattern.replace(match[0], formatted);
    }

    return pattern.toLowerCase();
  }

  /**
   * Format a date according to Elasticsearch date format patterns.
   */
  private formatDate(date: Date, format: string): string {
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, '0');
    const day = String(date.getUTCDate()).padStart(2, '0');
    const hour = String(date.getUTCHours()).padStart(2, '0');

    // Calculate week number (ISO 8601)
    const weekNumber = this.getWeekNumber(date);

    return format
      .replace(/yyyy/g, String(year))
      .replace(/yy/g, String(year).slice(-2))
      .replace(/MM/g, month)
      .replace(/dd/g, day)
      .replace(/HH/g, hour)
      .replace(/ww/g, String(weekNumber).padStart(2, '0'))
      .replace(/'W'/g, 'W');
  }

  /**
   * Get ISO week number for a date.
   */
  private getWeekNumber(date: Date): number {
    const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
    const dayNum = d.getUTCDay() || 7;
    d.setUTCDate(d.getUTCDate() + 4 - dayNum);
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.ceil((((d.getTime() - yearStart.getTime()) / 86400000) + 1) / 7);
  }

  // ===========================================================================
  // HTTP Communication
  // ===========================================================================

  /**
   * Test connection to Elasticsearch cluster.
   */
  private async testConnection(): Promise<void> {
    const node = this.getNextNode();

    try {
      const response = await fetch(node, {
        method: 'GET',
        headers: this.buildHeaders(),
      });

      if (!response.ok) {
        throw new Error(`Connection failed: ${response.status} ${response.statusText}`);
      }

      const info = (await response.json()) as { cluster_name?: string; version?: { number?: string } };
      console.log(
        `[ElasticConnector] Connected to cluster: ${info.cluster_name}, ` +
        `version: ${info.version?.number}`
      );
    } catch (error) {
      throw new Error(
        `Failed to connect to Elasticsearch at ${node}: ` +
        `${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Send a bulk request to Elasticsearch.
   */
  private async sendBulkRequest(body: string): Promise<BulkResponse> {
    const node = this.getNextNode();
    const url = `${node}/_bulk`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        ...this.buildHeaders(),
        'Content-Type': 'application/x-ndjson',
      },
      body,
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Bulk request failed: ${response.status} - ${text}`);
    }

    return response.json() as Promise<BulkResponse>;
  }

  /**
   * Build HTTP headers for Elasticsearch requests.
   */
  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
    };

    if (this.elasticConfig.apiKey) {
      headers['Authorization'] = `ApiKey ${this.elasticConfig.apiKey}`;
    } else if (this.elasticConfig.username && this.elasticConfig.password) {
      const credentials = Buffer.from(
        `${this.elasticConfig.username}:${this.elasticConfig.password}`
      ).toString('base64');
      headers['Authorization'] = `Basic ${credentials}`;
    }

    return headers;
  }

  /**
   * Get next node URL with round-robin load balancing.
   * If Cloud ID is configured, uses the decoded cloud endpoint instead.
   */
  private getNextNode(): string {
    // Use cloud endpoint if available (Cloud ID was decoded in constructor)
    if (this.cloudEndpoint) {
      return this.cloudEndpoint;
    }

    const node = this.elasticConfig.nodes[this.currentNodeIndex];
    this.currentNodeIndex = (this.currentNodeIndex + 1) % this.elasticConfig.nodes.length;
    return node.replace(/\/$/, ''); // Remove trailing slash
  }

  /**
   * Determine if an HTTP status code indicates a retryable error.
   */
  private isRetryableError(status: number): boolean {
    // Retry on server errors and rate limiting
    return status >= 500 || status === 429;
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

import { connectorRegistry } from './base';

/**
 * Factory function for creating ElasticConnector instances.
 */
export function createElasticConnector(config: ElasticConnectorConfig): ElasticConnector {
  return new ElasticConnector(config);
}

// Register with global connector registry
connectorRegistry.register('elastic', createElasticConnector);
