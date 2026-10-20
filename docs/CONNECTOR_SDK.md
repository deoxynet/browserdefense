# BrowserDefense Connector SDK

Build enterprise connectors to forward decrypted forensics events from BrowserDefense to your security stack.

## Overview

BrowserDefense connectors run on-premises (or in your private cloud) and receive encrypted forensics events from browser extensions. The connector service:

1. Receives encrypted payloads via HTTPS
2. Decrypts using customer-held RSA private keys
3. Forwards plaintext events to configured destinations

```
Browser Extension ──(encrypted)──> Connector Service ──(plaintext)──> SIEM/EDR/SOAR
                                         │
                                   Customer's RSA
                                   Private Key
```

**Key principle:** Private keys never leave the customer environment. BrowserDefense cannot decrypt your forensics data.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CONNECTOR SERVICE                                                          │
│                                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌─────────────────────────────┐ │
│  │  Ingest API  │────▶│  Decryption  │────▶│  Connector Framework        │ │
│  │  (HTTPS)     │     │  Engine      │     │                             │ │
│  └──────────────┘     └──────────────┘     │  ┌───────┐ ┌───────────┐   │ │
│         │                    │             │  │Splunk │ │CrowdStrike│   │ │
│         │              ┌─────┴─────┐       │  └───────┘ └───────────┘   │ │
│         │              │ Key Store │       │  ┌───────┐ ┌───────────┐   │ │
│         │              └───────────┘       │  │Elastic│ │ Webhook   │   │ │
│         │                                  │  └───────┘ └───────────┘   │ │
│  ┌──────┴───────┐                          └─────────────────────────────┘ │
│  │ Health/      │                                                          │
│  │ Metrics      │                                                          │
│  └──────────────┘                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Install the SDK

```bash
# For TypeScript/Node.js implementations
npm install @browserdefense/connector-sdk

# For Rust implementations
cargo add browserdefense-connector
```

### 2. Implement the Connector Interface

```typescript
import {
  BaseConnector,
  ForensicsEvent,
  SendResult,
  SplunkConnectorConfig,
} from '@browserdefense/connector-sdk';

export class SplunkConnector extends BaseConnector {
  readonly type = 'splunk' as const;
  private client: HecClient;

  constructor(private splunkConfig: SplunkConnectorConfig) {
    super(splunkConfig);
  }

  protected async doInit(): Promise<void> {
    this.client = new HecClient({
      url: this.splunkConfig.hecUrl,
      token: this.splunkConfig.hecToken,
    });
    await this.client.connect();
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    const splunkEvent = this.transform(event);
    const response = await this.client.send(splunkEvent);

    return {
      success: response.status === 200,
      eventId: event.eventId,
      retryable: response.status >= 500,
    };
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    const healthy = await this.client.ping();
    return {
      healthy,
      message: healthy ? 'Connected to Splunk HEC' : 'Cannot reach Splunk HEC',
    };
  }

  protected async doClose(): Promise<void> {
    await this.client.disconnect();
  }

  private transform(event: ForensicsEvent): SplunkEvent {
    return {
      time: new Date(event.timestamp).getTime() / 1000,
      source: 'browserdefense',
      sourcetype: 'browserdefense:forensics',
      index: this.splunkConfig.index,
      event: {
        blocked_url: event.blockedUrl,
        redirect_chain: event.redirectChain,
        match_type: event.matchType,
        matched_indicator: event.matchedIndicator,
        org_id: event.orgId,
        user_id: event.userId,
        device_id: event.deviceId,
        tab: {
          id: event.tabContext.tabId,
          title: event.tabContext.tabTitle,
          initiator: event.tabContext.initiatorUrl,
        },
      },
    };
  }
}
```

### 3. Register Your Connector

```typescript
import { connectorRegistry } from '@browserdefense/connector-sdk';
import { SplunkConnector } from './splunk-connector';

connectorRegistry.register('splunk', (config) => new SplunkConnector(config));
```

## Core Concepts

### ForensicsEvent

The primary data structure your connector receives after decryption:

```typescript
// IOC action type - block or unblock
type IocAction = 'block' | 'unblock';

interface ForensicsEvent {
  // Action type - block or unblock (defaults to 'block' for backwards compat)
  action?: IocAction;

  // The blocked URL that triggered the event
  blockedUrl: string;

  // ISO8601 timestamp when the block occurred
  timestamp: string;

  // Chain of redirects leading to the blocked URL
  redirectChain: string[];

  // Browser tab context at block time
  tabContext: {
    tabId: number;
    windowId: number;
    initiatorUrl?: string;
    tabTitle?: string;
    incognito: boolean;
  };

  // Organization identifier for multi-tenant deployments
  orgId: string;

  // Unique event identifier
  eventId: string;

  // IOC type that matched (domain, url, hash)
  matchType: 'domain' | 'url' | 'hash';

  // The specific IOC pattern that matched
  matchedIndicator: string;

  // User identifier (if available from enterprise directory)
  userId?: string;

  // Device identifier (if available from MDM)
  deviceId?: string;

  // Original raw decrypted payload for custom processing
  raw: Record<string, unknown>;
}
```

### Connector Lifecycle

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ construct│────▶│  init()  │────▶│  send()  │────▶│  close() │
└──────────┘     └──────────┘     │ unblock()│     └──────────┘
                      │           └──────────┘
                      │                │
                      │           ┌────┴────┐
                      │           │ health()│
                      │           └─────────┘
                      ▼
               Connection
               established
```

1. **Constructor**: Receive configuration, do NOT connect yet
2. **init()**: Establish connections, validate credentials
3. **send()**: Called for block events (with retry/batch support)
4. **unblock()**: Called for unblock events (if connector supports it)
5. **health()**: Called periodically for monitoring
6. **close()**: Clean shutdown, flush buffers

### Retry and Batching

The `BaseConnector` class provides built-in retry and batching support:

```typescript
// Configuration in connector config
{
  "name": "my-splunk",
  "type": "splunk",
  "retry": {
    "maxAttempts": 3,
    "initialDelayMs": 1000,
    "maxDelayMs": 30000,
    "backoffMultiplier": 2
  },
  "batch": {
    "maxSize": 100,
    "maxWaitMs": 5000
  }
}
```

Return `retryable: true` in `SendResult` to indicate transient failures:

```typescript
return {
  success: false,
  eventId: event.eventId,
  error: 'Connection timeout',
  retryable: true,  // Will retry with exponential backoff
};
```

### Event Filtering

Filter events before they reach your connector:

```typescript
{
  "name": "security-team-splunk",
  "type": "splunk",
  "filter": {
    // Only forward events from these orgs
    "orgIds": ["org-123", "org-456"],

    // Only forward domain and URL blocks
    "matchTypes": ["domain", "url"],

    // Exclude test patterns
    "excludePatterns": [".*\\.test\\.example\\.com$"]
  }
}
```

### Block and Unblock Support

Events can have an `action` field indicating whether to block or unblock an IOC:

- **`block`** (default): Create an incident, add IOC to blocklist, trigger alert
- **`unblock`**: Close incident, remove IOC from blocklist, resolve alert

#### Implementing Unblock Support

To support unblock operations in your connector:

1. Override `supportsUnblock` to return `true`
2. Implement the `doUnblock()` method

```typescript
export class MyPlatformConnector extends BaseConnector {
  readonly type = 'my-platform' as const;

  // Enable unblock support
  readonly supportsUnblock = true;

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    // Handle block events
    const response = await this.client.createIncident({
      indicator: event.matchedIndicator,
      url: event.blockedUrl,
    });

    return {
      success: true,
      eventId: event.eventId,
      response: { incidentId: response.id },
    };
  }

  protected async doUnblock(event: ForensicsEvent): Promise<UnblockResult> {
    // Find and close the incident for this indicator
    const incidents = await this.client.findIncidents({
      indicator: event.matchedIndicator,
      status: 'open',
    });

    if (incidents.length === 0) {
      return {
        success: true,
        eventId: event.eventId,
        alreadyClosed: true,
      };
    }

    await this.client.closeIncident(incidents[0].id, {
      resolution: 'IOC unblocked via BrowserDefense',
    });

    return {
      success: true,
      eventId: event.eventId,
      incidentId: incidents[0].id,
    };
  }
}
```

#### Default Behavior for Unsupported Connectors

Connectors that don't implement `doUnblock()` will:
- Return `success: true` for unblock events (no-op)
- Not throw errors or fail the event processing

This allows mixed connector configurations where some connectors support unblock and others don't.

## Supported Connector Types

### SIEMs

| Type | Platform | Configuration |
|------|----------|---------------|
| `splunk` | Splunk HEC | `hecUrl`, `hecToken`, `index` |
| `elastic` | Elasticsearch/OpenSearch | `nodes`, `apiKey`, `indexPattern` |
| `syslog` | Generic Syslog (RFC 5424) | `host`, `port`, `protocol` |

### EDRs

| Type | Platform | Configuration |
|------|----------|---------------|
| `crowdstrike` | CrowdStrike Falcon | `baseUrl`, `clientId`, `clientSecret` |
| `sentinelone` | SentinelOne | `consoleUrl`, `apiToken` |
| `defender` | Microsoft Defender | `tenantId`, `clientId`, `clientSecret` |

### SOARs

| Type | Platform | Configuration |
|------|----------|---------------|
| `webhook` | Generic Webhook | `url`, `method`, `headers`, `auth` |
| `xsoar` | Palo Alto XSOAR | `serverUrl`, `apiKey`, `incidentType` |

## Configuration Reference

### Full Service Configuration

```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls:
    certPath: "/etc/browserdefense/tls/server.crt"
    keyPath: "/etc/browserdefense/tls/server.key"
    verify: true
    minVersion: "TLS1.2"
  apiKeys:
    - "your-api-key-here"
  timeoutSeconds: 30
  maxBodyBytes: 10485760  # 10MB

keyStore:
  type: "vault"  # or "file", "env"
  vault:
    address: "https://vault.internal:8200"
    authMethod: "kubernetes"
    k8sRole: "browserdefense-connector"
    mountPath: "secret"
    secretPath: "browserdefense/keys/{org_id}"

connectors:
  - name: "prod-splunk"
    type: "splunk"
    enabled: true
    hecUrl: "https://splunk.internal:8088"
    hecToken: "${SPLUNK_HEC_TOKEN}"
    index: "browserdefense"
    sourceType: "browserdefense:forensics"
    retry:
      maxAttempts: 5
      initialDelayMs: 1000
    batch:
      maxSize: 100
      maxWaitMs: 5000

  - name: "security-webhook"
    type: "webhook"
    enabled: true
    url: "https://soar.internal/api/alerts"
    method: "POST"
    auth:
      type: "bearer"
      token: "${SOAR_API_TOKEN}"
    filter:
      matchTypes: ["domain"]  # Only domain blocks

logging:
  level: "info"
  format: "json"
  auditLogPath: "/var/log/browserdefense/audit.log"

metrics:
  enabled: true
  path: "/metrics"
  port: 9090
```

### Splunk HEC Configuration

```typescript
interface SplunkConnectorConfig {
  type: 'splunk';
  name: string;
  enabled: boolean;

  // Required
  hecUrl: string;      // e.g., "https://splunk.internal:8088"
  hecToken: string;    // HEC token

  // Optional
  index?: string;      // Target index (default: "main")
  sourceType?: string; // Source type (default: "browserdefense:forensics")
  source?: string;     // Source identifier
  host?: string;       // Host value for events

  // TLS configuration
  tls?: {
    verify: boolean;
    caCertPath?: string;
  };
}
```

### Elasticsearch Configuration

```typescript
interface ElasticConnectorConfig {
  type: 'elastic';
  name: string;
  enabled: boolean;

  // Required
  nodes: string[];           // e.g., ["https://es1:9200", "https://es2:9200"]
  indexPattern: string;      // e.g., "browserdefense-{yyyy.MM.dd}"

  // Authentication (choose one)
  apiKey?: string;           // API key authentication
  username?: string;         // Basic auth username
  password?: string;         // Basic auth password
  cloudId?: string;          // Elastic Cloud ID

  // TLS configuration
  tls?: {
    verify: boolean;
    caCertPath?: string;
  };
}
```

### CrowdStrike Configuration

```typescript
interface CrowdStrikeConnectorConfig {
  type: 'crowdstrike';
  name: string;
  enabled: boolean;

  // Required
  baseUrl: string;       // e.g., "https://api.crowdstrike.com"
  clientId: string;      // OAuth2 client ID
  clientSecret: string;  // OAuth2 client secret

  // Optional
  iocTarget?: 'ioc-manager' | 'intel-indicator';
}
```

### Generic Webhook Configuration

```typescript
interface WebhookConnectorConfig {
  type: 'webhook';
  name: string;
  enabled: boolean;

  // Required
  url: string;
  method: 'POST' | 'PUT';

  // Optional
  headers?: Record<string, string>;
  auth?: {
    type: 'bearer' | 'basic' | 'api-key' | 'oauth2';
    token?: string;       // For bearer auth
    username?: string;    // For basic auth
    password?: string;    // For basic auth
    apiKeyHeader?: string; // For API key auth
    apiKey?: string;       // For API key auth
    oauth2?: {            // For OAuth2
      tokenUrl: string;
      clientId: string;
      clientSecret: string;
      scopes?: string[];
    };
  };

  // Template for custom payload transformation (Handlebars)
  template?: string;
}
```

## Building a Custom Connector

### Step 1: Define Your Configuration Type

```typescript
// my-platform-connector.ts
import { BaseConnectorConfig } from '@browserdefense/connector-sdk';

export interface MyPlatformConnectorConfig extends BaseConnectorConfig {
  type: 'my-platform';
  apiEndpoint: string;
  apiKey: string;
  customField?: string;
}
```

### Step 2: Implement the Connector

```typescript
import {
  BaseConnector,
  ForensicsEvent,
  SendResult,
} from '@browserdefense/connector-sdk';
import { MyPlatformConnectorConfig } from './config';

export class MyPlatformConnector extends BaseConnector {
  readonly type = 'my-platform' as const;
  private apiClient: MyPlatformClient | null = null;

  constructor(private platformConfig: MyPlatformConnectorConfig) {
    super(platformConfig);
  }

  protected async doInit(): Promise<void> {
    // Validate configuration
    if (!this.platformConfig.apiEndpoint) {
      throw new Error('apiEndpoint is required');
    }

    // Initialize client
    this.apiClient = new MyPlatformClient({
      endpoint: this.platformConfig.apiEndpoint,
      apiKey: this.platformConfig.apiKey,
    });

    // Test connection
    await this.apiClient.ping();
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    if (!this.apiClient) {
      throw new Error('Connector not initialized');
    }

    try {
      const payload = this.transformEvent(event);
      const response = await this.apiClient.createAlert(payload);

      return {
        success: true,
        eventId: event.eventId,
        response: { alertId: response.id },
      };
    } catch (error) {
      const isRetryable = this.isRetryableError(error);
      return {
        success: false,
        eventId: event.eventId,
        error: error.message,
        retryable: isRetryable,
      };
    }
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    if (!this.apiClient) {
      return { healthy: false, message: 'Not initialized' };
    }

    try {
      await this.apiClient.ping();
      return { healthy: true, message: 'Connected' };
    } catch (error) {
      return { healthy: false, message: error.message };
    }
  }

  protected async doClose(): Promise<void> {
    if (this.apiClient) {
      await this.apiClient.disconnect();
      this.apiClient = null;
    }
  }

  private transformEvent(event: ForensicsEvent): MyPlatformAlert {
    return {
      title: `BrowserDefense: Blocked ${event.matchType} - ${event.matchedIndicator}`,
      severity: 'high',
      timestamp: event.timestamp,
      source: 'browserdefense',
      details: {
        blocked_url: event.blockedUrl,
        redirect_chain: event.redirectChain,
        user: event.userId,
        device: event.deviceId,
      },
    };
  }

  private isRetryableError(error: any): boolean {
    // Retry on network errors and 5xx responses
    return error.code === 'ECONNRESET' ||
           error.code === 'ETIMEDOUT' ||
           (error.status && error.status >= 500);
  }
}
```

### Step 3: Register and Use

```typescript
import { connectorRegistry, ConnectorServiceConfig } from '@browserdefense/connector-sdk';
import { MyPlatformConnector, MyPlatformConnectorConfig } from './my-platform-connector';

// Register the connector type
connectorRegistry.register('my-platform', (config) =>
  new MyPlatformConnector(config as MyPlatformConnectorConfig)
);

// Now it can be used in configuration
const config: ConnectorServiceConfig = {
  connectors: [
    {
      type: 'my-platform',
      name: 'production',
      enabled: true,
      apiEndpoint: 'https://api.myplatform.com',
      apiKey: process.env.MY_PLATFORM_API_KEY,
    },
  ],
  // ... rest of config
};
```

## Testing Your Connector

### Unit Testing

```typescript
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MyPlatformConnector } from './my-platform-connector';

describe('MyPlatformConnector', () => {
  let connector: MyPlatformConnector;

  beforeEach(() => {
    connector = new MyPlatformConnector({
      type: 'my-platform',
      name: 'test',
      enabled: true,
      apiEndpoint: 'https://test.api.com',
      apiKey: 'test-key',
    });
  });

  afterEach(async () => {
    await connector.close();
  });

  it('should initialize successfully', async () => {
    // Mock the API client
    vi.spyOn(connector as any, 'doInit').mockResolvedValue(undefined);

    await expect(connector.init()).resolves.not.toThrow();
  });

  it('should send events successfully', async () => {
    await connector.init();

    const event = createTestEvent();
    const result = await connector.send(event);

    expect(result.success).toBe(true);
    expect(result.eventId).toBe(event.eventId);
  });

  it('should retry on transient failures', async () => {
    await connector.init();

    // First call fails, second succeeds
    const sendSpy = vi.spyOn(connector as any, 'doSend')
      .mockRejectedValueOnce(new Error('Connection timeout'))
      .mockResolvedValueOnce({ success: true, eventId: 'test' });

    const event = createTestEvent();
    const result = await connector.send(event);

    expect(sendSpy).toHaveBeenCalledTimes(2);
    expect(result.success).toBe(true);
  });
});

function createTestEvent(): ForensicsEvent {
  return {
    eventId: 'test-event-123',
    blockedUrl: 'https://evil.com/phish',
    timestamp: new Date().toISOString(),
    redirectChain: ['https://example.com', 'https://evil.com/phish'],
    tabContext: {
      tabId: 1,
      windowId: 1,
      incognito: false,
    },
    orgId: 'org-123',
    matchType: 'domain',
    matchedIndicator: 'evil.com',
    raw: {},
  };
}
```

### Integration Testing

```typescript
import { describe, it, expect } from 'vitest';
import { MyPlatformConnector } from './my-platform-connector';

describe('MyPlatformConnector Integration', () => {
  // Skip if no test endpoint configured
  const testEndpoint = process.env.TEST_PLATFORM_ENDPOINT;
  const testApiKey = process.env.TEST_PLATFORM_API_KEY;

  it.skipIf(!testEndpoint)('should connect to real endpoint', async () => {
    const connector = new MyPlatformConnector({
      type: 'my-platform',
      name: 'integration-test',
      enabled: true,
      apiEndpoint: testEndpoint!,
      apiKey: testApiKey!,
    });

    await connector.init();

    const health = await connector.health();
    expect(health.healthy).toBe(true);

    await connector.close();
  });
});
```

## Deployment

### Docker

```dockerfile
FROM rust:1.75-slim as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/browserdefense-connector /usr/local/bin/

EXPOSE 8443 9090
ENTRYPOINT ["browserdefense-connector"]
CMD ["--config", "/etc/browserdefense/config.yaml"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: browserdefense-connector
spec:
  replicas: 2
  selector:
    matchLabels:
      app: browserdefense-connector
  template:
    metadata:
      labels:
        app: browserdefense-connector
    spec:
      containers:
        - name: connector
          image: browserdefense/connector:latest
          ports:
            - containerPort: 8443
              name: https
            - containerPort: 9090
              name: metrics
          volumeMounts:
            - name: config
              mountPath: /etc/browserdefense
            - name: tls
              mountPath: /etc/browserdefense/tls
          env:
            - name: SPLUNK_HEC_TOKEN
              valueFrom:
                secretKeyRef:
                  name: browserdefense-secrets
                  key: splunk-hec-token
      volumes:
        - name: config
          configMap:
            name: browserdefense-config
        - name: tls
          secret:
            secretName: browserdefense-tls
---
apiVersion: v1
kind: Service
metadata:
  name: browserdefense-connector
spec:
  ports:
    - port: 8443
      targetPort: 8443
      name: https
    - port: 9090
      targetPort: 9090
      name: metrics
  selector:
    app: browserdefense-connector
```

### Health Checks

The connector exposes health endpoints:

```
GET /health          # Liveness probe
GET /health/ready    # Readiness probe (checks all connectors)
GET /metrics         # Prometheus metrics
```

Example Prometheus metrics:

```
# HELP browserdefense_events_total Total events processed
# TYPE browserdefense_events_total counter
browserdefense_events_total{connector="prod-splunk",status="success"} 12345
browserdefense_events_total{connector="prod-splunk",status="failed"} 23

# HELP browserdefense_event_latency_seconds Event processing latency
# TYPE browserdefense_event_latency_seconds histogram
browserdefense_event_latency_seconds_bucket{connector="prod-splunk",le="0.1"} 10000
browserdefense_event_latency_seconds_bucket{connector="prod-splunk",le="0.5"} 12000

# HELP browserdefense_connector_health Connector health status
# TYPE browserdefense_connector_health gauge
browserdefense_connector_health{connector="prod-splunk"} 1
```

## Security Considerations

### Key Management

- **Never store private keys in configuration files.** Use environment variables, HashiCorp Vault, or cloud KMS.
- Rotate keys regularly (recommended: every 90 days)
- Use separate keys for each organization in multi-tenant deployments

### TLS Configuration

Always use TLS 1.2+ for the ingest endpoint:

```yaml
server:
  tls:
    certPath: "/etc/browserdefense/tls/server.crt"
    keyPath: "/etc/browserdefense/tls/server.key"
    verify: true
    minVersion: "TLS1.2"
```

### Audit Logging

Enable audit logging to track all decrypt operations:

```yaml
logging:
  auditLogPath: "/var/log/browserdefense/audit.log"
```

Audit log format:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "action": "decrypt",
  "org_id": "org-123",
  "event_id": "evt-456",
  "key_version": 1,
  "source_ip": "10.0.0.5",
  "connectors_notified": ["prod-splunk", "security-webhook"]
}
```

## Troubleshooting

### Common Issues

**Connector fails to initialize:**
- Check API credentials and endpoint URLs
- Verify TLS certificates if using mTLS
- Ensure network connectivity to the target platform

**Events not appearing in destination:**
- Check connector health: `GET /health/ready`
- Review logs for send failures
- Verify filter configuration isn't excluding events
- Check batch configuration (events may be buffered)

**High latency:**
- Reduce batch size for lower latency
- Check network latency to destination
- Review connector metrics for bottlenecks

**Memory usage growing:**
- Check retry queue size in metrics
- Reduce `maxAttempts` if destination is persistently unavailable
- Enable batching to reduce per-event overhead

### Debug Logging

Enable debug logging for troubleshooting:

```yaml
logging:
  level: "debug"
```

Or via environment variable:

```bash
BROWSERDEFENSE_LOG_LEVEL=debug browserdefense-connector --config /etc/browserdefense/config.yaml
```

## API Reference

### Ingest Endpoint

```
POST /v1/forensics
Content-Type: application/json
Authorization: Bearer <api-key>

{
  "encrypted_key": "<base64>",   // RSA-OAEP encrypted AES key
  "iv": "<base64>",              // 96-bit IV
  "ciphertext": "<base64>",      // AES-GCM encrypted payload
  "org_id": "<string>",          // For multi-tenant key lookup
  "key_version": 1,              // Key version for rotation
  "timestamp": "<ISO8601>"
}
```

Response:

```json
{
  "status": "accepted",
  "event_id": "evt-abc123"
}
```

### Health Endpoints

```
GET /health
{
  "status": "healthy"
}

GET /health/ready
{
  "status": "ready",
  "connectors": {
    "prod-splunk": { "healthy": true, "message": "Connected" },
    "security-webhook": { "healthy": true, "message": "Connected" }
  }
}
```

## Support

- GitHub Issues: https://github.com/irdbl/browserdefense/issues
- Documentation: https://docs.browserdefense.com/connectors
- Security issues: security@browserdefense.com
