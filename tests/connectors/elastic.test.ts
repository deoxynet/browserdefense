/**
 * ElasticConnector Tests
 *
 * Tests for the Elasticsearch/OpenSearch connector including:
 * - Configuration validation
 * - ECS field mapping
 * - Index pattern resolution
 * - Bulk API integration
 * - Error handling and retries
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ElasticConnector, EcsDocument, createElasticConnector } from '../../src/connectors/elastic';
import { ElasticConnectorConfig, ForensicsEvent } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestConfig(overrides: Partial<ElasticConnectorConfig> = {}): ElasticConnectorConfig {
  return {
    name: 'test-elastic',
    enabled: true,
    type: 'elastic',
    nodes: ['https://localhost:9200'],
    indexPattern: 'browserdefense-%{+yyyy.MM.dd}',
    apiKey: 'test-api-key',
    // Disable batching for tests to ensure immediate sends
    batch: { maxSize: 1, maxWaitMs: 0 },
    ...overrides,
  };
}

function createTestEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    eventId: 'evt-12345',
    blockedUrl: 'https://malware.example.com/payload.exe',
    timestamp: '2024-01-15T10:30:00.000Z',
    matchType: 'domain',
    matchedIndicator: 'malware.example.com',
    redirectChain: ['https://legit.com', 'https://redirect.example.com'],
    orgId: 'org-abc',
    tabContext: {
      tabId: 123,
      windowId: 1,
      initiatorUrl: 'https://email.example.com/message',
      tabTitle: 'Email - Important Message',
      incognito: false,
    },
    raw: { originalPayload: true },
    ...overrides,
  };
}

// =============================================================================
// Mock Fetch
// =============================================================================

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// =============================================================================
// Configuration Tests
// =============================================================================

describe('ElasticConnector Configuration', () => {
  it('should reject config without nodes', async () => {
    const config = createTestConfig({ nodes: [] });
    const connector = new ElasticConnector(config);

    await expect(connector.init()).rejects.toThrow('At least one Elasticsearch node URL is required');
  });

  it('should reject config without index pattern', async () => {
    const config = createTestConfig({ indexPattern: '' });
    const connector = new ElasticConnector(config);

    await expect(connector.init()).rejects.toThrow('Index pattern is required');
  });

  it('should reject config without authentication', async () => {
    const config = createTestConfig({
      apiKey: undefined,
      username: undefined,
      password: undefined,
      cloudId: undefined,
    });
    const connector = new ElasticConnector(config);

    await expect(connector.init()).rejects.toThrow('Authentication required');
  });

  it('should accept config with API key auth', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({ apiKey: 'test-key' });
    const connector = new ElasticConnector(config);

    await expect(connector.init()).resolves.toBeUndefined();
  });

  it('should accept config with basic auth', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({
      apiKey: undefined,
      username: 'elastic',
      password: 'changeme',
    });
    const connector = new ElasticConnector(config);

    await expect(connector.init()).resolves.toBeUndefined();
  });

  it('should accept config with cloud ID', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'cloud-cluster', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({
      apiKey: undefined,
      cloudId: 'my-deployment:dXMtZWFzdC0xLmF3cy5mb3VuZC5pbzo0NDMkc29tZWlkJA==',
    });
    const connector = new ElasticConnector(config);

    await expect(connector.init()).resolves.toBeUndefined();
  });

  it('should reject invalid cloud ID format', () => {
    // Cloud ID with invalid base64 that doesn't contain '$' separator
    const invalidCloudId = Buffer.from('invalid-format').toString('base64');
    const config = createTestConfig({
      apiKey: undefined,
      cloudId: `my-deployment:${invalidCloudId}`,
    });

    expect(() => new ElasticConnector(config)).toThrow('Invalid Cloud ID format');
  });
});

// =============================================================================
// Cloud ID Decoding Tests
// =============================================================================

describe('ElasticConnector Cloud ID Decoding', () => {
  it('should decode cloud ID and use extracted endpoint', async () => {
    // Cloud ID format: name:base64(host$esId$kibanaId)
    // Note: host contains the domain without port, esId can include port (esId:port)
    const cloudIdPayload = 'us-east-1.aws.found.io$my-es-id:9243$my-kb-id';
    const encodedPayload = Buffer.from(cloudIdPayload).toString('base64');
    const cloudId = `my-deployment:${encodedPayload}`;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'cloud-cluster', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({
      nodes: [], // Empty nodes array - should use cloud endpoint
      cloudId,
    });
    const connector = new ElasticConnector(config);
    await connector.init();

    // Check that the decoded endpoint was used with specified port
    expect(mockFetch).toHaveBeenCalledWith(
      'https://my-es-id.us-east-1.aws.found.io:9243',
      expect.anything()
    );
  });

  it('should decode cloud ID without port (default to 443)', async () => {
    // Cloud ID without explicit port
    const cloudIdPayload = 'us-east-1.aws.found.io$es-cluster-id$kb-id';
    const encodedPayload = Buffer.from(cloudIdPayload).toString('base64');
    const cloudId = `production:${encodedPayload}`;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'prod', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({
      nodes: [],
      cloudId,
    });
    const connector = new ElasticConnector(config);
    await connector.init();

    // Should default to port 443
    expect(mockFetch).toHaveBeenCalledWith(
      'https://es-cluster-id.us-east-1.aws.found.io:443',
      expect.anything()
    );
  });

  it('should decode cloud ID without human-readable prefix', async () => {
    // Cloud ID without the "name:" prefix (just the base64 part)
    const cloudIdPayload = 'elastic.cloud$my-cluster$kibana';
    const encodedPayload = Buffer.from(cloudIdPayload).toString('base64');

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({
      nodes: [],
      cloudId: encodedPayload, // No prefix
    });
    const connector = new ElasticConnector(config);
    await connector.init();

    expect(mockFetch).toHaveBeenCalledWith(
      'https://my-cluster.elastic.cloud:443',
      expect.anything()
    );
  });

  it('should use cloud endpoint for bulk requests', async () => {
    const cloudIdPayload = 'cloud.example.com$es-prod$kb-prod';
    const encodedPayload = Buffer.from(cloudIdPayload).toString('base64');

    // Mock init connection
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'cloud', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({
      nodes: [],
      cloudId: `prod:${encodedPayload}`,
    });
    const connector = new ElasticConnector(config);
    await connector.init();

    // Mock bulk response
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 5,
          errors: false,
          items: [{ index: { _index: 'blockioc-2024.01.15', _id: 'evt-12345', status: 201 } }],
        }),
    });

    const event = createTestEvent();
    await connector.send(event);

    // Second call should be bulk request to cloud endpoint
    expect(mockFetch.mock.calls[1][0]).toBe('https://es-prod.cloud.example.com:443/_bulk');
  });
});

// =============================================================================
// Index Pattern Tests
// =============================================================================

describe('ElasticConnector Index Pattern Resolution', () => {
  let connector: ElasticConnector;

  beforeEach(async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    connector = new ElasticConnector(createTestConfig());
    await connector.init();
  });

  it('should resolve static index pattern', () => {
    const connector2 = new ElasticConnector(createTestConfig({ indexPattern: 'browserdefense-events' }));
    const date = new Date('2024-03-15T10:30:00Z');

    expect(connector2.resolveIndexPattern(date)).toBe('browserdefense-events');
  });

  it('should resolve daily index pattern', () => {
    const date = new Date('2024-03-15T10:30:00Z');

    expect(connector.resolveIndexPattern(date)).toBe('browserdefense-2024.03.15');
  });

  it('should resolve monthly index pattern', () => {
    const connector2 = new ElasticConnector(
      createTestConfig({ indexPattern: 'browserdefense-%{+yyyy.MM}' })
    );
    const date = new Date('2024-03-15T10:30:00Z');

    expect(connector2.resolveIndexPattern(date)).toBe('browserdefense-2024.03');
  });

  it('should resolve weekly index pattern', () => {
    const connector2 = new ElasticConnector(
      createTestConfig({ indexPattern: "browserdefense-%{+yyyy-'W'ww}" })
    );
    // March 15, 2024 is in week 11
    const date = new Date('2024-03-15T10:30:00Z');

    expect(connector2.resolveIndexPattern(date)).toBe('browserdefense-2024-w11');
  });

  it('should handle multiple placeholders', () => {
    const connector2 = new ElasticConnector(
      createTestConfig({ indexPattern: 'browserdefense-%{+yyyy}-%{+MM}-%{+dd}' })
    );
    const date = new Date('2024-03-15T10:30:00Z');

    expect(connector2.resolveIndexPattern(date)).toBe('browserdefense-2024-03-15');
  });

  it('should convert index name to lowercase', () => {
    const connector2 = new ElasticConnector(
      createTestConfig({ indexPattern: 'BrowserDefense-%{+yyyy.MM.dd}' })
    );
    const date = new Date('2024-03-15T10:30:00Z');

    expect(connector2.resolveIndexPattern(date)).toBe('browserdefense-2024.03.15');
  });
});

// =============================================================================
// ECS Mapping Tests
// =============================================================================

describe('ElasticConnector ECS Field Mapping', () => {
  let connector: ElasticConnector;

  beforeEach(async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    connector = new ElasticConnector(createTestConfig());
    await connector.init();
  });

  it('should send event with correct ECS structure', async () => {
    // Mock bulk response
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 10,
          errors: false,
          items: [{ index: { _index: 'browserdefense-2024.01.15', _id: 'evt-12345', status: 201 } }],
        }),
    });

    const event = createTestEvent();
    await connector.send(event);

    // Check the bulk request was made
    expect(mockFetch).toHaveBeenCalledTimes(2); // init + send
    const [url, options] = mockFetch.mock.calls[1];

    expect(url).toBe('https://localhost:9200/_bulk');
    expect(options.method).toBe('POST');
    expect(options.headers['Content-Type']).toBe('application/x-ndjson');

    // Parse the NDJSON body
    const lines = options.body.trim().split('\n');
    expect(lines.length).toBe(2);

    const action = JSON.parse(lines[0]);
    const doc = JSON.parse(lines[1]) as EcsDocument;

    // Check action
    expect(action.index._index).toBe('browserdefense-2024.01.15');
    expect(action.index._id).toBe('evt-12345');

    // Check ECS base fields
    expect(doc['@timestamp']).toBe('2024-01-15T10:30:00.000Z');
    expect(doc.tags).toContain('browserdefense');
    expect(doc.tags).toContain('domain');

    // Check ECS event fields
    expect(doc.event.kind).toBe('alert');
    expect(doc.event.category).toContain('intrusion_detection');
    expect(doc.event.type).toContain('denied');
    expect(doc.event.action).toBe('url-blocked');
    expect(doc.event.id).toBe('evt-12345');

    // Check ECS threat fields (using enrichments pattern per ECS spec)
    expect(doc.threat.enrichments).toHaveLength(1);
    expect(doc.threat.enrichments[0].indicator.type).toBe('domain-name');
    expect(doc.threat.enrichments[0].matched.atomic).toBe('malware.example.com');
    expect(doc.threat.enrichments[0].matched.field).toBe('url.domain');
    expect(doc.threat.enrichments[0].matched.type).toBe('indicator_match_rule');
    expect(doc.threat.enrichments[0].matched.id).toBe('evt-12345');

    // Check ECS URL fields
    expect(doc.url.full).toBe('https://malware.example.com/payload.exe');
    expect(doc.url.domain).toBe('malware.example.com');
    expect(doc.url.scheme).toBe('https');

    // Check organization
    expect(doc.organization.id).toBe('org-abc');

    // Check BrowserDefense custom fields
    expect(doc.browserdefense.match_type).toBe('domain');
    expect(doc.browserdefense.redirect_chain).toHaveLength(2);
    expect(doc.browserdefense.tab_context.tab_id).toBe(123);
  });

  it('should map domain match type to domain-name indicator', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 5,
          errors: false,
          items: [{ index: { _index: 'browserdefense-2024.01.15', _id: 'evt-12345', status: 201 } }],
        }),
    });

    const event = createTestEvent({ matchType: 'domain' });
    await connector.send(event);

    const doc = JSON.parse(mockFetch.mock.calls[1][1].body.split('\n')[1]) as EcsDocument;
    expect(doc.threat.enrichments[0].indicator.type).toBe('domain-name');
    expect(doc.threat.enrichments[0].matched.field).toBe('url.domain');
  });

  it('should map url match type to url indicator', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 5,
          errors: false,
          items: [{ index: { _index: 'browserdefense-2024.01.15', _id: 'evt-url', status: 201 } }],
        }),
    });

    const event = createTestEvent({ eventId: 'evt-url', matchType: 'url' });
    await connector.send(event);

    const doc = JSON.parse(mockFetch.mock.calls[1][1].body.split('\n')[1]) as EcsDocument;
    expect(doc.threat.enrichments[0].indicator.type).toBe('url');
    expect(doc.threat.enrichments[0].matched.field).toBe('url.full');
  });

  it('should map hash match type to file indicator (ECS STIX 2.0 type)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 5,
          errors: false,
          items: [{ index: { _index: 'browserdefense-2024.01.15', _id: 'evt-hash', status: 201 } }],
        }),
    });

    const event = createTestEvent({ eventId: 'evt-hash', matchType: 'hash' });
    await connector.send(event);

    const doc = JSON.parse(mockFetch.mock.calls[1][1].body.split('\n')[1]) as EcsDocument;
    // ECS uses STIX 2.0 cyber observable types - 'file' for file hash indicators
    expect(doc.threat.enrichments[0].indicator.type).toBe('file');
    expect(doc.threat.enrichments[0].matched.field).toBe('file.hash.sha256');
  });

  it('should include user ID when present', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 5,
          errors: false,
          items: [{ index: { _index: 'browserdefense-2024.01.15', _id: 'evt-12345', status: 201 } }],
        }),
    });

    const event = createTestEvent({ userId: 'user-123' });
    await connector.send(event);

    const doc = JSON.parse(mockFetch.mock.calls[1][1].body.split('\n')[1]) as EcsDocument;
    expect(doc.user?.id).toBe('user-123');
  });

  it('should include device ID when present', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 5,
          errors: false,
          items: [{ index: { _index: 'browserdefense-2024.01.15', _id: 'evt-12345', status: 201 } }],
        }),
    });

    const event = createTestEvent({ deviceId: 'device-abc' });
    await connector.send(event);

    const doc = JSON.parse(mockFetch.mock.calls[1][1].body.split('\n')[1]) as EcsDocument;
    expect(doc.host?.id).toBe('device-abc');
  });
});

// =============================================================================
// Bulk API Tests
// =============================================================================

describe('ElasticConnector Bulk API', () => {
  let connector: ElasticConnector;

  beforeEach(async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    connector = new ElasticConnector(createTestConfig());
    await connector.init();
  });

  it('should send single event successfully', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 10,
          errors: false,
          items: [{ index: { _index: 'browserdefense-2024.01.15', _id: 'evt-12345', status: 201 } }],
        }),
    });

    const event = createTestEvent();
    const result = await connector.send(event);

    expect(result.success).toBe(true);
    expect(result.eventId).toBe('evt-12345');
    expect(result.response?.took).toBe(10);
  });

  it('should send batch of events', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 25,
          errors: false,
          items: [
            { index: { _index: 'browserdefense-2024.01.15', _id: 'evt-1', status: 201 } },
            { index: { _index: 'browserdefense-2024.01.15', _id: 'evt-2', status: 201 } },
            { index: { _index: 'browserdefense-2024.01.15', _id: 'evt-3', status: 201 } },
          ],
        }),
    });

    const events = [
      createTestEvent({ eventId: 'evt-1' }),
      createTestEvent({ eventId: 'evt-2' }),
      createTestEvent({ eventId: 'evt-3' }),
    ];

    const results = await connector.sendBatch(events);

    expect(results).toHaveLength(3);
    expect(results.every((r) => r.success)).toBe(true);

    // Check NDJSON format
    const body = mockFetch.mock.calls[1][1].body;
    const lines = body.trim().split('\n');
    expect(lines.length).toBe(6); // 3 actions + 3 docs
  });

  it('should handle partial bulk failures', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 20,
          errors: true,
          items: [
            { index: { _index: 'browserdefense-2024.01.15', _id: 'evt-1', status: 201 } },
            {
              index: {
                _index: 'browserdefense-2024.01.15',
                _id: 'evt-2',
                status: 400,
                error: { type: 'mapper_parsing_exception', reason: 'failed to parse field' },
              },
            },
            { index: { _index: 'browserdefense-2024.01.15', _id: 'evt-3', status: 201 } },
          ],
        }),
    });

    const events = [
      createTestEvent({ eventId: 'evt-1' }),
      createTestEvent({ eventId: 'evt-2' }),
      createTestEvent({ eventId: 'evt-3' }),
    ];

    const results = await connector.sendBatch(events);

    expect(results).toHaveLength(3);
    expect(results[0].success).toBe(true);
    expect(results[1].success).toBe(false);
    expect(results[1].error).toContain('mapper_parsing_exception');
    expect(results[1].retryable).toBe(false); // 400 is not retryable
    expect(results[2].success).toBe(true);
  });

  it('should mark 5xx errors as retryable', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 20,
          errors: true,
          items: [
            {
              index: {
                _index: 'browserdefense-2024.01.15',
                _id: 'evt-1',
                status: 503,
                error: { type: 'unavailable_exception', reason: 'node unavailable' },
              },
            },
          ],
        }),
    });

    const events = [createTestEvent({ eventId: 'evt-1' })];
    const results = await connector.sendBatch(events);

    expect(results[0].success).toBe(false);
    expect(results[0].retryable).toBe(true);
  });

  it('should mark 429 errors as retryable', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 5,
          errors: true,
          items: [
            {
              index: {
                _index: 'browserdefense-2024.01.15',
                _id: 'evt-1',
                status: 429,
                error: { type: 'es_rejected_execution_exception', reason: 'rejected' },
              },
            },
          ],
        }),
    });

    const events = [createTestEvent({ eventId: 'evt-1' })];
    const results = await connector.sendBatch(events);

    expect(results[0].success).toBe(false);
    expect(results[0].retryable).toBe(true);
  });
});

// =============================================================================
// Authentication Tests
// =============================================================================

describe('ElasticConnector Authentication', () => {
  it('should use API key header when configured', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({ apiKey: 'my-api-key' });
    const connector = new ElasticConnector(config);
    await connector.init();

    expect(mockFetch).toHaveBeenCalledWith(
      'https://localhost:9200',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'ApiKey my-api-key',
        }),
      })
    );
  });

  it('should use basic auth header when configured', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({
      apiKey: undefined,
      username: 'elastic',
      password: 'secret123',
    });
    const connector = new ElasticConnector(config);
    await connector.init();

    const expectedAuth = Buffer.from('elastic:secret123').toString('base64');
    expect(mockFetch).toHaveBeenCalledWith(
      'https://localhost:9200',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: `Basic ${expectedAuth}`,
        }),
      })
    );
  });
});

// =============================================================================
// Health Check Tests
// =============================================================================

describe('ElasticConnector Health Check', () => {
  let connector: ElasticConnector;

  beforeEach(async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    connector = new ElasticConnector(createTestConfig());
    await connector.init();
  });

  it('should report healthy for green cluster', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ status: 'green', cluster_name: 'production' }),
    });

    const health = await connector.health();

    expect(health.healthy).toBe(true);
    expect(health.message).toContain('production');
    expect(health.message).toContain('green');
  });

  it('should report healthy for yellow cluster', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ status: 'yellow', cluster_name: 'dev' }),
    });

    const health = await connector.health();

    expect(health.healthy).toBe(true);
    expect(health.message).toContain('yellow');
  });

  it('should report unhealthy for red cluster', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ status: 'red', cluster_name: 'broken' }),
    });

    const health = await connector.health();

    expect(health.healthy).toBe(false);
    expect(health.message).toContain('red');
  });

  it('should report unhealthy on connection error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

    const health = await connector.health();

    expect(health.healthy).toBe(false);
    expect(health.message).toContain('Connection refused');
  });
});

// =============================================================================
// Load Balancing Tests
// =============================================================================

describe('ElasticConnector Load Balancing', () => {
  it('should round-robin between nodes', async () => {
    // Mock multiple successful responses
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({
      nodes: ['https://node1:9200', 'https://node2:9200', 'https://node3:9200'],
    });
    const connector = new ElasticConnector(config);
    await connector.init();

    // Reset mock to track only subsequent calls
    mockFetch.mockClear();

    // Mock bulk responses
    mockFetch.mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          took: 5,
          errors: false,
          items: [{ index: { _index: 'browserdefense-2024.01.15', _id: 'evt-1', status: 201 } }],
        }),
    });

    // Send multiple events
    await connector.send(createTestEvent({ eventId: 'evt-1' }));
    await connector.send(createTestEvent({ eventId: 'evt-2' }));
    await connector.send(createTestEvent({ eventId: 'evt-3' }));

    // Check that different nodes were used
    const urls = mockFetch.mock.calls.map((call) => call[0]);
    expect(urls).toContain('https://node2:9200/_bulk');
    expect(urls).toContain('https://node3:9200/_bulk');
    expect(urls).toContain('https://node1:9200/_bulk');
  });
});

// =============================================================================
// Factory Registration Tests
// =============================================================================

describe('ElasticConnector Factory', () => {
  it('should create connector via factory function', () => {
    const config = createTestConfig();
    const connector = createElasticConnector(config);

    expect(connector).toBeInstanceOf(ElasticConnector);
    expect(connector.type).toBe('elastic');
    expect(connector.name).toBe('test-elastic');
  });

  it('should be registered in global registry', () => {
    expect(connectorRegistry.has('elastic')).toBe(true);
  });

  it('should create connector via registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);

    expect(connector).toBeInstanceOf(ElasticConnector);
  });
});

// =============================================================================
// Filtering Tests
// =============================================================================

describe('ElasticConnector Filtering', () => {
  it('should filter events by org ID', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
    });

    const config = createTestConfig({
      filter: {
        orgIds: ['org-allowed'],
      },
    });
    const connector = new ElasticConnector(config);
    await connector.init();

    const event = createTestEvent({ orgId: 'org-other' });
    const result = await connector.send(event);

    expect(result.success).toBe(true);
    expect(result.response?.filtered).toBe(true);

    // No bulk request should be made
    expect(mockFetch).toHaveBeenCalledTimes(1); // only init
  });

  it('should allow events matching org ID filter', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            took: 5,
            errors: false,
            items: [{ index: { _index: 'browserdefense-2024.01.15', _id: 'evt-12345', status: 201 } }],
          }),
      });

    const config = createTestConfig({
      filter: {
        orgIds: ['org-abc'],
      },
    });
    const connector = new ElasticConnector(config);
    await connector.init();

    const event = createTestEvent({ orgId: 'org-abc' });
    const result = await connector.send(event);

    expect(result.success).toBe(true);
    expect(result.response?.filtered).toBeUndefined();
    expect(mockFetch).toHaveBeenCalledTimes(2); // init + send
  });
});

// =============================================================================
// Error Handling Tests
// =============================================================================

describe('ElasticConnector Error Handling', () => {
  it('should throw on connection failure during init', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

    const config = createTestConfig();
    const connector = new ElasticConnector(config);

    await expect(connector.init()).rejects.toThrow('Failed to connect to Elasticsearch');
  });

  it('should handle HTTP error during init', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
    });

    const config = createTestConfig();
    const connector = new ElasticConnector(config);

    await expect(connector.init()).rejects.toThrow('Connection failed: 401');
  });

  it('should handle bulk request failure', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });

    const config = createTestConfig({
      // Disable retries to get immediate failure
      retry: { maxAttempts: 0, initialDelayMs: 0, maxDelayMs: 0, backoffMultiplier: 1 },
    });
    const connector = new ElasticConnector(config);
    await connector.init();

    const event = createTestEvent();
    const result = await connector.send(event);

    // With retry disabled, failure is returned as a result (not thrown)
    expect(result.success).toBe(false);
    expect(result.error).toContain('Bulk request failed: 500');
    expect(result.retryable).toBe(false); // No retries left
  });

  it('should handle malformed URL gracefully', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ cluster_name: 'test', version: { number: '8.11.0' } }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            took: 5,
            errors: false,
            items: [{ index: { _index: 'browserdefense-2024.01.15', _id: 'evt-12345', status: 201 } }],
          }),
      });

    const config = createTestConfig();
    const connector = new ElasticConnector(config);
    await connector.init();

    const event = createTestEvent({ blockedUrl: 'not-a-valid-url' });
    const result = await connector.send(event);

    expect(result.success).toBe(true);

    // Check that URL fields are empty but document is valid
    const doc = JSON.parse(mockFetch.mock.calls[1][1].body.split('\n')[1]) as EcsDocument;
    expect(doc.url.full).toBe('not-a-valid-url');
    expect(doc.url.domain).toBeUndefined();
  });
});
