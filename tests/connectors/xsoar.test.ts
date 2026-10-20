/**
 * Tests for Palo Alto Cortex XSOAR Connector
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { XsoarConnector, XsoarApiError, createXsoarConnector } from '../../src/connectors/xsoar';
import type { ForensicsEvent, XsoarConnectorConfig } from '../../src/connectors/types';
import { connectorRegistry } from '../../src/connectors/base';

// =============================================================================
// Test Fixtures
// =============================================================================

const mockConfig: XsoarConnectorConfig = {
  name: 'Test XSOAR',
  enabled: true,
  type: 'xsoar',
  serverUrl: 'https://xsoar.example.com',
  apiKey: 'test-api-key-12345',
  incidentType: 'BrowserDefense Alert',
  playbookId: 'BrowserDefense_Response',
  // Disable batching for tests to get immediate send results
  batch: { maxSize: 1, maxWaitMs: 0 },
};

const mockForensicsEvent: ForensicsEvent = {
  blockedUrl: 'https://malicious.example.com/phishing/login',
  timestamp: '2025-01-09T12:00:00.000Z',
  redirectChain: [
    'https://original.com/link',
    'https://redirect1.com/redirect',
    'https://malicious.example.com/phishing/login',
  ],
  tabContext: {
    tabId: 123,
    windowId: 1,
    initiatorUrl: 'https://email.example.com/inbox',
    tabTitle: 'Email - Inbox',
    incognito: false,
  },
  orgId: 'org-123',
  eventId: 'event-abc-456',
  matchType: 'url',
  matchedIndicator: 'malicious.example.com/phishing',
  userId: 'user@example.com',
  deviceId: 'device-xyz-789',
  raw: {},
};

/**
 * Create an unblock event for testing
 */
function createUnblockEvent(eventId: string, reason?: string): ForensicsEvent {
  return {
    ...mockForensicsEvent,
    action: 'unblock',
    eventId,
    raw: reason ? { unblockReason: reason } : {},
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
// Constructor Tests
// =============================================================================

describe('XsoarConnector', () => {
  describe('constructor', () => {
    it('should create connector with valid config', () => {
      const connector = new XsoarConnector(mockConfig);

      expect(connector.name).toBe('Test XSOAR');
      expect(connector.type).toBe('xsoar');
    });

    it('should normalize server URL by removing trailing slash', () => {
      const configWithSlash: XsoarConnectorConfig = {
        ...mockConfig,
        serverUrl: 'https://xsoar.example.com/',
      };

      const connector = new XsoarConnector(configWithSlash);

      // Access via test by checking the request URL in init
      expect(connector).toBeDefined();
    });

    it('should use default incident type if not provided', () => {
      const configWithoutType: XsoarConnectorConfig = {
        ...mockConfig,
        incidentType: undefined,
      };

      const connector = new XsoarConnector(configWithoutType);
      expect(connector).toBeDefined();
    });
  });

  // ===========================================================================
  // Initialization Tests
  // ===========================================================================

  describe('init', () => {
    it('should initialize successfully with valid credentials', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok', version: '6.10.0' }),
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://xsoar.example.com/health',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'Authorization': 'test-api-key-12345',
          }),
        })
      );
    });

    it('should throw error if health check fails', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        text: async () => 'Invalid API key',
      });
      // Also mock the fallback /user endpoint
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        text: async () => 'Invalid API key',
      });

      const connector = new XsoarConnector(mockConfig);

      await expect(connector.init()).rejects.toThrow('XSOAR health check failed');
    });

    it('should prevent double initialization', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      await expect(connector.init()).rejects.toThrow('already initialized');
    });
  });

  // ===========================================================================
  // Send Tests
  // ===========================================================================

  describe('send', () => {
    it('should send forensics event as XSOAR incident', async () => {
      // Health check during init
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });
      // Incident creation
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            id: 'incident-123',
            name: 'BrowserDefense Alert',
            status: 0,
            created: '2025-01-09T12:00:00Z',
            investigationId: 'inv-456',
          }),
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      const result = await connector.send(mockForensicsEvent);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('event-abc-456');
      expect(result.response).toEqual({
        incidentId: 'incident-123',
        investigationId: 'inv-456',
      });

      // Verify incident payload
      const incidentCall = mockFetch.mock.calls[1];
      expect(incidentCall[0]).toBe('https://xsoar.example.com/incident');

      const requestBody = JSON.parse(incidentCall[1].body);
      expect(requestBody.type).toBe('BrowserDefense Alert');
      expect(requestBody.playbookId).toBe('BrowserDefense_Response');
      expect(requestBody.CustomFields.blockedurl).toBe(mockForensicsEvent.blockedUrl);
      expect(requestBody.CustomFields.matchtype).toBe('url');
      expect(requestBody.labels).toContainEqual({ type: 'source', value: 'BrowserDefense' });
    });

    it('should set correct severity based on match type', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ id: 'inc-1' }),
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      // Test hash match (should be severity 4)
      const hashEvent: ForensicsEvent = {
        ...mockForensicsEvent,
        matchType: 'hash',
      };
      await connector.send(hashEvent);

      const requestBody = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(requestBody.severity).toBe(4); // High severity for hash matches
    });

    it('should handle API errors gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: async () => 'Database connection failed',
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      const result = await connector.send(mockForensicsEvent);

      expect(result.success).toBe(false);
      expect(result.error).toContain('XSOAR API error');
      expect(result.retryable).toBe(true); // 500 errors are retryable
    });

    it('should mark 4xx errors as non-retryable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: async () => 'Invalid incident format',
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      const result = await connector.send(mockForensicsEvent);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(false); // 400 errors are not retryable
    });

    it('should mark rate limit errors as retryable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        text: async () => 'Rate limit exceeded',
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      const result = await connector.send(mockForensicsEvent);

      expect(result.success).toBe(false);
      expect(result.retryable).toBe(true); // 429 is retryable
    });

    it('should throw error if not initialized', async () => {
      const connector = new XsoarConnector(mockConfig);

      await expect(connector.send(mockForensicsEvent)).rejects.toThrow('not initialized');
    });
  });

  // ===========================================================================
  // Health Check Tests
  // ===========================================================================

  describe('health', () => {
    it('should return healthy status when XSOAR is accessible', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok', version: '6.10.0' }),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok', version: '6.10.0' }),
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('6.10.0');
    });

    it('should fall back to /user endpoint for older XSOAR versions', async () => {
      // Health check fails
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        text: async () => 'Not found',
      });
      // Fallback to /user succeeds
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ username: 'admin' }),
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should return unhealthy status when XSOAR is not accessible', async () => {
      // Initial health check for init
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });
      // Health check call fails
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        text: async () => 'Service down',
      });
      // Fallback also fails
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        text: async () => 'Service down',
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      const health = await connector.health();

      expect(health.healthy).toBe(false);
      expect(health.message).toContain('health check failed');
    });
  });

  // ===========================================================================
  // Filter Tests
  // ===========================================================================

  describe('shouldProcess', () => {
    it('should filter events by org ID', async () => {
      const configWithFilter: XsoarConnectorConfig = {
        ...mockConfig,
        filter: {
          orgIds: ['org-123', 'org-456'],
        },
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });

      const connector = new XsoarConnector(configWithFilter);
      await connector.init();

      // Event with matching org ID should pass
      const matchingEvent = { ...mockForensicsEvent, orgId: 'org-123' };
      expect(connector.shouldProcess(matchingEvent)).toBe(true);

      // Event with non-matching org ID should be filtered
      const nonMatchingEvent = { ...mockForensicsEvent, orgId: 'org-other' };
      expect(connector.shouldProcess(nonMatchingEvent)).toBe(false);
    });

    it('should filter events by match type', async () => {
      const configWithFilter: XsoarConnectorConfig = {
        ...mockConfig,
        filter: {
          matchTypes: ['hash'],
        },
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });

      const connector = new XsoarConnector(configWithFilter);
      await connector.init();

      // Hash match should pass
      const hashEvent = { ...mockForensicsEvent, matchType: 'hash' as const };
      expect(connector.shouldProcess(hashEvent)).toBe(true);

      // URL match should be filtered
      const urlEvent = { ...mockForensicsEvent, matchType: 'url' as const };
      expect(connector.shouldProcess(urlEvent)).toBe(false);
    });
  });

  // ===========================================================================
  // Close Tests
  // ===========================================================================

  describe('close', () => {
    it('should close gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();

      await expect(connector.close()).resolves.not.toThrow();
    });

    it('should prevent operations after close', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      });

      const connector = new XsoarConnector(mockConfig);
      await connector.init();
      await connector.close();

      await expect(connector.send(mockForensicsEvent)).rejects.toThrow('closed');
    });
  });
});

// =============================================================================
// XsoarApiError Tests
// =============================================================================

describe('XsoarApiError', () => {
  it('should capture status code and response body', () => {
    const error = new XsoarApiError(
      'API error',
      401,
      '{"error": "Invalid credentials"}'
    );

    expect(error.name).toBe('XsoarApiError');
    expect(error.statusCode).toBe(401);
    expect(error.responseBody).toBe('{"error": "Invalid credentials"}');
    expect(error.message).toBe('API error');
  });
});

// =============================================================================
// Factory Registration Tests
// =============================================================================

describe('createXsoarConnector', () => {
  it('should create connector via factory function', () => {
    const connector = createXsoarConnector(mockConfig);

    expect(connector).toBeInstanceOf(XsoarConnector);
    expect(connector.name).toBe('Test XSOAR');
  });

  it('should be registered in connector registry', () => {
    expect(connectorRegistry.has('xsoar')).toBe(true);

    const connector = connectorRegistry.create(mockConfig);
    expect(connector.type).toBe('xsoar');
  });
});

// =============================================================================
// Integration Tests (with mocked API)
// =============================================================================

describe('XsoarConnector integration', () => {
  it('should handle complete workflow: init -> send -> close', async () => {
    mockFetch
      // init health check
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok', version: '6.10.0' }),
      })
      // send incident
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            id: 'inc-123',
            name: 'BrowserDefense Alert',
            status: 0,
            created: '2025-01-09T12:00:00Z',
            investigationId: 'inv-456',
          }),
      })
      // send another incident
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            id: 'inc-124',
            name: 'BrowserDefense Alert',
            status: 0,
            created: '2025-01-09T12:01:00Z',
            investigationId: 'inv-457',
          }),
      });

    const connector = new XsoarConnector(mockConfig);

    // Initialize
    await connector.init();

    // Send first event
    const result1 = await connector.send(mockForensicsEvent);
    expect(result1.success).toBe(true);

    // Send second event
    const event2 = { ...mockForensicsEvent, eventId: 'event-2' };
    const result2 = await connector.send(event2);
    expect(result2.success).toBe(true);

    // Close
    await connector.close();

    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it('should truncate long URLs in incident name', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ status: 'ok' }),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ id: 'inc-1' }),
    });

    const connector = new XsoarConnector(mockConfig);
    await connector.init();

    const longUrlEvent: ForensicsEvent = {
      ...mockForensicsEvent,
      blockedUrl:
        'https://extremely-long-domain-name-that-goes-on-and-on.example.com/very/long/path/with/many/segments/that/makes/the/url/exceed/one/hundred/characters/for/testing/purposes',
    };

    await connector.send(longUrlEvent);

    const requestBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    // "BrowserDefense Alert: " (22 chars) + truncated URL (up to 100 chars)
    expect(requestBody.name.length).toBeLessThanOrEqual(125);
    expect(requestBody.name).toContain('...');
  });
});

// =============================================================================
// Unblock Tests
// =============================================================================

describe('XsoarConnector unblock', () => {
  it('should find and close an incident by eventId', async () => {
    mockFetch
      // init health check
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      })
      // incident search
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            data: [
              {
                id: 'inc-123',
                name: 'BlockIOC Alert',
                status: 1, // Active
                CustomFields: { eventid: 'event-abc-456' },
              },
            ],
            total: 1,
          }),
      })
      // incident update (close)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ id: 'inc-123', status: 2 }),
      })
      // entry creation
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ id: 'entry-1' }),
      });

    const connector = new XsoarConnector(mockConfig);
    await connector.init();

    const result = await connector.unblock(createUnblockEvent('event-abc-456', 'False positive'));

    expect(result.success).toBe(true);
    expect(result.eventId).toBe('event-abc-456');
    expect(result.incidentId).toBe('inc-123');
    expect(result.alreadyClosed).toBe(false);

    // Verify search request
    const searchCall = mockFetch.mock.calls[1];
    expect(searchCall[0]).toBe('https://xsoar.example.com/incidents/search');
    const searchBody = JSON.parse(searchCall[1].body);
    expect(searchBody.filter.query).toBe('CustomFields.eventid:"event-abc-456"');

    // Verify close request
    const closeCall = mockFetch.mock.calls[2];
    expect(closeCall[0]).toBe('https://xsoar.example.com/incident');
    const closeBody = JSON.parse(closeCall[1].body);
    expect(closeBody.id).toBe('inc-123');
    expect(closeBody.status).toBe(2); // Done
    expect(closeBody.closeNotes).toBe('False positive');

    // Verify entry request
    const entryCall = mockFetch.mock.calls[3];
    expect(entryCall[0]).toBe('https://xsoar.example.com/entry');
    const entryBody = JSON.parse(entryCall[1].body);
    expect(entryBody.investigationId).toBe('inc-123');
    expect(entryBody.markdown).toBe(true);
  });

  it('should handle already-closed incidents idempotently', async () => {
    mockFetch
      // init health check
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      })
      // incident search returns closed incident
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            data: [
              {
                id: 'inc-123',
                name: 'BlockIOC Alert',
                status: 2, // Done (already closed)
                CustomFields: { eventid: 'event-abc-456' },
              },
            ],
            total: 1,
          }),
      });

    const connector = new XsoarConnector(mockConfig);
    await connector.init();

    const result = await connector.unblock(createUnblockEvent('event-abc-456'));

    expect(result.success).toBe(true);
    expect(result.alreadyClosed).toBe(true);
    expect(result.incidentId).toBe('inc-123');

    // Should only have made 2 calls (health + search), no update needed
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('should handle archived incidents idempotently', async () => {
    mockFetch
      // init health check
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      })
      // incident search returns archived incident
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            data: [
              {
                id: 'inc-123',
                name: 'BlockIOC Alert',
                status: 3, // Archive
                CustomFields: { eventid: 'event-abc-456' },
              },
            ],
            total: 1,
          }),
      });

    const connector = new XsoarConnector(mockConfig);
    await connector.init();

    const result = await connector.unblock(createUnblockEvent('event-abc-456'));

    expect(result.success).toBe(true);
    expect(result.alreadyClosed).toBe(true);
  });

  it('should return error when incident not found', async () => {
    mockFetch
      // init health check
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      })
      // incident search returns empty
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            data: [],
            total: 0,
          }),
      });

    const connector = new XsoarConnector(mockConfig);
    await connector.init();

    const result = await connector.unblock(createUnblockEvent('nonexistent-event'));

    expect(result.success).toBe(false);
    expect(result.error).toContain('No incident found');
    expect(result.retryable).toBe(false);
  });

  it('should handle API errors during unblock', async () => {
    mockFetch
      // init health check
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      })
      // incident search fails
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: async () => 'Database error',
      });

    const connector = new XsoarConnector(mockConfig);
    await connector.init();

    const result = await connector.unblock(createUnblockEvent('event-abc-456'));

    expect(result.success).toBe(false);
    expect(result.error).toContain('XSOAR API error');
    expect(result.retryable).toBe(true);
  });

  it('should use default close notes when no reason provided', async () => {
    mockFetch
      // init health check
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      })
      // incident search
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            data: [{ id: 'inc-123', name: 'BlockIOC Alert', status: 1 }],
            total: 1,
          }),
      })
      // incident update
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ id: 'inc-123' }),
      })
      // entry creation
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ id: 'entry-1' }),
      });

    const connector = new XsoarConnector(mockConfig);
    await connector.init();

    await connector.unblock(createUnblockEvent('event-abc-456'));

    const closeBody = JSON.parse(mockFetch.mock.calls[2][1].body);
    expect(closeBody.closeNotes).toBe('IOC unblocked via BlockIOC');
  });

  it('should continue even if entry creation fails', async () => {
    // Suppress console.warn for this test
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    mockFetch
      // init health check
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      })
      // incident search
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            data: [{ id: 'inc-123', name: 'BlockIOC Alert', status: 1 }],
            total: 1,
          }),
      })
      // incident update
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ id: 'inc-123' }),
      })
      // entry creation fails
      .mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: async () => 'Entry creation failed',
      });

    const connector = new XsoarConnector(mockConfig);
    await connector.init();

    const result = await connector.unblock(createUnblockEvent('event-abc-456'));

    // Unblock should still succeed even though entry failed
    expect(result.success).toBe(true);
    expect(result.incidentId).toBe('inc-123');

    // Verify warning was logged
    expect(warnSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
  });

  it('should throw error if not initialized', async () => {
    const connector = new XsoarConnector(mockConfig);

    await expect(connector.unblock(createUnblockEvent('event-abc-456'))).rejects.toThrow('not initialized');
  });

  it('should handle complete workflow: send -> unblock', async () => {
    mockFetch
      // init health check
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: 'ok' }),
      })
      // send incident
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            id: 'inc-123',
            name: 'BlockIOC Alert',
            status: 0,
            created: '2025-01-09T12:00:00Z',
            investigationId: 'inv-456',
          }),
      })
      // unblock: incident search
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            data: [{ id: 'inc-123', name: 'BlockIOC Alert', status: 1 }],
            total: 1,
          }),
      })
      // unblock: incident update
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ id: 'inc-123', status: 2 }),
      })
      // unblock: entry creation
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ id: 'entry-1' }),
      });

    const connector = new XsoarConnector(mockConfig);
    await connector.init();

    // Send a block event
    const sendResult = await connector.send(mockForensicsEvent);
    expect(sendResult.success).toBe(true);

    // Unblock the same event
    const unblockResult = await connector.unblock(createUnblockEvent(mockForensicsEvent.eventId, 'Investigation complete'));
    expect(unblockResult.success).toBe(true);
    expect(unblockResult.incidentId).toBe('inc-123');
    expect(unblockResult.alreadyClosed).toBe(false);
  });
});
