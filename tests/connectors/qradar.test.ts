import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  QRadarConnector,
  formatLeef,
  formatCef,
  buildSyslogMessage,
} from '../../src/connectors/qradar';
import { ForensicsEvent, QRadarConnectorConfig } from '../../src/connectors/types';

// =============================================================================
// Test Fixtures
// =============================================================================

/**
 * Create a mock forensics event for testing.
 */
function createMockEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    blockedUrl: 'https://evil.com/phishing/login.html',
    timestamp: '2024-01-15T10:30:00.000Z',
    redirectChain: ['https://click.tracker.com', 'https://redirect.evil.com'],
    tabContext: {
      tabId: 123,
      windowId: 1,
      initiatorUrl: 'https://legitimate-site.com/email',
      tabTitle: 'Your Account - Login',
      incognito: false,
    },
    orgId: 'org-12345',
    eventId: 'evt-abc-123-def-456',
    matchType: 'url',
    matchedIndicator: 'evil.com/phishing',
    userId: 'user@company.com',
    deviceId: 'DESKTOP-ABC123',
    raw: {},
    ...overrides,
  };
}

/**
 * Create a mock QRadar connector config.
 */
function createMockConfig(overrides: Partial<QRadarConnectorConfig> = {}): QRadarConnectorConfig {
  return {
    type: 'qradar',
    name: 'test-qradar',
    enabled: true,
    host: 'qradar.test.local',
    port: 514,
    protocol: 'udp',
    format: 'leef',
    ...overrides,
  };
}

// =============================================================================
// LEEF Format Tests
// =============================================================================

describe('LEEF Formatter', () => {
  describe('formatLeef', () => {
    it('should generate valid LEEF 2.0 header', () => {
      const event = createMockEvent();
      const leef = formatLeef(event);

      // Check LEEF header format
      expect(leef).toMatch(/^LEEF:2\.0\|BrowserDefense\|Connector\|1\.0\.0\|/);
    });

    it('should include correct event ID based on match type', () => {
      const domainEvent = createMockEvent({ matchType: 'domain' });
      const urlEvent = createMockEvent({ matchType: 'url' });
      const hashEvent = createMockEvent({ matchType: 'hash' });

      expect(formatLeef(domainEvent)).toContain('BlockedNavigation:domain|');
      expect(formatLeef(urlEvent)).toContain('BlockedNavigation:url|');
      expect(formatLeef(hashEvent)).toContain('BlockedNavigation:hash|');
    });

    it('should include blocked URL', () => {
      const event = createMockEvent({
        blockedUrl: 'https://malware.bad/payload.exe',
      });
      const leef = formatLeef(event);

      expect(leef).toContain('url=https://malware.bad/payload.exe');
    });

    it('should include organization ID as accountName', () => {
      const event = createMockEvent({ orgId: 'acme-corp-123' });
      const leef = formatLeef(event);

      // Use accountName per LEEF spec (src is reserved for IPv4/IPv6)
      expect(leef).toContain('accountName=acme-corp-123');
    });

    it('should include LEEF 2.0 delimiter specification in header', () => {
      const event = createMockEvent();
      const leef = formatLeef(event);

      // LEEF 2.0 requires delimiter as 6th header field
      expect(leef).toMatch(/^LEEF:2\.0\|BrowserDefense\|Connector\|1\.0\.0\|[^|]+\|0x09\|/);
    });

    it('should include user name when provided', () => {
      const event = createMockEvent({ userId: 'john.doe@acme.com' });
      const leef = formatLeef(event);

      expect(leef).toContain('usrName=john.doe@acme.com');
    });

    it('should omit user name when not provided', () => {
      const event = createMockEvent({ userId: undefined });
      const leef = formatLeef(event);

      expect(leef).not.toContain('usrName=');
    });

    it('should include device ID as host name when provided', () => {
      const event = createMockEvent({ deviceId: 'WORKSTATION-001' });
      const leef = formatLeef(event);

      expect(leef).toContain('identHostName=WORKSTATION-001');
    });

    it('should include initiator URL as source URL', () => {
      const event = createMockEvent();
      event.tabContext.initiatorUrl = 'https://phishing-email.com/link';
      const leef = formatLeef(event);

      expect(leef).toContain('srcURL=https://phishing-email.com/link');
    });

    it('should include tab title as source title', () => {
      const event = createMockEvent();
      event.tabContext.tabTitle = 'Fake Bank Login';
      const leef = formatLeef(event);

      expect(leef).toContain('srcTitle=Fake Bank Login');
    });

    it('should include redirect chain', () => {
      const event = createMockEvent({
        redirectChain: ['https://a.com', 'https://b.com', 'https://c.com'],
      });
      const leef = formatLeef(event);

      expect(leef).toContain('redirectChain=https://a.com -> https://b.com -> https://c.com');
    });

    it('should handle empty redirect chain', () => {
      const event = createMockEvent({ redirectChain: [] });
      const leef = formatLeef(event);

      expect(leef).not.toContain('redirectChain=');
    });

    it('should include category as WebBlock', () => {
      const event = createMockEvent();
      const leef = formatLeef(event);

      expect(leef).toContain('cat=WebBlock');
    });

    it('should include severity based on match type', () => {
      const domainEvent = createMockEvent({ matchType: 'domain' });
      const urlEvent = createMockEvent({ matchType: 'url' });
      const hashEvent = createMockEvent({ matchType: 'hash' });

      expect(formatLeef(domainEvent)).toContain('sev=5');
      expect(formatLeef(urlEvent)).toContain('sev=6');
      expect(formatLeef(hashEvent)).toContain('sev=4');
    });

    it('should include match type and matched indicator', () => {
      const event = createMockEvent({
        matchType: 'domain',
        matchedIndicator: 'evil-domain.com',
      });
      const leef = formatLeef(event);

      expect(leef).toContain('matchType=domain');
      expect(leef).toContain('matchedIndicator=evil-domain.com');
    });

    it('should include event ID', () => {
      const event = createMockEvent({ eventId: 'test-event-id-999' });
      const leef = formatLeef(event);

      expect(leef).toContain('eventId=test-event-id-999');
    });

    it('should include incognito flag', () => {
      const normalEvent = createMockEvent();
      normalEvent.tabContext.incognito = false;
      const incognitoEvent = createMockEvent();
      incognitoEvent.tabContext.incognito = true;

      expect(formatLeef(normalEvent)).toContain('incognito=false');
      expect(formatLeef(incognitoEvent)).toContain('incognito=true');
    });

    it('should format timestamp correctly', () => {
      const event = createMockEvent({
        timestamp: '2024-03-15T14:30:45.000Z',
      });
      const leef = formatLeef(event);

      // Should format as "MMM dd yyyy HH:mm:ss" - note the time will be in local timezone
      // so we just verify the format structure, not the exact time
      expect(leef).toMatch(/devTime=Mar \d{2} 2024 \d{2}:30:45/);
      expect(leef).toContain('devTimeFormat=MMM dd yyyy HH:mm:ss');
    });

    it('should use tab as delimiter between attributes', () => {
      const event = createMockEvent();
      const leef = formatLeef(event);

      // After the header, attributes should be tab-separated
      const attributesPart = leef.split('|').slice(5).join('|');
      const attributes = attributesPart.split('\t');

      // Should have multiple attributes
      expect(attributes.length).toBeGreaterThan(5);
    });

    it('should escape special characters in values', () => {
      const event = createMockEvent({
        blockedUrl: 'https://evil.com/path\twith\ttabs',
        matchedIndicator: 'value=with=equals',
      });
      const leef = formatLeef(event);

      // Tabs should be escaped as \t
      expect(leef).toContain('url=https://evil.com/path\\twith\\ttabs');
      // Equals should be escaped as \=
      expect(leef).toContain('matchedIndicator=value\\=with\\=equals');
    });

    it('should escape newlines in values', () => {
      const event = createMockEvent();
      event.tabContext.tabTitle = 'Title\nWith\nNewlines';
      const leef = formatLeef(event);

      expect(leef).toContain('srcTitle=Title\\nWith\\nNewlines');
    });
  });
});

// =============================================================================
// CEF Format Tests
// =============================================================================

describe('CEF Formatter', () => {
  describe('formatCef', () => {
    it('should generate valid CEF header', () => {
      const event = createMockEvent();
      const cef = formatCef(event);

      // Check CEF header format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|
      expect(cef).toMatch(/^CEF:0\|BrowserDefense\|Connector\|1\.0\.0\|/);
    });

    it('should include correct signature ID based on match type', () => {
      const domainEvent = createMockEvent({ matchType: 'domain' });
      const urlEvent = createMockEvent({ matchType: 'url' });

      expect(formatCef(domainEvent)).toContain('|blocked-domain|');
      expect(formatCef(urlEvent)).toContain('|blocked-url|');
    });

    it('should include event name with match type', () => {
      const event = createMockEvent({ matchType: 'hash' });
      const cef = formatCef(event);

      expect(cef).toContain('BrowserDefense Blocked Navigation (hash)');
    });

    it('should include request field with blocked URL', () => {
      const event = createMockEvent({
        blockedUrl: 'https://malware.site/payload',
      });
      const cef = formatCef(event);

      expect(cef).toContain('request=https://malware.site/payload');
    });

    it('should include custom string fields with labels', () => {
      const event = createMockEvent({
        eventId: 'evt-123',
        matchedIndicator: 'bad.domain.com',
        matchType: 'domain',
      });
      const cef = formatCef(event);

      expect(cef).toContain('cs1=evt-123');
      expect(cef).toContain('cs1Label=EventId');
      expect(cef).toContain('cs2=bad.domain.com');
      expect(cef).toContain('cs2Label=MatchedIndicator');
      expect(cef).toContain('cs3=domain');
      expect(cef).toContain('cs3Label=MatchType');
    });

    it('should include user when provided', () => {
      const event = createMockEvent({ userId: 'admin@company.com' });
      const cef = formatCef(event);

      expect(cef).toContain('suser=admin@company.com');
    });

    it('should include source host when device ID provided', () => {
      const event = createMockEvent({ deviceId: 'LAPTOP-XYZ' });
      const cef = formatCef(event);

      expect(cef).toContain('shost=LAPTOP-XYZ');
    });

    it('should include receipt time as epoch milliseconds', () => {
      const event = createMockEvent({
        timestamp: '2024-01-01T00:00:00.000Z',
      });
      const cef = formatCef(event);

      const expectedTime = new Date('2024-01-01T00:00:00.000Z').getTime();
      expect(cef).toContain(`rt=${expectedTime}`);
    });

    it('should escape pipe characters in header', () => {
      // The name field is in the header and might contain pipes
      // Our implementation uses a fixed name, but let's verify escaping works
      const event = createMockEvent({ matchType: 'url' });
      const cef = formatCef(event);

      // Should not have unescaped pipes in header values
      const headerParts = cef.split('|').slice(0, 7);
      expect(headerParts.length).toBe(7);
    });

    it('should escape equals signs in extension values', () => {
      const event = createMockEvent({
        matchedIndicator: 'param=value',
      });
      const cef = formatCef(event);

      expect(cef).toContain('cs2=param\\=value');
    });
  });
});

// =============================================================================
// Syslog Message Builder Tests
// =============================================================================

describe('Syslog Message Builder', () => {
  describe('buildSyslogMessage', () => {
    it('should calculate PRI correctly', () => {
      // PRI = facility * 8 + severity
      // facility=16 (local0), severity=5 (notice) = 133
      const message = buildSyslogMessage('test message', 16, 5, 'testapp');

      expect(message).toMatch(/^<133>/);
    });

    it('should use RFC 5424 version 1', () => {
      const message = buildSyslogMessage('test', 16, 5, 'app');

      expect(message).toMatch(/^<133>1 /);
    });

    it('should include ISO 8601 timestamp', () => {
      const message = buildSyslogMessage('test', 16, 5, 'app');

      // Should contain ISO timestamp pattern
      expect(message).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });

    it('should include app name', () => {
      const message = buildSyslogMessage('test', 16, 5, 'browserdefense');

      expect(message).toContain(' browserdefense ');
    });

    it('should include the message payload', () => {
      const payload = 'LEEF:2.0|BrowserDefense|Connector|1.0.0|TestEvent|attr=value';
      const message = buildSyslogMessage(payload, 16, 5, 'app');

      expect(message).toContain(payload);
    });

    it('should handle different facility values', () => {
      // facility=1 (user), severity=3 (error) = 11
      const message = buildSyslogMessage('test', 1, 3, 'app');
      expect(message).toMatch(/^<11>/);

      // facility=23 (local7), severity=7 (debug) = 191
      const message2 = buildSyslogMessage('test', 23, 7, 'app');
      expect(message2).toMatch(/^<191>/);
    });
  });
});

// =============================================================================
// QRadar Connector Tests
// =============================================================================

describe('QRadarConnector', () => {
  let connector: QRadarConnector;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(async () => {
    if (connector) {
      try {
        await connector.close();
      } catch {
        // Ignore errors during cleanup
      }
    }
  });

  describe('constructor', () => {
    it('should set default values for optional config', () => {
      const config = createMockConfig();
      connector = new QRadarConnector(config);

      expect(connector.type).toBe('qradar');
      expect(connector.name).toBe('test-qradar');
    });

    it('should accept custom facility and severity', () => {
      const config = createMockConfig({
        facility: 20,
        severity: 3,
      });
      connector = new QRadarConnector(config);

      // These are stored internally, we'll verify in send tests
      expect(connector).toBeDefined();
    });

    it('should default to LEEF format', () => {
      const config = createMockConfig({ format: undefined });
      connector = new QRadarConnector(config);

      expect(connector).toBeDefined();
    });

    it('should accept CEF format', () => {
      const config = createMockConfig({ format: 'cef' });
      connector = new QRadarConnector(config);

      expect(connector).toBeDefined();
    });
  });

  describe('shouldProcess', () => {
    it('should process all events when no filter configured', () => {
      const config = createMockConfig();
      connector = new QRadarConnector(config);

      const event = createMockEvent();
      expect(connector.shouldProcess(event)).toBe(true);
    });

    it('should filter by org ID', () => {
      const config = createMockConfig({
        filter: {
          orgIds: ['allowed-org-1', 'allowed-org-2'],
        },
      });
      connector = new QRadarConnector(config);

      const allowedEvent = createMockEvent({ orgId: 'allowed-org-1' });
      const blockedEvent = createMockEvent({ orgId: 'other-org' });

      expect(connector.shouldProcess(allowedEvent)).toBe(true);
      expect(connector.shouldProcess(blockedEvent)).toBe(false);
    });

    it('should filter by match type', () => {
      const config = createMockConfig({
        filter: {
          matchTypes: ['domain', 'hash'],
        },
      });
      connector = new QRadarConnector(config);

      const domainEvent = createMockEvent({ matchType: 'domain' });
      const hashEvent = createMockEvent({ matchType: 'hash' });
      const urlEvent = createMockEvent({ matchType: 'url' });

      expect(connector.shouldProcess(domainEvent)).toBe(true);
      expect(connector.shouldProcess(hashEvent)).toBe(true);
      expect(connector.shouldProcess(urlEvent)).toBe(false);
    });

    it('should filter by exclude patterns', () => {
      const config = createMockConfig({
        filter: {
          excludePatterns: ['^https://internal\\.', 'test\\.example\\.com'],
        },
      });
      connector = new QRadarConnector(config);

      const internalEvent = createMockEvent({
        blockedUrl: 'https://internal.company.com/path',
      });
      const testEvent = createMockEvent({
        blockedUrl: 'https://test.example.com/login',
      });
      const externalEvent = createMockEvent({
        blockedUrl: 'https://evil.external.com/malware',
      });

      expect(connector.shouldProcess(internalEvent)).toBe(false);
      expect(connector.shouldProcess(testEvent)).toBe(false);
      expect(connector.shouldProcess(externalEvent)).toBe(true);
    });
  });

  describe('health', () => {
    it('should report unhealthy before initialization', async () => {
      const config = createMockConfig();
      connector = new QRadarConnector(config);

      // Before init, calling health should throw
      await expect(connector.health()).rejects.toThrow('not initialized');
    });
  });
});

// =============================================================================
// Integration Tests (with mocked transport)
// =============================================================================

describe('QRadar Integration', () => {
  it('should format complete event for QRadar consumption', () => {
    const event = createMockEvent({
      blockedUrl: 'https://phishing.bad/steal-creds.html',
      timestamp: '2024-06-15T09:45:30.000Z',
      redirectChain: ['https://t.co/abc', 'https://bit.ly/xyz'],
      orgId: 'enterprise-org',
      eventId: 'block-event-001',
      matchType: 'url',
      matchedIndicator: 'phishing.bad/steal-creds',
      userId: 'jane.doe@enterprise.com',
      deviceId: 'CORP-LAPTOP-001',
    });

    const leef = formatLeef(event);
    const syslog = buildSyslogMessage(leef, 16, 5, 'browserdefense');

    // Verify it's a valid syslog message
    expect(syslog).toMatch(/^<133>1 /);

    // Verify LEEF content (includes 0x09 delimiter spec per LEEF 2.0)
    expect(syslog).toContain('LEEF:2.0|BrowserDefense|Connector|1.0.0|BlockedNavigation:url|0x09|');
    expect(syslog).toContain('url=https://phishing.bad/steal-creds.html');
    expect(syslog).toContain('accountName=enterprise-org');
    expect(syslog).toContain('usrName=jane.doe@enterprise.com');
    expect(syslog).toContain('identHostName=CORP-LAPTOP-001');
    expect(syslog).toContain('redirectChain=https://t.co/abc -> https://bit.ly/xyz');
    expect(syslog).toContain('matchedIndicator=phishing.bad/steal-creds');
  });

  it('should generate different output for CEF format', () => {
    const event = createMockEvent();

    const leef = formatLeef(event);
    const cef = formatCef(event);

    expect(leef).toMatch(/^LEEF:/);
    expect(cef).toMatch(/^CEF:/);

    // Both should contain the blocked URL but in different formats
    expect(leef).toContain('url=');
    expect(cef).toContain('request=');
  });
});
