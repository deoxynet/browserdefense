/**
 * Syslog Connector Tests
 *
 * Tests for CEF, LEEF, JSON, and raw formatting,
 * RFC 5424 message building, and connector lifecycle.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  SyslogConnector,
  createSyslogConnector,
  formatCef,
  formatLeef,
  formatJson,
  formatRaw,
  buildStructuredData,
  buildSyslogMessage,
  escapeCefValue,
  escapeLeefValue,
  escapeSDValue,
  CEF_SIG_ID,
  CEF_SEVERITY,
  DEFAULT_FACILITY,
  DEFAULT_SEVERITY,
  DEFAULT_APP_NAME,
  DEFAULT_CEF_VENDOR,
  DEFAULT_CEF_PRODUCT,
  DEFAULT_CEF_VERSION,
  BROWSERDEFENSE_PEN,
} from '../../src/connectors/syslog';
import {
  ForensicsEvent,
  SyslogConnectorConfig,
  connectorRegistry,
} from '../../src/connectors';

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestEvent(overrides: Partial<ForensicsEvent> = {}): ForensicsEvent {
  return {
    blockedUrl: 'https://malware.example.com/payload.exe',
    timestamp: '2024-01-15T10:30:00.000Z',
    redirectChain: ['https://trusted.com', 'https://redirect.example.com'],
    tabContext: {
      tabId: 123,
      windowId: 1,
      initiatorUrl: 'https://email.example.com/inbox',
      tabTitle: 'Inbox - Email',
      incognito: false,
    },
    orgId: 'org-12345',
    eventId: 'evt-abc123',
    matchType: 'domain',
    matchedIndicator: 'malware.example.com',
    userId: 'user@example.com',
    deviceId: 'device-xyz789',
    raw: {},
    ...overrides,
  };
}

function createTestConfig(overrides: Partial<SyslogConnectorConfig> = {}): SyslogConnectorConfig {
  return {
    type: 'syslog',
    name: 'test-syslog',
    enabled: true,
    host: 'localhost',
    port: 514,
    protocol: 'udp',
    format: 'cef',
    facility: 16,
    severity: 5,
    // Disable batching for tests so we get immediate results
    batch: { maxSize: 1, maxWaitMs: 0 },
    ...overrides,
  };
}

// =============================================================================
// Escape Function Tests
// =============================================================================

describe('Escape Functions', () => {
  describe('escapeCefValue', () => {
    it('should escape backslashes', () => {
      expect(escapeCefValue('path\\file')).toBe('path\\\\file');
    });

    it('should escape equals signs', () => {
      expect(escapeCefValue('key=value')).toBe('key\\=value');
    });

    it('should escape newlines', () => {
      expect(escapeCefValue('line1\nline2')).toBe('line1\\nline2');
    });

    it('should escape carriage returns', () => {
      expect(escapeCefValue('line1\rline2')).toBe('line1\\rline2');
    });

    it('should handle multiple escapes', () => {
      expect(escapeCefValue('path\\file=test\nvalue')).toBe('path\\\\file\\=test\\nvalue');
    });

    it('should handle empty strings', () => {
      expect(escapeCefValue('')).toBe('');
    });
  });

  describe('escapeLeefValue', () => {
    it('should escape tabs', () => {
      expect(escapeLeefValue('col1\tcol2')).toBe('col1\\tcol2');
    });

    it('should escape newlines', () => {
      expect(escapeLeefValue('line1\nline2')).toBe('line1\\nline2');
    });

    it('should escape carriage returns', () => {
      expect(escapeLeefValue('line1\rline2')).toBe('line1\\rline2');
    });
  });

  describe('escapeSDValue', () => {
    it('should escape backslashes', () => {
      expect(escapeSDValue('path\\file')).toBe('path\\\\file');
    });

    it('should escape double quotes', () => {
      expect(escapeSDValue('say "hello"')).toBe('say \\"hello\\"');
    });

    it('should escape right brackets', () => {
      expect(escapeSDValue('array[0]')).toBe('array[0\\]');
    });
  });
});

// =============================================================================
// CEF Formatting Tests
// =============================================================================

describe('CEF Formatting', () => {
  it('should format basic CEF message', () => {
    const event = createTestEvent();
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('CEF:0');
    expect(cef).toContain('|BrowserDefense|');
    expect(cef).toContain('|Connector|');
    expect(cef).toContain('|1.0|');
    expect(cef).toContain('|101|'); // Blocked Domain signature ID
    expect(cef).toContain('|Blocked Domain|');
  });

  it('should include request URL', () => {
    const event = createTestEvent();
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('request=https://malware.example.com/payload.exe');
  });

  it('should include org ID as source', () => {
    const event = createTestEvent();
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('src=org-12345');
  });

  it('should include matched indicator', () => {
    const event = createTestEvent();
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('cs1=malware.example.com cs1Label=MatchedIndicator');
  });

  it('should include redirect chain', () => {
    const event = createTestEvent();
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('cs4=https://trusted.com -> https://redirect.example.com cs4Label=RedirectChain');
  });

  it('should include initiator URL', () => {
    const event = createTestEvent();
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('surl=https://email.example.com/inbox');
  });

  it('should include user ID when present', () => {
    const event = createTestEvent();
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('suser=user@example.com');
  });

  it('should include device ID when present', () => {
    const event = createTestEvent();
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('dvchost=device-xyz789');
  });

  it('should use correct signature ID for URL match type', () => {
    const event = createTestEvent({ matchType: 'url' });
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('|102|'); // Blocked URL signature ID
    expect(cef).toContain('|Blocked URL|');
  });

  it('should use correct signature ID for hash match type', () => {
    const event = createTestEvent({ matchType: 'hash' });
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('|103|'); // Blocked Hash signature ID
    expect(cef).toContain('|Blocked Hash|');
  });

  it('should escape special characters in URL', () => {
    const event = createTestEvent({
      blockedUrl: 'https://evil.com/path?a=1&b=2',
    });
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(cef).toContain('request=https://evil.com/path?a\\=1&b\\=2');
  });

  it('should include receipt time as milliseconds', () => {
    const event = createTestEvent();
    const cef = formatCef(event, 'BrowserDefense', 'Connector', '1.0');

    const expectedRt = new Date('2024-01-15T10:30:00.000Z').getTime();
    expect(cef).toContain(`rt=${expectedRt}`);
  });
});

// =============================================================================
// LEEF Formatting Tests
// =============================================================================

describe('LEEF Formatting', () => {
  it('should format basic LEEF message', () => {
    const event = createTestEvent();
    const leef = formatLeef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(leef).toContain('LEEF:2.0');
    expect(leef).toContain('|BrowserDefense|');
    expect(leef).toContain('|Connector|');
    expect(leef).toContain('|1.0|');
    expect(leef).toContain('|BlockedDomain|');
  });

  it('should use tab separator for attributes', () => {
    const event = createTestEvent();
    const leef = formatLeef(event, 'BrowserDefense', 'Connector', '1.0');

    // After the header, attributes should be tab-separated
    const parts = leef.split('|');
    const attrs = parts[5]; // Last part contains attributes
    expect(attrs).toContain('\t');
  });

  it('should include ISO8601 timestamp', () => {
    const event = createTestEvent();
    const leef = formatLeef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(leef).toContain('devTime=2024-01-15T10:30:00.000Z');
    expect(leef).toContain('devTimeFormat=ISO8601');
  });

  it('should include blocked URL', () => {
    const event = createTestEvent();
    const leef = formatLeef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(leef).toContain('url=https://malware.example.com/payload.exe');
  });

  it('should use correct event ID for URL match type', () => {
    const event = createTestEvent({ matchType: 'url' });
    const leef = formatLeef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(leef).toContain('|BlockedURL|');
  });

  it('should use correct event ID for hash match type', () => {
    const event = createTestEvent({ matchType: 'hash' });
    const leef = formatLeef(event, 'BrowserDefense', 'Connector', '1.0');

    expect(leef).toContain('|BlockedHash|');
  });
});

// =============================================================================
// JSON Formatting Tests
// =============================================================================

describe('JSON Formatting', () => {
  it('should produce valid JSON', () => {
    const event = createTestEvent();
    const json = formatJson(event);

    expect(() => JSON.parse(json)).not.toThrow();
  });

  it('should include all event fields', () => {
    const event = createTestEvent();
    const json = formatJson(event);
    const parsed = JSON.parse(json);

    expect(parsed.blockedUrl).toBe('https://malware.example.com/payload.exe');
    expect(parsed.matchType).toBe('domain');
    expect(parsed.orgId).toBe('org-12345');
    expect(parsed.eventId).toBe('evt-abc123');
  });

  it('should include nested tab context', () => {
    const event = createTestEvent();
    const json = formatJson(event);
    const parsed = JSON.parse(json);

    expect(parsed.tabContext.tabId).toBe(123);
    expect(parsed.tabContext.initiatorUrl).toBe('https://email.example.com/inbox');
  });
});

// =============================================================================
// Raw Formatting Tests
// =============================================================================

describe('Raw Formatting', () => {
  it('should produce key=value format', () => {
    const event = createTestEvent();
    const raw = formatRaw(event);

    expect(raw).toContain('BrowserDefense');
    expect(raw).toContain('blocked_url=https://malware.example.com/payload.exe');
    expect(raw).toContain('match_type=domain');
    expect(raw).toContain('indicator=malware.example.com');
    expect(raw).toContain('org_id=org-12345');
    expect(raw).toContain('event_id=evt-abc123');
  });
});

// =============================================================================
// RFC 5424 Structured Data Tests
// =============================================================================

describe('RFC 5424 Structured Data', () => {
  it('should return NILVALUE when disabled', () => {
    const event = createTestEvent();
    const sd = buildStructuredData(event, false);

    expect(sd).toBe('-');
  });

  it('should include BrowserDefense SD-ID when enabled', () => {
    const event = createTestEvent();
    const sd = buildStructuredData(event, true);

    expect(sd).toContain(`[BrowserDefense@${BROWSERDEFENSE_PEN}`);
  });

  it('should include event fields in structured data', () => {
    const event = createTestEvent();
    const sd = buildStructuredData(event, true);

    expect(sd).toContain('blockedUrl="https://malware.example.com/payload.exe"');
    expect(sd).toContain('matchType="domain"');
    expect(sd).toContain('matchedIndicator="malware.example.com"');
    expect(sd).toContain('orgId="org-12345"');
    expect(sd).toContain('eventId="evt-abc123"');
  });

  it('should include optional fields when present', () => {
    const event = createTestEvent();
    const sd = buildStructuredData(event, true);

    expect(sd).toContain('userId="user@example.com"');
    expect(sd).toContain('deviceId="device-xyz789"');
  });

  it('should include redirect chain', () => {
    const event = createTestEvent();
    const sd = buildStructuredData(event, true);

    expect(sd).toContain('redirectChain="https://trusted.com -> https://redirect.example.com"');
  });

  it('should include custom structured data elements', () => {
    const event = createTestEvent();
    const customElements = [
      {
        id: 'CustomApp@12345',
        params: { key1: 'value1', key2: 'value2' },
      },
    ];
    const sd = buildStructuredData(event, false, customElements);

    expect(sd).toContain('[CustomApp@12345 key1="value1" key2="value2"]');
  });

  it('should escape special characters in SD values', () => {
    const event = createTestEvent({
      blockedUrl: 'https://evil.com/path"with]special\\chars',
    });
    const sd = buildStructuredData(event, true);

    expect(sd).toContain('blockedUrl="https://evil.com/path\\"with\\]special\\\\chars"');
  });
});

// =============================================================================
// RFC 5424 Message Building Tests
// =============================================================================

describe('RFC 5424 Message Building', () => {
  it('should build valid RFC 5424 message', () => {
    const event = createTestEvent();
    const config = createTestConfig();
    const payload = 'Test payload';

    const message = buildSyslogMessage(event, config, payload);

    // PRI = facility * 8 + severity = 16 * 8 + 5 = 133
    expect(message).toMatch(/^<133>1/);
  });

  it('should include ISO8601 timestamp', () => {
    const event = createTestEvent();
    const config = createTestConfig();
    const payload = 'Test payload';

    const message = buildSyslogMessage(event, config, payload);

    expect(message).toContain('2024-01-15T10:30:00.000Z');
  });

  it('should include hostname from org ID', () => {
    const event = createTestEvent();
    const config = createTestConfig();
    const payload = 'Test payload';

    const message = buildSyslogMessage(event, config, payload);

    expect(message).toContain(' org-12345 ');
  });

  it('should include app name', () => {
    const event = createTestEvent();
    const config = createTestConfig({ appName: 'my-app' });
    const payload = 'Test payload';

    const message = buildSyslogMessage(event, config, payload);

    expect(message).toContain(' my-app ');
  });

  it('should use default app name when not specified', () => {
    const event = createTestEvent();
    const config = createTestConfig();
    delete config.appName;
    const payload = 'Test payload';

    const message = buildSyslogMessage(event, config, payload);

    expect(message).toContain(` ${DEFAULT_APP_NAME} `);
  });

  it('should include payload with BOM', () => {
    const event = createTestEvent();
    const config = createTestConfig();
    const payload = 'Test payload';

    const message = buildSyslogMessage(event, config, payload);

    // BOM is \uFEFF
    expect(message).toContain('\uFEFFTest payload');
  });

  it('should calculate correct PRI for different facilities', () => {
    const event = createTestEvent();
    const payload = 'Test';

    // local1 (17) with severity 3 = 17 * 8 + 3 = 139
    const config1 = createTestConfig({ facility: 17, severity: 3 });
    const message1 = buildSyslogMessage(event, config1, payload);
    expect(message1).toMatch(/^<139>1/);

    // local7 (23) with severity 0 = 23 * 8 + 0 = 184
    const config2 = createTestConfig({ facility: 23, severity: 0 });
    const message2 = buildSyslogMessage(event, config2, payload);
    expect(message2).toMatch(/^<184>1/);
  });
});

// =============================================================================
// SyslogConnector Class Tests
// =============================================================================

describe('SyslogConnector', () => {
  let connector: SyslogConnector;

  afterEach(async () => {
    if (connector) {
      try {
        await connector.close();
      } catch {
        // Ignore
      }
    }
  });

  describe('Initialization', () => {
    it('should create connector with valid config', () => {
      const config = createTestConfig();
      connector = new SyslogConnector(config);

      expect(connector.type).toBe('syslog');
      expect(connector.name).toBe('test-syslog');
    });

    it('should initialize successfully', async () => {
      const config = createTestConfig();
      connector = new SyslogConnector(config);

      await expect(connector.init()).resolves.not.toThrow();
    });

    it('should reject empty host', async () => {
      const config = createTestConfig({ host: '' });
      connector = new SyslogConnector(config);

      await expect(connector.init()).rejects.toThrow('host is required');
    });

    it('should reject invalid port', async () => {
      const config = createTestConfig({ port: 0 });
      connector = new SyslogConnector(config);

      await expect(connector.init()).rejects.toThrow('Valid syslog port');
    });

    it('should reject port out of range', async () => {
      const config = createTestConfig({ port: 70000 });
      connector = new SyslogConnector(config);

      await expect(connector.init()).rejects.toThrow('Valid syslog port');
    });

    it('should reject invalid facility', async () => {
      const config = createTestConfig({ facility: 24 });
      connector = new SyslogConnector(config);

      await expect(connector.init()).rejects.toThrow('facility must be between 0 and 23');
    });

    it('should reject invalid severity', async () => {
      const config = createTestConfig({ severity: 8 });
      connector = new SyslogConnector(config);

      await expect(connector.init()).rejects.toThrow('severity must be between 0 and 7');
    });
  });

  describe('Formatting Methods', () => {
    beforeEach(async () => {
      const config = createTestConfig();
      connector = new SyslogConnector(config);
      await connector.init();
    });

    it('should format as CEF', () => {
      const event = createTestEvent();
      const cef = connector.formatAsCef(event);

      expect(cef).toContain('CEF:0');
      expect(cef).toContain('|BrowserDefense|');
    });

    it('should format as LEEF', () => {
      const event = createTestEvent();
      const leef = connector.formatAsLeef(event);

      expect(leef).toContain('LEEF:2.0');
    });

    it('should format as JSON', () => {
      const event = createTestEvent();
      const json = connector.formatAsJson(event);

      expect(() => JSON.parse(json)).not.toThrow();
    });

    it('should format as raw', () => {
      const event = createTestEvent();
      const raw = connector.formatAsRaw(event);

      expect(raw).toContain('BrowserDefense');
    });

    it('should build complete message', () => {
      const event = createTestEvent();
      const message = connector.buildMessage(event);

      // Should be RFC 5424 format with CEF payload
      expect(message).toMatch(/^<\d+>1/);
      expect(message).toContain('CEF:0');
    });
  });

  describe('Sending Events', () => {
    beforeEach(async () => {
      const config = createTestConfig();
      connector = new SyslogConnector(config);
      await connector.init();
    });

    it('should send event successfully', async () => {
      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.success).toBe(true);
      expect(result.eventId).toBe('evt-abc123');
    });

    it('should include format in response', async () => {
      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.response?.format).toBe('cef');
    });

    it('should include protocol in response', async () => {
      const event = createTestEvent();
      const result = await connector.send(event);

      expect(result.response?.protocol).toBe('udp');
    });
  });

  describe('Health Check', () => {
    beforeEach(async () => {
      const config = createTestConfig();
      connector = new SyslogConnector(config);
      await connector.init();
    });

    it('should report healthy status', async () => {
      const health = await connector.health();

      expect(health.healthy).toBe(true);
      expect(health.message).toContain('localhost:514');
    });

    it('should include metrics', async () => {
      const health = await connector.health();

      expect(health.metrics).toBeDefined();
      expect(health.metrics?.eventsSent).toBe(0);
    });

    it('should track sent events in metrics', async () => {
      const event = createTestEvent();
      await connector.send(event);
      await connector.send(event);

      const health = await connector.health();

      expect(health.metrics?.eventsSent).toBe(2);
    });
  });

  describe('Different Formats', () => {
    it('should use LEEF format when configured', async () => {
      const config = createTestConfig({ format: 'leef' });
      connector = new SyslogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const message = connector.buildMessage(event);

      expect(message).toContain('LEEF:2.0');
    });

    it('should use JSON format when configured', async () => {
      const config = createTestConfig({ format: 'json' });
      connector = new SyslogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const message = connector.buildMessage(event);

      // Message should contain valid JSON
      expect(message).toContain('"blockedUrl"');
    });

    it('should use raw format when configured', async () => {
      const config = createTestConfig({ format: 'raw' });
      connector = new SyslogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const message = connector.buildMessage(event);

      expect(message).toContain('blocked_url=');
    });
  });

  describe('Custom CEF Fields', () => {
    it('should use custom vendor', async () => {
      const config = createTestConfig({ cefVendor: 'CustomVendor' });
      connector = new SyslogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const cef = connector.formatAsCef(event);

      expect(cef).toContain('|CustomVendor|');
    });

    it('should use custom product', async () => {
      const config = createTestConfig({ cefProduct: 'CustomProduct' });
      connector = new SyslogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const cef = connector.formatAsCef(event);

      expect(cef).toContain('|CustomProduct|');
    });

    it('should use custom version', async () => {
      const config = createTestConfig({ cefVersion: '2.0' });
      connector = new SyslogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const cef = connector.formatAsCef(event);

      expect(cef).toContain('|2.0|');
    });
  });

  describe('Structured Data', () => {
    it('should include structured data when enabled', async () => {
      const config = createTestConfig({ includeStructuredData: true });
      connector = new SyslogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const message = connector.buildMessage(event);

      expect(message).toContain(`[BrowserDefense@${BROWSERDEFENSE_PEN}`);
    });

    it('should include custom structured data', async () => {
      const config = createTestConfig({
        structuredData: [
          { id: 'meta@12345', params: { env: 'prod', region: 'us-east' } },
        ],
      });
      connector = new SyslogConnector(config);
      await connector.init();

      const event = createTestEvent();
      const message = connector.buildMessage(event);

      expect(message).toContain('[meta@12345 env="prod" region="us-east"]');
    });
  });
});

// =============================================================================
// Factory Registration Tests
// =============================================================================

describe('Factory Registration', () => {
  it('should be registered in global registry', () => {
    expect(connectorRegistry.has('syslog')).toBe(true);
  });

  it('should create connector via registry', () => {
    const config = createTestConfig();
    const connector = connectorRegistry.create(config);

    expect(connector).toBeInstanceOf(SyslogConnector);
    expect(connector.type).toBe('syslog');
  });

  it('should create connector via factory function', () => {
    const config = createTestConfig();
    const connector = createSyslogConnector(config);

    expect(connector).toBeInstanceOf(SyslogConnector);
  });
});

// =============================================================================
// Constants Tests
// =============================================================================

describe('Constants', () => {
  it('should have correct default facility', () => {
    expect(DEFAULT_FACILITY).toBe(16); // local0
  });

  it('should have correct default severity', () => {
    expect(DEFAULT_SEVERITY).toBe(5); // notice
  });

  it('should have correct CEF signature IDs', () => {
    expect(CEF_SIG_ID.BLOCKED_NAVIGATION).toBe('100');
    expect(CEF_SIG_ID.BLOCKED_DOMAIN).toBe('101');
    expect(CEF_SIG_ID.BLOCKED_URL).toBe('102');
    expect(CEF_SIG_ID.BLOCKED_HASH).toBe('103');
  });

  it('should have correct CEF severity levels', () => {
    expect(CEF_SEVERITY.LOW).toBe('3');
    expect(CEF_SEVERITY.MEDIUM).toBe('5');
    expect(CEF_SEVERITY.HIGH).toBe('7');
    expect(CEF_SEVERITY.CRITICAL).toBe('10');
  });
});
