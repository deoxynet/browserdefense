/**
 * Tests for EDR Enrichment Export Module
 *
 * Tests for read-only forensic artifact export to EDR systems.
 * Covers artifact creation, caching, and export formats (JSON, STIX, CEF, LEEF).
 *
 * Reference: Issue #169
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  parseUserAgent,
  extractHostnamePort,
  generateArtifactId,
  DEFAULT_EDR_ENRICHMENT_CONFIG,
  type EDREnrichmentArtifact,
  type BrowserProcessContext,
  type URLArtifact,
  type IOCMatchArtifact,
  type DOMFingerprintArtifact,
  type FormSchemaArtifact,
} from '../src/types/edr-enrichment';
import { EDR_ENRICHMENT_CONFIG_KEY } from '../src/config/storage-keys';

// ============ Mock Chrome APIs ============

const mockStorage: Record<string, unknown> = {};

const mockChrome = {
  storage: {
    local: {
      get: vi.fn((key: string | string[]) => {
        if (typeof key === 'string') {
          return Promise.resolve({ [key]: mockStorage[key] });
        }
        const result: Record<string, unknown> = {};
        for (const k of key) {
          result[k] = mockStorage[k];
        }
        return Promise.resolve(result);
      }),
      set: vi.fn((items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
        return Promise.resolve();
      }),
      remove: vi.fn((key: string | string[]) => {
        if (typeof key === 'string') {
          delete mockStorage[key];
        } else {
          for (const k of key) {
            delete mockStorage[k];
          }
        }
        return Promise.resolve();
      }),
    },
  },
  tabs: {
    onRemoved: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
    },
  },
};

// @ts-expect-error - Mocking chrome global
globalThis.chrome = mockChrome;

// ============ Type Helper Tests ============

describe('EDR Enrichment Types', () => {
  describe('parseUserAgent', () => {
    it('should parse Chrome on Windows', () => {
      const ua =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
      const result = parseUserAgent(ua);

      expect(result.browserName).toBe('chrome');
      expect(result.browserVersion).toBe('120.0');
      expect(result.platform).toBe('windows');
    });

    it('should parse Edge on Windows', () => {
      const ua =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0';
      const result = parseUserAgent(ua);

      expect(result.browserName).toBe('edge');
      expect(result.browserVersion).toBe('120.0');
      expect(result.platform).toBe('windows');
    });

    it('should parse Chrome on macOS', () => {
      const ua =
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
      const result = parseUserAgent(ua);

      expect(result.browserName).toBe('chrome');
      expect(result.platform).toBe('macos');
    });

    it('should parse Chrome on Linux', () => {
      const ua =
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
      const result = parseUserAgent(ua);

      expect(result.browserName).toBe('chrome');
      expect(result.platform).toBe('linux');
    });

    it('should handle unknown browser', () => {
      const ua = 'Mozilla/5.0 (Unknown)';
      const result = parseUserAgent(ua);

      expect(result.browserName).toBe('unknown');
      expect(result.platform).toBe('unknown');
    });
  });

  describe('extractHostnamePort', () => {
    it('should extract hostname and default HTTPS port', () => {
      const result = extractHostnamePort('https://example.com/path');
      expect(result.hostname).toBe('example.com');
      expect(result.port).toBe(443);
    });

    it('should extract hostname and default HTTP port', () => {
      const result = extractHostnamePort('http://example.com/path');
      expect(result.hostname).toBe('example.com');
      expect(result.port).toBe(80);
    });

    it('should extract custom port', () => {
      const result = extractHostnamePort('https://example.com:8443/path');
      expect(result.hostname).toBe('example.com');
      expect(result.port).toBe(8443);
    });

    it('should handle invalid URL', () => {
      const result = extractHostnamePort('not-a-url');
      expect(result.hostname).toBe('');
      expect(result.port).toBe(0);
    });
  });

  describe('generateArtifactId', () => {
    it('should generate unique IDs', () => {
      const id1 = generateArtifactId();
      const id2 = generateArtifactId();

      expect(id1).toMatch(/^bioc-[a-z0-9]+-[a-z0-9]+$/);
      expect(id2).toMatch(/^bioc-[a-z0-9]+-[a-z0-9]+$/);
      expect(id1).not.toBe(id2);
    });

    it('should start with bioc- prefix', () => {
      const id = generateArtifactId();
      expect(id.startsWith('bioc-')).toBe(true);
    });
  });

  describe('DEFAULT_EDR_ENRICHMENT_CONFIG', () => {
    it('should have expected default values', () => {
      expect(DEFAULT_EDR_ENRICHMENT_CONFIG.enabled).toBe(true);
      expect(DEFAULT_EDR_ENRICHMENT_CONFIG.includeDOMFingerprint).toBe(true);
      expect(DEFAULT_EDR_ENRICHMENT_CONFIG.includeScreenshot).toBe(true);
      expect(DEFAULT_EDR_ENRICHMENT_CONFIG.includeFormSchemas).toBe(true);
      expect(DEFAULT_EDR_ENRICHMENT_CONFIG.includeTLSMetadata).toBe(true);
      expect(DEFAULT_EDR_ENRICHMENT_CONFIG.includeRedirectChain).toBe(true);
      expect(DEFAULT_EDR_ENRICHMENT_CONFIG.maxRedirectChainLength).toBe(10);
      expect(DEFAULT_EDR_ENRICHMENT_CONFIG.correlationWindowMs).toBe(2000);
    });
  });
});

describe('EDR Enrichment Module', () => {
  let edrModule: typeof import('../src/background/edr-enrichment');

  beforeEach(async () => {
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    vi.clearAllMocks();

    vi.resetModules();
    edrModule = await import('../src/background/edr-enrichment');
  });

  describe('getEDREnrichmentConfig', () => {
    it('should return default config when none stored', async () => {
      const config = await edrModule.getEDREnrichmentConfig();

      expect(config.enabled).toBe(true);
      expect(config.includeDOMFingerprint).toBe(true);
      expect(config.correlationWindowMs).toBe(2000);
    });

    it('should merge stored config with defaults', async () => {
      mockStorage[EDR_ENRICHMENT_CONFIG_KEY] = {
        enabled: false,
        includeScreenshot: false,
      };

      const config = await edrModule.getEDREnrichmentConfig();

      expect(config.enabled).toBe(false);
      expect(config.includeScreenshot).toBe(false);
      expect(config.includeDOMFingerprint).toBe(true); // Default preserved
    });
  });

  describe('updateEDREnrichmentConfig', () => {
    it('should update and return merged config', async () => {
      const updated = await edrModule.updateEDREnrichmentConfig({
        enabled: false,
        maxRedirectChainLength: 5,
      });

      expect(updated.enabled).toBe(false);
      expect(updated.maxRedirectChainLength).toBe(5);
      expect(mockChrome.storage.local.set).toHaveBeenCalled();
    });
  });

  describe('Fingerprint storage', () => {
    it('should store and retrieve fingerprint for tab', () => {
      const tabId = 123;
      const hash = 'abc123def456';
      const response = { confidence: 85, isNovel: false, action: 'block' as const };

      edrModule.storeFingerprintForTab(tabId, hash, response);

      const data = edrModule.consumeFingerprintForTab(tabId);
      expect(data).not.toBeNull();
      expect(data?.hash).toBe(hash);
      expect(data?.response?.confidence).toBe(85);
    });

    it('should consume and remove fingerprint', () => {
      const tabId = 456;
      edrModule.storeFingerprintForTab(tabId, 'hash123');

      const first = edrModule.consumeFingerprintForTab(tabId);
      expect(first).not.toBeNull();

      const second = edrModule.consumeFingerprintForTab(tabId);
      expect(second).toBeNull();
    });

    it('should clear fingerprint for tab', () => {
      const tabId = 789;
      edrModule.storeFingerprintForTab(tabId, 'hash456');
      edrModule.clearFingerprintForTab(tabId);

      const data = edrModule.consumeFingerprintForTab(tabId);
      expect(data).toBeNull();
    });
  });

  describe('createEDREnrichmentArtifact', () => {
    const baseForensics = {
      blockedUrl: 'https://evil.com/phishing',
      timestamp: '2024-01-15T10:30:00Z',
      redirectChain: ['https://original.com', 'https://redirect.com', 'https://evil.com/phishing'],
      tabId: 123,
      frameId: 0,
      normalizedUrl: 'evil.com/phishing',
      reason: 'ioc_match',
    };

    it('should create basic artifact', async () => {
      const artifact = await edrModule.createEDREnrichmentArtifact(baseForensics, {
        orgId: 'org-123',
      });

      expect(artifact.schemaVersion).toBe('1.0');
      expect(artifact.artifactType).toBe('browserdefense-enrichment');
      expect(artifact.orgId).toBe('org-123');
      expect(artifact.blockEvent.reason).toBe('ioc_match');
      expect(artifact.url.blockedUrl).toBe('https://evil.com/phishing');
      expect(artifact.url.redirectCount).toBe(3);
    });

    it('should include DOM fingerprint when provided', async () => {
      const artifact = await edrModule.createEDREnrichmentArtifact(baseForensics, {
        orgId: 'org-123',
        fingerprint: {
          hash: 'domhash123',
          response: {
            confidence: 90,
            kitId: 'office365-kit-v2',
            isNovel: false,
            action: 'block',
          },
        },
      });

      expect(artifact.domFingerprint).toBeDefined();
      expect(artifact.domFingerprint?.domHash).toBe('domhash123');
      expect(artifact.domFingerprint?.kitId).toBe('office365-kit-v2');
      expect(artifact.domFingerprint?.confidence).toBe(90);
    });

    it('should include screenshot reference when provided', async () => {
      const artifact = await edrModule.createEDREnrichmentArtifact(baseForensics, {
        orgId: 'org-123',
        screenshotHash: 'screenshothash456',
        screenshotDimensions: { width: 1920, height: 1080 },
        screenshotId: 'screenshot-id-789',
      });

      expect(artifact.screenshot).toBeDefined();
      expect(artifact.screenshot?.captured).toBe(true);
      expect(artifact.screenshot?.imageHash).toBe('screenshothash456');
      expect(artifact.screenshot?.dimensions?.width).toBe(1920);
    });

    it('should include form schemas when available', async () => {
      const forensicsWithForms = {
        ...baseForensics,
        formSchemas: [
          {
            action: 'https://evil.com/steal',
            method: 'POST' as const,
            fields: [
              { tag: 'input' as const, type: 'email', name: 'email', required: false },
              { tag: 'input' as const, type: 'password', name: 'password', required: true },
            ],
            fieldCount: 2,
            isLoginForm: true,
            isPaymentForm: false,
          },
        ],
      };

      const artifact = await edrModule.createEDREnrichmentArtifact(forensicsWithForms, {
        orgId: 'org-123',
      });

      expect(artifact.formSchemas).toBeDefined();
      expect(artifact.formSchemas?.formCount).toBe(1);
      expect(artifact.formSchemas?.hasLoginForm).toBe(true);
      expect(artifact.formSchemas?.hasPaymentForm).toBe(false);
      expect(artifact.formSchemas?.inputTypes).toContain('email');
      expect(artifact.formSchemas?.inputTypes).toContain('password');
    });

    it('should include process context with correlation hints', async () => {
      const artifact = await edrModule.createEDREnrichmentArtifact(baseForensics, {
        orgId: 'org-123',
      });

      expect(artifact.processContext).toBeDefined();
      expect(artifact.processContext.tabId).toBe(123);
      expect(artifact.processContext.correlationHints.targetHostname).toBe('evil.com');
      expect(artifact.processContext.correlationHints.targetPort).toBe(443);
      expect(artifact.processContext.correlationHints.correlationWindowMs).toBe(2000);
    });
  });

  describe('Artifact caching', () => {
    const baseForensics = {
      blockedUrl: 'https://test.com',
      timestamp: new Date().toISOString(),
      tabId: 1,
      frameId: 0,
      reason: 'test',
    };

    it('should cache and retrieve artifacts', async () => {
      const artifact = await edrModule.createEDREnrichmentArtifact(baseForensics, {
        orgId: 'test-org',
      });

      const retrieved = edrModule.getArtifact(artifact.artifactId);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.artifactId).toBe(artifact.artifactId);
    });

    it('should return null for unknown artifact', () => {
      const retrieved = edrModule.getArtifact('nonexistent-id');
      expect(retrieved).toBeNull();
    });

    it('should list recent artifacts', async () => {
      await edrModule.createEDREnrichmentArtifact(baseForensics, { orgId: 'org1' });
      await edrModule.createEDREnrichmentArtifact(baseForensics, { orgId: 'org2' });
      await edrModule.createEDREnrichmentArtifact(baseForensics, { orgId: 'org3' });

      const list = edrModule.listArtifacts(10);
      expect(list.length).toBe(3);
    });

    it('should clear all artifacts', async () => {
      await edrModule.createEDREnrichmentArtifact(baseForensics, { orgId: 'test' });
      edrModule.clearArtifacts();

      const list = edrModule.listArtifacts();
      expect(list.length).toBe(0);
    });
  });

  describe('Export formats', () => {
    let testArtifact: EDREnrichmentArtifact;

    beforeEach(async () => {
      const forensics = {
        blockedUrl: 'https://phishing.example.com/login',
        timestamp: '2024-01-15T10:30:00Z',
        redirectChain: ['https://phishing.example.com/login'],
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      testArtifact = await edrModule.createEDREnrichmentArtifact(forensics, {
        orgId: 'test-org',
        fingerprint: { hash: 'testhash123', response: { confidence: 85, isNovel: false, action: 'block' } },
        matchType: 'url',
        matchedIndicator: 'phishing.example.com/login',
        iocPriority: 'high',
      });
    });

    it('should export as JSON', () => {
      const exported = edrModule.exportArtifact(testArtifact, 'json');
      expect(exported).toEqual(testArtifact);
    });

    it('should export as STIX', () => {
      const exported = edrModule.exportArtifact(testArtifact, 'stix');
      expect(typeof exported).toBe('object');

      const stix = exported as { type: string; spec_version: string; objects: Record<string, unknown> };
      expect(stix.type).toBe('observed-data');
      expect(stix.spec_version).toBe('2.1');
      expect(stix.objects).toBeDefined();
      expect(stix.objects['url--0']).toBeDefined();
    });

    it('should export as CEF', () => {
      const exported = edrModule.exportArtifact(testArtifact, 'cef');
      expect(typeof exported).toBe('string');

      const cef = exported as string;
      expect(cef.startsWith('CEF:0|BrowserDefense|Browser|1.0|')).toBe(true);
      expect(cef).toContain('request=https://phishing.example.com/login');
      expect(cef).toContain('cs1=testhash123');
    });

    it('should export as LEEF', () => {
      const exported = edrModule.exportArtifact(testArtifact, 'leef');
      expect(typeof exported).toBe('string');

      const leef = exported as string;
      expect(leef.startsWith('LEEF:2.0|BrowserDefense|Browser|1.0|')).toBe(true);
      expect(leef).toContain('url=https://phishing.example.com/login');
      expect(leef).toContain('domHash=testhash123');
    });
  });

  describe('setupEDREnrichmentCleanup', () => {
    it('should register tab removal listener', () => {
      edrModule.setupEDREnrichmentCleanup();
      expect(mockChrome.tabs.onRemoved.addListener).toHaveBeenCalled();
    });
  });
});

describe('EDR Enrichment Artifact Structure', () => {
  it('should have correct BrowserProcessContext structure', () => {
    const ctx: BrowserProcessContext = {
      eventTimestamp: '2024-01-15T10:30:00Z',
      eventTimestampMs: 1705314600000,
      userAgent: 'Mozilla/5.0 Chrome/120.0',
      browserName: 'chrome',
      browserVersion: '120.0',
      platform: 'windows',
      tabId: 123,
      windowId: 1,
      incognito: false,
      tabTitle: 'Phishing Page',
      correlationHints: {
        targetHostname: 'evil.com',
        targetPort: 443,
        correlationWindowMs: 2000,
      },
    };

    expect(ctx.browserName).toBe('chrome');
    expect(ctx.correlationHints.targetHostname).toBe('evil.com');
  });

  it('should have correct URLArtifact structure', () => {
    const url: URLArtifact = {
      blockedUrl: 'https://evil.com/phish',
      normalizedUrl: 'evil.com/phish',
      redirectChain: ['https://legit.com', 'https://redirect.com', 'https://evil.com/phish'],
      redirectCount: 3,
      initialUrl: 'https://legit.com',
      initiator: 'link',
      sourceUrl: 'https://email-link.com',
    };

    expect(url.redirectCount).toBe(3);
    expect(url.initiator).toBe('link');
  });

  it('should have correct IOCMatchArtifact structure', () => {
    const ioc: IOCMatchArtifact = {
      matchType: 'domain',
      matchedIndicator: 'evil.com',
      source: 'threat-intel-feed',
      priority: 'critical',
      categories: ['phishing', 'credential-harvester'],
      iocAddedAt: '2024-01-01T00:00:00Z',
    };

    expect(ioc.matchType).toBe('domain');
    expect(ioc.priority).toBe('critical');
    expect(ioc.categories?.length).toBe(2);
  });

  it('should have correct DOMFingerprintArtifact structure', () => {
    const fingerprint: DOMFingerprintArtifact = {
      domHash: 'abc123def456',
      kitId: 'office365-kit-v2',
      kitName: 'Office 365 Credential Harvester',
      confidence: 95,
      isNovel: false,
      globalOccurrences: 150,
      tags: ['credential-harvester', 'o365-themed', 'high-confidence'],
    };

    expect(fingerprint.confidence).toBe(95);
    expect(fingerprint.tags?.length).toBe(3);
  });

  it('should have correct FormSchemaArtifact structure', () => {
    const forms: FormSchemaArtifact = {
      formCount: 2,
      hasLoginForm: true,
      hasPaymentForm: false,
      inputTypes: ['email', 'password', 'text'],
      actionUrls: ['https://evil.com/steal', 'https://evil.com/collect'],
    };

    expect(forms.formCount).toBe(2);
    expect(forms.hasLoginForm).toBe(true);
    expect(forms.inputTypes.length).toBe(3);
  });
});
