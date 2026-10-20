/**
 * Demo Mode Tests
 *
 * Tests for the demo mode functionality (Issue #571).
 * Demo mode allows safe testing with fake URLs that trigger blocking.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { matchesDemoUrl } from '../src/config/demo';

describe('Demo Mode URL Matching', () => {
  describe('matchesDemoUrl', () => {
    it('should return false for empty demo URLs array', () => {
      expect(matchesDemoUrl('https://example.com', [])).toBe(false);
    });

    it('should return false for undefined demo URLs', () => {
      expect(matchesDemoUrl('https://example.com', undefined as unknown as string[])).toBe(false);
    });

    it('should match exact domain', () => {
      const demoUrls = ['evil-phishing-site.example.com'];
      expect(matchesDemoUrl('https://evil-phishing-site.example.com', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://evil-phishing-site.example.com/login', demoUrls)).toBe(true);
      expect(matchesDemoUrl('http://evil-phishing-site.example.com', demoUrls)).toBe(true);
    });

    it('should match subdomains when using domain pattern', () => {
      const demoUrls = ['example.com'];
      expect(matchesDemoUrl('https://example.com', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://www.example.com', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://subdomain.example.com', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://deep.subdomain.example.com', demoUrls)).toBe(true);
    });

    it('should not match partial domain names', () => {
      const demoUrls = ['example.com'];
      // notexample.com should NOT match example.com (it's not a subdomain)
      expect(matchesDemoUrl('https://notexample.com', demoUrls)).toBe(false);
      expect(matchesDemoUrl('https://example.com.fake.com', demoUrls)).toBe(false);
    });

    it('should match full URL patterns', () => {
      const demoUrls = ['evil-phishing-site.example.com/login'];
      expect(matchesDemoUrl('https://evil-phishing-site.example.com/login', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://evil-phishing-site.example.com/login?param=value', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://evil-phishing-site.example.com/login/page', demoUrls)).toBe(true);
    });

    it('should not match wrong paths for URL patterns', () => {
      const demoUrls = ['evil-phishing-site.example.com/login'];
      expect(matchesDemoUrl('https://evil-phishing-site.example.com/', demoUrls)).toBe(false);
      expect(matchesDemoUrl('https://evil-phishing-site.example.com/other', demoUrls)).toBe(false);
    });

    it('should handle URLs with scheme in demo pattern', () => {
      const demoUrls = ['https://evil-phishing-site.example.com'];
      expect(matchesDemoUrl('https://evil-phishing-site.example.com', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://evil-phishing-site.example.com/page', demoUrls)).toBe(true);
    });

    it('should be case insensitive for domains', () => {
      const demoUrls = ['Evil-Phishing-Site.EXAMPLE.COM'];
      expect(matchesDemoUrl('https://evil-phishing-site.example.com', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://EVIL-PHISHING-SITE.example.COM', demoUrls)).toBe(true);
    });

    it('should match any of multiple demo URLs', () => {
      const demoUrls = [
        'phishing1.example.com',
        'malware-test.example.org',
        'demo.test.com/fake-login',
      ];
      expect(matchesDemoUrl('https://phishing1.example.com', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://malware-test.example.org', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://demo.test.com/fake-login', demoUrls)).toBe(true);
      expect(matchesDemoUrl('https://not-in-list.com', demoUrls)).toBe(false);
    });

    it('should handle whitespace in demo URLs', () => {
      const demoUrls = ['  evil-phishing-site.example.com  '];
      expect(matchesDemoUrl('https://evil-phishing-site.example.com', demoUrls)).toBe(true);
    });

    it('should skip empty demo URL patterns', () => {
      const demoUrls = ['', '   ', 'evil-phishing-site.example.com'];
      expect(matchesDemoUrl('https://evil-phishing-site.example.com', demoUrls)).toBe(true);
    });

    it('should return false for invalid URLs', () => {
      const demoUrls = ['evil-phishing-site.example.com'];
      expect(matchesDemoUrl('not-a-url', demoUrls)).toBe(false);
      expect(matchesDemoUrl('', demoUrls)).toBe(false);
    });

    it('should handle chrome:// and extension URLs gracefully', () => {
      const demoUrls = ['evil-phishing-site.example.com'];
      expect(matchesDemoUrl('chrome://settings', demoUrls)).toBe(false);
      expect(matchesDemoUrl('chrome-extension://abcd1234/popup.html', demoUrls)).toBe(false);
    });
  });
});

describe('Demo Config Storage', () => {
  const mockStorage: Record<string, unknown> = {};

  beforeEach(() => {
    // Clear mock storage
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);

    // Mock chrome.storage.local
    vi.stubGlobal('chrome', {
      storage: {
        local: {
          get: vi.fn((keys: string | string[] | Record<string, unknown>) => {
            if (typeof keys === 'string') {
              return Promise.resolve({ [keys]: mockStorage[keys] });
            }
            if (Array.isArray(keys)) {
              const result: Record<string, unknown> = {};
              keys.forEach((k) => {
                if (mockStorage[k] !== undefined) result[k] = mockStorage[k];
              });
              return Promise.resolve(result);
            }
            return Promise.resolve(mockStorage);
          }),
          set: vi.fn((data: Record<string, unknown>) => {
            Object.assign(mockStorage, data);
            return Promise.resolve();
          }),
        },
      },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('should load default config when no config exists', async () => {
    const { loadDemoConfig, DEFAULT_DEMO_CONFIG } = await import('../src/config/demo');
    const config = await loadDemoConfig();
    expect(config).toEqual(DEFAULT_DEMO_CONFIG);
    expect(config.demoMode).toBe(false);
    expect(config.demoUrls).toEqual([]);
  });

  it('should load saved demo config', async () => {
    mockStorage['browserdefense_demo_config'] = {
      demoMode: true,
      demoUrls: ['evil-phishing-site.example.com'],
    };

    // Re-import to get fresh module
    vi.resetModules();
    const { loadDemoConfig } = await import('../src/config/demo');
    const config = await loadDemoConfig();

    expect(config.demoMode).toBe(true);
    expect(config.demoUrls).toEqual(['evil-phishing-site.example.com']);
  });

  it('should save demo config', async () => {
    vi.resetModules();
    const { saveDemoConfig, loadDemoConfig } = await import('../src/config/demo');

    await saveDemoConfig({
      demoMode: true,
      demoUrls: ['test.example.com'],
    });

    expect(mockStorage['browserdefense_demo_config']).toEqual({
      demoMode: true,
      demoUrls: ['test.example.com'],
    });
  });

  it('should sanitize invalid demo config', async () => {
    mockStorage['browserdefense_demo_config'] = {
      demoMode: 'not-a-boolean', // Invalid type
      demoUrls: ['valid.com', 123, null], // Contains invalid items
    };

    vi.resetModules();
    const { loadDemoConfig } = await import('../src/config/demo');
    const config = await loadDemoConfig();

    expect(config.demoMode).toBe(false); // Sanitized to false
    expect(config.demoUrls).toEqual(['valid.com']); // Filtered to only strings
  });
});

describe('Demo Forensics Tagging', () => {
  it('should tag forensics payload as demo', async () => {
    const { captureForensics } = await import('../src/background/forensics');

    // Create mock navigation details
    const mockDetails: chrome.webNavigation.WebNavigationParentedCallbackDetails = {
      tabId: 1,
      url: 'https://evil-phishing-site.example.com/login',
      frameId: 0,
      timeStamp: Date.now(),
      processId: 1,
      parentFrameId: -1,
      frameType: 'outermost_frame',
      documentLifecycle: 'active',
    };

    // Capture forensics with isDemo flag
    const payload = captureForensics(mockDetails, mockDetails.url, {
      reason: 'demo_block',
      isDemo: true,
    });

    expect(payload.isDemo).toBe(true);
    expect(payload.reason).toBe('demo_block');
    expect(payload.blockedUrl).toBe('https://evil-phishing-site.example.com/login');
  });

  it('should not tag non-demo forensics', async () => {
    const { captureForensics } = await import('../src/background/forensics');

    const mockDetails: chrome.webNavigation.WebNavigationParentedCallbackDetails = {
      tabId: 1,
      url: 'https://real-malware.com/bad',
      frameId: 0,
      timeStamp: Date.now(),
      processId: 1,
      parentFrameId: -1,
      frameType: 'outermost_frame',
      documentLifecycle: 'active',
    };

    // Capture forensics without isDemo flag
    const payload = captureForensics(mockDetails, mockDetails.url, {
      reason: 'ioc_match',
    });

    expect(payload.isDemo).toBeUndefined();
    expect(payload.reason).toBe('ioc_match');
  });

  it('should support backward compatible signature', async () => {
    const { captureForensics } = await import('../src/background/forensics');

    const mockDetails: chrome.webNavigation.WebNavigationParentedCallbackDetails = {
      tabId: 1,
      url: 'https://example.com',
      frameId: 0,
      timeStamp: Date.now(),
      processId: 1,
      parentFrameId: -1,
      frameType: 'outermost_frame',
      documentLifecycle: 'active',
    };

    // Old signature: captureForensics(details, normalizedUrl, reason, formSchemas, tlsMetadata)
    const payload = captureForensics(mockDetails, mockDetails.url, 'ioc_match');

    expect(payload.reason).toBe('ioc_match');
    expect(payload.isDemo).toBeUndefined();
    expect(payload.blockedUrl).toBe('https://example.com');
  });
});
