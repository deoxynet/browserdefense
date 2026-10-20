/**
 * Gate 3 Validation: Forensics Usefulness
 *
 * This test suite validates that forensics data is actually useful for SOC incident response.
 * It tests the complete chain from capture to decryption to analysis.
 *
 * From docs/go-no-go-checklist.md Gate 3:
 * - [ ] Blocked events include redirect chain + timestamp + destination
 * - [ ] Forensics decrypt/view path works in under 2 minutes
 * - [ ] Data format is parseable and actionable
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  captureForensics,
  trackRedirect,
  getRedirectChain,
  clearRedirectChain,
  ForensicsPayload,
} from '../../src/background/forensics';
import {
  encryptForensics,
  decryptForensics,
  generateRSAKeyPair,
  EncryptedPayload,
} from '../../src/crypto/encryption';

// Mock chrome APIs
const mockStorage: Record<string, unknown> = {};
const mockChrome = {
  storage: {
    local: {
      get: vi.fn((key: string) => Promise.resolve({ [key]: mockStorage[key] })),
      set: vi.fn((items: Record<string, unknown>) => {
        Object.assign(mockStorage, items);
        return Promise.resolve();
      }),
      remove: vi.fn((key: string) => {
        delete mockStorage[key];
        return Promise.resolve();
      }),
    },
  },
  action: {
    setBadgeText: vi.fn(() => Promise.resolve()),
    setBadgeBackgroundColor: vi.fn(() => Promise.resolve()),
  },
  runtime: {
    getURL: (path: string) => `chrome-extension://test/${path}`,
  },
};

// @ts-expect-error - Mocking chrome global
globalThis.chrome = mockChrome;

/**
 * Required fields for SOC analyst actionability (from issue #38):
 * - blocked_url: The URL that was blocked
 * - final_url: Where the user would have ended up (same as blockedUrl)
 * - redirect_chain: Full path showing how user got to blocked URL
 * - timestamp: When the block occurred (ISO 8601)
 * - tab_url: The page the user was on when they clicked (referrer)
 * - user_agent: Browser info (not currently captured - noted as gap)
 * - org_id: Customer identifier (added during encryption)
 */

describe('Gate 3: Forensics Usefulness Validation', () => {
  beforeEach(() => {
    Object.keys(mockStorage).forEach(key => delete mockStorage[key]);
    vi.clearAllMocks();
  });

  describe('1. Required Forensics Fields Validation', () => {
    it('should capture all required fields for SOC actionability', () => {
      const tabId = 100;

      // Simulate user clicking through redirects
      trackRedirect(tabId, 'https://legitimate-email.com/link?id=abc');
      trackRedirect(tabId, 'https://tracking-service.com/r/123');
      trackRedirect(tabId, 'https://evil-phishing-site.com/login');

      const details = {
        tabId,
        url: 'https://evil-phishing-site.com/login',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
        initiator: 'https://webmail.example.com',
      };

      const payload = captureForensics(details, 'evil-phishing-site.com/login', 'ioc_match');

      // Validate all required fields are present
      expect(payload.blockedUrl).toBe('https://evil-phishing-site.com/login');
      expect(payload.timestamp).toBeDefined();
      expect(new Date(payload.timestamp).toISOString()).toBe(payload.timestamp); // Valid ISO 8601
      expect(payload.redirectChain).toBeDefined();
      expect(payload.redirectChain).toHaveLength(3);
      expect(payload.tabId).toBe(tabId);
      expect(payload.frameId).toBe(0);
      expect(payload.initiator).toBe('https://webmail.example.com');
      expect(payload.normalizedUrl).toBe('evil-phishing-site.com/login');
      expect(payload.reason).toBe('ioc_match');
    });

    it('should capture redirect chain in correct order (first to last)', () => {
      const tabId = 200;

      // Simulate redirect chain: email -> tracker -> landing -> payload
      trackRedirect(tabId, 'https://email-campaign.com/click?id=user123');
      trackRedirect(tabId, 'https://analytics-tracker.net/r/campaign');
      trackRedirect(tabId, 'https://landing-page.com/special-offer');
      trackRedirect(tabId, 'https://malware-download.evil/payload.exe');

      const details = {
        tabId,
        url: 'https://malware-download.evil/payload.exe',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const payload = captureForensics(details, 'malware-download.evil/payload.exe', 'ioc_match');

      expect(payload.redirectChain).toEqual([
        'https://email-campaign.com/click?id=user123',
        'https://analytics-tracker.net/r/campaign',
        'https://landing-page.com/special-offer',
        'https://malware-download.evil/payload.exe',
      ]);
    });

    it('should handle direct navigation without redirect chain', () => {
      const tabId = 300;

      const details = {
        tabId,
        url: 'https://known-bad-domain.com/malware',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
        initiator: undefined, // Direct navigation
      };

      const payload = captureForensics(details, 'known-bad-domain.com/malware', 'ioc_match');

      expect(payload.blockedUrl).toBe('https://known-bad-domain.com/malware');
      expect(payload.redirectChain).toBeUndefined();
      expect(payload.initiator).toBeUndefined();
    });
  });

  describe('2. Redirect Chain Capture (3+ redirects)', () => {
    it('should capture long redirect chains (5+ hops)', () => {
      const tabId = 400;

      // Complex redirect chain often seen in phishing campaigns
      const redirectUrls = [
        'https://bit.ly/xyz123',
        'https://t.co/abc456',
        'https://link-rotator.com/r/1',
        'https://geo-redirect.net/US',
        'https://temp-landing.com/bridge',
        'https://final-phishing.evil/steal-creds',
      ];

      redirectUrls.forEach(url => trackRedirect(tabId, url));

      const details = {
        tabId,
        url: redirectUrls[redirectUrls.length - 1],
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const payload = captureForensics(details, 'final-phishing.evil/steal-creds', 'ioc_match');

      expect(payload.redirectChain).toHaveLength(6);
      expect(payload.redirectChain![0]).toBe('https://bit.ly/xyz123');
      expect(payload.redirectChain![5]).toBe('https://final-phishing.evil/steal-creds');
    });

    it('should handle exactly 3 redirects (minimum for chain)', () => {
      const tabId = 500;

      trackRedirect(tabId, 'https://original.com');
      trackRedirect(tabId, 'https://middle.com');
      trackRedirect(tabId, 'https://final.com');

      const details = {
        tabId,
        url: 'https://final.com',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const payload = captureForensics(details, 'final.com', 'ioc_match');

      expect(payload.redirectChain).toHaveLength(3);
    });

    it('should limit chain to 20 entries to prevent memory issues', () => {
      const tabId = 600;

      // Add 25 redirects
      for (let i = 0; i < 25; i++) {
        trackRedirect(tabId, `https://redirect${i}.com`);
      }

      const details = {
        tabId,
        url: 'https://redirect24.com',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const payload = captureForensics(details, 'redirect24.com', 'ioc_match');

      expect(payload.redirectChain).toHaveLength(20);
      // Should keep the most recent 20, starting from redirect5
      expect(payload.redirectChain![0]).toBe('https://redirect5.com');
      expect(payload.redirectChain![19]).toBe('https://redirect24.com');
    });

    it('should not duplicate consecutive identical URLs', () => {
      const tabId = 700;

      // Sometimes the same URL can fire multiple events
      trackRedirect(tabId, 'https://start.com');
      trackRedirect(tabId, 'https://start.com'); // Duplicate
      trackRedirect(tabId, 'https://middle.com');
      trackRedirect(tabId, 'https://middle.com'); // Duplicate
      trackRedirect(tabId, 'https://end.com');

      const details = {
        tabId,
        url: 'https://end.com',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const payload = captureForensics(details, 'end.com', 'ioc_match');

      expect(payload.redirectChain).toEqual([
        'https://start.com',
        'https://middle.com',
        'https://end.com',
      ]);
    });

    it('should clear redirect chain after capture (no cross-contamination)', () => {
      const tabId = 800;

      trackRedirect(tabId, 'https://first-chain-1.com');
      trackRedirect(tabId, 'https://first-chain-2.com');

      // First capture
      const details1 = {
        tabId,
        url: 'https://first-chain-2.com',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const payload1 = captureForensics(details1, 'first-chain-2.com', 'ioc_match');
      expect(payload1.redirectChain).toHaveLength(2);

      // Second capture on same tab should not include first chain
      trackRedirect(tabId, 'https://second-chain-1.com');
      trackRedirect(tabId, 'https://second-chain-2.com');
      trackRedirect(tabId, 'https://second-chain-3.com');

      const details2 = {
        tabId,
        url: 'https://second-chain-3.com',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const payload2 = captureForensics(details2, 'second-chain-3.com', 'ioc_match');
      expect(payload2.redirectChain).toHaveLength(3);
      expect(payload2.redirectChain![0]).toBe('https://second-chain-1.com');
    });
  });

  describe('3. Timestamp Precision and Format', () => {
    it('should capture timestamp in ISO 8601 format', () => {
      const beforeCapture = new Date();

      const payload = captureForensics(
        {
          tabId: 900,
          url: 'https://blocked.com',
          frameId: 0,
          timeStamp: Date.now(),
          parentFrameId: -1,
          processId: 1,
          documentId: 'doc1',
          documentLifecycle: 'active' as const,
          frameType: 'outermost_frame' as const,
        },
        'blocked.com',
        'ioc_match'
      );

      const afterCapture = new Date();
      const capturedTime = new Date(payload.timestamp);

      // Verify format (ISO 8601 with milliseconds)
      expect(payload.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);

      // Verify time is within capture window
      expect(capturedTime.getTime()).toBeGreaterThanOrEqual(beforeCapture.getTime());
      expect(capturedTime.getTime()).toBeLessThanOrEqual(afterCapture.getTime());
    });

    it('should have millisecond precision for timeline reconstruction', () => {
      const payload1 = captureForensics(
        {
          tabId: 1000,
          url: 'https://blocked1.com',
          frameId: 0,
          timeStamp: Date.now(),
          parentFrameId: -1,
          processId: 1,
          documentId: 'doc1',
          documentLifecycle: 'active' as const,
          frameType: 'outermost_frame' as const,
        },
        'blocked1.com',
        'ioc_match'
      );

      // Small delay
      const start = Date.now();
      while (Date.now() - start < 5) {
        // busy wait for 5ms
      }

      const payload2 = captureForensics(
        {
          tabId: 1001,
          url: 'https://blocked2.com',
          frameId: 0,
          timeStamp: Date.now(),
          parentFrameId: -1,
          processId: 1,
          documentId: 'doc1',
          documentLifecycle: 'active' as const,
          frameType: 'outermost_frame' as const,
        },
        'blocked2.com',
        'ioc_match'
      );

      // Timestamps should be different
      const time1 = new Date(payload1.timestamp).getTime();
      const time2 = new Date(payload2.timestamp).getTime();
      expect(time2).toBeGreaterThan(time1);
    });
  });

  describe('4. Encryption/Decryption Round-Trip', () => {
    it('should encrypt and decrypt forensics payload correctly', async () => {
      const { publicKey, privateKey } = await generateRSAKeyPair();

      const originalPayload: ForensicsPayload = {
        blockedUrl: 'https://malicious-site.com/payload',
        timestamp: new Date().toISOString(),
        redirectChain: [
          'https://email-link.com/click',
          'https://tracker.net/r/123',
          'https://malicious-site.com/payload',
        ],
        tabId: 42,
        frameId: 0,
        initiator: 'https://webmail.example.com',
        normalizedUrl: 'malicious-site.com/payload',
        reason: 'ioc_match',
      };

      // Encrypt
      const encrypted = await encryptForensics(originalPayload, publicKey);

      // Verify encrypted structure
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.wrappedKey).toBeDefined();
      expect(encrypted.ciphertext).toBeDefined();

      // Verify all fields are base64
      expect(() => atob(encrypted.iv)).not.toThrow();
      expect(() => atob(encrypted.wrappedKey)).not.toThrow();
      expect(() => atob(encrypted.ciphertext)).not.toThrow();

      // Decrypt
      const decrypted = await decryptForensics<ForensicsPayload>(encrypted, privateKey);

      // Verify all fields match
      expect(decrypted.blockedUrl).toBe(originalPayload.blockedUrl);
      expect(decrypted.timestamp).toBe(originalPayload.timestamp);
      expect(decrypted.redirectChain).toEqual(originalPayload.redirectChain);
      expect(decrypted.tabId).toBe(originalPayload.tabId);
      expect(decrypted.frameId).toBe(originalPayload.frameId);
      expect(decrypted.initiator).toBe(originalPayload.initiator);
      expect(decrypted.normalizedUrl).toBe(originalPayload.normalizedUrl);
      expect(decrypted.reason).toBe(originalPayload.reason);
    });

    it('should handle multiple encrypted records', async () => {
      const { publicKey, privateKey } = await generateRSAKeyPair();

      const payloads: ForensicsPayload[] = [
        {
          blockedUrl: 'https://phishing1.com/login',
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          tabId: 1,
          frameId: 0,
          reason: 'ioc_match',
        },
        {
          blockedUrl: 'https://malware2.net/download.exe',
          timestamp: new Date(Date.now() - 1800000).toISOString(),
          redirectChain: ['https://short.link/abc', 'https://malware2.net/download.exe'],
          tabId: 2,
          frameId: 0,
          reason: 'ioc_match',
        },
        {
          blockedUrl: 'https://cryptominer.bad/script.js',
          timestamp: new Date().toISOString(),
          tabId: 3,
          frameId: 0,
          initiator: 'https://compromised-wordpress.com',
          reason: 'ioc_match',
        },
      ];

      // Encrypt all
      const encryptedRecords: EncryptedPayload[] = [];
      for (const payload of payloads) {
        encryptedRecords.push(await encryptForensics(payload, publicKey));
      }

      expect(encryptedRecords).toHaveLength(3);

      // Decrypt all
      const decryptedRecords: ForensicsPayload[] = [];
      for (const encrypted of encryptedRecords) {
        decryptedRecords.push(await decryptForensics<ForensicsPayload>(encrypted, privateKey));
      }

      expect(decryptedRecords).toHaveLength(3);
      expect(decryptedRecords[0].blockedUrl).toBe('https://phishing1.com/login');
      expect(decryptedRecords[1].redirectChain).toHaveLength(2);
      expect(decryptedRecords[2].initiator).toBe('https://compromised-wordpress.com');
    });

    it('should fail decryption with wrong private key', async () => {
      const { publicKey: publicKey1 } = await generateRSAKeyPair();
      const { privateKey: privateKey2 } = await generateRSAKeyPair();

      const payload: ForensicsPayload = {
        blockedUrl: 'https://evil.com',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      const encrypted = await encryptForensics(payload, publicKey1);

      // Try to decrypt with wrong key
      await expect(decryptForensics(encrypted, privateKey2)).rejects.toThrow();
    });

    it('should handle special characters in URLs', async () => {
      const { publicKey, privateKey } = await generateRSAKeyPair();

      const payload: ForensicsPayload = {
        blockedUrl: 'https://evil.com/path?param=value&other=test%20encoded',
        timestamp: new Date().toISOString(),
        redirectChain: [
          'https://short.ly/abc',
          'https://evil.com/path?param=value&other=test%20encoded',
        ],
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      const encrypted = await encryptForensics(payload, publicKey);
      const decrypted = await decryptForensics<ForensicsPayload>(encrypted, privateKey);

      expect(decrypted.blockedUrl).toBe(payload.blockedUrl);
      expect(decrypted.redirectChain).toEqual(payload.redirectChain);
    });

    it('should handle unicode in URLs', async () => {
      const { publicKey, privateKey } = await generateRSAKeyPair();

      const payload: ForensicsPayload = {
        blockedUrl: 'https://evil.com/path?name=%E4%B8%AD%E6%96%87',
        timestamp: new Date().toISOString(),
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      const encrypted = await encryptForensics(payload, publicKey);
      const decrypted = await decryptForensics<ForensicsPayload>(encrypted, privateKey);

      expect(decrypted.blockedUrl).toBe(payload.blockedUrl);
    });
  });

  describe('5. SOC Analyst Data Actionability', () => {
    it('should provide enough context to identify attack source', () => {
      const tabId = 1100;

      // Simulate a typical BEC (Business Email Compromise) attack
      trackRedirect(tabId, 'https://mail.google.com/mail/u/0/#inbox/xyz');
      trackRedirect(tabId, 'https://click.email-marketing.com/track?id=campaign123');
      trackRedirect(tabId, 'https://bit.ly/invoice-payment');
      trackRedirect(tabId, 'https://fake-invoice-portal.com/pay');

      const details = {
        tabId,
        url: 'https://fake-invoice-portal.com/pay',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
        initiator: 'https://mail.google.com',
      };

      const payload = captureForensics(details, 'fake-invoice-portal.com/pay', 'ioc_match');

      // SOC analyst can determine:
      // 1. The attack came via email (Gmail initiator + email marketing tracker)
      // 2. The user clicked a shortened link (bit.ly)
      // 3. The final destination was a fake invoice portal
      expect(payload.initiator).toBe('https://mail.google.com');
      expect(payload.redirectChain!.some(url => url.includes('bit.ly'))).toBe(true);
      expect(payload.redirectChain!.some(url => url.includes('email-marketing'))).toBe(true);
      expect(payload.blockedUrl).toContain('fake-invoice-portal');
    });

    it('should provide data exportable to SIEM (JSON structure)', async () => {
      const { publicKey, privateKey } = await generateRSAKeyPair();

      const payload: ForensicsPayload = {
        blockedUrl: 'https://c2-server.evil/beacon',
        timestamp: '2026-01-09T10:30:00.000Z',
        redirectChain: ['https://compromised-site.com/redirect', 'https://c2-server.evil/beacon'],
        tabId: 123,
        frameId: 0,
        initiator: 'https://internal-app.company.com',
        normalizedUrl: 'c2-server.evil/beacon',
        reason: 'ioc_match',
      };

      const encrypted = await encryptForensics(payload, publicKey);
      const decrypted = await decryptForensics<ForensicsPayload>(encrypted, privateKey);

      // Verify JSON serializable
      const json = JSON.stringify(decrypted);
      expect(json).toBeDefined();

      // Verify parseable
      const parsed = JSON.parse(json);

      // SIEM-friendly fields
      expect(parsed.blockedUrl).toBeDefined();
      expect(parsed.timestamp).toBeDefined();
      expect(parsed.redirectChain).toBeDefined();
      expect(parsed.initiator).toBeDefined();
      expect(parsed.reason).toBeDefined();
    });

    it('should capture subframe blocks (iframes)', () => {
      const details = {
        tabId: 1200,
        url: 'https://malicious-ad.com/iframe-payload.js',
        frameId: 5, // Non-zero = iframe
        timeStamp: Date.now(),
        parentFrameId: 0,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'sub_frame' as const,
        initiator: 'https://news-site.com',
      };

      const payload = captureForensics(details, 'malicious-ad.com/iframe-payload.js', 'ioc_match');

      expect(payload.frameId).toBe(5);
      expect(payload.initiator).toBe('https://news-site.com');

      // SOC analyst can see: legitimate news site loaded malicious ad iframe
    });
  });

  describe('6. Performance Benchmarks', () => {
    it('should capture forensics in under 1ms', () => {
      const tabId = 1300;
      trackRedirect(tabId, 'https://a.com');
      trackRedirect(tabId, 'https://b.com');
      trackRedirect(tabId, 'https://c.com');

      const details = {
        tabId,
        url: 'https://c.com',
        frameId: 0,
        timeStamp: Date.now(),
        parentFrameId: -1,
        processId: 1,
        documentId: 'doc1',
        documentLifecycle: 'active' as const,
        frameType: 'outermost_frame' as const,
      };

      const start = performance.now();
      captureForensics(details, 'c.com', 'ioc_match');
      const elapsed = performance.now() - start;

      expect(elapsed).toBeLessThan(1);
    });

    it('should encrypt forensics in under 50ms', async () => {
      const { publicKey } = await generateRSAKeyPair();

      const payload: ForensicsPayload = {
        blockedUrl: 'https://test.com',
        timestamp: new Date().toISOString(),
        redirectChain: ['https://a.com', 'https://b.com', 'https://test.com'],
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      const start = performance.now();
      await encryptForensics(payload, publicKey);
      const elapsed = performance.now() - start;

      // RSA operations can be slow, but should be under 50ms
      expect(elapsed).toBeLessThan(50);
    });

    it('should decrypt forensics in under 50ms', async () => {
      const { publicKey, privateKey } = await generateRSAKeyPair();

      const payload: ForensicsPayload = {
        blockedUrl: 'https://test.com',
        timestamp: new Date().toISOString(),
        redirectChain: ['https://a.com', 'https://b.com', 'https://test.com'],
        tabId: 1,
        frameId: 0,
        reason: 'ioc_match',
      };

      const encrypted = await encryptForensics(payload, publicKey);

      const start = performance.now();
      await decryptForensics(encrypted, privateKey);
      const elapsed = performance.now() - start;

      expect(elapsed).toBeLessThan(50);
    });
  });
});
