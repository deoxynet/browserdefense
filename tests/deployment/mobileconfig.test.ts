/**
 * Apple mobileconfig Validation Tests
 *
 * Tests that generated mobileconfig files are valid plist and contain required keys.
 */

import { describe, it, expect } from 'vitest';
import plist from 'plist';
import { generateMobileconfig } from '../../src/deployment/mobileconfig.js';
import { testConfig, testConfigWithSpecialChars } from './fixtures.js';

describe('mobileconfig Generator', () => {
  describe('Plist Validity', () => {
    it('generates valid plist', () => {
      const config = generateMobileconfig(testConfig);
      expect(() => plist.parse(config)).not.toThrow();
    });

    it('handles special characters in org name', () => {
      const config = generateMobileconfig(testConfigWithSpecialChars);
      expect(() => plist.parse(config)).not.toThrow();
    });

    it('parses to an object', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config);
      expect(typeof parsed).toBe('object');
    });
  });

  describe('Required Configuration Profile Keys', () => {
    it('has PayloadType = Configuration', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;
      expect(parsed.PayloadType).toBe('Configuration');
    });

    it('has PayloadIdentifier', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;
      expect(parsed.PayloadIdentifier).toMatch(/^com\.browserdefense\./);
    });

    it('has PayloadUUID', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;
      expect(parsed.PayloadUUID).toMatch(/^[0-9A-F-]{36}$/i);
    });

    it('has PayloadVersion = 1', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;
      expect(parsed.PayloadVersion).toBe(1);
    });

    it('has PayloadContent array', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;
      expect(Array.isArray(parsed.PayloadContent)).toBe(true);
    });

    it('has PayloadDisplayName', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;
      expect(parsed.PayloadDisplayName).toBeDefined();
    });

    it('has PayloadScope = System', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;
      expect(parsed.PayloadScope).toBe('System');
    });
  });

  describe('Chrome Extension Payload', () => {
    it('contains Chrome ExtensionSettings payload', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;

      const chromePayload = parsed.PayloadContent.find(
        (p: any) => p.PayloadType === 'com.google.Chrome'
      );
      expect(chromePayload).toBeDefined();
      expect(chromePayload.ExtensionSettings).toBeDefined();
    });

    it('configures force_installed mode', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;

      const chromePayload = parsed.PayloadContent.find(
        (p: any) => p.PayloadType === 'com.google.Chrome'
      );
      const extensionConfig = chromePayload.ExtensionSettings[testConfig.extensionId];
      expect(extensionConfig.installation_mode).toBe('force_installed');
    });

    it('contains extension policy payload', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;

      const policyPayload = parsed.PayloadContent.find(
        (p: any) => p.PayloadType === `com.google.Chrome.extensions.${testConfig.extensionId}`
      );
      expect(policyPayload).toBeDefined();
    });
  });

  describe('Pre-filled Values', () => {
    it('includes blocklist endpoint', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;

      const policyPayload = parsed.PayloadContent.find(
        (p: any) => p.PayloadType === `com.google.Chrome.extensions.${testConfig.extensionId}`
      );
      expect(policyPayload.blocklist_endpoint).toBe(testConfig.blocklistEndpoint);
    });

    it('includes forensics endpoint', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;

      const policyPayload = parsed.PayloadContent.find(
        (p: any) => p.PayloadType === `com.google.Chrome.extensions.${testConfig.extensionId}`
      );
      expect(policyPayload.forensics_endpoint).toBe(testConfig.forensicsEndpoint);
    });

    it('includes IOC salt', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;

      const policyPayload = parsed.PayloadContent.find(
        (p: any) => p.PayloadType === `com.google.Chrome.extensions.${testConfig.extensionId}`
      );
      expect(policyPayload.ioc_salt).toBe(testConfig.iocSalt);
    });

    it('includes signing public key as JSON string', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;

      const policyPayload = parsed.PayloadContent.find(
        (p: any) => p.PayloadType === `com.google.Chrome.extensions.${testConfig.extensionId}`
      );
      const keyJson = JSON.parse(policyPayload.signing_public_key);
      expect(keyJson.kty).toBe('EC');
      expect(keyJson.crv).toBe('P-256');
    });

    it('includes encryption public key as JSON string', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;

      const policyPayload = parsed.PayloadContent.find(
        (p: any) => p.PayloadType === `com.google.Chrome.extensions.${testConfig.extensionId}`
      );
      const keyJson = JSON.parse(policyPayload.encryption_public_key);
      expect(keyJson.kty).toBe('RSA');
    });

    it('includes update interval', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;

      const policyPayload = parsed.PayloadContent.find(
        (p: any) => p.PayloadType === `com.google.Chrome.extensions.${testConfig.extensionId}`
      );
      expect(policyPayload.update_interval_minutes).toBe(testConfig.updateIntervalMinutes);
    });
  });

  describe('Payload UUIDs', () => {
    it('generates unique UUIDs for each payload', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;

      const uuids = [
        parsed.PayloadUUID,
        ...parsed.PayloadContent.map((p: any) => p.PayloadUUID),
      ];

      const uniqueUuids = new Set(uuids);
      expect(uniqueUuids.size).toBe(uuids.length);
    });

    it('generates different UUIDs on each call', () => {
      const config1 = generateMobileconfig(testConfig);
      const config2 = generateMobileconfig(testConfig);

      const parsed1 = plist.parse(config1) as any;
      const parsed2 = plist.parse(config2) as any;

      expect(parsed1.PayloadUUID).not.toBe(parsed2.PayloadUUID);
    });
  });

  describe('Org-specific Identifiers', () => {
    it('includes org slug in PayloadIdentifier', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;
      expect(parsed.PayloadIdentifier).toContain(testConfig.orgSlug);
    });

    it('includes org display name in PayloadDisplayName', () => {
      const config = generateMobileconfig(testConfig);
      const parsed = plist.parse(config) as any;
      expect(parsed.PayloadDisplayName).toContain(testConfig.orgDisplayName);
    });
  });
});
