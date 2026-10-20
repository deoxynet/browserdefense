/**
 * Intune JSON Configuration Validation Tests
 *
 * Tests that generated Intune configs are valid JSON and contain required fields.
 */

import { describe, it, expect } from 'vitest';
import Ajv from 'ajv';
import { generateIntuneConfig, generateRawConfig } from '../../src/deployment/intune.js';
import { testConfig, testConfigWithSpecialChars } from './fixtures.js';

/**
 * JSON Schema for Intune Windows 10 Custom Configuration
 */
const intuneSchema = {
  type: 'object',
  required: ['@odata.type', 'displayName', 'description', 'omaSettings'],
  properties: {
    '@odata.type': {
      const: '#microsoft.graph.windows10CustomConfiguration',
    },
    displayName: { type: 'string', minLength: 1 },
    description: { type: 'string' },
    omaSettings: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        required: ['@odata.type', 'displayName', 'omaUri'],
        properties: {
          '@odata.type': { type: 'string' },
          displayName: { type: 'string' },
          description: { type: 'string' },
          omaUri: { type: 'string' },
          value: {},
        },
      },
    },
  },
};

/**
 * JSON Schema for raw config (RMM tools)
 */
const rawConfigSchema = {
  type: 'object',
  required: [
    'extension_id',
    'blocklist_endpoint',
    'forensics_endpoint',
    'ioc_salt',
    'signing_public_key',
    'encryption_public_key',
  ],
  properties: {
    extension_id: { type: 'string', minLength: 1 },
    blocklist_endpoint: { type: 'string', format: 'uri' },
    forensics_endpoint: { type: 'string', format: 'uri' },
    ioc_salt: { type: 'string', minLength: 32 },
    update_interval_minutes: { type: 'number', minimum: 5, maximum: 1440 },
    signing_public_key: { type: 'object' },
    encryption_public_key: { type: 'object' },
    enable_debug_logging: { type: 'boolean' },
  },
};

const ajv = new Ajv({ formats: { uri: true } });

describe('Intune Config Generator', () => {
  describe('JSON Validity', () => {
    it('generates valid JSON', () => {
      const config = generateIntuneConfig(testConfig);
      expect(() => JSON.parse(config)).not.toThrow();
    });

    it('handles special characters in org name', () => {
      const config = generateIntuneConfig(testConfigWithSpecialChars);
      expect(() => JSON.parse(config)).not.toThrow();
    });
  });

  describe('Schema Validation', () => {
    it('validates against Intune schema', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      const validate = ajv.compile(intuneSchema);
      const valid = validate(config);
      if (!valid) {
        console.error('Validation errors:', validate.errors);
      }
      expect(valid).toBe(true);
    });

    it('has correct @odata.type', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      expect(config['@odata.type']).toBe('#microsoft.graph.windows10CustomConfiguration');
    });
  });

  describe('Required OMA Settings', () => {
    it('includes ExtensionSettings', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      const extensionSettings = config.omaSettings.find(
        (s: any) => s.displayName === 'Extension Settings'
      );
      expect(extensionSettings).toBeDefined();
    });

    it('includes blocklist endpoint setting', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      const setting = config.omaSettings.find(
        (s: any) => s.displayName === 'Blocklist Endpoint'
      );
      expect(setting).toBeDefined();
      expect(setting.value).toBe(testConfig.blocklistEndpoint);
    });

    it('includes forensics endpoint setting', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      const setting = config.omaSettings.find(
        (s: any) => s.displayName === 'Forensics Endpoint'
      );
      expect(setting).toBeDefined();
      expect(setting.value).toBe(testConfig.forensicsEndpoint);
    });

    it('includes IOC salt setting', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      const setting = config.omaSettings.find(
        (s: any) => s.displayName === 'IOC Salt'
      );
      expect(setting).toBeDefined();
      expect(setting.value).toBe(testConfig.iocSalt);
    });

    it('includes signing public key setting', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      const setting = config.omaSettings.find(
        (s: any) => s.displayName === 'Signing Public Key'
      );
      expect(setting).toBeDefined();
      const keyJson = JSON.parse(setting.value);
      expect(keyJson.kty).toBe('EC');
    });

    it('includes encryption public key setting', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      const setting = config.omaSettings.find(
        (s: any) => s.displayName === 'Encryption Public Key'
      );
      expect(setting).toBeDefined();
      const keyJson = JSON.parse(setting.value);
      expect(keyJson.kty).toBe('RSA');
    });

    it('includes update interval setting', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      const setting = config.omaSettings.find(
        (s: any) => s.displayName === 'Update Interval'
      );
      expect(setting).toBeDefined();
      expect(setting.value).toBe(testConfig.updateIntervalMinutes);
    });
  });

  describe('OMA-URI Paths', () => {
    it('uses correct extension ID in OMA-URI paths', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      const settingsWithExtId = config.omaSettings.filter(
        (s: any) => s.omaUri.includes(testConfig.extensionId)
      );
      // All settings except ExtensionSettings should have extension ID in path
      expect(settingsWithExtId.length).toBeGreaterThan(5);
    });
  });

  describe('Org-specific Values', () => {
    it('includes org name in displayName', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      expect(config.displayName).toContain(testConfig.orgDisplayName);
    });

    it('includes org name in description', () => {
      const config = JSON.parse(generateIntuneConfig(testConfig));
      expect(config.description).toContain(testConfig.orgDisplayName);
    });
  });
});

describe('Raw Config Generator', () => {
  describe('JSON Validity', () => {
    it('generates valid JSON', () => {
      const config = generateRawConfig(testConfig);
      expect(() => JSON.parse(config)).not.toThrow();
    });
  });

  describe('Schema Validation', () => {
    it('validates against raw config schema', () => {
      const config = JSON.parse(generateRawConfig(testConfig));
      const validate = ajv.compile(rawConfigSchema);
      const valid = validate(config);
      if (!valid) {
        console.error('Validation errors:', validate.errors);
      }
      expect(valid).toBe(true);
    });
  });

  describe('Required Fields', () => {
    it('includes all required fields', () => {
      const config = JSON.parse(generateRawConfig(testConfig));
      expect(config.extension_id).toBe(testConfig.extensionId);
      expect(config.blocklist_endpoint).toBe(testConfig.blocklistEndpoint);
      expect(config.forensics_endpoint).toBe(testConfig.forensicsEndpoint);
      expect(config.ioc_salt).toBe(testConfig.iocSalt);
      expect(config.signing_public_key).toEqual(testConfig.signingPublicKey);
      expect(config.encryption_public_key).toEqual(testConfig.encryptionPublicKey);
    });

    it('includes optional fields with defaults', () => {
      const config = JSON.parse(generateRawConfig(testConfig));
      expect(config.update_interval_minutes).toBe(60);
      expect(config.enable_debug_logging).toBe(false);
    });
  });
});
