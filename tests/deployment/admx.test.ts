/**
 * ADMX/ADML Validation Tests
 *
 * Tests that generated ADMX/ADML files are valid XML and contain required elements.
 */

import { describe, it, expect } from 'vitest';
import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { generateADMX, generateADML, generateADMXBundle } from '../../src/deployment/admx.js';
import { testConfig, testConfigWithSpecialChars } from './fixtures.js';

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
});

describe('ADMX Generator', () => {
  describe('XML Validity', () => {
    it('generates valid XML', () => {
      const admx = generateADMX(testConfig);
      const result = XMLValidator.validate(admx);
      expect(result).toBe(true);
    });

    it('parses without errors', () => {
      const admx = generateADMX(testConfig);
      expect(() => parser.parse(admx)).not.toThrow();
    });

    it('handles special characters in org name', () => {
      const admx = generateADMX(testConfigWithSpecialChars);
      const result = XMLValidator.validate(admx);
      expect(result).toBe(true);
    });
  });

  describe('Required Elements', () => {
    it('has policyDefinitions root element', () => {
      const admx = generateADMX(testConfig);
      const parsed = parser.parse(admx);
      expect(parsed.policyDefinitions).toBeDefined();
    });

    it('has correct namespace', () => {
      const admx = generateADMX(testConfig);
      const parsed = parser.parse(admx);
      expect(parsed.policyDefinitions['@_xmlns']).toBe(
        'http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions'
      );
    });

    it('has policyNamespaces section', () => {
      const admx = generateADMX(testConfig);
      const parsed = parser.parse(admx);
      expect(parsed.policyDefinitions.policyNamespaces).toBeDefined();
      expect(parsed.policyDefinitions.policyNamespaces.target).toBeDefined();
    });

    it('has categories section', () => {
      const admx = generateADMX(testConfig);
      const parsed = parser.parse(admx);
      expect(parsed.policyDefinitions.categories).toBeDefined();
    });

    it('has policies section', () => {
      const admx = generateADMX(testConfig);
      const parsed = parser.parse(admx);
      expect(parsed.policyDefinitions.policies).toBeDefined();
    });

    it('includes required policies', () => {
      const admx = generateADMX(testConfig);
      const parsed = parser.parse(admx);
      const policies = parsed.policyDefinitions.policies.policy;

      const policyNames = policies.map((p: any) => p['@_name']);
      expect(policyNames).toContain('BlocklistEndpoint');
      expect(policyNames).toContain('ForensicsEndpoint');
      expect(policyNames).toContain('SigningPublicKey');
      expect(policyNames).toContain('EncryptionPublicKey');
      expect(policyNames).toContain('IocSalt');
      expect(policyNames).toContain('UpdateInterval');
    });
  });

  describe('Extension ID Embedding', () => {
    it('embeds extension ID in registry path', () => {
      const admx = generateADMX(testConfig);
      expect(admx).toContain(testConfig.extensionId);
    });
  });
});

describe('ADML Generator', () => {
  describe('XML Validity', () => {
    it('generates valid XML', () => {
      const adml = generateADML(testConfig);
      const result = XMLValidator.validate(adml);
      expect(result).toBe(true);
    });

    it('parses without errors', () => {
      const adml = generateADML(testConfig);
      expect(() => parser.parse(adml)).not.toThrow();
    });

    it('handles special characters in org name', () => {
      const adml = generateADML(testConfigWithSpecialChars);
      const result = XMLValidator.validate(adml);
      expect(result).toBe(true);
    });
  });

  describe('Required Elements', () => {
    it('has policyDefinitionResources root element', () => {
      const adml = generateADML(testConfig);
      const parsed = parser.parse(adml);
      expect(parsed.policyDefinitionResources).toBeDefined();
    });

    it('has stringTable section', () => {
      const adml = generateADML(testConfig);
      const parsed = parser.parse(adml);
      expect(parsed.policyDefinitionResources.resources.stringTable).toBeDefined();
    });

    it('has presentationTable section', () => {
      const adml = generateADML(testConfig);
      const parsed = parser.parse(adml);
      expect(parsed.policyDefinitionResources.resources.presentationTable).toBeDefined();
    });
  });

  describe('Pre-filled Values', () => {
    it('includes blocklist endpoint', () => {
      const adml = generateADML(testConfig);
      expect(adml).toContain(testConfig.blocklistEndpoint);
    });

    it('includes forensics endpoint', () => {
      const adml = generateADML(testConfig);
      expect(adml).toContain(testConfig.forensicsEndpoint);
    });

    it('includes IOC salt', () => {
      const adml = generateADML(testConfig);
      expect(adml).toContain(testConfig.iocSalt);
    });

    it('includes signing public key as JSON', () => {
      const adml = generateADML(testConfig);
      // Key should be embedded (may be escaped)
      expect(adml).toContain('P-256');
      expect(adml).toContain('EC');
    });

    it('includes encryption public key as JSON', () => {
      const adml = generateADML(testConfig);
      expect(adml).toContain('RSA');
    });

    it('includes org display name', () => {
      const adml = generateADML(testConfig);
      expect(adml).toContain(testConfig.orgDisplayName);
    });
  });
});

describe('ADMX Bundle Generator', () => {
  it('returns both admx and adml', () => {
    const bundle = generateADMXBundle(testConfig);
    expect(bundle.admx).toBeDefined();
    expect(bundle.adml).toBeDefined();
  });

  it('both files are valid XML', () => {
    const bundle = generateADMXBundle(testConfig);
    expect(XMLValidator.validate(bundle.admx)).toBe(true);
    expect(XMLValidator.validate(bundle.adml)).toBe(true);
  });
});
