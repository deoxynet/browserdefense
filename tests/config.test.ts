import { describe, it, expect } from 'vitest';
import { validateConfig, createExampleConfig } from '../src/config/schema';
import { parseConfigJson, exportConfigJson } from '../src/config/loader';

describe('Config Schema Validation', () => {
  describe('validateConfig', () => {
    it('should accept a valid complete configuration', () => {
      const config = createExampleConfig();
      const result = validateConfig(config);

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.config.org_id).toBe('example-org');
        expect(result.config.update_interval_minutes).toBe(60);
      }
    });

    it('should accept config without optional update_interval_minutes', () => {
      const config = createExampleConfig();
      const { update_interval_minutes: _, ...configWithoutInterval } = config;

      const result = validateConfig(configWithoutInterval);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.config.update_interval_minutes).toBeUndefined();
      }
    });

    it('should reject null input', () => {
      const result = validateConfig(null);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Zod reports "expected object, received null"
        expect(result.errors.some((e) => e.toLowerCase().includes('object') || e.includes('null'))).toBe(true);
      }
    });

    it('should reject non-object input', () => {
      const result = validateConfig('not an object');
      expect(result.valid).toBe(false);
    });

    it('should reject array input', () => {
      const result = validateConfig([]);
      expect(result.valid).toBe(false);
    });
  });

  describe('org_id validation', () => {
    it('should reject missing org_id', () => {
      const config = createExampleConfig();
      const { org_id: _, ...configWithoutOrgId } = config;

      const result = validateConfig(configWithoutOrgId);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errors.some((e) => e.includes('org_id'))).toBe(true);
      }
    });

    it('should reject empty org_id', () => {
      const config = { ...createExampleConfig(), org_id: '' };
      const result = validateConfig(config);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errors.some((e) => e.includes('org_id'))).toBe(true);
      }
    });

    it('should reject whitespace-only org_id', () => {
      const config = { ...createExampleConfig(), org_id: '   ' };
      const result = validateConfig(config);

      expect(result.valid).toBe(false);
    });

    it('should trim org_id whitespace', () => {
      const config = { ...createExampleConfig(), org_id: '  acme-corp  ' };
      const result = validateConfig(config);

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.config.org_id).toBe('acme-corp');
      }
    });
  });

  describe('signing_public_key validation', () => {
    it('should reject missing signing_public_key', () => {
      const config = createExampleConfig();
      const { signing_public_key: _, ...configWithoutKey } = config;

      const result = validateConfig(configWithoutKey);
      expect(result.valid).toBe(false);
    });

    it('should accept Ed25519 key (default)', () => {
      const config = createExampleConfig();
      const result = validateConfig(config);

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.config.signing_public_key.kty).toBe('OKP');
        expect(result.config.signing_public_key.crv).toBe('Ed25519');
      }
    });

    it('should accept P-256 key (legacy)', () => {
      const config = createExampleConfig();
      const result = validateConfig({
        ...config,
        signing_public_key: {
          kty: 'EC' as const,
          crv: 'P-256' as const,
          x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
          y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        },
      });

      expect(result.valid).toBe(true);
    });

    it('should reject unsupported key type (RSA)', () => {
      const config = createExampleConfig();
      const result = validateConfig({
        ...config,
        signing_public_key: {
          kty: 'RSA' as const,
          n: 'test',
          e: 'AQAB',
        },
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Zod discriminatedUnion reports "Invalid input" when discriminator doesn't match
        expect(result.errors.some((e) => e.includes('kty') || e.toLowerCase().includes('invalid'))).toBe(true);
      }
    });

    it('should reject unsupported EC curve (P-384)', () => {
      const config = createExampleConfig();
      const result = validateConfig({
        ...config,
        signing_public_key: {
          kty: 'EC' as const,
          crv: 'P-384' as const,
          x: 'test',
          y: 'test',
        },
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Zod literal reports invalid_literal error for crv
        expect(result.errors.some((e) => e.includes('crv') || e.toLowerCase().includes('invalid'))).toBe(true);
      }
    });

    it('should reject Ed25519 key with missing x', () => {
      const config = createExampleConfig();
      const result = validateConfig({
        ...config,
        signing_public_key: {
          kty: 'OKP' as const,
          crv: 'Ed25519' as const,
          // x is missing
        },
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Zod reports "Required" for missing fields
        expect(result.errors.some((e) => e.includes('x') || e.toLowerCase().includes('required'))).toBe(true);
      }
    });

    it('should reject P-256 key with missing x coordinate', () => {
      const config = createExampleConfig();
      const result = validateConfig({
        ...config,
        signing_public_key: {
          kty: 'EC' as const,
          crv: 'P-256' as const,
          y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
          // x is missing
        },
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Zod reports "Required" or the custom message for missing x
        expect(result.errors.some((e) => e.includes('x') || e.toLowerCase().includes('required'))).toBe(true);
      }
    });

    it('should reject P-256 key with missing y coordinate', () => {
      const config = createExampleConfig();
      const result = validateConfig({
        ...config,
        signing_public_key: {
          kty: 'EC' as const,
          crv: 'P-256' as const,
          x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
          // y is missing
        },
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Zod reports "Required" or the custom message for missing y
        expect(result.errors.some((e) => e.includes('y') || e.toLowerCase().includes('required'))).toBe(true);
      }
    });

    it('should reject invalid base64url in x coordinate', () => {
      const config = createExampleConfig();
      const result = validateConfig({
        ...config,
        signing_public_key: {
          kty: 'OKP' as const,
          crv: 'Ed25519' as const,
          x: 'invalid+chars/here==',
        },
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errors.some((e) => e.includes('base64url'))).toBe(true);
      }
    });
  });

  describe('encryption_public_key validation', () => {
    it('should reject missing encryption_public_key', () => {
      const config = createExampleConfig();
      const { encryption_public_key: _, ...configWithoutKey } = config;

      const result = validateConfig(configWithoutKey);
      expect(result.valid).toBe(false);
    });

    it('should reject non-RSA key type', () => {
      const config = createExampleConfig();
      const result = validateConfig({
        ...config,
        encryption_public_key: {
          kty: 'EC' as const,
          n: 'test',
          e: 'AQAB',
        },
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Zod literal reports invalid_literal error for kty
        expect(result.errors.some((e) => e.includes('kty') || e.toLowerCase().includes('invalid'))).toBe(true);
      }
    });

    it('should reject missing modulus', () => {
      const config = createExampleConfig();
      const { n: _, ...keyWithoutN } = config.encryption_public_key;

      const result = validateConfig({
        ...config,
        encryption_public_key: keyWithoutN,
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Zod reports "Required" for missing fields - n is the modulus field
        expect(result.errors.some((e) => e.includes('n') || e.toLowerCase().includes('required'))).toBe(true);
      }
    });

    it('should reject missing exponent', () => {
      const config = createExampleConfig();
      const { e: _, ...keyWithoutE } = config.encryption_public_key;

      const result = validateConfig({
        ...config,
        encryption_public_key: keyWithoutE,
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Zod reports "Required" for missing fields - e is the exponent field
        expect(result.errors.some((e) => e.includes('e') || e.toLowerCase().includes('required'))).toBe(true);
      }
    });

    it('should warn about short RSA modulus', () => {
      const config = createExampleConfig();
      const result = validateConfig({
        ...config,
        encryption_public_key: {
          ...config.encryption_public_key,
          n: 'shortkey',
        },
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errors.some((e) => e.includes('too short'))).toBe(true);
      }
    });
  });

  describe('endpoint validation', () => {
    it('should reject missing blocklist_endpoint', () => {
      const config = createExampleConfig();
      const { blocklist_endpoint: _, ...configWithout } = config;

      const result = validateConfig(configWithout);
      expect(result.valid).toBe(false);
    });

    it('should reject missing forensics_endpoint', () => {
      const config = createExampleConfig();
      const { forensics_endpoint: _, ...configWithout } = config;

      const result = validateConfig(configWithout);
      expect(result.valid).toBe(false);
    });

    it('should reject HTTP endpoints (require HTTPS)', () => {
      const config = {
        ...createExampleConfig(),
        blocklist_endpoint: 'http://insecure.example.com/blocklist',
      };

      const result = validateConfig(config);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errors.some((e) => e.includes('HTTPS'))).toBe(true);
      }
    });

    it('should reject invalid URL format', () => {
      const config = {
        ...createExampleConfig(),
        blocklist_endpoint: 'not-a-url',
      };

      const result = validateConfig(config);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Zod reports "Invalid URL" (capitalized)
        expect(result.errors.some((e) => e.toLowerCase().includes('url') || e.toLowerCase().includes('invalid'))).toBe(
          true
        );
      }
    });

    it('should accept valid HTTPS endpoints', () => {
      const config = createExampleConfig();
      const result = validateConfig(config);

      expect(result.valid).toBe(true);
    });
  });

  describe('update_interval_minutes validation', () => {
    it('should reject zero interval', () => {
      const config = { ...createExampleConfig(), update_interval_minutes: 0 };
      const result = validateConfig(config);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errors.some((e) => e.includes('update_interval_minutes'))).toBe(true);
      }
    });

    it('should reject negative interval', () => {
      const config = { ...createExampleConfig(), update_interval_minutes: -10 };
      const result = validateConfig(config);

      expect(result.valid).toBe(false);
    });

    it('should reject interval > 1440 (24 hours)', () => {
      const config = { ...createExampleConfig(), update_interval_minutes: 1441 };
      const result = validateConfig(config);

      expect(result.valid).toBe(false);
    });

    it('should accept interval = 1440 (24 hours)', () => {
      const config = { ...createExampleConfig(), update_interval_minutes: 1440 };
      const result = validateConfig(config);

      expect(result.valid).toBe(true);
    });

    it('should reject non-integer interval', () => {
      const config = { ...createExampleConfig(), update_interval_minutes: 30.5 };
      const result = validateConfig(config);

      expect(result.valid).toBe(false);
    });
  });

  describe('multiple errors', () => {
    it('should collect all validation errors', () => {
      const config = {
        org_id: '',
        signing_public_key: { kty: 'RSA' },
        encryption_public_key: { kty: 'EC' },
        blocklist_endpoint: 'http://insecure.com',
        forensics_endpoint: 'not-a-url',
      };

      const result = validateConfig(config);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        // Should have errors for: org_id, signing_key, encryption_key, both endpoints
        expect(result.errors.length).toBeGreaterThanOrEqual(5);
      }
    });
  });
});

describe('Config JSON Parsing', () => {
  describe('parseConfigJson', () => {
    it('should parse valid JSON config', () => {
      const config = createExampleConfig();
      const json = JSON.stringify(config);
      const result = parseConfigJson(json);

      expect(result.valid).toBe(true);
    });

    it('should reject invalid JSON syntax', () => {
      const result = parseConfigJson('{ invalid json }');
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.errors[0]).toContain('Invalid JSON');
      }
    });

    it('should reject empty string', () => {
      const result = parseConfigJson('');
      expect(result.valid).toBe(false);
    });

    it('should handle JSON with extra whitespace', () => {
      const config = createExampleConfig();
      const json = JSON.stringify(config, null, 4);
      const result = parseConfigJson(json);

      expect(result.valid).toBe(true);
    });

    it('should reject JSON array', () => {
      const result = parseConfigJson('[]');
      expect(result.valid).toBe(false);
    });

    it('should reject JSON primitive', () => {
      const result = parseConfigJson('"just a string"');
      expect(result.valid).toBe(false);
    });
  });

  describe('exportConfigJson', () => {
    it('should export formatted JSON', () => {
      const config = createExampleConfig();
      const json = exportConfigJson(config);

      expect(json).toContain('\n');
      expect(json).toContain('  ');
    });

    it('should roundtrip correctly', () => {
      const original = createExampleConfig();
      const json = exportConfigJson(original);
      const result = parseConfigJson(json);

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.config.org_id).toBe(original.org_id);
        expect(result.config.blocklist_endpoint).toBe(original.blocklist_endpoint);
      }
    });
  });
});

describe('createExampleConfig', () => {
  it('should create a valid example configuration', () => {
    const config = createExampleConfig();
    const result = validateConfig(config);

    expect(result.valid).toBe(true);
  });

  it('should have all required fields', () => {
    const config = createExampleConfig();

    expect(config.org_id).toBeDefined();
    expect(config.signing_public_key).toBeDefined();
    expect(config.encryption_public_key).toBeDefined();
    expect(config.blocklist_endpoint).toBeDefined();
    expect(config.forensics_endpoint).toBeDefined();
  });
});
