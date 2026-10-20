/**
 * Integration Test: Enterprise Policy Templates Field Validation
 *
 * This test suite validates that all enterprise policy templates include
 * the required config fields defined in src/config/schema.ts.
 *
 * Required fields (from BlockIOCConfig interface):
 * - org_id
 * - signing_public_key
 * - encryption_public_key
 * - blocklist_endpoint
 * - forensics_endpoint
 * - ioc_salt
 *
 * @see docs/Implementation_Review.md
 * @see https://github.com/irdbl/blockioc/issues/254
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Required config fields from src/config/schema.ts
const REQUIRED_CONFIG_FIELDS = [
  'org_id',
  'signing_public_key',
  'encryption_public_key',
  'blocklist_endpoint',
  'forensics_endpoint',
  'ioc_salt',
] as const;

// Template file paths relative to project root
const TEMPLATE_FILES = {
  registry: 'enterprise/registry/BrowserDefense-Sample.reg',
  admx: 'enterprise/admx/BrowserDefense.admx',
  adml: 'enterprise/admx/en-US/BrowserDefense.adml',
  mobileconfig: 'enterprise/macos/BrowserDefense.mobileconfig',
  intuneJson: 'enterprise/intune/BrowserDefense-OMA-URI.json',
  intunePs1: 'enterprise/intune/BrowserDefense-Configuration.ps1',
} as const;

/**
 * Extract config field names from Windows registry (.reg) file
 */
function extractFieldsFromRegistry(content: string): string[] {
  const fields: string[] = [];
  // Match quoted field names like "blocklist_endpoint"="..."
  const regex = /"([a-z_]+)"=/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    fields.push(match[1]);
  }
  return fields;
}

/**
 * Extract config field names from ADMX template
 */
function extractFieldsFromADMX(content: string): string[] {
  const fields: string[] = [];
  // Match valueName="field_name" in policy elements
  const regex = /valueName="([a-z_]+)"/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    fields.push(match[1]);
  }
  return [...new Set(fields)]; // Deduplicate
}

/**
 * Extract config field names from mobileconfig (plist) file
 */
function extractFieldsFromMobileconfig(content: string): string[] {
  const fields: string[] = [];
  // Match <key>field_name</key> patterns for config keys
  const regex = /<key>([a-z_]+)<\/key>/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    // Filter out plist structure keys (PayloadType, etc.)
    if (!match[1].startsWith('Payload') && !match[1].includes('installation')) {
      fields.push(match[1]);
    }
  }
  return [...new Set(fields)];
}

/**
 * Extract config field names from Intune OMA-URI JSON
 */
function extractFieldsFromIntuneJson(content: string): string[] {
  const fields: string[] = [];
  const json = JSON.parse(content);

  for (const setting of json.omaSettings || []) {
    // Extract field name from omaUri path
    const match = setting.omaUri?.match(/policy\/([a-z_]+)$/);
    if (match) {
      fields.push(match[1]);
    }
  }
  return fields;
}

/**
 * Extract config field names from PowerShell script parameters
 */
function extractFieldsFromPowerShell(content: string): string[] {
  const fields: string[] = [];

  // Match Set-ItemProperty calls with field names
  const setItemRegex = /-Name "([a-z_]+)"/g;
  let match;
  while ((match = setItemRegex.exec(content)) !== null) {
    fields.push(match[1]);
  }

  return [...new Set(fields)];
}

describe('Enterprise Policy Templates', () => {
  let templates: Record<keyof typeof TEMPLATE_FILES, string>;

  beforeAll(() => {
    const projectRoot = join(__dirname, '..');
    templates = {} as Record<keyof typeof TEMPLATE_FILES, string>;

    for (const [key, path] of Object.entries(TEMPLATE_FILES)) {
      try {
        templates[key as keyof typeof TEMPLATE_FILES] = readFileSync(
          join(projectRoot, path),
          'utf-8'
        );
      } catch {
        templates[key as keyof typeof TEMPLATE_FILES] = '';
      }
    }
  });

  describe('Windows Registry Template', () => {
    it('should include all required config fields', () => {
      const fields = extractFieldsFromRegistry(templates.registry);

      for (const required of REQUIRED_CONFIG_FIELDS) {
        expect(
          fields,
          `Registry template missing required field: ${required}`
        ).toContain(required);
      }
    });

    it('should use encryption_public_key (not forensics_public_key)', () => {
      expect(templates.registry).toContain('encryption_public_key');
      expect(templates.registry).not.toContain('forensics_public_key');
    });

    it('should mark forensics_endpoint as REQUIRED', () => {
      expect(templates.registry).toMatch(/; Forensics.*\(REQUIRED\)/i);
    });
  });

  describe('ADMX Template', () => {
    it('should include all required config fields', () => {
      const fields = extractFieldsFromADMX(templates.admx);

      for (const required of REQUIRED_CONFIG_FIELDS) {
        expect(
          fields,
          `ADMX template missing required field: ${required}`
        ).toContain(required);
      }
    });

    it('should use encryption_public_key (not forensics_public_key)', () => {
      expect(templates.admx).toContain('encryption_public_key');
      expect(templates.admx).not.toContain('forensics_public_key');
    });

    it('should mark forensics_endpoint as required="true"', () => {
      const forensicsPolicy = templates.admx.match(
        /valueName="forensics_endpoint"[\s\S]*?required="(\w+)"/
      );
      expect(forensicsPolicy?.[1]).toBe('true');
    });

    it('should mark ioc_salt as required="true"', () => {
      const iocSaltPolicy = templates.admx.match(
        /valueName="ioc_salt"[\s\S]*?required="(\w+)"/
      );
      expect(iocSaltPolicy?.[1]).toBe('true');
    });

    it('should mark encryption_public_key as required="true"', () => {
      const encryptionKeyPolicy = templates.admx.match(
        /valueName="encryption_public_key"[\s\S]*?required="(\w+)"/
      );
      expect(encryptionKeyPolicy?.[1]).toBe('true');
    });
  });

  describe('ADML Language File', () => {
    it('should have string definitions for ioc_salt', () => {
      expect(templates.adml).toContain('IocSalt_DisplayName');
      expect(templates.adml).toContain('IocSalt_ExplainText');
    });

    it('should have string definitions for encryption_public_key', () => {
      expect(templates.adml).toContain('EncryptionPublicKey_DisplayName');
      expect(templates.adml).toContain('EncryptionPublicKey_ExplainText');
    });

    it('should have presentation elements for ioc_salt', () => {
      expect(templates.adml).toContain('presentation id="IocSalt"');
      expect(templates.adml).toContain('refId="IocSalt_Value"');
    });

    it('should not reference forensics_public_key', () => {
      expect(templates.adml).not.toContain('ForensicsPublicKey_DisplayName');
      expect(templates.adml).not.toContain('ForensicsPublicKey_Value');
    });
  });

  describe('macOS mobileconfig Template', () => {
    it('should include all required config fields', () => {
      const fields = extractFieldsFromMobileconfig(templates.mobileconfig);

      for (const required of REQUIRED_CONFIG_FIELDS) {
        expect(
          fields,
          `mobileconfig template missing required field: ${required}`
        ).toContain(required);
      }
    });

    it('should use encryption_public_key (not forensics_public_key)', () => {
      expect(templates.mobileconfig).toContain('<key>encryption_public_key</key>');
      expect(templates.mobileconfig).not.toContain('<key>forensics_public_key</key>');
    });

    it('should include ioc_salt field', () => {
      expect(templates.mobileconfig).toContain('<key>ioc_salt</key>');
    });
  });

  describe('Intune OMA-URI JSON Template', () => {
    it('should include all required config fields', () => {
      const fields = extractFieldsFromIntuneJson(templates.intuneJson);

      for (const required of REQUIRED_CONFIG_FIELDS) {
        expect(
          fields,
          `Intune JSON template missing required field: ${required}`
        ).toContain(required);
      }
    });

    it('should use encryption_public_key (not forensics_public_key)', () => {
      expect(templates.intuneJson).toContain('encryption_public_key');
      expect(templates.intuneJson).not.toContain('forensics_public_key');
    });

    it('should include ioc_salt setting', () => {
      expect(templates.intuneJson).toContain('ioc_salt');
    });

    it('should mark required fields in descriptions', () => {
      const json = JSON.parse(templates.intuneJson);
      const iocSaltSetting = json.omaSettings.find((s: { name: string }) =>
        s.name.includes('IOC Salt')
      );
      expect(iocSaltSetting?.description).toContain('REQUIRED');
    });
  });

  describe('Intune PowerShell Script', () => {
    it('should include all required config fields in Set-ItemProperty calls', () => {
      const fields = extractFieldsFromPowerShell(templates.intunePs1);

      for (const required of REQUIRED_CONFIG_FIELDS) {
        expect(
          fields,
          `PowerShell script missing Set-ItemProperty for: ${required}`
        ).toContain(required);
      }
    });

    it('should use encryption_public_key (not forensics_public_key)', () => {
      expect(templates.intunePs1).toContain('"encryption_public_key"');
      expect(templates.intunePs1).not.toContain('"forensics_public_key"');
    });

    it('should have ioc_salt as mandatory parameter', () => {
      expect(templates.intunePs1).toMatch(/\[Parameter\(Mandatory = \$true\)\]\s*\[string\]\$IocSalt/);
    });

    it('should have forensics_endpoint as mandatory parameter', () => {
      expect(templates.intunePs1).toMatch(
        /\[Parameter\(Mandatory = \$true\)\]\s*\[string\]\$ForensicsEndpoint/
      );
    });

    it('should have encryption_public_key as mandatory parameter', () => {
      expect(templates.intunePs1).toMatch(
        /\[Parameter\(Mandatory = \$true\)\]\s*\[string\]\$EncryptionPublicKey/
      );
    });
  });

  describe('Cross-Template Consistency', () => {
    it('all templates should define the same required fields', () => {
      const registryFields = new Set(
        extractFieldsFromRegistry(templates.registry).filter((f) =>
          REQUIRED_CONFIG_FIELDS.includes(f as (typeof REQUIRED_CONFIG_FIELDS)[number])
        )
      );
      const admxFields = new Set(
        extractFieldsFromADMX(templates.admx).filter((f) =>
          REQUIRED_CONFIG_FIELDS.includes(f as (typeof REQUIRED_CONFIG_FIELDS)[number])
        )
      );
      const mobileconfigFields = new Set(
        extractFieldsFromMobileconfig(templates.mobileconfig).filter((f) =>
          REQUIRED_CONFIG_FIELDS.includes(f as (typeof REQUIRED_CONFIG_FIELDS)[number])
        )
      );
      const intuneFields = new Set(
        extractFieldsFromIntuneJson(templates.intuneJson).filter((f) =>
          REQUIRED_CONFIG_FIELDS.includes(f as (typeof REQUIRED_CONFIG_FIELDS)[number])
        )
      );

      // All templates should have the same set of required fields
      expect(registryFields.size).toBe(REQUIRED_CONFIG_FIELDS.length);
      expect(admxFields.size).toBe(REQUIRED_CONFIG_FIELDS.length);
      expect(mobileconfigFields.size).toBe(REQUIRED_CONFIG_FIELDS.length);
      expect(intuneFields.size).toBe(REQUIRED_CONFIG_FIELDS.length);
    });
  });
});

describe('Config Schema Alignment', () => {
  it('documents required fields from BlockIOCConfig interface', () => {
    // This test documents the source of truth for required fields
    // See: src/config/schema.ts:70-87
    const schemaRequiredFields = {
      org_id: 'Organization identifier',
      signing_public_key: 'Ed25519/P-256 public key for signature verification',
      encryption_public_key: 'RSA-OAEP public key for forensics encryption',
      blocklist_endpoint: 'URL for blocklist updates',
      forensics_endpoint: 'URL for encrypted forensics uploads',
      ioc_salt: 'Salt for IOC hashing (must match CLI)',
    };

    expect(Object.keys(schemaRequiredFields)).toEqual(
      expect.arrayContaining(REQUIRED_CONFIG_FIELDS as unknown as string[])
    );
  });

  it('validates field naming conventions', () => {
    // Ensure we use consistent snake_case naming
    for (const field of REQUIRED_CONFIG_FIELDS) {
      expect(field).toMatch(/^[a-z]+(_[a-z]+)*$/);
    }
  });
});
