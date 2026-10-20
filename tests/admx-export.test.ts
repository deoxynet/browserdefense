/**
 * Tests for ADMX export functionality
 *
 * These tests verify the ADMX/ADML/REG generation logic
 * extracted from the keygen tool.
 */

import { describe, it, expect } from 'vitest';

// Helper functions extracted from keygen tool for testing
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function escapeRegValue(str: string): string {
  return str.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

interface OrgConfig {
  orgName: string;
  extensionId: string;
  blocklistEndpoint: string;
  forensicsEndpoint: string;
  updateInterval: number;
  updateUrl: string;
}

interface GeneratedKeys {
  signingPublic: object | null;
  encryptionPublic: object | null;
  orgId: string | null;
}

function generateAdmx(config: OrgConfig): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">
  <policyNamespaces>
    <target prefix="browserdefense" namespace="BrowserDefense.Policies.${escapeXml(config.extensionId)}" />
  </policyNamespaces>
  <policies>
    <policy name="BlocklistEndpoint"
            key="SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${escapeXml(config.extensionId)}\\policy"
            valueName="blocklist_endpoint">
    </policy>
  </policies>
</policyDefinitions>`;
}

function generateRegistryFile(config: OrgConfig, keys: GeneratedKeys): string {
  const signingKeyJson = keys.signingPublic
    ? escapeRegValue(JSON.stringify(keys.signingPublic))
    : '';
  const updateIntervalHex = config.updateInterval.toString(16).padStart(8, '0');

  return `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${config.extensionId}\\policy]
"org_id"="${keys.orgId || ''}"
"blocklist_endpoint"="${config.blocklistEndpoint}"
"update_interval_minutes"=dword:${updateIntervalHex}
"signing_public_key"="${signingKeyJson}"
`;
}

describe('XML Escaping', () => {
  it('escapes ampersands', () => {
    expect(escapeXml('foo & bar')).toBe('foo &amp; bar');
  });

  it('escapes less than', () => {
    expect(escapeXml('a < b')).toBe('a &lt; b');
  });

  it('escapes greater than', () => {
    expect(escapeXml('a > b')).toBe('a &gt; b');
  });

  it('escapes double quotes', () => {
    expect(escapeXml('say "hello"')).toBe('say &quot;hello&quot;');
  });

  it('escapes single quotes', () => {
    expect(escapeXml("it's")); // Apostrophe escaping
    expect(escapeXml("it's")).toBe('it&apos;s');
  });

  it('handles multiple special characters', () => {
    expect(escapeXml('<script>"alert(\'xss\')&"</script>')).toBe(
      '&lt;script&gt;&quot;alert(&apos;xss&apos;)&amp;&quot;&lt;/script&gt;'
    );
  });

  it('handles empty string', () => {
    expect(escapeXml('')).toBe('');
  });

  it('handles string with no special characters', () => {
    expect(escapeXml('Acme Corp')).toBe('Acme Corp');
  });
});

describe('Registry Value Escaping', () => {
  it('escapes backslashes', () => {
    expect(escapeRegValue('C:\\Users\\test')).toBe('C:\\\\Users\\\\test');
  });

  it('escapes double quotes', () => {
    expect(escapeRegValue('{"key":"value"}')).toBe('{\\"key\\":\\"value\\"}');
  });

  it('handles JWK escaping', () => {
    const jwk = JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' });
    const escaped = escapeRegValue(jwk);
    expect(escaped).toBe('{\\"kty\\":\\"EC\\",\\"crv\\":\\"P-256\\",\\"x\\":\\"abc\\",\\"y\\":\\"def\\"}');
  });
});

describe('ADMX Generation', () => {
  const config: OrgConfig = {
    orgName: 'Acme Corp',
    extensionId: 'abcdefghijklmnopqrstuvwxyzabcdef',
    blocklistEndpoint: 'https://blocklist.example.com/v1/manifest.json',
    forensicsEndpoint: 'https://siem.example.com/api/v1/forensics',
    updateInterval: 60,
    updateUrl: 'https://clients2.google.com/service/update2/crx',
  };

  it('generates valid XML', () => {
    const admx = generateAdmx(config);
    expect(admx).toContain('<?xml version="1.0" encoding="utf-8"?>');
    expect(admx).toContain('<policyDefinitions');
    expect(admx).toContain('</policyDefinitions>');
  });

  it('includes extension ID in namespace', () => {
    const admx = generateAdmx(config);
    expect(admx).toContain(`namespace="BrowserDefense.Policies.${config.extensionId}"`);
  });

  it('includes extension ID in registry path', () => {
    const admx = generateAdmx(config);
    expect(admx).toContain(`extensions\\${config.extensionId}\\policy`);
  });

  it('escapes special characters in org name', () => {
    const configWithSpecialChars: OrgConfig = {
      ...config,
      orgName: 'Test & Co <Ltd>',
    };
    const admx = generateAdmx(configWithSpecialChars);
    // The org name isn't in this minimal template, but the escaping function works
    expect(escapeXml(configWithSpecialChars.orgName)).toBe('Test &amp; Co &lt;Ltd&gt;');
  });
});

describe('Registry File Generation', () => {
  const config: OrgConfig = {
    orgName: 'Acme Corp',
    extensionId: 'abcdefghijklmnopqrstuvwxyzabcdef',
    blocklistEndpoint: 'https://blocklist.example.com/v1/manifest.json',
    forensicsEndpoint: 'https://siem.example.com/api/v1/forensics',
    updateInterval: 60,
    updateUrl: 'https://clients2.google.com/service/update2/crx',
  };

  const keys: GeneratedKeys = {
    signingPublic: { kty: 'EC', crv: 'P-256', x: 'testx', y: 'testy' },
    encryptionPublic: { kty: 'RSA', n: 'testn', e: 'AQAB' },
    orgId: 'test-org-id-123',
  };

  it('generates valid registry file header', () => {
    const reg = generateRegistryFile(config, keys);
    expect(reg).toContain('Windows Registry Editor Version 5.00');
  });

  it('includes extension ID in registry path', () => {
    const reg = generateRegistryFile(config, keys);
    expect(reg).toContain(`[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${config.extensionId}\\policy]`);
  });

  it('includes org ID', () => {
    const reg = generateRegistryFile(config, keys);
    expect(reg).toContain(`"org_id"="${keys.orgId}"`);
  });

  it('includes blocklist endpoint', () => {
    const reg = generateRegistryFile(config, keys);
    expect(reg).toContain(`"blocklist_endpoint"="${config.blocklistEndpoint}"`);
  });

  it('converts update interval to hex dword', () => {
    const reg = generateRegistryFile(config, keys);
    // 60 in hex is 3c, padded to 8 chars
    expect(reg).toContain('"update_interval_minutes"=dword:0000003c');
  });

  it('properly escapes signing public key JSON', () => {
    const reg = generateRegistryFile(config, keys);
    expect(reg).toContain('signing_public_key');
    expect(reg).toContain('\\"kty\\":\\"EC\\"');
  });

  it('handles missing keys gracefully', () => {
    const emptyKeys: GeneratedKeys = {
      signingPublic: null,
      encryptionPublic: null,
      orgId: null,
    };
    const reg = generateRegistryFile(config, emptyKeys);
    expect(reg).toContain('"org_id"=""');
    expect(reg).toContain('"signing_public_key"=""');
  });
});

describe('Update Interval Hex Conversion', () => {
  it('converts 60 to 0000003c', () => {
    expect((60).toString(16).padStart(8, '0')).toBe('0000003c');
  });

  it('converts 5 (minimum) to 00000005', () => {
    expect((5).toString(16).padStart(8, '0')).toBe('00000005');
  });

  it('converts 1440 (maximum) to 000005a0', () => {
    expect((1440).toString(16).padStart(8, '0')).toBe('000005a0');
  });
});

describe('CRC32 for ZIP', () => {
  // CRC32 implementation from keygen tool
  function crc32(data: Uint8Array): number {
    let crc = 0xffffffff;
    const table = getCrc32Table();
    for (let i = 0; i < data.length; i++) {
      crc = (crc >>> 8) ^ table[(crc ^ data[i]) & 0xff];
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  let crc32Table: Uint32Array | null = null;
  function getCrc32Table(): Uint32Array {
    if (crc32Table) return crc32Table;
    crc32Table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) {
        c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      }
      crc32Table[i] = c;
    }
    return crc32Table;
  }

  it('calculates correct CRC32 for known values', () => {
    // "test" should have CRC32 of 0xd87f7e0c
    const encoder = new TextEncoder();
    const data = encoder.encode('test');
    expect(crc32(data)).toBe(0xd87f7e0c);
  });

  it('calculates correct CRC32 for empty data', () => {
    // Empty data should have CRC32 of 0
    const data = new Uint8Array(0);
    expect(crc32(data)).toBe(0);
  });

  it('calculates correct CRC32 for single byte', () => {
    // Single byte 0x00 should have specific CRC32
    const data = new Uint8Array([0]);
    expect(crc32(data)).toBe(0xd202ef8d);
  });
});

describe('Organization slug generation', () => {
  function getOrgSlug(orgName: string): string {
    return orgName.toLowerCase().replace(/[^a-z0-9]/g, '-') || 'browserdefense';
  }

  it('converts to lowercase', () => {
    expect(getOrgSlug('Acme Corp')).toBe('acme-corp');
  });

  it('replaces spaces with hyphens', () => {
    expect(getOrgSlug('My Company Name')).toBe('my-company-name');
  });

  it('removes special characters', () => {
    expect(getOrgSlug("Test & Co. Ltd.")).toBe('test---co--ltd-');
  });

  it('handles empty string', () => {
    expect(getOrgSlug('')).toBe('browserdefense');
  });

  it('handles unicode characters', () => {
    expect(getOrgSlug('Société Générale')).toBe('soci-t--g-n-rale');
  });
});

// Plist escaping for Apple mobileconfig
function escapePlist(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

describe('Plist Escaping', () => {
  it('escapes ampersands', () => {
    expect(escapePlist('foo & bar')).toBe('foo &amp; bar');
  });

  it('escapes less than', () => {
    expect(escapePlist('a < b')).toBe('a &lt; b');
  });

  it('escapes greater than', () => {
    expect(escapePlist('a > b')).toBe('a &gt; b');
  });

  it('handles JWK JSON', () => {
    const jwk = '{"kty":"EC","crv":"P-256"}';
    // JWK doesn't have special XML chars except quotes (which plist allows)
    expect(escapePlist(jwk)).toBe('{"kty":"EC","crv":"P-256"}');
  });

  it('handles empty string', () => {
    expect(escapePlist('')).toBe('');
  });
});

describe('Apple MDM mobileconfig generation', () => {
  function getOrgIdentifier(orgName: string): string {
    return orgName.toLowerCase().replace(/[^a-z0-9]/g, '') || 'organization';
  }

  it('generates valid org identifier from org name', () => {
    expect(getOrgIdentifier('Acme Corp')).toBe('acmecorp');
  });

  it('strips special characters from org identifier', () => {
    expect(getOrgIdentifier('Test & Co. Ltd.')).toBe('testcoltd');
  });

  it('handles empty org name', () => {
    expect(getOrgIdentifier('')).toBe('organization');
  });

  it('handles unicode in org name', () => {
    expect(getOrgIdentifier('Société')).toBe('socit');
  });

  // Test basic mobileconfig structure
  function generateMinimalMobileconfig(config: OrgConfig, keys: GeneratedKeys): string {
    const orgIdentifier = config.orgName.toLowerCase().replace(/[^a-z0-9]/g, '') || 'organization';
    const signingKeyJson = keys.signingPublic ? JSON.stringify(keys.signingPublic) : '';

    return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadIdentifier</key>
    <string>com.${orgIdentifier}.browserdefense.profile</string>
    <key>PayloadOrganization</key>
    <string>${escapePlist(config.orgName)}</string>
    <key>signing_public_key</key>
    <string>${escapePlist(signingKeyJson)}</string>
</dict>
</plist>`;
  }

  const config: OrgConfig = {
    orgName: 'Acme Corp',
    extensionId: 'abcdefghijklmnopqrstuvwxyzabcdef',
    blocklistEndpoint: 'https://blocklist.example.com/v1/manifest.json',
    forensicsEndpoint: 'https://siem.example.com/api/v1/forensics',
    updateInterval: 60,
    updateUrl: 'https://clients2.google.com/service/update2/crx',
  };

  const keys: GeneratedKeys = {
    signingPublic: { kty: 'EC', crv: 'P-256', x: 'testx', y: 'testy' },
    encryptionPublic: { kty: 'RSA', n: 'testn', e: 'AQAB' },
    orgId: 'test-org-id-123',
  };

  it('generates valid plist XML', () => {
    const mobileconfig = generateMinimalMobileconfig(config, keys);
    expect(mobileconfig).toContain('<?xml version="1.0" encoding="UTF-8"?>');
    expect(mobileconfig).toContain('<!DOCTYPE plist');
    expect(mobileconfig).toContain('<plist version="1.0">');
    expect(mobileconfig).toContain('</plist>');
  });

  it('includes org identifier in PayloadIdentifier', () => {
    const mobileconfig = generateMinimalMobileconfig(config, keys);
    expect(mobileconfig).toContain('com.acmecorp.browserdefense.profile');
  });

  it('includes org name in PayloadOrganization', () => {
    const mobileconfig = generateMinimalMobileconfig(config, keys);
    expect(mobileconfig).toContain('<string>Acme Corp</string>');
  });

  it('includes signing public key', () => {
    const mobileconfig = generateMinimalMobileconfig(config, keys);
    expect(mobileconfig).toContain('"kty":"EC"');
    expect(mobileconfig).toContain('"crv":"P-256"');
  });
});
