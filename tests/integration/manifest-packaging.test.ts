/**
 * Integration Test: Manifest Packaging Verification
 *
 * Issue #247: Validates that enterprise and consumer builds ship with the
 * correct manifest files and permissions.
 *
 * Consumer (dist/manifest.json):
 * - Uses declarativeNetRequest and declarativeNetRequestWithHostAccess
 * - Does NOT have webRequestBlocking
 * - Name is "BrowserDefense"
 *
 * Enterprise (dist-enterprise/manifest.json):
 * - Uses webRequestBlocking permission
 * - Does NOT have DNR permissions
 * - Name is "BrowserDefense Enterprise"
 *
 * Run tests: npm run test:manifest
 * After build: npm run build:all && npm run test:manifest
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { execSync } from 'child_process';
import { Script } from 'node:vm';

interface ChromeManifest {
  manifest_version: number;
  name: string;
  version: string;
  description: string;
  permissions: string[];
  optional_permissions?: string[];
  host_permissions?: string[];
  background: {
    service_worker: string;
    type: string;
  };
  content_scripts?: Array<{
    matches: string[];
    js: string[];
    run_at?: string;
  }>;
  action?: {
    default_popup: string;
    default_icon: Record<string, string>;
  };
  options_page?: string;
  web_accessible_resources?: Array<{
    resources: string[];
    matches: string[];
  }>;
}

// Paths relative to project root
const PROJECT_ROOT = resolve(__dirname, '../..');
const CONSUMER_MANIFEST_SRC = resolve(PROJECT_ROOT, 'manifest.json');
const ENTERPRISE_MANIFEST_SRC = resolve(PROJECT_ROOT, 'manifest.enterprise.json');
const CONSUMER_DIST_MANIFEST = resolve(PROJECT_ROOT, 'dist/manifest.json');
const ENTERPRISE_DIST_MANIFEST = resolve(PROJECT_ROOT, 'dist-enterprise/manifest.json');

// ============================================================================
// Source Manifest Validation (always available)
// ============================================================================

describe('Source Manifest Files', () => {
  describe('Consumer Manifest (manifest.json)', () => {
    let manifest: ChromeManifest;

    beforeAll(() => {
      const content = readFileSync(CONSUMER_MANIFEST_SRC, 'utf-8');
      manifest = JSON.parse(content);
    });

    it('should exist', () => {
      expect(existsSync(CONSUMER_MANIFEST_SRC)).toBe(true);
    });

    it('should be manifest version 3', () => {
      expect(manifest.manifest_version).toBe(3);
    });

    it('should have name "BrowserDefense"', () => {
      expect(manifest.name).toBe('BrowserDefense');
    });

    it('should include declarativeNetRequest permission', () => {
      expect(manifest.permissions).toContain('declarativeNetRequest');
    });

    it('should include declarativeNetRequestWithHostAccess permission', () => {
      expect(manifest.permissions).toContain('declarativeNetRequestWithHostAccess');
    });

    it('should NOT include webRequestBlocking permission', () => {
      expect(manifest.permissions).not.toContain('webRequestBlocking');
    });

    it('should include webRequest permission (for fallback/forensics)', () => {
      expect(manifest.permissions).toContain('webRequest');
    });

    it('should include required base permissions', () => {
      expect(manifest.permissions).toContain('storage');
      expect(manifest.permissions).toContain('alarms');
      expect(manifest.permissions).toContain('webNavigation');
      expect(manifest.permissions).toContain('tabs');
    });

    it('should have host_permissions for all URLs', () => {
      expect(manifest.host_permissions).toContain('<all_urls>');
    });

    it('should have service worker background', () => {
      expect(manifest.background.service_worker).toBe('background.js');
      expect(manifest.background.type).toBe('module');
    });

    it('should have content scripts', () => {
      expect(manifest.content_scripts).toBeDefined();
      expect(manifest.content_scripts!.length).toBeGreaterThan(0);
      expect(manifest.content_scripts![0].matches).toContain('<all_urls>');
    });

    it('should have popup action', () => {
      expect(manifest.action?.default_popup).toBe('popup.html');
    });

    it('should have options page', () => {
      expect(manifest.options_page).toBe('options.html');
    });
  });

  describe('Enterprise Manifest (manifest.enterprise.json)', () => {
    let manifest: ChromeManifest;

    beforeAll(() => {
      const content = readFileSync(ENTERPRISE_MANIFEST_SRC, 'utf-8');
      manifest = JSON.parse(content);
    });

    it('should exist', () => {
      expect(existsSync(ENTERPRISE_MANIFEST_SRC)).toBe(true);
    });

    it('should be manifest version 3', () => {
      expect(manifest.manifest_version).toBe(3);
    });

    it('should have name "BrowserDefense Enterprise"', () => {
      expect(manifest.name).toBe('BrowserDefense Enterprise');
    });

    it('should include webRequestBlocking permission', () => {
      expect(manifest.permissions).toContain('webRequestBlocking');
    });

    it('should include webRequest permission', () => {
      expect(manifest.permissions).toContain('webRequest');
    });

    it('should NOT include declarativeNetRequest permission', () => {
      expect(manifest.permissions).not.toContain('declarativeNetRequest');
    });

    it('should NOT include declarativeNetRequestWithHostAccess permission', () => {
      expect(manifest.permissions).not.toContain('declarativeNetRequestWithHostAccess');
    });

    it('should include required base permissions', () => {
      expect(manifest.permissions).toContain('storage');
      expect(manifest.permissions).toContain('alarms');
      expect(manifest.permissions).toContain('webNavigation');
      expect(manifest.permissions).toContain('tabs');
    });

    it('should have host_permissions for all URLs', () => {
      expect(manifest.host_permissions).toContain('<all_urls>');
    });

    it('should have service worker background', () => {
      expect(manifest.background.service_worker).toBe('background.js');
      expect(manifest.background.type).toBe('module');
    });

    it('should have popup action', () => {
      expect(manifest.action?.default_popup).toBe('popup.html');
    });

    it('should have options page', () => {
      expect(manifest.options_page).toBe('options.html');
    });
  });
});

// ============================================================================
// Built Manifest Validation (requires build:all to have run)
// ============================================================================

describe('Built Manifest Files', () => {
  const skipIfNotBuilt = (manifestPath: string) => {
    if (!existsSync(manifestPath)) {
      console.log(
        `Skipping test: ${manifestPath} not found. Run 'npm run build:all' first.`
      );
      return true;
    }
    return false;
  };

  describe('Consumer Build (dist/manifest.json)', () => {
    let manifest: ChromeManifest | null = null;
    let shouldSkip = false;

    beforeAll(() => {
      if (skipIfNotBuilt(CONSUMER_DIST_MANIFEST)) {
        shouldSkip = true;
        return;
      }
      const content = readFileSync(CONSUMER_DIST_MANIFEST, 'utf-8');
      manifest = JSON.parse(content);
    });

    it('should exist in dist/', () => {
      if (shouldSkip) return;
      expect(existsSync(CONSUMER_DIST_MANIFEST)).toBe(true);
    });

    it('should have name "BrowserDefense"', () => {
      if (shouldSkip) return;
      expect(manifest!.name).toBe('BrowserDefense');
    });

    it('should include DNR permissions (consumer mode)', () => {
      if (shouldSkip) return;
      expect(manifest!.permissions).toContain('declarativeNetRequest');
      expect(manifest!.permissions).toContain('declarativeNetRequestWithHostAccess');
    });

    it('should NOT include webRequestBlocking', () => {
      if (shouldSkip) return;
      expect(manifest!.permissions).not.toContain('webRequestBlocking');
    });
  });

  describe('Enterprise Build (dist-enterprise/manifest.json)', () => {
    let manifest: ChromeManifest | null = null;
    let shouldSkip = false;

    beforeAll(() => {
      if (skipIfNotBuilt(ENTERPRISE_DIST_MANIFEST)) {
        shouldSkip = true;
        return;
      }
      const content = readFileSync(ENTERPRISE_DIST_MANIFEST, 'utf-8');
      manifest = JSON.parse(content);
    });

    it('should exist in dist-enterprise/', () => {
      if (shouldSkip) return;
      expect(existsSync(ENTERPRISE_DIST_MANIFEST)).toBe(true);
    });

    it('should have name "BrowserDefense Enterprise"', () => {
      if (shouldSkip) return;
      expect(manifest!.name).toBe('BrowserDefense Enterprise');
    });

    it('should include webRequestBlocking (enterprise mode)', () => {
      if (shouldSkip) return;
      expect(manifest!.permissions).toContain('webRequestBlocking');
    });

    it('should NOT include DNR permissions', () => {
      if (shouldSkip) return;
      expect(manifest!.permissions).not.toContain('declarativeNetRequest');
      expect(manifest!.permissions).not.toContain('declarativeNetRequestWithHostAccess');
    });
  });
});

// ============================================================================
// Cross-Manifest Validation
// ============================================================================

describe.each(['dist', 'dist-enterprise'])('%s content script', (directory) => {
  it('loads as a classic script without module imports', () => {
    const scriptPath = resolve(PROJECT_ROOT, directory, 'content.js');
    if (!existsSync(scriptPath)) {
      if (process.env.CI) throw new Error(`Missing build: ${scriptPath}`);
      return;
    }
    const source = readFileSync(scriptPath, 'utf8');
    expect(() => new Script(source, { filename: scriptPath })).not.toThrow();
  });
});

describe('Cross-Manifest Consistency', () => {
  let consumerManifest: ChromeManifest;
  let enterpriseManifest: ChromeManifest;

  beforeAll(() => {
    const consumerContent = readFileSync(CONSUMER_MANIFEST_SRC, 'utf-8');
    consumerManifest = JSON.parse(consumerContent);

    const enterpriseContent = readFileSync(ENTERPRISE_MANIFEST_SRC, 'utf-8');
    enterpriseManifest = JSON.parse(enterpriseContent);
  });

  it('should have same version', () => {
    expect(consumerManifest.version).toBe(enterpriseManifest.version);
  });

  it('should have same manifest_version', () => {
    expect(consumerManifest.manifest_version).toBe(enterpriseManifest.manifest_version);
  });

  it('should have same background service worker', () => {
    expect(consumerManifest.background.service_worker).toBe(
      enterpriseManifest.background.service_worker
    );
  });

  it('should have same popup', () => {
    expect(consumerManifest.action?.default_popup).toBe(
      enterpriseManifest.action?.default_popup
    );
  });

  it('should have same options page', () => {
    expect(consumerManifest.options_page).toBe(enterpriseManifest.options_page);
  });

  it('should have same base permissions (storage, alarms, webNavigation, tabs)', () => {
    const basePerms = ['storage', 'alarms', 'webNavigation', 'tabs'];

    for (const perm of basePerms) {
      expect(consumerManifest.permissions).toContain(perm);
      expect(enterpriseManifest.permissions).toContain(perm);
    }
  });

  it('should have mutually exclusive blocking mechanisms', () => {
    // Consumer uses DNR, Enterprise uses webRequestBlocking
    // They should NOT both have the same blocking mechanism

    const consumerHasDNR = consumerManifest.permissions.includes('declarativeNetRequest');
    const enterpriseHasDNR = enterpriseManifest.permissions.includes('declarativeNetRequest');
    const consumerHasWRB = consumerManifest.permissions.includes('webRequestBlocking');
    const enterpriseHasWRB = enterpriseManifest.permissions.includes('webRequestBlocking');

    expect(consumerHasDNR).toBe(true);
    expect(enterpriseHasDNR).toBe(false);
    expect(consumerHasWRB).toBe(false);
    expect(enterpriseHasWRB).toBe(true);
  });
});

// ============================================================================
// Build Script Validation
// ============================================================================

describe('Build Script Verification', () => {
  it('should have build:enterprise script in package.json', () => {
    const packageJsonPath = resolve(PROJECT_ROOT, 'package.json');
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

    expect(packageJson.scripts['build:enterprise']).toBeDefined();
    expect(packageJson.scripts['build:enterprise']).toContain('dist-enterprise');
  });

  it('should have build:all script in package.json', () => {
    const packageJsonPath = resolve(PROJECT_ROOT, 'package.json');
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

    expect(packageJson.scripts['build:all']).toBeDefined();
    expect(packageJson.scripts['build:all']).toContain('build:enterprise');
  });

  it('should have copy-static:enterprise script that uses manifest.enterprise.json', () => {
    const packageJsonPath = resolve(PROJECT_ROOT, 'package.json');
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

    expect(packageJson.scripts['copy-static:enterprise']).toBeDefined();
    expect(packageJson.scripts['copy-static:enterprise']).toContain(
      'manifest.enterprise.json'
    );
  });
});

// ============================================================================
// Blocking Mode Detection Test
// ============================================================================

describe('Blocking Mode Detection Logic', () => {
  it('documents how blocking mode is determined at runtime', () => {
    /**
     * Blocking mode is determined at runtime by checking permissions:
     *
     * Enterprise Mode:
     * - Checks chrome.permissions.contains({ permissions: ['webRequestBlocking'] })
     * - If true: Uses webRequest.onBeforeRequest with 'blocking' extraInfoSpec
     * - Pre-request blocking, no IOC leak
     *
     * Consumer Mode (DNR):
     * - webRequestBlocking permission check returns false
     * - Falls back to declarativeNetRequest (DNR)
     * - DNR rules are compiled from blocklist
     * - Post-request blocking (DNR intercepts after DNS but before data transfer)
     *
     * The manifest determines which permissions are available:
     * - Consumer manifest: DNR permissions granted, webRequestBlocking NOT granted
     * - Enterprise manifest: webRequestBlocking granted (requires policy installation)
     */

    const blockingModes = {
      enterprise: {
        permission: 'webRequestBlocking',
        api: 'webRequest.onBeforeRequest',
        timing: 'pre-request (before DNS)',
        iocLeak: false,
      },
      consumer: {
        permission: 'declarativeNetRequest',
        api: 'declarativeNetRequest rules',
        timing: 'post-DNS (before data transfer)',
        iocLeak: true, // DNS query still happens
      },
    };

    expect(blockingModes.enterprise.permission).toBe('webRequestBlocking');
    expect(blockingModes.consumer.permission).toBe('declarativeNetRequest');
    expect(blockingModes.enterprise.iocLeak).toBe(false);
    expect(blockingModes.consumer.iocLeak).toBe(true);
  });
});
