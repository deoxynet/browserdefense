/**
 * Intune JSON Configuration Generator
 *
 * Generates OMA-URI configuration profiles for Microsoft Intune.
 */

import type { DeploymentConfig } from './types.js';

/**
 * Single OMA-URI setting
 */
interface OmaSetting {
  '@odata.type': string;
  displayName: string;
  description: string;
  omaUri: string;
  value: string | number | boolean;
}

/**
 * Intune Windows 10 Custom Configuration Profile
 */
interface IntuneConfig {
  '@odata.type': '#microsoft.graph.windows10CustomConfiguration';
  displayName: string;
  description: string;
  omaSettings: OmaSetting[];
}

/**
 * Generate Intune JSON configuration with org-specific values
 */
export function generateIntuneConfig(config: DeploymentConfig): string {
  const {
    orgSlug,
    extensionId,
    signingPublicKey,
    encryptionPublicKey,
    iocSalt,
    blocklistEndpoint,
    forensicsEndpoint,
    updateIntervalMinutes = 60,
    orgDisplayName = orgSlug,
    enableDebugLogging = false,
  } = config;

  const basePath = `./Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/ExtensionSettings`;
  const _policyPath = `SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${extensionId}\\policy`;

  const intuneConfig: IntuneConfig = {
    '@odata.type': '#microsoft.graph.windows10CustomConfiguration',
    displayName: `BrowserDefense - ${orgDisplayName}`,
    description: `BrowserDefense Chrome extension configuration for ${orgDisplayName}`,
    omaSettings: [
      {
        '@odata.type': '#microsoft.graph.omaSettingString',
        displayName: 'Extension Settings',
        description: 'Force-install BrowserDefense extension',
        omaUri: basePath,
        value: JSON.stringify({
          [extensionId]: {
            installation_mode: 'force_installed',
            update_url: 'https://clients2.google.com/service/update2/crx',
            toolbar_pin: 'force_pinned',
          },
        }),
      },
      {
        '@odata.type': '#microsoft.graph.omaSettingString',
        displayName: 'Blocklist Endpoint',
        description: 'URL for blocklist updates',
        omaUri: `./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/${extensionId}~blocklist_endpoint`,
        value: blocklistEndpoint,
      },
      {
        '@odata.type': '#microsoft.graph.omaSettingString',
        displayName: 'Forensics Endpoint',
        description: 'URL for encrypted forensics uploads',
        omaUri: `./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/${extensionId}~forensics_endpoint`,
        value: forensicsEndpoint,
      },
      {
        '@odata.type': '#microsoft.graph.omaSettingString',
        displayName: 'IOC Salt',
        description: 'Salt for IOC hashing',
        omaUri: `./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/${extensionId}~ioc_salt`,
        value: iocSalt,
      },
      {
        '@odata.type': '#microsoft.graph.omaSettingInteger',
        displayName: 'Update Interval',
        description: 'Blocklist update interval in minutes',
        omaUri: `./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/${extensionId}~update_interval_minutes`,
        value: updateIntervalMinutes,
      },
      {
        '@odata.type': '#microsoft.graph.omaSettingString',
        displayName: 'Signing Public Key',
        description: 'P-256 ECDSA public key for blocklist signature verification (JWK)',
        omaUri: `./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/${extensionId}~signing_public_key`,
        value: JSON.stringify(signingPublicKey),
      },
      {
        '@odata.type': '#microsoft.graph.omaSettingString',
        displayName: 'Encryption Public Key',
        description: 'RSA-OAEP public key for forensics encryption (JWK)',
        omaUri: `./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/${extensionId}~encryption_public_key`,
        value: JSON.stringify(encryptionPublicKey),
      },
      {
        '@odata.type': '#microsoft.graph.omaSettingBoolean',
        displayName: 'Enable Debug Logging',
        description: 'Enable verbose debug logging',
        omaUri: `./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/${extensionId}~enable_debug_logging`,
        value: enableDebugLogging,
      },
    ],
  };

  return JSON.stringify(intuneConfig, null, 2);
}

/**
 * Generate a simpler JSON config (for manual deployment / RMM tools)
 */
export function generateRawConfig(config: DeploymentConfig): string {
  const {
    extensionId,
    signingPublicKey,
    encryptionPublicKey,
    iocSalt,
    blocklistEndpoint,
    forensicsEndpoint,
    updateIntervalMinutes = 60,
    enableDebugLogging = false,
  } = config;

  return JSON.stringify({
    extension_id: extensionId,
    blocklist_endpoint: blocklistEndpoint,
    forensics_endpoint: forensicsEndpoint,
    ioc_salt: iocSalt,
    update_interval_minutes: updateIntervalMinutes,
    signing_public_key: signingPublicKey,
    encryption_public_key: encryptionPublicKey,
    enable_debug_logging: enableDebugLogging,
  }, null, 2);
}
