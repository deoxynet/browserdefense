/**
 * Apple mobileconfig Generator for Jamf/MDM
 *
 * Generates pre-configured .mobileconfig profiles with org-specific values.
 */

import type { DeploymentConfig } from './types.js';

/**
 * Generate a UUID v4 (for payload identifiers)
 */
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16).toUpperCase();
  });
}

function escapeXml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

/**
 * Generate Apple mobileconfig profile with org-specific configuration
 */
export function generateMobileconfig(config: DeploymentConfig): string {
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

  // Generate unique UUIDs for each payload
  const profileUUID = generateUUID();
  const extensionSettingsUUID = generateUUID();
  const extensionPolicyUUID = generateUUID();

  const signingKeyJson = JSON.stringify(signingPublicKey);
  const encryptionKeyJson = JSON.stringify(encryptionPublicKey);

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.google.Chrome</string>
            <key>PayloadIdentifier</key>
            <string>com.browserdefense.${escapeXml(orgSlug)}.chrome.extensionsettings</string>
            <key>PayloadUUID</key>
            <string>${extensionSettingsUUID}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>BrowserDefense Extension Installation</string>
            <key>PayloadDescription</key>
            <string>Force-installs BrowserDefense Chrome extension for ${escapeXml(orgDisplayName)}</string>
            <key>ExtensionSettings</key>
            <dict>
                <key>${escapeXml(extensionId)}</key>
                <dict>
                    <key>installation_mode</key>
                    <string>force_installed</string>
                    <key>update_url</key>
                    <string>https://clients2.google.com/service/update2/crx</string>
                    <key>toolbar_pin</key>
                    <string>force_pinned</string>
                </dict>
            </dict>
        </dict>

        <dict>
            <key>PayloadType</key>
            <string>com.google.Chrome.extensions.${escapeXml(extensionId)}</string>
            <key>PayloadIdentifier</key>
            <string>com.browserdefense.${escapeXml(orgSlug)}.chrome.policy</string>
            <key>PayloadUUID</key>
            <string>${extensionPolicyUUID}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>BrowserDefense Extension Configuration</string>
            <key>PayloadDescription</key>
            <string>Configures BrowserDefense extension for ${escapeXml(orgDisplayName)}</string>

            <key>blocklist_endpoint</key>
            <string>${escapeXml(blocklistEndpoint)}</string>

            <key>forensics_endpoint</key>
            <string>${escapeXml(forensicsEndpoint)}</string>

            <key>ioc_salt</key>
            <string>${escapeXml(iocSalt)}</string>

            <key>update_interval_minutes</key>
            <integer>${updateIntervalMinutes}</integer>

            <key>signing_public_key</key>
            <string>${escapeXml(signingKeyJson)}</string>

            <key>encryption_public_key</key>
            <string>${escapeXml(encryptionKeyJson)}</string>

            <key>enable_debug_logging</key>
            <${enableDebugLogging ? 'true' : 'false'}/>
        </dict>
    </array>

    <key>PayloadDisplayName</key>
    <string>BrowserDefense - ${escapeXml(orgDisplayName)}</string>
    <key>PayloadDescription</key>
    <string>Deploys and configures BrowserDefense browser-based IOC blocking extension for ${escapeXml(orgDisplayName)}</string>
    <key>PayloadIdentifier</key>
    <string>com.browserdefense.${escapeXml(orgSlug)}.profile</string>
    <key>PayloadOrganization</key>
    <string>${escapeXml(orgDisplayName)}</string>
    <key>PayloadRemovalDisallowed</key>
    <true/>
    <key>PayloadScope</key>
    <string>System</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${profileUUID}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;
}
