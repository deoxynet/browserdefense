/**
 * ADMX/ADML Generator for Windows Group Policy
 *
 * Generates pre-configured ADMX templates with org-specific values embedded.
 */

import type { DeploymentConfig, ADMXResult } from './types.js';

const ADMX_NAMESPACE = 'http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions';

/**
 * Generate ADMX template with org-specific configuration
 */
export function generateADMX(config: DeploymentConfig): string {
  const { extensionId } = config;

  return `<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   revision="1.0"
                   schemaVersion="1.0"
                   xmlns="${ADMX_NAMESPACE}">

  <policyNamespaces>
    <target prefix="browserdefense" namespace="BrowserDefense.Policies" />
    <using prefix="chrome" namespace="Google.Policies.Chrome" />
  </policyNamespaces>

  <resources minRequiredRevision="1.0" />

  <supportedOn>
    <definitions>
      <definition name="SUPPORTED_WIN7" displayName="$(string.SUPPORTED_WIN7)"/>
    </definitions>
  </supportedOn>

  <categories>
    <category name="BrowserDefense" displayName="$(string.BrowserDefense_Category)">
      <parentCategory ref="chrome:Cat_Google" />
    </category>
    <category name="BrowserDefense_Settings" displayName="$(string.BrowserDefense_Settings_Category)">
      <parentCategory ref="BrowserDefense" />
    </category>
    <category name="BrowserDefense_Security" displayName="$(string.BrowserDefense_Security_Category)">
      <parentCategory ref="BrowserDefense" />
    </category>
  </categories>

  <policies>
    <policy name="BlocklistEndpoint"
            class="Machine"
            displayName="$(string.BlocklistEndpoint_DisplayName)"
            explainText="$(string.BlocklistEndpoint_ExplainText)"
            key="SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${extensionId}\\policy"
            valueName="blocklist_endpoint">
      <parentCategory ref="BrowserDefense_Settings" />
      <supportedOn ref="SUPPORTED_WIN7" />
      <elements>
        <text id="BlocklistEndpoint_Value" valueName="blocklist_endpoint" required="true" />
      </elements>
    </policy>

    <policy name="ForensicsEndpoint"
            class="Machine"
            displayName="$(string.ForensicsEndpoint_DisplayName)"
            explainText="$(string.ForensicsEndpoint_ExplainText)"
            key="SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${extensionId}\\policy"
            valueName="forensics_endpoint">
      <parentCategory ref="BrowserDefense_Settings" />
      <supportedOn ref="SUPPORTED_WIN7" />
      <elements>
        <text id="ForensicsEndpoint_Value" valueName="forensics_endpoint" required="true" />
      </elements>
    </policy>

    <policy name="IocSalt"
            class="Machine"
            displayName="$(string.IocSalt_DisplayName)"
            explainText="$(string.IocSalt_ExplainText)"
            key="SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${extensionId}\\policy"
            valueName="ioc_salt">
      <parentCategory ref="BrowserDefense_Security" />
      <supportedOn ref="SUPPORTED_WIN7" />
      <elements>
        <text id="IocSalt_Value" valueName="ioc_salt" required="true" />
      </elements>
    </policy>

    <policy name="UpdateInterval"
            class="Machine"
            displayName="$(string.UpdateInterval_DisplayName)"
            explainText="$(string.UpdateInterval_ExplainText)"
            key="SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${extensionId}\\policy"
            valueName="update_interval_minutes">
      <parentCategory ref="BrowserDefense_Settings" />
      <supportedOn ref="SUPPORTED_WIN7" />
      <elements>
        <decimal id="UpdateInterval_Value" valueName="update_interval_minutes" minValue="5" maxValue="1440" />
      </elements>
    </policy>

    <policy name="SigningPublicKey"
            class="Machine"
            displayName="$(string.SigningPublicKey_DisplayName)"
            explainText="$(string.SigningPublicKey_ExplainText)"
            key="SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${extensionId}\\policy"
            valueName="signing_public_key">
      <parentCategory ref="BrowserDefense_Security" />
      <supportedOn ref="SUPPORTED_WIN7" />
      <elements>
        <text id="SigningPublicKey_Value" valueName="signing_public_key" required="true" maxLength="2048" />
      </elements>
    </policy>

    <policy name="EncryptionPublicKey"
            class="Machine"
            displayName="$(string.EncryptionPublicKey_DisplayName)"
            explainText="$(string.EncryptionPublicKey_ExplainText)"
            key="SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${extensionId}\\policy"
            valueName="encryption_public_key">
      <parentCategory ref="BrowserDefense_Security" />
      <supportedOn ref="SUPPORTED_WIN7" />
      <elements>
        <text id="EncryptionPublicKey_Value" valueName="encryption_public_key" required="true" maxLength="4096" />
      </elements>
    </policy>

    <policy name="EnableDebugLogging"
            class="Machine"
            displayName="$(string.EnableDebugLogging_DisplayName)"
            explainText="$(string.EnableDebugLogging_ExplainText)"
            key="SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${extensionId}\\policy"
            valueName="enable_debug_logging">
      <parentCategory ref="BrowserDefense_Settings" />
      <supportedOn ref="SUPPORTED_WIN7" />
      <enabledValue>
        <decimal value="1" />
      </enabledValue>
      <disabledValue>
        <decimal value="0" />
      </disabledValue>
    </policy>

  </policies>
</policyDefinitions>`;
}

/**
 * Generate ADML localization file with pre-filled values
 */
export function generateADML(config: DeploymentConfig): string {
  const {
    blocklistEndpoint,
    forensicsEndpoint,
    signingPublicKey,
    encryptionPublicKey,
    iocSalt,
    updateIntervalMinutes = 60,
    orgDisplayName = config.orgSlug,
  } = config;

  // Escape XML special characters in values
  const escapeXml = (str: string) => str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');

  const signingKeyJson = escapeXml(JSON.stringify(signingPublicKey));
  const encryptionKeyJson = escapeXml(JSON.stringify(encryptionPublicKey));

  return `<?xml version="1.0" encoding="utf-8"?>
<policyDefinitionResources xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                           revision="1.0"
                           schemaVersion="1.0"
                           xmlns="${ADMX_NAMESPACE}">
  <displayName>BrowserDefense Policy Definitions</displayName>
  <description>Administrative template for ${escapeXml(orgDisplayName)} - BrowserDefense Chrome extension.</description>

  <resources>
    <stringTable>
      <string id="SUPPORTED_WIN7">Windows 7 and later</string>

      <string id="BrowserDefense_Category">BrowserDefense</string>
      <string id="BrowserDefense_Settings_Category">Settings</string>
      <string id="BrowserDefense_Security_Category">Security</string>

      <string id="BlocklistEndpoint_DisplayName">Blocklist Endpoint URL</string>
      <string id="BlocklistEndpoint_ExplainText">URL for blocklist updates.

Pre-configured for ${escapeXml(orgDisplayName)}:
${escapeXml(blocklistEndpoint)}</string>

      <string id="ForensicsEndpoint_DisplayName">Forensics Upload Endpoint URL</string>
      <string id="ForensicsEndpoint_ExplainText">URL for encrypted forensics uploads.

Pre-configured for ${escapeXml(orgDisplayName)}:
${escapeXml(forensicsEndpoint)}</string>

      <string id="IocSalt_DisplayName">IOC Hash Salt</string>
      <string id="IocSalt_ExplainText">Salt for IOC hashing. Must match the value used when compiling blocklists.

Pre-configured for ${escapeXml(orgDisplayName)}:
${escapeXml(iocSalt)}</string>

      <string id="UpdateInterval_DisplayName">Blocklist Update Interval (minutes)</string>
      <string id="UpdateInterval_ExplainText">How frequently to check for blocklist updates.
Range: 5-1440 minutes. Default: ${updateIntervalMinutes} minutes.</string>

      <string id="SigningPublicKey_DisplayName">Blocklist Signing Public Key</string>
      <string id="SigningPublicKey_ExplainText">P-256 ECDSA public key for signature verification (JWK format).

Pre-configured for ${escapeXml(orgDisplayName)}:
${signingKeyJson}</string>

      <string id="EncryptionPublicKey_DisplayName">Forensics Encryption Public Key</string>
      <string id="EncryptionPublicKey_ExplainText">RSA-OAEP public key for forensics encryption (JWK format).

Pre-configured for ${escapeXml(orgDisplayName)}:
${encryptionKeyJson}</string>

      <string id="EnableDebugLogging_DisplayName">Enable Debug Logging</string>
      <string id="EnableDebugLogging_ExplainText">Enable verbose debug logging in the browser console.</string>

    </stringTable>

    <presentationTable>
      <presentation id="BlocklistEndpoint">
        <textBox refId="BlocklistEndpoint_Value">
          <label>Endpoint URL:</label>
          <defaultValue>${escapeXml(blocklistEndpoint)}</defaultValue>
        </textBox>
      </presentation>

      <presentation id="ForensicsEndpoint">
        <textBox refId="ForensicsEndpoint_Value">
          <label>Forensics Endpoint URL:</label>
          <defaultValue>${escapeXml(forensicsEndpoint)}</defaultValue>
        </textBox>
      </presentation>

      <presentation id="IocSalt">
        <textBox refId="IocSalt_Value">
          <label>IOC Salt:</label>
          <defaultValue>${escapeXml(iocSalt)}</defaultValue>
        </textBox>
      </presentation>

      <presentation id="UpdateInterval">
        <decimalTextBox refId="UpdateInterval_Value" defaultValue="${updateIntervalMinutes}">Update Interval (minutes):</decimalTextBox>
      </presentation>

      <presentation id="SigningPublicKey">
        <textBox refId="SigningPublicKey_Value">
          <label>Public Key (JWK):</label>
          <defaultValue>${signingKeyJson}</defaultValue>
        </textBox>
      </presentation>

      <presentation id="EncryptionPublicKey">
        <textBox refId="EncryptionPublicKey_Value">
          <label>Public Key (JWK):</label>
          <defaultValue>${encryptionKeyJson}</defaultValue>
        </textBox>
      </presentation>
    </presentationTable>
  </resources>
</policyDefinitionResources>`;
}

/**
 * Generate both ADMX and ADML files
 */
export function generateADMXBundle(config: DeploymentConfig): ADMXResult {
  return {
    admx: generateADMX(config),
    adml: generateADML(config),
  };
}
