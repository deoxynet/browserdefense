# BlockIOC Enterprise Deployment Guide

This guide covers deploying BlockIOC to managed endpoints using enterprise MDM solutions.

## Overview

BlockIOC supports centralized configuration via managed policies. Configuration is delivered through Chrome's enterprise policy mechanism, which the extension reads via `chrome.storage.managed`.

### Supported Platforms

| Platform | Deployment Method |
|----------|-------------------|
| Windows (AD) | Group Policy (ADMX) |
| Windows (Intune) | OMA-URI / PowerShell |
| macOS | Configuration Profile (.mobileconfig) |
| Chrome OS | Google Admin Console |

## Configuration Parameters

### Required Settings

| Parameter | Registry Key | Description |
|-----------|--------------|-------------|
| Blocklist Endpoint | `blocklist_endpoint` | URL for signed blocklist updates |
| Organization ID | `org_id` | Unique identifier for your org |
| GPO Private Key | `gpo_private_key` | X25519 key (JWK format) |

### Optional Settings

| Parameter | Registry Key | Default | Description |
|-----------|--------------|---------|-------------|
| Forensics Endpoint | `forensics_endpoint` | (none) | URL for encrypted forensics upload |
| Forensics Public Key | `forensics_public_key` | (none) | RSA-OAEP key for encryption |
| Update Interval | `update_interval_minutes` | 60 | Minutes between blocklist checks |
| Debug Logging | `enable_debug_logging` | false | Verbose console logging |

## Pre-Deployment Setup

### 1. Generate Cryptographic Keys

Use the BlockIOC CLI to generate required key pairs:

```bash
# Generate threat feed key pair (X25519)
npx blockioc-cli keygen --type mesh --output keys/

# Generate forensics encryption key pair (RSA-OAEP)
npx blockioc-cli keygen --type encryption --output keys/
```

This creates:
- `keys/mesh-private.jwk` - Deploy to endpoints (GPO/MDM)
- `keys/mesh-public.jwk` - Upload to BlockIOC for threat feed encryption
- `keys/encryption-public.jwk` - Deploy to endpoints
- `keys/encryption-private.jwk` - Keep secure, use in SIEM to decrypt

### 2. Set Up Blocklist Endpoint

Deploy a signed blocklist at your chosen endpoint. The manifest format:

```json
{
  "version": 1,
  "timestamp": "2024-01-15T10:30:00Z",
  "type": "full",
  "hashes": [
    "a948904f2f0f479b8f8564cbf12dac6b0eba0a4b2b2...",
    "..."
  ],
  "ciphertext": "base64-encrypted-feed..."
}
```

Upload your mesh public key to BlockIOC so threat feeds can be encrypted for your fleet.

### 3. Get Your Extension ID

After publishing to Chrome Web Store (or for self-hosted):
- Chrome Web Store: Find in the extension URL
- Self-hosted: Generate from the extension's public key

## Windows Deployment

### Option A: Group Policy (Active Directory)

1. **Install ADMX Template**

   Copy files to your Group Policy Central Store:
   ```
   \\domain\SYSVOL\domain\Policies\PolicyDefinitions\BlockIOC.admx
   \\domain\SYSVOL\domain\Policies\PolicyDefinitions\en-US\BlockIOC.adml
   ```

2. **Create GPO**

   - Open Group Policy Management Console
   - Create new GPO: "BlockIOC Configuration"
   - Navigate to: Computer Configuration > Administrative Templates > Google Chrome > BlockIOC

3. **Configure Settings**

   | Setting | Value |
   |---------|-------|
   | Blocklist Endpoint URL | `https://your-blocklist.example.com/v1/manifest.json` |
   | Organization ID | `your-org-id` |
| GPO Private Key | `{"kty":"OKP","crv":"X25519","kid":"2026_key_v2",...}` |

4. **Link GPO**

   Link to OUs containing target endpoints.

5. **Force Extension Installation**

   In the same GPO, configure:
   - Computer Configuration > Administrative Templates > Google Chrome > Extensions
   - Configure extension install sources and ExtensionSettings

### Option B: Microsoft Intune

#### Using PowerShell Script

1. **Upload Script to Intune**

   - Navigate to: Devices > Scripts > Add > Windows 10 and later
   - Upload `enterprise/intune/BlockIOC-Configuration.ps1`

2. **Configure Script Parameters**

   | Parameter | Value |
   |-----------|-------|
   | ExtensionId | Your Chrome Web Store extension ID |
   | BlocklistEndpoint | `https://your-blocklist.example.com/v1/manifest.json` |
   | OrgId | `your-org-id` |
   | GpoPrivateKey | `{"kty":"OKP","crv":"X25519","kid":"2026_key_v2",...}` |

3. **Assign to Device Group**

   Assign to groups containing target Windows endpoints.

#### Using OMA-URI Custom Policy

1. **Create Custom Configuration Profile**

   - Navigate to: Devices > Configuration profiles > Create profile
   - Platform: Windows 10 and later
   - Profile type: Templates > Custom

2. **Add OMA-URI Settings**

   Reference `enterprise/intune/BlockIOC-OMA-URI.json` for settings.

   Key OMA-URI paths:
   ```
   ./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/ExtensionSettings
   ./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome/3rdparty/extensions/{id}/policy/*
   ```

### Option C: Manual Registry (Testing)

For testing, import the sample registry file:

```cmd
reg import enterprise\registry\BlockIOC-Sample.reg
```

Or use PowerShell:

```powershell
# Set basic configuration
$ExtId = "your_extension_id"
$PolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$ExtId\policy"

New-Item -Path $PolicyPath -Force
Set-ItemProperty -Path $PolicyPath -Name "blocklist_endpoint" -Value "https://..."
Set-ItemProperty -Path $PolicyPath -Name "org_id" -Value "your-org-id"
```

## macOS Deployment

### Using MDM (Jamf, Mosyle, Kandji, etc.)

1. **Customize Configuration Profile**

   Edit `enterprise/macos/BlockIOC.mobileconfig`:
   - Replace `blockioc_extension_id` with your extension ID
   - Update endpoint URLs
   - Add your public keys

2. **Upload to MDM**

   - Jamf Pro: Settings > Computer Management > Configuration Profiles > Upload
   - Mosyle: Management > Profiles > Add Profile
   - Kandji: Library > Custom Profiles

3. **Scope to Devices**

   Assign to device groups or smart groups containing target Macs.

### Manual Installation (Testing)

```bash
sudo profiles install -path BlockIOC.mobileconfig
```

Verify:
```bash
sudo profiles list | grep blockioc
```

## Chrome OS Deployment

### Google Admin Console

1. **Navigate to Chrome Settings**

   Admin Console > Devices > Chrome > Settings > Users & browsers

2. **Configure Extension**

   Apps & Extensions > Add > Add Chrome app or extension by ID

3. **Set Managed Preferences**

   After adding, click the extension and configure:
   - Installation policy: Force install
   - Policy for extensions: (paste JSON configuration)

## Verification

### Verify Policy Delivery

1. Open Chrome
2. Navigate to `chrome://policy`
3. Search for "BlockIOC" or your extension ID
4. Verify all settings appear correctly

### Verify Extension Status

1. Click the BlockIOC extension icon
2. Check the popup shows:
   - Blocklist count > 0
   - Last update timestamp
   - Connected status

### Test Blocking

Navigate to a test URL that matches your blocklist. You should see the BlockIOC block page.

### Check Logs

If `enable_debug_logging` is enabled:
1. Open Chrome DevTools (F12)
2. Go to Application > Service Workers
3. Click "Inspect" on the BlockIOC worker
4. Check Console for debug output

## Troubleshooting

### Extension Not Installing

1. Verify ExtensionSettings policy is applied (`chrome://policy`)
2. Check Chrome version supports MV3 (Chrome 88+)
3. Verify update_url is accessible from endpoints

### Policies Not Applying

1. Force policy refresh: `gpupdate /force` (Windows) or restart Chrome
2. Check registry path is correct for your Chrome channel (Stable/Beta/Dev)
3. Verify JSON syntax in policy values

### Blocklist Not Updating

1. Verify `blocklist_endpoint` is accessible
2. Check `gpo_private_key.kid` matches the active threat feed header
3. Enable debug logging and check for decrypt errors

### Forensics Not Uploading

1. Verify `forensics_endpoint` is accessible
2. Check `forensics_public_key` is valid JWK format
3. Verify CORS allows requests from the extension origin

## Security Considerations

### Key Management

- **Mesh Public Key**: Store in BlockIOC so threat feeds can be encrypted for your fleet.
- **Encryption Private Key**: Store in your SIEM/analysis infrastructure. Never expose to endpoints.
- **Public Keys**: Safe to distribute via policy. Cannot be used to decrypt threat feeds.

### Network Security

- All endpoints (blocklist, forensics) should use HTTPS
- Consider IP allowlisting for forensics endpoint
- Use certificate pinning if self-hosting

### Audit Logging

Enable Windows Event logging for registry changes:
```
Computer Configuration > Windows Settings > Security Settings >
  Advanced Audit Policy > Object Access > Audit Registry
```

## Registry Reference

### Windows Registry Paths

```
HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionSettings\{extension_id}
HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\{extension_id}\policy\
```

### Full Registry Structure

```
HKLM\SOFTWARE\Policies\Google\Chrome\
├── ExtensionSettings\
│   └── {extension_id}         = "{\"installation_mode\":\"force_installed\",...}"
└── 3rdparty\
    └── extensions\
        └── {extension_id}\
            └── policy\
                ├── blocklist_endpoint       (REG_SZ)
                ├── org_id                   (REG_SZ)
                ├── forensics_endpoint       (REG_SZ)
                ├── update_interval_minutes  (REG_DWORD)
                ├── gpo_private_key          (REG_SZ)
                ├── forensics_public_key     (REG_SZ)
                └── enable_debug_logging     (REG_DWORD)
```

### macOS Preference Domain

```
com.google.Chrome.extensions.{extension_id}
```

## Support

For deployment issues:
1. Check the [Trust Center](../trust-center/) for security documentation
2. Open an issue on GitHub with:
   - MDM platform and version
   - Chrome version
   - Output of `chrome://policy`
   - Relevant log entries
