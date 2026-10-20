# Enterprise Policy Setup for BrowserDefense

This directory contains scripts to install BrowserDefense as an enterprise policy-managed extension, enabling the `webRequestBlocking` permission for true pre-request blocking in Chrome MV3.

## Why Enterprise Mode?

In Chrome MV3, the `webRequestBlocking` permission is only available to **policy-installed extensions**. This permission enables:

| Feature | Non-Enterprise | Enterprise |
|---------|---------------|------------|
| Blocking timing | Post-request (after DNS/TCP) | **Pre-request (before DNS)** |
| IOC leak | URL may leak to network | **No network activity** |
| Blocking method | webNavigation + redirect | webRequest.onBeforeRequest |
| User control | Can disable extension | Cannot disable (managed) |

## Quick Start

### 1. Build the Extension

```bash
npm run build
```

### 2. Get Extension ID

1. Open Chrome and navigate to `chrome://extensions`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked" and select the `dist/` directory
4. Note the Extension ID (32 lowercase letters, e.g., `abcdefghijklmnopqrstuvwxyzabcdef`)

### 3. Install via Policy

Choose your platform:

#### macOS

```bash
sudo ./setup-macos.sh <extension-id>
# Example: sudo ./setup-macos.sh abcdefghijklmnopqrstuvwxyzabcdef
```

#### Windows (PowerShell as Administrator)

```powershell
.\setup-windows.ps1 -ExtensionId "abcdefghijklmnopqrstuvwxyzabcdef"
```

#### Linux

```bash
sudo ./setup-linux.sh <extension-id>
```

### 4. Restart Chrome

Close all Chrome windows completely and reopen.

### 5. Verify Installation

1. Go to `chrome://extensions`
2. BrowserDefense should show **"Installed by enterprise policy"**
3. The extension cannot be disabled or removed

### 6. Run Tests

```bash
# Run enterprise-specific tests
npm run test:e2e -- --grep 'Enterprise'

# Run all E2E tests
npm run test:e2e
```

## Verification

After policy installation, verify enterprise mode is active:

1. Open the extension popup or options page
2. Check browser console for: `[BrowserDefense] Enterprise mode available (webRequestBlocking)`
3. Navigate to a blocked URL and observe:
   - **Enterprise mode**: Request blocked before any network activity
   - **Fallback mode**: Brief network activity before redirect

## Troubleshooting

### Extension doesn't show "Installed by enterprise policy"

1. Ensure Chrome was fully restarted (quit and reopen)
2. Verify policy file was created:
   - macOS: `/Library/Managed Preferences/com.google.Chrome.plist`
   - Windows: `HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`
   - Linux: `/etc/opt/chrome/policies/managed/browserdefense_enterprise.json`
3. Check Chrome policies: `chrome://policy`

### webRequestBlocking permission not granted

The permission is only granted to **policy-installed** extensions. Manually loaded unpacked extensions do NOT get this permission. You must:

1. Install via policy (not "Load unpacked")
2. For development, use the CRX packaging workflow with update URL

### Tests skip with "not in enterprise mode"

This is expected behavior. The tests detect whether enterprise mode is available and skip if not. Install via policy to run these tests.

## Removing the Policy

### macOS

```bash
sudo rm '/Library/Managed Preferences/com.google.Chrome.plist'
```

### Windows (PowerShell as Administrator)

```powershell
Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' -Recurse
```

### Linux

```bash
sudo rm /etc/opt/chrome/policies/managed/browserdefense_enterprise.json
```

Then restart Chrome.

## Production Deployment

For production enterprise deployment:

1. **Package as CRX**: Use Chrome's extension packaging to create a signed CRX file
2. **Host update manifest**: Create an `updates.xml` file on your server
3. **Deploy via GPO/MDM**: Use your organization's management tools to push the policy

Example update URL format:

```bash
sudo ./setup-macos.sh <extension-id> https://your-server.com/extensions/updates.xml
```

## Security Considerations

- Policy-installed extensions have elevated trust
- Users cannot disable the extension
- Ensure your mesh keys are properly secured
- Use HTTPS for update manifest URLs in production

## Related Documentation

- [Chrome Enterprise Extension Policy](https://support.google.com/chrome/a/answer/9296680)
- [MV3 webRequest API](https://developer.chrome.com/docs/extensions/reference/webRequest/)
- [BrowserDefense Implementation Review](../../docs/Implementation_Review.md)
