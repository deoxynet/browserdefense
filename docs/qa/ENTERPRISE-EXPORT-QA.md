# Enterprise Export QA Guide

Manual testing guide for ADMX, mobileconfig, and Intune exports.

## Overview

This document provides step-by-step QA procedures for validating BlockIOC enterprise deployment exports across Windows (ADMX/Intune) and macOS (mobileconfig) platforms.

## Test Environments Required

| Platform | Local Testing | Enterprise Testing |
|----------|--------------|-------------------|
| Windows | Windows 10/11 Pro with gpedit.msc | Active Directory + GPMC |
| macOS | macOS 12+ with profiles command | Jamf Pro or other MDM |
| Intune | PowerShell validation | Microsoft Intune admin |

---

## Part 1: Windows ADMX Testing

### Layer 1: Syntax Validation

Run from the repository root:

```bash
# Use the validation script
./scripts/qa/validate-admx.sh
```

Or manually:

```powershell
# Validate XML syntax
[xml]$admx = Get-Content enterprise/admx/BlockIOC.admx
[xml]$adml = Get-Content enterprise/admx/en-US/BlockIOC.adml

# Check for required elements
$admx.policyDefinitions.policies.policy | Select-Object name, key
```

**Pass Criteria:**
- [ ] XML parses without errors
- [ ] All policy elements have name and key attributes
- [ ] ADML strings match ADMX references

### Layer 2: Local Import (Windows Pro/Enterprise)

1. **Copy files to PolicyDefinitions:**
   ```powershell
   Copy-Item enterprise\admx\BlockIOC.admx C:\Windows\PolicyDefinitions\
   Copy-Item enterprise\admx\en-US\BlockIOC.adml C:\Windows\PolicyDefinitions\en-US\
   ```

2. **Open Local Group Policy Editor:**
   ```powershell
   gpedit.msc
   ```

3. **Navigate to policies:**
   - Computer Configuration > Administrative Templates
   - Look for "BlockIOC" category under Google Chrome

4. **Verify each policy:**
   - Open each policy setting
   - Verify display name and description appear
   - Check input fields render correctly

**Pass Criteria:**
- [ ] No import errors on gpedit.msc launch
- [ ] BlockIOC category appears under Chrome
- [ ] All policy settings are accessible
- [ ] Help text displays correctly

### Layer 3: Domain GPO Testing (with AD Admin)

**Provide AD admin with this checklist:**

```markdown
## BlockIOC GPO Test Checklist

### Prerequisites
- [ ] Received BlockIOC.admx and BlockIOC.adml files
- [ ] Created test OU with 1 Windows endpoint
- [ ] Chrome installed on test endpoint
- [ ] Test IOC URL available: https://blockioc-test.example.com/phish

### Import Steps
- [ ] Copied BlockIOC.admx to \\domain\SYSVOL\domain\Policies\PolicyDefinitions\
- [ ] Copied BlockIOC.adml to PolicyDefinitions\en-US\
- [ ] GPMC shows "BlockIOC" under Administrative Templates > Google Chrome
- [ ] No import errors in Event Viewer

### Policy Configuration
- [ ] Created GPO named "BlockIOC-Test"
- [ ] Enabled BlockIOC policies with test values:
  - Blocklist Endpoint: https://api.blockioc.com/blocklist
  - Forensics Endpoint: https://api.blockioc.com/forensics
  - Update Interval: 3600
- [ ] Linked GPO to test OU
- [ ] Set GPO security filtering to test computer only

### Endpoint Verification
- [ ] Run: gpupdate /force
- [ ] Verify: gpresult /r shows "BlockIOC-Test" applied
- [ ] Check registry:
  Get-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\*\policy"
- [ ] Open Chrome > chrome://policy > BlockIOC settings visible
- [ ] Extension reads managed config (check popup/options)
- [ ] Navigate to test IOC URL > block page appears

### Cleanup
- [ ] Unlink GPO from test OU
- [ ] Delete test GPO (optional)
```

**Verification Commands:**
```powershell
# On test endpoint after gpupdate /force
gpresult /r /scope computer | Select-String "BlockIOC"

# Check Chrome policies in registry
Get-ChildItem "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\" -Recurse

# Export applied policies
gpresult /h gpresult.html
```

---

## Part 2: macOS mobileconfig Testing

### Layer 1: Syntax Validation

Run from the repository root:

```bash
# Use the validation script
./scripts/qa/validate-mobileconfig.sh
```

Or manually:

```bash
# Validate plist syntax
plutil -lint enterprise/macos/BlockIOC.mobileconfig

# View contents
plutil -p enterprise/macos/BlockIOC.mobileconfig

# Check for required keys
/usr/libexec/PlistBuddy -c "Print :PayloadContent" enterprise/macos/BlockIOC.mobileconfig
```

**Pass Criteria:**
- [ ] plutil reports "OK"
- [ ] PayloadIdentifier is set
- [ ] PayloadType is "Configuration"
- [ ] Chrome extension settings are present

### Layer 2: Local Install (Developer Mac)

```bash
# Install the profile (will prompt for confirmation)
sudo profiles install -path enterprise/macos/BlockIOC.mobileconfig

# Verify installation
profiles list | grep -i blockioc

# Check Chrome managed preferences
defaults read com.google.Chrome ExtensionSettings 2>/dev/null || \
defaults read com.google.Chrome.canary ExtensionSettings

# Open Chrome and check chrome://policy

# Remove after testing
sudo profiles remove -identifier com.blockioc.enterprise.config
```

**Pass Criteria:**
- [ ] Profile installs without errors
- [ ] Profile appears in `profiles list`
- [ ] Chrome reads managed preferences
- [ ] chrome://policy shows BlockIOC settings
- [ ] Profile removes cleanly

### Layer 3: MDM Testing (Jamf Pro)

**Provide Jamf admin with this checklist:**

```markdown
## BlockIOC Jamf Configuration Profile Test

### Prerequisites
- [ ] Jamf Pro admin access
- [ ] Test Mac enrolled in Jamf
- [ ] Chrome installed on test Mac
- [ ] BlockIOC.mobileconfig file

### Upload to Jamf
- [ ] Computer > Configuration Profiles > Upload
- [ ] Upload BlockIOC.mobileconfig
- [ ] No validation errors during upload
- [ ] Profile appears in Jamf with correct payload info

### Scope Configuration
- [ ] Create Smart Group: "BlockIOC Test Macs"
- [ ] Add test Mac to group
- [ ] Scope profile to Smart Group only

### Endpoint Verification
- [ ] Force MDM check-in on test Mac:
  sudo jamf policy
- [ ] Verify profile installed:
  profiles list | grep -i blockioc
- [ ] Check Chrome preferences:
  defaults read com.google.Chrome
- [ ] Open Chrome > chrome://policy > settings visible
- [ ] Extension reads managed config
- [ ] Navigate to test IOC URL > block page appears

### Cleanup
- [ ] Remove test Mac from Smart Group (profile auto-removes)
- [ ] Or: Remove profile assignment manually
```

---

## Part 3: Intune JSON Testing

### Layer 1: JSON Validation

Run from the repository root:

```bash
# Use the validation script
./scripts/qa/validate-intune.sh
```

Or manually:

```powershell
# Validate JSON syntax
$config = Get-Content enterprise/intune/BlockIOC-OMA-URI.json | ConvertFrom-Json
$config | ConvertTo-Json -Depth 10

# Check required OMA-URI settings
$config.omaSettings | ForEach-Object {
    Write-Host "$($_.displayName): $($_.omaUri)"
}
```

**Pass Criteria:**
- [ ] JSON parses without errors
- [ ] All OMA-URI paths are valid
- [ ] Values are properly typed

### Layer 2: Intune Configuration

1. **Create Configuration Profile:**
   - Devices > Configuration profiles > Create profile
   - Platform: Windows 10 and later
   - Profile type: Templates > Custom
   - Name: "BlockIOC Configuration"

2. **Add OMA-URI Settings:**
   For each setting in `BlockIOC-OMA-URI.json`:
   ```
   Name: [from displayName]
   OMA-URI: [from omaUri]
   Data type: [from dataType]
   Value: [from value]
   ```

3. **Configure Assignment:**
   - Assign to a test device group
   - Use "Selected groups" for testing

4. **Force Sync:**
   ```powershell
   # On test device
   Start-Process "ms-settings:sync"
   # Or via Intune portal: Devices > [device] > Sync
   ```

### Layer 3: Endpoint Verification

```powershell
# Check registry for Chrome extension policy
$regPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions"
Get-ChildItem $regPath -Recurse | Get-ItemProperty

# Check Intune policy status
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device" |
    Where-Object { $_.Name -like "*Chrome*" }

# Verify in Chrome
# Open chrome://policy - BlockIOC settings should appear
```

**Pass Criteria:**
- [ ] Profile creates without errors
- [ ] Assignment completes successfully
- [ ] Policy syncs to device
- [ ] Registry keys created
- [ ] chrome://policy shows settings
- [ ] Extension reads managed config
- [ ] Blocking works E2E

---

## Test Matrix

| Test | ADMX | mobileconfig | Intune |
|------|------|--------------|--------|
| Syntax validation | [ ] | [ ] | [ ] |
| Local import/install | [ ] | [ ] | [ ] |
| Enterprise import | [ ] | [ ] | [ ] |
| Policy applies | [ ] | [ ] | [ ] |
| Chrome reads policy | [ ] | [ ] | [ ] |
| Extension configured | [ ] | [ ] | [ ] |
| Blocking works E2E | [ ] | [ ] | [ ] |

---

## Test IOC URLs

Use these URLs for E2E blocking verification:

```
# Primary test URL (add to blocklist before export)
https://blockioc-test.example.com/phish

# Alternative test domains
https://malware-test.blockioc.dev/payload
https://phishing-demo.blockioc.dev/login
```

---

## Troubleshooting

### ADMX Issues

| Issue | Solution |
|-------|----------|
| Category not appearing | Ensure ADML is in correct language folder (en-US) |
| Policy not applying | Check GPO link and security filtering |
| Registry keys missing | Verify extension ID in policy key path |

### mobileconfig Issues

| Issue | Solution |
|-------|----------|
| "Profile is not signed" | Expected for testing; Jamf will re-sign |
| Chrome not reading | Ensure PayloadType is "com.google.Chrome" |
| Profile won't remove | Use `sudo profiles remove -forced` |

### Intune Issues

| Issue | Solution |
|-------|----------|
| OMA-URI error | Verify path format matches Chrome ADMX docs |
| Policy not syncing | Check device compliance status |
| Conflict with GPO | Intune and GPO may conflict; use one method |

---

## Related Documentation

- [Chrome Enterprise Policy List](https://chromeenterprise.google/policies/)
- [Intune OMA-URI Reference](https://docs.microsoft.com/en-us/mem/intune/configuration/custom-settings-windows-10)
- [Apple Configuration Profile Reference](https://developer.apple.com/business/documentation/Configuration-Profile-Reference.pdf)
- [BlockIOC Enterprise Setup](../../scripts/enterprise-policy-setup/README.md)
