# Chrome Web Store Submission Guide

This guide walks through submitting BrowserDefense to the Chrome Web Store.

## Prerequisites

- [ ] Chrome Developer account ($5 one-time fee)
- [ ] Extension built and packaged
- [ ] Screenshots captured (see below)
- [ ] Privacy policy live at browserdefense.com/privacy
- [ ] Terms of service live at browserdefense.com/terms

## Step 1: Build and Package

```bash
# Build the extension
pnpm run build:all

# Create the submission package
chmod +x scripts/package-extension.sh
bash scripts/package-extension.sh
```

This creates `browserdefense-v{VERSION}.zip` in the project root. For managed policy deployment, use `bash scripts/package-extension.sh enterprise` to create a separate enterprise archive. Run `pnpm run package` to build and package both variants. Only the consumer archive is intended for the Chrome Web Store.

## Step 2: Capture Screenshots

Screenshots should show the extension in action. Use demo mode for safe capture.

### Enable Demo Mode

1. Load the extension in Chrome (`chrome://extensions` → Load unpacked → select `dist/`)
2. Open the extension options page
3. Enable "Demo Mode"
4. Add demo URLs:
   ```
   evil-phishing-site.example.com
   malware-test.example.com/login
   demo.test.com
   ```
5. Save settings

### Capture Block Page Screenshot

1. Navigate to `https://evil-phishing-site.example.com` (or any demo URL)
2. The block page appears
3. Take screenshot (1280x800 or 640x400)
4. Save as `screenshots/block-page.png`

### Capture Popup Screenshot

1. Click the BrowserDefense icon in the toolbar
2. The popup shows status and recent blocks
3. Take screenshot
4. Save as `screenshots/popup.png`

### Capture Options Page Screenshot

1. Right-click BrowserDefense icon → Options
2. Take screenshot showing configuration
3. Save as `screenshots/options.png`

### Screenshot Requirements

| Requirement | Value |
|-------------|-------|
| Minimum size | 640x400 |
| Maximum size | 1280x800 |
| Format | PNG or JPEG |
| Count | 1-5 screenshots |

## Step 3: Create Developer Account

1. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
2. Sign in with Google account
3. Pay $5 registration fee (one-time)
4. Accept Developer Agreement

## Step 4: Create New Item

1. Click "New Item"
2. Upload `browserdefense-v{VERSION}.zip`
3. Wait for upload to complete

## Step 5: Fill Store Listing

Copy content from `docs/STORE_LISTING.md`:

### Product Details

| Field | Content |
|-------|---------|
| Name | BrowserDefense |
| Summary | Protect your organization from phishing with zero-knowledge threat detection. Block malicious sites without compromising privacy. |
| Description | (Copy full description from STORE_LISTING.md) |
| Category | Security |
| Language | English |

### Graphic Assets

- **Icon**: Already in manifest (128x128)
- **Screenshots**: Upload from `screenshots/` folder

### Additional Fields

| Field | Value |
|-------|-------|
| Support email | support@browserdefense.com |
| Privacy policy | https://browserdefense.com/privacy |
| Terms of service | https://browserdefense.com/terms |

## Step 6: Privacy Practices

Fill in the privacy disclosure:

1. **Data Use**: Security (threat protection)
2. **Data Collection**:
   - Web history: Yes (blocked URLs only, encrypted)
   - Website content: No
   - User activity: No
   - Location: No
   - Personal communications: No
3. **Data Sharing**: No (zero-knowledge architecture)
4. **Certifications**: No remote code execution

## Step 7: Distribution

| Setting | Value |
|---------|-------|
| Visibility | Public |
| Distribution | All regions |
| Mature content | No |

## Step 8: Submit for Review

1. Review all sections
2. Click "Submit for Review"
3. Wait 1-3 business days for review

## Post-Submission

### If Rejected

Common rejection reasons and fixes:

| Reason | Fix |
|--------|-----|
| Permission justification missing | Add to host permission section |
| Privacy policy not found | Ensure URL is live and accessible |
| Unclear functionality | Improve description clarity |

### If Approved

1. Update README with store link
2. Announce on social media
3. Monitor reviews and ratings

## Troubleshooting

### Package Too Large

The extension should be under 10MB. If larger:
- Check for debug artifacts
- Ensure source maps are excluded
- Verify no unnecessary files in dist/

### Screenshots Rejected

- Ensure no personal data visible
- Use demo mode with fake URLs
- Check minimum size requirements (640x400)

### Permission Questions

All permissions are documented in STORE_LISTING.md with justifications.

---

## Quick Reference

```bash
# Full submission workflow
pnpm run build:all
bash scripts/package-extension.sh
# Upload browserdefense-v{VERSION}.zip to Chrome Web Store
```

Store listing content: `docs/STORE_LISTING.md`
