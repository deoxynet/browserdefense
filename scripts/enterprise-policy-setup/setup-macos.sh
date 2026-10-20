#!/bin/bash
#
# BrowserDefense Enterprise Policy Setup for macOS
#
# This script installs the BrowserDefense extension via Chrome enterprise policy,
# enabling webRequestBlocking permissions for MV3.
#
# REQUIREMENTS:
# - macOS with Chrome installed
# - Admin (sudo) access
# - Built extension in dist/ directory with known extension ID
#
# USAGE:
#   sudo ./setup-macos.sh <extension-id> [update-url]
#
# Example:
#   sudo ./setup-macos.sh abcdefghijklmnopqrstuvwxyzabcdef
#   sudo ./setup-macos.sh abcdefghijklmnopqrstuvwxyzabcdef https://your-server.com/updates.xml
#
# NOTES:
# - Chrome must be restarted after policy installation
# - Extension will show "Installed by enterprise policy"
# - Extension cannot be disabled/uninstalled by user
#

set -euo pipefail

EXTENSION_ID="${1:-}"
UPDATE_URL="${2:-}"

# Validate extension ID (32 lowercase hex chars)
if [[ -z "$EXTENSION_ID" || ! "$EXTENSION_ID" =~ ^[a-z]{32}$ ]]; then
    echo "Error: Extension ID must be 32 lowercase letters (a-z)"
    echo "Usage: sudo $0 <extension-id> [update-url]"
    echo ""
    echo "To get the extension ID:"
    echo "  1. Load unpacked extension in chrome://extensions (Developer mode)"
    echo "  2. Copy the ID shown under the extension name"
    exit 1
fi

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Policy directories
MANAGED_PREFS_DIR="/Library/Managed Preferences"
CHROME_PLIST="${MANAGED_PREFS_DIR}/com.google.Chrome.plist"

echo "=== BrowserDefense Enterprise Policy Setup for macOS ==="
echo "Extension ID: $EXTENSION_ID"
echo "Update URL: ${UPDATE_URL:-<none - local development mode>}"
echo ""

# Create managed preferences directory
mkdir -p "${MANAGED_PREFS_DIR}"

# Build policy value for ExtensionInstallForcelist
if [[ -n "$UPDATE_URL" ]]; then
    POLICY_VALUE="${EXTENSION_ID};${UPDATE_URL}"
else
    # For local development, use Chrome Web Store URL (extension must be uploaded)
    # Or use update_url from manifest.json in CRX file
    POLICY_VALUE="${EXTENSION_ID}"
fi

# Create plist with ExtensionInstallForcelist
cat > "${CHROME_PLIST}" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>ExtensionInstallForcelist</key>
    <array>
        <string>${POLICY_VALUE}</string>
    </array>
    <key>ExtensionSettings</key>
    <dict>
        <key>${EXTENSION_ID}</key>
        <dict>
            <key>installation_mode</key>
            <string>force_installed</string>
            <key>runtime_blocked_hosts</key>
            <array/>
            <key>runtime_allowed_hosts</key>
            <array>
                <string>*://*/*</string>
            </array>
        </dict>
    </dict>
</dict>
</plist>
EOF

# Fix permissions
chmod 644 "${CHROME_PLIST}"
chown root:wheel "${CHROME_PLIST}"

echo "Policy file created: ${CHROME_PLIST}"
echo ""

# Verify plist is valid
if plutil -lint "${CHROME_PLIST}" > /dev/null 2>&1; then
    echo "[OK] Policy file is valid"
else
    echo "[ERROR] Policy file is invalid!"
    exit 1
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Quit Chrome completely (Cmd+Q)"
echo "  2. Reopen Chrome"
echo "  3. Navigate to chrome://extensions"
echo "  4. Verify BrowserDefense shows 'Installed by enterprise policy'"
echo "  5. Run enterprise integration tests:"
echo "     npm run test:e2e -- --grep 'Enterprise'"
echo ""
echo "To remove policy:"
echo "  sudo rm '${CHROME_PLIST}'"
echo "  Then restart Chrome"
