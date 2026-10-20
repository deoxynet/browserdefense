#!/bin/bash
#
# BrowserDefense Enterprise Policy Setup for Linux
#
# This script installs the BrowserDefense extension via Chrome enterprise policy,
# enabling webRequestBlocking permissions for MV3.
#
# REQUIREMENTS:
# - Linux with Chrome installed
# - Root (sudo) access
# - Built extension in dist/ directory with known extension ID
#
# USAGE:
#   sudo ./setup-linux.sh <extension-id> [update-url]
#
# Example:
#   sudo ./setup-linux.sh abcdefghijklmnopqrstuvwxyzabcdef
#   sudo ./setup-linux.sh abcdefghijklmnopqrstuvwxyzabcdef https://your-server.com/updates.xml
#
# NOTES:
# - Chrome must be restarted after policy installation
# - Extension will show "Installed by enterprise policy"
# - Extension cannot be disabled/uninstalled by user
#

set -euo pipefail

EXTENSION_ID="${1:-}"
UPDATE_URL="${2:-}"

# Validate extension ID (32 lowercase letters)
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

# Policy directory
POLICY_DIR="/etc/opt/chrome/policies/managed"
POLICY_FILE="${POLICY_DIR}/browserdefense_enterprise.json"

echo "=== BrowserDefense Enterprise Policy Setup for Linux ==="
echo "Extension ID: $EXTENSION_ID"
echo "Update URL: ${UPDATE_URL:-<none - local development mode>}"
echo ""

# Create policy directory
mkdir -p "${POLICY_DIR}"

# Build policy value for ExtensionInstallForcelist
if [[ -n "$UPDATE_URL" ]]; then
    POLICY_VALUE="${EXTENSION_ID};${UPDATE_URL}"
else
    POLICY_VALUE="${EXTENSION_ID}"
fi

# Create policy JSON file
cat > "${POLICY_FILE}" << EOF
{
  "ExtensionInstallForcelist": [
    "${POLICY_VALUE}"
  ],
  "ExtensionSettings": {
    "${EXTENSION_ID}": {
      "installation_mode": "force_installed",
      "runtime_blocked_hosts": [],
      "runtime_allowed_hosts": ["*://*/*"]
    }
  }
}
EOF

# Fix permissions
chmod 644 "${POLICY_FILE}"

echo "Policy file created: ${POLICY_FILE}"
echo ""

# Validate JSON
if command -v python3 &> /dev/null; then
    if python3 -m json.tool "${POLICY_FILE}" > /dev/null 2>&1; then
        echo "[OK] Policy file is valid JSON"
    else
        echo "[ERROR] Policy file contains invalid JSON!"
        exit 1
    fi
elif command -v jq &> /dev/null; then
    if jq empty "${POLICY_FILE}" > /dev/null 2>&1; then
        echo "[OK] Policy file is valid JSON"
    else
        echo "[ERROR] Policy file contains invalid JSON!"
        exit 1
    fi
else
    echo "[WARN] Could not validate JSON (install python3 or jq)"
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Close all Chrome windows"
echo "  2. Reopen Chrome"
echo "  3. Navigate to chrome://extensions"
echo "  4. Verify BrowserDefense shows 'Installed by enterprise policy'"
echo "  5. Run enterprise integration tests:"
echo "     npm run test:e2e -- --grep 'Enterprise'"
echo ""
echo "To remove policy:"
echo "  sudo rm '${POLICY_FILE}'"
echo "  Then restart Chrome"

# Also support Chromium
CHROMIUM_POLICY_DIR="/etc/chromium/policies/managed"
if [[ -d "/etc/chromium" ]] || command -v chromium-browser &> /dev/null; then
    echo ""
    echo "Chromium detected - installing policy there too..."
    mkdir -p "${CHROMIUM_POLICY_DIR}"
    cp "${POLICY_FILE}" "${CHROMIUM_POLICY_DIR}/"
    chmod 644 "${CHROMIUM_POLICY_DIR}/browserdefense_enterprise.json"
    echo "[OK] Policy also installed for Chromium"
fi
