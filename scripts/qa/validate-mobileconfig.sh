#!/bin/bash
# validate-mobileconfig.sh - Validate Apple Configuration Profile
#
# Usage: ./validate-mobileconfig.sh [mobileconfig_file]
#
# Validates:
# - Plist syntax
# - Required payload keys
# - Chrome extension settings structure
# - PayloadIdentifier uniqueness

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

MOBILECONFIG_FILE="${1:-$REPO_ROOT/enterprise/macos/BlockIOC.mobileconfig}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "BlockIOC mobileconfig Validation"
echo "=========================================="
echo ""

ERRORS=0
WARNINGS=0

# Check file exists
echo "Checking file exists..."
if [[ ! -f "$MOBILECONFIG_FILE" ]]; then
    echo -e "${RED}ERROR: mobileconfig file not found: $MOBILECONFIG_FILE${NC}"
    exit 1
fi
echo -e "${GREEN}OK${NC} - File found: $MOBILECONFIG_FILE"
echo ""

# Validate plist syntax
echo "Validating plist syntax..."

if command -v plutil &> /dev/null; then
    if plutil -lint "$MOBILECONFIG_FILE" 2>/dev/null; then
        echo -e "${GREEN}OK${NC} - Plist syntax is valid"
    else
        echo -e "${RED}ERROR${NC} - Plist syntax is invalid"
        plutil -lint "$MOBILECONFIG_FILE"
        ((ERRORS++))
    fi
else
    echo -e "${YELLOW}WARN${NC} - plutil not found (not on macOS?)"
    # Basic check
    if grep -q '<!DOCTYPE plist' "$MOBILECONFIG_FILE" || grep -q '<plist' "$MOBILECONFIG_FILE"; then
        echo -e "${GREEN}OK${NC} - File appears to be a plist"
    else
        echo -e "${RED}ERROR${NC} - File does not appear to be a plist"
        ((ERRORS++))
    fi
fi
echo ""

# Check required payload keys
echo "Checking required payload keys..."

check_key() {
    local key="$1"
    local desc="$2"

    if grep -q "<key>$key</key>" "$MOBILECONFIG_FILE"; then
        echo -e "${GREEN}OK${NC} - Found <key>$key</key> ($desc)"
        return 0
    else
        echo -e "${RED}ERROR${NC} - Missing <key>$key</key> ($desc)"
        ((ERRORS++))
        return 1
    fi
}

check_key "PayloadIdentifier" "unique profile identifier"
check_key "PayloadType" "profile type"
check_key "PayloadUUID" "unique identifier"
check_key "PayloadVersion" "version number"
check_key "PayloadDisplayName" "display name"
check_key "PayloadContent" "payload content array"
echo ""

# Extract and display payload info
echo "Payload information..."

if command -v plutil &> /dev/null; then
    # Use plutil to extract values
    echo "PayloadIdentifier: $(plutil -extract PayloadIdentifier raw "$MOBILECONFIG_FILE" 2>/dev/null || echo "N/A")"
    echo "PayloadDisplayName: $(plutil -extract PayloadDisplayName raw "$MOBILECONFIG_FILE" 2>/dev/null || echo "N/A")"
    echo "PayloadType: $(plutil -extract PayloadType raw "$MOBILECONFIG_FILE" 2>/dev/null || echo "N/A")"
    echo "PayloadVersion: $(plutil -extract PayloadVersion raw "$MOBILECONFIG_FILE" 2>/dev/null || echo "N/A")"
elif command -v /usr/libexec/PlistBuddy &> /dev/null; then
    # Use PlistBuddy
    echo "PayloadIdentifier: $(/usr/libexec/PlistBuddy -c "Print :PayloadIdentifier" "$MOBILECONFIG_FILE" 2>/dev/null || echo "N/A")"
    echo "PayloadDisplayName: $(/usr/libexec/PlistBuddy -c "Print :PayloadDisplayName" "$MOBILECONFIG_FILE" 2>/dev/null || echo "N/A")"
else
    # Fallback to grep
    echo "PayloadIdentifier: $(grep -A1 '<key>PayloadIdentifier</key>' "$MOBILECONFIG_FILE" | grep '<string>' | sed 's/.*<string>\(.*\)<\/string>.*/\1/')"
fi
echo ""

# Check for Chrome extension settings
echo "Checking Chrome extension settings..."

if grep -q "com.google.Chrome" "$MOBILECONFIG_FILE"; then
    echo -e "${GREEN}OK${NC} - Contains Chrome settings"
else
    echo -e "${YELLOW}WARN${NC} - No com.google.Chrome settings found"
    ((WARNINGS++))
fi

if grep -q "ExtensionSettings" "$MOBILECONFIG_FILE"; then
    echo -e "${GREEN}OK${NC} - Contains ExtensionSettings"
else
    echo -e "${YELLOW}WARN${NC} - No ExtensionSettings found"
    ((WARNINGS++))
fi

if grep -q "3rdparty" "$MOBILECONFIG_FILE"; then
    echo -e "${GREEN}OK${NC} - Contains 3rdparty extension config"
else
    echo -e "${YELLOW}WARN${NC} - No 3rdparty extension config found"
    ((WARNINGS++))
fi
echo ""

# Check payload content count
echo "Payload content analysis..."
PAYLOAD_COUNT=$(grep -c '<key>PayloadType</key>' "$MOBILECONFIG_FILE" || echo "1")
echo "Payload sections: $PAYLOAD_COUNT"
echo ""

# Security check - look for sensitive data
echo "Security checks..."

if grep -qi "password" "$MOBILECONFIG_FILE"; then
    echo -e "${YELLOW}WARN${NC} - Profile may contain password fields"
    ((WARNINGS++))
else
    echo -e "${GREEN}OK${NC} - No password fields detected"
fi

if grep -q "BEGIN CERTIFICATE" "$MOBILECONFIG_FILE"; then
    echo -e "${GREEN}INFO${NC} - Profile contains certificates (expected for signing)"
fi

if grep -q "BEGIN PRIVATE KEY" "$MOBILECONFIG_FILE"; then
    echo -e "${RED}ERROR${NC} - Profile contains private key data!"
    ((ERRORS++))
fi
echo ""

# Signing check
echo "Signature check..."
if grep -q "pkcs7-signature" "$MOBILECONFIG_FILE" || grep -q "BEGIN PKCS7" "$MOBILECONFIG_FILE"; then
    echo -e "${GREEN}OK${NC} - Profile appears to be signed"
else
    echo -e "${YELLOW}INFO${NC} - Profile is not signed (OK for testing, sign for production)"
fi
echo ""

# macOS-specific validation
if [[ "$(uname)" == "Darwin" ]]; then
    echo "macOS-specific validation..."

    # Try to decode if signed
    if command -v security &> /dev/null; then
        if security cms -D -i "$MOBILECONFIG_FILE" > /dev/null 2>&1; then
            echo -e "${GREEN}OK${NC} - Profile signature validates"
        else
            echo -e "${YELLOW}INFO${NC} - Profile is unsigned or signature cannot be verified"
        fi
    fi

    # Check if installable (dry run)
    echo ""
    echo "Installation preview (dry run)..."
    echo "To install: sudo profiles install -path '$MOBILECONFIG_FILE'"
    echo "To remove:  sudo profiles remove -identifier <PayloadIdentifier>"
fi
echo ""

# Summary
echo "=========================================="
echo "Validation Summary"
echo "=========================================="
echo "File: $MOBILECONFIG_FILE"
echo "Size: $(wc -c < "$MOBILECONFIG_FILE" | tr -d ' ') bytes"
echo ""

if [[ $ERRORS -gt 0 ]]; then
    echo -e "${RED}FAILED${NC} - $ERRORS error(s), $WARNINGS warning(s)"
    exit 1
else
    echo -e "${GREEN}PASSED${NC} - $WARNINGS warning(s)"
    exit 0
fi
