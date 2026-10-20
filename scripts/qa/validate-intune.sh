#!/bin/bash
# validate-intune.sh - Validate Intune OMA-URI configuration
#
# Usage: ./validate-intune.sh [json_file]
#
# Validates:
# - JSON syntax
# - Required OMA-URI structure
# - Chrome extension policy paths
# - Data types

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

INTUNE_FILE="${1:-$REPO_ROOT/enterprise/intune/BlockIOC-OMA-URI.json}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "BlockIOC Intune Configuration Validation"
echo "=========================================="
echo ""

ERRORS=0
WARNINGS=0

# Check file exists
echo "Checking file exists..."
if [[ ! -f "$INTUNE_FILE" ]]; then
    echo -e "${RED}ERROR: Intune JSON file not found: $INTUNE_FILE${NC}"
    exit 1
fi
echo -e "${GREEN}OK${NC} - File found: $INTUNE_FILE"
echo ""

# Validate JSON syntax
echo "Validating JSON syntax..."

if command -v jq &> /dev/null; then
    if jq empty "$INTUNE_FILE" 2>/dev/null; then
        echo -e "${GREEN}OK${NC} - JSON syntax is valid"
    else
        echo -e "${RED}ERROR${NC} - JSON syntax is invalid"
        jq empty "$INTUNE_FILE"
        ((ERRORS++))
    fi
elif command -v python3 &> /dev/null; then
    if python3 -c "import json; json.load(open('$INTUNE_FILE'))" 2>/dev/null; then
        echo -e "${GREEN}OK${NC} - JSON syntax is valid"
    else
        echo -e "${RED}ERROR${NC} - JSON syntax is invalid"
        ((ERRORS++))
    fi
elif command -v node &> /dev/null; then
    if node -e "JSON.parse(require('fs').readFileSync('$INTUNE_FILE'))" 2>/dev/null; then
        echo -e "${GREEN}OK${NC} - JSON syntax is valid"
    else
        echo -e "${RED}ERROR${NC} - JSON syntax is invalid"
        ((ERRORS++))
    fi
else
    echo -e "${YELLOW}WARN${NC} - No JSON validator found (jq, python3, or node)"
    # Basic check
    if grep -q '"omaSettings"' "$INTUNE_FILE" || grep -q '"omaUri"' "$INTUNE_FILE"; then
        echo -e "${GREEN}OK${NC} - File appears to contain OMA-URI settings"
    else
        echo -e "${RED}ERROR${NC} - File does not appear to be Intune config"
        ((ERRORS++))
    fi
fi
echo ""

# Check OMA-URI structure
echo "Checking OMA-URI structure..."

if command -v jq &> /dev/null; then
    # Count settings
    if jq -e '.omaSettings' "$INTUNE_FILE" > /dev/null 2>&1; then
        SETTING_COUNT=$(jq '.omaSettings | length' "$INTUNE_FILE")
        echo -e "${GREEN}OK${NC} - Found omaSettings array with $SETTING_COUNT settings"
    elif jq -e '.[0].omaUri' "$INTUNE_FILE" > /dev/null 2>&1; then
        SETTING_COUNT=$(jq 'length' "$INTUNE_FILE")
        echo -e "${GREEN}OK${NC} - Found $SETTING_COUNT OMA-URI settings (array format)"
    else
        echo -e "${YELLOW}WARN${NC} - Non-standard structure, manual review needed"
        ((WARNINGS++))
    fi
else
    # Fallback to grep
    SETTING_COUNT=$(grep -c '"omaUri"' "$INTUNE_FILE" || echo "0")
    echo "Found approximately $SETTING_COUNT OMA-URI settings"
fi
echo ""

# Validate Chrome policy OMA-URI paths
echo "Validating OMA-URI paths..."

# Expected OMA-URI prefix for Chrome policies
CHROME_OMA_PREFIX="./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome"
CHROME_3P_PREFIX="./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions"

check_oma_uri() {
    local uri="$1"

    if [[ "$uri" == *"Chrome"* ]] || [[ "$uri" == *"chrome"* ]]; then
        echo -e "${GREEN}OK${NC} - Valid Chrome OMA-URI: $uri"
        return 0
    elif [[ "$uri" == "./Device/Vendor/MSFT/"* ]]; then
        echo -e "${YELLOW}WARN${NC} - Non-Chrome OMA-URI: $uri"
        ((WARNINGS++))
        return 0
    else
        echo -e "${RED}ERROR${NC} - Invalid OMA-URI format: $uri"
        ((ERRORS++))
        return 1
    fi
}

if command -v jq &> /dev/null; then
    # Extract all omaUri values
    jq -r '.. | .omaUri? // empty' "$INTUNE_FILE" 2>/dev/null | while read uri; do
        check_oma_uri "$uri"
    done
else
    # Fallback to grep
    grep -oE '"omaUri"\s*:\s*"[^"]*"' "$INTUNE_FILE" | sed 's/.*"omaUri"\s*:\s*"\([^"]*\)".*/\1/' | while read uri; do
        check_oma_uri "$uri"
    done
fi
echo ""

# Validate data types
echo "Validating data types..."

VALID_TYPES=("String" "Integer" "Boolean" "Base64" "DateTime" "XML")

if command -v jq &> /dev/null; then
    jq -r '.. | .dataType? // empty' "$INTUNE_FILE" 2>/dev/null | sort -u | while read dtype; do
        if [[ " ${VALID_TYPES[@]} " =~ " ${dtype} " ]]; then
            echo -e "${GREEN}OK${NC} - Valid data type: $dtype"
        else
            echo -e "${YELLOW}WARN${NC} - Unknown data type: $dtype"
            ((WARNINGS++))
        fi
    done
else
    grep -oE '"dataType"\s*:\s*"[^"]*"' "$INTUNE_FILE" | sed 's/.*"dataType"\s*:\s*"\([^"]*\)".*/\1/' | sort -u | while read dtype; do
        if [[ " ${VALID_TYPES[@]} " =~ " ${dtype} " ]]; then
            echo -e "${GREEN}OK${NC} - Valid data type: $dtype"
        else
            echo -e "${YELLOW}WARN${NC} - Unknown data type: $dtype"
        fi
    done
fi
echo ""

# List all settings
echo "OMA-URI Settings:"
if command -v jq &> /dev/null; then
    jq -r '.. | select(.displayName? and .omaUri?) | "  - \(.displayName): \(.omaUri)"' "$INTUNE_FILE" 2>/dev/null | head -20
else
    grep -E '"(displayName|omaUri)"' "$INTUNE_FILE" | head -20
fi
echo ""

# Security check
echo "Security checks..."

if grep -qi '"password"' "$INTUNE_FILE"; then
    echo -e "${YELLOW}WARN${NC} - Configuration may contain password settings"
    ((WARNINGS++))
else
    echo -e "${GREEN}OK${NC} - No password fields detected"
fi

if grep -qi 'private.*key\|secret' "$INTUNE_FILE"; then
    echo -e "${RED}ERROR${NC} - Configuration may contain sensitive keys!"
    ((ERRORS++))
else
    echo -e "${GREEN}OK${NC} - No obvious secrets detected"
fi
echo ""

# PowerShell validation script
echo "PowerShell validation command:"
echo ""
cat << 'PWSH'
# Run this in PowerShell to validate:
$config = Get-Content "enterprise/intune/BlockIOC-OMA-URI.json" | ConvertFrom-Json
$config.omaSettings | ForEach-Object {
    Write-Host "Setting: $($_.displayName)"
    Write-Host "  OMA-URI: $($_.omaUri)"
    Write-Host "  Type: $($_.dataType)"
    Write-Host ""
}
PWSH
echo ""

# Summary
echo "=========================================="
echo "Validation Summary"
echo "=========================================="
echo "File: $INTUNE_FILE"
echo "Size: $(wc -c < "$INTUNE_FILE" | tr -d ' ') bytes"
if [[ -n "$SETTING_COUNT" ]]; then
    echo "Settings: $SETTING_COUNT"
fi
echo ""

if [[ $ERRORS -gt 0 ]]; then
    echo -e "${RED}FAILED${NC} - $ERRORS error(s), $WARNINGS warning(s)"
    exit 1
else
    echo -e "${GREEN}PASSED${NC} - $WARNINGS warning(s)"
    exit 0
fi
