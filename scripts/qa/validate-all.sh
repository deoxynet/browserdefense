#!/bin/bash
# validate-all.sh - Run all enterprise export validations
#
# Usage: ./validate-all.sh
#
# Runs validation for:
# - ADMX (Windows Group Policy)
# - mobileconfig (macOS)
# - Intune JSON (Microsoft Endpoint Manager)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         BlockIOC Enterprise Export Validation Suite          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

TOTAL_ERRORS=0
TOTAL_WARNINGS=0
RESULTS=()

run_validation() {
    local name="$1"
    local script="$2"

    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Running: $name${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    if [[ -x "$script" ]]; then
        if "$script"; then
            RESULTS+=("${GREEN}PASS${NC} - $name")
        else
            RESULTS+=("${RED}FAIL${NC} - $name")
            ((TOTAL_ERRORS++))
        fi
    else
        echo -e "${YELLOW}SKIP${NC} - Script not found or not executable: $script"
        RESULTS+=("${YELLOW}SKIP${NC} - $name")
        ((TOTAL_WARNINGS++))
    fi
}

# Make scripts executable
chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null || true

# Run validations
run_validation "ADMX (Windows Group Policy)" "$SCRIPT_DIR/validate-admx.sh"
run_validation "mobileconfig (macOS MDM)" "$SCRIPT_DIR/validate-mobileconfig.sh"
run_validation "Intune JSON (Microsoft)" "$SCRIPT_DIR/validate-intune.sh"

# Summary
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                     Validation Summary                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

for result in "${RESULTS[@]}"; do
    echo -e "  $result"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $TOTAL_ERRORS -gt 0 ]]; then
    echo -e "${RED}Overall: FAILED${NC} - $TOTAL_ERRORS validation(s) failed"
    exit 1
else
    echo -e "${GREEN}Overall: PASSED${NC} - All validations successful"
    exit 0
fi
