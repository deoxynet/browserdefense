#!/bin/bash
# validate-admx.sh - Validate ADMX/ADML files for Windows Group Policy
#
# Usage: ./validate-admx.sh [admx_file] [adml_file]
#
# Validates:
# - XML syntax
# - Required ADMX elements
# - ADML string references
# - Policy registry paths

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ADMX_FILE="${1:-$REPO_ROOT/enterprise/admx/BlockIOC.admx}"
ADML_FILE="${2:-$REPO_ROOT/enterprise/admx/en-US/BlockIOC.adml}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "BlockIOC ADMX/ADML Validation"
echo "=========================================="
echo ""

ERRORS=0
WARNINGS=0

# Check files exist
echo "Checking files exist..."
if [[ ! -f "$ADMX_FILE" ]]; then
    echo -e "${RED}ERROR: ADMX file not found: $ADMX_FILE${NC}"
    exit 1
fi

if [[ ! -f "$ADML_FILE" ]]; then
    echo -e "${RED}ERROR: ADML file not found: $ADML_FILE${NC}"
    exit 1
fi
echo -e "${GREEN}OK${NC} - Files found"
echo ""

# Validate XML syntax
echo "Validating XML syntax..."

if command -v xmllint &> /dev/null; then
    if xmllint --noout "$ADMX_FILE" 2>/dev/null; then
        echo -e "${GREEN}OK${NC} - ADMX XML is valid"
    else
        echo -e "${RED}ERROR${NC} - ADMX XML is invalid"
        xmllint --noout "$ADMX_FILE"
        ((ERRORS++))
    fi

    if xmllint --noout "$ADML_FILE" 2>/dev/null; then
        echo -e "${GREEN}OK${NC} - ADML XML is valid"
    else
        echo -e "${RED}ERROR${NC} - ADML XML is invalid"
        xmllint --noout "$ADML_FILE"
        ((ERRORS++))
    fi
else
    echo -e "${YELLOW}WARN${NC} - xmllint not found, using basic check"
    # Basic XML check with grep
    if grep -q '<?xml version' "$ADMX_FILE" && grep -q '</policyDefinitions>' "$ADMX_FILE"; then
        echo -e "${GREEN}OK${NC} - ADMX appears well-formed"
    else
        echo -e "${RED}ERROR${NC} - ADMX may be malformed"
        ((ERRORS++))
    fi
fi
echo ""

# Check required ADMX elements
echo "Checking required ADMX elements..."

check_element() {
    local file="$1"
    local element="$2"
    local desc="$3"

    if grep -q "<$element" "$file"; then
        echo -e "${GREEN}OK${NC} - Found <$element> ($desc)"
    else
        echo -e "${RED}ERROR${NC} - Missing <$element> ($desc)"
        ((ERRORS++))
    fi
}

check_element "$ADMX_FILE" "policyDefinitions" "root element"
check_element "$ADMX_FILE" "policyNamespaces" "namespace definitions"
check_element "$ADMX_FILE" "categories" "policy categories"
check_element "$ADMX_FILE" "policies" "policy definitions"
echo ""

# Check ADML string resources
echo "Checking ADML string resources..."

check_element "$ADML_FILE" "policyDefinitionResources" "root element"
check_element "$ADML_FILE" "stringTable" "string table"
check_element "$ADML_FILE" "presentationTable" "presentation table"
echo ""

# Extract and validate string references
echo "Validating string references..."

# Extract string IDs from ADMX
ADMX_STRINGS=$(grep -oE '\$\(string\.[^)]+\)' "$ADMX_FILE" | sort -u | sed 's/\$(string\.\([^)]*\))/\1/g')

# Extract defined strings from ADML
ADML_STRINGS=$(grep -oE 'id="[^"]*"' "$ADML_FILE" | sed 's/id="//g; s/"//g' | sort -u)

MISSING=0
for str in $ADMX_STRINGS; do
    if ! echo "$ADML_STRINGS" | grep -q "^${str}$"; then
        echo -e "${RED}ERROR${NC} - Missing ADML string: $str"
        ((MISSING++))
        ((ERRORS++))
    fi
done

if [[ $MISSING -eq 0 ]]; then
    echo -e "${GREEN}OK${NC} - All string references resolved"
fi
echo ""

# Count policies
echo "Policy summary..."
POLICY_COUNT=$(grep -c '<policy ' "$ADMX_FILE" || echo "0")
echo "Total policies defined: $POLICY_COUNT"
echo ""

# List policies
echo "Policies found:"
grep -oE 'name="[^"]*"' "$ADMX_FILE" | grep -v 'namespace\|prefix' | head -20 | while read line; do
    name=$(echo "$line" | sed 's/name="//g; s/"//g')
    echo "  - $name"
done
echo ""

# Check registry paths
echo "Checking registry paths..."
REG_PATHS=$(grep -oE 'key="[^"]*"' "$ADMX_FILE" | sed 's/key="//g; s/"//g' | sort -u)

for path in $REG_PATHS; do
    if [[ "$path" == *"Google\Chrome"* ]]; then
        echo -e "${GREEN}OK${NC} - Valid Chrome policy path: $path"
    else
        echo -e "${YELLOW}WARN${NC} - Non-Chrome registry path: $path"
        ((WARNINGS++))
    fi
done
echo ""

# Summary
echo "=========================================="
echo "Validation Summary"
echo "=========================================="
echo "ADMX File: $ADMX_FILE"
echo "ADML File: $ADML_FILE"
echo "Policies: $POLICY_COUNT"
echo ""

if [[ $ERRORS -gt 0 ]]; then
    echo -e "${RED}FAILED${NC} - $ERRORS error(s), $WARNINGS warning(s)"
    exit 1
else
    echo -e "${GREEN}PASSED${NC} - $WARNINGS warning(s)"
    exit 0
fi
