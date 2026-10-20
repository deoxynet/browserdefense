# QA Validation Scripts

Scripts for validating BlockIOC enterprise deployment exports.

## Quick Start

```bash
# Run all validations
./scripts/qa/validate-all.sh

# Or run individually
./scripts/qa/validate-admx.sh
./scripts/qa/validate-mobileconfig.sh
./scripts/qa/validate-intune.sh
```

## Scripts

### validate-all.sh

Runs all validation scripts and provides a summary.

```bash
./scripts/qa/validate-all.sh
```

### validate-admx.sh

Validates Windows ADMX/ADML files for Group Policy deployment.

```bash
./scripts/qa/validate-admx.sh [admx_file] [adml_file]

# Default files:
#   enterprise/admx/BlockIOC.admx
#   enterprise/admx/en-US/BlockIOC.adml
```

**Checks:**
- XML syntax validation
- Required ADMX elements (policyDefinitions, namespaces, categories, policies)
- ADML string resource references
- Chrome policy registry paths

**Dependencies:**
- `xmllint` (optional, for full XML validation)

### validate-mobileconfig.sh

Validates Apple Configuration Profile for macOS MDM deployment.

```bash
./scripts/qa/validate-mobileconfig.sh [mobileconfig_file]

# Default file:
#   enterprise/macos/BlockIOC.mobileconfig
```

**Checks:**
- Plist syntax validation
- Required payload keys (PayloadIdentifier, PayloadType, etc.)
- Chrome extension settings presence
- Security checks (no embedded secrets)
- Signature validation (on macOS)

**Dependencies:**
- `plutil` (macOS built-in)
- `security` (macOS built-in, optional)

### validate-intune.sh

Validates Microsoft Intune OMA-URI configuration.

```bash
./scripts/qa/validate-intune.sh [json_file]

# Default file:
#   enterprise/intune/BlockIOC-OMA-URI.json
```

**Checks:**
- JSON syntax validation
- OMA-URI structure
- Chrome policy paths
- Data type validation
- Security checks

**Dependencies:**
- `jq` (recommended) or `python3` or `node`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All validations passed |
| 1 | One or more validations failed |

## CI Integration

Add to your CI pipeline:

```yaml
# GitHub Actions example
- name: Validate Enterprise Exports
  run: ./scripts/qa/validate-all.sh
```

## Full QA Guide

For comprehensive QA procedures including manual testing on enterprise infrastructure, see:

- [Enterprise Export QA Guide](../../docs/qa/ENTERPRISE-EXPORT-QA.md)

## Related

- [Enterprise Policy Setup](../enterprise-policy-setup/README.md)
- [ADMX Export Module](../../src/deployment/admx.ts)
- [mobileconfig Export Module](../../src/deployment/mobileconfig.ts)
- [Intune Export Module](../../src/deployment/intune.ts)
