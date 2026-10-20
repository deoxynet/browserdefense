# Gate 3: Forensics Usefulness Validation Report

**Date:** 2026-01-09
**Status:** PASS
**Validated by:** browserdefenses-claude-2

## Executive Summary

The BrowserDefense forensics system has been validated against the Gate 3 criteria from `docs/go-no-go-checklist.md`. All three requirements pass:

| Requirement | Status | Notes |
|-------------|--------|-------|
| Blocked events include redirect chain + timestamp + destination | PASS | Full chain captured with deduplication and 20-hop limit |
| Forensics decrypt/view path works in under 2 minutes | PASS | Decryption under 50ms, viewer tool available |
| Data format is parseable and actionable | PASS | JSON structure compatible with SIEM export |

## Test Results

```
21 tests passed
- Required Fields Validation: 3 tests
- Redirect Chain Capture: 6 tests
- Timestamp Precision: 2 tests
- Encryption/Decryption Round-Trip: 5 tests
- SOC Analyst Actionability: 3 tests
- Performance Benchmarks: 3 tests
```

---

## 1. Forensics Data Fields

### Fields Captured

| Field | Type | Description | SOC Use Case |
|-------|------|-------------|--------------|
| `blockedUrl` | string | The URL that triggered the block | Primary IOC reference |
| `timestamp` | ISO 8601 | When the block occurred (ms precision) | Timeline reconstruction |
| `redirectChain` | string[] | Full navigation path (max 20 hops) | Attack source identification |
| `tabId` | number | Chrome tab identifier | Correlate multiple blocks |
| `frameId` | number | 0=main frame, >0=iframe | Identify drive-by attacks |
| `initiator` | string | Page that initiated navigation | Identify compromised referrer |
| `normalizedUrl` | string | Canonicalized URL for hash match | Verify IOC match accuracy |
| `reason` | string | Why blocked (e.g., "ioc_match") | Filter by block type |

### Sample Forensics Payload

```json
{
  "blockedUrl": "https://fake-invoice-portal.com/pay",
  "timestamp": "2026-01-09T10:30:00.123Z",
  "redirectChain": [
    "https://mail.google.com/mail/u/0/#inbox/xyz",
    "https://click.email-marketing.com/track?id=campaign123",
    "https://bit.ly/invoice-payment",
    "https://fake-invoice-portal.com/pay"
  ],
  "tabId": 42,
  "frameId": 0,
  "initiator": "https://mail.google.com",
  "normalizedUrl": "fake-invoice-portal.com/pay",
  "reason": "ioc_match"
}
```

### Gap Identified

- **User-Agent not captured**: The current implementation does not capture the browser user-agent string. This is a minor gap as Chrome extensions have limited access to this header in MV3.

---

## 2. Redirect Chain Capture

### Behavior Validated

| Scenario | Expected | Actual |
|----------|----------|--------|
| 3 redirects | Chain captured | PASS |
| 6+ redirects | All captured | PASS |
| 25 redirects | Limited to 20, keeps most recent | PASS |
| Duplicate URLs | Deduplicated | PASS |
| Cross-tab isolation | Chains don't leak between tabs | PASS |
| Chain cleared after capture | No contamination | PASS |

### Example: Phishing Attack Chain

```
User clicks email link:
  1. https://mail.google.com/mail/u/0/#inbox/xyz
  2. https://click.email-marketing.com/track?id=campaign123
  3. https://bit.ly/invoice-payment
  4. https://fake-invoice-portal.com/pay  <-- BLOCKED
```

This chain tells the SOC analyst:
- Attack came via email (Gmail initiator)
- Used email marketing tracker (potential compromised campaign)
- Used URL shortener to obscure destination
- Final target was a fake invoice portal

---

## 3. Encryption/Decryption Workflow

### Crypto Stack

- **Key Wrapping:** RSA-OAEP with SHA-256 (2048-bit keys)
- **Payload Encryption:** AES-256-GCM
- **IV Size:** 96 bits (recommended for GCM)

### Round-Trip Verified

1. Generate RSA keypair (customer side)
2. Encrypt forensics with public key (extension side)
3. Decrypt with private key (SOC analyst side)

All fields preserved exactly after decryption.

### Performance

| Operation | Target | Measured |
|-----------|--------|----------|
| Capture forensics | < 1ms | < 1ms |
| Encrypt payload | < 50ms | < 50ms |
| Decrypt payload | < 50ms | < 50ms |

### Security Verified

- Wrong private key fails decryption (throws error)
- Each record uses unique AES key (ephemeral)
- Each record uses unique IV

---

## 4. SOC Analyst Workflow

### Decrypt Forensics (Under 2 Minutes)

**Step 1: Access Forensics Viewer**
```
Open: tools/forensics-viewer/index.html
```

**Step 2: Load Private Key**
- Drag and drop `.jwk` file OR paste JWK JSON

**Step 3: Load Encrypted Forensics**
- Drag and drop exported JSON OR paste encrypted payload

**Step 4: Click "Decrypt Forensics"**
- View results in table format
- Export to JSON or CSV for SIEM import

### Export Formats

**JSON Export:**
```json
[
  {
    "blockedUrl": "https://evil.com/payload",
    "timestamp": "2026-01-09T10:30:00.123Z",
    "redirectChain": ["https://a.com", "https://evil.com/payload"],
    "initiator": "https://webmail.example.com",
    "reason": "ioc_match"
  }
]
```

**CSV Export:**
```csv
Timestamp,Blocked URL,Normalized URL,Redirect Chain,Initiator,Reason,Tab ID,Frame ID
2026-01-09T10:30:00.123Z,https://evil.com/payload,evil.com/payload,https://a.com -> https://evil.com/payload,https://webmail.example.com,ioc_match,42,0
```

---

## 5. Investigation Scenarios

### Scenario A: BEC (Business Email Compromise)

**Forensics captured:**
```json
{
  "blockedUrl": "https://fake-invoice-portal.com/pay",
  "initiator": "https://mail.google.com",
  "redirectChain": [
    "https://mail.google.com/...",
    "https://click.email-marketing.com/track?id=xxx",
    "https://bit.ly/invoice-payment",
    "https://fake-invoice-portal.com/pay"
  ]
}
```

**SOC Analysis:**
1. Attack vector: Email (Gmail initiator)
2. Campaign tracking: email-marketing.com (potential malvertising)
3. Obfuscation: bit.ly shortener
4. Payload: Fake invoice portal (credential theft)

**Action:** Block email campaign ID, report to email-marketing.com

### Scenario B: Compromised Website Drive-By

**Forensics captured:**
```json
{
  "blockedUrl": "https://malicious-ad.com/iframe-payload.js",
  "frameId": 5,
  "initiator": "https://news-site.com"
}
```

**SOC Analysis:**
1. `frameId > 0` indicates iframe (not main navigation)
2. Legitimate news site loaded malicious ad
3. No user click required (drive-by attack)

**Action:** Report to news-site.com, block ad network

### Scenario C: Watering Hole Attack

**Forensics captured:**
```json
{
  "blockedUrl": "https://c2-server.evil/beacon",
  "initiator": "https://internal-app.company.com",
  "redirectChain": [
    "https://internal-app.company.com/compromised-page",
    "https://c2-server.evil/beacon"
  ]
}
```

**SOC Analysis:**
1. Internal application is compromised
2. Redirecting to C2 server
3. Potential supply chain attack

**Action:** Isolate internal app, forensic analysis required

---

## 6. Validation Checklist

### Gate 3 Requirements

- [x] Blocked events include redirect chain
- [x] Blocked events include timestamp (ISO 8601, ms precision)
- [x] Blocked events include destination (blockedUrl + normalizedUrl)
- [x] Forensics decrypt/view works in under 2 minutes
- [x] Data format is parseable (JSON)
- [x] Data format is actionable (fields support investigation)

### Additional Validations

- [x] Redirect chain limited to 20 entries
- [x] Duplicate URLs in chain deduplicated
- [x] Chain isolation between tabs
- [x] Encryption with wrong key fails safely
- [x] Special characters in URLs preserved
- [x] Unicode in URLs preserved
- [x] Iframe blocks captured (frameId > 0)
- [x] Performance under targets

---

## 7. Recommendations

### For v1 (Current)

The forensics system is **GO** for SOC dogfooding. All core requirements met.

### For Future Iterations

1. **Add user-agent capture** - Helpful for identifying browser version exploits
2. **Add tab URL field** - The full URL of the tab where user was when blocked
3. **Add hostname extraction** - Pre-extract domain for easier SIEM correlation
4. **Add geo-IP lookup** - Optional enrichment for blocked domains

---

## Test Files

- `tests/validation/forensics-usefulness.test.ts` - 21 comprehensive tests
- `tools/forensics-viewer/index.html` - Decryption UI
- `tools/forensics-viewer/test-data.html` - Generate test keypair + encrypted data

## Conclusion

**Gate 3: PASS**

The forensics system captures actionable data for SOC incident response. The decrypt workflow is fast and the data format supports SIEM export. Ready for SOC dogfooding.
