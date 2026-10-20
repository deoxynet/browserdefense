# Chrome Web Store Listing

This document contains the official Chrome Web Store listing content for BrowserDefense.

---

## Extension Name

**BrowserDefense**

## Short Description (132 characters max)

Protect your organization from phishing with zero-knowledge threat detection. Block malicious sites without compromising privacy.

## Detailed Description

### What is BrowserDefense?

BrowserDefense is an enterprise-grade browser security extension that protects your organization from phishing attacks and malicious websites. Unlike traditional security tools, BrowserDefense uses a privacy-first "zero-knowledge" architecture.

### How It Works

When you visit a webpage, BrowserDefense:
1. **URL Hash Check** - Checks the URL against a local, hashed IOC list (no network lookup required)
2. **DOM Skeleton Fingerprinting (opt-in)** - If shadow detection is enabled, analyzes page structure (tag hierarchy, form structure) to detect phishing kits. Only a SHA-256 hash of the structure is transmitted, never the actual content.
3. **Blocking** - Blocks the page if it matches a known threat
4. **Encrypted Forensics** - Captures block context (URL, redirect chain, timestamp) and encrypts it client-side before sending to your organization

### Key Features

**Instant Phishing Protection**
- Blocks known phishing sites before they can steal your credentials
- Detects phishing kits even on new, never-seen domains (when enabled)
- Updates automatically with the latest threat intelligence

**Zero-Knowledge Privacy**
- Never captures passwords, form inputs, or keystrokes
- Blocking decisions are local (no URL lookups)
- Any forensics are encrypted client-side before transmission
- Optional hash-only structural fingerprints in shadow mode

**Enterprise Ready**
- Centrally managed blocklists
- Encrypted forensics for incident response
- SOC team integration

### What We DON'T Do

BrowserDefense does NOT:
- **Read passwords or form inputs** - We never access what you type into any form field
- **Capture keystrokes** - No keyboard event listeners, no keystroke logging
- **Record page content** - Text, images, and media are never captured or stored
- **Take screenshots** - Unless explicitly enabled by your organization (opt-in only)
- **Track browsing history** - We only see blocked URLs; non-blocked navigation is never transmitted
- **Sell your data** - Zero data monetization, ever

### Optional Features (Require Explicit Opt-In)

These features are **disabled by default** and require explicit enablement by your organization:

| Feature | What It Does | Privacy Impact |
|---------|--------------|----------------|
| **DOM Skeleton Hashing** | Fingerprints page structure to detect phishing kits | Transmits only SHA-256 hash, not content |
| **Screenshot Capture** | Captures watermarked screenshot on block events | Encrypted before transmission; we cannot view |
| **Local History Analysis** | Uses browsing history for anomaly detection | **Never transmitted**; local-only Bloom filter |

### Permissions Explained

- **Read and change all your data on all websites**: Required to block threats on any site you visit and optionally fingerprint page structure.
- **Storage**: Store blocklist and settings locally in your browser.
- **Tabs**: Redirect you to a warning page when a threat is blocked.

---

## Privacy Practices Disclosure

### Data Collection Summary

| Data Type | Collected? | Transmitted? | Encrypted? | Opt-In Required? |
|-----------|------------|--------------|------------|------------------|
| Blocked URLs | Yes | Yes | **Yes** (zero-knowledge) | No (core feature) |
| Redirect chains | Yes | Yes | **Yes** (zero-knowledge) | No (core feature) |
| DOM skeleton hash | Yes (if enabled) | Yes | N/A (hash only) | **Yes** |
| Screenshots | Yes (if enabled) | Yes | **Yes** (zero-knowledge) | **Yes** |
| Local history Bloom | Yes (if enabled) | **No** | N/A | **Yes** |
| Keystrokes | **Never** | **Never** | N/A | N/A |
| Form values | **Never** | **Never** | N/A | N/A |
| Page content/text | **Never** | **Never** | N/A | N/A |

### What is DOM Skeleton Hashing?

When shadow detection is enabled, BrowserDefense analyzes **page structure only**:

**What we hash:**
- HTML tag hierarchy (e.g., `div > form > input`)
- Form structure (number of inputs, input types like `email`, `password`)
- Form action URLs

**What we DO NOT hash:**
- Page text or content
- Images
- User-entered data
- Personal information

The resulting SHA-256 hash is transmitted to detect known phishing kits. This hash **cannot be reversed** to reconstruct the page.

### What is Local History Analysis?

When enabled, BrowserDefense creates a local Bloom filter from your browsing history to detect first-time visits to suspicious domains. **This data never leaves your device** - it is used purely for local anomaly scoring.

### Data Usage

Collected data is used to:
- Block phishing and malware attacks
- Enable incident response (encrypted forensics)
- Improve threat detection across all customers (hash correlation only)

Data is **NOT** used for:
- Advertising
- User profiling
- Sale to third parties

### Data Sharing

| Data | Shared With | Purpose |
|------|-------------|---------|
| Encrypted forensics | Cloudflare R2 | Storage (we cannot decrypt) |
| DOM skeleton hashes | BrowserDefense analytics | Phishing kit detection (hash only) |
| Billing info | Stripe | Payment processing |

No data is shared with advertisers, data brokers, or other third parties.

---

## Single Purpose Description

BrowserDefense protects users from phishing and malware by blocking navigation to known malicious websites and optionally detecting phishing kits through privacy-preserving structural hashes.

---

## Host Permission Justification

BrowserDefense requires `<all_urls>` host permission because:

1. **Phishing can occur on any domain**: Attackers register new domains constantly. We cannot predict which domains will host phishing pages.

2. **Navigation blocking**: To protect users, we must be able to intercept navigation to malicious URLs regardless of domain.

3. **Optional structural fingerprinting**: If enabled, we analyze page structure to detect phishing kits.

Without this permission, BrowserDefense cannot provide comprehensive protection against phishing attacks.

---

## Remote Code Policy Compliance

BrowserDefense does NOT use remote code. All extension code is:
- Bundled in the extension package
- Reviewed during Chrome Web Store submission
- Does not execute code from external servers

The extension fetches:
- Blocklist updates (data only, not executable code)
- Threat intelligence (hash values, not code)

---

## Category

**Security**

## Language

English

---

## Screenshots

1. **Block page** - Shows the warning displayed when a threat is blocked
2. **Popup** - Shows the extension status and recent blocks
3. **Options** - Shows configuration settings

---

## Support Information

**Support email:** support@browserdefense.com
**Privacy policy URL:** https://browserdefense.com/privacy
**Terms of service URL:** https://browserdefense.com/terms
