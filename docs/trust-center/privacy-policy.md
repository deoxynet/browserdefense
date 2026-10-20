# Privacy Policy

**Last Updated:** January 2026

This privacy policy explains what data BrowserDefense collects, how we use it, and your rights regarding your information. BrowserDefense is designed with privacy as a core architectural principle, not an afterthought.

---

## Overview

BrowserDefense is a browser security extension that protects your organization from phishing and malware. We use a **zero-knowledge architecture** where sensitive data is encrypted before it leaves your browser. This document explains exactly what data we process and what we cannot access.

---

## Data We Collect

### 1. Encrypted Forensic Data (on block events)

When BrowserDefense blocks a malicious site, it captures forensic context and encrypts it **before transmission**:

| Data Captured | Purpose | Encrypted? |
|---------------|---------|------------|
| Blocked URL | Incident investigation | Yes (RSA-OAEP + AES-GCM) |
| Redirect chain | Attack path analysis | Yes |
| Timestamp | Timeline correlation | Yes |
| Tab context (initiator) | Attack vector analysis | Yes |
| Matched IOC type | Categorization | Yes |

**We cannot decrypt this data.** It is encrypted with your organization's public RSA key before transmission. Only your organization can decrypt it using your private key (which never leaves your systems).

### 2. DOM Skeleton Hash (optional, for phishing kit detection)

When shadow detection is enabled, BrowserDefense extracts a **structural fingerprint** of web pages to detect phishing kits:

| What We Hash | What We DO NOT Hash |
|--------------|---------------------|
| HTML tag hierarchy (e.g., `div > form > input`) | Page text content |
| Form structure (number of inputs, types) | Images or screenshots |
| Input field types (`email`, `password`, `text`) | User-entered data |
| Form action URLs (where forms submit to) | Personal information |

**This is a one-way hash (SHA-256).** We receive only the hash, not the underlying structure. This hash cannot be reversed to reconstruct the page.

**Example of what we see:**
```
SHA-256: a1b2c3d4e5f6...
Timestamp: 2026-01-09T14:32:17Z
Org ID: org_xxx
```

**Example of what we DO NOT see:**
```
URL: https://example.com/login
Page content: "Welcome to Example Corp..."
User data: [anything you typed]
```

### 3. Screenshot Capture (opt-in only)

Screenshot capture is **disabled by default** and requires explicit opt-in by your organization.

When enabled:
- Screenshots are taken **only after a block event**
- Screenshots are **encrypted client-side** before transmission
- Screenshots are **watermarked** with timestamp and block reason
- **We cannot view the screenshots** (encrypted with your key)

**This feature must be explicitly enabled via organization policy (GPO/MDM).**

### 4. Local History Bloom Filter (opt-in only, never transmitted)

When enabled, BrowserDefense can use your browsing history to build a **local-only** Bloom filter for anomaly detection:

| What This Does | Privacy Guarantee |
|----------------|-------------------|
| Creates a probabilistic data structure of sites you've visited | **Never transmitted to BrowserDefense servers** |
| Helps detect first-time visits to suspicious sites | Stored only in your browser |
| Used purely for local decision-making | Deleted when you uninstall the extension |

**This data never leaves your device.** It is used only for local anomaly scoring and is not transmitted anywhere.

---

## Data We Do NOT Collect

BrowserDefense explicitly does **not** collect:

| Data Type | Status | Explanation |
|-----------|--------|-------------|
| Keystrokes | **Never collected** | We do not use `keydown`, `keyup`, or `input` event listeners |
| Form values | **Never collected** | We do not read what you type into forms |
| Page content | **Never collected** | We do not capture or store page text, images, or media |
| Passwords | **Never collected** | We have no access to credential fields |
| Cookies | **Never collected** | We do not read or transmit cookie values |
| Non-blocked browsing | **Never collected** | Only block events generate forensics |
| Personal identifiers | **Never collected** | No names, emails, or user IDs are transmitted |

---

## How We Use Data

### Encrypted Forensics
- Stored in Cloudflare R2 until your organization downloads them
- Used only for your organization's incident response
- Automatically deleted after retention period (30-90 days depending on tier)

### DOM Skeleton Hashes
- Used to identify known phishing kits across all customers
- Enable detection of phishing pages on brand-new domains
- Power the analyst labeling workflow (true positive / false positive)
- Never reverse-engineered to reconstruct URLs or content

### Screenshots (when enabled)
- Stored encrypted alongside forensics
- Available only to your organization for incident investigation
- Subject to same retention policy as forensics

---

## Data Sharing

### We share data with:

| Third Party | Purpose | Data Shared |
|-------------|---------|-------------|
| Cloudflare | Storage infrastructure | Encrypted blobs only |
| Stripe | Payment processing | Billing info (separate system) |

### We do NOT share data with:
- Advertisers
- Data brokers
- Law enforcement (without valid legal process)
- Any other third parties

---

## Your Rights

### Access
Download your encrypted forensics anytime via the admin portal.

### Deletion
Request deletion of all data associated with your organization.

### Portability
Export forensics in standard JSON format.

### Opt-Out
Disable optional features (shadow detection, screenshot capture, history Bloom) at any time.

---

## Chrome Web Store Compliance

BrowserDefense complies with Chrome Web Store policies:

### Permissions Used

| Permission | Why Required |
|------------|--------------|
| `<all_urls>` | Block phishing on any domain (attackers use new domains constantly) |
| `storage` | Store blocklist and settings locally |
| `tabs` | Redirect to warning page on block |
| `webRequest` | Observe navigation for async blocking |

### Remote Code
BrowserDefense does **not** execute remote code. All extension code is bundled and reviewed during Chrome Web Store submission. We fetch only:
- Blocklist updates (data, not code)
- Threat intelligence hashes (data, not code)

---

## Changes to This Policy

We will notify users of material changes via:
- Email to organization admins
- In-extension notification
- Updated "Last Updated" date on this page

---

## Contact

**Privacy questions:** privacy@browserdefense.com
**Security vulnerabilities:** security@browserdefense.com
**General support:** support@browserdefense.com

---

## Summary

| Feature | Data Type | Transmitted? | Encrypted? | Opt-In Required? |
|---------|-----------|--------------|------------|------------------|
| URL blocking | Blocked URLs | Yes | Yes (zero-knowledge) | No (core feature) |
| Forensics capture | Block context | Yes | Yes (zero-knowledge) | No (core feature) |
| DOM fingerprinting | Structure hash | Yes | N/A (hash only) | Yes (shadow mode) |
| Screenshot capture | Page image | Yes | Yes (zero-knowledge) | Yes |
| History Bloom | Site visits | **No** | N/A | Yes |
| Keystroke logging | User input | **Never** | N/A | N/A |
| Content capture | Page text | **Never** | N/A | N/A |
