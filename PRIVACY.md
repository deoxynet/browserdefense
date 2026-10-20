# BrowserDefense Privacy Policy

**Last updated:** January 2026

BrowserDefense is a browser extension that protects you from phishing and malware. This privacy policy explains what data we collect, why, and how we protect your privacy.

## Our Privacy Promise

We built BrowserDefense with privacy as a core principle:

- **We never read your passwords or form inputs**
- **We never capture your keystrokes**
- **We never record what you type**
- **We never sell your data**

## What We Collect

### Always Collected (Required for Protection)

| Data | What It Is | Why We Need It |
|------|------------|----------------|
| **Page structure hash** | A fingerprint of how a webpage is built (not what it says) | To detect phishing kits that look like login pages |
| **Timestamp** | When you visited a page | To track when threats appear |

**Important:** The page structure hash is a one-way fingerprint. We can tell if two pages have the same structure, but we cannot reconstruct the original page from the hash.

### Never Collected

| Data | Status |
|------|--------|
| **Passwords** | Never collected |
| **Form inputs** | Never collected |
| **Keystrokes** | Never collected |
| **Page text content** | Never collected |
| **Images on pages** | Never collected |
| **Your browsing history** | Never transmitted (see opt-in below) |

### Opt-In Features (You Choose)

These features are **off by default**. You must explicitly enable them:

| Feature | What It Does | Data Involved |
|---------|--------------|---------------|
| **Screenshot capture** | Takes a picture of blocked pages for investigation | Screenshot image (watermarked) |
| **Form schema capture** | Records what fields a form has (not values) | Field names and types only |
| **Local history matching** | Uses your browsing history to detect anomalies | Stays on your device, never transmitted |

## What We Send to Our Servers

We send only two things:

1. **Page structure hash** - A 64-character code (like `a3f2b1c4...`)
2. **Timestamp** - When you visited

We do **not** send:
- The URL you visited
- Any page content
- Any personal information

This is called "zero-knowledge" architecture. Our servers know that *a page with structure X was seen at time T*, but they don't know *which page* or *who saw it*.

## How We Use This Data

1. **Detect phishing kits** - When many users see the same page structure, we can identify phishing campaigns
2. **Block threats faster** - Once a phishing kit is identified, we can protect all users
3. **No profiling** - We don't track individuals or build browsing profiles

## Data Storage

| Location | Data | Retention |
|----------|------|-----------|
| Your browser | Blocklist, settings, local cache | Until you uninstall |
| Our servers | Page structure hashes + timestamps | 90 days |

## Browser Permissions

BrowserDefense requests these permissions:

| Permission | Why We Need It |
|------------|----------------|
| `storage` | Store blocklist and settings locally |
| `webNavigation` | Detect when you navigate to a new page |
| `webRequest` | Check URLs against our blocklist |
| `tabs` | Redirect you to a warning page when blocking threats |
| `declarativeNetRequest` | Block known threats instantly |
| `<all_urls>` | Check any website (we can't protect you otherwise) |

## Your Rights

You can:
- **Disable the extension** at any time
- **Uninstall** to remove all local data
- **Opt out** of optional features
- **Request data deletion** by contacting us

## Changes to This Policy

We'll notify you of significant changes through the extension update notes.

## Contact

For privacy questions: privacy@browserdefense.com

---

## Technical Details (For the Curious)

### What is a "page structure hash"?

When you visit a webpage, we analyze its HTML structure - things like:
- How many forms are on the page
- What types of input fields exist (email, password, text)
- The hierarchy of HTML elements

We then create a SHA-256 hash of this structure. The hash is:
- **Deterministic**: Same structure = same hash
- **One-way**: You cannot reverse a hash to get the original structure
- **Privacy-preserving**: No text content, images, or personal data included

### Why this approach?

Phishing kits are templates that attackers reuse. A fake Microsoft login page looks structurally similar whether it's hosted on `evil1.com` or `evil9999.com`. By fingerprinting structure (not content), we can:

1. Detect new phishing domains instantly
2. Protect users without knowing what sites they visit
3. Maintain privacy while providing security

### Encryption

When you block a page, forensic data (if enabled) is encrypted client-side using:
- RSA-OAEP for key wrapping
- AES-256-GCM for payload encryption

Your organization holds the decryption key. We cannot read your forensic data.
