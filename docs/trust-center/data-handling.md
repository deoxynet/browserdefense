# Data Handling

This document details what data BrowserDefense collects, processes, and stores—and what data we explicitly **cannot** access.

## Data Collection Summary

### What We Collect

| Data Category | Collected By | Stored Where | Can BrowserDefense Read It? |
|---------------|--------------|--------------|----------------------|
| Encrypted forensic blobs | Extension | Cloudflare R2 | **No** |
| Shadow detection fingerprints (hash-only, optional) | Extension (if enabled) | BrowserDefense analytics store | Yes (hash-only) |
| Org ID | Extension | Cloudflare R2 | Yes (routing/billing) |
| Timestamp | Extension | Cloudflare R2 | Yes (ordering) |
| Key version | Extension | Cloudflare R2 | Yes (multi-key support) |
| Blob size | Extension | Cloudflare R2 | Yes (storage metrics) |

### What We Do NOT Collect

| Data Category | Status | Why |
|---------------|--------|-----|
| **Keystrokes** | Never collected | No keyboard event listeners used |
| **Form values** | Never collected | We do not read input field contents |
| **Page content/text** | Never collected | Only structure (for hashing) is analyzed |
| **Images/media** | Never collected | Not part of DOM skeleton extraction |
| Plaintext URLs | Not transmitted | Blocked URLs are only inside encrypted forensics |
| Redirect chains | Not transmitted plaintext | Encrypted before transmission |
| User identifiers | Not transmitted plaintext | Encrypted before transmission |
| Non-blocked navigation | Not transmitted | Only block events and opt-in hashes are sent |
| Browsing history | Not transmitted | Local Bloom filter only (opt-in), never sent to servers |
| Page screenshots | Not transmitted (unless opt-in) | Encrypted if enabled |
| Customer IOC lists | Never seen plaintext | Hashed with customer salt |
| Customer private keys | Never transmitted | Generated locally, exported by customer |

## Detailed Data Tables

### Data We Store (on BrowserDefense Infrastructure)

| Field | Type | Purpose | Encrypted? |
|-------|------|---------|------------|
| `org_id` | UUID | Route forensics to correct customer | No |
| `key_version` | Integer | Support key rotation | No |
| `timestamp` | ISO 8601 | Ordering, TTL enforcement | No |
| `iv` | Base64 (12 bytes) | AES-GCM initialization vector | No (needed for decryption) |
| `wrapped_key` | Base64 (256 bytes) | RSA-OAEP encrypted AES key | Yes (by customer RSA key) |
| `ciphertext` | Base64 (variable) | AES-GCM encrypted payload | Yes (by ephemeral AES key) |

**What's inside `ciphertext` (we cannot see this):**

```json
{
  "blocked_url": "https://evil-phishing-site.com/login",
  "redirect_chain": [
    "https://legitimate-looking.com/click",
    "https://tracking.ad-network.com/redir",
    "https://evil-phishing-site.com/login"
  ],
  "timestamp": "2026-01-09T14:32:17.000Z",
  "user_context": {
    "tab_id": 1234,
    "initiator": "https://email-provider.com/inbox"
  },
  "matched_ioc": "HOST_ONLY",
  "extension_version": "1.2.3"
}
```

### Optional Shadow Detection (DOM Skeleton Hashing)

If enabled, the extension can upload hash-only structural fingerprints to support kit correlation and research. This data does **not** include URLs, content, or screenshots.

Shadow detection is disabled by default and must be explicitly enabled by organization policy.

**What DOM Skeleton Hashing Captures:**

| Captured | NOT Captured |
|----------|--------------|
| HTML tag hierarchy (e.g., `div > form > input`) | Page text content |
| Form structure (number of inputs) | Images or media |
| Input field types (`email`, `password`, `text`) | User-entered data |
| Form action URLs | Personal information |

**Example of transmitted data:**
```json
{
  "org_id": "org_xxx",
  "timestamp": "2026-01-09T14:32:17Z",
  "dom_skeleton_hash": "a1b2c3d4e5f6...",  // SHA-256, not reversible
  "feature_version": "2.0"
}
```

**What we DO NOT see:**
- The actual URL visited
- Any page content or text
- What the user typed
- Screenshots or images

### Optional Local History Bloom Filter

If enabled, the extension creates a **local-only** Bloom filter from browsing history to detect anomalous first-time visits.

| Property | Value |
|----------|-------|
| **Storage location** | Browser local storage only |
| **Transmitted to BlockIOC?** | **Never** |
| **Purpose** | Local anomaly scoring |
| **Data lifetime** | Deleted on extension uninstall |
| **Opt-in required?** | Yes |

**How it works:**
1. Extension builds a probabilistic set of previously visited domains
2. When visiting a new domain, checks if it's in the Bloom filter
3. First-time visits to suspicious-looking domains get higher anomaly scores
4. All processing is local; no history data is ever transmitted

**Privacy guarantee:** This feature exists purely for local decision-making. The Bloom filter is a probabilistic data structure that cannot be reversed to list the sites you've visited, and it never leaves your device

### Data We Do NOT Store

| Data | Why Not Stored |
|------|----------------|
| Customer private keys | Generated in browser, exported by customer |
| Customer salt | Distributed via GPO/MDM, never sent to us |
| Plaintext IOCs | Hashed before distribution (BYO-Trust) |
| Non-block browsing activity | Extension does not transmit non-block events |
| User credentials | Never collected |
| Form data | Never collected |
| Cookie contents | Never collected |
| Screenshots | Not stored unless enabled; only encrypted inside forensics |

## Data in the Browser Extension

### What the Extension Stores Locally

| Data | Storage | Purpose | Persists? |
|------|---------|---------|-----------|
| Hash set (IOCs) | `chrome.storage.local` | Blocking decisions | Yes |
| Pending forensics queue | `chrome.storage.local` | Retry failed uploads | Yes |
| Org configuration | `chrome.storage.managed` | Public keys, salt, endpoints | Yes (via GPO) |
| Block count | `chrome.storage.local` | Badge display | Yes |

### What the Extension Observes (but does NOT store/transmit)

| Data | Why Observed | Why Not Transmitted |
|------|--------------|---------------------|
| All navigation URLs | To check against blocklist | Only blocked URLs generate forensics; no URL transmission |
| Redirect chains | To capture context on blocks | Encrypted before transmission |
| Tab metadata | To provide initiator context | Encrypted before transmission |

If shadow detection is enabled, the extension may transmit **hash-only structural fingerprints** for correlation. No URLs or page content are included.

**Important distinction:** The extension must observe navigation requests to perform blocking. It only transmits data on block (encrypted), and only transmits hash-only structural fingerprints when shadow detection is enabled.

## Data Retention

### BrowserDefense-Managed Forensics

| Tier | Retention Period | Customer Action |
|------|-----------------|-----------------|
| Team | 30 days | Download before expiration |
| Business | 90 days | Download before expiration |

After the retention period, encrypted blobs are permanently deleted. We cannot recover them.

### Self-Hosted Forensics

Customers on the Business tier can configure their own forensics endpoint. In this mode:

- Forensics are sent directly to customer infrastructure
- BrowserDefense never receives or stores the data
- Retention is controlled entirely by the customer

## BYO-Trust Mode (Zero-Knowledge IOCs)

In BYO-Trust mode, customers manage their own IOC blocklists:

```
Customer's CI/CD Pipeline
         │
         ▼
┌─────────────────────────────────────┐
│  1. Customer creates IOC list       │
│     (plaintext, internal only)      │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  2. Hash IOCs with customer salt    │
│     SHA-256(canonical_url + salt)   │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  3. Encrypt feed with customer key  │
│     X25519 + AES-GCM envelope       │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  4. Upload to customer CDN or       │
│     BrowserDefense CDN (hashes only)      │
└─────────────────────────────────────┘
```

**What BrowserDefense sees:** SHA-256 hashes (not reversible to URLs).

**What BrowserDefense cannot derive:** The original URLs, domains, or IOC intelligence.

## Metadata Exposure (What We Can Infer)

We are transparent about metadata we can observe:

| Metadata | What We Can Infer | Mitigation |
|----------|-------------------|------------|
| Block count per org | Threat exposure level | Required for billing |
| Block timing | When threats were encountered | Required for forensics ordering |
| Forensic blob size | Approximate payload complexity | Inherent to storage |
| Blocklist size | Number of IOCs deployed | Hashes only, not plaintext |

This metadata exposure is acceptable for a security tool and is necessary for operational purposes (billing, storage management, abuse prevention).

## Data Subject Rights (GDPR Considerations)

### Right to Access

Customers can download their encrypted forensics at any time via the admin portal or API. They decrypt locally with their private key.

### Right to Deletion

Customers can request deletion of their encrypted blobs. We cannot selectively delete specific records (we don't know what's inside them), but we can delete all data associated with an org_id.

### Right to Portability

Forensic data is JSON. Customers decrypt it with standard tools using their RSA private key.

### Data Processing Agreement

Available upon request for customers requiring GDPR DPA.

## Third-Party Subprocessors

| Subprocessor | Purpose | Data Processed |
|--------------|---------|----------------|
| Cloudflare | CDN, Storage (R2), Edge compute | Encrypted blobs, org_id, timestamps |
| Stripe | Payment processing | Billing info (separate from product data) |

We do not share forensic data (encrypted or otherwise) with any other third parties.

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  USER'S BROWSER                                                              │
│                                                                             │
│  Browsing activity ─────────────────────────────────────────────────────┐   │
│        │                                                                 │   │
│        ▼                                                                 │   │
│  ┌─────────────────────────────────────┐                                │   │
│  │  Extension observes all navigation  │  NOT TRANSMITTED               │   │
│  │  (required for blocking)            │◀────────────────────────────────   │
│  └──────────────────┬──────────────────┘                                    │
│                     │                                                        │
│         ┌───────────┴───────────┐                                           │
│         │                       │                                           │
│     Not blocked             Blocked                                         │
│         │                       │                                           │
│         ▼                       ▼                                           │
│  ┌─────────────┐        ┌─────────────────────────────────────┐            │
│  │ No data     │        │  Capture + Encrypt forensics       │            │
│  │ transmitted │        │  (RSA-OAEP + AES-GCM)              │            │
│  └─────────────┘        └──────────────────┬──────────────────┘            │
│                                            │                                │
│                                            ▼                                │
│                                    ENCRYPTED BLOB                          │
│                                            │                                │
└────────────────────────────────────────────┼────────────────────────────────┘
                                             │
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  BROWSERDEFENSE R2 STORAGE                                                         │
│                                                                             │
│  We receive:                        │  We CANNOT see:                       │
│  • org_id                           │  • Plaintext URL                      │
│  • timestamp                        │  • Redirect chain                     │
│  • iv (for decryption)              │  • User context                       │
│  • wrapped_key (RSA encrypted)      │  • Any forensic detail                │
│  • ciphertext (AES encrypted)       │                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                             │
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  CUSTOMER'S SECURITY TEAM                                                    │
│                                                                             │
│  1. Download encrypted blob                                                 │
│  2. Decrypt with private RSA key (never shared with BrowserDefense)              │
│  3. View plaintext forensics in Forensics Viewer                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Summary

**The zero-knowledge claim is structural, not policy-based:**

1. We encrypt data with keys we don't have
2. We store encrypted blobs we cannot decrypt
3. We hash IOCs with salts we never receive
4. Private keys are generated locally and never transmitted

This architecture means that even if BrowserDefense's infrastructure were completely compromised, attackers would only obtain encrypted data they cannot decrypt.
