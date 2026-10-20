# Architecture Overview

This document describes BrowserDefense's system architecture, data flows, and security boundaries.

## System Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              YOUR ORGANIZATION                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │  Admin Browser   │    │  GPO / MDM       │    │  Key Vault       │      │
│  │  (Key Generator) │───▶│  (Policy Config) │    │  (Private Keys)  │      │
│  └──────────────────┘    └────────┬─────────┘    └──────────────────┘      │
│                                   │                                         │
│                                   ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────┐      │
│  │                     Employee Browsers                             │      │
│  │  ┌─────────────────────────────────────────────────────────────┐ │      │
│  │  │  BrowserDefense Extension (Service Worker)                        │ │      │
│  │  │                                                             │ │      │
│  │  │  • Hash-based IOC lookup (local)                           │ │      │
│  │  │  • Signature verification (customer public key)            │ │      │
│  │  │  • Forensics encryption (customer public key)              │ │      │
│  │  │  • Local persistent queue                                  │ │      │
│  │  └─────────────────────────────────────────────────────────────┘ │      │
│  └──────────────────────────────────────────────────────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    Encrypted forensics only
                    (on block events)
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BROWSERDEFENSE INFRASTRUCTURE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │  Cloudflare CDN  │    │  Cloudflare R2   │    │  Static Admin    │      │
│  │  (Blocklist)     │    │  (Encrypted      │    │  Pages (Keygen,  │      │
│  │                  │    │   Forensics)     │    │   Viewer)        │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                                                             │
│  What BrowserDefense sees: Encrypted blobs, metadata (timestamps, org_id),       │
│  optional hash-only fingerprints (if enabled)                              │
│  What BrowserDefense cannot see: Plaintext URLs, IOCs, forensic details          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### Browser Extension (Service Worker)

The extension runs as a Manifest V3 service worker in Chrome/Chromium browsers.

| Component | Function | Security Property |
|-----------|----------|-------------------|
| **Blocking Engine** | Intercepts navigation requests, checks against local hash set | All lookups are local; no network calls during blocking |
| **Hash Storage** | Binary-packed SHA-256 hashes in `chrome.storage.local` | Compact format avoids Chrome storage limits |
| **Crypto Module** | RSA-OAEP encryption, X25519 envelope decrypt | Uses native Web Crypto API (browser-audited) |
| **Forensics Queue** | Persistent queue with retry logic | Data survives offline periods and SW restarts |
| **Shadow Detection (optional)** | Hash-only DOM fingerprinting for kit correlation | No URLs or content transmitted |
| **Heartbeat Alarm** | 4.9-minute keepalive to prevent SW termination | Maintains blocking readiness |

### Admin Tools (Static HTML)

All admin tools run entirely in the browser. **Zero server calls.**

| Tool | Purpose | Data Flow |
|------|---------|-----------|
| **Key Generator** | Generate RSA + X25519 keypairs | Keys generated in browser, exported to admin |
| **Forensics Viewer** | Decrypt and view forensic records | Encrypted blob + private key (local decryption) |
| **IOC Encryptor** | Encrypt IOCs for consumer tier | Plaintext IOCs never sent to server |

### Infrastructure (Cloudflare)

| Service | Purpose | Data Stored |
|---------|---------|-------------|
| **Cloudflare CDN** | Serve signed blocklist manifests | Public blocklist files (hashes, not plaintext) |
| **Cloudflare R2** | Store encrypted forensics | Encrypted blobs only |
| **Cloudflare Pages** | Host static admin tools | HTML/JS (no server-side logic) |
| **Event-driven analytics (optional)** | Hash-only kit correlation | Hash-only fingerprints |

## Data Flow: Blocking

```
User clicks link
       │
       ▼
┌─────────────────────────────────────┐
│  Extension intercepts navigation    │
│  (chrome.webRequest.onBeforeRequest)│
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  Canonicalize URL                   │
│  • Lowercase host                   │
│  • Remove trailing dot              │
│  • Strip default ports              │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  Hash URL with org salt             │
│  SHA-256(canonical_url + ":" + salt)│
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  Check hash against local Set       │
│  (Binary-packed in chrome.storage)  │
└──────────────────┬──────────────────┘
                   │
       ┌───────────┴───────────┐
       │                       │
   Not Found                 Found
       │                       │
       ▼                       ▼
┌─────────────┐        ┌─────────────┐
│ Allow       │        │ Block +     │
│ navigation  │        │ Capture     │
│             │        │ forensics   │
└─────────────┘        └─────────────┘
```

## Data Flow: Shadow Detection (Optional)

```
Navigation
       │
       ▼
┌─────────────────────────────────────┐
│  DOM skeleton extraction            │
│  (structure only, no content)       │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  Hash DOM skeleton                  │
│  SHA-256(structure)                 │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  Upload hash-only fingerprint       │
│  (if enabled)                       │
└─────────────────────────────────────┘
```

Shadow detection uploads hash-only fingerprints only. No URLs, content, or screenshots are transmitted for shadow detection. Blocking remains local.

## Data Flow: Forensics Upload

```
Block event occurs
       │
       ▼
┌─────────────────────────────────────┐
│  Capture forensic payload           │
│  { url, redirect_chain, timestamp,  │
│    user_context, device_id }        │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  Generate ephemeral AES-256 key     │
│  (crypto.subtle.generateKey)        │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  Encrypt payload with AES-GCM       │
│  Random 96-bit IV per encryption    │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  Wrap AES key with RSA-OAEP         │
│  (Customer's public key)            │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  Upload to R2 (or customer endpoint)│
│  { org_id, iv, wrapped_key,         │
│    ciphertext, timestamp }          │
└─────────────────────────────────────┘
```

## Data Flow: Blocklist Update

```
Blocklist update available
       │
       ▼
┌─────────────────────────────────────┐
│  Fetch manifest from CDN            │
│  { headers, iv, ciphertext }        │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  Decrypt X25519 envelope            │
│  (Customer's private mesh key)      │
└──────────────────┬──────────────────┘
                   │
       ┌───────────┴───────────┐
       │                       │
   Invalid                   Valid
       │                       │
       ▼                       ▼
┌─────────────┐        ┌─────────────┐
│ Keep cached │        │ Fetch new   │
│ blocklist   │        │ hash buckets│
│ Log warning │        │ Update local│
└─────────────┘        └─────────────┘
```

## Security Boundaries

### Trust Boundary 1: Browser Extension

**Inside the boundary:**
- Plaintext URLs during navigation interception
- Decrypted forensic payloads (briefly, before encryption)
- Customer's public keys (for encryption/verification)
- Org salt (for IOC hashing)

**Never crosses the boundary:**
- Customer's private keys (stored externally)
- Plaintext forensics (encrypted before network transmission)

### Trust Boundary 2: BrowserDefense Infrastructure

**What we receive:**
- Encrypted forensic blobs
- Org ID (for routing)
- Timestamps (for ordering)
- Key version (for multi-key support)

**What we cannot access:**
- Plaintext URLs that were blocked
- Redirect chains
- User identifiers
- Any forensic content

### Trust Boundary 3: Customer Infrastructure

**Customer controls:**
- Private encryption key (for decrypting forensics)
- Mesh public key (for threat feed encryption)
- Salt (for IOC hashing)
- Forensics endpoint (can self-host)

## Deployment Modes

### Enterprise Mode (webRequestBlocking)

- Uses Chrome enterprise policy to enable `webRequestBlocking` permission
- Unlimited IOC capacity (RAM-based lookup)
- Synchronous blocking (no race conditions)
- Requires GPO/MDM deployment

### Consumer Mode (declarativeNetRequest)

- Uses Chrome's DNR API for blocking
- Subject to Chrome's 30k dynamic rule limit
- Works without enterprise policies
- IOCs compiled to DNR rules locally after decryption

## Supported Browsers

| Browser | Support | Notes |
|---------|---------|-------|
| Google Chrome | Full | Primary target |
| Microsoft Edge (Chromium) | Full | Same extension |
| Brave | Full | Same extension |
| Opera | Full | Same extension |
| Firefox | Not supported | MV3 implementation differs |
| Safari | Not supported | Different extension architecture |

## Network Dependencies

| Operation | Network Required | Fallback |
|-----------|-----------------|----------|
| Blocking decision | No | Local hash lookup always works |
| Forensics upload | Yes | Queued locally, retried automatically |
| Blocklist update | Yes | Cached blocklist used until update succeeds |
| Extension operation | No | Functions fully offline |
