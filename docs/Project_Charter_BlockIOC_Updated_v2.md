# Project Charter: BlockIOC

## Project Name
**BlockIOC** — blockioc.com

## Tagline
Block IOCs at the browser. Zero-Knowledge forensics. Your keys, your data.

---

## ⚠️ IMPLEMENTATION REVIEW: CRITICAL FINDINGS

**Status:** ~80% locked, 20% requires validation POCs + wording fixes  
**Review Date:** January 2026

### Summary Assessment

The core thesis is strong: browser-level blocking + zero-knowledge forensics + SOC-first standalone pilot is a clean, credible angle. However, three foundational assumptions need immediate validation before building further.

### P0 Validation Required

| Issue | Current Assumption | Reality Check |
|-------|-------------------|---------------|
| **Threat feed crypto** | X25519 available in WebCrypto | Requires a minimum Chrome version and a fail-closed runtime check |
| **Blocklist storage** | `Array.from(set)` in `chrome.storage.local` | Will blow up at scale—JSON overhead + hex strings + 10MB default limit |
| **Consumer tier zero-knowledge** | "We never see plaintext IOCs" + DNR rules | Internally inconsistent—DNR cannot consult salted-hash Set |

### Critical Fixes Before Building

#### 1. X25519 in WebCrypto: Enforce Minimum Chrome Version

**Problem:** X25519 availability must be validated across target Chrome versions.

**Fix:**
- **Require a minimum Chrome version** in deployment guidance.
- **Fail closed** if X25519 is missing (no threat feed decrypt).
- **Surface clear errors** to avoid silent failures.

**Why this matters:** The entire BYO-Trust story lives or dies on "verification always works." If verify fails, updates must stop and the failure must be visible.

#### 2. Compact Storage Format Required

**Problem:** Current approach serializes as JSON hex strings:
```javascript
// BAD - will hit limits and perf walls
await chrome.storage.local.set({
  blocklist_hashes: Array.from(blocklist)  // 100k × 64-char hex strings
})
```

**Fix (Pick One):**
- **Binary snapshot:** Store hashes as raw 32-byte values in ArrayBuffer, base64 encode
- **Hash truncation:** Truncate to 128 bits (16 bytes) — same collision argument as "SHA-256 won't collide"
- **IndexedDB:** For streaming load at scale
- **`unlimitedStorage` permission:** + still store compactly (enterprise deployments accept this)

**Note:** Memory estimates in current docs are inconsistent (one place says 100k hashes ~10 MB, another says ~100 MB). Treat as placeholders until measured.

#### 3. Consumer Tier Zero-Knowledge Mechanics

**Problem:** DNR blocks by matching URL patterns/rules. It cannot consult a salted-hash Set. Current docs simultaneously claim:
- "We store only salted hashes; plaintext IOCs never touch our servers"
- "Consumer tier uses DNR rules updated from rules.json"

These can only both be true if rules.json is NOT derived from customer plaintext, OR it's derived but built locally after decryption.

**Fix (Encrypted Distribution + Local Compile):**
```
Upload: Analyst sends hash-only to oracle (preserves zero-knowledge)
Distribution: Server stores encrypted IOC plaintext or encrypted "rule deltas"
Endpoint: Decrypts with org key → compiles DNR rules → applies via updateDynamicRules
```

This preserves the zero-knowledge claim (server sees ciphertext only) while letting consumer tier block org-specific IOCs.

---

### Messaging Fixes (Remove Brittle Claims)

| Current Claim | Suggested Revision |
|--------------|-------------------|
| "Zero false positives" | "Exact-match blocking on normalized indicators (no probabilistic filters)" |
| "Backend infrastructure: none (static CDN + FCM)" | "No always-on compute for lookups; distribution is static + event-driven" |
| "CrowdStrike can't copy because closed source / phones home everything" | "Incumbents could build this, but it's strategically off-model: it reduces their telemetry moat and complicates their platform economics" |
| "Fail open" | "Protection continues using last-known-good blocklist; updates queue" (add optional "paranoid mode" policy knob) |

---

### Additional Sharp Edges

#### 4. Redirect Chain Forensics — Clarify Local Observation

**Issue:** "Redirect chain" capture is valuable, but requires local observation via `webRequest` events. Trust Center language should be precise:

**Recommended Trust Center language:**
> "We may observe request/redirect metadata locally to compute the redirect chain, but we only transmit encrypted forensics on block."

That's honest and still strong.

#### 5. Canonicalization Spec Required

**Issue:** Hash match is exact only after you normalize the input identically everywhere.

**Required: Write a "Canonicalization RFC" covering:**
- Punycode handling for IDNs
- Lowercase host
- Strip trailing dot
- Default ports (80/443)
- IPv6 bracket normalization
- IOC scope: host only? host+path? full URL?
- eTLD+1 vs full host (phishing often uses subdomains)

If you hash `evil.com` but the clicked URL is `http://evil.com.:80/%2e%2e/` and normalization differs between "add IOC" and "check request," you'll miss blocks. Treat canonicalization as a security boundary.

#### 6. "Fail Open" Reframe

**Issue:** Some security buyers will hear "fail open" and flinch.

**Reframe as:**
- "Protection continues using last-known-good blocklist; updates queue"
- **Optional:** Policy knob for "paranoid mode" customers (fail-closed on update verification failure only, not on network outage)

---

## P0 Validation POCs (Go/No-Go Tests)

These are the weekend tests that decide everything. No extra theory—just build and measure.

### POC 1: MV3 Enterprise Mode Gating

Force-install an MV3 extension via policy and confirm:
- [ ] `webRequestBlocking` works as expected in that configuration
- [ ] Service worker wake latency is acceptable
- [ ] You can block synchronously and still fire async forensics

### POC 2: Signature Verify Reality

On Chrome Stable + a couple older enterprise versions:
- [ ] Test `crypto.subtle` X25519 across target Chrome versions
- [ ] Add runtime check and explicit error if X25519 is missing

**Decision:** Ship X25519 for threat feeds and require compatible Chrome versions.

### POC 3: Storage/Perf Baseline

Load 100k / 300k / 1M hashes using the actual storage format you intend.

Measure:
- [ ] Cold start time to "ready to block"
- [ ] Memory usage
- [ ] Time to apply a 1k delta

Use this to set real limits and kill the contradictory tables.

---

## Red-Team: Commercial Failure Modes

| Failure Mode | Mitigation |
|-------------|------------|
| **Standalone Mode is still too annoying** (analysts paste salts/keys, fragile, pilots stall) | Make standalone config a single import file (JSON) that includes org_id + endpoints + public key + salt. Less copy-paste. |
| **"Zero-knowledge" triggers compliance questions anyway** | Keep your $15k "questionnaire tier." That's a clean filter. Don't oversell "no DPA needed" universally. |
| **Competitors don't need to copy—customers decide "we already have SWG"** | Hammer the remote worker + no VPN + fast IOC block workflow. That's your sharpest differentiated painkiller. |

---

## Problem Statement
SOC teams need to block IOCs fast. Current options are:
- **Slow:** DNS sinkholes, firewall rules — require VPN or on-prem
- **Expensive:** Enterprise browsers at $50k+ with 6-month deployments
- **Blind spots:** Remote workers not on VPN

When an analyst triages a phishing report from the abuse inbox, there's no quick way to block the malicious URL across the entire org — especially remote workers on managed devices — and capture forensic evidence when users click.

---

## Solution
A browser extension (uBlock Origin fork, MV3 compliant) that:
- Blocks IOCs at the browser level in near real-time
- **Dual architecture:** Consumer (Chrome Web Store) uses DNR rules; Enterprise (policy-installed) uses `webRequestBlocking` with in-memory Set (unlimited IOCs)
- Captures forensics **on block only**: redirect chain, timestamp, destination
- **Encrypts all data client-side** before sending to cloud (Zero-Knowledge)
- Deploys via **Standalone Mode** (manual config, no IT required) or GPO/MDM (enterprise rollout)
- Works on any managed device: corporate or remote (no VPN required)

---

## Target User

| Role | Need | Entry Point |
|------|------|-------------|
| **SOC Analyst** (Primary) | Block phishing IOCs fast, get evidence | Free tier, word of mouth |
| **SOC Manager** (Buyer) | Protect remote workers, close incidents faster | Team adopts → manager pays |
| **GRC Analyst** (Secondary) | Check NIST SI-4(24) box | Google, compliance content |

**Disqualified if:** They don't know what an IOC is.

### The Buyer ≠ Installer Problem (Addressed)

**The Reality:** SOC Analysts can't deploy GPOs. They lack Domain Admin or Intune/Jamf privileges. If an analyst pays $4k on a credit card and walks to IT asking for a fleet-wide GPO push, they'll get: *"Open a ticket."*

**The Solution:** Standalone Mode allows manual configuration via the extension's options page — no GPO required for initial pilot. See **Deployment Strategy: The SOC-First Wedge** below.

---

## Key Differentiators

| Feature | BlockIOC | Island/LayerX ($50k+) | CrowdStrike/EDR |
|---------|----------|----------------------|-----------------|
| Deployment | **Standalone (5 min) or GPO/MDM** | Full browser replacement | Heavy agent |
| Price | $4,000/year self-serve | $50k+ enterprise sales | $50k+ |
| Focus | SOC analyst workflow | CISO/IT-driven DLP | Everything |
| Forensics | Redirect chain + attribution | Limited/none | Phones home everything |
| Remote workers | Works on managed devices | Requires managed browser | Requires agent |
| Blocklist mgmt | Git commit = audit trail | Proprietary console | Vendor-controlled |
| Procurement | Credit card, instant | 6-month sales cycle | 6-month sales cycle |
| **IT Required for Pilot** | **✗ No (Standalone Mode)** | ✓ Yes | ✓ Yes |
| **Blocking Architecture** | **Consumer: DNR rules / Enterprise: in-memory Set** | Proprietary | Agent-based |
| **IOC Limit** | **Consumer: ~30k / Enterprise: Unlimited (RAM)** | Unknown | Vendor-limited |
| **Update Latency** | **~2 seconds (FCM push)** | Minutes-hours | Agent-dependent |
| **Backend Infrastructure** | **No always-on compute; static CDN + event-driven** | Active servers | Heavy infrastructure |
| **Key Resilience** | **Customer-managed (JWK files in 1Password)** | Vendor-managed | Vendor-managed |
| **Failure Mode** | **Stale-protect (last-known-good blocklist continues)** | Unknown | Agent-dependent |
| **Supply Chain Security** | **BYO-Trust: Customer signs own blocklist updates** | Vendor-signed | Vendor-signed |
| Vendor risk | Self-serve Trust Center | Months of questionnaires | Months of questionnaires |
| **Data privacy** | **Zero-Knowledge (full local lookup)** | Vendor sees all | Vendor sees all |
| **Open source** | **Extension is GPL** | Closed source | Closed source |
| **Coverage Scope** | **Layer 7 (HTTP/HTTPS)** | Full stack | Full stack |

### Coverage Scope Definition

BlockIOC operates at the **Application Layer (Layer 7)**:

| Traffic Type | BlockIOC Coverage | Complementary Solution |
|--------------|-------------------|----------------------|
| HTTP/HTTPS web requests | ✓ Full coverage | — |
| DNS queries | ✗ Out of scope | DNS sinkhole |
| Raw TCP/UDP | ✗ Out of scope | Network firewall |
| WebSocket | ✓ Initial handshake only | — |

**Why this is a feature, not a bug:**
> "We don't slow down your DNS resolution or break your UDP VPNs. We focus on the web attack surface where phishing actually happens—the click."

### Competitive Defense: Why Incumbents Won't Copy This

> "Incumbents could build this, but it's strategically off-model: it reduces their telemetry moat and complicates their platform economics."

**The Moat:**
1. **Open Source Auditability** — Security teams can read every line of code. "Don't trust us? Read `background.js` line 145 where we encrypt."
2. **Zero-Knowledge Architecture** — We are not designed to access customer forensic data. CrowdStrike's entire business model requires seeing customer data.
3. **Price Point** — $4k/year is below the radar. Not worth CrowdStrike's sales team's time.
4. **Different Buyer + Deployment Wedge** — SOC analysts buy it with a credit card and deploy Standalone Mode immediately. No IT ticket. By the time IT is involved, the SOC team has real data proving the tool works.
5. **Enterprise "God Mode"** — Policy-installed extensions get `webRequestBlocking` (infinite IOCs, full JS logic). Same zero-knowledge privacy, more power.
6. **BYO-Trust (Supply Chain Isolation)** — Enterprise customers sign their own blocklist updates. Even if BlockIOC is compromised, enterprise customers are unaffected.
7. **Real-Time Push ($0 infrastructure)** — Firebase Cloud Messaging delivers updates in ~2 seconds. Google pays for the socket.

---

## Technical Implementation

### Extension Manifests (MV3)

**Two manifests from the same codebase:**

#### Consumer Manifest (Chrome Web Store)

```json
{
  "manifest_version": 3,
  "name": "BlockIOC Agent",
  "version": "1.0.0",
  "permissions": [
    "declarativeNetRequest",
    "declarativeNetRequestWithHostAccess",
    "storage",
    "alarms",
    "gcm"
  ],
  "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "background.js" },
  "action": { "default_popup": "popup.html" },
  "storage": { "managed_schema": "schema.json" }
}
```

#### Enterprise Manifest (Policy-Installed via GPO/MDM)

```json
{
  "manifest_version": 3,
  "name": "BlockIOC Agent (Enterprise)",
  "version": "1.0.0",
  "permissions": [
    "webRequest",
    "webRequestBlocking",
    "storage",
    "unlimitedStorage",
    "alarms",
    "gcm",
    "scripting"
  ],
  "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "background.js" },
  "action": { "default_popup": "popup.html" },
  "storage": { "managed_schema": "schema.json" }
}
```

**Notes:**
- Enterprise manifest adds `unlimitedStorage` for large blocklists
- `webRequestBlocking` — Only allowed for policy-installed extensions

---

### Blocklist Storage Format (Revised)

**CRITICAL: Do NOT use naive JSON serialization.**

```javascript
// ❌ BAD - will blow up at scale
await chrome.storage.local.set({
  blocklist_hashes: Array.from(blocklist)  // JSON overhead kills you
});

// ✅ GOOD - binary compact format
async function storeBlocklist(hashes) {
  // Option A: Concatenated binary (32 bytes per hash)
  const buffer = new ArrayBuffer(hashes.size * 32);
  const view = new Uint8Array(buffer);
  let offset = 0;
  for (const hexHash of hashes) {
    const bytes = hexToBytes(hexHash);
    view.set(bytes, offset);
    offset += 32;
  }
  
  // Store as base64 (still overhead, but ~50% vs hex strings)
  const base64 = btoa(String.fromCharCode(...view));
  await chrome.storage.local.set({ blocklist_binary: base64 });
}

// Option B: Truncate to 128 bits (16 bytes) if collision risk acceptable
// Same SHA-256 security argument with different constants
```

**Storage Comparison (100k hashes):**

| Format | Size | Notes |
|--------|------|-------|
| JSON hex strings | ~7-8 MB | JSON overhead + 64 chars each |
| Binary base64 | ~4.3 MB | 32 bytes × 100k, base64 encoded |
| Binary truncated (128-bit) | ~2.1 MB | 16 bytes × 100k, base64 encoded |
| IndexedDB binary | ~3.2 MB | No base64 overhead |

---

### URL Canonicalization Specification

**CRITICAL: Treat canonicalization as a security boundary.**

All IOC hashing and URL checking MUST use identical normalization:

```javascript
function canonicalizeUrl(url) {
  const parsed = new URL(url);
  
  // 1. Lowercase scheme and host
  let canonical = parsed.protocol.toLowerCase() + '//';
  canonical += parsed.hostname.toLowerCase();
  
  // 2. Remove trailing dot from hostname
  canonical = canonical.replace(/\.$/, '');
  
  // 3. Remove default ports
  if ((parsed.protocol === 'http:' && parsed.port === '80') ||
      (parsed.protocol === 'https:' && parsed.port === '443')) {
    // omit port
  } else if (parsed.port) {
    canonical += ':' + parsed.port;
  }
  
  // 4. Normalize path (decode then re-encode)
  canonical += normalizePath(parsed.pathname);
  
  // 5. Sort query parameters (optional, for full URL IOCs)
  if (parsed.search) {
    const params = new URLSearchParams(parsed.search);
    params.sort();
    canonical += '?' + params.toString();
  }
  
  // 6. Strip fragment
  // (fragments are not sent to server, don't include in IOC)
  
  return canonical;
}

// IOC scope options (configurable per org):
// - HOST_ONLY: canonicalize and hash hostname only
// - HOST_PATH: hostname + path (no query)
// - FULL_URL: hostname + path + sorted query
```

**Punycode/IDN Handling:**
```javascript
// Always convert to punycode for hashing
const punyHost = new URL(url).hostname;  // Browser auto-converts IDN to punycode
```

---

### Threat Feed Decrypt (X25519)

```javascript
async function decryptThreatFeed(envelope, privateKeyJwk) {
  const key = await crypto.subtle.importKey(
    "jwk", privateKeyJwk,
    { name: "X25519" },
    false, ["deriveBits"]
  );
  // deriveBits + HKDF -> AES-GCM -> decrypt payload
}
```

---

### Consumer Tier: Encrypted Distribution + Local Compile

**To maintain zero-knowledge claim while supporting org-specific IOCs:**

```javascript
// Server stores: encrypted rule deltas (server sees ciphertext only)
// Client flow:
async function updateConsumerBlocklist(encryptedRules, orgKey) {
  // 1. Decrypt rules locally
  const decryptedRules = await decryptWithOrgKey(encryptedRules, orgKey);
  
  // 2. Compile to DNR format
  const dnrRules = decryptedRules.iocs.map((ioc, index) => ({
    id: index + 1,
    priority: 1,
    action: { type: "block" },
    condition: { urlFilter: `||${ioc}^` }
  }));
  
  // 3. Apply via DNR API
  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: dnrRules,
    removeRuleIds: await getCurrentRuleIds()
  });
}

// Zero-knowledge preserved:
// - Server only sees encrypted blob
// - Decryption happens client-side
// - Org key never leaves customer control
```

---

## Risk Matrix (Updated)

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Chrome MV3 `webRequestBlocking` deprecated for enterprise | Low | Monitor Chrome Enterprise blog; architecture is dual-mode |
| **X25519 WebCrypto unavailable on target Chrome versions** | **HIGH** | **Require minimum Chrome version and fail closed** |
| **Storage limits hit at scale** | **HIGH** | **Binary format + unlimitedStorage permission** |
| **Consumer zero-knowledge inconsistency exposed** | **MEDIUM** | **Encrypted distribution + local compile** |
| DNR rule quota consumed by other extensions | Medium | Enterprise tier uses `webRequestBlocking` (immune to quota) |
| CDN/Cloudflare outage | Medium | **Stale-protect: local cache continues; "Offline" badge** |
| Incumbents add feature | Medium | Zero-Knowledge is architectural — they'd have to rebuild |
| Free tier is "good enough" | Low | Technical friction enforced |
| Chrome Web Store rejection | Low | Minimal permissions, open source |
| Talk rejected by BSides | Medium | Record anyway, post to YouTube |

---

## Milestones

### Phase 0: Validation POCs (Target: 1 weekend) ⭐ NEW
- [ ] **POC 1:** MV3 enterprise mode gating test
- [ ] **POC 2:** Signature verify on Chrome Stable + older versions
- [ ] **POC 3:** Storage/perf baseline (100k/300k/1M hashes)
- [ ] **Decision gate:** X25519 support floor, storage format, perf limits

### Phase 1: MVP (Target: 2 weekends after POC)
- [ ] Extension on GitHub (public repo, GPL)
- [ ] **Binary blocklist storage format**
- [ ] **URL canonicalization module**
- [ ] **Standalone Mode config import (single JSON file)**
- [ ] **Architecture Hardening (see Architecture_Hardening_Specification.md):**
  - [ ] Warm-Keep Protocol (4.9-min heartbeat alarm)
  - [ ] Fail-Safe Forensics Queue with retry logic
  - [ ] Pending uploads badge indicator
- [ ] **Dual Architecture Support:**
  - [ ] **Consumer Version (Chrome Web Store):**
    - [ ] **Encrypted distribution + local DNR compile**
    - [ ] Fail-open with "stale-protect" messaging
  - [ ] **Enterprise Version (Policy-Installed):**
    - [ ] `webRequestBlocking` with in-memory Set
    - [ ] X25519 threat feed decrypt
- [ ] Block page
- [ ] Client-side forensics encryption (RSA-OAEP + AES-GCM)
- [ ] Key Generator page

### Phase 1.5: NOC-Friendly Kit (Target: +1 weekend) ⭐ NEW
- [ ] **Golden ADMX/ADML template** for Group Policy
- [ ] **Intune deployment guide**
- [ ] **"Standard Change" copy-paste email template** in docs
- [ ] **Deployment resources** in admin portal

### Phase 2: Dashboard Enhancements
- [ ] **Fleet Health widget** (Enterprise vs Free indicator)
- [ ] **AdBlock Immunity indicator** for Enterprise tier
- [ ] **IOC capacity meter**
- [ ] Deploy to own SOC team (local mode first)
- [ ] Test key generation + GPO deployment workflow
- [ ] Collect 2-3 real incident examples

---

## Resource Requirements
- **Time:** ~1 weekend POC validation + ~4 weekends to MVP
- **Money:** ~$15 (domain) + Stripe fees + ~$5-50/month R2 storage
- **Infra:** GitHub, Cloudflare R2/Pages/Workers, Firebase/FCM, Stripe

---

## Browser Support (MVP Scope)

| Browser | Support Status | Notes |
|---------|---------------|-------|
| Google Chrome | ✓ Full | Primary target |
| Microsoft Edge (Chromium) | ✓ Full | Same extension, different GPO path |
| Brave | ✓ Full | Chromium-based |
| Opera | ✓ Full | Chromium-based |
| Firefox | ✗ Not in v1 | MV3 implementation differs significantly |
| Safari | ✗ Not supported | Different extension architecture |

**Rationale:** Chromium represents ~90% of enterprise browser market share. Firefox's MV3 implementation (Event Pages vs Service Workers) would double development time for ~4% share.

**Messaging:**
> "For maximum security and stability, BlockIOC supports the **Chromium engine** (Chrome, Edge, Brave, Opera). Firefox support is on our roadmap."

---

## Constraints
- Solo founder side project
- Cannot interfere with day job
- Must be low-support model
- No enterprise sales calls
- Credit card self-serve only
- No custom security questionnaires (Trust Center only)
- No BYOD support (privacy liability)

---

## Project Owner
You

## Date
January 2026

---

*Register blockioc.com. Validate the POCs. Build the talk. Ship it. Let them audit the code.*

*"Don't trust me. Trust the math."*
