# BlockIOC Implementation Review

**Review Date:** January 2026  
**Status:** ~80% locked, 20% requires validation POCs + wording fixes

---

## Executive Summary

The wedge and narrative are extremely strong, but there are "physics of Chrome" constraints and internal contradictions that will bite unless tightened now.

**Keep the core thesis:** Browser-level blocking + zero-knowledge forensics + SOC-first standalone pilot is a clean, credible angle.

**Immediately validate/adjust these three foundations:**

1. **Threat feed crypto choice** (X25519 in WebCrypto) requires a clear minimum Chrome version and a fail-closed startup check.

2. **"Store the whole set locally" plan** conflicts with Chrome extension storage realities if you naïvely serialize `Array.from(set)` into `chrome.storage.local` (size + overhead). You'll hit limits and perf walls unless you use a compact format / IndexedDB / `unlimitedStorage`.

3. **Consumer tier + "salted hashes only" + DNR enforcement** is internally inconsistent unless you explicitly introduce client-side decryption + local compilation of DNR rules, or you relax the "we never see plaintext IOCs" claim for that tier.

Everything else is "hard but doable."

---

## The 6 Sharp Edges to Fix

### 1. X25519 in `crypto.subtle`: Enforce a Minimum Chrome Version

**The Problem:**

The spec repeatedly assumes:
```javascript
crypto.subtle.deriveBits({ name: "X25519", public: ... }, ...)
```

That only works if your enterprise fleet has X25519 available in WebCrypto everywhere you deploy.

**The Fix:**

- **Set a minimum Chrome version** (113+) in deployment docs and checks.
- **Fail closed** if X25519 is unavailable: threat feed decrypt must not run without the key agreement.
- **Surface a clear error** in logs to avoid silent failures.

**Why This Matters:**

Your threat feed story lives or dies on "decrypt always works." If decrypt fails, you must stop updates and surface the cause.

---

### 2. "Store a Set of Hashes in `chrome.storage.local`" Will Blow Up

**The Problem:**

Current code:
```javascript
await chrome.storage.local.set({
  blocklist_hashes: Array.from(blocklist)
})
```

That's worst-case storage inflation:
- JSON string overhead
- 64-char hex strings
- Array/object overhead

Chrome's storage docs are explicit that default extension storage is limited (10 MB for `storage.local` unless you take steps like `unlimitedStorage`).

**Fix Options (Pick One):**

1. **Binary snapshot format:** Store hashes as raw 32-byte values in one ArrayBuffer, base64 it, store that.
2. **Truncate hashes to 128 bits (16 bytes):** Accept "cryptographically negligible collision risk." Same argument as "SHA-256 collisions won't happen" with different constants.
3. **IndexedDB for storage + streaming load:** More code, but scales.
4. **`unlimitedStorage` permission + still store compactly:** Permission friction usually fine for enterprise deployments.

**Note:** The doc contradicts itself on memory—one place says 100k hashes ~10 MB, another says ~100 MB. Treat these as "marketing placeholders" until you measure in a real MV3 service worker.

---

### 3. Consumer Tier: DNR + "Salted Hashes Only" Doesn't Add Up

**The Problem:**

DNR blocks by matching URL patterns/rules. It cannot consult your salted-hash Set. One of these must be true:

- **A)** Consumer tier blocks only public/vendor threat list (fine), and org-specific IOCs require enterprise mode (but that hurts the SOC-first wedge), or
- **B)** Consumer tier distributes encrypted IOC plaintext (or encrypted rules), clients decrypt locally, and compile/apply DNR rules locally, or
- **C)** You abandon "we never see plaintext IOCs" for consumer org-specific IOCs (probably not what you want).

Current charter simultaneously claims:
- "We store only salted hashes; plaintext IOCs never touch our servers"
- "Consumer tier uses DNR rules updated from rules.json"

Those can both be true only if `rules.json` content is not derived from customer plaintext, or it is derived but built locally after decryption.

**Recommendation: Embrace Option B for the SOC-first wedge:**

```
Upload: Analyst sends hash-only to oracle (fine)
Distribution: Server stores encrypted IOC plaintext or encrypted "rule deltas"
Endpoint: Decrypts with org key → compiles DNR rules → applies via updateDynamicRules
```

That preserves the zero-knowledge claim (server sees ciphertext), while still letting consumer tier block org-specific IOCs.

---

### 4. Redirect-Chain Forensics: Be Explicit About Local Capture

**The Issue:**

"Redirect chain" is gold, yes. But implementation detail matters:
- If you rely on `webRequest` events to record redirects, you must keep per-tab state somewhere durable enough across MV3 service worker suspends
- You say "no scary permissions," but redirect chain capture generally implies broader visibility locally—even if you only upload on block

**The Fix:**

Trust Center language should be precise:

> "We may observe request/redirect metadata locally to compute the redirect chain, but we only transmit encrypted forensics on block."

That's honest and still strong.

---

### 5. Canonicalization: Where "Zero False Positives" Quietly Dies

**The Issue:**

Hash match is exact, sure—but only after you normalize the input the same way everywhere.

**You Need a Canonicalization Spec That Is Boring and Ruthless:**

- Punycode handling for IDNs
- Lowercase host
- Strip trailing dot
- Default ports
- IPv6 bracket normalization
- What counts as the IOC: host only? host+path? full URL?
- eTLD+1 vs full host (phishing often uses subdomains)

If you hash `evil.com` but the clicked URL is `http://evil.com.:80/%2e%2e/` and your normalization differs between "add IOC" and "check request," you'll miss blocks (false negatives). False positives can also happen if you over-broaden DNR patterns.

**Action:** Write a tiny "Canonicalization RFC" in the repo and treat it like a security boundary.

---

### 6. "Fail Open" Is Politically Smart—But Document It Better

**The Issue:**

Your outage behavior is the right user-behavior call (avoid scapegoating yourself). But some security buyers will hear "fail open" and flinch.

**Reframe As:**

- "Protection continues using last-known-good blocklist; updates queue."
- **Optional:** A policy knob for "paranoid mode" customers (fail-closed on update verification failure only, not on network outage).

---

## Messaging Fixes (Replace Absolute Claims)

| Current Claim | Better Version |
|--------------|----------------|
| "Zero false positives." | "Exact-match blocking on normalized indicators (no probabilistic filters)." |
| "Backend infrastructure: none (static CDN + FCM)." | "No always-on compute for lookups; distribution is static + event-driven." |
| "CrowdStrike can't copy because closed source / phones home everything." | "Incumbents could build this, but it's strategically off-model: it reduces their telemetry moat and complicates their platform economics." |

That keeps the swagger, removes the brittle claim.

---

## The 3 P0 Validation POCs

No extra theory—these are go/no-go.

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

### Failure Mode: "Standalone Mode" Is Still Too Annoying

If each analyst has to paste salts/keys and it's fragile, pilots stall.

**Mitigation:** Make standalone config a single import file (JSON) that includes org_id + endpoints + public mesh key + gpo private key + salt. Less copy-paste, fewer mistakes.

### Failure Mode: "Zero-Knowledge" Triggers Compliance Questions Anyway

Some enterprises will still demand DPAs and questionnaires.

**Mitigation:** Keep your $15k "questionnaire tier" exactly as you wrote it. That's a clean filter. Just don't oversell "no DPA needed" universally.

### Failure Mode: Competitors Don't Need to Copy—Customers Decide "We Already Have SWG"

**Mitigation:** Hammer the remote worker + no VPN + fast IOC block workflow. That's your sharpest differentiated painkiller.

---

## Summary Recommendation

**Proceed, but tighten the spec around three realities:**

1. **Ship threat feeds with X25519 only**, and set a minimum Chrome version requirement.

2. **Rewrite consumer-tier zero-knowledge mechanics** so DNR enforcement and "we never see plaintext IOCs" are consistent (encrypted distribution + local compile).

3. **Redesign local storage format now** (binary/compact + maybe `unlimitedStorage`), because `Array.from(Set)` in `chrome.storage.local` will not scale cleanly.

If you do those three, the rest of the charter reads like something you can actually ship—and demo on stage without the demo gods smiting you.

---

## Files Updated

| Document | Version | Key Changes |
|----------|---------|-------------|
| `Project_Charter_BlockIOC_Updated_v2.md` | v2 | Added Implementation Review section, P0 POCs, messaging fixes, canonicalization spec |
| `Cryptographic_Specification_v3.md` | v3 | Dual-stack X25519 + RSA, added binary storage format, added encrypted distribution |
| `Implementation_Review.md` | v1 | This document—full critique capture |

---

## Blue Team Response: Architecture Hardening

The following defensive measures have been designed to address Red Team findings:

### Technical Mitigations

| Red Team Finding | Blue Team Response | Implementation |
|-----------------|-------------------|----------------|
| **Cold start latency** | Warm-Keep Protocol | 4.9-minute heartbeat alarm keeps SW active |
| **Data loss during outages** | Fail-Safe Forensics Queue | Persistent local queue with retry logic |
| **DNS exfiltration claims** | Scope Lock | Explicitly define as "Layer 7 / HTTP(S) only" |

### Operational Mitigations

| Red Team Finding | Blue Team Response | Implementation |
|-----------------|-------------------|----------------|
| **Deployment friction** | NOC-Friendly Kit | Golden ADMX template + copy-paste email |
| **Browser blindspot** | Chromium-only MVP | Explicit support matrix, Firefox roadmap |
| **Free vs Enterprise confusion** | AdBlock Immunity Indicator | Fleet Health dashboard widget |

### Key Code: Warm-Keep Protocol

```javascript
// Keep Service Worker alive during active sessions
chrome.alarms.create("keepAlive", { periodInMinutes: 4.9 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "keepAlive") {
    console.log("[BlockIOC] Heartbeat: SW warm");
    checkPendingUploads();  // Also retry queued forensics
  }
});
```

### Key Narrative: Fail-Safe Queue

> "We function like a black box flight recorder. Even if the plane loses radio contact (internet), the data is saved locally and transmitted the moment connection is restored. **You never lose forensic evidence.**"

### Scope Lock Language (Trust Center)

> "BlockIOC operates at the **Application Layer (Layer 7)**. It captures rich URL redirects and payload metadata for web traffic. It does not inspect raw DNS (Layer 53/UDP) or TCP/UDP packets.
>
> This isn't a limitation—it's a design choice. We don't slow down your DNS resolution or break your UDP VPNs. We focus on the web attack surface where phishing actually happens."

See `Architecture_Hardening_Specification.md` for full implementation details.

---

## Files Updated

| Document | Version | Key Changes |
|----------|---------|-------------|
| `Project_Charter_BlockIOC_Updated_v2.md` | v2 | Added Implementation Review section, P0 POCs, messaging fixes, canonicalization spec |
| `Cryptographic_Specification_v3.md` | v3 | Dual-stack X25519 + RSA, added binary storage format, added encrypted distribution |
| `Implementation_Review.md` | v1.1 | Full critique capture + Blue Team responses |
| `Architecture_Hardening_Specification.md` | v1 | Warm-Keep, Fail-Safe Queue, Scope Lock, NOC-Friendly Kit |

---

*"Don't trust me. Trust the math."*  
*—But first, validate that the math actually works in Chrome 109.*
