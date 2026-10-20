# BlockIOC Threat Model

**Version:** 1.0
**Last Updated:** January 2026
**Status:** Active

This document defines the security boundaries, threat actors, and trust assumptions for BlockIOC. It is intended for security auditors, enterprise customers evaluating the product, and internal development reference.

---

## Executive Summary

BlockIOC is a browser-based IOC blocking extension with zero-knowledge forensics. The core security claim is:

> **BlockIOC cannot read your forensics data or your IOC lists.** We store encrypted blobs that only you can decrypt.

This threat model documents what that claim protects against, what it does not protect against, and the assumptions required for security to hold.

---

## 1. Assets Under Protection

### 1.1 High-Value Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| **Customer IOC Lists** | Domain/URL blocklists containing threat intelligence | HIGH - Reveals customer's threat awareness and potential vulnerabilities |
| **Forensics Data** | Blocked URL, redirect chain, tab context, timestamps | HIGH - Contains user browsing behavior and potential incident details |
| **Customer Private Keys** | RSA-2048 (forensics) and X25519 (threat feeds) | CRITICAL - Compromise breaks all confidentiality guarantees |
| **Organization Salt** | Per-org random salt for IOC hashing | HIGH - Required for blocklist lookup; shared only via GPO/MDM |

### 1.2 Operational Data (Not Encrypted)

| Data | Visibility | Purpose |
|------|------------|---------|
| `org_id` | BlockIOC sees | Routing, billing, rate limiting |
| `key_version` | BlockIOC sees | Multi-key rotation support |
| Block timestamps | BlockIOC sees | Operational metrics |
| Encrypted blob sizes | BlockIOC sees | Storage metrics |

This metadata exposure is intentional and required for billing and abuse prevention. It does not reveal blocked URLs or forensics content.

---

## 2. Threat Actors

### 2.1 External Attacker

**Capability:** Network access, phishing, malware hosting
**Goal:** Deliver malicious content to users

| Attack | BlockIOC Protection |
|--------|---------------------|
| Phishing URLs | Blocked if URL/domain is in customer's blocklist |
| Malware download sites | Blocked if URL/domain is in customer's blocklist |
| Zero-day phishing domains | NOT PROTECTED - requires IOC to be added first |
| Redirects through clean domains | Redirect chain captured in forensics |

### 2.2 Compromised Website (Injection Attack)

**Capability:** Can inject malicious content into legitimate pages
**Goal:** Redirect users to malicious destinations

| Attack | BlockIOC Protection |
|--------|---------------------|
| Injected redirect to phishing | Blocked if destination is in blocklist |
| Injected scripts (XSS) | NOT PROTECTED - not an IOC blocker |
| DOM manipulation | Shadow detection may fingerprint kit structure |

### 2.3 Compromised CDN / Man-in-the-Middle

**Capability:** Can modify network traffic between extension and BlockIOC servers
**Goal:** Tamper with blocklists or exfiltrate forensics

| Attack | BlockIOC Protection |
|--------|---------------------|
| Blocklist tampering | X25519 envelope encryption - attacker cannot forge valid encrypted feed |
| Blocklist downgrade | Stale-protect timestamp validation (30-day max age) |
| Forensics interception | RSA-OAEP encryption - attacker gets ciphertext they cannot decrypt |
| Replay old blocklist | Timestamp in signed payload prevents rollback |

### 2.4 Malicious Browser Extension

**Capability:** Browser extension with `host_permissions` or `webRequest` API
**Goal:** Bypass blocking or steal user data

| Attack | BlockIOC Protection |
|--------|---------------------|
| Modify outbound requests | NOT PROTECTED - malicious extensions run at same privilege level |
| Read page content | NOT PROTECTED - content script isolation is advisory |
| Disable BlockIOC | NOT PROTECTED - user/admin controls extension install |

**Mitigation:** Enterprise deployment via GPO/MDM with extension allowlisting.

### 2.5 BlockIOC Itself (Insider Threat / Zero-Knowledge Claim)

**Question:** Can BlockIOC read customer data?

| Data | Can BlockIOC Read? | Technical Reason |
|------|-------------------|------------------|
| Forensics content | NO | RSA-OAEP encrypted; private key never transmitted |
| Customer IOC lists | NO | X25519 envelope encrypted before upload |
| Which URLs were blocked | NO | Only encrypted blob and org_id visible |
| Block frequency per org | YES | Metadata required for billing |

**Key Point:** BlockIOC's zero-knowledge claim is cryptographic, not policy. Even a rogue employee or legal subpoena cannot decrypt customer data because we do not possess the keys.

### 2.6 Compromised BlockIOC (Supply Chain Attack)

**Capability:** Attacker controls BlockIOC's infrastructure or pushes malicious extension update
**Goal:** Exfiltrate data or disable protection

| Attack | BlockIOC Protection |
|--------|---------------------|
| Malicious extension update | Chrome Web Store review process; enterprise can pin versions |
| Backend database breach | Attackers get encrypted blobs they cannot decrypt |
| Push malicious blocklist | X25519 encryption - attacker cannot create valid encrypted feed without customer's public key |
| Disable blocking via config | Enterprise GPO/MDM takes precedence over remote config |

**BYO-Trust Model:** Enterprises with their own keys are protected even if BlockIOC infrastructure is fully compromised.

### 2.7 Compromised Endpoint (Attacker Has Root)

**Capability:** Full control of user's device
**Goal:** Any

| Attack | BlockIOC Protection |
|--------|---------------------|
| Read Chrome storage | NOT PROTECTED - root can access all browser data |
| Disable extension | NOT PROTECTED - root can modify Chrome |
| Extract private keys from GPO | NOT PROTECTED - keys stored in managed storage |

**Out of Scope:** If an attacker has root/admin on the endpoint, browser-level protections are ineffective. This is an EDR problem, not a browser extension problem.

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TRUSTED ZONE                                       │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   Customer's    │    │   Chrome        │    │   Customer's    │         │
│  │   Private Keys  │    │   Browser       │    │   GPO/MDM       │         │
│  │   (1Password,   │    │   (Executes     │    │   (Distributes  │         │
│  │    Vault, HSM)  │    │    extension)   │    │    config)      │         │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
│                                                                              │
│  Assumption: Customer protects keys. Browser is not compromised.            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                          TRUST BOUNDARY
                          (Encryption)
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          UNTRUSTED ZONE                                      │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   BlockIOC      │    │   Internet      │    │   CDN           │         │
│  │   Backend       │    │   (Network      │    │   (Blocklist    │         │
│  │   (Stores       │    │    transit)     │    │    distribution)│         │
│  │    ciphertext)  │    │                 │    │                 │         │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
│                                                                              │
│  These components see only encrypted data or metadata.                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Trust Boundary Details

| Boundary | Trust Level | Verification |
|----------|-------------|--------------|
| Extension ↔ Chrome APIs | Trusted | Chrome enforces MV3 sandbox |
| Extension ↔ BlockIOC CDN | Untrusted | X25519 envelope decryption; timestamp validation |
| Extension ↔ Forensics Endpoint | Untrusted | RSA-OAEP encryption before transmission |
| Customer ↔ BlockIOC | Zero-knowledge | We see ciphertext only; no shared secrets |
| Customer ↔ GPO/MDM | Trusted | Customer controls their own infrastructure |

---

## 4. In Scope: What BlockIOC Protects

### 4.1 Primary Protection

| Capability | Mechanism |
|------------|-----------|
| Block navigation to known-bad IOCs | Local hash lookup against encrypted blocklist |
| Capture forensics on block events | Redirect chain, timestamps, tab context |
| Protect forensics confidentiality | RSA-OAEP + AES-GCM hybrid encryption |
| Protect blocklist confidentiality | X25519 + HKDF + AES-GCM envelope encryption |
| Detect blocklist tampering | Envelope encryption with authenticated encryption (AEAD) |
| Survive network outages | Persistent forensics queue with retry logic |
| Fail safely (stale protection) | 30-day maximum staleness; configurable fail-closed |

### 4.2 Shadow Detection (Optional)

| Capability | Mechanism |
|------------|-----------|
| Fingerprint phishing kit structure | DOM skeleton hashing (hash-only, no content exfil) |
| Detect kit reuse across domains | Structural similarity scoring |
| Privacy-preserving analysis | Only hashes transmitted, not DOM content |

---

## 5. Out of Scope: What BlockIOC Does NOT Protect

### 5.1 Explicit Non-Goals

| Threat | Why Out of Scope |
|--------|------------------|
| **DNS-level blocking** | BlockIOC operates at browser level; use DNS filtering for network-wide |
| **Non-browser traffic** | Extension only intercepts browser navigation |
| **Post-exploitation detection** | We block initial access, not lateral movement |
| **Zero-day threats** | Requires IOC to be added first; no heuristic detection |
| **Compromised browser** | If Chrome itself is malicious, all bets are off |
| **Compromised endpoint** | Root/admin attacker bypasses all browser protections |
| **Other browser extensions** | Malicious extensions with host_permissions are peers |
| **Network inspection** | We don't inspect TLS traffic or file contents |
| **Email attachment scanning** | Browser extension, not email security |

### 5.2 Defense in Depth Expectations

BlockIOC is designed as one layer in a defense-in-depth strategy:

| Layer | Recommended Tool | BlockIOC Role |
|-------|------------------|---------------|
| Network | DNS filtering, NGFW | Complement with browser-level coverage |
| Endpoint | EDR (CrowdStrike, Defender) | BlockIOC forwards to EDR for correlation |
| Email | SEG (Proofpoint, Mimecast) | Block links that escape email filtering |
| Identity | SSO, MFA | No direct integration |
| SIEM | Splunk, Sentinel, etc. | BlockIOC exports forensics to SIEM |

---

## 6. Security Assumptions

For BlockIOC's security guarantees to hold, the following must be true:

### 6.1 Customer Responsibilities

| Assumption | Impact if Violated |
|------------|-------------------|
| Customer protects RSA private key | Forensics confidentiality lost |
| Customer protects X25519 private key | Blocklist confidentiality lost |
| Customer protects organization salt | IOC hashing can be reversed |
| GPO/MDM infrastructure is secure | Config can be tampered |
| Customer reviews extension updates | Malicious update risk |

### 6.2 Platform Assumptions

| Assumption | Impact if Violated |
|------------|-------------------|
| Chrome browser is not compromised | All browser-level protections bypassed |
| Web Crypto API is correctly implemented | Cryptographic guarantees void |
| Chrome extension sandbox is enforced | Extension isolation broken |
| MV3 service worker lifecycle is predictable | Blocking may fail during cold start |

### 6.3 Cryptographic Assumptions

| Assumption | Impact if Violated |
|------------|-------------------|
| RSA-2048 is secure | Forensics encryption broken |
| X25519 is secure | Threat feed encryption broken |
| AES-256-GCM is secure | Payload encryption broken |
| SHA-256 is collision-resistant | IOC hashing reliability degraded |
| HKDF-SHA256 is a secure KDF | Key derivation compromised |

---

## 7. Attack Scenarios and Mitigations

### 7.1 Scenario: BlockIOC Database Breach

**Attack:** Attacker exfiltrates BlockIOC's database.

**What Attacker Gets:**
- Encrypted forensics blobs
- Encrypted IOC packages
- Customer public keys (useless for decryption)
- org_id and timestamp metadata

**What Attacker Cannot Get:**
- Plaintext forensics content
- Plaintext IOC lists
- Customer private keys (never stored)

**Mitigation:** Zero-knowledge architecture. Breach yields encrypted data with no decryption capability.

### 7.2 Scenario: Rogue BlockIOC Employee

**Attack:** Employee with database access attempts to read customer data.

**Result:** Employee sees only encrypted blobs. No customer private keys exist in BlockIOC infrastructure.

**Mitigation:** Cryptographic enforcement. Policy says "we won't look"; architecture says "we can't look."

### 7.3 Scenario: Legal Subpoena

**Attack:** Law enforcement subpoenas BlockIOC for customer forensics.

**What BlockIOC Can Provide:**
- Encrypted blobs (useless without customer's key)
- Metadata (org_id, timestamps, blob sizes)
- Customer public keys

**What BlockIOC Cannot Provide:**
- Plaintext forensics
- Plaintext IOC lists
- Customer private keys

**Customer Control:** Customer holds the only decryption key. Compliance requires customer cooperation.

### 7.4 Scenario: Supply Chain Attack on Extension

**Attack:** Attacker pushes malicious extension update.

**Mitigations:**
1. Chrome Web Store review process
2. Enterprise can pin extension version via GPO
3. BYO-Trust model: keys are customer-controlled
4. Open source: code can be audited

### 7.5 Scenario: CDN Serves Malicious Blocklist

**Attack:** CDN compromised; serves empty or malicious blocklist.

**Mitigations:**
1. X25519 envelope encryption - attacker cannot create valid encrypted feed
2. Stale-protect - extension rejects blocklists older than 30 days
3. Last-known-good fallback - continues using cached blocklist on update failure

---

## 8. Cryptographic Protocol Summary

### 8.1 Threat Feed Distribution (X25519 + HKDF + AES-GCM)

```
Server (BlockIOC):
  1. Generate ephemeral X25519 keypair
  2. For each customer public key:
     a. Derive shared secret via ECDH
     b. Derive AES key via HKDF-SHA256
     c. Wrap session key with AES-GCM
  3. Encrypt IOC payload once with AES-256-GCM
  4. Publish envelope with per-customer headers

Client (Extension):
  1. Find header matching kid
  2. Derive shared secret from ephemeral_pub + private_key
  3. Derive AES key via HKDF-SHA256
  4. Unwrap session key
  5. Decrypt IOC payload
```

### 8.2 Forensics Export (RSA-OAEP + AES-GCM)

```
Client (Extension):
  1. Generate random AES-256 key
  2. Encrypt forensics payload with AES-GCM
  3. Wrap AES key with RSA-OAEP (customer public key)
  4. Transmit { wrapped_key, iv, ciphertext }

Server (BlockIOC):
  - Stores encrypted blob
  - Cannot decrypt (no private key)

Customer:
  1. Download encrypted blob
  2. Unwrap AES key with RSA private key
  3. Decrypt payload with AES-GCM
```

---

## 9. Compliance Considerations

### 9.1 GDPR / Privacy

| Requirement | BlockIOC Implementation |
|-------------|------------------------|
| Data minimization | Only capture necessary forensics fields |
| Encryption at rest | All forensics encrypted before storage |
| Right to erasure | Customer controls data; can delete from BlockIOC |
| Data portability | Standard JSON format for forensics export |
| Lawful basis | Security incident investigation (legitimate interest) |

### 9.2 SOC 2

| Control | Implementation |
|---------|----------------|
| Encryption in transit | TLS 1.2+ for all API calls |
| Encryption at rest | AES-256-GCM for all stored data |
| Access control | Zero-knowledge - no access to plaintext |
| Audit logging | Timestamp and org_id logged for all operations |
| Change management | Chrome Web Store review; enterprise version pinning |

---

## 10. Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | January 2026 | Initial threat model |

---

## 11. Contact

For security concerns or questions about this threat model:
- Email: security@blockioc.com
- GitHub: [Security Issues](https://github.com/deoxynet/browserdefense/security)

---

**End of Threat Model**
