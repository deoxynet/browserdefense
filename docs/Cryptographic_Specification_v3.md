# Cryptographic Specification: BlockIOC Zero-Knowledge Protocol

**Version:** 3.0  
**Status:** REQUIRES POC VALIDATION  
**Target:** Solo founder with ~200 lines of crypto wrapper code  

---

## ⚠️ IMPLEMENTATION REVIEW: CRITICAL CHANGES

**Review Date:** January 2026 (Updated)

### Breaking Changes from v2

| Component | v2 Assumption | v3 Requirement |
|-----------|--------------|----------------|
| **Crypto Domains** | Single-stack crypto | **Dual-stack: X25519 + AES-GCM (Team Mesh/Threat Feeds), RSA-OAEP + AES-GCM (Forensics)** |
| **Storage Format** | JSON hex strings | **Binary compact format** |
| **Consumer Zero-Knowledge** | Implicit | **Explicit encrypted distribution + local compile** |

### Rationale

1. **Dual-stack cryptography** is required: X25519 for internal mesh and threat feeds, RSA-OAEP for forensics exports.

2. **`Array.from(set)` in `chrome.storage.local`** will hit 10MB default limits and JSON overhead at scale. Binary format required.

3. **DNR cannot consult salted-hash Set**—consumer tier zero-knowledge claim requires encrypted distribution with local decryption/compilation.

---

## Design Philosophy

The beauty of client-side cryptography for a solo founder: **the code is hard to write once, but costs $0 to run forever.** It offloads the security burden from your servers to the client's browser.

**Two domains. That's it.**

1. **Internal Mesh** — Team Vault + Threat Feeds (X25519 + AES-GCM)
2. **Customer Forensics** — Evidence export (RSA-OAEP + AES-GCM)

Everything uses the native **Web Crypto API** (`window.crypto.subtle`). No heavy libraries. No OpenSSL. Fast, native, audited by browser vendors.

---

## 1. Cryptographic Primitives

| Function | Algorithm | Parameters | Web Crypto Name | Notes |
|----------|-----------|------------|-----------------|-------|
| **Asymmetric Encryption** | RSA-OAEP | 2048-bit, SHA-256 | `RSA-OAEP` | Forensics encryption |
| **Symmetric Encryption** | AES-GCM | 256-bit key, 96-bit IV | `AES-GCM` | Payload encryption |
| **Key Agreement** | X25519 (ECDH) | 255-bit | `X25519` | Team Mesh + Threat Feeds |
| **Key Derivation** | HKDF-SHA256 | 256-bit output | `HKDF` | Derive AES from shared secret |
| **Hashing** | SHA-256 | Standard | `SHA-256` | IOC hashing |

### Algorithm Selection Rationale

**Why X25519 for the internal mesh:**
- Constant-length 32-byte keys
- Fast generation and ECDH for viral sharing flows
- Small payload overhead for high-scale distribution

**Why RSA-OAEP for forensics:**
- Compatibility with enterprise HSMs and legacy SIEM tooling
- Standardized parameters across WebCrypto and Node.js

---

## 2. Key Management (Simplified)

### 2.1. Key Generation (Admin Tool)

The admin generates keys using a static HTML page (`admin.blockioc.com`). **Zero server calls.**

```javascript
// admin.blockioc.com/keygen.js

async function generateOrgKeys() {
  // 1. Generate RSA keypair for forensics encryption
  const encryptionKeypair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,  // extractable
    ["encrypt", "decrypt"]
  );

  // 2. Generate X25519 keypair for Team Mesh + Threat Feeds
  const meshKeypair = await crypto.subtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveBits"]
  );

  // 3. Generate random salt for IOC hashing
  const salt = crypto.getRandomValues(new Uint8Array(32));

  // 4. Export keys
  const publicEncryptionKey = await crypto.subtle.exportKey("jwk", encryptionKeypair.publicKey);
  const privateEncryptionKey = await crypto.subtle.exportKey("jwk", encryptionKeypair.privateKey);
  const publicMeshKey = await crypto.subtle.exportKey("jwk", meshKeypair.publicKey);
  const privateMeshKey = await crypto.subtle.exportKey("jwk", meshKeypair.privateKey);

  return {
    // Goes into GPO/MDM config (or Standalone Mode import file)
    gpo_config: {
      org_id: crypto.randomUUID(),
      public_encryption_key: publicEncryptionKey,
      gpo_private_key: privateMeshKey,  // X25519
      salt: btoa(String.fromCharCode(...salt)),
      key_version: 1,
      algorithm_version: "x25519-v1"
    },
    // Upload to BlockIOC for threat feed encryption
    public_keys: {
      mesh: publicMeshKey
    },
    // Admin keeps these secure (1Password, vault, etc.)
    private_keys: {
      encryption: privateEncryptionKey,
      mesh: privateMeshKey
    }
  };
}
```

### 2.2. Key Distribution

| Key | Where It Goes | Who Sees It |
|-----|---------------|-------------|
| `public_encryption_key` | GPO/MDM → Extension | Everyone (safe) |
| `private_encryption_key` | Admin's 1Password | Admin only |
| `public_mesh_key` | Customer vault → BlockIOC | Server encrypts threat feeds |
| `gpo_private_key` | GPO/MDM → Extension | Extension decrypts threat feeds |
| `salt` | GPO/MDM → Extension | Customer only (not BlockIOC) |

---

## 3. Forensics Export (RSA Hybrid)

**Objective:** Export evidence securely using the customer's RSA public key.

### 3.1. Key Ingestion

- **Input:** `-----BEGIN PUBLIC KEY-----` (PEM format)
- **Format Check:** Must be RSA-2048
- **Storage:** `chrome.storage.local.forensics_pub_key`
- **Constraint:** AES-GCM IV is 96-bit (12 bytes)

### 3.2. Encryption Flow

```javascript
async function encryptForForensics(fileData, rsaPublicKey) {
  // 1. Generate Ephemeral AES-GCM Key (256-bit)
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true, ["encrypt"]
  );

  // 2. Encrypt the Payload (The Evidence)
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    fileData
  );

  // 3. Wrap the AES Key with RSA-OAEP
  const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
  const wrappedKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP", hash: "SHA-256" },
    rsaPublicKey,
    rawAesKey
  );

  // 4. Return the Bundle
  return {
    wrapped_key: arrayBufferToBase64(wrappedKey),
    iv: arrayBufferToBase64(iv),
    payload: arrayBufferToBase64(ciphertext)
  };
}
```

---

## 4. Threat Feed Distribution (Broadcast)

### 4.1. Client-Side Key Logic

- **Priority 1 (Prod):** `chrome.storage.managed.gpo_private_key`
- **Priority 2 (Demo):** `chrome.storage.local.manual_private_key`

### 4.2. Payload Structure (Envelope Encryption)

Session key wrapping uses AES-256-GCM with a KEK derived from HKDF-SHA256(sharedSecret). Both `wrap_iv` and payload `iv` are 96-bit (12 bytes).

```json
{
  "meta": { "version": "2026-01-09", "generated_at": 1736480000 },
  "headers": [
    {
      "kid": "2025_key_v1",
      "ephemeral_pub": "BASE64_X25519...",
      "encrypted_session_key": "BASE64_AES_WRAPPED...",
      "wrap_iv": "BASE64_12_BYTES"
    },
    {
      "kid": "2026_key_v2",
      "ephemeral_pub": "BASE64_X25519...",
      "encrypted_session_key": "BASE64_AES_WRAPPED...",
      "wrap_iv": "BASE64_12_BYTES"
    }
  ],
  "iv": "BASE64_12_BYTES",
  "ciphertext": "BASE64_HUGE_IOC_LIST..."
}
```

### 4.3. Extension Decrypt Flow (WebCrypto)

1. Select key from managed or local storage by `kid`.
2. Import `gpo_private_key` (X25519).
3. Use `ephemeral_pub` + private key to derive shared secret.
4. Derive AES key-encryption-key via HKDF-SHA256.
5. Decrypt `encrypted_session_key` with AES-256-GCM (using `wrap_iv`).
6. Decrypt `ciphertext` with AES-256-GCM (using `iv`).

### 4.4. Server Encrypt Flow (Node.js)

1. Generate ephemeral X25519 keypair.
2. Derive shared secret with each active GPO public key.
3. Derive AES key-encryption-key via HKDF-SHA256.
4. Encrypt payload once with AES-256-GCM (96-bit IV).
5. Wrap session key per `kid` with AES-256-GCM, add header entry.

### 4.5. Team Vault (Viral Configuration)

**Lockbox (server-side):**

```json
{
  "team_id": "uuid",
  "encrypted_data": "AES_GCM_CIPHERTEXT",
  "iv": "hex_12_bytes",
  "updated_at": "timestamp"
}
```

**Keyring (server-side):**

```json
{
  "user_id": "alice@acme.com",
  "team_id": "uuid",
  "wrapped_vault_key": "BASE64...",
  "ephemeral_pub": "BASE64..."
}
```

**Approval Flow (client-side):**

1. Alice uses `Alice_Priv` to unwrap `Vault_Key`.
2. Alice fetches `Bob_Pub` (X25519) from server.
3. Alice generates ephemeral key, derives shared secret with Bob, encrypts `Vault_Key`.
4. Alice uploads new envelope to `key_envelopes`.

---

## 5. Blocklist Storage Format (Revised)

### 5.1. The Problem

```javascript
// ❌ BAD - This will blow up
await chrome.storage.local.set({
  blocklist_hashes: Array.from(blocklist)  // 100k × 64-char hex = ~7MB JSON
});
```

**Issues:**
- JSON serialization overhead
- 64-character hex strings (2x the actual data)
- Default 10MB limit for `chrome.storage.local`
- Array/object overhead

### 5.2. The Solution: Binary Compact Format

```javascript
// ✅ GOOD - Binary compact format

// Option A: Full 256-bit hashes (32 bytes each)
async function storeBlocklistBinary(hashes) {
  const buffer = new ArrayBuffer(hashes.size * 32);
  const view = new Uint8Array(buffer);
  
  let offset = 0;
  for (const hexHash of hashes) {
    const bytes = hexToBytes(hexHash);
    view.set(bytes, offset);
    offset += 32;
  }
  
  // Base64 encode for storage
  const base64 = btoa(String.fromCharCode.apply(null, view));
  await chrome.storage.local.set({ blocklist_binary: base64 });
}

async function loadBlocklistBinary() {
  const { blocklist_binary } = await chrome.storage.local.get('blocklist_binary');
  if (!blocklist_binary) return new Set();
  
  const binary = atob(blocklist_binary);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  
  const hashes = new Set();
  for (let i = 0; i < bytes.length; i += 32) {
    const hashBytes = bytes.slice(i, i + 32);
    const hexHash = bytesToHex(hashBytes);
    hashes.add(hexHash);
  }
  
  return hashes;
}

// Option B: Truncated 128-bit hashes (16 bytes each)
// Same collision argument as "SHA-256 won't collide" with different constants
// Risk: 2^64 operations to find collision (still computationally infeasible)
async function storeBlocklistTruncated(hashes) {
  const buffer = new ArrayBuffer(hashes.size * 16);
  const view = new Uint8Array(buffer);
  
  let offset = 0;
  for (const hexHash of hashes) {
    const bytes = hexToBytes(hexHash.slice(0, 32));  // First 128 bits
    view.set(bytes, offset);
    offset += 16;
  }
  
  const base64 = btoa(String.fromCharCode.apply(null, view));
  await chrome.storage.local.set({ blocklist_binary_128: base64 });
}

// Helper functions
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
```

### 5.3. Storage Size Comparison

| Format | 100k hashes | 300k hashes | 1M hashes |
|--------|-------------|-------------|-----------|
| JSON hex strings | ~7.5 MB | ~22.5 MB | ~75 MB |
| Binary base64 (256-bit) | ~4.3 MB | ~12.8 MB | ~42.7 MB |
| Binary base64 (128-bit) | ~2.1 MB | ~6.4 MB | ~21.3 MB |
| IndexedDB binary | ~3.2 MB | ~9.6 MB | ~32 MB |

**Recommendation:**
- Enterprise tier: Binary 256-bit + `unlimitedStorage` permission
- Consumer tier: Binary 128-bit (fits comfortably in default limits)

---

## 6. URL Canonicalization Specification

**CRITICAL: Treat canonicalization as a security boundary.**

If you hash `evil.com` but the clicked URL is `http://evil.com.:80/%2e%2e/` and normalization differs between "add IOC" and "check request," you'll miss blocks.

### 6.1. Canonicalization Rules

```javascript
function canonicalizeUrl(url, scope = 'HOST_ONLY') {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    // Invalid URL, return as-is for hash (will likely not match)
    return url.toLowerCase();
  }
  
  // 1. Lowercase scheme and host
  let canonical = parsed.protocol.toLowerCase() + '//';
  
  // 2. Convert IDN to punycode (browser does this automatically)
  let host = parsed.hostname.toLowerCase();
  
  // 3. Remove trailing dot
  host = host.replace(/\.$/, '');
  
  canonical += host;
  
  // 4. Remove default ports
  if (!((parsed.protocol === 'http:' && parsed.port === '80') ||
        (parsed.protocol === 'https:' && parsed.port === '443') ||
        parsed.port === '')) {
    canonical += ':' + parsed.port;
  }
  
  if (scope === 'HOST_ONLY') {
    return canonical;
  }
  
  // 5. Normalize path
  let path = parsed.pathname;
  // Decode percent-encoding, then re-encode consistently
  try {
    path = decodeURIComponent(path);
  } catch (e) {
    // Invalid encoding, keep as-is
  }
  // Re-encode with consistent rules
  path = path.split('/').map(segment => encodeURIComponent(segment)).join('/');
  // Normalize empty path to /
  if (!path) path = '/';
  
  canonical += path;
  
  if (scope === 'HOST_PATH') {
    return canonical;
  }
  
  // 6. Sort and normalize query parameters
  if (parsed.search) {
    const params = new URLSearchParams(parsed.search);
    // Sort parameters alphabetically
    const sortedParams = new URLSearchParams([...params.entries()].sort());
    canonical += '?' + sortedParams.toString();
  }
  
  // Fragment is never included (not sent to server)
  
  return canonical;
}
```

### 6.2. IOC Hashing

```javascript
async function hashIOC(ioc, salt, scope = 'HOST_ONLY') {
  // 1. Canonicalize
  const canonical = canonicalizeUrl(ioc, scope);
  
  // 2. Combine with salt
  const data = canonical + ':' + salt;
  
  // 3. SHA-256 hash
  const hashBuffer = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(data)
  );
  
  return bytesToHex(new Uint8Array(hashBuffer));
}
```

### 6.3. Configuration

```json
{
  "ioc_scope": "HOST_ONLY",  // or "HOST_PATH" or "FULL_URL"
  "notes": "HOST_ONLY recommended for phishing; HOST_PATH for malware paths"
}
```

---

## 7. Consumer Tier: Encrypted Distribution

**Problem:** DNR rules cannot consult a salted-hash Set. Consumer tier needs to maintain zero-knowledge while supporting org-specific IOCs.

**Solution:** Encrypted distribution + local compilation.

### 7.1. The Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  SOC ANALYST (adding IOC)                                                   │
│                                                                             │
│  1. Enters IOC in admin tool: "evil-phishing.com"                          │
│  2. Tool encrypts IOC with org's public key                                │
│  3. Uploads encrypted blob to BlockIOC CDN                                 │
│                                                                             │
│  Server sees: { org_id, encrypted_blob }                                   │
│  Server does NOT see: "evil-phishing.com"                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  BROWSER EXTENSION (on sync)                                                │
│                                                                             │
│  1. Fetch encrypted IOC list from CDN                                      │
│  2. Decrypt locally with org's private key (from GPO/Standalone config)    │
│  3. Compile decrypted IOCs to DNR rule format                              │
│  4. Apply via chrome.declarativeNetRequest.updateDynamicRules              │
│                                                                             │
│  Result: Zero-knowledge preserved (server never sees plaintext IOCs)       │
│          Consumer tier blocks org-specific IOCs                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.2. Implementation

```javascript
// Consumer tier: Encrypted IOC distribution (X25519 envelope)
async function syncConsumerBlocklist(config) {
  // 1. Fetch encrypted IOC package
  const response = await fetch(`${config.blocklist_endpoint}/encrypted/${config.org_id}.json`);
  const envelope = await response.json();

  // 2. Decrypt IOCs locally
  const iocs = await decryptThreatFeed(envelope, config.gpo_private_key);

  // 3. Compile to DNR rules
  const rules = iocs.map((ioc, index) => ({
    id: index + 1,
    priority: 1,
    action: { type: "block" },
    condition: { 
      urlFilter: `||${ioc}^`,
      resourceTypes: ["main_frame", "sub_frame"]
    }
  }));
  
  // 4. Apply rules
  const currentRules = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: currentRules.map(r => r.id),
    addRules: rules
  });
  
  console.log(`Applied ${rules.length} DNR rules`);
  return true;
}

async function decryptThreatFeed(envelope, privateKeyJwk) {
  // 1. Find matching header by kid
  const header = envelope.headers.find((entry) => entry.kid === privateKeyJwk.kid);
  if (!header) throw new Error("No matching key id for threat feed envelope");

  // 2. Import X25519 private key
  const privateKey = await crypto.subtle.importKey(
    "jwk", privateKeyJwk,
    { name: "X25519" },
    false, ["deriveBits"]
  );

  // 3. Derive shared secret from ephemeral pub key
  const ephemeralPub = await crypto.subtle.importKey(
    "raw",
    base64ToArrayBuffer(header.ephemeral_pub),
    { name: "X25519" },
    false, []
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "X25519", public: ephemeralPub },
    privateKey,
    256
  );

  // 4. Derive AES key-encryption-key via HKDF-SHA256
  const kek = await deriveAesKeyFromHkdf(sharedSecret);

  // 5. Unwrap session key
  const sessionKeyBytes = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToArrayBuffer(header.wrap_iv) },
    kek,
    base64ToArrayBuffer(header.encrypted_session_key)
  );
  const sessionKey = await crypto.subtle.importKey(
    "raw",
    sessionKeyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  // 6. Decrypt payload
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToArrayBuffer(envelope.iv) },
    sessionKey,
    base64ToArrayBuffer(envelope.ciphertext)
  );

  return JSON.parse(new TextDecoder().decode(plaintext));
}
```

---

## 8. What BlockIOC Stores vs. What BlockIOC Can Read

| Data | Stored | Can BlockIOC Read It? |
|------|--------|----------------------|
| Encrypted forensics blobs | ✓ | ✗ No (RSA-encrypted AES key) |
| **Encrypted IOC packages (consumer)** | ✓ | ✗ No (RSA-encrypted) |
| Forensics timestamp | ✓ | ✓ (operational metadata) |
| org_id | ✓ | ✓ (routing/billing) |
| key_version | ✓ | ✓ (for multi-key support) |
| Customer's public keys | ✓ | ✓ (public by design) |
| **Customer's private keys** | ✗ | ✗ (never transmitted) |
| **Customer's salt** | ✗ | ✗ (never transmitted) |
| **Plaintext forensics** | ✗ | ✗ (encrypted client-side) |
| **Plaintext IOCs** | ✗ | ✗ (encrypted before upload) |

---

## 9. Threat Model

### 9.1. What Is Protected

| Threat | Protection |
|--------|------------|
| BlockIOC database breach | Attackers get encrypted garbage |
| BlockIOC employee goes rogue | Cannot decrypt forensics or IOCs (no private key) |
| Legal subpoena to BlockIOC | Can only provide encrypted blobs |
| BlockIOC compromised (supply chain) | BYO-Trust customers unaffected; consumer tier protected by encryption |

### 9.2. What Is Exposed (Metadata)

| Metadata | Visible To BlockIOC |
|----------|---------------------|
| Number of blocks per org | ✓ (for billing/rate limiting) |
| Timing of blocks | ✓ (timestamp on uploads) |
| Blob sizes | ✓ (storage metrics) |
| Number of IOCs per org | ✓ (encrypted package size) |

**Mitigation:** This metadata exposure is acceptable for a security tool. Required for billing and abuse prevention.

---

## 10. Implementation Checklist

### 10.1. Extension (~200 lines of crypto code)

- [ ] `encryptForensics(payload, publicKey, keyVersion)` — RSA-OAEP + AES-GCM hybrid
- [ ] `decryptThreatFeed(envelope, privateKey)` — X25519 + HKDF + AES-GCM
- [ ] `wrapVaultKey(vaultKey, recipientPub)` — X25519 + HKDF + AES-GCM
- [ ] `hashIOC(ioc, salt, scope)` — SHA-256 with canonicalization
- [ ] `storeBlocklistBinary(hashes)` — Binary compact storage
- [ ] `loadBlocklistBinary()` — Binary compact loading
- [ ] `canonicalizeUrl(url, scope)` — URL normalization
- [ ] Helper functions: `hexToBytes`, `bytesToHex`, `arrayBufferToBase64`, `base64ToArrayBuffer`, `deriveAesKeyFromHkdf`

### 10.2. Admin Tool (Static HTML)

- [ ] Key generation page (`/keygen`) — **X25519 for Team Mesh**
- [ ] Forensics viewer page (`/viewer`)
- [ ] Threat feed encryptor for consumer tier
- [ ] Single-file config export for Standalone Mode

### 10.3. GPO/MDM Schema

```json
{
  "org_id": "uuid",
  "public_encryption_key": { "kty": "RSA", ... },
  "gpo_private_key": { "kty": "OKP", "crv": "X25519", "kid": "2026_key_v2", ... },
  "salt": "base64...",
  "key_version": 1,
  "algorithm_version": "x25519-v1",
  "blocklist_url": "https://customer-cdn.com/threat-feed.json"
}
```

### 10.4. Artifacts to Build

- `crypto-x25519.js` — Team Mesh + Threat Feed crypto wrapper
- `crypto-rsa.js` — Forensics export wrapper
- `background.js` — Team requests poll + ingest retry queue
- `admin-keygen.js` — Generate X25519 GPO keys (Node.js)
- `manifest.json` — `storage`, `unlimitedStorage`, `alarms` (runtime host permissions)

---

## 11. Why This Sells

### To Security-Conscious Customers:
> "We mathematically cannot read your data. Not 'we promise not to look' — we don't have the keys."

### To Compliance Teams:
> "Forensic content is encrypted client-side with customer-held keys. We store encrypted payloads we cannot decrypt. Decryption requires keys that never touch our servers."

### To Paranoid Enterprises:
> "Threat feeds are encrypted end-to-end with your own keys. Even if we get compromised, attackers can't read or tamper with your feeds."

### The Solo Founder Paradox:
> **"Simple to run, impossible to compromise."**

Infrastructure: Simple for blocking (static files on R2, no always-on compute). Optional hash-only analysis pipelines may run when enabled.  
Security: Advanced (client-side crypto, zero-knowledge design).

---

**Total Code:** ~200 lines of JavaScript wrapper code.  
**Dependencies:** Zero (Web Crypto API is native).  
**Server Cost:** $0 (crypto runs on client).

---

**End of Specification.**
