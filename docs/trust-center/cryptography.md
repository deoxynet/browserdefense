# Cryptographic Specification

This document describes BlockIOC's cryptographic architecture, algorithms, and key management practices.

## Design Philosophy

BlockIOC uses client-side cryptography with customer-controlled keys. The security model ensures that:

1. **BlockIOC cannot decrypt forensic data** — We don't have customer private keys
2. **BlockIOC cannot read or tamper with threat feeds** — Feeds are end-to-end encrypted
3. **Compromise of BlockIOC infrastructure yields encrypted garbage** — No plaintext ever stored

All cryptographic operations use the **Web Crypto API** (`crypto.subtle`), which is:
- Native to the browser (no external dependencies)
- FIPS 140-2 validated for RSA/AES in enterprise Chrome
- Audited by browser vendors

## Cryptographic Primitives

| Function | Algorithm | Parameters | Standard |
|----------|-----------|------------|----------|
| **Asymmetric Encryption** | RSA-OAEP | 2048-bit modulus, SHA-256 | PKCS#1 v2.1 |
| **Symmetric Encryption** | AES-GCM | 256-bit key, 96-bit IV | NIST SP 800-38D |
| **Key Agreement** | X25519 | 255-bit | RFC 7748 |
| **Key Derivation** | HKDF-SHA256 | 256-bit output | RFC 5869 |
| **Hashing** | SHA-256 | 256-bit output | FIPS 180-4 |

### Why These Algorithms?

| Algorithm | Rationale |
|-----------|-----------|
| **RSA-OAEP 2048** | Universal browser support, sufficient security margin through 2030+ |
| **AES-GCM 256** | Authenticated encryption, prevents tampering, industry standard |
| **X25519 + HKDF** | Fast ECDH, constant-size keys, clean envelope encryption |
| **SHA-256** | Collision-resistant, fast, universally supported |

### Why X25519?

X25519 is the standard for Team Mesh and Threat Feeds:
- Constant 32-byte keys
- Fast ECDH for high-frequency distribution
- Clean envelope encryption with HKDF + AES-GCM

## Protocol A: Forensics Encryption (Dead Drop)

Forensic data is encrypted using hybrid encryption (RSA + AES) before leaving the browser.

### Encryption Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: Generate ephemeral AES key                                         │
│                                                                             │
│  const aesKey = await crypto.subtle.generateKey(                           │
│    { name: "AES-GCM", length: 256 },                                       │
│    true,                                                                    │
│    ["encrypt"]                                                              │
│  );                                                                         │
│                                                                             │
│  // New key for every forensic payload (forward secrecy)                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: Encrypt payload with AES-GCM                                       │
│                                                                             │
│  const iv = crypto.getRandomValues(new Uint8Array(12));  // 96-bit IV      │
│                                                                             │
│  const ciphertext = await crypto.subtle.encrypt(                           │
│    { name: "AES-GCM", iv },                                                │
│    aesKey,                                                                  │
│    payloadBytes                                                             │
│  );                                                                         │
│                                                                             │
│  // Authenticated encryption: ciphertext includes authentication tag       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: Wrap AES key with RSA-OAEP                                         │
│                                                                             │
│  const wrappedKey = await crypto.subtle.encrypt(                           │
│    { name: "RSA-OAEP" },                                                   │
│    customerPublicKey,  // Only customer can decrypt                        │
│    rawAesKey                                                                │
│  );                                                                         │
│                                                                             │
│  // RSA protects the AES key; customer's private key required to unwrap    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 4: Transmit encrypted package                                         │
│                                                                             │
│  {                                                                          │
│    "org_id": "uuid",                                                       │
│    "key_version": 1,                                                       │
│    "iv": "base64...",          // Public (needed for decryption)           │
│    "wrapped_key": "base64...", // Encrypted with customer RSA key          │
│    "ciphertext": "base64..."   // Encrypted with ephemeral AES key         │
│  }                                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Confidentiality** | Only customer with RSA private key can decrypt |
| **Integrity** | AES-GCM authentication tag detects tampering |
| **Forward Secrecy** | Each payload uses a new AES key |
| **Non-repudiation** | Timestamp + org_id provides audit trail |

### Decryption (Customer-Side)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: Unwrap AES key with RSA private key                                │
│                                                                             │
│  const aesKey = await crypto.subtle.decrypt(                               │
│    { name: "RSA-OAEP" },                                                   │
│    privateKey,           // Customer's private key (never shared)          │
│    wrappedKeyBytes                                                          │
│  );                                                                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: Decrypt payload with AES-GCM                                       │
│                                                                             │
│  const plaintext = await crypto.subtle.decrypt(                            │
│    { name: "AES-GCM", iv },                                                │
│    aesKey,                                                                  │
│    ciphertext                                                               │
│  );                                                                         │
│                                                                             │
│  // If authentication tag fails, decryption throws (tampering detected)    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Protocol B: Threat Feed Encryption (Supply Chain Lock)

Threat feeds are distributed via public storage but encrypted end-to-end. BlockIOC cannot read or tamper with customer feeds.

### Encryption Flow (Server Side)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: Generate ephemeral X25519 keypair                                  │
│                                                                             │
│  STEP 2: Derive shared secret with customer's public mesh key               │
│                                                                             │
│  STEP 3: HKDF-SHA256(sharedSecret) -> AES key-encryption-key                │
│                                                                             │
│  STEP 4: Encrypt session key + payload with AES-256-GCM                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Decryption Flow (Browser Extension)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: Import gpo_private_key (X25519)                                    │
│                                                                             │
│  STEP 2: Derive shared secret with ephemeral_pub                            │
│                                                                             │
│  STEP 3: HKDF-SHA256(sharedSecret) -> AES key-encryption-key                │
│                                                                             │
│  STEP 4: Decrypt session key, then decrypt payload                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Security Properties

| Threat | Protection |
|--------|------------|
| Malicious CDN compromise | Encrypted payloads are unreadable |
| BlockIOC infrastructure compromise | Feeds remain encrypted |
| Man-in-the-middle | AES-GCM authentication fails |
| Rollback attack | Version field prevents downgrade |

## IOC Hashing

IOCs are hashed with a customer-specific salt before storage, preventing rainbow table attacks and ensuring BlockIOC cannot reverse hashes to URLs.

### Hashing Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: Canonicalize URL                                                   │
│                                                                             │
│  function canonicalizeUrl(url) {                                           │
│    const parsed = new URL(url);                                            │
│    let canonical = parsed.protocol + '//' +                                │
│                    parsed.hostname.toLowerCase().replace(/\.$/, '');       │
│    // Remove default ports, normalize path...                              │
│    return canonical;                                                        │
│  }                                                                          │
│                                                                             │
│  // Ensures matching regardless of URL format variations                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: Combine with customer salt                                         │
│                                                                             │
│  const data = canonical + ':' + salt;                                      │
│                                                                             │
│  // Salt is 256 bits, generated at org creation                            │
│  // Salt never leaves customer infrastructure                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: SHA-256 hash                                                       │
│                                                                             │
│  const hash = await crypto.subtle.digest('SHA-256', dataBytes);            │
│                                                                             │
│  // Result: 256-bit hash that cannot be reversed without salt              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Pre-image resistance** | Cannot derive URL from hash |
| **Salt protection** | Rainbow tables ineffective without customer salt |
| **Privacy** | BlockIOC cannot determine what IOCs customer blocks |

## Key Management

### Key Types

| Key | Algorithm | Generated By | Stored By | Purpose |
|-----|-----------|--------------|-----------|---------|
| **Encryption Public Key** | RSA-OAEP 2048 | Customer (browser) | GPO/MDM → Extension | Encrypt forensics |
| **Encryption Private Key** | RSA-OAEP 2048 | Customer (browser) | Customer vault | Decrypt forensics |
| **Mesh Public Key** | X25519 | Customer (browser) | BlockIOC | Encrypt threat feeds |
| **GPO Private Key** | X25519 | Customer (browser) | GPO/MDM → Extension | Decrypt threat feeds |
| **IOC Salt** | 256-bit random | Customer (browser) | GPO/MDM → Extension | Hash IOCs |

### Key Generation

All keys are generated in the customer's browser using the Key Generator tool:

```javascript
// RSA keypair for forensics encryption
const encryptionKeypair = await crypto.subtle.generateKey(
  {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256"
  },
  true,  // extractable
  ["encrypt", "decrypt"]
);

// X25519 keypair for threat feed encryption
const meshKeypair = await crypto.subtle.generateKey(
  { name: "X25519" },
  true,
  ["deriveBits"]
);

// Random salt for IOC hashing
const salt = crypto.getRandomValues(new Uint8Array(32));
```

### Key Distribution

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  KEY GENERATION (Admin's Browser)                                            │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  keygen.blockioc.com (static HTML, no server calls)                 │   │
│  │                                                                     │   │
│  │  1. Generate RSA keypair (encryption)                              │   │
│  │  2. Generate X25519 keypair (mesh)                                 │   │
│  │  3. Generate random salt                                           │   │
│  │  4. Export keys as JWK                                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                          │                                                  │
│          ┌───────────────┴───────────────┐                                 │
│          │                               │                                 │
│          ▼                               ▼                                 │
│  ┌───────────────────┐          ┌───────────────────┐                     │
│  │  PUBLIC CONFIG    │          │  PRIVATE KEYS     │                     │
│  │  (GPO/MDM)        │          │  (1Password/Vault)│                     │
│  │                   │          │                   │                     │
│  │  • public_enc_key │          │  • private_enc_key│                     │
│  │  • public_mesh_key│          │  • private_mesh_key│                    │
│  │  • salt           │          │                   │                     │
│  │  • org_id         │          │                   │                     │
│  └───────────────────┘          └───────────────────┘                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Rotation

Customers can rotate keys by:

1. Generating new keypairs in Key Generator
2. Updating GPO/MDM with new public keys
3. Incrementing `key_version`
4. Old forensics remain decryptable with old private key

The `key_version` field in forensic records indicates which key version was used for encryption.

## Threat Model

### What Is Protected

| Threat | Protection |
|--------|------------|
| BlockIOC database breach | Attackers get encrypted blobs only |
| BlockIOC employee malfeasance | Cannot decrypt without customer keys |
| Legal subpoena to BlockIOC | Can only provide encrypted data |
| CDN compromise | Signature verification rejects tampered blocklists |
| Network interception | All data encrypted; TLS for transport |

### Metadata Exposure

BlockIOC can observe:
- Number of forensic records per org
- Timing of block events
- Encrypted blob sizes
- Blocklist update frequency

This metadata is required for operational purposes and cannot be eliminated without removing service functionality.

### Out of Scope

| Threat | Why Out of Scope |
|--------|------------------|
| Compromised customer endpoint | If the browser is compromised, all bets are off |
| Customer key compromise | Customer responsibility to secure private keys |
| DNS-level attacks | BlockIOC operates at Layer 7 only |
| Browser vulnerabilities | Relies on browser's WebCrypto implementation |

## Algorithm Reference

### RSA-OAEP (Forensics Encryption)

```
Parameters:
  Modulus: 2048 bits
  Public exponent: 65537 (0x010001)
  Hash: SHA-256
  Mask generation function: MGF1-SHA-256

Key format: JWK (JSON Web Key)
Max plaintext size: 190 bytes (for RSA-2048 with SHA-256)
Ciphertext size: 256 bytes
```

### AES-GCM (Payload Encryption)

```
Parameters:
  Key size: 256 bits
  IV size: 96 bits (12 bytes)
  Tag size: 128 bits (16 bytes)

Key generation: crypto.getRandomValues
IV: Fresh random value per encryption
Authentication: Built into GCM mode
```

### X25519 (Key Agreement)

```
Parameters:
  Curve: X25519
  Shared secret: 32 bytes

Key format: JWK (OKP)
Public key size: 32 bytes
```

### SHA-256 (Hashing)

```
Parameters:
  Block size: 512 bits
  Output size: 256 bits (32 bytes)

Usage: IOC hashing, integrity verification
```

## Compliance Alignment

| Standard | Relevant Controls | BlockIOC Implementation |
|----------|-------------------|------------------------|
| NIST SP 800-57 | Key management | Customer-controlled keys, rotation support |
| NIST SP 800-38D | AES-GCM | Native WebCrypto implementation |
| RFC 7748 | Key agreement | X25519 |
| FIPS 180-4 | Secure hashing | SHA-256 |

## Additional Resources

- [Full Cryptographic Specification](../Cryptographic_Specification_v3.md)
- [Web Crypto API Specification](https://www.w3.org/TR/WebCryptoAPI/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/publications)
