# BrowserDefense Key Management Guide

This guide covers generating, deploying, and rotating cryptographic keys for BrowserDefense.

## Overview

BrowserDefense uses two key pairs:

| Key Type | Algorithm | Purpose |
|----------|-----------|---------|
| **Signing Keys** | P-256 ECDSA | Sign blocklist manifests to prevent tampering |
| **Encryption Keys** | RSA-OAEP 2048-bit | Encrypt forensics data client-side |

Both key pairs follow the same pattern:
- **Public key** → deployed to browser extensions
- **Private key** → kept secure on your infrastructure

## Quick Start: Generate All Keys

```bash
cd cli
npm install && npm run build

# Generate both signing and encryption keys + org config
./bin/browserdefense keygen --type all --output ./keys
```

This creates:
```
keys/
├── signing-public.jwk       # Deploy to extensions (blocklist verification)
├── signing-private.jwk      # Keep secure (sign blocklists)
├── encryption-public.jwk    # Deploy to extensions (forensics encryption)
├── encryption-private.jwk   # Keep secure (decrypt forensics in SIEM)
└── browserdefense-config.json  # Pre-filled config template
```

## Signing Keys (Blocklist Integrity)

Signing keys ensure blocklist updates haven't been tampered with.

### Generate Signing Keys

```bash
# P-256 ECDSA (recommended - maximum compatibility)
./bin/browserdefense keygen --type signing --output ./keys

# Ed25519 (experimental - requires Chrome 113+)
./bin/browserdefense keygen --type signing --ed25519 --output ./keys
```

### Sign a Blocklist

```bash
# Create a manifest from your IOCs
./bin/browserdefense compile --input iocs.txt --salt "your-secret-salt" --output ./blocklist

# Sign the manifest
./bin/browserdefense sign --key ./keys/signing-private.jwk --manifest ./blocklist/manifest.json
```

### Verify a Signature

```bash
./bin/browserdefense validate --key ./keys/signing-public.jwk --manifest ./blocklist/manifest.json
```

### Deploy Public Key

Add `signing-public.jwk` to your extension configuration:

```json
{
  "signing_public_key": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "...",
    "kid": "p256-v1"
  }
}
```

### Store Private Key Securely

The signing private key should be stored in:
- **CI/CD secrets** (GitHub Actions, GitLab CI)
- **Key management service** (AWS KMS, HashiCorp Vault)
- **Air-gapped machine** (for high-security environments)

Never commit `signing-private.jwk` to version control.

## Encryption Keys (Forensics Privacy)

Encryption keys protect forensics data with zero-knowledge architecture.

### Generate Encryption Keys

```bash
./bin/browserdefense keygen --type encryption --output ./keys
```

### How Encryption Works

1. Browser captures forensics event (redirect chain, timestamp, etc.)
2. Extension encrypts with your `encryption-public.jwk`
3. Encrypted blob uploaded to your endpoint
4. You decrypt with `encryption-private.jwk` in your SIEM

```
[Browser] --encrypt--> [Your Endpoint] --decrypt--> [SIEM/Analysis]
              ^                              ^
       public key                     private key
```

### Deploy Public Key

Add `encryption-public.jwk` to your extension configuration:

```json
{
  "encryption_public_key": {
    "kty": "RSA",
    "n": "...",
    "e": "AQAB",
    "alg": "RSA-OAEP-256"
  }
}
```

### Decrypt Forensics

```bash
# Decrypt a single file
./bin/browserdefense decrypt \
  --key ./keys/encryption-private.jwk \
  --input forensics-2026-01-11.enc \
  --format pretty

# Decrypt a directory of files
./bin/browserdefense decrypt \
  --key ./keys/encryption-private.jwk \
  --input ./forensics/ \
  --output ./decrypted/
```

### Store Private Key Securely

The encryption private key should be stored in:
- **SIEM/SOAR platform** (for automated decryption)
- **Secure analysis workstation** (for manual review)
- **HSM** (for regulated industries)

This key is the only way to decrypt forensics. Losing it means losing access to historical forensics data.

## Key Rotation

### When to Rotate

- **Signing keys**: Annually, or if private key is compromised
- **Encryption keys**: Annually, or when changing SIEM infrastructure

### Rotation Process

#### 1. Generate New Keys

```bash
./bin/browserdefense keygen --type all --output ./keys-v2
```

#### 2. Update Extension Configuration

Deploy new public keys via GPO/Intune:

```json
{
  "signing_public_key": { /* new key */ },
  "encryption_public_key": { /* new key */ },
  "key_version": 2
}
```

#### 3. Update Blocklist Signing

Start signing new blocklists with the new signing private key.

#### 4. Maintain Decryption Capability

Keep old encryption private keys to decrypt historical forensics:

```bash
# Old forensics (before rotation)
./bin/browserdefense decrypt --key ./keys-v1/encryption-private.jwk --input old.enc

# New forensics (after rotation)
./bin/browserdefense decrypt --key ./keys-v2/encryption-private.jwk --input new.enc
```

### Grace Period

During rotation, extensions will accept blocklists signed with either old or new keys for a configurable grace period. Configure this in your extension policy:

```json
{
  "key_rotation_grace_days": 30
}
```

## Configuration Template

The `keygen --type all` command generates a pre-filled config template:

```json
{
  "org_id": "generated-uuid",
  "signing_public_key": { /* JWK */ },
  "encryption_public_key": { /* JWK */ },
  "blocklist_endpoint": "https://YOUR_CDN_HERE/blocklist.json",
  "forensics_endpoint": "https://YOUR_ENDPOINT_HERE/forensics",
  "ioc_salt": "generated-salt",
  "key_version": 1,
  "algorithm_version": "p256-v1"
}
```

Update `blocklist_endpoint` and `forensics_endpoint` before deploying.

## Enterprise Deployment

### GPO (Windows)

1. Copy config to SYSVOL
2. Reference in registry policy:
   ```
   HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\{id}\policy\
   ```

### Intune (Windows/macOS)

1. Upload config as custom profile
2. Use OMA-URI for Chrome policies

### MDM (macOS)

1. Embed in `.mobileconfig` profile
2. Deploy via Jamf/Mosyle/Kandji

See [Enterprise Deployment Guide](enterprise/deployment.md) for detailed instructions.

## Security Best Practices

### Private Key Storage

| Environment | Recommended Storage |
|-------------|---------------------|
| CI/CD | Encrypted secrets (GitHub, GitLab) |
| Production | Key management service (AWS KMS, Vault) |
| Air-gapped | Encrypted USB, HSM |
| Development | Local file with restricted permissions |

### Access Control

- Limit access to private keys to key administrators only
- Use separate keys for production and development
- Audit key usage via your KMS logs

### Backup

- Back up private keys to secure, offline storage
- Test backup restoration annually
- Document recovery procedures

## Troubleshooting

### "Invalid signature" errors

1. Verify you're using the correct public key
2. Check that the manifest hasn't been modified after signing
3. Confirm the algorithm version matches (`p256-v1` vs `ed25519-v2`)

### "Decryption failed" errors

1. Verify you're using the correct private key version
2. Check that the encrypted file isn't corrupted
3. Confirm the file was encrypted with your public key

### Key mismatch

If public and private keys don't match:
```bash
# Regenerate the pair
./bin/browserdefense keygen --type <signing|encryption> --output ./keys
```

## CLI Reference

```bash
# Generate all keys and config
browserdefense keygen --type all --output ./keys

# Generate signing keys only
browserdefense keygen --type signing --output ./keys

# Generate encryption keys only
browserdefense keygen --type encryption --output ./keys

# Use Ed25519 (experimental)
browserdefense keygen --type signing --ed25519 --output ./keys

# Sign a blocklist
browserdefense sign --key ./keys/signing-private.jwk --manifest ./blocklist/manifest.json

# Validate a signature
browserdefense validate --key ./keys/signing-public.jwk --manifest ./blocklist/manifest.json

# Decrypt forensics
browserdefense decrypt --key ./keys/encryption-private.jwk --input ./forensics/
```
