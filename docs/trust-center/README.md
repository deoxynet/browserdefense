# BrowserDefense Trust Center

Welcome to the BrowserDefense Trust Center. This documentation provides security teams with the information needed to evaluate BrowserDefense for deployment in your organization.

## What is BrowserDefense?

BrowserDefense is a browser-based Indicator of Compromise (IOC) blocking extension with zero-knowledge forensics. It enables SOC teams to block phishing domains, malware URLs, and other malicious web content at the browser level while maintaining cryptographic privacy guarantees. Optional shadow detection fingerprints phishing kits using hash-only DOM structure (no URLs or content).

## Zero-Knowledge Architecture

**We mathematically cannot read your data.**

This isn't a policy promise—it's a cryptographic guarantee:

- **Forensic data** is encrypted client-side with your organization's RSA public key before transmission. We store encrypted blobs we cannot decrypt.
- **Threat feeds** are encrypted with your organization's X25519 keys. We cannot read or tamper with your feeds.
- **Optional shadow detection** uses hash-only structural fingerprints (no URLs, no content).
- **Your private keys never touch our servers.** Key generation happens in your browser. You export and secure the private keys yourself.

## Trust Center Contents

| Document | Description |
|----------|-------------|
| [Privacy Policy](./privacy-policy.md) | Plain-language privacy policy for end users |
| [Architecture](./architecture.md) | System design, data flows, and component overview |
| [Data Handling](./data-handling.md) | What data we collect, process, and store |
| [Cryptography](./cryptography.md) | Cryptographic algorithms, key management, and security properties |
| [Compliance](./compliance.md) | NIST mappings, SOC 2 relevance, and regulatory considerations |

## Quick Facts

| Question | Answer |
|----------|--------|
| Do you store plaintext URLs? | **No.** Forensics are encrypted client-side. |
| Do you see our IOC blocklists? | **No.** BYO-Trust uses customer-signed blocklists. |
| Where does data go? | Cloudflare R2 (encrypted blobs) or your own endpoint. |
| What browsers are supported? | Chromium-based (Chrome, Edge, Brave, Opera). |
| Is there an SLA? | No. Best-effort email support. |
| Can I audit the code? | Yes. Source available on GitHub. |
| Do you collect telemetry? | **No by default.** Optional hash-only shadow detection if enabled. |

## Security Contact

For security vulnerabilities or questions, contact: **security@browserdefense.com**

## Additional Resources

- [Cryptographic Specification (full technical detail)](../Cryptographic_Specification_v3.md)
- [Architecture Hardening Specification](../Architecture_Hardening_Specification.md)
- [GitHub Repository](https://github.com/deoxynet/browserdefense)
