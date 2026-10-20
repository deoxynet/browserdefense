# Security

Report vulnerabilities privately through [GitHub security advisories](https://github.com/deoxynet/browserdefense/security/advisories/new). Do not include credentials, private keys, real forensic captures, or customer indicators in public issues.

This initial release requires Chrome 133+ for native X25519 support. Other Chromium browsers require separate compatibility validation. Blocking covers browser HTTP(S) traffic; see the [threat model](docs/threat-model.md) for scope and limitations.

Private decryption/signing keys belong to the operator. Generate them locally and keep them outside the repository. Public verification/encryption keys and clearly synthetic examples are not private credentials.

The public repository starts from a reviewed snapshot rather than importing development history. The separately licensed admin application, local environment files, emulator databases, and development tooling binaries are excluded. Automated source checks run in CI, but operators must still protect their deployment credentials.
