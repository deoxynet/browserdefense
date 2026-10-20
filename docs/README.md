# BrowserDefense documentation

Start with the [repository README](../README.md) for installation and the [contributor guide](../CONTRIBUTING.md) for local checks.

## Specifications

- [Implementation review](Implementation_Review.md): architectural decisions and validation requirements
- [Cryptography](Cryptographic_Specification_v3.md): key agreement, encryption, and signing
- [Canonicalization](Canonicalization_Specification.md): indicator normalization
- [Architecture hardening](Architecture_Hardening_Specification.md): reliability design
- [Blocklist distribution](Blocklist_Distribution_Specification.md): signed update format
- [DOM detection](Architecture_v2_DOM_Detection.md): optional structural detection

Design documents include proposals and historical benchmarks. Validate behavior against the current source and tests; they are not release certifications. Chrome 133+ is required for native X25519 ([Chrome release notes](https://developer.chrome.com/release-notes/133)). A periodic heartbeat does not guarantee that Chrome keeps the service worker alive.

## Operations and release

- [Enterprise deployment](enterprise/deployment.md)
- [Key management](key-management.md)
- [Connector SDK](CONNECTOR_SDK.md)
- [Pilot go/no-go checklist](go-no-go-checklist.md)
- [Chrome Web Store submission](SUBMISSION_GUIDE.md)
- [Store listing draft](STORE_LISTING.md)

Managed endpoint deployment and real incident validation remain outstanding. Store listing and privacy disclosures need review against the enabled features before submission.

## Security

- [Security reporting](../SECURITY.md)
- [Threat model](threat-model.md)
- [Trust Center](trust-center/README.md)
- [Privacy policy](trust-center/privacy-policy.md)
- [Data handling](trust-center/data-handling.md)

The separately licensed admin application is not part of the public source snapshot. Private keys, environment files, emulator data, and development history are also excluded.
