# Compliance & Regulatory Alignment

This document maps BrowserDefense's security controls to common compliance frameworks and regulatory requirements.

## Compliance Philosophy

BrowserDefense's zero-knowledge architecture simplifies compliance:

1. **Minimized data exposure** — We store encrypted blobs we cannot decrypt
2. **Customer-controlled keys** — Customers maintain cryptographic control
3. **Clear scope definition** — We protect web traffic (Layer 7), not all network activity

This design means many compliance requirements are satisfied structurally, not through policy controls.

## NIST 800-53 Mapping

### SI-4: Information System Monitoring

BrowserDefense directly supports **SI-4(24): Indicators of Compromise**.

| SI-4 Control | BrowserDefense Implementation |
|--------------|------------------------|
| **SI-4(24)(a)** Discover, collect, distribute IOCs | IOC blocklists distributed to endpoints via signed manifests |
| **SI-4(24)(b)** Use automated mechanisms | Browser extension automates blocking decisions |
| **SI-4(24)(c)** Provide IOC information to stakeholders | Forensic records capture block events for SOC review |

### SC-8: Transmission Confidentiality and Integrity

| Control | BrowserDefense Implementation |
|---------|------------------------|
| **SC-8** Protect transmitted information | All forensics encrypted with RSA-OAEP + AES-GCM before transmission |
| **SC-8(1)** Cryptographic protection | Uses industry-standard algorithms (RSA-2048, AES-256, X25519, HKDF) |

### SC-12: Cryptographic Key Establishment and Management

| Control | BrowserDefense Implementation |
|---------|------------------------|
| **SC-12** Establish and manage keys | Customer generates keys locally; key rotation supported via `key_version` |
| **SC-12(1)** Symmetric key availability | AES keys are ephemeral (generated per forensic payload) |
| **SC-12(2)** Asymmetric key production | RSA and X25519 keys generated via Web Crypto API |

### SC-13: Cryptographic Protection

| Control | BrowserDefense Implementation |
|---------|------------------------|
| **SC-13** FIPS-validated cryptography | Web Crypto API implementations are FIPS-validated for RSA/AES in enterprise Chrome |

### SC-28: Protection of Information at Rest

| Control | BrowserDefense Implementation |
|---------|------------------------|
| **SC-28** Protect information at rest | Forensic data encrypted client-side; stored encrypted on Cloudflare R2 |
| **SC-28(1)** Cryptographic mechanisms | AES-GCM-256 encryption |

### AU-6: Audit Record Review, Analysis, and Reporting

| Control | BrowserDefense Implementation |
|---------|------------------------|
| **AU-6** Review and analyze audit records | Forensics Viewer enables SOC analysis of block events |
| **AU-6(3)** Correlate audit repositories | Forensic records exportable for SIEM integration |

### IR-4: Incident Handling

| Control | BrowserDefense Implementation |
|---------|------------------------|
| **IR-4(1)** Automated incident handling | Block events generate forensic records automatically |
| **IR-4(11)** Integrated incident team | Forensics include redirect chains, timestamps for investigation |

## SOC 2 Relevance

BrowserDefense's architecture supports SOC 2 Trust Service Criteria:

### Security (Common Criteria)

| Criteria | BrowserDefense Implementation |
|----------|------------------------|
| **CC6.1** Logical access security | Extension access controlled via GPO/MDM policy |
| **CC6.6** Restrict system boundaries | Extension operates within browser sandbox |
| **CC6.7** Protect transmission | All data encrypted before transmission |
| **CC7.2** Monitor for anomalies | Block events logged for security review |

### Confidentiality

| Criteria | BrowserDefense Implementation |
|----------|------------------------|
| **C1.1** Identify confidential information | Forensic data classified as confidential, encrypted accordingly |
| **C1.2** Protect confidential information | Encryption with customer-controlled keys |

### Availability

| Criteria | BrowserDefense Implementation |
|----------|------------------------|
| **A1.2** Environmental protections | Cloudflare infrastructure provides geographic redundancy |

**Note:** BrowserDefense is a security tool, not a SOC 2 compliant service. These mappings show how BrowserDefense supports your organization's SOC 2 posture.

## GDPR Considerations

### Data Minimization (Article 5(1)(c))

| Principle | BrowserDefense Implementation |
|-----------|------------------------|
| Collect only necessary data | Only blocked URL forensics collected; no browsing history |
| Limit retention | Configurable retention (30/90 days); automatic deletion |

### Security of Processing (Article 32)

| Requirement | BrowserDefense Implementation |
|-------------|------------------------|
| Encryption | End-to-end encryption with customer keys |
| Pseudonymization | User identifiers encrypted within forensic payloads |

### Data Subject Rights

| Right | BrowserDefense Support |
|-------|-----------------|
| **Access (Art. 15)** | Customers can export encrypted forensics |
| **Erasure (Art. 17)** | Customers can request deletion of org data |
| **Portability (Art. 20)** | Forensic data exportable as JSON |

### Data Processing Agreement

Available upon request for customers requiring GDPR DPA.

## PCI-DSS Considerations

BrowserDefense does not process, store, or transmit cardholder data. However, it supports PCI-DSS objectives:

| Requirement | BrowserDefense Support |
|-------------|-----------------|
| **Req. 5** Protect against malware | Blocks malicious URLs that could deliver malware |
| **Req. 10** Track access to resources | Forensic logging of blocked access attempts |
| **Req. 11** Test security systems | Supports threat detection at browser level |

## HIPAA Considerations

BrowserDefense's zero-knowledge architecture supports HIPAA requirements:

| Safeguard | BrowserDefense Implementation |
|-----------|------------------------|
| **Access Control (§164.312(a)(1))** | Extension access via GPO/MDM policy |
| **Transmission Security (§164.312(e)(1))** | All data encrypted in transit and at rest |
| **Encryption (§164.312(a)(2)(iv))** | AES-256-GCM encryption, RSA-2048 key wrapping |

### Business Associate Agreement

BrowserDefense can execute a BAA as part of the Compliance Package ($15,000).

## FedRAMP Alignment

While BrowserDefense is not FedRAMP authorized, its architecture aligns with FedRAMP requirements:

| Control Family | Alignment |
|---------------|-----------|
| **Access Control (AC)** | GPO/MDM-based deployment, no user-managed access |
| **Audit (AU)** | Forensic logging of security events |
| **Security Assessment (CA)** | Open source code available for review |
| **System and Communications Protection (SC)** | FIPS-validated cryptography, encrypted transmission |
| **System and Information Integrity (SI)** | IOC-based threat detection |

## CIS Controls Mapping

BrowserDefense supports several CIS Critical Security Controls:

| Control | BrowserDefense Support |
|---------|-----------------|
| **CIS 9: Email and Web Browser Protections** | Direct implementation via browser-level IOC blocking |
| **CIS 10: Malware Defenses** | Blocks known malicious URLs/domains |
| **CIS 13: Network Monitoring and Defense** | Forensic capture of blocked threats |

## Scope Limitations

BrowserDefense's compliance value is scoped to HTTP/HTTPS web traffic:

| In Scope | Out of Scope |
|----------|--------------|
| Web navigation blocking | DNS-level blocking |
| URL-based IOC detection | Raw packet inspection |
| Browser-level forensics | Network tap forensics |
| Redirect chain capture | Non-HTTP protocol analysis |

For complete network protection, complement BrowserDefense with:
- DNS sinkhole (Cisco Umbrella, Cloudflare Gateway)
- Network firewall (Palo Alto, Fortinet)
- EDR/XDR (CrowdStrike, SentinelOne)

## Security Questionnaire Shortcuts

Common security questionnaire questions and answers:

| Question | Answer |
|----------|--------|
| Do you store PII? | Encrypted forensics may contain URLs. We cannot decrypt them. |
| Where is data stored? | Cloudflare R2 (encrypted blobs). Customers can self-host. |
| Do you have SOC 2? | We do not have SOC 2 certification. See Trust Center for controls. |
| What encryption do you use? | RSA-OAEP-2048, AES-GCM-256, X25519 + HKDF for threat feeds. |
| Can employees access customer data? | No. Data is encrypted with customer keys we don't possess. |
| What is your incident response process? | security@browserdefense.com. Best-effort response. |
| Do you have a DPA? | Available upon request. |
| Do you have a BAA? | Available as part of Compliance Package ($15,000). |
| Is data encrypted at rest? | Yes. AES-256-GCM, customer-controlled keys. |
| Is data encrypted in transit? | Yes. TLS 1.3 for transport, plus application-layer encryption. |
| Do you support SSO? | No. Extension is deployed via GPO/MDM, not user login. |
| What is your data retention? | 30 days (Team), 90 days (Business). Configurable for self-hosted. |

## Compliance Package

For organizations requiring formal compliance documentation:

**Price:** $15,000 (one-time)

**Includes:**
- Security questionnaire completion (up to 200 questions)
- Signed standard BAA (if applicable)
- Architecture review documentation
- Cryptographic implementation summary

**Does NOT include:**
- Custom contract terms
- SLA commitments
- Dedicated support
- On-site assessments

## Audit Trail

BrowserDefense forensic records provide audit evidence:

```json
{
  "timestamp": "2026-01-09T14:32:17.000Z",
  "blocked_url": "https://phishing-site.example.com/login",
  "redirect_chain": [
    "https://email-link.example.com/click?id=abc",
    "https://tracking.example.net/redir",
    "https://phishing-site.example.com/login"
  ],
  "matched_ioc": "HOST_ONLY",
  "extension_version": "1.2.3",
  "user_context": {
    "initiator": "https://mail.example.com/inbox"
  }
}
```

**Audit-relevant fields:**
- `timestamp` — When the block occurred
- `redirect_chain` — Full attack path
- `initiator` — Where the user clicked from
- `matched_ioc` — What rule triggered the block

## Incident Response Contact

For security vulnerabilities or incidents:

**Email:** security@browserdefense.com

**Response commitment:** Best-effort, typically within 48 hours for security issues.

**Bug bounty:** Not currently offered.
