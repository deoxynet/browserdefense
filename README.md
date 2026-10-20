# BrowserDefense

**Block phishing domains in 30 seconds, not 3 days.**

Your firewall team has a ticket queue. Your DNS team has a change window. Meanwhile, the phishing campaign is already harvesting credentials.

BrowserDefense is a browser extension that blocks malicious URLs at the endpoint — instantly, regardless of VPN status, with zero-knowledge forensics that capture what your EDR can't see.

## The Problem

| Tool | What it misses |
|------|----------------|
| **DNS sinkhole** | Remote workers off-VPN |
| **Firewall rules** | 3-day ticket queue |
| **EDR** | Redirect chains, cloaked destinations |
| **Email security** | Cloaking defeats scanners |
| **Enterprise browser** | $50k+ and 6-month deployment |

**The gap**: Between "we identified a threat" and "it's blocked everywhere" is hours or days. That's where phishing succeeds.

## The Solution

1. **Add IOC** → API call or dashboard (30 seconds)
2. **Push to browsers** → Signed update propagates instantly
3. **Block everywhere** → Every managed browser, VPN or not
4. **Capture forensics** → Redirect chain, timestamps, context — encrypted client-side

No ticket. No change window. No VPN dependency.

## Features

### Instant IOC Blocking
- Local hash-based URL matching (sub-millisecond lookups)
- Push-based threat feed updates with X25519 envelope encryption
- Binary compact storage (supports 100k+ IOCs)
- Periodic heartbeat for update checks and queued uploads; Chrome may suspend the service worker between events

### Zero-Knowledge Forensics
- Captures redirect chains, referrers, and tab context on block events
- Client-side RSA-OAEP + AES-GCM hybrid encryption
- **You hold the only decryption key** — we literally cannot read your data
- Forensics queue with retry logic and offline support

### Shadow Detection (Optional)
- Hash-only structural fingerprints detect phishing kits on new domains
- No URLs or page content transmitted
- Domains rotate, kits persist — we fingerprint what matters

### Enterprise Connectors (22 integrations)

| Category | Connectors |
|----------|------------|
| **SIEM** | Splunk HEC, Elastic/ELK, IBM QRadar, Google Chronicle, Microsoft Sentinel, Sumo Logic, Datadog, Rapid7 InsightIDR |
| **EDR** | CrowdStrike Falcon, SentinelOne, Microsoft Defender, Carbon Black, Cortex XDR, Bitdefender GravityZone, HarfangLab |
| **SOAR** | Palo Alto XSOAR, ServiceNow |
| **Network** | FortiGate, Zscaler |
| **Cloud** | AWS Security Hub |
| **Universal** | Webhook, Syslog |

### Dual-Mode Platform
- **Sensor Mode (default):** Fleet devices receive updates, block threats, report forensics
- **Hunter Mode (authenticated):** Analysts trigger global blocks from context menu, view live kill feed

## Release status

This is an initial development release. Managed endpoint deployment and real incident validation remain pending; see the [pilot checklist](docs/go-no-go-checklist.md). The separately licensed Makerkit admin application is excluded from this public source distribution.

## Quick Start

```bash
# Clone and build
git clone https://github.com/deoxynet/browserdefense.git
cd browserdefense
corepack enable
pnpm install --frozen-lockfile
pnpm run build:all

# Load in Chrome:
# 1. Navigate to chrome://extensions
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select the dist/ directory
```

### Generate Keys (First-Time Setup)

```bash
cd cli && pnpm install --frozen-lockfile && pnpm run build

# Generate all keys + org config
node dist/index.js keygen --type all --output ./keys
```

### Add Your First IOC

```bash
# Compile IOCs to binary hash format
node dist/index.js compile --input iocs.txt --salt "your-secret-salt" --output ./blocklist

# Sign the blocklist
node dist/index.js sign --key ./keys/signing-private.jwk --manifest ./blocklist/manifest.json
```

## Browser Support

| Browser | Status | Notes |
|---------|--------|-------|
| **Chrome** | Supported | Primary target; Chrome 133+ required |
| **Edge** | Supported | Chromium-based, same APIs |
| **Brave** | Supported | Chromium-based, same APIs |
| **Opera** | Supported | Chromium-based, same APIs |
| **Arc** | Supported | Chromium-based, same APIs |
| **Firefox** | Roadmap | Not supported in this release |
| **Safari** | Not planned | Different extension API |

## Architecture

```
blockiocs/
├── src/
│   ├── background/        # Service worker (blocking, forensics, heartbeat)
│   ├── crypto/            # Web Crypto API (X25519, RSA-OAEP, AES-GCM)
│   ├── storage/           # Binary hash set (not JSON)
│   ├── connectors/        # Enterprise SIEM/EDR integrations
│   ├── popup/             # Extension popup UI
│   └── blocked/           # Block page shown to users
├── cli/                   # Blocklist management tools
├── functions/             # Cloudflare Workers API
└── docs/                  # Specifications and blog posts
```

## Documentation

| Document | Description |
|----------|-------------|
| [Cryptographic Spec](docs/Cryptographic_Specification_v3.md) | X25519, RSA-OAEP, AES-GCM key management |
| [Enterprise Deployment](docs/enterprise/deployment.md) | GPO, Intune, macOS templates |
| [Key Management](docs/key-management.md) | Key generation, rotation, security |
| [GTM Strategy](docs/GTM_Strategy.md) | Messaging and content strategy |
| [Trust Center](docs/trust-center/) | Security and compliance documentation |

## Blog

| Post | Topic |
|------|-------|
| [Why Your EDR Can't See Redirect Chains](docs/blog/edr-redirect-chains.md) | The cloaking problem and browser-level visibility |
| [Block IOCs in 30 Seconds](docs/blog/block-iocs-30-seconds.md) | Technical deep dive with code examples |
| [The Threat Intel Gap](docs/blog/threat-intel-gap.md) | MTTB metric and operationalization |
| [MSSP Value-Add Guide](docs/blog/mssp-value-add.md) | Channel partner deployment playbook |
| [NIST SI-4(24) Compliance](docs/blog/nist-compliance.md) | Audit evidence and control mapping |
| [VPN Blind Spot](docs/blog/vpn-blind-spot.md) | Remote worker protection gap |

## Security

- **No plaintext IOCs**: URLs hashed before storage and comparison
- **Encrypted updates**: X25519 + HKDF + AES-GCM envelope encryption
- **Zero-knowledge forensics**: Client-side encryption; vendor cannot decrypt
- **No external crypto libs**: Web Crypto API only
- **Open source**: Audit the code, verify the claims

Report security issues to security@browserdefense.com.

## License

GPL-3.0-only for the extension and service code. See [LICENSE](LICENSE). The CLI and connector packages retain their declared MIT licenses.

The extension is open source. Read the code. Verify the cryptography. Trust but verify.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

---

**Target audience**: SOC teams at mid-market companies who need fast IOC deployment, incident-ready forensics, and privacy-first data collection without firewall change windows.

**Positioning**: We fingerprint phishing kits, not just domains. We complement EDR with application-layer context. We keep your data zero-knowledge.
