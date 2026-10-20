# Block Phishing IOCs at the Browser in 30 Seconds

*Your firewall won't save you from phishing. Your VPN won't either. Here's what will.*

---

You're on call. Abuse inbox lights up. Someone forwarded a phishing email with a link to `secure-login-microsoft365[.]com`. Classic credential harvester.

You need to block it. Now. Before the next person clicks.

Your options:

1. **Submit a ticket to IT** — They'll add it to the firewall. ETA: Thursday.
2. **Update the DNS sinkhole** — Assuming you have access. And everyone's on VPN. (Spoiler: half your workforce is at home.)
3. **Send a Slack warning** — "Don't click this link." (They will click the link.)

None of these solve the actual problem: **block this domain, right now, on every managed browser, including remote workers who aren't on VPN.**

---

## The Browser Is the Last Line of Defense

DNS blocking is great when it works. Firewall rules catch known-bad IPs. But here's the reality:

- Remote workers on home WiFi don't hit your corporate DNS
- VPNs are optional (or split-tunneled)
- Firewall rules require network access you don't have
- Enterprise browsers cost $50K+ and take months to deploy

The attack succeeds in the browser. The user clicks a link, follows redirects, and enters credentials into a fake login page. That all happens at Layer 7, in Chrome, on a laptop at a coffee shop.

If you want to stop it, you need to block at the browser.

---

## BrowserDefense: Browser-Level IOC Blocking

BrowserDefense is a Chrome extension that blocks navigation to known-bad URLs and domains. It works on any managed device, regardless of network topology.

Here's the workflow:

```
1. Analyst identifies malicious domain
2. Add IOC to blocklist (API call or UI)
3. Every managed browser blocks it within seconds
4. If someone tries to visit → forensics captured
5. No VPN. No IT ticket. No waiting.
```

The extension maintains a local hash set of IOCs. Every navigation is hashed and checked client-side. Match = blocked. No network call required.

---

## Quick Setup: 30 Seconds to First Block

### Step 1: Install the Extension

For a quick pilot, install from Chrome Web Store. For production, deploy via GPO/Intune.

### Step 2: Configure Your Endpoint

Paste your org's configuration JSON in the extension options:

```json
{
  "orgId": "your-org-id",
  "blocklistEndpoint": "https://api.browserdefense.com/v1/blocklist",
  "forensicsEndpoint": "https://api.browserdefense.com/v1/forensics",
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
}
```

### Step 3: Add Your First IOC

```bash
# Add a domain to your blocklist
curl -X POST https://api.browserdefense.com/v1/blocklist \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [
      {"type": "domain", "value": "secure-login-microsoft365.com"},
      {"type": "url", "value": "https://phishing.example.com/login"}
    ]
  }'
```

The IOC is hashed, signed, and pushed to all extensions. Time from API call to block: ~2 seconds.

### Step 4: Verify It Works

Navigate to the blocked domain. You'll see a block page. Check your forensics dashboard — the attempt is logged with full context.

---

## How the Blocking Works (Technical Deep Dive)

The extension blocks with DNR rules in the Chrome Web Store and uses `webRequestBlocking` in enterprise installs. The flow below shows the enterprise path (simplified):

```typescript
// background/blocking.ts (enterprise, simplified)
chrome.webRequest.onBeforeRequest.addListener(async (details) => {
  const url = new URL(details.url);

  // Hash the domain
  const domainHash = await sha256(url.hostname.toLowerCase());

  // Check against local hash set (O(1) lookup)
  if (blocklistHashes.has(domainHash)) {
    // Capture forensics before blocking
    await captureForensics(details);

    // Block the request (block page shown separately)
    return { cancel: true };
  }
}, { urls: ["<all_urls>"] }, ["blocking"]);
```

The hash lookup is O(1) regardless of blocklist size. 100,000 IOCs? Same performance as 100.

### Binary Hash Storage

JSON arrays don't scale. A 100K IOC list as hex strings hits Chrome's storage limits. We use binary format:

```typescript
// storage/binary-set.ts
export async function loadBlocklist(): Promise<Set<string>> {
  const { blocklist } = await chrome.storage.local.get('blocklist');
  if (!blocklist) return new Set();

  // Decode base64 to binary
  const buffer = base64ToArrayBuffer(blocklist);
  const view = new Uint8Array(buffer);

  // Each hash is 32 bytes (SHA-256)
  const hashes = new Set<string>();
  for (let i = 0; i < view.length; i += 32) {
    const hash = bytesToHex(view.slice(i, i + 32));
    hashes.add(hash);
  }

  return hashes;
}
```

100,000 hashes = 3.2 MB. Fits comfortably in memory and storage.

### Signature Verification

Threat feed updates are encrypted with X25519 + AES-GCM. The extension decrypts before applying:

```typescript
// crypto/signing.ts
export async function decryptThreatFeed(
  envelope: ThreatFeedEnvelope,
  gpoPrivateKey: JsonWebKey
): Promise<IocList> {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    gpoPrivateKey,
    { name: 'X25519' },
    false,
    ['deriveBits']
  );

  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'X25519', public: ephemeralPubKey },
    privateKey,
    256
  );

  // HKDF(sharedSecret) -> AES-GCM key, then decrypt payload
}
```

If decryption fails, the update is rejected. Supply chain compromise = blocked.

---

## Forensics: Know What Happened

Blocking is half the story. You also need to know:

- Who clicked?
- When?
- What was the redirect chain?
- Where did the link come from?

When a user attempts to visit a blocked domain, the extension captures:

```typescript
interface ForensicsEvent {
  timestamp: string;           // ISO 8601
  userId: string;              // From org config (hashed)
  blockedUrl: string;          // The URL that was blocked
  redirectChain: string[];     // Full redirect path
  referrer: string | null;     // Where the click came from
  tabTitle: string;            // Page title (often reveals phishing)
}
```

### Redirect Chain Capture

Phishing campaigns use redirect chains to evade detection. `bit.ly → tracking.com → final-phish.com`. DNS blocking only sees the first hop. Browser blocking captures the whole chain. Implementation varies by mode (webRequest in enterprise, webNavigation best-effort in Web Store):

```typescript
// forensics/redirect-capture.ts (simplified)
const redirectChains = new Map<number, string[]>();

observeNavigation((event) => {
  if (event.type === "start") {
    redirectChains.set(event.tabId, [event.url]);
  }

  if (event.type === "redirect") {
    const chain = redirectChains.get(event.tabId) || [];
    chain.push(event.url);
    redirectChains.set(event.tabId, chain);
  }
});
```

When you block `final-phish.com`, you see the entire path: `email-link.com → tracker.co → final-phish.com`. That's intel DNS can't give you.

### Why This Matters for Incident Response

When you get the forensics report, you're not just seeing "user visited bad domain." You're seeing:

- The email link they clicked (referrer)
- Every redirect in between (tracking pixels, URL shorteners)
- The final destination that triggered the block
- Timestamp for correlation with other logs

This turns a blocking event into actionable threat intelligence. You can hunt for other users who received the same email. You can submit the redirect chain to your threat intel platform. You can build detection rules for the tracking domains.

---

## Zero-Knowledge Architecture

Most security tools phone home everything. Every URL. Every click. Your legal team has questions.

BrowserDefense takes a different approach:

1. **IOC hashes stored locally** — Blocking decisions are local; blocked URLs are only inside encrypted forensics
2. **Lookup happens client-side** — No network call for blocking decisions
3. **Forensics encrypted before transmission** — Your keys, not ours

### Client-Side Encryption

Forensics data is encrypted with your org's public key before leaving the device:

```typescript
// crypto/encryption.ts
export async function encryptForensics(
  data: ForensicsEvent,
  publicKeyPem: string
): Promise<EncryptedBlob> {
  // Generate random AES key
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt']
  );

  // Encrypt data with AES
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(JSON.stringify(data))
  );

  // Wrap AES key with RSA-OAEP
  const rsaPublicKey = await importRsaPublicKey(publicKeyPem);
  const wrappedKey = await crypto.subtle.wrapKey(
    'raw',
    aesKey,
    rsaPublicKey,
    { name: 'RSA-OAEP' }
  );

  return { iv, wrappedKey, ciphertext: encrypted };
}
```

We store encrypted blobs. You hold the private key. We literally cannot read your forensics data.

### Verifiable Claims

The extension is open source. Don't trust our zero-knowledge claims? Read `src/crypto/encryption.ts` line 47 where we encrypt. Verify the network tab shows only encrypted payloads.

---

## Deployment Options

### Standalone Mode (No IT Required)

For pilots or teams without admin access:

1. Install from Chrome Web Store
2. Configure via extension options page
3. 500 IOC limit (Chrome storage constraints)

Good for proving value before enterprise rollout.

### Enterprise Mode (GPO/Intune)

For production deployment:

```json
// Chrome policy (ExtensionSettings)
{
  "browserdefense-extension-id": {
    "installation_mode": "force_installed",
    "update_url": "https://clients2.google.com/service/update2/crx",
    "managed_storage": {
      "orgId": "your-org-id",
      "blocklistEndpoint": "https://api.browserdefense.com/v1/blocklist",
      "forensicsEndpoint": "https://api.browserdefense.com/v1/forensics"
    }
  }
}
```

Enterprise mode unlocks:
- `unlimitedStorage` permission (millions of IOCs)
- Managed configuration (no user setup)
- `webRequestBlocking` for enhanced capture

---

## Service Worker Reliability

Chrome kills service workers after 5 minutes of inactivity. Bad for a security tool. We use a heartbeat alarm:

```typescript
// background/heartbeat.ts
chrome.alarms.create('keepAlive', { periodInMinutes: 4.9 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'keepAlive') {
    console.log('[BrowserDefense] Heartbeat — service worker alive');

    // Check for pending forensics uploads
    await flushForensicsQueue();

    // Check for blocklist updates
    await checkBlocklistUpdates();
  }
});
```

The service worker stays alive, forensics get uploaded, and blocklist stays fresh.

---

## What This Isn't

Let's be clear about scope:

- **Not a full enterprise browser** — We extend Chrome, not replace it
- **Not DNS blocking** — We operate at Layer 7 only
- **Not EDR** — We don't monitor processes or files
- **Not a silver bullet** — Defense in depth still matters

BrowserDefense solves one problem well: block known-bad IOCs at the browser, instantly, with forensics.

---

## Try It

If you're a SOC analyst tired of 3-day turnaround times on firewall rules while phishing campaigns burn through your org, this might help.

- **GitHub:** github.com/browserdefense/extension (GPL-licensed)
- **Docs:** docs.browserdefense.com
- **API:** api.browserdefense.com

Free tier: 500 IOCs, public threat feeds, community support.
Paid tiers: More IOCs, forensics capture, priority support.

No sales calls. No demos required. The pricing is on the website. The code is on GitHub.

---

*Questions? File an issue on GitHub or email support@browserdefense.com*

---

**Keywords:** browser IOC blocking, phishing protection, SOC automation, zero-knowledge security, Chrome extension security
