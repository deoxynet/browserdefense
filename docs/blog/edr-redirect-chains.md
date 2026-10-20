---
title: "Why Your EDR Can't See Modern Phishing Redirect Chains"
description: "CrowdStrike, SentinelOne, and Defender are blind to cloaked redirects. So are email security vendors. Here's the visibility gap and how to close it."
date: 2026-01-11
author: BrowserDefense Team
tags: [phishing, EDR, redirect-chains, forensics, browser-security]
canonical: https://browserdefense.com/blog/edr-redirect-chains
---

# Why Your EDR Can't See Modern Phishing Redirect Chains

*CrowdStrike, SentinelOne, and Defender are blind to cloaked redirects. So are email security vendors. Here's why — and what to do about it.*

---

Modern phishing doesn't link directly to the credential harvester. That's amateur hour. The link in the email goes to:

```
hxxps://legitimate-looking-redirect[.]com/click?id=abc123
```

Which redirects to:

```
hxxps://tracker[.]marketing-platform[.]com/r/xyz789
```

Which redirects to:

```
hxxps://cdn[.]another-legit-service[.]net/auth?token=...
```

Which — only if you're on a Windows machine, in the US, not on a VPN, and not running security tools — redirects to:

```
hxxps://secure-microsoft365-login[.]com/signin
```

That's the credential harvester. Four hops later. With cloaking at every step.

Your EDR sees none of this.

---

## What EDR Actually Sees

Endpoint Detection and Response tools monitor:
- Process execution
- File system activity
- Registry changes
- Network connections (at the socket level)
- Some browser telemetry (varies by vendor)

When a user clicks a phishing link, here's what the EDR logs:

```
chrome.exe established connection to legitimate-looking-redirect.com:443
chrome.exe established connection to tracker.marketing-platform.com:443
chrome.exe established connection to cdn.another-legit-service.net:443
chrome.exe established connection to secure-microsoft365-login.com:443
```

Four connections. No redirect chain. No referrer headers. No URL paths. No query parameters.

The EDR sees "Chrome connected to four domains." It doesn't know they were sequential redirects from a single phishing click. It can't see the cloaking logic. It can't reconstruct the attack path.

---

## What Email Security Sees

Proofpoint, Mimecast, Abnormal — they analyze the email before delivery. They:
- Scan links in the email body
- Follow redirects (sometimes)
- Check destination against threat intel
- Maybe sandbox the final page

The problem: **cloaking defeats this entirely.**

When an email security scanner follows the link:
- It comes from a known security vendor IP range
- It has a bot-like User-Agent
- It doesn't execute JavaScript the same way
- The attacker's server detects this and serves a benign page

The scanner sees: "legitimate-looking-redirect.com → marketing-platform.com → another-legit-service.net → benign landing page"

The scanner says: "No threat detected."

The user clicks the same link, and the cloaking logic says: "Real user, real browser, real target geography, no security tools detected." And serves the credential harvester.

**Same link. Different destination. Email security never saw the real attack.**

---

## The Cloaking Arms Race

Modern phishing kits include cloaking out of the box. Common checks:

| Check | What It Detects | Result |
|-------|-----------------|--------|
| IP reputation | Security vendor IP ranges | Serve benign page |
| User-Agent | Bot signatures, headless browsers | Serve benign page |
| JavaScript execution | Sandbox environments | Redirect to benign page |
| Geolocation | Non-target countries | Serve benign page |
| Referrer header | Direct access (not from email) | Serve benign page |
| TLS fingerprinting | Non-standard browser stacks | Serve benign page |
| Mouse movement | Lack of human interaction | Delay or block |
| Timing | Too-fast page loads (automated) | Delay or block |

Attackers iterate on cloaking faster than vendors iterate on detection. The scanner sees what the attacker wants it to see.

---

## The Only Tool That Sees the Real Chain

The browser.

When a real user clicks a phishing link:
- Their browser follows every redirect
- Their browser executes the JavaScript
- Their browser passes every cloaking check (because it's real)
- Their browser lands on the actual credential harvester

The browser sees the complete attack chain. In order. With full context.

If you have instrumentation at the browser level, you can capture:
- Original clicked URL
- Every redirect in sequence (with referrer headers)
- Final destination
- Timestamp of each hop
- Form schema and optional screenshot (opt-in, encrypted)

**This is the forensic evidence your incident response team needs.** And no other tool in your stack can capture it.

Because kits persist across domains, capturing hash-only structural fingerprints lets you detect the same kit on new domains. This is optional and does not transmit URLs or page content.

---

## Why EDR Vendors Don't Solve This

"CrowdStrike has browser visibility!"

Sort of. EDR browser visibility typically means:
- URL of the page that triggered a download
- URL of the page that executed JavaScript leading to a process spawn
- Metadata about browser extensions

It does NOT mean:
- Full redirect chain for every navigation
- Referrer headers between hops
- Cloaking-resistant observation of the actual attack path

EDR is optimized for post-exploitation detection: "Chrome spawned PowerShell" is a signal. "Chrome visited four domains in sequence" is not actionable telemetry for an EDR.

---

## Why Email Vendors Don't Solve This

"Proofpoint rewrites URLs and scans at click time!"

Yes. And the cloaking logic detects Proofpoint's click-time scanners and serves a benign page.

The URL rewriting (safelinks, etc.) creates a new problem: the rewritten URL goes to the email vendor's proxy, which follows the redirect chain. The attacker's server sees the email vendor's proxy IP, not the user's IP. Cloaking triggers. Benign page served. Scan passes.

Then the user's actual browser follows the (now "safe") link, passes cloaking checks, and lands on the credential harvester.

**URL rewriting doesn't defeat cloaking. It just adds another hop for the attacker to fingerprint.**

---

## The Browser-Level Answer

A browser extension can:

1. **Intercept navigation events** — See every URL before the request leaves
2. **Capture redirect chains** — webRequest API exposes the full sequence
3. **Observe the real attack** — No cloaking, because it's the user's real browser
4. **Block known-bad IOCs** — Check against blocklist at each hop
5. **Capture forensics on block** — Full redirect chain, timestamps, context

When the extension blocks a phishing attempt, you get:

```json
{
  "timestamp": "2026-01-08T14:32:17Z",
  "user": "jsmith@corp.com",
  "chain": [
    "https://legitimate-looking-redirect.com/click?id=abc123",
    "https://tracker.marketing-platform.com/r/xyz789",
    "https://cdn.another-legit-service.net/auth?token=...",
    "https://secure-microsoft365-login.com/signin"  // BLOCKED
  ],
  "blocked_domain": "secure-microsoft365-login.com",
  "match_type": "ioc_hash"
}
```

That's the evidence. The complete attack path. Captured from the only vantage point that sees it.

---

## Complement, Not Compete

Browser-level context does not replace EDR. It adds the application-layer narrative (redirect chain, form schema, optional screenshot) to the alerts EDR already generates.

## The Objection: "We Already Have Browser Isolation"

Browser isolation (Menlo, Cyberix, etc.) renders pages remotely. It protects against exploitation but:

- Doesn't block known-bad IOCs faster than your update cycle
- Doesn't give you the redirect chain forensics
- Costs $20-50k+/year
- Adds latency to every page load

Isolation is a valid control for high-risk users. It's not an IOC blocking or forensics tool.

---

## The Operational Gap

You have:
- EDR on every endpoint (sees process behavior, not browser redirects)
- Email security on every mailbox (defeated by cloaking)
- Maybe DNS filtering (doesn't see the redirect chain)
- Maybe a web proxy (doesn't see cloaked destinations)

You don't have:
- Visibility into the actual redirect chain a user experiences
- Forensics captured at the browser level
- Fast IOC blocking that works regardless of cloaking

That's the gap. Browser-level instrumentation closes it.

---

## What to Do About It

**Option 1: Accept the gap**
- Rely on user training and hope cloaking doesn't get worse
- Accept that your incident response forensics will be incomplete

**Option 2: Deploy browser-level visibility**
- Extension-based IOC blocking
- Redirect chain capture on block events
- Works on managed browsers, including remote workers

**Option 3: Full enterprise browser**
- Replace Chrome/Edge entirely
- Deep visibility and control
- 6-month deployment, $50k+ cost

Option 2 gives you 80% of the visibility for 10% of the cost and deploys in days, not months.

---

## Try It Yourself

BrowserDefense captures full redirect chains on block events, encrypted client-side with your org's keys. Open source, auditable, zero-knowledge.

**Quick Start:**
- [GitHub Repository](https://github.com/deoxynet/browserdefense) — GPL-licensed, auditable
- [Enterprise Deployment Guide](../enterprise/deployment.md) — GPO, Intune, macOS
- [Trust Center](https://browserdefense.com/trust-center) — Security documentation

**Free tier:** 500 IOCs, public threat feeds, community support
**Paid tiers:** More IOCs, forensics capture, priority support

No sales calls. No demos required. The code is on GitHub.

---

**Cross-posted to:**
- [Medium](https://medium.com/@browserdefense)
- [dev.to](https://dev.to/browserdefense)
- [r/netsec](https://reddit.com/r/netsec)
- [r/blueteamsec](https://reddit.com/r/blueteamsec)

---

**Related posts:**
- [Block Phishing IOCs at the Browser in 30 Seconds](./block-iocs-30-seconds.md)
- [The "Always-On VPN" Lie: Why Your Remote Workers Are Unprotected](../blog_drafts/blog-vpn-blind-spot.md)
- [NIST SI-4(24) and Browser-Level Threat Blocking](../blog_drafts/blog-nist-compliance.md)

---

*Keywords: browser IOC blocking, phishing redirect chains, EDR blind spot, cloaking evasion, browser forensics, zero-knowledge security*
