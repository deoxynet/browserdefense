# BrowserDefense GTM Strategy (Narrative Stack)

**Status:** Final
**Scope:** Executive-level messaging for demand, trust, and differentiation
**Target Audience:** SOC teams at mid-market companies (500-5,000 employees)

---

## 1. Lead with What People Can See (Conversation Starters)

**Core GTM hook:** "We capture what the user actually saw."

**What you show:**
- Screenshot of the phishing page (opt-in, watermarked)
- Form schema (fields + submit flow)
- Redirect chain
- "Blocked before credentials were entered"

**Why it works:**
- Visceral and instantly understandable
- Highlights the EDR blind spot
- Turns abstract phishing into concrete evidence

**Who it converts:**
- SOC analysts
- Incident responders
- SOC managers

---

## 2. Reframe the Problem: From IOCs to Phishing Kits

**Primary message:** "We fingerprint phishing kits, not domains."

**Messaging angle:**
- Domains rotate
- Kits persist
- Structure is the invariant

**Why it resonates:**
- Experienced defenders already know IOC feeds lag
- Explains the "why" in a simple way
- Feels obvious in hindsight

**Where this lands:**
- r/netsec
- BSides / DEF CON talks
- Technical buyers
- EDR partners

---

## 3. Complement, Don't Compete, with EDR (Distribution Play)

**Primary message:** "We add application-layer context to EDR alerts."

**The story:**
- EDR shows `chrome.exe -> network connection`
- BrowserDefense shows a fake login page, brand impersonation, credential form, and user interaction timing

**Why this matters:**
- SOCs want narratives, not alerts
- CISOs want explainability
- EDR plugin stores become a channel

---

## 4. Proactivity Without Fear: Shadow Detection

**Primary message:** "We detect emerging threats before they are IOCs -- without blocking."

**Key idea:**
- Structural fingerprints are captured even when nothing is blocked
- No alerts, no enforcement, no user impact

**Why this builds trust:**
- Shows restraint and maturity
- Avoids false positives
- Reassures CISOs, privacy teams, and risk committees

---

## 5. Thought Leadership via Patterns, Not Incidents

**Primary message:** "We study how deception evolves -- not who was attacked."

**Research angles you own:**
- Which industries are targeted more
- How fast phishing kits spread
- How often attacks are novel vs reused
- Which authentication flows are most impersonated
- How early blocks change attacker behavior

**Why this works:**
- Safe to share without customer panic
- Board-friendly and authoritative
- Feeds blog, whitepaper, and conference content

---

## 6. Brand Impersonation Without Surveillance

**Primary message:** "We detect brand impersonation without reading page content."

**How you message it:**
- Visual hashes only (logos, favicons)
- Brand resolution via public reference sets
- No customer-derived brand labeling

**Why CISOs care:**
- Less privacy risk
- Fewer legal headaches
- Cleaner vendor story for regulated industries

---

## 7. Retroactive Insight = Instant Value

**Primary message:** "We can tell you if someone already visited this before it was known bad."

**Why this is powerful:**
- Turns new intel into immediate value
- Speeds incident retrospectives and audit answers
- Delivers value without continuous monitoring

---

## 8. Privacy as a Feature, Not a Footnote

**Primary message:** "We cannot see your data -- mathematically."

**What this enables:**
- Industry-level reports
- Global prevalence stats
- Trend analysis

**Without:**
- URLs
- Customer attribution
- Browsing history

**Why this closes deals:**
- Satisfies legal, compliance, and security architects

---

## 9. Pricing Justification (Quietly Strong)

**Pricing story:**
"We are not charging for blocking. We are charging for visibility, context, and understanding."

**Why it works:**
- Higher price feels justified
- Customers feel smarter, not sold to
- You avoid commodity feature comparisons

---

## One-Paragraph GTM Thesis (Internal)

BrowserDefense starts conversations by showing what the user actually saw, wins trust by avoiding surveillance, and compounds value by turning structural phishing signals into industry-level insight. We do not just stop phishing -- we explain it.

---

## Content-to-Channel Mapping

| Narrative | Content Asset | Primary Channel | CTA |
|-----------|---------------|-----------------|-----|
| 1. Visual Forensics | Demo video (3 min) | YouTube, Landing page | "See a block in action" |
| 2. Kits > Domains | Blog: EDR Redirect Chains | r/netsec, LinkedIn, DEF CON CFP | "Read the deep dive" |
| 3. EDR Complement | Integration docs, partner page | EDR vendor marketplaces | "Add browser context" |
| 4. Shadow Detection | Blog: Threat Intel Gap | ISAC newsletters | "Try shadow mode" |
| 5. Industry Patterns | Quarterly threat report | Email, LinkedIn | "Download the report" |
| 6. Privacy-First Brand | Trust Center, Crypto Spec | Compliance reviews | "Verify our claims" |
| 7. Retroactive Insight | Case study template | Sales enablement | "Check your exposure" |
| 8. Zero-Knowledge | Chrome Web Store listing | Organic search | "Install free tier" |
| 9. Pricing Story | Pricing page, FAQ | Direct comparison | "Start protecting" |

---

## Launch Content Checklist

**Day 1 (Chrome Web Store Launch):**
- [x] Chrome Web Store listing (`docs/STORE_LISTING.md`)
- [x] Landing page (live)
- [x] Trust Center documentation

**Week 1:**
- [x] Blog: "Block Phishing IOCs in 30 Seconds" (technical deep dive)
- [x] Blog: "Why Your EDR Can't See Redirect Chains" (problem awareness)
- [ ] Demo video (YouTube, 3-5 min)
- [ ] Product Hunt launch

**Week 2-4:**
- [x] Blog: "Threat Intel Operationalization Gap" (MTTB metric)
- [x] Blog: "MSSP Value-Add Guide" (channel partners)
- [x] Blog: "NIST SI-4(24) Compliance" (compliance angle)
- [x] Blog: "VPN Blind Spot" (remote worker gap)

**Month 2+:**
- [ ] EDR integration announcements (CrowdStrike, SentinelOne connectors)
- [ ] Quarterly threat report (phishing kit trends)
- [ ] BSides/DEF CON talk submission
- [ ] MSSP partner program launch

---

## Distribution Channels (Priority Order)

1. **Reddit** (`r/netsec`, `r/blueteamsec`, `r/msp`) - Technical credibility, organic reach
2. **LinkedIn** - SOC manager/CISO audience, thought leadership
3. **GitHub** - Open source credibility, developer trust
4. **Hacker News** - Technical validation, founder story angle
5. **Chrome Web Store** - Organic discovery for free tier
6. **Email** (opt-in from free users) - Conversion to paid
7. **EDR Marketplaces** - Distribution through existing tools
8. **ISAC Newsletters** - Industry-specific reach (FS-ISAC, H-ISAC)
