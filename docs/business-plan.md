# BrowserDefense Business Plan

**Version:** 1.0  
**Status:** DRAFT  
**Date:** January 2026  
**Author:** Solo Technical Founder

---

## Executive Summary

BrowserDefense is a browser-based IOC blocking tool with zero-knowledge forensics, sold self-serve to SOC teams. The business model is "no humans required": annual self-serve checkout, standard terms only, and best-effort email support. We target the mid-market with a hard price ceiling of $6k/year to stay out of enterprise sales cycles.

**Target Outcome:** $150k-$300k ARR, <$50/month infrastructure, no employees, 95%+ gross margin.

**Exit Path:** Acquisition by security vendor at 2-4x ARR ($300k-$1.2M) or perpetual side income.

---

## 1. Market Sizing

### 1.1 Total Addressable Market (TAM)

**Global Browser Security Market**

| Segment | Size | Source/Basis |
|---------|------|--------------|
| Enterprise browser market | $2.1B (2025) | Gartner estimate |
| Endpoint security market | $18.6B (2025) | IDC |
| Phishing protection segment | ~$4.2B | Subset of email + web security |

**TAM Calculation (Conservative):**
- Organizations with dedicated SOC function globally: ~150,000
- Average potential deal size: $3,000/year
- **TAM: ~$450M**

This is the "if everyone who could buy this, bought this" number. It's directionally useful, not actionable.

---

### 1.2 Serviceable Addressable Market (SAM)

**Who can we actually sell to with our constraints?**

| Filter | Rationale | Remaining |
|--------|-----------|-----------|
| Global orgs with SOC teams | Starting universe | 150,000 |
| English-speaking markets (US, UK, CA, AU, EU) | Self-serve requires English docs | 80,000 |
| Mid-market (200-5,000 employees) | Enterprise needs sales; SMB lacks SOC | 45,000 |
| Chromium browser standardized | Firefox/Safari not supported v1 | 40,000 |
| Not locked into enterprise browser (Island, Talon) | Already solved the problem differently | 35,000 |
| Has budget authority at SOC level | Can swipe card without procurement | 25,000 |

**SAM Calculation:**
- Addressable organizations: 25,000
- Average deal size: $3,000/year (blended across paid tiers)
- **SAM: ~$75M**

---

### 1.3 Serviceable Obtainable Market (SOM)

**What can a solo founder with no sales team realistically capture?**

| Scenario | Direct Customers | MSSPs | End Clients via MSSP | ARR | Assumptions |
|----------|------------------|-------|---------------------|-----|-------------|
| **Conservative (Year 1)** | 15 | 3 | 30 | $60k | Organic only, slow build |
| **Base Case (Year 2)** | 50 | 10 | 150 | $200k | Content + word-of-mouth + MSSP channel |
| **Optimistic (Year 3)** | 80 | 25 | 500 | $400k | Category recognition, MSSP referrals |
| **Ceiling (Solo)** | 100 | 50 | 1,000 | $750k | Max manageable without support staff |

**SOM Calculation (3-year target):**
- Direct customers: 50-80
- MSSP partners: 10-25 (each serving 10-40 clients)
- Average deal size: $3,000 direct, $6,000 MSSP (Business tier)
- **SOM: $200k-$400k ARR**

**MSSP Multiplier Effect:**
MSSPs are high-leverage: 1 MSSP relationship = 10-50 end clients deployed. They handle their own support, deployment, and billing. Your touch is near-zero after initial onboarding.

- 10 MSSPs × 20 clients average × $200/client/year = $40k ARR from 10 relationships
- MSSPs talk to each other — strong referral network in MSP communities (r/msp, IT Nation, Datto forums)
- Stickier than direct: MSSP won't rip out a working tool across 50 clients

**Reality check:** Capturing 0.2% of direct SAM (50/25,000) + 10-25 MSSPs is achievable with targeted content marketing. Security tools spread through peer networks, and MSPs are an especially tight-knit community.

---

## 2. Pricing Model

### 2.1 Pricing Philosophy (No Humans Required)

**Constraints driving the model:**
1. Annual self-serve checkout only (no sales calls)
2. Hard price ceiling of $6k/year to avoid enterprise procurement
3. Standard terms only (no SLAs, no custom contracts)
4. Support is docs + best-effort email

**Decision: Flat org tiers based on capability limits, not headcount.**

No per-seat math, no negotiation, no exceptions. Limits are enforced in the product.

---

### 2.2 No-Humans-Required Tiers

| Tier | Price | Limits | Support |
|------|-------|--------|---------|
| **Community** | Free | 500 IOCs, public feeds only, no forensics | GitHub Issues |
| **Team** | $2,400/year | 10k IOCs, forensics (30-day), dashboard | Email (best-effort) |
| **Business** | $6,000/year | Unlimited IOCs, forensics (90-day), BYO-Trust, API | Email (best-effort) |

**Notes:**
- Annual billing only (lower support + fewer billing edge cases)
- Limits are hard caps (no manual overrides)
- API is self-serve only (no custom integrations)

---

### 2.3 Compliance Package (Paperwork Service)

| Add-On | Price | Includes |
|--------|-------|----------|
| **Compliance Package** | $15,000 one-time | Security questionnaire completion (up to 200 questions) + signed standard BAA (if applicable) |

**Purpose:** A filter, not a support tier. If a buyer needs bespoke terms or ongoing compliance work, they are not a fit.

---

### 2.4 Automation Boundaries

| Customer Ask | Response |
|--------------|----------|
| "We need 50,000 endpoints" | "Business tier is unlimited. Sign up at browserdefense.com." |
| "Can we get a discount for volume?" | "Pricing is on the website." |
| "We need an SLA" | "We don't offer SLAs. Best-effort email support." |
| "Can we do a call?" | "Docs and demo video cover everything. Email with specific questions." |
| "We need a custom contract" | "We use standard terms only." |
| "Our security team needs a questionnaire" | "Compliance Package is $15k. Details in the Trust Center." |

---

### 2.5 Pricing Comparison

| Vendor | Price | BrowserDefense Equivalent |
|--------|-------|---------------------|
| Island Enterprise Browser | $50k-$150k/year | 8-60x more expensive |
| Talon (Palo Alto) | $40k-$100k/year | 7-40x more expensive |
| LayerX | $30k-$80k/year | 5-33x more expensive |
| CrowdStrike Falcon | $50k-$200k/year | Different product, but budget competition |
| **BrowserDefense Team** | **$2,400/year** | — |
| **BrowserDefense Business** | **$6,000/year** | — |

**Positioning:** "Fast IOC blocking at a self-serve price, deployed in minutes instead of months."

---

### 2.6 Free Tier (Community Edition)

**Recommendation: Community Edition (Limited Free)**

| Feature | Community (Free) | Paid |
|---------|------------------|------|
| IOC blocking | ✓ (500 IOC limit) | ✓ |
| Public threat feeds | ✓ | ✓ |
| Custom org IOCs | ✗ | ✓ |
| Forensics capture | ✗ | ✓ |
| Dashboard | ✗ | ✓ |
| BYO-Trust (encrypted feeds) | ✗ | ✓ |
| Support | GitHub Issues | Email (best-effort) |

**Conversion trigger:** 500 IOCs + no forensics is enough to test, not enough to run incident response.

---

## 3. Customer Acquisition

### 3.0 GTM Narrative Stack (Message Architecture)

The executive-level narrative stack that drives demand, trust, and differentiation is captured in [GTM_Strategy.md](GTM_Strategy.md). It is the source of truth for demos, content, and partner messaging.

### 3.1 Channel Strategy

**Constraint:** No paid acquisition. No sales team. No cold outreach. Must be organic/inbound only.

| Channel | Effort | Expected Yield | Timeline |
|---------|--------|----------------|----------|
| **GitHub presence** | Low (already building OSS) | 5-10 customers/year | Ongoing |
| **One killer blog post** | Medium (4-8 hours) | 10-20 customers/year | Month 1 |
| **BSides/conference talk** | Medium (20-30 hours prep) | 5-15 customers/year | Month 3-6 |
| **r/blueteamsec, r/netsec** | Low (periodic posting) | 3-8 customers/year | Ongoing |
| **LinkedIn (personal brand)** | Low-Medium | 5-10 customers/year | Ongoing |
| **YouTube demo video** | Medium (4-8 hours) | 5-15 customers/year | Month 2 |
| **Word of mouth** | Zero (it happens or doesn't) | 10-30 customers/year | Month 6+ |
| **MSSP partnerships** | Low (inbound via content) | 5-15 MSSPs/year (50-150 end clients) | Month 3+ |

**Total expected (Year 1):** 15-30 direct customers + 20-50 via MSSPs
**Total expected (Year 2):** 40-70 direct + 50-100 via MSSPs (compounding word-of-mouth)

---

### 3.1.1 MSSP Channel (High-Leverage)

**Why MSSPs are ideal for BrowserDefense:**

MSSPs (Managed Security Service Providers) serve 10-100+ SMB/mid-market clients each. They need:
- Tools that deploy easily across diverse client environments
- Value-adds that differentiate their service from competitors
- Low-touch solutions (they're already stretched thin)
- Defensible margins (they mark up and resell)

BrowserDefense fits perfectly:
- **Easy deployment:** GPO/Intune push, one policy per client
- **Zero-knowledge:** MSSP doesn't inherit liability for client browsing data
- **Instant value:** "We blocked 847 phishing attempts this month" in client reports
- **Low support burden:** Extension just works, clients never interact with it

**MSSP Economics:**

| Model | BrowserDefense Cost | MSSP Charges Client | MSSP Margin |
|-------|---------------|---------------------|-------------|
| Per-seat pass-through | ~$2/seat/month | $5-10/seat/month | 60-80% |
| Bundled in service | $2,400/year (Team) | Included in $X,000/mo retainer | 100% perceived |
| Value-add upsell | $6,000/year (Business) | $15,000/year package | 60% |

**MSSP Acquisition Strategy:**
1. **Content marketing:** Blog post "How MSSPs Can Add Browser-Level Phishing Protection in a Weekend"
2. **MSSP community presence:** Reddit r/msp, MSP subreddits, ConnectWise/Datto forums
3. **Conference presence:** MSP-focused events (IT Nation, DattoCon) via hallway track, not booths
4. **Referral program:** 20% rev share for MSSP referrals (optional, low-touch)

**Why this channel scales:**
- 1 MSSP deal = 10-50 end clients
- MSSPs talk to each other (strong word-of-mouth network)
- Once deployed, sticky (MSSP won't rip out working tool)
- No enterprise procurement (MSSP makes the buy decision)

---

### 3.2 Content Strategy (Minimal Viable Marketing)

**The 5 artifacts that work while you sleep:**

1. **GitHub README** — Problem → Solution → 30-second GIF → Install. The GIF is mandatory.

2. **Blog post: "How to Block Phishing IOCs at the Browser in 30 Seconds"**
   - Tactical, specific, shows workflow
   - Ends with soft CTA ("we built a tool for this")
   - Cross-post to Medium, dev.to, LinkedIn

3. **YouTube video: "BrowserDefense Demo — SOC Analyst Workflow"**
   - 5-7 minutes max
   - Screen recording with voiceover
   - Shows: add IOC → blocks in browser → forensics captured
   - Thumbnail: "Block phishing in 30 seconds"

4. **Landing page (browserdefense.com)**
   - Hero: Problem statement + demo GIF
   - 3 feature blocks with icons
   - Pricing table (no "contact us" anywhere)
   - Trust Center link
   - "Get Started" → GitHub or Stripe checkout

5. **Trust Center**
   - Architecture diagram
   - Cryptographic spec summary
   - "What data we store" table
   - Compliance mappings (NIST SI-4, SOC 2 relevance)
   - Eliminates 80% of security questionnaire requests

---

### 3.3 Customer Acquisition Cost (CAC)

| Cost Component | Amount | Notes |
|----------------|--------|-------|
| Domain | $15/year | browserdefense.com |
| Hosting (Cloudflare Pages) | $0 | Free tier |
| Video recording (Loom) | $0 | Free tier sufficient |
| Conference travel (1x BSides) | $500 | Optional |
| Time (content creation) | ~40 hours | Opportunity cost, not cash |

**Cash CAC:** ~$10-20 per customer (domain + misc amortized)  
**Blended CAC (including time):** ~$200-400 per customer at founder hourly rate

**Target CAC Ratio:** LTV:CAC > 10:1 (we're at ~33:1, very healthy)

---

## 4. Retention & Churn

### 4.1 Churn Assumptions

| Segment | Expected Annual Churn | Rationale |
|---------|----------------------|-----------|
| Team tier | 20-25% | Low-touch buyers, price-sensitive |
| Business tier | 15-20% | More committed, higher switching cost |
| **Blended average** | **22%** | Conservative assumption |

**Churn drivers (things that kill retention):**
- Customer gets acquired / goes out of business (uncontrollable)
- Customer buys full enterprise browser (Island, etc.) — we lose
- Budget cuts hit security tools (economic downturn)
- Product doesn't work reliably (controllable)
- Support experience is terrible (controllable)

**Churn mitigations:**
- Annual-only billing (no monthly = less churn surface)
- Usage data in dashboard ("you blocked 847 threats this year")
- Renewal reminder email with impact stats
- No SLA means we can't be fired for SLA breach

---

### 4.2 Retention Mechanics

**Stickiness factors:**
1. **Integration depth** — Once GPO-deployed, ripping out is work
2. **Forensics history** — Customers accumulate incident data they don't want to lose
3. **Workflow habit** — Analysts build muscle memory around "add IOC → blocks everywhere"
4. **Low cost** — At $2.4k-$6k, not worth the procurement hassle to switch

**Net Revenue Retention (NRR) target:** 80-90%

Expansion revenue is limited (org tiers are coarse), so NRR ≈ 100% - gross churn. At 22% churn, NRR = 78%. Not great for VC math, perfectly fine for lifestyle business.

---

### 4.3 Lifetime Value (LTV)

| Tier | Annual Price | Avg Lifespan | Gross Margin | LTV |
|------|--------------|--------------|--------------|-----|
| Team | $2,400 | 3 years | 95% | $6,840 |
| Business | $6,000 | 4 years | 95% | $22,800 |
| **Blended** | **$3,000** | **3.5 years** | **95%** | **$9,975** |

**LTV:CAC Ratio:** $9,975 / $300 = **33:1**

This is strong. Normal SaaS targets 3:1. We're at 33:1 because:
- Near-zero infrastructure cost
- Near-zero acquisition cost (organic)
- High gross margin (no COGS)

---

## 5. Unit Economics

### 5.1 Cost Structure

| Cost Category | Monthly | Annual | Notes |
|---------------|---------|--------|-------|
| **Infrastructure** | | | |
| Cloudflare R2 (storage) | $5-20 | $60-240 | Scales with forensics volume |
| Cloudflare Pages | $0 | $0 | Free tier |
| Cloudflare Workers | $0-5 | $0-60 | Minimal compute |
| Domain | — | $15 | browserdefense.com |
| **Services** | | | |
| Stripe fees | 2.9% + $0.30 | ~$90/customer | Per transaction (blended) |
| GitHub | $0 | $0 | Public repo |
| Email (Fastmail/similar) | $5 | $60 | Support inbox |
| **Total Fixed** | **~$15** | **~$180** | |
| **Total Variable** | **~3%** | **~$90/customer** | Stripe fees |

---

### 5.2 Margin Analysis

**Per-Customer Economics (Team Tier)**

| Line Item | Amount |
|-----------|--------|
| Revenue | $2,400 |
| Stripe fees (2.9% + $0.30) | ($70) |
| Infrastructure (allocated) | ($10) |
| **Gross Profit** | **$2,320** |
| **Gross Margin** | **96.7%** |

**Per-Customer Economics (Business Tier)**

| Line Item | Amount |
|-----------|--------|
| Revenue | $6,000 |
| Stripe fees (2.9% + $0.30) | ($174) |
| Infrastructure (allocated) | ($15) |
| **Gross Profit** | **$5,811** |
| **Gross Margin** | **96.8%** |

**Contribution Margin (blended, incl. CAC)**

| Line Item | Amount |
|-----------|--------|
| Gross Profit | $2,898 |
| CAC (allocated) | ($300) |
| **Contribution Margin** | **$2,598** |
| **Contribution %** | **86.6%** |

---

### 5.3 Scenario Modeling

**Scenario A: Conservative (50 paying customers)**

| Metric | Value |
|--------|-------|
| Customers | 50 |
| Blended ARPU | $3,000 |
| ARR | $150,000 |
| Gross margin | 95% |
| Gross profit | $142,500 |
| Fixed costs | $500 |
| **Net profit** | **$142,000** |
| **Net margin** | **94.7%** |

**Scenario B: Base Case (100 paying customers)**

| Metric | Value |
|--------|-------|
| Customers | 100 |
| Blended ARPU | $3,000 |
| ARR | $300,000 |
| Gross margin | 95% |
| Gross profit | $285,000 |
| Fixed costs | $800 |
| **Net profit** | **$284,200** |
| **Net margin** | **94.7%** |

**Scenario C: Stretch (150 paying customers)**

| Metric | Value |
|--------|-------|
| Customers | 150 |
| Blended ARPU | $3,000 |
| ARR | $450,000 |
| Gross margin | 95% |
| Gross profit | $427,500 |
| Fixed costs | $1,200 |
| **Net profit** | **$426,300** |
| **Net margin** | **94.7%** |

---

### 5.4 Break-Even Analysis

| Metric | Value |
|--------|-------|
| Fixed costs (annual) | ~$500 |
| Variable cost per customer | ~$90 |
| Average revenue per customer | $3,000 |
| Contribution per customer | $2,910 |
| **Break-even customers** | **1** |

You're profitable from customer #1. The business model has essentially zero fixed costs.

---

## 6. Financial Projections

### 6.1 Three-Year Projection

| Metric | Year 1 | Year 2 | Year 3 |
|--------|--------|--------|--------|
| **New customers** | 20 | 35 | 45 |
| **Churned customers** | 0 | 4 | 10 |
| **Ending customers** | 20 | 51 | 86 |
| **ARR** | $60,000 | $153,000 | $258,000 |
| **Revenue** | $60,000 | $153,000 | $258,000 |
| **Gross profit** | $57,000 | $145,350 | $245,100 |
| **Net profit** | $56,500 | $144,650 | $244,200 |

### 6.2 Cash Flow Characteristics

**Positive attributes:**
- Annual prepay = strong cash position
- No inventory, no receivables
- Revenue recognized monthly, but cash collected upfront
- Near-zero capex

**Cash runway at $0 revenue:** Infinite (no fixed costs to cover)

---

## 7. Exit Analysis

### 7.1 Exit Scenarios

| Exit Type | Likely Valuation | Probability | Notes |
|-----------|------------------|-------------|-------|
| **Acqui-hire** | $500k-$1M | Low | You + product, talent play |
| **Product acquisition** | 2-4x ARR | Medium | Security vendor buys for tech/customers |
| **Strategic acquisition** | 4-6x ARR | Low | Larger multiple if strategic fit |
| **Perpetual hold** | N/A (income stream) | High | $150-300k/year forever |

**At $150k ARR:**
- Product acquisition: $300k - $600k
- Strategic acquisition: $600k - $900k

**At $300k ARR:**
- Product acquisition: $600k - $1.2M
- Strategic acquisition: $1.2M - $1.8M

### 7.2 Likely Acquirers

| Category | Examples | Strategic Fit |
|----------|----------|---------------|
| Email security vendors | Proofpoint, Mimecast, Abnormal | Extend phishing protection to browser |
| Endpoint vendors | CrowdStrike, SentinelOne, Carbon Black | Add browser telemetry |
| Identity vendors | Okta, Ping, ForgeRock | Secure access layer |
| SIEM/SOAR vendors | Splunk, Palo Alto (Cortex), Rapid7 | Analyst workflow integration |
| Browser vendors | Island, Talon (if they don't view as threat) | Acqui-hire for zero-knowledge approach |

### 7.3 Exit Preparation Checklist

- [ ] Clean cap table (solo founder = easy)
- [ ] Customer contracts assignable
- [ ] No revenue concentration >20% single customer
- [ ] IP clean (no day-job entanglement)
- [ ] Code documented and transferable
- [ ] Customer list exportable

---

## 8. Risk Factors

### 8.1 Business Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Can't acquire customers organically | Medium | Fatal | Validate demand before building more |
| Chrome deprecates enterprise webRequestBlocking | Low | High | DNR fallback, monitor Chrome roadmap |
| Major competitor enters market | Medium | Medium | Speed + zero-knowledge positioning |
| Support burden exceeds capacity | Medium | Medium | Enforce boundaries; consider contractor only if absolutely needed |
| Key customer churns, revenue concentration | Low | Medium | Diversify customer base |
| Day job conflict | Low | Medium | Keep clean separation, no customer overlap |

### 8.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| MV3 breaks core functionality | Low | High | Dual architecture, monitor Chrome betas |
| Signature verification fails on some browsers | Medium | Medium | Require Chrome 113+ and fail closed |
| Storage limits hit | Medium | Medium | Binary format, unlimitedStorage permission |
| Zero-knowledge claim challenged | Low | High | Cryptographic spec, third-party audit option |

---

## 9. Success Metrics

### 9.1 North Star Metrics

| Metric | Year 1 Target | Year 2 Target | Year 3 Target |
|--------|---------------|---------------|---------------|
| **ARR** | $60k | $150k | $250k |
| **Active customers** | 20 | 50 | 85 |
| **Net revenue retention** | 85% | 80% | 80% |
| **Support hours/week** | <2 | <5 | <8 |

### 9.2 Leading Indicators

| Indicator | Target | Measurement |
|-----------|--------|-------------|
| GitHub stars | 500+ Year 1 | Weekly |
| Demo video views | 5,000+ Year 1 | Monthly |
| Inbound inquiries | 5+ per month | Weekly |
| Trial → paid conversion | 20%+ | Monthly |
| Time to first IOC blocked | <5 minutes | Per customer |

---

## 10. Go/No-Go Decision Framework

### 10.1 Validation Gates

**Gate 1: Technical (POC validation)**
- [ ] MV3 enterprise mode works as expected
- [ ] X25519 threat feed decrypt works across target Chrome versions
- [ ] Storage/performance acceptable at 100k+ IOCs
- **Decision:** Proceed to MVP build

**Gate 2: Demand (Pre-launch)**
- [ ] 10+ people express interest (email list, DMs, comments)
- [ ] 3+ people commit to pilot
- [ ] Blog post / Reddit post gets engagement
- **Decision:** Proceed to launch

**Gate 3: Product-Market Fit (Post-launch)**
- [ ] 5 paying customers within 3 months
- [ ] 2+ customers came from referral
- [ ] NPS > 30 (if measured)
- **Decision:** Continue investing time

**Gate 4: Scale (Month 12)**
- [ ] 15+ customers
- [ ] <5 hours/week support burden
- [ ] At least 1 customer upgraded tiers
- **Decision:** Maintain / grow / consider exit

---

## Appendix A: Competitive Landscape Detail

### Enterprise Browsers

| Vendor | Price | Deployment | Positioning |
|--------|-------|------------|-------------|
| Island | $50-150k | 3-6 months | Full browser replacement, DLP focus |
| Talon (Palo Alto) | $40-100k | 3-6 months | Zero trust browser |
| LayerX | $30-80k | 2-4 months | Browser security layer |

### DNS/Network Blocking

| Vendor | Price | Limitation vs BrowserDefense |
|--------|-------|------------------------|
| Cisco Umbrella | $20-50k | No browser forensics, requires VPN/agent |
| Zscaler | $30-80k | Heavy infrastructure, no zero-knowledge |
| Cloudflare Gateway | $5-20k | DNS only, no redirect chain capture |

### EDR/XDR (Indirect Competition)

| Vendor | Price | Limitation vs BrowserDefense |
|--------|-------|------------------------|
| CrowdStrike | $50-200k | Heavy agent, phones home everything |
| SentinelOne | $40-150k | No browser-specific IOC workflow |
| Microsoft Defender | Included | Limited IOC management flexibility |

---

## Appendix B: Pricing Sensitivity Analysis

| Price Point | Expected Volume Impact | Revenue Impact | Recommendation |
|-------------|----------------------|----------------|----------------|
| $1,800 | +35% volume | -20% revenue | Too cheap, attracts wrong buyers |
| $2,400 | Baseline | Baseline | **Team tier price** |
| $3,000 | -15% volume | +6% revenue | Test after 20 customers |
| $4,000 | -35% volume | -8% revenue | Likely triggers procurement |

**Conclusion:** $2,400 is the right self-serve starting point. $6,000 stays as the Business ceiling.

---

## Appendix C: Monthly Operating Rhythm

| Task | Frequency | Time |
|------|-----------|------|
| Check support inbox | Daily | 10 min |
| Review dashboard metrics | Weekly | 15 min |
| Process new signups | As needed | 5 min each |
| Content creation | Monthly | 2-4 hours |
| Blocklist/IOC feed updates | Weekly | 30 min |
| Invoice/billing review | Monthly | 30 min |
| **Total** | | **~3-5 hours/week** |

This is compatible with a full-time day job.

---

*"The best business model is one where the marginal cost of serving a customer approaches zero, and the marginal value to the customer approaches infinity."*

*BrowserDefense isn't quite infinity, but 95% gross margin on a security tool that deploys in minutes is pretty close.*

---

**Document History**

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | January 2026 | No-humans-required pricing + revised economics |
