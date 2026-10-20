# BrowserDefense Architecture v2: DOM-Based Proactive Detection

**Version:** 2.0
**Status:** APPROVED FOR IMPLEMENTATION
**Date:** January 2026

---

## Executive Summary

This document defines the architectural pivot from reactive IOC blocking to **proactive phishing kit detection** via DOM skeleton fingerprinting.

**Key insight:** Traditional IOC blocking is a losing game. Attackers rotate domains faster than defenders can block them. The winning strategy is to fingerprint the **phishing kit structure itself**, not the IOC.

---

## Architecture Principles

### 1. Async-First Enforcement

DNR (Declarative Net Request) has hard limits (30k rules) and cold-start issues. The new architecture uses:

- **DNR** for high-confidence, curated IOCs only (sync path)
- **webRequest observer** for async interception (no blocking flag)
- **Post-navigation redirect/overlay** for phishing detection

This decouples detection from MV3 service worker constraints.

### 2. Structure Over Content

We fingerprint **DOM structure**, not content:

```
✓ Tag topology
✓ Form structure
✓ Input types
✗ Text content
✗ Images
✗ User data
```

A phishing kit targeting Microsoft looks structurally identical whether hosted on `evil1.com` or `evil9999.com`.

### 3. Hash-Only Uplink

Zero-knowledge remains intact:

```
Client → Server: SHA-256(DOM skeleton) + timestamp
Server → Client: confidence score + known kit ID (if any)
```

No URLs. No content. No screenshots (unless opt-in).

### 4. Human-in-the-Loop

Automated detection suggests. Humans decide.

- New DOM fingerprints enter **shadow mode** (alert only)
- Analysts label as TP/FP
- Labels propagate to all customers via hash
- Confidence threshold gates enforcement

---

## Detection Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DETECTION PIPELINE                               │
│                                                                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐         │
│  │ Navigate │───▶│ DNR Check│───▶│ webReq   │───▶│ Content  │         │
│  │          │    │ (sync)   │    │ Observer │    │ Script   │         │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘         │
│                       │               │               │                 │
│                       ▼               ▼               ▼                 │
│                  ┌─────────┐    ┌─────────┐    ┌─────────┐            │
│                  │ BLOCK   │    │ ASYNC   │    │ DOM     │            │
│                  │ (known) │    │ CHECK   │    │ EXTRACT │            │
│                  └─────────┘    └─────────┘    └─────────┘            │
│                                      │               │                 │
│                                      ▼               ▼                 │
│                                 ┌─────────┐    ┌─────────┐            │
│                                 │ Local   │◀───│ SHA-256 │            │
│                                 │ Cache   │    │ Hash    │            │
│                                 └─────────┘    └─────────┘            │
│                                      │               │                 │
│                                      │    ┌─────────┘                 │
│                                      ▼    ▼                           │
│                                 ┌─────────────┐                       │
│                                 │ Hash Uplink │                       │
│                                 │ (if novel)  │                       │
│                                 └─────────────┘                       │
│                                      │                                 │
│                                      ▼                                 │
│                                 ┌─────────────┐                       │
│                                 │ Confidence  │                       │
│                                 │ Check       │                       │
│                                 └─────────────┘                       │
│                                      │                                 │
│                          ┌──────────┴──────────┐                      │
│                          ▼                     ▼                       │
│                    ┌─────────┐           ┌─────────┐                  │
│                    │ BLOCK   │           │ SHADOW  │                  │
│                    │ (conf>T)│           │ (alert) │                  │
│                    └─────────┘           └─────────┘                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Specifications

### DOM Skeleton Extractor

Deterministic extraction of page structure:

```typescript
interface DOMSkeleton {
  tagTree: string;      // Serialized tag hierarchy
  formCount: number;
  inputTypes: string[]; // ['email', 'password', 'text']
  actionUrls: string[]; // Form action URLs (normalized)
  hasLoginForm: boolean;
  hasPaymentForm: boolean;
}

function extractSkeleton(doc: Document): DOMSkeleton {
  // Walk DOM, capture structure only
  // Exclude: text nodes, style, script content, images
  // Include: tag names, attributes (name, type, action only)
}
```

**Performance target:** <10ms on typical page.

### IOC Priority System

```typescript
type IOCPriority = 'sync' | 'async';

interface IOC {
  hash: string;
  priority: IOCPriority;
  source: string;
  added: Date;
}

// 'sync' → DNR rules (30k cap, instant block)
// 'async' → webRequest path (unlimited, post-nav block)
```

### Storage Architecture

| Store | Purpose | Technology |
|-------|---------|------------|
| IOC Set | Authoritative IOC list | IndexedDB |
| DOM Cache | Seen skeleton hashes | IndexedDB |
| Bloom Filter | Fast negative prefilter | Binary blob |
| Config | Settings, keys | chrome.storage.local |

### Confidence Scoring

Rules-based (no ML):

```typescript
interface ConfidenceFactors {
  globalNovelty: number;   // 0-1, lower = more novel = suspicious
  localNovelty: number;    // 0-1, have we seen this before?
  analystLabels: number;   // TP count - FP count
  temporalBurst: number;   // Spike in global occurrence
}

function computeConfidence(factors: ConfidenceFactors): number {
  // Weighted combination, deterministic
  // Returns 0-100
}

const BLOCK_THRESHOLD = 80;
const SHADOW_THRESHOLD = 50;
```

---

## Privacy Architecture

### What We Collect

| Data | Collected | Transmitted | Purpose |
|------|-----------|-------------|---------|
| DOM skeleton hash | ✓ | ✓ | Kit fingerprinting |
| Timestamp | ✓ | ✓ | Temporal correlation |
| URL | ✓ | ✗ | Local display only |
| Screenshot | Opt-in | Opt-in | IR evidence |
| Form schema | Opt-in | Opt-in | IR evidence |
| Form values | ✗ | ✗ | Never |
| Keystrokes | ✗ | ✗ | Never |

### Opt-In Features

These require explicit user consent:

1. **Screenshot capture** - Watermarked, post-block only
2. **Form schema capture** - Field names/types, no values
3. **History-derived Bloom** - Local only, never transmitted

---

## Migration Path

### Phase 1: Foundation (Week 1-2)
- Async webRequest interception
- IndexedDB migration
- DOM skeleton extraction

### Phase 2: Detection (Week 3-4)
- DOM hashing + cache
- Hash uplink (server endpoint)
- Basic confidence scoring

### Phase 3: Value (Week 5-6)
- Analyst labeling UI
- Screenshot capture (opt-in)
- Form schema capture (opt-in)

### Phase 4: Scale (Week 7-8)
- Bloom filter optimization
- History-derived Bloom (opt-in)
- EDR enrichment export

---

## Risk Mitigations

| Risk | Mitigation |
|------|------------|
| False positives on legitimate sites | Shadow mode + human review before enforcement |
| Performance on complex pages | DOM extraction timeout, skip if >100ms |
| Privacy perception | Clear disclosure, opt-in forensics, hash-only uplink |
| Chrome Web Store rejection | Pre-submit privacy review, explicit permissions |
| Kit authors adapt | Structural similarity persists; variations cluster |

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Novel kit detection time | <24h from first sighting |
| False positive rate | <0.1% |
| DOM extraction latency | <10ms p99 |
| Storage efficiency | 100k IOCs in <50MB |
| Analyst labeling turnaround | <1h for high-confidence |

---

## Appendix: Issue Backlog

See GitHub issues GH-1 through GH-16 for implementation tickets.

**Recommended execution order:**
1. GH-1 → GH-3 → GH-6 → GH-7 → GH-8 (core pivot)
2. GH-2 → GH-4 → GH-5 (performance + scaling)
3. GH-9 → GH-10 → GH-11 (value + conversion)
4. Everything else is optional / GTM leverage
