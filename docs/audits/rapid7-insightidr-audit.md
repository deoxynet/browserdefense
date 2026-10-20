# Rapid7 InsightIDR Connector Audit

**Date:** 2026-01-09
**Connector:** `src/connectors/rapid7.ts`
**Status:** Partial Alignment - Critical Fix Needed

## References

### Official Vendor Documentation
- [HTTP POST | InsightOps Documentation](https://docs.rapid7.com/insightops/insightops-webhook/) - Primary reference for webhook/HTTP POST log ingestion
- [Custom Logs | SIEM Documentation](https://docs.rapid7.com/insightidr/custom-logs/) - InsightIDR custom log sources
- [InsightIDR REST API Documentation](https://docs.rapid7.com/insightidr/insightidr-rest-api/)
- [Command Platform API Overview](https://docs.rapid7.com/insight/api-overview/)

### Open Source References
- [rapid7/r7insight_js](https://github.com/rapid7/r7insight_js) - Official JavaScript logging library
- [rapid7/r7insight_python](https://github.com/rapid7/r7insight_python) - Official Python logging library
- [rapid7/r7insight_node](https://github.com/rapid7/r7insight_node) - Official Node.js logging library

---

## Findings Summary

| Component | Status | Notes |
|-----------|--------|-------|
| Endpoint URL | **MISMATCH** | Using wrong hostname for HTTP POST |
| Authentication | **UNCLEAR** | `X-Insight-Token` header not documented |
| Regions | Aligned | All 7 regions correctly supported |
| NDJSON Batch Format | Aligned | Newline-delimited JSON is correct |
| Error Handling | Aligned | 429/5xx retryable, 4xx non-retryable |
| Timeout | Aligned | 30s default is reasonable |

---

## Detailed Analysis

### 1. Endpoint URL - MISMATCH (Critical)

**Current Implementation:**
```typescript
const REGION_ENDPOINTS: Record<InsightIDRRegion, string> = {
  us: 'us.data.logs.insight.rapid7.com',
  us2: 'us2.data.logs.insight.rapid7.com',
  // ...
};
this.endpoint = `https://${host}/v1/noformat/${this.logToken}`;
```

**Official Documentation:**

Rapid7 has **two distinct endpoints** for log ingestion:

| Endpoint Type | Hostname | Protocol | Use Case |
|---------------|----------|----------|----------|
| HTTP POST (Webhook) | `{region}.webhook.logs.insight.rapid7.com` | HTTPS POST | Browser/HTTP clients |
| TCP Streaming | `{region}.data.logs.insight.rapid7.com` | TCP socket (port 80/443) | Agents, long-running processes |

**Evidence from official sources:**

From [HTTP POST documentation](https://docs.rapid7.com/insightops/insightops-webhook/):
> Sample URL format: `https://us.webhook.logs.insight.rapid7.com/v1/noformat/abc123-abc2-xyz1-abc-1234567890`

From [r7insight_js wiki](https://github.com/rapid7/r7insight_js/wiki/API):
> Requests look like `https://us.webhook.logs.insight.rapid7.com/v1/logs/94e2188b-506a-40cd-8601-9be0f40ede27`

From [r7insight_python source](https://github.com/rapid7/r7insight_python/blob/master/r7insight/utils.py):
> `LE_ENDPOINT_DEFAULT = "{}.data.logs.insight.rapid7.com"` with ports 80/443 for **TCP** connections

**Issue:** Our implementation uses `data.logs.insight.rapid7.com` (designed for TCP streaming) with HTTP POST path format (`/v1/noformat`). This may work in some cases, but is not the documented approach for HTTP-based log ingestion.

**Fix Required:**
```typescript
const REGION_ENDPOINTS: Record<InsightIDRRegion, string> = {
  us: 'us.webhook.logs.insight.rapid7.com',
  us2: 'us2.webhook.logs.insight.rapid7.com',
  us3: 'us3.webhook.logs.insight.rapid7.com',
  eu: 'eu.webhook.logs.insight.rapid7.com',
  ca: 'ca.webhook.logs.insight.rapid7.com',
  au: 'au.webhook.logs.insight.rapid7.com',
  ap: 'ap.webhook.logs.insight.rapid7.com',
};
```

---

### 2. Authentication Header - UNCLEAR

**Current Implementation:**
```typescript
headers: {
  'Content-Type': 'application/json',
  'X-Insight-Token': this.logToken,
},
```

**Official Documentation:**

The official HTTP POST documentation shows the token embedded in the URL path, with no additional authentication header:

```bash
curl -i -H "Accept: application/json" -X POST \
  -d '{"message":"sending logs"}' \
  https://us.webhook.logs.insight.rapid7.com/v1/noformat/YOUR-TOKEN-HERE
```

For other Rapid7 APIs (like Log Search), authentication uses `X-Api-Key`:
> Authentication is performed by passing your API key via a single HTTP header: `X-Api-Key`

**Issue:** The `X-Insight-Token` header is not mentioned in any official documentation. The token is typically part of the URL path for the noformat webhook endpoint.

**Recommendation:**
- Remove the `X-Insight-Token` header (it may be ignored)
- The token in the URL path is sufficient for authentication
- Alternatively, keep it for defense-in-depth (no harm if ignored)

---

### 3. Regions - ALIGNED

**Current Implementation:**
```typescript
type InsightIDRRegion = 'us' | 'us2' | 'us3' | 'eu' | 'ca' | 'au' | 'ap';
```

**Official Documentation:** Supported regions are `us`, `us2`, `us3`, `eu`, `ap`, `ca`, `au`

**Status:** All 7 regions are correctly supported.

---

### 4. NDJSON Batch Format - ALIGNED

**Current Implementation:**
```typescript
const ndjson = logEntries.map((entry) => JSON.stringify(entry)).join('\n');
```

**Official Documentation:** Newline-delimited JSON is the standard format for batch log uploads.

**Status:** Correctly implemented.

---

### 5. Response Handling - ALIGNED

**Current Implementation:**
- 200-299: Success
- 429: Rate limited (retryable)
- 5xx: Server error (retryable)
- 4xx: Client error (non-retryable)

**Official Documentation:**
> A successful response returns `HTTP/1.1 204 No Content`

**Status:** The implementation correctly handles success responses (including 204). Consider explicitly checking for 204 as the expected success response.

---

## Actionable Fixes

### Required Changes

1. **Change endpoint hostname** from `data.logs.insight.rapid7.com` to `webhook.logs.insight.rapid7.com`
   - Priority: **Critical**
   - Risk: Current implementation may not work reliably

### Recommended Changes

2. **Remove `X-Insight-Token` header** or document why it's included
   - Priority: Low
   - Risk: None (likely ignored by server)

3. **Add `Accept: application/json` header** (shown in official curl examples)
   - Priority: Low
   - Risk: None

4. **Document expected 204 response** for successful submissions
   - Priority: Low
   - Risk: None

---

## Code Change

```diff
// Constants
const REGION_ENDPOINTS: Record<InsightIDRRegion, string> = {
-  us: 'us.data.logs.insight.rapid7.com',
-  us2: 'us2.data.logs.insight.rapid7.com',
-  us3: 'us3.data.logs.insight.rapid7.com',
-  eu: 'eu.data.logs.insight.rapid7.com',
-  ca: 'ca.data.logs.insight.rapid7.com',
-  au: 'au.data.logs.insight.rapid7.com',
-  ap: 'ap.data.logs.insight.rapid7.com',
+  us: 'us.webhook.logs.insight.rapid7.com',
+  us2: 'us2.webhook.logs.insight.rapid7.com',
+  us3: 'us3.webhook.logs.insight.rapid7.com',
+  eu: 'eu.webhook.logs.insight.rapid7.com',
+  ca: 'ca.webhook.logs.insight.rapid7.com',
+  au: 'au.webhook.logs.insight.rapid7.com',
+  ap: 'ap.webhook.logs.insight.rapid7.com',
};

// In sendRequest method
private async sendRequest(body: string): Promise<Response> {
  // ...
  return await fetch(this.endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
-     'X-Insight-Token': this.logToken,
+     'Accept': 'application/json',
    },
    body,
    signal: controller.signal,
  });
}
```

---

## Testing Recommendations

1. **Verify endpoint connectivity** with a test log entry to each region
2. **Confirm 204 response** is the expected success status
3. **Test rate limiting behavior** (if possible with staging account)
4. **Validate NDJSON batch uploads** with multiple entries
