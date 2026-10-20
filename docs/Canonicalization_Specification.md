# URL Canonicalization Specification

**Version:** 1.0
**Status:** IMPLEMENTATION READY
**Purpose:** Define exact normalization rules for URLs before hashing to ensure consistent IOC matching

---

## Overview

URL canonicalization is a **security boundary**. If normalization differs between "add IOC" and "check request", attacks will bypass blocking.

**The Core Problem:**
```
IOC added:     evil.com
URL clicked:   http://EVIL.COM.:80/%2e%2e/
Result:        BYPASS (if not normalized consistently)
```

This specification defines the exact normalization steps to prevent such bypasses.

---

## Design Principles

1. **Consistency over correctness** — The same input must always produce the same output
2. **Minimize attack surface** — Normalize away encoding tricks attackers use
3. **Follow browser behavior** — Match how browsers resolve URLs
4. **Configurable scope** — Support HOST_ONLY, HOST_PATH, and FULL_URL modes

---

## Canonicalization Rules

### 1. Scheme Normalization

| Rule | Input | Output |
|------|-------|--------|
| Lowercase scheme | `HTTP://` | `http://` |
| Require http/https | `ftp://` | (reject) |

**Implementation:**
```typescript
const scheme = url.protocol.toLowerCase();
if (scheme !== 'http:' && scheme !== 'https:') {
  throw new Error('Unsupported scheme');
}
```

### 2. Hostname Normalization

| Rule | Input | Output | Rationale |
|------|-------|--------|-----------|
| Lowercase | `EVIL.COM` | `evil.com` | DNS is case-insensitive |
| Strip trailing dot | `evil.com.` | `evil.com` | DNS root marker |
| IDN to Punycode | `évil.com` | `xn--vil-loa.com` | Browser does this automatically |
| Remove leading/trailing whitespace | ` evil.com ` | `evil.com` | URL constructor handles this |
| IPv4 normalization | `0177.0.0.1` | `127.0.0.1` | Prevent octal/hex bypass |
| IPv6 bracket normalization | `[::1]` | `[::1]` | Keep brackets for IPv6 |

**IPv4 Octal/Hex Bypass:**
Attackers use octal (`0177.0.0.1`) or hex (`0x7f.0.0.1`) to represent `127.0.0.1`. The URL constructor normalizes these automatically.

**Implementation:**
```typescript
let hostname = url.hostname.toLowerCase();

// Strip trailing dot (DNS root)
if (hostname.endsWith('.')) {
  hostname = hostname.slice(0, -1);
}

// URL constructor already handles:
// - IDN to Punycode conversion
// - IPv4 octal/hex normalization
// - IPv6 bracket handling
```

### 3. Port Normalization

| Rule | Input | Output |
|------|-------|--------|
| Remove default HTTP port | `http://evil.com:80/` | `http://evil.com/` |
| Remove default HTTPS port | `https://evil.com:443/` | `https://evil.com/` |
| Keep non-default ports | `http://evil.com:8080/` | `http://evil.com:8080/` |

**Note:** `url.hostname` excludes port; `url.host` includes it. We use `hostname` and only add port if non-default.

**Implementation:**
```typescript
let hostWithPort = hostname;
if (url.port && url.port !== '80' && url.port !== '443') {
  hostWithPort = `${hostname}:${url.port}`;
}
```

### 4. Path Normalization

| Rule | Input | Output | Rationale |
|------|-------|--------|-----------|
| Empty path to `/` | `http://evil.com` | `http://evil.com/` | Consistent representation |
| Remove trailing slash (non-root) | `/path/` | `/path` | `example.com/path` = `example.com/path/` |
| Keep root slash | `/` | `/` | Root must have slash |
| Resolve `..` and `.` | `/a/../b` | `/b` | URL constructor does this |
| Decode percent-encoding | `/%2e%2e/` | `/../` → `/` | Prevent encoding bypass |
| Re-encode consistently | `/hello world/` | `/hello%20world/` | Consistent encoding |
| Lowercase path? | `/PATH` | `/PATH` | **NO** - paths are case-sensitive |

**Percent-Encoding Attack:**
```
IOC:    evil.com/admin
Attack: evil.com/%61dmin  (%61 = 'a')
```
Decoding then re-encoding consistently prevents this.

**Double-Encoding Attack:**
```
IOC:    evil.com/..
Attack: evil.com/%252e%252e  (%25 = '%', so %252e = %2e = '.')
```
Must decode iteratively until stable.

**Implementation:**
```typescript
let path = url.pathname;

// URL constructor already resolves . and ..
// But we need to handle percent-encoding consistently

// Decode iteratively until stable (handles double-encoding)
let decoded = path;
let prev = '';
while (decoded !== prev) {
  prev = decoded;
  try {
    decoded = decodeURIComponent(decoded);
  } catch {
    break; // Malformed encoding, stop
  }
}

// Re-encode with consistent rules
path = decoded
  .split('/')
  .map(segment => encodeURIComponent(segment))
  .join('/');

// Normalize empty path to /
if (!path || path === '') {
  path = '/';
}

// Remove trailing slash except for root
if (path.length > 1 && path.endsWith('/')) {
  path = path.slice(0, -1);
}
```

### 5. Query String Handling

| Scope | Query Handling |
|-------|---------------|
| `HOST_ONLY` | Ignore query string |
| `HOST_PATH` | Ignore query string |
| `FULL_URL` | Include, sorted alphabetically |

**Why sort query parameters?**
```
evil.com?b=2&a=1  vs  evil.com?a=1&b=2
```
These are functionally equivalent but different strings. Sorting ensures consistency.

**Implementation (FULL_URL mode):**
```typescript
if (scope === 'FULL_URL' && url.search) {
  const params = new URLSearchParams(url.search);
  const sorted = new URLSearchParams([...params.entries()].sort());
  query = '?' + sorted.toString();
}
```

### 6. Fragment Handling

**Always remove fragments.** They are never sent to the server.

```typescript
// url.hash is automatically excluded when we build from components
// No action needed - just don't include it
```

---

## Scope Modes

BrowserDefense supports three canonicalization scopes:

| Mode | Includes | Use Case |
|------|----------|----------|
| `HOST_ONLY` | `hostname` | Domain-level blocking (phishing domains) |
| `HOST_PATH` | `hostname + path` | Path-specific blocking (malware URLs) |
| `FULL_URL` | `hostname + path + query` | Exact URL blocking (specific campaigns) |

**Recommendation:** Use `HOST_PATH` as default. It catches most phishing while allowing legitimate use of the same domain.

---

## IOC Hashing

After canonicalization, the IOC is hashed with an organization-specific salt:

```typescript
async function hashIOC(canonicalUrl: string, salt: string): Promise<string> {
  const data = canonicalUrl + ':' + salt;
  const hashBuffer = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(data)
  );
  return bytesToHex(new Uint8Array(hashBuffer));
}
```

**Why salt?**
- Prevents rainbow table attacks on IOC hashes
- Different orgs have different hash sets (can't cross-reference)
- Salt is org-specific, never leaves the org

---

## Test Vectors

### Hostname Normalization

| Input | Expected Output |
|-------|-----------------|
| `HTTP://EVIL.COM/path` | `evil.com/path` |
| `http://evil.com./path` | `evil.com/path` |
| `http://evil.com:80/path` | `evil.com/path` |
| `https://evil.com:443/path` | `evil.com/path` |
| `http://evil.com:8080/path` | `evil.com:8080/path` |
| `http://192.168.1.1/path` | `192.168.1.1/path` |
| `http://[::1]/path` | `[::1]/path` |

### Path Normalization

| Input | Expected Output |
|-------|-----------------|
| `http://evil.com` | `evil.com/` |
| `http://evil.com/` | `evil.com/` |
| `http://evil.com/path/` | `evil.com/path` |
| `http://evil.com/a/../b` | `evil.com/b` |
| `http://evil.com/a/./b` | `evil.com/a/b` |
| `http://evil.com/%2e%2e/secret` | `evil.com/secret` |
| `http://evil.com/hello%20world` | `evil.com/hello%20world` |
| `http://evil.com/%61dmin` | `evil.com/admin` |

### Encoding Attacks

| Attack Type | Input | Expected Output |
|-------------|-------|-----------------|
| Case bypass | `http://EVIL.COM/ADMIN` | `evil.com/ADMIN` |
| Trailing dot | `http://evil.com./` | `evil.com/` |
| Percent-encode | `http://evil.com/%61dmin` | `evil.com/admin` |
| Double-encode | `http://evil.com/%252e%252e/` | `evil.com/` |
| Octal IP | `http://0177.0.0.1/` | `127.0.0.1/` |
| Default port | `http://evil.com:80/` | `evil.com/` |

### Edge Cases

| Input | Expected Output | Notes |
|-------|-----------------|-------|
| `http://evil.com?query` | `evil.com/` | Query ignored (HOST_PATH) |
| `http://evil.com#fragment` | `evil.com/` | Fragment always ignored |
| `http://evil.com/path?a=1&b=2` | `evil.com/path` | Query ignored (HOST_PATH) |
| `http://evil.com//double//slash` | `evil.com//double//slash` | Preserved (significant) |
| `http://user:pass@evil.com/` | `evil.com/` | Credentials ignored |

---

## Security Considerations

### Attacks This Prevents

1. **Case manipulation** — `EVIL.COM` vs `evil.com`
2. **Trailing dot** — `evil.com.` vs `evil.com`
3. **Default port** — `evil.com:80` vs `evil.com`
4. **Percent-encoding** — `%61dmin` vs `admin`
5. **Double-encoding** — `%252e` vs `%2e` vs `.`
6. **Path traversal** — `/../secret` resolving differently
7. **IP obfuscation** — Octal/hex IP representations

### Attacks This Does NOT Prevent

1. **DNS rebinding** — Requires DNS-level protection
2. **Homograph attacks** — `еvil.com` (Cyrillic 'е') vs `evil.com`
3. **URL shorteners** — `bit.ly/xyz` hiding the real URL
4. **Redirects** — Captured in forensics, not blocking

### Homograph Attack Mitigation

Punycode conversion helps but doesn't fully prevent homograph attacks:
- `еvil.com` (Cyrillic) → `xn--vil-dmc.com` (Punycode)
- This is a different string from `evil.com`

**Recommendation:** Block at Punycode level. If blocking `evil.com`, also consider blocking known Punycode variants.

---

## Implementation Checklist

- [x] Lowercase hostname
- [x] Strip trailing dot
- [x] Remove default ports
- [x] IDN to Punycode (browser handles)
- [x] IPv4 normalization (browser handles)
- [x] IPv6 bracket preservation
- [x] Path `.` and `..` resolution (browser handles)
- [x] Percent-decoding and re-encoding
- [x] Double-encoding protection
- [x] Trailing slash normalization
- [x] Empty path to `/`
- [x] Query string handling (scope-dependent)
- [x] Fragment removal
- [x] Credentials removal

---

## References

- [WHATWG URL Standard](https://url.spec.whatwg.org/)
- [Google Safe Browsing Canonicalization](https://developers.google.com/safe-browsing/v4/urls-hashing)
- [RFC 3986 - URI Generic Syntax](https://tools.ietf.org/html/rfc3986)
- [Public Suffix List](https://publicsuffix.org/)

---

*"The attacker only needs to find one normalization difference. We need to close them all."*
