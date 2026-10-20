# Syslog Connector Audit Report

**Connector:** `src/connectors/syslog.ts`
**Issue:** #216
**Date:** 2026-01-09
**Author:** Claude Code

## References

- **RFC 5424** - The Syslog Protocol (Modern structured syslog)
- **RFC 3164** - BSD Syslog Protocol (Legacy/traditional)
- **RFC 6587** - Transmission of Syslog Messages over TCP
- **CEF Spec** - ArcSight Common Event Format
- **LEEF Spec** - IBM QRadar Log Event Extended Format

## Summary

| Area | Status | Notes |
|------|--------|-------|
| RFC 5424 Message Format | ✅ Aligned | Correct PRI, VERSION, headers, structured data |
| RFC 5424 Structured Data | ✅ Aligned | Proper SD-ELEMENT format with escaping |
| RFC 6587 TCP Framing | ✅ Aligned | Uses octet counting method |
| RFC 3164 Support | ❌ Missing | No legacy BSD syslog support |
| CEF Format | ✅ Aligned | Correct v0 format with escaping |
| LEEF Format | ✅ Aligned | Correct v2.0 with tab delimiters |
| Transport Layer | ⚠️ Partial | Mock implementation only |

## Detailed Analysis

### RFC 5424 Compliance

#### Message Format (Section 6)

The implementation correctly follows the ABNF:

```
SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]
HEADER     = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
```

**Implementation (`buildSyslogMessage`, line 304):**
```typescript
`<${pri}>1 ${timestamp} ${hostname} ${appName} ${procId} ${msgId} ${structuredData} ${bom}${payload}`
```

| Field | Spec | Implementation | Status |
|-------|------|----------------|--------|
| PRI | `<Facility*8+Severity>` | `facility * 8 + severity` | ✅ Correct |
| VERSION | "1" for RFC 5424 | Fixed "1" | ✅ Correct |
| TIMESTAMP | RFC 3339 (ISO 8601) | `new Date().toISOString()` | ✅ Correct |
| HOSTNAME | 255 chars max, NILVALUE="-" | Uses orgId or "-" | ✅ Correct |
| APP-NAME | 48 chars max, NILVALUE="-" | Configurable, default="blockioc-connector" | ✅ Correct |
| PROCID | 128 chars max, NILVALUE="-" | Defaults to "-" | ✅ Correct |
| MSGID | 32 chars max, NILVALUE="-" | Defaults to "-" | ✅ Correct |

#### Structured Data (Section 6.3)

The `buildStructuredData` function correctly implements SD-ELEMENT format:

```
SD-ELEMENT = "[" SD-ID *(SP SD-PARAM) "]"
SD-ID      = SD-NAME "@" SD-PEN
SD-PARAM   = PARAM-NAME "=" %d34 PARAM-VALUE %d34
```

- ✅ Uses PEN format: `BlockIOC@55555`
- ✅ Escapes required chars: `\`, `"`, `]` (line 96-101)
- ✅ NILVALUE "-" when no SD present

#### MSG Field (Section 6.4)

- ✅ BOM (`\uFEFF`) prefix for UTF-8 messages
- Note: BOM is optional when message contains only US-ASCII

### RFC 3164 Compliance

**Status: Not Implemented**

RFC 3164 (BSD syslog) uses a different format:
```
<PRI>TIMESTAMP HOSTNAME TAG: MSG
```

Where:
- TIMESTAMP is "Mmm dd hh:mm:ss" (not ISO 8601)
- No version field
- No structured data support

**Impact:** Some legacy syslog servers (older rsyslog, syslog-ng configurations, network appliances) may only understand RFC 3164 format.

**Recommendation:** Add a `rfc3164` option to `format` config:
```typescript
format: 'cef' | 'leef' | 'json' | 'raw' | 'rfc3164'
```

### RFC 6587 Compliance (TCP Transport)

#### Octet Counting (Section 3.4.1)

**Implementation (`sendTcp`, line 614):**
```typescript
const framedMessage = `${Buffer.byteLength(message, 'utf8')} ${message}`;
```

✅ Correctly implements:
```
OCTET-COUNT SP SYSLOG-MSG
```

#### Non-Transparent-Framing (Section 3.4.2)

**Status: Not Implemented**

Some syslog servers expect LF-terminated messages:
```
SYSLOG-MSG TRAILER
TRAILER = LF
```

**Recommendation:** Add `tcpFraming: 'octet-counting' | 'lf-terminated'` config option.

### CEF Format Compliance

Reference: ArcSight Common Event Format v25

**Header Format:**
```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

✅ Implementation (line 167):
```typescript
`CEF:0|${vendor}|${product}|${version}|${sigId}|${name}|${CEF_SEVERITY.MEDIUM}|${extensions.join(' ')}`
```

**Extension Escaping (line 73-79):**
- ✅ Backslash → `\\`
- ✅ Equals → `\=`
- ✅ Newline → `\n`
- ✅ Carriage return → `\r`

**Standard Fields Used:**
| Field | Description | Used |
|-------|-------------|------|
| rt | Receipt Time (epoch ms) | ✅ |
| request | Request URL | ✅ |
| src | Source | ✅ (orgId) |
| cat | Category | ✅ (WebSecurity) |
| act | Action | ✅ (Block) |
| surl | Source URL | ✅ (initiatorUrl) |
| suser | Source User | ✅ |
| dvchost | Device Hostname | ✅ |
| cs1-cs4 | Custom strings | ✅ |

### LEEF Format Compliance

Reference: IBM QRadar LEEF Format v2.0

**Header Format:**
```
LEEF:Version|Vendor|Product|Version|EventID|attrs
```

✅ Implementation (line 229):
```typescript
`LEEF:2.0|${vendor}|${product}|${version}|${eventId}|${attrs.join('\t')}`
```

- ✅ Uses LEEF 2.0 (not 1.0)
- ✅ Tab-separated attributes (default delimiter)
- ✅ Proper escaping of tab, newline, carriage return

## Issues and Recommendations

### High Priority

#### 1. Mock Transport Layer

**Issue:** The `MockSocket` class doesn't perform actual network operations. This is fine for unit testing but the connector won't work in production.

**Location:** `syslog.ts:356-396`

**Recommendation:**
- For Node.js environments: Use `net` and `tls` modules
- For browser environments: Use WebSocket bridge or HTTP-based syslog relay
- Consider using a library like `modern-syslog` or implementing native transport

#### 2. Placeholder PEN

**Issue:** Uses `55555` as Private Enterprise Number.

**Location:** `syslog.ts:47`

**Recommendation:**
- Register for an IANA PEN at https://pen.iana.org/pen/PenApplication.page
- Or document that customers should use their own PEN

### Medium Priority

#### 3. No RFC 3164 Support

**Issue:** Cannot send to legacy syslog servers.

**Recommendation:** Add legacy format option:
```typescript
interface SyslogConnectorConfig {
  // ... existing fields
  rfcVersion?: '5424' | '3164';
}
```

#### 4. No LF-Terminated TCP Framing

**Issue:** Some servers expect newline-terminated messages.

**Recommendation:** Add framing option:
```typescript
interface SyslogConnectorConfig {
  tcpFraming?: 'octet-counting' | 'lf-terminated';
}
```

#### 5. TLS Not Actually Implemented

**Issue:** TCP+TLS is listed as supported but certificate validation is not implemented.

**Location:** `syslog.ts:470-477`

**Recommendation:** When implementing real transport, add:
- CA certificate validation
- Client certificate authentication
- Certificate pinning option

### Low Priority

#### 6. BOM Always Present

**Issue:** BOM is always added to MSG, but it's only required for UTF-8 messages that don't use structured data for text conveyance.

**Recommendation:** Make BOM optional:
```typescript
interface SyslogConnectorConfig {
  includeBom?: boolean; // default true for backward compat
}
```

#### 7. Hostname Length Validation

**Issue:** RFC 5424 limits HOSTNAME to 255 characters, not validated.

**Location:** `buildSyslogMessage`

**Recommendation:** Truncate or validate hostname length.

#### 8. APP-NAME Length Validation

**Issue:** RFC 5424 limits APP-NAME to 48 characters.

**Recommendation:** Add validation in `doInit()` or truncate.

## Test Coverage Assessment

The test file (`tests/connectors/syslog.test.ts`) provides good coverage:

| Area | Coverage |
|------|----------|
| Escape functions | ✅ Comprehensive |
| CEF formatting | ✅ Comprehensive |
| LEEF formatting | ✅ Good |
| JSON formatting | ✅ Good |
| Raw formatting | ✅ Basic |
| Structured data | ✅ Comprehensive |
| Message building | ✅ Good |
| Connector lifecycle | ✅ Good |
| Config validation | ✅ Good |
| Error handling | ⚠️ Limited (mock transport) |

**Recommended Additional Tests:**
1. Hostname/APP-NAME length edge cases
2. Very large messages (UDP 65507 byte limit)
3. Connection failure scenarios
4. Retry behavior

## Conclusion

The Syslog connector implementation is **well-aligned** with RFC 5424 and RFC 6587 specifications. The CEF and LEEF formatters follow their respective specifications correctly.

**Main gaps:**
1. Transport layer is mock-only (expected for v1, needs real implementation)
2. No RFC 3164 legacy support (may limit compatibility)
3. Placeholder PEN needs replacement for production

**Recommended next steps:**
1. Implement real transport layer (Node.js net/tls)
2. Add RFC 3164 format option for legacy compatibility
3. Register for or document PEN requirements
4. Add config validation for field length limits
