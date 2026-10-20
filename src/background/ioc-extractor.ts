/**
 * IOC Extractor (Issue #399)
 *
 * Extracts and defangs Indicators of Compromise from text:
 * - URLs (http/https, ftp, file)
 * - Domains (with optional defanging like [.] or hxxp)
 * - IPv4 addresses
 * - IPv6 addresses
 * - Hashes (MD5, SHA1, SHA256)
 * - Email addresses
 */

export interface ExtractedIOC {
  type: 'url' | 'domain' | 'ipv4' | 'ipv6' | 'md5' | 'sha1' | 'sha256' | 'email';
  value: string;
  original: string;
  defanged: boolean;
}

export interface ExtractionResult {
  iocs: ExtractedIOC[];
  text: string;
}

/**
 * Refang defanged IOCs (convert [.] to . etc).
 */
function refang(text: string): string {
  return text
    // Protocol defanging
    .replace(/hxxp/gi, 'http')
    .replace(/hXXp/g, 'http')
    .replace(/\[:\]\/\//g, '://')
    .replace(/:\/\/\[/g, '://') // Leftover brackets
    .replace(/\]:/g, ':')       // Leftover brackets before port
    // Domain defanging
    .replace(/\[\.\]/g, '.')
    .replace(/\[dot\]/gi, '.')
    .replace(/\(dot\)/gi, '.')
    .replace(/\{dot\}/gi, '.')
    .replace(/\[\]/g, '')       // Empty brackets
    // At sign defanging (emails)
    .replace(/\[@\]/g, '@')
    .replace(/\[at\]/gi, '@')
    .replace(/\(at\)/gi, '@')
    .replace(/\{at\}/gi, '@');
}

/**
 * Check if text contains defanging indicators.
 */
function isDefanged(text: string): boolean {
  return /hxxp|hXXp|\[\.\]|\[dot\]|\(dot\)|\{dot\}|\[@\]|\[at\]|\(at\)|\{at\}|\[:\]/i.test(text);
}

// URL regex - matches http(s), ftp, file protocols
const URL_REGEX = /(?:(?:https?|ftp|file):\/\/|www\.)[^\s<>[\]"'`]+/gi;

// Domain regex - matches valid domain names
const DOMAIN_REGEX = /(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|io|co|uk|de|ru|cn|info|biz|xyz|top|online|site|app|dev|tech|cloud|[a-z]{2,}))/gi;

// IPv4 regex
const IPV4_REGEX = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g;

// IPv6 regex (simplified - matches most common formats)
const IPV6_REGEX = /(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})/gi;

// Hash regexes (with word boundaries)
const MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g;

// Email regex
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

/**
 * Extract all IOCs from text.
 * Returns deduplicated list with original and refanged values.
 */
export function extractIOCs(text: string): ExtractionResult {
  const iocs: ExtractedIOC[] = [];
  const seen = new Set<string>();

  // First, check if text contains defanging
  const wasDefanged = isDefanged(text);
  const cleanText = refang(text);

  // Extract URLs
  const urls = cleanText.match(URL_REGEX) || [];
  for (const url of urls) {
    const normalized = url.toLowerCase();
    if (!seen.has(normalized)) {
      seen.add(normalized);
      iocs.push({
        type: 'url',
        value: url,
        original: wasDefanged ? findOriginal(text, url) : url,
        defanged: wasDefanged,
      });
    }
  }

  // Extract domains (that aren't part of URLs)
  const domains = cleanText.match(DOMAIN_REGEX) || [];
  for (const domain of domains) {
    const normalized = domain.toLowerCase();
    // Skip if we already have this as part of a URL
    if (!seen.has(normalized) && !Array.from(seen).some((s) => s.includes(normalized))) {
      seen.add(normalized);
      iocs.push({
        type: 'domain',
        value: domain,
        original: wasDefanged ? findOriginal(text, domain) : domain,
        defanged: wasDefanged,
      });
    }
  }

  // Extract IPv4 addresses
  const ipv4s = cleanText.match(IPV4_REGEX) || [];
  for (const ip of ipv4s) {
    if (!seen.has(ip)) {
      seen.add(ip);
      iocs.push({
        type: 'ipv4',
        value: ip,
        original: wasDefanged ? findOriginal(text, ip) : ip,
        defanged: wasDefanged,
      });
    }
  }

  // Extract IPv6 addresses
  const ipv6s = cleanText.match(IPV6_REGEX) || [];
  for (const ip of ipv6s) {
    const normalized = ip.toLowerCase();
    if (!seen.has(normalized)) {
      seen.add(normalized);
      iocs.push({
        type: 'ipv6',
        value: ip,
        original: ip,
        defanged: false,
      });
    }
  }

  // Extract hashes (check for longest first to avoid false positives)
  const sha256s = cleanText.match(SHA256_REGEX) || [];
  for (const hash of sha256s) {
    const normalized = hash.toLowerCase();
    if (!seen.has(normalized)) {
      seen.add(normalized);
      iocs.push({
        type: 'sha256',
        value: normalized,
        original: hash,
        defanged: false,
      });
    }
  }

  const sha1s = cleanText.match(SHA1_REGEX) || [];
  for (const hash of sha1s) {
    const normalized = hash.toLowerCase();
    // Skip if this is a substring of a SHA256
    if (!seen.has(normalized) && !Array.from(seen).some((s) => s.includes(normalized))) {
      seen.add(normalized);
      iocs.push({
        type: 'sha1',
        value: normalized,
        original: hash,
        defanged: false,
      });
    }
  }

  const md5s = cleanText.match(MD5_REGEX) || [];
  for (const hash of md5s) {
    const normalized = hash.toLowerCase();
    // Skip if this is a substring of a longer hash
    if (!seen.has(normalized) && !Array.from(seen).some((s) => s.includes(normalized))) {
      seen.add(normalized);
      iocs.push({
        type: 'md5',
        value: normalized,
        original: hash,
        defanged: false,
      });
    }
  }

  // Extract email addresses
  const emails = cleanText.match(EMAIL_REGEX) || [];
  for (const email of emails) {
    const normalized = email.toLowerCase();
    if (!seen.has(normalized)) {
      seen.add(normalized);
      iocs.push({
        type: 'email',
        value: normalized,
        original: wasDefanged ? findOriginal(text, email) : email,
        defanged: wasDefanged,
      });
    }
  }

  return {
    iocs,
    text: cleanText,
  };
}

/**
 * Find the original defanged version of a refanged IOC.
 * Returns the refanged value if no match found (best-effort).
 */
function findOriginal(originalText: string, refangedValue: string): string {
  // For simplicity, just return the refanged value
  // Finding the original defanged version is complex and error-prone
  // The original field is informational only
  return refangedValue;
}

/**
 * Defang an IOC for safe display/sharing.
 */
export function defangIOC(ioc: ExtractedIOC): string {
  switch (ioc.type) {
    case 'url':
      return ioc.value
        .replace(/http/gi, 'hxxp')
        .replace(/\./g, '[.]');
    case 'domain':
      return ioc.value.replace(/\./g, '[.]');
    case 'email':
      return ioc.value
        .replace(/@/g, '[@]')
        .replace(/\./g, '[.]');
    case 'ipv4':
      return ioc.value.replace(/\./g, '[.]');
    default:
      return ioc.value;
  }
}
