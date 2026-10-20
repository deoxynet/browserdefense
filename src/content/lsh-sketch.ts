/**
 * LSH (Locality-Sensitive Hashing) Sketch Generation
 *
 * Generates similarity-preserving sketches from DOM skeletons for phishing kit
 * variant discovery. Uses MinHash algorithm to create compact signatures that
 * allow approximate similarity comparison.
 *
 * PRIVACY GUARANTEES:
 * - NO URLs or text content transmitted
 * - NO user data captured
 * - Sketches are non-reversible (one-way hash functions)
 * - Structure-only fingerprints
 *
 * Sketch Types:
 * - dom_layout_lsh: Structural layout patterns (tag hierarchy)
 * - form_structure_lsh: Form field structures and patterns
 * - script_structure_lsh: Script/resource patterns
 *
 * Reference: Issue #200
 */

import type { DOMSkeleton } from './dom-skeleton';
import type { FormSchema } from './form-schema';

// ============ Types ============

/**
 * LSH sketches for similarity detection.
 */
export interface LSHSketches {
  /** DOM layout structure sketch (MinHash signature) */
  dom_layout_lsh: string;
  /** Form structure sketch (MinHash signature) */
  form_structure_lsh: string;
  /** Script/resource structure sketch (MinHash signature) */
  script_structure_lsh: string;
  /** Generation time in ms (for monitoring) */
  generationTimeMs: number;
}

/**
 * Extended skeleton info including scripts for LSH generation.
 */
export interface ExtendedSkeletonInfo {
  skeleton: DOMSkeleton;
  formSchemas?: FormSchema[];
  scriptSrcs?: string[];
  linkHrefs?: string[];
}

// ============ Constants ============

/** Number of hash functions for MinHash (determines sketch size) */
const NUM_HASHES = 64;

/** Shingle size (n-gram length) for text features */
const SHINGLE_SIZE = 3;

/** Large prime for hash function */
const LARGE_PRIME = 4294967311;

/** Another large prime for hash mixing */
const HASH_PRIME_A = 2654435761;
const HASH_PRIME_B = 2246822519;

// Pre-computed random coefficients for MinHash
// Generated deterministically for reproducibility
const HASH_COEFFICIENTS_A: number[] = [];
const HASH_COEFFICIENTS_B: number[] = [];

for (let i = 0; i < NUM_HASHES; i++) {
  // Use deterministic seed based on index
  HASH_COEFFICIENTS_A.push(((i * HASH_PRIME_A) % LARGE_PRIME) | 0);
  HASH_COEFFICIENTS_B.push(((i * HASH_PRIME_B + 1) % LARGE_PRIME) | 0);
}

// ============ MinHash Implementation ============

/**
 * Compute a simple hash of a string (djb2 algorithm).
 * Fast and produces reasonable distribution.
 */
function hashString(str: string): number {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash + str.charCodeAt(i)) >>> 0;
  }
  return hash;
}

/**
 * Apply a hash function to a value using linear hash family.
 * h_i(x) = (a_i * x + b_i) mod p
 */
function applyHashFunction(value: number, index: number): number {
  const a = HASH_COEFFICIENTS_A[index];
  const b = HASH_COEFFICIENTS_B[index];
  return (((a * value + b) >>> 0) % LARGE_PRIME) >>> 0;
}

/**
 * Generate MinHash signature from a set of shingles.
 *
 * MinHash produces a fixed-size signature that preserves Jaccard similarity.
 * Two sets with high Jaccard similarity will have similar MinHash signatures.
 *
 * @param shingles - Set of string shingles (n-grams)
 * @returns Array of NUM_HASHES minimum hash values
 */
function minHash(shingles: Set<string>): number[] {
  if (shingles.size === 0) {
    // Return zeros for empty sets
    return new Array(NUM_HASHES).fill(0);
  }

  // Initialize signature with max values
  const signature = new Array(NUM_HASHES).fill(Number.MAX_SAFE_INTEGER);

  // For each shingle, compute its hash and update min values
  for (const shingle of shingles) {
    const baseHash = hashString(shingle);

    for (let i = 0; i < NUM_HASHES; i++) {
      const hashValue = applyHashFunction(baseHash, i);
      if (hashValue < signature[i]) {
        signature[i] = hashValue;
      }
    }
  }

  return signature;
}

/**
 * Convert MinHash signature to compact hex string.
 * Uses 4 bytes per hash value, total 256 bytes for 64 hashes.
 */
function signatureToHex(signature: number[]): string {
  const bytes: string[] = [];
  for (const value of signature) {
    // Take lower 32 bits and convert to 8 hex chars
    bytes.push((value >>> 0).toString(16).padStart(8, '0'));
  }
  return bytes.join('');
}

// ============ Shingle Extraction ============

/**
 * Extract character n-grams (shingles) from a string.
 */
function extractShingles(text: string, n: number = SHINGLE_SIZE): Set<string> {
  const shingles = new Set<string>();

  if (text.length < n) {
    if (text.length > 0) {
      shingles.add(text);
    }
    return shingles;
  }

  for (let i = 0; i <= text.length - n; i++) {
    shingles.add(text.slice(i, i + n));
  }

  return shingles;
}

/**
 * Extract structural tokens from tag tree for DOM layout LSH.
 *
 * Extracts patterns like:
 * - "div>form" (parent-child relationships)
 * - "input[type=password]" (element attributes)
 * - "div(3)" (element with 3 children - normalized)
 */
function extractDOMLayoutShingles(tagTree: string): Set<string> {
  const shingles = new Set<string>();

  // Extract tag names and attributes
  const tagPattern = /([a-z]+)(\[[^\]]*\])?/g;
  let match;

  while ((match = tagPattern.exec(tagTree)) !== null) {
    const tag = match[1];
    const attrs = match[2] || '';

    // Add tag with attributes
    shingles.add(tag + attrs);

    // Add just the tag
    shingles.add(tag);
  }

  // Extract parent-child patterns from structure
  // Look for patterns like "div(input" -> "div>input"
  const parentChildPattern = /([a-z]+)(?:\[[^\]]*\])?\(([a-z]+)/g;
  while ((match = parentChildPattern.exec(tagTree)) !== null) {
    shingles.add(`${match[1]}>${match[2]}`);
  }

  // Extract sibling patterns (elements separated by comma in same parent)
  const siblingPattern = /\(([^)]+)\)/g;
  while ((match = siblingPattern.exec(tagTree)) !== null) {
    const siblings = match[1].split(',').map((s) => {
      const tagMatch = s.match(/^([a-z]+)/);
      return tagMatch ? tagMatch[1] : '';
    }).filter(Boolean);

    // Add adjacent sibling pairs
    for (let i = 0; i < siblings.length - 1; i++) {
      shingles.add(`${siblings[i]}+${siblings[i + 1]}`);
    }
  }

  // Add n-gram shingles of the normalized tree
  const ngramShingles = extractShingles(tagTree, SHINGLE_SIZE);
  for (const s of ngramShingles) {
    shingles.add(`ng:${s}`);
  }

  return shingles;
}

/**
 * Extract form structure shingles from form schemas.
 *
 * Captures:
 * - Field type sequences
 * - Autocomplete attribute patterns
 * - Form method and structure
 */
function extractFormStructureShingles(formSchemas: FormSchema[]): Set<string> {
  const shingles = new Set<string>();

  if (!formSchemas || formSchemas.length === 0) {
    shingles.add('no-forms');
    return shingles;
  }

  shingles.add(`form-count:${Math.min(formSchemas.length, 10)}`);

  for (let formIdx = 0; formIdx < formSchemas.length; formIdx++) {
    const form = formSchemas[formIdx];

    // Form-level features
    shingles.add(`method:${form.method.toLowerCase()}`);

    if (form.isLoginForm) {
      shingles.add('is-login-form');
    }
    if (form.isPaymentForm) {
      shingles.add('is-payment-form');
    }

    // Field type sequence
    const fieldTypes = form.fields.map((f) => f.type || f.tag).join(',');
    shingles.add(`field-types:${fieldTypes}`);

    // Individual field features
    for (const field of form.fields) {
      shingles.add(`field:${field.tag}`);

      if (field.type) {
        shingles.add(`type:${field.type}`);
      }

      if (field.autocomplete) {
        shingles.add(`ac:${field.autocomplete}`);
      }

      if (field.required) {
        shingles.add(`req:${field.type || field.tag}`);
      }

      // Name patterns (normalized - just the pattern, not the actual name)
      if (field.name) {
        const namePattern = field.name.replace(/[0-9]+/g, '#').toLowerCase();
        shingles.add(`name-pattern:${namePattern}`);
      }
    }

    // Field count bucket
    const fieldCountBucket = Math.min(Math.floor(form.fieldCount / 3), 5);
    shingles.add(`field-bucket:${fieldCountBucket}`);
  }

  return shingles;
}

/**
 * Extract script/resource structure shingles.
 *
 * Captures:
 * - Script source patterns (domain, path structure)
 * - Link/stylesheet patterns
 * - Resource loading patterns
 */
function extractScriptStructureShingles(
  scriptSrcs: string[],
  linkHrefs: string[]
): Set<string> {
  const shingles = new Set<string>();

  if (scriptSrcs.length === 0 && linkHrefs.length === 0) {
    shingles.add('no-resources');
    return shingles;
  }

  // Script count bucket
  const scriptBucket = Math.min(Math.floor(scriptSrcs.length / 3), 5);
  shingles.add(`script-bucket:${scriptBucket}`);

  // Link count bucket
  const linkBucket = Math.min(Math.floor(linkHrefs.length / 3), 5);
  shingles.add(`link-bucket:${linkBucket}`);

  // Extract patterns from script sources
  for (const src of scriptSrcs) {
    const patterns = extractResourcePatterns(src, 'script');
    for (const p of patterns) {
      shingles.add(p);
    }
  }

  // Extract patterns from link hrefs
  for (const href of linkHrefs) {
    const patterns = extractResourcePatterns(href, 'link');
    for (const p of patterns) {
      shingles.add(p);
    }
  }

  return shingles;
}

/**
 * Extract normalized patterns from a resource URL.
 * Does NOT include the full URL - only structural patterns.
 */
function extractResourcePatterns(url: string, type: string): string[] {
  const patterns: string[] = [];

  try {
    // Handle relative URLs
    if (url.startsWith('//')) {
      url = 'https:' + url;
    } else if (url.startsWith('/')) {
      // Relative path - extract path patterns only
      const pathParts = url.split('/').filter(Boolean);
      patterns.push(`${type}:rel-path`);
      patterns.push(`${type}:depth-${Math.min(pathParts.length, 5)}`);

      // File extension pattern
      const lastPart = pathParts[pathParts.length - 1] || '';
      const extMatch = lastPart.match(/\.([a-z0-9]+)$/i);
      if (extMatch) {
        patterns.push(`${type}:ext-${extMatch[1].toLowerCase()}`);
      }

      return patterns;
    } else if (!url.match(/^https?:\/\//i)) {
      // Other relative URL
      patterns.push(`${type}:rel`);
      return patterns;
    }

    const parsed = new URL(url);

    // Domain pattern (TLD only for privacy)
    const hostParts = parsed.hostname.split('.');
    if (hostParts.length >= 2) {
      const tld = hostParts[hostParts.length - 1];
      patterns.push(`${type}:tld-${tld}`);

      // Check for CDN patterns
      const domain = hostParts.slice(-2).join('.');
      if (isCDNDomain(domain)) {
        patterns.push(`${type}:cdn`);
      }
    }

    // Path depth
    const pathParts = parsed.pathname.split('/').filter(Boolean);
    patterns.push(`${type}:depth-${Math.min(pathParts.length, 5)}`);

    // File extension
    const lastPart = pathParts[pathParts.length - 1] || '';
    const extMatch = lastPart.match(/\.([a-z0-9]+)$/i);
    if (extMatch) {
      patterns.push(`${type}:ext-${extMatch[1].toLowerCase()}`);
    }

    // Has query string
    if (parsed.search) {
      patterns.push(`${type}:has-query`);
    }
  } catch {
    patterns.push(`${type}:invalid-url`);
  }

  return patterns;
}

/**
 * Check if a domain appears to be a CDN.
 */
function isCDNDomain(domain: string): boolean {
  const cdnPatterns = [
    'cloudflare.com',
    'cloudfront.net',
    'akamai.net',
    'fastly.net',
    'jsdelivr.net',
    'unpkg.com',
    'cdnjs.cloudflare.com',
    'googleapis.com',
    'gstatic.com',
    'bootstrapcdn.com',
  ];
  return cdnPatterns.some((cdn) => domain.includes(cdn) || domain.endsWith(cdn));
}

// ============ Public API ============

/**
 * Extract script and link resource info from the document.
 * Call this from content script before sending to background.
 */
export function extractScriptInfo(doc: Document): {
  scriptSrcs: string[];
  linkHrefs: string[];
} {
  const scriptSrcs: string[] = [];
  const linkHrefs: string[] = [];

  // Extract script sources
  const scripts = doc.querySelectorAll('script[src]');
  for (const script of scripts) {
    const src = script.getAttribute('src');
    if (src) {
      scriptSrcs.push(src);
    }
  }

  // Extract stylesheet links
  const links = doc.querySelectorAll('link[rel="stylesheet"]');
  for (const link of links) {
    const href = link.getAttribute('href');
    if (href) {
      linkHrefs.push(href);
    }
  }

  return { scriptSrcs, linkHrefs };
}

/**
 * Generate all LSH sketches from DOM skeleton and related info.
 *
 * @param skeleton - DOM skeleton from extractSkeleton()
 * @param formSchemas - Form schemas from extractFormSchemas()
 * @param scriptInfo - Script/link info from extractScriptInfo()
 * @returns LSH sketches for all three types
 */
export function generateAllSketches(
  skeleton: DOMSkeleton,
  formSchemas?: FormSchema[],
  scriptInfo?: { scriptSrcs: string[]; linkHrefs: string[] }
): LSHSketches {
  const startTime = performance.now();

  // Generate DOM layout LSH
  const layoutShingles = extractDOMLayoutShingles(skeleton.tagTree);
  const layoutSignature = minHash(layoutShingles);
  const dom_layout_lsh = signatureToHex(layoutSignature);

  // Generate form structure LSH
  const formShingles = extractFormStructureShingles(formSchemas || []);
  const formSignature = minHash(formShingles);
  const form_structure_lsh = signatureToHex(formSignature);

  // Generate script structure LSH
  const scriptShingles = extractScriptStructureShingles(
    scriptInfo?.scriptSrcs || [],
    scriptInfo?.linkHrefs || []
  );
  const scriptSignature = minHash(scriptShingles);
  const script_structure_lsh = signatureToHex(scriptSignature);

  const generationTimeMs = performance.now() - startTime;

  return {
    dom_layout_lsh,
    form_structure_lsh,
    script_structure_lsh,
    generationTimeMs,
  };
}

/**
 * Estimate Jaccard similarity between two MinHash signatures.
 * Useful for testing and debugging.
 *
 * @param sig1 - First signature (hex string)
 * @param sig2 - Second signature (hex string)
 * @returns Estimated Jaccard similarity [0, 1]
 */
export function estimateSimilarity(sig1: string, sig2: string): number {
  if (sig1.length !== sig2.length || sig1.length !== NUM_HASHES * 8) {
    throw new Error('Invalid signature length');
  }

  let matches = 0;
  for (let i = 0; i < NUM_HASHES; i++) {
    const start = i * 8;
    const hash1 = sig1.slice(start, start + 8);
    const hash2 = sig2.slice(start, start + 8);
    if (hash1 === hash2) {
      matches++;
    }
  }

  return matches / NUM_HASHES;
}

// ============ Exports for Testing ============

export {
  hashString as _hashString,
  minHash as _minHash,
  extractShingles as _extractShingles,
  extractDOMLayoutShingles as _extractDOMLayoutShingles,
  extractFormStructureShingles as _extractFormStructureShingles,
  extractScriptStructureShingles as _extractScriptStructureShingles,
  NUM_HASHES as _NUM_HASHES,
};
