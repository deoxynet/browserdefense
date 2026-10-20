/**
 * DOM Skeleton Extraction
 *
 * Captures page structure for phishing kit fingerprinting.
 * Deterministic extraction of tag topology without content.
 *
 * What we capture:
 * - Tag hierarchy (structure)
 * - Form elements and their types
 * - Input types (email, password, text, etc.)
 * - Form action URLs (normalized)
 *
 * What we exclude:
 * - Text content
 * - Images
 * - Styles/CSS
 * - Form values (user data)
 * - Script content
 *
 * Performance target: <10ms on typical pages
 *
 * Reference: docs/Architecture_v2_DOM_Detection.md
 */

/**
 * DOM skeleton structure for fingerprinting.
 */
export interface DOMSkeleton {
  /** Serialized tag hierarchy (deterministic) */
  tagTree: string;
  /** Number of form elements */
  formCount: number;
  /** Unique input types found (sorted) */
  inputTypes: string[];
  /** Form action URLs (normalized, sorted) */
  actionUrls: string[];
  /** Whether a login-like form is detected */
  hasLoginForm: boolean;
  /** Whether a payment-like form is detected */
  hasPaymentForm: boolean;
  /** Extraction time in ms (for monitoring) */
  extractionTimeMs: number;
}

/**
 * Tags to include in skeleton (structural elements).
 * Excludes script, style, svg, canvas, etc.
 */
const _STRUCTURAL_TAGS = new Set([
  'html', 'head', 'body',
  'header', 'footer', 'main', 'nav', 'aside', 'section', 'article',
  'div', 'span', 'p', 'a',
  'form', 'input', 'button', 'select', 'textarea', 'label', 'fieldset', 'legend',
  'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td',
  'ul', 'ol', 'li', 'dl', 'dt', 'dd',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'iframe',
]);

/**
 * Tags to skip entirely (including children).
 */
const SKIP_TAGS = new Set([
  'script', 'style', 'noscript', 'template',
  'svg', 'canvas', 'video', 'audio',
  'img', 'picture', 'source',
]);

/**
 * Input types that indicate login forms.
 */
const LOGIN_INPUT_TYPES = new Set(['password', 'email']);

/**
 * Input types/names that indicate payment forms.
 */
const PAYMENT_INDICATORS = new Set([
  'card', 'credit', 'cvv', 'cvc', 'expiry', 'expire',
  'cardnumber', 'card-number', 'cc-number', 'ccnum',
]);

/**
 * Extract DOM skeleton from a document.
 * Deterministic - same DOM structure produces identical output.
 *
 * @param doc - Document to extract from
 * @returns DOMSkeleton structure
 */
export function extractSkeleton(doc: Document): DOMSkeleton {
  const startTime = performance.now();

  const inputTypes = new Set<string>();
  const actionUrls = new Set<string>();
  let formCount = 0;
  let hasLoginForm = false;
  let hasPaymentForm = false;

  // Extract tag tree (deterministic serialization)
  const tagTree = serializeNode(doc.documentElement, inputTypes);

  // Count forms and extract action URLs
  const forms = Array.from(doc.querySelectorAll('form'));
  formCount = forms.length;

  for (const form of forms) {
    // Extract action URL (normalized)
    const action = form.getAttribute('action');
    if (action) {
      try {
        // If action is already a path (starts with /), use it directly
        if (action.startsWith('/')) {
          actionUrls.add(action.split('?')[0].split('#')[0]);
        } else if (action.startsWith('http://') || action.startsWith('https://')) {
          // Absolute URL - extract path only
          const url = new URL(action);
          actionUrls.add(url.pathname);
        } else {
          // Relative URL - try to normalize with baseURI
          const baseUri = doc.baseURI || 'http://example.com';
          const url = new URL(action, baseUri);
          actionUrls.add(url.pathname);
        }
      } catch {
        // Invalid URL, skip
      }
    }

    // Check for login form indicators
    const inputs = Array.from(form.querySelectorAll('input'));
    for (const input of inputs) {
      const type = (input.getAttribute('type') || 'text').toLowerCase();
      const name = (input.getAttribute('name') || '').toLowerCase();

      if (LOGIN_INPUT_TYPES.has(type)) {
        hasLoginForm = true;
      }

      // Check for payment indicators in type or name
      for (const indicator of PAYMENT_INDICATORS) {
        if (name.includes(indicator) || type.includes(indicator)) {
          hasPaymentForm = true;
          break;
        }
      }
    }
  }

  const extractionTimeMs = performance.now() - startTime;

  return {
    tagTree,
    formCount,
    inputTypes: Array.from(inputTypes).sort(),
    actionUrls: Array.from(actionUrls).sort(),
    hasLoginForm,
    hasPaymentForm,
    extractionTimeMs,
  };
}

/**
 * Serialize a DOM node to a deterministic string representation.
 * Only captures structure, not content.
 *
 * Format: tagName[attrs]>children
 * Children are sorted for determinism.
 *
 * @param node - Node to serialize
 * @param inputTypes - Set to collect input types
 * @returns Serialized string
 */
function serializeNode(node: Element | null, inputTypes: Set<string>): string {
  if (!node) return '';

  const tagName = node.tagName.toLowerCase();

  // Skip non-structural tags entirely
  if (SKIP_TAGS.has(tagName)) {
    return '';
  }

  // Build attribute string (only structural attributes)
  const attrs = getStructuralAttrs(node, inputTypes);
  const attrStr = attrs.length > 0 ? `[${attrs.join(',')}]` : '';

  // Recursively process children
  const childStrings: string[] = [];
  const children = Array.from(node.children);

  for (const child of children) {
    const childStr = serializeNode(child, inputTypes);
    if (childStr) {
      childStrings.push(childStr);
    }
  }

  // Sort children for determinism (same structure = same output)
  childStrings.sort();

  // Build result
  if (childStrings.length === 0) {
    return `${tagName}${attrStr}`;
  }

  return `${tagName}${attrStr}(${childStrings.join(',')})`;
}

/**
 * Get structural attributes from an element.
 * Only includes attributes relevant for fingerprinting.
 *
 * @param element - Element to extract attributes from
 * @param inputTypes - Set to collect input types
 * @returns Array of attribute strings (sorted)
 */
function getStructuralAttrs(element: Element, inputTypes: Set<string>): string[] {
  const attrs: string[] = [];
  const tagName = element.tagName.toLowerCase();

  // For input elements, capture type
  if (tagName === 'input') {
    const type = (element.getAttribute('type') || 'text').toLowerCase();
    attrs.push(`type=${type}`);
    inputTypes.add(type);
  }

  // For button elements, capture type
  if (tagName === 'button') {
    const type = (element.getAttribute('type') || 'submit').toLowerCase();
    attrs.push(`type=${type}`);
  }

  // For form elements, capture method
  if (tagName === 'form') {
    const method = (element.getAttribute('method') || 'get').toLowerCase();
    attrs.push(`method=${method}`);
  }

  // For links, capture if external (different origin)
  if (tagName === 'a') {
    const href = element.getAttribute('href');
    if (href) {
      try {
        const url = new URL(href, document.baseURI);
        if (url.origin !== window.location.origin) {
          attrs.push('external');
        }
      } catch {
        // Invalid URL, skip
      }
    }
  }

  // For iframes, note their presence
  if (tagName === 'iframe') {
    const src = element.getAttribute('src');
    if (src) {
      attrs.push('has-src');
    }
  }

  return attrs.sort();
}

/**
 * Check if we're in the main frame (not an iframe).
 */
export function isMainFrame(): boolean {
  try {
    return window.self === window.top;
  } catch {
    // Cross-origin iframe - not main frame
    return false;
  }
}

/**
 * Check if the document appears to be HTML (not XML, SVG, etc.).
 */
export function isHtmlDocument(doc: Document): boolean {
  return doc.contentType === 'text/html' ||
         doc.contentType?.startsWith('text/html') ||
         doc.documentElement?.tagName.toLowerCase() === 'html';
}
