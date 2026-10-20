/**
 * DOM Skeleton Extraction Tests
 *
 * Tests for deterministic DOM structure capture.
 * Issue #162: P0 - DOM Skeleton Extraction
 *
 * Key requirements:
 * - Captures tag topology, form structure, input types
 * - Excludes text, images, styles, values
 * - Deterministic serialization
 * - Executes in <10ms on typical pages
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  extractSkeleton,
  isMainFrame,
  isHtmlDocument,
  type DOMSkeleton,
} from '../src/content/dom-skeleton';

/**
 * Create a JSDOM document from HTML string.
 */
function createDocument(html: string): Document {
  const dom = new JSDOM(html, { contentType: 'text/html' });
  return dom.window.document;
}

describe('DOM Skeleton Extraction', () => {
  describe('extractSkeleton', () => {
    it('should extract basic structure', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <head><title>Test</title></head>
          <body>
            <div>
              <p>Some text</p>
            </div>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.tagTree).toContain('html');
      expect(skeleton.tagTree).toContain('head');
      expect(skeleton.tagTree).toContain('body');
      expect(skeleton.tagTree).toContain('div');
      expect(skeleton.tagTree).toContain('p');
    });

    it('should capture form count', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <form id="login"></form>
            <form id="search"></form>
            <form id="contact"></form>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.formCount).toBe(3);
    });

    it('should capture input types', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <form>
              <input type="email" name="email">
              <input type="password" name="pass">
              <input type="text" name="name">
              <input type="submit" value="Login">
            </form>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.inputTypes).toContain('email');
      expect(skeleton.inputTypes).toContain('password');
      expect(skeleton.inputTypes).toContain('text');
      expect(skeleton.inputTypes).toContain('submit');
      // Input types should be sorted
      expect(skeleton.inputTypes).toEqual(['email', 'password', 'submit', 'text']);
    });

    it('should detect login form', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <form>
              <input type="email" name="email">
              <input type="password" name="pass">
              <button type="submit">Login</button>
            </form>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.hasLoginForm).toBe(true);
    });

    it('should not detect login form without password', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <form>
              <input type="text" name="search">
              <button type="submit">Search</button>
            </form>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.hasLoginForm).toBe(false);
    });

    it('should detect payment form by input name', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <form>
              <input type="text" name="cardnumber">
              <input type="text" name="cvv">
              <input type="text" name="expiry">
            </form>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.hasPaymentForm).toBe(true);
    });

    it('should extract form action URLs', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <form action="/login">
            </form>
            <form action="/api/submit">
            </form>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.actionUrls).toContain('/login');
      expect(skeleton.actionUrls).toContain('/api/submit');
    });

    it('should exclude script and style tags', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <head>
            <script>alert('xss')</script>
            <style>.red { color: red; }</style>
          </head>
          <body>
            <div>Content</div>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.tagTree).not.toContain('script');
      expect(skeleton.tagTree).not.toContain('style');
      expect(skeleton.tagTree).not.toContain('alert');
      expect(skeleton.tagTree).not.toContain('.red');
    });

    it('should exclude image tags', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <img src="logo.png" alt="Logo">
            <picture>
              <source srcset="logo.webp">
              <img src="logo.png">
            </picture>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.tagTree).not.toContain('img');
      expect(skeleton.tagTree).not.toContain('picture');
      expect(skeleton.tagTree).not.toContain('source');
    });

    it('should not capture text content', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <h1>Secret Password: hunter2</h1>
            <p>User data: john@example.com</p>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.tagTree).not.toContain('Secret');
      expect(skeleton.tagTree).not.toContain('Password');
      expect(skeleton.tagTree).not.toContain('hunter2');
      expect(skeleton.tagTree).not.toContain('john@example.com');
    });

    it('should not capture input values', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <form>
              <input type="text" value="sensitive data">
              <input type="password" value="my-password">
            </form>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.tagTree).not.toContain('sensitive');
      expect(skeleton.tagTree).not.toContain('my-password');
    });

    it('should record extraction time', () => {
      const doc = createDocument(`<!DOCTYPE html><html><body></body></html>`);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.extractionTimeMs).toBeGreaterThanOrEqual(0);
      expect(skeleton.extractionTimeMs).toBeLessThan(100); // Should be fast
    });
  });

  describe('Determinism', () => {
    it('should produce identical output for identical DOM', () => {
      const html = `
        <!DOCTYPE html>
        <html>
          <body>
            <form>
              <input type="email">
              <input type="password">
            </form>
          </body>
        </html>
      `;

      const doc1 = createDocument(html);
      const doc2 = createDocument(html);

      const skeleton1 = extractSkeleton(doc1);
      const skeleton2 = extractSkeleton(doc2);

      expect(skeleton1.tagTree).toBe(skeleton2.tagTree);
      expect(skeleton1.inputTypes).toEqual(skeleton2.inputTypes);
    });

    it('should produce same output regardless of sibling order', () => {
      // Elements in different order should produce same sorted output
      const html1 = `
        <!DOCTYPE html>
        <html>
          <body>
            <div id="a"></div>
            <div id="b"></div>
          </body>
        </html>
      `;

      const html2 = `
        <!DOCTYPE html>
        <html>
          <body>
            <div id="b"></div>
            <div id="a"></div>
          </body>
        </html>
      `;

      const doc1 = createDocument(html1);
      const doc2 = createDocument(html2);

      const skeleton1 = extractSkeleton(doc1);
      const skeleton2 = extractSkeleton(doc2);

      // Tag trees should be identical (siblings are sorted)
      expect(skeleton1.tagTree).toBe(skeleton2.tagTree);
    });
  });

  describe('Performance', () => {
    it('should extract simple page in <10ms', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <head><title>Simple</title></head>
          <body>
            <div><p>Content</p></div>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.extractionTimeMs).toBeLessThan(10);
    });

    it('should extract form-heavy page in <10ms', () => {
      // Create a page with multiple forms
      let formsHtml = '';
      for (let i = 0; i < 10; i++) {
        formsHtml += `
          <form id="form${i}">
            <input type="text" name="field1">
            <input type="email" name="email">
            <input type="password" name="pass">
            <button type="submit">Submit</button>
          </form>
        `;
      }

      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>${formsHtml}</body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.extractionTimeMs).toBeLessThan(10);
      expect(skeleton.formCount).toBe(10);
    });

    it('should extract nested structure in <10ms', () => {
      // Create deeply nested structure
      let nestedHtml = '<div>';
      for (let i = 0; i < 50; i++) {
        nestedHtml += '<div>';
      }
      nestedHtml += 'deep content';
      for (let i = 0; i < 50; i++) {
        nestedHtml += '</div>';
      }
      nestedHtml += '</div>';

      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>${nestedHtml}</body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.extractionTimeMs).toBeLessThan(10);
    });

    it('should extract wide structure in <10ms', () => {
      // Create wide structure (many siblings)
      let wideHtml = '';
      for (let i = 0; i < 100; i++) {
        wideHtml += `<div><span>Item ${i}</span></div>`;
      }

      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>${wideHtml}</body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.extractionTimeMs).toBeLessThan(10);
    });
  });

  describe('Phishing Kit Detection', () => {
    it('should capture Microsoft login page structure', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <div>
              <form action="/login">
                <input type="email" name="loginfmt" placeholder="Email">
                <input type="password" name="passwd" placeholder="Password">
                <button type="submit">Sign in</button>
              </form>
            </div>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.hasLoginForm).toBe(true);
      expect(skeleton.inputTypes).toContain('email');
      expect(skeleton.inputTypes).toContain('password');
      expect(skeleton.formCount).toBe(1);
    });

    it('should capture PayPal checkout structure', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <form action="/checkout">
              <input type="text" name="card-number">
              <input type="text" name="expiry">
              <input type="text" name="cvv">
              <input type="text" name="billing-address">
              <button type="submit">Pay Now</button>
            </form>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.hasPaymentForm).toBe(true);
      expect(skeleton.actionUrls).toContain('/checkout');
    });

    it('should capture multi-step phishing flow', () => {
      const doc = createDocument(`
        <!DOCTYPE html>
        <html>
          <body>
            <div id="step1">
              <form action="/step1">
                <input type="email" name="email">
                <button>Next</button>
              </form>
            </div>
            <div id="step2">
              <form action="/step2">
                <input type="password" name="password">
                <button>Login</button>
              </form>
            </div>
          </body>
        </html>
      `);

      const skeleton = extractSkeleton(doc);

      expect(skeleton.formCount).toBe(2);
      expect(skeleton.hasLoginForm).toBe(true);
      expect(skeleton.actionUrls).toContain('/step1');
      expect(skeleton.actionUrls).toContain('/step2');
    });
  });

  describe('isHtmlDocument', () => {
    it('should return true for text/html content type', () => {
      const doc = createDocument('<!DOCTYPE html><html></html>');
      expect(isHtmlDocument(doc)).toBe(true);
    });

    it('should return true for html root element', () => {
      const dom = new JSDOM('<html></html>');
      expect(isHtmlDocument(dom.window.document)).toBe(true);
    });
  });
});

describe('Structural Fingerprinting', () => {
  it('same structure with different content produces same skeleton', () => {
    // Two phishing pages targeting the same brand
    // Different text but same structure
    const kit1 = createDocument(`
      <!DOCTYPE html>
      <html>
        <body>
          <div class="container">
            <h1>Sign in to Microsoft</h1>
            <form action="/login1">
              <input type="email" placeholder="Email">
              <input type="password" placeholder="Password">
              <button>Sign in</button>
            </form>
          </div>
        </body>
      </html>
    `);

    const kit2 = createDocument(`
      <!DOCTYPE html>
      <html>
        <body>
          <div class="wrapper">
            <h1>Login to Your Account</h1>
            <form action="/login2">
              <input type="email" placeholder="Enter email">
              <input type="password" placeholder="Enter password">
              <button>Log in</button>
            </form>
          </div>
        </body>
      </html>
    `);

    const skeleton1 = extractSkeleton(kit1);
    const skeleton2 = extractSkeleton(kit2);

    // Structure should be identical (excluding action URLs which may vary)
    expect(skeleton1.tagTree).toBe(skeleton2.tagTree);
    expect(skeleton1.inputTypes).toEqual(skeleton2.inputTypes);
    expect(skeleton1.hasLoginForm).toBe(skeleton2.hasLoginForm);
  });
});
