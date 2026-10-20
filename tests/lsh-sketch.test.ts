/**
 * Tests for LSH Sketch Generation (Issue #200)
 *
 * Verifies:
 * - MinHash algorithm correctness
 * - Sketch determinism (same input = same output)
 * - Similarity preservation (similar DOMs = similar sketches)
 * - Privacy guarantees (no content/URLs in sketches)
 */

import { describe, it, expect } from 'vitest';
import {
  generateAllSketches,
  extractScriptInfo,
  estimateSimilarity,
  type LSHSketches,
  _hashString,
  _minHash,
  _extractShingles,
  _extractDOMLayoutShingles,
  _extractFormStructureShingles,
  _extractScriptStructureShingles,
  _NUM_HASHES,
} from '../src/content/lsh-sketch';
import type { DOMSkeleton } from '../src/content/dom-skeleton';
import type { FormSchema } from '../src/content/form-schema';

// ============ Test Helpers ============

function createMockSkeleton(overrides: Partial<DOMSkeleton> = {}): DOMSkeleton {
  return {
    tagTree: 'html(head,body(div(form[method=post](input[type=email],input[type=password],button[type=submit]))))',
    formCount: 1,
    inputTypes: ['email', 'password'],
    actionUrls: ['/login'],
    hasLoginForm: true,
    hasPaymentForm: false,
    extractionTimeMs: 5,
    ...overrides,
  };
}

function createMockFormSchema(overrides: Partial<FormSchema> = {}): FormSchema {
  return {
    method: 'POST',
    fieldCount: 2,
    fields: [
      { tag: 'input', type: 'email', name: 'email', required: true },
      { tag: 'input', type: 'password', name: 'password', required: true },
    ],
    isLoginForm: true,
    isPaymentForm: false,
    ...overrides,
  };
}

// ============ Tests ============

describe('LSH Sketch Generation', () => {
  describe('Hash Function', () => {
    it('should produce consistent hash for same string', () => {
      const str = 'test-string';
      const hash1 = _hashString(str);
      const hash2 = _hashString(str);
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different strings', () => {
      const hash1 = _hashString('string-a');
      const hash2 = _hashString('string-b');
      expect(hash1).not.toBe(hash2);
    });

    it('should return positive integers', () => {
      const hash = _hashString('test');
      expect(hash).toBeGreaterThan(0);
      expect(Number.isInteger(hash)).toBe(true);
    });
  });

  describe('Shingle Extraction', () => {
    it('should extract character n-grams', () => {
      const shingles = _extractShingles('hello', 3);
      expect(shingles.has('hel')).toBe(true);
      expect(shingles.has('ell')).toBe(true);
      expect(shingles.has('llo')).toBe(true);
    });

    it('should handle strings shorter than n', () => {
      const shingles = _extractShingles('ab', 3);
      expect(shingles.size).toBe(1);
      expect(shingles.has('ab')).toBe(true);
    });

    it('should handle empty strings', () => {
      const shingles = _extractShingles('', 3);
      expect(shingles.size).toBe(0);
    });
  });

  describe('MinHash', () => {
    it('should produce signature of correct length', () => {
      const shingles = new Set(['a', 'b', 'c']);
      const signature = _minHash(shingles);
      expect(signature.length).toBe(_NUM_HASHES);
    });

    it('should produce consistent signature for same input', () => {
      const shingles = new Set(['hello', 'world', 'test']);
      const sig1 = _minHash(shingles);
      const sig2 = _minHash(shingles);
      expect(sig1).toEqual(sig2);
    });

    it('should handle empty sets', () => {
      const shingles = new Set<string>();
      const signature = _minHash(shingles);
      expect(signature.length).toBe(_NUM_HASHES);
      expect(signature.every(v => v === 0)).toBe(true);
    });

    it('should produce similar signatures for similar sets', () => {
      // Two sets with high overlap
      const set1 = new Set(['a', 'b', 'c', 'd', 'e']);
      const set2 = new Set(['a', 'b', 'c', 'd', 'f']); // 4/6 = 0.67 Jaccard

      const sig1 = _minHash(set1);
      const sig2 = _minHash(set2);

      // Count matching positions
      let matches = 0;
      for (let i = 0; i < _NUM_HASHES; i++) {
        if (sig1[i] === sig2[i]) matches++;
      }

      // Estimated similarity should be reasonably close to actual
      const estimated = matches / _NUM_HASHES;
      expect(estimated).toBeGreaterThan(0.3); // Should show significant similarity
    });
  });

  describe('DOM Layout Shingles', () => {
    it('should extract tag names', () => {
      const shingles = _extractDOMLayoutShingles('html(body(div))');
      expect(shingles.has('html')).toBe(true);
      expect(shingles.has('body')).toBe(true);
      expect(shingles.has('div')).toBe(true);
    });

    it('should extract tags with attributes', () => {
      const shingles = _extractDOMLayoutShingles('form[method=post](input[type=email])');
      expect(shingles.has('form[method=post]')).toBe(true);
      expect(shingles.has('input[type=email]')).toBe(true);
    });

    it('should extract parent-child patterns', () => {
      const shingles = _extractDOMLayoutShingles('div(form(input))');
      expect(shingles.has('div>form')).toBe(true);
      // Nested patterns are captured via n-grams, not the simple parent-child regex
      // The n-gram pattern 'ng:m(i' captures the form->input relationship
      expect(shingles.has('ng:m(i')).toBe(true);
    });
  });

  describe('Form Structure Shingles', () => {
    it('should extract form method', () => {
      const forms = [createMockFormSchema({ method: 'POST' })];
      const shingles = _extractFormStructureShingles(forms);
      expect(shingles.has('method:post')).toBe(true);
    });

    it('should extract login form indicator', () => {
      const forms = [createMockFormSchema({ isLoginForm: true })];
      const shingles = _extractFormStructureShingles(forms);
      expect(shingles.has('is-login-form')).toBe(true);
    });

    it('should extract payment form indicator', () => {
      const forms = [createMockFormSchema({ isPaymentForm: true, isLoginForm: false })];
      const shingles = _extractFormStructureShingles(forms);
      expect(shingles.has('is-payment-form')).toBe(true);
    });

    it('should handle empty form list', () => {
      const shingles = _extractFormStructureShingles([]);
      expect(shingles.has('no-forms')).toBe(true);
    });

    it('should extract field types', () => {
      const forms = [createMockFormSchema()];
      const shingles = _extractFormStructureShingles(forms);
      expect(shingles.has('type:email')).toBe(true);
      expect(shingles.has('type:password')).toBe(true);
    });
  });

  describe('Script Structure Shingles', () => {
    it('should extract script count bucket', () => {
      const shingles = _extractScriptStructureShingles(
        ['/js/app.js', '/js/vendor.js', '/js/utils.js'],
        []
      );
      expect(shingles.has('script-bucket:1')).toBe(true); // 3 scripts = bucket 1
    });

    it('should extract link count bucket', () => {
      const shingles = _extractScriptStructureShingles(
        [],
        ['/css/style.css', '/css/theme.css']
      );
      expect(shingles.has('link-bucket:0')).toBe(true); // 2 links = bucket 0
    });

    it('should handle empty resources', () => {
      const shingles = _extractScriptStructureShingles([], []);
      expect(shingles.has('no-resources')).toBe(true);
    });

    it('should extract relative path indicator', () => {
      const shingles = _extractScriptStructureShingles(['/js/app.js'], []);
      expect(shingles.has('script:rel-path')).toBe(true);
    });

    it('should extract file extension', () => {
      const shingles = _extractScriptStructureShingles(['/js/app.js'], ['/css/style.css']);
      expect(shingles.has('script:ext-js')).toBe(true);
      expect(shingles.has('link:ext-css')).toBe(true);
    });
  });

  describe('generateAllSketches', () => {
    it('should generate all three sketch types', () => {
      const skeleton = createMockSkeleton();
      const sketches = generateAllSketches(skeleton);

      expect(sketches.dom_layout_lsh).toBeDefined();
      expect(sketches.form_structure_lsh).toBeDefined();
      expect(sketches.script_structure_lsh).toBeDefined();
    });

    it('should produce 512-character hex strings (64 * 8)', () => {
      const skeleton = createMockSkeleton();
      const sketches = generateAllSketches(skeleton);

      expect(sketches.dom_layout_lsh.length).toBe(512);
      expect(sketches.form_structure_lsh.length).toBe(512);
      expect(sketches.script_structure_lsh.length).toBe(512);

      // Verify hex format
      expect(sketches.dom_layout_lsh).toMatch(/^[a-f0-9]{512}$/);
    });

    it('should be deterministic', () => {
      const skeleton = createMockSkeleton();
      const formSchemas = [createMockFormSchema()];
      const scriptInfo = { scriptSrcs: ['/js/app.js'], linkHrefs: ['/css/style.css'] };

      const sketches1 = generateAllSketches(skeleton, formSchemas, scriptInfo);
      const sketches2 = generateAllSketches(skeleton, formSchemas, scriptInfo);

      expect(sketches1.dom_layout_lsh).toBe(sketches2.dom_layout_lsh);
      expect(sketches1.form_structure_lsh).toBe(sketches2.form_structure_lsh);
      expect(sketches1.script_structure_lsh).toBe(sketches2.script_structure_lsh);
    });

    it('should track generation time', () => {
      const skeleton = createMockSkeleton();
      const sketches = generateAllSketches(skeleton);

      expect(sketches.generationTimeMs).toBeGreaterThanOrEqual(0);
      expect(sketches.generationTimeMs).toBeLessThan(100); // Should be fast
    });
  });

  describe('estimateSimilarity', () => {
    it('should return 1.0 for identical signatures', () => {
      const skeleton = createMockSkeleton();
      const sketches = generateAllSketches(skeleton);

      const similarity = estimateSimilarity(
        sketches.dom_layout_lsh,
        sketches.dom_layout_lsh
      );

      expect(similarity).toBe(1.0);
    });

    it('should return value between 0 and 1', () => {
      const skeleton1 = createMockSkeleton({ tagTree: 'html(body(div(a,b,c)))' });
      const skeleton2 = createMockSkeleton({ tagTree: 'html(body(div(x,y,z)))' });

      const sketches1 = generateAllSketches(skeleton1);
      const sketches2 = generateAllSketches(skeleton2);

      const similarity = estimateSimilarity(
        sketches1.dom_layout_lsh,
        sketches2.dom_layout_lsh
      );

      expect(similarity).toBeGreaterThanOrEqual(0);
      expect(similarity).toBeLessThanOrEqual(1);
    });

    it('should show higher similarity for similar structures', () => {
      // Two similar login forms
      const skeleton1 = createMockSkeleton({
        tagTree: 'html(body(div(form[method=post](input[type=email],input[type=password],button[type=submit]))))',
      });
      const skeleton2 = createMockSkeleton({
        tagTree: 'html(body(div(form[method=post](input[type=email],input[type=password],input[type=submit]))))',
      });

      // Completely different structure
      const skeleton3 = createMockSkeleton({
        tagTree: 'html(body(article(h1,p,p,p,footer)))',
      });

      const sketches1 = generateAllSketches(skeleton1);
      const sketches2 = generateAllSketches(skeleton2);
      const sketches3 = generateAllSketches(skeleton3);

      const simSimilar = estimateSimilarity(sketches1.dom_layout_lsh, sketches2.dom_layout_lsh);
      const simDifferent = estimateSimilarity(sketches1.dom_layout_lsh, sketches3.dom_layout_lsh);

      // Similar structures should have higher similarity than different ones
      expect(simSimilar).toBeGreaterThan(simDifferent);
    });

    it('should throw for invalid signature length', () => {
      expect(() => estimateSimilarity('abc', '123')).toThrow('Invalid signature length');
    });
  });

  describe('Similarity Preservation', () => {
    it('should produce similar sketches for variant phishing pages', () => {
      // Simulating two variants of the same phishing kit
      const variant1 = createMockSkeleton({
        tagTree: 'html(body(div(form[method=post](div(input[type=email]),div(input[type=password]),button[type=submit]))))',
      });
      const variant2 = createMockSkeleton({
        tagTree: 'html(body(div(form[method=post](span(input[type=email]),span(input[type=password]),button[type=submit]))))',
      });

      // Completely different page
      const differentPage = createMockSkeleton({
        tagTree: 'html(body(nav,main(article(h1,p,p,p)),footer))',
        hasLoginForm: false,
      });

      const sketches1 = generateAllSketches(variant1);
      const sketches2 = generateAllSketches(variant2);
      const sketchesDiff = generateAllSketches(differentPage);

      const simVariants = estimateSimilarity(sketches1.dom_layout_lsh, sketches2.dom_layout_lsh);
      const simDifferent = estimateSimilarity(sketches1.dom_layout_lsh, sketchesDiff.dom_layout_lsh);

      // Variants should be more similar than completely different pages
      expect(simVariants).toBeGreaterThan(simDifferent);
    });

    it('should produce similar form sketches for login form variants', () => {
      const form1 = [createMockFormSchema({
        fields: [
          { tag: 'input', type: 'email', name: 'email', required: true },
          { tag: 'input', type: 'password', name: 'password', required: true },
        ],
        isLoginForm: true,
      })];

      const form2 = [createMockFormSchema({
        fields: [
          { tag: 'input', type: 'text', name: 'username', required: true, autocomplete: 'username' },
          { tag: 'input', type: 'password', name: 'pwd', required: true },
        ],
        isLoginForm: true,
      })];

      const paymentForm = [createMockFormSchema({
        fields: [
          { tag: 'input', type: 'text', name: 'card_number', required: true },
          { tag: 'input', type: 'text', name: 'cvv', required: true },
        ],
        isLoginForm: false,
        isPaymentForm: true,
      })];

      const skeleton = createMockSkeleton();
      const sketches1 = generateAllSketches(skeleton, form1);
      const sketches2 = generateAllSketches(skeleton, form2);
      const sketchesPayment = generateAllSketches(skeleton, paymentForm);

      const simLogins = estimateSimilarity(sketches1.form_structure_lsh, sketches2.form_structure_lsh);
      const simDifferent = estimateSimilarity(sketches1.form_structure_lsh, sketchesPayment.form_structure_lsh);

      // Two login forms should be more similar than login vs payment
      expect(simLogins).toBeGreaterThan(simDifferent);
    });
  });

  describe('Privacy Guarantees', () => {
    it('should not contain URLs in sketches', () => {
      const skeleton = createMockSkeleton({
        actionUrls: ['https://evil.com/steal-credentials'],
      });
      const formSchemas = [createMockFormSchema({
        action: 'https://phishing.com/login',
      })];
      const scriptInfo = {
        scriptSrcs: ['https://cdn.attacker.com/malicious.js'],
        linkHrefs: ['https://phishing.com/fake-bank.css'],
      };

      const sketches = generateAllSketches(skeleton, formSchemas, scriptInfo);

      // Convert to string for searching
      const allSketches = JSON.stringify(sketches);

      // Should not contain any URLs or domains
      expect(allSketches).not.toContain('evil.com');
      expect(allSketches).not.toContain('phishing.com');
      expect(allSketches).not.toContain('attacker.com');
      expect(allSketches).not.toContain('http');
    });

    it('should not contain form field values', () => {
      const skeleton = createMockSkeleton();
      const formSchemas = [createMockFormSchema({
        fields: [
          { tag: 'input', type: 'email', name: 'email', required: true },
          { tag: 'input', type: 'password', name: 'password', required: true },
        ],
      })];

      const sketches = generateAllSketches(skeleton, formSchemas);

      // Sketches are hex strings - they should not contain readable text
      expect(sketches.form_structure_lsh).toMatch(/^[a-f0-9]+$/);
    });

    it('should produce non-reversible signatures', () => {
      // MinHash signatures cannot be reversed to recover original data
      const skeleton = createMockSkeleton({
        tagTree: 'html(body(div(secret-content)))',
      });

      const sketches = generateAllSketches(skeleton);

      // Verify it's a hex hash, not original content
      expect(sketches.dom_layout_lsh).not.toContain('secret');
      expect(sketches.dom_layout_lsh).toMatch(/^[a-f0-9]{512}$/);
    });
  });

  /**
   * Issue #200: DOM Structural Similarity Sketches (LSH)
   *
   * These tests verify the acceptance criteria:
   * - Generate LSH sketches from DOM skeleton
   * - Three sketch types: dom_layout_lsh, form_structure_lsh, script_structure_lsh
   * - Shadow mode only (no enforcement)
   * - Privacy-preserving (non-reversible, structure-only)
   */
  describe('Issue #200 Acceptance Criteria', () => {
    it('should generate three distinct LSH sketch types', () => {
      const skeleton = createMockSkeleton();
      const formSchemas = [createMockFormSchema()];
      const scriptInfo = { scriptSrcs: ['/js/app.js'], linkHrefs: ['/css/style.css'] };

      const sketches = generateAllSketches(skeleton, formSchemas, scriptInfo);

      // All three types must be present
      expect(sketches.dom_layout_lsh).toBeDefined();
      expect(sketches.form_structure_lsh).toBeDefined();
      expect(sketches.script_structure_lsh).toBeDefined();

      // They should be different (different inputs = different sketches)
      expect(sketches.dom_layout_lsh).not.toBe(sketches.form_structure_lsh);
      expect(sketches.form_structure_lsh).not.toBe(sketches.script_structure_lsh);
    });

    it('should work for pages without forms', () => {
      const skeleton = createMockSkeleton({
        tagTree: 'html(body(article(h1,p,p,p)))',
        formCount: 0,
        hasLoginForm: false,
        hasPaymentForm: false,
      });

      const sketches = generateAllSketches(skeleton, []);

      // Should still produce valid sketches
      expect(sketches.dom_layout_lsh).toMatch(/^[a-f0-9]{512}$/);
      expect(sketches.form_structure_lsh).toMatch(/^[a-f0-9]{512}$/);
      expect(sketches.script_structure_lsh).toMatch(/^[a-f0-9]{512}$/);
    });

    it('should work for pages without scripts', () => {
      const skeleton = createMockSkeleton();
      const formSchemas = [createMockFormSchema()];

      const sketches = generateAllSketches(skeleton, formSchemas, {
        scriptSrcs: [],
        linkHrefs: [],
      });

      // Should still produce valid sketches
      expect(sketches.script_structure_lsh).toMatch(/^[a-f0-9]{512}$/);
    });

    it('should enable kit variant discovery through similarity', () => {
      // Simulating multiple variants of a phishing kit
      const baseKit = {
        tagTree: 'html(body(div(form[method=post](input[type=email],input[type=password],button[type=submit]))))',
        hasLoginForm: true,
      };

      const variant1 = createMockSkeleton({
        ...baseKit,
        tagTree: baseKit.tagTree.replace('div', 'section'),
      });

      const variant2 = createMockSkeleton({
        ...baseKit,
        tagTree: baseKit.tagTree.replace('button', 'input'),
      });

      const sketches1 = generateAllSketches(variant1);
      const sketches2 = generateAllSketches(variant2);

      const similarity = estimateSimilarity(
        sketches1.dom_layout_lsh,
        sketches2.dom_layout_lsh
      );

      // Kit variants should have measurable similarity
      expect(similarity).toBeGreaterThan(0.2);
    });
  });
});
