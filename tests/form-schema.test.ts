/**
 * Tests for form schema extraction.
 *
 * Verifies:
 * - Correct field extraction
 * - Login form detection
 * - Payment form detection
 * - Privacy guarantees (no values captured)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  extractFormSchemas,
  extractFormSchema,
  hasSensitiveForms,
  type FormSchema,
  type FormFieldSchema,
} from '../src/content/form-schema';

describe('Form Schema Extraction', () => {
  let dom: JSDOM;
  let document: Document;

  beforeEach(() => {
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'https://example.com/page',
    });
    document = dom.window.document;
  });

  describe('extractFormSchema', () => {
    it('extracts basic form metadata', () => {
      document.body.innerHTML = `
        <form id="test-form" name="testForm" action="/submit" method="POST">
          <input type="text" name="username" />
          <input type="password" name="password" />
          <button type="submit">Submit</button>
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com/page');

      expect(schema.id).toBe('test-form');
      expect(schema.name).toBe('testForm');
      expect(schema.action).toBe('https://example.com/submit');
      expect(schema.method).toBe('POST');
      expect(schema.fieldCount).toBe(2); // Excludes submit button
    });

    it('resolves relative action URLs', () => {
      document.body.innerHTML = `
        <form action="../api/login" method="POST">
          <input type="text" name="email" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com/auth/page');

      expect(schema.action).toBe('https://example.com/api/login');
    });

    it('handles forms without action', () => {
      document.body.innerHTML = `
        <form method="POST">
          <input type="text" name="search" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com/page');

      expect(schema.action).toBeUndefined();
    });

    it('defaults method to GET', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="q" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com/page');

      expect(schema.method).toBe('GET');
    });
  });

  describe('Field Extraction', () => {
    it('extracts input field attributes', () => {
      document.body.innerHTML = `
        <form>
          <input
            type="email"
            name="user_email"
            id="email-input"
            required
            autocomplete="email"
            pattern="[a-z]+@[a-z]+\\.[a-z]+"
            maxlength="100"
            minlength="5"
          />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.fields).toHaveLength(1);
      const field = schema.fields[0];

      expect(field.tag).toBe('input');
      expect(field.type).toBe('email');
      expect(field.name).toBe('user_email');
      expect(field.id).toBe('email-input');
      expect(field.required).toBe(true);
      expect(field.autocomplete).toBe('email');
      expect(field.pattern).toBe('[a-z]+@[a-z]+\\.[a-z]+');
      expect(field.maxLength).toBe(100);
      expect(field.minLength).toBe(5);
    });

    it('extracts select fields', () => {
      document.body.innerHTML = `
        <form>
          <select name="country" id="country-select" required>
            <option value="us">United States</option>
            <option value="uk">United Kingdom</option>
          </select>
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.fields).toHaveLength(1);
      const field = schema.fields[0];

      expect(field.tag).toBe('select');
      expect(field.name).toBe('country');
      expect(field.id).toBe('country-select');
      expect(field.required).toBe(true);
    });

    it('extracts textarea fields', () => {
      document.body.innerHTML = `
        <form>
          <textarea name="message" maxlength="500" minlength="10"></textarea>
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.fields).toHaveLength(1);
      const field = schema.fields[0];

      expect(field.tag).toBe('textarea');
      expect(field.name).toBe('message');
      expect(field.maxLength).toBe(500);
      expect(field.minLength).toBe(10);
    });

    it('skips hidden inputs', () => {
      document.body.innerHTML = `
        <form>
          <input type="hidden" name="csrf_token" value="abc123" />
          <input type="text" name="username" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.fields).toHaveLength(1);
      expect(schema.fields[0].name).toBe('username');
    });

    it('skips submit and button inputs', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="query" />
          <input type="submit" value="Search" />
          <input type="button" value="Cancel" />
          <input type="reset" value="Clear" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.fields).toHaveLength(1);
      expect(schema.fields[0].name).toBe('query');
    });
  });

  describe('Login Form Detection', () => {
    it('detects login form with password and email', () => {
      document.body.innerHTML = `
        <form>
          <input type="email" name="email" />
          <input type="password" name="password" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.isLoginForm).toBe(true);
    });

    it('detects login form with password and username autocomplete', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" autocomplete="username" />
          <input type="password" autocomplete="current-password" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.isLoginForm).toBe(true);
    });

    it('detects login form by field name patterns', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="user_login" />
          <input type="password" name="pass" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.isLoginForm).toBe(true);
    });

    it('does not flag non-login forms', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="search_query" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.isLoginForm).toBe(false);
    });
  });

  describe('Payment Form Detection', () => {
    it('detects payment form by autocomplete', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" autocomplete="cc-number" />
          <input type="text" autocomplete="cc-exp" />
          <input type="text" autocomplete="cc-csc" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.isPaymentForm).toBe(true);
    });

    it('detects payment form by field names', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="card_number" />
          <input type="text" name="cvv" />
          <input type="text" name="expiry_date" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.isPaymentForm).toBe(true);
    });

    it('detects credit card patterns', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="cc_num" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.isPaymentForm).toBe(true);
    });

    it('does not flag non-payment forms', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="shipping_address" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      expect(schema.isPaymentForm).toBe(false);
    });
  });

  describe('extractFormSchemas', () => {
    it('extracts all forms from document', () => {
      document.body.innerHTML = `
        <form id="form1">
          <input type="text" name="field1" />
        </form>
        <form id="form2">
          <input type="email" name="email" />
          <input type="password" name="password" />
        </form>
      `;

      const schemas = extractFormSchemas(document);

      expect(schemas).toHaveLength(2);
      expect(schemas[0].id).toBe('form1');
      expect(schemas[1].id).toBe('form2');
    });

    it('skips empty forms', () => {
      document.body.innerHTML = `
        <form id="empty-form"></form>
        <form id="has-fields">
          <input type="text" name="query" />
        </form>
      `;

      const schemas = extractFormSchemas(document);

      expect(schemas).toHaveLength(1);
      expect(schemas[0].id).toBe('has-fields');
    });

    it('returns empty array for pages without forms', () => {
      document.body.innerHTML = `
        <div>No forms here</div>
      `;

      const schemas = extractFormSchemas(document);

      expect(schemas).toHaveLength(0);
    });
  });

  describe('hasSensitiveForms', () => {
    it('returns true for login forms', () => {
      document.body.innerHTML = `
        <form>
          <input type="email" name="email" />
          <input type="password" name="password" />
        </form>
      `;

      const schemas = extractFormSchemas(document);
      expect(hasSensitiveForms(schemas)).toBe(true);
    });

    it('returns true for payment forms', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="card_number" />
        </form>
      `;

      const schemas = extractFormSchemas(document);
      expect(hasSensitiveForms(schemas)).toBe(true);
    });

    it('returns false for non-sensitive forms', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="search" />
        </form>
      `;

      const schemas = extractFormSchemas(document);
      expect(hasSensitiveForms(schemas)).toBe(false);
    });

    it('returns false for empty schemas', () => {
      expect(hasSensitiveForms([])).toBe(false);
    });
  });

  describe('Privacy Guarantees', () => {
    it('never captures field values', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="username" value="secretuser" />
          <input type="password" name="password" value="secretpass" />
          <textarea name="bio">Secret bio content</textarea>
          <select name="country">
            <option value="us" selected>United States</option>
          </select>
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      // Verify schema structure
      expect(schema.fields).toHaveLength(4);

      // Check that no field has a 'value' property
      for (const field of schema.fields) {
        expect(field).not.toHaveProperty('value');
        expect(field).not.toHaveProperty('defaultValue');
        expect(field).not.toHaveProperty('selectedValue');
      }

      // JSON stringify to catch any hidden properties
      const json = JSON.stringify(schema);
      expect(json).not.toContain('secretuser');
      expect(json).not.toContain('secretpass');
      expect(json).not.toContain('Secret bio');
    });

    it('never captures placeholder text that might contain examples', () => {
      document.body.innerHTML = `
        <form>
          <input type="text" name="ssn" placeholder="123-45-6789" />
          <input type="password" placeholder="Enter your secret" />
        </form>
      `;

      const form = document.querySelector('form') as HTMLFormElement;
      const schema = extractFormSchema(form, 'https://example.com');

      for (const field of schema.fields) {
        expect(field).not.toHaveProperty('placeholder');
      }

      const json = JSON.stringify(schema);
      expect(json).not.toContain('123-45-6789');
      expect(json).not.toContain('secret');
    });
  });
});
