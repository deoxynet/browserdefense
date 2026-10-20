/**
 * Form Schema Extraction for BrowserDefense.
 *
 * Extracts form field structure (metadata only) from pages.
 * Used for forensics on blocked phishing pages.
 *
 * PRIVACY CRITICAL:
 * - NO typed values are captured
 * - NO autofill data is captured
 * - NO keystrokes are captured
 * - Only field names, types, and structural information
 *
 * Reference: Issue #167 - P1: Form Schema Capture
 */

// ============ Types ============

/**
 * Schema for a single form field.
 * Contains structural metadata only - no values.
 */
export interface FormFieldSchema {
  /** Element tag name (input, select, textarea) */
  tag: 'input' | 'select' | 'textarea';
  /** Input type attribute (text, password, email, etc.) */
  type?: string;
  /** Field name attribute */
  name?: string;
  /** Field id attribute */
  id?: string;
  /** Whether the field is required */
  required: boolean;
  /** Autocomplete attribute value */
  autocomplete?: string;
  /** Pattern attribute for validation */
  pattern?: string;
  /** Maximum length constraint */
  maxLength?: number;
  /** Minimum length constraint */
  minLength?: number;
}

/**
 * Schema for an entire form.
 * Contains structural metadata only - no values.
 */
export interface FormSchema {
  /** Form action URL (where data would be submitted) */
  action?: string;
  /** HTTP method (GET, POST, etc.) */
  method: string;
  /** Form id attribute */
  id?: string;
  /** Form name attribute */
  name?: string;
  /** Number of form fields */
  fieldCount: number;
  /** Schema for each field */
  fields: FormFieldSchema[];
  /** Whether this appears to be a login form */
  isLoginForm: boolean;
  /** Whether this appears to be a payment form */
  isPaymentForm: boolean;
}

// ============ Field Detection Patterns ============

/** Input types commonly used for usernames/emails */
const USERNAME_TYPES = ['text', 'email', 'tel'];

/** Autocomplete values indicating username/email fields */
const USERNAME_AUTOCOMPLETE = ['username', 'email', 'tel'];

/** Name/id patterns indicating username/email fields */
const USERNAME_PATTERNS = [
  /user/i,
  /email/i,
  /login/i,
  /account/i,
  /phone/i,
];

/** Autocomplete values indicating payment fields */
const PAYMENT_AUTOCOMPLETE = [
  'cc-name',
  'cc-number',
  'cc-exp',
  'cc-exp-month',
  'cc-exp-year',
  'cc-csc',
  'cc-type',
];

/** Name/id patterns indicating payment fields */
const PAYMENT_PATTERNS = [
  /card/i,
  /credit/i,
  /cc[-_]?num/i,
  /cvv/i,
  /cvc/i,
  /expir/i,
  /ccv/i,
];

// ============ Extraction Functions ============

/**
 * Extract a single field's schema.
 * PRIVACY: Only extracts metadata, never values.
 */
function extractFieldSchema(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
): FormFieldSchema {
  const tagName = element.tagName.toLowerCase();
  const tag = tagName as 'input' | 'select' | 'textarea';

  const schema: FormFieldSchema = {
    tag,
    required: element.required,
  };

  // Extract type for input elements
  if (tagName === 'input') {
    const inputType = (element as HTMLInputElement).type || 'text';
    schema.type = inputType;
  }

  // Extract name and id if present
  if (element.name) {
    schema.name = element.name;
  }
  if (element.id) {
    schema.id = element.id;
  }

  // Extract autocomplete attribute
  const autocomplete = element.getAttribute('autocomplete');
  if (autocomplete) {
    schema.autocomplete = autocomplete;
  }

  // Extract validation attributes for input/textarea
  if (tagName === 'input' || tagName === 'textarea') {
    const pattern = element.getAttribute('pattern');
    if (pattern) {
      schema.pattern = pattern;
    }

    const maxLength = element.getAttribute('maxlength');
    if (maxLength) {
      schema.maxLength = parseInt(maxLength, 10);
    }

    const minLength = element.getAttribute('minlength');
    if (minLength) {
      schema.minLength = parseInt(minLength, 10);
    }
  }

  return schema;
}

/**
 * Check if a field looks like a username/email input.
 */
function isUsernameField(field: FormFieldSchema): boolean {
  // Check autocomplete attribute
  if (field.autocomplete && USERNAME_AUTOCOMPLETE.includes(field.autocomplete)) {
    return true;
  }

  // Check input type
  if (field.type && USERNAME_TYPES.includes(field.type)) {
    // Also check name/id patterns
    const nameOrId = (field.name || '') + (field.id || '');
    if (USERNAME_PATTERNS.some((pattern) => pattern.test(nameOrId))) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a field looks like a password input.
 */
function isPasswordField(field: FormFieldSchema): boolean {
  return field.type === 'password';
}

/**
 * Check if a field looks like a payment field.
 */
function isPaymentField(field: FormFieldSchema): boolean {
  // Check autocomplete attribute
  if (field.autocomplete && PAYMENT_AUTOCOMPLETE.includes(field.autocomplete)) {
    return true;
  }

  // Check name/id patterns
  const nameOrId = (field.name || '') + (field.id || '');
  if (PAYMENT_PATTERNS.some((pattern) => pattern.test(nameOrId))) {
    return true;
  }

  return false;
}

/**
 * Detect if a form appears to be a login form.
 * A login form typically has a password field and a username/email field.
 */
function detectLoginForm(fields: FormFieldSchema[]): boolean {
  const hasPassword = fields.some(isPasswordField);
  const hasUsername = fields.some(isUsernameField);

  // Also check for password autocomplete
  const hasPasswordAutocomplete = fields.some(
    (f) => f.autocomplete === 'current-password' || f.autocomplete === 'new-password'
  );

  return hasPassword && (hasUsername || hasPasswordAutocomplete);
}

/**
 * Detect if a form appears to be a payment form.
 * A payment form has credit card related fields.
 */
function detectPaymentForm(fields: FormFieldSchema[]): boolean {
  return fields.some(isPaymentField);
}

/**
 * Extract schema from a single form element.
 * @param form - The form element to extract from
 * @param baseUrl - Base URL for resolving relative action URLs
 */
export function extractFormSchema(form: HTMLFormElement, baseUrl: string): FormSchema {
  // Get all form fields
  const inputs = form.querySelectorAll('input, select, textarea');
  const fields: FormFieldSchema[] = [];

  inputs.forEach((element) => {
    const tagName = element.tagName.toLowerCase();
    // Skip hidden fields and submit/button inputs
    if (tagName === 'input') {
      const inputType = (element as HTMLInputElement).type;
      if (inputType === 'hidden' || inputType === 'submit' || inputType === 'button' || inputType === 'reset') {
        return;
      }
    }

    fields.push(extractFieldSchema(element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement));
  });

  // Resolve action URL
  let action: string | undefined;
  const rawAction = form.getAttribute('action');
  if (rawAction) {
    try {
      action = new URL(rawAction, baseUrl).href;
    } catch {
      action = rawAction; // Keep raw value if URL parsing fails
    }
  }

  return {
    action,
    method: (form.method || 'GET').toUpperCase(),
    id: form.id || undefined,
    name: form.name || undefined,
    fieldCount: fields.length,
    fields,
    isLoginForm: detectLoginForm(fields),
    isPaymentForm: detectPaymentForm(fields),
  };
}

/**
 * Extract schemas from all forms in a document.
 * @param doc - Document to extract from
 * @returns Array of form schemas
 */
export function extractFormSchemas(doc: Document): FormSchema[] {
  const forms = doc.querySelectorAll('form');
  const schemas: FormSchema[] = [];
  const baseUrl = doc.location?.href || '';

  forms.forEach((form) => {
    const schema = extractFormSchema(form as HTMLFormElement, baseUrl);
    // Only include forms with at least one field
    if (schema.fieldCount > 0) {
      schemas.push(schema);
    }
  });

  return schemas;
}

/**
 * Check if any forms have sensitive fields (login or payment).
 * Useful for determining forensics priority.
 */
export function hasSensitiveForms(schemas: FormSchema[]): boolean {
  return schemas.some((schema) => schema.isLoginForm || schema.isPaymentForm);
}
