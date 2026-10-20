/**
 * Form Schema Store for BrowserDefense.
 *
 * Temporary in-memory storage of form schemas by tab ID.
 * Used to capture form metadata when a page is blocked.
 *
 * Lifecycle:
 * 1. Content script extracts form schemas on page load
 * 2. Schemas are sent to background and stored here by tab ID
 * 3. When blocking occurs, schemas are consumed and included in forensics
 * 4. Cleanup happens on tab close or after a timeout
 *
 * Reference: Issue #167 - P1: Form Schema Capture
 */

import type { FormSchema } from '../content/form-schema';

// ============ Types ============

interface StoredFormSchemas {
  /** Form schemas for this tab */
  schemas: FormSchema[];
  /** URL the schemas were extracted from */
  url: string;
  /** Timestamp when stored */
  storedAt: number;
}

// ============ Storage ============

/** In-memory store of form schemas by tab ID */
const formSchemaStore = new Map<number, StoredFormSchemas>();

/** How long to keep schemas before cleanup (5 minutes) */
const SCHEMA_TTL_MS = 5 * 60 * 1000;

// ============ Functions ============

/**
 * Store form schemas for a tab.
 * Replaces any existing schemas for the tab.
 */
export function storeFormSchemas(tabId: number, schemas: FormSchema[], url: string): void {
  formSchemaStore.set(tabId, {
    schemas,
    url,
    storedAt: Date.now(),
  });

  // Log for debugging
  const sensitiveCount = schemas.filter((s) => s.isLoginForm || s.isPaymentForm).length;
  if (sensitiveCount > 0) {
    console.log(
      `[BrowserDefense] Stored ${schemas.length} form schema(s) for tab ${tabId} ` +
        `(${sensitiveCount} sensitive)`
    );
  }
}

/**
 * Get form schemas for a tab without removing them.
 */
export function getFormSchemas(tabId: number): FormSchema[] | undefined {
  const stored = formSchemaStore.get(tabId);
  return stored?.schemas;
}

/**
 * Consume form schemas for a tab (get and remove).
 * Used when blocking to include schemas in forensics.
 */
export function consumeFormSchemas(tabId: number): FormSchema[] | undefined {
  const stored = formSchemaStore.get(tabId);
  if (stored) {
    formSchemaStore.delete(tabId);
    console.log(`[BrowserDefense] Consumed ${stored.schemas.length} form schema(s) for tab ${tabId}`);
    return stored.schemas;
  }
  return undefined;
}

/**
 * Clear form schemas for a tab.
 * Called when tab is closed.
 */
export function clearFormSchemas(tabId: number): void {
  if (formSchemaStore.has(tabId)) {
    formSchemaStore.delete(tabId);
  }
}

/**
 * Get the number of tabs with stored schemas.
 */
export function getStoredTabCount(): number {
  return formSchemaStore.size;
}

/**
 * Clean up stale entries older than TTL.
 */
function cleanupStaleEntries(): void {
  const now = Date.now();
  let cleanedCount = 0;

  // Use Array.from to avoid iterator issues
  for (const [tabId, stored] of Array.from(formSchemaStore.entries())) {
    if (now - stored.storedAt > SCHEMA_TTL_MS) {
      formSchemaStore.delete(tabId);
      cleanedCount++;
    }
  }

  if (cleanedCount > 0) {
    console.log(`[BrowserDefense] Cleaned up ${cleanedCount} stale form schema entries`);
  }
}

/**
 * Initialize the form schema store.
 * Sets up cleanup on tab close and periodic cleanup.
 */
export function initFormSchemaStore(): void {
  // Clean up when tabs are closed
  chrome.tabs.onRemoved.addListener((tabId) => {
    clearFormSchemas(tabId);
  });

  // Periodic cleanup of stale entries (every 5 minutes)
  setInterval(cleanupStaleEntries, SCHEMA_TTL_MS);

  console.log('[BrowserDefense] Form schema store initialized');
}
