// BrowserDefense Content Script
// Page context capture for forensics

import {
  extractSkeleton,
  isMainFrame,
  isHtmlDocument,
  type DOMSkeleton,
} from './dom-skeleton';
import { extractFormSchemas, type FormSchema } from './form-schema';
import {
  generateAllSketches,
  extractScriptInfo,
  type LSHSketches,
} from './lsh-sketch';

console.log('[BrowserDefense] Content script loaded');

/**
 * Send DOM skeleton, form schemas, and LSH sketches to background for phishing analysis.
 */
function sendSkeletonToBackground(
  skeleton: DOMSkeleton,
  formSchemas: FormSchema[],
  lshSketches: LSHSketches
): void {
  chrome.runtime.sendMessage({
    type: 'DOM_SKELETON',
    payload: skeleton,
    url: window.location.href,
    timestamp: Date.now(),
    formSchemas: formSchemas.length > 0 ? formSchemas : undefined,
    lshSketches,
  }).catch((error) => {
    // Extension context may be invalidated, ignore
    if (!error.message?.includes('Extension context invalidated')) {
      console.warn('[BrowserDefense] Failed to send skeleton:', error);
    }
  });
}

/**
 * Extract and send DOM skeleton, form schemas, and LSH sketches when document is ready.
 */
function onDomReady(): void {
  // Only run in main frame for HTML documents
  if (!isMainFrame()) {
    return;
  }

  if (!isHtmlDocument(document)) {
    return;
  }

  try {
    const skeleton = extractSkeleton(document);

    // Log extraction time for monitoring
    if (skeleton.extractionTimeMs > 10) {
      console.warn('[BrowserDefense] Slow skeleton extraction:', skeleton.extractionTimeMs, 'ms');
    }

    // Extract form schemas (structure only, no values - privacy safe)
    const formSchemas = extractFormSchemas(document);

    // Extract script/link info for LSH generation
    const scriptInfo = extractScriptInfo(document);

    // Generate LSH sketches for kit variant discovery (Issue #200)
    const lshSketches = generateAllSketches(skeleton, formSchemas, scriptInfo);

    // Log LSH generation time for monitoring
    if (lshSketches.generationTimeMs > 10) {
      console.warn('[BrowserDefense] Slow LSH generation:', lshSketches.generationTimeMs, 'ms');
    }

    sendSkeletonToBackground(skeleton, formSchemas, lshSketches);
  } catch (error) {
    console.error('[BrowserDefense] Skeleton extraction failed:', error);
  }
}

// Run when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', onDomReady);
} else {
  // DOM already loaded
  onDomReady();
}
