/**
 * Incident Review UI Logic
 *
 * Handles the incident review page for viewing and labeling DOM kit hashes.
 * Labels do NOT trigger automatic enforcement - they are for research only.
 *
 * Reference: Issue #205
 */

import type { HashLabel, HashLabelType, LabelListResponse } from '../types/hash-labels';

// ============ Configuration ============

interface IncidentReviewConfig {
  endpoint: string;
  timeoutMs: number;
}

let config: IncidentReviewConfig | null = null;
let currentCursor: string | undefined;
let allLabels: HashLabel[] = [];

// ============ Initialization ============

document.addEventListener('DOMContentLoaded', async () => {
  await initializeConfig();
  setupEventListeners();
  await loadLabels();
  await loadStats();
});

/**
 * Initialize configuration from storage.
 */
async function initializeConfig(): Promise<void> {
  try {
    const { browserdefense_config } = await chrome.storage.local.get('browserdefense_config');
    if (browserdefense_config?.hash_labels_endpoint) {
      config = {
        endpoint: browserdefense_config.hash_labels_endpoint,
        timeoutMs: browserdefense_config.hash_labels_timeout_ms ?? 10000,
      };
    } else {
      showStatus('Hash labels endpoint not configured. Please configure in options.', 'error');
    }
  } catch (err) {
    console.error('[IncidentReview] Failed to load config:', err);
    showStatus('Failed to load configuration', 'error');
  }
}

/**
 * Set up event listeners.
 */
function setupEventListeners(): void {
  // Refresh button
  document.getElementById('refresh-btn')?.addEventListener('click', async () => {
    allLabels = [];
    currentCursor = undefined;
    await loadLabels();
    await loadStats();
  });

  // Status close button
  document.getElementById('status-close')?.addEventListener('click', () => {
    hideStatus();
  });

  // Apply filters button
  document.getElementById('apply-filters')?.addEventListener('click', async () => {
    allLabels = [];
    currentCursor = undefined;
    await loadLabels();
  });

  // Label form submission
  document.getElementById('label-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await handleLabelSubmit();
  });

  // Load more button
  document.getElementById('load-more')?.addEventListener('click', async () => {
    await loadLabels(true);
  });
}

// ============ API Functions ============

/**
 * Load labels from the API.
 */
async function loadLabels(append = false): Promise<void> {
  if (!config) {
    showEmptyState();
    return;
  }

  const labelsList = document.getElementById('labels-list');
  if (!labelsList) return;

  if (!append) {
    labelsList.innerHTML = '<p class="loading">Loading labels...</p>';
  }

  try {
    // Get filter values
    const labelFilterEl = document.getElementById('filter-label') as HTMLSelectElement | null;
    const analystFilterEl = document.getElementById('filter-analyst') as HTMLInputElement | null;
    const labelFilter = labelFilterEl?.value;
    const analystFilter = analystFilterEl?.value;

    // Build query params
    const params = new URLSearchParams();
    if (labelFilter) params.set('label', labelFilter);
    if (analystFilter) params.set('analyst', analystFilter);
    params.set('limit', '50');
    if (append && currentCursor) params.set('cursor', currentCursor);

    const url = `${config.endpoint}/labels${params.toString() ? '?' + params.toString() : ''}`;
    const response = await fetch(url, {
      method: 'GET',
      signal: AbortSignal.timeout(config.timeoutMs),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data: LabelListResponse = await response.json();

    if (append) {
      allLabels = [...allLabels, ...data.labels];
    } else {
      allLabels = data.labels;
    }

    currentCursor = data.cursor;

    renderLabels();

    // Show/hide load more button
    const pagination = document.getElementById('pagination');
    if (pagination) {
      pagination.classList.toggle('hidden', !data.has_more);
    }

    if (allLabels.length === 0) {
      showEmptyState();
    } else {
      hideEmptyState();
    }
  } catch (err) {
    console.error('[IncidentReview] Failed to load labels:', err);
    labelsList.innerHTML = '<p class="loading">Failed to load labels. Check your configuration.</p>';
  }
}

/**
 * Load label statistics.
 */
async function loadStats(): Promise<void> {
  if (!config) return;

  try {
    // Fetch counts for each label type
    const [_tpResponse, _fpResponse, _unknownResponse] = await Promise.all([
      fetch(`${config.endpoint}/labels?label=TP&limit=1`, { signal: AbortSignal.timeout(config.timeoutMs) }),
      fetch(`${config.endpoint}/labels?label=FP&limit=1`, { signal: AbortSignal.timeout(config.timeoutMs) }),
      fetch(`${config.endpoint}/labels?label=UNKNOWN&limit=1`, { signal: AbortSignal.timeout(config.timeoutMs) }),
    ]);

    // Note: This is a simplified approach. In production, you'd want a dedicated stats endpoint.
    // For now, we'll just show the loaded labels count.
    updateStatElement('stat-total', allLabels.length.toString());

    const tpCount = allLabels.filter((l) => l.label === 'TP').length;
    const fpCount = allLabels.filter((l) => l.label === 'FP').length;
    const unknownCount = allLabels.filter((l) => l.label === 'UNKNOWN').length;

    updateStatElement('stat-tp', tpCount.toString());
    updateStatElement('stat-fp', fpCount.toString());
    updateStatElement('stat-unknown', unknownCount.toString());
  } catch (err) {
    console.error('[IncidentReview] Failed to load stats:', err);
  }
}

/**
 * Handle label form submission.
 */
async function handleLabelSubmit(): Promise<void> {
  if (!config) {
    showStatus('Hash labels endpoint not configured', 'error');
    return;
  }

  const hashInput = document.getElementById('hash-input') as HTMLInputElement | null;
  const labelSelect = document.getElementById('label-select') as HTMLSelectElement | null;
  const analystInput = document.getElementById('analyst-input') as HTMLInputElement | null;
  const notesInput = document.getElementById('notes-input') as HTMLTextAreaElement | null;

  const hash = hashInput?.value.trim();
  const label = labelSelect?.value as HashLabelType | undefined;
  const analyst = analystInput?.value.trim();
  const notes = notesInput?.value.trim();

  // Validate hash format
  if (!hash || !/^sha256:[a-f0-9]{64}$/i.test(hash)) {
    showStatus('Invalid hash format. Must be sha256: followed by 64 hex characters.', 'error');
    return;
  }

  if (!label) {
    showStatus('Please select a label type.', 'error');
    return;
  }

  try {
    const response = await fetch(`${config.endpoint}/labels`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        dom_kit_hash: hash,
        label,
        analyst: analyst || undefined,
        notes: notes || undefined,
      }),
      signal: AbortSignal.timeout(config.timeoutMs),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: 'Unknown error' })) as { error?: string };
      throw new Error(errorData.error || `HTTP ${response.status}`);
    }

    const result = await response.json() as { status: string };

    showStatus(`Label ${result.status} successfully!`, 'success');

    // Clear form
    if (hashInput) hashInput.value = '';
    if (labelSelect) labelSelect.value = '';
    if (notesInput) notesInput.value = '';

    // Reload labels
    allLabels = [];
    currentCursor = undefined;
    await loadLabels();
    await loadStats();
  } catch (err) {
    console.error('[IncidentReview] Failed to save label:', err);
    showStatus(`Failed to save label: ${(err as Error).message}`, 'error');
  }
}

/**
 * Handle label deletion.
 */
async function handleDeleteLabel(hash: string): Promise<void> {
  if (!config) return;

  if (!confirm(`Delete label for ${hash.slice(0, 20)}...?`)) {
    return;
  }

  try {
    const encodedHash = encodeURIComponent(hash);
    const response = await fetch(`${config.endpoint}/labels/${encodedHash}`, {
      method: 'DELETE',
      signal: AbortSignal.timeout(config.timeoutMs),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    showStatus('Label deleted successfully!', 'success');

    // Remove from local list and re-render
    allLabels = allLabels.filter((l) => l.dom_kit_hash !== hash);
    renderLabels();
    await loadStats();
  } catch (err) {
    console.error('[IncidentReview] Failed to delete label:', err);
    showStatus(`Failed to delete label: ${(err as Error).message}`, 'error');
  }
}

// ============ Rendering ============

/**
 * Render the labels list.
 */
function renderLabels(): void {
  const labelsList = document.getElementById('labels-list');
  if (!labelsList) return;

  if (allLabels.length === 0) {
    labelsList.innerHTML = '';
    return;
  }

  labelsList.innerHTML = allLabels.map((label) => renderLabelItem(label)).join('');

  // Add delete button event listeners
  labelsList.querySelectorAll('.delete-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      const hash = (e.currentTarget as HTMLElement).dataset.hash;
      if (hash) handleDeleteLabel(hash);
    });
  });
}

/**
 * Render a single label item.
 */
function renderLabelItem(label: HashLabel): string {
  const badgeClass = label.label.toLowerCase();
  const createdDate = new Date(label.created_at).toLocaleString();
  const analystInfo = label.analyst ? `<span>by ${escapeHtml(label.analyst)}</span>` : '';

  return `
    <div class="label-item">
      <div class="label-info">
        <div class="label-hash">${escapeHtml(label.dom_kit_hash)}</div>
        <div class="label-meta">
          <span class="label-badge ${badgeClass}">${label.label}</span>
          ${analystInfo}
          <span>${createdDate}</span>
        </div>
        ${label.notes ? `<div class="label-notes" style="margin-top: 4px; font-size: 12px; color: #6b7280;">${escapeHtml(label.notes)}</div>` : ''}
      </div>
      <div class="label-actions">
        <button class="btn btn-danger btn-small delete-btn" data-hash="${escapeHtml(label.dom_kit_hash)}">Delete</button>
      </div>
    </div>
  `;
}

// ============ UI Helpers ============

/**
 * Show status message.
 */
function showStatus(message: string, type: 'success' | 'error' | 'info'): void {
  const statusBar = document.getElementById('status-bar');
  const statusMessage = document.getElementById('status-message');

  if (statusBar && statusMessage) {
    statusBar.className = `status-bar ${type}`;
    statusMessage.textContent = message;
    statusBar.classList.remove('hidden');

    // Auto-hide success messages after 5 seconds
    if (type === 'success') {
      setTimeout(hideStatus, 5000);
    }
  }
}

/**
 * Hide status message.
 */
function hideStatus(): void {
  const statusBar = document.getElementById('status-bar');
  statusBar?.classList.add('hidden');
}

/**
 * Update a stat element.
 */
function updateStatElement(id: string, value: string): void {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}

/**
 * Show empty state.
 */
function showEmptyState(): void {
  document.getElementById('empty-state')?.classList.remove('hidden');
  document.getElementById('labels-list')?.classList.add('hidden');
}

/**
 * Hide empty state.
 */
function hideEmptyState(): void {
  document.getElementById('empty-state')?.classList.add('hidden');
  document.getElementById('labels-list')?.classList.remove('hidden');
}

/**
 * Escape HTML to prevent XSS.
 */
function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
