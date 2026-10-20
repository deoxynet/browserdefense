/**
 * BrowserDefense Options Page
 *
 * Handles configuration import/export for standalone deployment.
 */

import {
  BrowserDefenseConfig,
  loadConfig,
  saveConfig,
  clearConfig,
  parseConfigJson,
  exportConfigJson,
  loadDemoConfig,
  saveDemoConfig,
  type DemoConfig,
} from '../config';

// DOM elements
const elements = {
  // Status section
  statusDot: document.getElementById('status-dot') as HTMLElement,
  statusText: document.getElementById('status-text') as HTMLElement,
  configDetails: document.getElementById('config-details') as HTMLElement,
  configOrgId: document.getElementById('config-org-id') as HTMLElement,
  configBlocklistEndpoint: document.getElementById('config-blocklist-endpoint') as HTMLElement,
  configForensicsEndpoint: document.getElementById('config-forensics-endpoint') as HTMLElement,
  configUpdateInterval: document.getElementById('config-update-interval') as HTMLElement,

  // Import section
  dropZone: document.getElementById('drop-zone') as HTMLElement,
  fileInput: document.getElementById('file-input') as HTMLInputElement,
  btnBrowse: document.getElementById('btn-browse') as HTMLButtonElement,
  textareaArea: document.getElementById('textarea-area') as HTMLElement,
  configTextarea: document.getElementById('config-textarea') as HTMLTextAreaElement,
  btnImportText: document.getElementById('btn-import-text') as HTMLButtonElement,
  btnToggleTextarea: document.getElementById('btn-toggle-textarea') as HTMLButtonElement,
  importError: document.getElementById('import-error') as HTMLElement,
  importSuccess: document.getElementById('import-success') as HTMLElement,

  // Export section
  exportSection: document.getElementById('export-section') as HTMLElement,
  btnExport: document.getElementById('btn-export') as HTMLButtonElement,

  // Danger section
  dangerSection: document.getElementById('danger-section') as HTMLElement,
  btnClear: document.getElementById('btn-clear') as HTMLButtonElement,

  // Demo mode section (Issue #571)
  demoModeToggle: document.getElementById('demo-mode-toggle') as HTMLInputElement,
  demoUrlsArea: document.getElementById('demo-urls-area') as HTMLElement,
  demoUrls: document.getElementById('demo-urls') as HTMLTextAreaElement,
  btnSaveDemo: document.getElementById('btn-save-demo') as HTMLButtonElement,
  demoSuccess: document.getElementById('demo-success') as HTMLElement,

  // Footer
  version: document.getElementById('version') as HTMLElement,
};

/**
 * Update the status display.
 */
function updateStatus(config: BrowserDefenseConfig | null): void {
  if (config) {
    elements.statusDot.className = 'status-dot configured';
    elements.statusText.textContent = 'Configured';
    elements.configDetails.style.display = 'block';

    elements.configOrgId.textContent = config.org_id;
    elements.configBlocklistEndpoint.textContent = config.blocklist_endpoint;
    elements.configBlocklistEndpoint.title = config.blocklist_endpoint;
    elements.configForensicsEndpoint.textContent = config.forensics_endpoint;
    elements.configForensicsEndpoint.title = config.forensics_endpoint;
    elements.configUpdateInterval.textContent = `${config.update_interval_minutes ?? 60} minutes`;

    // Show export and danger sections
    elements.exportSection.style.display = 'block';
    elements.dangerSection.style.display = 'block';
  } else {
    elements.statusDot.className = 'status-dot not-configured';
    elements.statusText.textContent = 'Not configured';
    elements.configDetails.style.display = 'none';

    // Hide export and danger sections
    elements.exportSection.style.display = 'none';
    elements.dangerSection.style.display = 'none';
  }
}

/**
 * Show an error message.
 */
function showError(errors: string[]): void {
  elements.importSuccess.style.display = 'none';

  if (errors.length === 1) {
    elements.importError.textContent = errors[0];
  } else {
    elements.importError.innerHTML =
      'Configuration validation failed:<ul>' +
      errors.map((e) => `<li>${escapeHtml(e)}</li>`).join('') +
      '</ul>';
  }

  elements.importError.style.display = 'block';
}

/**
 * Show a success message.
 */
function showSuccess(message: string): void {
  elements.importError.style.display = 'none';
  elements.importSuccess.textContent = message;
  elements.importSuccess.style.display = 'block';

  // Auto-hide after 5 seconds
  setTimeout(() => {
    elements.importSuccess.style.display = 'none';
  }, 5000);
}

/**
 * Clear messages.
 */
function clearMessages(): void {
  elements.importError.style.display = 'none';
  elements.importSuccess.style.display = 'none';
}

/**
 * Escape HTML for safe display.
 */
function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Process a config file.
 */
async function processConfigFile(file: File): Promise<void> {
  clearMessages();

  if (!file.name.endsWith('.json') && file.type !== 'application/json') {
    showError(['Please select a JSON file']);
    return;
  }

  try {
    const text = await file.text();
    await importConfig(text);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to read file';
    showError([message]);
  }
}

/**
 * Import config from JSON string.
 */
async function importConfig(jsonString: string): Promise<void> {
  const result = parseConfigJson(jsonString);

  if (!result.valid) {
    showError(result.errors);
    return;
  }

  try {
    await saveConfig(result.config);

    // Notify background script of config change
    try {
      await chrome.runtime.sendMessage({ type: 'configUpdated' });
    } catch {
      // Background might not be listening yet, that's okay
    }

    showSuccess(`Configuration imported for ${result.config.org_id}`);
    updateStatus(result.config);

    // Clear the textarea
    elements.configTextarea.value = '';
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to save configuration';
    showError([message]);
  }
}

/**
 * Export config to file download.
 */
async function exportConfig(): Promise<void> {
  const config = await loadConfig();

  if (!config) {
    showError(['No configuration to export']);
    return;
  }

  const json = exportConfigJson(config);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `browserdefense-config-${config.org_id}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showSuccess('Configuration exported');
}

/**
 * Clear the configuration.
 */
async function handleClearConfig(): Promise<void> {
  const confirmed = confirm(
    'Are you sure you want to clear the configuration?\n\n' +
      'This will stop IOC blocking until a new configuration is imported.'
  );

  if (!confirmed) {
    return;
  }

  try {
    await clearConfig();

    // Notify background script
    try {
      await chrome.runtime.sendMessage({ type: 'configCleared' });
    } catch {
      // Background might not be listening
    }

    showSuccess('Configuration cleared');
    updateStatus(null);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to clear configuration';
    showError([message]);
  }
}

/**
 * Toggle textarea visibility.
 */
function toggleTextarea(): void {
  const isVisible = elements.textareaArea.style.display !== 'none';

  if (isVisible) {
    elements.textareaArea.style.display = 'none';
    elements.btnToggleTextarea.textContent = 'Paste JSON instead';
  } else {
    elements.textareaArea.style.display = 'block';
    elements.btnToggleTextarea.textContent = 'Hide JSON input';
    elements.configTextarea.focus();
  }
}

/**
 * Setup drag and drop handlers.
 */
function setupDragDrop(): void {
  const dropZone = elements.dropZone;

  dropZone.addEventListener('dragenter', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragleave', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');

    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      processConfigFile(files[0]);
    }
  });

  // Click to browse
  dropZone.addEventListener('click', () => {
    elements.fileInput.click();
  });
}

/**
 * Setup event handlers.
 */
function setupEventHandlers(): void {
  // File input
  elements.fileInput.addEventListener('change', () => {
    const file = elements.fileInput.files?.[0];
    if (file) {
      processConfigFile(file);
      // Reset input so same file can be selected again
      elements.fileInput.value = '';
    }
  });

  // Browse button
  elements.btnBrowse.addEventListener('click', (e) => {
    e.stopPropagation();
    elements.fileInput.click();
  });

  // Import from textarea
  elements.btnImportText.addEventListener('click', () => {
    const text = elements.configTextarea.value.trim();
    if (text) {
      importConfig(text);
    } else {
      showError(['Please paste a configuration JSON']);
    }
  });

  // Toggle textarea
  elements.btnToggleTextarea.addEventListener('click', toggleTextarea);

  // Export
  elements.btnExport.addEventListener('click', exportConfig);

  // Clear
  elements.btnClear.addEventListener('click', handleClearConfig);

  // Demo mode toggle (Issue #571)
  elements.demoModeToggle.addEventListener('change', handleDemoModeToggle);

  // Save demo settings
  elements.btnSaveDemo.addEventListener('click', saveDemoSettings);
}

// ============ Demo Mode Functions (Issue #571) ============

/**
 * Update demo mode UI with current settings.
 */
async function updateDemoModeUI(): Promise<void> {
  try {
    const demoConfig = await loadDemoConfig();
    elements.demoModeToggle.checked = demoConfig.demoMode;
    elements.demoUrls.value = demoConfig.demoUrls.join('\n');
    elements.demoUrlsArea.style.display = demoConfig.demoMode ? 'block' : 'none';
  } catch (err) {
    console.error('[BrowserDefense] Failed to load demo config:', err);
  }
}

/**
 * Handle demo mode toggle change.
 */
async function handleDemoModeToggle(): Promise<void> {
  const enabled = elements.demoModeToggle.checked;
  elements.demoUrlsArea.style.display = enabled ? 'block' : 'none';

  // Auto-save when toggling off
  if (!enabled) {
    await saveDemoSettings();
  }
}

/**
 * Save demo mode settings.
 */
async function saveDemoSettings(): Promise<void> {
  const demoMode = elements.demoModeToggle.checked;
  const demoUrlsText = elements.demoUrls.value.trim();

  // Parse demo URLs (one per line, filter empty lines)
  const demoUrls = demoUrlsText
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  const config: DemoConfig = { demoMode, demoUrls };

  try {
    await saveDemoConfig(config);

    // Notify background script to reload demo config
    try {
      await chrome.runtime.sendMessage({ type: 'demoConfigUpdated' });
    } catch {
      // Background might not be listening
    }

    showDemoSuccess(
      demoMode
        ? `Demo mode enabled with ${demoUrls.length} URL(s)`
        : 'Demo mode disabled'
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to save demo settings';
    showError([message]);
  }
}

/**
 * Show demo success message.
 */
function showDemoSuccess(message: string): void {
  elements.demoSuccess.textContent = message;
  elements.demoSuccess.style.display = 'block';

  // Auto-hide after 3 seconds
  setTimeout(() => {
    elements.demoSuccess.style.display = 'none';
  }, 3000);
}

/**
 * Initialize the options page.
 */
async function init(): Promise<void> {
  console.log('[BrowserDefense] Options page loaded');

  // Set version
  const manifest = chrome.runtime.getManifest();
  elements.version.textContent = manifest.version;

  // Setup handlers
  setupDragDrop();
  setupEventHandlers();

  // Load current config
  try {
    const config = await loadConfig();
    updateStatus(config);
  } catch (err) {
    console.error('[BrowserDefense] Failed to load config:', err);
    updateStatus(null);
  }

  // Load demo mode settings (Issue #571)
  await updateDemoModeUI();
}

// Start
init();

// Mark as module
export {};
