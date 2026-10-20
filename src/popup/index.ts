/**
 * BrowserDefense Popup
 * Dashboard showing extension status, stats, and recent blocks.
 */

/** Health status from network monitoring */
type HealthStatus = 'online' | 'stale' | 'offline' | 'critical';

interface HealthCheckResult {
  status: HealthStatus;
  message: string;
  isOnline: boolean;
  isStale: boolean;
  isCritical: boolean;
  blocklistAgeMs: number | null;
  consecutiveFailures: number;
  lastError: string | null;
}

interface PopupData {
  blocklist: {
    initialized: boolean;
    count: number;
  };
  update: {
    version: number | null;
    timestamp: string | null;
    updatedAt: number | null;
  };
  forensics: {
    pendingCount: number;
    recentBlocks: Array<{
      url: string;
      timestamp: number;
    }>;
  };
  isOnline: boolean;
  health: HealthCheckResult;
}

/** Auth state from background */
interface AuthState {
  mode: 'sensor' | 'hunter';
  token: string | null;
  isValid: boolean;
}

// DOM elements
const elements = {
  statusDot: document.getElementById('status-dot') as HTMLElement,
  statusText: document.getElementById('status-text') as HTMLElement,
  iocCount: document.getElementById('ioc-count') as HTMLElement,
  lastUpdate: document.getElementById('last-update') as HTMLElement,
  blocksCount: document.getElementById('blocks-count') as HTMLElement,
  pendingRow: document.getElementById('pending-row') as HTMLElement,
  pendingCount: document.getElementById('pending-count') as HTMLElement,
  btnUpdate: document.getElementById('btn-update') as HTMLButtonElement,
  btnSettings: document.getElementById('btn-settings') as HTMLButtonElement,
  recentList: document.getElementById('recent-list') as HTMLElement,
  // Hunter mode elements
  hunterSection: document.getElementById('hunter-section') as HTMLElement,
  iocInput: document.getElementById('ioc-input') as HTMLInputElement,
  btnAddIoc: document.getElementById('btn-add-ioc') as HTMLButtonElement,
  iocFeedback: document.getElementById('ioc-feedback') as HTMLElement,
};

/**
 * Format a number with locale-appropriate separators.
 */
function formatNumber(n: number): string {
  return n.toLocaleString();
}

/**
 * Format a relative time string (e.g., "2 minutes ago").
 */
function formatRelativeTime(timestamp: number | null): string {
  if (!timestamp) return '--';

  const now = Date.now();
  const diff = now - timestamp;

  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return 'Just now';
  if (minutes === 1) return '1 minute ago';
  if (minutes < 60) return `${minutes} minutes ago`;
  if (hours === 1) return '1 hour ago';
  if (hours < 24) return `${hours} hours ago`;
  if (days === 1) return '1 day ago';
  return `${days} days ago`;
}

/**
 * Extract and truncate domain from URL for display.
 */
function formatUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;
    // Truncate long domains
    if (domain.length > 30) {
      return domain.substring(0, 27) + '...';
    }
    return domain;
  } catch {
    // Not a valid URL, truncate directly
    if (url.length > 30) {
      return url.substring(0, 27) + '...';
    }
    return url;
  }
}

/**
 * Update the UI with popup data.
 */
function updateUI(data: PopupData): void {
  // Status indicator based on health check
  const health = data.health;

  if (!data.blocklist.initialized) {
    elements.statusDot.className = 'status-dot disconnected';
    elements.statusText.textContent = 'Not initialized';
  } else {
    // Use health status for indicator
    switch (health.status) {
      case 'online':
        elements.statusDot.className = 'status-dot connected';
        elements.statusText.textContent = 'Protected';
        break;
      case 'stale':
        elements.statusDot.className = 'status-dot stale';
        elements.statusText.textContent = 'Stale (>24h)';
        break;
      case 'critical':
        elements.statusDot.className = 'status-dot critical';
        elements.statusText.textContent = 'Critical (>7d)';
        break;
      case 'offline':
        elements.statusDot.className = 'status-dot offline';
        elements.statusText.textContent = 'Offline';
        break;
    }
  }

  // Blocklist count
  if (data.blocklist.count > 0) {
    elements.iocCount.textContent = `${formatNumber(data.blocklist.count)} IOCs`;
    elements.iocCount.className = 'stat-value highlight';
  } else {
    elements.iocCount.textContent = 'No blocklist loaded';
    elements.iocCount.className = 'stat-value';
  }

  // Last update time
  elements.lastUpdate.textContent = formatRelativeTime(data.update.updatedAt);

  // Recent blocks count
  elements.blocksCount.textContent = String(data.forensics.recentBlocks.length);

  // Pending uploads
  if (data.forensics.pendingCount > 0) {
    elements.pendingRow.classList.add('visible');
    elements.pendingCount.textContent = String(data.forensics.pendingCount);
    elements.pendingCount.className = 'stat-value warning';
  } else {
    elements.pendingRow.classList.remove('visible');
  }

  // Recent blocks list
  if (data.forensics.recentBlocks.length > 0) {
    elements.recentList.innerHTML = data.forensics.recentBlocks
      .map(
        (block) => `
        <div class="recent-item">
          <span class="recent-url" title="${escapeHtml(block.url)}">${escapeHtml(formatUrl(block.url))}</span>
          <span class="recent-time">${formatRelativeTime(block.timestamp)}</span>
        </div>
      `
      )
      .join('');
  } else {
    elements.recentList.innerHTML = '<div class="recent-empty">No recent blocks</div>';
  }
}

/**
 * Escape HTML to prevent XSS.
 */
function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Fetch popup data from background service worker.
 */
async function fetchPopupData(): Promise<PopupData> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: 'getPopupData' }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response as PopupData);
    });
  });
}

/**
 * Trigger a blocklist update.
 */
async function triggerUpdate(): Promise<void> {
  elements.btnUpdate.disabled = true;
  elements.btnUpdate.textContent = 'Updating...';

  try {
    const response = await new Promise<{ success: boolean; error?: string }>((resolve, reject) => {
      chrome.runtime.sendMessage({ type: 'forceUpdate' }, (result) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(result);
      });
    });

    if (response.success) {
      // Refresh data after update
      const data = await fetchPopupData();
      updateUI(data);
    } else {
      console.error('[BrowserDefense] Update failed:', response.error);
    }
  } catch (err) {
    console.error('[BrowserDefense] Update error:', err);
  } finally {
    elements.btnUpdate.disabled = false;
    elements.btnUpdate.textContent = 'Update Now';
  }
}

/**
 * Open extension options page.
 */
function openSettings(): void {
  if (chrome.runtime.openOptionsPage) {
    chrome.runtime.openOptionsPage();
  } else {
    // Fallback for older Chrome versions
    window.open(chrome.runtime.getURL('options.html'));
  }
}

/**
 * Get auth state from background.
 */
async function getAuthState(): Promise<AuthState> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: 'auth_getState' }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (response?.success && response.state) {
        resolve(response.state as AuthState);
      } else {
        // Default to sensor mode if unable to get state
        resolve({ mode: 'sensor', token: null, isValid: false });
      }
    });
  });
}

/**
 * Show or hide hunter section based on auth state.
 */
function updateHunterSection(authState: AuthState): void {
  if (authState.mode === 'hunter') {
    elements.hunterSection.classList.add('visible');
  } else {
    elements.hunterSection.classList.remove('visible');
  }
}

/**
 * Show feedback message in the IOC feedback area.
 */
function showFeedback(message: string, type: 'success' | 'error' | 'info'): void {
  elements.iocFeedback.textContent = message;
  elements.iocFeedback.className = `ioc-feedback ${type}`;

  // Auto-clear success messages after 3 seconds
  if (type === 'success') {
    setTimeout(() => {
      elements.iocFeedback.textContent = '';
      elements.iocFeedback.className = 'ioc-feedback';
    }, 3000);
  }
}

/**
 * Handle adding an IOC to the blocklist.
 */
async function handleAddIoc(): Promise<void> {
  const input = elements.iocInput.value.trim();

  if (!input) {
    showFeedback('Please enter a domain, URL, or IP', 'error');
    return;
  }

  elements.btnAddIoc.disabled = true;
  elements.btnAddIoc.textContent = '...';
  showFeedback('Broadcasting...', 'info');

  try {
    const response = await new Promise<{
      success: boolean;
      iocs?: Array<{ type: string; value: string }>;
      error?: string;
    }>((resolve, reject) => {
      chrome.runtime.sendMessage({ type: 'ioc_broadcast', text: input }, (result) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(result);
      });
    });

    if (response.success) {
      const count = response.iocs?.length ?? 1;
      showFeedback(`Broadcast ${count} IOC${count > 1 ? 's' : ''} to team`, 'success');
      elements.iocInput.value = '';
    } else {
      showFeedback(response.error || 'Failed to broadcast', 'error');
    }
  } catch (err) {
    console.error('[BrowserDefense] Add IOC error:', err);
    showFeedback('Failed to broadcast IOC', 'error');
  } finally {
    elements.btnAddIoc.disabled = false;
    elements.btnAddIoc.textContent = 'Add';
  }
}

/**
 * Initialize popup.
 */
async function init(): Promise<void> {
  console.log('[BrowserDefense] Popup loaded');

  // Set loading state
  elements.statusDot.className = 'status-dot loading';
  elements.statusText.textContent = 'Loading...';

  // Setup button handlers
  elements.btnUpdate.addEventListener('click', triggerUpdate);
  elements.btnSettings.addEventListener('click', openSettings);

  // Hunter mode: Add IOC handlers
  elements.btnAddIoc.addEventListener('click', handleAddIoc);
  elements.iocInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddIoc();
    }
  });

  try {
    // Fetch popup data and auth state in parallel
    const [data, authState] = await Promise.all([
      fetchPopupData(),
      getAuthState(),
    ]);

    updateUI(data);
    updateHunterSection(authState);
  } catch (err) {
    console.error('[BrowserDefense] Failed to load popup data:', err);
    elements.statusDot.className = 'status-dot disconnected';
    elements.statusText.textContent = 'Error';
    elements.iocCount.textContent = 'Failed to load';
  }
}

// Start
init();

// Mark as module
export {};
