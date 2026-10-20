/**
 * Dashboard UI Logic
 *
 * Displays block metrics, recent forensics events with similarity scores,
 * and extension deployment status.
 *
 * Reference: Issue #280
 */

import { formatTimeAgo, truncateUrl, getSimilarityInfo, escapeHtml, type SimilarityInfo } from './helpers';

// ============ Types ============

interface DashboardStats {
  blocksToday: number;
  newKitsSeen: number;
  pendingTriage: number;
}

interface RecentBlock {
  id: string;
  url: string;
  timestamp: number;
  similarityScore: number | null; // null means unknown/new kit
  category?: 'phishing' | 'malware' | 'c2' | 'unknown';
}

interface DeploymentStatus {
  configured: number;
  unconfigured: number;
}

interface DashboardData {
  stats: DashboardStats;
  recentBlocks: RecentBlock[];
  deployment: DeploymentStatus;
  lastUpdated: number;
}

// ============ Constants ============

const REFRESH_INTERVAL_MS = 30000; // 30 seconds

// ============ State ============

let refreshInterval: ReturnType<typeof setInterval> | null = null;

// ============ Initialization ============

document.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  await loadDashboard();
  startAutoRefresh();
});

/**
 * Set up event listeners.
 */
function setupEventListeners(): void {
  // Refresh button
  document.getElementById('refresh-btn')?.addEventListener('click', async () => {
    await loadDashboard();
  });

  // Status close button
  document.getElementById('status-close')?.addEventListener('click', () => {
    hideStatus();
  });

  // View all link
  document.getElementById('view-all-link')?.addEventListener('click', (e) => {
    e.preventDefault();
    // Navigate to incident review page
    chrome.tabs.create({ url: chrome.runtime.getURL('incident-review/incident-review.html') });
  });

  // Open options button (in empty state)
  document.getElementById('open-options')?.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });
}

/**
 * Start auto-refresh timer.
 */
function startAutoRefresh(): void {
  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
  refreshInterval = setInterval(async () => {
    await loadDashboard();
  }, REFRESH_INTERVAL_MS);
}

// ============ Data Loading ============

/**
 * Load dashboard data from service worker.
 */
async function loadDashboard(): Promise<void> {
  try {
    const data = await fetchDashboardData();
    renderDashboard(data);
    updateLastUpdated();
    hideEmptyState();
  } catch (err) {
    console.error('[Dashboard] Failed to load data:', err);
    showStatus(`Failed to load dashboard: ${(err as Error).message}`, 'error');
  }
}

/**
 * Fetch dashboard data from service worker.
 */
async function fetchDashboardData(): Promise<DashboardData> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: 'getDashboardData' }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response?.success) {
        reject(new Error(response?.error || 'Unknown error'));
        return;
      }
      resolve(response.data);
    });
  });
}

// ============ Rendering ============

/**
 * Render the dashboard with data.
 */
function renderDashboard(data: DashboardData): void {
  renderStats(data.stats);
  renderRecentBlocks(data.recentBlocks);
  renderDeploymentStatus(data.deployment);
}

/**
 * Render stats cards.
 */
function renderStats(stats: DashboardStats): void {
  updateElement('stat-blocks-today', stats.blocksToday.toString());
  updateElement('stat-new-kits', stats.newKitsSeen.toString());
  updateElement('stat-pending', stats.pendingTriage.toString());
}

/**
 * Render recent blocks list.
 */
function renderRecentBlocks(blocks: RecentBlock[]): void {
  const list = document.getElementById('recent-blocks-list');
  if (!list) return;

  if (blocks.length === 0) {
    list.innerHTML = '<p class="loading">No recent blocks</p>';
    return;
  }

  list.innerHTML = blocks.map((block) => renderBlockItem(block)).join('');

  // Add click handlers for navigation
  list.querySelectorAll('.block-item').forEach((item) => {
    item.addEventListener('click', () => {
      const id = (item as HTMLElement).dataset.id;
      if (id) {
        navigateToForensicsDetail(id);
      }
    });
  });
}

/**
 * Render a single block item.
 */
function renderBlockItem(block: RecentBlock): string {
  const timeAgo = formatTimeAgo(block.timestamp);
  const truncatedUrl = truncateUrl(block.url);
  const similarity = getSimilarityInfo(block.similarityScore);

  return `
    <div class="block-item" data-id="${escapeHtml(block.id)}">
      <span class="block-time">${timeAgo}</span>
      <span class="block-url" title="${escapeHtml(block.url)}">${escapeHtml(truncatedUrl)}</span>
      <div class="similarity-container">
        ${renderSimilarityBar(similarity)}
      </div>
    </div>
  `;
}

/**
 * Render similarity bar or new kit badge.
 */
function renderSimilarityBar(similarity: SimilarityInfo): string {
  if (similarity.isNew) {
    return '<span class="new-kit-badge">new</span>';
  }

  return `
    <div class="similarity-bar">
      <div class="similarity-fill ${similarity.level}" style="width: ${similarity.percent}%"></div>
    </div>
    <span class="similarity-label ${similarity.level}">${similarity.percent}% sim</span>
  `;
}

/**
 * Render deployment status.
 */
function renderDeploymentStatus(deployment: DeploymentStatus): void {
  const total = deployment.configured + deployment.unconfigured;
  const percentage = total > 0 ? Math.round((deployment.configured / total) * 100) : 0;

  updateElement('configured-count', deployment.configured.toString());
  updateElement('unconfigured-count', deployment.unconfigured.toString());

  const bar = document.getElementById('deployment-bar');
  if (bar) {
    bar.style.width = `${percentage}%`;
  }

  const note = document.getElementById('deployment-note');
  if (note) {
    if (total === 0) {
      note.textContent = 'No endpoints registered';
    } else if (deployment.unconfigured === 0) {
      note.textContent = 'All endpoints configured';
    } else {
      note.textContent = `${percentage}% of endpoints configured`;
    }
  }
}

// ============ Navigation ============

/**
 * Navigate to forensics detail page.
 * Fetches the full event data and opens a detail view.
 */
function navigateToForensicsDetail(id: string): void {
  console.log('[Dashboard] Navigate to forensics detail:', id);

  // Fetch full event details from background
  chrome.runtime.sendMessage({ type: 'getForensicsById', id }, (response) => {
    if (chrome.runtime.lastError) {
      showStatus(`Failed to load event: ${chrome.runtime.lastError.message}`, 'error');
      return;
    }

    if (!response?.success || !response.event) {
      showStatus(response?.error || 'Event not found', 'error');
      return;
    }

    // Store event in session storage and open detail view
    const event = response.event;
    const detailHtml = generateForensicsDetailHtml(event);
    const blob = new Blob([detailHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    chrome.tabs.create({ url });
  });
}

/**
 * Generate HTML for forensics detail view.
 */
function generateForensicsDetailHtml(event: {
  id: string;
  payload: {
    blockedUrl: string;
    timestamp: string;
    redirectChain?: string[];
    tabId: number;
    frameId: number;
    initiator?: string;
    normalizedUrl?: string;
    reason: string;
  };
  queuedAt: string;
  attempts: number;
}): string {
  const payload = event.payload;
  const escapedUrl = escapeHtml(payload.blockedUrl);
  const escapedNormalized = escapeHtml(payload.normalizedUrl || '-');
  const escapedInitiator = escapeHtml(payload.initiator || '-');
  const escapedReason = escapeHtml(payload.reason);
  const redirectChainHtml = payload.redirectChain?.length
    ? payload.redirectChain.map((url) => `<li>${escapeHtml(url)}</li>`).join('')
    : '<li>No redirect chain captured</li>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forensics Detail - BrowserDefense</title>
  <style>
    :root { --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #c9d1d9; --text-muted: #8b949e; --primary: #58a6ff; --danger: #f85149; }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; line-height: 1.6; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { margin: 0 0 8px; font-size: 24px; }
    .subtitle { color: var(--text-muted); margin-bottom: 24px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
    .card-title { font-weight: 600; margin-bottom: 16px; color: var(--primary); }
    .field { margin-bottom: 12px; }
    .field-label { font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }
    .field-value { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 14px; word-break: break-all; }
    .field-value.url { color: var(--danger); }
    .chain-list { list-style: none; padding: 0; margin: 0; }
    .chain-list li { padding: 4px 0; font-size: 13px; font-family: monospace; }
    .chain-list li:before { content: "→ "; color: var(--text-muted); }
    .chain-list li:last-child { color: var(--danger); }
    .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; }
    code { background: var(--bg); padding: 2px 6px; border-radius: 4px; font-size: 13px; }
    .actions { margin-top: 24px; }
    button { background: var(--primary); color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; }
    button:hover { opacity: 0.9; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Forensics Event Detail</h1>
    <p class="subtitle">Event ID: ${escapeHtml(event.id)}</p>

    <div class="card">
      <div class="card-title">Blocked URL</div>
      <div class="field">
        <div class="field-label">Original URL</div>
        <div class="field-value url">${escapedUrl}</div>
      </div>
      <div class="field">
        <div class="field-label">Normalized URL (matched)</div>
        <div class="field-value">${escapedNormalized}</div>
      </div>
      <div class="field">
        <div class="field-label">Block Reason</div>
        <div class="field-value"><code>${escapedReason}</code></div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Redirect Chain</div>
      <ul class="chain-list">${redirectChainHtml}</ul>
    </div>

    <div class="card">
      <div class="card-title">Context</div>
      <div class="meta">
        <div class="field">
          <div class="field-label">Timestamp</div>
          <div class="field-value">${escapeHtml(payload.timestamp)}</div>
        </div>
        <div class="field">
          <div class="field-label">Initiator</div>
          <div class="field-value">${escapedInitiator}</div>
        </div>
        <div class="field">
          <div class="field-label">Tab ID</div>
          <div class="field-value">${payload.tabId}</div>
        </div>
        <div class="field">
          <div class="field-label">Frame ID</div>
          <div class="field-value">${payload.frameId}</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Queue Info</div>
      <div class="meta">
        <div class="field">
          <div class="field-label">Queued At</div>
          <div class="field-value">${escapeHtml(event.queuedAt)}</div>
        </div>
        <div class="field">
          <div class="field-label">Upload Attempts</div>
          <div class="field-value">${event.attempts}</div>
        </div>
      </div>
    </div>

    <div class="actions">
      <button onclick="window.close()">Close</button>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Update last updated timestamp.
 */
function updateLastUpdated(): void {
  const element = document.getElementById('last-updated');
  if (element) {
    const now = new Date();
    element.textContent = `Last updated: ${now.toLocaleTimeString()}`;
  }
}

// ============ UI Helpers ============

/**
 * Update element text content.
 */
function updateElement(id: string, value: string): void {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}

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

    // Auto-hide success/info messages after 5 seconds
    if (type === 'success' || type === 'info') {
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
 * Show empty state.
 */
function _showEmptyState(): void {
  document.getElementById('empty-state')?.classList.remove('hidden');
  document.querySelector('.stats-section')?.classList.add('hidden');
  document.querySelector('.recent-blocks-section')?.classList.add('hidden');
  document.querySelector('.deployment-section')?.classList.add('hidden');
}

/**
 * Hide empty state.
 */
function hideEmptyState(): void {
  document.getElementById('empty-state')?.classList.add('hidden');
  document.querySelector('.stats-section')?.classList.remove('hidden');
  document.querySelector('.recent-blocks-section')?.classList.remove('hidden');
  document.querySelector('.deployment-section')?.classList.remove('hidden');
}

// Re-export helpers for external use
export { formatTimeAgo, truncateUrl, getSimilarityInfo, escapeHtml, type SimilarityInfo } from './helpers';

// Export dashboard types
export type { DashboardData, DashboardStats, RecentBlock, DeploymentStatus };
