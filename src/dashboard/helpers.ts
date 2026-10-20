/**
 * Dashboard Helper Functions
 * Shared utilities for the dashboard UI.
 *
 * Reference: Issue #280
 */

// ============ Types ============

export interface SimilarityInfo {
  percent: number;
  level: 'high' | 'medium' | 'low' | 'unknown';
  isNew: boolean;
}

// ============ Formatting Helpers ============

/**
 * Get similarity info based on score.
 */
export function getSimilarityInfo(score: number | null): SimilarityInfo {
  if (score === null) {
    return { percent: 0, level: 'unknown', isNew: true };
  }

  const percent = Math.round(score * 100);

  if (percent >= 90) {
    return { percent, level: 'high', isNew: false };
  } else if (percent >= 70) {
    return { percent, level: 'medium', isNew: false };
  } else if (percent >= 50) {
    return { percent, level: 'low', isNew: false };
  } else {
    return { percent, level: 'unknown', isNew: true };
  }
}

/**
 * Format timestamp as relative time.
 */
export function formatTimeAgo(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp;

  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return 'now';
}

/**
 * Truncate URL for display.
 */
export function truncateUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname;
    const path = parsed.pathname;

    // Return host + truncated path
    if (path.length > 20) {
      return `${host}${path.slice(0, 20)}...`;
    }
    return `${host}${path}`;
  } catch {
    // Fallback for invalid URLs
    return url.length > 50 ? url.slice(0, 50) + '...' : url;
  }
}

/**
 * Escape HTML to prevent XSS.
 */
export function escapeHtml(str: string): string {
  // Use a DOM-free implementation for compatibility with tests
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
