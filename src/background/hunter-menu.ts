/**
 * Hunter Context Menu (Issue #399)
 *
 * Provides context menu for hunter mode:
 * - "Broadcast IOCs" - extracts IOCs from selected text and broadcasts
 * - Only visible when auth_token is valid
 */

import { extractIOCs, type ExtractedIOC } from './ioc-extractor';
import { getAuthToken, type AuthState } from './auth';
import { loadConfig } from '../config/loader';

const MENU_ID = 'blockioc-broadcast-iocs';

let menuCreated = false;

/**
 * Create the context menu for hunter mode.
 */
export async function createHunterMenu(): Promise<void> {
  if (menuCreated) return;

  try {
    await chrome.contextMenus.create({
      id: MENU_ID,
      title: 'Broadcast IOCs to Team',
      contexts: ['selection'],
    });
    menuCreated = true;
    console.log('[BlockIOC] Hunter context menu created');
  } catch (err) {
    // Menu might already exist from previous session
    if (String(err).includes('duplicate id')) {
      menuCreated = true;
    } else {
      console.error('[BlockIOC] Failed to create context menu:', err);
    }
  }
}

/**
 * Remove the context menu (when switching to sensor mode).
 */
export async function removeHunterMenu(): Promise<void> {
  if (!menuCreated) return;

  try {
    await chrome.contextMenus.remove(MENU_ID);
    menuCreated = false;
    console.log('[BlockIOC] Hunter context menu removed');
  } catch (err) {
    // Menu might not exist
    if (!String(err).includes('Cannot find menu item')) {
      console.error('[BlockIOC] Failed to remove context menu:', err);
    }
    menuCreated = false;
  }
}

/**
 * Update context menu based on auth state.
 */
export async function updateHunterMenu(state: AuthState): Promise<void> {
  if (state.mode === 'hunter') {
    await createHunterMenu();
  } else {
    await removeHunterMenu();
  }
}

/**
 * Broadcast result returned to the user.
 */
export interface BroadcastResult {
  success: boolean;
  iocs: ExtractedIOC[];
  error?: string;
}

/**
 * Broadcast IOCs to the team endpoint.
 */
export async function broadcastIOCs(iocs: ExtractedIOC[]): Promise<BroadcastResult> {
  const token = getAuthToken();
  if (!token) {
    return { success: false, iocs, error: 'Not authenticated' };
  }

  const config = await loadConfig();
  if (!config) {
    return { success: false, iocs, error: 'No configuration found' };
  }

  // Get broadcast endpoint - derive from blocklist_endpoint base
  // by replacing the path with /api/v1/broadcast
  const blocklistUrl = new URL(config.blocklist_endpoint);
  const baseUrl = `${blocklistUrl.origin}/api/v1/broadcast`;

  try {
    const response = await fetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        iocs: iocs.map((ioc) => ({
          type: ioc.type,
          value: ioc.value,
          defanged: ioc.defanged,
        })),
        timestamp: Date.now(),
        source: 'hunter-extension',
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      return { success: false, iocs, error: `API error: ${response.status} ${text}` };
    }

    console.log(`[BlockIOC] Broadcast ${iocs.length} IOCs successfully`);
    return { success: true, iocs };
  } catch (err) {
    console.error('[BlockIOC] Broadcast failed:', err);
    return { success: false, iocs, error: String(err) };
  }
}

/**
 * Handle context menu click.
 */
async function handleMenuClick(
  info: chrome.contextMenus.OnClickData,
  tab?: chrome.tabs.Tab
): Promise<BroadcastResult> {
  if (info.menuItemId !== MENU_ID) {
    return { success: false, iocs: [], error: 'Unknown menu item' };
  }

  const selectedText = info.selectionText;
  if (!selectedText) {
    return { success: false, iocs: [], error: 'No text selected' };
  }

  console.log(`[BlockIOC] Extracting IOCs from: "${selectedText.slice(0, 100)}..."`);

  const result = extractIOCs(selectedText);

  if (result.iocs.length === 0) {
    console.log('[BlockIOC] No IOCs found in selection');
    // Show notification to user
    if (tab?.id) {
      try {
        await chrome.tabs.sendMessage(tab.id, {
          type: 'BLOCKIOC_NOTIFICATION',
          message: 'No IOCs found in selected text',
          level: 'info',
        });
      } catch {
        // Content script might not be loaded
      }
    }
    return { success: true, iocs: [], error: 'No IOCs found in selection' };
  }

  console.log(`[BlockIOC] Found ${result.iocs.length} IOCs:`, result.iocs.map((i) => i.type));

  // Broadcast to API
  const broadcastResult = await broadcastIOCs(result.iocs);

  // Notify user of result
  if (tab?.id) {
    try {
      await chrome.tabs.sendMessage(tab.id, {
        type: 'BLOCKIOC_NOTIFICATION',
        message: broadcastResult.success
          ? `Broadcast ${result.iocs.length} IOC(s) to team`
          : `Broadcast failed: ${broadcastResult.error}`,
        level: broadcastResult.success ? 'success' : 'error',
      });
    } catch {
      // Content script might not be loaded
    }
  }

  return broadcastResult;
}

/**
 * Set up context menu click listener.
 */
export function setupMenuListener(): void {
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    handleMenuClick(info, tab).catch((err) => {
      console.error('[BlockIOC] Menu click handler error:', err);
    });
  });
}

/**
 * Initialize hunter menu system.
 * Called on extension startup with initial auth state.
 */
export async function initHunterMenu(state: AuthState): Promise<void> {
  setupMenuListener();
  await updateHunterMenu(state);
}
