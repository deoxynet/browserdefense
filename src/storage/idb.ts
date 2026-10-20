/**
 * IndexedDB Storage for BrowserDefense
 *
 * Provides persistent storage for IOC blocklists without size limits.
 * chrome.storage.local has ~10MB limit; IndexedDB has no practical limit.
 *
 * Schema:
 * - Database: browserdefense
 * - Object store: blocklist (key: 'data', value: base64 serialized BinaryHashSet)
 * - Object store: meta (key-value pairs for metadata)
 */

const DB_NAME = 'browserdefense';
const DB_VERSION = 1;
const BLOCKLIST_STORE = 'blocklist';
const META_STORE = 'meta';
const BLOCKLIST_KEY = 'data';

let dbPromise: Promise<IDBDatabase> | null = null;

/**
 * Open or create the IndexedDB database.
 * Uses lazy initialization - only opens when first needed.
 */
function openDB(): Promise<IDBDatabase> {
  if (dbPromise) {
    return dbPromise;
  }

  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => {
      console.error('[BrowserDefense] IndexedDB open failed:', request.error);
      dbPromise = null;
      reject(request.error);
    };

    request.onsuccess = () => {
      const db = request.result;

      // Handle database close (e.g., due to version upgrade elsewhere)
      db.onclose = () => {
        console.log('[BrowserDefense] IndexedDB connection closed');
        dbPromise = null;
      };

      resolve(db);
    };

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // Create blocklist store if it doesn't exist
      if (!db.objectStoreNames.contains(BLOCKLIST_STORE)) {
        db.createObjectStore(BLOCKLIST_STORE);
        console.log('[BrowserDefense] Created blocklist object store');
      }

      // Create meta store for general metadata
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE);
        console.log('[BrowserDefense] Created meta object store');
      }
    };
  });

  return dbPromise;
}

/**
 * Save blocklist data to IndexedDB.
 * @param data - Base64-encoded serialized BinaryHashSet
 */
export async function saveBlocklistToIDB(data: string): Promise<void> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(BLOCKLIST_STORE, 'readwrite');
    const store = transaction.objectStore(BLOCKLIST_STORE);

    const request = store.put(data, BLOCKLIST_KEY);

    request.onerror = () => {
      console.error('[BrowserDefense] Failed to save blocklist to IndexedDB:', request.error);
      reject(request.error);
    };

    transaction.oncomplete = () => {
      resolve();
    };

    transaction.onerror = () => {
      reject(transaction.error);
    };
  });
}

/**
 * Load blocklist data from IndexedDB.
 * @returns Base64-encoded serialized BinaryHashSet, or null if not found
 */
export async function loadBlocklistFromIDB(): Promise<string | null> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(BLOCKLIST_STORE, 'readonly');
    const store = transaction.objectStore(BLOCKLIST_STORE);

    const request = store.get(BLOCKLIST_KEY);

    request.onerror = () => {
      console.error('[BrowserDefense] Failed to load blocklist from IndexedDB:', request.error);
      reject(request.error);
    };

    request.onsuccess = () => {
      resolve(request.result ?? null);
    };
  });
}

/**
 * Clear blocklist data from IndexedDB.
 */
export async function clearBlocklistFromIDB(): Promise<void> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(BLOCKLIST_STORE, 'readwrite');
    const store = transaction.objectStore(BLOCKLIST_STORE);

    const request = store.delete(BLOCKLIST_KEY);

    request.onerror = () => {
      reject(request.error);
    };

    transaction.oncomplete = () => {
      resolve();
    };
  });
}

/**
 * Save metadata to IndexedDB.
 * @param key - Metadata key
 * @param value - Metadata value (must be structured cloneable)
 */
export async function saveMetaToIDB<T>(key: string, value: T): Promise<void> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(META_STORE, 'readwrite');
    const store = transaction.objectStore(META_STORE);

    const request = store.put(value, key);

    request.onerror = () => {
      reject(request.error);
    };

    transaction.oncomplete = () => {
      resolve();
    };
  });
}

/**
 * Load metadata from IndexedDB.
 * @param key - Metadata key
 * @returns Metadata value, or null if not found
 */
export async function loadMetaFromIDB<T>(key: string): Promise<T | null> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(META_STORE, 'readonly');
    const store = transaction.objectStore(META_STORE);

    const request = store.get(key);

    request.onerror = () => {
      reject(request.error);
    };

    request.onsuccess = () => {
      resolve(request.result ?? null);
    };
  });
}

/**
 * Delete metadata from IndexedDB.
 * @param key - Metadata key
 */
export async function deleteMetaFromIDB(key: string): Promise<void> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction(META_STORE, 'readwrite');
    const store = transaction.objectStore(META_STORE);

    const request = store.delete(key);

    request.onerror = () => {
      reject(request.error);
    };

    transaction.oncomplete = () => {
      resolve();
    };
  });
}

/**
 * Get storage statistics from IndexedDB.
 * Note: IndexedDB doesn't have a quota limit like chrome.storage.local.
 */
export async function getIDBStats(): Promise<{
  hasData: boolean;
  dataSize: number;
}> {
  const data = await loadBlocklistFromIDB();

  return {
    hasData: data !== null,
    dataSize: data ? data.length : 0,
  };
}

/**
 * Check if IndexedDB is available.
 * Should always be true in Chrome extensions, but good to check.
 */
export function isIndexedDBAvailable(): boolean {
  return typeof indexedDB !== 'undefined';
}

/**
 * Close the database connection.
 * Useful for testing or cleanup.
 */
export async function closeDB(): Promise<void> {
  if (dbPromise) {
    const db = await dbPromise;
    db.close();
    dbPromise = null;
  }
}
