import type { AppSettings, RecentFileEntry, SavedProject } from '../types';

const SETTINGS_KEY = 'spet_decompiler_settings_v1';
const DB_NAME = 'spet_decompiler_idb_v1';
const DB_VERSION = 1;
const STORE_RECENT = 'recent_files';
const STORE_PROJECTS = 'saved_projects';

export const DEFAULT_SETTINGS: AppSettings = {
  theme: 'dark',
  enhancedFonts: true,
  monospaceCodeFont: 'JetBrains Mono',
  compactLayout: false,
  showAddresses: true,
  showBytes: true,
  showComments: true,
  showFunctionSignatures: true,
  showAnalysisDetails: true,
  showBackgroundStars: true,
  animations: true,
  reducedMotion: false,
  workerMemoryLimitMb: 512,
  analysisTimeoutSec: 45,
  minStringLength: 4,
  autoAnalyzeOnOpen: true,
  autoNameFunctions: true,
  autoSaveProject: true,
};

export function loadAppSettings(): AppSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveAppSettings(settings: AppSettings): void {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
  } catch {

  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_RECENT)) {
        db.createObjectStore(STORE_RECENT, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORE_PROJECTS)) {
        db.createObjectStore(STORE_PROJECTS, { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('IndexedDB open error'));
  });
}

export async function saveRecentFile(entry: RecentFileEntry): Promise<void> {
  try {
    const db = await openDatabase();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_RECENT, 'readwrite');
      tx.objectStore(STORE_RECENT).put(entry);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {

  }
}

export async function loadRecentFiles(): Promise<RecentFileEntry[]> {
  try {
    const db = await openDatabase();
    return await new Promise<RecentFileEntry[]>((resolve, reject) => {
      const tx = db.transaction(STORE_RECENT, 'readonly');
      const req = tx.objectStore(STORE_RECENT).getAll();
      req.onsuccess = () => {
        const list = (req.result || []) as RecentFileEntry[];
        resolve(list.sort((a, b) => b.openedAt - a.openedAt).slice(0, 12));
      };
      req.onerror = () => reject(req.error);
    });
  } catch {
    return [];
  }
}

export async function clearRecentFiles(): Promise<void> {
  try {
    const db = await openDatabase();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_RECENT, 'readwrite');
      tx.objectStore(STORE_RECENT).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {

  }
}

export async function saveProjectToDb(project: SavedProject): Promise<void> {
  try {
    const db = await openDatabase();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_PROJECTS, 'readwrite');
      tx.objectStore(STORE_PROJECTS).put(project);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {

  }
}

export async function loadProjectsFromDb(): Promise<SavedProject[]> {
  try {
    const db = await openDatabase();
    return await new Promise<SavedProject[]>((resolve, reject) => {
      const tx = db.transaction(STORE_PROJECTS, 'readonly');
      const req = tx.objectStore(STORE_PROJECTS).getAll();
      req.onsuccess = () => {
        const list = (req.result || []) as SavedProject[];
        resolve(list.sort((a, b) => b.updatedAt - a.updatedAt));
      };
      req.onerror = () => reject(req.error);
    });
  } catch {
    return [];
  }
}
