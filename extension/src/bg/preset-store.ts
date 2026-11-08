// The browser-only vault's lock preset, kept in the extension's own
// IndexedDB. As with the kept site icons (ui/icon-store.ts), only the
// extension's own pages and service worker can open it. chrome.storage.local,
// where the preset used to be, is writable by content scripts too, so a
// compromised renderer could have chosen a preset that never locks.

import { DEFAULT_PRESET, isPreset } from "../device-rules"
import type { LockPreset } from "../messages"

const DB = "deadbolt-lock"
const STORE = "settings"
const KEY = "preset"
/** Where chrome.storage.local kept it before: read once, then removed. */
export const LEGACY_PRESET_KEY = "deadbolt.lockPreset"

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function run<T>(mode: IDBTransactionMode, act: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open()
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = act(db.transaction(STORE, mode).objectStore(STORE))
      req.onsuccess = () => resolve(req.result)
      req.onerror = () => reject(req.error)
    })
  } finally {
    db.close()
  }
}

/**
 * The preset kept here. The first time, a preset chrome.storage.local kept
 * moves here, except "until-quit", which anyone could have written there: it
 * becomes Relaxed. After that chrome.storage.local isn't read again. If the
 * store can't be read, the default.
 */
export async function readPreset(): Promise<LockPreset> {
  try {
    const kept = await run<unknown>("readonly", (s) => s.get(KEY))
    if (isPreset(kept)) return kept
    const legacy = (await chrome.storage.local.get(LEGACY_PRESET_KEY).catch(() => ({}) as Record<string, unknown>))[LEGACY_PRESET_KEY]
    const preset: LockPreset = !isPreset(legacy) ? DEFAULT_PRESET : legacy === "until-quit" ? "relaxed" : legacy
    await run("readwrite", (s) => s.put(preset, KEY))
    await chrome.storage.local.remove(LEGACY_PRESET_KEY).catch(() => {})
    return preset
  } catch {
    return DEFAULT_PRESET
  }
}

export async function writePreset(preset: LockPreset): Promise<void> {
  await run("readwrite", (s) => s.put(preset, KEY))
}
