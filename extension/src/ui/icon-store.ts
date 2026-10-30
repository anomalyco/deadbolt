// Site icons: the two settings that show them, and the SVG icons Deadbolt
// kept from the sites themselves (see bg/site-icons.ts).
//
// The settings are in chrome.storage.local, as the extension's other
// settings. The icons are in the extension's own IndexedDB, which only its
// own pages and service worker can open: unlike chrome.storage.local, a
// content script can't read it, so a page (or a compromised renderer) can't
// list which sites have a saved login by their icons.

/** chrome.storage.local: whether rows show site icons, in the inline menu and in the vault (the popup and device.html). */
export const ICONS_MENU_KEY = "siteIconsMenu"
export const ICONS_VAULT_KEY = "siteIconsVault"

export interface IconSettings {
  /** Default off: every login in the menu is the page's own site's, so the icon would only repeat. */
  menu: boolean
  /** Default on. */
  vault: boolean
}

export const iconSettingsOf = (stored: Record<string, unknown>): IconSettings => ({
  menu: stored[ICONS_MENU_KEY] === true,
  vault: stored[ICONS_VAULT_KEY] !== false,
})

export async function iconSettings(): Promise<IconSettings> {
  const stored = await chrome.storage.local.get([ICONS_MENU_KEY, ICONS_VAULT_KEY]).catch(() => ({}) as Record<string, unknown>)
  return iconSettingsOf(stored)
}

export async function setIconSetting(which: keyof IconSettings, on: boolean) {
  await chrome.storage.local.set({ [which === "menu" ? ICONS_MENU_KEY : ICONS_VAULT_KEY]: on }).catch(() => {})
  // Off in both places: the kept icons go too, and no more are kept.
  const now = await iconSettings()
  if (!now.menu && !now.vault) await clearIcons()
}

/** Calls `changed` whenever either setting changes, from any page. */
export function onIconSettings(changed: (settings: IconSettings) => void) {
  chrome.storage.onChanged?.addListener((changes, area) => {
    if (area === "local" && (ICONS_MENU_KEY in changes || ICONS_VAULT_KEY in changes)) void iconSettings().then(changed)
  })
}

// ---- Kept icons ------------------------------------------------------------

/** A site's own icon, sanitized (ui/svg-safe.ts): `mask` is a monochrome mask-icon, painted in `color`. */
export interface StoredIcon {
  svg: string
  mask?: boolean
  color?: string
  /** When it was read (ms since the epoch). */
  at: number
}

const DB = "deadbolt-site-icons"
const STORE = "icons"
/** The most icons kept; the oldest go first. */
export const MAX_ICONS = 400
/** An icon this old is read again on the next visit. */
export const ICON_FRESH_MS = 30 * 24 * 3600_000

let opened: Promise<IDBDatabase> | null = null
function db(): Promise<IDBDatabase> {
  opened ??= new Promise<IDBDatabase>((resolve, reject) => {
    const req = indexedDB.open(DB, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
  opened.catch(() => (opened = null))
  return opened
}

function request<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return db().then(
    (d) =>
      new Promise<T>((resolve, reject) => {
        const req = run(d.transaction(STORE, mode).objectStore(STORE))
        req.onsuccess = () => resolve(req.result)
        req.onerror = () => reject(req.error)
      }),
  )
}

/** The key an icon is kept under: the host, without a leading "www.". */
export const iconKey = (host: string) => host.toLowerCase().replace(/^www\./, "")

export function storedIcon(host: string): Promise<StoredIcon | undefined> {
  if (typeof indexedDB === "undefined") return Promise.resolve(undefined)
  return request<StoredIcon | undefined>("readonly", (s) => s.get(iconKey(host))).catch(() => undefined)
}

export async function keepIcon(hosts: string[], icon: StoredIcon) {
  if (typeof indexedDB === "undefined") return
  for (const host of new Set(hosts.map(iconKey))) await request("readwrite", (s) => s.put(icon, host)).catch(() => {})
  // Over the cap: the oldest go.
  const keys = (await request<IDBValidKey[]>("readonly", (s) => s.getAllKeys()).catch(() => [])) as string[]
  if (keys.length <= MAX_ICONS) return
  const all = (await request<StoredIcon[]>("readonly", (s) => s.getAll()).catch(() => [])) as StoredIcon[]
  const order = keys.map((k, i) => [k, all[i]?.at ?? 0] as const).sort((a, b) => a[1] - b[1])
  for (const [k] of order.slice(0, keys.length - MAX_ICONS)) await request("readwrite", (s) => s.delete(k)).catch(() => {})
}

export async function clearIcons() {
  if (typeof indexedDB === "undefined") return
  await request("readwrite", (s) => s.clear()).catch(() => {})
}
