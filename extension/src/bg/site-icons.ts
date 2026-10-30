// Keeps a site's own SVG icon, read from the site's page (content/site-icon.ts),
// for the vault's rows and the menu's (ui/site-icon.ts).
//
// Only after Deadbolt filled a login on the site or saw a sign-in there
// go through (see `used`), never just because a page loaded: by then the
// site already knows this visitor has an account, so reading its icon tells
// it nothing new. The page's script could still notice the cache read; a
// page load alone never reveals that the vault has a login for the site.
// Only while a site icon setting is on, at most once a month per host, never
// in an incognito tab, and the content script reads only what the browser
// already has cached from the page's own origin: Deadbolt itself never
// sends a request for an icon.
//
// The background decides which host an icon is for, from the browser's
// record of the top document, never the page's word, and keeps it under
// that exact host only (less a leading "www."): a page can't set the icon of
// another subdomain's login, or of its parent domain's.

import type { PageIcon } from "../content/site-icon"
import { ICON_FRESH_MS, iconKey, iconSettings, keepIcon, storedIcon } from "../ui/icon-store"
import { MAX_SVG_BYTES } from "../ui/svg-safe"
import type { VaultBackend } from "./backend"
import { newToken, sendToFrame, topTarget } from "./frames"
import { fillableOrigin, siteOf } from "./site"

/** chrome.storage.session: salted hashes of hosts whose page had no cached SVG icon lately, so each fill doesn't ask again. */
const CHECKED_KEY = "siteIconsChecked"
/** chrome.storage.session: the salt for the hashes this file and the menu's reveals keep, made once per browser session. */
const SALT_KEY = "siteIconsSalt"
const CHECK_AGAIN_MS = 6 * 3600_000
const MAX_CHECKED = 500

let salting: Promise<string> | undefined

/** A host under this browser session's salt: the session store lists no sites by name. */
export async function hostHash(host: string): Promise<string> {
  salting ??= (async () => {
    const stored = (await chrome.storage.session.get(SALT_KEY))[SALT_KEY]
    if (typeof stored === "string" && stored) return stored
    const made = newToken()
    await chrome.storage.session.set({ [SALT_KEY]: made })
    return made
  })()
  salting.catch(() => (salting = undefined))
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${await salting}\n${iconKey(host)}`))
  return Array.from(new Uint8Array(digest).slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("")
}

/** What the content script sent, if it's the shape asked for. */
export function pageIconOf(raw: unknown): PageIcon | null {
  if (!raw || typeof raw !== "object") return null
  const r = raw as Record<string, unknown>
  if (typeof r.svg !== "string" || !r.svg.startsWith("<svg") || r.svg.length > MAX_SVG_BYTES) return null
  const color = typeof r.color === "string" && /^(#[0-9a-f]{3,8}|[a-z]{3,20})$/i.test(r.color) ? r.color : undefined
  return { svg: r.svg, ...(r.mask === true ? { mask: true } : {}), ...(color ? { color } : {}) }
}

export class SiteIcons {
  private busy = new Set<string>()

  constructor(private host: VaultBackend) {}

  /**
   * Deadbolt just filled a login in `tabId`, or a sign-in there went
   * through, on `site`: read the top page's icon if it's on that site and
   * this host's kept icon is missing or a month old.
   */
  async used(tabId: number, site: string) {
    const tab = await chrome.tabs.get(tabId).catch(() => null)
    if (!tab || tab.incognito) return
    const { target, url } = await topTarget(tabId)
    if (!target || !url || !fillableOrigin(url) || siteOf(url.hostname) !== site || this.host.status.state !== "ready") return
    const key = iconKey(url.hostname)
    if (this.busy.has(key)) return
    this.busy.add(key)
    try {
      const settings = await iconSettings()
      if (!settings.menu && !settings.vault) return
      const kept = await storedIcon(key)
      if (kept && Date.now() - kept.at < ICON_FRESH_MS) return
      if (await this.checkedLately(key)) return
      const icon = pageIconOf(await sendToFrame(target, { type: "db:site-icon" }))
      if (!icon) return void (await this.checked(key))
      // The page may have moved on while it answered: only the document asked counts.
      const now = await topTarget(tabId)
      if (now.target?.documentId !== target.documentId) return
      await keepIcon([key], { ...icon, at: Date.now() })
    } finally {
      this.busy.delete(key)
    }
  }

  private async checkedLately(key: string): Promise<boolean> {
    const all = await this.checkedAll()
    return Date.now() - (all[await hostHash(key)] ?? 0) < CHECK_AGAIN_MS
  }

  private async checked(key: string) {
    const all = await this.checkedAll()
    all[await hostHash(key)] = Date.now()
    const kept = Object.entries(all).sort((a, b) => b[1] - a[1]).slice(0, MAX_CHECKED)
    await chrome.storage.session.set({ [CHECKED_KEY]: Object.fromEntries(kept) }).catch(() => {})
  }

  private async checkedAll(): Promise<Record<string, number>> {
    const got = (await chrome.storage.session.get(CHECKED_KEY).catch(() => ({}))) as Record<string, unknown>
    const v = got[CHECKED_KEY]
    return v && typeof v === "object" ? (v as Record<string, number>) : {}
  }
}
