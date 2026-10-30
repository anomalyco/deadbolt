// Keeps a site's own SVG icon, read from the site as the user visits it
// (content/site-icon.ts), for the vault's rows and the menu's (ui/site-icon.ts).
//
// Only for a top page on a site with a saved login, only while a site icon
// setting is on, and at most once a month per site: Deadbolt never asks
// anyone else for an icon, and never asks a site the user isn't on, so no
// server learns which sites the vault has logins for from Deadbolt. The
// background decides which site an icon is for, from the browser's record
// of the page, never the page's word: a page can only set its own site's
// icon. It's kept under the page's host and under the hosts of the logins
// listed for it (a login for acme.com gets accounts.acme.com's icon), the
// same hosts that would get those logins filled.

import type { PageIcon } from "../content/site-icon"
import type { ListReply } from "../protocol"
import { ICON_FRESH_MS, iconKey, iconSettings, keepIcon, storedIcon } from "../ui/icon-store"
import { MAX_SVG_BYTES } from "../ui/svg-safe"
import type { VaultBackend } from "./backend"
import { sendToFrame, topTarget } from "./frames"
import { fillableOrigin, siteOf } from "./site"

/** chrome.storage.session: hosts looked at lately with no login, or whose page had no SVG icon, so a visit doesn't ask the vault every time. */
const CHECKED_KEY = "siteIconsChecked"
const CHECK_AGAIN_MS = 6 * 3600_000
const MAX_CHECKED = 500

/** What the content script sent, if it's the shape asked for. */
export function pageIconOf(raw: unknown): PageIcon | null {
  if (!raw || typeof raw !== "object") return null
  const r = raw as Record<string, unknown>
  if (typeof r.svg !== "string" || !r.svg.startsWith("<svg") || r.svg.length > MAX_SVG_BYTES) return null
  const color = typeof r.color === "string" && /^(#[0-9a-f]{3,8}|[a-z]{3,20})$/i.test(r.color) ? r.color : undefined
  return { svg: r.svg, ...(r.mask === true ? { mask: true } : {}), ...(color ? { color } : {}) }
}

/** The hosts an icon read on `pageHost` is kept under: the page's, and its listed logins' on the same site. */
export function iconHosts(pageHost: string, reply: ListReply): string[] {
  const site = siteOf(pageHost)
  const hosts = new Set([iconKey(pageHost)])
  for (const a of reply.accounts)
    for (const u of a.urls) {
      try {
        const h = new URL(u.includes("://") ? u : `https://${u}`).hostname
        if (site && siteOf(h) === site) hosts.add(iconKey(h))
      } catch {}
    }
  return [...hosts]
}

export class SiteIcons {
  private busy = new Set<string>()

  constructor(private host: VaultBackend) {}

  /** A top page finished loading (webNavigation.onCompleted). */
  async completed(d: { tabId: number; frameId: number; url: string }) {
    if (d.frameId !== 0) return
    let url: URL
    try {
      url = new URL(d.url)
    } catch {
      return
    }
    if (!fillableOrigin(url) || this.host.status.state !== "ready") return
    const key = iconKey(url.hostname)
    if (this.busy.has(key)) return
    this.busy.add(key)
    try {
      const settings = await iconSettings()
      if (!settings.menu && !settings.vault) return
      if (await this.checkedLately(key)) return
      const kept = await storedIcon(key)
      if (kept && Date.now() - kept.at < ICON_FRESH_MS) return
      const reply = await this.host.send({ type: "list", origin: url.origin }).catch(() => null)
      if (!reply) return
      if (!reply.accounts.length) return void (await this.checked(key))
      const { target } = await topTarget(d.tabId)
      if (!target || target.origin !== url.origin) return
      const icon = pageIconOf(await sendToFrame(target, { type: "db:site-icon" }))
      if (!icon) return void (await this.checked(key))
      await keepIcon(iconHosts(url.hostname, reply), { ...icon, at: Date.now() })
    } finally {
      this.busy.delete(key)
    }
  }

  private async checkedLately(key: string): Promise<boolean> {
    const all = await this.checkedAll()
    return Date.now() - (all[key] ?? 0) < CHECK_AGAIN_MS
  }

  private async checked(key: string) {
    const all = await this.checkedAll()
    all[key] = Date.now()
    const kept = Object.entries(all).sort((a, b) => b[1] - a[1]).slice(0, MAX_CHECKED)
    await chrome.storage.session.set({ [CHECKED_KEY]: Object.fromEntries(kept) }).catch(() => {})
  }

  private async checkedAll(): Promise<Record<string, number>> {
    const got = (await chrome.storage.session.get(CHECKED_KEY).catch(() => ({}))) as Record<string, unknown>
    const v = got[CHECKED_KEY]
    return v && typeof v === "object" ? (v as Record<string, number>) : {}
  }
}
