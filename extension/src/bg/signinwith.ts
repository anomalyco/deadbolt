// "Sign in with Google": after the user picks such a login in the menu,
// Deadbolt points at the site's own button (the user clicks it), and for a
// few minutes follows the tab (or the popup it opens) to the provider. On the
// provider's account chooser it points at the tile for the linked account,
// and on the provider's own sign-in pages the menu narrows to that account's
// login. It never clicks or fills anything by itself.

import { sendToFrame } from "./frames"
import type { Host } from "./host"
import { siteOf } from "./site"
import { isChooserPage, isProviderPage, provider } from "../signin"

/** How long a tab follows a sign-in with a provider. */
export const SIGN_IN_WITH_TTL_MS = 3 * 60_000

interface Linked {
  /** The provider's id or name, as the login has it. */
  provider: string
  /** The linked account's username (or title), if Deadbolt knows it. */
  account?: string
  /** The site the user is signing in to: coming back to it ends this. */
  site: string
  until: number
  /** The tab has left the site (for the provider) since it started. */
  left: boolean
}

const hostOf = (url: string | undefined): string | null => {
  try {
    return url ? new URL(url).hostname : null
  } catch {
    return null
  }
}

export class SignInWith {
  private tabs = new Map<number, Linked>()
  private timers = new Map<number, ReturnType<typeof setTimeout>>()

  constructor(
    host: Host,
    private now: () => number = Date.now,
  ) {
    // Locked or gone: nothing to follow.
    host.onChange((status) => {
      if (status.state !== "ready") for (const tabId of [...this.tabs.keys()]) this.end(tabId)
    })
  }

  /** The user picked a sign-in-with login on `site` in `tabId`. */
  start(tabId: number, signIn: { provider: string; account?: string }, site: string) {
    this.set(tabId, { provider: signIn.provider, ...(signIn.account ? { account: signIn.account } : {}), site, until: this.now() + SIGN_IN_WITH_TTL_MS, left: false })
  }

  private set(tabId: number, linked: Linked) {
    clearTimeout(this.timers.get(tabId))
    this.tabs.set(tabId, linked)
    this.timers.set(tabId, setTimeout(() => this.end(tabId), Math.max(0, linked.until - this.now())))
  }

  end(tabId: number) {
    clearTimeout(this.timers.get(tabId))
    this.timers.delete(tabId)
    this.tabs.delete(tabId)
  }

  private get(tabId: number): Linked | undefined {
    const l = this.tabs.get(tabId)
    if (l && l.until > this.now()) return l
    if (l) this.end(tabId)
    return undefined
  }

  /** A popup the tab opened (window.open, a link with target) follows the same sign-in. */
  opened(sourceTabId: number, tabId: number) {
    const l = this.get(sourceTabId)
    if (l) this.set(tabId, { ...l, left: true })
  }

  /** The tab's top page committed a new document: back on the site after leaving it, the sign-in is over. */
  navigated(tabId: number, url: string) {
    const l = this.get(tabId)
    const host = hostOf(url)
    if (!l || !host) return
    const site = siteOf(host)
    if (site === l.site) {
      if (l.left) this.end(tabId)
    } else l.left = true
  }

  /**
   * The linked account, for a page of the provider's own in `tabId`; nothing
   * for any other page. The menu narrows to its login there (see Autofill.query).
   */
  accountFor(tabId: number, origin: string): string | undefined {
    const l = this.get(tabId)
    return l?.account && isProviderPage(provider(l.provider), origin) ? l.account : undefined
  }

  /**
   * The top page of `tabId` finished loading (or changed route): if it's the
   * provider's own, hand its content script the account to point at on the
   * chooser. Only that document, on that origin, ever gets it, and only for
   * a provider whose chooser has a reliable pattern (see Provider.chooser).
   */
  async loaded(d: { tabId: number; frameId: number; url: string; documentId?: string }) {
    if (d.frameId !== 0 || !d.documentId) return
    const l = this.get(d.tabId)
    if (!l?.account || !isChooserPage(provider(l.provider), d.url)) return
    await sendToFrame({ tabId: d.tabId, frameId: 0, documentId: d.documentId, origin: new URL(d.url).origin }, { type: "db:chooser", account: l.account })
  }

  forgetTab(tabId: number) {
    this.end(tabId)
  }
}
