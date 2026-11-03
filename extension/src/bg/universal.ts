import { authState, exactSignInOrigin, SIGNED_IN_MS, SIGNIN_QUIET_MS, SIGNIN_SETTING, signInOn, type AuthReport } from "../auth-state"
import { provider as providerOf, providerOrigins, savedAtProvider } from "../signin"
import type { ProviderChain } from "./provider-chain"
import type { MenuLoadReply, PickReply, SignInReply } from "../messages"
import type { Account } from "../protocol"
import { Autofill, oneRowEach, resizeMessage } from "./autofill"
import type { VaultBackend } from "./backend"
import { menuFrameOf, sendToFrame, targetFor, topTarget, type FrameTarget } from "./frames"
import { hostHash } from "./site-icons"
import { siteOf } from "./site"

interface Offer extends FrameTarget {
  at: number
  accounts: Account[]
  /** The known providers whose buttons the page showed (see providerAccounts). */
  providers: string[]
  menuDocumentId?: string
  picked?: boolean
  picking?: boolean
  cancelled?: boolean
}
interface Memory { signedIn?: number; quietUntil?: number }
/** An offer's authority lasts this long between renewals (see UniversalSignIn.token). */
const OFFER_MS = 60_000

/** The corner offer, with "Offer to sign in" on. Browse fills never enter this path. */
export class UniversalSignIn {
  private offers = new Map<string, Offer>()
  private checking = new Set<number>()
  private lists = new Map<string, { at: number; accounts: Account[] }>()
  /** Pages (by what of a sign-in they show, URL included, see content.ts) that got no offer: not probed again until the vault changes, or ten minutes. */
  private nothing = new Map<string, number>()
  private on?: Promise<boolean>
  constructor(private host: VaultBackend, private autofill: Autofill, private occupied: (tab: number) => boolean, private providers: ProviderChain) {
    host.onChange((status) => { this.lists.clear(); this.nothing.clear(); if (status.state !== "ready") void this.closeAll() })
    chrome.storage.onChanged?.addListener((changes, area) => {
      if (area !== "local" || !(SIGNIN_SETTING in changes)) return
      this.on = undefined
      if (!signInOn(changes[SIGNIN_SETTING].newValue)) void this.closeAll()
    })
  }

  /** Memoized until the setting changes; a failed read is retried next time. */
  private enabled() {
    const on = this.on ??= chrome.storage.local.get(SIGNIN_SETTING).then((s) => signInOn(s[SIGNIN_SETTING]))
    on.catch(() => { if (this.on === on) this.on = undefined })
    return on.catch(() => false)
  }
  /** Each origin's memory key, hashed once (see hostHash). */
  private keys = new Map<string, Promise<string>>()
  private key(origin: string) {
    let key = this.keys.get(origin)
    if (!key) {
      if (this.keys.size >= 100) this.keys.delete(this.keys.keys().next().value!)
      key = hostHash(origin).then((h) => `signin-memory:${h}`)
      key.catch(() => this.keys.delete(origin))
      this.keys.set(origin, key)
    }
    return key
  }
  private async memory(origin: string): Promise<Memory> {
    const key = await this.key(origin)
    return (await chrome.storage.session.get(key))[key] ?? {}
  }
  private async remember(origin: string, change: Memory) {
    const key = await this.key(origin)
    await chrome.storage.session.set({ [key]: { ...await this.memory(origin), ...change } })
    const all = await chrome.storage.session.get(null)
    const entries = Object.entries(all).filter(([k]) => k.startsWith("signin-memory:")) as Array<[string, Memory]>
    entries.sort((a, b) => Math.max(b[1].signedIn ?? 0, b[1].quietUntil ?? 0) - Math.max(a[1].signedIn ?? 0, a[1].quietUntil ?? 0))
    const old = entries.filter(([, v], i) => i >= 100 || Math.max((v.signedIn ?? 0) + SIGNED_IN_MS, v.quietUntil ?? 0) < Date.now()).map(([k]) => k)
    if (old.length) await chrome.storage.session.remove(old)
  }

  /**
   * For a pick that would sign in (Autofill.signedOut): a fresh probe of the
   * top page finds it signed out, and no sign-in is remembered there lately.
   */
  async signedOutNow(target: FrameTarget): Promise<boolean> {
    if (target.frameId !== 0) return false
    const facts = await this.probe(target, true)
    if (!facts) return false
    const memory = await this.memory(target.origin)
    return authState(facts, Date.now() - (memory.signedIn ?? 0) < SIGNED_IN_MS) === "signed-out"
  }

  /** The existing save/outcome judge confirmed a sign-in; no new heuristic. */
  async signedIn(tabId: number) {
    if (!await this.enabled()) return
    const { target } = await topTarget(tabId)
    if (target) await this.remember(target.origin, { signedIn: Date.now() })
  }

  async signedOut(sender: chrome.runtime.MessageSender) {
    const target = await targetFor(sender)
    if (target?.frameId === 0) await this.remember(target.origin, { signedIn: 0 })
  }

  /** A site with none keeps its empty list until the vault changes (see the constructor); others for five seconds. */
  private async accounts(origin: string, fresh = false): Promise<Account[]> {
    const cached = this.lists.get(origin)
    if (!fresh && cached && (!cached.accounts.length || Date.now() - cached.at < 5000)) return cached.accounts
    const list = await this.host.send({ type: "list", origin })
    const accounts = list.accounts.filter((a) => (a.hasPassword || a.signIn) && a.urls.some((u) => exactSignInOrigin(u, origin)))
    if (this.lists.size >= 100) this.lists.delete(this.lists.keys().next().value!)
    this.lists.set(origin, { at: Date.now(), accounts })
    return accounts
  }
  /**
   * The person's own accounts at the providers whose "Sign in with …"
   * buttons the page shows: logins saved at a provider's own sign-in host
   * (savedAtProvider), each offered as "Sign in with Google · <account>",
   * a pick of which starts the provider chain for it (see pick). Not one a
   * site login already links to. Most used first, as the vault lists them.
   */
  private async providerAccounts(ids: string[], site: Account[], home: string, fresh = false): Promise<Account[]> {
    const linked = (p: string, username: string) => site.some((a) => a.signIn?.provider === p && a.signIn.account?.trim().toLowerCase() === username.trim().toLowerCase())
    const found: Account[] = []
    const homeSite = siteOf(new URL(home).hostname)
    for (const id of ids) {
      const p = providerOf(id)
      // Never on a site of the provider's own (gist.github.com, sites.google.com).
      if (p.hosts.some((h) => siteOf(h) === homeSite)) continue
      for (const origin of providerOrigins(p)) {
        // Kept apart from the site lists (see accounts), which are filtered.
        // Until the vault changes (see the constructor), not per check.
        const key = `provider:${origin}`
        const cached = this.lists.get(key)
        const listed = !fresh && cached ? cached.accounts : (await this.host.send({ type: "list", origin }).catch(() => null))?.accounts ?? []
        if (this.lists.size >= 100) this.lists.delete(this.lists.keys().next().value!)
        this.lists.set(key, { at: Date.now(), accounts: listed })
        for (const a of listed) {
          const username = a.username?.trim()
          // A provider login saved for the site too is already listed as the site's own.
          if (!username || !a.hasPassword || a.signIn || !a.urls.some((u) => savedAtProvider(p, u)) || linked(p.id, username) || site.some((x) => x.ref === a.ref) || found.some((f) => f.ref === a.ref)) continue
          found.push({ ...a, title: p.name, hasPassword: false, hasTotp: false, signIn: { provider: p.id, account: username } })
        }
      }
    }
    return found
  }
  /** `fresh` skips the page's short report cache, for the guarded pick. */
  private probe(target: FrameTarget, fresh = false) {
    return sendToFrame<AuthReport>(target, { type: "db:auth-probe", ...(fresh ? { fresh } : {}) })
  }
  private rememberNothing(signal: string) {
    if (this.nothing.size >= 200) this.nothing.delete(this.nothing.keys().next().value!)
    this.nothing.set(signal, Date.now() + 10 * 60_000)
  }
  private open(tabId: number) { return [...this.offers.values()].some((o) => o.tabId === tabId) }
  /** A fresh sign-in or a recent offer/dismissal on this origin: don't probe at all. */
  private quiet(memory: Memory) {
    return Date.now() - (memory.signedIn ?? 0) < SIGNED_IN_MS || Date.now() < (memory.quietUntil ?? 0)
  }

  /**
   * A page that shows something of a sign-in asks once per change (see
   * content.ts askAboutSignIn). "retry": nothing could be decided yet
   * (Deadbolt locked or busy, a check or a sign-in under way), so it asks
   * again in a few seconds.
   */
  async check(sender: chrome.runtime.MessageSender, signal?: unknown, provider = false): Promise<"retry" | undefined> {
    const target = await targetFor(sender)
    const shown = typeof signal === "string" && signal.length <= 4096 ? signal : undefined
    if (shown && (this.nothing.get(shown) ?? 0) > Date.now()) return
    // Cheapest first. An open offer stays until navigation, pick, dismissal,
    // lock or the setting going off; it is never re-probed.
    if (!target || target.frameId !== 0 || this.open(target.tabId)) return
    if (this.checking.has(target.tabId) || this.host.status.state !== "ready" || this.occupied(target.tabId) || this.providers.active(target.tabId)) return "retry"
    this.checking.add(target.tabId)
    try {
      if (!await this.enabled() || this.quiet(await this.memory(target.origin))) return
      if (await this.autofill.signingIn(target.tabId)) return "retry"
      const own = await this.accounts(target.origin)
      // Nothing saved for the site: only a provider button could offer anything, so no probe without one.
      if (own.length > 50 || (!own.length && !provider)) return
      const facts = await this.probe(target)
      if (!facts) return
      // This page as it is got no offer: don't probe it again (see nothing).
      const none = () => { if (shown) this.rememberNothing(shown); return undefined }
      if (facts.signOut) await this.remember(target.origin, { signedIn: Date.now() })
      if (authState(facts) !== "signed-out" || !facts.action) return none()
      if (this.open(target.tabId)) return
      // The site's own logins first, then the person's provider accounts for its provider buttons; at most 50.
      const providers = cleanProviders(facts.providers)
      const accounts = oneRowEach([...own, ...(await this.providerAccounts(providers, own, target.origin))], target.origin).slice(0, 50)
      if (!accounts.length) return none()
      if (this.open(target.tabId)) return
      if (!await this.enabled() || this.host.status.state !== "ready" || this.quiet(await this.memory(target.origin))) return
      const token = crypto.randomUUID()
      this.offers.set(token, { ...target, at: Date.now(), accounts, providers })
      if (await sendToFrame(target, { type: "db:signin-offer", token }))
        await this.remember(target.origin, { quietUntil: Date.now() + SIGNIN_QUIET_MS })
      else this.offers.delete(token)
    } finally { this.checking.delete(target.tabId) }
  }

  owns(token: string) { return this.offers.has(token) }
  private async token(token: string, sender: chrome.runtime.MessageSender, parent?: string) {
    const o = this.offers.get(token)
    if (!o || !sender.documentId || sender.tab?.id !== o.tabId) return null
    if (!o.menuDocumentId) {
      if (parent === undefined || !await menuFrameOf(sender, o, parent)) return null
      o.menuDocumentId = sender.documentId
    }
    if (o.menuDocumentId !== sender.documentId) return null
    // Out of time and not yet picked: renewed quietly while the page still
    // qualifies, else the offer goes. It never says it expired.
    if (Date.now() - o.at > OFFER_MS && !o.picked && !(await this.renew(o))) {
      await this.closeTab(o.tabId)
      return null
    }
    return o
  }
  /** An open offer past its time: the page still signed out (a fresh probe) with accounts to offer, so it lives on with them. */
  private async renew(o: Offer): Promise<boolean> {
    if (o.cancelled || !await this.enabled() || this.host.status.state !== "ready") return false
    const facts = await this.probe(o, true)
    const memory = await this.memory(o.origin)
    if (!facts?.action || authState(facts, Date.now() - (memory.signedIn ?? 0) < SIGNED_IN_MS) !== "signed-out") return false
    const own = await this.accounts(o.origin, true)
    const accounts = oneRowEach([...own, ...(await this.providerAccounts(o.providers, own, o.origin, true))], o.origin).slice(0, 50)
    if (!accounts.length || o.cancelled) return false
    o.accounts = accounts
    o.at = Date.now()
    return true
  }
  async load(token: string, sender: chrome.runtime.MessageSender, parent: string): Promise<MenuLoadReply | null> {
    const o = await this.token(token, sender, parent)
    return o && !o.picked && await this.enabled() && this.host.status.state === "ready"
      ? { kind: "accounts", site: new URL(o.origin).hostname, accounts: o.accounts, focused: "username", universal: true }
      : null
  }
  async pick(token: string, ref: string, sender: chrome.runtime.MessageSender, provider = false): Promise<PickReply> {
    const o = await this.token(token, sender)
    // Gone (see token): the surface is on its way out, and says nothing.
    if (!o || o.picked || !await this.enabled() || this.host.status.state !== "ready") return { ok: false, message: "" }
    // Consume before awaiting a probe; keep dismissal authority while the
    // frame says "Continuing sign-in", so Escape there still cancels.
    o.picked = o.picking = true
    try {
      const own = await this.accounts(o.origin, true)
      const fresh = [...own, ...(await this.providerAccounts(o.providers, own, o.origin, true))]
      const account = fresh.find((a) => a.ref === ref && o.accounts.some((saved) => saved.ref === ref))
      // One of the person's provider accounts, not a login saved for the site (see providerAccounts).
      const unlinked = !!account && !own.some((a) => a.ref === ref)
      const facts = account && await this.probe(o, true)
      const memory = await this.memory(o.origin)
      if (o.cancelled || !account || !facts?.action || authState(facts, Date.now() - (memory.signedIn ?? 0) < SIGNED_IN_MS) !== "signed-out")
        return { ok: false, message: "The page changed. Nothing was filled." }
      // Only a pick of a provider-linked sign-in, with the account and the
      // provider's sign-in hosts known, starts a chain. Every other pick, a
      // plain login on a provider's own host included, is the ordinary
      // automatic sign-in; a provider Deadbolt has no hosts for (Okta, a
      // custom one) gets the site's button pointed at, as before.
      const chain = provider && !!account.signIn?.account && providerOf(account.signIn.provider).hosts.length > 0
      let reply: PickReply
      if (chain) {
        await this.autofill.stopAutomatic(o.tabId)
        if (o.cancelled) return { ok: true }
        const starting = this.providers.start(o, account, unlinked)
        await this.closeTab(o.tabId)
        reply = await starting
      } else if (unlinked) return { ok: false, message: "The page changed. Nothing was filled." }
      else reply = await this.autofill.startAutomatic(o, account, facts.action, provider)
      if (o.cancelled) {
        this.providers.stop(o.tabId)
        await this.autofill.stopAutomatic(o.tabId)
      }
      return reply
    } finally { o.picking = false }
  }
  async provider(token: string, ref: string, sender: chrome.runtime.MessageSender): Promise<SignInReply> {
    const name = this.offers.get(token)?.accounts.find((a) => a.ref === ref)?.signIn?.provider
    if (!name) return { ok: false, message: "That provider isn't here anymore." }
    const reply = await this.pick(token, ref, sender, true)
    return reply.ok ? { ok: true, found: true, provider: name } : reply
  }
  async resize(token: string, sender: chrome.runtime.MessageSender, height: number, width?: unknown, mode?: unknown) {
    const o = await this.token(token, sender)
    if (o) await sendToFrame(o, resizeMessage(token, height, width, mode))
  }
  async dismiss(token: string, sender: chrome.runtime.MessageSender) {
    const o = await this.token(token, sender)
    if (!o) return
    o.cancelled = true
    this.providers.stop(o.tabId)
    if (o.picked) await this.autofill.stopAutomatic(o.tabId)
    await this.remember(o.origin, { quietUntil: Date.now() + SIGNIN_QUIET_MS })
    await this.closeTab(o.tabId)
  }
  closed(token: string, sender: chrome.runtime.MessageSender, dismissed = false) {
    const o = this.offers.get(token)
    if (o && o.tabId === sender.tab?.id && o.documentId === sender.documentId) {
      if (dismissed) o.cancelled = true
      if (dismissed && o.picked) {
        this.providers.stop(o.tabId)
        void this.autofill.stopAutomatic(o.tabId)
      }
      this.offers.delete(token)
    }
  }
  async closeTab(tabId: number) {
    for (const [token, o] of this.offers) if (o.tabId === tabId) {
      this.offers.delete(token)
      await sendToFrame(o, { type: "db:close-menu", token })
    }
  }
  private async closeAll() {
    for (const o of this.offers.values()) {
      o.cancelled = true
      this.providers.stop(o.tabId)
      await this.closeTab(o.tabId)
    }
  }
}

/** A content script's provider ids, kept to known providers with sign-in hosts. */
function cleanProviders(raw: unknown): string[] {
  return Array.isArray(raw) ? [...new Set(raw.filter((p): p is string => typeof p === "string" && p.length <= 64 && providerOf(p).hosts.length > 0))].slice(0, 12) : []
}
