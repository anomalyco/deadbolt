import { authState, exactSignInOrigin, SIGNED_IN_MS, SIGNIN_QUIET_MS, SIGNIN_SETTING, type AuthReport } from "../auth-state"
import type { MenuLoadReply, PickReply, SignInReply } from "../messages"
import type { Account } from "../protocol"
import { Autofill, resizeMessage } from "./autofill"
import type { VaultBackend } from "./backend"
import { menuFrameOf, sendToFrame, targetFor, topTarget, type FrameTarget } from "./frames"
import { hostHash } from "./site-icons"

interface Offer extends FrameTarget {
  at: number
  accounts: Account[]
  menuDocumentId?: string
  picked?: boolean
  picking?: boolean
  cancelled?: boolean
}
interface Memory { signedIn?: number; quietUntil?: number }

/** Opt-in offers only. Ordinary menu and Browse fills never enter this path. */
export class UniversalSignIn {
  private offers = new Map<string, Offer>()
  private checking = new Set<number>()
  private lists = new Map<string, { at: number; accounts: Account[] }>()
  constructor(private host: VaultBackend, private autofill: Autofill, private occupied: (tab: number) => boolean) {
    host.onChange((status) => { this.lists.clear(); if (status.state !== "ready") void this.closeAll() })
    chrome.storage.onChanged?.addListener((changes, area) => {
      if (area === "local" && changes[SIGNIN_SETTING]?.newValue !== true && SIGNIN_SETTING in changes) void this.closeAll()
    })
  }

  private async enabled() { return (await chrome.storage.local.get(SIGNIN_SETTING))[SIGNIN_SETTING] === true }
  private async key(origin: string) { return `signin-memory:${await hostHash(origin)}` }
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

  /** The existing save/outcome judge confirmed a sign-in; no new heuristic. */
  async signedIn(tabId: number) {
    if (!await this.enabled()) return
    const { target } = await topTarget(tabId)
    if (target) await this.remember(target.origin, { signedIn: Date.now() })
    await this.closeTab(tabId)
  }

  async signedOut(sender: chrome.runtime.MessageSender) {
    const target = await targetFor(sender)
    if (target?.frameId === 0) await this.remember(target.origin, { signedIn: 0 })
  }

  private async accounts(origin: string, fresh = false): Promise<Account[]> {
    const cached = this.lists.get(origin)
    if (!fresh && cached && Date.now() - cached.at < 5000) return cached.accounts
    const list = await this.host.send({ type: "list", origin })
    const accounts = list.accounts.filter((a) => (a.hasPassword || a.signIn) && a.urls.some((u) => exactSignInOrigin(u, origin)))
    if (this.lists.size >= 100) this.lists.delete(this.lists.keys().next().value!)
    this.lists.set(origin, { at: Date.now(), accounts })
    return accounts
  }
  private probe(target: FrameTarget, accounts: Account[]) {
    return sendToFrame<AuthReport>(target, { type: "db:auth-probe", usernames: accounts.flatMap((a) => a.username ? [a.username] : []).slice(0, 50) })
  }

  async check(sender: chrome.runtime.MessageSender) {
    const target = await targetFor(sender)
    if (!target || target.frameId !== 0 || this.checking.has(target.tabId)) return
    if ([...this.offers.values()].some((o) => o.tabId === target.tabId && o.picking)) return
    this.checking.add(target.tabId)
    try {
      if (!await this.enabled() || this.host.status.state !== "ready" || this.occupied(target.tabId) || await this.autofill.signingIn(target.tabId)) return
      const memory = await this.memory(target.origin)
      if (Date.now() < (memory.quietUntil ?? 0) && ![...this.offers.values()].some((o) => o.tabId === target.tabId)) return
      const accounts = await this.accounts(target.origin)
      if (!accounts.length || accounts.length > 50) return
      const facts = await this.probe(target, accounts)
      if (!facts) return
      if ([...this.offers.values()].some((o) => o.tabId === target.tabId && o.picking)) return
      const state = authState(facts, Date.now() - (memory.signedIn ?? 0) < SIGNED_IN_MS)
      if (facts.signOut || facts.account) await this.remember(target.origin, { signedIn: Date.now() })
      if (state !== "signed-out") return this.closeTab(target.tabId)
      if (!facts.action || Date.now() < (memory.quietUntil ?? 0)) return
      if ([...this.offers.values()].some((o) => o.tabId === target.tabId)) return
      if (!await this.enabled() || this.host.status.state !== "ready") return
      const token = crypto.randomUUID()
      this.offers.set(token, { ...target, at: Date.now(), accounts })
      if (await sendToFrame(target, { type: "db:signin-offer", token }))
        await this.remember(target.origin, { quietUntil: Date.now() + SIGNIN_QUIET_MS })
      else this.offers.delete(token)
    } finally { this.checking.delete(target.tabId) }
  }

  owns(token: string) { return this.offers.has(token) }
  private async token(token: string, sender: chrome.runtime.MessageSender, parent?: string) {
    const o = this.offers.get(token)
    if (!o || Date.now() - o.at > 60_000 || !sender.documentId || sender.tab?.id !== o.tabId) return null
    if (!o.menuDocumentId) {
      if (parent === undefined || !await menuFrameOf(sender, o, parent)) return null
      o.menuDocumentId = sender.documentId
    }
    return o.menuDocumentId === sender.documentId ? o : null
  }
  async load(token: string, sender: chrome.runtime.MessageSender, parent: string): Promise<MenuLoadReply | null> {
    const o = await this.token(token, sender, parent)
    return o && !o.picked && await this.enabled() && this.host.status.state === "ready"
      ? { kind: "accounts", site: new URL(o.origin).hostname, accounts: o.accounts, focused: "username", universal: true }
      : null
  }
  async pick(token: string, ref: string, sender: chrome.runtime.MessageSender, provider = false): Promise<PickReply> {
    const o = await this.token(token, sender)
    if (!o || o.picked || !await this.enabled() || this.host.status.state !== "ready") return { ok: false, message: "This offer has expired." }
    if (o.picked) return { ok: false, message: "This offer has expired." }
    // Consume before awaiting a probe; keep dismissal authority while the
    // frame says "Continuing sign-in", so Escape there still cancels.
    o.picked = o.picking = true
    try {
      const account = (await this.accounts(o.origin, true)).find((a) => a.ref === ref && o.accounts.some((saved) => saved.ref === ref))
      const facts = account && await this.probe(o, [account])
      const memory = await this.memory(o.origin)
      if (o.cancelled || !account || !facts?.action || authState(facts, Date.now() - (memory.signedIn ?? 0) < SIGNED_IN_MS) !== "signed-out")
        return { ok: false, message: "The page changed. Nothing was filled." }
      const reply = await this.autofill.startAutomatic(o, account, facts.action, provider)
      if (o.cancelled) await this.autofill.stopAutomatic(o.tabId)
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
    if (o.picked) await this.autofill.stopAutomatic(o.tabId)
    await this.remember(o.origin, { quietUntil: Date.now() + SIGNIN_QUIET_MS })
    await this.closeTab(o.tabId)
  }
  closed(token: string, sender: chrome.runtime.MessageSender, dismissed = false) {
    const o = this.offers.get(token)
    if (o && o.tabId === sender.tab?.id && o.documentId === sender.documentId) {
      if (dismissed) o.cancelled = true
      if (dismissed && o.picked) void this.autofill.stopAutomatic(o.tabId)
      this.offers.delete(token)
    }
  }
  async closeTab(tabId: number) {
    for (const [token, o] of this.offers) if (o.tabId === tabId) {
      this.offers.delete(token)
      await sendToFrame(o, { type: "db:close-menu", token })
    }
  }
  private async closeAll() { for (const o of this.offers.values()) await this.closeTab(o.tabId) }
}
