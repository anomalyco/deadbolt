// One guarded corner pick, one provider account, one short-lived chain. This
// authority is deliberately memory-only: a restarted worker cannot resume it.
import { authState, exactSignInOrigin, SIGNIN_SETTING, type AuthReport } from "../auth-state"
import { IDENTIFIER_ROLES, type FillValues, type PickReply, type ProviderReport } from "../messages"
import type { Account, Passkey } from "../protocol"
import { isProviderPage, isSignInPage, provider, returnsTo, type Provider } from "../signin"
import { flowFor, namedBy, wantFor } from "./autofill"
import type { VaultBackend } from "./backend"
import { sendToFrame, targetFor, topTarget, type FrameTarget } from "./frames"
import type { Passkeys } from "./passkeys"
import { siteOf } from "./site"
import type { SignInWith } from "./signinwith"

export const PROVIDER_CHAIN_TTL_MS = 120_000
export const PROVIDER_CHAIN_ACTIONS = 8
const UNRELATED = new Set(["typed", "auto_bookmark", "generated", "keyword", "keyword_generated", "reload", "start_page", "auto_toplevel"])
const NEEDS = { consent: "Review access", phone: "Approve on your phone", sms: "Enter your code", "security-key": "Use your security key", captcha: "Complete the verification", unknown: "" }

interface Chain {
  id: string
  home: FrameTarget
  /** The home origin's registrable domain: where the provider's return URLs must lead. */
  site: string
  tab: number
  popup?: number
  popupClaimed?: boolean
  documentId?: string
  provider: Provider
  username: string
  ref?: string
  phase: "entry" | "provider" | "return"
  until: number
  actions: number
  opening?: number
  busy: boolean
  again: boolean
  used: Set<string>
  filled: Set<string>
  passkeyDocument?: string
  filling?: boolean
  stop: AbortController
  timer?: ReturnType<typeof setTimeout>
}

export class ProviderChain {
  private chains = new Set<Chain>()
  private generations = new Map<number, number>()
  constructor(private host: VaultBackend, private passkeys: Passkeys, private linked: SignInWith) {
    host.onChange((status) => { if (status.state !== "ready") this.endAll() })
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && SIGNIN_SETTING in changes && changes[SIGNIN_SETTING].newValue !== true) this.endAll()
    })
    passkeys.automatic = (target, keys, optional) => this.passkey(target, keys, optional)
    passkeys.automaticSession = (target) => {
      const s = this.chain(target.tabId)
      return s && this.ownsProvider(s, target) ? s.stop.signal : undefined
    }
  }

  private chain(tab: number) { return [...this.chains].find((s) => s.home.tabId === tab || s.popup === tab) }
  active(tab: number) { return !!this.chain(tab) }
  private ownsProvider(s: Chain, target: FrameTarget) {
    return target.frameId === 0 && target.tabId === s.tab && target.documentId === s.documentId && s.phase === "provider" && isProviderPage(s.provider, target.origin)
  }
  private live(s: Chain) { return this.chains.has(s) && !s.stop.signal.aborted && Date.now() < s.until && this.host.status.state === "ready" }
  private async ready(s: Chain) {
    return this.live(s) && (await chrome.storage.local.get(SIGNIN_SETTING))[SIGNIN_SETTING] === true && this.live(s)
  }
  private allowed(s: Chain, origin: string) { return origin === s.home.origin || isProviderPage(s.provider, origin) }
  /** A provider page the chain may act on: a sign-in or OAuth path whose return URLs, if any, lead to the home site. */
  private step(s: Chain, url: string) { return isSignInPage(s.provider, url) && returnsTo(s.provider, url, s.site) !== "foreign" }
  private consume(s: Chain) {
    if (!this.live(s) || s.actions >= PROVIDER_CHAIN_ACTIONS) { this.end(s); return false }
    s.actions++
    return true
  }
  stop(tab: number) {
    this.generations.set(tab, (this.generations.get(tab) ?? 0) + 1)
    const s = this.chain(tab)
    if (s) this.end(s)
  }
  private endAll() {
    for (const tab of this.generations.keys()) this.generations.set(tab, this.generations.get(tab)! + 1)
    for (const s of this.chains) this.end(s)
  }
  private end(s: Chain, label = "") {
    if (!this.chains.delete(s)) return
    clearTimeout(s.timer)
    s.stop.abort()
    this.linked.end(s.home.tabId)
    if (s.popup !== undefined) this.linked.end(s.popup)
    for (const tab of new Set([s.home.tabId, s.tab])) void topTarget(tab).then(({ target }) => {
      if (target && this.allowed(s, target.origin)) void sendToFrame(target, { type: "db:provider-status", session: s.id, label, done: true })
    })
  }

  /**
   * Called only by UniversalSignIn after its existing dwell/confirmPick, for a
   * pick of a login linked to a provider with known sign-in hosts.
   */
  async start(target: FrameTarget, account: Account): Promise<PickReply> {
    this.stop(target.tabId)
    const generation = this.generations.get(target.tabId)
    const p = account.signIn ? provider(account.signIn.provider) : undefined
    const username = account.signIn?.account
    const site = siteOf(new URL(target.origin).hostname)
    if (!p?.hosts.length || !username || !site || target.frameId !== 0 || !account.urls.some((u) => exactSignInOrigin(u, target.origin)) ||
        this.host.status.state !== "ready" || (await chrome.storage.local.get(SIGNIN_SETTING))[SIGNIN_SETTING] !== true) return { ok: true }
    if (generation !== this.generations.get(target.tabId) || this.host.status.state !== "ready") return { ok: true }
    const s: Chain = { id: crypto.randomUUID(), home: target, site, tab: target.tabId, provider: p, username,
      phase: "entry", until: Date.now() + PROVIDER_CHAIN_TTL_MS, actions: 0, busy: false, again: false,
      used: new Set(), filled: new Set(), stop: new AbortController() }
    this.chains.add(s)
    s.timer = setTimeout(() => this.end(s), PROVIDER_CHAIN_TTL_MS)
    this.linked.start(target.tabId, { provider: p.id, account: username }, site)
    await this.advance(s, target)
    // Ambiguity is a quiet handoff, not an error in the old account menu.
    return { ok: true }
  }

  async check(sender: chrome.runtime.MessageSender) {
    const s = sender.tab?.id === undefined ? undefined : this.chain(sender.tab.id)
    if (!s) return
    const target = await targetFor(sender)
    if (target?.frameId === 0 && target.tabId === s.tab) await this.advance(s, target)
  }
  private async checkTop(s: Chain) {
    const { target } = await topTarget(s.tab)
    if (target) await this.advance(s, target)
  }

  private async advance(s: Chain, target: FrameTarget) {
    if (!this.live(s)) return this.end(s)
    if (s.busy) { s.again = true; return }
    s.busy = true
    try {
      if (!await this.ready(s) || target.tabId !== s.tab || !this.allowed(s, target.origin)) return this.end(s)
      if (s.phase === "entry" && (target.origin !== s.home.origin || target.documentId !== s.home.documentId)) return this.end(s)
      if (s.phase === "provider" && !isProviderPage(s.provider, target.origin)) return this.end(s)
      if (s.phase === "return") {
        if (target.origin !== s.home.origin) return this.end(s)
        await sendToFrame(target, { type: "db:provider-status", session: s.id, label: `Signing in with ${s.provider.name}…` })
        const facts = await sendToFrame<AuthReport>(target, { type: "db:auth-probe", fresh: true })
        if (facts && authState(facts) === "signed-in" && !facts.challenge && !facts.uncertain) this.end(s, "Signed in")
        else if (facts && (facts.loginForm || facts.challenge || facts.entry)) this.end(s)
        return
      }
      await sendToFrame(target, { type: "db:provider-status", session: s.id, label: `Signing in with ${s.provider.name}…` })
      if (!await this.ready(s)) return this.end(s)
      const report = await sendToFrame<ProviderReport>(target, { type: "db:provider-probe", session: s.id, provider: s.provider.id, site: s.site,
        ...(s.phase === "entry" ? { entry: true } : { account: s.username }) })
      if (!this.live(s)) return
      // An acknowledged click can unload its document before a queued scan's
      // probe answers. It grants no further action; the next committed page
      // must supply its own report. Explicit unknown/consent still ends now.
      if (!report && [...s.used].some((key) => key.startsWith(`${target.documentId}:`))) return
      if (!report || report.kind === "stop") return this.end(s, NEEDS[report?.reason ?? "unknown"])
      if (report.kind === "success") { if (target.origin === s.home.origin) this.end(s, "Signed in"); return }
      if (!report.action) return this.end(s)
      const key = `${target.documentId}:${report.kind}:${report.form ?? ""}`
      if (s.used.has(key) || s.passkeyDocument === target.documentId) return
      if (s.phase === "provider" && (report.kind === "form" || report.kind === "passkey") && await this.passkeys.resumeAutomatic(target)) return
      if (!this.live(s) || s.passkeyDocument === target.documentId) return
      let values: FillValues | undefined
      if (report.kind === "form") {
        if (s.phase !== "provider") return this.end(s)
        const roles = report.roles ?? []
        if (!roles.length || roles.some((r) => ![...IDENTIFIER_ROLES, "password", "otp"].includes(r)) ||
            roles.some((r) => s.filled.has(r) && (!IDENTIFIER_ROLES.includes(r) || s.filled.has("password")))) return this.end(s)
        const accounts = (await this.host.send({ type: "list", origin: target.origin })).accounts
        const matches = namedBy(accounts, s.username).filter((a) => (!s.ref || a.ref === s.ref) && a.urls.some((u) => exactSignInOrigin(u, target.origin)))
        if (matches.length !== 1) return this.end(s)
        const account = matches[0]
        if (roles.includes("password") && !account.hasPassword || roles.includes("otp") && (!account.hasTotp || (await flowFor(siteOf(new URL(target.origin).hostname)!))?.code !== true)) return this.end(s)
        s.ref = account.ref
        const want = wantFor(roles, account)
        if (!want.length || !await this.ready(s)) return this.end(s)
        s.filling = true
        const reply = await this.host.send({ type: "fill", origin: target.origin, ref: account.ref, want }, { signal: s.stop.signal })
        values = { ...(want.includes("username") ? { username: reply.username } : {}), ...(want.includes("password") ? { password: reply.password } : {}), ...(want.includes("totp") ? { totp: reply.totp } : {}) }
        if (want.some((w) => !values?.[w])) return this.end(s)
      } else if (report.kind === "passkey") {
        if (s.phase !== "provider" || !this.host.capabilities.includes("passkeys")) return this.end(s)
        const listed = await this.host.send({ type: "passkey-list", origin: target.origin })
        if (listed.passkeys.filter((k) => this.sameAccount(k.username, s.username)).length !== 1) return this.end(s)
      } else if (report.kind !== (s.phase === "entry" ? "entry" : "chooser")) return this.end(s)
      if (!await this.ready(s) || s.passkeyDocument === target.documentId || !this.consume(s)) return
      s.used.add(key)
      if (s.phase === "entry") s.opening = Date.now()
      const acted = await sendToFrame<boolean>(target, { type: "db:provider-act", session: s.id, action: report.action, ...(values ? { values } : {}) })
      if (!this.live(s)) return
      if (!acted) return this.end(s)
      for (const role of report.roles ?? []) s.filled.add(role)
    } catch { this.end(s) }
    finally {
      s.filling = false
      s.busy = false
      if (s.again && this.live(s)) { s.again = false; void this.checkTop(s) }
    }
  }

  private sameAccount(a: string | undefined, b: string) { return !!a && a.trim().toLowerCase() === b.trim().toLowerCase() }
  private async passkey(target: FrameTarget, keys: Passkey[], optional = false) {
    const s = this.chain(target.tabId)
    if (!s) return undefined
    if (!this.ownsProvider(s, target)) return undefined
    if (optional && !keys.some((k) => this.sameAccount(k.username, s.username))) return undefined
    if (!keys.length) { this.end(s); return null }
    if (s.passkeyDocument === target.documentId) return null
    if (!await this.ready(s)) { this.end(s); return null }
    if (s.filling) { this.end(s); return null }
    await sendToFrame(target, { type: "db:provider-status", session: s.id, label: `Signing in with ${s.provider.name}…` })
    const report = await sendToFrame<ProviderReport>(target, { type: "db:provider-probe", session: s.id, provider: s.provider.id, site: s.site, account: s.username })
    const matches = keys.filter((k) => this.sameAccount(k.username, s.username))
    if (optional && report?.kind === "chooser") return undefined
    if (!report || !["form", "passkey"].includes(report.kind) || matches.length !== 1 || !await this.ready(s)) { this.end(s); return null }
    if (s.passkeyDocument === target.documentId) return null
    if (s.filling || !this.consume(s)) { this.end(s); return null }
    s.passkeyDocument = target.documentId
    return { ref: matches[0].ref, signal: s.stop.signal }
  }

  /** Browser-owned popup provenance, only during the one provider-button action. */
  async opened(d: { sourceTabId: number; sourceFrameId: number; tabId: number }) {
    const s = this.chain(d.sourceTabId)
    if (!s || s.home.tabId !== d.sourceTabId || d.sourceFrameId !== 0 || s.phase !== "entry" || s.popupClaimed || !s.opening || Date.now() - s.opening > 5000) return
    s.popupClaimed = true
    const { target } = await topTarget(d.sourceTabId)
    if (!this.live(s) || target?.documentId !== s.home.documentId || target.origin !== s.home.origin) return this.end(s)
    s.popup = d.tabId
    s.tab = d.tabId
    s.phase = "provider"
    this.linked.opened(d.sourceTabId, d.tabId)
    // The first committed document may have arrived while provenance was checked.
    const current = await topTarget(d.tabId)
    if (current.target && (!isProviderPage(s.provider, current.target.origin) || !current.url || !this.step(s, current.url.href))) return this.end(s)
    s.documentId = current.target?.documentId
    // A content-script scan / DOMContentLoaded drives the first action, not an about:blank popup.
  }

  navigated(d: { tabId: number; frameId: number; url: string; documentId?: string; transitionType?: string; transitionQualifiers?: string[] }) {
    const s = this.chain(d.tabId)
    if (!s || d.frameId !== 0) return
    let origin: string
    try { origin = new URL(d.url).origin } catch { return this.end(s) }
    if (UNRELATED.has(d.transitionType ?? "") || d.transitionQualifiers?.includes("forward_back") || !this.allowed(s, origin)) return this.end(s)
    if (d.tabId !== s.tab) {
      if (origin !== s.home.origin) this.end(s)
      return
    }
    if (isProviderPage(s.provider, origin)) {
      // Off the provider's sign-in pages, or sending the person anywhere but home: stop, untouched.
      if (!this.step(s, d.url)) return this.end(s)
      s.phase = "provider"
      s.documentId = d.documentId
    }
    else if (s.phase === "provider" && origin === s.home.origin) s.phase = "return"
    else if (s.phase === "entry") this.end(s)
  }

  async loaded(d: { tabId: number; frameId: number }) {
    const s = this.chain(d.tabId)
    if (s && d.frameId === 0 && d.tabId === s.tab) await this.checkTop(s)
  }
  async closed(tab: number) {
    this.generations.delete(tab)
    const s = this.chain(tab)
    if (!s) return
    if (tab === s.home.tabId) return this.end(s)
    s.tab = s.home.tabId
    s.phase = "return"
    await this.checkTop(s)
  }
  /** Existing outcome judge may confirm the destination, never the provider. */
  async signedIn(tab: number) {
    const s = this.chain(tab)
    if (!s || tab !== s.home.tabId || s.phase !== "return") return
    const { target } = await topTarget(tab)
    if (target?.origin === s.home.origin && this.live(s)) this.end(s, "Signed in")
  }
}
