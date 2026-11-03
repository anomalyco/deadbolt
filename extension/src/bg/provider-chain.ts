// One guarded corner pick, one provider account, one short-lived chain. This
// authority is deliberately memory-only: a restarted worker cannot resume it.
import { authState, exactSignInOrigin, SIGNIN_SETTING, signInEnabled, signInOn, type AuthReport } from "../auth-state"
import { IDENTIFIER_ROLES, type FillValues, type PickReply, type ProviderReport } from "../messages"
import type { Account, Passkey } from "../protocol"
import { isProviderPage, isSignInPage, provider, returnsTo, savedAtProvider, type Provider } from "../signin"
import { flowFor, namedBy, wantFor } from "./autofill"
import type { VaultBackend } from "./backend"
import { sendToFrame, targetFor, topTarget, type FrameTarget } from "./frames"
import type { Passkeys } from "./passkeys"
import { siteOf } from "./site"
import type { SignInWith } from "./signinwith"

export const PROVIDER_CHAIN_TTL_MS = 120_000
export const PROVIDER_CHAIN_ACTIONS = 8
const UNRELATED = new Set(["typed", "auto_bookmark", "generated", "keyword", "keyword_generated", "reload", "start_page", "auto_toplevel"])
const NEEDS = { consent: "Review access", phone: "Approve on your phone", sms: "Enter your code", "security-key": "Use your security key", captcha: "Complete the verification", unknown: "", choose: "Choose your account" }

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
  /**
   * Picked as one of the person's provider accounts on a site with no login
   * for it (an unlinked chain): held to stricter rules (see step, the
   * probe's `home`), and once signed in the site is linked to it (see link).
   */
  link?: string
  /**
   * Where an unlinked chain's provider pages may send the person back: the
   * home host, and any host of the home's site the chain itself saw the
   * site's own navigation or popup pass through on the way to the provider.
   */
  hosts: Set<string>
  /** Actions taken on the provider's own pages (chooser, form, passkey): a link needs one. */
  providerActions: number
  /** The provider sign-in page the chain's tab last committed. */
  lastProviderUrl?: string
  /** The home tab came back from a provider page whose return URL led home, after a provider action: only then is a sign-in linked. */
  returnedHome?: boolean
  /** The chooser document waiting for the person to pick their own tile (an unlinked site's sharing notice). */
  choosing?: string
  /** The person picked on the chooser: the next form must show the account picked, never ask for it. */
  chose?: boolean
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
      if (area === "local" && SIGNIN_SETTING in changes && !signInOn(changes[SIGNIN_SETTING].newValue)) this.endAll()
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
    return this.live(s) && await signInEnabled() && this.live(s)
  }
  private allowed(s: Chain, origin: string) { return origin === s.home.origin || isProviderPage(s.provider, origin) }
  /**
   * A provider page the chain may act on: a sign-in or OAuth path whose
   * return URLs, if any, lead to the home site. An unlinked chain needs
   * one that leads to its home's exact host.
   */
  private step(s: Chain, url: string) {
    if (!isSignInPage(s.provider, url)) return false
    return s.link ? returnsTo(s.provider, url, s.site, [...s.hosts]) === "home" : returnsTo(s.provider, url, s.site) !== "foreign"
  }
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
    // Linked only after a sign-in that went through the provider and came back home from it.
    if (label === "Signed in" && s.link && s.returnedHome) void this.link(s, s.link).catch(() => {})
    for (const tab of new Set([s.home.tabId, s.tab])) void topTarget(tab).then(({ target }) => {
      if (target && this.allowed(s, target.origin)) void sendToFrame(target, { type: "db:provider-status", session: s.id, label, done: true })
    })
  }

  /**
   * Called only for a guarded pick of a login linked to a provider with known
   * sign-in hosts, after the menu frame's dwell and confirmPick: the corner
   * offer's (UniversalSignIn) or the inline menu's (Autofill.menuSignIn).
   * `unlinked`: the corner offer's pick of one of the person's provider
   * accounts on a site with no login for it. That account (`account.ref`,
   * the provider login itself) must then be saved at the provider's own
   * sign-in host instead of the site's exact origin; the chain's home is
   * still the page's exact origin, and the provider steps fill only that login.
   */
  async start(target: FrameTarget, account: Account, unlinked = false): Promise<PickReply> {
    this.stop(target.tabId)
    const generation = this.generations.get(target.tabId)
    const p = account.signIn ? provider(account.signIn.provider) : undefined
    const username = account.signIn?.account
    const site = siteOf(new URL(target.origin).hostname)
    const saved = unlinked ? !!p && account.urls.some((u) => savedAtProvider(p, u)) : account.urls.some((u) => exactSignInOrigin(u, target.origin))
    // A provider account never signs in to a site of the provider's own (gist.github.com, sites.google.com): those pages are the provider's.
    const ownSite = unlinked && !!p && p.hosts.some((h) => siteOf(h) === site)
    if (!p?.hosts.length || !username || !site || target.frameId !== 0 || !saved || ownSite ||
        this.host.status.state !== "ready" || !(await signInEnabled())) return { ok: true }
    if (generation !== this.generations.get(target.tabId) || this.host.status.state !== "ready") return { ok: true }
    const s: Chain = { id: crypto.randomUUID(), home: target, site, hosts: new Set([new URL(target.origin).hostname]), tab: target.tabId, provider: p, username,
      phase: "entry", until: Date.now() + PROVIDER_CHAIN_TTL_MS, actions: 0, providerActions: 0, busy: false, again: false,
      used: new Set(), filled: new Set(), stop: new AbortController(), ...(unlinked ? { ref: account.ref, link: account.ref } : {}) }
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
      // Waiting on the person's own pick in this chooser: nothing more to do here.
      if (s.choosing === target.documentId) return
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
        ...(s.phase === "entry" ? { entry: true } : { account: s.username }), ...(s.link ? { home: [...s.hosts] } : {}) })
      if (!this.live(s)) return
      // An acknowledged click can unload its document before a queued scan's
      // probe answers. It grants no further action; the next committed page
      // must supply its own report. Explicit unknown/consent still ends now.
      if (!report && [...s.used].some((key) => key.startsWith(`${target.documentId}:`))) return
      // An unlinked site's chooser asks the person to share their account
      // with it: that's theirs to agree to. Deadbolt waits for their own
      // pick of a tile and goes on from the page it leads to.
      if (report?.kind === "stop" && report.reason === "choose" && s.link && s.phase === "provider") {
        s.choosing = target.documentId
        s.chose = true
        return void (await sendToFrame(target, { type: "db:provider-status", session: s.id, label: NEEDS.choose, hold: true }))
      }
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
        // After the person's own pick, the account comes from the provider's page: a form asking for it again is someone else's.
        if (s.chose && roles.some((r) => IDENTIFIER_ROLES.includes(r))) return this.end(s)
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
      if (s.phase === "provider") s.providerActions++
      for (const role of report.roles ?? []) s.filled.add(role)
    } catch { this.end(s) }
    finally {
      s.filling = false
      s.busy = false
      if (s.again && this.live(s)) { s.again = false; void this.checkTop(s) }
    }
  }

  /**
   * The site's sign-in through one of the person's provider accounts worked:
   * save a login for the site that signs in with it (`signIn`, no password),
   * so the site lists it as its own next time. Not if one already does.
   */
  private async link(s: Chain, ref: string) {
    const origin = s.home.origin
    const listed = (await this.host.send({ type: "list", origin })).accounts
    if (listed.some((a) => a.signIn?.provider === s.provider.id && this.sameAccount(a.signIn.account, s.username))) return
    await this.host.send({ type: "save", origin, entry: { title: new URL(origin).hostname, url: origin, signIn: { provider: s.provider.id, account: ref } } })
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
    s.providerActions++
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
    s.lastProviderUrl = current.url?.href
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
      s.lastProviderUrl = d.url
      s.choosing = undefined
    }
    else if (s.phase === "provider" && origin === s.home.origin) {
      s.phase = "return"
      // Home again in the chain's own tab, by a navigation off a provider
      // page that sent it here (not a popup coming back or closing).
      const back = s.lastProviderUrl ? returnsTo(s.provider, s.lastProviderUrl, s.site, s.link ? [...s.hosts] : undefined) : "none"
      s.returnedHome = d.tabId === s.home.tabId && s.providerActions > 0 && back === "home"
    }
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
