// Background side of passkeys: answers the page's navigator.credentials calls
// (relayed by content/passkeys.ts from passkey-hook.ts) with Deadbolt's
// passkeys, or hands them back to the browser's own WebAuthn. Frame and rpId
// checks and the conditional (autofill) flow are ported from Foyer
// (github.com/R44VC0RP/foyer, src/autofill/vault.ts, by Ryan Vogel).
//
// The page supplies only its options. The origin is the browser's record of
// the sender, and the agent builds the client data from it and checks the
// rpId again (docs/autofill.md). The user answers in browser UI the page
// can't reach: the toolbar popup for a modal call, the inline menu for an
// autofill one.

import type { FieldRole, HookReply, MenuPasskey, PasskeyChoice, PasskeyPrompt, PickReply, ToBackground } from "../messages"
import { IDENTIFIER_ROLES } from "../messages"
import { isB64url, isRef, type Passkey, type PasskeysReply, type UserVerification, type ReplyFor } from "../protocol"
import { frameChain, fromExtensionPage, newToken, sameSiteTop, type FrameTarget } from "./frames"
import { HostError, type VaultBackend, type ReauthBody } from "./backend"
import { openPopupFor } from "./save"
import { fillableOrigin, senderOrigin, siteOf } from "./site"

/** ES256, the only algorithm the agent signs with. */
const ES256 = -7
const TIMEOUT = { default: 5 * 60_000, min: 60_000, max: 10 * 60_000 }
/** A ceremony waits on Touch ID in the agent. */
const CEREMONY_MS = 5 * 60_000
/** Calls waiting at once in a tab, counted from the moment one arrives. */
const MAX_PER_TAB = 8
/** Each document lists passkeys a few at once, then one a second; calls for the same rpId share one. */
const LIST_BURST = 4
const LIST_EVERY_MS = 1000
const MAX_CHALLENGE = 1366
const MAX_USER_ID = 86
const MAX_USER_NAME = 1024
const MAX_CREDENTIAL_ID = 1364
const MAX_LISTED = 64
const BADGE = "#f02e29"

const NOT_ALLOWED = "The operation either timed out or was not allowed."
const fail = (name: string, message = NOT_ALLOWED): HookReply => ({ error: { name, message } })
const FALLBACK: HookReply = { fallback: true }
/** Thrown once a call has ended (aborted, navigated, closed) to stop its work. */
const GONE = new Error("the call ended")

interface GetOptions {
  kind: "get"
  challenge: string
  rpId?: string
  allow: string[]
  userVerification: UserVerification
  mediation?: string
  timeout: number
}

interface CreateOptions {
  kind: "create"
  challenge: string
  rpId?: string
  user: { id: string; name: string }
  algorithms: number[]
  exclude: string[]
  userVerification: UserVerification
  attachment?: string
  timeout: number
}

/** A page's call, from the moment it arrives until it's answered. */
interface Pending extends FrameTarget {
  key: string
  /** The relying party, once the agent has said. */
  rpId: string
  resolve: (reply: HookReply) => void
  done: boolean
  /** Aborted when the call ends, so a ceremony not yet sent never is. */
  stop: AbortController
  timer?: ReturnType<typeof setTimeout>
  /** The host request id of a running ceremony, which a cancel names. */
  hostId?: number
  /** Shown in the popup, answered by `choose`. */
  prompt?: PasskeyPrompt
  choose?: (choice: PasskeyChoice) => void
  /** An autofill sign-in: the passkeys the inline menu may offer. */
  conditional?: { passkeys: Passkey[]; challenge: string; rpId?: string; userVerification: UserVerification; canVerify: boolean }
  /** An autofill sign-in held in a login frame on another origin of the top page's site (see conditional). */
  framed?: boolean
  automaticSignal?: AbortSignal
  automaticCleanup?: () => void
  automaticOptional?: boolean
  automaticUsed?: boolean
}

const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/

/**
 * The relying party id a page at `page` may use: its host, or a parent of it
 * on the same site (registrable domain under the full Public Suffix List),
 * never a public suffix or an IP address. The agent checks again with the
 * same rule (crates/cli/src/site.rs); this one only saves asking the user.
 */
export function rpIdFor(page: URL, rpId?: string): string | null {
  if (!fillableOrigin(page)) return null
  const host = page.hostname.toLowerCase().replace(/\.$/, "")
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) return null
  const site = siteOf(host)
  if (!site || !DOMAIN.test(site)) return null
  if (rpId === undefined) return host
  const rp = rpId.toLowerCase()
  const within = rp === host || host.endsWith(`.${rp}`)
  return DOMAIN.test(rp) && within && siteOf(rp) === site ? rp : null
}

const verification = (v: unknown): UserVerification => (v === "required" || v === "discouraged" ? v : "preferred")
const timeout = (v: unknown) => Math.min(Math.max(typeof v === "number" && Number.isFinite(v) ? v : TIMEOUT.default, TIMEOUT.min), TIMEOUT.max)
/** A credential list, whole: null (the browser's) if it's too long or any entry isn't a credential id. */
const ids = (v: unknown): string[] | null => {
  if (v === undefined) return []
  if (!Array.isArray(v) || v.length > MAX_LISTED || !v.every((id) => isB64url(id, MAX_CREDENTIAL_ID))) return null
  return v
}
const optional = (v: unknown) => (typeof v === "string" ? v : undefined)

/** The hook's serialized options, if they're whole; anything else is the browser's to refuse. */
export function parseOptions(kind: "get" | "create", raw: unknown): GetOptions | CreateOptions | null {
  if (typeof raw !== "object" || raw === null) return null
  const o = raw as Record<string, any>
  if (!isB64url(o.challenge, MAX_CHALLENGE)) return null
  if (o.rpId !== undefined && typeof o.rpId !== "string") return null
  const common = { challenge: o.challenge, rpId: optional(o.rpId), userVerification: verification(o.userVerification), timeout: timeout(o.timeout) }
  if (kind === "get") {
    const allow = ids(o.allow)
    return allow && { kind, ...common, allow, mediation: optional(o.mediation) }
  }
  const user = o.user ?? {}
  if (!isB64url(user.id, MAX_USER_ID) || typeof user.name !== "string" || new TextEncoder().encode(user.name).length > MAX_USER_NAME) return null
  // Every algorithm the site lists, or none (the default, ES256 among them).
  const algorithms = Array.isArray(o.algorithms) && o.algorithms.length <= MAX_LISTED && o.algorithms.every((a: unknown) => typeof a === "number") ? (o.algorithms as number[]) : null
  const exclude = ids(o.exclude)
  return exclude && algorithms && { kind, ...common, user: { id: user.id, name: user.name }, algorithms, exclude, attachment: optional(o.attachment) }
}

export interface PasskeyOptions {
  /** Opens the toolbar popup over the tab while `current` holds. */
  openPopup?: (tabId: number, current: () => boolean) => Promise<void>
  /** Whether the tab's badge is still needed for something else (a save offer). */
  keepBadge?: (tabId: number) => boolean
  now?: () => number
}

/** One document's listings: a token bucket, and the lists in flight by rpId (or its logins). */
interface Lister {
  tokens: number
  at: number
  inflight: Map<string, Promise<unknown>>
}

export class Passkeys {
  /** Only the guarded provider chain supplies this one-ceremony authority. */
  automatic?: (target: FrameTarget, keys: Passkey[], optional?: boolean) => Promise<{ ref: string; signal: AbortSignal } | null | undefined>
  automaticSession?: (target: FrameTarget) => AbortSignal | undefined
  private pending = new Map<string, Pending>()
  private lists = new Map<string, Lister>()
  private openPopup: NonNullable<PasskeyOptions["openPopup"]>
  private keepBadge: NonNullable<PasskeyOptions["keepBadge"]>
  private now: () => number

  constructor(
    private host: VaultBackend,
    options: PasskeyOptions = {},
  ) {
    this.openPopup = options.openPopup ?? openPopupFor
    this.keepBadge = options.keepBadge ?? (() => false)
    this.now = options.now ?? Date.now
  }

  listen() {
    chrome.runtime.onMessage.addListener((message: ToBackground, sender, respond) => {
      if (typeof message?.type !== "string" || !message.type.startsWith("pk:")) return
      this.handle(message, sender).then(
        (reply) => respond(reply ?? null),
        () => respond(null),
      )
      return true
    })
    chrome.webNavigation.onCommitted.addListener((d) => this.navigated(d))
    chrome.tabs.onRemoved.addListener((tabId) => this.forgetTab(tabId))
  }

  async handle(message: ToBackground, sender: chrome.runtime.MessageSender): Promise<unknown> {
    switch (message.type) {
      case "pk:get":
      case "pk:create":
        return this.request(message.type === "pk:get" ? "get" : "create", sender, message.request, message.options, message.allowed)
      case "pk:cancel":
        return this.cancelFrom(sender, message.request)
      case "pk:popup-choose":
        return fromExtensionPage(sender, "popup.html") ? this.choose(message.tabId, String(message.id), message.choice) : { ok: false }
    }
  }

  /**
   * The frame a passkey call came from, by the browser's record of the
   * sender. A sandboxed or opaque frame (origin "null") is refused, as
   * WebAuthn refuses it.
   */
  private frameOf(sender: chrome.runtime.MessageSender): FrameTarget | HookReply {
    const tabId = sender.tab?.id
    if (tabId === undefined || sender.tab?.incognito || sender.id !== chrome.runtime.id || !sender.documentId) return FALLBACK
    if (sender.origin === "null") return fail("NotAllowedError", "Deadbolt offers no passkeys to sandboxed frames.")
    const url = senderOrigin(sender)
    if (!url || !fillableOrigin(url)) return FALLBACK
    return { tabId, frameId: sender.frameId ?? 0, documentId: sender.documentId, origin: url.origin }
  }

  /**
   * Whether `p` is still its frame's document, and it and every frame above
   * it are on its origin. Anywhere else the call is cross-origin, which the
   * browser's own flow handles with the policy that delegates it.
   */
  private async sameOrigin(p: FrameTarget): Promise<boolean> {
    const chain = await frameChain(p)
    return !!chain && chain.every((f) => f.origin === p.origin)
  }

  /**
   * A page's navigator.credentials call. `allowed` is the frame's
   * Permissions Policy for it, read by its content script; where that
   * doesn't allow the call, the browser's own flow refuses it. The call
   * holds its tab's slot from here, before anything is awaited, so an abort,
   * a navigation or a closed tab ends it at any step.
   */
  async request(kind: "get" | "create", sender: chrome.runtime.MessageSender, request: unknown, raw: unknown, allowed?: unknown): Promise<HookReply> {
    if (!Number.isSafeInteger(request)) return FALLBACK
    const frame = this.frameOf(sender)
    if (!("tabId" in frame)) return frame
    if (allowed !== true) return FALLBACK
    const key = `${frame.documentId}:${request}`
    if (this.pending.has(key) || [...this.pending.values()].filter((p) => p.tabId === frame.tabId).length >= MAX_PER_TAB) return fail("NotAllowedError")
    return new Promise<HookReply>((resolve) => {
      const p: Pending = { ...frame, key, rpId: "", resolve, done: false, stop: new AbortController() }
      this.pending.set(key, p)
      void this.start(p, kind, raw).then(
        (reply) => this.deliver(p, reply),
        (err) => this.finish(p, err === GONE ? fail("NotAllowedError") : errorReply(err)),
      )
    })
  }

  private async start(p: Pending, kind: "get" | "create", raw: unknown): Promise<HookReply> {
    const options = parseOptions(kind, raw)
    if (!options) return FALLBACK
    const conditional = options.kind === "get" && options.mediation === "conditional"
    p.automaticOptional = conditional
    const automatic = !conditional && this.automaticSession?.(p)
    if (automatic) this.bindAutomatic(p, automatic)
    const same = await this.sameOrigin(p)
    this.live(p)
    if (p.automaticSignal && options.kind === "create") return fail("NotAllowedError")
    // Off one origin all the way up, only a login frame's autofill sign-in is Deadbolt's (see conditional).
    if (!same && !(conditional && (await sameSiteTop(p)))) return FALLBACK
    this.live(p)
    p.framed = !same
    if (!rpIdFor(new URL(p.origin), options.rpId)) return fail("SecurityError", "This relying party ID isn't this site's.")
    if (options.kind === "create") {
      // The agent makes ES256 passkeys only, and is a platform authenticator.
      if ((options.algorithms.length && !options.algorithms.includes(ES256)) || options.attachment === "cross-platform") return FALLBACK
    } else if (options.mediation === "silent") return FALLBACK

    await this.host.connect()
    this.live(p)
    // Locked or not running: Deadbolt has no menu to offer, and the browser's dropdown covers nothing.
    if (this.host.status.state !== "ready") return FALLBACK
    if (options.kind === "get" && conditional) return this.conditional(p, options)
    if (!this.host.capabilities.includes("passkeys")) return FALLBACK
    const listed = await this.passkeysFor(p, options.rpId)
    if (!("passkeys" in listed)) return listed
    // Without Touch ID the agent can't verify the user; the browser may.
    if (options.userVerification === "required" && !listed.canVerify) {
      // A chain must hand off, not open an unsolicited browser-device fallback.
      if (options.kind === "get" && await this.automatic?.(p, []) !== undefined) return fail("NotAllowedError")
      return FALLBACK
    }
    p.rpId = listed.rpId
    if (options.kind === "get") {
      const keys = options.allow.length ? listed.passkeys.filter((k) => options.allow.includes(k.credentialId)) : listed.passkeys
      const automatic = await this.automaticGet(p, keys, options, listed.canVerify)
      if (automatic !== undefined) return automatic
    }
    return options.kind === "create" ? this.create(p, options, listed) : this.get(p, options, listed)
  }

  /** The site's passkeys for `p`, or how its call ends without them. */
  private async passkeysFor(p: Pending, rpId: string | undefined): Promise<PasskeysReply | HookReply> {
    const listing = this.list(p, rpId ?? "", () => this.host.send({ type: "passkey-list", origin: p.origin, rpId }))
    if (!listing) return fail("NotAllowedError")
    let listed: PasskeysReply
    try {
      listed = await listing
    } catch (err) {
      if (err instanceof HostError && err.code === "domain_mismatch") return fail("SecurityError", "This relying party ID isn't this site's.")
      if (err instanceof HostError && err.code === "rate_limited") return fail("NotAllowedError")
      return FALLBACK
    }
    this.live(p)
    return listed
  }

  /**
   * An autofill sign-in (mediation "conditional"), on the top page or in a
   * login frame (see sameSiteTop): where Deadbolt's inline menu opens on the
   * page's login fields. The browser draws its own autofill dropdown (other
   * providers' passkeys, such as Apple Passwords') in browser UI, above
   * anything a page or an extension shows, so whenever Deadbolt has
   * something for the site it holds the call and the browser never gets it.
   * The menu offers its passkeys beside the logins: picking a passkey
   * answers the call, picking a login fills and leaves it waiting, as the
   * browser's own does. With neither, the browser's dropdown shows instead.
   * The site's modal sign-in (its "Sign in with a passkey" button) still
   * reaches the browser's sheet and every other provider whenever Deadbolt
   * has no passkey for it (docs/autofill.md, Passkeys).
   *
   * In a login frame on another origin of the site (Apple's sign-in frame
   * in App Store Connect), the client data the agent signs, never
   * crossOrigin, wouldn't be true: the call is held for the logins alone.
   */
  private async conditional(p: Pending, o: GetOptions): Promise<HookReply> {
    let passkeys: Passkey[] = []
    let canVerify = false
    if (!p.framed && this.host.capabilities.includes("passkeys")) {
      const listed = await this.passkeysFor(p, o.rpId)
      if (!("passkeys" in listed)) return listed
      p.rpId = listed.rpId
      canVerify = listed.canVerify
      // Without Touch ID the agent can't verify the user. A nonempty allow list names the only passkeys the site takes.
      if (o.userVerification !== "required" || listed.canVerify) passkeys = o.allow.length ? listed.passkeys.filter((k) => o.allow.includes(k.credentialId)) : listed.passkeys
    }
    const automatic = await this.automaticGet(p, passkeys, o, canVerify, true)
    if (automatic !== undefined) return automatic
    if (!passkeys.length && !(await this.hasLogins(p))) return FALLBACK
    // One autofill sign-in per document; a newer one replaces it.
    for (const other of this.pending.values()) if (other !== p && other.conditional && other.documentId === p.documentId) this.finish(other, fail("NotAllowedError"))
    p.conditional = { passkeys, challenge: o.challenge, rpId: o.rpId, userVerification: o.userVerification, canVerify }
    // Answered by menuPick, or ended by a cancel or navigation.
    return new Promise<HookReply>(() => {})
  }

  /** Whether Deadbolt has logins for `p`'s origin, which its inline menu offers. */
  private async hasLogins(p: Pending): Promise<boolean> {
    const listed = await this.list(p, " logins", () => this.host.send({ type: "list", origin: p.origin }))?.catch(() => null)
    this.live(p)
    return !!listed?.accounts.length
  }

  /**
   * One listing for `p`'s document. Calls for the same `key` (an rpId, or
   * " logins", which no rpId is) while one is listing share it; past the
   * document's burst, null.
   */
  private list<T>(p: Pending, key: string, send: () => Promise<T>): Promise<T> | null {
    const now = this.now()
    for (const [doc, l] of this.lists) if (!l.inflight.size && now - l.at >= LIST_BURST * LIST_EVERY_MS) this.lists.delete(doc)
    let l = this.lists.get(p.documentId)
    if (!l) this.lists.set(p.documentId, (l = { tokens: LIST_BURST, at: now, inflight: new Map() }))
    const lister = l
    const shared = lister.inflight.get(key)
    if (shared) return shared as Promise<T>
    const earned = Math.floor((now - lister.at) / LIST_EVERY_MS)
    if (earned > 0) {
      lister.tokens = Math.min(LIST_BURST, lister.tokens + earned)
      lister.at = lister.tokens === LIST_BURST ? now : lister.at + earned * LIST_EVERY_MS
    }
    if (lister.tokens === 0) return null
    lister.tokens--
    const listing = send().finally(() => lister.inflight.delete(key))
    lister.inflight.set(key, listing)
    return listing
  }

  /** Stops work on a call that has ended. */
  private live(p: Pending) {
    if (p.done) throw GONE
  }

  /** Before asking the user or the agent: the call is still live, in the same document, on the same origin all the way up. */
  private async ready(p: Pending) {
    this.live(p)
    const same = await this.sameOrigin(p)
    this.live(p)
    if (!same) {
      this.finish(p, fail("NotAllowedError"))
      throw GONE
    }
  }

  private async create(p: Pending, o: CreateOptions, listed: PasskeysReply): Promise<HookReply> {
    const registered = listed.passkeys.some((k) => o.exclude.includes(k.credentialId))
    // The worker's own preset, as it listed: the prompt's note is what the ceremony then asks.
    const passphrase = o.userVerification !== "discouraged" && listed.asksPassphrase === true
    const choice = await this.ask(p, { id: newToken(), kind: "create", rpId: p.rpId, verify: listed.canVerify && o.userVerification !== "discouraged", passphrase, username: o.user.name, registered }, o.timeout)
    if (choice.action === "fallback") return FALLBACK
    if (registered && choice.action !== "cancel") return fail("InvalidStateError", "A passkey for this account is already saved.")
    if (choice.action !== "save") return fail(registered ? "InvalidStateError" : "NotAllowedError")
    await this.ready(p)
    const made = await this.ceremony(p,
      { type: "passkey-create", origin: p.origin, rpId: o.rpId, challenge: o.challenge, user: o.user, exclude: o.exclude, userVerification: o.userVerification },
      o.user.name,
    )
    const { credentialId, clientDataJSON, attestationObject, authenticatorData, publicKey } = made
    return { credential: { credentialId, clientDataJSON, attestationObject, authenticatorData, publicKey } }
  }

  private async get(p: Pending, o: GetOptions, listed: PasskeysReply): Promise<HookReply> {
    // A nonempty allow list names the only passkeys the site takes.
    const passkeys = o.allow.length ? listed.passkeys.filter((k) => o.allow.includes(k.credentialId)) : listed.passkeys
    if (!passkeys.length) return FALLBACK
    const verify = listed.canVerify && o.userVerification !== "discouraged"
    const passphrase = o.userVerification !== "discouraged" && listed.asksPassphrase === true
    const choice = await this.ask(p, { id: newToken(), kind: "get", rpId: p.rpId, verify, passphrase, passkeys: passkeys.map(({ ref, vault, username, created }) => ({ ref, vault, username, created })) }, o.timeout)
    if (choice.action === "fallback") return FALLBACK
    const passkey = choice.action === "use" ? passkeys.find((k) => k.ref === choice.ref) : undefined
    if (!passkey) return fail("NotAllowedError")
    return this.assert(p, passkey, o.challenge, o.rpId, o.userVerification)
  }

  private async assert(p: Pending, passkey: Passkey, challenge: string, rpId: string | undefined, userVerification: UserVerification): Promise<HookReply> {
    await this.ready(p)
    const signed = await this.ceremony(p,
      { type: "passkey-get", origin: p.origin, rpId, ref: passkey.ref, challenge, userVerification },
      passkey.username ?? "Passkey",
    )
    if (signed.credentialId !== passkey.credentialId) return fail("NotAllowedError")
    const { credentialId, clientDataJSON, authenticatorData, signature, userHandle } = signed
    return { credential: { credentialId, clientDataJSON, authenticatorData, signature, userHandle } }
  }

  /** The native agent verifies there; standalone Strict asks in extension UI. */
  private async ceremony<T extends "passkey-create" | "passkey-get">(p: Pending, body: Extract<ReauthBody, { type: T }>, title: string): Promise<ReplyFor[T]> {
    try {
      return await this.host.send(body, { timeout: CEREMONY_MS, onId: (id) => (p.hostId = id), signal: p.stop.signal })
    } catch (error) {
      if (!(error instanceof HostError) || error.code !== "passphrase_needed" || !this.host.reauth) throw error
      await this.ready(p)
      return this.host.reauth(body, { tabId: p.tabId, title, site: p.rpId }, p.stop.signal)
    }
  }

  /**
   * Puts `prompt` in the toolbar popup for the tab and waits for the user's
   * answer. One prompt per tab at a time, as the browser's own dialog.
   */
  private async ask(p: Pending, prompt: PasskeyPrompt, ms: number): Promise<PasskeyChoice> {
    await this.ready(p)
    if ([...this.pending.values()].some((other) => other !== p && other.tabId === p.tabId && other.prompt)) return { action: "cancel" }
    return new Promise<PasskeyChoice>((resolve) => {
      p.prompt = prompt
      p.choose = (choice) => {
        p.prompt = undefined
        p.choose = undefined
        this.unbadge(p.tabId)
        resolve(choice)
      }
      p.timer = setTimeout(() => this.finish(p, fail("NotAllowedError")), ms)
      void Promise.all([chrome.action.setBadgeBackgroundColor({ tabId: p.tabId, color: BADGE }), chrome.action.setBadgeText({ tabId: p.tabId, text: "1" })]).catch(() => {})
      void this.openPopup(p.tabId, () => p.prompt?.id === prompt.id)
    })
  }

  private unbadge(tabId: number) {
    if (this.keepBadge(tabId) || [...this.pending.values()].some((p) => p.tabId === tabId && p.prompt)) return
    void chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {})
  }

  /**
   * Answers the page with what the agent made, if the call is still live in
   * the same document and the client data is what was asked for: this
   * origin, never cross-origin. Whether the credential went.
   */
  private async deliver(p: Pending, reply: HookReply): Promise<boolean> {
    if (p.done) return false
    if (p.automaticSignal?.aborted) { this.finish(p, fail("NotAllowedError")); return false }
    if (!("credential" in reply)) {
      this.finish(p, reply)
      return false
    }
    const kind = "attestationObject" in reply.credential ? "webauthn.create" : "webauthn.get"
    const data = clientData(reply.credential.clientDataJSON)
    const fits = data?.type === kind && data.origin === p.origin && data.crossOrigin === false && !("topOrigin" in data)
    if (!fits || !(await this.sameOrigin(p)) || p.done) {
      this.finish(p, fail("NotAllowedError"))
      return false
    }
    this.finish(p, reply)
    return true
  }

  /** Answers the page once; a running ceremony is cancelled, which dismisses Touch ID. */
  private finish(p: Pending, reply: HookReply) {
    if (p.done) return
    p.done = true
    p.automaticCleanup?.()
    if (p.automaticSignal && !("credential" in reply)) {
      reply = fail("NotAllowedError")
      if (!p.automaticSignal.aborted && (!p.automaticOptional || p.automaticUsed)) void this.automatic?.(p, []).catch(() => {})
    }
    p.stop.abort()
    this.pending.delete(p.key)
    clearTimeout(p.timer)
    // Lets a waiting prompt unwind; its answer comes too late to matter.
    p.choose?.({ action: "cancel" })
    if (p.hostId !== undefined && "error" in reply) void this.host.send({ type: "passkey-cancel", request: p.hostId }).catch(() => {})
    p.resolve(reply)
  }

  /** The page aborted its call (AbortSignal). */
  cancelFrom(sender: chrome.runtime.MessageSender, request: unknown): boolean {
    const p = this.pending.get(`${sender.documentId}:${request}`)
    if (!p || p.tabId !== sender.tab?.id) return false
    this.finish(p, fail("AbortError", "The operation was aborted."))
    return true
  }

  /**
   * A frame committed a new document: calls from the old one (and, for the
   * top frame, from every frame) end. A frame's navigation also removes the
   * frames inside it, so the tab's other calls are checked again.
   */
  navigated(d: { tabId: number; frameId: number; documentId?: string }) {
    for (const p of [...this.pending.values()]) {
      if (p.tabId !== d.tabId) continue
      if ((d.frameId === 0 || p.frameId === d.frameId) && p.documentId !== d.documentId) this.finish(p, fail("NotAllowedError"))
      else void this.stillPlaced(p).then((ok) => ok || this.finish(p, fail("NotAllowedError")))
    }
  }

  /** Whether `p`'s frame is still where its call may be Deadbolt's: one origin all the way up, or, held in a login frame, one site. */
  private stillPlaced(p: Pending): Promise<boolean> {
    return p.framed ? sameSiteTop(p).then(Boolean) : this.sameOrigin(p)
  }

  forgetTab(tabId: number) {
    for (const p of [...this.pending.values()]) if (p.tabId === tabId) this.finish(p, fail("NotAllowedError"))
  }

  /** The passkey prompt waiting in this tab, for the popup. */
  prompt(tabId: number): PasskeyPrompt | undefined {
    for (const p of this.pending.values()) if (p.tabId === tabId && p.prompt) return p.prompt
    return undefined
  }

  private bindAutomatic(p: Pending, signal: AbortSignal) {
    if (p.automaticSignal === signal) return
    p.automaticCleanup?.()
    p.automaticSignal = signal
    const cancel = () => this.finish(p, fail("NotAllowedError"))
    signal.addEventListener("abort", cancel, { once: true })
    p.automaticCleanup = () => signal.removeEventListener("abort", cancel)
    if (signal.aborted) cancel()
  }

  /**
   * Reuses all existing RP, allow-list, UV and Strict ceremony checks. A
   * chain's assertion still needs the person: only where the agent verifies
   * them (`canVerify`, and the site doesn't discourage it) does it sign
   * without a prompt. Otherwise a modal call ends the chain quietly and goes
   * on as an ordinary call, to the usual passkey prompt.
   */
  private async automaticGet(p: Pending, keys: Passkey[], o: { challenge: string; rpId?: string; userVerification: UserVerification }, canVerify: boolean, optional = false): Promise<HookReply | undefined> {
    if (!canVerify || o.userVerification === "discouraged") {
      if (!optional && this.automaticSession?.(p)) {
        // Unbound first, so the chain's end doesn't cancel the call itself.
        p.automaticCleanup?.()
        p.automaticSignal = p.automaticCleanup = undefined
        await this.automatic?.(p, [])
      }
      return undefined
    }
    const choice = await this.automatic?.(p, keys, optional)
    if (choice === undefined) return undefined
    if (!choice || choice.signal.aborted) return fail("NotAllowedError")
    const key = keys.find((k) => k.ref === choice.ref)
    if (!key) return fail("NotAllowedError")
    p.automaticUsed = true
    this.bindAutomatic(p, choice.signal)
    this.live(p)
    return this.assert(p, key, o.challenge, o.rpId, o.userVerification)
  }

  /** A conditional call can predate a corner pick on the provider itself. */
  async resumeAutomatic(target: FrameTarget): Promise<boolean> {
    const p = this.conditionalFor(target)
    if (!p?.conditional) return false
    const options = p.conditional
    p.conditional = undefined
    try {
      const reply = await this.automaticGet(p, options.passkeys, options, options.canVerify, true)
      if (reply === undefined) { p.conditional = options; return false }
      await this.deliver(p, reply)
    } catch (err) { this.finish(p, err === GONE ? fail("NotAllowedError") : errorReply(err)) }
    return true
  }

  /** The popup's answer to prompt `id`; any other prompt is untouched. */
  choose(tabId: number, id: string, choice: PasskeyChoice): { ok: boolean } {
    const p = [...this.pending.values()].find((p) => p.tabId === tabId && p.prompt?.id === id)
    const clean = cleanChoice(choice)
    if (!p?.choose || !clean) return { ok: false }
    p.choose(clean)
    return { ok: true }
  }

  /** Passkeys the inline menu on `focused` in this document may offer, for its waiting autofill sign-in. */
  menuPasskeys(target: FrameTarget, focused: FieldRole): MenuPasskey[] {
    if (!(IDENTIFIER_ROLES.includes(focused) || focused === "password")) return []
    const p = this.conditionalFor(target)
    return p?.conditional?.passkeys.map(({ ref, vault, username }) => ({ ref, vault, username })) ?? []
  }

  private conditionalFor(target: FrameTarget): Pending | undefined {
    for (const p of this.pending.values())
      if (p.conditional && p.tabId === target.tabId && p.frameId === target.frameId && p.documentId === target.documentId && p.origin === target.origin) return p
    return undefined
  }

  /**
   * The user picked passkey `ref` in the inline menu of `target` (the menu's
   * own checks passed): sign in with it. Null when `ref` isn't a passkey
   * this document's sign-in is waiting for.
   */
  async menuPick(target: FrameTarget, ref: string): Promise<PickReply | null> {
    const p = this.conditionalFor(target)
    const passkey = p?.conditional?.passkeys.find((k) => k.ref === ref)
    if (!p?.conditional || !passkey) return null
    const { challenge, rpId, userVerification } = p.conditional
    // Used once: a second pick while this one signs gets nothing.
    p.conditional = undefined
    try {
      if (await this.deliver(p, await this.assert(p, passkey, challenge, rpId, userVerification))) return { ok: true }
      return { ok: false, message: "Couldn't sign in with that passkey." }
    } catch (err) {
      this.finish(p, err === GONE ? fail("NotAllowedError") : errorReply(err))
      return { ok: false, message: err instanceof HostError && err.code === "cancelled" ? "Cancelled." : "Couldn't sign in with that passkey." }
    }
  }
}

function cleanChoice(choice: unknown): PasskeyChoice | null {
  const c = choice as PasskeyChoice | null
  if (c?.action === "use") return isRef(c.ref) ? { action: "use", ref: c.ref } : null
  return c?.action === "save" || c?.action === "fallback" || c?.action === "cancel" ? { action: c.action } : null
}

/** The page sees only that it wasn't allowed; Deadbolt's reasons stay here. */
function errorReply(err: unknown): HookReply {
  if (err instanceof HostError && err.code === "domain_mismatch") return fail("SecurityError", "This relying party ID isn't this site's.")
  // A passkey the site excluded was saved meanwhile (from another device, say).
  if (err instanceof HostError && err.code === "exists") return fail("InvalidStateError", "A passkey for this account is already saved.")
  return fail("NotAllowedError")
}

function clientData(b64url: string | undefined): Record<string, unknown> | null {
  try {
    const data = JSON.parse(atob(b64url!.replace(/-/g, "+").replace(/_/g, "/")))
    return typeof data === "object" && data !== null ? data : null
  } catch {
    return null
  }
}
