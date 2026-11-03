// Background side of filling: lists logins for the frame that asked, hands
// the inline menu a one-time token bound to that frame, and fills only into
// that frame after the user picks a login. Token-bound frame targeting is
// ported from Foyer (github.com/R44VC0RP/foyer, src/autofill/service.ts, by
// Ryan Vogel), and so is the start of the sign-in session (its email-first
// continuation), which here follows a login through every step of a sign-in.

import { FIELD_ROLES, GENERATE_KINDS, IDENTIFIER_ROLES, MENU_ROLES, phoneLike, type ToContent, type SignInReply, type Approved, type Box, type FieldRole, type FillAck, type FillValues, type MenuLoadReply, type MenuPasskey, type PickReply, type PopupReply, type QueryReply, type SurfaceKind } from "../messages"
import type { Account, FieldRules, ListReply, Want } from "../protocol"
import { boxesInTop, cleanApproved, cleanBox, LOGIN_FRAME_PLACE, menuFrameOf, newToken, sameSiteTop, sendToFrame, shownInPage, stillShown, targetFor, topTarget, type FrameTarget } from "./frames"
import { HostError, type VaultBackend } from "./backend"
import { isAccountPage, pageAccountOf } from "../signin"
import type { SignInWith } from "./signinwith"
import { siteOf } from "./site"
import { iconKey, iconSettings, storedIcon, type StoredIcon } from "../ui/icon-store"
import { hostHash } from "./site-icons"
import { exactSignInOrigin, SIGNIN_SETTING } from "../auth-state"

const TOKEN_TTL_MS = 2 * 60_000
const LIST_TTL_MS = 30_000
/** A sign-in session lasts this long from the pick that started it. */
export const SESSION_TTL_MS = 3 * 60_000
/** A home/modal entry must reach its first login step promptly, not arm a later task. */
export const AUTOMATIC_ENTRY_MS = 20_000
const MAX_AUTOMATIC_SUBMITS = 4
/** On a site whose steps come by navigation (see Flow), this much longer, for a slow page. */
const SESSION_GRACE_MS = 60_000
/** chrome.storage.local: the shape of each site's sign-in (see Flow), by a salted hash of the site. */
export const FLOWS_KEY = "signinFlows"
const MAX_FLOWS = 300
const NOT_SHOWN = "That login form isn't fully visible. Nothing was filled."
/** Navigations the user started themselves end an email-first sign-in, as does going back or forward (see navigated). */
const UNRELATED = new Set(["typed", "auto_bookmark", "generated", "keyword", "keyword_generated", "reload", "start_page", "auto_toplevel"])

interface MenuToken extends FrameTarget {
  /**
   * For a field in a frame below (see sameSiteTop): the top page, where the
   * menu is. The token itself names the frame, the only one it fills.
   */
  owner?: FrameTarget
  roles: FieldRole[]
  focused: FieldRole
  /** The form snapshot the menu opened on. */
  form: number
  createdAt: number
  /** The menu document that first loaded the token; only it may use it after. */
  menuDocumentId?: string
  /** On a sign-up or change-password form's new-password box: what the page asks of a generated password. */
  generate?: FieldRules
  /** Only these logins: the one the form's username names (see query). */
  only?: string[]
  /** A pill showing that a session's step filled, not a menu: it picks nothing. */
  notice?: { label: string; title: string }
  /** Picked: the menu folds into its pill and resizes it to say how the fill went, but answers nothing more. */
  picked?: boolean
}

/**
 * A sign-in session: the login the user picked, followed through the next
 * steps of the sign-in in the same tab. When the top page, or a frame that
 * may have the inline menu (see sameSiteTop), shows the next step (a
 * password, a one-time code, the username asked again beside a password), it
 * fills from the same login without another pick: once per step, only after
 * the user's own submit (see Autofill.page), only on the origin the pick was
 * on or one whose host a saved URL of the login names exactly, only into a
 * frame whose fields show through every frame above, and only for a few
 * minutes.
 */
interface Session {
  /** Only the opt-in corner offer's guarded pick may enable auto-submit. */
  automatic?: boolean
  /** Submit calls made by this automatic session, carried across its steps. */
  automaticSubmits?: number
  ref: string
  /** The site (registrable domain): leaving it ends the session. */
  site: string
  /** The origin the pick was on. Another origin is a step only if a saved URL of the login names its host. */
  origin: string
  /** The document the last step filled, and when. */
  documentId: string
  filledAt: number
  /** What the session has filled so far. */
  filled: FieldRole[]
  startedAt: number
  until: number
}

/**
 * The shape of a site's sign-in, learned from sign-ins that worked (no
 * usernames, no values): whether it asks for the username on a step of its
 * own first, whether a code step usually follows the password, and whether
 * its steps come by navigation or in the same document.
 */
export interface Flow {
  identifierFirst: boolean
  code: boolean
  navigates: boolean
  /** How many sign-ins it was learned from, how many had a code step, and when it was last. */
  seen: number
  codeSeen: number
  at: number
}

/**
 * What a tab's top page, or one of its login frames (see sameSiteTop), has
 * shown of the current sign-in, to learn its Flow from. Each frame has its
 * own: a top page's identifier and a frame's password box aren't one form's
 * steps.
 */
interface Track {
  site: string
  identifierDoc?: string
  passwordDoc?: string
  otp: boolean
}

/** The login forms each tab's frames last reported. Filling from the popup needs one. */
interface PageReport extends FrameTarget {
  kind: SurfaceKind | null
  roles: FieldRole[]
  form: number
}

export function wantFor(roles: FieldRole[], account: Pick<Account, "hasPassword" | "hasTotp">): Want[] {
  const want: Want[] = []
  if (roles.some((r) => IDENTIFIER_ROLES.includes(r))) want.push("username")
  if (roles.includes("password") && account.hasPassword) want.push("password")
  if (roles.includes("otp") && account.hasTotp) want.push("totp")
  return want
}

/**
 * What the menu offers under a field: on a code field, only logins with a
 * one-time password; on a phone field, only logins whose username is a
 * phone number; on a password field, logins with a password or a
 * "Sign in with …" (which shows as that, never as a fill).
 *
 * A login with no username (a key or a PIN saved as a login, say) can't
 * sign in to a form that asks for one: on a form with a username box
 * (`roles`), it's left out while another login has a username, and
 * anywhere else it comes last.
 */
export function menuAccounts(accounts: Account[], focused: FieldRole, roles: FieldRole[] = []): Account[] {
  if (focused === "otp") return accounts.filter((a) => a.hasTotp)
  // A phone box takes only a phone number: a login saved under an email or a name can't go in it.
  if (focused === "phone") return accounts.filter((a) => phoneLike(a.username))
  const offered = focused === "password" ? accounts.filter((a) => a.hasPassword || a.signIn) : accounts
  // A "Sign in with …" has no username of its own, and isn't one of these.
  const nameless = (a: Account) => !a.signIn && !a.username?.trim()
  const named = offered.filter((a) => !nameless(a))
  if (named.length === offered.length) return offered
  if (named.length && roles.some((r) => IDENTIFIER_ROLES.includes(r))) return named
  return [...named, ...offered.filter(nameless)]
}

/** How many rows the menu shows for these logins: a login with both a password and a sign-in-with has two. */
export const menuRowCount = (accounts: Account[], focused: FieldRole) =>
  accounts.reduce((n, a) => n + (a.signIn ? (a.hasPassword && focused !== "otp" ? 2 : 1) : 1), 0)

/** The step a sign-in session waits for after its fills wrote `filled`, if any. */
export function nextStep(filled: FieldRole[], account: Pick<Account, "hasPassword" | "hasTotp">): "password" | "otp" | undefined {
  if (filled.includes("otp")) return undefined
  if (filled.includes("password")) return account.hasTotp ? "otp" : undefined
  if (filled.some((r) => IDENTIFIER_ROLES.includes(r))) return account.hasPassword ? "password" : account.hasTotp ? "otp" : undefined
  return undefined
}

/**
 * What a step's form should get from the session, given the roles it
 * reported: a password step its password (and the username, if the box for
 * it came back empty beside the password); a code step its code, if the
 * login has one. An identifier on its own isn't a step to fill: empty, it's
 * "Use a different account" (see Autofill.page).
 */
export function stepRoles(roles: FieldRole[], account: Pick<Account, "hasPassword" | "hasTotp">, idEmpty: boolean): FieldRole[] {
  if (roles.includes("password") && account.hasPassword) return ["password", ...(idEmpty ? roles.filter((r) => IDENTIFIER_ROLES.includes(r)) : [])]
  if (roles.includes("otp") && account.hasTotp) return ["otp"]
  return []
}

/**
 * What a sign-in session's step may fill in a form the content script
 * reported, or "end" when the form says the sign-in turned into something
 * else. Only a sign-in step: on a login form, its current password (never
 * when the form also has a new-password box, or a password box asks for a
 * new password by autocomplete, which may be a sign-up the detector took for
 * a login) and the username beside it; on a code step, the code. A sign-up
 * or change-password form ends the session: its password box wants a new
 * password, never the saved one. Anything else, a login form it can't be
 * sure of included, fills nothing; an explicit pick still can.
 */
export function sessionStep(kind: SurfaceKind | null, roles: FieldRole[], asksNew: boolean): FieldRole[] | "end" {
  if (kind === "signup" || kind === "change-password") return "end"
  if (kind === "mfa") return ["otp"]
  if (kind !== "login" || roles.includes("new-password") || asksNew) return []
  return [...IDENTIFIER_ROLES, "password", "otp"]
}

/** The pill's word for a step: what it filled that matters most. */
export function stepLabel(filled: FieldRole[]): string {
  if (filled.includes("otp")) return "Code filled"
  if (filled.includes("password")) return "Password filled"
  return "Filled"
}

/** Logins whose username is exactly `identifier`, ignoring case. */
export function namedBy(accounts: Account[], identifier: string): Account[] {
  const id = identifier.trim().toLowerCase()
  return id ? accounts.filter((a) => a.username?.trim().toLowerCase() === id) : []
}

/** Passkeys a waiting autofill sign-in offers in the inline menu (see bg/passkeys.ts). */
export interface MenuPasskeys {
  menuPasskeys(target: FrameTarget, focused: FieldRole): MenuPasskey[]
  /** Null when `ref` isn't one of them. */
  menuPick(target: FrameTarget, ref: string): Promise<PickReply | null>
}

export class Autofill {
  private tokens = new Map<string, MenuToken>()
  private lists = new Map<string, { at: number; reply: ListReply }>()
  private pages = new Map<number, Map<number, PageReport>>()
  private sessionTimers = new Map<number, ReturnType<typeof setTimeout>>()
  /** What each tab's top page and login frames have shown of its sign-in, by frame, to learn the site's Flow from. */
  private tracks = new Map<number, Map<number, Track>>()
  /** The last time the user themselves submitted a login form in each tab's top page (or same-site login frame), and in which document. */
  private submits = new Map<number, { documentId: string; at: number }>()
  /** Each tab's session work runs one piece at a time, so a step is used once. */
  private queues = new Map<number, Promise<unknown>>()
  /** Bumped when a tab's sign-in session ends; work started before then arms nothing. */
  private cancels = new Map<number, number>()
  /** Sites whose fields already showed the locked row on focus since Deadbolt last locked or unlocked. */
  private lockedShown = new Set<string>()
  private lastState: string
  /** A picked login was filled in `tabId` on `site` (bg/site-icons.ts reads the site's icon then). */
  filled?: (tabId: number, site: string) => void
  /** The document whose locked row was clicked last, to focus again once unlocked. Memory only: a restarted worker returns nowhere. */
  private unlockReturn: MenuToken | null = null

  constructor(
    private host: VaultBackend,
    private passkeys?: MenuPasskeys,
    /** The username the user submitted in this tab on `site`, if any (bg/save.ts holds it). */
    private submittedName?: (tabId: number, site: string) => string | undefined,
    /** Sign-ins with a provider the tab is following (see bg/signinwith.ts). */
    private signInWith?: SignInWith,
  ) {
    this.lastState = host.status.state
    chrome.storage.onChanged?.addListener((changes, area) => {
      if (area === "local" && SIGNIN_SETTING in changes && changes[SIGNIN_SETTING].newValue !== true) void this.stopAllAutomatic()
    })
    host.onChange((status) => {
      this.lists.clear()
      if (status.state !== this.lastState) this.lockedShown.clear()
      this.lastState = status.state
      // Locked or gone: no session goes on, including ones kept from before a service worker restart.
      if (status.state !== "ready") void this.endAll()
    })
  }

  private async list(origin: string, fresh = false): Promise<ListReply> {
    const cached = this.lists.get(origin)
    if (!fresh && cached && Date.now() - cached.at < LIST_TTL_MS) return cached.reply
    const reply = await this.host.send({ type: "list", origin })
    this.lists.set(origin, { at: Date.now(), reply })
    return reply
  }

  /**
   * A menu token, used by the menu frame it was made for. The first load
   * (with `parent`, see menuFrameOf) binds it to that menu document; after
   * that, only that document may use it. A picked token serves only
   * `resize` (its pill's size), and nothing else.
   */
  private async token(token: string, sender: chrome.runtime.MessageSender, parent?: string, resize = false): Promise<MenuToken | undefined> {
    const t = this.tokens.get(token)
    if (!t || Date.now() - t.createdAt > TOKEN_TTL_MS || !sender.documentId || (t.picked && !resize)) return undefined
    if (t.menuDocumentId === undefined) {
      if (parent === undefined || !(await menuFrameOf(sender, t.owner ?? t, parent))) return undefined
      t.menuDocumentId = sender.documentId
    }
    return t.menuDocumentId === sender.documentId && sender.tab?.id === t.tabId ? t : undefined
  }

  private sweep() {
    const now = Date.now()
    for (const [t, v] of this.tokens) if (now - v.createdAt > TOKEN_TTL_MS) this.tokens.delete(t)
  }

  /**
   * The menu for a focused field. `explicit`: the user clicked into it again
   * or pressed ↓. While Deadbolt is locked, a field that was only focused
   * shows the locked row once per site until Deadbolt locks or unlocks again.
   *
   * On a password or code field, the username the sign-in is for (the
   * form's own box, `identifier`, or else the one the user submitted on an
   * earlier step) narrows the menu to the logins it names. When it names
   * none, the user is signing in by hand: no menu, unless they ask with ↓
   * or a second click (`again`).
   *
   * With neither, on a provider's own sign-in page whose page-set account
   * is trusted (`https://accounts.google.com`, see isAccountPage, checked
   * here on the frame's origin, not the content script's word), the account
   * the page shows (`pageAccount`) narrows the menu to the logins it names.
   * Naming none, it's ignored: the whole list shows. It never hides the menu.
   *
   * On a sign-up or change-password form's new-password box (`kind`), the
   * menu offers a generated password within the page's `rules` instead, if
   * the daemon says they allow a strong one.
   *
   * In the top page, the token goes back to the content script, which opens
   * the menu under the field. A field in a frame below gets the menu only
   * when the frame and every frame above it are one site over https (see
   * sameSiteTop): the background opens it in the top page, under where the
   * field shows there (`box`, carried up through every frame and checked on
   * the way, see boxesInTop), lists the frame's own origin's logins and
   * fills only that frame. The frame gets no token. No generated passwords
   * in frames.
   */
  async query(
    sender: chrome.runtime.MessageSender,
    roles: unknown,
    focused: unknown,
    form: unknown,
    explicit = false,
    identifier?: unknown,
    again = false,
    kind?: unknown,
    rules?: unknown,
    pageAccount?: unknown,
    box?: unknown,
  ): Promise<QueryReply> {
    const target = await targetFor(sender)
    const clean = sanitizeRoles(roles)
    if (!target || !Number.isSafeInteger(form) || !MENU_ROLES.includes(focused as FieldRole) || !clean.includes(focused as FieldRole)) return { rows: 0 }
    // A new-password box offers a generated password, and only on sign-up and change-password forms.
    const generating = focused === "new-password"
    if (generating && (target.frameId !== 0 || !GENERATE_KINDS.includes(kind as SurfaceKind))) return { rows: 0 }
    // The menu opens only in the top page (see inline.ts), for a frame's field under where it shows there.
    let owner: FrameTarget | undefined
    let at: Box | undefined
    if (target.frameId !== 0) {
      const own = cleanBox(box)
      const top = own ? await sameSiteTop(target) : null
      const shown = top && own ? await boxesInTop(target, [own], LOGIN_FRAME_PLACE) : null
      if (!top || !shown) return { rows: 0 }
      owner = top
      at = shown[0]
    }
    // In a frame, a sign-in session fills this step itself once the user goes
    // on (see page): a field it waits for doesn't open the list on focus
    // alone (a widget focusing the password box it just opened, say), as that
    // list would keep the step's fields from being measured. A click or ↓
    // still opens it. A top page's list never blocks its step.
    if (!explicit && target.frameId !== 0 && (focused === "password" || focused === "otp")) {
      const s = await this.session(target.tabId)
      if (s && !s.filled.includes(focused) && siteOf(new URL(target.origin).hostname) === s.site) return { rows: 0 }
    }
    await this.host.connect()
    const generate = generating ? fieldRules(rules) : undefined
    const site = siteOf(new URL(target.origin).hostname) ?? target.origin
    let rows = 0
    let only: string[] | undefined
    const state = this.host.status.state
    // Locked or not, the daemon says whether the page's rules allow a strong password: no row if they don't.
    if (generate && (state === "locked" || state === "ready")) rows = await this.host.send({ type: "generate-check", origin: target.origin, ...generate }).then(() => 1, () => 0)
    else if (state === "locked") {
      if (explicit || !this.lockedShown.has(site)) rows = 1
      this.lockedShown.add(site)
    } else if (state === "ready") {
      const reply = await this.list(target.origin).catch(() => null)
      let shown = reply ? menuAccounts(reply.accounts, focused as FieldRole, clean) : []
      const later = focused === "password" || focused === "otp"
      const named = later ? (typeof identifier === "string" && identifier.length <= 500 && identifier.trim()) || this.submittedName?.(target.tabId, site) || "" : ""
      // On the provider's own pages during a sign-in with it, its linked
      // account: the menu narrows to that login. With none matching, the
      // username named on the form narrows it as anywhere else.
      const linked = this.signInWith?.accountFor(target.tabId, target.origin)
      const linkedMatches = linked ? namedBy(shown, linked) : []
      if (linkedMatches.length) {
        shown = linkedMatches
        only = linkedMatches.map((a) => a.ref)
      } else if (named) {
        const matches = namedBy(shown, named)
        if (matches.length) {
          shown = matches
          only = matches.map((a) => a.ref)
        } else if (!again) shown = []
      } else if (later && isAccountPage(target.origin)) {
        const account = pageAccountOf(pageAccount)
        const matches = account ? namedBy(shown, account) : []
        if (matches.length) {
          shown = matches
          only = matches.map((a) => a.ref)
        }
      }
      rows = menuRowCount(shown, focused as FieldRole) + (this.passkeys?.menuPasskeys(target, focused as FieldRole).length ?? 0)
    }
    if (!rows) return { rows: 0 }
    this.sweep()
    const token = newToken()
    this.tokens.set(token, { ...target, ...(owner ? { owner } : {}), roles: clean, focused: focused as FieldRole, form: form as number, createdAt: Date.now(), ...(generate ? { generate } : {}), ...(only ? { only } : {}) })
    if (!owner || !at) return { token, rows }
    const opened = await sendToFrame<boolean>(owner, { type: "db:open-at", token, rows, box: at })
    if (!opened) this.tokens.delete(token)
    return { rows: opened ? rows : 0 }
  }

  async menuLoad(token: string, sender: chrome.runtime.MessageSender, parent: string): Promise<MenuLoadReply | null> {
    const t = await this.token(token, sender, parent)
    if (!t) return null
    if (this.host.status.state !== "ready") return { kind: "status", status: this.host.status }
    if (t.notice) return { kind: "notice", ...t.notice }
    if (t.generate) return { kind: "generate", site: new URL(t.origin).hostname }
    try {
      const reply = await this.list(t.origin)
      const passkeys = this.passkeys?.menuPasskeys(t, t.focused)
      const accounts = menuAccounts(reply.accounts, t.focused, t.roles).filter((a) => !t.only || t.only.includes(a.ref))
      // One login on a site that asks for the username first: "Continue as …".
      const flow = IDENTIFIER_ROLES.includes(t.focused) && accounts.length === 1 ? await flowFor(siteOf(new URL(t.origin).hostname) ?? "") : undefined
      const icons = (await iconSettings()).menu ? await menuIcons(accounts) : undefined
      const reveal = icons ? await firstReveals(Object.keys(icons)) : []
      return { kind: "accounts", site: reply.site, accounts, focused: t.focused, ...(passkeys?.length ? { passkeys } : {}), ...(flow?.identifierFirst ? { continueAs: true } : {}), ...(icons ? { icons, reveal } : {}) }
    } catch {
      return { kind: "status", status: this.host.status }
    }
  }

  async menuPick(token: string, ref: string, sender: chrome.runtime.MessageSender): Promise<PickReply> {
    const t = await this.token(token, sender)
    // A generated-password menu or a notice pill lists no accounts to pick.
    if (!t || t.generate || t.notice || (t.only && !t.only.includes(ref))) return { ok: false, message: "This menu has expired." }
    const signedIn = await this.passkeys?.menuPick(t, ref)
    if (signedIn) {
      this.tokens.delete(token)
      if (signedIn.ok) await sendToFrame(t.owner ?? t, { type: "db:close-menu", token })
      return signedIn
    }
    const reply = await this.list(t.origin).catch(() => null)
    const account = reply?.accounts.find((a) => a.ref === ref)
    if (!account) return { ok: false, message: "That login isn't here anymore." }
    // A login that signs in with a provider and has no password is never a fill.
    if (account.signIn && !account.hasPassword) return { ok: false, message: "This login signs in with another account." }
    // Picked once: its pill may still resize to say how the fill went (see token).
    t.picked = true
    if (!t.owner) return this.fillAndArm(t, account, t.roles, t.form)
    // A frame's fields: only those that show through every frame above, checked now and again once the values are in hand.
    const framed = await this.measured(t.tabId, () => shownInPage(t, t.form, true), null)
    if (!framed) return { ok: false, message: NOT_SHOWN }
    return this.fillAndArm(t, account, t.roles, t.form, framed)
  }

  /**
   * The user picked the generated password: the daemon makes one within the
   * page's rules, a candidate for the page's origin, and it goes into every
   * new-password box the content script approves. Once it's in, the daemon
   * holds it as pending; one that didn't go in is dropped. Nothing is saved;
   * a successful submit offers to (see Saver). The content script asked for
   * the characters and lengths its boxes' patterns take (see generate.ts), so
   * a pattern turning the password down means the page changed, and there's
   * no second try.
   */
  async menuGenerate(token: string, sender: chrome.runtime.MessageSender): Promise<PickReply> {
    const t = await this.token(token, sender)
    if (!t?.generate) return { ok: false, message: "This menu has expired." }
    t.picked = true
    const generation = this.generation(t.tabId)
    const approved = cleanApproved(await sendToFrame(t, { type: "db:approve", form: t.form, measure: false }))
    if (!approved?.roles.includes("new-password")) return { ok: false, message: "The page changed. Try again." }
    let generated: string
    let filled: FieldRole[] = []
    try {
      const reply = await this.host.send({ type: "generate", origin: t.origin, ...t.generate })
      generated = reply.generated
      try {
        if (generation !== this.generation(t.tabId)) return { ok: false, message: "" }
        const values: FillValues = { newPassword: reply.password }
        const ack = await sendToFrame<FillAck>(t, { type: "db:fill", values, form: t.form, approval: approved.approval, generated })
        if (ack?.rejected) return { ok: false, message: NO_FIT }
        filled = sanitizeRoles(ack?.filled)
      } finally {
        if (!filled.includes("new-password")) await this.host.send({ type: "generate-drop", origin: t.origin, generated }).catch(() => {})
        // Only once the daemon holds it may the page name it by id. If it
        // can't (locked, gone, disconnected), a submit sends it as typed.
        else if (await this.host.send({ type: "generate-keep", origin: t.origin, generated }).then(() => true, () => false))
          await sendToFrame(t, { type: "db:generated", generated })
      }
    } catch (err) {
      return { ok: false, message: generateError(err) }
    }
    return filled.includes("new-password") ? { ok: true } : { ok: false, message: "The page changed. Try again." }
  }

  /**
   * The user picked a "Sign in with …" row: start following the sign-in in
   * this tab (see SignInWith), and have the page's content script point at
   * the site's own button for it. Nothing is filled, and nothing clicked.
   */
  async menuSignIn(token: string, ref: string, sender: chrome.runtime.MessageSender): Promise<SignInReply> {
    const t = await this.token(token, sender)
    if (!t || t.generate || t.notice || (t.only && !t.only.includes(ref))) return { ok: false, message: "This menu has expired." }
    const reply = await this.list(t.origin).catch(() => null)
    const account = reply?.accounts.find((a) => a.ref === ref)
    if (!account?.signIn) return { ok: false, message: "That login isn't here anymore." }
    const site = siteOf(new URL(t.origin).hostname)
    if (site) this.signInWith?.start(t.tabId, account.signIn, site)
    // A sign-in with a provider isn't the session's step-by-step fill.
    await this.cancel(t.tabId)
    const found = (await sendToFrame<boolean>(t, { type: "db:point", provider: account.signIn.provider })) === true
    if (found) this.tokens.delete(token)
    return { ok: true, found, provider: account.signIn.provider }
  }

  async menuDismiss(token: string, sender: chrome.runtime.MessageSender) {
    const t = await this.token(token, sender)
    if (!t) return
    await this.cancel(t.tabId)
    await sendToFrame(t.owner ?? t, { type: "db:close-menu", token })
  }

  /** The locked row was clicked in the menu `token` was made for: true if it was, and Deadbolt is still locked. The menu closes. */
  async menuUnlock(token: string, sender: chrome.runtime.MessageSender): Promise<boolean> {
    const t = await this.token(token, sender)
    if (!t || this.host.status.state !== "locked") return false
    this.unlockReturn = t
    await sendToFrame(t, { type: "db:unlock-wait" })
    await this.cancel(t.tabId)
    await sendToFrame(t.owner ?? t, { type: "db:close-menu", token, unlock: true })
    return true
  }

  /** Returns only to the document that requested unlock; never fills anything. */
  async returnAfterUnlock(): Promise<boolean> {
    const t = this.unlockReturn
    this.unlockReturn = null
    if (!t || Date.now() - t.createdAt > TOKEN_TTL_MS) return false
    const tab = await chrome.tabs.update(t.tabId, { active: true }).catch(() => null)
    if (!tab) return false
    await chrome.windows.update(tab.windowId, { focused: true }).catch(() => {})
    return (await sendToFrame(t, { type: "db:unlock-return" })) === true
  }

  async menuResize(token: string, height: number, sender: chrome.runtime.MessageSender, width?: unknown, mode?: unknown) {
    const t = await this.token(token, sender, undefined, true)
    if (t) await sendToFrame(t.owner ?? t, resizeMessage(token, height, width, mode))
  }

  /**
   * A frame's field the menu opened for in the top page: the user typed in
   * it, clicked elsewhere in the frame, or pressed esc there (`dismissed`),
   * none of which the top page sees. Its open menu goes; a pick's pill stays.
   */
  async menuAway(sender: chrome.runtime.MessageSender, dismissed: boolean) {
    const target = await targetFor(sender)
    if (!target || target.frameId === 0) return
    let open = false
    for (const [token, t] of this.tokens) {
      if (!t.owner || t.picked || t.notice || t.tabId !== target.tabId || t.frameId !== target.frameId || t.documentId !== target.documentId) continue
      open = true
      this.tokens.delete(token)
      await sendToFrame(t.owner, { type: "db:close-menu", token })
    }
    // Esc said no to an open menu, as in the top page; with none open (it was picked), it says nothing of the sign-in.
    if (dismissed && open) await this.cancel(target.tabId)
  }

  /**
   * A frame's field the menu is open for in the top page moved inside its
   * frame, which the top page can't see: it now shows at `box` in the
   * frame's viewport. The box goes up through every frame with the checks
   * it had when the menu opened (see query), and the menu follows it there
   * (it waits its dwell again, as for any move); when it doesn't show, the
   * menu goes. True if a menu followed.
   */
  async menuMove(sender: chrome.runtime.MessageSender, box: unknown): Promise<boolean> {
    const target = await targetFor(sender)
    if (!target || target.frameId === 0) return false
    const own = cleanBox(box)
    let moved = false
    for (const [token, t] of this.tokens) {
      if (!t.owner || t.picked || t.notice || t.tabId !== target.tabId || t.frameId !== target.frameId || t.documentId !== target.documentId) continue
      const top = own ? await sameSiteTop(target) : null
      const shown = top && own && top.documentId === t.owner.documentId ? await boxesInTop(target, [own], LOGIN_FRAME_PLACE) : null
      if (shown && this.tokens.get(token) === t && (await sendToFrame<boolean>(t.owner, { type: "db:move-at", token, box: shown[0] })) === true) {
        moved = true
        continue
      }
      // Picked (it's a pill now) or closed while the box went up: not this move's to close.
      if (t.picked || this.tokens.get(token) !== t) continue
      this.tokens.delete(token)
      await sendToFrame(t.owner, { type: "db:close-menu", token })
    }
    return moved
  }

  /** The page closed its menu; with `dismissed`, the user said no (esc). */
  async menuClose(token: string, dismissed: boolean, sender: chrome.runtime.MessageSender) {
    const t = this.tokens.get(token)
    if (!t || sender.tab?.id !== t.tabId || sender.documentId !== (t.owner ?? t).documentId) return
    this.tokens.delete(token)
    // A frame's field: its frame hears the menu went (see db:menu-gone).
    if (t.owner) await sendToFrame(t, { type: "db:menu-gone" })
    if (dismissed) await this.cancel(t.tabId)
  }

  /**
   * Fills form `form` in that one document: the content script first fixes
   * which of its fields may be filled (db:approve, or for a frame the
   * `framed` approval shownInPage got), the host is asked only for the
   * values those fields and `roles` both take, and the content script writes
   * only into those fields. Nothing goes out if the tab's sign-in was
   * cancelled since `generation`, or for a frame, if its fields no longer all
   * show once the values are in hand. Returns what the content script says it
   * wrote. A session step's pill (`notice`) shows on the last field written:
   * for a frame's, in the top page, where that field shows there.
   */
  private async fill(target: FrameTarget, account: Account, roles: FieldRole[], form: number, generation: number, framed?: Approved, notice?: boolean, automatic = false): Promise<FieldRole[]> {
    const approved = framed ?? cleanApproved(await sendToFrame(target, { type: "db:approve", form, measure: false }))
    if (!approved) return []
    const want = wantFor(roles.filter((r) => approved.roles.includes(r)), account)
    if (!want.length) return []
    const reply = await this.host.send({ type: "fill", origin: target.origin, ref: account.ref, want })
    // Esc, or the user leaving, while the host answered: nothing goes out.
    if (generation !== this.generation(target.tabId)) return []
    if (automatic && (await chrome.storage.local.get(SIGNIN_SETTING))[SIGNIN_SETTING] !== true) return []
    if (framed && !(await this.measured(target.tabId, () => stillShown(target, framed), false))) throw new Error(NOT_SHOWN)
    if (generation !== this.generation(target.tabId)) return []
    const values: FillValues = {}
    if (want.includes("username") && reply.username) values.username = reply.username
    if (want.includes("password") && reply.password) values.password = reply.password
    if (want.includes("totp") && reply.totp) values.totp = reply.totp
    // A step filled without a pick says so on the field, in a pill of its own (see stepLabel).
    let pill: string | undefined
    const owner = notice && target.frameId !== 0 ? await sameSiteTop(target) : undefined
    if (notice && (target.frameId === 0 || owner)) {
      pill = newToken()
      const filled = want.map((w): FieldRole => (w === "username" ? "username" : w === "totp" ? "otp" : "password"))
      this.tokens.set(pill, { ...target, ...(owner ? { owner } : {}), roles: [], focused: "password", form, createdAt: Date.now(), notice: { label: stepLabel(filled), title: account.title } })
    }
    const ack = await sendToFrame<FillAck>(target, { type: "db:fill", values, form, approval: approved.approval, ...(pill ? { notice: pill } : {}), ...(automatic ? { automatic: true } : {}) })
    const wrote = sanitizeRoles(ack?.filled)
    // A frame's step pill opens in the top page, where the frame says the field it wrote last shows.
    const box = cleanBox(ack?.box)
    const shown = pill && owner && wrote.length && box ? await boxesInTop(target, [box], LOGIN_FRAME_PLACE) : null
    if (pill && owner && shown) await sendToFrame(owner, { type: "db:open-at", token: pill, rows: 0, box: shown[0], mode: "pill" })
    return wrote
  }

  /**
   * Runs `measure` (a frame's fields checked through every frame above) with
   * the login pill in the tab's top page out of sight: Chromium reads nothing
   * as fully visible while anything shows in the top layer (see db:hold).
   * Only a pill of this tab's logins is put away, never another surface (a
   * card's pill): with one showing, nothing is measured, and `fallback` is
   * the answer.
   */
  private async measured<T>(tabId: number, measure: () => Promise<T>, fallback: T): Promise<T> {
    const { target: top } = await topTarget(tabId)
    if (!top) return fallback
    const token = this.pillIn(top)
    if ((await sendToFrame<boolean>(top, { type: "db:hold", token, hold: true })) !== true) {
      if (token) await sendToFrame(top, { type: "db:hold", token, hold: false })
      return fallback
    }
    try {
      return await measure()
    } finally {
      await sendToFrame(top, { type: "db:hold", token, hold: false })
    }
  }

  /** The newest login pill (a pick's or a step's) in the top page document `top`, if any ("" if none). */
  private pillIn(top: FrameTarget): string {
    let pill = ""
    for (const [token, t] of this.tokens) {
      const owner = t.owner ?? t
      if ((t.picked || t.notice) && owner.tabId === top.tabId && owner.frameId === 0 && owner.documentId === top.documentId) pill = token
    }
    return pill
  }

  /** Fill, and say what the session is now if this fill, in the top page or a frame that may have the menu, wrote something (null: over). */
  private async fillStep(
    target: FrameTarget,
    account: Account,
    roles: FieldRole[],
    form: number,
    generation: number,
    framed?: Approved,
    session?: Session,
  ): Promise<{ reply: PickReply; next?: Session | null }> {
    let filled: FieldRole[]
    try {
      filled = await this.fill(target, account, roles, form, generation, framed, !!session, session?.automatic)
    } catch (err) {
      return { reply: { ok: false, message: fillError(err) } }
    }
    if (!filled.length) return { reply: { ok: false, message: "The page changed. Try again." } }
    if (target.frameId !== 0 && !(await sameSiteTop(target))) return { reply: { ok: true } }
    const site = siteOf(new URL(target.origin).hostname)
    const all = [...new Set([...(session?.ref === account.ref ? session.filled : []), ...filled])]
    if (!site || !nextStep(all, account)) return { reply: { ok: true }, next: null }
    const now = Date.now()
    const flow = await flowFor(site)
    const startedAt = session?.ref === account.ref ? session.startedAt : now
    const until = startedAt + SESSION_TTL_MS + (flow?.navigates ? SESSION_GRACE_MS : 0)
    const origin = session?.ref === account.ref ? session.origin : target.origin
    return { reply: { ok: true }, next: { ref: account.ref, site, origin, documentId: target.documentId, filledAt: now, filled: all, startedAt, until, ...(session?.automatic ? { automatic: true, automaticSubmits: session.automaticSubmits ?? 0 } : {}) } }
  }

  /** A fill the user chose (menu or popup), then the sign-in session that follows it. */
  private async fillAndArm(target: FrameTarget, account: Account, roles: FieldRole[], form: number, framed?: Approved): Promise<PickReply> {
    const generation = this.generation(target.tabId)
    const { reply, next } = await this.fillStep(target, account, roles, form, generation, framed)
    if (next !== undefined) await this.serial(target.tabId, () => this.arm(target.tabId, generation, next))
    const site = siteOf(new URL(target.origin).hostname)
    if (reply.ok && site) this.filled?.(target.tabId, site)
    return reply
  }

  /**
   * Sets the tab's session, or ends it, unless it was cancelled since
   * `generation` or the top page has left the session's site. Call it inside
   * `serial`.
   */
  private async arm(tabId: number, generation: number, next: Session | null) {
    if (generation !== this.generation(tabId)) return
    if (next) {
      const top = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null)
      if (siteOfUrl(top?.url) !== next.site || generation !== this.generation(tabId)) return
    }
    await this.setSession(tabId, next ?? undefined)
  }

  private generation(tabId: number): number {
    return this.cancels.get(tabId) ?? 0
  }

  private serial<T>(tabId: number, work: () => Promise<T>): Promise<T> {
    const run = (this.queues.get(tabId) ?? Promise.resolve()).then(work)
    this.queues.set(tabId, run.catch(() => {}))
    return run
  }

  /** The tab's session, kept in session storage so a service worker restart doesn't lose the step. */
  private async session(tabId: number): Promise<Session | undefined> {
    const key = `session:${tabId}`
    const stored = (await chrome.storage.session.get(key))[key] as Session | undefined
    if (stored && Date.now() < stored.until) return stored
    if (stored) await chrome.storage.session.remove(key)
    return undefined
  }

  async signingIn(tabId: number): Promise<boolean> { return !!await this.session(tabId) }
  async stopAutomatic(tabId: number) { if ((await this.session(tabId))?.automatic) await this.cancel(tabId) }

  private async stopAllAutomatic() {
    const all = await chrome.storage.session.get(null)
    for (const [key, value] of Object.entries(all))
      if (key.startsWith("session:") && (value as Session)?.automatic) void this.cancel(Number(key.slice(8)))
  }

  /** Entry from an extension-owned, visibility-guarded offer only. No popup,
   * inline-menu or agent fill gains this authority implicitly. */
  async startAutomatic(target: FrameTarget, account: Account, action: string, provider = false): Promise<PickReply> {
    if (this.host.status.state !== "ready" || target.frameId !== 0 || (await chrome.storage.local.get(SIGNIN_SETTING))[SIGNIN_SETTING] !== true ||
        !account.urls.some((u) => exactSignInOrigin(u, target.origin))) return { ok: false, message: "This sign-in isn't available here." }
    await this.cancel(target.tabId)
    const generation = this.generation(target.tabId)
    const site = siteOf(new URL(target.origin).hostname)
    if (!site) return { ok: false, message: "This sign-in isn't available here." }
    if (provider && account.signIn) {
      this.signInWith?.start(target.tabId, account.signIn, site)
      const found = await sendToFrame(target, { type: "db:point", provider: account.signIn.provider })
      return found ? { ok: true } : { ok: false, message: "Open the site's provider sign-in to continue." }
    }
    const now = Date.now()
    if (this.host.status.state !== "ready" || generation !== this.generation(target.tabId)) return { ok: false, message: "Sign-in stopped." }
    await this.setSession(target.tabId, { ref: account.ref, site, origin: target.origin, documentId: target.documentId,
      filled: [], filledAt: now, startedAt: now, until: now + AUTOMATIC_ENTRY_MS, automatic: true, automaticSubmits: 0 })
    if (this.host.status.state !== "ready" || generation !== this.generation(target.tabId)) {
      await this.cancel(target.tabId)
      return { ok: false, message: "Sign-in stopped." }
    }
    const started = await sendToFrame(target, { type: "db:signin-go", action })
    if (!started) await this.cancel(target.tabId)
    return started ? { ok: true } : { ok: false, message: "The page changed. Try again." }
  }

  private async setSession(tabId: number, s: Session | undefined) {
    const key = `session:${tabId}`
    clearTimeout(this.sessionTimers.get(tabId))
    this.sessionTimers.delete(tabId)
    if (!s) return chrome.storage.session.remove(key)
    await chrome.storage.session.set({ [key]: s })
    this.sessionTimers.set(
      tabId,
      setTimeout(() => void this.setSession(tabId, undefined), Math.max(0, s.until - Date.now())),
    )
  }

  /** The tab's session ends, including fills still on their way. */
  private cancel(tabId: number) {
    this.cancels.set(tabId, this.generation(tabId) + 1)
    return this.serial(tabId, () => this.setSession(tabId, undefined))
  }

  /** Every session ends: each one in session storage, whether or not this worker started it. */
  private async endAll() {
    const all = (await chrome.storage.session.get(null).catch(() => ({}))) as Record<string, unknown>
    const tabs = new Set([...this.sessionTimers.keys()])
    for (const key of Object.keys(all)) if (key.startsWith("session:")) tabs.add(Number(key.slice(8)))
    await Promise.all([...tabs].map((tabId) => this.cancel(tabId)))
    const left = Object.keys(all).filter((k) => k.startsWith("session:"))
    if (left.length) await chrome.storage.session.remove(left).catch(() => {})
  }

  /**
   * The user themselves submitted a login form (content.ts: a trusted click
   * on its submit control or Enter in a field, never a page's own submit).
   * A session's next step in another document needs one in the document the
   * last step filled.
   */
  async submitted(sender: chrome.runtime.MessageSender) {
    const target = await targetFor(sender)
    if (target && (target.frameId === 0 || (await sameSiteTop(target)))) this.submits.set(target.tabId, { documentId: target.documentId, at: Date.now() })
  }

  /** What the top page (or its same-site login frame) shows of the sign-in, step by step, to learn the site's Flow from. */
  private track(tabId: number, target: FrameTarget, roles: FieldRole[]) {
    const site = siteOf(new URL(target.origin).hostname)
    if (!site) return
    const frames = this.tracks.get(tabId) ?? new Map<number, Track>()
    this.tracks.set(tabId, frames)
    // Another site's sign-in starts over, in every frame.
    for (const [id, other] of frames) if (other.site !== site) frames.delete(id)
    let t = frames.get(target.frameId)
    if (!t) frames.set(target.frameId, (t = { site, otp: false }))
    const id = roles.some((r) => IDENTIFIER_ROLES.includes(r))
    if (roles.includes("password")) t.passwordDoc ??= target.documentId
    else if (id) t.identifierDoc ??= target.documentId
    if (roles.includes("otp") && t.passwordDoc) t.otp = true
  }

  /**
   * A sign-in in `tabId` on `site` worked (bg/save.ts judged it): remember
   * its shape (see Flow), from what the top page showed of it.
   */
  async learnFlow(tabId: number, site: string) {
    const frames = [...(this.tracks.get(tabId) ?? new Map<number, Track>())]
    this.tracks.delete(tabId)
    // The top page's sign-in if it showed a password, else the login frame's that did.
    const t = frames.sort(([a], [b]) => a - b).map(([, x]) => x).find((x) => x.site === site && x.passwordDoc)
    if (!t) return
    const flows = await readFlows()
    const key = await flowKey(site)
    const before = flows[key]
    const seen = Math.min((before?.seen ?? 0) + 1, 99)
    const codeSeen = Math.min((before?.codeSeen ?? 0) + (t.otp ? 1 : 0), seen)
    flows[key] = {
      identifierFirst: !!t.identifierDoc,
      // A code step "usually" follows: in more than half the sign-ins seen.
      code: codeSeen * 2 > seen,
      codeSeen,
      navigates: !!t.identifierDoc && t.identifierDoc !== t.passwordDoc,
      seen,
      at: Date.now(),
    }
    // Keep the most recent sites only.
    const sites = Object.entries(flows).sort((a, b) => b[1].at - a[1].at).slice(0, MAX_FLOWS)
    await chrome.storage.local.set({ [FLOWS_KEY]: Object.fromEntries(sites) }).catch(() => {})
  }

  /**
   * A content script found a login form: remember it, and fill the tab's
   * sign-in session's next step into it (see Session).
   */
  async page(sender: chrome.runtime.MessageSender, kind: SurfaceKind | null, roles: unknown, form: unknown, stepped = false, idEmpty = false, asksNew = false) {
    // Taken before any await: a cancel from here on wins, even one queued behind this.
    const generation = sender.tab?.id === undefined ? 0 : this.generation(sender.tab.id)
    const target = await targetFor(sender)
    if (!target || !Number.isSafeInteger(form)) return
    const clean = sanitizeRoles(roles)
    const frames = this.pages.get(target.tabId) ?? new Map<number, PageReport>()
    // No form (any more): forget the frame's, so the popup looks elsewhere.
    if (!kind) frames.delete(target.frameId)
    else frames.set(target.frameId, { ...target, kind, roles: clean, form: form as number })
    this.pages.set(target.tabId, frames)
    if (!kind) return
    // Only frames that may have the inline menu go on with a session (see sameSiteTop).
    const framed = target.frameId !== 0
    if (framed && !(await sameSiteTop(target))) return
    this.track(target.tabId, target, clean)

    await this.serial(target.tabId, async () => {
      const s = await this.session(target.tabId)
      if (!s || generation !== this.generation(target.tabId) || siteOf(new URL(target.origin).hostname) !== s.site) return
      if (s.automatic && (target.frameId !== 0 || target.origin !== s.origin ||
          (kind !== "login" && kind !== "mfa") || (s.automaticSubmits ?? 0) >= MAX_AUTOMATIC_SUBMITS))
        return this.endSession(target.tabId)
      // A form showing up isn't a step by itself: the user has to have
      // submitted the last one themselves. In the same document, content.ts
      // says so (`stepped`: their own click or Enter, never a page's own
      // submit or its taking the fields away). In another document, the
      // user's own submit has to have come from the document the last step
      // filled, after it filled.
      const sub = this.submits.get(target.tabId)
      const first = s.automatic && s.filled.length === 0
      if (first && kind !== "login") return this.endSession(target.tabId)
      if (!first && (target.documentId === s.documentId ? !stepped : !sub || sub.documentId !== s.documentId || sub.at < s.filledAt)) return
      // A session fills sign-in steps only (see sessionStep). An address the
      // site doesn't know often gets "Create your account" instead of a
      // password box: a sign-up or change-password form ends the session,
      // and anything else it can't be sure of is left to a pick.
      const allowed = sessionStep(kind, clean, asksNew)
      if (allowed === "end") return this.endSession(target.tabId)
      const identifierOnly = clean.some((r) => IDENTIFIER_ROLES.includes(r)) && !clean.includes("password") && !clean.includes("otp")
      // "Not you? Use a different account": the username box came back
      // empty. The session ends; whoever signs in now picks again.
      if (identifierOnly && !first) return void (idEmpty && (await this.endSession(target.tabId)))
      if (s.automatic && (await chrome.storage.local.get(SIGNIN_SETTING))[SIGNIN_SETTING] !== true) return this.endSession(target.tabId)
      if (this.host.status.state !== "ready" || generation !== this.generation(target.tabId)) return
      const reply = await this.list(target.origin).catch(() => null)
      const account = reply?.accounts.find((a) => a.ref === s.ref)
      if (!account || generation !== this.generation(target.tabId)) return
      // The daemon lists a login for every origin of its saved hosts' sites
      // and their subdomains; a step here fills only on the pick's own origin,
      // or one whose host a saved URL of the login names exactly.
      if (target.origin !== s.origin && !account.urls.some((u) => sameHost(u, target.origin))) return
      if (s.automatic && !account.urls.some((u) => exactSignInOrigin(u, target.origin))) return this.endSession(target.tabId)
      const step = (first ? clean : stepRoles(clean, account, idEmpty)).filter((r) => allowed.includes(r)).filter((r) => !s.filled.includes(r) || (IDENTIFIER_ROLES.includes(r) && (!s.automatic || !s.filled.includes("password"))))
      if (!step.length) return
      const shown = framed ? await this.measured(target.tabId, () => shownInPage(target, form as number, true), null) : undefined
      // A frame's step fills only fields that show through every frame above. One
      // that shows none of them yet (a password box still collapsed) isn't the
      // step yet: the frame reports again once more of its fields show.
      if (framed && (!shown || !step.some((r) => shown.roles.includes(r)) || generation !== this.generation(target.tabId))) return
      // Used once: whatever happens next, this step in this document doesn't fill again.
      await this.setSession(target.tabId, { ...s, documentId: target.documentId })
      const { reply: filled, next } = await this.fillStep(target, account, step, form as number, generation, shown ?? undefined, s)
      if (generation !== this.generation(target.tabId)) return
      if (s.automatic && !filled.ok) return this.endSession(target.tabId)
      // A saved TOTP can fill an unfamiliar code step, but only a learned
      // code flow authorizes submitting it. Content also vetoes SMS/email prompts.
      const submit = s.automatic && filled.ok && (!clean.includes("otp") || (await flowFor(s.site))?.code === true)
      if (generation !== this.generation(target.tabId)) return
      if (s.automatic && (await chrome.storage.local.get(SIGNIN_SETTING))[SIGNIN_SETTING] !== true) return this.endSession(target.tabId)
      if (generation !== this.generation(target.tabId)) return
      const automaticSubmits = (s.automaticSubmits ?? 0) + (submit ? 1 : 0)
      if (next !== undefined) await this.arm(target.tabId, generation, next && submit ? { ...next, automaticSubmits } : next)
      if (submit && generation === this.generation(target.tabId)) {
        this.submits.set(target.tabId, { documentId: target.documentId, at: Date.now() })
        const submitted = await sendToFrame(target, { type: "db:signin-submit", form: form as number })
        if (generation !== this.generation(target.tabId)) return
        // Four attempts are enough: leave any further step to a fresh user pick.
        if (!submitted || automaticSubmits >= MAX_AUTOMATIC_SUBMITS) await this.endSession(target.tabId)
      }
    })
  }

  /** Ends the tab's session from inside `serial`. */
  private async endSession(tabId: number) {
    this.cancels.set(tabId, this.generation(tabId) + 1)
    await this.setSession(tabId, undefined)
  }

  /**
   * A frame committed a new document: its menus and form report go. In the
   * top page, the session goes on to another page of the same site; a page
   * of another site, or a navigation the user started (a typed address, a
   * bookmark, a reload, back or forward), ends it.
   */
  async navigated(d: { tabId: number; frameId: number; url: string; transitionType?: string; transitionQualifiers?: string[] }) {
    if (d.frameId === 0) this.pages.delete(d.tabId)
    else this.pages.get(d.tabId)?.delete(d.frameId)
    for (const [token, t] of this.tokens) if (t.tabId === d.tabId && (d.frameId === 0 || t.frameId === d.frameId)) this.tokens.delete(token)
    if (d.frameId !== 0) return
    const tracked = this.tracks.get(d.tabId)
    if (tracked && [...tracked.values()].some((t) => t.site !== siteOfUrl(d.url))) this.tracks.delete(d.tabId)
    if (UNRELATED.has(d.transitionType ?? "") || d.transitionQualifiers?.includes("forward_back")) return this.cancel(d.tabId)
    const s = await this.serial(d.tabId, () => this.session(d.tabId))
    if (s && siteOfUrl(d.url) !== s.site) await this.cancel(d.tabId)
  }

  forgetTab(tabId: number) {
    this.pages.delete(tabId)
    this.tracks.delete(tabId)
    this.submits.delete(tabId)
    for (const [token, t] of this.tokens) if (t.tabId === tabId) this.tokens.delete(token)
    if (this.unlockReturn?.tabId === tabId) this.unlockReturn = null
    void this.cancel(tabId)
  }

  async popupLoad(tabId: number): Promise<PopupReply> {
    await this.host.reconnectNow()
    const status = this.host.status
    const { target, url } = await topTarget(tabId)
    const base: PopupReply = { status, accounts: [], host: url?.hostname }
    if (!target) return { ...base, unfillable: url && /^https?:$/.test(url.protocol) ? "insecure" : "scheme" }
    if (status.state !== "ready") return base
    try {
      const reply = await this.list(target.origin, true)
      return { ...base, site: reply.site, accounts: reply.accounts }
    } catch (err) {
      return { ...base, status: this.host.status, error: (err as Error).message }
    }
  }

  /**
   * Fill from the popup: into the login form the top page's content script
   * reported or, if it has none, the one form in a (same-site) frame that the
   * user can see through every frame above it, checked once to choose it and
   * again once the values are in hand (see shownInPage). The popup is no
   * evidence that the user sees a frame. Without a report from the current
   * document (sandboxed and opaque-origin pages never make one), nothing.
   */
  async popupFill(tabId: number, ref: string): Promise<PickReply> {
    // The top page's report may be stale (a page can swap its form for a
    // frame without navigating): ask for a fresh one first.
    const top = this.pages.get(tabId)?.get(0) ?? (await topTarget(tabId)).target
    if (top) await sendToFrame(top, { type: "db:report" })
    const forms = [...(this.pages.get(tabId)?.values() ?? [])].filter((p) => p.kind && p.kind !== "reset" && p.roles.length)
    let page = forms.find((p) => p.frameId === 0)
    let framed: Approved | undefined
    if (!page) {
      if (!forms.length) return { ok: false, message: "No login form to fill on this page." }
      const seen = await Promise.all(forms.map((p) => shownInPage(p, p.form)))
      const visible = forms.flatMap((p, i) => (seen[i] ? [{ page: p, approved: seen[i] }] : []))
      if (visible.length > 1) return { ok: false, message: "There's more than one login form here. Nothing was filled." }
      if (!visible[0]) return { ok: false, message: NOT_SHOWN }
      ;({ page, approved: framed } = visible[0])
    }
    const reply = await this.list(page.origin).catch((err: HostError) => err)
    if (reply instanceof Error) return { ok: false, message: fillError(reply) }
    const account = reply.accounts.find((a) => a.ref === ref)
    if (!account) return { ok: false, message: "That login isn't here anymore." }
    // A login that signs in with a provider and has no password is never a fill.
    if (account.signIn && !account.hasPassword) return { ok: false, message: "This login signs in with another account." }
    return this.fillAndArm(page, account, page.roles, page.form, framed)
  }
}

const NO_FIT = "No password fits this site's rules."

function generateError(err: unknown): string {
  if (err instanceof HostError && err.code === "failed") return NO_FIT
  if (err instanceof HostError && err.code === "weak") return "This site allows only weak passwords. Deadbolt won't make one."
  return fillError(err)
}

/**
 * What a surface frame asked for, within bounds: a height of 28 to 400 px,
 * a width of 28 (the save offer's dot) to 420, and the one mode a surface
 * may fold into (a pill).
 */
export function resizeMessage(token: string, height: number, width?: unknown, mode?: unknown): ToContent {
  const h = Number.isFinite(height) ? Math.min(Math.max(height, 28), 400) : 40
  const w = typeof width === "number" && Number.isFinite(width) ? Math.min(Math.max(width, 28), 420) : undefined
  return { type: "db:resize-menu", token, height: h, ...(w !== undefined ? { width: w } : {}), ...(mode === "pill" ? { mode: "pill" as const } : {}) }
}

function siteOfUrl(url: string | undefined): string | null {
  try {
    return url ? siteOf(new URL(url).hostname) : null
  } catch {
    return null
  }
}

/** The kept site icons for the hosts of `accounts`' first URLs, for the menu (see MenuLoadReply). */
async function menuIcons(accounts: Account[]): Promise<Record<string, StoredIcon | null>> {
  const hosts = new Set<string>()
  for (const a of accounts) {
    try {
      const u = a.urls.find(Boolean)
      if (u) hosts.add(iconKey(new URL(u.includes("://") ? u : `https://${u}`).hostname))
    } catch {}
  }
  const icons: Record<string, StoredIcon | null> = {}
  for (const h of hosts) icons[h] = (await storedIcon(h)) ?? null
  return icons
}

/** chrome.storage.session: salted hashes of hosts whose icon a menu already dithered in this browser session. */
const REVEALED_KEY = "siteIconsRevealed"

/** Which of `hosts` no menu has revealed this browser session; they count as revealed from now. */
async function firstReveals(hosts: string[]): Promise<string[]> {
  if (!hosts.length) return []
  const got = (await chrome.storage.session.get(REVEALED_KEY).catch(() => ({}))) as Record<string, unknown>
  const seen = Array.isArray(got[REVEALED_KEY]) ? (got[REVEALED_KEY] as string[]) : []
  // Kept as salted hashes (see hostHash): the session store names no sites.
  const hashes = await Promise.all(hosts.map(hostHash))
  const fresh = hosts.filter((_, i) => !seen.includes(hashes[i]))
  const added = hashes.filter((h) => !seen.includes(h))
  if (added.length) await chrome.storage.session.set({ [REVEALED_KEY]: [...added, ...seen].slice(0, 300) }).catch(() => {})
  return fresh
}

/** Whether saved URL `url` names exactly the host (and scheme, and port if it has one) of `origin`. */
export function sameHost(url: string, origin: string): boolean {
  try {
    const u = new URL(url.includes("://") ? url : `https://${url}`)
    const o = new URL(origin)
    return u.protocol === o.protocol && u.hostname === o.hostname && (!u.port || u.port === o.port)
  } catch {
    return false
  }
}

/** chrome.storage.local: a random salt made once per install, for the keys of FLOWS_KEY. */
export const FLOWS_SALT_KEY = "signinFlowsSalt"
let flowSalt: Promise<string> | undefined

/**
 * Sites are kept under a salted hash, not by name: the list says how often
 * a site's sign-in was seen, not which sites those are. The salt stays
 * with the install (in local storage), so the hashes match from one
 * browser session to the next.
 */
async function flowKey(site: string): Promise<string> {
  flowSalt ??= (async () => {
    const stored = (await chrome.storage.local.get(FLOWS_SALT_KEY))[FLOWS_SALT_KEY]
    if (typeof stored === "string" && stored) return stored
    const made = newToken()
    await chrome.storage.local.set({ [FLOWS_SALT_KEY]: made })
    return made
  })()
  flowSalt.catch(() => (flowSalt = undefined))
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${await flowSalt}\n${site}`))
  return Array.from(new Uint8Array(digest).slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("")
}

async function readFlows(): Promise<Record<string, Flow>> {
  const stored = (await chrome.storage.local.get(FLOWS_KEY).catch(() => ({})) as Record<string, unknown>)[FLOWS_KEY]
  return stored && typeof stored === "object" ? (stored as Record<string, Flow>) : {}
}

/** What's been learned of `site`'s sign-in, if anything (see Flow). */
export async function flowFor(site: string): Promise<Flow | undefined> {
  return site ? (await readFlows())[await flowKey(site)] : undefined
}

/** Rate limiting is the host pacing fills, not a fault: say so calmly. */
export function fillError(err: unknown): string {
  if (err instanceof HostError && err.code === "rate_limited") return "Filling too quickly. Try again in a moment."
  return (err as Error)?.message || "Couldn't fill."
}

/** A content script's field rules, kept to the documented fields. */
export function fieldRules(raw: unknown): FieldRules {
  const r = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>
  const text = (v: unknown) => (typeof v === "string" && v.length > 0 && v.length <= 1024 ? v : undefined)
  const length = (v: unknown) => (Number.isSafeInteger(v) && (v as number) > 0 && (v as number) < 1000 ? (v as number) : undefined)
  const rules: FieldRules = { rules: text(r.rules), minLength: length(r.minLength), maxLength: length(r.maxLength), allowed: text(r.allowed) }
  return Object.fromEntries(Object.entries(rules).filter(([, v]) => v !== undefined)) as FieldRules
}

function sanitizeRoles(roles: unknown): FieldRole[] {
  return Array.isArray(roles) ? roles.filter((r): r is FieldRole => FIELD_ROLES.includes(r)) : []
}
