// Offering to save a login after a successful sign-in. The flow follows
// Foyer's (github.com/R44VC0RP/foyer, src/autofill/vault.ts, by Ryan Vogel):
// keep what was submitted in memory, ask the host whether it's new, changed
// or already saved, and save only after the user says so.
//
// Whether a sign-in worked is judged from what the top page shows once it
// settles (the content script's `db:settled`): the background asks it for
// PageFacts (`db:probe`, booleans only) and judges them (see judge). A failed
// sign-in, a code step or a captcha offers nothing; a page that shows the
// account or a Sign out control confirms it; a page with neither, a moment
// later, is only likely, and gets a badge but never opens the popup.
//
// Where the offer shows: the toolbar button always gets a badge, and the
// popup shows the offer when opened. After a confirmed sign-in that took the
// site's turn, it also shows in the page, as Deadbolt's surface at the top
// right (an extension frame in a closed shadow root, see content/inline.ts),
// and the popup is the fallback. A page can see that the surface appeared,
// so it learns that the check found a new or changed login: every check that
// finishes uses up the site's turn, whatever it said, and the surface (or,
// where it can't open, the popup) shows for at most one check per site every
// ten minutes, across tabs. Every other offer only badges. Only a confirmed
// sign-in may show it, and only its check uses the turn: a likely one never
// shows anything a page can see, so its check tells the page nothing. The
// surface gets the site and username to show, never the password, and
// answers through the same offer id the popup does.

import type { ChooseReply, MenuLoadReply, OfferChoice, PageFacts, SaveOffer } from "../messages"
import type { SaveReply } from "../protocol"
import { resizeMessage } from "./autofill"
import { menuFrameOf, newToken, sendToFrame, targetFor, type FrameTarget } from "./frames"
import { HostError, type Host } from "./host"
import { saveTitle, saveUrl, senderOrigin, siteOf } from "./site"

/** How long a submitted password is kept while the sign-in finishes. */
export const CAPTURE_TTL_MS = 3 * 60_000
/** How long an offer (and the password in it) waits for an answer. */
export const OFFER_TTL_MS = 5 * 60_000
/** A capture waiting on a code step or a captcha is kept this long at most, from its password. */
export const HELD_TTL_MS = 5 * 60_000
/** A page that showed nothing either way is looked at again this much later. */
export const REPROBE_MS = 4000
/** The popup opens by itself at most once per site in this long, across tabs. */
export const AUTO_OPEN_EVERY_MS = 10 * 60_000
/** Not now holds back the same login on the same site this long. */
export const NOT_NOW_MS = 24 * 60 * 60_000
/** chrome.storage.local: sites the user said Never for. */
export const NEVER_KEY = "neverSave"
/** chrome.storage.session: SHA-256 of `site\nusername` → until when Not now holds it back. */
const NOT_NOW_KEY = "notNow"
/** chrome.storage.session: the salt for those hashes, made once per browser session. */
const SALT_KEY = "notNowSalt"
const MAX_PASSWORD = 4096
const MAX_USERNAME = 500
const BADGE = "#f02e29"

interface Capture {
  site: string
  origin: string
  username?: string
  /** The current password (login forms, or the "current" box when changing it). */
  password?: string
  /** Sign-up and change-password forms. */
  newPassword?: string
  /** What a new login is named and where it's saved: the form's page title and URL. */
  title: string
  url: string
  /** When the password was submitted. */
  since: number
  /** When it's forgotten: set when a password is submitted, never pushed back by a username alone; a code step or captcha may hold it longer. */
  until: number
  timer: ReturnType<typeof setTimeout>
  /** A page said this sign-in failed: only a confirmed one may offer it now. */
  failed: boolean
}

/**
 * What was going on in a tab when work for it started. Leaving the site,
 * closing the tab, saying Not now or Deadbolt locking moves it on, and work
 * that finishes after that is thrown away.
 */
interface Ticket {
  tab: number
  epoch: number
}

interface Offer {
  offer: SaveOffer
  ticket: Ticket
  save: () => Promise<SaveReply>
  timer: ReturnType<typeof setTimeout>
  /** Save was clicked and the host hasn't answered yet. */
  saving: boolean
}

type Pending = { offer: Omit<SaveOffer, "id">; save: Offer["save"] }

/** The save offer shown in a page: the document it's for, and the offer it answers. */
interface Surface {
  target: FrameTarget
  offer: string
  /** The surface frame that first loaded the token; only it may use it after. */
  menuDocumentId?: string
  /** The surface itself is answering: it shows the result and leaves on its own. */
  answering: boolean
  /** Answered: it may still resize as it folds away, but answers nothing more. */
  answered?: boolean
}

/**
 * What a settled page says about the sign-in:
 * - failed: an error without the account or Sign out showing, or the form
 *   back (with an error, or its password emptied). No offer, and from then on
 *   only a confirmed sign-in offers this capture.
 * - pending: a code step or a captcha. No offer yet; the capture is held.
 * - undecided: nothing either way yet. Looked at again, then no offer.
 * - confirmed: no form, error or challenge, and the account or Sign out shows. Offer; the popup may open.
 * - likely: no form, error or challenge and nothing more, on the second look. Badge only.
 */
export type Outcome = "failed" | "pending" | "undecided" | "confirmed" | "likely"

/**
 * `second`: the page was looked at once already. `created`: a sign-up or
 * new password, whose next page is often "verify your email" on a sign-in
 * looking URL.
 */
export function judge(f: PageFacts, second: boolean, created: boolean): Outcome {
  // An error on a page that signed in (a stale banner, a widget's notice) doesn't undo it.
  if (f.error && (f.loginForm || !(f.account || f.signOut))) return "failed"
  if (f.mfa || f.challenge) return "pending"
  if (f.loginForm) return f.passwordEmpty ? "failed" : "undecided"
  if (f.account || f.signOut) return "confirmed"
  // A sign-in URL without evidence (/login?error=1, /session) isn't enough.
  if (f.loginish && !created) return "undecided"
  return second ? "likely" : "undecided"
}

const FACTS: Array<keyof PageFacts> = ["loginForm", "passwordEmpty", "mfa", "error", "challenge", "account", "signOut", "loginish"]

/** A content script's PageFacts, if it answered with exactly those booleans. */
export function cleanFacts(reply: unknown): PageFacts | null {
  if (!reply || typeof reply !== "object") return null
  const r = reply as Record<string, unknown>
  return FACTS.every((k) => typeof r[k] === "boolean") ? (Object.fromEntries(FACTS.map((k) => [k, r[k]])) as unknown as PageFacts) : null
}

let salting: Promise<string> | undefined

/** The session's salt, so a stored hash can't be checked against a guessed username without it. */
function salt(): Promise<string> {
  salting ??= (async () => {
    const stored = (await chrome.storage.session.get(SALT_KEY))[SALT_KEY]
    if (typeof stored === "string" && stored) return stored
    const made = newToken()
    await chrome.storage.session.set({ [SALT_KEY]: made })
    return made
  })()
  salting.catch(() => (salting = undefined))
  return salting
}

async function hashLogin(site: string, username: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${await salt()}\n${site}\n${username}`))
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("")
}

async function neverSites(): Promise<string[]> {
  const list = (await chrome.storage.local.get(NEVER_KEY).catch(() => ({})) as Record<string, unknown>)[NEVER_KEY]
  return Array.isArray(list) ? list.filter((s): s is string => typeof s === "string") : []
}

const clip = (value: unknown, max: number) => (typeof value === "string" && value.length > 0 && value.length <= max ? value : undefined)

function siteOfUrl(url: string | undefined): string | null {
  try {
    return url ? siteOf(new URL(url).hostname) : null
  } catch {
    return null
  }
}

export class Saver {
  /** Submitted credentials, in memory only, until the sign-in finishes or they expire. */
  private captures = new Map<number, Capture>()
  private offers = new Map<number, Offer>()
  private generations = new Map<number, number>()
  private epoch = 0
  /** The site each tab's top page was last on, to tell when a tab leaves it. */
  private sites = new Map<number, string | null>()

  /** Save offers open in pages, by their surface token. */
  private surfaces = new Map<string, Surface>()
  /** Bumped by each settled page in a tab; a second look for an older one is dropped. */
  private rounds = new Map<number, number>()

  /** Serializes the once-per-site check, so two tabs can't both take the turn. */
  private opening: Promise<unknown> = Promise.resolve()
  private ttl: { capture: number; offer: number; held: number; reprobe: number }

  constructor(
    private host: Host,
    ttl: { capture?: number; offer?: number; held?: number; reprobe?: number } = {},
    private now: () => number = Date.now,
  ) {
    this.ttl = { capture: CAPTURE_TTL_MS, offer: OFFER_TTL_MS, held: HELD_TTL_MS, reprobe: REPROBE_MS, ...ttl }
    // Locked or gone: nothing waits to be saved, and nothing is kept.
    host.onChange((status) => {
      if (status.state !== "ready") this.forgetAll()
    })
  }

  private ticket(tabId: number): Ticket {
    return { tab: this.generations.get(tabId) ?? 0, epoch: this.epoch }
  }

  private fresh(tabId: number, t: Ticket): boolean {
    return t.tab === (this.generations.get(tabId) ?? 0) && t.epoch === this.epoch && this.host.status.state === "ready"
  }

  private moveOn(tabId: number) {
    this.generations.set(tabId, (this.generations.get(tabId) ?? 0) + 1)
  }

  /** Nothing has moved the tab on since `t`, Deadbolt is unlocked, and the tab's top page is still on `site`. */
  private async still(tabId: number, t: Ticket, site: string): Promise<boolean> {
    if (!this.fresh(tabId, t)) return false
    const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null)
    return siteOfUrl(frame?.url) === site && this.fresh(tabId, t)
  }

  async capture(sender: chrome.runtime.MessageSender, raw: { username?: unknown; password?: unknown; newPassword?: unknown; title?: unknown }) {
    const tabId = sender.tab?.id
    if (tabId === undefined) return
    const ticket = this.ticket(tabId)
    const target = await targetFor(sender)
    const page = senderOrigin(sender)
    if (!target || !page || !this.fresh(tabId, ticket)) return
    const site = siteOf(new URL(target.origin).hostname)
    if (!site) return
    // Never for this site: what was typed isn't even kept.
    if ((await neverSites()).includes(site) || !this.fresh(tabId, ticket)) return
    const username = typeof raw.username === "string" && raw.username.length <= MAX_USERNAME ? raw.username.trim() || undefined : undefined
    const password = clip(raw.password, MAX_PASSWORD)
    const newPassword = clip(raw.newPassword, MAX_PASSWORD)
    const now = this.now()
    const prev = this.captures.get(tabId)
    const same = prev && prev.site === site && prev.until > now ? prev : undefined
    // A username on its own (an email-first step) joins the password already
    // held, and it goes when that password would have.
    const restart = password || newPassword || !same
    const until = restart ? now + this.ttl.capture : same.until
    const since = restart ? now : same.since
    const base = same
      ? { ...same, username: username ?? same.username, password: password ?? same.password, newPassword: newPassword ?? same.newPassword }
      : { site, origin: target.origin, username, password, newPassword, title: saveTitle(raw.title, site), url: saveUrl(page) }
    this.dropCapture(tabId)
    const timer = setTimeout(() => this.dropCapture(tabId), Math.max(0, until - now))
    // A new password is a new attempt; a username joining it keeps what was said about it.
    const failed = restart ? false : same.failed
    this.captures.set(tabId, { ...base, since, until, timer, failed })
  }

  /** A code step or captcha: keep the capture a while longer, up to the held cap. */
  private hold(tabId: number, c: Capture) {
    const now = this.now()
    const until = Math.min(Math.max(c.until, now + this.ttl.capture), c.since + this.ttl.held)
    if (until <= c.until) return
    clearTimeout(c.timer)
    c.until = until
    c.timer = setTimeout(() => this.dropCapture(tabId), Math.max(0, until - now))
  }

  private dropCapture(tabId: number) {
    const c = this.captures.get(tabId)
    if (!c) return
    clearTimeout(c.timer)
    this.captures.delete(tabId)
  }

  /**
   * The top page of a tab settled after a submit: it shows no login form, or
   * a code step, or the submit is a moment old. Look at it, and offer if the
   * sign-in worked (see judge).
   */
  async settled(sender: chrome.runtime.MessageSender) {
    const tabId = sender.tab?.id
    if (tabId === undefined || sender.frameId !== 0 || !this.captures.has(tabId)) return
    const ticket = this.ticket(tabId)
    const round = (this.rounds.get(tabId) ?? 0) + 1
    this.rounds.set(tabId, round)
    const target = await targetFor(sender)
    const c = this.captures.get(tabId)
    if (!target || !c || !this.fresh(tabId, ticket) || siteOf(new URL(target.origin).hostname) !== c.site) return
    const current = () => this.captures.get(tabId) === c && this.rounds.get(tabId) === round && this.fresh(tabId, ticket)
    const created = !!c.newPassword
    let facts = await this.probe(target, c)
    let outcome = facts ? judge(facts, false, created) : "undecided"
    if (outcome === "undecided" && facts) {
      await new Promise((resolve) => setTimeout(resolve, this.ttl.reprobe))
      if (!current()) return
      facts = await this.probe(target, c)
      outcome = facts ? judge(facts, true, created) : "undecided"
    }
    if (!current()) return
    if (outcome === "pending") this.hold(tabId, c)
    if (outcome === "failed") c.failed = true
    // Failed or not sure: keep it. A retry replaces it; a later page may settle it,
    // but after a failure only by showing the account or Sign out.
    if (outcome !== "confirmed" && (outcome !== "likely" || c.failed)) return
    this.dropCapture(tabId)
    if (c.until <= this.now()) return
    if ((await neverSites()).includes(c.site)) return
    if (c.username && !c.newPassword && (await this.heldBack(c.site, c.username))) return
    const decided = await this.decide(c).catch((): { asked: boolean; pending?: Pending } => ({ asked: true }))
    // The page may be watching for the popup: a finished check uses up the
    // site's turn whether or not there's anything to offer. Only a confirmed
    // sign-in may open the popup, so only its check takes the turn.
    const turn = decided.asked && outcome === "confirmed" ? await this.openTurn(c.site).catch(() => false) : false
    if (!decided.pending || !(await this.still(tabId, ticket, c.site))) return
    if (await this.heldBack(c.site, decided.pending.offer.username)) return
    await this.publish(tabId, ticket, decided.pending, turn, target)
  }

  /** What the top page shows now, from the document that settled. */
  private async probe(target: FrameTarget, c: Capture): Promise<PageFacts | null> {
    return cleanFacts(await sendToFrame(target, { type: "db:probe", ...(c.username ? { username: c.username } : {}) }))
  }

  /** Not now was said to this login on this site in the last day. */
  private async heldBack(site: string, username: string): Promise<boolean> {
    const held = (await chrome.storage.session.get(NOT_NOW_KEY).catch(() => ({})) as Record<string, unknown>)[NOT_NOW_KEY]
    if (!held || typeof held !== "object") return false
    const until = (held as Record<string, unknown>)[await hashLogin(site, username)]
    return typeof until === "number" && until > this.now()
  }

  private async holdBack(site: string, username: string) {
    const stored = (await chrome.storage.session.get(NOT_NOW_KEY).catch(() => ({})) as Record<string, unknown>)[NOT_NOW_KEY]
    const now = this.now()
    const held: Record<string, number> = {}
    if (stored && typeof stored === "object") for (const [k, v] of Object.entries(stored)) if (typeof v === "number" && v > now) held[k] = v
    held[await hashLogin(site, username)] = now + NOT_NOW_MS
    await chrome.storage.session.set({ [NOT_NOW_KEY]: held }).catch(() => {})
  }

  /**
   * Asks the host what to offer. Throws when the host does (locked, rate
   * limited or gone): offer nothing. `asked` says whether a check was sent.
   */
  private async decide(c: Capture): Promise<{ asked: boolean; pending?: Pending }> {
    if (c.newPassword && c.password) return { asked: true, pending: await this.passwordChange(c) }
    const password = c.newPassword ?? c.password
    if (!password || !c.username) return { asked: false }
    return { asked: true, pending: await this.saveOrUpdate({ ...c, password }) }
  }

  private async saveOrUpdate(c: Capture): Promise<Pending | undefined> {
    if (!c.password || !c.username) return undefined
    const check = await this.host.send({ type: "check", origin: c.origin, username: c.username, password: c.password })
    if (check.status === "same") return undefined
    const ref = check.status === "update" ? check.matches[0] : undefined
    const entry = { title: c.title, url: c.url, username: c.username, password: c.password }
    return { offer: { site: c.site, username: c.username, update: !!ref }, save: () => this.host.send({ type: "save", origin: c.origin, ref, entry }) }
  }

  /** Changing a password: update the saved login that still has the old one. */
  private async passwordChange(c: Capture): Promise<Pending | undefined> {
    const newPassword = c.newPassword!
    let target: { ref: string; username: string } | undefined
    if (c.username && c.password) {
      const check = await this.host.send({ type: "check", origin: c.origin, username: c.username, password: c.password })
      if (check.status === "same" && check.matches[0]) target = { ref: check.matches[0], username: c.username }
    } else {
      // No username on the form: only act when there's exactly one saved login here.
      const list = await this.host.send({ type: "list", origin: c.origin })
      const saved = list.accounts.filter((a) => a.hasPassword)
      if (saved.length === 1) target = { ref: saved[0].ref, username: saved[0].username ?? "" }
    }
    if (!target) return c.username ? this.saveOrUpdate({ ...c, password: newPassword }) : undefined
    const { ref, username } = target
    const entry = { title: c.title, url: c.url, username, password: newPassword }
    return { offer: { site: c.site, username: username || c.site, update: true }, save: () => this.host.send({ type: "save", origin: c.origin, ref, entry }) }
  }

  /** Hold the offer for the tab under a new id, badge the toolbar button, and open the popup if the site had its turn. */
  /**
   * Hold the offer for the tab under a new id and badge the toolbar button.
   * If the site had its turn, show it in the page that settled (`target`),
   * or where that can't be, open the popup.
   */
  private async publish(tabId: number, ticket: Ticket, pending: Pending, turn: boolean, target?: FrameTarget) {
    this.dropOffer(tabId)
    const id = newToken()
    const timer = setTimeout(() => this.dropOffer(tabId, id), this.ttl.offer)
    this.offers.set(tabId, { offer: { ...pending.offer, id }, ticket, save: pending.save, timer, saving: false })
    void Promise.all([chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE }), chrome.action.setBadgeText({ tabId, text: "1" })]).catch(() => {})
    if (!turn) return
    const current = () => this.offers.get(tabId)?.offer.id === id
    if (target && target.frameId === 0 && (await this.showInPage(target, id))) return
    await openPopupFor(tabId, current)
  }

  /** Opens the offer's surface in the top page's document `target`. False if it didn't take it. */
  private async showInPage(target: FrameTarget, offer: string): Promise<boolean> {
    const token = newToken()
    this.surfaces.set(token, { target, offer, answering: false })
    const shown = (await sendToFrame(target, { type: "db:surface", token })) === true
    if (!shown || this.offers.get(target.tabId)?.offer.id !== offer) {
      this.surfaces.delete(token)
      // It opened, but the offer went (answered, expired, Deadbolt locked) on the way: close it.
      if (shown) void sendToFrame(target, { type: "db:close-menu", token })
      return shown
    }
    return true
  }

  ownsSurface(token: unknown): boolean {
    return typeof token === "string" && this.surfaces.has(token)
  }

  /**
   * The surface frame claiming `token`: on its first load (with `parent`, see
   * menuFrameOf) it binds the token to that frame's document, and after that
   * only that document may use it.
   */
  private async surface(token: string, sender: chrome.runtime.MessageSender, parent?: string): Promise<Surface | undefined> {
    const s = this.surfaces.get(token)
    if (!s || !sender.documentId || sender.tab?.id !== s.target.tabId) return undefined
    if (s.menuDocumentId === undefined) {
      if (parent === undefined || !(await menuFrameOf(sender, s.target, parent)) || this.surfaces.get(token) !== s) return undefined
      s.menuDocumentId = sender.documentId
    }
    return s.menuDocumentId === sender.documentId ? s : undefined
  }

  /** What the surface may show: the site, the username and whether it's an update. */
  async surfaceLoad(token: string, sender: chrome.runtime.MessageSender, parent: string): Promise<MenuLoadReply | null> {
    const s = await this.surface(token, sender, parent)
    const o = s && this.offers.get(s.target.tabId)
    if (!s || !o || o.offer.id !== s.offer || this.host.status.state !== "ready") return null
    return { kind: "offer", site: o.offer.site, username: o.offer.username, update: o.offer.update }
  }

  /**
   * The surface was answered. Save and Never answer the offer as the popup
   * does; Not now only puts the surface away, and the toolbar keeps the offer.
   * Each token answers once, except a save the host turned down for now
   * (locked, busy), which may be tried again.
   */
  async surfaceChoose(token: string, sender: chrome.runtime.MessageSender, choice: OfferChoice): Promise<ChooseReply> {
    const s = await this.surface(token, sender)
    if (!s) return { ok: false, message: "This offer has expired.", gone: true }
    if (choice === "later") {
      this.surfaces.delete(token)
      return { ok: true, message: "" }
    }
    if (s.answered) return { ok: false, message: "This offer has expired.", gone: true }
    if (s.answering) return { ok: false, message: "Saving…" }
    s.answering = true
    const reply = await this.choose(s.target.tabId, s.offer, choice)
    if (reply.ok || ("gone" in reply && reply.gone)) s.answered = true
    else s.answering = false
    return reply
  }

  async surfaceResize(token: string, sender: chrome.runtime.MessageSender, height: number, width?: unknown, mode?: unknown) {
    const s = await this.surface(token, sender)
    if (s) await sendToFrame(s.target, resizeMessage(token, height, width, mode))
  }

  /** Escape in the surface: put it away, as Not now does. */
  async surfaceDismiss(token: string, sender: chrome.runtime.MessageSender) {
    const s = await this.surface(token, sender)
    if (!s) return
    this.surfaces.delete(token)
    await sendToFrame(s.target, { type: "db:close-menu", token })
  }

  /** The page's content script closed the surface (its time ran out, or it left). */
  surfaceClosed(token: string, sender: chrome.runtime.MessageSender) {
    const s = this.surfaces.get(token)
    if (s && sender.tab?.id === s.target.tabId && sender.documentId === s.target.documentId) this.surfaces.delete(token)
  }

  /**
   * The offer `id` was answered or went away: its surfaces close, except one
   * showing its own answer, which folds away by itself (and is forgotten
   * when its page closes it or leaves).
   */
  private dropSurfaces(id: string) {
    for (const [token, s] of this.surfaces) {
      if (s.offer !== id || s.answering) continue
      this.surfaces.delete(token)
      void sendToFrame(s.target, { type: "db:close-menu", token })
    }
  }

  private dropTabSurfaces(tabId: number) {
    for (const [token, s] of this.surfaces) if (s.target.tabId === tabId) this.surfaces.delete(token)
  }

  /**
   * Whether the popup may open by itself for this site now, taking the turn if
   * so. Kept in session storage, so a service worker restart doesn't reset it.
   */
  private openTurn(site: string): Promise<boolean> {
    const turn = this.opening.then(async () => {
      const key = `opened:${site}`
      const last = (await chrome.storage.session.get(key))[key]
      const now = this.now()
      if (typeof last === "number" && Math.abs(now - last) < AUTO_OPEN_EVERY_MS) return false
      await chrome.storage.session.set({ [key]: now })
      return true
    })
    this.opening = turn.catch(() => {})
    return turn
  }

  /** Drops the tab's offer; with `id`, only if that's still the one waiting. */
  private dropOffer(tabId: number, id?: string) {
    const o = this.offers.get(tabId)
    if (!o || (id !== undefined && o.offer.id !== id)) return
    clearTimeout(o.timer)
    this.offers.delete(tabId)
    this.dropSurfaces(o.offer.id)
    void chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {})
  }

  /** The offer waiting in this tab, for the popup. */
  pending(tabId: number): SaveOffer | undefined {
    const o = this.offers.get(tabId)
    return o?.offer
  }

  /** The user answered the offer with this id, the one the popup showed. Any other offer is untouched. */
  async choose(tabId: number, id: string, choice: OfferChoice): Promise<ChooseReply> {
    const o = this.offers.get(tabId)
    if (!o || o.offer.id !== id) return { ok: false, message: "This offer has expired.", gone: true }
    if (o.saving) return { ok: false, message: "Saving…" }
    if (choice !== "save") {
      this.moveOn(tabId)
      this.dropOffer(tabId, id)
      if (choice === "never") {
        this.dropCapture(tabId)
        await this.setNever(o.offer.site, true)
      } else await this.holdBack(o.offer.site, o.offer.username)
      return { ok: true, message: "" }
    }
    o.saving = true
    if (!(await this.still(tabId, o.ticket, o.offer.site)) || this.offers.get(tabId) !== o) {
      this.dropOffer(tabId, id)
      return { ok: false, message: "This offer has expired.", gone: true }
    }
    try {
      const reply = await o.save()
      this.dropOffer(tabId, id)
      return { ok: true, message: reply.created ? "Saved to Deadbolt" : "Password updated" }
    } catch (err) {
      o.saving = false
      if (err instanceof HostError && err.code === "locked") return { ok: false, message: "Deadbolt is locked. Unlock it, then save again." }
      if (err instanceof HostError && err.code === "rate_limited") return { ok: false, message: "Deadbolt is busy. Try again in a moment." }
      return { ok: false, message: (err as Error).message || "Couldn't save." }
    }
  }

  private async setNever(site: string, never: boolean) {
    const list = (await neverSites()).filter((s) => s !== site)
    if (never) list.push(site)
    await chrome.storage.local.set({ [NEVER_KEY]: list }).catch(() => {})
  }

  private async topSite(tabId: number): Promise<string | null> {
    const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null)
    return siteOfUrl(frame?.url)
  }

  /** The tab's site, if the user said Never for it. */
  async savingOff(tabId: number): Promise<string | undefined> {
    const site = await this.topSite(tabId)
    return site && (await neverSites()).includes(site) ? site : undefined
  }

  /** Offer to save on the tab's site again. */
  async savingOn(tabId: number): Promise<boolean> {
    const site = await this.topSite(tabId)
    if (!site) return false
    await this.setNever(site, false)
    return true
  }

  /** The tab's top page committed a new document. Another site's page ends the sign-in and its offer. */
  navigated(tabId: number, url: string) {
    // The page the surface was in is gone, and the surface with it.
    this.dropTabSurfaces(tabId)
    const site = siteOfUrl(url)
    if (!this.sites.has(tabId) || this.sites.get(tabId) !== site) this.moveOn(tabId)
    this.sites.set(tabId, site)
    if (this.captures.get(tabId)?.site !== site) this.dropCapture(tabId)
    if (this.offers.get(tabId)?.offer.site !== site) this.dropOffer(tabId)
  }

  forgetTab(tabId: number) {
    this.moveOn(tabId)
    this.sites.delete(tabId)
    this.rounds.delete(tabId)
    this.dropTabSurfaces(tabId)
    this.dropCapture(tabId)
    this.dropOffer(tabId)
  }

  forgetAll() {
    this.epoch++
    for (const tabId of [...this.captures.keys()]) this.dropCapture(tabId)
    for (const tabId of [...this.offers.keys()]) this.dropOffer(tabId)
  }
}

/**
 * Opens the toolbar popup over the tab, when the tab is the one showing in
 * its window and its offer is still `current` (Chrome 127+ lets an extension
 * do this without a click). It fails when the window isn't focused; the badge
 * is there for that.
 */
export async function openPopupFor(tabId: number, current: () => boolean) {
  const action = chrome.action as typeof chrome.action & { openPopup?: (options?: { windowId?: number }) => Promise<void> }
  if (typeof action.openPopup !== "function") return
  const tab = await chrome.tabs.get(tabId).catch(() => null)
  if (!tab?.active || !current()) return
  await action.openPopup({ windowId: tab.windowId }).catch(() => {})
}
