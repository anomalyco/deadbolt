// Offering to save a login after a successful sign-in. The flow follows
// Foyer's (github.com/R44VC0RP/foyer, src/autofill/vault.ts, by Ryan Vogel):
// keep what was submitted in memory, ask the host whether it's new, changed
// or already saved, and save only after the user says so.
//
// A sign-in counts as successful when the top page of the same site then
// shows no login form for a moment (the content script's `db:quiet`) on a
// page that doesn't look like a sign-in step. It has failed when the form
// that was submitted still shows about five seconds later, in place or posted
// back (1Password's check), and it's abandoned when the user goes elsewhere
// by hand (a typed address or a bookmark): neither offers anything.
//
// The offer is browser UI, never page UI: the toolbar button gets a badge and
// the popup shows the offer when opened. A page can see any element put into
// it, so an in-page prompt would tell it what the check said. Opening the
// popup by itself does move focus away from the page, which a page can see.
// So every check that finishes uses up the site's turn, whatever it said: the
// popup opens by itself for at most one check per site every ten minutes,
// across tabs, and every other offer only badges.

import type { ChooseReply, FieldRole, OfferChoice, SaveOffer, SurfaceKind } from "../messages"
import type { CheckReply, PasswordValue, SaveReply } from "../protocol"
import { newToken, targetFor } from "./frames"
import { HostError, type Host } from "./host"
import { saveTitle, saveUrl, senderOrigin, siteOf } from "./site"

/** How long a submitted password is kept while the sign-in finishes. */
export const CAPTURE_TTL_MS = 3 * 60_000
/** How long an offer (and the password in it) waits for an answer. */
export const OFFER_TTL_MS = 5 * 60_000
/** The popup opens by itself at most once per site in this long, across tabs. */
export const AUTO_OPEN_EVERY_MS = 10 * 60_000
/** How long after a submit to wait before offering: the content script reports a form still showing at five seconds. */
export const SETTLE_MS = 5500
/** Fields whose showing again means the submit didn't go through. */
const SECRET_ROLES: FieldRole[] = ["password", "new-password", "otp"]
/** Ways into a page that aren't the next step of a sign-in. */
const BY_HAND = new Set(["typed", "auto_bookmark", "generated", "keyword", "keyword_generated"])
const MAX_PASSWORD = 4096
const MAX_USERNAME = 500
const BADGE = "#f02e29"

interface Capture {
  site: string
  /**
   * Where the passwords were submitted, which a check and save go to: a
   * generated one is the agent's for this origin only. Until one is, where
   * the username was.
   */
  origin: string
  username?: string
  /**
   * Where the username was submitted, and whether as a sign-in's own step (a
   * login or sign-up form on the top page). Only such a step, with no
   * password yet, carries it to a password on another of the site's hosts.
   */
  usernameOrigin?: string
  usernameStep?: boolean
  /** The current password (login forms, or the "current" box when changing it). */
  password?: string
  /** Sign-up and change-password forms. */
  newPassword?: string
  /** Instead of `newPassword`: the id of the generated password the agent holds. */
  generated?: string
  /** What a new login is named and where it's saved: the title and URL of the page the passwords were submitted on. */
  title: string
  url: string
  /** When it's forgotten: set when a password is submitted, never pushed back by a username alone. */
  until: number
  timer: ReturnType<typeof setTimeout>
  /** When it was submitted. */
  at: number
  /**
   * The page, document, submit count (see content.ts), kind and secret fields
   * of the form that submitted the passwords (until there are any, the
   * username), to tell it showing again.
   */
  form: string
  document?: string
  submission?: number
  kind?: SurfaceKind
  secrets: FieldRole[]
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

const clip = (value: unknown, max: number) => (typeof value === "string" && value.length > 0 && value.length <= max ? value : undefined)

/** The new password a capture names, typed or generated. */
function newSecret(c: Capture): PasswordValue | undefined {
  if (c.generated) return { generated: c.generated }
  return c.newPassword ? { password: c.newPassword } : undefined
}

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

  /** Serializes the once-per-site check, so two tabs can't both take the turn. */
  private opening: Promise<unknown> = Promise.resolve()

  constructor(
    private host: Host,
    private ttl: { capture: number; offer: number; settle?: number } = { capture: CAPTURE_TTL_MS, offer: OFFER_TTL_MS, settle: SETTLE_MS },
    private now: () => number = Date.now,
  ) {
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

  async capture(
    sender: chrome.runtime.MessageSender,
    raw: { username?: unknown; password?: unknown; newPassword?: unknown; generated?: unknown; title?: unknown; kind?: unknown; roles?: unknown; submission?: unknown },
  ) {
    const tabId = sender.tab?.id
    if (tabId === undefined) return
    const ticket = this.ticket(tabId)
    const target = await targetFor(sender)
    const page = senderOrigin(sender)
    if (!target || !page || !this.fresh(tabId, ticket)) return
    const site = siteOf(new URL(target.origin).hostname)
    if (!site) return
    const username = typeof raw.username === "string" && raw.username.length <= MAX_USERNAME ? raw.username.trim() || undefined : undefined
    const password = clip(raw.password, MAX_PASSWORD)
    const generated = clip(raw.generated, 64)
    const newPassword = generated ? undefined : clip(raw.newPassword, MAX_PASSWORD)
    const fresh = newPassword || generated ? { newPassword, generated } : undefined
    const now = this.now()
    const prev = this.captures.get(tabId)
    const same = prev && prev.site === site && prev.until > now ? prev : undefined
    const held = same && (same.password || newSecret(same)) ? same : undefined
    const kind = typeof raw.kind === "string" ? (raw.kind as SurfaceKind) : undefined
    const here = { origin: target.origin, title: saveTitle(raw.title, site), url: saveUrl(page) }
    const submitted = {
      at: now,
      form: saveUrl(page),
      document: sender.documentId,
      submission: Number.isSafeInteger(raw.submission) ? (raw.submission as number) : undefined,
      kind,
      secrets: Array.isArray(raw.roles) ? SECRET_ROLES.filter((r) => (raw.roles as unknown[]).includes(r)) : [],
    }
    const usernameFrom = { usernameOrigin: target.origin, usernameStep: sender.frameId === 0 && (kind === "login" || kind === "signup") }
    if (!password && !fresh) {
      if (!username) return
      // A username on its own. With a password held, it joins only one from
      // its own origin that has none yet, and changes nothing else: once a
      // username is paired with a password nothing replaces it, and another
      // host's username never joins.
      if (held) {
        if (held.username || held.origin !== target.origin) return
        this.captures.set(tabId, { ...held, username, ...usernameFrom })
        return
      }
      // Else it waits for the password, as an email-first step's does.
      this.keep(tabId, { site, ...here, username, ...usernameFrom, until: now + this.ttl.capture, ...submitted })
      return
    }
    // Passwords stay with the origin they were submitted on: one from another
    // of the site's hosts takes over, and the earlier ones and their username
    // go, unless that username was a sign-in's own step with no password yet
    // and this is the top page. Nor do passwords carry to another username.
    const sameUser = (a?: string, b?: string) => !a || !b || a.toLowerCase() === b.toLowerCase()
    const kept = held && held.origin === target.origin && sameUser(username, held.username) ? held : undefined
    const step = !held && same?.username && (same.usernameOrigin === target.origin || (same.usernameStep && sender.frameId === 0)) ? same : undefined
    const from = username ? { username, ...usernameFrom } : (kept ?? step)
    this.keep(tabId, {
      site,
      ...here,
      username: from?.username,
      usernameOrigin: from?.usernameOrigin,
      usernameStep: from?.usernameStep,
      password: password ?? kept?.password,
      newPassword: fresh ? newPassword : kept?.newPassword,
      generated: fresh ? generated : kept?.generated,
      until: now + this.ttl.capture,
      ...submitted,
    })
  }

  /** Holds `c` for the tab until it expires. */
  private keep(tabId: number, c: Omit<Capture, "timer">) {
    this.dropCapture(tabId)
    const timer = setTimeout(() => this.dropCapture(tabId), Math.max(0, c.until - this.now()))
    this.captures.set(tabId, { ...c, timer })
  }

  /** The form submitted as `submission` still shows in place, five seconds on: the sign-in failed. A failure for an earlier submit, or from another document, says nothing. */
  failed(sender: chrome.runtime.MessageSender, submission: unknown) {
    const tabId = sender.tab?.id
    const page = senderOrigin(sender)
    const c = tabId === undefined ? undefined : this.captures.get(tabId)
    if (!c || !page || saveUrl(page) !== c.form || !sender.documentId || sender.documentId !== c.document) return
    if (Number.isSafeInteger(submission) && submission === c.submission) this.dropCapture(tabId!)
  }

  /** A page reported its form. The one just submitted, posted back to the same page as a new document, means the sign-in failed. */
  page(sender: chrome.runtime.MessageSender, kind: SurfaceKind | null, roles: FieldRole[]) {
    const tabId = sender.tab?.id
    const page = senderOrigin(sender)
    const c = tabId === undefined ? undefined : this.captures.get(tabId)
    if (!c || !page || !kind || kind !== c.kind || sender.documentId === c.document || saveUrl(page) !== c.form) return
    if (c.secrets.some((r) => roles.includes(r))) this.dropCapture(tabId!)
  }

  private dropCapture(tabId: number) {
    const c = this.captures.get(tabId)
    if (!c) return
    clearTimeout(c.timer)
    this.captures.delete(tabId)
  }

  /** The top page of a tab shows no login form: the sign-in may have gone through. */
  async quiet(sender: chrome.runtime.MessageSender, loginish: boolean) {
    const tabId = sender.tab?.id
    if (tabId === undefined || sender.frameId !== 0 || loginish || !this.captures.has(tabId)) return
    const ticket = this.ticket(tabId)
    // Give a failed submit its five seconds to show.
    const held = this.captures.get(tabId)!
    const wait = held.at + (this.ttl.settle ?? 0) - this.now()
    if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait))
    const target = await targetFor(sender)
    const c = this.captures.get(tabId)
    if (!target || c !== held || !this.fresh(tabId, ticket) || siteOf(new URL(target.origin).hostname) !== c.site) return
    this.dropCapture(tabId)
    if (c.until <= this.now()) return
    const decided = await this.decide(c).catch((): { asked: boolean; pending?: Pending } => ({ asked: true }))
    // The page may be watching for the popup: a finished check uses up the
    // site's turn whether or not there's anything to offer.
    const turn = decided.asked ? await this.openTurn(c.site).catch(() => false) : false
    if (!decided.pending || !(await this.still(tabId, ticket, c.site))) return
    await this.publish(tabId, ticket, decided.pending, turn)
  }

  /**
   * Asks the host what to offer. Throws when the host does (locked, rate
   * limited or gone): offer nothing. `asked` says whether a check was sent.
   */
  private async decide(c: Capture): Promise<{ asked: boolean; pending?: Pending }> {
    const next = newSecret(c)
    if (next && c.password) return { asked: true, pending: await this.passwordChange(c, next, c.password) }
    const secret = next ?? (c.password ? { password: c.password } : undefined)
    if (!secret || !c.username) return { asked: false }
    return { asked: true, pending: await this.saveOrUpdate(c, c.username, secret) }
  }

  private async saveOrUpdate(c: Capture, username: string, secret: PasswordValue): Promise<Pending | undefined> {
    return this.offerFor(c, username, secret, await this.host.send({ type: "check", origin: c.origin, username, ...secret }))
  }

  private offerFor(c: Capture, username: string, secret: PasswordValue, check: CheckReply): Pending | undefined {
    if (check.status === "same") return undefined
    const ref = check.status === "update" ? check.matches[0] : undefined
    const entry = { title: c.title, url: c.url, username, ...secret }
    return { offer: { site: c.site, username, update: !!ref }, save: () => this.host.send({ type: "save", origin: c.origin, ref, entry }) }
  }

  /**
   * Changing a password: update the saved login that still has the old one.
   * The host sees the same requests whether or not the current password
   * matched, so neither its rate limit nor what follows tells the page.
   */
  private async passwordChange(c: Capture, next: PasswordValue, current: string): Promise<Pending | undefined> {
    if (next.password === current) return undefined
    let target: { ref: string; username: string } | undefined
    if (c.username) {
      const old = await this.host.send({ type: "check", origin: c.origin, username: c.username, password: current })
      const fresh = await this.host.send({ type: "check", origin: c.origin, username: c.username, ...next })
      if (old.status === "same" && old.matches[0]) target = { ref: old.matches[0], username: c.username }
      else return this.offerFor(c, c.username, next, fresh)
    } else {
      // No username on the form: the one login here whose password is the
      // current one, else the only login here.
      const check = await this.host.send({ type: "check", origin: c.origin, password: current })
      const saved = (await this.host.send({ type: "list", origin: c.origin })).accounts.filter((a) => a.hasPassword)
      const match = check.status === "same" && check.matches.length === 1 ? saved.find((a) => a.ref === check.matches[0]) : saved.length === 1 ? saved[0] : undefined
      if (match) target = { ref: match.ref, username: match.username ?? "" }
    }
    if (!target) return undefined
    const { ref, username } = target
    const entry = { title: c.title, url: c.url, username, ...next }
    return { offer: { site: c.site, username: username || c.site, update: true }, save: () => this.host.send({ type: "save", origin: c.origin, ref, entry }) }
  }

  /** Hold the offer for the tab under a new id, badge the toolbar button, and open the popup if the site had its turn. */
  private async publish(tabId: number, ticket: Ticket, pending: Pending, turn: boolean) {
    this.dropOffer(tabId)
    const id = newToken()
    const timer = setTimeout(() => this.dropOffer(tabId, id), this.ttl.offer)
    this.offers.set(tabId, { offer: { ...pending.offer, id }, ticket, save: pending.save, timer, saving: false })
    void Promise.all([chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE }), chrome.action.setBadgeText({ tabId, text: "1" })]).catch(() => {})
    if (turn) await openPopupFor(tabId, () => this.offers.get(tabId)?.offer.id === id)
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

  /**
   * The tab's top page committed a new document. Another site's page ends the
   * sign-in and its offer; going anywhere by hand ends the sign-in, its offer
   * and any check still on its way, on the same site too.
   */
  navigated(tabId: number, url: string, transition?: string) {
    const site = siteOfUrl(url)
    const byHand = !!transition && BY_HAND.has(transition)
    if (!this.sites.has(tabId) || this.sites.get(tabId) !== site || byHand) this.moveOn(tabId)
    this.sites.set(tabId, site)
    if (this.captures.get(tabId)?.site !== site || byHand) this.dropCapture(tabId)
    if (this.offers.get(tabId)?.offer.site !== site || byHand) this.dropOffer(tabId)
  }

  forgetTab(tabId: number) {
    this.moveOn(tabId)
    this.sites.delete(tabId)
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
