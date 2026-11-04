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
// later, is only likely, and gets a badge but never opens the popup. Two
// signs from the form itself end it with no offer at all: the form that was
// submitted still showing about five seconds later in the same document
// (`db:failed`, 1Password's check), or posted back to the same page as a new
// document. Going elsewhere by hand (a typed address or a bookmark) abandons
// it, on the same site too.
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
//
// Cards and identities typed into a checkout or registration form get the
// same offer ("Save card?", "Update address?"), from the same corner and
// popup, on the same turn rule (see formCapture): what the user submitted is
// kept in memory only until the submit has gone through and the offer is
// answered or ends, never a security code, and the surface shows a card only
// as its brand and last four digits.

import type { ChooseReply, FieldRole, MenuLoadReply, OfferChoice, PageFacts, SaveOffer, SaveWhat, SurfaceKind } from "../messages"
import type { CardField, CheckReply, FormCard, FormKind, IdentityField, PasswordValue } from "../protocol"
import { IDENTITY_FIELDS } from "../protocol"
import { cardBrand } from "../payments"
import { resizeMessage } from "./autofill"
import { formsTargetFor, type FormsReport } from "./forms"
import { menuFrameOf, newToken, sendToFrame, targetFor, topTarget, type FrameTarget } from "./frames"
import { HostError, type VaultBackend } from "./backend"
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
/**
 * chrome.storage.local: sites the user said Never for, by name, unlike the
 * other site memories (salted hashes): Settings › Saving lists them to turn
 * back on, and a hash can't be shown as a name (docs/autofill.md).
 */
export const NEVER_KEY = "neverSave"
/** chrome.storage.session: SHA-256 of `site\nusername` → until when Not now holds it back. */
const NOT_NOW_KEY = "notNow"
/** chrome.storage.session: the salt for those hashes, made once per browser session. */
const SALT_KEY = "notNowSalt"
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
   * generated one is the daemon's for this origin only. Until one is, where
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
  /** Instead of `newPassword`: the id of the generated password the daemon holds. */
  generated?: string
  /** What a new login is named and where it's saved: the title and URL of the page the passwords were submitted on. */
  title: string
  url: string
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
  save: () => Promise<{ created: boolean }>
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

// ---- Cards and identities typed into a form -----------------------------------------

/** A card as a form gave it, by the host's field names: never its security code. */
export type CardValues = Partial<Record<Exclude<CardField, "cvv">, string>>
export type IdentityValues = Partial<Record<IdentityField, string>>

/** What a form save would write: the item's changed fields (`ref`), or a new one's. */
export interface FormPlan {
  ref?: string
  fields: Record<string, string>
  /** "Visa •••• 4242", "1 Main St, Springfield": all of it an offer shows. */
  label: string
  what: SaveWhat
}

interface FormCapture {
  site: string
  /** The top page's origin, which the save goes to, and its page (saveUrl), to tell it posted back. */
  origin: string
  page: string
  card?: CardValues
  identity?: IdentityValues
  /** The top page's document when the user submitted. */
  document: string
  /** The document whose submit this is (the top page's, or a frame's), and its count, for its outcome. */
  from: { document: string; submission?: number }
  until: number
  timer: ReturnType<typeof setTimeout>
}

const CARD_KEYS = ["number", "expiry", "cardholder", "brand"] as const
const MAX_FORM_VALUE = 500
/** Identities compared with what was typed, at most: each costs a fill-form of its fields. */
const MAX_COMPARED = 8
const ADDRESS_FIELDS: IdentityField[] = ["address-line1", "address-line2", "address-line3", "city", "region", "postal-code", "country"]
/** Groups of an identity's fields that change together: a move changes the address, not the name. */
const IDENTITY_GROUPS: IdentityField[][] = [
  ["honorific", "given-name", "additional-name", "family-name", "nickname"],
  ["email"],
  ["phone"],
  ADDRESS_FIELDS,
  ["organization", "job-title"],
  ["birthday"],
]
const UPDATED: Record<SaveWhat, string> = { card: "Card updated", address: "Address updated", details: "Details updated" }

/** A content script's values of `keys`, trimmed, nothing else. */
function cleanValues<K extends string>(raw: unknown, keys: readonly K[]): Partial<Record<K, string>> | undefined {
  if (!raw || typeof raw !== "object") return undefined
  const out: Partial<Record<K, string>> = {}
  for (const k of keys) {
    const v = (raw as Record<string, unknown>)[k]
    if (typeof v === "string" && v.trim() && v.length <= MAX_FORM_VALUE) out[k] = v.trim()
  }
  return Object.keys(out).length ? out : undefined
}

/** A card's values: a number only as 12 to 19 digits, an expiry only as YYYY-MM, and never a code. */
export function cleanCard(raw: unknown): CardValues | undefined {
  const card = cleanValues(raw, CARD_KEYS)
  if (card?.number && !/^\d{12,19}$/.test(card.number)) delete card.number
  if (card?.expiry && !/^\d{4}-(0[1-9]|1[0-2])$/.test(card.expiry)) delete card.expiry
  return card && Object.keys(card).length ? card : undefined
}

export const cleanIdentity = (raw: unknown): IdentityValues | undefined => cleanValues(raw, IDENTITY_FIELDS)

const merged = <T extends object>(a: T | undefined, b: T | undefined): T | undefined => (a || b ? { ...a, ...b } as T : undefined)

const folded = (s: string | undefined) => (s ?? "").trim().toLowerCase().replace(/\s+/g, " ")
const digitsOf = (s: string | undefined) => (s ?? "").replace(/\D/g, "")

/** Whether a saved value is the one typed: as text, a phone by its digits (one may lack the calling code). */
function sameValue(field: string, typed: string | undefined, saved: string | undefined): boolean {
  if (field === "phone") {
    const [a, b] = [digitsOf(typed), digitsOf(saved)]
    return a.length >= 7 && b.length >= 7 ? a.endsWith(b) || b.endsWith(a) : a === b
  }
  return folded(typed) === folded(saved)
}

/** "Visa •••• 4242": a card's brand and last four digits, all of its number an offer shows. */
export const cardLabel = (brand: string | undefined, last4: string) => `${brand || "Card"} •••• ${last4}`

/** "1 Main St, Springfield", else the name, the email or the phone. */
export function identityLabel(v: IdentityValues): string {
  const place = [v["address-line1"], v.city].filter(Boolean).join(", ")
  const name = [v["given-name"], v["family-name"]].filter(Boolean).join(" ")
  return Array.from(place || name || v.email || v.phone || "Address").slice(0, 80).join("")
}

/**
 * What to offer for a card typed into a form, against the vault's cards
 * (`forms`, which has no numbers): a card with the same last four digits
 * and brand is that card, offered as an update of its expiry or name when
 * either changed and not at all when neither did; any other is a new card.
 * The number itself never changes on an update.
 */
export function cardPlan(card: CardValues, cards: FormCard[]): FormPlan | null {
  const number = card.number
  if (!number) return null
  const last4 = number.slice(-4)
  const match = cards.find((c) => c.last4 === last4 && (!c.brand || !card.brand || folded(c.brand) === folded(card.brand)))
  if (!match) {
    const fields = Object.fromEntries(CARD_KEYS.filter((k) => card[k]).map((k) => [k, card[k]!]))
    return { fields, label: cardLabel(card.brand, last4), what: "card" }
  }
  const fields: Record<string, string> = {}
  if (card.expiry && card.expiry !== match.expiry) fields.expiry = card.expiry
  if (card.cardholder && !sameValue("cardholder", card.cardholder, match.cardholder)) fields.cardholder = card.cardholder
  return Object.keys(fields).length ? { ref: match.ref, fields, label: cardLabel(match.brand || card.brand, last4), what: "card" } : null
}

/** Enough of an identity to be worth keeping: an address (its street and city or postal code), or a name with an email and a phone. */
export function worthKeeping(v: IdentityValues): boolean {
  return (!!v["address-line1"] && !!(v.city || v["postal-code"])) || (!!(v["given-name"] || v["family-name"]) && !!v.email && !!v.phone)
}

/**
 * What to offer for an identity typed into a form, against the vault's
 * identities' values for the same fields: none if one already has them all;
 * an update of the one that differs in at most one group of fields (a new
 * address, a new phone) and agrees on another, the most agreeing first,
 * with what changed or was missing; else a new identity.
 */
export function identityPlan(identity: IdentityValues, known: Array<{ ref: string; values: IdentityValues }>): FormPlan | null {
  if (!worthKeeping(identity)) return null
  const label = identityLabel(identity)
  const what: SaveWhat = ADDRESS_FIELDS.some((f) => identity[f]) ? "address" : "details"
  let best: { ref: string; fields: Record<string, string>; agree: number } | undefined
  for (const k of known) {
    let agree = 0
    let differ = 0
    const fields: Record<string, string> = {}
    for (const group of IDENTITY_GROUPS) {
      const mine = group.filter((f) => identity[f])
      if (!mine.length) continue
      const changed = mine.filter((f) => !sameValue(f, identity[f], k.values[f]))
      if (!changed.length) {
        agree++
        continue
      }
      if (changed.some((f) => k.values[f])) differ++
      for (const f of changed) fields[f] = identity[f]!
    }
    if (!Object.keys(fields).length) return null
    if (agree && differ <= 1 && (!best || agree > best.agree)) best = { ref: k.ref, fields, agree }
  }
  if (best) return { ref: best.ref, fields: best.fields, label, what }
  return { fields: { ...identity } as Record<string, string>, label, what }
}

/** What Not now holds back: a login by its username, a card or identity by its label. */
const heldKey = (o: Pick<SaveOffer, "username" | "what">) => (o.what ? `${o.what}:${o.username}` : o.username)

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
  /** Told when a sign-in in a tab worked (confirmed or likely), with its site. */
  signedIn?: (tabId: number, site: string) => void
  /**
   * The username of a sign-in its form said failed (see failed, page), while
   * its capture would have been kept: nothing of it is offered, but the next
   * try's menu still narrows to it (see username).
   */
  private failedNames = new Map<number, { site: string; username: string; until: number }>()
  /** Bumped by each settled page in a tab; a second look for an older one is dropped. */
  private rounds = new Map<number, number>()

  /** Cards and identities a form submitted, in memory only, until the submit is judged or they expire. */
  private formCaptures = new Map<number, FormCapture>()
  /** The frames of a tab that reported identity or card fields (bg/forms.ts), to read on a top page's submit and to tell a form posted back. */
  formFrames?: (tabId: number) => FormsReport[]

  /** Serializes the once-per-site check, so two tabs can't both take the turn. */
  private opening: Promise<unknown> = Promise.resolve()
  private ttl: { capture: number; offer: number; held: number; reprobe: number }

  constructor(
    private host: VaultBackend,
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
    // Never for this site: what was typed isn't even kept.
    if ((await neverSites()).includes(site) || !this.fresh(tabId, ticket)) return
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
      // its own origin that has none yet, and changes nothing else (what was
      // said about that password stays, and it goes when that password
      // would have): once a username is paired with a password nothing
      // replaces it, and another host's username never joins.
      if (held) {
        if (held.username || held.origin !== target.origin) return
        this.captures.set(tabId, { ...held, username, ...usernameFrom })
        return
      }
      // Else it waits for the password, as an email-first step's does.
      this.keep(tabId, { site, ...here, username, ...usernameFrom, since: now, until: now + this.ttl.capture, failed: false, ...submitted })
      return
    }
    // Passwords stay with the origin they were submitted on: one from another
    // of the site's hosts takes over, and the earlier ones and their username
    // go, unless that username was a sign-in's own step with no password yet
    // and this is the top page. Nor do passwords carry to another username.
    // A new password is a new attempt: nothing said about an earlier one holds.
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
      since: now,
      until: now + this.ttl.capture,
      failed: false,
      ...submitted,
    })
  }

  /** Holds `c` for the tab until it expires. */
  private keep(tabId: number, c: Omit<Capture, "timer">) {
    this.dropCapture(tabId)
    this.failedNames.delete(tabId)
    const timer = setTimeout(() => this.dropCapture(tabId), Math.max(0, c.until - this.now()))
    this.captures.set(tabId, { ...c, timer })
  }

  /**
   * The form submitted as `submission` still shows in place, five seconds
   * on: the sign-in failed, and nothing it submitted is offered. A failure
   * for an earlier submit, or from another document, says nothing.
   */
  failed(sender: chrome.runtime.MessageSender, submission: unknown) {
    const tabId = sender.tab?.id
    const page = senderOrigin(sender)
    const c = tabId === undefined ? undefined : this.captures.get(tabId)
    if (!c || !page || saveUrl(page) !== c.form || !sender.documentId || sender.documentId !== c.document) return
    if (Number.isSafeInteger(submission) && submission === c.submission) this.dropFailed(tabId!, c)
  }

  /** A page reported its form. The one just submitted, posted back to the same page as a new document, means the sign-in failed. */
  page(sender: chrome.runtime.MessageSender, kind: SurfaceKind | null, roles: FieldRole[]) {
    const tabId = sender.tab?.id
    const page = senderOrigin(sender)
    const c = tabId === undefined ? undefined : this.captures.get(tabId)
    if (!c || !page || !kind || kind !== c.kind || sender.documentId === c.document || saveUrl(page) !== c.form) return
    if (c.secrets.some((r) => roles.includes(r))) this.dropFailed(tabId!, c)
  }

  /** The sign-in `c` failed: nothing of it is offered; only its username is kept, for the menu. */
  private dropFailed(tabId: number, c: Capture) {
    this.dropCapture(tabId)
    if (c.username) this.failedNames.set(tabId, { site: c.site, username: c.username, until: c.until })
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

  /**
   * The username the user submitted in this tab on `site`, while its capture
   * is kept: the next step's menu narrows to the login it names (see
   * Autofill.query). It doesn't leave the extension.
   */
  username(tabId: number, site: string): string | undefined {
    const c = this.captures.get(tabId)
    if (c) return c.site === site && c.until > this.now() ? c.username : undefined
    const f = this.failedNames.get(tabId)
    return f && f.site === site && f.until > this.now() ? f.username : undefined
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
    if (tabId === undefined || sender.frameId !== 0) return
    const form = this.formCaptures.get(tabId)
    if (form && sender.documentId && sender.documentId !== form.document) void this.formSettled(tabId, form, sender)
    if (!this.captures.has(tabId)) return
    const ticket = this.ticket(tabId)
    const round = (this.rounds.get(tabId) ?? 0) + 1
    this.rounds.set(tabId, round)
    const target = await targetFor(sender)
    const c = this.captures.get(tabId)
    if (!target || !c || !this.fresh(tabId, ticket) || siteOf(new URL(target.origin).hostname) !== c.site) return
    // A username on its own is the first step of a sign-in, not its end:
    // nothing to judge (and no "failed" to keep) until a password comes.
    if (!c.password && !newSecret(c)) return
    const current = () => this.captures.get(tabId) === c && this.rounds.get(tabId) === round && this.fresh(tabId, ticket)
    const created = !!newSecret(c)
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
    // It worked: the site's sign-in shape is worth remembering (bg/autofill.ts Flow).
    this.signedIn?.(tabId, c.site)
    this.dropCapture(tabId)
    if (c.until <= this.now()) return
    if ((await neverSites()).includes(c.site)) return
    if (c.username && !newSecret(c) && (await this.heldBack(c.site, c.username))) return
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
    const next = newSecret(c)
    if (next && c.password) return { asked: true, pending: await this.passwordChange(c, next, c.password) }
    const secret = next ?? (c.password ? { password: c.password } : undefined)
    if (!secret || !c.username) return { asked: false }
    return { asked: true, pending: await this.saveOrUpdate(c, c.username, secret) }
  }

  private async saveOrUpdate(c: Capture, username: string, secret: PasswordValue): Promise<Pending | undefined> {
    return this.offerFor(c, username, secret, await this.host.send({ type: "check", origin: c.origin, username, ...secret }))
  }

  // ---- Cards and identities ----------------------------------------------------------

  /**
   * The user submitted card or identity fields they typed into: keep the
   * values in memory for the tab until the submit is judged (see
   * formOutcome, formSettled) or they expire. A frame gets only what it may
   * be filled with (formsTargetFor): a provider's card frame a card, the
   * site's own frames an identity too. The top page's submit also reads the
   * frames below that reported such fields, so a card typed into Stripe's
   * frame joins the name typed in the page, as one offer. Nothing is kept
   * for a site saving is off for, or a vault that can't save forms.
   */
  async formCapture(sender: chrome.runtime.MessageSender, raw: { card?: unknown; identity?: unknown; submission?: unknown }) {
    const tabId = sender.tab?.id
    if (tabId === undefined || !sender.documentId || !this.host.capabilities.includes("save-form")) return
    const ticket = this.ticket(tabId)
    const [cardFrom, identityFrom] = await Promise.all([formsTargetFor(sender, "card"), formsTargetFor(sender, "identity")])
    // The top page's own submit is judged by its document (it may have moved on already); a frame's, by the page around it.
    const { target: top, url: topUrl } = sender.frameId === 0 ? { target: null, url: senderOrigin(sender) } : await topTarget(tabId)
    const url = topUrl ?? null
    const document = sender.frameId === 0 ? sender.documentId : top?.documentId
    const site = url ? siteOf(url.hostname) : null
    if ((!cardFrom && !identityFrom) || !document || !url || !site || !this.fresh(tabId, ticket)) return
    if ((await neverSites()).includes(site) || !this.fresh(tabId, ticket)) return
    let card = cardFrom ? cleanCard(raw.card) : undefined
    let identity = identityFrom ? cleanIdentity(raw.identity) : undefined
    if (sender.frameId === 0) {
      for (const frame of this.formFrames?.(tabId) ?? []) {
        if (frame.frameId === 0) continue
        const got = await sendToFrame<{ card?: unknown; identity?: unknown }>(frame, { type: "db:forms-read" })
        if (!got) continue
        if (frame.kinds.includes("card")) card = merged(card, cleanCard(got.card))
        if (!frame.provider && frame.kinds.includes("identity")) identity = merged(identity, cleanIdentity(got.identity))
      }
      if (!this.fresh(tabId, ticket)) return
    }
    const now = this.now()
    const prev = this.formCaptures.get(tabId)
    const same = prev && prev.site === site && prev.until > now ? prev : undefined
    card = merged(same?.card, card)
    identity = merged(same?.identity, identity)
    // A frame's number without a brand of its own: the number's first digits say.
    if (card?.number && !card.brand) card.brand = cardBrand(card.number)
    if (!card && !identity) return
    this.dropFormCapture(tabId)
    const timer = setTimeout(() => this.dropFormCapture(tabId), this.ttl.capture)
    const submission = Number.isSafeInteger(raw.submission) ? (raw.submission as number) : undefined
    this.formCaptures.set(tabId, { site, origin: url.origin, page: saveUrl(url), card, identity, document, from: { document: sender.documentId, submission }, until: now + this.ttl.capture, timer })
  }

  /** The document that submitted says how it went: its fields went away (it went through), or it shows it was turned down. */
  async formOutcome(sender: chrome.runtime.MessageSender, submission: unknown, ok: boolean) {
    const tabId = sender.tab?.id
    const c = tabId === undefined ? undefined : this.formCaptures.get(tabId)
    if (!c || !sender.documentId || sender.documentId !== c.from.document || submission !== c.from.submission) return
    if (!ok) return this.dropFormCapture(tabId!)
    await this.offerForm(tabId!, c)
  }

  /**
   * The top page settled on a new document after a card or identity was
   * submitted: it went through, unless the new document is the same page
   * showing the same kind of fields again (posted back, as a declined card is).
   */
  private async formSettled(tabId: number, c: FormCapture, sender: chrome.runtime.MessageSender) {
    const page = senderOrigin(sender)
    const target = await targetFor(sender)
    if (!page || !target || this.formCaptures.get(tabId) !== c) return
    const shown = new Set((this.formFrames?.(tabId) ?? []).flatMap((f) => f.kinds))
    if (saveUrl(page) === c.page && ((c.card && shown.has("card")) || (c.identity && shown.has("identity")))) return this.dropFormCapture(tabId)
    await this.offerForm(tabId, c, target)
  }

  private dropFormCapture(tabId: number) {
    const c = this.formCaptures.get(tabId)
    if (!c) return
    clearTimeout(c.timer)
    this.formCaptures.delete(tabId)
  }

  /** The submit went through: what to offer, on the same turn rule as a login (see settled). */
  private async offerForm(tabId: number, c: FormCapture, target?: FrameTarget) {
    if (this.formCaptures.get(tabId) !== c) return
    this.dropFormCapture(tabId)
    const ticket = this.ticket(tabId)
    if (c.until <= this.now() || (await neverSites()).includes(c.site) || !this.fresh(tabId, ticket)) return
    const decided = await this.decideForm(c, tabId).catch((): { asked: boolean; pending?: Pending } => ({ asked: true }))
    const turn = decided.asked ? await this.openTurn(c.site).catch(() => false) : false
    if (!decided.pending || !(await this.still(tabId, ticket, c.site))) return
    if (await this.heldBack(c.site, heldKey(decided.pending.offer))) return
    const top = target ?? (await topTarget(tabId)).target ?? undefined
    await this.publish(tabId, ticket, decided.pending, turn, top)
  }

  /**
   * Asks the vault what it has: a card is compared by the listing alone
   * (last four digits, brand, expiry, name; never its number), an identity
   * by the values of the fields typed, for a few identities that have them.
   * A card comes first; its offer leaves the identity's for the next submit.
   */
  private async decideForm(c: FormCapture, tabId: number): Promise<{ asked: boolean; pending?: Pending }> {
    const listed = await this.host.send({ type: "forms", origin: c.origin, kinds: ["identity", "card"] })
    const card = c.card ? cardPlan(c.card, listed.cards) : null
    if (card) return { asked: true, pending: this.formPending(tabId, c, "card", card) }
    const identity = c.identity
    if (!identity || !worthKeeping(identity)) return { asked: true }
    const candidates = listed.identities.filter((i) => i.fields.some((f) => identity[f])).slice(0, MAX_COMPARED)
    const known = await Promise.all(
      candidates.map(async (i) => ({ ref: i.ref, values: (await this.host.send({ type: "fill-form", origin: c.origin, ref: i.ref, fields: i.fields.filter((f) => identity[f]) })).values as IdentityValues })),
    )
    const plan = identityPlan(identity, known)
    return { asked: true, pending: plan ? this.formPending(tabId, c, "identity", plan) : undefined }
  }

  private formPending(tabId: number, c: FormCapture, kind: FormKind, plan: FormPlan): Pending {
    const body = { type: "save-form" as const, origin: c.origin, kind, ...(plan.ref ? { ref: plan.ref } : {}), fields: plan.fields }
    return {
      offer: { site: c.site, username: plan.label, update: !!plan.ref, what: plan.what },
      save: async () => {
        try {
          return await this.host.send(body)
        } catch (err) {
          // The browser-only vault under Strict: a card's save asks for the passphrase, as showing its number does.
          if (!(this.host.reauth && err instanceof HostError && err.code === "passphrase_needed")) throw err
          return this.host.reauth(body, { tabId, title: plan.label, site: c.site }, new AbortController().signal)
        }
      },
    }
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

  /** What the surface may show: the site, the username (a card's or identity's label) and whether it's an update. */
  async surfaceLoad(token: string, sender: chrome.runtime.MessageSender, parent: string): Promise<MenuLoadReply | null> {
    const s = await this.surface(token, sender, parent)
    const o = s && this.offers.get(s.target.tabId)
    if (!s || !o || o.offer.id !== s.offer || this.host.status.state !== "ready") return null
    return { kind: "offer", site: o.offer.site, username: o.offer.username, update: o.offer.update, ...(o.offer.what ? { what: o.offer.what } : {}) }
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
        this.dropFormCapture(tabId)
        await this.setNever(o.offer.site, true)
      } else await this.holdBack(o.offer.site, heldKey(o.offer))
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
      return { ok: true, message: reply.created ? "Saved to Deadbolt" : o.offer.what ? UPDATED[o.offer.what] : "Password updated" }
    } catch (err) {
      o.saving = false
      if (err instanceof HostError && err.code === "locked") return { ok: false, message: "Deadbolt is locked. Unlock it, then save again." }
      if (err instanceof HostError && err.code === "cancelled") return { ok: false, message: "Deadbolt didn't get your passphrase. Nothing was saved." }
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

  /**
   * The tab's top page committed a new document. Another site's page ends the
   * sign-in and its offer; going anywhere by hand ends the sign-in, its offer
   * and any check still on its way, on the same site too.
   */
  navigated(tabId: number, url: string, transition?: string) {
    // The page the surface was in is gone, and the surface with it.
    this.dropTabSurfaces(tabId)
    const site = siteOfUrl(url)
    const byHand = !!transition && BY_HAND.has(transition)
    if (!this.sites.has(tabId) || this.sites.get(tabId) !== site || byHand) this.moveOn(tabId)
    this.sites.set(tabId, site)
    if (this.captures.get(tabId)?.site !== site || byHand) this.dropCapture(tabId)
    if (this.formCaptures.get(tabId)?.site !== site || byHand) this.dropFormCapture(tabId)
    if (this.failedNames.get(tabId)?.site !== site || byHand) this.failedNames.delete(tabId)
    if (this.offers.get(tabId)?.offer.site !== site || byHand) this.dropOffer(tabId)
  }

  forgetTab(tabId: number) {
    this.moveOn(tabId)
    this.sites.delete(tabId)
    this.rounds.delete(tabId)
    this.failedNames.delete(tabId)
    this.dropTabSurfaces(tabId)
    this.dropCapture(tabId)
    this.dropFormCapture(tabId)
    this.dropOffer(tabId)
  }

  forgetAll() {
    this.epoch++
    this.failedNames.clear()
    for (const tabId of [...this.captures.keys()]) this.dropCapture(tabId)
    for (const tabId of [...this.formCaptures.keys()]) this.dropFormCapture(tabId)
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
