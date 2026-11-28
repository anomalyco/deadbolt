// A tab's sign-in, followed step by step: the AuthFlow state machine.
//
// A guarded pick (the inline menu, the corner offer, the toolbar popup)
// starts a flow; each step's fill moves it on (identifier, then secret, then
// mfa) until nothing is left to fill (settled), and its timer, Esc, a lock,
// the user's own navigation or another site ends it (idle). The transitions
// are pure (see transition), so each rule is tested on its own; AuthFlows
// keeps each tab's flow in session storage, so a service worker restart
// doesn't lose the step, and runs each tab's work one piece at a time.
//
// The shape of each site's sign-in, learned from sign-ins that worked, is
// kept here too (see SiteFlow): whether it asks for the username first, and
// whether its steps come by navigation.

import { IDENTIFIER_ROLES, type FieldRole, type SurfaceKind } from "../messages"
import type { Account } from "../protocol"
import { newToken, type FrameTarget } from "./frames"
import { siteOf } from "./site"

/** A flow lasts this long from the pick that started it. */
export const SESSION_TTL_MS = 3 * 60_000
/** A home/modal entry must reach its first login step promptly, not arm a later task. */
export const AUTOMATIC_ENTRY_MS = 20_000
/** An automatic flow's next step must show this soon after its last automatic submit. */
export const AUTOMATIC_STEP_MS = 20_000
export const MAX_AUTOMATIC_SUBMITS = 4
/** On a site whose steps come by navigation (see SiteFlow), this much longer, for a slow page. */
export const SESSION_GRACE_MS = 60_000
/** chrome.storage.local: the shape of each site's sign-in (see SiteFlow), by a salted hash of the site. */
export const FLOWS_KEY = "signinFlows"
/** chrome.storage.local: a random salt made once per install, for the keys of FLOWS_KEY. */
export const FLOWS_SALT_KEY = "signinFlowsSalt"
const MAX_FLOWS = 300
/** Navigations the user started themselves end a flow, as does going back or forward (see transition). */
const UNRELATED = new Set(["typed", "auto_bookmark", "generated", "keyword", "keyword_generated", "reload", "start_page", "auto_toplevel"])
/** Each tab's flow is kept in session storage under this prefix and its tab id. */
const KEY = "session:"

/**
 * A sign-in flow: the login the user picked, followed through the next
 * steps of the sign-in in the same tab. When the top page, or a frame that
 * may have the inline menu (see sameSiteTop), shows the next step (a
 * password, a one-time code, the username asked again beside a password), it
 * fills from the same login without another pick: once per step, only after
 * the user's own submit (see Autofill.page), only on the origin the pick was
 * on or one whose host a saved URL of the login names exactly, only into a
 * frame whose fields show through every frame above, and only for a few
 * minutes.
 */
export interface AuthFlow {
  /**
   * Auto-submit, with "Offer to sign in" on: set only by startAutomatic, for
   * a guarded pick in an extension-owned surface (the corner offer, the
   * inline menu) or the toolbar popup's Fill. Never by a page's own event.
   */
  automatic?: boolean
  /** Submit calls made by this automatic flow, carried across its steps. */
  automaticSubmits?: number
  /** When a password step of this automatic flow was last submitted (by it or the user): a code step may be submitted only soon after. */
  passwordSubmittedAt?: number
  ref: string
  /** The site (registrable domain): leaving it ends the flow. */
  site: string
  /** The origin the pick was on. Another origin is a step only if a saved URL of the login names its host. */
  origin: string
  /** The document the last step filled, and when. */
  documentId: string
  filledAt: number
  /** What the flow has filled so far. */
  filled: FieldRole[]
  startedAt: number
  until: number
}

/** What a first step's fill needs of the flow it starts. */
export type FlowStart = Pick<AuthFlow, "ref" | "origin" | "filled" | "startedAt" | "automatic" | "automaticSubmits">

/**
 * Where a flow stands, by what it waits for: identifier, an automatic entry
 * that hasn't reached its first login step; secret, the password after the
 * username went in; mfa, the code after the password; settled, nothing more
 * to fill. idle: no flow.
 */
export type AuthPhase = "idle" | "identifier" | "secret" | "mfa" | "settled"

export function phaseOf(flow: AuthFlow | undefined, account?: Pick<Account, "hasPassword" | "hasTotp">): AuthPhase {
  if (!flow) return "idle"
  if (!flow.filled.length) return "identifier"
  const next = account ? nextStep(flow.filled, account) : flow.filled.includes("otp") ? undefined : flow.filled.includes("password") ? "otp" : "password"
  return next === "password" ? "secret" : next === "otp" ? "mfa" : "settled"
}

/** What moves a flow on, or ends it. */
export type FlowEvent =
  /** A step's fill wrote these roles into the target (navigates: the site's learned steps come by navigation). */
  | { type: "filled"; account: Pick<Account, "ref" | "hasPassword" | "hasTotp">; site: string; target: Pick<FrameTarget, "origin" | "documentId">; filled: FieldRole[]; now: number; navigates: boolean }
  /** The automatic flow submitted a step whose form had these roles. */
  | { type: "step-submitted"; roles: FieldRole[]; now: number }
  /** The user themselves submitted a login form in this document. */
  | { type: "user-submitted"; documentId: string; at: number }
  | { type: "tick"; now: number }
  | { type: "escape" }
  | { type: "lock" }
  | { type: "signed-in" }
  /** The top page committed a new document at this URL. */
  | { type: "navigate"; url: string; transitionType?: string; transitionQualifiers?: string[] }

const live = (flow: AuthFlow | FlowStart | undefined): flow is AuthFlow => !!flow && "until" in flow

/** Whether the user started this navigation themselves (a typed address, a bookmark, a reload, back or forward): it ends any flow. */
export const userNavigation = (event: { transitionType?: string; transitionQualifiers?: string[] }) =>
  UNRELATED.has(event.transitionType ?? "") || !!event.transitionQualifiers?.includes("forward_back")

/**
 * The flow after an event; undefined when it's over. For "filled", the flow
 * given is the one the fill was a step of (or a pick's start): a step of the
 * same login keeps its start, origin and what it filled before; another
 * login's fill starts afresh. A fill that leaves nothing more to fill
 * settles it. Esc and a lock end any flow; the user's own navigation (typed,
 * a bookmark, a reload, back or forward) or another site ends it; a
 * confirmed sign-in ends an automatic one.
 */
export function transition(flow: AuthFlow | FlowStart | undefined, event: FlowEvent): AuthFlow | undefined {
  switch (event.type) {
    case "filled": {
      const { account, now } = event
      const same = flow?.ref === account.ref ? flow : undefined
      const filled = [...new Set([...(same?.filled ?? []), ...event.filled])]
      if (!nextStep(filled, account)) return undefined
      const startedAt = same?.startedAt ?? now
      const until = startedAt + SESSION_TTL_MS + (event.navigates ? SESSION_GRACE_MS : 0)
      // Only the same login's flow carries its automatic submits on; another login's fill starts as a fill.
      const auto = same?.automatic ? { automatic: true, automaticSubmits: same.automaticSubmits ?? 0 } : {}
      return { ref: account.ref, site: event.site, origin: same?.origin ?? event.target.origin, documentId: event.target.documentId, filledAt: now, filled, startedAt, until, ...auto }
    }
    case "tick":
      return live(flow) && event.now < flow.until ? flow : undefined
    case "escape":
    case "lock":
      return undefined
    case "signed-in":
      return live(flow) && !flow.automatic ? flow : undefined
    case "navigate":
      if (!live(flow) || userNavigation(event)) return undefined
      return siteOfUrl(event.url) === flow.site ? flow : undefined
    case "step-submitted": {
      if (!live(flow)) return undefined
      // Submitted, the next step has to show promptly; a password step submitted lets a code step follow it.
      const until = Math.min(flow.until, event.now + AUTOMATIC_STEP_MS)
      return { ...flow, automaticSubmits: (flow.automaticSubmits ?? 0) + 1, until, ...(event.roles.includes("password") ? { passwordSubmittedAt: event.now } : {}) }
    }
    case "user-submitted":
      // The user's own submit of an automatic flow's password step lets its code step follow, as an automatic one does.
      if (!live(flow)) return undefined
      return flow.automatic && flow.documentId === event.documentId && flow.filled.includes("password") ? { ...flow, passwordSubmittedAt: event.at } : flow
  }
}

/** The step a flow waits for after its fills wrote these roles, if any. */
export function nextStep(filled: FieldRole[], account: Pick<Account, "hasPassword" | "hasTotp">): "password" | "otp" | undefined {
  if (filled.includes("otp")) return undefined
  if (filled.includes("password")) return account.hasTotp ? "otp" : undefined
  if (filled.some((r) => IDENTIFIER_ROLES.includes(r))) return account.hasPassword ? "password" : account.hasTotp ? "otp" : undefined
  return undefined
}

/**
 * What a step's form should get from the flow, given the roles it
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
 * What a flow's step may fill in a form the content script reported, or
 * "end" when the form says the sign-in turned into something else. Only a
 * sign-in step: on a login form, its current password (never when the form
 * also has a new-password box, or a password box asks for a new password by
 * autocomplete, which may be a sign-up the detector took for a login) and
 * the username beside it; on a code step, the code. A sign-up or
 * change-password form ends the flow: its password box wants a new
 * password, never the saved one. Anything else, a login form it can't be
 * sure of included, fills nothing; an explicit pick still can.
 */
export function sessionStep(kind: SurfaceKind | null, roles: FieldRole[], asksNew: boolean): FieldRole[] | "end" {
  if (kind === "signup" || kind === "change-password") return "end"
  if (kind === "mfa") return ["otp"]
  if (kind !== "login" || roles.includes("new-password") || asksNew) return []
  return [...IDENTIFIER_ROLES, "password", "otp"]
}

/**
 * Whether a pick on this form may sign in rather than only fill: a login
 * form with a username box (a first step), never a code step on its own, a
 * sign-up or change-password form, or one whose password box asks for a new
 * password (see sessionStep). A password or code box alone is more often a
 * re-authentication (Confirm access, a withdrawal, turning 2FA off) than a
 * sign-in. The pick also needs the page to look signed out (see startAutomatic).
 */
export const signsIn = (kind: SurfaceKind | null | undefined, roles: FieldRole[], asksNew = false) =>
  kind === "login" && !asksNew && !roles.includes("new-password") && roles.some((r) => IDENTIFIER_ROLES.includes(r))

/** The pill's word for a step: what it filled that matters most. */
export function stepLabel(filled: FieldRole[]): string {
  if (filled.includes("otp")) return "Code filled"
  if (filled.includes("password")) return "Password filled"
  return "Filled"
}

export function siteOfUrl(url: string | undefined): string | null {
  try {
    return url ? siteOf(new URL(url).hostname) : null
  } catch {
    return null
  }
}

/**
 * Each tab's flow, kept in session storage, with a timer that ends it when
 * it runs out. A tab's flow work runs one piece at a time (see serial), so a
 * step is used once; ending a flow bumps the tab's generation, and work
 * started before then arms nothing.
 */
export class AuthFlows {
  private timers = new Map<number, ReturnType<typeof setTimeout>>()
  private queues = new Map<number, Promise<unknown>>()
  private cancels = new Map<number, number>()
  /** Bumped when every flow ends (a lock): work in any tab started before then arms nothing, stored flow or not. */
  private epoch = 0
  /** The last time the user themselves (or an automatic flow) submitted a login form in each tab, and in which document. */
  private submits = new Map<number, { documentId: string; at: number }>()

  /** The tab's flow, if it hasn't run out. */
  async get(tabId: number): Promise<AuthFlow | undefined> {
    const key = KEY + tabId
    const stored = (await chrome.storage.session.get(key))[key] as AuthFlow | undefined
    const flow = transition(stored, { type: "tick", now: Date.now() })
    if (stored && !flow) await chrome.storage.session.remove(key)
    return flow
  }

  async set(tabId: number, flow: AuthFlow | undefined) {
    const key = KEY + tabId
    clearTimeout(this.timers.get(tabId))
    this.timers.delete(tabId)
    if (!flow) return chrome.storage.session.remove(key)
    await chrome.storage.session.set({ [key]: flow })
    this.timers.set(tabId, setTimeout(() => void this.set(tabId, undefined), Math.max(0, flow.until - Date.now())))
  }

  /** Changes whenever the tab's flow ends, or every flow does: both only ever count up. */
  generation(tabId: number): number {
    return this.epoch + (this.cancels.get(tabId) ?? 0)
  }

  serial<T>(tabId: number, work: () => Promise<T>): Promise<T> {
    const run = (this.queues.get(tabId) ?? Promise.resolve()).then(work)
    this.queues.set(tabId, run.catch(() => {}))
    return run
  }

  /** The tab's flow ends (Esc, the user leaving), including fills still on their way. */
  cancel(tabId: number) {
    this.cancels.set(tabId, (this.cancels.get(tabId) ?? 0) + 1)
    return this.serial(tabId, () => this.set(tabId, undefined))
  }

  /** Ends the tab's flow from inside serial. */
  async end(tabId: number) {
    this.cancels.set(tabId, (this.cancels.get(tabId) ?? 0) + 1)
    await this.set(tabId, undefined)
  }

  /** Every flow ends (Deadbolt locked or went away): each one in session storage, whether or not this worker started it. */
  async endAll() {
    this.epoch++
    const all = (await chrome.storage.session.get(null).catch(() => ({}))) as Record<string, unknown>
    const tabs = new Set([...this.timers.keys()])
    for (const key of Object.keys(all)) if (key.startsWith(KEY)) tabs.add(Number(key.slice(KEY.length)))
    await Promise.all([...tabs].map((tabId) => this.cancel(tabId)))
    const left = Object.keys(all).filter((k) => k.startsWith(KEY))
    if (left.length) await chrome.storage.session.remove(left).catch(() => {})
  }

  /** Every automatic flow ends ("Offer to sign in" turned off). */
  async endAutomatic() {
    const all = await chrome.storage.session.get(null)
    for (const [key, value] of Object.entries(all)) if (key.startsWith(KEY) && (value as AuthFlow)?.automatic) void this.cancel(Number(key.slice(KEY.length)))
  }

  /** A login form was submitted in this tab's document, by the user or by an automatic flow. */
  noteSubmit(tabId: number, documentId: string, at = Date.now()) {
    this.submits.set(tabId, { documentId, at })
  }

  lastSubmit(tabId: number): { documentId: string; at: number } | undefined {
    return this.submits.get(tabId)
  }

  forget(tabId: number) {
    this.submits.delete(tabId)
    return this.cancel(tabId)
  }
}

// ---- What each site's sign-in looks like ------------------------------------

/**
 * The shape of a site's sign-in, learned from sign-ins that worked (no
 * usernames, no values): whether it asks for the username on a step of its
 * own first, whether a code step usually follows the password, and whether
 * its steps come by navigation or in the same document.
 */
export interface SiteFlow {
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
 * shown of the current sign-in, to learn its SiteFlow from. Each frame has
 * its own: a top page's identifier and a frame's password box aren't one
 * form's steps.
 */
interface Track {
  site: string
  identifierDoc?: string
  passwordDoc?: string
  otp: boolean
}

/** What each tab has shown of its sign-in, and the SiteFlow learned once one works. */
export class FlowLearner {
  private tracks = new Map<number, Map<number, Track>>()

  /** What the top page (or its same-site login frame) shows of the sign-in, step by step. */
  track(target: FrameTarget, roles: FieldRole[]) {
    const site = siteOf(new URL(target.origin).hostname)
    if (!site) return
    const frames = this.tracks.get(target.tabId) ?? new Map<number, Track>()
    this.tracks.set(target.tabId, frames)
    // Another site's sign-in starts over, in every frame.
    for (const [id, other] of frames) if (other.site !== site) frames.delete(id)
    let t = frames.get(target.frameId)
    if (!t) frames.set(target.frameId, (t = { site, otp: false }))
    const id = roles.some((r) => IDENTIFIER_ROLES.includes(r))
    if (roles.includes("password")) t.passwordDoc ??= target.documentId
    else if (id) t.identifierDoc ??= target.documentId
    if (roles.includes("otp") && t.passwordDoc) t.otp = true
  }

  /** The top page committed a new document: a sign-in tracked on another site starts over. */
  navigated(tabId: number, url: string) {
    const tracked = this.tracks.get(tabId)
    if (tracked && [...tracked.values()].some((t) => t.site !== siteOfUrl(url))) this.tracks.delete(tabId)
  }

  forget(tabId: number) {
    this.tracks.delete(tabId)
  }

  /** A sign-in in this tab on this site worked (bg/save.ts judged it): remember its shape, from what the top page showed of it. */
  async learn(tabId: number, site: string) {
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
}

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
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode((await flowSalt) + "\n" + site))
  return Array.from(new Uint8Array(digest).slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("")
}

async function readFlows(): Promise<Record<string, SiteFlow>> {
  const stored = (await chrome.storage.local.get(FLOWS_KEY).catch(() => ({})) as Record<string, unknown>)[FLOWS_KEY]
  return stored && typeof stored === "object" ? (stored as Record<string, SiteFlow>) : {}
}

/** What's been learned of a site's sign-in, if anything (see SiteFlow). */
export async function flowFor(site: string): Promise<SiteFlow | undefined> {
  return site ? (await readFlows())[await flowKey(site)] : undefined
}
