// Background side of filling: lists logins for the frame that asked, hands
// the inline menu a one-time token bound to that frame, and fills only into
// that frame after the user picks a login. Token-bound frame targeting and the
// email-first continuation are ported from Foyer (github.com/R44VC0RP/foyer,
// src/autofill/service.ts, by Ryan Vogel).

import { FIELD_ROLES, IDENTIFIER_ROLES, MENU_ROLES, type ToContent, type Approved, type FieldRole, type FillAck, type FillValues, type MenuLoadReply, type MenuPasskey, type PickReply, type PopupReply, type QueryReply, type SurfaceKind } from "../messages"
import type { Account, ListReply, Want } from "../protocol"
import { cleanApproved, menuFrameOf, newToken, sendToFrame, shownInPage, stillShown, targetFor, topTarget, type FrameTarget } from "./frames"
import { HostError, type Host } from "./host"
import { siteOf } from "./site"

const TOKEN_TTL_MS = 2 * 60_000
const LIST_TTL_MS = 30_000
const CONTINUE_TTL_MS = 2 * 60_000
const NOT_SHOWN = "That login form isn't fully visible. Nothing was filled."
/** Navigations the user started themselves end an email-first sign-in, as does going back or forward (see navigated). */
const UNRELATED = new Set(["typed", "auto_bookmark", "generated", "keyword", "keyword_generated", "reload", "start_page", "auto_toplevel"])

interface MenuToken extends FrameTarget {
  roles: FieldRole[]
  focused: FieldRole
  /** The form snapshot the menu opened on. */
  form: number
  createdAt: number
  /** The menu document that first loaded the token; only it may use it after. */
  menuDocumentId?: string
}

/**
 * Email-first sign-in: after a fill that wrote the email (or the password of
 * a login with a code) into the top page, fill the next step once, from the
 * same login. Frames never continue: a frame's fields fill only when the
 * user picks a login in the popup for them.
 */
interface Continuation {
  ref: string
  /** Only the top page on the same origin continues, never another site's page or a frame. */
  origin: string
  /** The document the last step filled. The next step needs a new document, or `stepped` in this one. */
  documentId: string
  next: "password" | "otp"
  at: number
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

/** What the menu offers under a field: on a code field, only logins with a one-time password. */
export function menuAccounts(accounts: Account[], focused: FieldRole): Account[] {
  if (focused === "otp") return accounts.filter((a) => a.hasTotp)
  if (focused === "password") return accounts.filter((a) => a.hasPassword)
  return accounts
}

/** The step an email-first sign-in waits for after a fill wrote `filled`, if any. */
export function nextStep(filled: FieldRole[], account: Pick<Account, "hasPassword" | "hasTotp">): Continuation["next"] | undefined {
  if (filled.includes("otp")) return undefined
  if (filled.includes("password")) return account.hasTotp ? "otp" : undefined
  if (filled.some((r) => IDENTIFIER_ROLES.includes(r))) return account.hasPassword ? "password" : account.hasTotp ? "otp" : undefined
  return undefined
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
  private continueTimers = new Map<number, ReturnType<typeof setTimeout>>()
  /** Each tab's continuation work runs one piece at a time, so a step is used once. */
  private queues = new Map<number, Promise<unknown>>()
  /** Bumped when a tab's email-first sign-in is cancelled; work started before then arms nothing. */
  private cancels = new Map<number, number>()
  /** Sites whose fields already showed the locked row on focus since Deadbolt last locked or unlocked. */
  private lockedShown = new Set<string>()
  private lastState: string

  constructor(
    private host: Host,
    private passkeys?: MenuPasskeys,
  ) {
    this.lastState = host.status.state
    host.onChange((status) => {
      this.lists.clear()
      if (status.state !== this.lastState) this.lockedShown.clear()
      this.lastState = status.state
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
   * that, only that document may use it.
   */
  private async token(token: string, sender: chrome.runtime.MessageSender, parent?: string): Promise<MenuToken | undefined> {
    const t = this.tokens.get(token)
    if (!t || Date.now() - t.createdAt > TOKEN_TTL_MS || !sender.documentId) return undefined
    if (t.menuDocumentId === undefined) {
      if (parent === undefined || !(await menuFrameOf(sender, t, parent))) return undefined
      t.menuDocumentId = sender.documentId
    }
    return t.menuDocumentId === sender.documentId && sender.tab?.id === t.tabId ? t : undefined
  }

  private sweep() {
    const now = Date.now()
    for (const [t, v] of this.tokens) if (now - v.createdAt > TOKEN_TTL_MS) this.tokens.delete(t)
  }

  /**
   * The menu for a focused field. `explicit`: the user clicked into it or
   * pressed ↓. While Deadbolt is locked, a field that was only focused shows
   * the locked row once per site until Deadbolt locks or unlocks again.
   */
  async query(sender: chrome.runtime.MessageSender, roles: unknown, focused: unknown, form: unknown, explicit = false): Promise<QueryReply> {
    const target = await targetFor(sender)
    const clean = sanitizeRoles(roles)
    // The menu opens only in the top page (see inline.ts).
    if (!target || target.frameId !== 0 || !Number.isSafeInteger(form) || !MENU_ROLES.includes(focused as FieldRole) || !clean.includes(focused as FieldRole)) return { rows: 0 }
    await this.host.connect()
    let rows = 0
    if (this.host.status.state === "locked") {
      const site = siteOf(new URL(target.origin).hostname) ?? target.origin
      if (explicit || !this.lockedShown.has(site)) rows = 1
      this.lockedShown.add(site)
    } else if (this.host.status.state === "ready") {
      const reply = await this.list(target.origin).catch(() => null)
      rows = reply ? menuAccounts(reply.accounts, focused as FieldRole).length : 0
      rows += this.passkeys?.menuPasskeys(target, focused as FieldRole).length ?? 0
    }
    if (!rows) return { rows: 0 }
    this.sweep()
    const token = newToken()
    this.tokens.set(token, { ...target, roles: clean, focused: focused as FieldRole, form: form as number, createdAt: Date.now() })
    return { token, rows }
  }

  async menuLoad(token: string, sender: chrome.runtime.MessageSender, parent: string): Promise<MenuLoadReply | null> {
    const t = await this.token(token, sender, parent)
    if (!t) return null
    if (this.host.status.state !== "ready") return { kind: "status", status: this.host.status }
    try {
      const reply = await this.list(t.origin)
      const passkeys = this.passkeys?.menuPasskeys(t, t.focused)
      return { kind: "accounts", site: reply.site, accounts: menuAccounts(reply.accounts, t.focused), focused: t.focused, ...(passkeys?.length ? { passkeys } : {}) }
    } catch {
      return { kind: "status", status: this.host.status }
    }
  }

  async menuPick(token: string, ref: string, sender: chrome.runtime.MessageSender): Promise<PickReply> {
    const t = await this.token(token, sender)
    if (!t) return { ok: false, message: "This menu has expired." }
    const signedIn = await this.passkeys?.menuPick(t, ref)
    if (signedIn) {
      this.tokens.delete(token)
      if (signedIn.ok) await sendToFrame(t, { type: "db:close-menu", token })
      return signedIn
    }
    const reply = await this.list(t.origin).catch(() => null)
    const account = reply?.accounts.find((a) => a.ref === ref)
    if (!account) return { ok: false, message: "That login isn't here anymore." }
    this.tokens.delete(token)
    return this.fillAndArm(t, account, t.roles, t.form)
  }

  async menuDismiss(token: string, sender: chrome.runtime.MessageSender) {
    const t = await this.token(token, sender)
    if (!t) return
    await this.cancel(t.tabId)
    await sendToFrame(t, { type: "db:close-menu", token })
  }

  async menuResize(token: string, height: number, sender: chrome.runtime.MessageSender, width?: unknown, mode?: unknown) {
    const t = await this.token(token, sender)
    if (t) await sendToFrame(t, resizeMessage(token, height, width, mode))
  }

  /** The page closed its menu; with `dismissed`, the user said no (esc). */
  async menuClose(token: string, dismissed: boolean, sender: chrome.runtime.MessageSender) {
    const t = this.tokens.get(token)
    if (!t || sender.tab?.id !== t.tabId || sender.documentId !== t.documentId) return
    this.tokens.delete(token)
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
   * wrote.
   */
  private async fill(target: FrameTarget, account: Account, roles: FieldRole[], form: number, generation: number, framed?: Approved): Promise<FieldRole[]> {
    const approved = framed ?? cleanApproved(await sendToFrame(target, { type: "db:approve", form, measure: false }))
    if (!approved) return []
    const want = wantFor(roles.filter((r) => approved.roles.includes(r)), account)
    if (!want.length) return []
    const reply = await this.host.send({ type: "fill", origin: target.origin, ref: account.ref, want })
    // Esc, or the user leaving, while the host answered: nothing goes out.
    if (generation !== this.generation(target.tabId)) return []
    if (framed && !(await stillShown(target, framed))) throw new Error(NOT_SHOWN)
    if (generation !== this.generation(target.tabId)) return []
    const values: FillValues = {}
    if (want.includes("username") && reply.username) values.username = reply.username
    if (want.includes("password") && reply.password) values.password = reply.password
    if (want.includes("totp") && reply.totp) values.totp = reply.totp
    const ack = await sendToFrame<FillAck>(target, { type: "db:fill", values, form, approval: approved.approval })
    return sanitizeRoles(ack?.filled)
  }

  /** Fill, and say which step comes next if this fill, in the top page, wrote something. */
  private async fillStep(
    target: FrameTarget,
    account: Account,
    roles: FieldRole[],
    form: number,
    generation: number,
    framed?: Approved,
  ): Promise<{ reply: PickReply; next?: Continuation | null }> {
    let filled: FieldRole[]
    try {
      filled = await this.fill(target, account, roles, form, generation, framed)
    } catch (err) {
      return { reply: { ok: false, message: fillError(err) } }
    }
    if (!filled.length) return { reply: { ok: false, message: "The page changed. Try again." } }
    const next = target.frameId === 0 ? nextStep(filled, account) : undefined
    return { reply: { ok: true }, next: next ? { ref: account.ref, origin: target.origin, documentId: target.documentId, next, at: Date.now() } : null }
  }

  /** A fill the user chose (menu or popup), then the next step's continuation. */
  private async fillAndArm(target: FrameTarget, account: Account, roles: FieldRole[], form: number, framed?: Approved): Promise<PickReply> {
    const generation = this.generation(target.tabId)
    const { reply, next } = await this.fillStep(target, account, roles, form, generation, framed)
    if (next !== undefined) await this.serial(target.tabId, () => this.arm(target.tabId, generation, next))
    return reply
  }

  /**
   * Sets the next step, or clears the old one, unless the sign-in was
   * cancelled since `generation` or the top page has left the step's origin.
   * Call it inside `serial`.
   */
  private async arm(tabId: number, generation: number, next: Continuation | null) {
    if (generation !== this.generation(tabId)) return
    if (next) {
      const top = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null)
      let origin = ""
      try {
        origin = top?.url ? new URL(top.url).origin : ""
      } catch {}
      if (origin !== next.origin || generation !== this.generation(tabId)) return
    }
    await this.setContinuation(tabId, next ?? undefined)
  }

  private generation(tabId: number): number {
    return this.cancels.get(tabId) ?? 0
  }

  private serial<T>(tabId: number, work: () => Promise<T>): Promise<T> {
    const run = (this.queues.get(tabId) ?? Promise.resolve()).then(work)
    this.queues.set(tabId, run.catch(() => {}))
    return run
  }

  private async continuation(tabId: number): Promise<Continuation | undefined> {
    const key = `continue:${tabId}`
    const stored = (await chrome.storage.session.get(key))[key] as Continuation | undefined
    if (stored && Date.now() - stored.at < CONTINUE_TTL_MS) return stored
    if (stored) await chrome.storage.session.remove(key)
    return undefined
  }

  private async setContinuation(tabId: number, c: Continuation | undefined) {
    const key = `continue:${tabId}`
    clearTimeout(this.continueTimers.get(tabId))
    this.continueTimers.delete(tabId)
    if (!c) return chrome.storage.session.remove(key)
    await chrome.storage.session.set({ [key]: c })
    this.continueTimers.set(
      tabId,
      setTimeout(() => void this.setContinuation(tabId, undefined), CONTINUE_TTL_MS),
    )
  }

  /** No more automatic steps in this tab, including from fills still on their way. */
  private cancel(tabId: number) {
    this.cancels.set(tabId, this.generation(tabId) + 1)
    return this.serial(tabId, () => this.setContinuation(tabId, undefined))
  }

  /** A content script found a login form: remember it, and continue an email-first fill. */
  async page(sender: chrome.runtime.MessageSender, kind: SurfaceKind | null, roles: unknown, form: unknown, stepped = false) {
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
    if (target.frameId !== 0 || !kind) return

    await this.serial(target.tabId, async () => {
      const cont = await this.continuation(target.tabId)
      if (!cont || target.origin !== cont.origin || !clean.includes(cont.next)) return
      // A matching form showing up isn't a next step by itself: the page has
      // to have moved on, to a new document, or in this one by the user
      // submitting or the filled fields going away.
      if (target.documentId === cont.documentId && !stepped) return
      // Used once: whatever happens next, this step doesn't fill again.
      await this.setContinuation(target.tabId, undefined)
      if (this.host.status.state !== "ready") return
      const reply = await this.list(target.origin).catch(() => null)
      const account = reply?.accounts.find((a) => a.ref === cont.ref)
      if (!account || generation !== this.generation(target.tabId)) return
      const step = cont.next === "password" ? clean.filter((r) => r === "password" || r === "otp") : (["otp"] as FieldRole[])
      const { next } = await this.fillStep(target, account, step, form as number, generation)
      if (next !== undefined) await this.arm(target.tabId, generation, next)
    })
  }

  /** A frame committed a new document: its menus, form report and (unless it's the next step) continuation go. */
  async navigated(d: { tabId: number; frameId: number; url: string; transitionType?: string; transitionQualifiers?: string[] }) {
    if (d.frameId === 0) this.pages.delete(d.tabId)
    else this.pages.get(d.tabId)?.delete(d.frameId)
    for (const [token, t] of this.tokens) if (t.tabId === d.tabId && (d.frameId === 0 || t.frameId === d.frameId)) this.tokens.delete(token)
    if (d.frameId !== 0) return
    if (UNRELATED.has(d.transitionType ?? "") || d.transitionQualifiers?.includes("forward_back")) return this.cancel(d.tabId)
    let origin = ""
    try {
      origin = new URL(d.url).origin
    } catch {}
    const cont = await this.serial(d.tabId, () => this.continuation(d.tabId))
    if (cont && origin !== cont.origin) await this.cancel(d.tabId)
  }

  forgetTab(tabId: number) {
    this.pages.delete(tabId)
    for (const [token, t] of this.tokens) if (t.tabId === tabId) this.tokens.delete(token)
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
   * evidence that the user sees a frame, and frames get no inline menu.
   * Without a report from the current document (sandboxed and opaque-origin
   * pages never make one), nothing.
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
    return this.fillAndArm(page, account, page.roles, page.form, framed)
  }
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

/** Rate limiting is the host pacing fills, not a fault: say so calmly. */
export function fillError(err: unknown): string {
  if (err instanceof HostError && err.code === "rate_limited") return "Filling too quickly. Try again in a moment."
  return (err as Error)?.message || "Couldn't fill."
}

function sanitizeRoles(roles: unknown): FieldRole[] {
  return Array.isArray(roles) ? roles.filter((r): r is FieldRole => FIELD_ROLES.includes(r)) : []
}
