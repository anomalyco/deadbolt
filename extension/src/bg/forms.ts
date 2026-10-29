// Background side of filling addresses, contact details and cards: the menu
// for an identity or card field, and the fill after a pick. The rules are the
// logins' (bg/autofill.ts): a one-time token bound to the menu document,
// fills delivered to the exact document that was checked, only the fields
// the content script approved, and a frame's fields only if the user can see
// them through every frame above.
//
// Which frames get what (docs/autofill.md, "Frames and payment providers"):
// identities go to the top page and frames of its own site; cards go there
// too, and into a payment provider's cross-origin frame (src/payments.ts) on
// an https page. Every other frame gets nothing.

import { FORM_ROLES, fieldsFor, VERIFIED_FIELDS, type Box, type FormRole, type FormsAck, type FormsApproved, type MenuLoadReply, type PickReply, type QueryReply } from "../messages"
import type { FormItemKind, FormsReply } from "../protocol"
import { paymentProvider, securePage } from "../payments"
import { boxesInTop, isBoxes, menuFrameOf, newToken, sendToFrame, type FrameTarget } from "./frames"
import { fillError, resizeMessage } from "./autofill"
import { HostError, type Host } from "./host"
import { fillableOrigin, sameSite, senderOrigin, siteOf } from "./site"

const TOKEN_TTL_MS = 2 * 60_000
const LIST_TTL_MS = 30_000
/** A card's number waits on Touch ID, which the user may take a while over. */
const VERIFY_TIMEOUT_MS = 90_000
const NOT_SHOWN = "That form isn't fully visible. Nothing was filled."

interface FormsToken {
  /** The top page, where the menu is. */
  owner: FrameTarget
  /** The frame the field is in (the owner, or a frame below it). */
  source: FrameTarget
  kind: FormItemKind
  form: number
  section: string
  createdAt: number
  menuDocumentId?: string
}

interface FormsReport extends FrameTarget {
  kinds: FormItemKind[]
  form: number
}

/** A frame's place in the page, for what it may get. */
interface Placed extends FrameTarget {
  /** A payment provider's frame: its name. */
  provider?: string
}

/**
 * The frame a content-script message came from, if it may get `kind`: the
 * top page; a frame of the top page's site; or, for a card, a payment
 * provider's frame on an https page. Origins come from the browser's record
 * of the sender; sandboxed and opaque frames get nothing, as do incognito tabs.
 */
export async function formsTargetFor(sender: chrome.runtime.MessageSender, kind: FormItemKind): Promise<Placed | null> {
  const tabId = sender.tab?.id
  if (tabId === undefined || sender.tab?.incognito || sender.id !== chrome.runtime.id || !sender.documentId) return null
  const url = senderOrigin(sender)
  if (!url || !fillableOrigin(url)) return null
  const frameId = sender.frameId ?? 0
  const target = { tabId, frameId, documentId: sender.documentId, origin: url.origin }
  if (frameId === 0) return target
  const top = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null)
  let topUrl: URL
  try {
    topUrl = new URL(top?.url ?? "")
  } catch {
    return null
  }
  if (!fillableOrigin(topUrl)) return null
  if (sameSite(url, topUrl)) return target
  const provider = kind === "card" && securePage(topUrl) ? paymentProvider(url) : null
  return provider ? { ...target, provider: provider.name } : null
}

const cleanRoles = (roles: unknown): FormRole[] => (Array.isArray(roles) ? roles.filter((r): r is FormRole => FORM_ROLES.includes(r)) : [])

function cleanApproved(reply: unknown): FormsApproved | null {
  const a = reply as Partial<FormsApproved> | null
  if (!a || typeof a.approval !== "string" || !a.approval) return null
  const roles = cleanRoles(a.roles)
  if (!roles.length || (a.boxes !== undefined && !isBoxes(a.boxes))) return null
  return { approval: a.approval, roles, boxes: a.boxes }
}

function cleanBox(box: unknown): Box | null {
  return isBoxes([box]) ? (box as Box) : null
}

export class Forms {
  private tokens = new Map<string, FormsToken>()
  private lists = new Map<string, { at: number; reply: FormsReply }>()
  /** The identity and card forms each tab's frames last reported. */
  private pages = new Map<number, Map<number, FormsReport>>()
  /** Sites whose fields already showed the locked row on focus since Deadbolt last locked or unlocked. */
  private lockedShown = new Set<string>()

  constructor(private host: Host) {
    host.onChange(() => {
      this.lists.clear()
      this.lockedShown.clear()
    })
  }

  owns(token: unknown): boolean {
    return typeof token === "string" && this.tokens.has(token)
  }

  private async list(origin: string): Promise<FormsReply> {
    const cached = this.lists.get(origin)
    if (cached && Date.now() - cached.at < LIST_TTL_MS) return cached.reply
    const reply = await this.host.send({ type: "forms", origin, kinds: ["identity", "card"] })
    this.lists.set(origin, { at: Date.now(), reply })
    return reply
  }

  private async token(token: string, sender: chrome.runtime.MessageSender, parent?: string): Promise<FormsToken | undefined> {
    const t = this.tokens.get(token)
    if (!t || Date.now() - t.createdAt > TOKEN_TTL_MS || !sender.documentId) return undefined
    if (t.menuDocumentId === undefined) {
      if (parent === undefined || !(await menuFrameOf(sender, t.owner, parent))) return undefined
      t.menuDocumentId = sender.documentId
    }
    return t.menuDocumentId === sender.documentId && sender.tab?.id === t.owner.tabId ? t : undefined
  }

  /** A content script reported which kinds of form its frame has now. */
  async page(sender: chrome.runtime.MessageSender, kinds: unknown, form: unknown) {
    const clean = Array.isArray(kinds) ? (["identity", "card"] as const).filter((k) => kinds.includes(k)) : []
    const target = await formsTargetFor(sender, clean.includes("card") ? "card" : "identity")
    if (!target || !Number.isSafeInteger(form)) return
    const frames = this.pages.get(target.tabId) ?? new Map<number, FormsReport>()
    if (!clean.length) frames.delete(target.frameId)
    else frames.set(target.frameId, { ...target, kinds: [...clean], form: form as number })
    this.pages.set(target.tabId, frames)
  }

  /**
   * The menu for an identity or card field the user clicked into. In the
   * top page, its token goes back to the content script, which opens the
   * menu under the field. In a frame below, the background opens it in the
   * top page, under where the field shows there (`box`, carried up through
   * every frame and checked on the way: see boxesInTop), and the frame gets
   * no token.
   */
  async query(sender: chrome.runtime.MessageSender, kind: unknown, form: unknown, section: unknown, explicit: boolean, box: unknown): Promise<QueryReply> {
    if (kind !== "identity" && kind !== "card") return { rows: 0 }
    if (!Number.isSafeInteger(form) || typeof section !== "string" || section.length > 200) return { rows: 0 }
    const source = await formsTargetFor(sender, kind)
    if (!source) return { rows: 0 }
    let owner: FrameTarget = source
    let at: Box | undefined
    if (source.frameId !== 0) {
      const own = cleanBox(box)
      const top = own ? await chrome.webNavigation.getFrame({ tabId: source.tabId, frameId: 0 }).catch(() => null) : null
      const shown = own ? await boxesInTop(source, [own]) : null
      if (!top?.documentId || !shown) return { rows: 0 }
      owner = { tabId: source.tabId, frameId: 0, documentId: top.documentId, origin: new URL(top.url).origin }
      at = shown[0]
    }
    await this.host.connect()
    const state = this.host.status.state
    const site = siteOf(new URL(owner.origin).hostname) ?? owner.origin
    let rows = 0
    if (state === "locked") {
      if (explicit || !this.lockedShown.has(site)) rows = 1
      this.lockedShown.add(site)
    } else if (state === "ready" && this.host.capabilities.includes("forms")) {
      const reply = await this.list(source.origin).catch(() => null)
      rows = reply ? (kind === "card" ? reply.cards.length : reply.identities.length) : 0
    }
    if (!rows) return { rows: 0 }
    for (const [t, v] of this.tokens) if (Date.now() - v.createdAt > TOKEN_TTL_MS) this.tokens.delete(t)
    const token = newToken()
    this.tokens.set(token, { owner, source, kind, form: form as number, section, createdAt: Date.now() })
    if (!at) return { token, rows }
    const opened = await sendToFrame<boolean>(owner, { type: "db:forms-open", token, rows, box: at })
    if (!opened) this.tokens.delete(token)
    return { rows: opened ? rows : 0 }
  }

  /** The frames a pick of `t` fills: its own section, and for a card, every other frame of the tab with card fields it may get. */
  private targets(t: FormsToken): Array<{ target: Placed; form: number; section?: string }> {
    const own = { target: t.source as Placed, form: t.form, section: t.section }
    if (t.kind !== "card") return [own]
    const others = [...(this.pages.get(t.owner.tabId)?.values() ?? [])]
      .filter((p) => p.kinds.includes("card") && p.frameId !== t.source.frameId)
      .map((p) => ({ target: p as Placed, form: p.form }))
    return [own, ...others]
  }

  async menuLoad(token: string, sender: chrome.runtime.MessageSender, parent: string): Promise<MenuLoadReply | null> {
    const t = await this.token(token, sender, parent)
    if (!t) return null
    if (this.host.status.state !== "ready") return { kind: "status", status: this.host.status }
    try {
      const reply = await this.list(t.source.origin)
      const site = siteOf(new URL(t.owner.origin).hostname) ?? new URL(t.owner.origin).hostname
      const into = t.kind === "card" ? this.targets(t).find((x) => x.target.provider)?.target.provider : undefined
      return { kind: "forms", form: t.kind, site, identities: t.kind === "identity" ? reply.identities : [], cards: t.kind === "card" ? reply.cards : [], verify: t.kind === "card", ...(into ? { into } : {}) }
    } catch {
      return { kind: "status", status: this.host.status }
    }
  }

  /**
   * The user picked an identity or card: every frame it goes to fixes which
   * of its fields may be filled (a frame below the top page only if they all
   * show through every frame above), the host is asked once for just the
   * values those fields need (a card's number or code make the agent ask
   * for Touch ID), frames below are checked again once the values are in
   * hand, and each frame gets the values for its own fields.
   */
  async menuPick(token: string, ref: string, sender: chrome.runtime.MessageSender): Promise<PickReply> {
    const t = await this.token(token, sender)
    if (!t) return { ok: false, message: "This menu has expired." }
    const reply = await this.list(t.source.origin).catch(() => null)
    const item = t.kind === "card" ? reply?.cards.find((c) => c.ref === ref) : reply?.identities.find((i) => i.ref === ref)
    if (!item) return { ok: false, message: "That isn't here anymore." }
    this.tokens.delete(token)
    const targets = this.targets(t)
    // The surface folds into its pill before any frame is measured, so it covers none of their fields.
    if (targets.some((x) => x.target.frameId !== 0)) await sendToFrame(t.owner, { type: "db:forms-settle", token })
    const approved: Array<{ target: Placed; form: number; approved: FormsApproved }> = []
    for (const x of targets) {
      const framed = x.target.frameId !== 0
      const a = cleanApproved(await sendToFrame(x.target, { type: "db:forms-approve", form: x.form, kind: t.kind, ...(x.section !== undefined ? { section: x.section } : {}), measure: framed }))
      if (!a) continue
      if (framed && !(a.boxes && (await boxesInTop(x.target, a.boxes)))) continue
      approved.push({ target: x.target, form: x.form, approved: a })
    }
    // The field the user picked from has to be among them.
    if (!approved.some((a) => a.target.frameId === t.source.frameId)) return { ok: false, message: t.source.frameId === 0 ? "The page changed. Try again." : NOT_SHOWN }
    const fields = fieldsFor(approved.flatMap((a) => a.approved.roles))
    if (!fields.length) return { ok: false, message: "The page changed. Try again." }
    const verify = fields.some((f) => VERIFIED_FIELDS.includes(f))
    let values: Record<string, string>
    try {
      ;({ values } = await this.host.send({ type: "fill-form", origin: t.source.origin, ref, fields }, verify ? { timeout: VERIFY_TIMEOUT_MS } : {}))
    } catch (err) {
      return { ok: false, message: formsError(err) }
    }
    let filled = 0
    for (const a of approved) {
      if (a.target.frameId !== 0 && !(await stillShown(a.target, a.approved))) {
        if (a.target.frameId === t.source.frameId) return { ok: false, message: NOT_SHOWN }
        continue
      }
      const mine = fieldsFor(a.approved.roles)
      const own = Object.fromEntries(Object.entries(values).filter(([k]) => mine.includes(k)))
      const ack = await sendToFrame<FormsAck>(a.target, { type: "db:forms-fill", values: own, form: a.form, approval: a.approved.approval })
      filled += cleanRoles(ack?.filled).length
    }
    return filled ? { ok: true } : { ok: false, message: "The page changed. Try again." }
  }

  async menuResize(token: string, height: number, sender: chrome.runtime.MessageSender, width?: unknown, mode?: unknown) {
    const t = await this.token(token, sender)
    if (!t) return
    await sendToFrame(t.owner, resizeMessage(token, height, width, mode))
  }

  async menuDismiss(token: string, sender: chrome.runtime.MessageSender) {
    const t = await this.token(token, sender)
    if (t) await sendToFrame(t.owner, { type: "db:close-menu", token })
  }

  async menuClose(token: string, sender: chrome.runtime.MessageSender) {
    const t = this.tokens.get(token)
    if (t && sender.tab?.id === t.owner.tabId && sender.documentId === t.owner.documentId) this.tokens.delete(token)
  }

  navigated(d: { tabId: number; frameId: number }) {
    if (d.frameId === 0) this.pages.delete(d.tabId)
    else this.pages.get(d.tabId)?.delete(d.frameId)
    for (const [token, t] of this.tokens) if (t.owner.tabId === d.tabId && (d.frameId === 0 || t.source.frameId === d.frameId)) this.tokens.delete(token)
  }

  forgetTab(tabId: number) {
    this.pages.delete(tabId)
    for (const [token, t] of this.tokens) if (t.owner.tabId === tabId) this.tokens.delete(token)
  }
}

async function stillShown(target: FrameTarget, approved: FormsApproved): Promise<boolean> {
  const boxes = (await sendToFrame<{ boxes: Box[] }>(target, { type: "db:forms-approved", approval: approved.approval }))?.boxes
  return isBoxes(boxes) && !!(await boxesInTop(target, boxes))
}

/** Touch ID turned down, or the card isn't there: say so plainly. */
export function formsError(err: unknown): string {
  if (err instanceof HostError && err.code === "cancelled") return "Touch ID was cancelled. Nothing was filled."
  if (err instanceof HostError && err.code === "not_found") return "That isn't in Deadbolt anymore."
  return fillError(err)
}
