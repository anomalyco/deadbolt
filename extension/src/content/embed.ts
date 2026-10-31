// Answers the background's questions before a fill: which of the form's
// fields may be filled (see Approvals), and for a frame, can the user see
// them, asked one frame at a time from the form's frame up to the top page
// (see shownInPage in bg/frames.ts). A frame's form fills (from the toolbar
// popup, or a pick in the menu the top page opened for it) only when every
// frame above it says yes.

import type { Approved, Box, FrameBoxes, ToContent } from "../messages"
import { visibleNow } from "../ui/dom"
import type { FormControl } from "./detect"
import { fillable, throughFrame, visibleBox } from "./fill"
import { approvals } from "./approvals"
import { menuHost, type PageState } from "./inline"
import { deepQueryAll } from "./shadow"

const ANNOUNCE_WAIT_MS = 1500
const KEEP_MS = 10_000

/**
 * Which window below announced each nonce. The frame below posts its nonce
 * to this window, so `source` names the element it's in. A page can't learn a
 * nonce before the frame's own message arrives (this listener is the first on
 * the window, from document_start, and stops it there), so a second window
 * announcing the same nonce means something's wrong: no answer.
 */
export class Announcements {
  private heard = new Map<string, { source: unknown; at: number; clash: boolean }>()
  private waiting = new Map<string, () => void>()

  hear(nonce: string, source: unknown, now: number) {
    for (const [k, v] of this.heard) if (now - v.at > KEEP_MS) this.heard.delete(k)
    const prior = this.heard.get(nonce)
    if (prior) prior.clash ||= prior.source !== source
    else this.heard.set(nonce, { source, at: now, clash: false })
    this.waiting.get(nonce)?.()
  }

  /** The one window that announced `nonce`, waiting up to `ms`; each nonce answers once. */
  async from(nonce: string, ms: number): Promise<unknown> {
    if (!this.heard.has(nonce))
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, ms)
        this.waiting.set(nonce, () => {
          clearTimeout(timer)
          resolve()
        })
      })
    this.waiting.delete(nonce)
    const h = this.heard.get(nonce)
    this.heard.delete(nonce)
    return h && !h.clash ? h.source : null
  }
}

/**
 * Where these fields show in this frame's viewport, if every one of them
 * does: each passes the checks a fill makes, and (`observe`) a fresh
 * Intersection Observer v2 reading, which also sees what covers it while
 * letting clicks through, here or in any page above. Without it, a same-site
 * frame's: the frames above read the frame's element instead (see
 * shownInPage).
 */
export async function ownBoxes(fields: Array<{ el: Element & FormControl }>, observe = true): Promise<Box[] | null> {
  if (!fields.length || !fields.every((f) => fillable(f.el))) return null
  const boxes = fields.map((f) => visibleBox(f.el))
  if (boxes.some((b) => !b)) return null
  if (!observe) return boxes as Box[]
  const seen = await Promise.all(fields.map((f) => visibleNow(1000, f.el)))
  return seen.every(Boolean) ? (boxes as Box[]) : null
}

const reply = (boxes: Box[] | null): FrameBoxes | null => (boxes ? { boxes } : null)

/** The form's fields that may be filled now; with `measure`, only if they all show. */
async function approve(state: PageState, form: number, measure: boolean, sameSite: boolean): Promise<Approved | null> {
  state.rescan()
  if (state.form() !== form) return null
  // The menu the user picked from isn't closed until the fill arrives.
  const ours = menuHost()
  const fields = state.targets().filter((f) => fillable(f.el, ours))
  if (!fields.length) return null
  const boxes = measure ? await ownBoxes(fields, !sameSite) : undefined
  if (boxes === null || state.form() !== form) return null
  return { approval: approvals.grant(form, fields), roles: [...new Set(fields.map((f) => f.role))], boxes }
}

/** Where an approval's fields show now: all of them, still in the form. */
function approved(state: PageState, id: string, sameSite: boolean): Promise<Box[] | null> {
  state.rescan()
  const fields = approvals.get(id, state.form())
  const current = state.targets()
  if (!fields || !fields.every((f) => current.some((c) => c.el === f.el && c.role === f.role))) return Promise.resolve(null)
  return ownBoxes(fields, !sameSite)
}

export function initFrameChecks(state: PageState) {
  const announcements = new Announcements()
  window.addEventListener(
    "message",
    (e: MessageEvent<{ type?: unknown; nonce?: unknown }>) => {
      if (e.data?.type !== "db:frame-here" || typeof e.data.nonce !== "string") return
      e.stopImmediatePropagation()
      announcements.hear(e.data.nonce, e.source, Date.now())
    },
    true,
  )
  chrome.runtime.onMessage.addListener((message: ToContent, _sender, respond) => {
    switch (message?.type) {
      case "db:approve":
        approve(state, message.form, message.measure === true, message.sameSite === true).then(respond, () => respond(null))
        return true
      case "db:approved":
        approved(state, String(message.approval), message.sameSite === true).then((b) => respond(reply(b)), () => respond(null))
        return true
      case "db:frame-child":
        // For a login frame (`unsandboxed`): not through a frame that is
        // sandboxed itself, by attribute or by a CSP `sandbox` header
        // without allow-same-origin, which leaves its URL's origin but makes
        // its real one opaque (the browser's frame records show the URL's).
        if (message.unsandboxed === true && self.origin === "null") return void respond(null)
        announcements.from(message.nonce, ANNOUNCE_WAIT_MS).then(async (source) => {
          const el = source ? deepQueryAll<HTMLIFrameElement>("iframe, frame").find((f) => f.contentWindow === source) : undefined
          // Only placing a surface (`place`, never a fill's check): Deadbolt's own surface here isn't a cover.
          const ours = message.place === true && message.track !== true ? menuHost() : null
          const boxes = el ? throughFrame(el, message.boxes, message.unsandboxed === true, ours) : null
          // The frame element may be taller than the viewport: unobscured and on screen is enough (the fields' boxes are cut to what shows).
          respond(reply(boxes && el && message.track === true && !(await visibleNow(1000, el, true)) ? null : boxes))
        }, () => respond(null))
        return true
      case "db:frame-announce":
        if (window === window.top) return void respond(false)
        window.parent.postMessage({ type: "db:frame-here", nonce: message.nonce }, "*")
        return void respond(true)
    }
  })
}
