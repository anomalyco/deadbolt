// Frames that may receive logins, and delivery to exactly the document that
// asked. Ported from Foyer (github.com/R44VC0RP/foyer,
// src/autofill/service.ts, by Ryan Vogel).

import { FIELD_ROLES, type Approved, type Box, type FieldRole, type FrameBoxes, type ToContent } from "../messages"
import { fillableOrigin, sameSite, senderOrigin } from "./site"

export interface FrameTarget {
  tabId: number
  frameId: number
  /** The exact document that asked; fills are delivered to it and nothing else. */
  documentId: string
  origin: string
}

/**
 * The frame a content-script message came from, if it may have logins. The
 * origin always comes from the browser's record of the sender, never from
 * anything the page or content script says.
 */
export async function targetFor(sender: chrome.runtime.MessageSender): Promise<FrameTarget | null> {
  const tabId = sender.tab?.id
  if (tabId === undefined || sender.tab?.incognito || sender.id !== chrome.runtime.id) return null
  const url = senderOrigin(sender)
  if (!url || !fillableOrigin(url)) return null
  const frameId = sender.frameId ?? 0
  if (!sender.documentId) return null
  // Subframes only get logins for the same site as the page around them.
  if (frameId !== 0) {
    const top = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null)
    if (!top?.url || !sameSite(url, new URL(top.url))) return null
  }
  return { tabId, frameId, documentId: sender.documentId, origin: url.origin }
}

/**
 * The top frame of a tab, for the popup's list. Only a content script's own
 * report (with the browser's sender origin) is good enough to fill.
 */
export async function topTarget(tabId: number): Promise<{ target: FrameTarget | null; url?: URL }> {
  const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null)
  if (!frame?.url) return { target: null }
  let url: URL
  try {
    url = new URL(frame.url)
  } catch {
    return { target: null }
  }
  if (!fillableOrigin(url) || !frame.documentId) return { target: null, url }
  return { target: { tabId, frameId: 0, documentId: frame.documentId, origin: url.origin }, url }
}

/**
 * Deliver to the exact document that was checked. The host can take a moment,
 * and a frame can be navigated elsewhere in the meantime; a frameId alone
 * would follow it to the new page.
 */
export async function sendToFrame<T = unknown>(target: FrameTarget, message: ToContent): Promise<T | null> {
  if (!target.documentId) return null
  const frame = await chrome.webNavigation.getFrame({ tabId: target.tabId, frameId: target.frameId }).catch(() => null)
  if (!frame?.url || frame.documentId !== target.documentId) return null
  try {
    if (new URL(frame.url).origin !== target.origin) return null
  } catch {
    return null
  }
  return chrome.tabs.sendMessage(target.tabId, message, { documentId: target.documentId }).then(
    (reply) => (reply ?? null) as T | null,
    () => null,
  )
}

/**
 * The inline menu and the popup are extension pages; content scripts report
 * the web page's URL. The menu loads from the per-session dynamic id
 * (`use_dynamic_url`), so the URL's host isn't always the extension id.
 * `page` is the file, such as "menu.html".
 */
export function fromExtensionPage(sender: chrome.runtime.MessageSender, page?: string): boolean {
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith("chrome-extension://")) return false
  if (!page) return true
  try {
    return new URL(sender.url).pathname === `/${page}`
  } catch {
    return false
  }
}

/**
 * A menu frame claiming `owner`'s token. webNavigation doesn't report
 * extension frames, so the frame tree can't be read here. The token reaches the
 * menu only by postMessage from the owner document's content script into its
 * own child frame (never in the URL), and the menu reports the origin of the
 * parent window that sent it. So: the extension's menu page, in the owner's tab,
 * handed the token by a parent on the owner's origin, while the owner document
 * is still the frame's current one.
 */
export async function menuFrameOf(sender: chrome.runtime.MessageSender, owner: FrameTarget, parent: string): Promise<boolean> {
  if (!fromExtensionPage(sender, "menu.html") || !sender.documentId || sender.tab?.id !== owner.tabId || parent !== owner.origin) return false
  const frame = await chrome.webNavigation.getFrame({ tabId: owner.tabId, frameId: owner.frameId }).catch(() => null)
  return frame?.documentId === owner.documentId
}

/** Frames nested deeper than this are never verified. */
const MAX_DEPTH = 8

const isBoxes = (boxes: unknown): boxes is Box[] =>
  Array.isArray(boxes) && boxes.length > 0 && boxes.every((b: Box) => b && [b.left, b.top, b.right, b.bottom].every(Number.isFinite))

/**
 * Which fields of form `form` in frame `target` may be filled, if the user can
 * see every one of them through every frame above it, now. The frame's
 * content script fixes the fields that pass the checks a field gets before a
 * fill and says where they show in its own viewport (with a fresh
 * Intersection Observer v2 reading); see throughParents for the rest. The
 * fill then asks for and writes only those fields.
 */
export async function shownInPage(target: FrameTarget, form: number): Promise<Approved | null> {
  const approved = cleanApproved(await sendToFrame(target, { type: "db:approve", form, measure: true }))
  return approved?.boxes && (await throughParents(target, approved.boxes)) ? approved : null
}

/** Whether the fields `approved` fixed still all show, through every frame above. */
export async function stillShown(target: FrameTarget, approved: Approved): Promise<boolean> {
  const boxes = (await sendToFrame<FrameBoxes>(target, { type: "db:approved", approval: approved.approval }))?.boxes
  return isBoxes(boxes) && throughParents(target, boxes)
}

/**
 * The fields a content script approved (see Approved), if its answer makes
 * sense: an id, known roles and, if it measured, boxes.
 */
export function cleanApproved(reply: unknown): Approved | null {
  const a = reply as Partial<Approved> | null
  if (!a || typeof a.approval !== "string" || !a.approval || !Array.isArray(a.roles)) return null
  const roles = a.roles.filter((r): r is FieldRole => FIELD_ROLES.includes(r))
  if (!roles.length || (a.boxes !== undefined && !isBoxes(a.boxes))) return null
  return { approval: a.approval, roles, boxes: a.boxes }
}

/**
 * Whether `boxes`, where fields show in frame `target`'s viewport, show in
 * the top page. One frame up at a time, the parent's content script finds the
 * element that embeds the frame below (that frame names it by posting a
 * one-time nonce to its parent), gives it the checks a field gets and passes
 * the boxes up in its own coordinates. A frame that can't answer, such as an
 * ancestor without the content script, means no.
 */
async function throughParents(target: FrameTarget, first: Box[]): Promise<boolean> {
  const frames = await chrome.webNavigation.getAllFrames({ tabId: target.tabId }).catch(() => null)
  if (!frames) return false
  const byId = new Map(frames.map((f) => [f.frameId, f]))
  let boxes: Box[] | undefined = first
  let child = target
  for (let depth = 0; child.frameId !== 0; depth++) {
    if (!isBoxes(boxes) || depth >= MAX_DEPTH) return false
    const parentId = byId.get(child.frameId)?.parentFrameId
    const info = parentId === undefined ? undefined : byId.get(parentId)
    if (parentId === undefined || !info?.documentId) return false
    let origin: string
    try {
      origin = new URL(info.url).origin
    } catch {
      return false
    }
    const parent: FrameTarget = { tabId: target.tabId, frameId: parentId, documentId: info.documentId, origin }
    const nonce = newToken()
    // Ask the parent first, so it's listening when the child speaks up.
    const answer: Promise<FrameBoxes | null> = sendToFrame<FrameBoxes>(parent, { type: "db:frame-child", nonce, boxes })
    if (!(await sendToFrame(child, { type: "db:frame-announce", nonce }))) return false
    boxes = (await answer)?.boxes
    child = parent
  }
  return isBoxes(boxes)
}

export function newToken(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("")
}
