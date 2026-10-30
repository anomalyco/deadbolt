// Writes credentials into the page so plain forms and framework-controlled
// inputs (React, Vue, Angular) both accept them. Ported from Foyer
// (github.com/R44VC0RP/foyer, src/autofill/fill.ts, by Ryan Vogel).
//
// The value is set through the native HTMLInputElement setter from the
// extension's isolated world, then input/change events are dispatched. A
// framework's own value tracker lives in the page's world, so it sees the DOM
// value differ from what it last rendered and runs its change handler.

import { IDENTIFIER_ROLES, type Box, type FieldRole, type FillValues } from "../messages"
import { inPlace, type Field, type FormControl } from "./detect"

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

// ---- Typed or filled ----------------------------------------------------------

/**
 * A keyed digest of the value each field last got from a trusted input event
 * or from Deadbolt, so no plaintext is kept. The key never leaves this
 * content script and can't be exported. Only matching values are captured on
 * submit. That cuts noise from pages that fill fields themselves; it isn't
 * proof the user chose the value (a page can change a field around the
 * user's own keystrokes), and nothing depends on it being so.
 */
const key: Promise<CryptoKey | null> | null = globalThis.crypto?.subtle
  ? crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]).catch(() => null)
  : null
const digests = new WeakMap<Element, Promise<string | null>>()
/** The same, for the values Deadbolt itself last wrote into identity and card fields only. */
const ours = new WeakMap<Element, Promise<string | null>>()

async function digest(value: string): Promise<string | null> {
  const k = await key
  if (!k) return null
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(value)))
  return Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("")
}

export function trackUserInput(event: Event) {
  const el = event.composedPath()[0]
  if (key && event.isTrusted && (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) digests.set(el, digest(el.value))
}

/** Deadbolt is writing `value` into an identity or card field (see formfill.ts). */
export function noteFilled(el: Element, value: string) {
  if (!key) return
  const d = digest(value)
  digests.set(el, d)
  ours.set(el, d)
}

/**
 * Whether the field holds what the user typed into it themselves: its value
 * is the last one a trusted input event left, and not one Deadbolt wrote.
 * A value the page put there itself, or one Deadbolt filled before, isn't.
 */
export async function typedByUser(el: Element, value: string): Promise<boolean> {
  if (!value || (await ownValue(el, value)) === undefined) return false
  const mine = ours.get(el)
  if (!mine) return true
  const [a, b] = await Promise.all([mine, digest(value)])
  return a === null || a !== b
}

/** `value` if it's what the user last typed into the field or Deadbolt filled. */
export async function ownValue(el: Element, value: string): Promise<string | undefined> {
  const recorded = digests.get(el)
  if (!value || !recorded) return undefined
  const [a, b] = await Promise.all([recorded, digest(value)])
  return a !== null && a === b ? value : undefined
}

// ---- Can the user see it? -----------------------------------------------------

const MIN_SIDE = 8

function shadowRootOf(el: Element): ShadowRoot | null {
  if (el.shadowRoot) return el.shadowRoot
  // Content scripts can see closed roots too, where a page could hide a slot.
  const dom = (globalThis as { chrome?: { dom?: { openOrClosedShadowRoot?: (e: HTMLElement) => ShadowRoot | null } } }).chrome?.dom
  try {
    return el instanceof HTMLElement ? (dom?.openOrClosedShadowRoot?.(el) ?? null) : null
  } catch {
    return null
  }
}

/**
 * An element's parent as it's rendered: a shadow host's light-DOM child sits
 * under the slot it's assigned to, and a shadow root's children under its
 * host. `undefined` means the element isn't rendered at all (a host's child
 * no slot takes).
 */
export function renderedParent(node: Element): Element | null | undefined {
  const parent = node.parentElement
  if (parent) {
    const root = shadowRootOf(parent)
    if (!root) return parent
    if (node.assignedSlot) return node.assignedSlot
    for (const slot of Array.from(root.querySelectorAll("slot"))) if (slot.assignedElements().includes(node)) return slot
    return undefined
  }
  const up = node.parentNode
  return up instanceof ShadowRoot ? up.host : null
}

const cssNumber = (value: string, fallback = 1) => {
  if (!value) return fallback
  const n = value.trim().endsWith("%") ? parseFloat(value) / 100 : parseFloat(value)
  return Number.isFinite(n) ? n : fallback
}

/** opacity() inside a filter multiplies like opacity does. */
function filterOpacity(filter: string): number {
  let factor = 1
  for (const m of filter.matchAll(/opacity\(\s*([\d.]+%?)\s*\)/g)) factor *= cssNumber(m[1])
  return factor
}

/**
 * Style anywhere up the rendered tree that hides the element: opacity
 * (multiplied, filters too), display, content-visibility, or a clip. No depth
 * limit: every shadow host and slot counts.
 */
export function hiddenByStyle(el: Element): boolean {
  const own = getComputedStyle(el)
  if (own.visibility === "hidden" || own.visibility === "collapse") return true
  let opacity = 1
  for (let node: Element | null | undefined = el; node; ) {
    const style = getComputedStyle(node)
    if (style.display === "none" || style.getPropertyValue("content-visibility") === "hidden") return true
    opacity *= cssNumber(style.opacity) * filterOpacity(style.getPropertyValue("filter"))
    if (opacity < 0.1) return true
    const clipPath = style.getPropertyValue("clip-path")
    const clip = style.getPropertyValue("clip")
    if ((clipPath && clipPath !== "none") || (clip && clip !== "auto")) return true
    const next = renderedParent(node)
    if (next === undefined) return true
    node = next
  }
  return false
}

/**
 * The part of the element that's on screen: its box cut by every scrolling or
 * clipping ancestor and (`viewport`) the viewport, if at least MIN_SIDE each
 * way. A fixed
 * element escapes the ancestors above it; the root's overflow belongs to the
 * viewport.
 */
export function clippedBox(el: Element, viewport = true): Box | null {
  const r = el.getBoundingClientRect()
  let box: Box = { left: r.left, top: r.top, right: r.right, bottom: r.bottom }
  let fixed = getComputedStyle(el).position === "fixed"
  for (let node = renderedParent(el); node && !fixed; node = renderedParent(node)) {
    if (node === document.documentElement || node === document.body) break
    const style = getComputedStyle(node)
    if (style.overflowX !== "visible" || style.overflowY !== "visible") {
      const a = node.getBoundingClientRect()
      box = { left: Math.max(box.left, a.left), top: Math.max(box.top, a.top), right: Math.min(box.right, a.right), bottom: Math.min(box.bottom, a.bottom) }
    }
    if (style.position === "fixed") fixed = true
  }
  if (viewport) box = { left: Math.max(box.left, 0), top: Math.max(box.top, 0), right: Math.min(box.right, innerWidth), bottom: Math.min(box.bottom, innerHeight) }
  return box.right - box.left < MIN_SIDE || box.bottom - box.top < MIN_SIDE ? null : box
}

const area = (b: Box) => (b.right - b.left) * (b.bottom - b.top)

/**
 * Whether the element is drawn at a usable size, wherever the page is
 * scrolled to: not hidden by style, and most of it not cut off by a
 * scrolling or clipping ancestor (a box collapsed to zero height, say).
 */
export function rendered(el: Element): boolean {
  const r = el.getBoundingClientRect()
  if (r.width < MIN_SIDE || r.height < MIN_SIDE || hiddenByStyle(el)) return false
  const box = clippedBox(el, false)
  return !!box && area(box) >= 0.5 * r.width * r.height
}

/** The part of the element on screen, if most of it is: not a sliver at a clipped edge. */
export function visibleBox(el: Element): Box | null {
  const r = el.getBoundingClientRect()
  const box = clippedBox(el)
  return box && area(box) >= 0.5 * r.width * r.height ? box : null
}

/**
 * What the user would hit in the middle of the visible part is the field.
 * `ours`, Deadbolt's own menu, doesn't count as covering it.
 */
export function onTop(el: FormControl, box: Box, ours?: Element | null): boolean {
  const root = el.getRootNode() as Document | ShadowRoot
  const x = (box.left + box.right) / 2
  const y = (box.top + box.bottom) / 2
  const hit = ours ? root.elementsFromPoint?.(x, y).find((h) => h !== ours) : root.elementFromPoint?.(x, y)
  if (!hit) return false
  return hit === el || el.contains(hit) || (hit.closest("label") as HTMLLabelElement | null)?.control === el
}

/**
 * Never fill something the user can't see: hidden, transparent, clipped,
 * off-screen or covered fields are how pages skim credentials. Checked again
 * right before each value is written. When fields are approved for a fill,
 * the menu the user is picking from is still open, perhaps over the next
 * field: `ours` names it, so it isn't taken for a cover. It's gone by the
 * time anything is written.
 */
export function fillable(el: FormControl, ours?: Element | null): boolean {
  if (!el.isConnected || el.disabled || ("readOnly" in el && el.readOnly)) return false
  const r = el.getBoundingClientRect()
  if (r.width < MIN_SIDE || r.height < MIN_SIDE || hiddenByStyle(el)) return false
  el.scrollIntoView?.({ block: "nearest", inline: "nearest" })
  const box = visibleBox(el)
  return !!box && onTop(el, box, ours)
}

/**
 * Where a child frame's fields show in this page, given where they show in
 * the frame (`boxes`, in its viewport), or null if any doesn't. The element
 * embedding the frame gets the checks a field gets (style up the rendered
 * tree, size, clipping, on screen), has to sit as laid out (no scaling,
 * rotation or skew) and has to be what's under the middle of each field.
 * With `unsandboxed`, a frame element with a `sandbox` attribute doesn't show
 * anything either: a login menu never serves a sandboxed frame (see
 * sameSiteTop).
 */
export function throughFrame(el: HTMLElement, boxes: Box[], unsandboxed = false): Box[] | null {
  if (!el.isConnected || (unsandboxed && el.hasAttribute("sandbox"))) return null
  const r = el.getBoundingClientRect()
  if (r.width < MIN_SIDE || r.height < MIN_SIDE || hiddenByStyle(el)) return null
  if (Math.abs(r.width - el.offsetWidth) > 1 || Math.abs(r.height - el.offsetHeight) > 1) return null
  const clip = clippedBox(el)
  if (!clip) return null
  const style = getComputedStyle(el)
  const offset = { x: r.left + el.clientLeft + (parseFloat(style.paddingLeft) || 0), y: r.top + el.clientTop + (parseFloat(style.paddingTop) || 0) }
  const root = el.getRootNode() as Document | ShadowRoot
  return placeBoxes(boxes, offset, clip, (x, y) => root.elementFromPoint?.(x, y) === el)
}

/** Moves each box by `offset` and cuts it to `clip`: most of it has to show, and `hits` its middle. */
export function placeBoxes(boxes: Box[], offset: { x: number; y: number }, clip: Box, hits: (x: number, y: number) => boolean): Box[] | null {
  const out: Box[] = []
  for (const b of boxes) {
    const moved = { left: b.left + offset.x, top: b.top + offset.y, right: b.right + offset.x, bottom: b.bottom + offset.y }
    const shown = { left: Math.max(moved.left, clip.left), top: Math.max(moved.top, clip.top), right: Math.min(moved.right, clip.right), bottom: Math.min(moved.bottom, clip.bottom) }
    if (shown.right - shown.left < MIN_SIDE || shown.bottom - shown.top < MIN_SIDE || area(shown) < 0.5 * area(moved)) return null
    if (!hits((shown.left + shown.right) / 2, (shown.top + shown.bottom) / 2)) return null
    out.push(shown)
  }
  return out.length ? out : null
}

// ---- Writing ------------------------------------------------------------------

/**
 * The input a page's framework put in the place of `f.el` while this fill
 * was writing (some re-render a form on every input event, with new
 * elements): under the same parent, in the same form, with the same id,
 * name, type and autocomplete, and the only one there. It still has to pass
 * every check a field does before anything is written into it.
 */
export function successor(f: Field): HTMLInputElement | null {
  const { el, owner } = f
  if (el.isConnected || !owner.parent?.isConnected || (!el.id && !el.name)) return null
  const same = Array.from(owner.parent.childNodes).filter(
    (c): c is HTMLInputElement =>
      c instanceof HTMLInputElement && c.id === el.id && c.name === el.name && c.type === el.type && c.getAttribute("autocomplete") === el.getAttribute("autocomplete") && (c.form ?? c.closest("form")) === owner.form,
  )
  return same.length === 1 ? same[0] : null
}

/**
 * Focuses the field, then checks it once more right before the value goes in:
 * the page's focus and key handlers run in between and could move or hide it.
 */
export function setInputValue(el: HTMLInputElement, value: string, guard: (el: HTMLInputElement) => boolean = () => true): boolean {
  const nativeValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!
  el.focus({ preventScroll: true })
  el.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, composed: true, key: "Unidentified" }))
  if (!guard(el)) return false
  if (key) digests.set(el, digest(value))
  nativeValue.call(el, value)
  el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertReplacementText", data: value }))
  el.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true, composed: true, key: "Unidentified" }))
  el.dispatchEvent(new Event("change", { bubbles: true }))
  return true
}

/**
 * Fills the fields of one form snapshot. Every write is checked right before
 * it happens: the field must still be where it was scanned (same form, same
 * parent) and pass `check`. One-digit code boxes fill only as a whole group:
 * as many boxes as digits, all in the same form and all fillable, and none
 * moved before each digit goes in.
 */
export async function fillFields(fields: Field[], values: FillValues, check: (el: HTMLInputElement) => boolean = fillable): Promise<{ filled: FieldRole[]; last?: HTMLInputElement; written: HTMLInputElement[] }> {
  const filled: FieldRole[] = []
  let last: HTMLInputElement | undefined
  const written: HTMLInputElement[] = []
  // A single field that one of this fill's own writes replaced is checked, and
  // written, as its successor (see successor); only one that was in the page
  // when the fill began.
  const present = new Set(fields.filter((f) => f.el.isConnected).map((f) => f.el))
  const now = (f: Field): Field => {
    const next = !f.el.isConnected && present.has(f.el) && written.length ? successor(f) : null
    return next ? { ...f, el: next } : f
  }
  const checkField = check
  check = (el) => {
    const f = fields.find((x) => x.el === el)
    return checkField(f ? now(f).el : el)
  }
  const write = (field: Field, value: string, group: Field[] = [field]) => {
    const f = group.length === 1 ? now(field) : field
    const all = group.length === 1 ? [f] : group
    const ok = (el: HTMLInputElement) => all.every(inPlace) && checkField(el)
    if (!(ok(f.el) && setInputValue(f.el, value, ok))) return false
    written.push(f.el)
    return true
  }
  // A beat between fields for pages that react to each one. None after the
  // last: the ack has to leave before a page that submits on fill navigates.
  const pause = () => (filled.length ? sleep(30) : undefined)

  const ident = fields.find((t) => IDENTIFIER_ROLES.includes(t.role) && check(t.el))
  if (ident && values.username && write(ident, values.username)) {
    filled.push(ident.role)
    last = ident.el
  }

  if (values.password) await pause()
  const password = fields.find((t) => t.role === "password" && check(t.el))
  if (password && values.password && write(password, values.password)) {
    filled.push("password")
    last = password.el
  }

  // A generated password goes into every new-password box, the new one and
  // its confirmation, and only when every one can take it.
  if (values.newPassword) {
    await pause()
    const boxes = fields.filter((t) => t.role === "new-password")
    if (boxes.length && boxes.every((b) => check(b.el))) {
      let i = 0
      while (i < boxes.length && write(boxes[i], values.newPassword, boxes)) i++
      if (i === boxes.length) {
        filled.push("new-password")
        last = boxes[i - 1].el
      }
    }
  }

  if (values.totp) {
    await pause()
    const boxes = fields.filter((t) => t.role === "otp" && t.split)
    if (boxes.length) {
      boxes.sort((a, b) => (a.el.compareDocumentPosition(b.el) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1))
      const form = boxes[0].owner.form
      const whole = boxes.length === values.totp.length && boxes.every((b) => b.owner.form === form && inPlace(b) && check(b.el))
      if (whole) {
        let i = 0
        while (i < boxes.length && write(boxes[i], values.totp[i], boxes)) i++
        if (i === boxes.length) {
          filled.push("otp")
          last = boxes[i - 1].el
        }
      }
    } else {
      const otp = fields.find((t) => t.role === "otp" && check(t.el))
      if (otp && write(otp, values.totp)) {
        filled.push("otp")
        last = otp.el
      }
    }
  }
  return { filled, last: written.at(-1) ?? last, written }
}
