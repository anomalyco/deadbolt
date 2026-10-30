// Writes credentials into the page so plain forms and framework-controlled
// inputs (React, Vue, Angular) both accept them. Ported from Foyer
// (github.com/R44VC0RP/foyer, src/autofill/fill.ts, by Ryan Vogel).
//
// The value is set through the native HTMLInputElement setter from the
// extension's isolated world, then input/change events are dispatched. A
// framework's own value tracker lives in the page's world, so it sees the DOM
// value differ from what it last rendered and runs its change handler.

import { IDENTIFIER_ROLES, phoneLike, type Box, type FieldRole, type FillValues } from "../messages"
import { inPlace, type Field, type FormControl } from "./detect"
import { MAX_ROOTS, eventTarget, isOwnHost, openRoots, shadowRootOf } from "./shadow"

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
  const el = eventTarget(event)
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

/** The largest blur a field may be drawn with and still count as readable, in CSS pixels. */
const MAX_BLUR_PX = 1

/**
 * Whether a filter can make what's under it unreadable: anything but none,
 * opacity() (counted with opacity) and a blur of at most MAX_BLUR_PX. A heavy
 * blur, brightness(0), an SVG url() filter and anything else count; fails
 * closed on what it doesn't know.
 */
export function obscuringFilter(filter: string): boolean {
  if (!filter || filter === "none") return false
  const rest = filter
    .replace(/opacity\(\s*[\d.]+%?\s*\)/g, "")
    .replace(/blur\(\s*([\d.]+)px\s*\)/g, (m, px: string) => (Number(px) <= MAX_BLUR_PX ? "" : m))
  return rest.trim() !== ""
}

/** Whether a box with this style is painted through a mask: any mask image or mask border, which can make it transparent. */
function masked(style: CSSStyleDeclaration): boolean {
  return ["mask-image", "-webkit-mask-image", "mask-border-source", "-webkit-mask-box-image-source"].some((p) => (style.getPropertyValue(p) || "none") !== "none")
}

/** Whether a box with this style is drawn transformed: its client rect is then only a bounding box. */
function transformed(style: CSSStyleDeclaration): boolean {
  return ["transform", "translate", "rotate", "scale", "offset-path"].some((p) => (style.getPropertyValue(p) || "none") !== "none")
}

/** A length of a clip-path inset() in CSS pixels, a percentage taken of `of`; NaN for anything else (calc(), em...). */
function insetLength(v: string, of: number): number {
  const m = /^(-?[\d.]+)(px|%)?$/.exec(v)
  if (!m || (m[2] === undefined && Number(m[1]) !== 0)) return NaN
  return m[2] === "%" ? (Number(m[1]) / 100) * of : Number(m[1])
}

/**
 * Whether `node`'s clip-path leaves all of `field` showing: an inset()
 * whose rectangle, resolved against `node`'s border box (percentages of its
 * size), contains the field's box to within half a pixel, with any rounded
 * corners no larger than the room the field leaves inside it. Design systems
 * put one on a field's wrapper to leave its focus ring room (Stripe's
 * sign-in: `inset(-8px)`). Anything else counts as hiding the field: another
 * shape, a value it can't resolve, or a transform on `node` or between it and
 * the field (`transformedBetween`), which makes client rects bounding boxes.
 */
export function insetKeepsField(node: Element, clipPath: string, field: Element, transformedBetween: boolean): boolean {
  const m = /^inset\((.*)\)$/.exec(clipPath.trim())
  if (!m || transformedBetween) return false
  const [sidesText, roundText] = m[1].split(/\s+round\s+/)
  const sides = sidesText.trim().split(/\s+/)
  if (!sides.length || sides.length > 4) return false
  const [t, r = t, b = t, l = r] = sides
  const a = node.getBoundingClientRect()
  const top = insetLength(t, a.height), right = insetLength(r, a.width), bottom = insetLength(b, a.height), left = insetLength(l, a.width)
  if ([top, right, bottom, left].some(Number.isNaN)) return false
  const f = field.getBoundingClientRect()
  const room = Math.min(f.left - (a.left + left), f.top - (a.top + top), a.right - right - f.right, a.bottom - bottom - f.bottom)
  if (room < -0.5) return false
  if (roundText === undefined) return true
  const radii = roundText.trim().split(/[\s/]+/).map((v) => insetLength(v, Math.max(a.width, a.height)))
  return radii.every((v) => !Number.isNaN(v) && v <= Math.max(room, 0))
}

/**
 * Style anywhere up the rendered tree that hides the element: opacity
 * (multiplied, filters too), display, content-visibility, a mask, a filter
 * that can obscure it (see obscuringFilter), or a clip (a clip-path counts
 * unless it is an inset that leaves the whole field showing, see
 * insetKeepsField). No depth limit: every shadow host and slot counts.
 */
export function hiddenByStyle(el: Element): boolean {
  const own = getComputedStyle(el)
  if (own.visibility === "hidden" || own.visibility === "collapse") return true
  let opacity = 1
  let bent = false
  for (let node: Element | null | undefined = el; node; ) {
    const style = getComputedStyle(node)
    if (style.display === "none" || style.getPropertyValue("content-visibility") === "hidden") return true
    opacity *= cssNumber(style.opacity) * filterOpacity(style.getPropertyValue("filter"))
    if (opacity < 0.1) return true
    if (masked(style) || obscuringFilter(style.getPropertyValue("filter"))) return true
    bent ||= transformed(style)
    const clipPath = style.getPropertyValue("clip-path")
    const clip = style.getPropertyValue("clip")
    if ((clipPath && clipPath !== "none" && !insetKeepsField(node, clipPath, el, bent)) || (clip && clip !== "auto")) return true
    const next = renderedParent(node)
    if (next === undefined) return true
    node = next
  }
  return false
}

/**
 * Whether a box with this style is the containing block of fixed boxes inside
 * it (and so of absolutely positioned ones too): a transform of any kind
 * (transform, translate, rotate, scale, offset-path), perspective, a filter,
 * containment, or a will-change for one of them. Errs towards yes: a yes
 * keeps its overflow counting as a clip.
 */
function holdsFixed(style: CSSStyleDeclaration): boolean {
  return (
    transformed(style) ||
    style.getPropertyValue("perspective") !== "none" ||
    style.filter !== "none" ||
    (style.getPropertyValue("backdrop-filter") || "none") !== "none" ||
    /paint|layout|strict|content/.test(style.getPropertyValue("contain")) ||
    /transform|translate|rotate|scale|offset-path|perspective|filter|contain/.test(style.getPropertyValue("will-change")) ||
    (style.getPropertyValue("container-type") || "normal") !== "normal" ||
    style.getPropertyValue("content-visibility") === "auto"
  )
}

/**
 * The part of the element that's on screen: its box cut by every scrolling or
 * clipping ancestor and (`viewport`) the viewport, if at least MIN_SIDE each
 * way. An absolutely positioned element escapes the ancestors between it and
 * its containing block (an overflow box that doesn't hold it doesn't clip it:
 * Intercom's sign-in sits in a 0 px tall scrolling row), and a fixed one
 * every ancestor up to one that holds fixed boxes (a transformed one, say);
 * paint containment clips like overflow; a box with no box of its own
 * (`display: contents`, inline) clips nothing; the root's overflow belongs to
 * the viewport. The field's check also hit-tests the centre of what's left
 * (see onTop), and only the centre.
 */
export function clippedBox(el: Element, viewport = true): Box | null {
  const r = el.getBoundingClientRect()
  let box: Box = { left: r.left, top: r.top, right: r.right, bottom: r.bottom }
  const own = getComputedStyle(el)
  let escape: "none" | "absolute" | "fixed" = own.position === "fixed" ? "fixed" : own.position === "absolute" ? "absolute" : "none"
  for (let node = renderedParent(el); node; node = renderedParent(node)) {
    if (node === document.documentElement || node === document.body) break
    const style = getComputedStyle(node)
    const fixedHolder = holdsFixed(style)
    const holds = escape === "fixed" ? fixedHolder : fixedHolder || style.position !== "static"
    const boxed = style.display !== "contents" && style.display !== "inline"
    const clips = boxed && (style.overflowX !== "visible" || style.overflowY !== "visible" || /paint|strict|content/.test(style.getPropertyValue("contain")))
    if (clips && (escape === "none" || holds)) {
      const a = node.getBoundingClientRect()
      box = { left: Math.max(box.left, a.left), top: Math.max(box.top, a.top), right: Math.min(box.right, a.right), bottom: Math.min(box.bottom, a.bottom) }
    }
    if (holds) escape = "none"
    if (style.position === "absolute") escape = "absolute"
    if (style.position === "fixed") escape = "fixed"
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
 * What the user would hit in the middle of the visible part is the field,
 * and nothing that lets clicks through paints over it there (see
 * paintedOver). `ours`, Deadbolt's own menu, doesn't count as covering it.
 */
export function onTop(el: FormControl, box: Box, ours?: Element | null): boolean {
  const root = el.getRootNode() as Document | ShadowRoot
  const x = (box.left + box.right) / 2
  const y = (box.top + box.bottom) / 2
  const hit = ours ? root.elementsFromPoint?.(x, y).find((h) => h !== ours) : root.elementFromPoint?.(x, y)
  if (!hit) return false
  const labelOf = (h: Element) => (h.closest("label") as HTMLLabelElement | null)?.control === el
  if (hit !== el && !el.contains(hit) && !labelOf(hit)) return false
  return !paintedOver(el, root, x, y, ours, labelOf)
}

/** Every element takes part in hit tests, whatever the page's styles say: adopted only for the length of one synchronous check. */
let probeSheet: CSSStyleSheet | null = null
const PROBE_CSS = `*, *::before, *::after { pointer-events: auto !important; interactivity: auto !important }
::backdrop { pointer-events: auto !important }`

/** The alpha of a computed colour; 1 (fails closed) for one it can't read. */
function alpha(color: string): number {
  if (!color || color === "transparent") return 0
  const legacy = /^rgba\([^,]+,[^,]+,[^,]+,\s*([\d.]+)\s*\)$/.exec(color)
  if (legacy) return Number(legacy[1])
  const slash = /\/\s*([\d.]+)(%?)\s*\)$/.exec(color)
  if (slash) return Number(slash[1]) / (slash[2] ? 100 : 1)
  return 1
}

const GRAPHIC = new Set(["IMG", "VIDEO", "CANVAS", "IFRAME", "EMBED", "OBJECT", "INPUT", "TEXTAREA", "SELECT", "BUTTON", "METER", "PROGRESS"])

/**
 * Whether a box with this style paints over what's under it at the point
 * (x, y) inside its border box: a background colour that isn't (nearly)
 * transparent, a background image, a backdrop filter, an inset shadow, or a
 * border the point is on. Its text doesn't count.
 */
function opaqueStyle(style: CSSStyleDeclaration, at?: { r: DOMRect; x: number; y: number }): boolean {
  if (alpha(style.backgroundColor) >= 0.1 || (style.backgroundImage || "none") !== "none") return true
  if ((style.getPropertyValue("backdrop-filter") || "none") !== "none" || /\binset\b/.test(style.boxShadow || "")) return true
  if ((style.getPropertyValue("border-image-source") || "none") !== "none") return true
  const sides = (["top", "right", "bottom", "left"] as const).map((s) => ({
    width: parseFloat(style.getPropertyValue(`border-${s}-width`)) || 0,
    shown: !/none|hidden/.test(style.getPropertyValue(`border-${s}-style`)) && alpha(style.getPropertyValue(`border-${s}-color`)) >= 0.1,
  }))
  if (!sides.some((s) => s.width > 0 && s.shown)) return false
  // Without the point (a pseudo-element's box is unknown), any border counts.
  if (!at || transformed(style)) return true
  const { r, x, y } = at
  const [t, ri, b, l] = sides.map((s) => (s.shown ? s.width : 0))
  return y < r.top + t || x > r.right - ri || y > r.bottom - b || x < r.left + l
}

/**
 * Whether the element, hit at (x, y), draws anything there: it isn't
 * (nearly) faded out, and it's a graphic or form control, an SVG shape, or
 * it or its ::before or ::after has opaque style (see opaqueStyle).
 */
function paints(h: Element, x: number, y: number): boolean {
  const own = getComputedStyle(h)
  if (own.visibility === "hidden" || own.visibility === "collapse") return false
  let opacity = 1
  for (let node: Element | null | undefined = h; node; node = renderedParent(node)) {
    const style = getComputedStyle(node)
    opacity *= cssNumber(style.opacity) * filterOpacity(style.getPropertyValue("filter"))
    if (opacity < 0.1) return false
  }
  if (GRAPHIC.has(h.tagName) || h instanceof SVGElement) return true
  return opaqueStyle(own, { r: h.getBoundingClientRect(), x, y }) || pseudoPaints(h)
}

/** Whether the element's ::before or ::after draws anything opaque (an image, or opaque style). Its box is unknown, so anywhere counts. */
function pseudoPaints(h: Element): boolean {
  return ["::before", "::after"].some((p) => {
    const s = getComputedStyle(h, p)
    const content = s.getPropertyValue("content")
    return content !== "none" && content !== "normal" && s.display !== "none" && (/url\(|image\(|gradient\(/.test(content) || opaqueStyle(s))
  })
}

/**
 * Whether something the page lets clicks through (`pointer-events: none`,
 * `inert`) paints over the field at (x, y). Hit tests skip such elements,
 * so for one synchronous check every element in the document and its shadow
 * roots is made to take part (a stylesheet adopted into each root, inline
 * `!important` pointer-events and `inert` lifted), and each element the
 * browser then stacks above the field must draw nothing there (see paints).
 * Inside a shadow host above it, so must each element of its root. The
 * field's own label and Deadbolt's own surfaces don't count. Fails closed:
 * no hit testing, a page with more shadow roots than are walked, or a field
 * the test doesn't find means covered.
 */
function paintedOver(el: Element, root: Document | ShadowRoot, x: number, y: number, ours: Element | null | undefined, labelOf: (h: Element) => boolean): boolean {
  if (typeof root.elementsFromPoint !== "function" || typeof CSSStyleSheet === "undefined") return true
  const roots = openRoots()
  if (roots.length >= MAX_ROOTS) return true
  if (!probeSheet) {
    probeSheet = new CSSStyleSheet()
    probeSheet.replaceSync(PROBE_CSS)
  }
  const sheet = probeSheet
  const undo: Array<() => void> = []
  try {
    for (const r of roots) {
      const before = r.adoptedStyleSheets
      r.adoptedStyleSheets = [...before, sheet]
      undo.push(() => (r.adoptedStyleSheets = r.adoptedStyleSheets.filter((s) => s !== sheet)))
      for (const e of Array.from(r.querySelectorAll<HTMLElement>('[inert], [style*="pointer-events" i], [style*="interactivity" i]'))) {
        const inert = e.getAttribute("inert")
        if (inert !== null) {
          e.removeAttribute("inert")
          undo.push(() => e.setAttribute("inert", inert))
        }
        for (const p of ["pointer-events", "interactivity"]) {
          if (!e.style || e.style.getPropertyPriority(p) !== "important") continue
          const value = e.style.getPropertyValue(p)
          e.style.setProperty(p, "auto", "important")
          undo.push(() => e.style.setProperty(p, value, "important"))
        }
      }
    }
    const skip = (h: Element) => h === ours || (!!ours && ours.contains(h)) || isOwnHost(h)
    // `stop` is the field, in the list of what's at the point in its own
    // root; null for the list inside a shadow host above it, of which only
    // that root's elements count (the rest are in the outer list).
    const above = (list: Element[], stop: Element | null, scope: Document | ShadowRoot): boolean => {
      for (const h of list) {
        if (h === stop) return false
        if ((!stop && h.getRootNode() !== scope) || skip(h) || el.contains(h)) continue
        // An ancestor of the field is listed above it only for a pseudo-element.
        if (holds(h, el)) {
          if (pseudoPaints(h)) return true
          continue
        }
        if (labelOf(h)) {
          if (opaqueLabel(h)) return true
          continue
        }
        const inner = shadowRootOf(h)
        if (inner && above(inner.elementsFromPoint(x, y), null, inner)) return true
        if (paints(h, x, y)) return true
      }
      // The field itself never came up: fail closed.
      return stop !== null
    }
    return above(root.elementsFromPoint(x, y), el, root)
  } catch {
    return true
  } finally {
    for (const f of undo.reverse()) f()
  }
}

/** Whether `h` is `el` or an ancestor of it, across shadow roots. */
function holds(h: Node, el: Node): boolean {
  for (let n: Node | null = el; n; n = n.parentNode ?? (n instanceof ShadowRoot ? n.host : null)) if (n === h) return true
  return false
}

/** The field's own label may sit over it (a floating label), so long as it doesn't hide it: no opaque background. */
function opaqueLabel(h: Element): boolean {
  const s = getComputedStyle(h)
  return alpha(s.backgroundColor) >= 0.1 || (s.backgroundImage || "none") !== "none" || (s.getPropertyValue("backdrop-filter") || "none") !== "none"
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
 * The input a page's framework put in the place of `f.el` while a fill was
 * writing (some re-render a form on every input event, with new elements):
 * under the same parent, in the same form, with the same id, name, type and
 * autocomplete, the only one there, and (given `was`, the field's box when
 * the fill began) covering at least half of where the field was. It still
 * has to pass every check a field does before anything is written into it.
 */
export function successor(f: Pick<Field, "el" | "owner">, was?: DOMRect): HTMLInputElement | null {
  const { el, owner } = f
  if (el.isConnected || !owner.parent?.isConnected || (!el.id && !el.name)) return null
  const same = Array.from(owner.parent.childNodes).filter(
    (c): c is HTMLInputElement =>
      c instanceof HTMLInputElement && c.id === el.id && c.name === el.name && c.type === el.type && c.getAttribute("autocomplete") === el.getAttribute("autocomplete") && (c.form ?? c.closest("form")) === owner.form,
  )
  if (same.length !== 1) return null
  if (!was) return same[0]
  const r = same[0].getBoundingClientRect()
  const overlap = Math.max(0, Math.min(r.right, was.right) - Math.max(r.left, was.left)) * Math.max(0, Math.min(r.bottom, was.bottom) - Math.max(r.top, was.top))
  return was.width * was.height > 0 && overlap >= 0.5 * was.width * was.height ? same[0] : null
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
 * Whether the user could have entered `value` in the field: no longer than
 * its maxlength (the browser stops typing and pasting there), and a phone
 * number in a phone box. A value that doesn't fit isn't written: the site
 * would reject it, or keep a cut-off copy.
 */
export function fits(el: HTMLInputElement, role: FieldRole, value: string): boolean {
  if (el.maxLength > 0 && value.length > el.maxLength) return false
  return role !== "phone" || phoneLike(value)
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
  // A single field (not a box of a group) that one of this fill's own
  // writes replaced is checked, and written, as its successor (see
  // successor): it was in the page when the last write began and is gone
  // now. Pages re-render after the write returns (a microtask, a batched
  // update), so it's the last write's start that's compared, at the field's
  // turn. Its successor has to sit where the field was when the fill began.
  const single = (f: Field) => !f.split && f.role !== "new-password"
  const was = new Map(fields.filter((f) => f.el.isConnected && single(f)).map((f) => [f.el, f.el.getBoundingClientRect()]))
  let liveAtLastWrite = new Set<HTMLInputElement>()
  const now = (f: Field): Field => {
    const next = !f.el.isConnected && single(f) && liveAtLastWrite.has(f.el) ? successor(f, was.get(f.el)) : null
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
    if (!ok(f.el)) return false
    liveAtLastWrite = new Set([...was.keys()].filter((el) => el.isConnected))
    if (!setInputValue(f.el, value, ok)) return false
    written.push(f.el)
    return true
  }
  // A beat between fields for pages that react to each one. None after the
  // last: the ack has to leave before a page that submits on fill navigates.
  const pause = () => (filled.length ? sleep(30) : undefined)

  const ident = fields.find((t) => IDENTIFIER_ROLES.includes(t.role) && check(t.el))
  if (ident && values.username && fits(ident.el, ident.role, values.username) && write(ident, values.username)) {
    filled.push(ident.role)
    last = ident.el
  }

  if (values.password) await pause()
  const password = fields.find((t) => t.role === "password" && check(t.el))
  if (password && values.password && fits(password.el, "password", values.password) && write(password, values.password)) {
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
      if (otp && fits(otp.el, "otp", values.totp) && write(otp, values.totp)) {
        filled.push("otp")
        last = otp.el
      }
    }
  }
  return { filled, last: written.at(-1) ?? last, written }
}
