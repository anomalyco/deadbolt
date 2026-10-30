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
import { eventTarget, isOwnHost, openRoots, shadowRootOf } from "./shadow"

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

/** A filter's functions, each with its argument text: `drop-shadow(rgb(0 0 0) 1px 1px)` is one. Null for text it can't split. */
export function filterFunctions(filter: string): Array<{ name: string; arg: string }> | null {
  const out: Array<{ name: string; arg: string }> = []
  let i = 0
  while (i < filter.length) {
    if (/\s/.test(filter[i])) {
      i++
      continue
    }
    const m = /^([a-z-]+)\(/i.exec(filter.slice(i))
    if (!m) return null
    let depth = 0
    let j = i + m[1].length
    for (; j < filter.length; j++) {
      if (filter[j] === "(") depth++
      else if (filter[j] === ")" && --depth === 0) break
    }
    if (depth !== 0 || j >= filter.length) return null
    out.push({ name: m[1].toLowerCase(), arg: filter.slice(i + m[1].length + 1, j).trim() })
    i = j + 1
  }
  return out
}

/** A filter amount: a number or a percentage, as a factor; NaN for anything else. */
const amount = (arg: string, empty = 1) => {
  if (!arg) return empty
  const m = /^([\d.]+)(%?)$/.exec(arg)
  return m ? Number(m[1]) / (m[2] ? 100 : 1) : NaN
}

/**
 * Whether a filter can make what's under it unreadable. Allowed, as filters
 * that keep a page readable (Dark Reader puts invert() and hue-rotate() on
 * <html>): opacity() (counted with opacity), a blur of at most MAX_BLUR_PX,
 * drop-shadow(), hue-rotate(), saturate(), sepia(), grayscale(), invert()
 * other than near half (which turns everything one grey), brightness() from
 * 0.2 to 5 and contrast() from 0.2 to 5. Anything else, an SVG url() filter
 * or a function it doesn't know counts; fails closed.
 */
export function obscuringFilter(filter: string): boolean {
  if (!filter || filter === "none") return false
  const fns = filterFunctions(filter)
  if (!fns) return true
  return !fns.every(({ name, arg }) => {
    const n = amount(arg)
    switch (name) {
      case "opacity":
      case "drop-shadow":
      case "hue-rotate":
      case "saturate":
      case "sepia":
      case "grayscale":
        return true
      case "blur": {
        const m = /^([\d.]+)px$/.exec(arg || "0px")
        return !!m && Number(m[1]) <= MAX_BLUR_PX
      }
      case "invert":
        return n <= 0.35 || n >= 0.65
      case "brightness":
      case "contrast":
        return n >= 0.2 && n <= 5
      default:
        return false
    }
  })
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
 * that can obscure it (see obscuringFilter), a blend mode, or a clip (a clip-path counts
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
    if (masked(style) || obscuringFilter(style.getPropertyValue("filter")) || (style.getPropertyValue("mix-blend-mode") || "normal") !== "normal") return true
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
  if (hit !== el && !el.contains(hit) && (hit.closest("label") as HTMLLabelElement | null)?.control !== el) return false
  return !paintedOver(el, root, x, y, ours)
}

/** Shadow roots the paint check walks; a page with more counts as covering. */
const PROBE_ROOTS = 5000

/**
 * Every element takes part in hit tests, whatever the page's styles say, for
 * the length of one synchronous check. In a cascade layer declared before
 * any of the page's, its !important beats every other rule of the page, in
 * a layer or not (only inline !important beats it: see paintedOver).
 */
const PROBE_CSS = `@layer deadbolt-probe {
  *, *::before, *::after { pointer-events: auto !important; interactivity: auto !important }
  ::backdrop { pointer-events: auto !important }
  :host { pointer-events: auto !important; interactivity: auto !important }
}`
let probeSheet: CSSStyleSheet | null = null

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

const within = (r: Box, x: number, y: number, by = 0) => x >= r.left - by && x <= r.right + by && y >= r.top - by && y <= r.bottom + by

/**
 * Whether a box with this style paints over what's under it at the point
 * (x, y) inside its border box: a background colour that isn't (nearly)
 * transparent, a background image, a backdrop filter, an inset shadow, or a
 * border the point is on.
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

/** Whether text in this style is drawn: its fill, or a stroke, isn't (nearly) transparent. */
function inkShown(style: CSSStyleDeclaration): boolean {
  const fill = style.getPropertyValue("-webkit-text-fill-color") || style.color
  return alpha(fill) >= 0.1 || ((parseFloat(style.getPropertyValue("-webkit-text-stroke-width")) || 0) > 0 && alpha(style.getPropertyValue("-webkit-text-stroke-color")) >= 0.1)
}

/** Whether the element's own text (its text node children) has a glyph run over (x, y), drawn in a colour that shows. */
function textAt(h: Element, x: number, y: number, style: CSSStyleDeclaration): boolean {
  if (!inkShown(style)) return false
  const range = document.createRange()
  for (const node of Array.from(h.childNodes)) {
    if (node.nodeType !== Node.TEXT_NODE || !node.textContent?.trim()) continue
    range.selectNodeContents(node)
    for (const r of Array.from(range.getClientRects())) if (within(r, x, y)) return true
  }
  return false
}

/** Whether the element's computed opacity, up the rendered tree, leaves it (nearly) invisible, or it's hidden. */
function faded(h: Element, own: CSSStyleDeclaration): boolean {
  if (own.visibility === "hidden" || own.visibility === "collapse") return true
  let opacity = 1
  for (let node: Element | null | undefined = h; node; node = renderedParent(node)) {
    const style = node === h ? own : getComputedStyle(node)
    opacity *= cssNumber(style.opacity) * filterOpacity(style.getPropertyValue("filter"))
    if (opacity < 0.1) return true
  }
  return false
}

/**
 * Whether the element, hit at (x, y), draws anything there: it isn't
 * (nearly) faded out, and it's a graphic or form control, an SVG shape, its
 * own text runs over the point, or it or its ::before or ::after has opaque
 * style (see opaqueStyle).
 */
function paints(h: Element, x: number, y: number): boolean {
  const own = getComputedStyle(h)
  if (faded(h, own)) return false
  if (GRAPHIC.has(h.tagName) || h instanceof SVGElement) return true
  return opaqueStyle(own, { r: h.getBoundingClientRect(), x, y }) || textAt(h, x, y, own) || pseudoPaints(h)
}

/** Whether a ::before or ::after style draws anything: an image, text that shows, or opaque style. Its box is unknown, so anywhere counts. */
function pseudoDraws(s: CSSStyleDeclaration): boolean {
  const content = s.getPropertyValue("content")
  if (!content || content === "none" || content === "normal" || s.display === "none") return false
  return /url\(|image\(|gradient\(/.test(content) || (/"[^"]+"|counter|attr\(/.test(content) && inkShown(s)) || opaqueStyle(s)
}

/** Whether the element's ::before or ::after draws anything (see pseudoDraws). */
function pseudoPaints(h: Element): boolean {
  return ["::before", "::after"].some((p) => pseudoDraws(getComputedStyle(h, p)))
}

/** A computed shadow list (box-shadow, text-shadow) split into shadows: its colour's alpha, its lengths in px, and whether it's inset. */
function shadows(list: string): Array<{ alpha: number; lengths: number[]; inset: boolean }> {
  if (!list || list === "none") return []
  const parts: string[] = []
  let depth = 0
  let start = 0
  for (let i = 0; i < list.length; i++) {
    if (list[i] === "(") depth++
    else if (list[i] === ")") depth--
    else if (list[i] === "," && depth === 0) {
      parts.push(list.slice(start, i))
      start = i + 1
    }
  }
  parts.push(list.slice(start))
  return parts.map((p) => {
    const color = /[a-z-]+\([^()]*\)|#[0-9a-f]+|\btransparent\b/i.exec(p)?.[0] ?? ""
    const rest = color ? p.replace(color, " ") : p
    return { alpha: color ? alpha(color) : 1, lengths: Array.from(rest.matchAll(/(-?[\d.]+)px/g), (m) => Number(m[1])), inset: /\binset\b/.test(rest) }
  })
}

/**
 * Whether paint the browser doesn't hit-test, drawn outside the element's
 * box, reaches (x, y): an outline (drawn over the element's own content,
 * so the field's own and an ancestor's count too), or, for anything but the field and its ancestors
 * (whose shadows are drawn under it), an outer box-shadow's solid part, a
 * text-shadow, a drop-shadow() filter or a border image outset. Anything
 * not (nearly) transparent counts; where shadows of text or content fall
 * is taken as anywhere within their reach.
 */
function overflowPaintAt(style: CSSStyleDeclaration, r: DOMRect, x: number, y: number, ancestor: boolean): boolean {
  const outline = style.getPropertyValue("outline-style")
  if (outline && !/none|hidden/.test(outline) && alpha(style.getPropertyValue("outline-color")) >= 0.1) {
    const w = parseFloat(style.getPropertyValue("outline-width")) || 0
    const o = parseFloat(style.getPropertyValue("outline-offset")) || 0
    if (w > 0 && within(r, x, y, o + w) && !within(r, x, y, o)) return true
  }
  if (ancestor || within(r, x, y)) return false
  for (const s of shadows(style.boxShadow)) {
    if (s.inset || s.alpha < 0.1) continue
    const [ox = 0, oy = 0, , spread = 0] = s.lengths
    if (within({ left: r.left + ox, right: r.right + ox, top: r.top + oy, bottom: r.bottom + oy }, x, y, spread)) return true
  }
  const reach: Array<{ alpha: number; lengths: number[] }> = shadows(style.getPropertyValue("text-shadow"))
  const filter = style.getPropertyValue("filter")
  if (filter && filter !== "none") for (const f of filterFunctions(filter) ?? []) if (f.name === "drop-shadow") reach.push(...shadows(f.arg))
  for (const s of reach) {
    if (s.alpha < 0.1) continue
    const [ox = 0, oy = 0, blur = 0] = s.lengths
    if (within({ left: r.left + ox, right: r.right + ox, top: r.top + oy, bottom: r.bottom + oy }, x, y, blur)) return true
  }
  if ((style.getPropertyValue("border-image-source") || "none") !== "none") {
    const widths = ["top", "right", "bottom", "left"].map((s) => parseFloat(style.getPropertyValue(`border-${s}-width`)) || 0)
    const outset = Math.max(0, ...(style.getPropertyValue("border-image-outset") || "0").split(/\s+/).map((v) => (/px$/.test(v) ? parseFloat(v) : (parseFloat(v) || 0) * Math.max(...widths))))
    if (outset > 0 && within(r, x, y, outset)) return true
  }
  return false
}

/** Whether a box with this style may paint outside itself (see overflowPaintAt): cheap, before its box is measured. */
function overflows(style: CSSStyleDeclaration): boolean {
  const outline = style.getPropertyValue("outline-style")
  return (
    (!!outline && outline !== "none") ||
    (style.boxShadow || "none") !== "none" ||
    (style.getPropertyValue("text-shadow") || "none") !== "none" ||
    /drop-shadow/.test(style.getPropertyValue("filter")) ||
    (style.getPropertyValue("border-image-source") || "none") !== "none"
  )
}

/** Whether `h` is `el` or an ancestor of it, across shadow roots. */
function holds(h: Node, el: Node): boolean {
  for (let n: Node | null = el; n; n = composedParent(n)) if (n === h) return true
  return false
}

const composedParent = (n: Node): Node | null => n.parentNode ?? (n instanceof ShadowRoot ? n.host : null)

/** Whether anything from the field up to (not including) its ancestor `h` has a negative z-index, which puts it under `h`'s own paint. */
function behind(el: Element, h: Element): boolean {
  for (let n: Node | null = el; n && n !== h; n = composedParent(n)) if (n instanceof Element && (parseFloat(getComputedStyle(n).zIndex) || 0) < 0) return true
  return false
}

/**
 * Whether something the page lets clicks through (`pointer-events: none`,
 * `inert`) paints over the field at (x, y), or paint the browser never
 * hit-tests does (see overflowPaintAt). Hit tests skip such elements, so
 * for one synchronous check every element of the document and its shadow
 * roots is made to take part: PROBE_CSS first in each root (`:host` too),
 * `inert` lifted, and an inline `!important` pointer-events on each element
 * over the point that still has none (one with its own inline !important).
 * All of it is put back before the check returns, each part even if
 * another fails. Each element the browser then stacks above the field must
 * draw nothing there (see paints); inside a shadow host above it, so must
 * each element of its root. An ancestor listed above the field draws over
 * it through a pseudo-element, or, if the field sits under it by a negative
 * z-index, through its own box too. Deadbolt's own surfaces don't count.
 * Fails closed: no hit testing, more shadow roots than PROBE_ROOTS, an
 * element over the point that still can't be hit and draws, or a field the
 * test doesn't find all mean covered.
 */
function paintedOver(el: Element, root: Document | ShadowRoot, x: number, y: number, ours: Element | null | undefined): boolean {
  if (typeof root.elementsFromPoint !== "function") return true
  const roots = openRoots(document, PROBE_ROOTS)
  if (roots.length >= PROBE_ROOTS) return true
  const undo: Array<() => void> = []
  const lifted = new Set<Element>()
  const lift = (e: Element) => {
    const style = (e as HTMLElement).style as CSSStyleDeclaration | undefined
    if (lifted.has(e) || !style) return
    lifted.add(e)
    const before = e.getAttribute("style")
    style.setProperty("pointer-events", "auto", "important")
    style.setProperty("interactivity", "auto", "important")
    undo.push(() => (before === null ? e.removeAttribute("style") : e.setAttribute("style", before)))
  }
  const skip = (h: Element) => h === ours || (!!ours && ours.contains(h)) || isOwnHost(h)
  const stuck = (s: CSSStyleDeclaration) => s.pointerEvents === "none" || s.getPropertyValue("interactivity") === "inert"
  try {
    // The probe's rules, in a cascade layer declared before any of the
    // page's, first in each root. A page whose CSP refuses the style
    // element gets an adopted stylesheet instead, which a page's own
    // layered !important beats: then every pseudo-element is looked at too.
    let thorough = false
    for (const r of roots) {
      // A shadow root without styles of its own has nothing to beat the
      // document's rule its host inherits from (inline styles are lifted below).
      const styled = r === document || r.styleSheets.length > 0 || r.adoptedStyleSheets.length > 0
      const probe = document.createElement("style")
      probe.textContent = PROBE_CSS
      if (styled) {
        ;(r === document ? document.documentElement : r).prepend(probe)
        undo.push(() => probe.remove())
      }
      if (styled && !probe.sheet) {
        thorough = true
        if (typeof CSSStyleSheet === "undefined") return true
        if (!probeSheet) {
          probeSheet = new CSSStyleSheet()
          probeSheet.replaceSync(PROBE_CSS)
        }
        const sheet = probeSheet
        r.adoptedStyleSheets = [...r.adoptedStyleSheets, sheet]
        undo.push(() => (r.adoptedStyleSheets = r.adoptedStyleSheets.filter((s) => s !== sheet)))
      }
      for (const e of Array.from(r.querySelectorAll("[inert]"))) {
        const inert = e.getAttribute("inert")!
        e.removeAttribute("inert")
        undo.push(() => e.setAttribute("inert", inert))
      }
    }
    // One pass over every element: lift what's over the point and still
    // can't be hit (an inline !important, which beats any layer), and look
    // for paint that isn't hit-tested reaching it.
    const over: Element[] = []
    for (const r of roots) {
      for (const e of Array.from(r.querySelectorAll("*"))) {
        if (skip(e) || (e !== el && el.contains(e))) continue
        const style = getComputedStyle(e)
        const isStuck = stuck(style)
        if (!isStuck && !overflows(style) && !thorough) continue
        const rect = e.getBoundingClientRect()
        if (isStuck && within(rect, x, y)) {
          over.push(e)
          lift(e)
        }
        // The field's own outline counts as one over it; its shadows are outside it.
        const ancestor = holds(e, el)
        if (overflowPaintAt(style, rect, x, y, ancestor) && !faded(e, style)) return true
        if (thorough && !ancestor && ["::before", "::after"].some((p) => {
          const s = getComputedStyle(e, p)
          return stuck(s) && pseudoDraws(s)
        }) && !faded(e, style)) return true
      }
    }
    // Still none after all that (a transition holding it): covered if it draws.
    for (const e of over) if (e !== el && !holds(e, el) && stuck(getComputedStyle(e)) && paints(e, x, y)) return true
    // `stop` is the field, in the list of what's at the point in its own
    // root; null for the list inside a shadow host above it, of which only
    // that root's elements count (the rest are in the outer list).
    const above = (list: Element[], stop: Element | null, scope: Document | ShadowRoot): boolean => {
      for (const h of list) {
        if (h === stop) return false
        if ((!stop && h.getRootNode() !== scope) || skip(h) || el.contains(h)) continue
        if (holds(h, el)) {
          if (pseudoPaints(h)) return true
          if (behind(el, h)) {
            const s = getComputedStyle(h)
            if (!faded(h, s) && (opaqueStyle(s, { r: h.getBoundingClientRect(), x, y }) || textAt(h, x, y, s))) return true
          }
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
    for (const f of undo.reverse()) {
      try {
        f()
      } catch {}
    }
  }
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
