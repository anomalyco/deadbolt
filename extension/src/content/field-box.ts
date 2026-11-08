// The box a field is drawn in, which the inline menu and its pill are placed
// on. Usually that's the field itself. A floating-label field (Ramp's email:
// "Email address *" over a bare <input>) draws its frame on a wrapper around
// the label and the input, and the input is only the lower half of what the
// person sees as the field. The wrapper counts when it draws something
// (a border, a background or a shadow), holds no other control, and is
// little bigger than the field: its width and a label's worth of height.

/** How far up from the field a drawn box is looked for. */
const LEVELS = 5
/** Another control in a box makes it a form row, not the field's frame. */
const CONTROLS = "input:not([type=hidden]), select, textarea, button:not([type=button])"

/** Each field's drawn box, found once: placement reads it every frame. */
const boxes = new WeakMap<Element, Element>()

/** Whether `outer` holds `inner` and is no bigger than a field's frame and its label. */
function fits(outer: DOMRect, inner: DOMRect): boolean {
  if (inner.width <= 0 || inner.height <= 0) return false
  return outer.left <= inner.left + 1 && outer.right >= inner.right - 1 && outer.top <= inner.top + 1 && outer.bottom >= inner.bottom - 1 &&
    outer.width <= inner.width * 1.25 + 32 && outer.height <= inner.height * 2.5 + 24
}

/** Whether a color is painted at all: not `transparent` or alpha 0. */
function painted(color: string): boolean {
  if (!color || color === "transparent") return false
  const parts = /^rgba?\(([^)]*)\)$/.exec(color)?.[1].split(/[\s,/]+/).filter(Boolean) ?? []
  return parts.length < 4 || parseFloat(parts[3]) > 0
}

function bordered(style: CSSStyleDeclaration): boolean {
  return (["Top", "Right", "Bottom", "Left"] as const).some((side) =>
    parseFloat(style[`border${side}Width`]) > 0 && !["none", "hidden"].includes(style[`border${side}Style`]) && painted(style[`border${side}Color`]))
}

/** Whether `el` draws a frame the person sees: a border or a shadow, or (for a wrapper) a background. */
function draws(el: Element, wrapper: boolean): boolean {
  const style = getComputedStyle(el)
  return bordered(style) || (!!style.boxShadow && style.boxShadow !== "none") || (wrapper && painted(style.backgroundColor))
}

function find(field: Element, own: DOMRect): Element {
  if (draws(field, false)) return field
  let el = field.parentElement
  for (let level = 0; el && level < LEVELS; level++, el = el.parentElement) {
    if (!fits(el.getBoundingClientRect(), own)) break
    if (Array.from(el.querySelectorAll(CONTROLS)).some((c) => c !== field)) break
    if (draws(el, true)) return el
  }
  return field
}

/**
 * Where the field shows as the person sees it, in the viewport: its drawn
 * box (see above), else the field's own box. The box is found once per
 * field once it has a size; a box the page has since taken away or grown
 * past a field's frame gives way to the field's own.
 */
export function fieldRect(field: Element): DOMRect {
  const own = field.getBoundingClientRect()
  let box = boxes.get(field)
  if (!box || (box !== field && !(box.isConnected && box.contains(field)))) {
    if (own.width <= 0 || own.height <= 0) return own
    boxes.set(field, (box = find(field, own)))
  }
  if (box === field) return own
  const r = box.getBoundingClientRect()
  return fits(r, own) ? r : own
}
