// A site's own SVG icon, cut down to shapes. The page writes this markup, so
// it's rebuilt from an allowlist into a fresh document, never kept as given:
// shapes, groups, gradients, clips and masks, with geometry and paint
// attributes only. No script, foreignObject, style, image, use, text, event
// handler or link; a paint or clip reference may only point inside the icon
// (`url(#id)`). The result is only ever drawn as an image (an <img> from a
// blob: URL, then a canvas; see ui/site-icon.ts), where it couldn't run
// anything anyway: this is the second wall, and it keeps stored icons small.

const SVG_NS = "http://www.w3.org/2000/svg"

/** The longest icon kept, as markup (before and after cleaning). */
export const MAX_SVG_BYTES = 32 * 1024
const MAX_NODES = 400

const ELEMENTS = new Set([
  "svg", "g", "path", "circle", "ellipse", "rect", "line", "polyline", "polygon",
  "defs", "lineargradient", "radialgradient", "stop", "clippath", "mask",
])

const ATTRIBUTES = new Set([
  "viewbox", "width", "height", "preserveaspectratio", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry", "fx", "fy",
  "d", "points", "transform", "opacity", "fill", "fill-rule", "fill-opacity", "clip-rule", "clip-path", "mask",
  "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-dasharray", "stroke-dashoffset", "stroke-opacity",
  "offset", "stop-color", "stop-opacity", "gradientunits", "gradienttransform", "spreadmethod",
  "clippathunits", "maskunits", "maskcontentunits", "id", "color",
])
/** Attributes that may hold a reference: only `url(#id)` to an element of the icon itself. */
const REFERENCES = new Set(["fill", "stroke", "clip-path", "mask"])

/** A value with nothing in it that reaches out: no url() but a local one, no scheme, no escapes. */
function safeValue(name: string, value: string): boolean {
  if (value.length > 8192 || /[\\<>]|&#|expression|javascript:|data:|@import/i.test(value)) return false
  // A local reference, with at most a plain colour after it as the fallback paint.
  if (/url\s*\(/i.test(value)) return REFERENCES.has(name) && /^\s*url\(\s*#[\w-]{1,64}\s*\)(?:\s+(?:none|currentColor|#[0-9a-f]{3,8}|[a-z]{3,20}))?\s*$/i.test(value)
  if (name === "id") return /^[\w-]{1,64}$/.test(value)
  // A colon would be a scheme: no attribute that's left needs one.
  return !value.includes(":")
}

/**
 * The icon in `markup`, rebuilt from the allowlist as standalone SVG markup,
 * or null if it isn't a well-formed SVG of reasonable size.
 */
export function sanitizeSvg(markup: string): string | null {
  if (typeof markup !== "string" || !markup || markup.length > MAX_SVG_BYTES) return null
  // A DOCTYPE can declare entities that expand into anything: none at all.
  if (/<!DOCTYPE|<!ENTITY/i.test(markup)) return null
  let parsed: Document
  try {
    parsed = new DOMParser().parseFromString(markup, "image/svg+xml")
  } catch {
    return null
  }
  const src = parsed.documentElement
  if (!src || src.localName !== "svg" || src.namespaceURI !== SVG_NS || parsed.getElementsByTagName("parsererror").length) return null
  // A fresh element, in no document's tree, that only the allowlist fills.
  const root = document.createElementNS(SVG_NS, "svg")
  root.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", SVG_NS)
  let nodes = 0
  const copy = (from: Element, to: Element) => {
    for (const attr of Array.from(from.attributes)) {
      const name = attr.name.toLowerCase()
      // Namespaced attributes (xlink:href, xml:base, …) and every on* handler are gone with the rest.
      if (attr.namespaceURI || name.includes(":") || !ATTRIBUTES.has(name)) continue
      const value = attr.value.trim()
      if (safeValue(name, value)) to.setAttribute(attr.localName, value)
    }
    for (const child of Array.from(from.children)) {
      if (++nodes > MAX_NODES) throw new Error("too many nodes")
      if (child.namespaceURI !== SVG_NS || !ELEMENTS.has(child.localName.toLowerCase()) || child.localName === "svg") continue
      const el = document.createElementNS(SVG_NS, child.localName)
      copy(child, el)
      to.append(el)
    }
  }
  try {
    copy(src, root)
  } catch {
    return null
  }
  if (!root.hasAttribute("viewBox")) {
    // Without a viewBox, the drawing's own size stands in for one.
    const w = parseFloat(root.getAttribute("width") ?? "")
    const h = parseFloat(root.getAttribute("height") ?? "")
    if (!(w > 0 && h > 0)) return null
    root.setAttribute("viewBox", `0 0 ${w} ${h}`)
  }
  if (!root.children.length) return null
  const out = new XMLSerializer().serializeToString(root)
  return out.length <= MAX_SVG_BYTES ? out : null
}
