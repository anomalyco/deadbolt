// One pass over the page's form controls, shared by login detection
// (detect.ts) and identity and payment detection (forms.ts): the document
// and its shadow roots are walked once, each control's box, style and label
// are read once, and the controls are split into clusters, the forms they
// belong to. Every judgement about a control's neighbours (a code split into
// one box per digit, a password after a username, a decoy's wording) is made
// within its cluster, so two forms on one page never mix.
//
// A cluster is the control's <form> when that holds at most MAX_FORM
// controls; else (no form, or a page-sized one) the nearest section-like
// container around it (a dialog, main, section, article, aside, header or
// footer); else the page. Nothing here keeps a value: the fingerprint is the
// controls' shapes only.

import { words } from "./clues"
import { deepQueryAll, openRoots } from "./shadow"

/** An input, select or textarea: what identity and payment forms are made of. */
export type FormControl = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement

/** A <form> with more controls than this is a page wrapped in a form (ASP.NET's), not one form. */
const MAX_FORM = 50
/** Controls read per scan: a page with more is mostly a table of them. */
const MAX_CONTROLS = 300
/** Inputs that hold no text to fill, never a control here. */
const NOT_TEXT = new Set(["hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file", "range", "color"])
/** Containers that bound a cluster of controls outside any <form>. */
const CONTAINER = "dialog, [role=dialog], [role=alertdialog], main, [role=main], section, article, aside, header, footer, [role=form], [role=search]"
const HEADING = "h1, h2, h3, h4, legend, [role=heading]"
const LABELABLE = "button, input:not([type=hidden]), meter, output, progress, select, textarea"

/**
 * Marks sites put on fields, forms or <body> to keep password managers away:
 * 1Password's, LastPass's, Bitwarden's, Dashlane's and Deadbolt's own.
 */
export function optedOut(el: Element | null | undefined): boolean {
  if (!el) return false
  const on = (name: string) => el.hasAttribute(name) && el.getAttribute(name)?.toLowerCase() !== "false"
  return (
    on("data-1p-ignore") ||
    on("data-op-ignore") ||
    on("data-bwignore") ||
    on("data-deadbolt-ignore") ||
    el.getAttribute("data-lpignore")?.toLowerCase() === "true" ||
    el.getAttribute("data-form-type")?.toLowerCase() === "other"
  )
}

/** The site asked password managers to leave this field alone, on it, its form or the page. */
export const ignored = (el: FormControl) => optedOut(el) || optedOut(el.form ?? el.closest("form")) || optedOut(document.body)

const shown = (rect: DOMRect, style: () => CSSStyleDeclaration) => {
  if (rect.width < 2 || rect.height < 2) return false
  const s = style()
  return s.visibility !== "hidden" && s.display !== "none" && Number(s.opacity || 1) > 0.05
}

export const isVisible = (el: Element): boolean => shown(el.getBoundingClientRect(), () => getComputedStyle(el))

/**
 * A box drawn on the page that no one is meant to reach: inside an inert
 * subtree, or hidden from assistive tech (aria-hidden) and either out of the
 * tab order or faded out between it and that ancestor. Google's
 * hiddenPassword, Apple's and Clerk's collapsed password boxes: a bot fills
 * them, a person never does.
 */
export function concealed(el: Element, style: (el: Element) => CSSStyleDeclaration = getComputedStyle): boolean {
  if (composedClosest(el, "[inert]")) return true
  const hidden = composedClosest(el, '[aria-hidden="true"]')
  if (!hidden) return false
  if ((el as HTMLElement).tabIndex < 0) return true
  for (let node: Element | null = el; node; node = composedParent(node)) {
    if (Number(style(node).opacity || 1) <= 0.05) return true
    if (node === hidden) break
  }
  return false
}

export const innerText = (el: Element | null | undefined) => ((el as HTMLElement | null)?.innerText ?? el?.textContent ?? "").trim()

/** Closest preceding text when a field has no <label>, e.g. a <span> above it. */
function nearbyText(el: Element): string {
  let node: Element | null = el
  for (let depth = 0; node && depth < 3; depth++) {
    let sibling = node.previousElementSibling
    for (let i = 0; sibling && i < 2; i++, sibling = sibling.previousElementSibling) {
      if (sibling.matches("input, select, textarea") || sibling.querySelector("input, select, textarea")) return ""
      const text = innerText(sibling)
      if (text) return text.length <= 80 ? text : ""
    }
    node = node.parentElement
  }
  return ""
}

/** A field's labels, aria label, placeholder and title, or the text just before it. */
export function labelText(el: FormControl, labels: ArrayLike<HTMLLabelElement> = el.labels ?? []): string {
  const parts: string[] = []
  for (const label of Array.from(labels)) parts.push(innerText(label))
  const labelledBy = el.getAttribute("aria-labelledby")
  const root = el.getRootNode() as Document | ShadowRoot
  if (labelledBy) for (const id of labelledBy.split(/\s+/)) parts.push(innerText(root.getElementById?.(id)))
  const placeholder = el.getAttribute("placeholder") ?? ""
  parts.push(el.getAttribute("aria-label") ?? "", placeholder, el.getAttribute("title") ?? "")
  if (!parts.some(Boolean)) parts.push(nearbyText(el))
  // "you@example.com" as a placeholder means an email box.
  if (placeholder.includes("@")) parts.push("email")
  return parts.filter(Boolean).join(" ").slice(0, 300)
}

/** The element's parent, or its shadow root's host. */
const composedParent = (el: Element): Element | null => el.parentElement ?? ((el.getRootNode() as ShadowRoot).host ?? null)

/** The nearest element around `el` matching `selector`, through shadow hosts. */
function composedClosest(el: Element, selector: string): Element | null {
  for (let node: Element | null = el; node; ) {
    const found = node.closest(selector)
    if (found) return found
    const root = node.getRootNode()
    node = root instanceof ShadowRoot ? root.host : null
  }
  return null
}

/** Whether `el` is `root` or inside it, through shadow hosts. */
export function within(root: Element, el: Element): boolean {
  for (let node: Element | null = el; node; ) {
    if (root.contains(node)) return true
    const r = node.getRootNode()
    node = r instanceof ShadowRoot ? r.host : null
  }
  return false
}

/** FNV-1a, 32 bits, as hex: the fingerprint of a cluster's shape. */
function fnv(text: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 0x01000193)
  return (h >>> 0).toString(16).padStart(8, "0")
}

/** What a control is, without its value or label: its tag, type, autocomplete and length. */
function shape(el: FormControl): string {
  const type = el instanceof HTMLInputElement ? (el.getAttribute("type") || "text").toLowerCase() : el.localName
  const max = el instanceof HTMLInputElement && el.maxLength > 0 ? el.maxLength : ""
  return `${type}/${(el.getAttribute("autocomplete") || "").toLowerCase().trim()}/${max}`
}

export interface FormCluster {
  /** Its place in the scan's list, stable for one scan. */
  id: number
  /** The <form>, or the container around the controls; null for controls in neither (the page). */
  root: Element | null
  /** The <form> it is, if it is one. */
  form: HTMLFormElement | null
  /** Its controls, in page order. */
  controls: FormControl[]
  /** A value-free hash of the controls' shapes, in order: the same form scans to the same one. */
  fingerprint: string
}

export interface FormGraph {
  roots: Array<Document | ShadowRoot>
  /** Every text-like control that's drawn, reachable and not opted out, in page order. */
  controls: FormControl[]
  clusters: FormCluster[]
  clusterOf(el: Element): FormCluster | undefined
  /** labelText, from labels collected once per root. */
  label(el: FormControl): string
  /** isVisible, read once per element per scan. */
  visible(el: Element): boolean
  /** The element's computed style, read once per scan. */
  style(el: Element): CSSStyleDeclaration
  /** words() of the cluster's own text and the heading just above it (empty for the page). */
  context(cluster: FormCluster | undefined): string
}

/** `<label for>` elements by the id they name, in one root. */
function labelMap(root: Document | ShadowRoot): Map<string, HTMLLabelElement[]> {
  const map = new Map<string, HTMLLabelElement[]>()
  for (const label of Array.from(root.querySelectorAll<HTMLLabelElement>("label[for]"))) {
    const list = map.get(label.htmlFor)
    if (list) list.push(label)
    else map.set(label.htmlFor, [label])
  }
  return map
}

/** The heading that names a container: its own first one, else one just before it, a few levels up. */
function headingFor(root: Element): string {
  const own = root.querySelector(HEADING)
  if (own) return innerText(own)
  let node: Element | null = root
  for (let depth = 0; node && depth < 3; depth++, node = node.parentElement) {
    let sibling = node.previousElementSibling
    for (let i = 0; sibling && i < 3; i++, sibling = sibling.previousElementSibling) {
      if (sibling.matches(HEADING)) return innerText(sibling)
      if (sibling.matches("input, select, textarea, form") || sibling.querySelector("input, select, textarea")) return ""
    }
  }
  return ""
}

/** A select's options are a list of countries or months, not what the form says; the rest never show as text. */
const SKIP_TEXT = new Set(["script", "style", "noscript", "template", "svg", "option", "optgroup", "datalist"])
/** Elements read per cluster's text: a page of empty wrappers costs a style read each. */
const MAX_TEXT_NODES = 1500

/**
 * An element's text with a space at every element edge, hidden subtrees left
 * out: innerText runs inline elements together ("Code" in a label and
 * "Verify" on the button after it read "codeverify"), and a page rendered
 * without whitespace between tags (React's) is all inline edges.
 */
function spacedText(root: Element, style: (el: Element) => CSSStyleDeclaration, max: number): string {
  const parts: string[] = []
  let length = 0
  let nodes = 0
  const walk = (node: Node) => {
    for (let child = node.firstChild; child && length < max && nodes < MAX_TEXT_NODES; child = child.nextSibling) {
      nodes++
      if (child.nodeType === Node.TEXT_NODE) {
        const text = child.nodeValue ?? ""
        if (text.trim()) {
          parts.push(text)
          length += text.length + 1
        }
      } else if (child.nodeType === Node.ELEMENT_NODE) {
        const el = child as Element
        if (SKIP_TEXT.has(el.localName) || el.hasAttribute("hidden")) continue
        const s = style(el)
        if (s.display !== "none" && s.visibility !== "hidden") walk(el)
      }
    }
  }
  walk(root)
  return parts.join(" ").slice(0, max)
}

/** Walks the page once and splits its controls into clusters. */
export function scanGraph(roots: Array<Document | ShadowRoot> = openRoots()): FormGraph {
  const labels = new Map<Document | ShadowRoot, Map<string, HTMLLabelElement[]>>()
  const visibleCache = new Map<Element, boolean>()
  const styleCache = new Map<Element, CSSStyleDeclaration>()
  const labelCache = new Map<FormControl, string>()
  const contextCache = new Map<FormCluster, string>()
  const formOptedOut = new Map<HTMLFormElement, boolean>()

  const style = (el: Element) => {
    let s = styleCache.get(el)
    if (!s) styleCache.set(el, (s = getComputedStyle(el)))
    return s
  }
  const visible = (el: Element) => {
    let v = visibleCache.get(el)
    if (v === undefined) visibleCache.set(el, (v = shown(el.getBoundingClientRect(), () => style(el))))
    return v
  }
  // A box in a web component inside a <form> is the form's, though the DOM doesn't associate it.
  const formOf = (el: FormControl) => el.form ?? (composedClosest(el, "form") as HTMLFormElement | null)
  const skipped = (el: FormControl) => {
    if (optedOut(el)) return true
    const form = formOf(el)
    if (!form) return false
    let out = formOptedOut.get(form)
    if (out === undefined) formOptedOut.set(form, (out = optedOut(form)))
    return out
  }

  const controls: FormControl[] = []
  if (!optedOut(document.body))
    for (const el of deepQueryAll<FormControl>("input, select, textarea", roots).slice(0, MAX_CONTROLS)) {
      if (el instanceof HTMLInputElement && NOT_TEXT.has((el.getAttribute("type") || "text").toLowerCase())) continue
      if (!visible(el) || skipped(el) || concealed(el, style)) continue
      controls.push(el)
    }

  // Each control's cluster: its form, unless that's page-sized; else its container; else the page.
  const perForm = new Map<HTMLFormElement, number>()
  for (const el of controls) {
    const form = formOf(el)
    if (form) perForm.set(form, (perForm.get(form) ?? 0) + 1)
  }
  const byRoot = new Map<Element | null, FormCluster>()
  const clusters: FormCluster[] = []
  const of = new Map<Element, FormCluster>()
  for (const el of controls) {
    const form = formOf(el)
    const small = form && perForm.get(form)! <= MAX_FORM ? form : null
    const root = small ?? composedClosest(el, CONTAINER)
    let cluster = byRoot.get(root)
    if (!cluster) {
      cluster = { id: clusters.length, root, form: small, controls: [], fingerprint: "" }
      byRoot.set(root, cluster)
      clusters.push(cluster)
    }
    cluster.controls.push(el)
    of.set(el, cluster)
  }
  for (const c of clusters) c.fingerprint = fnv(`${c.root?.localName ?? "page"}|${c.controls.map(shape).join(",")}`)

  return {
    roots,
    controls,
    clusters,
    clusterOf: (el) => of.get(el),
    visible,
    style,
    label(el) {
      let text = labelCache.get(el)
      if (text !== undefined) return text
      const root = el.getRootNode() as Document | ShadowRoot
      let map = labels.get(root)
      if (!map) labels.set(root, (map = labelMap(root)))
      const own = el.id ? (map.get(el.id) ?? []) : []
      // A <label> around the field with no for= labels its first labelable control.
      const wrap = el.closest("label")
      const found = wrap && !wrap.htmlFor && wrap.querySelector(LABELABLE) === el ? [wrap, ...own] : own
      labelCache.set(el, (text = labelText(el, found)))
      return text
    },
    context(cluster) {
      if (!cluster?.root) return ""
      let text = contextCache.get(cluster)
      if (text === undefined) contextCache.set(cluster, (text = words(`${headingFor(cluster.root)} \n ${spacedText(cluster.root, style, 2000)}`)))
      return text
    },
  }
}

/** A graph, or the roots to build one from: what scanPage and scanForms take. */
export type ScanSource = FormGraph | Array<Document | ShadowRoot>
export const graphOf = (source: ScanSource = openRoots()): FormGraph => (Array.isArray(source) ? scanGraph(source) : source)
