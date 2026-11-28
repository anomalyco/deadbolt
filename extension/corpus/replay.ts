// Loads a frozen corpus page (freeze.ts) into the global happy-dom window the
// detector runs in, for score.ts: no scripts, no network, and the layout
// Chromium measured when the page was frozen (data-db-box) in place of
// happy-dom's, which has none: getBoundingClientRect gives its box and
// checkVisibility its vis. The detector itself reads only the box and the
// inline styles freeze.ts kept, as it reads a live page's, so a trap it would
// claim live (Google's hiddenPassword: a 20 px box inside a 1 px parent) it
// claims here too. Shadow roots come back from their
// <template shadowrootmode> markup, closed ones as closed roots the detector
// reaches the way the extension does (chrome.dom.openOrClosedShadowRoot).
// Frames stay empty: each frozen page is one document.

import { GlobalRegistrator } from "@happy-dom/global-registrator"

/** "x,y,w,h,vis" in CSS pixels at a 1280×800 viewport; vis is Chromium's checkVisibility() (1 or 0). */
export const BOX = "data-db-box"
/** On a shadow host: "closed" when the page made its root closed. */
export const SHADOW = "data-db-shadow"
/** The size a control with no box of its own gets (an unmeasured page, or one written by hand). */
const DEFAULT_BOX = { x: 0, y: 0, w: 240, h: 32 }

const closedRoots = new WeakMap<Element, ShadowRoot>()
let ready = false

export interface Box {
  x: number
  y: number
  w: number
  h: number
  vis: boolean
}

export function parseBox(value: string | null): Box | null {
  if (!value) return null
  const [x, y, w, h, vis] = value.split(",").map(Number)
  if (![x, y, w, h].every(Number.isFinite)) return null
  return { x, y, w, h, vis: vis !== 0 }
}

function hiddenUp(el: Element): boolean {
  for (let node: Element | null = el; node; node = node.parentElement ?? ((node.getRootNode() as ShadowRoot).host ?? null)) {
    if (node.hasAttribute("hidden")) return true
    const style = getComputedStyle(node)
    if (style.display === "none" || style.visibility === "hidden") return true
  }
  return false
}

function rect(x: number, y: number, w: number, h: number): DOMRect {
  return { x, y, top: y, left: x, right: x + w, bottom: y + h, width: w, height: h, toJSON() {} } as DOMRect
}

/** Sets up the global window once. Every request it would make fails: the corpus never touches the network. */
export function register() {
  if (ready) return
  ready = true
  GlobalRegistrator.register({
    url: "https://corpus.invalid/",
    width: 1280,
    height: 800,
    settings: {
      disableJavaScriptEvaluation: true,
      disableJavaScriptFileLoading: true,
      disableCSSFileLoading: true,
      disableIframePageLoading: true,
      handleDisabledFileLoadingAsSuccess: true,
      navigation: { disableMainFrameNavigation: true, disableChildFrameNavigation: true, disableChildPageNavigation: true, disableFallbackToSetURL: true },
    },
  })
  globalThis.fetch = (() => Promise.reject(new Error("the corpus never touches the network"))) as unknown as typeof fetch
  ;(globalThis as { chrome?: unknown }).chrome = { dom: { openOrClosedShadowRoot: (el: HTMLElement) => el.shadowRoot ?? closedRoots.get(el) ?? null } }
  // Chromium's own verdict on whether the box is drawn, for code that asks it.
  Element.prototype.checkVisibility = function (this: Element) {
    const box = parseBox(this.getAttribute(BOX))
    return box ? box.vis && !hiddenUp(this) : !hiddenUp(this)
  }
  Element.prototype.getBoundingClientRect = function (this: Element) {
    const box = parseBox(this.getAttribute(BOX))
    if (box) return rect(box.x, box.y, box.w, box.h)
    if (hiddenUp(this)) return rect(0, 0, 0, 0)
    return rect(DEFAULT_BOX.x, DEFAULT_BOX.y, DEFAULT_BOX.w, DEFAULT_BOX.h)
  }
}

/** Turns each <template shadowrootmode> into the shadow root it stands for, innermost last. */
function attachTemplates(root: ParentNode) {
  for (const t of Array.from(root.querySelectorAll<HTMLTemplateElement>("template[shadowrootmode]"))) {
    const host = t.parentElement
    if (!host || host.shadowRoot || closedRoots.has(host)) continue
    const mode = t.getAttribute("shadowrootmode") === "closed" || host.getAttribute(SHADOW) === "closed" ? "closed" : "open"
    const shadow = host.attachShadow({ mode })
    shadow.innerHTML = t.innerHTML
    t.remove()
    if (mode === "closed") closedRoots.set(host, shadow)
    attachTemplates(shadow)
  }
}

/** Replaces the window's document with a frozen page, at the URL it was frozen from. */
export function load(html: string, url: string) {
  register()
  // A frame is kept as an element of its own name: happy-dom would try to
  // load even an empty <iframe>. Its source is in data-db-src (freeze.ts).
  html = html.replace(/<(\/?)iframe\b/gi, "<$1db-frame")
  ;(window as unknown as { happyDOM: { setURL(u: string): void } }).happyDOM.setURL(url)
  const head = /<head[^>]*>([\s\S]*?)<\/head>/i.exec(html)?.[1] ?? ""
  const body = /<body[^>]*>([\s\S]*)<\/body>/i.exec(html)?.[1] ?? html
  document.head.innerHTML = head
  document.body.innerHTML = body
  for (const attr of Array.from(document.body.attributes)) document.body.removeAttribute(attr.name)
  const bodyAttrs = /<body([^>]*)>/i.exec(html)?.[1] ?? ""
  for (const [, name, value] of bodyAttrs.matchAll(/([\w:-]+)(?:="([^"]*)")?/g)) document.body.setAttribute(name, value ?? "")
  attachTemplates(document)
}

/** A stable name for a control, the same in gold labels and predictions: "#id", or tag[name=…], or tag@n; a shadow root's controls are prefixed with their host's. */
export function controlKey(el: Element): string {
  const root = el.getRootNode()
  const prefix = root instanceof ShadowRoot ? `${controlKey(root.host)} >> ` : ""
  const tag = el.localName
  if (el.id) return `${prefix}#${el.id}`
  const name = el.getAttribute("name")
  const scope = root as Document | ShadowRoot
  if (name && Array.from(scope.querySelectorAll(tag)).filter((o) => o.getAttribute("name") === name).length === 1) return `${prefix}${tag}[name="${name}"]`
  return `${prefix}${tag}@${Array.from(scope.querySelectorAll(tag)).indexOf(el)}`
}
