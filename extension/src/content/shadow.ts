// Ported from Foyer (github.com/R44VC0RP/foyer, src/shadow.ts, by Ryan Vogel).
//
// Login forms built from web components live inside shadow roots, which
// document.querySelectorAll can't see. These helpers walk them: open roots,
// and closed ones too, which a content script may open
// (chrome.dom.openOrClosedShadowRoot); openRoots returns both. A closed root hides a form from other
// scripts of the page, not from the person looking at it, and every fill
// still checks the field is shown through every host up the tree. Deadbolt's
// own closed roots (its menu and rings) are left out.

const MAX_ROOTS = 200

/** Hosts of Deadbolt's own closed roots, never walked. */
const own = new WeakSet<Element>()

/** Marks a host whose shadow root is Deadbolt's own. */
export function markOwnHost(host: Element) {
  own.add(host)
}

/** Whether the element hosts one of Deadbolt's own closed roots. */
export function isOwnHost(el: Element): boolean {
  return own.has(el)
}

/** The element's shadow root, open or closed, unless it's Deadbolt's own. */
export function shadowRootOf(el: Element): ShadowRoot | null {
  if (own.has(el)) return null
  if (el.shadowRoot) return el.shadowRoot
  const dom = (globalThis as { chrome?: { dom?: { openOrClosedShadowRoot?: (e: HTMLElement) => ShadowRoot | null } } }).chrome?.dom
  try {
    return el instanceof HTMLElement ? (dom?.openOrClosedShadowRoot?.(el) ?? null) : null
  } catch {
    return null
  }
}

/**
 * The only HTML elements attachShadow accepts today (DOM spec, "valid shadow
 * host name"), besides custom elements, whose names all have a hyphen.
 */
const HOSTS = new Set(["article", "aside", "blockquote", "body", "div", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "main", "nav", "p", "section", "span"])

/**
 * The document plus every shadow root under it, open and closed (despite the
 * name), outermost first. Closed roots include those other extensions put in
 * the page; at most `max` (MAX_ROOTS) are walked, whoever made them.
 * `discovery` skips asking for a closed root on elements outside HOSTS, the
 * extension call that is most of a walk's cost: for finding forms only,
 * where a root missed (on a host a later spec allows) means a form not
 * offered. Checks of what a fill may write (fill.ts) walk every element.
 */
export function openRoots(start: Document | ShadowRoot = document, max = MAX_ROOTS, discovery = false): Array<Document | ShadowRoot> {
  const roots: Array<Document | ShadowRoot> = [start]
  for (let i = 0; i < roots.length && roots.length < max; i++) {
    const walker = document.createTreeWalker(roots[i], NodeFilter.SHOW_ELEMENT)
    for (let node = walker.nextNode() as Element | null; node; node = walker.nextNode() as Element | null) {
      const root = discovery && !node.shadowRoot && !HOSTS.has(node.localName) && !node.localName.includes("-") ? null : shadowRootOf(node)
      if (root) roots.push(root)
      if (roots.length >= max) break
    }
  }
  return roots
}

/** querySelectorAll across the document and its shadow roots, in that order. */
export function deepQueryAll<E extends Element = Element>(selector: string, roots = openRoots()): E[] {
  return roots.flatMap((r) => Array.from(r.querySelectorAll<E>(selector)))
}

/** True when the page uses any shadow roots (cheap pre-check). */
export function hasShadowRoots(): boolean {
  return openRoots().length > 1
}

/** The focused element, looking inside shadow roots (document.activeElement stops at the host). */
export function deepActiveElement(): Element | null {
  let el: Element | null = document.activeElement
  for (let root = el && shadowRootOf(el); root?.activeElement; root = shadowRootOf(el!)) el = root.activeElement
  return el
}

/** A pointer event that has a real position: not a click the keyboard made (Enter or Space on a button), whose clientX/Y are 0. */
const positioned = (event: Event): event is MouseEvent =>
  event instanceof MouseEvent && (event.detail > 0 || (typeof PointerEvent !== "undefined" && event instanceof PointerEvent && event.pointerType !== ""))

/**
 * What an event is about, inside closed shadow roots too: for a listener
 * outside one, composedPath() stops at the closed root's host. Focus, key
 * and input events, and clicks the keyboard made, go on to the element
 * focused inside it; pointer events to the element under the pointer. Only
 * an element of that same root counts, so a point that lands elsewhere
 * leaves the host as the target.
 */
export function eventTarget(event: Event): EventTarget | null {
  let el: EventTarget | null = event.composedPath()[0] ?? event.target
  for (let depth = 0; depth < 32 && el instanceof Element; depth++) {
    const root = shadowRootOf(el)
    if (!root) break
    const inner = positioned(event) ? root.elementFromPoint(event.clientX, event.clientY) : root.activeElement
    if (!inner || inner === el || inner.getRootNode() !== root) break
    el = inner
  }
  return el
}
