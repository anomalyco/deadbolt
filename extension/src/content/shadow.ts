// Ported from Foyer (github.com/R44VC0RP/foyer, src/shadow.ts, by Ryan Vogel).
//
// Login forms built from web components live inside shadow roots, which
// document.querySelectorAll can't see. These helpers walk open shadow roots
// (closed ones are private by design and left alone).

const MAX_ROOTS = 200

/** The document plus every open shadow root under it, outermost first. */
export function openRoots(start: Document | ShadowRoot = document): Array<Document | ShadowRoot> {
  const roots: Array<Document | ShadowRoot> = [start]
  for (let i = 0; i < roots.length && roots.length < MAX_ROOTS; i++) {
    const walker = document.createTreeWalker(roots[i], NodeFilter.SHOW_ELEMENT)
    for (let node = walker.nextNode() as Element | null; node; node = walker.nextNode() as Element | null) {
      const root = node.shadowRoot
      if (root && root.mode === "open") roots.push(root)
      if (roots.length >= MAX_ROOTS) break
    }
  }
  return roots
}

/** querySelectorAll across the document and open shadow roots, in that order. */
export function deepQueryAll<E extends Element = Element>(selector: string, roots = openRoots()): E[] {
  return roots.flatMap((r) => Array.from(r.querySelectorAll<E>(selector)))
}

/** True when the page uses any open shadow roots (cheap pre-check). */
export function hasShadowRoots(): boolean {
  return openRoots().length > 1
}

/** The focused element, looking inside shadow roots (document.activeElement stops at the host). */
export function deepActiveElement(): Element | null {
  let el: Element | null = document.activeElement
  while (el?.shadowRoot?.activeElement) el = el.shadowRoot.activeElement
  return el
}
