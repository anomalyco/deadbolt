// A DOM for the detection tests. happy-dom does no layout, so boxes get a
// fixed size unless they, or an ancestor, are hidden.
import { GlobalRegistrator } from "@happy-dom/global-registrator"

GlobalRegistrator.register({ url: "https://example.com/login" })

function hidden(el: Element | null): boolean {
  for (let node = el; node; node = node.parentElement ?? ((node.getRootNode() as ShadowRoot).host ?? null)) {
    if (node.hasAttribute("hidden")) return true
    const style = getComputedStyle(node)
    if (style.display === "none" || style.visibility === "hidden") return true
  }
  return false
}

Element.prototype.getBoundingClientRect = function (this: Element) {
  const size = hidden(this) ? 0 : 1
  const width = 240 * size
  const height = 32 * size
  return { x: 0, y: 0, top: 0, left: 0, right: width, bottom: height, width, height, toJSON() {} } as DOMRect
}
