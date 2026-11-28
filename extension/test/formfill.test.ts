import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { approveForms, fillCheck, fillForm, offScreen, takeApproved, type FormsState } from "../src/content/formfill"
import { scanForms } from "../src/content/forms"

// happy-dom does no layout: each element sits where its data-y says on a
// page 800 px tall in view, scrolled by "scrolled"; data-x, data-w and data-h
// move and size it. Hit testing finds the field drawn at a point. Its
// computed overflow is empty unless set, which counts as a clip: the forms
// here say visible.
let scrolled = 0
/** The options each scroll was asked with: scrollIntoView's, then the window's scrollTo. */
let scrolls: Array<ScrollIntoViewOptions | ScrollToOptions> = []
const saved = {
  rect: Element.prototype.getBoundingClientRect,
  into: Element.prototype.scrollIntoView,
  to: window.scrollTo,
  one: document.elementFromPoint,
  all: document.elementsFromPoint,
}
function box(el: Element): DOMRect {
  const n = (k: string, d: number) => (el.hasAttribute(k) ? Number(el.getAttribute(k)) : d)
  const y = n("data-y", 0) - scrolled
  const x = n("data-x", 0)
  const width = n("data-w", 240)
  const height = n("data-h", 32)
  return { x, y, left: x, top: y, right: x + width, bottom: y + height, width, height, toJSON() {} } as DOMRect
}
const at = (x: number, y: number) =>
  Array.from(document.querySelectorAll("input, select")).find((el) => {
    const r = el.getBoundingClientRect()
    return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom
  }) ?? null
beforeAll(() => {
  Object.defineProperty(window, "innerHeight", { value: 800, configurable: true })
  Object.defineProperty(window, "innerWidth", { value: 1000, configurable: true })
  Object.defineProperty(window, "scrollY", { get: () => scrolled, configurable: true })
  Object.defineProperty(window, "scrollX", { get: () => 0, configurable: true })
  Element.prototype.getBoundingClientRect = function (this: Element) {
    const placed = this.closest("[data-y]")
    return placed ? box(placed) : saved.rect.call(this)
  }
  Element.prototype.scrollIntoView = function (this: Element, options?: boolean | ScrollIntoViewOptions) {
    if (typeof options === "object") scrolls.push(options)
    scrolled = Math.max(0, Number(this.closest("[data-y]")?.getAttribute("data-y") ?? 0) - 400)
  }
  window.scrollTo = ((options: ScrollToOptions | number, y?: number) => {
    if (typeof options === "object") {
      scrolls.push(options)
      scrolled = options.top ?? scrolled
    } else scrolled = y ?? scrolled
  }) as typeof window.scrollTo
  document.elementFromPoint = ((x: number, y: number) => at(x, y)) as typeof document.elementFromPoint
  document.elementsFromPoint = ((x: number, y: number) => [at(x, y)].filter((h) => !!h)) as typeof document.elementsFromPoint
})
afterAll(() => {
  Object.assign(Element.prototype, { getBoundingClientRect: saved.rect, scrollIntoView: saved.into })
  Object.assign(window, { scrollTo: saved.to })
  Object.assign(document, { elementFromPoint: saved.one, elementsFromPoint: saved.all })
})

/** A checkout whose name shows, its address below the fold, and beside it every way of hiding a field. */
function checkout() {
  scrolled = 0
  scrolls = []
  for (const el of [document.documentElement, document.body]) el.removeAttribute("style")
  document.body.innerHTML = `<form id="ship" style="overflow-x:visible;overflow-y:visible">
    <label for="name">Full name</label><input id="name" autocomplete="shipping name" data-y="700">
    <label for="line1">Address</label><input id="line1" autocomplete="shipping address-line1" data-y="1200">
    <label for="city">City</label><input id="city" autocomplete="shipping address-level2" data-y="1300">
    <label for="zip">ZIP</label><input id="zip" autocomplete="shipping postal-code" data-y="1400">
    <input id="t-opacity" autocomplete="shipping address-line2" data-y="1500" style="opacity:0">
    <input id="t-tab" autocomplete="shipping address-line2" data-y="1500" tabindex="-1">
    <div inert style="overflow-x:visible;overflow-y:visible"><input id="t-inert" autocomplete="shipping address-line2" data-y="1500"></div>
    <div aria-hidden="true" style="overflow-x:visible;overflow-y:visible"><input id="t-aria" autocomplete="shipping address-line2" data-y="1500"></div>
    <input id="t-side" autocomplete="shipping address-line2" data-y="1500" data-x="-9999">
    <input id="t-tiny" autocomplete="shipping address-line2" data-y="1500" data-w="1" data-h="1">
    <input id="t-clip" autocomplete="shipping address-line2" data-y="1500" style="clip-path:inset(50%)">
    <div style="overflow:scroll" data-y="1500" data-w="12" data-h="12"><input id="t-box" autocomplete="shipping address-line2" data-y="1500"></div>
  </form><form id="other" style="overflow-x:visible;overflow-y:visible"><input id="foreign" autocomplete="shipping address-line1" data-y="1600"></form>`
}
const $ = (id: string) => document.getElementById(id) as HTMLInputElement
const TRAPS = ["t-opacity", "t-tab", "t-inert", "t-aria", "t-side", "t-tiny", "t-clip", "t-box"]

describe("offScreen", () => {
  test("a field of the same form, below the fold, may be scrolled to", () => {
    checkout()
    expect(offScreen($("line1"), $("name"))).toBe(true)
    expect(offScreen($("zip"), $("name"))).toBe(true)
  })

  test("never a concealed one, nor one in another form", () => {
    checkout()
    for (const id of TRAPS) expect([id, offScreen($(id), $("name"))]).toEqual([id, false])
    expect(offScreen($("foreign"), $("name"))).toBe(false)
    expect(offScreen($("foreign"))).toBe(true)
    $("line1").disabled = true
    expect(offScreen($("line1"), $("name"))).toBe(false)
  })

  test("not on a page whose root won't scroll: a field below the fold there is out of the user's reach", () => {
    for (const style of ["overflow-y:hidden", "overflow-y:clip"]) {
      checkout()
      document.documentElement.setAttribute("style", style)
      expect(offScreen($("line1"), $("name"))).toBe(false)
      checkout()
      document.body.setAttribute("style", style)
      expect(offScreen($("line1"), $("name"))).toBe(false)
    }
    // A body that scrolls on its own inside a root that does: the body's box clips.
    checkout()
    document.documentElement.setAttribute("style", "overflow-y:auto")
    document.body.setAttribute("style", "overflow-y:auto")
    document.body.setAttribute("data-y", "0")
    document.body.setAttribute("data-h", "800")
    try {
      expect(offScreen($("line1"), $("name"))).toBe(false)
    } finally {
      document.body.removeAttribute("data-y")
      document.body.removeAttribute("data-h")
    }
  })

  test("a field outside any form is never reached", () => {
    scrolled = 0
    document.body.innerHTML = `<input id="name" autocomplete="name" data-y="100"><input id="city" autocomplete="address-level2" data-y="1200">`
    expect(offScreen($("city"), $("name"))).toBe(false)
  })
})

describe("an identity pick on a tall checkout", () => {
  const values = { "given-name": "Alex", "family-name": "Mercer", "address-line1": "123 Main St", "address-line2": "Apt 4", city: "Brooklyn", "postal-code": "11201" }
  const state = (): FormsState => ({ fields: () => scanForms(), form: () => 1, rescan() {} })
  const section = () => scanForms().find((f) => f.el.id === "name")!.section

  test("approves the form's fields below the fold, not the traps or another form's", async () => {
    checkout()
    const approved = await approveForms(state(), 1, "identity", section(), false)
    expect(approved?.roles.sort()).toEqual(["address-level2", "address-line1", "name", "postal-code"])
  })

  test("fills each one scrolled into view, writes 0 bytes to every trap, and puts the page back", async () => {
    checkout()
    const s = state()
    const approved = (await approveForms(s, 1, "identity", section(), false))!
    const targets = takeApproved(s, approved.approval, 1)!
    const { filled } = await fillForm(targets, values, (el) => fillCheck("identity")(el), (el) => offScreen(el))
    expect(filled.sort()).toEqual(["address-level2", "address-line1", "name", "postal-code"])
    expect(["name", "line1", "city", "zip"].map((id) => $(id).value)).toEqual(["Alex Mercer", "123 Main St", "Brooklyn", "11201"])
    for (const id of [...TRAPS, "foreign"]) expect([id, $(id).value]).toEqual([id, ""])
    expect(scrolled).toBe(0)
    // Instant both ways, whatever the page's scroll-behavior: each field is checked right after it's brought into view.
    expect(scrolls.length).toBeGreaterThan(1)
    expect(scrolls.every((o) => o.behavior === "instant")).toBe(true)
  })

  test("a root with overflow hidden: nothing below the fold is scrolled to or filled", async () => {
    checkout()
    document.documentElement.setAttribute("style", "overflow-y:hidden")
    const s = state()
    const approved = (await approveForms(s, 1, "identity", section(), false))!
    expect(approved.roles).toEqual(["name"])
    const targets = takeApproved(s, approved.approval, 1)!
    const { filled } = await fillForm(targets, values, (el) => fillCheck("identity")(el), (el) => offScreen(el))
    expect(filled).toEqual(["name"])
    expect(["line1", "city", "zip"].map((id) => $(id).value)).toEqual(["", "", ""])
    expect(scrolls).toEqual([])
  })

  test("without reach, only what shows fills, as before", async () => {
    checkout()
    const fields = scanForms().filter((f) => f.el.form?.id === "ship")
    const { filled } = await fillForm(fields, values, (el) => fillCheck("identity")(el))
    expect(filled).toEqual(["name"])
    expect(scrolled).toBe(0)
  })

  test("a field still covered once scrolled to gets nothing", async () => {
    checkout()
    const fields = scanForms().filter((f) => ["name", "line1"].includes(f.el.id))
    const one = document.elementFromPoint
    document.elementFromPoint = ((x: number, y: number) => (at(x, y)?.id === "line1" ? document.body : at(x, y))) as typeof document.elementFromPoint
    try {
      const { filled } = await fillForm(fields, values, (el) => fillCheck("identity")(el), (el) => offScreen(el))
      expect(filled).toEqual(["name"])
      expect($("line1").value).toBe("")
      expect(scrolled).toBe(0)
    } finally {
      document.elementFromPoint = one
    }
  })
})
