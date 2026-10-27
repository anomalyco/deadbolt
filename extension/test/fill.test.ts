import { describe, expect, test } from "bun:test"
import { fillable, fillFields, hiddenByStyle, ownValue, renderedParent, setInputValue, trackUserInput, visibleBox } from "../src/content/fill"
import { ownerOf, type Field } from "../src/content/detect"

function input(): HTMLInputElement {
  document.body.innerHTML = `<input type="password">`
  return document.querySelector("input")!
}

describe("ownValue", () => {
  test("a value a page script set isn't the user's", async () => {
    const el = input()
    el.value = "guess"
    expect(await ownValue(el, el.value)).toBeUndefined()
  })

  test("a value Deadbolt filled is", async () => {
    const el = input()
    setInputValue(el, "correct horse")
    expect(await ownValue(el, el.value)).toBe("correct horse")
  })

  test("a page changing a filled value afterwards loses it", async () => {
    const el = input()
    setInputValue(el, "correct horse")
    el.value = "guess"
    expect(await ownValue(el, el.value)).toBeUndefined()
  })

  test("untrusted input events don't count", async () => {
    const el = input()
    el.value = "guess"
    const event = new Event("input", { bubbles: true, composed: true })
    el.addEventListener("input", trackUserInput)
    el.dispatchEvent(event)
    expect(event.isTrusted).toBeFalsy()
    expect(await ownValue(el, el.value)).toBeUndefined()
  })
})

describe("hiddenByStyle walks the whole rendered tree", () => {
  test("a transparent shadow host hides the field inside it", () => {
    document.body.innerHTML = `<div id="host" style="opacity: 0"></div>`
    const root = document.getElementById("host")!.attachShadow({ mode: "open" })
    root.innerHTML = `<input type="password">`
    const el = root.querySelector("input")!
    expect(renderedParent(el)).toBe(document.getElementById("host"))
    expect(hiddenByStyle(el)).toBe(true)
  })

  test("a slotted field under a transparent wrapper in a closed shadow root", () => {
    document.body.innerHTML = `<div id="host"><input type="password"></div>`
    const host = document.getElementById("host")!
    const root = host.attachShadow({ mode: "closed" })
    root.innerHTML = `<div style="opacity: 0.02"><slot></slot></div>`
    // Content scripts reach closed roots with chrome.dom.
    ;(globalThis as unknown as { chrome: unknown }).chrome = { dom: { openOrClosedShadowRoot: (e: Element) => (e === host ? root : null) } }
    const el = host.querySelector("input")!
    expect(renderedParent(el)).toBe(root.querySelector("slot"))
    expect(hiddenByStyle(el)).toBe(true)
    delete (globalThis as unknown as { chrome?: unknown }).chrome
  })

  test("a host's child that no slot takes isn't rendered", () => {
    document.body.innerHTML = `<div id="host"><input type="password"></div>`
    document.getElementById("host")!.attachShadow({ mode: "open" }).innerHTML = `<p>no slot</p>`
    const el = document.querySelector("input")!
    expect(renderedParent(el)).toBeUndefined()
    expect(hiddenByStyle(el)).toBe(true)
  })

  test("no depth limit", () => {
    document.body.innerHTML = `<div style="opacity: 0">${"<div>".repeat(40)}<input type="password">${"</div>".repeat(40)}</div>`
    expect(hiddenByStyle(document.querySelector("input")!)).toBe(true)
  })

  test("opacity multiplies down the tree, filters included", () => {
    document.body.innerHTML = `<div style="opacity: 0.3"><div style="filter: opacity(0.3)"><input></div></div>`
    expect(hiddenByStyle(document.querySelector("input")!)).toBe(true)
  })

  test("clips and visibility hide it", () => {
    document.body.innerHTML = `<div style="clip-path: inset(50%)"><input></div>`
    expect(hiddenByStyle(document.querySelector("input")!)).toBe(true)
    document.body.innerHTML = `<input style="visibility: hidden">`
    expect(hiddenByStyle(document.querySelector("input")!)).toBe(true)
  })

  test("a plain field is visible", () => {
    document.body.innerHTML = `<form><div style="opacity: 0.9"><input></div></form>`
    expect(hiddenByStyle(document.querySelector("input")!)).toBe(false)
  })
})

describe("visibleBox", () => {
  const rect = (el: Element, left: number, top: number, width: number, height: number) => {
    el.getBoundingClientRect = () => ({ left, top, width, height, right: left + width, bottom: top + height, x: left, y: top, toJSON() {} }) as DOMRect
  }

  test("a field scrolled out of a clipping box isn't visible", () => {
    document.body.innerHTML = `<div style="overflow: hidden"><input></div>`
    const box = document.querySelector("div")!
    const el = document.querySelector("input")!
    rect(box, 0, 0, 300, 40)
    rect(el, 0, 600, 240, 32)
    expect(visibleBox(el)).toBeNull()
    rect(el, 0, 4, 240, 32)
    expect(visibleBox(el)).not.toBeNull()
  })

  test("off screen isn't visible", () => {
    document.body.innerHTML = `<input>`
    const el = document.querySelector("input")!
    rect(el, -500, 10, 240, 32)
    expect(visibleBox(el)).toBeNull()
  })
})

describe("fillable", () => {
  test("a field under something else isn't, unless what's over it is Deadbolt's own open menu", () => {
    document.body.innerHTML = `<input><section></section>`
    const el = document.querySelector("input")!
    const cover = document.querySelector("section")!
    const menu = document.createElement("div")
    document.documentElement.append(menu)
    const before = { one: document.elementFromPoint, all: document.elementsFromPoint }
    try {
      document.elementFromPoint = () => menu
      document.elementsFromPoint = () => [menu, el]
      expect(fillable(el)).toBe(false)
      expect(fillable(el, menu)).toBe(true)
      // The menu doesn't excuse a cover under it.
      document.elementsFromPoint = () => [menu, cover, el]
      expect(fillable(el, menu)).toBe(false)
      document.elementFromPoint = () => cover
      document.elementsFromPoint = () => [cover, el]
      expect(fillable(el, menu)).toBe(false)
    } finally {
      Object.assign(document, { elementFromPoint: before.one, elementsFromPoint: before.all })
      menu.remove()
    }
  })
})

describe("fillFields", () => {
  const field = (el: HTMLInputElement, role: Field["role"], split?: number): Field => ({ el, role, split, owner: ownerOf(el) })

  test("checks each field again right before writing it", async () => {
    document.body.innerHTML = `<form><input id="u"><input id="p" type="password"></form>`
    const u = document.getElementById("u") as HTMLInputElement
    const p = document.getElementById("p") as HTMLInputElement
    // The password passes when fields are picked, then the page hides it.
    let checksOfP = 0
    const check = (el: HTMLInputElement) => el !== p || ++checksOfP < 2
    const { filled } = await fillFields([field(u, "username"), field(p, "password")], { username: "kit", password: "secret" }, check)
    expect(filled).toEqual(["username"])
    expect(p.value).toBe("")
  })

  test("a field moved to another form since the scan isn't written", async () => {
    document.body.innerHTML = `<form id="a"><input id="u"><input id="p" type="password"></form><form id="b" action="https://evil.test/"></form>`
    const u = document.getElementById("u") as HTMLInputElement
    const p = document.getElementById("p") as HTMLInputElement
    const fields = [field(u, "username"), field(p, "password")]
    // Between the username and the password, the page moves the password box.
    u.addEventListener("change", () => document.getElementById("b")!.append(p))
    const { filled } = await fillFields(fields, { username: "kit", password: "secret" }, () => true)
    expect(filled).toEqual(["username"])
    expect(p.value).toBe("")
  })

  test("a field moved within its form, or out of the page, isn't written", async () => {
    document.body.innerHTML = `<form><div id="a"><input id="p" type="password"></div><div id="b"></div></form>`
    const p = document.getElementById("p") as HTMLInputElement
    let fields = [field(p, "password")]
    document.getElementById("b")!.append(p)
    expect((await fillFields(fields, { password: "secret" }, () => true)).filled).toEqual([])
    fields = [field(p, "password")]
    p.remove()
    expect((await fillFields(fields, { password: "secret" }, () => true)).filled).toEqual([])
    expect(p.value).toBe("")
  })

  test("answers in the same task as the last write, before a submit can navigate", async () => {
    document.body.innerHTML = `<form><input id="u"><input id="p" type="password"></form>`
    const u = document.getElementById("u") as HTMLInputElement
    const p = document.getElementById("p") as HTMLInputElement
    let late = false
    p.addEventListener("change", () => setTimeout(() => (late = true), 0))
    const { filled } = await fillFields([field(u, "username"), field(p, "password")], { username: "kit", password: "secret" }, () => true)
    expect(filled).toEqual(["username", "password"])
    expect(late).toBe(false)
  })

  test("code boxes fill only as one whole group in one form", async () => {
    const boxes = (html: string) => {
      document.body.innerHTML = html
      return Array.from(document.querySelectorAll("input")).map((el) => field(el, "otp", 6))
    }
    const six = `<form>${"<input maxlength=1>".repeat(6)}</form>`
    let fields = boxes(six)
    expect((await fillFields(fields, { totp: "492039" }, () => true)).filled).toEqual(["otp"])
    expect(fields.map((f) => f.el.value).join("")).toBe("492039")

    // Split across two forms.
    fields = boxes(`<form>${"<input maxlength=1>".repeat(3)}</form><form>${"<input maxlength=1>".repeat(3)}</form>`)
    expect((await fillFields(fields, { totp: "492039" }, () => true)).filled).toEqual([])
    // One box more than digits.
    fields = boxes(`<form>${"<input maxlength=1>".repeat(7)}</form>`)
    expect((await fillFields(fields, { totp: "492039" }, () => true)).filled).toEqual([])
    // One hidden box.
    fields = boxes(six)
    const hidden = fields[2].el
    expect((await fillFields(fields, { totp: "492039" }, (el) => el !== hidden)).filled).toEqual([])
    expect(fields.map((f) => f.el.value).join("")).toBe("")
  })

  test("code boxes stop the moment any box of the group moves", async () => {
    document.body.innerHTML = `<form>${"<input maxlength=1>".repeat(6)}</form><form id="evil"></form>`
    const fields = Array.from(document.querySelectorAll("input")).map((el) => field(el, "otp", 6))
    // While the third digit goes in, the page takes the last box away.
    fields[2].el.addEventListener("keydown", () => document.getElementById("evil")!.append(fields[5].el))
    expect((await fillFields(fields, { totp: "492039" }, () => true)).filled).toEqual([])
    expect(fields.map((f) => f.el.value).join("")).toBe("49")
  })
})
