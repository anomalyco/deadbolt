import { describe, expect, test } from "bun:test"
import { fillable, fillFields, hiddenByStyle, ownValue, renderedParent, setInputValue, trackUserInput, visibleBox } from "../src/content/fill"
import { ownerOf, type Field } from "../src/content/detect"
import { scanForms } from "../src/content/forms"
import { fillForm } from "../src/content/formfill"
import { splitNumber, valueFor } from "../src/content/transform"
import { fillsWords } from "../src/messages"

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

  test("a generated password goes into every new-password box, or none", async () => {
    document.body.innerHTML = `<form><input id="c" type="password"><input id="n1" type="password"><input id="n2" type="password"></form>`
    const [c, n1, n2] = ["c", "n1", "n2"].map((id) => document.getElementById(id) as HTMLInputElement)
    const fields = [field(c, "password"), field(n1, "new-password"), field(n2, "new-password")]
    expect((await fillFields(fields, { newPassword: "Generated-1" }, () => true)).filled).toEqual(["new-password"])
    expect([c.value, n1.value, n2.value]).toEqual(["", "Generated-1", "Generated-1"])
    n1.value = n2.value = ""
    expect((await fillFields(fields, { newPassword: "Generated-2" }, (el) => el !== n2)).filled).toEqual([])
    expect([n1.value, n2.value]).toEqual(["", ""])
  })

  test("a value the field can't take isn't written: past its maxlength, or not a phone number in a phone box", async () => {
    document.body.innerHTML = `<form><input id="u" type="tel"><input id="p" type="password" maxlength="6"></form>`
    const [u, p] = ["u", "p"].map((id) => document.getElementById(id) as HTMLInputElement)
    const fields = [field(u, "phone"), field(p, "password")]
    expect((await fillFields(fields, { username: "kit@acme.test", password: "correct horse" }, () => true)).filled).toEqual([])
    expect([u.value, p.value]).toEqual(["", ""])
    expect((await fillFields(fields, { username: "+1 (415) 555-0123", password: "482916" }, () => true)).filled).toEqual(["phone", "password"])
    expect([u.value, p.value]).toEqual(["+1 (415) 555-0123", "482916"])
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

describe("form values", () => {
  const el = (html: string) => {
    document.body.innerHTML = html
    return document.body.firstElementChild as HTMLInputElement & HTMLSelectElement & HTMLTextAreaElement
  }
  const kit = {
    "given-name": "Kit", "additional-name": "J", "family-name": "Langton", phone: "+14155550123", country: "US", region: "NY",
    "address-line1": "123 Main St", "address-line2": "Apt 4", city: "Brooklyn", "postal-code": "11201", birthday: "1990-07-04",
  }
  const card = { number: "4242424242424242", cvv: "123", expiry: "2028-08", cardholder: "Kit J Langton", brand: "Visa" }

  test("names: full and split", () => {
    expect(valueFor("name", el(`<input>`), kit)).toBe("Kit J Langton")
    expect(valueFor("cc-given-name", el(`<input>`), card)).toBe("Kit J")
    expect(valueFor("cc-family-name", el(`<input>`), card)).toBe("Langton")
  })

  test("street address joined in one box, lines in a textarea", () => {
    expect(valueFor("street-address", el(`<input>`), kit)).toBe("123 Main St, Apt 4")
    expect(valueFor("street-address", el(`<textarea></textarea>`), kit)).toBe("123 Main St\nApt 4")
  })

  test("phone international, national when the box is short", () => {
    expect(valueFor("tel", el(`<input type="tel">`), kit)).toBe("+14155550123")
    expect(valueFor("tel", el(`<input type="tel" maxlength="10">`), kit)).toBe("4155550123")
    expect(valueFor("tel-national", el(`<input>`), { ...kit, phone: "+442071234567", country: "GB" })).toBe("02071234567")
    expect(valueFor("tel-country-code", el(`<input>`), kit)).toBe("+1")
  })

  test("country and region: code, name or the matching option", () => {
    expect(valueFor("country", el(`<input maxlength="2">`), kit)).toBe("US")
    expect(valueFor("country", el(`<input>`), kit)).toBe("United States")
    expect(valueFor("country", el(`<select><option value="">Choose</option><option value="CA">Canada</option><option value="USA">United States of America</option></select>`), kit)).toBe("USA")
    expect(valueFor("address-level1", el(`<select><option value="1">New Jersey</option><option value="2">New York</option></select>`), kit)).toBe("2")
    expect(valueFor("address-level1", el(`<input maxlength="2">`), { ...kit, region: "New York" })).toBe("NY")
  })

  test("birthday whole and in parts", () => {
    expect(valueFor("bday", el(`<input type="date">`), kit)).toBe("1990-07-04")
    expect(valueFor("bday", el(`<input placeholder="MM/DD/YYYY">`), kit)).toBe("07/04/1990")
    expect(valueFor("bday-month", el(`<select><option value="6">June</option><option value="7">July</option></select>`), kit)).toBe("7")
    expect(valueFor("bday-year", el(`<input maxlength="4">`), kit)).toBe("1990")
  })

  test("expiry in one box, and as month and year", () => {
    expect(valueFor("cc-exp", el(`<input placeholder="MM / YY">`), card)).toBe("08 / 28")
    expect(valueFor("cc-exp", el(`<input placeholder="MM/YYYY">`), card)).toBe("08/2028")
    expect(valueFor("cc-exp", el(`<input maxlength="4">`), card)).toBe("0828")
    expect(valueFor("cc-exp", el(`<input>`), card)).toBe("08/28")
    expect(valueFor("cc-exp-month", el(`<select><option value="07">07</option><option value="08">08</option></select>`), card)).toBe("08")
    expect(valueFor("cc-exp-year", el(`<select><option value="27">27</option><option value="28">28</option></select>`), card)).toBe("28")
    expect(valueFor("cc-exp-year", el(`<input maxlength="2">`), card)).toBe("28")
  })

  test("an expiry year box: two digits only for YY, four for YYYY", () => {
    expect(valueFor("cc-exp-year", el(`<input placeholder="YYYY">`), card)).toBe("2028")
    expect(valueFor("cc-exp-year", el(`<input placeholder="YY">`), card)).toBe("28")
    expect(valueFor("cc-exp-year", el(`<input>`), card)).toBe("2028")
    expect(valueFor("cc-exp", el(`<input placeholder="MM / YYYY">`), card)).toBe("08 / 2028")
    expect(valueFor("cc-exp", el(`<input placeholder="mm/yy">`), card)).toBe("08/28")
  })

  test("what an identity fills, in words", () => {
    const roles = ["given-name", "family-name", "email", "tel", "address-line1", "country"] as const
    expect(fillsWords([...roles], ["given-name", "email", "phone", "address-line1", "country"])).toEqual(["name", "email", "phone", "address"])
    // A country alone doesn't fill a phone box.
    expect(fillsWords(["tel"], ["country"])).toEqual([])
  })

  test("card number with or without spaces, and split over boxes", () => {
    expect(valueFor("cc-number", el(`<input>`), card)).toBe("4242424242424242")
    expect(valueFor("cc-number", el(`<input placeholder="1234 1234 1234 1234">`), card)).toBe("4242 4242 4242 4242")
    document.body.innerHTML = `<input maxlength="4"><input maxlength="4"><input maxlength="4"><input maxlength="4">`
    expect(splitNumber(card.number, Array.from(document.querySelectorAll("input")))).toEqual(["4242", "4242", "4242", "4242"])
  })

  test("a whole section fills, selects included", async () => {
    document.body.innerHTML = `<form><input id="n" autocomplete="name"><input id="z" autocomplete="postal-code"><select id="c" autocomplete="country"><option value="">-</option><option value="US">United States</option></select></form>`
    const fields = scanForms()
    const { filled } = await fillForm(fields, kit, () => true)
    expect(filled).toEqual(["name", "postal-code", "country"])
    expect((document.getElementById("n") as HTMLInputElement).value).toBe("Kit J Langton")
    expect((document.getElementById("c") as HTMLSelectElement).value).toBe("US")
  })

  test("a birth date box whose placeholder shows a whole date takes the whole date", async () => {
    document.body.innerHTML = `<form><label for="g">First name</label><input id="g"><label for="d">Date of birth</label><input id="d" placeholder="MM/DD/YYYY" maxlength="10"></form>`
    const fields = scanForms()
    expect(fields.map((f) => f.role)).toEqual(["given-name", "bday"])
    await fillForm(fields, kit, () => true)
    expect((document.getElementById("d") as HTMLInputElement).value).toBe("07/04/1990")
  })

  test("a select the page loads once an earlier field is chosen fills after it", async () => {
    document.body.innerHTML = `<form><select id="c" autocomplete="country"><option value="">-</option><option value="US">United States</option></select><select id="s" autocomplete="address-level1" disabled><option value="">Choose a country first</option></select></form>`
    const [country, state] = ["c", "s"].map((id) => document.getElementById(id) as HTMLSelectElement)
    country.addEventListener("change", () => setTimeout(() => {
      state.innerHTML = `<option value="">State</option><option value="CA">California</option><option value="NY">New York</option>`
      state.disabled = false
    }, 200))
    const { filled } = await fillForm(scanForms(), kit, (el) => !el.disabled)
    expect(filled).toEqual(["country", "address-level1"])
    expect(state.value).toBe("NY")
  })

  test("split card boxes fill only as a whole", async () => {
    document.body.innerHTML = `<form><label for="a">Card number</label><input id="a" maxlength="4"><input maxlength="4"><input maxlength="4"><input maxlength="4"></form>`
    const fields = scanForms()
    const boxes = Array.from(document.querySelectorAll("input"))
    expect((await fillForm(fields, card, (e) => e !== boxes[2])).filled).toEqual([])
    expect(boxes.map((b) => b.value).join("")).toBe("")
    expect((await fillForm(fields, card, () => true)).filled).toEqual(["cc-number"])
    expect(boxes.map((b) => b.value)).toEqual(["4242", "4242", "4242", "4242"])
  })
})
