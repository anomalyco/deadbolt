import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { parseAddress, withAddressParts } from "../src/content/address"
import { fillForm } from "../src/content/formfill"
import { scanForms } from "../src/content/forms"
import type { FormRole } from "../src/messages"

// The address from the bug report: a whole address kept in an identity's first line.
const ONE_LINE = "1112 Cole St, San Francisco, CA, 94117, United States"

describe("parseAddress", () => {
  const sf = { line1: "1112 Cole St", city: "San Francisco", region: "CA", postal: "94117", country: "US" }

  test("US addresses, with or without a country, the state and ZIP apart or together", () => {
    expect(parseAddress(ONE_LINE)).toEqual(sf)
    expect(parseAddress("1112 Cole St, San Francisco, CA 94117, USA")).toEqual(sf)
    expect(parseAddress("1112 Cole St, San Francisco, CA 94117")).toEqual(sf)
    expect(parseAddress("1112 Cole St, San Francisco, California, 94117")).toEqual(sf)
    expect(parseAddress("1112 Cole St, San Francisco CA 94117")).toEqual(sf)
    expect(parseAddress("1112 Cole St\nSan Francisco, CA 94117")).toEqual(sf)
    expect(parseAddress("1 Main St, Springfield, IL 62701-1234")).toEqual({ line1: "1 Main St", city: "Springfield", region: "IL", postal: "62701-1234", country: "US" })
  })

  test("a unit goes second, whichever way round it's written", () => {
    expect(parseAddress("1112 Cole St, Apt 4, San Francisco, CA 94117")).toEqual({ ...sf, line2: "Apt 4" })
    expect(parseAddress("Apt 4, 1112 Cole St, San Francisco, CA 94117")).toEqual({ ...sf, line2: "Apt 4" })
  })

  test("Canada, the UK, Australia and Germany", () => {
    expect(parseAddress("100 Example St W, Toronto, ON M5H 2N2, Canada")).toEqual({ line1: "100 Example St W", city: "Toronto", region: "ON", postal: "M5H 2N2", country: "CA" })
    expect(parseAddress("Flat 2, 10 Example Rd, London SW1A 1AA")).toEqual({ line1: "10 Example Rd", line2: "Flat 2", city: "London", postal: "SW1A 1AA", country: "GB" })
    expect(parseAddress("10 Example Rd, London, SW1A 1AA, United Kingdom")).toEqual({ line1: "10 Example Rd", city: "London", postal: "SW1A 1AA", country: "GB" })
    expect(parseAddress("1 Example St, Sydney NSW 2000, Australia")).toEqual({ line1: "1 Example St", city: "Sydney", region: "NSW", postal: "2000", country: "AU" })
    expect(parseAddress("Beispielstraße 5, 10115 Berlin, Deutschland")).toEqual({ line1: "Beispielstraße 5", city: "Berlin", postal: "10115", country: "DE" })
    // Five digits with no state or country could be anywhere.
    expect(parseAddress("Beispielstraße 5, 10115 Berlin")).toEqual({ line1: "Beispielstraße 5", city: "Berlin", postal: "10115" })
  })

  test("anything unsure is null", () => {
    expect(parseAddress("1112 Cole St")).toBeNull()
    expect(parseAddress("1112 Cole St, San Francisco")).toBeNull()
    expect(parseAddress("Flat 2, 10 Example Rd")).toBeNull()
    // A US ZIP in Canada, a state that isn't one.
    expect(parseAddress("1112 Cole St, San Francisco, CA, 94117, Canada")).toBeNull()
    expect(parseAddress("1112 Cole St, San Francisco, ZZ 94117")).toBeNull()
    // No street left.
    expect(parseAddress("San Francisco, CA 94117")).toBeNull()
    // Georgia the country: no city or postal code to go on.
    expect(parseAddress("Atlanta, Georgia")).toBeNull()
  })
})

describe("withAddressParts", () => {
  const separate: FormRole[] = ["address-line1", "address-line2", "address-level2", "address-level1", "postal-code", "country"]

  test("splits the line for a form that asks for the parts", () => {
    expect(withAddressParts({ "address-line1": ONE_LINE }, separate)).toEqual({ "address-line1": "1112 Cole St", city: "San Francisco", region: "CA", "postal-code": "94117", country: "US" })
  })

  test("keeps it whole for a form with one address box", () => {
    expect(withAddressParts({ "address-line1": ONE_LINE }, ["name", "address-line1"])).toEqual({ "address-line1": ONE_LINE })
    expect(withAddressParts({ "address-line1": ONE_LINE }, ["name", "street-address", "postal-code"])).toEqual({ "address-line1": ONE_LINE })
  })

  test("the identity's own fields win, and an identity with parts isn't split", () => {
    expect(withAddressParts({ "address-line1": ONE_LINE, region: "California", country: "us" }, separate)).toMatchObject({ region: "California", country: "us", city: "San Francisco" })
    const parts = { "address-line1": "1112 Cole St, Apt 4", city: "San Francisco" }
    expect(withAddressParts(parts, separate)).toBe(parts)
  })

  test("a unit stays in the first line when the form has no second line, or the identity has its own", () => {
    const line = "1112 Cole St, Apt 4, San Francisco, CA 94117"
    expect(withAddressParts({ "address-line1": line }, separate)).toMatchObject({ "address-line1": "1112 Cole St", "address-line2": "Apt 4" })
    expect(withAddressParts({ "address-line1": line }, ["address-line1", "address-level2"])["address-line1"]).toBe("1112 Cole St, Apt 4")
    expect(withAddressParts({ "address-line1": line, "address-line2": "Rear" }, separate)).toMatchObject({ "address-line1": "1112 Cole St, Apt 4", "address-line2": "Rear" })
  })
})

// ---- A registrant form shaped like a domain registrar's checkout ------------------

const US_STATES = ["California", "New Jersey", "New York", "Washington"]
const PROVINCES = ["British Columbia", "Ontario", "Quebec"]

/**
 * A combobox as Base UI and the like draw one: typing filters a list
 * rendered elsewhere in the page, only clicking an option chooses it, and
 * the text goes back to the chosen option on blur or Escape.
 */
function combobox(input: HTMLInputElement, items: () => string[], selected: string) {
  let current = selected
  const id = `${input.id}-list`
  input.value = current
  input.setAttribute("role", "combobox")
  input.setAttribute("aria-autocomplete", "list")
  input.setAttribute("aria-expanded", "false")
  const close = () => {
    document.getElementById(id)?.remove()
    input.setAttribute("aria-expanded", "false")
    input.removeAttribute("aria-controls")
  }
  const open = () => {
    close()
    const list = document.createElement("div")
    list.id = id
    list.setAttribute("role", "listbox")
    const shown = items().filter((text) => text.toLowerCase().includes(input.value.toLowerCase()))
    list.getBoundingClientRect = () => ({ x: 0, y: 400, left: 0, top: 400, right: 240, bottom: 400 + shown.length * 32, width: 240, height: shown.length * 32, toJSON() {} }) as DOMRect
    shown.forEach((text, n) => {
        const option = document.createElement("div")
        option.setAttribute("role", "option")
        option.setAttribute("aria-selected", String(text === current))
        option.textContent = text
        const top = 400 + n * 32
        option.getBoundingClientRect = () => ({ x: 0, y: top, left: 0, top, right: 240, bottom: top + 32, width: 240, height: 32, toJSON() {} }) as DOMRect
        option.addEventListener("pointerdown", (e) => e.preventDefault())
        option.addEventListener("click", () => {
          current = text
          input.value = text
          close()
        })
        list.append(option)
      })
    document.body.append(list)
    input.setAttribute("aria-expanded", "true")
    input.setAttribute("aria-controls", id)
  }
  input.addEventListener("input", open)
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") open()
    if (e.key === "Escape") {
      input.value = current
      close()
    }
  })
  input.addEventListener("blur", () => {
    input.value = current
    close()
  })
  return { chosen: () => current }
}

function registrant({ stateFirst = false, states = US_STATES, phoneCode = "+1" } = {}) {
  const state = `<label for="state">State/Province</label><input id="state">`
  document.body.innerHTML = `<form>
    <label for="first">First name</label><input id="first"><label for="last">Last name</label><input id="last">
    <label for="email">Email</label><input id="email" type="email"><label for="org">Organization (optional)</label><input id="org">
    <span id="phone-label">Phone</span><input id="code" aria-labelledby="phone-label"><input id="phone" type="tel" aria-labelledby="phone-label">
    ${stateFirst ? state : ""}
    <label for="country">Country</label><input id="country">
    <label for="a1">Address</label><input id="a1"><label for="a2">Address 2 (optional)</label><input id="a2">
    <label for="city">City</label><input id="city" value="Hoboken"><label for="zip">Postal code</label><input id="zip" value="07030">
    ${stateFirst ? "" : state}
  </form>`
  const $ = (id: string) => document.getElementById(id) as HTMLInputElement
  const code = combobox($("code"), () => ["Canada +1", "United Kingdom +44", "United States +1"], phoneCode)
  const country = combobox($("country"), () => ["Canada", "United Kingdom", "United States"], "United States")
  // The state list is the chosen country's.
  const region = combobox($("state"), () => (country.chosen() === "Canada" ? PROVINCES : states), "New Jersey")
  return { $, code, country, region }
}

describe("a registrant form with custom comboboxes", () => {
  const before = { one: document.elementFromPoint }
  beforeEach(() => {
    // happy-dom does no hit testing: what's at a point is the option drawn there.
    document.elementFromPoint = ((x: number, y: number) =>
      Array.from(document.querySelectorAll("[role=option]")).find((o) => {
        const r = o.getBoundingClientRect()
        return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom
      }) ?? null) as typeof document.elementFromPoint
  })
  afterEach(() => Object.assign(document, { elementFromPoint: before.one }))

  const address = ($: (id: string) => HTMLInputElement) => ["a1", "a2", "city", "zip", "state", "country"].map((id) => $(id).value)
  const kit = { "given-name": "Kit", "family-name": "Langton" }

  test("every field gets its role", () => {
    registrant()
    expect(scanForms().map((f) => [f.el.id, f.role])).toEqual([
      ["first", "given-name"], ["last", "family-name"], ["email", "email"], ["org", "organization"], ["code", "tel-country-code"], ["phone", "tel"],
      ["country", "country"], ["a1", "address-line1"], ["a2", "address-line2"], ["city", "address-level2"], ["zip", "postal-code"], ["state", "address-level1"],
    ])
    expect(new Set(scanForms().map((f) => f.section)).size).toBe(1)
  })

  test("one fill of an address kept on one line completes every part of it", async () => {
    const { $ } = registrant()
    const { filled } = await fillForm(scanForms(), { ...kit, "address-line1": ONE_LINE }, () => true)
    expect(address($)).toEqual(["1112 Cole St", "", "San Francisco", "94117", "California", "United States"])
    expect([$("first").value, $("last").value, $("org").value]).toEqual(["Kit", "Langton", ""])
    // The country already showed United States: nothing to choose.
    expect(filled).toEqual(["given-name", "family-name", "address-line1", "address-level2", "postal-code", "address-level1"])
    expect(document.querySelector("[role=listbox]")).toBeNull()
  })

  test("the same from an identity with the parts, its phone's calling code chosen too", async () => {
    const { $ } = registrant({ phoneCode: "+44" })
    const values = { ...kit, "address-line1": "1112 Cole St", city: "San Francisco", region: "CA", "postal-code": "94117", country: "US", phone: "+14155550123" }
    const { filled } = await fillForm(scanForms(), values, () => true)
    expect(address($)).toEqual(["1112 Cole St", "", "San Francisco", "94117", "California", "United States"])
    expect([$("code").value, $("phone").value]).toEqual(["United States +1", "4155550123"])
    expect(filled).toContain("tel-country-code")
  })

  test("the country is chosen before a state list that depends on it, wherever it is", async () => {
    const { $ } = registrant({ stateFirst: true })
    $("country").value = "Can"
    $("country").dispatchEvent(new Event("input"))
    document.querySelector<HTMLElement>("[role=option]")!.click()
    expect($("country").value).toBe("Canada")
    await fillForm(scanForms(), { ...kit, "address-line1": ONE_LINE }, () => true)
    // The country came from the line, which the identity doesn't have on its own.
    expect([$("country").value, $("state").value]).toEqual(["United States", "California"])
  })

  test("a combobox with no matching option is left as it was", async () => {
    const { $, region } = registrant({ states: ["New Jersey", "New York"] })
    const { filled } = await fillForm(scanForms(), { ...kit, "address-line1": ONE_LINE }, () => true)
    expect(filled).not.toContain("address-level1")
    expect([$("state").value, region.chosen()]).toEqual(["New Jersey", "New Jersey"])
    expect($("state").getAttribute("aria-expanded")).toBe("false")
    expect(address($).slice(0, 4)).toEqual(["1112 Cole St", "", "San Francisco", "94117"])
  })

  test("a combobox that fails the field check isn't touched", async () => {
    const { $ } = registrant()
    await fillForm(scanForms(), { ...kit, "address-line1": ONE_LINE }, (el) => el.id !== "state")
    expect($("state").value).toBe("New Jersey")
    expect(document.querySelector("[role=listbox]")).toBeNull()
  })

  test("an option that isn't what's on screen isn't clicked", async () => {
    const { $ } = registrant()
    document.elementFromPoint = (() => document.body) as typeof document.elementFromPoint
    await fillForm(scanForms(), { ...kit, "address-line1": ONE_LINE }, () => true)
    expect($("state").value).toBe("New Jersey")
  })

  test("a form with one address box gets the whole line", async () => {
    document.body.innerHTML = `<form><label for="n">Full name</label><input id="n"><label for="a">Address</label><input id="a"></form>`
    await fillForm(scanForms(), { ...kit, "address-line1": ONE_LINE }, () => true)
    expect((document.getElementById("a") as HTMLInputElement).value).toBe(ONE_LINE)
    document.body.innerHTML = `<form><label for="n">Full name</label><input id="n"><label for="a">Address</label><textarea id="a"></textarea><label for="z">ZIP</label><input id="z"></form>`
    await fillForm(scanForms(), { ...kit, "address-line1": ONE_LINE }, () => true)
    expect((document.getElementById("a") as HTMLTextAreaElement).value).toBe(ONE_LINE)
  })
})
