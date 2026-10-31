import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { SIGNIN_SETTING } from "../src/auth-state"
import { authReport, takeSignInAction } from "../src/content/auth-state"
import { scanPage, type Field } from "../src/content/detect"
import type { PageState } from "../src/content/inline"
import { initProviderChain } from "../src/content/provider-chain"
import type { ProviderReport, ToContent } from "../src/messages"
import { installChrome, settle, type FakeChrome } from "./chrome"

// A laid-out page: elements with data-box="left top width height" sit there,
// anything else fills the viewport; a point hits the deepest boxed element.
const rect = Element.prototype.getBoundingClientRect
const hit = { one: document.elementFromPoint, all: document.elementsFromPoint }
let cover: Element | null = null
function boxOf(el: Element) {
  const b = el.getAttribute("data-box")?.split(" ").map(Number)
  const [left, top, width, height] = b ?? [0, 0, innerWidth, innerHeight]
  return { x: left, y: top, left, top, width, height, right: left + width, bottom: top + height, toJSON() {} } as DOMRect
}
function at(x: number, y: number): Element | null {
  if (cover) return cover
  const boxed = Array.from(document.querySelectorAll("[data-box]")).filter((el) => {
    const r = boxOf(el)
    return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom
  })
  return boxed.at(-1) ?? document.body
}

let fake: FakeChrome
let fields: Field[] = []
let formId = 0
let kind: ReturnType<typeof scanPage>["kind"] = null
const submits: Array<{ form: HTMLFormElement | null; button: HTMLElement }> = []
const state: PageState = {
  targets: () => fields,
  form: () => formId,
  kind: () => kind,
  rescan() {
    const r = scanPage()
    const next = r.kind && r.kind !== "reset" ? r.fields : []
    if (next.length !== fields.length || next.some((f, i) => f.el !== fields[i].el)) formId++
    fields = next
    kind = r.kind
  },
  formFields: () => [],
  formsForm: () => 0,
}

const WORKER = () => ({ id: chrome.runtime.id, url: chrome.runtime.getURL("background.js") }) as chrome.runtime.MessageSender
function deliver<T>(message: ToContent, sender = WORKER()): Promise<T> {
  return new Promise((resolve) => {
    for (const l of fake.listeners) l(message, sender, (r) => resolve(r as T))
  })
}
const status = (session: string, label = "Signing in with Google…", done?: boolean) => deliver<boolean>({ type: "db:provider-status", session, label, ...(done ? { done } : {}) })
const probe = (session: string, account?: string) => deliver<ProviderReport>({ type: "db:provider-probe", session, provider: "google", ...(account ? { account } : {}) })
const act = (session: string, action: string, values?: Record<string, string>) => deliver<boolean>({ type: "db:provider-act", session, action, ...(values ? { values } : {}) })

function page(html: string, url = "https://accounts.google.com/v3/signin/identifier") {
  ;(window as unknown as { happyDOM: { setURL(u: string): void } }).happyDOM.setURL(url)
  document.body.innerHTML = html
  fields = []
  kind = null
}

let n = 0
const fresh = () => `session-${++n}`

beforeAll(() => {
  Element.prototype.getBoundingClientRect = function (this: Element) {
    return boxOf(this)
  }
  document.elementFromPoint = at
  document.elementsFromPoint = (x, y) => [at(x, y)].filter((e): e is Element => !!e)
  fake = installChrome()
  fake.local[SIGNIN_SETTING] = true
  initProviderChain(state, { enabled: () => true, submit: (form, button) => void submits.push({ form, button }) })
})
afterAll(() => {
  ;(window as unknown as { happyDOM: { setURL(u: string): void } }).happyDOM.setURL("https://example.com/login")
  Element.prototype.getBoundingClientRect = rect
  document.elementFromPoint = hit.one
  document.elementsFromPoint = hit.all
})
beforeEach(() => {
  cover = null
  submits.length = 0
})

const LOGIN = `<main data-box="0 100 600 400"><form action="/v3/signin/challenge" data-box="0 100 600 400">
  <label for="e">Email</label><input id="e" type="email" autocomplete="username" data-box="10 120 300 32">
  <label for="p">Password</label><input id="p" type="password" autocomplete="current-password" data-box="10 170 300 32">
  <button type="submit" data-box="10 220 100 32">Next</button></form></main>`

describe("provider chain, page side", () => {
  test("a provider button is an offer's entry, with an action the go step can't use", () => {
    page(`<button data-box="10 10 200 40">Continue with Google</button>`, "https://www.example.com/")
    const facts = authReport(state, true)
    expect(facts.entry).toBe(true)
    expect(facts.action).toBeString()
    expect(takeSignInAction(facts.action!, state)).toBeNull()
  })

  test("only the service worker drives it", async () => {
    page(LOGIN)
    expect(await deliver({ type: "db:provider-status", session: fresh(), label: "x" }, { id: "other" } as chrome.runtime.MessageSender)).toBe(false)
  })

  test("hard consent preempts the chooser's tile", async () => {
    const s = fresh()
    page(`<h1>Choose an account</h1><ul><li data-box="10 100 300 48" data-identifier="kit@gmail.com">Kit</li></ul>`, "https://accounts.google.com/o/oauth2/v2/auth")
    await status(s)
    expect((await probe(s, "kit@gmail.com")).kind).toBe("chooser")
    document.body.insertAdjacentHTML("beforeend", `<button data-box="400 300 80 32">Allow</button>`)
    expect(await probe(s, "kit@gmail.com")).toEqual({ kind: "stop", reason: "consent" })
    // "to continue to" is Google's chooser copy, not consent.
    page(`<h1>Choose an account</h1><p>to continue to Example</p><ul><li data-box="10 100 300 48" data-identifier="kit@gmail.com">Kit</li></ul>`, "https://accounts.google.com/o/oauth2/v2/auth")
    expect((await probe(s, "kit@gmail.com")).kind).toBe("chooser")
  })

  test("consent appearing after the probe stops the click", async () => {
    const s = fresh()
    page(`<ul><li id="t" data-box="10 100 300 48" data-identifier="kit@gmail.com">Kit</li></ul>`, "https://accounts.google.com/o/oauth2/v2/auth")
    await status(s)
    const report = await probe(s, "kit@gmail.com")
    let clicked = 0
    document.getElementById("t")!.addEventListener("click", () => clicked++)
    document.body.insertAdjacentHTML("beforeend", `<p>Example wants to access your Google Account</p>`)
    expect(await act(s, report.action!)).toBe(false)
    await settle()
    expect(clicked).toBe(0)
  })

  test("two tiles for the account are ambiguous", async () => {
    const s = fresh()
    page(`<ul><li data-box="10 100 300 48" data-identifier="kit@gmail.com">Kit</li><li data-box="10 160 300 48" data-email="kit@gmail.com">Kit</li></ul>`, "https://accounts.google.com/o/oauth2/v2/auth")
    await status(s)
    expect((await probe(s, "kit@gmail.com")).kind).toBe("stop")
  })

  test("a form fills whole and submits, or not at all", async () => {
    const s = fresh()
    page(LOGIN)
    await status(s)
    const report = await probe(s)
    expect(report).toMatchObject({ kind: "form", roles: ["password", "username"] })
    const email = document.getElementById("e") as HTMLInputElement
    const password = document.getElementById("p") as HTMLInputElement
    // A missing value writes nothing; nor does a value for a role the form doesn't have.
    expect(await act(s, report.action!, { username: "kit@example.com" })).toBe(false)
    expect([email.value, password.value]).toEqual(["", ""])
    const again = await probe(s)
    expect(await act(s, again.action!, { username: "kit@example.com", password: "pw", totp: "123456" })).toBe(false)
    expect([email.value, password.value]).toEqual(["", ""])
    const third = await probe(s)
    expect(await act(s, third.action!, { username: "kit@example.com", password: "pw" })).toBe(true)
    expect([email.value, password.value]).toEqual(["kit@example.com", "pw"])
    await Bun.sleep(200)
    expect(submits).toHaveLength(1)
    expect(submits[0].button.textContent).toBe("Next")
  })

  test("a fill interrupted midway takes back what it wrote", async () => {
    const s = fresh()
    page(LOGIN)
    await status(s)
    const report = await probe(s)
    const pending = act(s, report.action!, { username: "kit@example.com", password: "pw" })
    // Between the identifier and the password, the chain ends.
    await Bun.sleep(5)
    await status(s, "", true)
    expect(await pending).toBe(false)
    expect((document.getElementById("e") as HTMLInputElement).value).toBe("")
    expect((document.getElementById("p") as HTMLInputElement).value).toBe("")
    expect(submits).toHaveLength(0)
  })

  test("a cross-origin action stops before any value is asked for", async () => {
    const s = fresh()
    page(LOGIN.replace('action="/v3/signin/challenge"', 'action="https://evil.test/collect"'))
    await status(s)
    expect(await probe(s)).toEqual({ kind: "stop", reason: "unknown" })
  })

  test("a cover over the field, Deadbolt's own pill included, fails closed", async () => {
    const s = fresh()
    page(LOGIN)
    await status(s)
    cover = document.documentElement.lastElementChild
    expect(await probe(s)).toEqual({ kind: "stop", reason: "unknown" })
  })

  test("a stopped session stays stopped; an older end never removes a newer pill", async () => {
    const s = fresh()
    page(LOGIN)
    await status(s)
    // The person's own press (simulated: dispatched events are untrusted, so mark it).
    const press = new Event("pointerdown")
    Object.defineProperty(press, "isTrusted", { value: true })
    window.dispatchEvent(press)
    expect(fake.sent).toContainEqual({ type: "db:signin-stop" })
    expect(await status(s)).toBe(false)
    expect(await probe(s)).toEqual({ kind: "stop", reason: "unknown" })
    const next = fresh()
    expect(await status(next)).toBe(true)
    expect(await status(s, "Signed in", true)).toBe(false)
    const old = fresh()
    await status(old)
    await status(next)
    expect(await status(old, "", true)).toBe(true)
    expect((await probe(next)).kind).toBe("form")
  })

  test("a click finds its control afresh when it lands", async () => {
    const TILE = `<ul><li id="t" data-box="10 100 300 48" data-identifier="kit@gmail.com">Kit</li></ul>`
    const s = fresh()
    page(TILE, "https://accounts.google.com/o/oauth2/v2/auth")
    await status(s)
    let clicked = 0
    document.getElementById("t")!.addEventListener("click", () => clicked++)
    expect(await act(s, (await probe(s, "kit@gmail.com")).action!)).toBe(true)
    await settle()
    expect(clicked).toBe(1)
    // A second tile for the account between the answer and the click: ambiguous, no click.
    expect(await act(s, (await probe(s, "kit@gmail.com")).action!)).toBe(true)
    document.querySelector("ul")!.insertAdjacentHTML("beforeend", `<li data-box="10 160 300 48" data-email="kit@gmail.com">Kit</li>`)
    await settle()
    expect(clicked).toBe(1)
  })

  async function filled() {
    const s = fresh()
    page(LOGIN)
    await status(s)
    expect(await act(s, (await probe(s)).action!, { username: "kit@example.com", password: "pw" })).toBe(true)
    return { email: document.getElementById("e") as HTMLInputElement, password: document.getElementById("p") as HTMLInputElement }
  }
  const setValue = (el: HTMLInputElement, v: string) => Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(el, v)

  test("a same-document URL change revokes the delayed submit", async () => {
    const { email, password } = await filled()
    history.replaceState(null, "", "/v3/signin/changed")
    await Bun.sleep(200)
    expect(submits).toHaveLength(0)
    expect([email.value, password.value]).toEqual(["kit@example.com", "pw"])
  })

  test("the delayed submit declines a stale form", async () => {
    // Restyled: the submit control moved out of view.
    await filled()
    document.querySelector("button")!.setAttribute("data-box", "10 900 100 32")
    await Bun.sleep(200)
    // A field swapped for another holding the same value.
    const swap = await filled()
    const twin = swap.password.cloneNode() as HTMLInputElement
    swap.password.replaceWith(twin)
    setValue(twin, "pw")
    await Bun.sleep(200)
    // A value changed after the fill.
    const changed = await filled()
    setValue(changed.email, "someone@example.com")
    await Bun.sleep(200)
    // A new field to type in.
    await filled()
    document.querySelector("form")!.insertAdjacentHTML("beforeend", `<input type="text" name="extra" data-box="10 270 300 32">`)
    await Bun.sleep(200)
    expect(submits).toHaveLength(0)
    expect(changed.email.value).toBe("someone@example.com")
  })

  test("an ended session can't be rearmed by a late active status", async () => {
    const s = fresh()
    page(LOGIN)
    await status(s)
    expect(await status(s, "", true)).toBe(true)
    expect(await status(s)).toBe(false)
    expect(await probe(s)).toEqual({ kind: "stop", reason: "unknown" })
  })

  test("a press before the first status still stops the pick", async () => {
    await Bun.sleep(350)
    const before = fake.sent.length
    const press = new Event("pointerdown")
    Object.defineProperty(press, "isTrusted", { value: true })
    window.dispatchEvent(press)
    expect(fake.sent.slice(before)).toContainEqual({ type: "db:signin-stop" })
  })

  test("Google's sign-in disclosure is not consent; a consent control still is", async () => {
    const s = fresh()
    const footer = "<p>To continue, Google will share your name, email address, language preference and profile picture with Acme.</p>"
    page(`<h1>Choose an account</h1><ul><li data-box="10 100 300 48" data-identifier="kit@gmail.com">Kit</li></ul>${footer}`, "https://accounts.google.com/o/oauth2/v2/auth")
    await status(s)
    expect((await probe(s, "kit@gmail.com")).kind).toBe("chooser")
    document.body.insertAdjacentHTML("beforeend", `<button data-box="400 300 120 32">Continue as Kit</button>`)
    expect(await probe(s, "kit@gmail.com")).toEqual({ kind: "stop", reason: "consent" })
  })

  const TOTP = (chip: string, extra = "") => `<h1>2-Step Verification</h1>
<p><span data-profile-identifier="" data-box="10 60 200 20">${chip}</span></p>
<p>Get a verification code from the Google Authenticator app.</p>${extra}
<form action="/v3/signin/challenge/totp" data-box="0 100 600 300"><input type="tel" name="totpPin" autocomplete="one-time-code" inputmode="numeric" maxlength="6" aria-label="Enter code" data-box="10 120 300 32"><button data-box="10 170 100 32">Next</button></form>`
  const TOTP_URL = "https://accounts.google.com/v3/signin/challenge/totp"

  test("a Google code step's account chip for the linked account is not a delivery address", async () => {
    const s = fresh()
    page(TOTP("kit@gmail.com"), TOTP_URL)
    await status(s)
    expect(await probe(s, "kit@gmail.com")).toMatchObject({ kind: "form", roles: ["otp"] })
    // Strict otherwise: no account named, another account's chip, or any other line with it.
    expect(await probe(s)).toEqual({ kind: "stop", reason: "sms" })
    page(TOTP("someone@gmail.com"), TOTP_URL)
    expect(await probe(s, "kit@gmail.com")).toEqual({ kind: "stop", reason: "sms" })
    page(TOTP("kit@gmail.com", "<p>We sent a code to kit@gmail.com</p>"), TOTP_URL)
    expect(await probe(s, "kit@gmail.com")).toEqual({ kind: "stop", reason: "sms" })
    page(TOTP("kit@gmail.com", "<p>kit@gmail.com</p><p>Or get a text message instead</p>"), TOTP_URL)
    expect(await probe(s, "kit@gmail.com")).toEqual({ kind: "stop", reason: "sms" })
  })

  const pill = () => Array.from(document.documentElement.children).find((el) => el instanceof HTMLElement && el.style.zIndex === "2147483647")

  test("a new session's pill survives the old one's fade", async () => {
    const a = fresh(), b = fresh()
    page(LOGIN)
    await status(a)
    await status(a, "Signed in", true)
    const old = pill()
    await status(b)
    expect(pill()).not.toBe(old)
    await Bun.sleep(1500)
    expect(pill()?.isConnected).toBe(true)
    await status(b, "", true)
    expect(pill()).toBeUndefined()
  })

  test("a declined submit ends the chain at once and keeps the filled form", async () => {
    await Bun.sleep(350)
    const before = fake.sent.length
    const { email, password } = await filled()
    setValue(email, "someone@example.com")
    await Bun.sleep(200)
    expect(submits).toHaveLength(0)
    expect(fake.sent.slice(before)).toContainEqual({ type: "db:signin-stop" })
    expect([email.value, password.value]).toEqual(["someone@example.com", "pw"])
    await Bun.sleep(400)
    expect(pill()).toBeUndefined()
  })

  test("in a frame, a press only forwards a stop; status, probes and acts are refused", async () => {
    await settle()
    const s = fresh()
    page(LOGIN)
    const real = Object.getOwnPropertyDescriptor(window, "top")
    Object.defineProperty(window, "top", { configurable: true, get: () => ({}) })
    try {
      expect(window === window.top).toBe(false)
      expect(await status(s)).toBe(false)
      expect(await probe(s)).toEqual({ kind: "stop", reason: "unknown" })
      expect(pill()).toBeUndefined()
      await Bun.sleep(350)
      const before = fake.sent.length
      const press = new Event("click")
      Object.defineProperty(press, "isTrusted", { value: true })
      window.dispatchEvent(press)
      expect(fake.sent.slice(before)).toContainEqual({ type: "db:signin-stop" })
      // Focus leaving (a provider popup opening) is no stop.
      window.dispatchEvent(new FocusEvent("blur"))
      await Bun.sleep(350)
      const blurred = new FocusEvent("blur")
      Object.defineProperty(blurred, "isTrusted", { value: true })
      const after = fake.sent.length
      window.dispatchEvent(blurred)
      expect(fake.sent.length).toBe(after)
    } finally {
      if (real) Object.defineProperty(window, "top", real)
      else delete (window as { top?: unknown }).top
    }
    expect(window === window.top).toBe(true)
  })
})
