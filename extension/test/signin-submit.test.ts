import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test"
import { scanPage } from "../src/content/detect"
import { accountChip, submitPlan } from "../src/content/signin-submit"

// happy-dom does no hit testing: the box last measured is on top there.
const rect = Element.prototype.getBoundingClientRect
const hit = document.elementFromPoint
let measured: Element | null = null
beforeAll(() => {
  Element.prototype.getBoundingClientRect = function (this: Element) {
    if (this instanceof HTMLInputElement) measured = this
    return rect.call(this)
  }
  document.elementFromPoint = () => measured
})
afterAll(() => {
  Element.prototype.getBoundingClientRect = rect
  document.elementFromPoint = hit
})

function page(html: string, title = "Sign in") {
  history.replaceState(null, "", "/login")
  document.title = title
  document.body.innerHTML = html
}

/** What an automatic session may submit of the page as scanned now. */
function plan(first = false, account?: string) {
  const scan = scanPage()
  return submitPlan({ kind: scan.kind, fields: scan.fields, submit: scan.submit, first, account })
}

function fill(selector: string, value: string) {
  const el = document.querySelector<HTMLInputElement>(selector)!
  el.value = value
}

const NEXT = `<div jsaction="click:cOuCgd"><button type="button" id="next"><span>Next</span></button></div>`

afterEach(() => {
  document.body.innerHTML = ""
})

describe("a form-less step (Google's)", () => {
  const email = `<main><h1>Sign in</h1>
    <input type="email" id="identifierId" name="identifier" autocomplete="username webauthn" aria-label="Email or phone">
    <button type="button">Forgot email?</button><button type="button">Create account</button>${NEXT}</main>`

  test("its sole Next submits the email step", () => {
    page(email)
    fill("#identifierId", "kit@acme.test")
    const p = plan(true)
    expect(typeof p).toBe("object")
    if (typeof p === "string") return
    expect(p.form).toBeNull()
    expect(p.button.id).toBe("next")
  })

  test("a password step beside a hidden email box submits too", () => {
    page(`<main><h1>Welcome</h1><div data-profile-identifier>kit@acme.test</div>
      <input type="email" name="identifier" hidden value="kit@acme.test">
      <input type="password" name="Passwd" autocomplete="current-password" aria-label="Enter your password">
      <button type="button">Forgot password?</button>${NEXT}</main>`)
    fill("input[name=Passwd]", "correct horse")
    expect(typeof plan()).toBe("object")
  })

  test("not with the value missing", () => {
    page(email)
    expect(plan(true)).toBe("values")
  })

  test("not when two controls read like its submit", () => {
    page(email.replace("Create account", "Continue"))
    fill("#identifierId", "kit@acme.test")
    expect(plan(true)).toBe("scope")
  })

  test("not past a CAPTCHA", () => {
    page(email.replace("</main>", `<div class="g-recaptcha"></div></main>`))
    fill("#identifierId", "kit@acme.test")
    expect(plan(true)).toBe("captcha")
  })

  test("not while an error shows, or a field is marked invalid", () => {
    page(email.replace("</main>", `<div role="alert">Couldn't find your Google Account</div></main>`))
    fill("#identifierId", "kit@acme.test")
    expect(plan(true)).toBe("error")
    page(email.replace('id="identifierId"', 'id="identifierId" aria-invalid="true"'))
    fill("#identifierId", "kit@acme.test")
    expect(plan(true)).toBe("error")
  })

  test("an empty alert region is no error", () => {
    page(email.replace("</main>", `<div role="alert" aria-live="assertive"></div></main>`))
    fill("#identifierId", "kit@acme.test")
    expect(typeof plan(true)).toBe("object")
  })

  test("a first step that asks to confirm something else isn't a sign-in", () => {
    page(email.replace("<h1>Sign in</h1>", "<h1>Delete your account</h1>"), "Delete your account")
    fill("#identifierId", "kit@acme.test")
    expect(plan(true)).toBe("first")
  })

  const code = (prompt: string) => `<main><h1>2-Step Verification</h1><div data-profile-identifier>kit@acme.test</div>
    <p>${prompt}</p><input type="tel" name="totpPin" id="totpPin" autocomplete="one-time-code" aria-label="Enter code">
    <button type="button">Try another way</button>${NEXT}</main>`

  test("an authenticator code step submits, reading past the session's own account chip", () => {
    page(code("Get a verification code from the Google Authenticator app"))
    fill("#totpPin", "492039")
    expect(typeof plan(false, "kit@acme.test")).toBe("object")
    // Without the account, the chip's address reads as where a code went.
    expect(plan(false)).toBe("delivered")
  })

  test("a code sent by text is the person's to bring", () => {
    page(code("A text message with a 6-digit verification code was just sent to •••• 0123"))
    fill("#totpPin", "492039")
    // The scan already offers no code box there; were one found, the submit still refuses.
    const scan = scanPage()
    const el = document.querySelector<HTMLInputElement>("#totpPin")!
    const fields = [{ el, role: "otp" as const, owner: { form: null, parent: el.parentElement } }] as unknown as typeof scan.fields
    expect(submitPlan({ kind: "mfa", fields, submit: document.querySelector("#next")!, first: false, account: "kit@acme.test" })).toBe("delivered")
  })
})

describe("a form", () => {
  const form = (attrs: string) => `<form ${attrs}><h1>Sign in</h1>
    <input name="username" autocomplete="username"><input type="password" name="password" autocomplete="current-password">
    <button type="submit">Sign in</button></form>`

  test("a POST to this origin submits", () => {
    page(form(`method="post" action="/session"`))
    fill("input[name=username]", "kit")
    fill("input[name=password]", "correct horse")
    const p = plan(true)
    expect(typeof p === "object" && p.form).toBeInstanceOf(HTMLFormElement)
  })

  test("a GET, another origin or another tab doesn't", () => {
    for (const attrs of [`action="/session"`, `method="post" action="https://evil.test/session"`, `method="post" target="_blank"`]) {
      page(form(attrs))
      fill("input[name=username]", "kit")
      fill("input[name=password]", "correct horse")
      expect(plan(true)).toBe("destination")
    }
  })

  test("a sign-up form isn't a sign-in step", () => {
    page(`<form method="post"><h1>Create your account</h1><input name="email" autocomplete="email">
      <input type="password" name="new" autocomplete="new-password"><input type="password" name="confirm" autocomplete="new-password">
      <button type="submit">Next</button></form>`, "Create your account")
    fill("input[name=email]", "kit@acme.test")
    fill("input[name=new]", "x")
    fill("input[name=confirm]", "x")
    expect(plan()).toBe("kind")
  })
})

describe("accountChip", () => {
  test("only when every visible chip is exactly the account", () => {
    page(`<div data-profile-identifier>Kit@Acme.test</div>`)
    expect(accountChip("kit@acme.test")).toBe("kit@acme.test")
    expect(accountChip("olive@acme.test")).toBeUndefined()
    page(`<div data-profile-identifier>kit@acme.test</div><div data-profile-identifier>olive@acme.test</div>`)
    expect(accountChip("kit@acme.test")).toBeUndefined()
    page(`<p>kit@acme.test</p>`)
    expect(accountChip("kit@acme.test")).toBeUndefined()
  })
})
