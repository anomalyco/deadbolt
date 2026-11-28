import { afterEach, describe, expect, test } from "bun:test"
import { scanPage } from "../src/content/detect"
import { scanForms } from "../src/content/forms"
import { scanGraph } from "../src/content/graph"

function page(html: string, path = "/login", title = "") {
  history.replaceState(null, "", path)
  document.title = title
  document.body.innerHTML = html
}
const setURL = (url: string) => (window as unknown as { happyDOM: { setURL(u: string): void } }).happyDOM.setURL(url)
const MONTHS = Array.from({ length: 12 }, (_, i) => `<option value="${i + 1}">${String(i + 1).padStart(2, "0")}</option>`).join("")
const ids = (els: Element[]) => els.map((el) => el.id)
const digits = (prefix: string, label: string) =>
  [1, 2, 3, 4, 5, 6].map((i) => `<input id="${prefix}${i}" maxlength="1" inputmode="numeric" aria-label="${label}, digit ${i}">`).join("")

afterEach(() => {
  document.body.innerHTML = ""
  setURL("https://example.com/login")
})

describe("clusters", () => {
  test("a form is one; outside forms, the nearest section-like container; else the page", () => {
    page(`<header><input id="q" placeholder="Search the shop"><button>Go</button></header>
      <main><form id="f"><input id="u" autocomplete="username"><input id="p" type="password"></form><section><input id="zip" placeholder="ZIP"></section></main>
      <div><input id="loose"></div>`)
    const graph = scanGraph()
    expect(graph.clusters.map((c) => [c.root?.localName ?? null, ids(c.controls)])).toEqual([
      ["header", ["q"]],
      ["form", ["u", "p"]],
      ["section", ["zip"]],
      [null, ["loose"]],
    ])
    expect(graph.clusterOf(document.getElementById("p")!)?.form).toBe(document.getElementById("f") as HTMLFormElement)
  })

  test("a page-sized form isn't one form: its parts are", () => {
    const rows = Array.from({ length: 60 }, (_, i) => `<input id="r${i}" name="row${i}">`).join("")
    page(`<form id="aspnet"><section id="login"><input id="u" autocomplete="username"><input id="p" type="password"></section><section>${rows}</section></form>`)
    const graph = scanGraph()
    expect(graph.clusterOf(document.getElementById("p")!)?.root?.id).toBe("login")
    expect(graph.clusterOf(document.getElementById("p")!)?.form).toBeNull()
  })

  test("a box in a web component inside a form is the form's", () => {
    page(`<form id="f"><input id="u" autocomplete="username"><pw-box></pw-box></form>`)
    const inner = document.querySelector("pw-box")!.attachShadow({ mode: "open" })
    inner.innerHTML = `<input id="p" type="password">`
    const graph = scanGraph()
    expect(graph.clusters).toHaveLength(1)
    expect(graph.clusterOf(inner.getElementById("p")!)?.root?.id).toBe("f")
  })

  test("the fingerprint is the form's shape, never its values", () => {
    page(`<form><input id="u" autocomplete="username"><input id="p" type="password" maxlength="64"></form>`)
    const before = scanGraph().clusters[0].fingerprint
    ;(document.getElementById("u") as HTMLInputElement).value = "kit@example.com"
    ;(document.getElementById("p") as HTMLInputElement).value = "hunter2"
    expect(scanGraph().clusters[0].fingerprint).toBe(before)
    expect(before).toMatch(/^[0-9a-f]{8}$/)
    document.querySelector("form")!.insertAdjacentHTML("beforeend", `<input id="otp" autocomplete="one-time-code">`)
    expect(scanGraph().clusters[0].fingerprint).not.toBe(before)
  })

  test("one graph serves both scans, as the roots would", () => {
    page(`<form><input autocomplete="email" id="e"><input type="password" id="p" autocomplete="current-password"><button>Sign in</button></form>
      <form><input id="n" autocomplete="name"><input id="a1" autocomplete="address-line1"><input id="z" autocomplete="postal-code"></form>`)
    const graph = scanGraph()
    expect(scanPage(graph)).toEqual(scanPage())
    expect(scanForms(graph)).toEqual(scanForms())
  })
})

describe("scoped login detection", () => {
  test("two six-box code groups in two forms: the authenticator's is the code, the texted one isn't", () => {
    page(`<h1>Verify it's you</h1>
      <form id="totp"><h2>Authenticator app</h2>${digits("a", "Authenticator code")}<button>Verify</button></form>
      <form id="sms"><h2>Text message</h2><p>Or enter the code we texted to your phone.</p>${digits("s", "Texted code")}<button>Verify</button></form>`, "/login/verify")
    const result = scanPage()
    expect(result.kind).toBe("mfa")
    expect(result.fields.map((f) => [f.el.id, f.role, f.split])).toEqual([1, 2, 3, 4, 5, 6].map((i) => [`a${i}`, "otp", 6]))
  })

  test("a page asking for two codes it sent, in two forms, is no sign-in step", () => {
    page(`<h1>Verify your contact details</h1>
      <form><p>We sent a code to your email.</p>${digits("e", "Email code")}<button>Verify email</button></form>
      <form><p>We texted a code to your phone.</p>${digits("t", "Phone code")}<button>Verify phone</button></form>`, "/account/verify-contact")
    expect(scanPage().kind).toBeNull()
  })

  test("a password box no one can see or reach isn't a field: Google's hiddenPassword", () => {
    page(`<form><input type="email" id="id" autocomplete="username webauthn" aria-label="Email or phone">
      <div aria-hidden="true" style="opacity:0"><input type="password" name="hiddenPassword" tabindex="-1" aria-hidden="true"></div>
      <div role="button" id="next">Next</div></form>`, "/v3/signin/identifier")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.fields.map((f) => [f.el.id, f.role])).toEqual([["id", "username"]])
  })

  test("a collapsed password box, faded out under aria-hidden, waits for its step", () => {
    page(`<form><label for="u">Email</label><input id="u" name="identifier">
      <div aria-hidden="true" style="opacity:0"><input type="password" id="p" autocomplete="current-password"></div><button>Continue</button></form>`, "/sign-in")
    expect(scanPage().fields.map((f) => f.role)).toEqual(["email"])
  })

  test("the host's name never makes a login: a blog on author.example.com", () => {
    setURL("https://author.example.com/posts/hello")
    page(`<form><label for="e">Email</label><input id="e" type="email" autocomplete="email"><button>Post comment</button></form>`, "/posts/hello")
    expect(scanPage().kind).toBeNull()
  })

  test("a bank's Online ID and Passcode are a username and password", () => {
    page(`<form><label for="id">Online ID</label><input id="id" name="onlineId" maxlength="32">
      <label for="pc">Passcode</label><input id="pc" name="passcode" type="password" maxlength="20"><button type="submit">Log In</button></form>`, "/")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.fields.map((f) => [f.el.id, f.role])).toEqual([["id", "username"], ["pc", "password"]])
  })

  test("a transfer's PIN, a product's purchase code and a gift card's access number are no sign-in", () => {
    page(`<form><label for="n">Payee name</label><input id="n"><label for="a">Amount</label><input id="a" inputmode="decimal">
      <label for="pin">Confirm with your 4-digit PIN</label><input id="pin" type="password" inputmode="numeric" maxlength="4"><button>Send money</button></form>`, "/transfers/new")
    expect(scanPage().kind).toBeNull()
    page(`<form><label for="m">Model number</label><input id="m"><label for="s">Serial number</label><input id="s">
      <label for="c">6-digit purchase code</label><input id="c" inputmode="numeric" maxlength="6"><label for="e">Email</label><input id="e" type="email" autocomplete="email"><button>Register</button></form>`, "/register")
    expect(scanPage().kind).toBeNull()
    page(`<section><h2>Gift card</h2><form><label for="g">Gift card number</label><input id="g" inputmode="numeric" maxlength="15">
      <label for="pin">Access number</label><input id="pin" type="password" inputmode="numeric" maxlength="8"><button>Apply gift card</button></form></section>`, "/cart")
    expect(scanPage()).toMatchObject({ kind: null, fields: [] })
  })

  test("a secret the page shows, read-only, isn't a password to fill", () => {
    page(`<section><label for="k">Secret key</label><input id="k" type="password" readonly><button>Reveal</button></section>`, "/apikeys")
    expect(scanPage().kind).toBeNull()
  })

  test("new passwords with no box for who you are change one, not sign up", () => {
    page(`<form><label for="n">New password</label><input id="n" type="password" autocomplete="new-password">
      <label for="c">Confirm new password</label><input id="c" type="password" autocomplete="new-password"><button>Change password</button></form>`, "/signinoptions/password")
    expect(scanPage().kind).toBe("change-password")
  })

  test("a gift card form above a real email-first sign-in doesn't hide it", () => {
    page(`<section><h2>Send a gift card</h2><form id="gift"><label for="to">Recipient's email</label><input id="to" type="email">
      <button>Send gift card</button></form></section>
      <form id="login"><h2>Sign in</h2><label for="e">Email</label><input id="e" type="email" autocomplete="username"><button type="submit">Continue</button></form>`, "/checkout")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.fields.map((f) => [f.el.id, f.role])).toEqual([["e", "username"]])
  })

  test("a sign-in's first step with a workspace, a region and a work email is still a login", () => {
    page(`<h1>Sign in</h1><form><label for="w">Workspace</label><input id="w" name="workspace">
      <label for="r">Region</label><select id="r" name="region"><option>US</option><option>EU</option></select>
      <label for="e">Work email</label><input id="e" type="email" name="email"><button type="submit">Sign in</button></form>`, "/login")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.fields.map((f) => [f.el.id, f.role])).toEqual([["e", "email"]])
  })

  test("a masked 2FA box with no maxlength beside the password stays a code", () => {
    page(`<form><label for="u">Username</label><input id="u" name="username">
      <label for="p">Password</label><input id="p" type="password" name="password">
      <label for="t">Two-factor code</label><input id="t" type="password" name="mfa"><button type="submit">Sign in</button></form>`, "/login")
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.fields.map((f) => [f.el.id, f.role])).toEqual([["u", "username"], ["p", "password"], ["t", "otp"]])
  })

  test("a form's submit button inside a web component is still its submit", () => {
    page(`<form><label for="u">Username</label><input id="u" autocomplete="username"><label for="p">Password</label><input id="p" type="password" autocomplete="current-password"><my-button></my-button></form>`, "/login")
    const inner = document.querySelector("my-button")!.attachShadow({ mode: "open" })
    inner.innerHTML = `<button type="submit" id="go">Sign in</button>`
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.submit).toBe(inner.getElementById("go")!)
  })

  test("two forms each asking for a code they sent, in one box each, are no sign-in step", () => {
    page(`<h1>Verify your contact details</h1>
      <form><p>We sent a code to your email.</p><label for="ec">Verification code</label><input id="ec" inputmode="numeric" maxlength="6"><button>Verify email</button></form>
      <form><p>We texted a code to your phone.</p><label for="pc">Verification code</label><input id="pc" inputmode="numeric" maxlength="6"><button>Verify phone</button></form>`, "/account/verify-contact")
    expect(scanPage()).toMatchObject({ kind: null, fields: [] })
  })

  test("a box under aria-hidden through a shadow host, out of the tab order, is concealed", () => {
    page(`<form><label for="u">Email</label><input id="u" type="email" autocomplete="username"><div aria-hidden="true"><pw-box></pw-box></div><button>Next</button></form>`, "/login")
    const inner = document.querySelector("pw-box")!.attachShadow({ mode: "open" })
    inner.innerHTML = `<input type="password" id="trap" tabindex="-1">`
    expect(scanPage().fields.map((f) => f.el.id)).toEqual(["u"])
  })
})

describe("scoped identity and card detection", () => {
  test("a gift card's number and code aren't a payment card", () => {
    page(`<h1>Check your gift card balance</h1><form><label for="n">Card number</label><input id="n" inputmode="numeric" maxlength="16">
      <label for="c">Security code</label><input id="c" inputmode="numeric" maxlength="8"><button>Check balance</button></form>`, "/gift/balance")
    expect(scanForms()).toEqual([])
  })

  test("a payment card with an expiry is one, gift card words or not", () => {
    page(`<h2>Pay with a card or gift card</h2><form><label for="n">Card number</label><input id="n"><label for="x">Expiry (MM/YY)</label><input id="x">
      <label for="c">Security code</label><input id="c"></form>`, "/checkout")
    expect(scanForms().map((f) => f.role)).toEqual(["cc-number", "cc-exp", "cc-csc"])
  })

  test("a card with month and year dropdowns is a payment card, beside gift card words", () => {
    page(`<section><h2>Pay with credit card or gift card</h2><form><label for="n">Card number</label><input id="n">
      <label for="m">Month</label><select id="m"><option value="">Month</option>${MONTHS}</select>
      <label for="y">Year</label><select id="y"><option value="">Year</option>${Array.from({ length: 10 }, (_, i) => `<option>${new Date().getFullYear() + i}</option>`).join("")}</select>
      <label for="c">Security code</label><input id="c"></form></section>`, "/checkout")
    expect(scanForms().map((f) => [f.el.id, f.role])).toEqual([["n", "cc-number"], ["m", "cc-exp-month"], ["y", "cc-exp-year"], ["c", "cc-csc"]])
  })

  test("a URL box isn't an address", () => {
    page(`<form><label for="t">Site title</label><input id="t"><label for="u">WordPress Address (URL)</label><input id="u" type="url">
      <label for="e">Administration Email Address</label><input id="e" type="email"></form>`, "/wp-admin/options-general.php")
    expect(scanForms().map((f) => f.role)).not.toContain("address-line1")
  })
})
