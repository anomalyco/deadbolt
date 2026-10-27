import { afterEach, describe, expect, test } from "bun:test"
import { scanPage } from "../src/content/detect"

function page(html: string, path = "/login", title = "") {
  history.replaceState(null, "", path)
  document.title = title
  document.body.innerHTML = html
}

const roles = () => scanPage().fields.map((f) => f.role)

afterEach(() => {
  document.body.innerHTML = ""
})

describe("login forms", () => {
  test("username and password", () => {
    page(`
      <form>
        <label for="u">Username</label><input id="u" name="username" autocomplete="username">
        <label for="p">Password</label><input id="p" type="password" name="password" autocomplete="current-password">
        <button type="submit">Sign in</button>
      </form>`)
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.fields.map((f) => f.role)).toEqual(["username", "password"])
    expect(result.submit?.textContent).toBe("Sign in")
  })

  test("email-first step", () => {
    page(
      `<h1>Sign in</h1>
      <form><input type="email" name="email" placeholder="you@example.com" autocomplete="username"><button>Continue</button></form>`,
      "/signin/identifier",
    )
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.fields.map((f) => f.role)).toEqual(["email"])
  })

  test("password step alone", () => {
    page(`<h1>Enter your password</h1><form><input type="password" name="passwd"><button>Next</button></form>`, "/signin/challenge")
    expect(scanPage().kind).toBe("login")
    expect(roles()).toEqual(["password"])
  })

  test("hidden fields are ignored", () => {
    page(`
      <form>
        <input name="username"><input type="password" name="password">
        <div hidden><input type="password" name="trap"></div>
        <button>Log in</button>
      </form>`)
    expect(roles()).toEqual(["username", "password"])
  })

  test("a login form without <form>", () => {
    page(`<div><input name="login" placeholder="Email or username"><input type="password" placeholder="Password"><button>Log in</button></div>`)
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.fields.map((f) => f.role)).toEqual(["username", "password"])
  })
})

describe("other forms", () => {
  test("sign-up: new passwords, not a login", () => {
    page(
      `<h1>Create your account</h1>
      <form>
        <input type="email" name="email" autocomplete="email">
        <input type="password" name="password" autocomplete="new-password">
        <input type="password" name="confirm" autocomplete="new-password">
        <button>Create account</button>
      </form>`,
      "/signup",
    )
    const result = scanPage()
    expect(result.kind).toBe("signup")
    expect(result.fields.map((f) => f.role)).toEqual(["email", "new-password", "new-password"])
  })

  test("change password: current then new", () => {
    page(
      `<h1>Change password</h1>
      <form>
        <label for="a">Current password</label><input id="a" type="password" autocomplete="current-password">
        <label for="b">New password</label><input id="b" type="password" autocomplete="new-password">
        <label for="c">Confirm new password</label><input id="c" type="password" autocomplete="new-password">
        <button>Update password</button>
      </form>`,
      "/settings/security",
    )
    const result = scanPage()
    expect(result.kind).toBe("change-password")
    expect(result.fields.map((f) => f.role)).toEqual(["password", "new-password", "new-password"])
  })

  test("one-time code split into boxes", () => {
    page(
      `<h1>Two-factor authentication</h1><p>Enter the 6-digit code from your authenticator app</p>
      <form>${'<input maxlength="1" inputmode="numeric">'.repeat(6)}<button>Verify</button></form>`,
      "/2fa",
    )
    const result = scanPage()
    expect(result.kind).toBe("mfa")
    expect(result.fields).toHaveLength(6)
    expect(result.fields.every((f) => f.role === "otp" && f.split === 6)).toBe(true)
  })

  test("one-time code in one box", () => {
    page(
      `<h1>Verify it's you</h1><form><label for="c">Authentication code</label><input id="c" name="otp" autocomplete="one-time-code" inputmode="numeric"><button>Verify</button></form>`,
      "/mfa",
    )
    expect(scanPage().kind).toBe("mfa")
    expect(roles()).toEqual(["otp"])
  })

  test("a search box is nothing", () => {
    page(`<form role="search"><input type="search" name="q" placeholder="Search"><button>Go</button></form>`, "/")
    const result = scanPage()
    expect(result.kind).toBeNull()
    expect(result.fields).toEqual([])
  })
})

describe("shadow DOM", () => {
  test("finds a login form inside open shadow roots", () => {
    page(`<login-card></login-card>`)
    const outer = document.querySelector("login-card")!.attachShadow({ mode: "open" })
    outer.innerHTML = `<form><input name="username" autocomplete="username"><password-box></password-box><button type="submit">Sign in</button></form>`
    const inner = outer.querySelector("password-box")!.attachShadow({ mode: "open" })
    inner.innerHTML = `<input type="password" name="password" autocomplete="current-password">`
    const result = scanPage()
    expect(result.kind).toBe("login")
    expect(result.fields.map((f) => f.role)).toEqual(["username", "password"])
    expect(result.fields[1].el.getRootNode()).toBe(inner)
  })
})

describe("frames", () => {
  // The content script runs in every frame, and each copy scans only its own
  // document. Which frames may receive logins is decided in the background
  // (see site.test.ts).
  test("the page around a login iframe has no login form of its own", () => {
    page(`<h1>Welcome</h1><iframe srcdoc="<form><input name=username><input type=password name=password><button>Sign in</button></form>"></iframe>`, "/")
    const result = scanPage()
    expect(result.kind).toBeNull()
    expect(result.fields).toEqual([])
  })

  test("inside the frame, the same markup is a login form", () => {
    page(`<form><input name="username"><input type="password" name="password"><button>Sign in</button></form>`, "/embed/login")
    expect(scanPage().kind).toBe("login")
  })
})
