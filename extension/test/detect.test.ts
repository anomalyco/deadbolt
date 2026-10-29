import { afterEach, describe, expect, test } from "bun:test"
import { findAccountTile, findProviderButton, scanPage, signInWithText } from "../src/content/detect"
import { isChooserPage, isProviderPage, provider } from "../src/signin"
import { pageFacts } from "../src/content/outcome"

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

describe("sites that opt out", () => {
  const form = (attrs = "", fieldAttrs = "") => `
    <form ${attrs}>
      <input name="username" autocomplete="username" ${fieldAttrs}>
      <input type="password" name="password" autocomplete="current-password" ${fieldAttrs}>
      <button type="submit">Sign in</button>
    </form>`

  test("on the field, the form or the page", () => {
    for (const mark of ["data-1p-ignore", "data-op-ignore", 'data-lpignore="true"', "data-bwignore", 'data-form-type="other"', "data-deadbolt-ignore"]) {
      page(form(mark))
      expect(scanPage().fields).toEqual([])
      page(form("", mark))
      expect(scanPage().fields).toEqual([])
    }
    page(form())
    document.body.setAttribute("data-1p-ignore", "")
    expect(scanPage().fields).toEqual([])
    document.body.removeAttribute("data-1p-ignore")
    page(form('data-lpignore="false"', 'data-1p-ignore="false"'))
    expect(roles()).toEqual(["username", "password"])
  })
})

describe("what the page shows after a sign-in", () => {
  const facts = (html: string, username?: string, path = "/", title = "") => {
    page(html, path, title)
    const scan = scanPage()
    return pageFacts(scan.kind, scan.fields, username)
  }

  test("a signed-in page with the account and Sign out", () => {
    const f = facts(`<header><span>kit@example.com</span><a href="/logout">Sign out</a></header><h1>Dashboard</h1>`, "kit@example.com", "/home")
    expect(f).toEqual({ loginForm: false, passwordEmpty: false, mfa: false, error: false, challenge: false, account: true, signOut: true, loginish: false })
  })

  test("an email's name before the @, in a label", () => {
    expect(facts(`<img alt="Avatar for kitsune" src="a.png">`, "kitsune@example.com").account).toBe(true)
    expect(facts(`<p>Welcome</p>`, "kit@example.com").account).toBe(false)
    // Whole words, and four characters at least.
    expect(facts(`<p>Your toolkit</p>`, "kit").account).toBe(false)
    expect(facts(`<p>kit</p>`, "kit").account).toBe(false)
    expect(facts(`<p>Administrator tools</p>`, "admin").account).toBe(false)
    expect(facts(`<p>Signed in as admin.</p>`, "admin").account).toBe(true)
    expect(facts(`<p>Hi kitsune!</p>`, "kitsune@example.com").account).toBe(true)
    expect(facts(`<p>kitsunes</p>`, "kitsune@example.com").account).toBe(false)
    // Not hidden text or a field's value.
    expect(facts(`<p hidden>kit@example.com</p><input value="kit@example.com">`, "kit@example.com").account).toBe(false)
  })

  test("an error, in an alert or an error box", () => {
    expect(facts(`<div role="alert">Incorrect password. Try again.</div>`).error).toBe(true)
    expect(facts(`<p class="form-Error">Too many attempts</p>`).error).toBe(true)
    expect(facts(`<p class="login-error">Mot de passe incorrect</p>`).error).toBe(true)
    expect(facts(`<div role="alert">Welcome back!</div><p>Incorrect is a word</p>`).error).toBe(false)
    expect(facts(`<div role="alert" hidden>Wrong password</div>`).error).toBe(false)
    // Generic words count only by a login form; notice boxes only short and by it.
    expect(facts(`<div role="alert">Your trial expired</div>`).error).toBe(false)
    expect(facts(`<div class="alert">Wrong password</div>`).error).toBe(false)
    expect(facts(`<div aria-live="polite">Upload failed</div>`).error).toBe(false)
    const login = `<form><input name="username" autocomplete="username"><input type="password" autocomplete="current-password"><button>Sign in</button></form>`
    expect(facts(`<div class="alert">Session expired. Try again.</div>${login}`, undefined, "/login").error).toBe(true)
    expect(facts(`<div role="alert">Account locked</div>${login}`, undefined, "/login").error).toBe(true)
    // A whole section that happens to be an error box isn't read.
    expect(facts(`<div class="errors">${"<p>Wrong password</p>".repeat(20)}</div>`).error).toBe(false)
  })

  test("the form back with an empty password, and a field marked invalid", () => {
    const f = facts(`<form><input name="username" autocomplete="username" aria-invalid="true"><input type="password" autocomplete="current-password"><button>Sign in</button></form>`, "kit", "/login")
    expect(f).toMatchObject({ loginForm: true, passwordEmpty: true, error: true, loginish: true })
  })

  test("a challenge", () => {
    expect(facts(`<p>Checking your browser</p>`, undefined, "/", "Just a moment...").challenge).toBe(true)
    // (happy-dom loads no frames, so captcha frames are left to the e2e run.)
    expect(facts(`<div class="g-recaptcha" data-size="invisible"></div>`).challenge).toBe(false)
    expect(facts(`<div class="cf-turnstile"></div>`).challenge).toBe(true)
    // A captcha box counts only on a login form.
    page(`<input id="c">`)
    const el = document.getElementById("c") as HTMLInputElement
    const captcha = [{ el, role: "captcha" as const, owner: { form: null, parent: el.parentNode } }]
    expect(pageFacts(null, captcha).challenge).toBe(false)
    expect(pageFacts("login", captcha).challenge).toBe(true)
  })

  test("a code step", () => {
    const f = facts(`<form><label for="c">Authentication code</label><input id="c" autocomplete="one-time-code" inputmode="numeric"><button>Verify</button></form>`, "kit", "/mfa")
    expect(f).toMatchObject({ mfa: true, loginForm: false })
  })
})

describe("sign in with a provider", () => {
  const google = provider("google")

  test("button text that asks to sign in with the provider, and little else", () => {
    for (const yes of ["Sign in with Google", "Continue with Google", "Log in via Google", "SIGN IN WITH GOOGLE", "Sign up with Google", "Continue with your Google account", "Google – Sign in"])
      expect([yes, signInWithText(yes, google)]).toEqual([yes, true])
    for (const no of ["Sign in with Google to sync your calendar", "Share on Google", "Follow us on Google", "Google", "Sign in", "Continue with Apple", "Learn how we use Google to sign you in"])
      expect([no, signInWithText(no, google)]).toEqual([no, false])
    expect(signInWithText("Continue with your Apple ID", provider("apple"))).toBe(true)
    expect(signInWithText("Sign in with X", provider("x"))).toBe(true)
    expect(signInWithText("Sign in to X Corp's blog with your email", provider("x"))).toBe(false)
  })

  test("finds the site's button, not a sentence about it or a share button", () => {
    page(`<p><a href="/about">Sign in with Google to sync your calendar</a></p>
      <button id="share">Share on Google</button>
      <div class="social"><button id="go" type="button"><img alt="" src="g.svg"><span>Continue with Google</span></button></div>`, "/login")
    expect(findProviderButton(google)?.id).toBe("go")
    page(`<a id="tagged" href="/auth/google" data-provider="google"><img alt="Google"></a>`, "/login")
    expect(findProviderButton(google)?.id).toBe("tagged")
    page(`<div id="gis" class="g_id_signin"></div>`, "/login")
    expect(findProviderButton(google)?.id).toBe("gis")
    page(`<button>Share on Google</button><a href="/x">Sign in with Google to sync your calendar</a>`, "/login")
    expect(findProviderButton(google)).toBeNull()
  })

  test("finds the chooser tile for the account", () => {
    page(`<ul><li><div role="link" id="a" data-identifier="other@gmail.com">Other<br>other@gmail.com</div></li>
      <li><div role="link" id="b" data-identifier="Kit@Gmail.com">Kit<br>kit@gmail.com</div></li></ul>`, "/signin")
    expect(findAccountTile("kit@gmail.com")?.id).toBe("b")
    // Never by text alone: the page's own text could name anyone.
    page(`<ul><li id="c"><button id="d">Kit Mercer kit@gmail.com</button></li></ul>`, "/signin")
    expect(findAccountTile("kit@gmail.com")).toBeNull()
    expect(findAccountTile("someone@gmail.com")).toBeNull()
  })

  test("provider pages: its own hosts over https; .test hosts only in an e2e build", () => {
    expect(isProviderPage(google, "https://accounts.google.com/signin")).toBe(true)
    expect(isProviderPage(google, "http://accounts.google.com/signin")).toBe(false)
    expect(isProviderPage(google, "http://accounts.google.test:8080/x")).toBe(false)
    expect(isProviderPage(google, "https://accounts.google.test/x")).toBe(false)
    expect(isProviderPage(google, "https://mail.google.com/")).toBe(false)
    expect(isProviderPage(provider("Acme SSO"), "https://acme.com/")).toBe(false)
    // Only Google's chooser gets the account; GitHub's pages are its users' too.
    expect(isChooserPage(google, "https://accounts.google.com/")).toBe(true)
    expect(isChooserPage(provider("github"), "https://github.com/login")).toBe(false)
    expect(isProviderPage(provider("github"), "https://github.com/login")).toBe(true)
    const g = globalThis as { DEADBOLT_E2E?: boolean }
    g.DEADBOLT_E2E = true
    try {
      expect(isProviderPage(google, "http://accounts.google.test:8080/x")).toBe(true)
      expect(isProviderPage(google, "http://accounts.google.com.evil.test/x")).toBe(false)
    } finally {
      delete g.DEADBOLT_E2E
    }
  })
})
