// End-to-end run of the extension in headless Chromium against a fake
// native host (e2e/fake-host.py) and local test pages. It builds its own copy
// first (scripts/build.ts --e2e, into a temporary directory), the only build
// whose provider pages may be on `.test` hosts. Nothing here touches a
// real browser profile or vault: each run uses a fresh profile directory with
// the fake host's manifest in it.
//
//   bun run e2e [--standalone] [--stills <dir>] [--video <dir>] [--only <scenario>,<scenario>] [--shard <i>/<n>] [--list] [--dist <dir>]
//
// `--video <dir>` records the `film` run (the menu, a fill, a sign-in and
// the save offer in the page) to <dir>/deadbolt-surface.webm.
//
// `--dist <dir>` uses an e2e build already made there (scripts/build.ts
// --e2e <dir>) instead of building, so parallel shards share one build.
//
// `--only security` is the fast subset CI runs first: hidden and covered fields, form
// swaps, opaque origins, value swaps, navigation during a fill and the
// back/forward cache.
//
// `--standalone` runs the same scenarios against the browser-only device
// (bg/standalone.ts, a `--standalone` e2e build) and its real wasm vault
// instead of the fake host: each profile creates a vault through the
// extension's own page and saves the fake host's logins, identities and
// card into it (seedVault), and the host log is what the service worker
// sent the vault. The fake host's other knobs have counterparts there (a
// locked vault, one never set up, slow or rate-limited answers from the
// worker's side). Native-agent passkey and Touch ID scenarios are skipped
// by name; e2e/standalone.ts covers real standalone passkeys and Strict reauth.
//
// `--deadbolt <path to the deadbolt binary>` adds the passkey run, which
// needs a real agent to sign: it makes a throwaway store (fast KDF, local
// network only) in the run's temporary directory, runs that binary as the
// host, and checks each credential with @simplewebauthn/server.
//
// Needs Playwright's Chromium (`bunx playwright-core install chromium`).

import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse, type WebAuthnCredential } from "@simplewebauthn/server"
import { chromium, type BrowserContext, type Frame, type Page, type Worker } from "playwright-core"
import { createHmac } from "node:crypto"
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { VAULT_REQUEST } from "../src/bg/vault-messages"

const ID = "jhocodkhpifjndffenppfmdkmiolngal"
const root = join(import.meta.dir, "..")
const arg = (name: string) => {
  const i = process.argv.indexOf(name)
  return i > 0 ? process.argv[i + 1] : undefined
}
// An e2e build of its own (DEADBOLT_E2E: provider pages on .test hosts), never dist/.
const standalone = process.argv.includes("--standalone")
const prebuilt = arg("--dist")
const dist = prebuilt ?? (await mkdtemp(join(tmpdir(), "deadbolt-e2e-dist-")))
if (!prebuilt) {
  const built = Bun.spawnSync(["bun", join(root, "scripts", "build.ts"), "--e2e", dist, standalone ? "--standalone" : "--native"], { stdout: "inherit", stderr: "inherit" })
  if (!built.success) throw new Error("the e2e build failed")
}
const stills = arg("--stills")
const video = arg("--video")
const only = arg("--only")
// Absolute: Chromium reads a relative host path in the manifest as relative to the manifest.
const deadbolt = arg("--deadbolt") && resolve(arg("--deadbolt")!)
if (stills) await mkdir(stills, { recursive: true })
if (video) await mkdir(video, { recursive: true })

// ---- Test pages ---------------------------------------------------------------

/** Google's password step, the real page's markup (see the /v3/signin/challenge/pwd route). */
const GOOGLE_PWD = await readFile(join(import.meta.dir, "google-pwd-step.html"), "utf8")

const html = (title: string, body: string, headers: Record<string, string> = {}) =>
  new Response(
    `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><style>
      body{font:15px/1.5 -apple-system,system-ui,sans-serif;margin:0;background:#f4f4f5;color:#18181b}
      @media (prefers-color-scheme:dark){body{background:#0f0f10;color:#e4e4e7}input{background:#1c1c1f;color:#e4e4e7;border-color:#3f3f46}}
      main{max-width:360px;margin:72px auto;padding:28px;border-radius:14px;background:color-mix(in srgb,currentColor 4%,transparent)}
      h1{font-size:22px;margin:0 0 18px}label{display:block;font-size:13px;margin:12px 0 4px}
      input{width:100%;box-sizing:border-box;height:38px;padding:0 10px;border:1px solid #d4d4d8;border-radius:8px;font:inherit}
      button{margin-top:18px;width:100%;height:38px;border:0;border-radius:8px;background:#18181b;color:#fff;font:inherit}
    </style></head><body><main>${body}</main></body></html>`,
    { headers: { "content-type": "text/html; charset=utf-8", ...headers } },
  )

// What a page could watch for: elements added outside <body>, and focus leaving it.
const PROBE = () => {
  const probe = { added: [] as string[], blurs: 0 }
  ;(window as unknown as { __probe: typeof probe }).__probe = probe
  // Init scripts can run before <html> exists: watch the document, and keep what lands on <html> itself.
  new MutationObserver((records) => {
    for (const r of records)
      if (r.target === document.documentElement) for (const n of Array.from(r.addedNodes)) if (n.nodeName !== "HEAD" && n.nodeName !== "BODY" && n.nodeType === 1) probe.added.push(n.nodeName)
  }).observe(document, { childList: true, subtree: true })
  window.addEventListener("blur", () => probe.blurs++)
}

/** The page sees the menu's host element arrive (a popover); these pages misuse that. */
const onMenu = (js: string) => `<script>
  new MutationObserver((records) => {
    for (const r of records) for (const host of r.addedNodes) if (host.nodeType === 1 && host.hasAttribute("popover")) { ${js} }
  }).observe(document.documentElement, { childList: true })
</script>`

/**
 * Restyles the menu's host from script, every frame while `when` holds. Its
 * inline \`!important\` styles beat any stylesheet and Deadbolt sets them
 * again each frame, so a page has to keep at it.
 */
const restyle = (prop: string, value: string, when = "true") =>
  onMenu(`const loop = () => { if (!host.isConnected) return; if (${when}) host.style.setProperty("${prop}", "${value}", "important"); requestAnimationFrame(loop) }; loop()`)

/** Where the menu is, for a sheet over just it (one over the field too would stop the fill anyway). */
const overMenu = "const r = host.getBoundingClientRect(); const at = `left:${r.left}px;top:${r.top}px;width:${r.width}px;height:${r.height}px`"

/** A sheet in the top layer over the menu, shown `after` ms past it: in the page, or in a shadow root Deadbolt can't watch. */
const topCover = (where: "page" | "shadow", clicks: boolean, after = 50) =>
  onMenu(`setTimeout(() => {
    ${overMenu}
    const c = document.createElement("div")
    c.popover = "manual"
    c.style.cssText = "position:fixed;inset:auto;margin:0;padding:0;border:0;background:rgb(255 255 255 / 92%);pointer-events:${clicks ? "auto" : "none"};" + at
    if ("${where}" === "shadow") { const h = document.createElement("span"); document.body.append(h); h.attachShadow({ mode: "closed" }).append(c) } else document.body.append(c)
    c.showPopover()
  }, ${after})`)

const emailField = `<label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username">`
const passwordField = `<input id="password" name="password" type="password" autocomplete="current-password">`
const hiddenForm = (wrapped: string, extra = "") => `<h1>Sign in to Acme</h1><form method="post" action="/home" novalidate>
  ${emailField}<label>Password</label>${wrapped}<button type="submit">Sign in</button></form>${extra}`

// Ways a page can make a password field the user can't see.
const HIDDEN: Record<string, string> = {
  visible: hiddenForm(passwordField),
  "shadow-host": hiddenForm(`<div id="h" style="opacity:0"></div>`, `<script>document.getElementById("h").attachShadow({ mode: "open" }).innerHTML = '${passwordField}'</script>`),
  "closed-slot": hiddenForm(`<div id="h">${passwordField}</div>`, `<script>document.getElementById("h").attachShadow({ mode: "closed" }).innerHTML = '<div style="opacity:0.02"><slot></slot></div>'</script>`),
  clipped: hiddenForm(`<div style="clip-path:inset(50%)">${passwordField}</div>`),
  "zero-height": hiddenForm(`<div style="height:0;overflow:hidden">${passwordField}</div>`),
  offscreen: hiddenForm(`<div style="position:absolute;left:-2000px;width:300px">${passwordField}</div>`),
  // Visible until Deadbolt focuses it to write.
  "hide-on-focus": hiddenForm(`<div id="w">${passwordField}</div>`, `<script>document.getElementById("password").addEventListener("focus", () => document.getElementById("w").style.opacity = "0")</script>`),
}

// Ways a page can try to get a click into a menu the user can't see properly.
// The menu's host is a popover Deadbolt adds to <html>.
const OVERLAY: Record<string, string> = {
  none: "",
  fade: restyle("opacity", "0.4"),
  clip: restyle("clip-path", "inset(0 0 25% 0)"),
  // A near-opaque sheet over everything in the top layer, letting clicks
  // through to the menu, in a shadow root: Deadbolt can't see it go up.
  cover: topCover("shadow", false),
  // Fade it out the moment the click starts (focus moves into the menu), so a
  // visibility reading taken before the click is stale.
  "on-press": `<script>addEventListener("blur", () => (window.pressed = true))</script>${restyle("opacity", "0", "window.pressed")}`,
  // The reverse: keep it all but see-through over a decoy (still taking
  // clicks, which a fully transparent frame doesn't) and show it the moment
  // the press lands, so a reading taken after the click finds it visible.
  "reveal-on-press": `<script>addEventListener("blur", () => (window.pressed = true))</script>${restyle("opacity", "0.02", "!window.pressed")}`,
  // Shown a moment before the press instead (as the pointer nears it), so
  // nothing changes after the press: the test calls reveal() 250 ms before.
  "reveal-before-press": `<script>window.reveal = () => (window.revealed = true)</script>${restyle("opacity", "0.02", "!window.revealed")}`,
}

// Ways that no longer work on a menu in the top layer: it still fills.
const BEATEN: Record<string, string> = {
  // Stylesheets lose to its inline !important styles, whatever they aim at.
  css: `<style>[popover], :popover-open, html > :not(head, body) { opacity: 0.02 !important; clip-path: inset(50%) !important; transform: scale(0.5) !important }</style>`,
  // The highest z-index is still under the top layer.
  "z-index": onMenu(`setTimeout(() => { ${overMenu}; const c = document.createElement("section"); c.style.cssText = "position:fixed;z-index:2147483647;background:rgb(255 255 255 / 92%);" + at; document.documentElement.append(c) }, 50)`),
  // A popover shown after the menu: Deadbolt raises the menu back over it.
  "top-cover": topCover("page", true),
  // One in a shadow root that takes clicks: the menu's hit checks find it.
  "shadow-cover": topCover("shadow", true),
}

// Ways to show the site's login page in a frame. Hidden ones aren't fully
// transparent: such a frame takes no clicks, so it would prove nothing.
const loginFrame = (style = "", query = "") => `<iframe src="/login?next=home${query}" style="width:600px;height:460px;border:0;${style}"></iframe>`
const FRAMED: Record<string, string> = {
  visible: loginFrame(),
  hidden: loginFrame("opacity:0.02"),
  clipped: `<div style="height:40px;overflow:hidden">${loginFrame()}</div>`,
  offscreen: loginFrame("position:absolute;left:-2000px"),
  // A sheet over the frame that lets clicks through: no hit test sees it.
  covered: `${loginFrame()}<section style="position:fixed;inset:0;z-index:9;pointer-events:none;background:rgb(244 244 245 / 97%)"></section>`,
  // A frame inside a frame: visible all the way up, or hidden by the middle page.
  nested: `<iframe src="/framed/visible" style="width:700px;height:640px;border:0"></iframe>`,
  "nested-hidden": `<iframe src="/framed/hidden" style="width:700px;height:640px;border:0"></iframe>`,
  // A sheet over just the password box, which is disabled when the fill is
  // checked and enabled by the page as the email box is focused to fill it.
  "enabled-on-focus": `${loginFrame("", "&lock=password")}<section id="sheet" style="position:absolute;z-index:9;pointer-events:none;background:rgb(244 244 245 / 97%)"></section><script>
    const frame = document.querySelector("iframe")
    frame.addEventListener("load", () => {
      const f = frame.getBoundingClientRect()
      const p = frame.contentDocument.getElementById("password").getBoundingClientRect()
      Object.assign(document.getElementById("sheet").style, { left: \`\${scrollX + f.left + p.left - 6}px\`, top: \`\${scrollY + f.top + p.top - 6}px\`, width: \`\${p.width + 12}px\`, height: \`\${p.height + 12}px\` })
    })
  </script>`,
}

// Covers everything (letting clicks through) for `ms`, starting `after` ms
// past the press into the menu (the page's blur), or right away with cover().
// The cover is a popover in a shadow root, over the menu in the top layer.
const SWEEP = `<script>
  const cover = (ms) => {
    const h = document.createElement("span")
    const c = document.createElement("div")
    c.popover = "manual"
    c.style.cssText = "position:fixed;inset:0;margin:0;width:auto;height:auto;border:0;pointer-events:none;background:#fff"
    document.body.append(h)
    h.attachShadow({ mode: "closed" }).append(c)
    c.showPopover()
    window.__shown = performance.now()
    setTimeout(() => h.remove(), ms)
  }
  window.cover = cover
  window.coverAfterPress = (after, ms) => addEventListener("blur", () => (after ? setTimeout(() => cover(ms), after) : cover(ms)), { once: true })
  addEventListener("blur", () => (window.__press = performance.now()))
</script>`

const PASSKEY_PAGE = `<h1>Sign in to Acme</h1>
  <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username webauthn">
  <script>
    const calls = {}
    window.start = (name, kind, json, extra = {}) => {
      const publicKey = kind === "create" ? PublicKeyCredential.parseCreationOptionsFromJSON(json) : PublicKeyCredential.parseRequestOptionsFromJSON(json)
      // generator: each list as a page's generator, which reads only once.
      const { generator, ...rest } = extra
      if (generator) for (const key of ["allowCredentials", "excludeCredentials", "pubKeyCredParams"]) {
        const list = publicKey[key]
        if (list) publicKey[key] = (function* () { yield* list })()
      }
      const abort = new AbortController()
      const call = (calls[name] = { abort })
      navigator.credentials[kind]({ publicKey, signal: abort.signal, ...rest }).then(
        (c) => (call.done = { ok: true, value: c.toJSON() }),
        (e) => (call.done = { ok: false, value: e.name + ": " + e.message }),
      )
    }
    window.result = (name) => calls[name]?.done ?? null
    window.results = (prefix) => Object.keys(calls).filter((n) => n.startsWith(prefix)).map((n) => calls[n].done ?? null)
    window.abort = (name) => calls[name].abort.abort()
  </script>`

// When to show and when to stay quiet: one page per case, from Foyer's test
// pages and detector bugs (Ryan Vogel's list). Each says what the content
// script should make of it: the form's kind and roles, nothing at all, or,
// on a page with no form, whether it still looks like a sign-in step (a
// sign-in-provider button, an authenticator picker, a CAPTCHA).
type Detect = {
  body: string
  title?: string
  /** Served from this host instead of localhost (a *.localhost name). */
  host?: string
  expect:
    | { kind: SurfaceKindE2E; has?: string[]; not?: string[] }
    | { quiet: true; signingIn: boolean; not?: string[] }
    /** Showing a field must open the menu, or must not. */
    | { kind: SurfaceKindE2E; menu: { on: string; off: string } }
    /** The frame `frame` loads never reports a form. */
    | { frameQuiet: string }
}
type SurfaceKindE2E = "login" | "signup" | "change-password" | "reset" | "mfa"
const pw = (id: string, ac = "", label = "Password", extra = "") =>
  `<label for="${id}">${label}</label><input id="${id}" name="${id}" type="password"${ac ? ` autocomplete="${ac}"` : ""}${extra}>`
const text = (id: string, label: string, extra = "") => `<label for="${id}">${label}</label><input id="${id}" name="${id}"${extra}>`
const provider = (label: string, tag = "button") =>
  `<h1>Welcome to Acme</h1><p>Pick how you'd like to continue.</p><${tag} ${tag === "a" ? 'href="#"' : 'type="button"'}>${label}</${tag}>`
const DETECT: Record<string, Detect> = {
  // Form kind.
  "new-account": {
    body: `<h1>Create your account</h1><form>${text("email", "Email", ` type="email"`)}${pw("password")}${pw("confirm", "", "Confirm password")}<button>Create account</button></form>`,
    expect: { kind: "signup", has: ["new-password"], not: ["password"] },
  },
  "current-new-confirm": {
    body: `<h1>Security</h1><form>${pw("current", "", "Current password")}${pw("new", "", "New password")}${pw("confirm", "", "Confirm new password")}<button>Update password</button></form>`,
    expect: { kind: "change-password", has: ["password", "new-password"] },
  },
  "beside-signup": {
    body: `<h1>Account</h1><form><h2>Login</h2>${text("email", "Email", ` type="email"`)}${pw("password")}<button>Sign in</button></form>
      <form><h2>Create account</h2>${text("first", "First name")}${text("last", "Last name")}${text("email2", "Email", ` type="email"`)}${pw("password2")}<button>Create</button></form>`,
    expect: { kind: "login", has: ["password"], not: ["new-password"] },
  },
  "password-and-pin": {
    body: `<h1>Online banking</h1><form>${text("userid", "User ID")}${pw("password")}${pw("pin", "", "PIN", ` inputmode="numeric" maxlength="6"`)}<button>Log on</button></form>`,
    expect: { kind: "login", has: ["password"], not: ["new-password"] },
  },
  "password-and-token": {
    body: `<h1>VPN portal</h1><form>${text("username", "Username")}${pw("password")}<label for="otp">Token code</label><input id="otp" name="otp" type="password"><button>Log in</button></form>`,
    expect: { kind: "login", has: ["password"], not: ["new-password"] },
  },
  "anti-autofill": {
    body: `<h1>Acme</h1><form>${text("email", "Email", ` type="email"`)}${pw("password", "new-password")}<button>Sign in</button></form>`,
    expect: { kind: "login", has: ["password"], not: ["new-password"] },
  },
  "email-first-create": {
    body: `<h1>Acme</h1><form>${text("email", "Email address", ` type="email"`)}<button>Continue</button><button type="button">Create account</button></form>`,
    expect: { kind: "login" },
  },
  french: {
    body: `<h1>Bienvenue</h1><form>${text("email", "Adresse e-mail")}${pw("password", "", "Mot de passe")}<button>Se connecter</button></form>`,
    expect: { kind: "login", has: ["password"] },
  },
  japanese: {
    body: `<h1>ようこそ</h1><form>${text("email", "メールアドレス")}${pw("password", "", "パスワード")}<button>ログイン</button></form>`,
    expect: { kind: "login", has: ["password"] },
  },
  "span-labels": {
    body: `<h1>Acme</h1><div><span>Email</span><div><input id="email"></div></div><div><span>Password</span><div><input id="password" type="password"></div></div><div role="button">Continue</div>`,
    expect: { kind: "login", has: ["password"] },
  },
  "shadow-root": {
    body: `<h1>Acme</h1><acme-login></acme-login><script>
      customElements.define("acme-login", class extends HTMLElement { connectedCallback() { this.attachShadow({ mode: "open" }).innerHTML =
        '<form><label for="e">Email</label><input id="e" type="email"><label for="p">Password</label><input id="p" type="password"><button>Sign in</button></form>' } })</script>`,
    expect: { kind: "login", has: ["password"] },
  },
  // Should stay quiet.
  checkout: {
    body: `<header><a href="/login">Sign in</a></header><h1>Checkout</h1><form>${text("name", "Full name")}${text("phone", "Phone", ` type="tel"`)}${text("street", "Street address")}${text("promo", "Promo code", ` maxlength="8"`)}<button>Pay now</button></form>`,
    expect: { quiet: true, signingIn: false, not: ["otp"] },
  },
  blog: {
    body: `<header><a href="/login">Log in</a></header><h1>Calendars, finally</h1><p>Sign in with Google to sync your calendar, then share it.</p>
      <form><label for="news">Get the newsletter</label><input id="news" type="email" placeholder="you@example.com"><button>Subscribe</button></form><footer><a href="https://github.com/acme">GitHub</a></footer>`,
    expect: { quiet: true, signingIn: false },
  },
  "with-newsletter": {
    body: `<h1>Sign in to Acme</h1><form>${text("email", "Email", ` type="email" autocomplete="username"`)}${pw("password", "current-password")}<button>Sign in</button></form>
      <footer><form><label for="news">Newsletter</label><input id="news" type="email" placeholder="you@example.com"><button>Subscribe</button></form></footer>`,
    expect: { kind: "login", menu: { on: "#email", off: "#news" } },
  },
  "not-codes": {
    body: `<h1>Your details</h1><form>${text("birthyear", "Birth year", ` type="number" maxlength="4"`)}${text("zipcode", "ZIP", ` maxlength="5"`)}${text("amount", "Amount", ` inputmode="numeric"`)}<button>Save</button></form>`,
    expect: { quiet: true, signingIn: false, not: ["otp"] },
  },
  "checkout-amazon-pay": {
    body: `<h1>Checkout</h1><form>${text("email", "Email", ` type="email"`)}${text("cvc", "Card security code", ` maxlength="4"`)}<button type="button">Amazon Pay</button><button type="button">Pay with Amazon</button><button>Place order</button></form>`,
    expect: { quiet: true, signingIn: false, not: ["otp", "password"] },
  },
  puzzle: {
    body: `<h1>Crossword</h1><div>${Array.from({ length: 12 }, (_, i) => `<input maxlength="1" name="c${i}" style="width:24px;display:inline-block">`).join("")}</div>`,
    expect: { quiet: true, signingIn: false, not: ["otp"] },
  },
  "split-code": {
    body: `<h1>Check your email</h1><p>We sent a code to k***@acme.test.</p><form>${Array.from({ length: 6 }, (_, i) => `<input maxlength="1" inputmode="numeric" name="d${i}" style="width:32px;display:inline-block">`).join("")}<button>Verify</button></form>`,
    expect: { kind: "mfa", has: ["otp"] },
  },
  // Sign-in buttons on a page with no form: it's still a sign-in page.
  "provider-github": { body: provider("Continue with GitHub"), expect: { quiet: true, signingIn: true } },
  "provider-linkedin": { body: provider(`<span class="signInWithLinkedIn">Sign in with LinkedIn</span>`), expect: { quiet: true, signingIn: true } },
  "provider-google-ja": { body: provider("Googleでログイン"), expect: { quiet: true, signingIn: true } },
  "provider-google-fr": { body: provider("Continuer avec Google"), expect: { quiet: true, signingIn: true } },
  "provider-google-de": { body: provider("Mit Google anmelden"), expect: { quiet: true, signingIn: true } },
  "provider-discord": { body: provider("Login via Discord", "a"), expect: { quiet: true, signingIn: true } },
  "close-x": { body: `<h1>Welcome to Acme</h1><p>Here's what's new this week.</p><button type="button" aria-label="X">X</button>`, expect: { quiet: true, signingIn: false } },
  // Sign-in state between steps.
  "method-picker": {
    title: "Acme",
    body: `<h2>Verify with one of these methods</h2><p>Select an authenticator</p><ul><li>Okta Verify <a href="#">Select</a></li><li>Phone <a href="#">Select</a></li><li>Security Key or Biometric <a href="#">Select</a></li></ul>`,
    expect: { quiet: true, signingIn: true },
  },
  captcha: {
    title: "Acme",
    body: `<h1>One more step</h1><p>Please complete the security check to continue.</p><div class="g-recaptcha" style="width:300px;height:74px;border:1px solid #ccc">I'm not a robot</div>`,
    expect: { quiet: true, signingIn: true },
  },
  "really-you": {
    title: "Acme",
    body: `<h1>Verify it's you</h1><p>To help keep your account safe, Acme wants to make sure it's really you trying to sign in.</p><button type="button">Try another way</button>`,
    expect: { quiet: true, signingIn: true },
  },
  spinner: { title: "Acme", body: `<div role="progressbar" aria-busy="true" style="width:32px;height:32px;border-radius:50%;border:3px solid #999"></div>`, expect: { quiet: true, signingIn: true } },
  "company-dashboard": { host: "sso.localhost", title: "Dashboard", body: `<h1>Dashboard</h1><p>Welcome back, Kit. Three things need you today.</p>`, expect: { quiet: true, signingIn: false } },
  "embedded-google-button": { body: `<h1>Acme blog</h1><p>Comments</p><iframe src="EMBED/detect-frame/google-button" style="width:300px;height:60px;border:0"></iframe>`, expect: { frameQuiet: "/detect-frame/google-button" } },
}
const DETECT_FRAMES: Record<string, string> = {
  "google-button": `<div role="button" style="width:240px;height:40px;border:1px solid #ccc">Sign in with Google</div>`,
}

/** Step two of a sign-in: the password, for the username step one sent (shown, and carried in a hidden box). */
const FLOW_PASSWORD = (email: string) => `<h1>Enter your password</h1><p>${email}</p><form method="post" action="/flow/nav/next" novalidate>
  <input type="hidden" name="email" value="${email}">
  <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit" id="go">Sign in</button></form><p><a id="other" href="/flow/nav">Use a different account</a></p>`

/** Step three: a six-digit code, one box per digit. */
const FLOW_CODE = (email: string) => `<h1>Two-step verification</h1><p>Enter the code from your authenticator app.</p><form method="post" action="/flow/done" novalidate>
  <input type="hidden" name="email" value="${email}">
  <div style="display:flex;gap:6px">${[1, 2, 3, 4, 5, 6].map((i) => `<input id="d${i}" name="d${i}" maxlength="1" inputmode="numeric" autocomplete="one-time-code" style="width:40px;text-align:center">`).join("")}</div>
  <button type="submit" id="go">Verify</button></form>`

// novalidate: "admin" isn't an email, and the browser would block the submit.
const loginForm = (action: string) => `<h1>Sign in to Acme</h1><form method="post" action="${action}" novalidate>
  <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username">
  <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button></form>`

const NEW_RULES = `maxlength="16" passwordrules="minlength: 12; required: digit; required: upper;"`
/** The new-password box's rules on sign-up variants: a six-digit PIN is weak, a lookahead is outside the pattern subset. */
const SIGNUP_RULES: Record<string, string> = {
  weak: `maxlength="6" pattern="\\d{6}"`,
  lookahead: `pattern="(?=.*\\d).{8,}"`,
  pattern: `pattern="[a-z0-9]{16,24}"`,
}
const signupForm = (action: string, rules = NEW_RULES) => `<h1>Create your Acme account</h1><form method="post" action="${action}" novalidate>
  <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username">
  <label for="new">Password</label><input id="new" name="password" type="password" autocomplete="new-password" ${rules}>
  <label for="confirm">Confirm password</label><input id="confirm" name="confirm" type="password" autocomplete="new-password">
  <button type="submit">Create account</button></form>`

// Pages that use the top layer themselves.
const TOP: Record<string, string> = {
  // Re-shows its popover whenever the menu goes back on top.
  "keeps-covering": loginForm("/home") + onMenu(`
    const c = document.createElement("div")
    c.popover = "manual"
    c.style.cssText = "position:fixed;inset:0;margin:0;width:auto;height:auto;border:0;background:#fff"
    document.body.append(c)
    window.raised = 0
    host.addEventListener("toggle", (e) => {
      if (e.newState !== "open") return
      window.raised++
      if (c.matches(":popover-open")) c.hidePopover()
      c.showPopover()
    })`),
  // A login modal: showModal() makes everything outside the dialog inert.
  dialog: `<dialog id="modal" style="border:0;border-radius:14px;padding:28px;width:360px">${loginForm("/home")}</dialog><script>document.getElementById("modal").showModal()</script>`,
  // A modal the login form isn't in, shown over the open menu.
  "dialog-over": `${loginForm("/home")}<dialog id="banner"><p>We use cookies.</p></dialog>${onMenu(`setTimeout(() => document.getElementById("banner").showModal(), 300)`)}`,
  // Full screen: F2 for the box the form is in, F4 for another.
  fullscreen: `<div id="box" style="background:#f4f4f5">${loginForm("/home")}</div><div id="other" style="background:#000;color:#fff">Video</div><script>
    addEventListener("keydown", (e) => {
      if (e.key === "F2") document.getElementById("box").requestFullscreen()
      if (e.key === "F4") document.getElementById("other").requestFullscreen()
    }, true)
  </script>`,
  // Full screen on a web component, the form in its shadow root: F2.
  "fullscreen-shadow": `<div id="widget"></div><script>
    document.getElementById("widget").attachShadow({ mode: "open" }).innerHTML = ${JSON.stringify(`<div style="background:#f4f4f5">${loginForm("/home")}</div>`)}
    addEventListener("keydown", (e) => e.key === "F2" && document.getElementById("widget").requestFullscreen(), true)
  </script>`,
}

// Identity and card forms (see forms*): checkout pages and payment frames.
const months = `<option value="">Month</option>${Array.from({ length: 12 }, (_, i) => `<option value="${String(i + 1).padStart(2, "0")}">${String(i + 1).padStart(2, "0")}</option>`).join("")}`
const years = (from: number) => `<option value="">Year</option>${Array.from({ length: 12 }, (_, i) => `<option value="${from + i}">${from + i}</option>`).join("")}`
const states = `<option value="">State</option><option value="CA">California</option><option value="NJ">New Jersey</option><option value="NY">New York</option><option value="TX">Texas</option><option value="WA">Washington</option><option value="FL">Florida</option><option value="OH">Ohio</option><option value="OR">Oregon</option><option value="GA">Georgia</option><option value="AZ">Arizona</option>`
const countries = `<option value="">Country</option><option value="CA">Canada</option><option value="DE">Germany</option><option value="FR">France</option><option value="GB">United Kingdom</option><option value="US">United States</option>`
const sel = (id: string, label: string, options: string, extra = "") => `<label for="${id}">${label}</label><select id="${id}" name="${id}"${extra}>${options}</select>`
const FORMS: Record<string, string> = {
  // A US shipping address, with autocomplete tokens.
  tokens: `<style>main{margin-top:24px}#tokens label{margin:4px 0 2px}#tokens input,#tokens select{height:30px}</style><h1>Shipping</h1><form id="tokens">
    <label for="ship-name">Full name</label><input id="ship-name" autocomplete="shipping name">
    <label for="ship-a1">Address</label><input id="ship-a1" autocomplete="shipping address-line1">
    <label for="ship-a2">Apartment</label><input id="ship-a2" autocomplete="shipping address-line2">
    <label for="ship-city">City</label><input id="ship-city" autocomplete="shipping address-level2">
    ${sel("ship-state", "State", states, ` autocomplete="shipping address-level1"`)}
    <label for="ship-zip">ZIP</label><input id="ship-zip" autocomplete="shipping postal-code">
    ${sel("ship-country", "Country", countries, ` autocomplete="shipping country"`)}
    <label for="ship-tel">Phone</label><input id="ship-tel" type="tel" autocomplete="shipping tel">
    <input id="ship-org" autocomplete="shipping organization" style="width:24px;height:12px;padding:0">
    <div style="position:relative"><input id="ship-a3" autocomplete="shipping address-line3"><div style="position:absolute;inset:0;background:#f4f4f5"></div></div>
    <div style="height:900px"></div><label for="ship-email">Email</label><input id="ship-email" type="email" autocomplete="shipping email">
    <button type="button">Continue</button></form>`,
  // The same without tokens, in German, the name split in two, the region and country as selects.
  labels: `<h1>Lieferadresse</h1><form>
    <label for="vn">Vorname</label><input id="vn" name="vn"><label for="nn">Nachname</label><input id="nn" name="nn">
    <label for="str">Straße und Hausnummer</label><input id="str" name="str">
    <label for="plz">PLZ</label><input id="plz" name="plz"><label for="ort">Ort</label><input id="ort" name="ort">
    ${sel("bl", "Bundesland", states)}${sel("land", "Land", countries)}
    <button type="button">Weiter</button></form>`,
  // A card: the expiry in one box.
  "card-single": `<h1>Payment</h1><form>
    <label for="cc">Card number</label><input id="cc" inputmode="numeric" placeholder="1234 1234 1234 1234">
    <label for="exp">Expiration</label><input id="exp" placeholder="MM / YY">
    <label for="cvc">CVC</label><input id="cvc" inputmode="numeric">
    <label for="holder">Name on card</label><input id="holder">
    <button type="button">Pay</button></form>`,
  // A card: the expiry as month and year selects.
  "card-selects": `<h1>Payment</h1><form>
    <label for="cc">Card number</label><input id="cc" autocomplete="cc-number">
    ${sel("mm", "Expiry month", months)}${sel("yy", "Expiry year", years(new Date().getFullYear()))}
    <label for="cvv">Security code</label><input id="cvv" autocomplete="cc-csc">
    <button type="button">Pay</button></form>`,
  // A card number in four boxes.
  "card-split": `<h1>Payment</h1><form>
    <label for="b1">Card number</label><div style="display:flex;gap:6px"><input id="b1" maxlength="4"><input id="b2" maxlength="4"><input id="b3" maxlength="4"><input id="b4" maxlength="4"></div>
    <label for="cvv">CVV</label><input id="cvv" maxlength="4">
    <button type="button">Pay</button></form>`,
}
/** A payment provider's card frame, served on the provider's .test alias (or an unknown host). */
const CARD_FRAME = `<!doctype html><html><head><meta charset="utf-8"><style>
  body{margin:0;padding:8px;font:14px system-ui,sans-serif;background:#fff}label{display:block;margin:6px 0 2px}input{width:100%;box-sizing:border-box;height:34px}
</style></head><body><form>
  <label for="cardnumber">Card number</label><input id="cardnumber" autocomplete="cc-number" inputmode="numeric">
  <label for="exp-date">Expiration date</label><input id="exp-date" autocomplete="cc-exp" placeholder="MM / YY">
  <label for="cvc">CVC</label><input id="cvc" autocomplete="cc-csc">
</form></body></html>`
const cardFrame = (host: string, port: string) => `<h1>Payment</h1>
  <label for="holder">Name on card</label><input id="holder" autocomplete="cc-name">
  <iframe id="pay" src="http://${host}:${port}/forms/card-frame" style="width:100%;height:220px;border:0;margin-top:12px"></iframe>`

/**
 * Apple's sign-in widget as appstoreconnect.apple.com embeds it
 * (idmsa.apple.com/appleauth/auth/signin, checked in October 2026): no
 * <form>, a text box for the account (autocomplete=off) with its label
 * floating over it, and a password box collapsed to zero height until
 * Continue, all in the one frame document.
 * The second Continue tells the page around it, which goes on to the
 * signed-in page.
 */
const APPLE_WIDGET = `<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title><style>
  body{margin:0;font:15px/1.4 system-ui,sans-serif;background:#fff;color:#1d1d1f}
  .signin{max-width:340px;margin:16px auto}h1{font-size:19px;margin:0 0 14px}
  .form-cell-wrapper{position:relative;overflow:hidden}.hide-password .password .form-cell-wrapper{height:0}
  input{display:block;width:100%;box-sizing:border-box;height:52px;padding:18px 12px 0;margin:0 0 8px;font:inherit;border:1px solid #d2d2d7;border-radius:10px}
  .form-textbox-label{position:absolute;left:13px;top:7px;font-size:12px;color:#6e6e73;pointer-events:none}
  button{width:100%;height:40px;border:0;border-radius:10px;background:#0071e3;color:#fff;font:inherit}button:disabled{opacity:.5}
</style></head><body><div id="content" class="si-body"><div class="signin"><div id="sign_in_form" class="signin-form hide-password">
  <h1>Sign in with Apple Account</h1>
  <div class="signin-content">
    <div class="account-name"><div class="form-cell-wrapper form-textbox"><input type="text" id="account_name_text_field" enterkeyhint="done" can-field="accountName" aria-labelledby="apple_id_field_label" autocorrect="off" autocapitalize="off" aria-required="true" required spellcheck="false" class="force-ltr form-textbox-input" autocomplete="off"><span aria-hidden="true" id="apple_id_field_label" class="form-textbox-label">Email or Phone Number</span></div></div>
    <div class="password" aria-hidden="true"><div class="form-cell-wrapper form-textbox"><input type="password" id="password_text_field" aria-labelledby="password_field_label" aria-required="true" required can-field="password" class="form-textbox-input" autocomplete="current-password" tabindex="-1"><span id="password_field_label" aria-hidden="true" class="form-textbox-label">Password</span></div></div>
  </div>
  <button id="sign-in" class="button button-rounded-rectangle" disabled><span>Continue</span></button>
</div></div></div><script>
  const form = document.getElementById("sign_in_form"), account = document.getElementById("account_name_text_field"), password = document.getElementById("password_text_field"), go = document.getElementById("sign-in")
  const step = () => form.classList.contains("hide-password")
  const update = () => (go.disabled = !(step() ? account.value : password.value))
  account.addEventListener("input", update)
  password.addEventListener("input", update)
  go.addEventListener("click", () => {
    if (!step()) return parent.postMessage({ type: "signed-in", account: account.value }, "*")
    setTimeout(() => {
      form.classList.remove("hide-password")
      password.tabIndex = 0
      password.closest(".password").removeAttribute("aria-hidden")
      update()
    }, 200)
  })
</script></body></html>`
/**
 * The page around it: App Store Connect's sign-in page, with the widget from
 * `frame` (or through a frame on `via`), maybe under a sheet that lets clicks
 * through, maybe with `sandbox` flags on its iframe, maybe (`tall`) taller
 * than the viewport. `csp`: the frame on `via` is sandboxed by its
 * Content-Security-Policy header instead, without allow-same-origin. The
 * frame may call WebAuthn, as Apple's does for its passkey autofill.
 */
const appleLogin = (port: string, frame: string, via?: string, cover = false, sandbox?: string, tall = false, csp = false) => {
  const widget = `http://${frame}:${port}/appleauth/auth/signin?widgetKey=e2e&language=en_US`
  const src = via ? `http://${via}:${port}/apple/shell?inner=${encodeURIComponent(widget)}${csp ? "&csp" : ""}` : widget
  const flags = sandbox === undefined ? "" : ` sandbox="${sandbox.replace(/[^a-z -]/g, "")}"`
  return `<h1>App Store Connect</h1><iframe id="aid-auth-widget-iFrame" name="aid-auth-widget" allow="publickey-credentials-get"${flags} src="${src}" style="width:100%;height:${tall ? 1400 : 330}px;border:0"></iframe>
    ${cover ? `<section style="position:fixed;inset:0;z-index:9;pointer-events:none;background:rgb(244 244 245 / 97%)"></section>` : ""}
    <script>addEventListener("message", (e) => { if (e.data?.type === "signed-in") location.assign("/apple/apps?u=" + encodeURIComponent(e.data.account)) })</script>`
}

/**
 * Schwab's sign-in bar as www.schwab.com shows it (issue #88): a 630×65
 * frame in the header (`#schwablmslogin`, "log in form") from
 * sws-gateway-nr.schwab.com, holding a Login ID box (type text, no name, no
 * autocomplete), a password box (autocomplete=off) and a "Log in" button,
 * with no form. Too small to hold a menu: it has to open in the page.
 */
const SCHWAB_BAR = `<!doctype html><html><head><meta charset="utf-8"><title>Log in</title><style>
  body{margin:0;font:13px system-ui,sans-serif;background:#fff}
  .bar{display:flex;gap:8px;align-items:center;height:65px;padding:0 10px;box-sizing:border-box}
  input{width:200px;height:34px;box-sizing:border-box;padding:0 8px;border:1px solid #9ca3af;border-radius:4px;font:inherit}
  button{height:34px;padding:0 16px;border:0;border-radius:4px;background:#00a0df;color:#fff;font:inherit}
  .sr{position:absolute;left:-9999px}
</style></head><body><div class="bar">
  <label class="sr" for="loginIdInput">Login ID</label><input type="text" id="loginIdInput" placeholder="Login ID" maxlength="40">
  <label class="sr" for="passwordInput">Password</label><input type="password" id="passwordInput" placeholder="Password" autocomplete="off">
  <button type="button" id="btnLogin">Log in</button>
</div></body></html>`
const SCHWAB_HOME = (port: string) => `<!doctype html><html><head><meta charset="utf-8"><title>Charles Schwab | A modern approach to investing &amp; retirement</title><style>
  body{margin:0;font:15px system-ui,sans-serif;background:#f4f4f5}header{display:flex;justify-content:space-between;align-items:center;height:80px;padding:0 20px;background:#fff;border-bottom:1px solid #e4e4e7}
  main{padding:40px}
</style></head><body><header><strong>charles SCHWAB</strong>
  <iframe id="schwablmslogin" title="log in form" src="http://sws-gateway-nr.schwab.test:${port}/ui/host/?clientId=schwab-prospect&startInSetId=1&redirectUri=https%3A%2F%2Fclient.schwab.test%2F&enableappd=false" width="630" height="65" style="border:0"></iframe>
</header><main><h1>Own your tomorrow</h1><p>Invest, trade and plan with Schwab.</p></main></body></html>`

const changeForm = `<h1>Change your password</h1><form method="post" action="/home" novalidate>
  <label for="current">Current password</label><input id="current" name="current" type="password" autocomplete="current-password">
  <label for="new">New password</label><input id="new" name="new" type="password" autocomplete="new-password">
  <label for="confirm">Confirm new password</label><input id="confirm" name="confirm" type="password" autocomplete="new-password">
  <button type="submit">Change password</button></form>`

const server = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  async fetch(req): Promise<Response> {
    const url = new URL(req.url)
    // Where the sign-in outcome forms post (see signInOutcomes). The email
    // posted is shown back where a real site would show the account.
    if (req.method === "POST") {
      const email = String((await req.formData().catch(() => null))?.get("email") ?? "").replace(/[<>&"]/g, "")
      // Multi-step sign-ins (see signInSessions): the password page, then a
      // code page for the login that has one, then the signed-in page.
      if (url.pathname === "/flow/nav/password") return html("Enter your password", FLOW_PASSWORD(email))
      if (url.pathname === "/flow/nav/next")
        return email === "kit@acme.test"
          ? html("Two-step verification", FLOW_CODE(email))
          : html("Acme", `<h1>Welcome</h1><p>Signed in as <strong>${email}</strong>.</p><a href="/flow/nav">Sign out</a>`)
      if (url.pathname === "/flow/done") return html("Acme", `<h1>Welcome</h1><p>Signed in as <strong>${email}</strong>.</p><a href="/flow/nav">Sign out</a>`)
      if (url.pathname === "/flow/failed") return Response.redirect(`/flow/failed?email=${encodeURIComponent(email)}`, 303)
      switch (url.pathname) {
        case "/":
          return html("Acme", `<h1>Acme</h1><div role="alert" class="notice">Incorrect password. Try again.</div><p><a href="/outcome/login?to=/">Back</a></p>`)
        case "/outcome/wait":
          return html(
            "Just a moment...",
            `<h1>Checking your browser</h1><p>This takes a few seconds.</p><script>setTimeout(() => location.assign("/outcome/welcome?u=" + encodeURIComponent(${JSON.stringify(email)})), 9000)</script>`,
          )
        case "/auth/complete":
          return html("Acme", `<h1>Welcome</h1><p>Signed in as <strong>${email}</strong>.</p>`)
        // A signed-in page with its own fixed header, links at the top right.
        case "/outcome/header":
          return new Response(
            `<!doctype html><html><head><meta charset="utf-8"><title>Acme</title><style>
              body{margin:0;font:15px/1.5 system-ui,sans-serif;background:#f4f4f5}
              header{position:fixed;top:0;left:0;right:0;height:56px;display:flex;align-items:center;justify-content:space-between;padding:0 20px;background:#fff;border-bottom:1px solid #e4e4e7}
              header nav{display:flex;gap:16px;align-items:center}
              main{padding:120px 40px}
            </style></head><body><header><strong>Acme</strong><nav><span>${email}</span><a id="settings" href="#">Settings</a><a id="signout" href="#">Sign out</a></nav></header>
            <main><h1>Dashboard</h1><p>Signed in.</p></main></body></html>`,
            { headers: { "content-type": "text/html; charset=utf-8" } },
          )
      }
    }
    switch (url.pathname) {
      // Apple's sign-in (see APPLE_WIDGET): ?frame=<host> serves the widget from another host, ?via=<host> through a frame there.
      case "/apple/login":
        return html("App Store Connect", appleLogin(url.port, url.searchParams.get("frame") ?? "idmsa.apple.test", url.searchParams.get("via") ?? undefined, url.searchParams.has("cover"), url.searchParams.get("sandbox") ?? undefined, url.searchParams.has("tall"), url.searchParams.has("csp")))
      case "/appleauth/auth/signin":
        return new Response(APPLE_WIDGET, { headers: { "content-type": "text/html; charset=utf-8" } })
      case "/apple/shell": {
        const inner = url.searchParams.get("inner") ?? ""
        const src = /^http:\/\/[a-z.]+\.test:\d+\/appleauth\//.test(inner) ? inner.replace(/"/g, "") : "about:blank"
        // ?csp: sandboxed by its own header, so its URL keeps the site's origin while its real one is opaque.
        const csp: Record<string, string> = url.searchParams.has("csp") ? { "content-security-policy": "sandbox allow-scripts allow-forms" } : {}
        return new Response(`<!doctype html><body style="margin:0"><iframe src="${src}" style="width:100%;height:320px;border:0"></iframe></body>`, { headers: { "content-type": "text/html; charset=utf-8", ...csp } })
      }
      // Schwab's homepage (see SCHWAB_BAR): the sign-in bar is a 65 px frame from another host of the site.
      case "/schwab/":
        return new Response(SCHWAB_HOME(url.port), { headers: { "content-type": "text/html; charset=utf-8" } })
      case "/ui/host/":
        return new Response(SCHWAB_BAR, { headers: { "content-type": "text/html; charset=utf-8" } })
      case "/apple/apps":
        return html("App Store Connect", `<h1>Apps</h1><p>Signed in as <strong>${(url.searchParams.get("u") ?? "").replace(/[<>&"]/g, "")}</strong>.</p><a href="/apple/login">Sign out</a>`)
      // Step one, the username alone. With ?accounts, the next step is on
      // another origin of the same site (accounts.acme.test).
      case "/flow/nav": {
        // ?to=<host>: the next step on another host of acme.test (accounts, or a user-content sibling).
        const to = url.searchParams.get("to")
        const next = to ? `http://${to}.acme.test:${url.port}/flow/nav/password` : url.searchParams.has("accounts") ? `http://accounts.acme.test:${url.port}/flow/nav/password` : "/flow/nav/password"
        return html(
          "Sign in to Acme",
          `<h1>Sign in to Acme</h1><form method="post" action="${next}" novalidate>
            <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username">
            <button type="submit" id="go">Continue</button></form>`,
        )
      }
      // The same two steps in one document: Continue swaps the username box for a password box.
      case "/flow/spa":
        return html(
          "Sign in to Acme",
          `<h1>Sign in to Acme</h1><form id="f" novalidate>
            <div id="step"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username"></div>
            <button type="submit" id="go">Continue</button></form><script>
            let who = ""
            document.getElementById("f").addEventListener("submit", (e) => {
              e.preventDefault()
              if (!who) {
                who = document.getElementById("email").value
                document.getElementById("step").innerHTML = '<p>' + who.replace(/[<>&]/g, "") + '</p><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">'
                document.getElementById("go").textContent = "Sign in"
              } else location.assign("/flow/spa/done?u=" + encodeURIComponent(who))
            })
          </script>`,
        )
      case "/flow/spa/done":
        return html("Acme", `<h1>Welcome</h1><p>Signed in as <strong>${(url.searchParams.get("u") ?? "").replace(/[<>&"]/g, "")}</strong>.</p>`)
      // A site's sign-in page with a "Continue with Google" button, and a fake
      // Google account chooser on accounts.google.test (mapped to this server).
      case "/social":
        return html(
          "Sign in to Acme",
          `<h1>Sign in to Acme</h1>${loginForm("/home").replace("</form>", "</form>")}
          <p style="text-align:center;color:#71717a;margin:18px 0 0">or</p>
          <button id="google" type="button" style="background:#fff;color:#18181b;border:1px solid #d4d4d8">Continue with Google</button>
          <script>document.getElementById("google").addEventListener("click", () => location.assign("http://accounts.google.test:${url.port}/o/oauth2/chooser?return=" + encodeURIComponent(location.origin + "/social/done")))</script>`,
        )
      case "/social/done":
        return html("Acme", `<h1>Welcome</h1><p>Signed in as <strong>${(url.searchParams.get("as") ?? "").replace(/[<>&"]/g, "")}</strong> with Google.</p>`)
      // Google's password step: a cleaned copy of the real page's <main>
      // (google-pwd-step.html, no <form>). The page itself sets the account:
      // the chip's text (?as; ?nochip takes the chip out) and the hidden
      // username boxes' values (?hidden, else ?as).
      case "/v3/signin/challenge/pwd": {
        const clean = (v: string | null) => (v ?? "").replace(/[<>&"']/g, "")
        const as = clean(url.searchParams.get("as"))
        const hidden = url.searchParams.has("hidden") ? clean(url.searchParams.get("hidden")) : as
        let page = GOOGLE_PWD.replaceAll("person@example.com", as)
          .replace('id="hiddenEmail">', `id="hiddenEmail" value="${hidden}">`)
          .replace('id="identifierId">', `id="identifierId" value="${hidden}">`)
        if (url.searchParams.has("nochip")) page = page.replace(/<div jsname="bQIQze"[^>]*data-profile-identifier[^>]*>[^<]*<\/div>/, "")
        return new Response(page, { headers: { "content-type": "text/html; charset=utf-8" } })
      }
      case "/o/oauth2/chooser": {
        const back = url.searchParams.get("return") ?? "/"
        const tile = (name: string, email: string) =>
          `<li style="list-style:none;border-top:1px solid #e4e4e7"><div role="link" tabindex="0" data-identifier="${email}" style="display:flex;gap:12px;align-items:center;padding:12px 8px;cursor:pointer"><span style="width:28px;height:28px;border-radius:50%;background:#e0e7ff;display:grid;place-items:center">${name[0]}</span><span><span style="display:block;font-weight:500">${name}</span><span style="color:#71717a;font-size:13px">${email}</span></span></div></li>`
        return html("Sign in - Google Accounts", `<h1 style="font-weight:400">Choose an account</h1><p>to continue to Acme</p><ul style="padding:0">${tile("Other Person", "other@gmail.com")}${tile("Kit Mercer", "kit@gmail.com")}</ul>
          <script>for (const t of document.querySelectorAll("[data-identifier]")) t.addEventListener("click", () => location.assign(${JSON.stringify(back)} + "?as=" + encodeURIComponent(t.dataset.identifier)))</script>`)
      }
      // A form whose "button" is a plain div: a click on it submits by script
      // (form.requestSubmit()). ?step: the username alone, on to the password page.
      case "/flow/divbutton": {
        const step = url.searchParams.has("step")
        return html(
          "Sign in to Acme",
          `<h1>Sign in to Acme</h1><form id="f" method="post" action="${step ? "/flow/nav/password" : "/auth/complete"}" novalidate>
            <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username">
            ${step ? "" : `<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">`}
            <div id="lets-go" class="fake-button" style="margin-top:18px;height:38px;border-radius:8px;background:#18181b;color:#fff;display:grid;place-items:center;cursor:pointer">Let's go</div>
          </form><script>document.getElementById("lets-go").addEventListener("click", () => document.getElementById("f").requestSubmit())</script>`,
        )
      }
      // Pages that try to step themselves once Deadbolt fills the username: one
      // swaps the username box for a password box, one submits the form.
      case "/flow/sneaky-swap":
        return html(
          "Sign in to Acme",
          `<h1>Sign in to Acme</h1><form id="f" novalidate><div id="step"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username"></div><button type="submit">Continue</button></form><script>
            document.getElementById("email").addEventListener("change", () => setTimeout(() => {
              document.getElementById("step").innerHTML = '<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">'
            }, 300))
          </script>`,
        )
      case "/flow/sneaky-submit":
        return html(
          "Sign in to Acme",
          `<h1>Sign in to Acme</h1><form id="f" method="post" action="/flow/nav/password" novalidate><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username"><button type="submit">Continue</button></form><script>
            document.getElementById("email").addEventListener("change", () => setTimeout(() => document.getElementById("f").requestSubmit(), 300))
          </script>`,
        )
      // A sign-in that failed, back with the username it was given (one no login has).
      case "/flow/failed":
        return html(
          "Sign in to Acme",
          `<h1>Sign in to Acme</h1>${url.searchParams.has("email") ? `<div role="alert">Incorrect password. Try again.</div>` : ""}<form method="post" action="/flow/failed" novalidate>
            <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" value="${(url.searchParams.get("email") ?? "").replace(/[<>&"]/g, "")}">
            <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
            <button type="submit">Sign in</button></form>`,
        )
      case "/outcome/login":
        return html("Sign in to Acme", loginForm(url.searchParams.get("to") ?? "/home"))
      case "/outcome/welcome":
        return html("Acme", `<header><span>${(url.searchParams.get("u") ?? "").replace(/[<>&"]/g, "")}</span> <button type="button">Sign out</button></header><h1>Dashboard</h1>`)
      // Centred in the viewport, as many sign-in pages are: an infobar coming or going moves the form.
      case "/centred":
        return html("Sign in to Acme", `<style>html,body{height:100%}body{display:flex;align-items:center;justify-content:center}main{margin:0}</style>${loginForm("/home")}`)
      case "/login": {
        const form = loginForm(url.searchParams.get("next") === "home" ? "/home" : "/mfa")
        // A password the page enables only once the email box is focused.
        if (url.searchParams.get("lock") !== "password") return html("Sign in to Acme", form)
        return html(
          "Sign in to Acme",
          form.replace(`autocomplete="current-password"`, `autocomplete="current-password" disabled`) +
            `<script>document.getElementById("email").addEventListener("focus", () => (document.getElementById("password").disabled = false))</script>`,
        )
      }
      case "/mfa":
        return html(
          "Two-factor authentication",
          `<h1>Two-factor authentication</h1><form method="post" action="/home">
            <label for="code">Authentication code</label><input id="code" name="code" autocomplete="one-time-code" inputmode="numeric">
            <button type="submit">Verify</button></form>`,
        )
      case "/home":
        return html("Acme", `<h1>Welcome back</h1><p>You're signed in.</p>`)
      // A single-page app: the button posts with fetch and the app changes route.
      case "/app/login":
        return html(
          "Acme app",
          `<div id="view">${loginForm("#").replace('<button type="submit">', '<button type="submit" id="go">')}</div><script>
            document.querySelector("form").addEventListener("submit", async (e) => {
              e.preventDefault()
              await fetch("/api/session", { method: "POST", body: new FormData(e.target) })
              history.pushState(null, "", "/app/dashboard")
              document.getElementById("view").innerHTML = "<h1>Dashboard</h1><p>Signed in.</p>"
            })
          </script>`,
        )
      case "/api/session":
        return Response.json({ ok: true })
      // Email first, then the password on its own page.
      case "/signin":
        return html(
          "Sign in to Acme",
          `<h1>Sign in to Acme</h1><form method="post" action="/signin/password">
            <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username">
            <button type="submit">Continue</button></form>`,
        )
      case "/signin/password":
        return html(
          "Enter your password",
          `<h1>Enter your password</h1><form method="post" action="/home">
            <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
            <button type="submit">Sign in</button></form>`,
        )
      // A page that fills in a password itself and submits: the extension must not check it.
      case "/sneaky":
        return html(
          "Sign in to Acme",
          `${loginForm("/home")}<script>
            window.guess = () => {
              document.getElementById("email").value = "admin"
              document.getElementById("password").value = "hunter2"
              document.querySelector("form").requestSubmit()
            }
          </script>`,
        )
      // A page with an opaque origin (CSP sandbox): it gets no logins.
      case "/sandboxed":
        return html("Sign in to Acme", loginForm("/home"), { "content-security-policy": "sandbox allow-scripts allow-forms" })
      // A page script that swaps the password at the window, before anyone else sees the input.
      case "/swap":
        return html(
          "Sign in to Acme",
          `<script>addEventListener("input", (e) => { if (e.target.id === "password") e.target.value = "page-chosen" }, true)</script>${loginForm("/home")}`,
        )
      // Swaps the password field for a copy while the menu is open.
      case "/replace":
        return html("Sign in to Acme", loginForm("/home") + onMenu(`setTimeout(() => { const p = document.getElementById("password"); p.replaceWith(p.cloneNode()) }, 100)`))
      // A single-page app that swaps its own login form for the site's login
      // page in a frame, without navigating, and so has no form of its own.
      case "/spa":
        return html(
          "Sign in to Acme",
          `${loginForm("/home")}<script>window.swap = () => { document.title = "Acme"; document.body.innerHTML = \`<h1>Acme</h1>${loginFrame()}\` }</script>`,
        )
      // A WebAuthn test page: the test drives navigator.credentials through
      // start() and reads each call's outcome with result().
      case "/passkey":
        return html("Sign in to Acme", PASSKEY_PAGE)
      case "/passkey/framed":
        return html("Acme", `<h1>Acme</h1><iframe sandbox="allow-scripts" src="/passkey" style="width:600px;height:420px;border:0"></iframe>`)
      case "/passkey/sandboxed":
        return html("Sign in to Acme", PASSKEY_PAGE, { "content-security-policy": "sandbox allow-scripts" })
      // Same-origin frames: one the page lets call WebAuthn (as it may by
      // default), one it doesn't.
      case "/passkey/same":
        return html("Acme", `<h1>Acme</h1><iframe src="/passkey" style="width:600px;height:420px;border:0"></iframe>`)
      case "/passkey/same-denied":
        return html("Acme", `<h1>Acme</h1><iframe allow="publickey-credentials-get 'none'; publickey-credentials-create 'none'" src="/passkey" style="width:600px;height:420px;border:0"></iframe>`)
      // A page whose Permissions Policy turns WebAuthn off.
      case "/passkey/denied":
        return html("Sign in to Acme", PASSKEY_PAGE, { "permissions-policy": "publickey-credentials-get=(), publickey-credentials-create=()" })
      // The site inside another origin inside the site: the top page
      // matches, but WebAuthn calls the innermost frame cross-origin.
      case "/passkey/nested":
        return html("Acme", `<h1>Acme</h1><iframe allow="publickey-credentials-get; publickey-credentials-create" src="http://127.0.0.1:${url.port}/passkey/relay" style="width:640px;height:480px;border:0"></iframe>`)
      case "/passkey/relay":
        return html("Other", `<iframe allow="publickey-credentials-get; publickey-credentials-create" src="http://localhost:${url.port}/passkey" style="width:600px;height:420px;border:0"></iframe>`)
      // An occluder the sweep times around the press (see occlusionSweep).
      case "/sweep":
        return html("Sign in to Acme", loginForm("/home") + SWEEP)
      // Sign-ins that fail and leave the form showing: in place, and posted back.
      case "/fails/spa":
        return html(
          "Sign in to Acme",
          `${loginForm("#")}<p id="error"></p><a id="home" href="/home">Home</a><script>
            document.querySelector("form").addEventListener("submit", async (e) => {
              e.preventDefault()
              await fetch("/api/session", { method: "POST", body: new FormData(e.target) })
              document.getElementById("error").textContent = "That password isn't right."
            })
          </script>`,
        )
      // Turns down a wrong password at once, and takes two and a half seconds to accept the right one.
      case "/fails/retry":
        return html(
          "Sign in to Acme",
          `${loginForm("#")}<p id="error"></p><script>
            document.querySelector("form").addEventListener("submit", async (e) => {
              e.preventDefault()
              const data = new FormData(e.target)
              await fetch("/api/session", { method: "POST", body: data })
              if (data.get("password") !== "the right password") return void (document.getElementById("error").textContent = "That password isn't right.")
              await new Promise((r) => setTimeout(r, 2500))
              history.pushState(null, "", "/app/dashboard")
              document.body.innerHTML = "<h1>Dashboard</h1><p>Signed in.</p>"
            })
          </script>`,
        )
      // Sign-up and change-password forms for the generator.
      case "/signup":
        return html("Create your Acme account", signupForm("/home"))
      case "/signup/fails":
        return html("Create your Acme account", `${signupForm("/signup/fails")}${req.method === "POST" ? `<p>That email is taken.</p>` : ""}<a id="home" href="/home">Home</a>`)
      case "/account/password":
        return html("Change password", changeForm)
      case "/signup/weak":
      case "/signup/lookahead":
      case "/signup/pattern":
        return html("Create your Acme account", signupForm("/home", SIGNUP_RULES[url.pathname.slice(8)]))
      case "/fails/post":
        return html("Sign in to Acme", `${loginForm("/fails/post")}${req.method === "POST" ? `<p>That password isn't right.</p>` : ""}<a id="home" href="/home">Home</a>`)
    }
    if (url.pathname === "/forms/card-frame") return new Response(CARD_FRAME, { headers: { "content-type": "text/html; charset=utf-8" } })
    if (url.pathname === "/forms/stripe") return html("Checkout", cardFrame("js.stripe.test", url.port))
    if (url.pathname === "/forms/unknown") return html("Checkout", cardFrame("pay.evilpay.test", url.port))
    if (url.pathname.startsWith("/forms/") && FORMS[url.pathname.slice(7)]) return html("Checkout", FORMS[url.pathname.slice(7)])
    if (url.pathname.startsWith("/detect/") && DETECT[url.pathname.slice(8)]) {
      const d = DETECT[url.pathname.slice(8)]
      return html(d.title ?? "Acme", d.body.replace("EMBED", `http://127.0.0.1:${server.port}`))
    }
    if (url.pathname.startsWith("/detect-frame/") && DETECT_FRAMES[url.pathname.slice(14)]) return html("Acme", DETECT_FRAMES[url.pathname.slice(14)])
    // The site's own login page in a frame, on pages with no form of their own.
    if (url.pathname.startsWith("/framed/") && FRAMED[url.pathname.slice(8)]) return html("Acme", `<h1>Acme</h1>${FRAMED[url.pathname.slice(8)]}`)
    if (url.pathname.startsWith("/hidden/") && HIDDEN[url.pathname.slice(8)]) return html("Sign in to Acme", HIDDEN[url.pathname.slice(8)])
    if (url.pathname.startsWith("/overlay/") && url.pathname.slice(9) in OVERLAY) return html("Sign in to Acme", loginForm("/home") + OVERLAY[url.pathname.slice(9)])
    if (url.pathname.startsWith("/beaten/") && url.pathname.slice(8) in BEATEN) return html("Sign in to Acme", loginForm("/home") + BEATEN[url.pathname.slice(8)])
    if (url.pathname.startsWith("/top/") && url.pathname.slice(5) in TOP) return html("Sign in to Acme", TOP[url.pathname.slice(5)])
    return new Response("not found", { status: 404 })
  },
})
// Plain http is fillable only on local development hosts such as localhost.
const site = `http://localhost:${server.port}`

// ---- Browser --------------------------------------------------------------------

interface Run {
  context: BrowserContext
  worker: Worker
  log: string
  dir: string
}

interface LaunchOptions {
  status?: string
  host?: boolean
  scheme?: "light" | "dark"
  rateLimit?: string
  fillDelay?: number
  /** Seconds the vault holds each list of logins (a slow menu load). */
  listDelay?: number
  /** Playwright turns the back/forward cache off; keep it on. */
  bfcache?: boolean
  /** Runs the deadbolt binary as the host, with this environment. */
  realHost?: Record<string, string>
  /** Records every page to this directory. */
  record?: string
  /** Device pixels per CSS pixel (2 unless set). */
  scale?: number
  /** The fake host adds "Sign in with Google" logins. */
  signIn?: boolean
  /** The fake host lists three Google logins instead of its own. */
  google?: boolean
  /** "deny": the fake host turns down Touch ID for a card's number. */
  touchId?: string
  /** http origins the browser treats as secure contexts, which WebAuthn needs. */
  secure?: string[]
}

async function launch(options: LaunchOptions = {}): Promise<Run> {
  const dir = await mkdtemp(join(tmpdir(), "deadbolt-e2e-"))
  const log = join(dir, "host.log")
  if (options.host !== false && !standalone) {
    await mkdir(join(dir, "NativeMessagingHosts"))
    await writeFile(
      join(dir, "NativeMessagingHosts", "pw.deadbolt.browser.json"),
      JSON.stringify({
        name: "pw.deadbolt.browser",
        description: options.realHost ? "deadbolt" : "fake",
        path: options.realHost ? deadbolt : join(import.meta.dir, "fake-host.py"),
        type: "stdio",
        allowed_origins: [`chrome-extension://${ID}/`],
      }),
    )
  }
  const context = await chromium.launchPersistentContext(dir, {
    channel: "chromium",
    headless: true,
    colorScheme: options.scheme ?? "light",
    viewport: { width: 900, height: 640 },
    deviceScaleFactor: options.scale ?? 2,
    // *.acme.test is one site on this machine: two origins of it for the sign-in session runs; *.apple.test for Apple's sign-in frame.
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, "--host-resolver-rules=MAP *.acme.test 127.0.0.1, MAP *.apple.test 127.0.0.1, MAP *.schwab.test 127.0.0.1, MAP *.google.test 127.0.0.1, MAP *.stripe.test 127.0.0.1, MAP *.evilpay.test 127.0.0.1", ...(options.secure ? [`--unsafely-treat-insecure-origin-as-secure=${options.secure.join(",")}`] : [])],
    ignoreDefaultArgs: options.bfcache ? ["--disable-back-forward-cache"] : [],
    ...(options.record ? { recordVideo: { dir: options.record, size: { width: 900, height: 640 } } } : {}),
    env: {
      ...process.env,
      DEADBOLT_FAKE_STATUS: options.status ?? "ready",
      DEADBOLT_FAKE_LOG: log,
      DEADBOLT_FAKE_RATE_LIMIT: options.rateLimit ?? "",
      DEADBOLT_FAKE_FILL_DELAY: String(options.fillDelay ?? 0),
      DEADBOLT_FAKE_LIST_DELAY: String(options.listDelay ?? 0),
      DEADBOLT_FAKE_SIGNIN: options.signIn ? "1" : "",
      DEADBOLT_FAKE_GOOGLE: options.google ? "1" : "",
      DEADBOLT_FAKE_TOUCHID: options.touchId ?? "",
      ...options.realHost,
    },
  })
  await context.addInitScript(PROBE)
  context.setDefaultTimeout(10_000)
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"))
  check(worker.url().startsWith(`chrome-extension://${ID}/`), `extension id is ${ID}`)
  // A probe: every content-script message the worker receives, for diagnosis.
  await worker.evaluate(() => {
    const seen: string[] = []
    ;(globalThis as unknown as { __seen: string[] }).__seen = seen
    // And the menu tokens it hands out, to play a page that stole one.
    const tokens: string[] = []
    ;(globalThis as unknown as { __tokens: string[] }).__tokens = tokens
    // And what the content scripts said about each page (see detection).
    const verdicts: unknown[] = []
    ;(globalThis as unknown as { __verdicts: unknown[] }).__verdicts = verdicts
    // And which messages to pages were answered, by type.
    const answered: string[] = []
    ;(globalThis as unknown as { __answered: string[] }).__answered = answered
    const send = chrome.tabs.sendMessage.bind(chrome.tabs) as (...args: unknown[]) => Promise<unknown>
    ;(chrome.tabs as unknown as { sendMessage: unknown }).sendMessage = (...args: unknown[]) => {
      const reply = send(...args)
      reply.then(() => answered.push(String((args[1] as { type?: string })?.type)), () => {})
      return reply
    }
    chrome.runtime.onMessage.addListener((m: { type?: string; token?: string; kind?: unknown; roles?: unknown; loginish?: unknown }, s) => {
      if (s.tab) seen.push(`${m?.type}@${s.frameId}:${s.url ? new URL(s.url).pathname : "?"}`)
      if (s.tab && s.url && m?.type === "db:page") verdicts.push({ type: m.type, frame: s.frameId, url: s.url.split("?")[0], kind: m.kind, roles: m.roles })
      // A page with no form settled: ask it what it shows, as the save check does, for whether it's still a sign-in step.
      if (s.tab?.id !== undefined && s.url && m?.type === "db:settled" && s.frameId === 0) {
        const url = s.url.split("?")[0]
        void send(s.tab.id, { type: "db:probe" }, { frameId: 0 }).then(
          (f) => verdicts.push({ type: "db:quiet", frame: 0, url, loginish: (f as { loginish?: unknown } | null)?.loginish === true }),
          () => {},
        )
      }
      if (m?.type === "db:menu-load" && m.token) tokens.push(m.token)
    })
  })
  const run = { context, worker, log, dir }
  runs.set(context, run)
  if (standalone) await seedVault(run, options)
  return run
}

// ---- The standalone device ------------------------------------------------------

/** The one-time password the seeded Acme login has, and its codes (RFC 6238, SHA-1, 30 s, 6 digits). */
const TOTP_SECRET = "JBSWY3DPEHPK3PXP"
function totpAt(seconds: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = ""
  for (const c of TOTP_SECRET) bits += alphabet.indexOf(c).toString(2).padStart(5, "0")
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(seconds / 30)))
  const mac = createHmac("sha1", key).update(counter).digest()
  const at = mac[mac.length - 1] & 0xf
  return String((mac.readUInt32BE(at) & 0x7fffffff) % 1_000_000).padStart(6, "0")
}
/** Whether `code` is the Acme login's one-time code: the fake host's fixed one, or the vault's current (or just-ended) one. */
const isCode = (code: string) => (standalone ? [totpAt(Date.now() / 1000), totpAt(Date.now() / 1000 - 30)].includes(code) : code === "492039")

const SEED_PASSPHRASE = "e2e standalone synthetic passphrase"

/**
 * Puts the fake host's data in the profile's own vault: created through
 * device.html as a person would (the real KDF), then the logins (on every
 * test site, as the fake host lists them everywhere), the two identities
 * and the card, with the fake host's values. `status: "locked"` locks it
 * after; `host: false` leaves it never set up. Before any page asks, the
 * service worker's messages to the vault are logged (the host log), and
 * `fillDelay` and `rateLimit` act on them as the fake host would.
 */
async function seedVault(run: Run, options: LaunchOptions) {
  await run.worker.evaluate(
    ({ type, delay, listDelay, limited }) => {
      const log: unknown[] = []
      ;(globalThis as unknown as { __vaultLog: unknown[] }).__vaultLog = log
      const send = chrome.runtime.sendMessage.bind(chrome.runtime) as (...args: unknown[]) => Promise<unknown>
      ;(chrome.runtime as unknown as { sendMessage: unknown }).sendMessage = (...args: unknown[]) => {
        const m = args[0] as { type?: string; body?: Record<string, unknown> }
        const kind = String(m?.body?.type ?? "")
        if (m?.type !== type || kind.startsWith("device-")) return send(...args)
        log.push(JSON.parse(JSON.stringify(m.body)))
        if (limited.includes(kind)) return Promise.resolve({ reply: { type: "error", code: "rate_limited", message: "too many requests; try again in a moment" } })
        if (delay && (kind === "fill" || kind === "fill-form")) return new Promise((r) => setTimeout(r, delay * 1000)).then(() => send(...args))
        if (listDelay && kind === "list") return new Promise((r) => setTimeout(r, listDelay * 1000)).then(() => send(...args))
        return send(...args)
      }
    },
    { type: VAULT_REQUEST, delay: options.fillDelay ?? 0, listDelay: options.listDelay ?? 0, limited: (options.rateLimit ?? "").split(",").filter(Boolean) },
  )
  if (options.host === false) return
  const page = await run.context.newPage()
  try {
    await page.goto(`chrome-extension://${ID}/device.html`)
    const ask = async (command: Record<string, unknown>) => {
      const r = (await page.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command)) as { ok: boolean; message?: string; reply?: Record<string, unknown> }
      if (!r?.ok) throw new Error(`seeding the vault: ${command.type}: ${r?.message}`)
      return r.reply!
    }
    await ask({ type: "device-create", passphrase: SEED_PASSPHRASE, name: "personal" })
    const port = server.port
    const sites = [`http://localhost:${port}`, `http://www.acme.test:${port}`, `http://accounts.acme.test:${port}`, `http://appstoreconnect.apple.test:${port}`, `http://www.schwab.test:${port}`]
    const urls = (list: string[]) => list.map((value, i) => (i ? { name: `url-${i + 1}`, value, type: "url" } : { name: "url", value }))
    const login = async (name: string, fields: Array<{ name: string; value: string; type?: string }>) => String((await ask({ type: "device-item-save", kind: "login", name, fields })).ref)
    if (options.google) {
      // Also for acme.test, where the same page must narrow nothing (googleAccount).
      for (const u of ["ryan@gmail.com", "ryan@anoma.ly", "kit@gmail.com"]) await login("Google", [...urls([`http://accounts.google.test:${port}`, `http://www.acme.test:${port}`]), { name: "username", value: u }, { name: "password", value: "google password" }])
    } else {
      await login("Acme", [...urls(sites), { name: "username", value: "kit@acme.test" }, { name: "password", value: "correct horse" }, { name: "otp", value: TOTP_SECRET }])
      await login("Acme admin", [...urls(sites), { name: "username", value: "admin" }, { name: "password", value: "hunter2" }])
      if (options.signIn) {
        const google = await login("Google", [...urls([`http://accounts.google.test:${port}`]), { name: "username", value: "kit@gmail.com" }, { name: "password", value: "google password" }])
        await login("Acme", [...urls(sites), { name: "sign-in-with", value: "google" }, { name: "sign-in-account", value: google.split(":")[1] }])
      }
    }
    const item = (kind: string, name: string, values: Record<string, string>) => ask({ type: "device-item-save", kind, name, fields: Object.entries(values).map(([name, value]) => ({ name, value })) })
    await item("identity", "Home", { "given-name": "Kit", "family-name": "Langton", email: "kit@acme.test", phone: "+14155550123", organization: "Acme", "address-line1": "123 Main St", "address-line2": "Apt 4", city: "Brooklyn", region: "NY", "postal-code": "11201", country: "US", birthday: "1990-07-04" })
    await item("identity", "Work", { "given-name": "Kit", "family-name": "Langton", "address-line1": "1 Market St", city: "San Francisco", region: "CA", "postal-code": "94105", country: "US" })
    await item("card", "Personal Visa", { number: "4242424242424242", cvv: "123", expiry: "2028-08", cardholder: "Kit Langton", brand: "Visa" })
    if (options.status === "locked") await ask({ type: "device-lock" })
  } finally {
    await page.close()
  }
}

const runs = new Map<BrowserContext, Run>()

async function close(run: Run) {
  await run.context.close()
  await rm(run.dir, { recursive: true, force: true })
}

async function hostLog(run: Run): Promise<Array<Record<string, unknown>>> {
  if (standalone) return run.worker.evaluate(() => (globalThis as unknown as { __vaultLog?: Array<Record<string, unknown>> }).__vaultLog ?? []).catch(() => [])
  const text = await readFile(run.log, "utf8").catch(() => "")
  return text
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l))
}

async function diagnose(run: Run, page: Page, what: string) {
  const seen = await run.worker.evaluate(() => (globalThis as unknown as { __seen: string[] }).__seen.splice(0)).catch(() => [])
  const host = (await hostLog(run)).map((r) => r.type).join(", ")
  const menu = extensionFrame(page, "menu.html")
  const foot = menu ? await footText(menu) : ""
  console.log(`  ${what}: at ${new URL(page.url()).pathname}, menu frame: ${menu ? `yes (${foot || "no footer"})` : "no"}\n    worker saw: ${seen.join(" ")}\n    host saw: ${host}`)
}

let failures = 0
function check(ok: boolean, what: string) {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`)
  if (!ok) failures++
  return ok
}

async function until<T>(what: string, fn: () => Promise<T | null | undefined | false> | T | null | undefined | false, timeout = 8000): Promise<T | null> {
  const start = Date.now()
  const end = start + timeout
  while (Date.now() < end) {
    const v = await fn()
    if (v) {
      // Cold starts on a loaded machine are slow; say so rather than hide it.
      if (Date.now() - start > 3000) console.log(`  slow: ${what} took ${Date.now() - start}ms`)
      return v
    }
    await Bun.sleep(100)
  }
  check(false, `timed out: ${what}`)
  return null
}

/** Like until, but not finding it in time is an answer, not a failure. */
async function soon<T>(fn: () => T | null | undefined | false, timeout: number): Promise<T | null> {
  const end = Date.now() + timeout
  while (Date.now() < end) {
    const v = fn()
    if (v) return v
    await Bun.sleep(100)
  }
  return null
}

const extensionFrame = (page: Page, file: string) => page.frames().find((f) => f.url().includes(`/${file}`)) ?? null

async function shot(page: Page, name: string, clip?: { x: number; y: number; width: number; height: number }) {
  if (!stills) return
  await page.screenshot({ path: join(stills, `${name}.png`), clip })
}

/** A still of the surface in `frame`, with room for its shadow, and (`include`) the field it belongs to. */
async function shotAround(page: Page, name: string, frame: Frame, include?: string) {
  if (!stills) return
  const box = await (await frame.frameElement().catch(() => null))?.boundingBox()
  if (!box) return
  let [x0, y0, x1, y1] = [box.x, box.y, box.x + box.width, box.y + box.height]
  const extra = include ? await page.locator(include).boundingBox().catch(() => null) : null
  if (extra) [x0, y0, x1, y1] = [Math.min(x0, extra.x), Math.min(y0, extra.y), Math.max(x1, extra.x + extra.width), Math.max(y1, extra.y + extra.height)]
  const view = page.viewportSize() ?? { width: 900, height: 640 }
  // The shadow reaches about 30px down and 20px to the sides.
  const clip = { x: Math.max(0, x0 - 40), y: Math.max(0, y0 - 32), right: Math.min(view.width, x1 + 40), bottom: Math.min(view.height, y1 + 56) }
  await page.screenshot({ path: join(stills, `${name}.png`), clip: { x: clip.x, y: clip.y, width: clip.right - clip.x, height: clip.bottom - clip.y } })
}

/** The popup page, pointed at a tab: tabs.query would otherwise find the popup's own tab. */
async function popup(run: Run, tabPrefix: string, name?: string): Promise<Page> {
  const page = await run.context.newPage()
  await page.setViewportSize({ width: 360, height: 420 })
  await page.goto(`chrome-extension://${ID}/popup.html`)
  await page.evaluate(async (prefix) => {
    // Without the tabs permission tab.url is hidden; webNavigation has it, as the background uses.
    let tab: chrome.tabs.Tab | undefined
    for (const t of await chrome.tabs.query({})) {
      const frame = t.id === undefined ? null : await chrome.webNavigation.getFrame({ tabId: t.id, frameId: 0 })
      if (frame?.url.startsWith(prefix)) tab = t
    }
    chrome.tabs.query = (async () => [tab]) as typeof chrome.tabs.query
    document.getElementById("app")!.replaceChildren()
    const s = document.createElement("script")
    s.src = "popup.js?again"
    document.body.append(s)
  }, tabPrefix)
  await page.waitForSelector(".top")
  await Bun.sleep(400)
  if (name) {
    const height = await page.evaluate(() => Math.ceil(document.body.getBoundingClientRect().height))
    await shot(page, name, { x: 0, y: 0, width: 360, height })
  }
  return page
}

/** The popup's rows for the page's logins, and their Fill when it's the primary button: the native popup's, or the vault's (src/vault). */
const POPUP_TITLE = standalone ? ".vrow.here .title" : ".account-title"
const POPUP_FILL_PRIMARY = standalone ? ".vrow button.fill.primary" : ".account button.primary"

/** The toolbar badge for the tab showing `prefix`. */
const badge = (run: Run, prefix = site) =>
  run.worker.evaluate(async (prefix) => {
    for (const t of await chrome.tabs.query({})) {
      const frame = t.id === undefined ? null : await chrome.webNavigation.getFrame({ tabId: t.id, frameId: 0 }).catch(() => null)
      if (frame?.url.startsWith(prefix)) return chrome.action.getBadgeText({ tabId: t.id })
    }
    return ""
  }, prefix)

/** Clears the badge, so the next offer is seen as new. The offer itself stays until replaced. */
const clearBadge = (run: Run) =>
  run.worker.evaluate(async () => {
    for (const t of await chrome.tabs.query({})) if (t.id !== undefined) await chrome.action.setBadgeText({ tabId: t.id, text: "" })
  })

/** An offer is waiting: the toolbar button has its badge. */
const offered = (run: Run, what = "an offer badges the toolbar button") => until(what, async () => (await badge(run)) === "1", 20_000)

/** What the page could have noticed: elements outside <body>, and losing focus. */
const probe = (page: Page) => page.evaluate(() => (window as unknown as { __probe: { added: string[]; blurs: number } }).__probe)

// ---- Scenarios ------------------------------------------------------------------

type Scheme = "light" | "dark"

async function fillAndTotp(scheme: Scheme) {
  const run = await launch({ scheme })
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/login`)
    await page.click("#email")
    const menu = await until("inline menu opens", async () => {
      const f = extensionFrame(page, "menu.html")
      return f && (await f.locator(".row").count()) > 0 ? f : null
    })
    if (menu) {
      check((await menu.locator(".row .title").allTextContents()).join(",") === "Acme,Acme admin", "menu lists the site's logins by title")
      check((await menu.locator(".row .sub").first().textContent()) === "kit@acme.test", "menu rows show the username")
      const fonts = await menu.evaluate(async () => {
        await Promise.all([document.fonts.load('13px "Inter"'), document.fonts.load('12px "IBM Plex Mono"')]).catch(() => {})
        return [...document.fonts].map((f) => `${f.family}:${f.status}`).join(" ")
      })
      check(!fonts.includes("error") && fonts.includes("loaded"), `Inter and IBM Plex Mono load in the menu (${fonts})`)
      await Bun.sleep(500)
      await shotAround(page, `menu-${scheme}`, menu, "#email")
      // The frame is exactly the surface: no transparent strip of it over the page.
      const frameBox = await (await menu.frameElement()).boundingBox()
      const surfaceBox = await menu.evaluate(() => document.getElementById("surface")!.getBoundingClientRect().toJSON() as DOMRect)
      check(!!frameBox && Math.abs(frameBox.height - surfaceBox.height) < 1 && Math.abs(frameBox.width - surfaceBox.width) < 1, `the menu's frame is exactly its surface (${frameBox?.height} vs ${surfaceBox.height})`)
      await settled(menu)
      // Keyboard: ↓ moves into the menu, ↓↑ choose, ⏎ fills.
      await page.keyboard.press("ArrowDown")
      await page.keyboard.press("ArrowDown")
      await page.keyboard.press("ArrowUp")
      await Bun.sleep(150)
      await page.keyboard.press("Enter")
      await until("username and password fill", async () => (await page.inputValue("#password")) === "correct horse")
      check((await page.inputValue("#email")) === "kit@acme.test", "username filled")
      check((await page.inputValue("#password")) === "correct horse", "password filled")
      // The menu folded into a pill on the field, which says Filled and goes by itself.
      const filled = await until("the pill says Filled", async () => (await menu.locator(".pill.ok .pill-label[aria-label='Filled']").count().catch(() => 0)) > 0)
      check(!!filled, "the menu folds into a pill that says Filled")
      await Bun.sleep(350)
      await shotAround(page, `surface-filled-${scheme}`, menu, "#email")
      check(!!(await until("the pill goes", () => !extensionFrame(page, "menu.html"), 5000)), "and goes by itself")
      await page.click("button[type=submit]")
      await page.waitForURL("**/mfa")
      const code = await until("one-time code fills on the next page", async () => isCode(await page.inputValue("#code")))
      check(!!code, "TOTP filled on the code page")
    }

    // Escape dismisses for that field; ↓ reopens.
    await page.goto(`${site}/login?next=home`)
    await page.click("#email")
    await until("menu reopens on a new page", () => extensionFrame(page, "menu.html"))
    await page.keyboard.press("Escape")
    await until("esc closes the menu", () => !extensionFrame(page, "menu.html"))
    await page.keyboard.press("ArrowDown")
    check(!!(await until("↓ reopens the menu", () => extensionFrame(page, "menu.html"))), "↓ reopens the menu")
    await page.keyboard.press("Escape")

    const requests = await hostLog(run)
    check(
      requests.every((r) => r.type === "hello" || r.origin === site),
      "every host request names the page's origin",
    )
    const fills = requests.filter((r) => r.type === "fill")
    check(JSON.stringify(fills.map((r) => r.want)) === JSON.stringify([["username", "password"], ["totp"]]), "fills ask only for the fields on each page")

    const p = await popup(run, site, `popup-ready-${scheme}`)
    check((await p.locator(POPUP_TITLE).allTextContents()).join(",") === "Acme,Acme admin", "popup lists the site's logins")
    // The standalone popup is the vault itself, which copies a password when asked (docs/extension-device.md).
    if (!standalone) check(!(await p.locator("button", { hasText: /copy password/i }).count()), "popup offers no password copy")
  } catch (err) {
    check(false, `fill scenario threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "fill")
  } finally {
    await close(run)
  }
}

/** Clicks a field, closes the menu it opens, and types into it as a person would. */
async function type(run: Run, page: Page, selector: string, text: string) {
  await formFound(page)
  await page.click(selector)
  // The test site always has logins, so the username box's menu always
  // comes; wait for it rather than click where it's about to appear. A
  // password box opens none when the username typed names no saved login.
  const password = (await page.locator(selector).getAttribute("type")) === "password"
  const menu = password ? await soon(() => extensionFrame(page, "menu.html"), 1500) : await until(`menu opens on ${selector}`, () => extensionFrame(page, "menu.html"), 15_000)
  if (menu) {
    await page.keyboard.press("Escape")
    await until("esc closes the menu", () => !extensionFrame(page, "menu.html"))
  } else if (!password) await diagnose(run, page, `no menu on ${selector}`)
  await page.locator(selector).pressSequentially(text)
}

/** Signs in with what the user typed. */
async function signIn(run: Run, page: Page, path: string, username: string, password: string, how: "click" | "enter" = "click") {
  await page.goto(`${site}${path}`)
  await type(run, page, "#email", username)
  await type(run, page, "#password", password)
  if (how === "enter") await page.keyboard.press("Enter")
  else await page.click("button[type=submit]")
}

/** The offer waiting in the popup for the tab showing `prefix`, if any. */
async function offerIn(run: Run, name?: string) {
  const p = await popup(run, site, name)
  const title = p.locator(".offer h2")
  return { p, title: (await title.count()) ? await title.textContent() : null }
}

async function savePrompt(scheme: Scheme) {
  const run = await launch({ scheme })
  const page = await run.context.newPage()
  try {
    // A form that posts and navigates, submitted with a click, to a page that shows the account.
    await signIn(run, page, "/outcome/login?to=/auth/complete", "new@acme.test", "a new password")
    await page.waitForURL("**/auth/complete")
    if (!(await offered(run))) await diagnose(run, page, "new login, click + navigation")
    else {
      // A confirmed sign-in shows the offer in the page too, as Deadbolt's
      // surface: one element in a closed shadow root holding an extension
      // frame, which the page can't look into.
      const surface = await until("the save offer shows in the page", () => extensionFrame(page, "menu.html"))
      // The host is a popover with a random custom-element name (see topLayer).
      const added = (await probe(page)).added
      check(added.length === 1 && /^[A-Z]{5}-[A-Z]{5}$/.test(added[0]), `only one element is added to the page for an offer (${JSON.stringify(added)})`)
      const sees = await page.evaluate(() => {
        const host = [...document.documentElement.children].find((el) => el.matches(":popover-open"))
        const frames: string[] = []
        for (let i = 0; i < window.frames.length; i++)
          try {
            frames.push(window.frames[i].document.body.innerText)
          } catch {
            frames.push("blocked")
          }
        return { shadow: host?.shadowRoot === null, inside: host?.innerHTML ?? null, frames }
      })
      check(!!surface && sees.shadow && sees.inside === "" && sees.frames.every((f) => f === "blocked"), `the page can't read the offer (${JSON.stringify(sees)})`)
      check(!((await surface?.content()) ?? "").includes("a new password"), "the surface never holds the password")
      check(!(await hostLog(run)).some((r) => r.type === "save"), "nothing saved before the click")
      const { p, title } = await offerIn(run, `offer-save-${scheme}`)
      check(title === "Save login for localhost?", `the popup asks to save (${title})`)
      check((await p.locator(POPUP_FILL_PRIMARY).count()) === 0, "with an offer showing, no Fill button is primary")
      await p.click(".offer button.primary")
      await until("save sent after the click", async () => (await hostLog(run)).some((r) => r.type === "save"))
      const save = (await hostLog(run)).find((r) => r.type === "save") as { entry?: Record<string, string>; origin?: string }
      check(save?.origin === site && save.entry?.username === "new@acme.test", "save carries the submitted login")
      check(save?.entry?.title === "Sign in to Acme" && save.entry?.url === `${site}/outcome/login`, `save names it after the page (${save?.entry?.title}, ${save?.entry?.url})`)
      check(!!(await until("popup confirms", async () => ((await p.locator(".done").textContent().catch(() => "")) ?? "").includes("Saved"))), "the popup confirms the save")
      check(!!(await until("badge clears", async () => (await badge(run)) === "")), "and the badge clears")
      check(!!(await until("the surface closes", () => !extensionFrame(page, "menu.html"))), "and answering in the popup closes the offer in the page")
      await p.close()
    }

    // An existing username with a different password offers an update; Enter in the password field.
    await signIn(run, page, "/login?next=home", "admin", "changed it", "enter")
    await page.waitForURL("**/home")
    if (!(await offered(run, "an update badges the toolbar button"))) await diagnose(run, page, "update, Enter + navigation")
    else {
      const { p, title } = await offerIn(run, `offer-update-${scheme}`)
      check(title === "Update password for admin?", `Enter in the password field offers an update (${title})`)
      await p.click(".offer button:not(.primary)")
      check(!!(await until("not now removes the offer", async () => (await p.locator(".offer").count()) === 0)), "Not now removes the offer")
      check((await badge(run)) === "", "and the badge")
      check(!(await hostLog(run)).some((r) => r.type === "save" && (r.entry as { username?: string })?.username === "admin"), "and saves nothing")
      await p.close()
    }

    // A saved login signed in with the same password offers nothing.
    await signIn(run, page, "/login?next=home", "admin", "hunter2")
    await page.waitForURL("**/home")
    await Bun.sleep(4000)
    check((await badge(run)) === "", "no badge for an unchanged login")
    const { p, title } = await offerIn(run)
    check(title === null, "and no offer in the popup")
    await p.close()
  } catch (err) {
    check(false, `save scenario threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "save")
  } finally {
    await close(run)
  }
}

/** Clicks a new-password box and picks the generated password from the menu. */
async function generateIn(run: Run, page: Page, name?: string): Promise<string | null> {
  await formFound(page)
  await page.click("#new")
  const menu = await until("the menu offers a generated password", async () => {
    const f = extensionFrame(page, "menu.html")
    return f && (await f.locator("button.row .title").textContent().catch(() => "")) === "Use a strong password" ? f : null
  }, 15_000)
  if (!menu) {
    await diagnose(run, page, "no generator row")
    return null
  }
  await settled(menu)
  if (name) {
    const box = await (await menu.frameElement()).boundingBox()
    if (box) await shot(page, name, { x: box.x - 24, y: box.y - 64, width: box.width + 48, height: box.height + 88 })
  }
  await menu.locator("button.row").click()
  return until("both new-password boxes fill", async () => {
    const value = await page.inputValue("#new")
    return value && value === (await page.inputValue("#confirm")) ? value : null
  })
}

/** The generator: a sign-up fills every new-password box, nothing is saved before a successful submit, and the agent's id stands in for the password. */
async function generator(scheme: Scheme) {
  const run = await launch({ scheme })
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/signup`)
    await type(run, page, "#email", "fresh@acme.test")
    const value = await generateIn(run, page, `generator-${scheme}`)
    check(!!value && value.length >= 12 && value.length <= 16 && /\d/.test(value) && /[A-Z]/.test(value), `the generated password keeps the field's rules (${value?.length} characters)`)
    const asked = (await hostLog(run)).find((r) => r.type === "generate")
    check(asked?.origin === site && asked.maxLength === 16 && asked.rules === "minlength: 12; required: digit; required: upper;", "the host is asked with the field's rules")
    check(!(await hostLog(run)).some((r) => r.type === "save" || r.type === "check"), "nothing is checked or saved before the submit")
    check(!!(await until("the agent is told to keep it", async () => (await hostLog(run)).some((r) => r.type === "generate-keep" && r.origin === site))), "once it's in the page, the agent is told to keep it")
    // The page names it by id once the keep's answer is back; a person takes longer than that to submit.
    await until("the page is told the kept id", () => run.worker.evaluate(() => (globalThis as unknown as { __answered: string[] }).__answered.includes("db:generated")))
    await page.click("button[type=submit]")
    await page.waitForURL("**/home")
    if (!(await offered(run, "a generated sign-up badges the toolbar button"))) await diagnose(run, page, "generated sign-up")
    else {
      const checked = (await hostLog(run)).find((r) => r.type === "check")
      check(typeof checked?.generated === "string" && !("password" in (checked ?? {})), "the check names the generated password by id, not the password")
      const { p, title } = await offerIn(run, `offer-generated-${scheme}`)
      check(title === "Save login for localhost?", `the popup offers to save the new account (${title})`)
      check((await p.locator("button.primary").count()) === 1 && (await p.locator(".offer button.primary").count()) === 1, "with an offer showing, its Save is the only primary button")
      await p.click(".offer button.primary")
      const save = (await until("save sent after the click", async () => (await hostLog(run)).find((r) => r.type === "save"))) as { entry?: Record<string, string> } | null
      check(save?.entry?.username === "fresh@acme.test" && typeof save.entry.generated === "string" && !("password" in save.entry), "the save names the generated password by id")
      await p.close()
    }

    // A sign-up whose form posts back offers nothing.
    await clearBadge(run)
    await page.goto(`${site}/signup/fails`)
    await type(run, page, "#email", "taken@acme.test")
    if (await generateIn(run, page)) {
      await page.click("button[type=submit]")
      await Bun.sleep(6000)
      await page.click("#home")
      await page.waitForURL("**/home")
      await Bun.sleep(5000)
      check((await badge(run)) === "", "a generated sign-up that posts back offers nothing")
    }

    // Changing a password with no username: the login whose password is the current one.
    await clearBadge(run)
    await page.goto(`${site}/account/password`)
    await type(run, page, "#current", "hunter2")
    if (await generateIn(run, page)) {
      await page.click("button[type=submit]")
      await page.waitForURL("**/home")
      if (await offered(run, "a changed password badges the toolbar button")) {
        const { p, title } = await offerIn(run)
        check(title === "Update password for admin?", `the login with the current password is offered the update (${title})`)
        await p.close()
      } else await diagnose(run, page, "change password")
    }

    // A pattern the subset reads: its characters and lengths go to the host, and the password keeps to them.
    await page.goto(`${site}/signup/pattern`)
    const fitted = await generateIn(run, page)
    const shaped = (await hostLog(run)).filter((r) => r.type === "generate").at(-1)
    check(!!fitted && /^[a-z0-9]{16,24}$/.test(fitted), `a password for [a-z0-9]{16,24} fits it (${fitted})`)
    check(shaped?.allowed === "0123456789abcdefghijklmnopqrstuvwxyz" && shaped.minLength === 16 && shaped.maxLength === 24, `the host is asked for the pattern's characters and lengths (${JSON.stringify(shaped)})`)

    // No generator row for a field that allows only weak passwords, or a pattern outside the subset.
    for (const [path, why] of [["weak", "a six-digit PIN is all the field takes"], ["lookahead", "the pattern has a lookahead"]]) {
      const before = (await hostLog(run)).length
      await page.goto(`${site}/signup/${path}`)
      await formFound(page)
      await page.click("#new")
      await Bun.sleep(2000)
      const asked = (await hostLog(run)).slice(before).map((r) => r.type)
      check(!extensionFrame(page, "menu.html") && !asked.includes("generate"), `no generator row when ${why} (${asked.join(", ")})`)
      if (path === "weak") check(asked.includes("generate-check"), "the agent is asked how strong a password the field allows")
      else check(!asked.includes("generate-check"), "a pattern outside the subset isn't sent anywhere")
    }

    // A sign-in's password box offers no generator.
    await page.goto(`${site}/login?next=home`)
    await menuOn(page, "#password")
    check((await extensionFrame(page, "menu.html")?.locator("button.row .title").first().textContent()) === "Acme", "a sign-in's password box lists logins, not a generated password")
  } catch (err) {
    check(false, `generator scenario threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "generator")
  } finally {
    await close(run)
  }
}

/** Other sign-in shapes that must still count, and a page that must not. */
async function signInShapes() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    // Button click, fetch, and a client-side route change: no navigation.
    await signIn(run, page, "/app/login", "spa@acme.test", "spa password")
    await page.waitForURL("**/app/dashboard")
    if (!check(!!(await offered(run)), "SPA sign-in (fetch + route change) offers a save")) await diagnose(run, page, "SPA")
    await clearBadge(run)

    // Playwright's fill (focus plus inserted text, no clicks) still counts as typing.
    const checksBefore = (await hostLog(run)).filter((r) => r.type === "check").length
    await page.goto(`${site}/login?next=home`)
    await page.fill("#email", "filled@acme.test")
    await page.fill("#password", "filled in")
    await page.click("button[type=submit]")
    await page.waitForURL("**/home")
    if (!check(!!(await offered(run)), "a form filled without clicks offers a save")) await diagnose(run, page, "page.fill")
    await clearBadge(run)
    check((await hostLog(run)).filter((r) => r.type === "check").length === checksBefore + 1, "with one check")

    // Email first, password on the next page.
    await page.goto(`${site}/signin`)
    await type(run, page, "#email", "two@acme.test")
    await page.click("button[type=submit]")
    await page.waitForURL("**/signin/password")
    await type(run, page, "#password", "two step")
    await page.click("button[type=submit]")
    await page.waitForURL("**/home")
    if (!check(!!(await offered(run)), "email-first sign-in offers a save")) await diagnose(run, page, "email-first")
    await clearBadge(run)
    const checks = (await hostLog(run)).filter((r) => r.type === "check")
    check(checks.some((r) => r.username === "two@acme.test" && r.password === "two step"), "email-first check pairs the username from step one")

    // A div "button" whose click submits by script: the user's click still captures, and the save is offered.
    await newTurn(run)
    await page.goto(`${site}/flow/divbutton`)
    await type(run, page, "#email", "div@acme.test")
    await type(run, page, "#password", "div password")
    await page.click("#lets-go")
    await page.waitForURL("**/auth/complete")
    if (!check(!!(await offered(run)), "a form submitted by script after a click on a div button offers a save")) await diagnose(run, page, "div button")
    check((await hostLog(run)).some((r) => r.type === "check" && r.username === "div@acme.test"), "with the login typed")
    await clearBadge(run)

    // A page script that sets a password and submits gets no check.
    const before = (await hostLog(run)).filter((r) => r.type === "check").length
    await page.goto(`${site}/sneaky`)
    await page.click("h1")
    await page.evaluate(() => (window as unknown as { guess: () => void }).guess())
    await page.waitForURL("**/home")
    await Bun.sleep(4000)
    check((await hostLog(run)).filter((r) => r.type === "check").length === before, "a page-set password is never checked")
    check((await badge(run)) === "", "and offers nothing")
  } catch (err) {
    check(false, `sign-in shapes threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "shapes")
  } finally {
    await close(run)
  }
}

/** The first thing in a fresh profile: a form filled without clicks, then submitted. */
async function coldSave() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/login?next=home`)
    await page.fill("#email", "cold@acme.test")
    await page.fill("#password", "cold start")
    await page.click("button[type=submit]")
    await page.waitForURL("**/home")
    if (!check(!!(await offered(run)), "a sign-in straight after the browser starts offers a save")) await diagnose(run, page, "cold")
  } catch (err) {
    check(false, `cold save threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "cold")
  } finally {
    await close(run)
  }
}

/** The save offer's surface in `page`, once it shows its offer. */
const saveSurface = (page: Page, what = "the save offer shows in the page", timeout = 20_000) =>
  until(what, async () => {
    const f = extensionFrame(page, "menu.html")
    return f && (await f.locator(".offer").count().catch(() => 0)) > 0 ? f : null
  }, timeout)

/** Where a surface's frame is on the page. */
const frameBox = async (f: Frame) => (await (await f.frameElement()).boundingBox()) ?? { x: 0, y: 0, width: 0, height: 0 }

/** A new turn for the site, so the next confirmed sign-in may show its offer again. */
const newTurn = (run: Run) => run.worker.evaluate(() => chrome.storage.session.remove("opened:localhost"))


/** The save offer in the page after a confirmed sign-in: Save, Not now, its time running out, and none for a likely one. */
async function savedInPage(scheme: Scheme) {
  const run = await launch({ scheme })
  const page = await run.context.newPage()
  try {
    await signIn(run, page, "/outcome/login?to=/auth/complete", "surface@acme.test", "surface password")
    let surface = await saveSurface(page)
    if (!surface) return void (await diagnose(run, page, "surface"))
    check(((await surface.locator(".offer-title").textContent()) ?? "") === "Save login?", "the surface asks to save")
    check(((await surface.locator(".offer-user").textContent()) ?? "") === "surface@acme.test · localhost", "with the username and site inside")
    await Bun.sleep(500)
    check((await frameBox(surface)).height <= 40, "it starts as a small pill in the corner")
    await shotAround(page, `surface-compact-${scheme}`, surface)
    await surface.locator(".offer-row").hover()
    check(!!(await until("it opens on approach", async () => (await frameBox(surface!)).height > 60)), "it opens on approach")
    await settled(surface)
    await shotAround(page, `surface-expanded-${scheme}`, surface)
    await surface.locator(".offer-row .btn.primary").click()
    await until("Save in the page saves", async () => (await hostLog(run)).some((r) => r.type === "save" && (r.entry as { username?: string })?.username === "surface@acme.test"))
    check(!!(await until("the surface folds into a Saved pill", async () => (await surface!.locator(".pill.ok").count().catch(() => 0)) > 0)), "the surface folds into a Saved pill")
    await Bun.sleep(300)
    await shotAround(page, `surface-saved-${scheme}`, surface)
    check(!!(await until("the pill goes", () => !extensionFrame(page, "menu.html"), 5000)), "and goes toward the toolbar button")
    check(!!(await until("badge clears", async () => (await badge(run)) === "")), "and the badge clears")

    // Not now puts the surface away; the toolbar keeps the offer.
    await newTurn(run)
    await signIn(run, page, "/outcome/login?to=/auth/complete", "later@acme.test", "later password")
    surface = await saveSurface(page)
    if (surface) {
      await Bun.sleep(500)
      await surface.locator(".offer-row").hover()
      await until("it opens on approach", async () => (await frameBox(surface!)).height > 60)
      await settled(surface)
      await surface.locator(".offer-actions .btn").click()
      check(!!(await until("Not now puts the surface away", () => !extensionFrame(page, "menu.html"), 5000)), "Not now puts the surface away")
      check((await badge(run)) === "1", "and the toolbar keeps the offer")
      const { p, title } = await offerIn(run)
      check(title === "Save login for localhost?", `which the popup still shows (${title})`)
      await p.close()
    }

    // An update, left alone: its time runs out and the offer waits in the toolbar.
    await newTurn(run)
    await signIn(run, page, "/outcome/login?to=/auth/complete", "admin", "changed again")
    surface = await saveSurface(page)
    if (surface) {
      check(((await surface.locator(".offer-title").textContent()) ?? "") === "Update password?" && ((await surface.locator(".offer-user").textContent()) ?? "").startsWith("admin"), "a changed password asks to update, for its username")
      await Bun.sleep(500)
      await shotAround(page, `surface-update-${scheme}`, surface)
      check(!!(await until("its time runs out: a dot in the corner", async () => (await frameBox(surface!)).width <= 30, 16_000)), "when its time runs out it shrinks to a dot in the corner")
      await Bun.sleep(400)
      await shotAround(page, `surface-dot-${scheme}`, surface)
      check((await badge(run)) === "1", "and the toolbar keeps the offer")
    }

    // A likely sign-in only badges: nothing in the page.
    await newTurn(run)
    await clearBadge(run)
    await signIn(run, page, "/login?next=home", "likely@acme.test", "likely password")
    await page.waitForURL("**/home")
    check(!!(await offered(run)), "a likely sign-in badges")
    await Bun.sleep(1000)
    check(!extensionFrame(page, "menu.html"), "and shows nothing in the page")
  } catch (err) {
    check(false, `save in page threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "save in page")
  } finally {
    await close(run)
  }
}

/**
 * A short recording for `--video` at one device pixel per CSS pixel: the
 * menu, a fill, a sign-in and the save offer in the page. Also writes 30 fps
 * frame strips of the pick folding into the pill and of Save folding into
 * the saved pill (strip-fill.png, strip-save.png).
 */
async function film() {
  if (!video) return void console.log("  (needs --video <dir>)")
  const run = await launch({ record: video, scale: 1 })
  const page = await run.context.newPage()
  const t0 = Date.now()
  const marks: Record<string, { at: number; clip: { x: number; y: number; width: number; height: number } }> = {}
  const around = (b: { x: number; y: number; width: number; height: number }, w: number, hgt: number) => ({
    x: Math.max(0, Math.round(b.x + b.width / 2 - w / 2)),
    y: Math.max(0, Math.round(b.y + b.height / 2 - hgt / 2)),
    width: w,
    height: hgt,
  })
  try {
    await page.goto(`${site}/outcome/login?to=/auth/complete`)
    await Bun.sleep(600)
    const menu = await menuOn(page)
    if (!menu) return void (await diagnose(run, page, "film menu"))
    for (const key of ["ArrowDown", "ArrowDown", "ArrowUp"]) {
      await page.keyboard.press(key)
      await Bun.sleep(450)
    }
    const field = await page.locator("#email").boundingBox()
    marks.fill = { at: (Date.now() - t0) / 1000, clip: around(field ?? { x: 270, y: 150, width: 360, height: 38 }, 420, 240) }
    await page.keyboard.press("Enter")
    await until("the pill says Filled", async () => (await menu.locator(".pill.ok").count().catch(() => 0)) > 0)
    await until("the pill goes", () => !extensionFrame(page, "menu.html"), 5000)
    await Bun.sleep(400)
    await page.click("#password")
    await until("menu on the password", () => extensionFrame(page, "menu.html"))
    await page.keyboard.press("Escape")
    await page.keyboard.press("ControlOrMeta+a")
    await page.locator("#password").pressSequentially("a fresh horse", { delay: 45 })
    await Bun.sleep(300)
    await page.click("button[type=submit]")
    const surface = await saveSurface(page)
    if (!surface) return void (await diagnose(run, page, "film surface"))
    await settled(surface)
    await Bun.sleep(600)
    marks.save = { at: (Date.now() - t0) / 1000, clip: { x: 900 - 400, y: 0, width: 400, height: 200 } }
    await surface.locator(".offer-row .btn.primary").click()
    await until("the pill goes", () => !extensionFrame(page, "menu.html"), 6000)
    await Bun.sleep(800)
    check(true, "recorded the surface")
  } catch (err) {
    check(false, `film threw: ${(err as Error).message.split("\n")[0]}`)
  } finally {
    const recording = await page.video()?.path().catch(() => null)
    const blank = await Promise.all(run.context.pages().filter((p) => p !== page).map((p) => p.video()?.path().catch(() => null)))
    await close(run)
    const out = join(video, "deadbolt-surface.webm")
    if (recording) await rename(recording, out).catch((err) => check(false, `couldn't keep the recording: ${err}`))
    for (const path of blank) if (path) await rm(path, { force: true })
    console.log(`  video: ${out}`)
    // The fold starts once the pick passes its checks, about 0.4 s after the press.
    for (const [name, mark] of Object.entries(marks)) {
      const { x, y, width, height } = mark.clip
      const strip = join(video, `strip-${name}.png`)
      // The pick's fold takes 0.8 s; Save holds "Saving…" in the button first, so its strip runs 1.8 s.
      const [length, tile] = name === "save" ? ["1.8", "9x6"] : ["0.8", "6x4"]
      const ffmpeg = Bun.spawnSync(["ffmpeg", "-v", "error", "-y", "-ss", String(mark.at + 0.3), "-t", length, "-i", out, "-vf", `fps=30,crop=${width}:${height}:${x}:${y},tile=${tile}`, "-frames:v", "1", strip])
      check(ffmpeg.exitCode === 0, `wrote ${strip}${ffmpeg.exitCode ? `: ${ffmpeg.stderr.toString().trim()}` : ""}`)
    }
  }
}

/** Counts the popup opening by itself, without opening it. */
const countOpens = (run: Run) =>
  run.worker.evaluate(() => {
    const g = globalThis as unknown as { __opens: number }
    g.__opens = 0
    ;(chrome.action as unknown as { openPopup: () => Promise<void> }).openPopup = async () => void g.__opens++
  })
const opens = (run: Run) => run.worker.evaluate(() => (globalThis as unknown as { __opens: number }).__opens)
const checksFor = async (run: Run, username: string) => (await hostLog(run)).filter((r) => r.type === "check" && r.username === username).length

/** Whether a sign-in worked, judged from the page it lands on. */
async function signInOutcomes() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    await countOpens(run)

    // A wrong password: the site answers with an error and no form, on a page that isn't a sign-in URL.
    await signIn(run, page, "/outcome/login?to=/", "wrong@acme.test", "a wrong guess")
    await page.waitForSelector("[role=alert]")
    await Bun.sleep(9000)
    check((await checksFor(run, "wrong@acme.test")) === 0, "a failed sign-in is never checked")
    check((await badge(run)) === "", "and offers nothing")

    // Signed in, but the page shows neither the account nor Sign out: badge only.
    await signIn(run, page, "/login?next=home", "likely@acme.test", "likely password")
    await page.waitForURL("**/home")
    if (!check(!!(await offered(run)), "a sign-in without evidence still badges")) await diagnose(run, page, "likely")
    check((await opens(run)) === 0 && !extensionFrame(page, "menu.html"), "but neither opens the popup nor shows anything in the page")
    await clearBadge(run)

    // A bot check after the submit, then the signed-in page. Long enough on
    // the check for a page without evidence to have been offered by now.
    await signIn(run, page, "/outcome/login?to=/outcome/wait", "captcha@acme.test", "captcha password")
    await page.waitForURL("**/outcome/wait")
    await Bun.sleep(8000)
    check((await checksFor(run, "captcha@acme.test")) === 0 && (await badge(run)) === "", "a challenge page offers nothing yet")
    await page.waitForURL("**/outcome/welcome**", { timeout: 15_000 })
    if (!check(!!(await offered(run)), "the page after the challenge offers a save")) await diagnose(run, page, "challenge")
    check((await checksFor(run, "captcha@acme.test")) === 1, "with one check")
    check(!!(await saveSurface(page, "the offer shows in the page")), "and, showing the account, shows the offer in the page")
    check((await opens(run)) === 0, "instead of opening the popup")
    await clearBadge(run)

    // Signed in on a sign-in looking URL that shows the account. A fresh turn for the popup.
    await run.worker.evaluate(() => chrome.storage.session.remove("opened:localhost"))
    await signIn(run, page, "/outcome/login?to=/auth/complete", "complete@acme.test", "complete password")
    await page.waitForURL("**/auth/complete")
    if (!check(!!(await offered(run)), "a sign-in landing on /auth/complete with the account shown offers a save")) await diagnose(run, page, "auth/complete")
    check(!!(await saveSurface(page, "the offer shows in the page")), "and shows the offer in the page")
    const { p, title } = await offerIn(run)
    check(title === "Save login for localhost?", `the popup asks to save (${title})`)
    await p.close()
  } catch (err) {
    check(false, `sign-in outcomes threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "outcomes")
  } finally {
    await close(run)
  }
}

async function rateLimited() {
  const run = await launch({ rateLimit: "fill,generate-keep" })
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/login`)
    const p = await popup(run, site)
    await p.locator("button", { hasText: "Fill" }).first().click()
    const message = await until("rate-limited fill says so", async () => {
      const text = (await p.locator("body").textContent()) ?? ""
      return text.includes("Try again in a moment") ? text : null
    })
    check(!!message && message.includes("Filling too quickly"), "a rate-limited fill says to try again")
    check((await page.inputValue("#password")) === "", "and fills nothing")
    await p.close()

    // The agent doesn't keep a generated password: the page never names its
    // id, and a sign-up that goes through is offered with it as typed.
    await page.goto(`${site}/signup`)
    await type(run, page, "#email", "unkept@acme.test")
    const value = await generateIn(run, page)
    if (value) {
      await page.click("button[type=submit]")
      await page.waitForURL("**/home")
      if (await offered(run, "a sign-up with an unkept generated password badges the toolbar button")) {
        const checked = (await hostLog(run)).find((r) => r.type === "check")
        check(checked?.password === value && !("generated" in checked), "its check sends the password as typed, not an id the agent can't resolve")
        const offer = await offerIn(run)
        check(offer.title === "Save login for localhost?", `the popup offers to save it (${offer.title})`)
        await offer.p.click(".offer button.primary")
        const save = (await until("save sent after the click", async () => (await hostLog(run)).find((r) => r.type === "save"))) as { entry?: Record<string, string> } | null
        check(save?.entry?.username === "unkept@acme.test" && save.entry.password === value, "and saves that password")
        await offer.p.close()
      } else await diagnose(run, page, "unkept generated sign-up")
    }
  } catch (err) {
    check(false, `rate limit threw: ${(err as Error).message.split("\n")[0]}`)
  } finally {
    await close(run)
  }
}

async function locked(scheme: Scheme) {
  const run = await launch({ status: "locked", scheme })
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/login`)
    await page.click("#email")
    const menu = await until("locked menu", async () => {
      const f: Frame | null = extensionFrame(page, "menu.html")
      return f && (await f.locator(standalone ? ".row" : ".notice").count()) > 0 ? f : null
    })
    if (menu) {
      // The browser-only vault's menu offers to unlock it in its own page.
      if (standalone) check(((await menu.locator(".title").textContent()) ?? "") === "Unlock Deadbolt", "menu offers to unlock Deadbolt")
      else check(((await menu.locator(".title").textContent()) ?? "").includes("locked"), "menu says Deadbolt is locked")
      await Bun.sleep(400)
      await shotAround(page, `menu-locked-${scheme}`, menu, "#email")
    }
    const p = await popup(run, site, `popup-locked-${scheme}`)
    if (standalone) {
      // The browser-only vault unlocks in its own popup.
      check((await p.locator("input[type=password]").count()) === 1 && (await p.locator("button", { hasText: "Unlock" }).count()) > 0, "popup asks for the passphrase to unlock")
    } else {
      check(((await p.locator("h2").textContent()) ?? "") === "Unlock Deadbolt", "popup says Unlock Deadbolt")
      check(!(await p.locator("input[type=password]").count()), "popup never asks for the passphrase")
    }
  } catch (err) {
    check(false, `locked threw: ${(err as Error).message.split("\n")[0]}`)
  } finally {
    await close(run)
  }
}

async function notInstalled(scheme: Scheme) {
  const run = await launch({ host: false, scheme })
  try {
    const page = await run.context.newPage()
    await page.goto(`${site}/login`)
    const p = await popup(run, site, `popup-not-installed-${scheme}`)
    if (standalone) check((await p.locator("button", { hasText: /pair with an existing device/i }).count()) > 0, "a vault never set up offers to pair or create one")
    else check(((await p.locator(".command code").textContent()) ?? "") === "deadbolt browser install", "popup shows the install command")
  } catch (err) {
    check(false, `not installed threw: ${(err as Error).message.split("\n")[0]}`)
  } finally {
    await close(run)
  }
}

/** Clicks a field and waits for the menu to list logins. */
/**
 * The menu opens only right after a click; on a loaded machine the click can
 * beat the content script finding the form, so wait for it first.
 */
async function formFound(page: Page) {
  const run = runs.get(page.context())
  const path = new URL(page.url()).pathname
  if (run) await until(`the form on ${path} is found`, () => run.worker.evaluate((p) => (globalThis as unknown as { __seen: string[] }).__seen.some((s) => s.startsWith("db:page@0:") && s.endsWith(p)), path), 15_000)
}

async function menuOn(page: Page, selector = "#email", timeout = 15_000) {
  await formFound(page)
  await page.click(selector)
  const menu = await until(`menu lists logins on ${new URL(page.url()).pathname}`, async () => {
    const f = extensionFrame(page, "menu.html")
    return f && (await f.locator("button.row").count()) > 0 ? f : null
  }, timeout)
  if (menu) await settled(menu)
  return menu
}

/**
 * The menu takes a pick only once it has sat still and visible for half a
 * second, and it grows when its fonts load: wait until its frame stops
 * moving, then that half second and a little.
 */
async function settled(menu: Frame) {
  const frame = await menu.frameElement().catch(() => null)
  const start = Date.now()
  let last = ""
  let still = Date.now()
  while (frame && Date.now() - start < 8000 && Date.now() - still < 300) {
    const box = JSON.stringify(await frame.boundingBox().catch(() => null))
    if (box !== last) [last, still] = [box, Date.now()]
    await Bun.sleep(50)
  }
  await Bun.sleep(700)
}

const fillCount = async (run: Run) => (await hostLog(run)).filter((r) => r.type === "fill").length
const footText = async (menu: Frame) => ((await menu.locator("#foot").textContent().catch(() => "")) ?? "").trim()

/**
 * What a hostile page can try against filling, in a real browser with real
 * layout: hidden and covered fields, a hidden frame, an opaque origin, a stolen
 * menu token, a swapped form, a swapped value, navigating mid-fill and the
 * back/forward cache.
 */
async function securityPage() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    // Hidden fields never get a secret, however they're hidden, even when it
    // happens only as Deadbolt focuses them.
    for (const name of Object.keys(HIDDEN)) {
      await page.goto(`${site}/hidden/${name}`)
      const menu = await menuOn(page)
      if (!menu) {
        await diagnose(run, page, `hidden/${name}`)
        continue
      }
      await menu.locator("button.row").first().click()
      await Bun.sleep(1500)
      const password = await page.inputValue("#password")
      if (name === "visible") check(password === "correct horse", "a visible password field fills")
      else check(password === "", `a password field hidden by ${name} stays empty (${JSON.stringify(password)})`)
    }

    // An opaque-origin page gets no menu and no fill from the popup.
    await page.goto(`${site}/sandboxed`)
    check(await page.evaluate(() => origin === "null"), "the sandboxed page has an opaque origin")
    await page.click("#email")
    await Bun.sleep(1500)
    check(!extensionFrame(page, "menu.html"), "an opaque-origin page gets no menu")
    {
      const before = await fillCount(run)
      const p = await popup(run, site)
      const fill = p.locator("button", { hasText: "Fill" }).first()
      if (await fill.count()) {
        await fill.click()
        await Bun.sleep(800)
      }
      check((await page.inputValue("#password")) === "" && (await fillCount(run)) === before, "nor a fill from the popup")
      await p.close()
    }

    // A same-site login page in a frame: the menu opens in the top page (see
    // frameLogins), never inside the frame, and the popup fills it only if
    // the user can see it through every frame above.
    for (const how of Object.keys(FRAMED)) {
      await run.worker.evaluate(() => void (globalThis as unknown as { __seen: string[] }).__seen.splice(0))
      await page.goto(`${site}/framed/${how}`)
      let inner = await until(`the framed login page loads (${how})`, () => page.frames().find((f) => f.url().includes("/login?next=home")) ?? null)
      if (!inner) {
        await diagnose(run, page, `framed/${how}`)
        continue
      }
      await until("the frame's form is found", () => run.worker.evaluate(() => (globalThis as unknown as { __seen: string[] }).__seen.some((s) => /^db:page@[1-9]/.test(s) && s.endsWith("/login"))), 15_000)
      if (how === "visible") {
        await inner.click("#email")
        const menu = await until("a same-site frame's field opens the menu", () => extensionFrame(page, "menu.html"), 15_000)
        check(!!menu && menu.parentFrame() === page.mainFrame(), "a same-site frame's field opens the menu in the top page, not in the frame")
        // Esc in the frame's field closes it, before the popup's turn.
        await page.keyboard.press("Escape")
        check(!!(await until("esc in the frame closes the menu", () => !extensionFrame(page, "menu.html"), 5000)), "esc in the frame's field closes the menu")
      } else if (how !== "nested") {
        // Every other way of making the frame hard to see: no menu, or one
        // whose pick fills nothing and never asks the host.
        const before = await fillCount(run)
        await inner.click("#email", { force: true, timeout: 3000 }).catch(() => {})
        let menu: Frame | null = null
        for (let i = 0; i < 25 && !menu; i++) {
          const f = extensionFrame(page, "menu.html")
          if (f && (await f.locator("button.row").count().catch(() => 0)) > 0) menu = f
          else await Bun.sleep(100)
        }
        if (menu) {
          await settled(menu)
          await menu.locator("button.row", { hasText: "kit@acme.test" }).click({ timeout: 3000 }).catch(() => {})
          await until(`the pick on a frame made ${how} answers`, async () => !extensionFrame(page, "menu.html") || (await menu!.locator(".pill.failed").count().catch(() => 0)) > 0, 8000)
        }
        const values = [await inner.inputValue("#email"), await inner.inputValue("#password")]
        check(values.every((v) => v === "") && (await fillCount(run)) === before, `a frame made ${how} gets ${menu ? "a menu whose pick fills nothing and doesn't ask the host" : "no menu"} (${JSON.stringify(values)})`)
        await until("the menu goes before the popup's turn", () => !extensionFrame(page, "menu.html"), 8000)
      }
      // Focusing its email box enabled the password box: the popup's run starts from a fresh page.
      if (how === "enabled-on-focus") {
        await run.worker.evaluate(() => void (globalThis as unknown as { __seen: string[] }).__seen.splice(0))
        await page.goto(`${site}/framed/${how}`)
        inner = await until(`the framed login page loads again (${how})`, () => page.frames().find((f) => f.url().includes("/login?next=home")) ?? null)
        if (!inner) continue
        await until("the frame's form is found again", () => run.worker.evaluate(() => (globalThis as unknown as { __seen: string[] }).__seen.some((s) => /^db:page@[1-9]/.test(s) && s.endsWith("/login"))), 15_000)
      }
      const before = await fillCount(run)
      const p = await popup(run, `${site}/framed/${how}`)
      const fill = p.locator("button", { hasText: "Fill" }).first()
      let said = ""
      if (await until("the popup lists logins", async () => (await fill.count()) > 0)) {
        await fill.click()
        await until("the popup answers", async () => p.isClosed() || (await p.locator("#error").isVisible().catch(() => false)))
        said = p.isClosed() ? "" : ((await p.locator("#error").textContent().catch(() => "")) ?? "")
      }
      const password = await inner.inputValue("#password")
      if (how === "enabled-on-focus") {
        const last = (await hostLog(run)).filter((r) => r.type === "fill").at(-1)
        check(
          password === "" && (await inner.inputValue("#email")) === "kit@acme.test" && JSON.stringify(last?.want) === JSON.stringify(["username"]),
          `the popup fills only the frame's fields that showed when checked, not a covered password the page enabled as it filled (${JSON.stringify(password)}, asked for ${JSON.stringify(last?.want)}${said ? `: ${said}` : ""})`,
        )
      } else if (how === "visible" || how === "nested") check(password === "correct horse", `the popup fills a same-site frame the user can see (${how}${said ? `: ${said}` : ""})`)
      else check(password === "" && (await fillCount(run)) === before, `the popup doesn't fill a frame made ${how} (${said || "no message"})`)
      if (!p.isClosed()) await p.close()
    }

    // The top page's form going away (here, swapped for a frame's without a
    // navigation) leaves the popup free to fill the frame's.
    {
      const seen = () => run.worker.evaluate(() => (globalThis as unknown as { __seen: string[] }).__seen)
      await run.worker.evaluate(() => void (globalThis as unknown as { __seen: string[] }).__seen.splice(0))
      await page.goto(`${site}/spa`)
      await until("the top form is found", async () => (await seen()).some((s) => s.startsWith("db:page@0")), 15_000)
      await page.evaluate(() => (window as unknown as { swap: () => void }).swap())
      const inner = await until("the swapped-in frame loads", () => page.frames().find((f) => f.url().includes("/login?next=home")) ?? null)
      await until("the frame's form is found", async () => (await seen()).some((s) => /^db:page@[1-9]/.test(s) && s.endsWith("/login")), 15_000)
      const p = await popup(run, `${site}/spa`)
      const fill = p.locator("button", { hasText: "Fill" }).first()
      let said = ""
      if (await until("the popup lists logins", async () => (await fill.count()) > 0)) {
        await fill.click()
        await until("the popup answers", async () => p.isClosed() || (await p.locator("#error").isVisible().catch(() => false)))
        said = p.isClosed() ? "" : ((await p.locator("#error").textContent().catch(() => "")) ?? "")
      }
      check((await inner?.inputValue("#password")) === "correct horse", `the popup fills a frame that replaced the top page's form (${said || "no message"})`)
      if (!p.isClosed()) await p.close()
    }

    // A menu token used from anywhere but the menu Deadbolt opened gets nothing.
    await page.goto(`${site}/login?next=home`)
    const menu = await menuOn(page)
    const token = await run.worker.evaluate(() => (globalThis as unknown as { __tokens: string[] }).__tokens.at(-1))
    if (menu && token) {
      // A same-site page in another tab with the stolen token, handing it to a menu frame of its own.
      const menuUrl = await run.worker.evaluate(() => chrome.runtime.getURL("menu.html"))
      const other = await run.context.newPage()
      await other.goto(`${site}/home`)
      await other.evaluate(
        ([src, token]) =>
          new Promise<void>((resolve) => {
            const f = document.createElement("iframe")
            f.src = src
            f.style.cssText = "width:320px;height:200px"
            f.onload = () => {
              f.contentWindow!.postMessage({ type: "db:menu-token", token }, "*")
              resolve()
            }
            document.body.append(f)
          }),
        [menuUrl, token],
      )
      // The menu is a web-accessible resource with use_dynamic_url, so a page may
      // not be able to load it at all; if it can, the token gets it nothing.
      await Bun.sleep(1500)
      const stolen = other.frames().find((f) => f !== other.mainFrame())
      const foot = stolen && (await stolen.locator("#foot").count()) ? await footText(stolen) : null
      console.log(`  stolen token frame: ${foot === null ? "menu page didn't load" : JSON.stringify(foot)}`)
      check(!stolen || ((await stolen.locator("button.row").count()) === 0 && (foot === null || foot === "This menu has expired.")), "a stolen token in another page's frame lists nothing")
      // The same page handing it to the frame Deadbolt opened gets nothing new either: it's already bound.
      // Opened as a page of its own: Chrome blocks it, or it has no parent to hand it a token.
      const blocked = await other.goto(menuUrl).then(() => false, (err: Error) => err.message.includes("ERR_BLOCKED_BY_CLIENT"))
      if (!blocked) await Bun.sleep(800)
      check(blocked || (await other.locator("button.row").count()) === 0, `a menu page opened on its own gets nothing (${blocked ? "blocked" : "no token"})`)
      await other.close()
      // The real menu still works, once it's been back in view for a moment.
      await Bun.sleep(900)
      await menu.locator("button.row").first().click()
      check(!!(await until("the real menu still fills", async () => (await page.inputValue("#password")) === "correct horse")), "the menu Deadbolt opened still fills")
    }

    // The form changes under an open menu: the pick fills nothing.
    await page.goto(`${site}/replace`)
    {
      const menu = await menuOn(page)
      if (menu) {
        await menu.locator("button.row").first().click()
        await Bun.sleep(1000)
        check((await page.inputValue("#email")) === "" && (await page.inputValue("#password")) === "", "a form replaced after the menu opened isn't filled")
      }
    }

    // A page that rewrites the password at the window before anyone else sees
    // the keystroke doesn't get its own value checked.
    {
      const before = (await hostLog(run)).filter((r) => r.type === "check").length
      await signIn(run, page, "/swap", "typed@acme.test", "typed password")
      await page.waitForURL("**/home")
      await Bun.sleep(4000)
      const checks = (await hostLog(run)).filter((r) => r.type === "check")
      check(!checks.some((r) => r.password === "page-chosen"), "a password the page swapped in is never checked")
      check(checks.length === before && (await badge(run)) === "", "and nothing is offered")
    }
  } catch (err) {
    check(false, `security threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "security")
  } finally {
    await close(run)
  }
}

/**
 * Focus can reach the menu without the user's ↓: the page can make the menu
 * the next stop after the field, so the user's Tab lands in it, or a script
 * holding the menu's window can focus it. Either way the user's next Enter (or
 * Space) must not pick. Only the user's own ↓ from the field lets the keyboard
 * pick, and only until focus leaves the menu.
 */
async function keyboardEntry() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/login?next=home`)
    const menu = await menuOn(page)
    if (!menu) return await diagnose(run, page, "keyboard entry")
    // The menu's frame is in a closed shadow root: window.frames doesn't list it.
    check((await page.evaluate(() => window.length)) === 0, "the page can't reach the menu's window through window.frames")
    // Everything after the field leaves the tab order, so Tab goes to the menu.
    await page.evaluate(() => document.querySelectorAll("input:not(#email), button").forEach((el) => el.setAttribute("tabindex", "-1")))
    const inMenu = () => menu.evaluate(() => document.hasFocus())
    const intoMenu: Record<string, () => Promise<void>> = {
      "the user's Tab": async () => {
        await page.focus("#email")
        await page.keyboard.press("Tab")
      },
      "a script": async () => {
        await page.focus("#email")
        await menu.evaluate(() => window.focus())
      },
    }
    const before = await fillCount(run)
    for (const [how, focus] of Object.entries(intoMenu)) {
      for (const key of ["Enter", " "]) {
        await settled(menu)
        await focus()
        if (!(await inMenu())) {
          check(false, `${how} puts focus in the menu`)
          continue
        }
        await page.keyboard.press(key)
        await Bun.sleep(1200)
        const name = key === " " ? "Space" : key
        check((await page.inputValue("#password")) === "" && (await fillCount(run)) === before, `focus from ${how} takes no ${name} (${await footText(menu)})`)
      }
    }
    // The user's ↓ enters the menu; the page takes focus back, and the user tabs in again.
    await page.focus("#email")
    await page.keyboard.press("ArrowDown")
    await Bun.sleep(200)
    check(await inMenu(), "↓ puts focus in the menu")
    await page.evaluate(() => document.getElementById("email")!.focus())
    await page.keyboard.press("Tab")
    check(await inMenu(), "Tab puts it back")
    await page.keyboard.press("Enter")
    await Bun.sleep(1200)
    check((await page.inputValue("#password")) === "" && (await fillCount(run)) === before, "focus that left the menu and came back takes no Enter")
    // The user's own ↓ from the field, then Enter, fills.
    await page.focus("#email")
    await page.keyboard.press("ArrowDown")
    await Bun.sleep(150)
    await page.keyboard.press("Enter")
    check(!!(await until("↓ then Enter fills", async () => (await page.inputValue("#password")) === "correct horse")), "the user's ↓ then Enter fills")
  } catch (err) {
    check(false, `keyboard entry threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "keyboard entry")
  } finally {
    await close(run)
  }
}

/**
 * The menu's visibility guard samples (Intersection Observer v2 readings,
 * at most every 100 ms): it can miss a page covering the menu for less
 * than that. Covers the menu for a range of times around the press and says
 * which picks went through. Covers of 250 ms or more must never fill.
 */
async function occlusionSweep() {
  const run = await launch()
  const page = await run.context.newPage()
  const results: string[] = []
  try {
    let menu: Frame | null = null
    let at: { x: number; y: number } | null = null
    for (const ms of [16, 50, 100, 250]) {
      for (const offset of [-300, -120, -40, 0, 150]) {
        if (!menu || menu.isDetached() || !(await menu.locator("button.row").count().catch(() => 0))) {
          await page.goto(`${site}/sweep`)
          menu = await menuOn(page)
          const box = menu && (await menu.locator("button.row").first().boundingBox())
          at = box && { x: box.x + box.width / 2, y: box.y + box.height / 2 }
        } else await settled(menu)
        if (!menu || !at) {
          await diagnose(run, page, "sweep")
          break
        }
        // Focus back in the page, so the press moves it into the menu and the page sees blur.
        await page.focus("#email")
        await page.evaluate(() => {
          const w = window as unknown as { __shown?: number; __press?: number }
          w.__shown = w.__press = undefined
        })
        const before = await fillCount(run)
        if (offset < 0) {
          await page.evaluate((ms) => (window as unknown as { cover: (ms: number) => void }).cover(ms), ms)
          await Bun.sleep(-offset)
        } else await page.evaluate(([after, ms]) => (window as unknown as { coverAfterPress: (a: number, ms: number) => void }).coverAfterPress(after, ms), [offset, ms])
        await page.mouse.click(at.x, at.y)
        await Bun.sleep(1500)
        const real = await page.evaluate(() => {
          const w = window as unknown as { __shown?: number; __press?: number }
          return w.__shown !== undefined && w.__press !== undefined ? Math.round(w.__shown - w.__press) : null
        })
        const filled = (await fillCount(run)) > before
        results.push(`${String(ms).padStart(4)} ms at ${real === null ? "  ?" : String(real).padStart(5)} ms: ${filled ? "FILLED" : "refused"}`)
        check(real !== null, `the ${ms} ms cover at ${offset} ms was shown and the press seen`)
        if (ms >= 250) check(!filled, `a ${ms} ms cover at ${real ?? offset} ms around the press fills nothing`)
        if (filled) menu = null
      }
    }
  } catch (err) {
    check(false, `sweep threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "sweep")
  } finally {
    console.log("  cover length, start relative to the press: result\n    " + results.join("\n    "))
    await close(run)
  }
}

/** A menu the user can't see properly, or saw only as the press landed, takes no pick and asks for nothing. */
async function coveredMenu() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    for (const name of Object.keys(OVERLAY)) {
      await page.goto(`${site}/overlay/${name}`)
      const menu = await menuOn(page)
      if (!menu) {
        await diagnose(run, page, `overlay/${name}`)
        continue
      }
      const before = await fillCount(run)
      if (name === "reveal-before-press") {
        await page.evaluate(() => (window as unknown as { reveal: () => void }).reveal())
        await Bun.sleep(250)
      }
      await menu.locator("button.row").first().click({ force: true })
      await Bun.sleep(1500)
      const password = await page.inputValue("#password")
      if (name === "none") check(password === "correct horse", `an uncovered menu fills (${password ? "" : await footText(menu)})`)
      else {
        check(password === "" && (await fillCount(run)) === before, `a menu made ${name} fills nothing and asks the host for nothing`)
        const foot = await footText(menu)
        check(foot.includes("covered") || (name.startsWith("reveal") && foot.includes("in a moment")), `and says it's covered (${foot})`)
        // The refused press put focus in the menu, which by now has been in
        // plain view for a while: the user's next Enter there must not pick.
        const focused = await menu.evaluate(() => document.hasFocus())
        await page.keyboard.press("Enter")
        await Bun.sleep(1500)
        check(
          focused && (await page.inputValue("#password")) === "" && (await fillCount(run)) === before,
          `and a later Enter in the menu ${focused ? "" : "(not focused!) "}fills nothing either (${await footText(menu)})`,
        )
      }
    }
    for (const name of Object.keys(BEATEN)) {
      await page.goto(`${site}/beaten/${name}`)
      // From the last field, so a sheet over the menu covers no field.
      const menu = await menuOn(page, "#password")
      if (!menu) {
        await diagnose(run, page, `beaten/${name}`)
        continue
      }
      await Bun.sleep(300)
      await settled(menu)
      await menu.locator("button.row").first().click()
      const filled = await until(`beaten/${name} fills`, async () => (await page.inputValue("#password")) === "correct horse", 4000)
      check(!!filled, `a menu in the top layer beats ${name} and fills (${filled ? "" : await footText(menu)})`)
      if (!filled) await diagnose(run, page, `beaten/${name}`)
    }
  } catch (err) {
    check(false, `covered menu threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "covered menu")
  } finally {
    await close(run)
  }
}

/**
 * The browser resizing the viewport (an infobar such as "started debugging this
 * browser" coming or going) reflows a centred form, and the menu moves with
 * it: that doesn't restart the dwell. The page moving the menu itself still
 * does, even in the frame right after a resize.
 */
async function viewportResize() {
  const run = await launch()
  const page = await run.context.newPage()
  const viewport = page.viewportSize()!
  const shrink = (by: number) => page.setViewportSize({ width: viewport.width, height: viewport.height - by })
  try {
    await page.goto(`${site}/centred`)
    let menu = await menuOn(page)
    if (!menu) return void (await diagnose(run, page, "viewport resize"))
    const at = async () => (await (await menu!.frameElement()).boundingBox())?.y ?? 0
    const before = await at()
    // 40 px less, just before the press, and back just after it.
    await shrink(40)
    check(!!(await until("the centred menu moves with the resize", async () => Math.abs((await at()) - before) >= 10, 2000)), "a 40 px resize moves the centred menu")
    await Bun.sleep(150)
    await menu.locator("button.row").first().click()
    await Bun.sleep(150)
    await shrink(0)
    const filled = await until("a pick after a resize fills", async () => (await page.inputValue("#password")) === "correct horse", 4000)
    check(!!filled, `a pick right after the browser resized the viewport fills (${filled ? "" : await footText(menu)})`)

    // The page moves the form itself, 200 ms before the press.
    await page.goto(`${site}/centred`)
    menu = await menuOn(page)
    if (!menu) return void (await diagnose(run, page, "viewport resize: page move"))
    await page.evaluate(() => (document.querySelector("main")!.style.transform = "translateY(-24px)"))
    await Bun.sleep(200)
    await menu.locator("button.row").first().click()
    await Bun.sleep(1200)
    check((await page.inputValue("#password")) === "" && (await fillCount(run)) === 1, `a menu the page moved 200 ms before the press fills nothing (${await footText(menu)})`)
    check((await footText(menu)).includes("in a moment"), "and asks for the pick again")

    // The page moves the form further than the viewport changed, on the resize itself.
    await page.goto(`${site}/centred`)
    menu = await menuOn(page)
    if (!menu) return void (await diagnose(run, page, "viewport resize: piggyback"))
    await page.evaluate(() => addEventListener("resize", () => (document.querySelector("main")!.style.transform = "translateY(-120px)"), { once: true }))
    await shrink(40)
    await Bun.sleep(200)
    await menu.locator("button.row").first().click()
    await Bun.sleep(1200)
    check((await page.inputValue("#password")) === "" && (await fillCount(run)) === 1, `a page moving the menu further than a resize did fills nothing (${await footText(menu)})`)
  } catch (err) {
    check(false, `viewport resize threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "viewport resize")
  } finally {
    await close(run)
  }
}

/**
 * The menu grows in only once its frame has its rows (see openMenu): never a
 * blank box (its shadow, a ghost) with the rows popping in half faded.
 */
async function menuReveal() {
  // A slow list: the frame is up a while before it has rows to show.
  const run = await launch({ listDelay: 0.3 })
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/outcome/login`)
    await formFound(page)
    const loaded = page.waitForEvent("framenavigated", (f) => f.url().includes("/menu.html"))
    await page.click("#email")
    const menu = await loaded
    const seen: string[] = []
    const end = Date.now() + 1500
    while (Date.now() < end) {
      const [opacity, rows] = await Promise.all([
        menu.frameElement().then((el) => el.evaluate((e) => Number(getComputedStyle(e as Element).opacity))).catch(() => -1),
        menu.locator("button.row").count().catch(() => -1),
      ])
      if (opacity >= 0 && rows >= 0) seen.push(`${rows ? "rows" : "blank"}@${opacity.toFixed(2)}`)
      if (rows && opacity === 1) break
    }
    const ghost = seen.filter((s) => s.startsWith("blank") && !s.endsWith("@0.00"))
    check(ghost.length === 0 && seen.some((s) => s.startsWith("rows")), `the menu shows nothing until it has its rows (${seen.filter((s, i) => s !== seen[i - 1]).join(" ")})`)
    check(!!(await until("the revealed menu takes a pick", async () => (await menu.locator("button.row").count()) > 0)), "and then lists its logins")
  } catch (err) {
    check(false, `menu reveal threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "menu reveal")
  } finally {
    await close(run)
  }
}

/** The menu's host: a popover with a random name, raised over what the page puts in the top layer, and inside a login modal. */
async function topLayer() {
  const run = await launch()
  const page = await run.context.newPage()
  const hostOf = () => page.evaluate(() => {
    const h = document.querySelector(":popover-open")
    return h ? { tag: h.localName, parent: h.parentElement?.localName ?? "", in: h.parentElement?.id ?? "", important: (h as HTMLElement).style.getPropertyPriority("position") } : null
  })
  try {
    const tags: string[] = []
    for (let i = 0; i < 2; i++) {
      await page.goto(`${site}/login?next=home`)
      if (!(await menuOn(page))) await diagnose(run, page, "top layer")
      const h = await hostOf()
      if (h) tags.push(h.tag)
      check(!!h && h.parent === "html" && h.important === "important", `the menu is an open popover on <html> with !important styles (${JSON.stringify(h)})`)
    }
    check(tags.length === 2 && tags.every((t) => t.includes("-") && t !== "div") && tags[0] !== tags[1], `its tag is random each time (${tags.join(", ")})`)

    await page.goto(`${site}/top/keeps-covering`)
    await formFound(page)
    await page.click("#email")
    const gone = await until("a page that keeps covering the menu gets it closed", async () => {
      const raised = await page.evaluate(() => (window as unknown as { raised?: number }).raised ?? 0)
      return raised > 0 && !extensionFrame(page, "menu.html") ? raised : null
    })
    check(!!gone && gone <= 5, `the menu goes back on top a few times, then closes (${gone} raises)`)
    check(!(await hostLog(run)).some((r) => r.type === "fill"), "and nothing fills")

    await page.goto(`${site}/top/dialog`)
    const inDialog = await menuOn(page)
    check((await hostOf())?.parent === "dialog", "in a login modal, the menu goes inside the dialog")
    if (inDialog) {
      await inDialog.locator("button.row").first().click()
      check(!!(await until("the modal's menu fills", async () => (await page.inputValue("#password")) === "correct horse")), "and takes clicks there")
    } else await diagnose(run, page, "dialog")

    await page.goto(`${site}/top/dialog-over`)
    if (await menuOn(page, "#email", 15_000)) {
      check(!!(await until("a modal the form isn't in closes the menu", () => !extensionFrame(page, "menu.html"))), "a modal shown over the menu, without the form, closes it")
    }

    // Full screen draws only the full-screen element, and the top layer in it.
    await page.goto(`${site}/top/fullscreen`)
    if (await menuOn(page)) {
      await page.keyboard.press("F2")
      const entered = await until("the form's box goes full screen", () => page.evaluate(() => document.fullscreenElement?.id === "box"))
      await page.click("#email")
      const inside = await until("the menu opens inside the full-screen element", async () => (await hostOf())?.in === "box" && extensionFrame(page, "menu.html"))
      check(!!entered && !!inside, `in full screen, the menu opens inside the full-screen element (${JSON.stringify(await hostOf())})`)
      if (inside) {
        await settled(inside)
        await inside.locator("button.row").first().click()
        check(!!(await until("the menu fills in full screen", async () => (await page.inputValue("#password")) === "correct horse")), "and takes clicks there")
      }
      await page.evaluate(() => document.exitFullscreen())
    } else await diagnose(run, page, "fullscreen")
    // On a shadow host with the form in its shadow root: in the shadow root, as the host's own children aren't drawn.
    await page.goto(`${site}/top/fullscreen-shadow`)
    if (await menuOn(page)) {
      await page.keyboard.press("F2")
      const entered = await until("the web component goes full screen", () => page.evaluate(() => document.fullscreenElement?.id === "widget"))
      await page.click("#email")
      const where = () => page.evaluate(() => {
        const widget = document.getElementById("widget")!
        const open = (n: ParentNode) => [...n.children].some((c) => c.matches("[popover]:popover-open"))
        const popovers = [document, widget.shadowRoot!].flatMap((r) => [...r.querySelectorAll("[popover]")]).map((p) => `${p.parentNode === widget.shadowRoot ? "#shadow-root" : (p.parentNode as Element).localName}:${p.matches(":popover-open")}`)
        return { shadow: open(widget.shadowRoot!), light: open(widget), full: document.fullscreenElement?.id ?? null, popovers }
      })
      const inside = await until("the menu opens in the web component's shadow root", async () => (await where()).shadow && extensionFrame(page, "menu.html"))
      check(!!entered && !!inside, `in full screen on a shadow host, the menu opens in its shadow root (${JSON.stringify(await where())})`)
      if (inside) {
        await settled(inside)
        await inside.locator("button.row").first().click()
        check(!!(await until("the menu fills in full screen in a shadow root", async () => (await page.inputValue("#password")) === "correct horse")), "and takes clicks there")
      }
      await page.evaluate(() => document.exitFullscreen().catch(() => {}))
    } else await diagnose(run, page, "fullscreen-shadow")
    await page.goto(`${site}/top/fullscreen`)
    if (await menuOn(page)) {
      await page.keyboard.press("F4")
      await until("another element goes full screen", () => page.evaluate(() => document.fullscreenElement?.id === "other"))
      check(!!(await until("full screen elsewhere closes the menu", () => !extensionFrame(page, "menu.html"))), "full screen on another element closes the menu")
      await page.evaluate(() => document.exitFullscreen().catch(() => {}))
    }
  } catch (err) {
    check(false, `top layer threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "top layer")
  } finally {
    await close(run)
  }
}

/**
 * Sign-in sessions: a login picked on the first step fills the later ones
 * (password, code) without another pick, through same-document steps,
 * navigations and another origin of the same site, with a pill for each,
 * until a "Use a different account" step ends it. A username typed by hand
 * narrows the password step's menu to its login; one no login has (a failed
 * sign-in that came back with it) brings no menu at all.
 */
async function signInSessions() {
  const run = await launch()
  const page = await run.context.newPage()
  const pillSays = async (label: string) =>
    until(`a pill says ${label}`, async () => {
      const f = extensionFrame(page, "menu.html")
      return f && ((await f.locator(".pill.ok .pill-label").textContent().catch(() => "")) ?? "").includes(label)
    })
  const pickLogin = async (username: string) => {
    const menu = await menuOn(page)
    if (!menu) throw new Error("no menu")
    await menu.locator("button.row", { hasText: username }).click()
    await until(`${username} fills`, async () => (await page.inputValue("#email")) === username)
    await until("the pill goes", () => !extensionFrame(page, "menu.html"), 6000)
  }
  const wants = async () => (await hostLog(run)).filter((r) => r.type === "fill").map((r) => (r.want as string[]).join("+"))
  try {
    // (a) The same document: the username box is replaced by the password box.
    await page.goto(`${site}/flow/spa`)
    await pickLogin("kit@acme.test")
    await page.click("#go")
    check(!!(await until("the password fills in place", async () => (await page.inputValue("#password").catch(() => "")) === "correct horse")), "a same-document password step fills from the login picked on the first")
    check(!!(await pillSays("Password filled")), "and its pill says Password filled")
    check(JSON.stringify(await wants()) === JSON.stringify(["username", "password"]), `with one fill per step (${await wants()})`)

    // (b) + (d) Navigation to the password page, then a code page of split boxes.
    await page.goto(`${site}/flow/nav`)
    await pickLogin("kit@acme.test")
    await page.click("#go")
    await page.waitForURL("**/flow/nav/password")
    check(!!(await until("the password page fills", async () => (await page.inputValue("#password")) === "correct horse")), "the password page after a navigation fills")
    check(!!(await pillSays("Password filled")), "with its pill")
    await until("the pill goes", () => !extensionFrame(page, "menu.html"), 6000)
    await page.click("#go")
    await page.waitForURL("**/flow/nav/next")
    const code = await until("the code boxes fill", async () => {
      const digits = await Promise.all([1, 2, 3, 4, 5, 6].map((i) => page.inputValue(`#d${i}`)))
      return isCode(digits.join(""))
    })
    check(!!code, "the code step's split boxes fill with the current code")
    check(!!(await pillSays("Code filled")), "and its pill says Code filled")

    // (c) The password step on another origin of the same site.
    await page.goto(`http://www.acme.test:${server.port}/flow/nav?accounts`)
    await pickLogin("kit@acme.test")
    await page.click("#go")
    await page.waitForURL("http://accounts.acme.test:*/flow/nav/password")
    check(!!(await until("the other origin's password step fills", async () => (await page.inputValue("#password")) === "correct horse")), "a password step on another origin of the same site fills")

    // (e) "Use a different account" ends the session.
    await page.goto(`${site}/flow/nav`)
    await pickLogin("admin")
    await page.click("#go")
    await page.waitForURL("**/flow/nav/password")
    await until("admin's password fills", async () => (await page.inputValue("#password")) === "hunter2")
    await until("the pill goes", () => !extensionFrame(page, "menu.html"), 6000)
    await page.click("#other")
    await page.waitForURL("**/flow/nav")
    await formFound(page)
    await page.click("#email")
    await page.locator("#email").pressSequentially("other@acme.test", { delay: 20 })
    await page.click("#go")
    await page.waitForURL("**/flow/nav/password")
    await Bun.sleep(2000)
    check((await page.inputValue("#password")) === "", "after \"Use a different account\", the next password step gets nothing")
    await page.click("#password")
    await Bun.sleep(1200)
    check(!extensionFrame(page, "menu.html"), "and, for a username no login has, no menu")

    // (f) A username typed by hand that a login has: the password step's menu is just that login.
    await page.goto(`${site}/flow/nav`)
    await formFound(page)
    await page.click("#email")
    await page.locator("#email").pressSequentially("admin", { delay: 30 })
    // Enter, as a person would with the narrowed menu still over the button.
    await page.keyboard.press("Enter")
    await page.waitForURL("**/flow/nav/password")
    await formFound(page)
    await page.click("#password")
    const narrowed = await until("the password menu opens", async () => {
      const f = extensionFrame(page, "menu.html")
      return f && (await f.locator("button.row").count()) > 0 ? f : null
    })
    check(!!narrowed && (await narrowed.locator("button.row").count()) === 1 && ((await narrowed.locator(".row .sub").textContent()) ?? "") === "admin", "a username typed by hand narrows the password step's menu to its login")
    await page.keyboard.press("Escape")

    // (g) A failed sign-in, typed by hand, back with a username no login has: no menu on the password field.
    await page.goto(`${site}/flow/failed`)
    await type(run, page, "#email", "nobody@acme.test")
    await type(run, page, "#password", "a wrong guess")
    await page.keyboard.press("Enter")
    await page.waitForURL("**/flow/failed?email=*")
    await formFound(page)
    await page.click("#password")
    await Bun.sleep(1500)
    check(!extensionFrame(page, "menu.html"), "a failed sign-in back with an unknown username opens no menu on the password field")
    await page.keyboard.press("ArrowDown")
    check(!!(await until("↓ still brings the full list", () => extensionFrame(page, "menu.html"))), "↓ still brings the list")
    await page.keyboard.press("Escape")

    // (h) A sibling host the agent would list the login on, but no saved URL names: nothing.
    await page.goto(`http://www.acme.test:${server.port}/flow/nav?to=user-content`)
    await pickLogin("kit@acme.test")
    await page.click("#go")
    await page.waitForURL("http://user-content.acme.test:*/flow/nav/password")
    await formFound(page)
    await Bun.sleep(2000)
    check((await page.inputValue("#password")) === "", "a sibling host no saved URL names gets nothing on its password step")

    // (i) The page swaps the username box for a password box itself: no user submit, no step.
    await page.goto(`${site}/flow/sneaky-swap`)
    await pickLogin("kit@acme.test")
    await until("the page swaps its own form", async () => (await page.locator("#password").count()) > 0)
    await Bun.sleep(2000)
    check((await page.inputValue("#password")) === "", "a page that swaps in a password box itself gets nothing")

    // (k) A div "button" the user clicks, which submits by script: not the
    // user's own submit to the step gate, so the next step isn't filled.
    await page.goto(`${site}/flow/divbutton?step`)
    await pickLogin("kit@acme.test")
    await page.click("#lets-go")
    await page.waitForURL("**/flow/nav/password")
    await formFound(page)
    await Bun.sleep(2000)
    check((await page.inputValue("#password")) === "", "a step submitted by script from a div \"button\" gets no auto-fill")

    // (j) The page submits itself (form.requestSubmit()): no user submit, no step.
    await page.goto(`${site}/flow/sneaky-submit`)
    await pickLogin("kit@acme.test")
    await page.waitForURL("**/flow/nav/password")
    await formFound(page)
    await Bun.sleep(2000)
    check((await page.inputValue("#password")) === "", "a page that submits its own form gets nothing on the next step")
  } catch (err) {
    check(false, `sign-in sessions threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "sessions")
  } finally {
    await close(run)
  }
}

/**
 * A sign-in in a frame of the page's own site, as Apple's: App Store Connect
 * (appstoreconnect.apple.test) embeds its sign-in widget from
 * idmsa.apple.test, with no <form> and the password in the same frame after
 * Continue. The menu opens in the top page under the frame's field, the pick
 * fills only the frame, and the password step fills from the same login
 * with its pill on the field. A username typed by hand narrows the password
 * step's menu. A cross-site frame, or a same-site one inside a cross-site
 * frame, gets no menu.
 */
async function frameLogins() {
  const run = await launch()
  const page = await run.context.newPage()
  const top = `http://appstoreconnect.apple.test:${server.port}`
  const seen = () => run.worker.evaluate(() => (globalThis as unknown as { __seen: string[] }).__seen)
  const widget = () => page.frames().find((f) => f.url().includes("/appleauth/auth/signin")) ?? null
  /** The widget, once its frame reported the form. */
  const open = async (query = "", reported = true) => {
    await run.worker.evaluate(() => void (globalThis as unknown as { __seen: string[] }).__seen.splice(0))
    await page.goto(`${top}/apple/login${query}`)
    const inner = await until(`the sign-in frame loads${query ? ` (${query})` : ""}`, widget)
    const found = async () => (await seen()).some((s) => /^db:page@[1-9]\d*:\/appleauth\/auth\/signin$/.test(s))
    // A sandboxed frame may never report: wait a while, without failing.
    if (inner && reported) await until("the frame's form is found", found, 15_000)
    else if (inner) for (let i = 0; i < 30 && !(await found()); i++) await Bun.sleep(100)
    return inner
  }
  const menuNow = async () => {
    const f = extensionFrame(page, "menu.html")
    return f && (await f.locator("button.row").count()) > 0 ? f : null
  }
  const pillOn = async (label: string) =>
    until(`a pill says ${label}`, async () => {
      const f = extensionFrame(page, "menu.html")
      return f && ((await f.locator(".pill.ok .pill-label").textContent().catch(() => "")) ?? "").includes(label) ? f : null
    })
  const wants = async () => (await hostLog(run)).filter((r) => r.type === "fill").map((r) => `${(r.want as string[]).join("+")}@${r.origin}`)
  const fieldBox = () => page.locator("#aid-auth-widget-iFrame").boundingBox()
  try {
    const inner = await open()
    if (!inner) return
    await inner.click("#account_name_text_field")
    const menu = await until("the menu opens for the frame's field", menuNow, 15_000)
    if (!menu) return void (await diagnose(run, page, "frameLogins"))
    check(menu.parentFrame() === page.mainFrame(), "a login field in a same-site frame opens the menu in the top page")
    const box = await (await menu.frameElement()).boundingBox()
    const field = await inner.locator("#account_name_text_field").boundingBox()
    check(!!box && !!field && box.y >= field.y + field.height && box.y < field.y + field.height + 24 && Math.abs(box.x - field.x) < 8, `under where the field shows (${JSON.stringify(box)} vs ${JSON.stringify(field)})`)
    await shotAround(page, "frame-login-menu", menu, "#aid-auth-widget-iFrame")
    await settled(menu)
    await menu.locator("button.row", { hasText: "kit@acme.test" }).click()
    check(!!(await until("the frame's username fills", async () => (await inner.inputValue("#account_name_text_field")) === "kit@acme.test")), "picking a login fills the frame's username box")
    check((await inner.inputValue("#password_text_field")) === "", "and not its collapsed password box")
    const pill = await pillOn("Filled")
    const pillBox = pill ? await (await pill.frameElement()).boundingBox() : null
    check(!!pillBox && !!field && pillBox.y >= field.y - 2 && pillBox.y + pillBox.height <= field.y + field.height + 2, `its pill sits on the frame's field in the top page (${JSON.stringify(pillBox)})`)
    await until("the pill goes", () => !extensionFrame(page, "menu.html"), 6000)
    // Esc in the frame's field once the pick has filled it says nothing of the sign-in.
    await inner.focus("#account_name_text_field")
    await page.keyboard.press("Escape")
    // The user clicks Continue in the frame; its password box opens in the same document.
    await inner.click("#sign-in")
    check(!!(await until("the password step fills", async () => (await inner.inputValue("#password_text_field")) === "correct horse")), "the password step in the same frame fills from the login picked on the first")
    const stepPill = await pillOn("Password filled")
    check(!!stepPill && stepPill.parentFrame() === page.mainFrame(), "and its pill, in the top page, says Password filled")
    const password = await inner.locator("#password_text_field").boundingBox()
    const stepBox = stepPill ? await (await stepPill.frameElement()).boundingBox() : null
    check(!!stepBox && !!password && stepBox.y >= password.y - 2 && stepBox.y + stepBox.height <= password.y + password.height + 2, `on the frame's password box (${JSON.stringify(stepBox)} vs ${JSON.stringify(password)})`)
    await shotAround(page, "frame-login-pill", stepPill ?? menu, "#aid-auth-widget-iFrame")
    const frameOrigin = `http://idmsa.apple.test:${server.port}`
    check(JSON.stringify(await wants()) === JSON.stringify([`username@${frameOrigin}`, `password@${frameOrigin}`]), `one fill per step, each for the frame's own origin (${await wants()})`)
    check(!!(await fieldBox()), "the page around the frame keeps its frame")

    // Typed by hand: the username narrows the password step's menu to its login.
    const typed = await open()
    if (typed) {
      await typed.click("#account_name_text_field")
      await until("the menu opens", menuNow, 15_000)
      await typed.locator("#account_name_text_field").pressSequentially("admin", { delay: 30 })
      check(!!(await until("typing in the frame puts the menu away", () => !extensionFrame(page, "menu.html"), 5000)), "typing in the frame's field puts the top page's menu away")
      await typed.click("#sign-in")
      await until("the password box opens", async () => ((await typed.locator("#password_text_field").boundingBox())?.height ?? 0) > 20)
      await Bun.sleep(400)
      await typed.click("#password_text_field")
      const narrowed = await until("the password menu opens", menuNow, 15_000)
      check(!!narrowed && (await narrowed.locator("button.row").count()) === 1 && ((await narrowed.locator(".row .sub").textContent()) ?? "") === "admin", "a username typed by hand narrows the frame's password step to its login")
      if (narrowed) {
        await settled(narrowed)
        await narrowed.locator("button.row").click()
        check(!!(await until("admin's password fills", async () => (await typed.inputValue("#password_text_field")) === "hunter2")), "and picking it fills the frame's password")
      }
    }

    // A sheet over the frame that lets clicks through: the pick fills nothing.
    const covered = await open("?cover")
    if (covered) {
      const before = (await wants()).length
      await covered.click("#account_name_text_field")
      const coveredMenu = await until("the menu opens over the sheet", menuNow, 15_000)
      if (coveredMenu) {
        await settled(coveredMenu)
        await coveredMenu.locator("button.row", { hasText: "kit@acme.test" }).click()
        await until("the pill says it didn't fill", async () => (await coveredMenu.locator(".pill.failed").count().catch(() => 0)) > 0)
      }
      check((await covered.inputValue("#account_name_text_field")) === "" && (await wants()).length === before, "a frame under a sheet that lets clicks through gets nothing, and the host isn't asked")
    }

    // A login frame taller than the viewport: only part of it shows, and its field fills.
    const tall = await open("?tall")
    if (tall) {
      check(((await page.locator("#aid-auth-widget-iFrame").boundingBox())?.height ?? 0) > (page.viewportSize()?.height ?? 0), "the frame is taller than the viewport")
      await tall.click("#account_name_text_field")
      const tallMenu = await until("the menu opens for the tall frame's field", menuNow, 15_000)
      if (tallMenu) {
        await settled(tallMenu)
        await tallMenu.locator("button.row", { hasText: "admin" }).click()
        check(!!(await until("the tall frame's field fills", async () => (await tall.inputValue("#account_name_text_field")) === "admin")), "a login frame taller than the viewport fills")
      }
    }

    // Schwab's homepage: a 65 px sign-in bar frame from another host of the
    // site. The menu opens in the page, below the bar, and fills both boxes.
    await run.worker.evaluate(() => void (globalThis as unknown as { __seen: string[] }).__seen.splice(0))
    await page.goto(`http://www.schwab.test:${server.port}/schwab/`)
    const bar = await until("Schwab's sign-in bar loads", () => page.frames().find((f) => f.url().includes("/ui/host/")) ?? null)
    if (bar) {
      await until("the bar's form is found", async () => (await seen()).some((s) => /^db:page@[1-9]\d*:\/ui\/host\/$/.test(s)), 15_000)
      await bar.click("#loginIdInput")
      const schwab = await until("the menu opens for the bar's Login ID", menuNow, 15_000)
      if (schwab) {
        check(schwab.parentFrame() === page.mainFrame(), "Schwab's 65 px sign-in bar opens the menu in the top page")
        const m = await (await schwab.frameElement()).boundingBox()
        const frame = await page.locator("#schwablmslogin").boundingBox()
        check(!!m && !!frame && m.y >= frame.y + frame.height - 20 && m.height > frame.height, `below the bar, taller than the frame could hold (${JSON.stringify(m)} vs ${JSON.stringify(frame)})`)
        await shotAround(page, "frame-login-schwab", schwab, "#schwablmslogin")
        await settled(schwab)
        await schwab.locator("button.row", { hasText: "admin" }).click()
        const both = await until("both boxes fill", async () => (await bar.inputValue("#loginIdInput")) === "admin" && (await bar.inputValue("#passwordInput")) === "hunter2")
        check(!!both, "the pick fills the bar's Login ID and password")
      }
    }

    // A frame on another site, one of the site inside a frame on another
    // site, and sandboxed frames (keeping their origin or not, or inside a
    // sandboxed frame of the site): no menu.
    for (const [query, what] of [
      ["?frame=idmsa.evilpay.test", "a cross-site frame"],
      ["?via=shell.evilpay.test", "a same-site frame inside a cross-site frame"],
      ["?sandbox=allow-scripts allow-same-origin allow-forms", "a sandboxed same-site frame that keeps its origin"],
      ["?sandbox=allow-scripts allow-forms", "a sandboxed same-site frame with an opaque origin"],
      ["?via=shell.apple.test&sandbox=allow-scripts allow-same-origin", "a same-site frame inside a sandboxed same-site frame"],
      ["?via=shell.apple.test&csp", "a same-site frame inside a same-site frame its CSP header sandboxes"],
    ]) {
      const other = await open(query, false)
      if (!other) continue
      await other.click("#account_name_text_field")
      await Bun.sleep(2500)
      check(!extensionFrame(page, "menu.html"), `${what} gets no menu`)
    }
  } catch (err) {
    check(false, `frameLogins threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "frameLogins")
  } finally {
    await close(run)
  }
}

/** The rings Deadbolt draws (closed shadow roots on elements of its own): how many show, and where. */
const rings = (page: Page) =>
  page.evaluate(() => [...document.documentElement.children].filter((el) => el.nodeName === "DIV" && (el as HTMLElement).style.inset === "0px" && el.shadowRoot === null).length)

/**
 * "Sign in with Google": the menu shows the login as that, picking it rings
 * the site's own button (nothing filled, nothing clicked), and on Google's
 * account chooser the linked account's tile is ringed.
 */
async function signInWith(scheme: Scheme) {
  const run = await launch({ scheme, signIn: true })
  const page = await run.context.newPage()
  try {
    await page.goto(`http://www.acme.test:${server.port}/social`)
    const menu = await menuOn(page)
    if (!menu) return void (await diagnose(run, page, "sign in with"))
    const row = menu.locator("button.row", { hasText: "Sign in with Google" })
    check((await row.count()) === 1 && ((await row.locator(".sub").textContent()) ?? "") === "kit@gmail.com", "the menu shows the login as Sign in with Google · its account")
    check((await menu.locator("button.row", { hasText: "Acme admin" }).count()) === 1, "beside the site's password logins")
    await shotAround(page, `signin-menu-${scheme}`, menu, "#email")
    await settled(menu)
    await row.click()
    check(!!(await until("the menu goes", () => !extensionFrame(page, "menu.html"), 5000)), "picking it puts the menu away")
    check(!!(await until("a ring shows", async () => (await rings(page)) === 1, 5000)), "and rings the site's Continue with Google button")
    await Bun.sleep(600)
    const button = await page.locator("#google").boundingBox()
    if (stills && button) await page.screenshot({ path: join(stills, `signin-ring-${scheme}.png`), clip: { x: Math.max(0, button.x - 60), y: Math.max(0, button.y - 70), width: button.width + 120, height: button.height + 120 } })
    await Bun.sleep(1000)
    check(new URL(page.url()).pathname === "/social", "nothing clicks it for the user")
    check((await page.inputValue("#email")) === "" && (await page.inputValue("#password")) === "", "and nothing is filled")
    await page.click("#google")
    await page.waitForURL("http://accounts.google.test:*/o/oauth2/chooser*")
    check(!!(await until("the chooser's tile is ringed", async () => (await rings(page)) === 1, 6000)), "on Google's chooser, a ring shows")
    await Bun.sleep(600)
    const tile = await page.locator('[data-identifier="kit@gmail.com"]').boundingBox()
    if (stills && tile) await page.screenshot({ path: join(stills, `signin-chooser-${scheme}.png`), clip: { x: Math.max(0, tile.x - 40), y: Math.max(0, tile.y - 60), width: tile.width + 80, height: tile.height + 100 } })
    await Bun.sleep(1200)
    check(new URL(page.url()).pathname === "/o/oauth2/chooser", "and nothing picks the account for the user")
    check(!(await hostLog(run)).some((r) => r.type === "fill"), "no fill anywhere")
    await page.click('[data-identifier="kit@gmail.com"]')
    await page.waitForURL("**/social/done**")
    check((await rings(page)) === 0, "back on the site, nothing is pointed at")
  } catch (err) {
    check(false, `sign in with threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "sign in with")
  } finally {
    await close(run)
  }
}

/** Typing narrows the menu, and a login typed by hand puts it away for the rest of the form. */
async function narrowing() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/login?next=home`)
    const menu = await menuOn(page)
    if (!menu) return void (await diagnose(run, page, "narrowing"))
    const shown = () => menu.locator("button.row:not([hidden]):not(.leaving)")
    const height = async () => (await (await menu.frameElement()).boundingBox())?.height ?? 0
    const tall = await height()
    await page.keyboard.type("k")
    check(!!(await until("typing narrows the list", async () => (await shown().count()) === 1)), "typing in the field narrows the menu to the logins that match")
    check(((await shown().locator(".sub").textContent()) ?? "") === "kit@acme.test", "to the one that matches")
    check(!!(await until("the menu shrinks to fit", async () => (await height()) < tall - 30)), "and the menu shrinks to fit")
    await page.keyboard.type("z")
    check(!!(await until("nothing matches: the menu goes", () => !extensionFrame(page, "menu.html"), 5000)), "when nothing matches, the menu goes by itself")
    await page.click("#password")
    await Bun.sleep(1500)
    check(!extensionFrame(page, "menu.html"), "and the rest of the form, typed by hand, gets no menu on click")
    await page.keyboard.press("ArrowDown")
    check(!!(await until("↓ still asks for it", () => extensionFrame(page, "menu.html"))), "↓ still brings it")
    await page.keyboard.press("Escape")
    // Clearing the identifier starts over; a password typed by hand puts the menu away.
    await page.click("#email")
    await until("a second click on the field brings the menu back", () => extensionFrame(page, "menu.html"))
    await page.keyboard.press("Escape")
    await page.keyboard.press("ControlOrMeta+a")
    await page.keyboard.press("Backspace")
    await page.click("#password")
    check(!!(await until("with the identifier cleared, the password field gets its menu again", () => extensionFrame(page, "menu.html"))), "clearing the identifier brings the menu back to the form")
    await Bun.sleep(700)
    await page.keyboard.type("x")
    check(!!(await until("typing a password puts the menu away", () => !extensionFrame(page, "menu.html"), 5000)), "typing a password by hand puts the menu away")
    check((await fillCount(run)) === 0, "and nothing was filled")
  } catch (err) {
    check(false, `narrowing threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "narrowing")
  } finally {
    await close(run)
  }
}

/**
 * Google's password step names the account it's for itself: the menu on its
 * password field narrows to that login, only on accounts.google.com (here
 * its e2e alias), and shows the whole list when no login matches. The same
 * page anywhere else narrows nothing.
 */
async function googleAccount() {
  const run = await launch({ google: true })
  const page = await run.context.newPage()
  const rows = async (path: string) => {
    await page.goto(path)
    const menu = await menuOn(page, 'input[name="Passwd"]')
    return menu ? ((await menu.locator("button.row .sub").allTextContents()) ?? []).map((t) => t.trim()) : null
  }
  try {
    const google = `http://accounts.google.test:${server.port}/v3/signin/challenge/pwd`
    const chip = await rows(`${google}?as=ryan@anoma.ly&hidden=`)
    check(JSON.stringify(chip) === JSON.stringify(["ryan@anoma.ly"]), `on Google's password step, the menu lists only the login for the account shown (${JSON.stringify(chip)})`)
    const first = await rows(`${google}?as=ryan@anoma.ly&hidden=kit@gmail.com`)
    check(JSON.stringify(first) === JSON.stringify(["ryan@anoma.ly"]), `the chip the user sees comes before the hidden box (${JSON.stringify(first)})`)
    const hidden = await rows(`${google}?as=ryan@anoma.ly&hidden=kit@gmail.com&nochip`)
    check(JSON.stringify(hidden) === JSON.stringify(["kit@gmail.com"]), `with no chip, the hidden username box names it, with no <form> around it (${JSON.stringify(hidden)})`)
    const none = await rows(`${google}?as=nobody@anoma.ly`)
    check(none?.length === 3, `an account no login has shows the whole list (${JSON.stringify(none)})`)
    const elsewhere = await rows(`http://www.acme.test:${server.port}/v3/signin/challenge/pwd?as=ryan@anoma.ly`)
    check(elsewhere?.length === 3, `the same page on another host narrows nothing (${JSON.stringify(elsewhere)})`)
    check((await fillCount(run)) === 0, "and nothing was filled")
  } catch (err) {
    check(false, `google account threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "google account")
  } finally {
    await close(run)
  }
}

/**
 * The save offer sits in the top right corner as a small pill, even over a
 * site's own header; it opens on approach and closes after, and a click in
 * the page shrinks it to a dot that reopens it.
 */
async function corner() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    await signIn(run, page, "/outcome/login?to=/outcome/header", "header@acme.test", "header password")
    const surface = await saveSurface(page)
    if (!surface) return void (await diagnose(run, page, "corner"))
    await Bun.sleep(700)
    const compact = await frameBox(surface)
    const view = page.viewportSize() ?? { width: 900, height: 640 }
    const inCorner = (b: typeof compact) => Math.abs(b.x + b.width - (view.width - 12)) <= 1.5 && Math.abs(b.y - 12) <= 1.5
    check(inCorner(compact) && compact.height <= 40 && compact.width < 260, `the offer is a small pill in the top right corner (${JSON.stringify(compact)})`)
    await surface.locator(".offer-row").hover()
    const open = await until("it opens on approach, down and to the left", async () => {
      const b = await frameBox(surface)
      return b.height > 60 && b.width > compact.width ? b : null
    })
    check(!!open && inCorner(open), `it opens on approach, from the corner (${JSON.stringify(open)})`)
    await page.mouse.move(80, 520)
    check(!!(await until("leaving closes it again", async () => (await frameBox(surface)).height <= 40, 3000)), "moving away closes it again")
    await page.mouse.click(80, 520)
    const dot = await until("a click in the page shrinks it to a dot", async () => {
      const b = await frameBox(surface)
      return b.width <= 30 && b.height <= 30 ? b : null
    }, 3000)
    check(!!dot && inCorner(dot), `a click in the page shrinks it to a dot in the corner (${JSON.stringify(dot)})`)
    check((await badge(run)) === "1", "and the toolbar keeps it")
    // Onto the dot, from the page, as a hand would.
    await page.mouse.move(dot!.x - 40, dot!.y + 40)
    await page.mouse.move(dot!.x + dot!.width / 2, dot!.y + dot!.height / 2, { steps: 6 })
    check(!!(await until("hovering the dot brings the pill back", async () => (await frameBox(surface)).width > 100, 3000)), "hovering the dot brings the pill back")
    // Save straight from the pill, without waiting for it to open.
    {
      await Bun.sleep(1200)
      const b = await surface.locator(".offer-row .btn.primary").boundingBox()
      await page.mouse.click(b!.x + b!.width / 2, b!.y + b!.height / 2)
      check(!!(await until("Save from the compact pill saves", async () => (await hostLog(run)).some((r) => r.type === "save"))), "Save straight from the compact pill saves")
      await until("the saved pill goes", () => !extensionFrame(page, "menu.html"), 6000)
    }
  } catch (err) {
    check(false, `corner threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "corner")
  } finally {
    await close(run)
  }
}

/**
 * The pill is an element of the page: a page that restyles it (with
 * !important) to cover the form while a fill is on its way gets nothing
 * written; the pill counts as Deadbolt's own only where Deadbolt put it.
 */
async function coveredPill() {
  const run = await launch({ fillDelay: 1 })
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/login?next=home`)
    const menu = await menuOn(page)
    if (menu) {
      await menu.locator("button.row").first().click()
      await until("the menu folds into a pill", async () => (await menu.locator(".pill").count().catch(() => 0)) > 0)
      // The host's own styles are inline and !important, which no stylesheet
      // beats; a page script can still rewrite them, and does after every write.
      await page.evaluate(() => {
        const host = document.querySelector(":popover-open") as HTMLElement
        const stretch = "position:fixed !important;inset:0 !important;width:100vw !important;height:100vh !important;margin:0 !important;display:block !important"
        // Only when Deadbolt changed it back (its own write sets a pixel width), or this would answer itself.
        new MutationObserver(() => host.style.width !== "100vw" && (host.style.cssText = stretch)).observe(host, { attributes: true, attributeFilter: ["style"] })
        host.style.cssText = stretch
      })
      await until("the delayed fill reaches the host", async () => (await fillCount(run)) > 0)
      await Bun.sleep(2500)
      check((await page.inputValue("#email")) === "" && (await page.inputValue("#password")) === "", "a pill the page stretched over the form isn't Deadbolt's own: nothing is written under it")
    }
  } catch (err) {
    check(false, `covered pill threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "covered pill")
  } finally {
    await close(run)
  }
}

/** Navigating away while the host is still answering: the new page gets nothing. */
async function midFill() {
  const run = await launch({ fillDelay: 2 })
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/login?next=home`)
    const menu = await menuOn(page)
    if (menu) {
      await menu.locator("button.row").first().click()
      await until("the menu folds into a Filling pill", async () => ((await menu.locator(".pill .pill-label").textContent().catch(() => "")) ?? "").includes("Filling"))
      await page.goto(`${site}/login?next=home`)
      await until("the delayed fill reaches the host", async () => (await fillCount(run)) > 0)
      await Bun.sleep(3000)
      check((await page.inputValue("#email")) === "" && (await page.inputValue("#password")) === "", "a fill that lands after navigating fills nothing")
    }
  } catch (err) {
    check(false, `navigation during fill threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "mid-fill")
  } finally {
    await close(run)
  }
}

/** Back to a page from the back/forward cache: no stale menu, and filling works again from a fresh report. */
async function backForward() {
  const run = await launch({ bfcache: true })
  const page = await run.context.newPage()
  // Chrome says whether a navigation came from the cache, and if not, why.
  const cdp = await run.context.newCDPSession(page)
  const navigations: string[] = []
  const notUsed: string[] = []
  cdp.on("Page.backForwardCacheNotUsed", (e: { notRestoredExplanations: Array<{ reason: string; type: string }> }) => {
    for (const r of e.notRestoredExplanations) notUsed.push(`${r.type}:${r.reason}`)
  })
  cdp.on("Page.frameNavigated", (e: { type: string; frame: { parentId?: string } }) => void (!e.frame.parentId && navigations.push(e.type)))
  await cdp.send("Page.enable")
  try {
    await page.goto(`${site}/login?next=home`)
    const start = Date.now()
    if (!(await menuOn(page, "#email", 30_000))) await diagnose(run, page, "bfcache first menu")
    else console.log(`  first menu after ${Date.now() - start}ms`)
    // A page holding an extension frame can't enter the cache (EmbedderExtensionFrame),
    // so leave with the menu closed, as after any fill.
    await page.keyboard.press("Escape")
    await until("esc closes the menu", () => !extensionFrame(page, "menu.html"))
    // Another site: same-site navigations may keep the browsing instance, which keeps the page out of the cache.
    await page.goto(`http://127.0.0.1:${server.port}/home`)
    // A page restored from the cache fires no load event.
    await page.goBack({ waitUntil: "commit" })
    await until("back on the login page", () => navigations.length === 3 || notUsed.length > 0)
    await Bun.sleep(500)
    const restored = navigations.at(-1) === "BackForwardCacheRestore"
    if (check(restored, `the login page comes back from the back/forward cache${notUsed.length ? ` (not: ${notUsed.join(", ")})` : ""}`)) {
      check(!extensionFrame(page, "menu.html"), "with no menu left open")
      const p = await popup(run, site)
      await p.locator("button", { hasText: "Fill" }).first().click()
      check(!!(await until("popup fill after restore", async () => (await page.inputValue("#password")) === "correct horse")), "the popup fills the restored page")
      await p.close()
      await page.evaluate(() => {
        for (const el of document.querySelectorAll("input")) el.value = ""
      })
      // Picked with the keyboard: headless Chromium on Linux sends a click on
      // a frame added to a restored page to the page itself (the host element
      // gets it, the menu never does) until the page is reloaded, a hit-test
      // gap in the browser no script can fill. Keyboard input goes to the
      // focused frame instead, so this still runs the whole pick.
      if (await menuOn(page)) {
        await page.focus("#email")
        await page.keyboard.press("ArrowDown")
        await Bun.sleep(300)
        await page.keyboard.press("ArrowDown")
        await Bun.sleep(300)
        await page.keyboard.press("Enter")
        check(!!(await until("menu fill after restore", async () => (await page.inputValue("#password")) === "hunter2")), "and so does a new menu")
      }
    }
  } catch (err) {
    check(false, `bfcache threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "bfcache")
  } finally {
    await close(run)
  }
}

// ---- Passkeys (a real agent signs) ------------------------------------------------

/** The agent's AAGUID (crates/cli/src/webauthn.rs): a credential with it is Deadbolt's. */
const DEADBOLT_AAGUID = "3a31ecda-fefc-f251-1f3e-a11bfdc1de5f"

type Outcome = { ok: boolean; value: any }
const startCall = (target: Page | Frame, name: string, kind: "create" | "get", json: unknown, extra: Record<string, unknown> = {}) =>
  target.evaluate(([n, k, j, e]) => (window as any).start(n, k, j, e), [name, kind, json, extra] as const)
const outcome = (target: Page | Frame, name: string, what: string, timeout = 15_000) =>
  until<Outcome>(what, () => target.evaluate((n) => (window as any).result(n), name), timeout)
/** The client data in a credential's JSON. */
const clientData = (credential: any) => JSON.parse(Buffer.from(credential.response.clientDataJSON, "base64url").toString())
/** Deadbolt's credentials are for the page's own origin, never cross-origin. */
const ownOrigin = (credential: any, how: string) => {
  const data = clientData(credential)
  check(data.origin === site && data.crossOrigin === false && !("topOrigin" in data), `${how}: crossOrigin is false (${JSON.stringify({ crossOrigin: data.crossOrigin, topOrigin: data.topOrigin })})`)
}
/** A frame of `page` showing the passkey test page, once its script runs. */
const passkeyFrame = (page: Page, what: string, match: (f: Frame) => boolean) =>
  until(what, async () => {
    const f = page.frames().find((f) => f !== page.mainFrame() && f.url().endsWith("/passkey") && match(f))
    return f && (await f.evaluate(() => typeof (window as any).start === "function").catch(() => false)) ? f : null
  })

/**
 * Every navigator.credentials.get that reaches the browser's own WebAuthn,
 * by mediation, in `__nativeGets`. An init script runs before the
 * extension's document_start scripts, so Deadbolt's hook (passkey-hook.ts)
 * wraps this spy and hands it only what it falls back on; `__spyUnder`
 * says the hook wasn't there first.
 */
const NATIVE_GETS = () => {
  const proto = CredentialsContainer.prototype as any
  const w = window as any
  w.__nativeGets = []
  w.__spyUnder = !proto[Symbol.for("deadbolt.passkeys")]
  const get = proto.get
  proto.get = function (this: CredentialsContainer, options?: any) {
    w.__nativeGets.push(options?.mediation ?? "optional")
    return get.call(this, options)
  }
}

/**
 * What the page's passkey autofill does, as Apple's sign-in frame: marks
 * the account field `webauthn` and starts a conditional get, whose state
 * stays in `__conditional`.
 */
const CONDITIONAL_GET = (selector: string) => {
  const w = window as any
  document.querySelector(selector)!.setAttribute("autocomplete", "username webauthn")
  w.__conditional = "pending"
  navigator.credentials.get({ mediation: "conditional", publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)) } } as CredentialRequestOptions).then(
    () => (w.__conditional = "answered"),
    (e) => (w.__conditional = e.name),
  )
}
const nativeGets = (target: Page | Frame) => target.evaluate(() => ({ under: (window as any).__spyUnder as boolean, gets: (window as any).__nativeGets as string[], secure: window.isSecureContext }))
const conditionalState = (target: Page | Frame) => target.evaluate(() => (window as any).__conditional as string)

/**
 * A passkey autofill sign-in (mediation "conditional") where Deadbolt's
 * inline menu opens: the top page, and Apple's sign-in frame in App Store
 * Connect (idmsa inside appstoreconnect, one site). The browser draws its
 * own passkey dropdown in browser UI, over Deadbolt's menu, so Deadbolt
 * holds the call: its menu shows, the browser's get is never called, and
 * picking a login fills it and leaves the call waiting. A cross-site
 * frame's call still goes to the browser.
 */
async function conditionalHeld() {
  const port = server.port
  const apple = `http://appstoreconnect.apple.test:${port}`
  const run = await launch({ secure: [apple, `http://idmsa.apple.test:${port}`, `http://idmsa.evilpay.test:${port}`] })
  await run.context.addInitScript(NATIVE_GETS)
  const page = await run.context.newPage()
  const menuNow = async () => {
    const f = extensionFrame(page, "menu.html")
    return f && (await f.locator("button.row").count()) > 0 ? f : null
  }
  try {
    // The top page.
    await page.goto(`${site}/passkey`)
    await formFound(page)
    await page.evaluate(CONDITIONAL_GET, "#email")
    const top = await menuOn(page, "#email")
    const spied = await nativeGets(page)
    check(spied.under && spied.secure, `the spy sits under Deadbolt's hook, in a secure context (${JSON.stringify(spied)})`)
    check(!!top, "a top page's conditional get leaves Deadbolt's menu to open on its webauthn field")
    check(spied.gets.length === 0, `and the browser's get is never called (${spied.gets})`)
    if (top) {
      await top.locator("button.row", { hasText: "kit@acme.test" }).click()
      check(!!(await until("the top page's field fills", async () => (await page.inputValue("#email")) === "kit@acme.test")), "picking a login fills it")
      await Bun.sleep(300)
      check((await conditionalState(page)) === "pending", `and leaves the conditional get waiting (${await conditionalState(page)})`)
    }

    // Apple's sign-in frame.
    await page.goto(`${apple}/apple/login`)
    const widget = await until("the sign-in frame loads", () => page.frames().find((f) => f.url().includes("/appleauth/auth/signin")) ?? null)
    if (widget) {
      const reports = async () => (await run.worker.evaluate(() => (globalThis as unknown as { __seen: string[] }).__seen)).filter((s) => /^db:page@[1-9]\d*:\/appleauth\/auth\/signin$/.test(s)).length
      await until("the frame's form is found", async () => (await reports()) > 0, 15_000)
      const before = await reports()
      await widget.evaluate(CONDITIONAL_GET, "#account_name_text_field")
      // The new autocomplete changes the frame's form: let it report again before the click.
      await until("the frame reports its webauthn field", async () => (await reports()) > before, 5000)
      await widget.click("#account_name_text_field")
      const menu = await until("the menu opens for the frame's field", menuNow, 15_000)
      const framed = await nativeGets(widget)
      check(framed.under && framed.secure, `the frame's spy sits under the hook, in a secure context (${JSON.stringify(framed)})`)
      check(!!menu && menu.parentFrame() === page.mainFrame(), "Apple's frame's conditional get leaves Deadbolt's menu to open in the top page")
      check(framed.gets.length === 0, `and the browser's get is never called (${framed.gets})`)
      check(((await menu?.locator(".row .sub").allTextContents()) ?? []).every((s) => !s.startsWith("Passkey")), "with logins only: the agent's client data couldn't say cross-origin")
      if (menu) {
        await settled(menu)
        await menu.locator("button.row", { hasText: "kit@acme.test" }).click()
        check(!!(await until("the frame's field fills", async () => (await widget.inputValue("#account_name_text_field")) === "kit@acme.test")), "picking a login fills the frame")
        check((await conditionalState(widget)) === "pending", `and leaves its conditional get waiting (${await conditionalState(widget)})`)
      } else await diagnose(run, page, "conditionalHeld")
    }

    // A cross-site frame: the browser's own.
    await page.goto(`${apple}/apple/login?frame=idmsa.evilpay.test`)
    const evil = await until("the cross-site frame loads", () => page.frames().find((f) => f.url().startsWith(`http://idmsa.evilpay.test:${port}/`)) ?? null)
    if (evil) {
      await until("its field shows", () => evil.evaluate(() => !!document.querySelector("#account_name_text_field")).catch(() => false))
      await evil.evaluate(CONDITIONAL_GET, "#account_name_text_field")
      const went = await until("the cross-site frame's get reaches the browser", async () => ((await nativeGets(evil)).gets.includes("conditional") ? true : null), 5000)
      check(!!went, "a cross-site frame's conditional get goes to the browser")
    }
  } catch (err) {
    check(false, `conditionalHeld threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "conditionalHeld")
  } finally {
    await close(run)
  }
}

/** A throwaway Deadbolt store and the environment that points the binary at it. */
async function deadboltStore() {
  // Short: the agent's socket path must fit in a sockaddr (104 bytes on macOS).
  const dir = await mkdtemp(process.platform === "darwin" ? "/tmp/dbpk-" : join(tmpdir(), "dbpk-"))
  const env = {
    DEADBOLT_HOME: join(dir, "home"),
    XDG_RUNTIME_DIR: join(dir, "run"),
    XDG_STATE_HOME: join(dir, "state"),
    XDG_CONFIG_HOME: join(dir, "config"),
    DEADBOLT_NET: "local",
    DEADBOLT_KDF: "fast",
    DEADBOLT_PASSPHRASE: "correct horse battery",
  }
  const cli = (...args: string[]) => {
    const r = Bun.spawnSync([deadbolt!, ...args], { env: { ...process.env, ...env }, stdin: "ignore" })
    return { ok: r.exitCode === 0, out: `${r.stdout}${r.stderr}` }
  }
  return { dir, env, cli }
}

async function passkeys() {
  if (!deadbolt) return void console.log("skip: passkeys need --deadbolt <path to the deadbolt binary>")
  const store = await deadboltStore()
  const init = store.cli("init", "--device-name", "e2e")
  if (!check(init.ok, "a throwaway store is set up")) return void console.log(init.out)
  const run = await launch({ realHost: store.env })
  const page = await run.context.newPage()
  const rpID = "localhost"
  // The browser's own WebAuthn, for the calls Deadbolt hands back to it.
  const cdp = await run.context.newCDPSession(page)
  await cdp.send("WebAuthn.enable", { enableUI: false })
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  })
  const prompt = async (name: string) => {
    if (!(await offered(run, `${name}: the passkey prompt badges the toolbar button`))) return null
    return popup(run, site, name)
  }
  const press = async (p: Page, label: string) => {
    await p.locator(".passkey-prompt button", { hasText: label }).first().click()
    await p.close().catch(() => {})
  }
  try {
    await page.goto(`${site}/passkey`)
    await formFound(page)

    // Registration, asked in the popup and signed by the agent.
    const reg = await generateRegistrationOptions({
      rpName: "Acme",
      rpID,
      userName: "kit@acme.test",
      attestationType: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
      supportedAlgorithmIDs: [-7, -257],
    })
    await startCall(page, "register", "create", reg)
    const save = await prompt("passkey-save")
    let credential: WebAuthnCredential | null = null
    if (save) {
      check((await save.locator(".passkey-prompt h2").textContent()) === "Save a passkey for localhost?", "the popup asks to save a passkey for the site")
      await press(save, "Save")
      const made = await outcome(page, "register", "registration settles")
      if (check(!!made?.ok, `the page gets a credential (${made?.value && !made.ok ? made.value : "ok"})`)) {
        const v = await verifyRegistrationResponse({ response: made!.value, expectedChallenge: reg.challenge, expectedOrigin: site, expectedRPID: rpID, requireUserVerification: false }).catch((e) => {
          check(false, `registration verifies: ${e.message}`)
          return null
        })
        if (v && check(v.verified, "@simplewebauthn/server verifies the registration")) {
          const info = v.registrationInfo!
          check(info.aaguid === DEADBOLT_AAGUID, `the agent made it (AAGUID ${info.aaguid})`)
          check(info.fmt === "none" && info.credentialType === "public-key", "with none attestation")
          check(info.credentialDeviceType === "multiDevice" && info.credentialBackedUp, "flagged as a synced (backed-up) passkey")
          check(!info.userVerified, "and not user-verified: no Touch ID here")
          check(info.credential.counter === 0, "with a zero sign counter")
          ownOrigin(made!.value, "registration")
          credential = info.credential
        }
      }
      const shown = store.cli("show", "--reveal", rpID)
      check(shown.ok && shown.out.includes("kit@acme.test") && !shown.out.includes("private-key"), "the vault has the passkey, and never shows its private key")
    }

    // The same account again: the site excluded it, so it's already saved.
    if (credential) {
      await startCall(page, "again", "create", { ...reg, excludeCredentials: [{ id: credential.id, type: "public-key" }] })
      const again = await prompt("passkey-registered")
      if (again) {
        check((await again.locator(".passkey-prompt h2").textContent()) === "This passkey is already saved", "an excluded passkey shows as already saved")
        await press(again, "OK")
        const r = await outcome(page, "again", "excluded registration settles")
        check(!!r && !r.ok && String(r.value).startsWith("InvalidStateError"), `and the page gets InvalidStateError (${r?.value})`)
      }
    }

    // Modal sign-in: the popup lists the site's passkeys.
    if (credential) {
      const auth = await generateAuthenticationOptions({ rpID, userVerification: "preferred" })
      await startCall(page, "modal", "get", auth)
      const signIn = await prompt("passkey-sign-in")
      if (signIn) {
        check((await signIn.locator(".passkey-prompt .account-title").allTextContents()).join(",") === "kit@acme.test", "the popup lists the passkey by username")
        await press(signIn, "Sign in")
        const r = await outcome(page, "modal", "modal sign-in settles")
        if (check(!!r?.ok, `modal sign-in returns an assertion (${r && !r.ok ? r.value : "ok"})`)) {
          await verifyAssertion(r!.value, auth.challenge, credential, "modal")
          ownOrigin(r!.value, "modal sign-in")
        }
      }
    }

    // Autofill sign-in: the passkey waits in the inline menu.
    if (credential) {
      await page.reload()
      await formFound(page)
      const auth = await generateAuthenticationOptions({ rpID, userVerification: "preferred" })
      await startCall(page, "auto", "get", auth, { mediation: "conditional" })
      await Bun.sleep(500)
      check((await badge(run)) === "", "an autofill sign-in opens no prompt by itself")
      const menu = await menuOn(page, "#email")
      if (menu) {
        check((await menu.locator(".row .title").allTextContents()).join(",") === "kit@acme.test", "the inline menu offers the passkey")
        const sub = (await menu.locator(".row .sub").first().textContent()) ?? ""
        check(/^Passkey · \S/.test(sub), `as a passkey, with its vault (${sub})`)
        await shot(page, "passkey-menu", { x: 250, y: 80, width: 420, height: 240 })
        await menu.locator("button.row").first().click()
        const r = await outcome(page, "auto", "autofill sign-in settles")
        if (check(!!r?.ok, `picking it signs in (${r && !r.ok ? r.value : "ok"})`)) {
          await verifyAssertion(r!.value, auth.challenge, credential, "autofill")
          ownOrigin(r!.value, "autofill sign-in")
        }
      } else await diagnose(run, page, "passkey menu")
    }

    // The page's AbortSignal ends the prompt.
    await startCall(page, "aborted", "get", await generateAuthenticationOptions({ rpID }))
    if (await offered(run, "a modal sign-in badges the toolbar button")) {
      await page.evaluate(() => (window as any).abort("aborted"))
      const r = await outcome(page, "aborted", "aborted sign-in settles")
      check(!!r && !r.ok && String(r.value).startsWith("AbortError"), `an aborted sign-in rejects with AbortError (${r?.value})`)
      check(!!(await until("abort clears the badge", async () => (await badge(run)) === "")), "and the prompt goes away")
    }

    // Leaving the page ends its prompt.
    await startCall(page, "left", "get", await generateAuthenticationOptions({ rpID }))
    if (await offered(run, "another sign-in badges the toolbar button")) {
      await page.goto(`${site}/home`)
      check(!!(await until("navigation clears the badge", async () => (await badge(run)) === "")), "navigating away ends the passkey prompt")
      const p = await popup(run, site)
      check((await p.locator(".passkey-prompt").count()) === 0, "and the popup no longer shows it")
      await p.close()
    }

    // A page flooding calls takes its own tab's few slots; another tab's
    // abort still lands at once, and its next sign-in still works.
    if (credential) {
      await page.goto(`${site}/passkey?b`)
      await formFound(page)
      const b = `${site}/passkey?b`
      await startCall(page, "waiting", "get", await generateAuthenticationOptions({ rpID }))
      if (await until("the other tab's sign-in badges its button", async () => (await badge(run, b)) === "1", 20_000)) {
        const flood = await run.context.newPage()
        await flood.goto(`${site}/passkey?flood`)
        await flood.bringToFront()
        const auth = await generateAuthenticationOptions({ rpID })
        const reg = await generateRegistrationOptions({ rpName: "Acme", rpID, userName: "flood@acme.test", attestationType: "none", supportedAlgorithmIDs: [-7] })
        await flood.evaluate(
          ([a, r]) => {
            for (let i = 0; i < 40; i++) (window as any).start(`flood${i}`, i % 2 ? "create" : "get", i % 2 ? r : a)
          },
          [auth, reg] as const,
        )
        const refused = await until("the flood past the tab's slots is refused", async () => {
          const done = (await flood.evaluate(() => (window as any).results("flood"))) as (Outcome | null)[]
          return done.filter((r) => r && !r.ok && String(r.value).startsWith("NotAllowedError")).length >= 32 && done
        })
        check(!!refused, `a flooding page gets NotAllowedError past its tab's slots (${refused ? refused.filter(Boolean).length : 0} of 40 settled)`)
        const started = Date.now()
        await page.evaluate(() => (window as any).abort("waiting"))
        const r = await outcome(page, "waiting", "the other tab's abort settles", 3000)
        check(!!r && !r.ok && String(r.value).startsWith("AbortError") && Date.now() - started < 3000, `another tab's abort lands during the flood (${r?.value}, ${Date.now() - started}ms)`)
        await flood.close()
        await page.bringToFront()
        const auth2 = await generateAuthenticationOptions({ rpID, userVerification: "preferred" })
        await startCall(page, "after-flood", "get", auth2)
        if (await until("a sign-in after the flood badges its button", async () => (await badge(run, b)) === "1", 20_000)) {
          await press(await popup(run, b), "Sign in")
          const after = await outcome(page, "after-flood", "the sign-in after the flood settles")
          if (check(!!after?.ok, `and its next sign-in works (${after && !after.ok ? after.value : "ok"})`)) await verifyAssertion(after!.value, auth2.challenge, credential, "after the flood")
        }
      }
    }

    // Use another device: the browser's own WebAuthn takes over.
    let nativeId: string | null = null
    await page.goto(`${site}/passkey`)
    await formFound(page)
    const other = await generateRegistrationOptions({ rpName: "Acme", rpID, userName: "other@acme.test", attestationType: "none", supportedAlgorithmIDs: [-7] })
    await startCall(page, "native", "create", other)
    const choose = await prompt("passkey-other-device")
    if (choose) {
      // The real popup is a bubble over the site's tab, which stays shown;
      // here it is a tab of its own, and Chromium refuses the browser's
      // WebAuthn ("the page does not have focus") unless the site's tab is
      // the one shown. Show it, as the real popup leaves it.
      await page.bringToFront()
      await press(choose, "Use another device")
      const r = await outcome(page, "native", "fallback registration settles")
      const v = r?.ok ? await verifyRegistrationResponse({ response: r.value, expectedChallenge: other.challenge, expectedOrigin: site, expectedRPID: rpID }).catch(() => null) : null
      check(!!v?.verified && v.registrationInfo!.aaguid !== DEADBOLT_AAGUID, `"Use another device" hands the call to the browser (${r?.ok ? v?.registrationInfo?.aaguid : r?.value})`)
      if (v?.verified) nativeId = v.registrationInfo!.credential.id
    }

    // Credential lists Deadbolt can't take whole go to the browser whole,
    // even with Deadbolt's own passkey on them: one past 64 entries (which
    // the browser refuses too), or one with an entry that isn't a public-key id.
    if (credential && nativeId) {
      const filler = () => Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64url")
      const lists = {
        long: [credential.id, ...Array.from({ length: 63 }, filler), nativeId].map((id) => ({ id, type: "public-key" })),
        odd: [{ id: credential.id, type: "public-key" }, { id: filler(), type: "future-type" }, { id: nativeId, type: "public-key" }],
      }
      for (const [name, allowCredentials] of Object.entries(lists)) {
        await startCall(page, `list-${name}`, "get", { ...(await generateAuthenticationOptions({ rpID })), allowCredentials })
        const r = await outcome(page, `list-${name}`, `the ${name} allow list settles`)
        if (name === "long") check(!!r && !r.ok && /^RangeError: .*allowCredentials.*\(64\)/.test(r.value), `a 65-entry allow list goes whole to the browser, which refuses it (${r?.ok ? r.value.id : r?.value})`)
        else check(!!r?.ok && r.value.id === nativeId, `a mixed-type allow list goes whole to the browser (${r?.ok ? (r.value.id === nativeId ? "the browser's passkey" : r.value.id) : r?.value})`)
        check((await badge(run)) === "", "with no Deadbolt prompt")
      }
    }

    // A same-origin frame is Deadbolt's.
    if (credential) {
      await page.goto(`${site}/passkey/same`)
      const frame = await passkeyFrame(page, "the same-origin frame loads", () => true)
      if (frame) {
        const auth = await generateAuthenticationOptions({ rpID })
        await startCall(frame, "same", "get", auth)
        const signIn = await prompt("passkey-same-frame")
        if (signIn) {
          await press(signIn, "Sign in")
          const r = await outcome(frame, "same", "same-origin frame sign-in settles")
          if (check(!!r?.ok, `a same-origin frame signs in with Deadbolt (${r && !r.ok ? r.value : "ok"})`)) ownOrigin(r!.value, "same-origin frame")
        }
      }
    }

    // The site inside another origin inside the site: the browser's, which
    // marks it cross-origin.
    if (nativeId) {
      await page.goto(`${site}/passkey/nested`)
      const inner = await passkeyFrame(page, "the nested frame loads", (f) => !!f.parentFrame()?.url().startsWith("http://127.0.0.1"))
      if (inner) {
        await startCall(inner, "nested", "get", await generateAuthenticationOptions({ rpID }))
        const r = await outcome(inner, "nested", "nested-frame sign-in settles")
        const data = r?.ok ? clientData(r.value) : null
        check(!!data && data.crossOrigin === true && r!.value.id === nativeId, `a frame under another origin gets the browser's flow (${data ? `crossOrigin ${data.crossOrigin}` : r?.value})`)
        check((await badge(run, `${site}/passkey/nested`)) === "", "with no Deadbolt prompt")
      }
    }

    // Where Permissions Policy turns WebAuthn off, the browser refuses it.
    await page.goto(`${site}/passkey/denied`)
    for (const kind of ["get", "create"] as const) {
      await startCall(page, `denied-${kind}`, kind, kind === "get" ? await generateAuthenticationOptions({ rpID }) : reg)
      const r = await outcome(page, `denied-${kind}`, `policy-denied ${kind} settles`)
      check(!!r && !r.ok && String(r.value).startsWith("NotAllowedError") && !String(r.value).includes("Deadbolt"), `a page whose policy denies ${kind} gets the browser's refusal (${r?.value})`)
    }
    check((await badge(run, `${site}/passkey/denied`)) === "", "with no Deadbolt prompt")
    await page.goto(`${site}/passkey/same-denied`)
    const denied = await passkeyFrame(page, "the denied frame loads", () => true)
    if (denied) {
      await startCall(denied, "frame-denied", "get", await generateAuthenticationOptions({ rpID }))
      const r = await outcome(denied, "frame-denied", "policy-denied frame settles")
      check(!!r && !r.ok && String(r.value).startsWith("NotAllowedError") && !String(r.value).includes("Deadbolt"), `so does a frame its page denies (${r?.value})`)
      check((await badge(run, `${site}/passkey/same-denied`)) === "", "with no Deadbolt prompt")
    }
    await page.goto(`${site}/passkey`)
    await formFound(page)

    // Lists the page passes as generators reach the browser whole, after
    // Deadbolt has read them: a restricted sign-in never turns into discovery,
    // an exclusion never vanishes, and RS256-only stays RS256-only.
    if (credential && nativeId) {
      const filler = () => Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64url")
      const allowCredentials = [credential.id, ...Array.from({ length: 63 }, filler), nativeId].map((id) => ({ id, type: "public-key" }))
      await startCall(page, "gen-allow", "get", { ...(await generateAuthenticationOptions({ rpID })), allowCredentials }, { generator: true })
      const allowed = await outcome(page, "gen-allow", "the generated allow list settles")
      check(!!allowed && !allowed.ok && /^RangeError: .*allowCredentials.*\(64\)/.test(allowed.value), `a generated 65-entry allow list reaches the browser whole (${allowed?.ok ? `signed with ${allowed.value.id === nativeId ? "the browser's passkey" : allowed.value.id}` : allowed?.value})`)
      const excluded = await generateRegistrationOptions({ rpName: "Acme", rpID, userName: "gen@acme.test", attestationType: "none", supportedAlgorithmIDs: [-7] })
      const excludeCredentials = [{ id: nativeId, type: "public-key" }, { id: filler(), type: "future-type" }]
      await startCall(page, "gen-exclude", "create", { ...excluded, excludeCredentials }, { generator: true })
      const ex = await outcome(page, "gen-exclude", "the generated exclude list settles")
      check(!!ex && !ex.ok && String(ex.value).startsWith("InvalidStateError"), `a generated exclude list still excludes in the browser (${ex?.ok ? "made a passkey" : ex?.value})`)
      const rs = await generateRegistrationOptions({ rpName: "Acme", rpID, userName: "gen-rsa@acme.test", attestationType: "none", supportedAlgorithmIDs: [-257] })
      await startCall(page, "gen-rsa", "create", rs, { generator: true })
      const made = await outcome(page, "gen-rsa", "the generated RS256-only registration settles")
      check(!!made?.ok && made.value.response.publicKeyAlgorithm === -257, `generated RS256-only params go to the browser (${made?.ok ? made.value.response.publicKeyAlgorithm : made?.value})`)
      check((await badge(run)) === "", "none of them asks Deadbolt's user")
    }

    // A site that doesn't take ES256 gets the browser's flow without asking.
    const rsa = await generateRegistrationOptions({ rpName: "Acme", rpID, userName: "rsa@acme.test", attestationType: "none", supportedAlgorithmIDs: [-257] })
    await startCall(page, "rsa", "create", rsa)
    const rsaDone = await outcome(page, "rsa", "RS256-only registration settles")
    check((await badge(run)) === "", "an RS256-only site gets no Deadbolt prompt")
    check(!!rsaDone && (rsaDone.ok ? rsaDone.value.response.publicKeyAlgorithm !== -7 : !String(rsaDone.value).includes("Deadbolt")), `and goes to the browser (${rsaDone?.ok ? "made by the browser" : rsaDone?.value})`)

    // Another site's rpId: refused before anyone is asked.
    await startCall(page, "wrong", "create", { ...(await generateRegistrationOptions({ rpName: "Evil", rpID: "example.com", userName: "kit" })) })
    const wrong = await outcome(page, "wrong", "wrong-rpId registration settles")
    check(!!wrong && !wrong.ok && wrong.value === "SecurityError: This relying party ID isn't this site's.", `a wrong rpId is Deadbolt's SecurityError (${wrong?.value})`)
    await startCall(page, "wrong-get", "get", await generateAuthenticationOptions({ rpID: "com" }))
    const wrongGet = await outcome(page, "wrong-get", "public-suffix sign-in settles")
    check(!!wrongGet && !wrongGet.ok && wrongGet.value === "SecurityError: This relying party ID isn't this site's.", `a public suffix rpId is too (${wrongGet?.value})`)
    check((await badge(run)) === "", "and neither asks the user")

    // Sandboxed frames and pages: opaque origins get nothing.
    await page.goto(`${site}/passkey/framed`)
    const frame = await passkeyFrame(page, "the sandboxed frame loads", () => true)
    if (frame) {
      await startCall(frame, "sandboxed", "get", await generateAuthenticationOptions({ rpID }))
      const r = await outcome(frame, "sandboxed", "sandboxed-frame sign-in settles")
      check(!!r && !r.ok && r.value === "NotAllowedError: Deadbolt offers no passkeys to sandboxed frames.", `a sandboxed frame is refused by Deadbolt (${r?.value})`)
    }
    await page.goto(`${site}/passkey/sandboxed`)
    await startCall(page, "csp", "create", reg)
    const csp = await outcome(page, "csp", "sandboxed-page registration settles")
    check(!!csp && !csp.ok && csp.value === "NotAllowedError: Deadbolt offers no passkeys to sandboxed frames.", `so is a page sandboxed by its CSP (${csp?.value})`)
    check((await badge(run, `${site}/passkey/sandboxed`)) === "", "with no prompt")
    const after = store.cli("show", rpID)
    check(after.ok && !after.out.includes("other@acme.test") && !after.out.includes("rsa@acme.test"), "only the passkey saved through Deadbolt is in the vault")
  } catch (err) {
    check(false, `passkeys threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "passkeys")
  } finally {
    await close(run)
    store.cli("agent", "stop")
    await rm(store.dir, { recursive: true, force: true })
  }
}

async function verifyAssertion(response: any, expectedChallenge: string, credential: WebAuthnCredential, how: string) {
  const v = await verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin: site, expectedRPID: "localhost", credential, requireUserVerification: false }).catch((e) => {
    check(false, `${how} assertion verifies: ${e.message}`)
    return null
  })
  if (v) check(v.verified && !v.authenticationInfo.userVerified, `@simplewebauthn/server verifies the ${how} assertion (no UV without Touch ID)`)
}

// ---- Addresses and cards ------------------------------------------------------------

/** The frame of the page whose URL starts with `prefix`, once it has reported its identity or card fields. */
async function formsFound(run: Run, page: Page, path: string) {
  await until(`the forms on ${path} are found`, () => run.worker.evaluate((p) => (globalThis as unknown as { __seen: string[] }).__seen.some((s) => s.startsWith("db:forms-page@") && s.endsWith(p)), path), 15_000)
}

/** Clicks a field (in `frame`, or the page) and waits for the forms menu, at rest. */
async function formsMenu(run: Run, page: Page, selector: string, path: string, frame?: Frame) {
  await formsFound(run, page, path)
  await (frame ?? page).click(selector)
  const menu = await until(`forms menu on ${selector}`, async () => {
    const f = extensionFrame(page, "menu.html")
    return f && (await f.locator("button.row").count()) > 0 ? f : null
  }, 15_000)
  if (menu) await settled(menu)
  return menu
}

/** Picks the row with `text` with the pointer, and waits for the pill to say how it went. */
async function pickRow(menu: Frame, text: string) {
  await menu.locator("button.row", { hasText: text }).first().click()
  return until(`the pill settles after picking ${text}`, async () => {
    if (await menu.locator(".pill.ok").count().catch(() => 0)) return "ok"
    if (await menu.locator(".pill.failed").count().catch(() => 0)) {
      console.log(`  the pill says: ${await menu.locator(".pill .pill-label").getAttribute("title").catch(() => "?")}`)
      return "failed"
    }
    return null
  }, 15_000)
}

const formFills = async (run: Run) => (await hostLog(run)).filter((r) => r.type === "fill-form") as Array<{ ref: string; fields: string[]; origin: string }>
const values = (page: Page | Frame, ids: string[]) => Promise.all(ids.map((id) => page.inputValue(`#${id}`)))

/** A shipping address with tokens and a card with its expiry in one box, in the light and dark themes, with stills of both menus. */
async function formsSurface(scheme: Scheme) {
  const run = await launch({ scheme })
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/forms/tokens`)
    const menu = await formsMenu(run, page, "#ship-name", "/forms/tokens")
    if (menu) {
      check((await menu.locator(".row .title").allTextContents()).join(",") === "Home,Work", "an address field lists the identities")
      const sub = await menu.locator(".row .sub").first().textContent()
      check(sub === "Fills name, phone, address · Kit Langton · 123 Main St, Brooklyn", `with what each fills and its summary (${sub})`)
      await shotAround(page, `forms-address-${scheme}`, menu, "#ship-name")
      check((await pickRow(menu, "Home")) === "ok", "picking an identity says Filled")
      const got = await values(page, ["ship-name", "ship-a1", "ship-a2", "ship-city", "ship-state", "ship-zip", "ship-country", "ship-tel"])
      check(JSON.stringify(got) === JSON.stringify(["Kit Langton", "123 Main St", "Apt 4", "Brooklyn", "NY", "11201", "US", "+14155550123"]), `the whole address fills, selects included (${got.join(" | ")})`)
      const skipped = await values(page, ["ship-org", "ship-a3", "ship-email"])
      check(skipped.every((v) => !v), `a tiny field, a covered one and one off screen get nothing (${skipped.join(" | ")})`)
      check((await page.evaluate(() => scrollY)) === 0, "and the page isn't scrolled to fill")
      const asked = (await formFills(run))[0]
      check(!!asked && !asked.fields.includes("number") && !asked.fields.includes("birthday") && asked.fields.includes("phone"), `fill-form asks only for what the fields need (${asked?.fields.join(",")})`)
    }

    await page.goto(`${site}/forms/card-single`)
    const cards = await formsMenu(run, page, "#cc", "/forms/card-single")
    if (cards) {
      check((await cards.locator(".row .title").first().textContent()) === "Visa ••4242 · 08/28", "a card field lists cards as brand, last digits and expiry")
      // The browser-only vault has no Touch ID: Comfortable fills on the pick (Strict's passphrase is e2e/standalone.ts's).
      if (standalone) check((await footText(cards)) === "", "and asks for nothing more under Comfortable")
      else check((await footText(cards)) === "Deadbolt may ask for Touch ID.", "and says Touch ID may be asked")
      await shotAround(page, `forms-card-${scheme}`, cards, "#cc")
      check((await pickRow(cards, "Visa")) === "ok", "picking a card says Filled")
      const got = await values(page, ["cc", "exp", "cvc", "holder"])
      check(JSON.stringify(got) === JSON.stringify(["4242 4242 4242 4242", "08 / 28", "123", "Kit Langton"]), `the card fills: spaced number, MM / YY, code, name (${got.join(" | ")})`)
    }
  } catch (err) {
    check(false, `formsSurface threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "formsSurface")
  } finally {
    await close(run)
  }
}

/** Addresses by labels only (German, split name, selects), and cards with expiry selects and split number boxes. */
async function formsShapes() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/forms/labels`)
    // What the user types themselves stays: the city, typed before the pick.
    await formsFound(run, page, "/forms/labels")
    await page.click("#ort")
    await Bun.sleep(400)
    await page.keyboard.type("Berlin")
    await page.keyboard.press("Escape")
    const menu = await formsMenu(run, page, "#vn", "/forms/labels")
    if (menu && (await pickRow(menu, "Home")) === "ok") {
      const got = await values(page, ["vn", "nn", "str", "plz", "ort", "bl", "land"])
      check(JSON.stringify(got) === JSON.stringify(["Kit", "Langton", "123 Main St", "11201", "Berlin", "NY", "US"]), `a labels-only address fills, the name split, region and country selects matched, the typed city kept (${got.join(" | ")})`)
      await until("the pill goes", () => !extensionFrame(page, "menu.html"), 5000)
      // Another pick replaces what Deadbolt filled, never what was typed.
      const again = await formsMenu(run, page, "#vn", "/forms/labels")
      if (again && (await pickRow(again, "Work")) === "ok") {
        const next = await values(page, ["str", "plz", "ort", "bl"])
        check(JSON.stringify(next) === JSON.stringify(["1 Market St", "94105", "Berlin", "CA"]), `picking another identity replaces Deadbolt's values, not the user's (${next.join(" | ")})`)
      } else check(false, "a second pick fills")
    } else check(false, "the labels-only address fills")

    await page.goto(`${site}/forms/card-selects`)
    const selects = await formsMenu(run, page, "#cc", "/forms/card-selects")
    if (selects && (await pickRow(selects, "Visa")) === "ok") {
      const got = await values(page, ["cc", "mm", "yy", "cvv"])
      check(JSON.stringify(got) === JSON.stringify(["4242424242424242", "08", "2028", "123"]), `expiry month and year selects fill (${got.join(" | ")})`)
    } else check(false, "the card with expiry selects fills")

    await page.goto(`${site}/forms/card-split`)
    const split = await formsMenu(run, page, "#b1", "/forms/card-split")
    if (split && (await pickRow(split, "Visa")) === "ok") {
      const got = await values(page, ["b1", "b2", "b3", "b4", "cvv"])
      check(JSON.stringify(got) === JSON.stringify(["4242", "4242", "4242", "4242", "123"]), `a card number split over four boxes fills each (${got.join(" | ")})`)
    } else check(false, "the split card number fills")
  } catch (err) {
    check(false, `formsShapes threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "formsShapes")
  } finally {
    await close(run)
  }
}

/**
 * A card into a payment provider's cross-origin frame (Stripe, on its
 * e2e alias): the menu opens in the top page under the frame's field,
 * names both, and the card goes into the frame and the page's own name
 * box. An unknown cross-origin frame gets no menu and no card.
 */
async function formsFrames() {
  const run = await launch()

  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/forms/stripe`)
    const frame = await until("the Stripe frame loads", () => page.frames().find((f) => f.url().includes("js.stripe.test")) ?? null)
    if (frame) {
      const menu = await formsMenu(run, page, "#cardnumber", "/forms/card-frame", frame)
      if (menu) {
        check(menu.parentFrame() === page.mainFrame(), "a field in the provider's frame opens the menu in the top page")
        check(((await menu.locator("#caption").textContent()) ?? "").trim() === "Into Stripe on localhost", "the menu names the provider and the site")
        await shotAround(page, "forms-card-frame-light", menu, "#pay")
        const box = await (await menu.frameElement()).boundingBox()
        const field = await page.locator("#pay").boundingBox()
        check(!!box && !!field && box.y > field.y && box.y < field.y + field.height, "under the frame's field")
        check((await pickRow(menu, "Visa")) === "ok", "picking the card says Filled")
        const got = await values(frame, ["cardnumber", "exp-date", "cvc"])
        check(JSON.stringify(got) === JSON.stringify(["4242424242424242", "08 / 28", "123"]), `the card fills into the provider's frame (${got.join(" | ")})`)
        check((await page.inputValue("#holder")) === "", "but not the page's own name-on-card box: one pick, one party")
        const asked = (await formFills(run)).at(-1)
        check(JSON.stringify(asked?.fields.sort()) === JSON.stringify(["cvv", "expiry", "number"]), `fill-form asks only for the provider frame's fields (${asked?.fields.join(",")})`)
        await until("the pill goes", () => !extensionFrame(page, "menu.html"), 5000)
        // From the page's own field: the page only, never the provider's frame.
        const own = await formsMenu(run, page, "#holder", "/forms/stripe")
        if (own) {
          check(((await own.locator("#caption").textContent()) ?? "").trim() === "On localhost", "the page's own card menu names only the site")
          await frame.fill("#cardnumber", "")
          check((await pickRow(own, "Visa")) === "ok", "picking the card from the page's field fills")
          check((await page.inputValue("#holder")) === "Kit Langton", "the page's name-on-card box")
          check((await frame.inputValue("#cardnumber")) === "", "and nothing goes into the provider's frame from it")
          check(!(await formFills(run)).at(-1)?.fields.includes("number"), "nor is the number asked for")
        }
      }
    }

    await page.goto(`${site}/forms/unknown`)
    const evil = await until("the unknown frame loads", () => page.frames().find((f) => f.url().includes("evilpay.test")) ?? null)
    if (evil) {
      await formsFound(run, page, "/forms/unknown")
      await Bun.sleep(1500)
      await evil.click("#cardnumber")
      await Bun.sleep(2500)
      check(!extensionFrame(page, "menu.html"), "an unknown cross-origin card frame opens no menu")
      // A card picked from the page's own field doesn't go into it either.
      const menu = await formsMenu(run, page, "#holder", "/forms/unknown")
      check(!!menu && !((await menu.locator("#caption").textContent()) ?? "").includes("Into"), "the page's own card menu names no provider")
      if (menu) check((await pickRow(menu, "Visa")) === "ok", "picking the card fills the page's own field")
      check((await page.inputValue("#holder")) === "Kit Langton", "the page's name-on-card box fills")
      const got = await values(evil, ["cardnumber", "exp-date", "cvc"])
      check(got.every((v) => !v), "nothing goes into the unknown frame")
      const last = (await formFills(run)).at(-1)
      check(!!last && !last.fields.includes("number") && !last.fields.includes("cvv"), `and its number and code are never asked for (${last?.fields.join(",")})`)
    }
  } catch (err) {
    check(false, `formsFrames threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "formsFrames")
  } finally {
    await close(run)
  }
}

/** A card's number waits on Touch ID: it fills once the agent answers, and nothing fills when Touch ID is turned down. */
async function formsTouchId() {
  const slow = await launch({ fillDelay: 1.5 })
  const page = await slow.context.newPage()
  try {
    await page.goto(`${site}/forms/card-single`)
    const menu = await formsMenu(slow, page, "#cc", "/forms/card-single")
    if (menu) {
      await menu.locator("button.row").first().click()
      check(!!(await until("the pill waits while Touch ID is asked", async () => (await menu.locator(".pill:not(.ok):not(.failed)").count().catch(() => 0)) > 0 && (await page.inputValue("#cc")) === "", 3000)), "the pill says Filling… while the agent asks for Touch ID")
      check(!!(await until("the card fills once verified", async () => (await page.inputValue("#cc")) !== "", 8000)), "the card fills once Touch ID is answered")
    }
  } catch (err) {
    check(false, `formsTouchId threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(slow, page, "formsTouchId")
  } finally {
    await close(slow)
  }
  const denied = await launch({ touchId: "deny" })
  const page2 = await denied.context.newPage()
  try {
    await page2.goto(`${site}/forms/card-single`)
    const menu = await formsMenu(denied, page2, "#cc", "/forms/card-single")
    if (menu) {
      check((await pickRow(menu, "Visa")) === "failed", "Touch ID turned down: the pill says it couldn't fill")
      check((await menu.locator(".pill .pill-label").getAttribute("title").catch(() => "")) === "Touch ID didn't confirm it's you. Nothing was filled.", "and why")
      const got = await values(page2, ["cc", "exp", "cvc", "holder"])
      check(got.every((v) => !v), "and nothing is written, not even the name")
    }
  } catch (err) {
    check(false, `formsTouchId (denied) threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(denied, page2, "formsTouchId")
  } finally {
    await close(denied)
  }
}

type Verdict = { type: string; frame: number; url: string; kind?: string | null; roles?: string[]; loginish?: boolean }
const verdicts = (run: Run, url: string) =>
  run.worker.evaluate((url) => ((globalThis as unknown as { __verdicts: Verdict[] }).__verdicts ?? []).filter((v) => v.url === url), url) as Promise<Verdict[]>

/** What the content script makes of each page in DETECT; one check per page. */
async function detection() {
  const run = await launch()
  const page = await run.context.newPage()
  let passed = 0
  try {
    for (const [name, d] of Object.entries(DETECT)) {
      const url = `http://${d.host ?? "localhost"}:${server.port}/detect/${name}`
      await page.goto(url)
      const e = d.expect
      let got = ""
      let ok = false
      if ("frameQuiet" in e) {
        const frameUrl = `http://127.0.0.1:${server.port}${e.frameQuiet}`
        await Bun.sleep(3500)
        const v = await verdicts(run, frameUrl)
        const forms = v.filter((x) => x.type === "db:page" && x.kind)
        got = forms.length ? `the frame reports ${forms[0].kind}` : "the frame reports no form"
        ok = !forms.length
      } else if ("quiet" in e) {
        const quiet = await until(`${name}: the page settles`, async () => (await verdicts(run, url)).find((x) => x.type === "db:quiet" && x.frame === 0), 8000)
        const v = await verdicts(run, url)
        const form = v.find((x) => x.type === "db:page" && x.frame === 0 && x.kind)
        const roles = new Set(v.flatMap((x) => (x.type === "db:page" && x.frame === 0 && x.kind ? (x.roles ?? []) : [])))
        got = form ? `a ${form.kind} form (${[...roles].join(", ")})` : quiet ? `no form, ${quiet.loginish ? "still signing in" : "not a sign-in step"}` : "no verdict"
        ok = !form && !!quiet && quiet.loginish === e.signingIn && !(e.not ?? []).some((r) => roles.has(r))
      } else {
        const form = await until(`${name}: a form is found`, async () => (await verdicts(run, url)).findLast((x) => x.type === "db:page" && x.frame === 0 && x.kind), 8000)
        await Bun.sleep(800)
        const last = (await verdicts(run, url)).findLast((x) => x.type === "db:page" && x.frame === 0) ?? form
        const roles = new Set(last?.roles ?? [])
        got = last?.kind ? `${last.kind} (${[...roles].join(", ")})` : "no form"
        ok = last?.kind === e.kind && ("has" in e ? (e.has ?? []).every((r) => roles.has(r)) && !(e.not ?? []).some((r) => roles.has(r)) : true)
        if (ok && "menu" in e) {
          await page.click(e.menu.off)
          await Bun.sleep(1500)
          const off = !extensionFrame(page, "menu.html")
          await page.click(e.menu.on)
          const on = !!(await until(`${name}: menu on ${e.menu.on}`, () => extensionFrame(page, "menu.html"), 8000))
          got += `, menu on ${e.menu.off}: ${off ? "no" : "yes"}, on ${e.menu.on}: ${on ? "yes" : "no"}`
          ok = off && on
        }
      }
      const want = "frameQuiet" in e ? "no form in the frame" : "quiet" in e ? `no form, ${e.signingIn ? "still signing in" : "not a sign-in step"}` : e.kind
      if (check(ok, `detect ${name}: want ${want}, got ${got}`)) passed++
    }
    passed += await failedSignIns(run, page)
  } catch (err) {
    check(false, `detection threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "detection")
  } finally {
    console.log(`  detection: ${passed} of ${Object.keys(DETECT).length + 4} pass`)
    await close(run)
  }
}

/**
 * Sign-ins that didn't finish: the password field still showing five seconds
 * after the submit (in place, or posted back), and a typed address before
 * the sign-in finished. None of them offers a save. Returns how many pass,
 * as part of the detection count.
 */
async function failedSignIns(run: Run, page: Page): Promise<number> {
  let passed = 0
  for (const path of ["/fails/spa", "/fails/post"]) {
    await clearBadge(run)
    await signIn(run, page, path, `failed${path.replace(/\W/g, "-")}@acme.test`, "a wrong password")
    await Bun.sleep(6000)
    await page.click("#home")
    await page.waitForURL("**/home")
    await Bun.sleep(5000)
    if (check((await badge(run)) === "", `detect ${path}: a password field still showing after the submit offers nothing`)) passed++
  }
  // A retry four seconds after a wrong password, still on its way when the
  // first submit's five seconds are up: that check is about the first submit.
  await clearBadge(run)
  await signIn(run, page, "/fails/retry", "retry@acme.test", "a wrong password")
  await page.locator("#error").filter({ hasText: "isn't right" }).waitFor()
  await Bun.sleep(4000)
  await page.locator("#password").fill("")
  await page.locator("#password").pressSequentially("the right password")
  await page.click("button[type=submit]")
  await page.waitForURL("**/app/dashboard")
  if (check(!!(await offered(run)), "detect retry: the first submit's failure doesn't end the retry that went through")) passed++
  else await diagnose(run, page, "retry")
  await clearBadge(run)
  await signIn(run, page, "/login", "typed@acme.test", "first step")
  await page.waitForURL("**/mfa")
  await page.goto(`${site}/home`)
  await Bun.sleep(5000)
  if (check((await badge(run)) === "", "detect typed address: going elsewhere by hand mid sign-in offers nothing")) passed++
  return passed
}

/** The lines of every learning log: what the native host was asked to write, or what the browser-only vault keeps (bg/learn-log.ts). */
async function learnLines(run: Run): Promise<Array<Record<string, unknown>>> {
  if (!standalone) return (await hostLog(run)).filter((r) => r.type === "learn").map((r) => r.line as Record<string, unknown>)
  const page = await run.context.newPage()
  try {
    await page.goto(`chrome-extension://${ID}/device.html`)
    return await page.evaluate(
      () =>
        new Promise<Array<Record<string, unknown>>>((resolve) => {
          const req = indexedDB.open("deadbolt-learn", 1)
          req.onupgradeneeded = () => req.result.createObjectStore("logs", { keyPath: "session" })
          req.onsuccess = () => {
            const all = req.result.transaction("logs").objectStore("logs").getAll()
            all.onsuccess = () => resolve((all.result as Array<{ lines: string[] }>).flatMap((l) => l.lines.map((x) => JSON.parse(x))))
          }
        }),
    )
  } finally {
    await page.close()
  }
}

/**
 * "Learn this site" from the popup: a sign-in by hand is logged as steps
 * (never what's typed) and the session ends after it works. Then "Never for
 * this site" on an offer: the popup says saving is off, and Turn on undoes
 * it (the browser-only vault also lists it in Settings).
 */
async function learnAndNever() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    await page.goto(`${site}/login?next=home`)
    await formFound(page)
    const p = await popup(run, site)
    await p.locator("button", { hasText: "Learn this site" }).click()
    const learning = await until("the popup shows the site learning", async () => {
      const again = await popup(run, site)
      const shown = (await again.locator(".offer h2", { hasText: "Learning" }).count()) > 0
      await again.close()
      return shown
    })
    check(!!learning, "Learn this site starts a learning session for the tab")
    await p.close().catch(() => {})
    // While the tab learns, Deadbolt keeps its menu out of the way: type as a person would.
    await page.click("#email")
    await page.keyboard.type("learner@acme.test", { delay: 20 })
    await page.click("#password")
    await page.keyboard.type("typed-by-hand-secret", { delay: 20 })
    await page.click("button[type=submit]")
    await page.waitForURL("**/home")
    const lines = await until("the session ends after the sign-in", async () => {
      const got = await learnLines(run)
      return got.some((l) => l.event === "end") ? got : null
    }, 15_000)
    const events = (lines ?? []).map((l) => l.event)
    check(events[0] === "start" && events.includes("step") && (lines ?? []).at(-1)?.reason === "signed-in", `the log has the start, the steps and a signed-in end (${events.join(",")})`)
    check(!JSON.stringify(lines).includes("typed-by-hand-secret") && !JSON.stringify(lines).includes("learner@acme.test"), "and never what was typed")
    if (standalone) {
      const s = await popup(run, site)
      await s.getByRole("button", { name: "Settings", exact: true }).click()
      check(!!(await until("Settings lists the learning log", async () => (await s.locator(".settings").textContent())?.includes("1 session"))), "Settings keeps the learning log, with Download")
      await s.close()
    }

    await signIn(run, page, "/login?next=home", "never@acme.test", "never password")
    await page.waitForURL("**/home")
    if (!(await offered(run, "the sign-in is offered"))) return void (await diagnose(run, page, "never"))
    const { p: o } = await offerIn(run)
    await o.locator(".offer button.link", { hasText: "Never for this site" }).click()
    check(!!(await until("the popup says saving is off", async () => (await o.locator(".saving-off", { hasText: "Saving is off for localhost" }).count()) > 0)), "Never for this site: the popup says saving is off, with Turn on")
    if (standalone) {
      const s = await popup(run, site)
      await s.getByRole("button", { name: "Settings", exact: true }).click()
      check(!!(await until("Settings lists the site", async () => (await s.getByRole("button", { name: "Turn saving on for localhost" }).count()) > 0)), "and Settings lists it")
      await s.close()
    }
    await o.locator(".saving-off button", { hasText: "Turn on" }).click()
    check(!!(await until("Turn on undoes it", async () => (await o.locator(".saving-off", { hasText: "Saving is off" }).count()) === 0)), "Turn on offers to save there again")
    await o.close()
  } catch (err) {
    check(false, `learn and never threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "learn and never")
  } finally {
    await close(run)
  }
}

const scenarios: Record<string, (scheme: Scheme) => Promise<void>> = { fillAndTotp, savePrompt, savedInPage, generator, signInWith, locked, notInstalled, formsSurface }
const once: Record<string, () => Promise<void>> = {
  film,
  detection,
  coldSave,
  signInShapes,
  signInOutcomes,
  narrowing,
  googleAccount,
  corner,
  signInSessions,
  frameLogins,
  conditionalHeld,
  rateLimited,
  securityPage,
  keyboardEntry,
  coveredMenu,
  topLayer,
  viewportResize,
  menuReveal,
  occlusionSweep,
  midFill,
  coveredPill,
  backForward,
  passkeys,
  formsShapes,
  formsFrames,
  formsTouchId,
  learnAndNever,
}
const groups: Record<string, string[]> = { forms: ["formsSurface", "formsShapes", "formsFrames", "formsTouchId"], security: ["securityPage", "keyboardEntry", "coveredMenu", "topLayer", "viewportResize", "occlusionSweep", "midFill", "coveredPill", "backForward"] }
const picked = only?.split(",").flatMap((name) => groups[name] ?? [name])

// `--shard <i>/<n>` runs the i-th of n deterministic slices of the units below
// (each scenario in each scheme, then each `once` entry), balanced by these
// rough run times in seconds (per scheme; unlisted ones count 10); `--list`
// prints the units and their shards.
const cost: Record<string, number> = {
  detection: 108, occlusionSweep: 55, signInSessions: 52, frameLogins: 25, conditionalHeld: 12, savedInPage: 46, securityPage: 46, coveredMenu: 46, generator: 42, signInOutcomes: 39,
  signInShapes: 34, savePrompt: 20, topLayer: 17, keyboardEntry: 14, corner: 12, passkeys: 12, rateLimited: 11, signInWith: 9, fillAndTotp: 8,
  coldSave: 8, backForward: 7, narrowing: 6, googleAccount: 8, midFill: 6, coveredPill: 5, viewportResize: 6, menuReveal: 4, locked: 2, notInstalled: 1,
  formsSurface: 12, formsShapes: 15, formsFrames: 18, formsTouchId: 12, learnAndNever: 15,
}
/** Scenarios tied to the native agent; standalone passkeys/Strict are in standalone.ts. */
const NATIVE_ONLY = new Set(["passkeys", "formsTouchId"])
const units = [
  ...(["light", "dark"] as const).flatMap((scheme) =>
    Object.entries(scenarios).map(([name, run]) => ({ key: name, name: `${name} (${scheme})`, run: () => run(scheme) })),
  ),
  ...Object.entries(once).map(([name, run]) => ({ key: name, name, run })),
  // The recording runs only when asked for.
].filter((u) => (!picked || picked.includes(u.key)) && (u.key !== "film" || video) && !(standalone && NATIVE_ONLY.has(u.key)))
const [part, parts] = (arg("--shard") ?? "1/1").split("/").map(Number)
if (!(parts >= 1 && part >= 1 && part <= parts)) throw new Error("--shard wants <i>/<n> with 1 <= i <= n")
const load = Array<number>(parts).fill(0)
const shardOf = new Map<string, number>()
for (const u of [...units].sort((a, b) => (cost[b.key] ?? 10) - (cost[a.key] ?? 10))) {
  const bin = load.indexOf(Math.min(...load))
  load[bin] += cost[u.key] ?? 10
  shardOf.set(u.name, bin + 1)
}
const mine = units.filter((u) => shardOf.get(u.name) === part)
if (process.argv.includes("--list")) {
  for (const u of units) console.log(`${shardOf.get(u.name)}/${parts}  ${u.name}`)
  server.stop(true)
  process.exit(0)
}
if (parts > 1) console.log(`shard ${part}/${parts}: ${mine.map((u) => u.name).join(", ") || "nothing"}`)

try {
  for (const u of mine) {
    console.log(`\n# ${u.name}`)
    const start = Date.now()
    await u.run()
    console.log(`  (${u.name}: ${((Date.now() - start) / 1000).toFixed(1)} s)`)
  }
} finally {
  server.stop(true)
}
console.log(failures ? `\n${failures} failed` : "\nall passed")
process.exit(failures ? 1 : 0)
