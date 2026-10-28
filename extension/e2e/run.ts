// End-to-end run of the built extension in headless Chromium against a fake
// native host (e2e/fake-host.py) and local test pages. Nothing here touches a
// real browser profile or vault: each run uses a fresh profile directory with
// the fake host's manifest in it.
//
//   bun run e2e [--stills <dir>] [--video <dir>] [--only <scenario>,<scenario>]
//
// `--video <dir>` records the `film` run (the menu, a fill, a sign-in and
// the save offer in the page) to <dir>/deadbolt-surface.webm.
//
// `--only security` is the subset CI runs: hidden and covered fields, form
// swaps, opaque origins, value swaps, navigation during a fill and the
// back/forward cache.
//
// `--deadbolt <path to the deadbolt binary>` adds the passkey run, which
// needs a real agent to sign: it makes a throwaway store (fast KDF, local
// network only) in the run's temporary directory, runs that binary as the
// host, and checks each credential with @simplewebauthn/server.
//
// Needs Playwright's Chromium (`bunx playwright-core install chromium`).

import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse, type WebAuthnCredential } from "@simplewebauthn/server"
import { chromium, type BrowserContext, type Frame, type Page, type Worker } from "playwright-core"
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

const ID = "jhocodkhpifjndffenppfmdkmiolngal"
const root = join(import.meta.dir, "..")
const dist = join(root, "dist")
const arg = (name: string) => {
  const i = process.argv.indexOf(name)
  return i > 0 ? process.argv[i + 1] : undefined
}
const stills = arg("--stills")
const video = arg("--video")
const only = arg("--only")
const deadbolt = arg("--deadbolt")
if (stills) await mkdir(stills, { recursive: true })
if (video) await mkdir(video, { recursive: true })

// ---- Test pages ---------------------------------------------------------------

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

/** The page sees the menu's host element arrive; these pages misuse that. */
const onMenu = (js: string) => `<script>
  new MutationObserver((records) => {
    for (const r of records) for (const host of r.addedNodes) if (host.nodeName === "DIV") { ${js} }
  }).observe(document.documentElement, { childList: true })
</script>`

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
// The menu's host is the <div> Deadbolt adds to <html>.
const OVERLAY: Record<string, string> = {
  none: "",
  fade: `<style>html > div { opacity: 0.4 !important }</style>`,
  clip: `<style>html > div { clip-path: inset(0 0 25% 0) !important }</style>`,
  // A near-opaque sheet over everything that lets clicks through to the menu.
  cover: onMenu(`const c = document.createElement("section"); c.style.cssText = "position:fixed;inset:0;z-index:2147483647;pointer-events:none;background:rgb(255 255 255 / 92%)"; setTimeout(() => document.documentElement.append(c), 50)`),
  // Fade it out the moment the click starts (focus moves into the menu), so a
  // visibility reading taken before the click is stale.
  "on-press": `<script>addEventListener("blur", () => document.head.insertAdjacentHTML("beforeend", "<style>html > div { opacity: 0 !important }</style>"))</script>`,
  // The reverse: keep it all but see-through over a decoy (still taking
  // clicks, which a fully transparent frame doesn't) and show it the moment
  // the press lands, so a reading taken after the click finds it visible.
  "reveal-on-press": `<style id="seethrough">html > div { opacity: 0.02 !important }</style><script>addEventListener("blur", () => document.getElementById("seethrough").remove())</script>`,
  // Shown a moment before the press instead (as the pointer nears it), so
  // nothing changes after the press: the test calls reveal() 250 ms before.
  "reveal-before-press": `<style id="seethrough">html > div { opacity: 0.02 !important }</style><script>window.reveal = () => document.getElementById("seethrough").remove()</script>`,
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
const SWEEP = `<script>
  const cover = (ms) => {
    const c = document.createElement("section")
    c.style.cssText = "position:fixed;inset:0;z-index:2147483647;pointer-events:none;background:#fff"
    document.documentElement.append(c)
    window.__shown = performance.now()
    setTimeout(() => c.remove(), ms)
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

// novalidate: "admin" isn't an email, and the browser would block the submit.
const loginForm = (action: string) => `<h1>Sign in to Acme</h1><form method="post" action="${action}" novalidate>
  <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username">
  <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button></form>`

const server = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  async fetch(req) {
    const url = new URL(req.url)
    // Where the sign-in outcome forms post (see signInOutcomes). The email
    // posted is shown back where a real site would show the account.
    if (req.method === "POST") {
      const email = String((await req.formData().catch(() => null))?.get("email") ?? "").replace(/[<>&"]/g, "")
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
      case "/outcome/login":
        return html("Sign in to Acme", loginForm(url.searchParams.get("to") ?? "/home"))
      case "/outcome/welcome":
        return html("Acme", `<header><span>${(url.searchParams.get("u") ?? "").replace(/[<>&"]/g, "")}</span> <button type="button">Sign out</button></header><h1>Dashboard</h1>`)
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
    }
    // The site's own login page in a frame, on pages with no form of their own.
    if (url.pathname.startsWith("/framed/") && FRAMED[url.pathname.slice(8)]) return html("Acme", `<h1>Acme</h1>${FRAMED[url.pathname.slice(8)]}`)
    if (url.pathname.startsWith("/hidden/") && HIDDEN[url.pathname.slice(8)]) return html("Sign in to Acme", HIDDEN[url.pathname.slice(8)])
    if (url.pathname.startsWith("/overlay/") && url.pathname.slice(9) in OVERLAY) return html("Sign in to Acme", loginForm("/home") + OVERLAY[url.pathname.slice(9)])
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
  /** Playwright turns the back/forward cache off; keep it on. */
  bfcache?: boolean
  /** Runs the deadbolt binary as the host, with this environment. */
  realHost?: Record<string, string>
  /** Records every page to this directory. */
  record?: string
  /** Device pixels per CSS pixel (2 unless set). */
  scale?: number
}

async function launch(options: LaunchOptions = {}): Promise<Run> {
  const dir = await mkdtemp(join(tmpdir(), "deadbolt-e2e-"))
  const log = join(dir, "host.log")
  if (options.host !== false) {
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
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
    ignoreDefaultArgs: options.bfcache ? ["--disable-back-forward-cache"] : [],
    ...(options.record ? { recordVideo: { dir: options.record, size: { width: 900, height: 640 } } } : {}),
    env: {
      ...process.env,
      DEADBOLT_FAKE_STATUS: options.status ?? "ready",
      DEADBOLT_FAKE_LOG: log,
      DEADBOLT_FAKE_RATE_LIMIT: options.rateLimit ?? "",
      DEADBOLT_FAKE_FILL_DELAY: String(options.fillDelay ?? 0),
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
    chrome.runtime.onMessage.addListener((m: { type?: string; token?: string }, s) => {
      if (s.tab) seen.push(`${m?.type}@${s.frameId}:${s.url ? new URL(s.url).pathname : "?"}`)
      if (m?.type === "db:menu-load" && m.token) tokens.push(m.token)
    })
  })
  const run = { context, worker, log, dir }
  runs.set(context, run)
  return run
}

const runs = new Map<BrowserContext, Run>()

async function close(run: Run) {
  await run.context.close()
  await rm(run.dir, { recursive: true, force: true })
}

async function hostLog(run: Run): Promise<Array<Record<string, unknown>>> {
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
        await Promise.all([document.fonts.load('13px "Geist"'), document.fonts.load('12px "Geist Mono"')]).catch(() => {})
        return [...document.fonts].map((f) => `${f.family}:${f.status}`).join(" ")
      })
      check(!fonts.includes("error") && fonts.includes("loaded"), `Geist fonts load in the menu (${fonts})`)
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
      const code = await until("one-time code fills on the next page", async () => (await page.inputValue("#code")) === "492039")
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
    check((await p.locator(".account-title").allTextContents()).join(",") === "Acme,Acme admin", "popup lists the site's logins")
    check(!(await p.locator("button", { hasText: /copy password/i }).count()), "popup offers no password copy")
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
  // The test site always has logins, so the menu always comes; wait for it
  // rather than click where it's about to appear.
  if (await until(`menu opens on ${selector}`, () => extensionFrame(page, "menu.html"), 15_000)) {
    await page.keyboard.press("Escape")
    await until("esc closes the menu", () => !extensionFrame(page, "menu.html"))
  } else await diagnose(run, page, `no menu on ${selector}`)
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
      check(JSON.stringify((await probe(page)).added) === '["DIV"]', `only one element is added to the page for an offer (${JSON.stringify((await probe(page)).added)})`)
      const sees = await page.evaluate(() => {
        const host = [...document.documentElement.children].find((el) => el.nodeName === "DIV")
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
    check(((await surface.locator(".offer-title").textContent()) ?? "") === "Save login for localhost?", "the surface asks to save")
    check(((await surface.locator(".offer-user").textContent()) ?? "") === "surface@acme.test", "with the username under it")
    await Bun.sleep(500)
    await shotAround(page, `surface-save-${scheme}`, surface)
    await settled(surface)
    await surface.locator(".offer-actions .btn.primary").click()
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
      await settled(surface)
      await surface.locator(".offer-actions .btn:not(.primary)").click()
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
      check(!!(await until("the offer leaves when its time runs out", () => !extensionFrame(page, "menu.html"), 16_000)), "the offer leaves the page when its time runs out")
      check((await badge(run)) === "1", "and waits in the toolbar")
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
    await surface.locator(".offer-actions .btn.primary").click()
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
  const run = await launch({ rateLimit: "fill" })
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
      return f && (await f.locator(".notice").count()) > 0 ? f : null
    })
    if (menu) {
      check(((await menu.locator(".title").textContent()) ?? "").includes("locked"), "menu says Deadbolt is locked")
      await Bun.sleep(400)
      await shotAround(page, `menu-locked-${scheme}`, menu, "#email")
    }
    const p = await popup(run, site, `popup-locked-${scheme}`)
    check(((await p.locator("h2").textContent()) ?? "") === "Unlock Deadbolt", "popup says Unlock Deadbolt")
    check(!(await p.locator("input[type=password]").count()), "popup never asks for the passphrase")
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
    check(((await p.locator(".command code").textContent()) ?? "") === "deadbolt browser install", "popup shows the install command")
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

    // A same-site login page in a frame: no menu inside it, and the popup
    // fills it only if the user can see it through every frame above.
    for (const how of Object.keys(FRAMED)) {
      await run.worker.evaluate(() => void (globalThis as unknown as { __seen: string[] }).__seen.splice(0))
      await page.goto(`${site}/framed/${how}`)
      const inner = await until(`the framed login page loads (${how})`, () => page.frames().find((f) => f.url().includes("/login?next=home")) ?? null)
      if (!inner) {
        await diagnose(run, page, `framed/${how}`)
        continue
      }
      await until("the frame's form is found", () => run.worker.evaluate(() => (globalThis as unknown as { __seen: string[] }).__seen.some((s) => /^db:page@[1-9]/.test(s) && s.endsWith("/login"))), 15_000)
      if (how === "visible") {
        await inner.click("#email")
        await Bun.sleep(1500)
        check(!page.frames().some((f) => f.url().includes("/menu.html")), "a frame's field gets no menu")
        await page.keyboard.press("ArrowDown")
        await Bun.sleep(1000)
        check(!page.frames().some((f) => f.url().includes("/menu.html")), "nor on ↓")
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
  } catch (err) {
    check(false, `covered menu threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "covered menu")
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

/** The save offer keeps clear of the page's own header links, and tucks away on a click in the page. */
async function placement() {
  const run = await launch()
  const page = await run.context.newPage()
  try {
    await signIn(run, page, "/outcome/login?to=/outcome/header", "header@acme.test", "header password")
    const surface = await saveSurface(page)
    if (!surface) return void (await diagnose(run, page, "placement"))
    await Bun.sleep(600)
    const frame = await (await surface.frameElement()).boundingBox()
    const link = await page.locator("#signout").boundingBox()
    const overlaps = !!frame && !!link && frame.x < link.x + link.width && link.x < frame.x + frame.width && frame.y < link.y + link.height && link.y < frame.y + frame.height
    check(!!frame && !overlaps && frame.y >= 56, `the offer keeps clear of a header's links (${JSON.stringify(frame)})`)
    await shotAround(page, "surface-placed", surface)
    await page.mouse.click(80, 520)
    check(!!(await until("a click in the page tucks the offer away", () => !extensionFrame(page, "menu.html"), 5000)), "a click in the page tucks the offer away")
    check((await badge(run)) === "1", "and the toolbar keeps it")
  } catch (err) {
    check(false, `placement threw: ${(err as Error).message.split("\n")[0]}`)
    await diagnose(run, page, "placement")
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
      await page.addStyleTag({ content: "html > div { inset: 0 !important; width: 100vw !important; height: 100vh !important; top: 0 !important; left: 0 !important }" })
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

const scenarios: Record<string, (scheme: Scheme) => Promise<void>> = { fillAndTotp, savePrompt, savedInPage, locked, notInstalled }
const once: Record<string, () => Promise<void>> = { film, coldSave, signInShapes, signInOutcomes, narrowing, placement, rateLimited, securityPage, keyboardEntry, coveredMenu, occlusionSweep, midFill, coveredPill, backForward, passkeys }
const groups: Record<string, string[]> = { security: ["securityPage", "keyboardEntry", "coveredMenu", "occlusionSweep", "midFill", "coveredPill", "backForward"] }
const picked = only?.split(",").flatMap((name) => groups[name] ?? [name])

try {
  for (const scheme of ["light", "dark"] as const) {
    for (const [name, run] of Object.entries(scenarios)) {
      if (picked && !picked.includes(name)) continue
      console.log(`\n# ${name} (${scheme})`)
      await run(scheme)
    }
  }
  for (const [name, run] of Object.entries(once)) {
    if (picked && !picked.includes(name)) continue
    // The recording runs only when asked for.
    if (name === "film" && !video) continue
    console.log(`\n# ${name}`)
    await run()
  }
} finally {
  server.stop(true)
}
console.log(failures ? `\n${failures} failed` : "\nall passed")
process.exit(failures ? 1 : 0)
