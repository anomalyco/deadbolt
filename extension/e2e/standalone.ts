// The standalone (browser-only) device in headless Chromium, with no native
// host: a `--standalone` e2e build, its real wasm vault, real OPFS and the
// real content script. Three runs:
//
//   bun e2e/standalone.ts --smoke [--dist <dir>]
//     Offline: create, save, list, autofill, lock, wrong passphrase, unlock
//     and browser restart. Chromium reaches only loopback, so it needs no
//     public relay and no CLI (CI runs this one).
//   bun e2e/standalone.ts --deadbolt <path to deadbolt> [--dist <dir>]
//     Everything above with a real CLI over n0's public relays: pairing,
//     background sync both ways without asking the extension to sync, and
//     quick answers while a background sync waits on a suspended CLI.
//   bun e2e/standalone.ts --join --deadbolt <path to deadbolt>
//     Fresh extension joins an existing CLI vault of five logins (one with
//     TOTP), then lists, fills, locks and reopens its local encrypted replica.
//
// Every run also checks a login saved for acme.test is listed and filled
// on accounts.acme.test (mapped to loopback). Trusted localhost pages check
// the save offer after a sign-in, the update after
// a changed password, and generated passwords for a sign-up and a password
// change, saved through the offer. The two CLI runs add the same on the real
// demo site (https://acme-demo.i.vogel.dev: sign-up, password change, two-step
// sign-in), and an identity and a card written on the CLI and filled on a
// loopback checkout and the demo's: Relaxed and Comfortable fill the card at
// once; Strict asks for the passphrase on a trusted extension surface first.
//
// Every run also makes and uses passkeys in the browser's own vault on a
// localhost page (passkeyFlows): registration, modal and autofill sign-in,
// required UV handed to the browser, Strict's passphrase for preferred UV
// and none for discouraged, and deletion from the device page, each checked
// with @simplewebauthn/server. The CLI runs also sync passkeys both ways and
// sign with them through `deadbolt browser-host`.
//
// `--latency-ms <n>` is the limit for hello, list and fill over the vault's
// RPC (default 1000 ms, 1500 ms when CI is set). `--video <dir>` records each
// page (headless) to <dir>/<nn>-<flow>.webm. Only synthetic credentials,
// in a disposable profile and store, deleted at the end. Online runs leave
// synthetic accounts on the demo backend. Toolbar popup stills accompany --video.
import { chromium, type BrowserContext, type Frame, type Page, type Worker } from "playwright-core"
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse, type WebAuthnCredential } from "@simplewebauthn/server"
import { copyFile, mkdir, mkdtemp, rm, readdir, readFile, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import type { DeviceCommand, DevicePasskey, DeviceReply, VaultDevice } from "../src/messages"
import { VAULT_REQUEST, type VaultResponse } from "../src/bg/vault-messages"

const arg = (name: string) => { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1] }
const smoke = process.argv.includes("--smoke")
const joinExisting = process.argv.includes("--join")
if (smoke && joinExisting) throw new Error("--join requires the real CLI, not --smoke")
const binary = arg("--deadbolt")
if (smoke && binary) throw new Error("--smoke runs without the CLI; drop --deadbolt")
if (!smoke && !binary) throw new Error("--deadbolt must name the CLI built from this worktree (or pass --smoke)")
const deadbolt = binary ? resolve(binary) : ""
const limit = Number(arg("--latency-ms") ?? (process.env.CI ? 1500 : 1000))
if (!(limit > 0)) throw new Error("--latency-ms wants a positive number")
const root = await mkdtemp(join(tmpdir(), "db-ext-device-"))
const dist = arg("--dist") ? resolve(arg("--dist")!) : join(root, "extension")
let cliMarker: Buffer | null | undefined
const profile = join(root, "profile")
const ID = "jhocodkhpifjndffenppfmdkmiolngal"
/** The background's sync alarm (bg/standalone.ts). */
const SYNC_ALARM = "deadbolt-sync"
const env = {
  ...process.env,
  DEADBOLT_HOME: join(root, "vault"), XDG_RUNTIME_DIR: join(root, "run"),
  XDG_STATE_HOME: join(root, "state"), XDG_CONFIG_HOME: join(root, "config"),
  DEADBOLT_NET: "relay", DEADBOLT_KDF: "fast", DEADBOLT_PASSPHRASE: "standalone cli fixture",
}
const passphrase = "standalone browser fixture with real argon2"
const browserPassword = "browser-only-synthetic-secret-83219"
const cliPassword = "cli-only-synthetic-secret-97264"
let context: BrowserContext | undefined
let joining: ReturnType<typeof Bun.spawn> | undefined
/** The CLI agent while it's suspended (SIGSTOP), to resume before stopping it. */
let suspended: number | undefined
/** The real demo site the CLI runs sign up, change a password and check out on. */
const DEMO = "https://acme-demo.i.vogel.dev"
const video = arg("--video") ? resolve(arg("--video")!) : undefined
/** Each recorded page's video file and the flow it shows, copied to `video` at the end. */
const recordings: Array<{ path: string; name: string }> = []
const escape = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)
const html = (title: string, body: string) => new Response(`<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>
    <main style="width:360px;margin:60px auto;font:16px sans-serif">${body}</main></body></html>`, { headers: { "content-type": "text/html" } })
const input = (id: string, label: string, attrs: string) =>
  `<label for="${id}">${label}</label><input id="${id}" name="${id}" ${attrs} style="display:block;width:100%;height:36px;margin-bottom:8px">`
/**
 * A WebAuthn test page (as e2e/run.ts's): the test drives
 * navigator.credentials through start/result/abort, with an email box that
 * takes an autofill (conditional) passkey sign-in.
 */
const PASSKEY_PAGE = `<label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username webauthn" style="display:block;width:100%;height:36px">
  <script>
    const calls = {}
    window.start = (name, kind, json, extra = {}) => {
      const publicKey = kind === "create" ? PublicKeyCredential.parseCreationOptionsFromJSON(json) : PublicKeyCredential.parseRequestOptionsFromJSON(json)
      const abort = new AbortController()
      const call = (calls[name] = { abort })
      navigator.credentials[kind]({ publicKey, signal: abort.signal, ...extra }).then(
        (c) => (call.done = { ok: true, value: c.toJSON() }),
        (e) => (call.done = { ok: false, value: e.name + ": " + e.message }),
      )
    }
    window.result = (name) => calls[name]?.done ?? null
    window.abort = (name) => calls[name].abort.abort()
  </script>`
/** Sign-in, sign-up, password change and checkout pages, like the demo site's; each sign-in lands on an account page. */
/** Each request for /iconed's icon, by its Sec-Fetch-Dest: the page's own loads are "image", a script's fetch "empty". */
const iconRequests: string[] = []
async function fixture(request: Request) {
  const url = new URL(request.url)
  const form = request.method === "POST" ? await request.formData() : null
  const signedIn = (user: unknown) => Response.redirect(`${url.origin}/account?u=${encodeURIComponent(String(user ?? ""))}`, 303)
  switch (url.pathname) {
    case "/signin":
      if (form) return signedIn(form.get("email"))
      return html("Sign in to Acme", `<h1>Sign in to Acme</h1><form method="post" action="/signin" novalidate>
        ${input("email", "Email", `type="email" autocomplete="username"`)}${input("password", "Password", `type="password" autocomplete="current-password"`)}
        <button type="submit">Sign in</button></form>`)
    case "/signup":
      if (form) return signedIn(form.get("email"))
      return html("Create your Acme account", `<h1>Create your Acme account</h1><form method="post" action="/signup" novalidate>
        ${input("email", "Email", `type="email" autocomplete="username"`)}${input("new", "Password", `type="password" autocomplete="new-password" minlength="12"`)}
        ${input("confirm", "Confirm password", `type="password" autocomplete="new-password" minlength="12"`)}<button type="submit">Create account</button></form>`)
    case "/settings/password":
      if (form) return signedIn(form.get("username"))
      return html("Change your password", `<h1>Change your password</h1><form method="post" action="/settings/password" novalidate>
        <input type="email" name="username" value="${escape(url.searchParams.get("u") ?? "")}" autocomplete="username" hidden readonly>
        ${input("current", "Current password", `type="password" autocomplete="current-password"`)}${input("new", "New password", `type="password" autocomplete="new-password" minlength="12"`)}
        ${input("confirm", "Confirm new password", `type="password" autocomplete="new-password" minlength="12"`)}<button type="submit">Update password</button></form>`)
    // A sign-in page with its own SVG icon, and that icon, which counts who asks for it (see siteIcon).
    case "/iconed":
      return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>Iconed</title><link rel="icon" type="image/svg+xml" href="/icon.svg"></head><body>
        <main style="width:360px;margin:60px auto;font:16px sans-serif"><img src="/icon.svg" width="24" height="24" alt=""><h1>Sign in</h1><form>
        ${input("username", "Email", `type="email" autocomplete="username"`)}${input("password", "Password", `type="password" autocomplete="current-password"`)}
        <button type="submit">Sign in</button></form></main></body></html>`, { headers: { "content-type": "text/html" } })
    case "/icon.svg":
      iconRequests.push(request.headers.get("sec-fetch-dest") ?? "")
      return new Response(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#e5484d"/><script>alert(1)</script></svg>`, { headers: { "content-type": "image/svg+xml", "cache-control": "max-age=3600" } })
    case "/passkey":
      return html("Sign in to Acme", PASSKEY_PAGE)
    case "/account":
      return html("Acme", `<h1>Your account</h1><p>Signed in as ${escape(url.searchParams.get("u") ?? "")}</p><a href="/signin">Sign out</a>`)
    case "/checkout":
      if (form) return html("Order placed", "<h1>Thanks for your order</h1>")
      // Two columns, so every field of both sections shows in the 1000×700 viewport, as on a real checkout.
      return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>Checkout</title></head><body>
        <main style="width:760px;margin:24px auto;font:16px sans-serif"><h1 style="margin:0 0 16px">Checkout</h1>
        <form method="post" action="/checkout" novalidate style="display:grid;grid-template-columns:1fr 1fr;gap:0 40px">
        <section aria-label="Shipping">${input("ship-name", "Full name", `autocomplete="shipping name"`)}${input("ship-email", "Email", `type="email" autocomplete="shipping email"`)}
        ${input("ship-line1", "Address", `autocomplete="shipping address-line1"`)}${input("ship-city", "City", `autocomplete="shipping address-level2"`)}
        ${input("ship-state", "State", `autocomplete="shipping address-level1"`)}${input("ship-zip", "ZIP", `autocomplete="shipping postal-code" inputmode="numeric"`)}</section>
        <section aria-label="Payment">${input("cc-name", "Name on card", `autocomplete="cc-name"`)}${input("cc-number", "Card number", `autocomplete="cc-number" inputmode="numeric" placeholder="1234 1234 1234 1234"`)}
        ${input("cc-exp", "Expiry", `autocomplete="cc-exp" inputmode="numeric" placeholder="MM / YY"`)}${input("cc-csc", "Security code", `autocomplete="cc-csc" inputmode="numeric" maxlength="4" placeholder="CVC"`)}
        <button type="submit">Pay</button></section></form></main></body></html>`, { headers: { "content-type": "text/html" } })
  }
  return html("Standalone proof", `<h1>Sign in</h1><form>
    <label for="username">Email</label><input id="username" type="email" autocomplete="username" style="display:block;width:100%;height:36px">
    <label for="password">Password</label><input id="password" type="password" autocomplete="current-password" style="display:block;width:100%;height:36px">
    <button type="submit">Sign in</button></form>`)
}
const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: fixture })
const origin = `http://localhost:${server.port}`
/** One site of several hosts on this machine (Chromium maps `*.acme.test` to loopback). */
const acme = (host?: string) => `http://${host ? `${host}.` : ""}acme.test:${server.port}`

function check(ok: unknown, message: string): asserts ok {
  if (!ok) throw new Error(message)
  console.log(`ok: ${message}`)
}
async function cli(...args: string[]) {
  const process = Bun.spawn([deadbolt, ...args], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const [out, error, exit] = await Promise.all([new Response(process.stdout).text(), new Response(process.stderr).text(), process.exited])
  if (exit !== 0) throw new Error(`deadbolt ${args[0]} failed: ${error}`)
  return out.trim()
}
async function until<T>(label: string, probe: () => Promise<T | null | undefined | false>, ms = 30_000): Promise<T> {
  const deadline = Date.now() + ms
  do {
    const value = await probe().catch(() => null)
    if (value) return value
    await Bun.sleep(200)
  } while (Date.now() < deadline)
  throw new Error(`Timed out: ${label}`)
}
async function command(page: Page, command: DeviceCommand): Promise<DeviceReply> {
  return page.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command)
}
async function request(page: Page, body: DeviceCommand) {
  const result = await command(page, body)
  if (!result?.ok) throw new Error(`${body.type}: ${result?.message ?? "no response"}`)
  return result
}
/** Every login in the vault, as the device page lists them. */
async function logins(page: Page) {
  return ((await request(page, { type: "device-items" })).reply.items as Array<{ kind: string; title: string; username?: string }>).filter((i) => i.kind === "login")
}
async function state(page: Page) {
  return (await request(page, { type: "device-status" })).status.state
}
/** The device page's list of logins shows `title` by itself, without a click. */
async function shown(page: Page, title: string, ms = 15_000) {
  await page.locator(".list-view .vrow .title").getByText(title, { exact: true }).first().waitFor({ timeout: ms })
}
/** The site icon kept for `host`, if any, read from the extension's own IndexedDB (ui/icon-store.ts). */
async function keptIcon(page: Page, host: string): Promise<string | null> {
  return page.evaluate((host) => new Promise<string | null>((resolve) => {
    const open = indexedDB.open("deadbolt-site-icons", 1)
    open.onupgradeneeded = () => open.result.createObjectStore("icons")
    open.onsuccess = () => {
      const get = open.result.transaction("icons").objectStore("icons").get(host)
      get.onsuccess = () => resolve((get.result as { svg?: string } | undefined)?.svg ?? null)
      get.onerror = () => resolve(null)
    }
    open.onerror = () => resolve(null)
  }), host)
}
/**
 * A site's own icon is read only after a fill there, and only from the
 * browser's cache: a page load reads nothing, and no request for it ever
 * comes from Deadbolt (only the page's own "image" loads reach the server).
 */
async function siteIcon(device: Page) {
  const page = await newPage("site-icon")
  await page.goto(`${origin}/iconed`)
  await page.locator("img").evaluate((img: HTMLImageElement) => img.decode())
  await Bun.sleep(2000)
  check(await keptIcon(device, "localhost") === null, "a page load alone reads no site icon")
  const menu = await menuOn(page, "#username", "From browser")
  await menu.locator("button.row", { hasText: "From browser" }).first().click()
  await until("From browser filled on the iconed page", async () => await page.inputValue("#password") === browserPassword)
  const svg = await until("the site's icon is kept after the fill", () => keptIcon(device, "localhost"), 10_000)
  check(svg.includes("circle") && !svg.includes("script"), "after a fill, the site's icon is kept, sanitized")
  check(iconRequests.length > 0 && iconRequests.every((dest) => dest === "image"), `no icon request ever came from Deadbolt (${iconRequests.join(", ")})`)
  await page.close()
}
/** One request to the vault, as the service worker sends it to the offscreen document and its worker, timed there. */
async function vault(worker: Worker, body: Record<string, unknown> & { type: string }) {
  const { ms, response } = await worker.evaluate(async ([type, body]) => {
    const started = performance.now()
    const response = await chrome.runtime.sendMessage({ type, body })
    return { ms: performance.now() - started, response }
  }, [VAULT_REQUEST, body] as const)
  const reply = (response as VaultResponse | undefined)
  if (!reply || "error" in reply) throw new Error(`${body.type}: ${reply ? reply.error : "no response"}`)
  return { ms, reply: reply.reply as Record<string, unknown> }
}
/** hello, list and fill each answer within the limit; `during` says what else is going on. */
async function quick(worker: Worker, title: string, password: string, during: string) {
  const hello = await vault(worker, { type: "hello" })
  check(hello.reply.type === "hello" && hello.ms < limit, `hello answers in ${hello.ms.toFixed(0)} ms (< ${limit}) ${during}`)
  const list = await vault(worker, { type: "list", origin })
  const account = (list.reply.accounts as Array<{ ref: string; title: string }> | undefined)?.find((a) => a.title === title)
  check(account && list.ms < limit, `list answers in ${list.ms.toFixed(0)} ms (< ${limit}) ${during}`)
  const fill = await vault(worker, { type: "fill", origin, ref: account.ref, want: ["username", "password"] })
  check(fill.reply.password === password && fill.ms < limit, `fill answers in ${fill.ms.toFixed(0)} ms (< ${limit}) ${during}`)
}
async function launch() {
  context = await chromium.launchPersistentContext(profile, {
    channel: "chromium", headless: true, viewport: { width: 1000, height: 700 },
    ...(arg("--browser") ? { executablePath: resolve(arg("--browser")!) } : {}),
    args: [
      `--disable-extensions-except=${dist}`, `--load-extension=${dist}`,
      // The toolbar popup isn't among Playwright's pages: the card prompt drives it over DevTools (loopback only).
      "--remote-debugging-port=0",
      // The smoke reaches nothing but this machine: no name resolves but
      // acme.test's, and anything not on loopback goes to a proxy that isn't there.
      ...(smoke
        ? ["--host-resolver-rules=MAP acme.test 127.0.0.1, MAP *.acme.test 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1", "--proxy-server=http://127.0.0.1:9", "--proxy-bypass-list=acme.test;*.acme.test"]
        : ["--host-resolver-rules=MAP acme.test 127.0.0.1, MAP *.acme.test 127.0.0.1"]),
    ],
    ...(video ? { recordVideo: { dir: join(root, "video"), size: { width: 1000, height: 700 } } } : {}),
  })
  context.setDefaultTimeout(15_000)
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker")
  check(worker.url().startsWith(`chrome-extension://${ID}/`), "loaded standalone extension")
  await worker.evaluate(() => {
    const global = globalThis as unknown as { nativeCalls: number }
    global.nativeCalls = 0
    chrome.runtime.connectNative = () => { global.nativeCalls++; throw new Error("Native host forbidden by standalone proof") }
  })
  const device = await newPage(recordings.some((r) => r.name === "device") ? "device-restarted" : "device")
  device.on("pageerror", (error) => console.error("device page error:", error.message))
  await device.goto(`chrome-extension://${ID}/device.html`)
  return { worker, device }
}
/** A new tab, recorded as `name` with --video. */
async function newPage(name: string) {
  const page = await context!.newPage()
  const path = await page.video()?.path()
  if (path) recordings.push({ path, name })
  return page
}
/** Clicks into `selector` on the page at `url` and picks `title` from the real inline menu. */
async function autofill(title: string, username: string, password: string, url = origin, user = "#username") {
  const page = await newPage(`fill-${new URL(url).hostname}`)
  await page.goto(url)
  const menu = await menuOn(page, user, title)
  await menu.locator("button.row", { hasText: title }).first().click()
  await until(`${title} filled`, async () => await page.inputValue("#password") === password)
  check(await page.inputValue(user) === username, `real content script fills ${title} on ${new URL(url).host} without a native host`)
  await page.close()
}
const menuFrame = (page: Page) => page.frames().find((frame) => frame.url().includes("menu.html")) ?? null
/**
 * The production clickjacking gate takes a pick only once the menu has sat
 * still and visible for half a second: wait until its frame stops moving,
 * then that and a little.
 */
async function settle(menu: Frame) {
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
/** Clicks `selector` until the inline menu shows a row with `row`, and returns the settled menu. */
async function menuOn(page: Page, selector: string, row: string) {
  let menu: Frame | null = null
  for (let attempt = 0; attempt < 3 && !menu; attempt++) {
    // The content script may not have scanned the form at the first click.
    if (attempt) await page.keyboard.press("Escape")
    await page.locator(selector).click()
    menu = await until(`inline menu on ${selector} lists ${row}`, async () => {
      const frame = menuFrame(page)
      return frame && await frame.locator("button.row", { hasText: row }).count() ? frame : null
    }, attempt < 2 ? 6000 : 20_000).catch(() => null)
  }
  if (!menu) throw new Error(`No inline menu with ${row} on ${selector} at ${new URL(page.url()).host}`)
  await settle(menu)
  return menu
}
/** Types into `selector` as a person does, closing the menu a click may open first. */
async function typeInto(page: Page, selector: string, text: string) {
  await page.locator(selector).click()
  if (await until("a menu may open", async () => menuFrame(page), 1500).catch(() => null)) {
    await page.keyboard.press("Escape")
    await until("Escape closes the menu", async () => !menuFrame(page), 5000)
  }
  await page.locator(selector).pressSequentially(text)
}
/** Picks the generated password in the menu of a new-password box; both boxes then hold it. */
async function generate(page: Page, box: string, confirm: string) {
  const menu = await menuOn(page, box, "Use a strong password")
  check(await menu.locator("button.row .title").first().textContent() === "Use a strong password", `a new-password box on ${new URL(page.url()).host} offers a generated password first`)
  await menu.locator("button.row", { hasText: "Use a strong password" }).first().click()
  const value = await until("both new-password boxes fill", async () => {
    const value = await page.inputValue(box)
    return value && value === await page.inputValue(confirm) ? value : null
  })
  // The page names it by its kept id once the vault has answered; a person takes longer than this to submit.
  await Bun.sleep(1500)
  return value
}
/** A new turn for every site, so the next confirmed sign-in shows its offer in the page again. */
async function newTurn(worker: Worker) {
  await worker.evaluate(async () => {
    const keys = Object.keys(await chrome.storage.session.get(null)).filter((k) => k.startsWith("opened:"))
    await chrome.storage.session.remove(keys)
  })
}
/** The offer in the page after a confirmed sign-in, or null if none shows within `ms`. */
async function offerShown(page: Page, title: "Save login?" | "Update password?", ms = 30_000) {
  return until(`"${title}" shows in the page`, async () => {
    const frame = menuFrame(page)
    return frame && await frame.locator(".offer-title").textContent().catch(() => null) === title ? frame : null
  }, ms).catch(() => null)
}
/** Opens the page's offer on approach and presses its primary button (Save or Update). */
async function acceptOffer(surface: Frame, what: string) {
  // Let the initial resize finish before approaching, as in the native suite.
  await settle(surface)
  await surface.locator(".offer-row").hover()
  await until("the offer opens on approach", async () => ((await (await surface.frameElement()).boundingBox())?.height ?? 0) > 60)
  await settle(surface)
  await surface.locator(".offer-row .btn.primary").click()
  await until("the offer folds into its Saved pill", async () => await surface.locator(".pill.ok").count().catch(() => 0) > 0)
  check(true, what)
}
/** The password of `username`'s one login for `site`, as the vault fills it there. */
async function savedPassword(worker: Worker, site: string, username: string) {
  const listed = await vault(worker, { type: "list", origin: site })
  const mine = (listed.reply.accounts as Array<{ ref: string; username?: string }>).filter((a) => a.username === username)
  if (mine.length !== 1) return null
  return (await vault(worker, { type: "fill", origin: site, ref: mine[0].ref, want: ["password"] })).reply.password as string
}
const isSaved = (worker: Worker, site: string, username: string, password: string, ms = 20_000) =>
  until(`${username}'s saved password on ${new URL(site).host}`, async () => await savedPassword(worker, site, username) === password, ms)

/**
 * Logins on loopback pages, each through the real inline menu
 * and in-page offer: a login saved for the site fills on a subdomain, a
 * sign-in offers to save, a changed password offers the update, and a
 * generated password is saved for a sign-up and for a password change.
 * Returns how many logins it adds.
 */
async function siteFlows(device: Page, worker: Worker) {
  const before = (await logins(device)).length
  const site = acme()
  const accounts = acme("accounts")
  // Saved for acme.test, filled on accounts.acme.test; lookalikes get nothing.
  const subPassword = "subdomain-synthetic-secret-50417"
  await addLogin(device, "Acme accounts", "sub@acme.test", subPassword, site)
  await shown(device, "Acme accounts")
  await autofill("Acme accounts", "sub@acme.test", subPassword, `${accounts}/signin`, "#email")
  for (const other of [`http://notacme.test:${server.port}`, `http://acme.test.evil.test:${server.port}`]) {
    const listed = (await vault(worker, { type: "list", origin: other })).reply.accounts as unknown[] | undefined
    check(!listed?.length, `a login for acme.test isn't listed on ${new URL(other).hostname}`)
  }

  // Trusted localhost has Web Crypto for typed-value tracking; HTTP .test does not.
  // A sign-in with a login Deadbolt doesn't have: Save in the page saves it.
  const page = await newPage("save-update-generate")
  const user = "saved@acme.test"
  const first = "save-offer-synthetic-secret-61822"
  await newTurn(worker)
  await page.goto(`${origin}/signin`)
  await typeInto(page, "#email", user)
  await typeInto(page, "#password", first)
  await page.locator("button[type=submit]").click()
  await page.waitForURL(/\/account\?/)
  const save = await offerShown(page, "Save login?")
  check(save, "a confirmed sign-in offers to save the new login in the page")
  check(!await save.content().then((c) => c.includes(first)), "the offer never holds the password")
  await acceptOffer(save, "Save in the page saves it")
  check(await isSaved(worker, origin, user, first), "the vault fills the saved sign-in's password")

  // The site changed it: signing in with the new one offers the update.
  const changed = "changed-synthetic-secret-73905"
  await newTurn(worker)
  await page.goto(`${origin}/signin`)
  await typeInto(page, "#email", user)
  await typeInto(page, "#password", changed)
  await page.locator("button[type=submit]").click()
  await page.waitForURL(/\/account\?/)
  const update = await offerShown(page, "Update password?")
  check(update, "signing in with a changed password offers the update")
  await acceptOffer(update, "Update in the page updates it")
  check(await isSaved(worker, origin, user, changed), "the vault fills the updated password, in the same login")

  // A sign-up with a generated password: saved through the offer.
  const fresh = "fresh@acme.test"
  await newTurn(worker)
  await page.goto(`${origin}/signup`)
  await typeInto(page, "#email", fresh)
  const generated = await generate(page, "#new", "#confirm")
  check(generated.length >= 12 && generated !== first && generated !== changed, `the generated password fills both boxes (${generated.length} characters)`)
  await page.locator("button[type=submit]").click()
  await page.waitForURL(/\/account\?/)
  const signup = await offerShown(page, "Save login?")
  check(signup, "a sign-up with a generated password offers to save it")
  await acceptOffer(signup, "Save saves the new account")
  check(await isSaved(worker, origin, fresh, generated), "the vault fills the generated password it saved")

  // A password change: the current one from the menu, a generated new one, saved through the update.
  await newTurn(worker)
  await page.goto(`${origin}/settings/password?u=${encodeURIComponent(user)}`)
  const current = await menuOn(page, "#current", user)
  await current.locator("button.row", { hasText: user }).first().click()
  await until("the current password fills", async () => await page.inputValue("#current") === changed)
  check(true, "the menu fills the current password on the change form")
  const next = await generate(page, "#new", "#confirm")
  check(next !== changed, "the new password is a generated one")
  await page.locator("button[type=submit]").click()
  await page.waitForURL(/\/account\?/)
  const changedOffer = await offerShown(page, "Update password?")
  check(changedOffer, "changing to a generated password offers the update")
  await acceptOffer(changedOffer, "Update saves the generated password")
  check(await isSaved(worker, origin, user, next), "the vault fills the generated new password")
  await page.close()
  const added = (await logins(device)).length - before
  check(added === 3, `the site flows add three logins and update in place (${added})`)
  return added
}

/**
 * The same on the real demo site: a sign-up with a generated password, a
 * password change to another generated one, and the two-step sign-in that
 * follows, each through the inline menu and in-page offer. Returns how many
 * logins it adds (one).
 */
async function demoFlows(device: Page, worker: Worker) {
  const before = (await logins(device)).length
  const user = `standalone-${Date.now().toString(36)}@example.test`
  const page = await newPage("demo")
  await newTurn(worker)
  await page.goto(`${DEMO}/signup`)
  await page.locator("#name").fill("Standalone Proof")
  await typeInto(page, "#email", user)
  const first = await generate(page, "#password", "#confirm")
  await page.locator("button[type=submit]").click()
  await page.waitForURL((u) => u.origin === DEMO && u.pathname === "/app")
  const save = await offerShown(page, "Save login?")
  check(save, "the demo's sign-up offers to save the generated password")
  await acceptOffer(save, "Save on the demo saves the new account")
  check(await isSaved(worker, DEMO, user, first), "the vault fills the demo account's generated password")

  // The settings page shows its form again after the change ("Password updated.").
  await newTurn(worker)
  await page.goto(`${DEMO}/settings/password`)
  const current = await menuOn(page, "#current", user)
  await current.locator("button.row", { hasText: user }).first().click()
  await until("the demo's current password fills", async () => await page.inputValue("#current") === first)
  check(true, "the menu fills the current password on the demo's change form")
  const next = await generate(page, "#new", "#confirm")
  check(next !== first, "the demo's new password is a generated one")
  await page.locator("button[type=submit]").click()
  await page.getByText("Password updated.").waitFor()
  const inPlace = await offerShown(page, "Update password?", 8000)
  if (inPlace) await acceptOffer(inPlace, "the demo's change form offers the update in place")
  console.log(`note: the demo's change form ${inPlace ? "offered the update in place" : "offered nothing in place; the next sign-in must"}`)

  // Signing in again with the new password: the update, unless it was taken in place.
  await page.goto(`${DEMO}/logout`)
  await newTurn(worker)
  await page.goto(`${DEMO}/login`)
  await typeInto(page, "#email", user)
  await page.locator("button[type=submit]").click()
  await page.locator("#password").waitFor()
  await typeInto(page, "#password", next)
  await page.locator("button[type=submit]").click()
  await page.waitForURL((u) => u.origin === DEMO && u.pathname === "/app")
  if (!inPlace) {
    const update = await offerShown(page, "Update password?")
    check(update, "the demo sign-in with the changed password offers the update")
    await acceptOffer(update, "Update on the demo updates it")
  }
  check(await isSaved(worker, DEMO, user, next), "the vault fills the demo's changed, generated password")

  // And the two-step sign-in fills from the menu: the email, then the password.
  await page.goto(`${DEMO}/logout`)
  await page.goto(`${DEMO}/login`)
  const email = await menuOn(page, "#email", user)
  await email.locator("button.row", { hasText: user }).first().click()
  await until("the demo's email fills", async () => await page.inputValue("#email") === user)
  await page.locator("button[type=submit]").click()
  await page.locator("#password").waitFor()
  const password = await menuOn(page, "#password", user)
  await password.locator("button.row", { hasText: user }).first().click()
  await until("the demo's password fills", async () => await page.inputValue("#password") === next)
  await page.locator("button[type=submit]").click()
  await page.waitForURL((u) => u.origin === DEMO && u.pathname === "/app")
  check(true, "the demo's two-step sign-in fills from the menu and signs in")
  await page.close()
  const added = (await logins(device)).length - before
  check(added === 1, `the demo adds one login and updates it in place (${added})`)
  return added
}

/** The identity and card the CLI writes for the forms flows (synthetic; 4242… is a test number). */
const IDENTITY = ["new", "identity", "--name", "Home", "given-name=Kit", "family-name=Proof", "email=kit@example.test",
  "phone=+14155550123", "address-line1=123 Main St", "city=Brooklyn", "region=NY", "postal-code=11201", "country=US"]
const CARD = ["new", "card", "--name", "Visa", "number=4242424242424242", "expiry=2028-08", "cvv=123", "cardholder=Kit Proof", "brand=Visa"]
const digits = (s: string) => s.replace(/\D/g, "")
/** The re-auth prompt a card fill raises: "Fill <card>", a Passphrase box, Fill and Cancel. */
const CARD_REAUTH = /^Fill /
/** The re-auth prompt a passkey sign-in or registration on localhost raises under Strict. */
const PASSKEY_REAUTH = /^(Sign in to|Save a passkey for) localhost$/
/** A re-auth prompt whose heading matches `heading`: a Passphrase box, its submit button and Cancel. */
const reauthPrompt = (page: Page, heading = CARD_REAUTH) => page.locator("form.view.center.unlock").filter({ has: page.getByRole("heading", { name: heading }) })
/** A prompt the test answers as a person would: its heading, typing the passphrase and pressing its submit button, its error, and whether it's gone. */
interface Prompt {
  where: "toolbar popup" | "new device tab"
  heading(): Promise<string>
  answer(passphrase: string): Promise<void>
  refused(): Promise<boolean>
  gone(): Promise<boolean>
  close(): void
}
/** The browser's DevTools targets (`--remote-debugging-port=0` writes its port to the profile). */
async function targets() {
  const port = (await Bun.file(join(profile, "DevToolsActivePort")).text()).split("\n")[0]
  return await (await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(5000) })).json() as Array<{ id: string; type: string; url: string; webSocketDebuggerUrl: string }>
}
/** A minimal DevTools connection to one target. */
async function devtools(url: string) {
  const ws = new WebSocket(url)
  const waiting = new Map<number, (r: { result?: Record<string, unknown>; error?: { message: string } }) => void>()
  ws.onmessage = (e) => {
    const m = JSON.parse(String(e.data)) as { id?: number; result?: Record<string, unknown>; error?: { message: string } }
    if (m.id !== undefined) waiting.get(m.id)?.(m)
  }
  await new Promise((ok, fail) => {
    const timer = setTimeout(() => { ws.close(); fail(new Error("DevTools connection timed out")) }, 5000)
    ws.onopen = (event) => { clearTimeout(timer); ok(event) }
    ws.onerror = (event) => { clearTimeout(timer); fail(event) }
  })
  const closed = () => { for (const reply of waiting.values()) reply({ error: { message: "DevTools target closed" } }) }
  ws.onclose = closed
  ws.onerror = closed
  let id = 0
  const send = (method: string, params: Record<string, unknown> = {}) =>
    new Promise<Record<string, unknown>>((ok, fail) => {
      const request = ++id
      const timer = setTimeout(() => { waiting.delete(request); fail(new Error(`${method}: timed out`)) }, 5000)
      waiting.set(request, (r) => {
        clearTimeout(timer)
        waiting.delete(request)
        if (r.error) fail(new Error(`${method}: ${r.error.message}`))
        else ok(r.result ?? {})
      })
      ws.send(JSON.stringify({ id: request, method, params }))
    })
  const evaluate = async <T>(expression: string) => ((await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result as { value: T }).value
  return { send, evaluate, close: () => ws.close() }
}
/** In the popup's document: the form of the prompt whose heading matches `heading`. */
const popupForm = (heading: RegExp) => `[...document.querySelectorAll("form.view.center.unlock")].find((f) => ${heading}.test(f.querySelector("h2")?.textContent ?? ""))`
/**
 * The toolbar popup's prompt. Playwright doesn't list an action popup among
 * the context's pages, so this drives it over DevTools, with trusted input:
 * typed text and a mouse click on its submit button (Fill for a card).
 * `shots` names its stills.
 */
async function popupPrompt(heading = CARD_REAUTH, shots = "strict-reauth"): Promise<Prompt | null> {
  const POPUP_FORM = popupForm(heading)
  const target = (await targets()).find((t) => t.url.startsWith(`chrome-extension://${ID}/popup.html`))
  if (!target) return null
  const popup = await devtools(target.webSocketDebuggerUrl)
  if (!await popup.evaluate<boolean>(`!!(${POPUP_FORM})`).catch(() => false)) return popup.close(), null
  const still = async (name: string) => {
    if (!video) return
    await mkdir(video, { recursive: true })
    const image = await popup.send("Page.captureScreenshot", { format: "png" })
    await Bun.write(join(video, `${name}.png`), Buffer.from(image.data as string, "base64"))
  }
  await still(`${shots}-prompt`)
  return {
    where: "toolbar popup",
    heading: () => popup.evaluate<string>(`${POPUP_FORM}?.querySelector("h2")?.textContent ?? ""`),
    async answer(given) {
      // As a person waits for Fill to come back after a wrong try.
      await until("the popup's submit button is ready", () => popup.evaluate<boolean>(`!!(${POPUP_FORM})?.querySelector("button[type=submit]:not([disabled])")`), 15_000)
      await popup.evaluate(`(() => { const box = ${POPUP_FORM}.querySelector("input[type=password]"); box.focus(); box.select() })()`)
      await popup.send("Input.insertText", { text: given })
      const at = await popup.evaluate<{ x: number; y: number }>(`(() => { const r = ${POPUP_FORM}.querySelector("button[type=submit]").getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 } })()`)
      for (const type of ["mousePressed", "mouseReleased"]) await popup.send("Input.dispatchMouseEvent", { type, ...at, button: "left", clickCount: 1 })
    },
    refused: async () => {
      const refused = await popup.evaluate<boolean>(`!!(${POPUP_FORM}?.querySelector("p.error")?.textContent?.trim())`).catch(() => false)
      if (refused) await still(`${shots}-wrong-passphrase`)
      return refused
    },
    gone: async () => !(await targets()).some((t) => t.id === target.id) || !await popup.evaluate<boolean>(`!!(${POPUP_FORM})`).catch(() => false),
    close: () => popup.close(),
  }
}
/**
 * Where the prompt shows: the toolbar popup the fill opens, or the device tab
 * it opens instead when it can't, never the original device page. That one
 * sits in a background tab and gets the broadcast too: answering there would
 * hide the product's real path.
 */
async function promptShown(device: Page, heading = CARD_REAUTH, shots = "strict-reauth"): Promise<Prompt | null> {
  const popup = await popupPrompt(heading, shots).catch(() => null)
  if (popup) return popup
  for (const p of context!.pages()) {
    if (p === device || p.isClosed() || !p.url().startsWith(`chrome-extension://${ID}/device.html`) || !await reauthPrompt(p, heading).count().catch(() => 0)) continue
    const prompt = reauthPrompt(p, heading)
    const path = await p.video()?.path()
    if (path && !recordings.some((r) => r.path === path)) recordings.push({ path, name: `${shots}-device-tab` })
    return {
      where: "new device tab",
      heading: async () => await prompt.getByRole("heading").first().textContent() ?? "",
      async answer(given) {
        const submit = prompt.locator("button[type=submit]:not([disabled])")
        await submit.waitFor({ timeout: 15_000 })
        await prompt.getByLabel("Passphrase", { exact: true }).fill(given)
        await submit.click()
      },
      refused: async () => !!(await prompt.locator("p.error").first().textContent().catch(() => ""))?.trim(),
      gone: async () => p.isClosed() || await prompt.count() === 0,
      close: () => {},
    }
  }
  return null
}
/** Picks `row` in the forms menu. */
async function pick(menu: Frame, row: string) {
  await menu.locator("button.row", { hasText: row }).first().click()
}
/**
 * Waits for the pick's pill to say Filled (and fails on its error): a form
 * fills field by field, so its first value alone doesn't mean the rest are in.
 */
async function filled(menu: Frame, what: string) {
  let failed: string | undefined
  await until(what, async () => {
    if (await menu.locator(".pill.failed").count().catch(() => 0)) {
      failed = await menu.locator(".pill .pill-label").getAttribute("title").catch(() => null) ?? "Unknown fill error"
      return true
    }
    return await menu.locator(".pill.ok").count().catch(() => 0) > 0
  }, 30_000)
  if (failed) throw new Error(`${what}: ${failed}`)
}
/** Picks the card in the menu of the card number box, answering the prompt with each of `passphrases` (the right one last). */
async function fillCard(page: Page, device: Page, passphrases: string[] = []) {
  // A fresh navigation, not a reload: Chromium restores a reloaded form's values.
  await page.goto(page.url())
  // As a person would, scroll the card block into view first: fields out of view take nothing.
  await page.locator("#cc-number").evaluate((el) => el.scrollIntoView({ block: "center" }))
  const menu = await menuOn(page, "#cc-number", "4242")
  const hint = menu.getByText("Deadbolt asks for your passphrase first.", { exact: true })
  check(await hint.isVisible() === (passphrases.length > 0), "the card menu explains passphrase reauthentication only under Strict")
  await pick(menu, "4242")
  const nothing = async () => await page.inputValue("#cc-number") === "" && await page.inputValue("#cc-csc") === ""
  let prompt: Prompt | null = null
  try {
    for (const [i, given] of passphrases.entries()) {
      if (!prompt) prompt = await until("the card fill asks for the passphrase", () => promptShown(device), 15_000)
      const shown = prompt
      if (!i) {
        console.log(`note: the card's passphrase prompt shows in the ${shown.where}`)
        check(/^Fill Visa/.test(await shown.heading()), "the card fill asks for the passphrase, naming the card")
      }
      check(await nothing(), `nothing of the card is written before the passphrase${i ? " is right" : ""}`)
      await shown.answer(given)
      if (given !== passphrase) {
        await until("the prompt says the passphrase is wrong", () => shown.refused(), 30_000)
        check(await nothing(), "a wrong passphrase is refused and fills nothing of the card")
      }
    }
    // No bringToFront: answering the prompt must hand the checkout its tab back itself.
    await filled(menu, "the card's pill says Filled")
    if (prompt) {
      const shown = prompt
      check(await until("the prompt goes", () => shown.gone(), 10_000), "the prompt goes once the card fills")
    }
  } finally {
    prompt?.close()
  }
  return { number: digits(await page.inputValue("#cc-number")), expiry: digits(await page.inputValue("#cc-exp")), code: await page.inputValue("#cc-csc"), holder: await page.inputValue("#cc-name") }
}
/**
 * The CLI's identity and card on a checkout at `url`: the identity fills the
 * address, and the card fills at once under Relaxed and after the passphrase
 * under Strict (a wrong one first). Comfortable follows the native no-Touch-ID rule.
 */
async function formFlows(device: Page, worker: Worker, url: string) {
  const host = new URL(url).host
  await until("the CLI's identity and card reach the browser", async () => {
    const r = (await vault(worker, { type: "forms", origin: new URL(url).origin, kinds: ["identity", "card"] })).reply
    return (r.identities as unknown[] | undefined)?.length && (r.cards as unknown[] | undefined)?.length
  }, 90_000)
  const page = await newPage(`checkout-${new URL(url).hostname}`)
  try {
    await page.goto(url)
    const identities = await menuOn(page, "#ship-name", "Home")
    await pick(identities, "Home")
    await filled(identities, "the identity's pill says Filled")
    const address = await Promise.all(["#ship-name", "#ship-line1", "#ship-city", "#ship-zip"].map((s) => page.inputValue(s)))
    check(JSON.stringify(address) === JSON.stringify(["Kit Proof", "123 Main St", "Brooklyn", "11201"]), `the identity fills the address on ${host} (${address.join(" | ")})`)

    await request(device, { type: "device-preset", preset: "relaxed" })
    const relaxed = await fillCard(page, device)
    check(relaxed.number === "4242424242424242" && relaxed.expiry === "0828" && relaxed.code === "123" && relaxed.holder === "Kit Proof", `Relaxed fills the whole card on ${host} with no passphrase`)

    await request(device, { type: "device-preset", preset: "strict" })
    const forms = (await vault(worker, { type: "forms", origin: new URL(url).origin, kinds: ["card"] })).reply
    const card = (forms.cards as Array<{ ref: string; last4: string }>).find((c) => c.last4 === "4242")!
    const injected = (await vault(worker, { type: "fill-form", origin: new URL(url).origin, ref: card.ref, fields: ["number", "cvv"], preset: "relaxed" })).reply
    check(injected.type === "error" && injected.code === "passphrase_needed" && !("values" in injected), "a preset smuggled into fill-form cannot weaken Strict")
    for (const type of ["device-create", "device-unlock", "device-join-finish"]) {
      const failed = (await vault(worker, { type, preset: "relaxed", passphrase: "wrong" })).reply
      check(failed.type === "error", `${type} refuses to open an already-open vault`)
      const guarded = (await vault(worker, { type: "fill-form", origin: new URL(url).origin, ref: card.ref, fields: ["number", "cvv"] })).reply
      check(guarded.code === "passphrase_needed" && !("values" in guarded), `a failed ${type} leaves Strict unchanged`)
    }
    await vault(worker, { type: "hello", preset: "relaxed" })
    const refused = (await vault(worker, { type: "fill-form", origin: new URL(url).origin, ref: card.ref, fields: ["number", "cvv"] })).reply
    check(refused.type === "error" && refused.code === "passphrase_needed" && !("values" in refused), "Rust keeps Strict after a preset smuggled into hello, even without the UI gate")
    const strict = await fillCard(page, device, ["wrong fixture passphrase", passphrase])
    check(strict.number === "4242424242424242" && strict.code === "123", `Strict fills the card on ${host} after the passphrase`)
    await fillCard(page, device, [passphrase])
    check(true, "and asks again for the next card fill")
    await page.goto(url)
    const again = await menuOn(page, "#ship-name", "Home")
    await pick(again, "Home")
    await filled(again, "the identity's pill says Filled under Strict")
    check(await page.inputValue("#ship-zip") === "11201", "the whole address fills under Strict")
    const none = await promptShown(device)
    none?.close()
    check(!none, "an identity fills under Strict without the passphrase")

    await request(device, { type: "device-preset", preset: "comfortable" })
    await fillCard(page, device)
    check(true, `Comfortable follows the native Touch-ID-off rule on ${host}`)
  } finally {
    await request(device, { type: "device-preset", preset: "comfortable" }).catch(() => {})
    await page.close()
  }
}
// ---- Passkeys (the browser's own vault signs) ---------------------------------------

/** Deadbolt's AAGUID (crates/cli/src/webauthn.rs): the browser vault's passkeys carry it too. */
const DEADBOLT_AAGUID = "3a31ecda-fefc-f251-1f3e-a11bfdc1de5f"
async function devicePasskeys(device: Page) {
  const reply = (await request(device, { type: "device-passkeys" })).reply
  const metadata = new Set(["ref", "vault", "rpId", "credentialId", "username", "created"])
  if (!Array.isArray(reply.passkeys) || reply.passkeys.some((k) => Object.keys(k).some((key) => !metadata.has(key)))) throw new Error("device-passkeys returned more than public metadata")
  return reply.passkeys as DevicePasskey[]
}
type Outcome = { ok: boolean; value: any }
const startCall = (page: Page, name: string, kind: "create" | "get", json: unknown, extra: Record<string, unknown> = {}) =>
  page.evaluate(([n, k, j, e]) => (window as any).start(n, k, j, e), [name, kind, json, extra] as const)
const result = (page: Page, name: string) => page.evaluate((n) => (window as any).result(n), name) as Promise<Outcome | null>
const outcome = (page: Page, name: string, what: string, ms = 30_000) => until<Outcome>(what, () => result(page, name), ms)
/** The client data in a credential's JSON. */
const clientData = (credential: any) => JSON.parse(Buffer.from(credential.response.clientDataJSON, "base64url").toString())
/** Deadbolt's credentials are for the page's own origin, never cross-origin. */
function ownOrigin(credential: any, how: string) {
  const data = clientData(credential)
  check(data.origin === origin && data.crossOrigin === false && !("topOrigin" in data), `${how}: for this origin, crossOrigin false`)
}
/** The toolbar badge of the tab showing `prefix`. */
const badge = (worker: Worker, prefix: string) =>
  worker.evaluate(async (prefix) => {
    for (const t of await chrome.tabs.query({})) {
      const frame = t.id === undefined ? null : await chrome.webNavigation.getFrame({ tabId: t.id, frameId: 0 }).catch(() => null)
      if (frame?.url.startsWith(prefix)) return chrome.action.getBadgeText({ tabId: t.id })
    }
    return ""
  }, prefix)
/** In the popup's document: the passkey prompt. */
const PASSKEY_CARD = `document.querySelector(".passkey-prompt")`
/** The toolbar popup's passkey prompt: its heading, the passkeys it lists by username, and a trusted click on one of its buttons. */
interface PasskeyPopup {
  heading: string
  accounts: string[]
  /** "Deadbolt asks for your passphrase next.", or empty. */
  note: string
  /** Presses `label` (in `account`'s row, if given), and waits for the popup to close. */
  press(label: string, account?: string): Promise<void>
  close(): void
}
/** Waits for the toolbar popup the page's passkey call opens, as the card prompt's is driven: over DevTools. */
function passkeyPopup(what: string, ms = 20_000): Promise<PasskeyPopup> {
  return until(what, async () => {
    const target = (await targets()).find((t) => t.url.startsWith(`chrome-extension://${ID}/popup.html`))
    if (!target) return null
    const popup = await devtools(target.webSocketDebuggerUrl)
    const seen = await popup.evaluate<{ heading: string; accounts: string[]; note: string } | null>(`(() => {
      const card = ${PASSKEY_CARD}
      return card && { heading: card.querySelector("h2")?.textContent ?? "", accounts: [...card.querySelectorAll(".account-title")].map((e) => e.textContent), note: card.querySelector(".note")?.textContent?.trim() ?? "" }
    })()`).catch(() => null)
    if (!seen) return popup.close(), null
    if (video) {
      await mkdir(video, { recursive: true })
      const image = await popup.send("Page.captureScreenshot", { format: "png" }).catch(() => null)
      if (image) await Bun.write(join(video, `passkey-${seen.heading.split(" ")[0].toLowerCase()}.png`), Buffer.from(image.data as string, "base64"))
    }
    return {
      ...seen,
      async press(label, account) {
        const scope = account
          ? `[...card.querySelectorAll(".account")].find((a) => a.querySelector(".account-title")?.textContent === ${JSON.stringify(account)})`
          : "card"
        const at = await popup.evaluate<{ x: number; y: number } | null>(`(() => {
          const card = ${PASSKEY_CARD}
          const b = [...(${scope})?.querySelectorAll("button") ?? []].find((b) => b.textContent.trim() === ${JSON.stringify(label)})
          if (!b) return null
          const r = b.getBoundingClientRect()
          return { x: r.x + r.width / 2, y: r.y + r.height / 2 }
        })()`)
        if (!at) throw new Error(`the passkey prompt has no ${label} button${account ? ` for ${account}` : ""}`)
        for (const type of ["mousePressed", "mouseReleased"]) await popup.send("Input.dispatchMouseEvent", { type, ...at, button: "left", clickCount: 1 })
        // It closes, or shows what comes next (Strict's passphrase) in place of the prompt.
        await until("the passkey prompt goes", async () => !(await targets()).some((t) => t.id === target.id) || !await popup.evaluate<boolean>(`!!${PASSKEY_CARD}`).catch(() => false), 10_000)
        popup.close()
      },
      close: () => popup.close(),
    }
  }, ms)
}
/** That no passkey prompt shows for the page within `ms`: no badge and no popup prompt. */
async function noPasskeyPrompt(worker: Worker, ms = 2000) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    if ((await badge(worker, origin)) !== "") return false
    if (await passkeyPopup("a passkey popup", 1).then((p) => (p.close(), true), () => false)) return false
    await Bun.sleep(200)
  }
  return true
}
async function verifyRegistration(response: any, expectedChallenge: string, how: string) {
  const v = await verifyRegistrationResponse({ response, expectedChallenge, expectedOrigin: origin, expectedRPID: "localhost", requireUserVerification: false })
  check(v.verified, `@simplewebauthn/server verifies the ${how} registration`)
  return v.registrationInfo!
}
/** A Deadbolt registration: ES256, none attestation, synced, never user-verified (a passphrase isn't UV), counter 0. */
async function deadboltRegistration(response: any, expectedChallenge: string, how: string) {
  const info = await verifyRegistration(response, expectedChallenge, how)
  check(info.aaguid === DEADBOLT_AAGUID, `${how}: made by Deadbolt (AAGUID ${info.aaguid})`)
  check(info.fmt === "none" && info.credentialType === "public-key", `${how}: with none attestation`)
  check(info.credentialDeviceType === "multiDevice" && info.credentialBackedUp, `${how}: flagged as a synced (backed-up) passkey`)
  check(!info.userVerified, `${how}: not user-verified`)
  check(info.credential.counter === 0, `${how}: with a zero sign counter`)
  return info.credential
}
async function verifyAssertion(response: any, expectedChallenge: string, credential: WebAuthnCredential, how: string) {
  const v = await verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin: origin, expectedRPID: "localhost", credential, requireUserVerification: false })
  check(v.verified && !v.authenticationInfo.userVerified, `@simplewebauthn/server verifies the ${how} assertion, not user-verified`)
  check(response.id === credential.id, `${how}: signed with the expected passkey`)
}
/** A registration from the page, saved in the popup; under Strict, `reauth` answers the passphrase prompt that follows. */
async function registerInPage(page: Page, device: Page, name: string, username: string, how: string, reauth = false, userID?: Uint8Array<ArrayBuffer>) {
  const reg = await generateRegistrationOptions({
    rpName: "Acme", rpID: "localhost", userName: username, userID, attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" }, supportedAlgorithmIDs: [-7, -257],
  })
  await page.bringToFront()
  await startCall(page, name, "create", reg)
  const save = await passkeyPopup(`${how}: the popup asks to save the passkey`)
  check(save.heading === "Save a passkey for localhost?", `${how}: the popup asks to save a passkey for localhost`)
  check(save.note === (reauth ? "Deadbolt asks for your passphrase next." : ""), `${how}: the popup ${reauth ? "says the passphrase comes next" : "promises no Touch ID or passphrase"}`)
  await save.press("Save")
  if (reauth) await answerReauth(page, device, name, "passkey-create", how)
  const made = await outcome(page, name, `${how}: registration settles`)
  if (!made.ok) throw new Error(`${how}: ${made.value}`)
  ownOrigin(made.value, how)
  return deadboltRegistration(made.value, reg.challenge, how)
}
/** A modal sign-in, answered in the popup with `account`'s passkey; returns the assertion and its challenge. */
async function signInInPage(page: Page, device: Page, name: string, account: string, how: string, { listed, verification = "preferred", reauth = false }: { listed?: string[]; verification?: "preferred" | "discouraged"; reauth?: boolean } = {}) {
  const auth = await generateAuthenticationOptions({ rpID: "localhost", userVerification: verification })
  await page.bringToFront()
  await startCall(page, name, "get", auth)
  const signIn = await passkeyPopup(`${how}: the popup asks which passkey`)
  check(signIn.heading === "Sign in to localhost with a passkey?", `${how}: the popup asks to sign in to localhost`)
  check(signIn.note === (reauth ? "Deadbolt asks for your passphrase next." : ""), `${how}: the popup ${reauth ? "says the passphrase comes next" : "promises no Touch ID or passphrase"}`)
  if (listed) check(JSON.stringify([...signIn.accounts].sort()) === JSON.stringify([...listed].sort()), `${how}: the popup lists ${listed.join(", ")} (${signIn.accounts.join(", ")})`)
  await signIn.press("Sign in", account)
  if (reauth) await answerReauth(page, device, name, "passkey-get", how)
  const r = await outcome(page, name, `${how}: sign-in settles`)
  if (!r.ok) throw new Error(`${how}: ${r.value}`)
  ownOrigin(r.value, how)
  return { response: r.value, challenge: auth.challenge }
}
/** Strict's passphrase prompt for a passkey ceremony: nothing reaches the page before it; a wrong passphrase first, then the right one. */
async function answerReauth(page: Page, device: Page, name: string, kind: "passkey-get" | "passkey-create", how: string) {
  const waiting = await until(`${how}: the background waits on the passphrase`, async () => (await request(device, { type: "device-reauth" })).reply.reauth as { kind?: string; site?: string } | null, 15_000)
  check(waiting.kind === kind && waiting.site === "localhost", `${how}: Strict holds the ${kind} for the passphrase`)
  const prompt = await until(`${how}: the passphrase prompt shows`, () => promptShown(device, PASSKEY_REAUTH, "passkey-reauth"), 15_000)
  try {
    console.log(`note: ${how}: the passphrase prompt shows in the ${prompt.where} ("${await prompt.heading()}")`)
    check(await result(page, name) === null, `${how}: Strict asks for the passphrase before the page gets anything`)
    await prompt.answer("wrong fixture passphrase")
    await until(`${how}: the prompt says the passphrase is wrong`, () => prompt.refused(), 30_000)
    check(await result(page, name) === null, `${how}: a wrong passphrase is refused and the page still has nothing`)
    await prompt.answer(passphrase)
    check(await until(`${how}: the prompt goes`, () => prompt.gone(), 15_000), `${how}: the prompt goes once the passphrase is right`)
  } finally {
    prompt.close()
  }
}

/** `deadbolt browser-host`, as the native-host build's browser starts it: framed JSON on stdin and stdout. */
function browserHost() {
  const child = Bun.spawn([deadbolt, "browser-host", `chrome-extension://${ID}/`], { env, stdin: "pipe", stdout: "pipe", stderr: "inherit" })
  const waiting = new Map<number, (reply: Record<string, any>) => void>()
  void (async () => {
    let buffer = Buffer.alloc(0)
    for await (const chunk of child.stdout as ReadableStream<Uint8Array>) {
      buffer = Buffer.concat([buffer, chunk])
      while (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32LE(0)) {
        const n = buffer.readUInt32LE(0)
        const message = JSON.parse(buffer.subarray(4, 4 + n).toString()) as Record<string, any>
        buffer = buffer.subarray(4 + n)
        if (typeof message.id === "number") waiting.get(message.id)?.(message)
      }
    }
  })().catch(() => {})
  let next = 0
  const send = (body: Record<string, unknown> & { type: string }, ms = 30_000) =>
    new Promise<Record<string, any>>((ok, fail) => {
      const id = ++next
      const timer = setTimeout(() => { waiting.delete(id); fail(new Error(`browser-host ${body.type}: timed out`)) }, ms)
      waiting.set(id, (reply) => {
        clearTimeout(timer)
        waiting.delete(id)
        if (reply.type === "error") fail(new Error(`browser-host ${body.type}: ${reply.code}: ${reply.message}`))
        else ok(reply)
      })
      const data = Buffer.from(JSON.stringify({ id, ...body }))
      const head = Buffer.alloc(4)
      head.writeUInt32LE(data.length)
      child.stdin.write(Buffer.concat([head, data]))
      void child.stdin.flush()
    })
  return { send, close: () => { void child.stdin.end(); child.kill() } }
}
/** The CLI vault's passkeys for this origin, after a CLI sync, through browser-host's passkey-list. */
async function cliPasskeys(host: ReturnType<typeof browserHost>) {
  await cli("sync").catch(() => {})
  return (await host.send({ type: "passkey-list", origin })).passkeys as Array<{ ref: string; credentialId: string; username?: string }>
}

/**
 * Passkeys in the browser's own vault, on a trusted localhost page: a
 * registration (ES256, preferred UV) saved in the popup, a modal sign-in and
 * an autofill one from the inline menu, each checked with
 * @simplewebauthn/server; required UV handed to the browser's own WebAuthn
 * (a virtual authenticator); Strict asking for the passphrase for preferred
 * verification, never for discouraged, with UV false either way; and a
 * passkey deleted from the device page. With the CLI: a browser passkey
 * signs on the CLI, and a CLI passkey signs in the browser, both through
 * `deadbolt browser-host` and synced, and the deletion reaches the CLI.
 */
async function passkeyFlows(device: Page, worker: Worker) {
  const page = await newPage("passkeys")
  // The browser's own WebAuthn, for the calls Deadbolt hands back to it.
  const cdp = await context!.newCDPSession(page)
  await cdp.send("WebAuthn.enable", { enableUI: false })
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  })
  const host = smoke ? null : browserHost()
  try {
    await page.goto(`${origin}/passkey`)
    check((await devicePasskeys(device)).length === 0, "the browser vault starts with no passkeys")

    // Registration and modal sign-in, under Comfortable.
    const kit = await registerInPage(page, device, "register", "kit@acme.test", "browser registration")
    const listed = await devicePasskeys(device)
    const saved = listed.find((k) => k.credentialId === kit.id)
    check(true, "device-passkeys never holds a passkey's private key")
    check(listed.length === 1 && saved?.rpId === "localhost" && saved.username === "kit@acme.test" && !!saved.ref && !!saved.vault, "device-passkeys lists the new passkey with its relying party and username")
    const modal = await signInInPage(page, device, "modal", "kit@acme.test", "modal sign-in", { listed: ["kit@acme.test"] })
    await verifyAssertion(modal.response, modal.challenge, kit, "modal sign-in")

    // Autofill sign-in: the passkey waits in the inline menu, with no prompt.
    await page.reload()
    const auto = await generateAuthenticationOptions({ rpID: "localhost", userVerification: "preferred" })
    await startCall(page, "auto", "get", auto, { mediation: "conditional" })
    check(await noPasskeyPrompt(worker), "an autofill sign-in opens no prompt by itself")
    const menu = await menuOn(page, "#email", "kit@acme.test")
    const row = menu.locator("button.row").filter({ has: menu.locator(".sub", { hasText: /^Passkey · \S/ }) })
    check(await row.count() === 1 && (await row.locator(".title").textContent()) === "kit@acme.test", "the inline menu offers the passkey, with its vault")
    await row.click()
    const picked = await outcome(page, "auto", "autofill sign-in settles")
    if (!picked.ok) throw new Error(`autofill sign-in: ${picked.value}`)
    ownOrigin(picked.value, "autofill sign-in")
    await verifyAssertion(picked.value, auto.challenge, kit, "autofill sign-in")

    // Required UV: no Touch ID here, so the browser's own WebAuthn takes it without asking.
    const required = await generateRegistrationOptions({
      rpName: "Acme", rpID: "localhost", userName: "required@acme.test", attestationType: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "required" }, supportedAlgorithmIDs: [-7],
    })
    await page.bringToFront()
    await startCall(page, "required", "create", required)
    const native = await outcome(page, "required", "required-UV registration settles")
    check(native.ok, `required UV registration settles in the browser (${native.ok ? "ok" : native.value})`)
    const nativeInfo = await verifyRegistration(native.value, required.challenge, "required-UV")
    check(nativeInfo.aaguid !== DEADBOLT_AAGUID && nativeInfo.userVerified, "required UV goes to the browser's own authenticator, which verifies the user")
    check(await noPasskeyPrompt(worker, 500), "with no Deadbolt prompt")
    const requiredGet = await generateAuthenticationOptions({ rpID: "localhost", userVerification: "required" })
    await startCall(page, "required-get", "get", requiredGet)
    const nativeGet = await outcome(page, "required-get", "required-UV sign-in settles")
    check(nativeGet.ok && nativeGet.value.id === nativeInfo.credential.id, `a required-UV sign-in goes to the browser too (${nativeGet.ok ? nativeGet.value.id === nativeInfo.credential.id ? "the browser's passkey" : nativeGet.value.id : nativeGet.value})`)
    check((await devicePasskeys(device)).length === 1, "the browser's own passkey never lands in Deadbolt")

    let cliCredential: WebAuthnCredential | undefined
    if (host) {
      const hello = await host.send({ type: "hello" })
      check((hello.capabilities as string[]).includes("passkeys"), "the CLI's browser-host takes passkeys")
      // Browser to CLI: the CLI lists the browser's passkey and signs with it.
      const onCli = await until("the browser's passkey reaches the CLI", async () => (await cliPasskeys(host)).find((k) => k.credentialId === kit.id), 90_000)
      check(onCli.username === "kit@acme.test", "the browser's passkey syncs to the CLI")
      const challenge = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url")
      const signed = await host.send({ type: "passkey-get", origin, ref: onCli.ref, challenge, userVerification: "preferred" }, 60_000)
      await verifyAssertion({
        id: signed.credentialId, rawId: signed.credentialId, type: "public-key", clientExtensionResults: {},
        response: { clientDataJSON: signed.clientDataJSON, authenticatorData: signed.authenticatorData, signature: signed.signature, userHandle: signed.userHandle },
      }, challenge, kit, "CLI browser-host (browser-made passkey)")

      // CLI to browser: browser-host makes one; the browser syncs it and signs in with it.
      const reg = await generateRegistrationOptions({ rpName: "Acme", rpID: "localhost", userName: "cli@acme.test", attestationType: "none", supportedAlgorithmIDs: [-7] })
      const made = await host.send({ type: "passkey-create", origin, challenge: reg.challenge, user: { id: reg.user.id, name: "cli@acme.test" }, exclude: [], userVerification: "preferred" }, 60_000)
      cliCredential = await deadboltRegistration({
        id: made.credentialId, rawId: made.credentialId, type: "public-key", clientExtensionResults: {},
        response: { clientDataJSON: made.clientDataJSON, attestationObject: made.attestationObject, transports: [] },
      }, reg.challenge, "CLI browser-host registration")
      await until("the CLI's passkey reaches the browser", async () => {
        await request(device, { type: "device-sync", wait: true }).catch(() => {})
        return (await devicePasskeys(device)).some((k) => k.credentialId === cliCredential!.id)
      }, 90_000)
      check(true, "the CLI's passkey syncs to the browser")
      const fromCli = await signInInPage(page, device, "from-cli", "cli@acme.test", "sign-in with the CLI's passkey", { listed: ["kit@acme.test", "cli@acme.test"] })
      await verifyAssertion(fromCli.response, fromCli.challenge, cliCredential, "sign-in with the CLI's passkey")
    }

    // Strict: preferred verification asks for the passphrase; discouraged doesn't; UV stays false.
    await request(device, { type: "device-preset", preset: "strict" })
    const strict = await signInInPage(page, device, "strict-get", "kit@acme.test", "Strict preferred sign-in", { reauth: true })
    await verifyAssertion(strict.response, strict.challenge, kit, "Strict preferred sign-in")
    const quiet = await signInInPage(page, device, "strict-discouraged", "kit@acme.test", "Strict discouraged sign-in", { verification: "discouraged" })
    check((await request(device, { type: "device-reauth" })).reply.reauth === null, "Strict asks no passphrase when the site discourages verification")
    await verifyAssertion(quiet.response, quiet.challenge, kit, "Strict discouraged sign-in")
    const strictMade = await registerInPage(page, device, "strict-register", "strict@acme.test", "Strict preferred registration", true)
    // Discoverable: Deadbolt has passkeys here, so only the required UV sends it to the browser.
    await page.bringToFront()
    await startCall(page, "strict-required", "get", await generateAuthenticationOptions({ rpID: "localhost", userVerification: "required" }))
    const strictRequired = await outcome(page, "strict-required", "Strict required-UV sign-in settles")
    check(strictRequired.ok && strictRequired.value.id === nativeInfo.credential.id, `Strict hands required UV to the browser too (${strictRequired.ok ? "the browser's passkey" : strictRequired.value})`)
    await request(device, { type: "device-preset", preset: "comfortable" })

    // The offline CI run also chooses among several accounts, not only the
    // online run that adds a CLI key. Verify the chosen account's actual key.
    const multiple = await signInInPage(page, device, "multiple", "strict@acme.test", "multiple-account sign-in", { listed: ["kit@acme.test", "strict@acme.test", ...(cliCredential ? ["cli@acme.test"] : [])] })
    await verifyAssertion(multiple.response, multiple.challenge, strictMade, "multiple-account sign-in")

    // The RP might discard a new registration. Reusing the user handle must
    // leave the original credential usable with its original public key.
    const again = await registerInPage(page, device, "same-user", "second@acme.test", "same-user registration", false, Uint8Array.from(Buffer.from(modal.response.response.userHandle, "base64url")))
    const kept = await devicePasskeys(device)
    const second = kept.find((k) => k.credentialId === again.id)!
    check(again.id !== kit.id && second.ref !== saved!.ref && kept.some((k) => k.credentialId === kit.id), "same-user registration creates a separate item and preserves the old credential")
    const original = await signInInPage(page, device, "original-again", "kit@acme.test", "original sign-in after same-user registration")
    await verifyAssertion(original.response, original.challenge, kit, "original sign-in after same-user registration")
    const repeated = await signInInPage(page, device, "second-sign-in", "second@acme.test", "new same-user sign-in")
    await verifyAssertion(repeated.response, repeated.challenge, again, "new same-user sign-in")

    // Rust enforces Strict even without the Settings UI or service-worker gate.
    await request(device, { type: "device-preset", preset: "strict" })
    for (const type of ["device-delete", "device-item-delete"]) for (const supplied of [undefined, "wrong fixture passphrase"]) {
      const refused = await vault(worker, { type, ref: second.ref, ...(supplied === undefined ? {} : { passphrase: supplied }) })
      check(refused.reply.type === "error" && refused.reply.code === (supplied === undefined ? "passphrase_needed" : "wrong_passphrase"), "Strict deletion refuses a missing or wrong passphrase in Rust")
      check((await devicePasskeys(device)).some((k) => k.credentialId === again.id), "refused deletion leaves the new same-user credential intact")
    }
    // The general item-detail page must enforce the same deletion consent as
    // Settings, and neither its listing nor secret endpoint may expose the key.
    const detail = await request(device, { type: "device-item", ref: second.ref })
    check(Array.isArray(detail.reply.fields) && !detail.reply.fields.some((f: { name: string }) => f.name === "private-key"), "the general item detail omits the passkey private key")
    check(!(await command(device, { type: "device-secret", ref: second.ref, field: "private-key", passphrase })).ok, "even reauthentication cannot reveal the passkey private key")
    await device.reload()
    await device.locator(".list-view .vrow").filter({ hasText: "second@acme.test" }).locator("button.vrow-main").click()
    const deleteItem = device.getByRole("button", { name: "Delete localhost", exact: true })
    await deleteItem.click()
    await deleteItem.click()
    const deletionAuth = device.locator("form.reauth")
    await deletionAuth.getByLabel("Passphrase", { exact: true }).fill("wrong fixture passphrase")
    await deletionAuth.getByRole("button", { name: "Delete", exact: true }).click()
    await deletionAuth.locator(".error").waitFor({ state: "visible" })
    check((await devicePasskeys(device)).some((k) => k.credentialId === again.id), "item-detail deletion keeps the passkey after a wrong Strict passphrase")
    await deletionAuth.getByLabel("Passphrase", { exact: true }).fill(passphrase)
    await deletionAuth.getByRole("button", { name: "Delete", exact: true }).click()
    await until("item detail deletes the selected passkey", async () => !(await devicePasskeys(device)).some((k) => k.credentialId === again.id))
    check((await devicePasskeys(device)).some((k) => k.credentialId === kit.id), "Strict item-detail deletion removes only the selected credential")
    // Delete through Settings under Strict, including confirmation and reauth,
    // not a worker shortcut. The page refreshes its preset from the service worker.
    await device.reload()
    await device.bringToFront()
    const settings = device.getByRole("button", { name: "Settings", exact: true })
    if (await settings.getAttribute("aria-pressed") !== "true") await settings.click()
    const remove = device.getByRole("button", { name: "Delete passkey kit@acme.test for localhost", exact: true })
    await remove.click()
    const confirmation = device.locator(".vrow.confirming").filter({ hasText: "Delete passkey for localhost?" })
    await confirmation.getByRole("button", { name: "Cancel", exact: true }).click()
    check((await devicePasskeys(device)).some((k) => k.credentialId === kit.id), "cancelling deletion keeps the passkey")
    await remove.click()
    await confirmation.getByLabel("Passphrase", { exact: true }).fill("wrong fixture passphrase")
    // A sync/status refresh must not discard the confirmation or its input.
    // Observe the devices repaint to know App.refresh has actually completed.
    await device.evaluate(() => {
      const rows = document.querySelector(".settings .rows")!
      rows.removeAttribute("data-refreshed")
      const observer = new MutationObserver(() => {
        observer.disconnect()
        rows.setAttribute("data-refreshed", "true")
      })
      observer.observe(rows, { childList: true })
    })
    const current = (await request(device, { type: "device-status" })).status
    await worker.evaluate((status) => chrome.runtime.sendMessage({ type: "db:status", status, change: "items" }), current)
    await device.locator('.settings .rows[data-refreshed="true"]').waitFor()
    check(await confirmation.count() === 1, "a vault refresh preserves the passkey deletion confirmation")
    check(await confirmation.getByLabel("Passphrase", { exact: true }).inputValue() === "wrong fixture passphrase", "a vault refresh preserves the entered deletion passphrase")
    await confirmation.getByRole("button", { name: "Delete", exact: true }).click()
    await confirmation.getByText("That passphrase isn't right.", { exact: true }).waitFor().catch(async (error) => {
      console.error("Settings deletion confirmation:", await confirmation.allTextContents())
      console.error("Settings deletion controls:", await confirmation.locator("button").allTextContents())
      throw error
    })
    check((await devicePasskeys(device)).some((k) => k.credentialId === kit.id), "Settings keeps the passkey after a wrong Strict passphrase")
    await confirmation.getByLabel("Passphrase", { exact: true }).fill(passphrase)
    await confirmation.getByRole("button", { name: "Delete", exact: true }).click()
    await until("Settings deletes the passkey", async () => !(await devicePasskeys(device)).some((k) => k.credentialId === kit.id))
    await request(device, { type: "device-preset", preset: "comfortable" })
    await settings.click()
    const left = (await devicePasskeys(device)).map((k) => k.credentialId)
    check(!left.includes(kit.id) && left.includes(strictMade.id) && (!cliCredential || left.includes(cliCredential.id)), "device-delete removes the passkey, and only it")
    const auth = await generateAuthenticationOptions({ rpID: "localhost" })
    await page.bringToFront()
    await startCall(page, "after-delete", "get", auth)
    const after = await passkeyPopup("a sign-in after the deletion asks which passkey")
    check(!after.accounts.includes("kit@acme.test") && after.accounts.includes("strict@acme.test"), `the deleted passkey isn't offered (${after.accounts.join(", ")})`)
    await after.press("Cancel")
    const cancelled = await outcome(page, "after-delete", "cancelled sign-in settles")
    check(!cancelled.ok && String(cancelled.value).startsWith("NotAllowedError"), `Cancel rejects with NotAllowedError (${cancelled.value})`)
    if (host) {
      await until("the deletion reaches the CLI", async () => {
        const ids = (await cliPasskeys(host)).map((k) => k.credentialId)
        return !ids.includes(kit.id) && ids.includes(cliCredential!.id) && ids.includes(strictMade.id)
      }, 90_000)
      check(true, "the deletion syncs to the CLI")
    }
  } finally {
    await request(device, { type: "device-preset", preset: "comfortable" }).catch(() => {})
    host?.close()
    await page.close()
  }
}

async function addLogin(device: Page, title: string, username: string, password: string, website = origin) {
  await device.getByRole("button", { name: "Add an item", exact: true }).click()
  await device.getByRole("button", { name: "Login", exact: true }).click()
  await device.getByLabel("Website", { exact: true }).fill(website)
  await device.getByLabel("Title", { exact: true }).fill(title)
  await device.getByLabel("Username", { exact: true }).fill(username)
  await device.getByLabel("Password", { exact: true }).fill(password)
  await device.getByRole("button", { name: "Save", exact: true }).click()
  // Saved, it shows the new login; back to the list.
  await device.getByRole("button", { name: "Edit", exact: true }).waitFor()
  await device.getByRole("button", { name: "Back", exact: true }).click()
}
/**
 * Other item types on the device page: a secure note and an API credential
 * added, shown (secrets only when asked), found by search (never by a
 * secret), edited without touching the secret, and deleted; and a login
 * given a one-time password, whose current code then shows.
 */
async function itemTypes(device: Page) {
  const add = async (kind: string) => {
    await device.getByRole("button", { name: "Add an item", exact: true }).click()
    await device.getByRole("button", { name: kind, exact: true }).click()
  }
  const save = async () => {
    await device.getByRole("button", { name: "Save", exact: true }).click()
    await device.locator(".detail .detail-head .title").waitFor()
  }
  const title = () => device.locator(".detail .detail-head .title").textContent()
  const back = () => device.getByRole("button", { name: "Back", exact: true }).click()
  await add("Secure note")
  await device.getByLabel("Name", { exact: true }).fill("Home router")
  await device.getByLabel("Notes", { exact: true }).fill("admin / synthetic-router-secret\nsecond line")
  await save()
  check(await title() === "Home router", "the page adds a secure note")
  check(!(await device.locator(".detail").textContent())?.includes("synthetic-router-secret"), "a note's body stays hidden until asked")
  await device.getByRole("button", { name: "Show Notes", exact: true }).click()
  await device.locator(".detail .secret", { hasText: "synthetic-router-secret" }).waitFor()
  check(true, "and shows it when asked")
  await back()
  await add("API credential")
  await device.getByLabel("Name", { exact: true }).fill("Stripe test key")
  await device.getByLabel("Credential", { exact: true }).fill("sk_test_synthetic_4242")
  await device.getByLabel("Username", { exact: true }).fill("acct_synthetic")
  await device.getByLabel("Environment", { exact: true }).fill("test")
  await save()
  check(await title() === "Stripe test key", "the page adds an API credential")
  await device.getByRole("button", { name: "Edit", exact: true }).click()
  await device.getByLabel("Environment", { exact: true }).fill("staging")
  await save()
  await device.locator(".detail .value", { hasText: "staging" }).waitFor()
  await device.getByRole("button", { name: "Show Credential", exact: true }).click()
  await device.locator(".detail .secret", { hasText: "sk_test_synthetic_4242" }).waitFor()
  check(true, "editing a plain field keeps the credential it didn't show")
  await back()
  const search = device.getByRole("searchbox", { name: "Search the vault" })
  await search.fill("acct_synthetic")
  await device.locator(".list-view .vrow .title", { hasText: "Stripe test key" }).waitFor()
  await search.fill("sk_test_synthetic")
  await device.locator(".list-view .empty").waitFor()
  check(true, "search finds an API credential by its username, never by its secret")
  await search.fill("")
  await device.locator(".list-view .vrow .title", { hasText: "Home router" }).click()
  await device.getByRole("button", { name: "Delete Home router", exact: true }).click()
  await device.getByRole("button", { name: "Delete Home router", exact: true }).click()
  await device.getByRole("searchbox", { name: "Search the vault" }).waitFor()
  await until("the deleted note leaves the list", async () => !(await device.locator(".list-view .vrow .title", { hasText: "Home router" }).count()))
  check(true, "a deleted item leaves the list")
  await device.locator(".list-view .vrow .title", { hasText: "From browser" }).first().click()
  await device.getByRole("button", { name: "Edit", exact: true }).click()
  await device.getByLabel("One-time password", { exact: true }).fill("JBSWY3DPEHPK3PXP")
  await device.getByRole("button", { name: "Save", exact: true }).click()
  const code = await until("the login's one-time code shows", async () => (await device.locator(".detail .code-value").textContent().catch(() => null))?.replace(/\s/g, ""))
  check(/^\d{6}$/.test(code), "a login given a one-time password shows its current code")
  await back()
}
async function unlockOnPage(device: Page) {
  await device.reload()
  await device.getByLabel("Passphrase", { exact: true }).fill(passphrase)
  await device.getByRole("button", { name: "Unlock", exact: true }).click()
  await until("device page unlocks", async () => await state(device) === "ready", 60_000)
}
/** The CLI agent's pid, from `deadbolt agent status`. */
async function agentPid() {
  const pid = Number(/running pid (\d+)/.exec(await cli("agent", "status"))?.[1])
  if (!(pid > 0)) throw new Error("the CLI agent isn't running")
  return pid
}
/** Reads `deadbolt join`'s code, pairs the extension with it, and waits for the join to finish. */
async function pair(device: Page) {
  joining = Bun.spawn([deadbolt, "join", "--device-name", "proof-cli"], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const reader = (joining.stdout as ReadableStream<Uint8Array>).getReader()
  let output = ""
  const code = await Promise.race([
    (async () => {
      for (;;) {
        const part = await reader.read()
        if (part.done) throw new Error("CLI join ended before a code")
        output += new TextDecoder().decode(part.value)
        const match = /Code: ([a-z]+(?:-[a-z]+){3})/.exec(output)
        if (match) return match[1]
      }
    })(),
    Bun.sleep(45_000).then(() => { throw new Error("CLI join did not publish a code") }),
  ])
  // Keep draining so the child can finish after the code is consumed.
  const drained = (async () => { while (!(await reader.read()).done) {} })()
  const joinError = new Response(joining.stderr as ReadableStream<Uint8Array>).text()
  await request(device, { type: "device-pair", code })
  const joined = await joining.exited
  await joinError // Drain diagnostics without logging the one-time pairing code.
  check(joined === 0, "CLI joins the browser vault")
  await drained
}

/** The first-run direction: the browser shows a code; an existing CLI admits it. */
async function joinExistingVault(device: Page, worker: Worker) {
  await cli("init", "existing-demo", "--device-name", "existing-cli")
  const fixtures = [
    ["Acme", origin], ["Code Forge", "https://code.example.test"],
    ["Demo Mail", "https://mail.example.test"], ["Team Docs", "https://docs.example.test"],
    ["Status Board", "https://status.example.test"],
  ]
  for (const [title, url] of fixtures) {
    await cli("new", "login", "--name", title, `url=${url}`, "username=cli@example.test", `password=${cliPassword}`,
      ...(title === "Acme" ? ["otp=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"] : []))
  }
  // Not logins: the forms flows fill them, and the counts leave them out.
  await cli(...IDENTITY)
  await cli(...CARD)
  const pairChoice = device.getByRole("button", { name: /^Pair with (?:an existing device|Deadbolt on this (?:Mac|computer))$/ })
  const begin = async () => {
    await pairChoice.click()
    return until("extension publishes its join code", async () => {
      const r = (await request(device, { type: "device-join-status" })).reply
      return r.phase === "waiting" && typeof r.code === "string" ? r.code : null
    }, 60_000)
  }
  const abandoned = await begin()
  await device.getByRole("button", { name: "Cancel", exact: true }).click()
  await pairChoice.waitFor()
  check((await request(device, { type: "device-join-status" })).reply.phase === "idle", "cancel discards the pending join")
  check(await state(device) === "not-set-up", "cancel does not create a browser vault")

  const code = await begin()
  check(/^[a-z]+(?:-[a-z]+){3}$/.test(code) && code !== abandoned, "retry generates a new four-word code")
  await device.reload()
  await device.getByText(code, { exact: true }).first().waitFor()
  check((await request(device, { type: "device-join-status" })).reply.code === code, "waiting join survives device-page reload")
  // Never print the code or CLI argv to the test log.
  await cli("pair", code)
  await until("browser receives the existing vault", async () => (await request(device, { type: "device-join-status" })).reply.phase === "admitted", 60_000)
  check(await state(device) === "not-set-up", "admission alone does not publish an unencrypted local store")
  await device.getByLabel("Passphrase", { exact: true }).fill(passphrase)
  await device.getByLabel("Passphrase again", { exact: true }).fill(passphrase)
  await device.getByRole("button", { name: "Finish", exact: true }).click()
  await shown(device, "Acme", 60_000)
  check((await logins(device)).length === fixtures.length, "all existing CLI logins appear after browser join")
  const devices = (await request(device, { type: "device-devices" })).reply.devices as VaultDevice[]
  check(devices.length === 2 && devices.filter(d => d.current).length === 1 && devices.some(d => d.name === "existing-cli"), "joined vault lists both named devices")
  await quick(worker, "Acme", cliPassword, "after joining the existing CLI vault")
  await autofill("Acme", "cli@example.test", cliPassword)
  await until("joined TOTP matches the CLI", async () => {
    const listed = await vault(worker, { type: "list", origin })
    const account = (listed.reply.accounts as Array<{ ref: string; title: string; hasTotp: boolean }>).find(a => a.title === "Acme")!
    if (!account.hasTotp) return false
    const expected = await cli("code", "Acme")
    return (await vault(worker, { type: "fill", origin, ref: account.ref, want: ["totp"] })).reply.totp === expected
  })
  check(true, "joined OTP field fills the same current code as the CLI")
  check(!(await command(device, { type: "device-join-start" })).ok, "joining cannot replace an initialized browser vault")
  return fixtures.length
}

async function unlockLifetime(device: Page, worker: Worker) {
  for (const preset of ["comfortable", "relaxed", "strict"] as const) {
    await request(device, { type: "device-preset", preset })
    await worker.evaluate(() => chrome.offscreen.closeDocument())
    check(await state(device) === "locked", `${preset}: offscreen loss locks the vault`)
    await request(device, { type: "device-unlock", passphrase })
  }
  await request(device, { type: "device-preset", preset: "comfortable" })
  await request(device, { type: "device-lock" })
  await worker.evaluate(() => chrome.offscreen.closeDocument())
  check(await state(device) === "locked", "offscreen restart after explicit lock cannot restore")
  await request(device, { type: "device-unlock", passphrase })
}

async function inlineUnlock(device: Page, previous: Worker) {
  await request(device, { type: "device-lock" })
  const page = await newPage("inline-unlock")
  await page.goto(origin)
  const locked = await menuOn(page, "#username", "Unlock Deadbolt")
  const opened = context!.waitForEvent("page")
  await locked.getByRole("button", { name: /Unlock Deadbolt/ }).click()
  const surface = await opened
  await surface.waitForURL(`chrome-extension://${ID}/device.html#unlock`)
  const denied = await surface.evaluate(async (url) => {
    // No tabs permission: identify the fixture using the webNavigation API
    // the real background already uses, not tabs.query's sensitive URL filter.
    for (const tab of await chrome.tabs.query({})) {
      if (tab.id === undefined) continue
      const frames = await chrome.webNavigation.getAllFrames({ tabId: tab.id })
      if (!frames?.some(f => f.frameId === 0 && f.url === `${url}/`)) continue
      return Promise.all(["db:unlock-wait", "db:unlock-return"].map(type => chrome.tabs.sendMessage(tab.id!, { type }, { frameId: 0 })))
    }
    throw new Error("Missing inline fixture tab")
  }, origin)
  check(denied.every(answer => answer === false), "extension pages cannot forge inline unlock wait/return messages")
  // Lose the service worker's in-memory tab id, then ask from the locked row
  // again. getContexts must recover that exact surface, including its hash.
  const cdp = await context!.newCDPSession(surface)
  let version: string | undefined
  let stopped = false
  cdp.on("ServiceWorker.workerVersionUpdated", ({ versions }) => {
    for (const v of versions) if (v.scriptURL === `chrome-extension://${ID}/background.js`) {
      if (v.runningStatus === "running") version = v.versionId
      if (v.runningStatus === "stopped") stopped = true
    }
  })
  await cdp.send("ServiceWorker.enable")
  const versionId = await until("running extension service worker", async () => version)
  check(await previous.evaluate(() => (globalThis as unknown as { nativeCalls: number }).nativeCalls) === 0, "no native messaging before service-worker restart")
  await cdp.send("ServiceWorker.stopWorker", { versionId })
  await until("extension service worker stopped", async () => stopped)
  await state(surface)
  const worker = context!.serviceWorkers()[0] ?? await context!.waitForEvent("serviceworker")
  await worker.evaluate(() => {
    const global = globalThis as unknown as { nativeCalls: number }
    global.nativeCalls = 0
    chrome.runtime.connectNative = () => { global.nativeCalls++; throw new Error("Native host forbidden by standalone proof") }
  })
  await cdp.detach()
  // A new locked-row click must reuse the first surface, not orphan it.
  // A menu token minted by the old worker is intentionally invalid now;
  // reload the fixture so this click comes from a freshly reported document.
  await page.reload()
  await page.bringToFront()
  const again = await menuOn(page, "#username", "Unlock Deadbolt")
  await again.getByRole("button", { name: /Unlock Deadbolt/ }).click()
  // Don't focus the surface until the clickjacking gate has confirmed the
  // pick. Playwright emulates document.hasFocus() even in background tabs.
  await until("second unlock click is accepted", async () => !menuFrame(page))
  await until("second unlock click reuses its surface", async () => surface.evaluate(async () => (await chrome.tabs.getCurrent())?.active))
  check(context!.pages().filter(p => p.url() === `chrome-extension://${ID}/device.html#unlock`).length === 1, "second unlock click after a service-worker restart creates no extra tab")
  await surface.getByLabel("Passphrase", { exact: true }).fill(passphrase)
  await surface.getByLabel("Passphrase", { exact: true }).press("Enter")
  await until("inline unlock closes its own surface", async () => surface.isClosed())
  await until("inline unlock reopens the menu", async () => {
    const frame = menuFrame(page)
    return frame && await frame.locator("button.row").count() > 0 && !(await frame.getByText("Unlock Deadbolt", { exact: true }).count())
  })
  check(await page.inputValue("#password") === "", "inline unlock returns to the page and reopens the menu without filling")
  await page.close()
  return worker
}

async function biometricUnlock(device: Page, worker: Worker) {
  const cdp = await context!.newCDPSession(device)
  await cdp.send("WebAuthn.enable")
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
  } })
  await device.bringToFront()
  await device.getByRole("button", { name: "Settings", exact: true }).click()
  await device.getByRole("button", { name: "Set up Touch ID", exact: true }).click()
  await device.getByLabel("Passphrase for Touch ID").fill("wrong enrollment passphrase")
  await device.getByRole("button", { name: "Enable Touch ID", exact: true }).click()
  await device.getByText("That passphrase isn't right.", { exact: true }).waitFor()
  check((await cdp.send("WebAuthn.getCredentials", { authenticatorId })).credentials.length === 0, "wrong enrollment passphrase creates no provider passkey")
  await device.getByLabel("Passphrase for Touch ID").fill(passphrase)
  await device.getByRole("button", { name: "Enable Touch ID", exact: true }).click()
  await device.getByRole("button", { name: "Reset Touch ID", exact: true }).waitFor({ timeout: 60_000 })
  check(true, "extension-origin platform passkey enrolls with real WebAuthn PRF")
  await request(device, { type: "device-preset", preset: "strict" })
  await request(device, { type: "device-lock" })
  // Exercise the UI's explicit UV check even if a provider/browser violates
  // required UV: retain real PRF output but clear UV on the returned assertion.
  await device.evaluate(() => {
    const original = navigator.credentials.get.bind(navigator.credentials)
    navigator.credentials.get = async (options) => {
      navigator.credentials.get = original
      const credential = await original(options) as PublicKeyCredential
      const response = credential.response as AuthenticatorAssertionResponse
      const data = response.authenticatorData.slice(0)
      new Uint8Array(data)[32]! &= ~0x04
      return { rawId: credential.rawId, response: { authenticatorData: data }, getClientExtensionResults: () => credential.getClientExtensionResults() } as unknown as PublicKeyCredential
    }
  })
  await device.getByRole("button", { name: "Unlock with Touch ID", exact: true }).click()
  await device.getByText("The authenticator didn't verify you. Use your passphrase instead.", { exact: true }).waitFor()
  check(await state(device) === "locked", "PRF output without the UV flag cannot unlock")
  await device.getByRole("button", { name: "Unlock with Touch ID", exact: true }).click()
  await until("PRF unlock", async () => await state(device) === "ready")
  check(true, "Touch ID unlock unwraps the second slot without a passphrase")
  const list = await vault(worker, { type: "device-items" })
  const ref = (list.reply.items as Array<{ref: string; kind: string}>).find(item => item.kind === "login")!.ref
  check(!(await command(device, { type: "device-secret", ref })).ok, "Strict reveal still requires a fresh proof")
  const info = await request(device, { type: "device-biometric-info" })
  const prf = await device.evaluate(async (metadata) => {
    const t = JSON.parse(metadata as string)
    const bytes = (s: string) => Uint8Array.from(s.match(/../g)!, b => parseInt(b, 16))
    const credential = await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), userVerification: "required",
      allowCredentials: [{ type: "public-key", id: bytes(t.id), transports: ["internal"] }],
      extensions: { prf: { eval: { first: bytes(t.salt) } } } as AuthenticationExtensionsClientInputs,
    } }) as PublicKeyCredential
    const result = credential.getClientExtensionResults() as unknown as {prf: {results: {first: ArrayBuffer}}}
    return Array.from(new Uint8Array(result.prf.results.first), b => b.toString(16).padStart(2, "0")).join("")
  }, info.reply.token)
  check((await command(device, { type: "device-secret", ref, prf })).ok, "Strict reveal accepts the authenticator's PRF output")
  // Unlock PRF is not website-passkey consent: both deletion routes and
  // ceremony authorization must still require the explicit Strict passphrase.
  const passkeys = await devicePasskeys(device)
  const passkey = passkeys.find((k) => k.rpId === "localhost")!
  const listed = await vault(worker, { type: "passkey-list", origin, rpId: "localhost" })
  check(listed.reply.canVerify === false && listed.reply.asksPassphrase === true, "PRF unlock does not advertise website UV or weaken Strict passkey policy")
  for (const type of ["device-delete", "device-item-delete"]) {
    const denied = await vault(worker, { type, ref: passkey.ref, prf })
    check(denied.reply.type === "error" && denied.reply.code === "passphrase_needed", "valid unlock PRF cannot bypass Strict passkey deletion")
  }
  const ceremony = {
    type: "passkey-get", origin, rpId: "localhost", ref: passkey.ref,
    challenge: Buffer.from("strict-prf-separation").toString("base64url"), userVerification: "preferred",
  }
  const assertion = await vault(worker, { ...ceremony, prf })
  check(assertion.reply.type === "error" && assertion.reply.code === "passphrase_needed", "valid unlock PRF cannot bypass Strict website-passkey signing")
  const denied = await vault(worker, { type: "passkey-authorize", prf, ceremony })
  check(denied.reply.type === "error" && denied.reply.code === "passphrase_needed", "valid unlock PRF cannot authorize a Strict website-passkey ceremony")
  check((await devicePasskeys(device)).length === passkeys.length, "PRF refusal preserves every website passkey")
  check(!(await command(device, { type: "device-secret", ref, prf: "00".repeat(32) })).ok, "Strict reveal rejects a fake PRF output")
  if (!smoke) {
    const forms = await vault(worker, { type: "forms", origin, kinds: ["card"] })
    const card = (forms.reply.cards as Array<{ref: string}>)[0]!
    const fill = { type: "fill-form", origin, ref: card.ref, fields: ["number", "cvv"] }
    check((await vault(worker, { ...fill, prf: "00".repeat(32) })).reply.type === "error", "Strict card fill rejects a fake PRF output")
    check((await vault(worker, { ...fill, prf })).reply.type === "fill-form", "Strict card fill accepts the authenticator's PRF output")
  }
  await cdp.send("WebAuthn.clearCredentials", { authenticatorId })
  await request(device, { type: "device-lock" })
  await device.getByRole("button", { name: "Unlock with Touch ID", exact: true }).click()
  await device.getByText(/Touch ID was cancelled, unavailable, or its passkey was removed/).waitFor({ timeout: 70_000 })
  check(await state(device) === "locked", "a deleted authenticator passkey cannot unlock and explains passphrase fallback")
  check(await device.evaluate(async () => (await chrome.storage.local.get("deadbolt.unlockMethod"))["deadbolt.unlockMethod"]) === "passphrase", "unavailable passkey resets the preferred unlock method")
  await request(device, { type: "device-unlock", passphrase })
  await request(device, { type: "device-biometric-reset" })
  check(!(await command(device, { type: "device-secret", ref, prf })).ok, "Reset Touch ID invalidates the old PRF slot")
  await request(device, { type: "device-lock" })
  await request(device, { type: "device-unlock", passphrase })
  await request(device, { type: "device-preset", preset: "comfortable" })
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId })
  const unsupported = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: false,
  } })
  await device.getByRole("button", { name: "Settings", exact: true }).click()
  await device.getByRole("button", { name: "Set up Touch ID", exact: true }).click()
  await device.getByLabel("Passphrase for Touch ID").fill(passphrase)
  await device.getByRole("button", { name: "Enable Touch ID", exact: true }).click()
  await device.getByText(/This authenticator doesn't support PRF unlock/).waitFor()
  check((await request(device, { type: "device-biometric-info" })).reply.token === null, "unsupported PRF is explained and saves no unlock slot")
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: unsupported.authenticatorId })
  await cdp.detach()
}

/** Settings' About: the version, no update check for a build from source, and an issue with no vault data. */
async function about(device: Page) {
  await device.getByRole("button", { name: "Settings", exact: true }).click()
  const version = await device.evaluate(() => chrome.runtime.getManifest().version)
  check((await device.locator("#about-version").innerText()) === version, "settings show this build's version")
  await device.getByText("Built from source: it doesn't check for updates.").waitFor()
  check(true, "a build from source doesn't ask the release service")
  // GitHub is beyond the smoke's reach: answer for it, to read the URL the tab opened.
  await context!.route("https://github.com/**", (route) => route.fulfill({ body: "issue", contentType: "text/plain" }))
  const opened = context!.waitForEvent("page")
  await device.getByRole("button", { name: "Report an issue", exact: true }).click()
  const issue = await opened
  await issue.waitForURL(/^https:\/\/github\.com\//)
  const url = new URL(issue.url())
  await issue.close()
  const body = url.searchParams.get("body") ?? ""
  check(url.origin + url.pathname === "https://github.com/anomalyco/deadbolt/issues/new" && url.searchParams.get("labels") === "standalone", "Report an issue opens a standalone issue on anomalyco/deadbolt")
  check(body.includes(`Deadbolt standalone extension ${version}`) && /Browser: .+/.test(body) && /OS: linux/.test(body), "the issue carries the version, browser and OS")
  check(![browserPassword, passphrase, "browser@example.test", "From browser"].some((secret) => url.href.includes(encodeURIComponent(secret)) || url.href.includes(secret)), "the issue carries no vault data")
  await device.getByRole("button", { name: "Back", exact: true }).click()
}

try {
  if (!arg("--dist")) {
    const build = Bun.spawnSync(["bun", "scripts/build.ts", "--e2e", dist, "--standalone"], { cwd: join(import.meta.dir, ".."), stdout: "inherit", stderr: "inherit" })
    check(build.success, "standalone build succeeds")
  }
  // The smoke's copy is one the CLI keeps (`deadbolt update` leaves this
  // marker), so first run offers Deadbolt on this computer by name.
  if (smoke) {
    cliMarker = await readFile(join(dist, ".deadbolt-extension")).catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return null
      throw error
    })
    await writeFile(join(dist, ".deadbolt-extension"), "manifest.json\n")
  }
  let { worker, device } = await launch()
  check((await readdir(join(profile, "NativeMessagingHosts")).catch(() => [])).filter((name) => name.endsWith(".json")).length === 0, "profile has no native host manifest")
  if (smoke) {
    const offline = await device.evaluate(() => fetch("https://example.com/", { mode: "no-cors" }).then(() => false, () => true))
    check(offline, "Chromium can't reach the network beyond loopback")
    await device.getByRole("button", { name: "Pair with Deadbolt on this computer", exact: true }).click()
    await device.getByRole("heading", { name: "Pairing didn't work", exact: true }).waitFor({ timeout: 60_000 })
    check(/sync service/i.test(await device.locator(".notice .error").innerText()), "offline joining says Deadbolt's sync service can't be reached")
    await device.getByRole("button", { name: "Cancel", exact: true }).click()
  }
  let count = 1
  if (joinExisting) {
    count = await joinExistingVault(device, worker)
  } else {
  await device.getByRole("button", { name: "Create a new vault", exact: true }).click()
  await device.getByLabel("Passphrase", { exact: true }).fill(passphrase)
  await device.getByLabel("Passphrase again", { exact: true }).fill(passphrase)
  await device.getByRole("button", { name: "Create vault", exact: true }).click()
  await device.getByRole("searchbox", { name: "Search the vault" }).waitFor({ timeout: 60_000 })
  check(await state(device) === "ready", "extension creates and opens its own vault")
  await addLogin(device, "From browser", "browser@example.test", browserPassword)
  await shown(device, "From browser")
  check(true, "device page lists the saved login without being asked")
  check((await logins(device)).length === 1, "extension writes a login")
  await itemTypes(device)

  if (smoke) {
    await quick(worker, "From browser", browserPassword, "with no peers")
    await siteIcon(device)
    await autofill("From browser", "browser@example.test", browserPassword)
    await about(device)
  } else {
    await pair(device)
    check(await cli("get", "From browser") === browserPassword, "browser-created login arrives on CLI through pairing")
    const devices = (await request(device, { type: "device-devices" })).reply.devices as VaultDevice[]
    check(devices.length === 2 && devices.filter((d) => d.current).length === 1, "extension lists itself and the CLI as the vault's devices")

    // Browser to CLI: the extension answers the CLI's sync in the background.
    await addLogin(device, "After pairing", "after@example.test", browserPassword)
    await shown(device, "After pairing")
    await until("post-pair browser write reaches CLI", async () => {
      await cli("sync").catch(() => {})
      return await cli("get", "After pairing") === browserPassword
    }, 90_000)
    check(true, "post-pair browser write syncs to CLI")

    // CLI to browser: written while the extension is locked, fetched by the
    // sync that unlocking starts, and shown without a click.
    await request(device, { type: "device-lock" })
    check(await state(device) === "locked", "lock closes the vault")
    await cli("new", "login", "--name", "From CLI", `url=${origin}`, "username=cli@example.test", `password=${cliPassword}`, "otp=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    await cli(...IDENTITY)
    await cli(...CARD)
    await unlockOnPage(device)
    await shown(device, "From CLI", 90_000)
    check(true, "CLI login written while the extension was locked appears after unlock, by background sync")
    await autofill("From CLI", "cli@example.test", cliPassword)
    await until("synced OTP field fills the current code", async () => {
      const listed = await vault(worker, { type: "list", origin })
      const account = (listed.reply.accounts as Array<{ ref: string; title: string; hasTotp: boolean }>).find(a => a.title === "From CLI")!
      check(account.hasTotp, "synced OTP field is reflected in hasTotp")
      const code = await cli("code", "From CLI")
      return (await vault(worker, { type: "fill", origin, ref: account.ref, want: ["totp"] })).reply.totp === code
    })
    check(true, "Rust core generates the same current TOTP as the CLI")
    count = 3

    // A peer that stops answering mid-connection (a sleeping laptop): the
    // sync alarm's background sync waits on it, and the vault still answers.
    suspended = await agentPid()
    process.kill(suspended, "SIGSTOP")
    await worker.evaluate((name) => chrome.alarms.create(name, { when: Date.now() + 50, periodInMinutes: 5 }), SYNC_ALARM)
    await until("sync alarm fires", () => worker.evaluate(async (name) => ((await chrome.alarms.get(name))?.scheduledTime ?? 0) > Date.now() + 60_000, SYNC_ALARM), 10_000)
    await Bun.sleep(500) // The background sync is now dialing the suspended CLI.
    await quick(worker, "From CLI", cliPassword, "while a background sync waits on a suspended CLI")
    const menuStarted = Date.now()
    await autofill("From CLI", "cli@example.test", cliPassword)
    console.log(`MEASURE inline menu pick and fill during background sync: ${Date.now() - menuStarted} ms (includes the 1 s menu settle)`)
    process.kill(suspended, "SIGCONT")
    suspended = undefined
  }
  }

  count += await siteFlows(device, worker)
  await passkeyFlows(device, worker)
  if (!smoke) {
    count += await demoFlows(device, worker)
    await formFlows(device, worker, `${origin}/checkout`)
    await formFlows(device, worker, `${DEMO}/checkout`)
  }

  const keptPasskeys = (await devicePasskeys(device)).map((k) => k.credentialId).sort()
  await unlockLifetime(device, worker)
  worker = await inlineUnlock(device, worker)
  await biometricUnlock(device, worker)
  await request(device, { type: "device-lock" })
  check(await state(device) === "locked", "lock closes the vault")
  // Worker termination releases the exclusive OPFS handle asynchronously.
  const encrypted = await until("OPFS handle released after lock", () => device.evaluate(async (markers) => {
    const directory = await navigator.storage.getDirectory()
    const handle = await directory.getFileHandle("vault.redb")
    const bytes = await (await handle.getFile()).arrayBuffer()
    const text = new TextDecoder().decode(bytes)
    return bytes.byteLength > 0 && markers.every((marker) => !text.includes(marker))
  }, [browserPassword, cliPassword, "browser@example.test", "From CLI", "From browser", "saved@acme.test", "Acme accounts", "4242424242424242", "strict@acme.test"]))
  check(encrypted, "OPFS contains no plaintext credential or item-label markers")
  check(!(await command(device, { type: "device-items" })).ok, "locked vault refuses item listing")
  check(!(await command(device, { type: "device-passkeys" })).ok, "locked vault refuses passkey listing")
  check(!(await command(device, { type: "device-unlock", passphrase: "wrong fixture passphrase" })).ok, "wrong passphrase is rejected")
  const unlocked = await request(device, { type: "device-unlock", passphrase })
  console.log(`MEASURE wasm unlock real Argon2id (64 MiB, 3 passes, 1 lane), RPC wall time: ${unlocked.ms.toFixed(1)} ms`)
  await until("unlock restores persisted signed log", async () => (await logins(device)).length === count, 60_000)
  check(true, "unlock restores persisted signed log")
  // No read or delay between lock and unlock: the old worker may still be
  // releasing its exclusive OPFS handle when the new one opens it.
  await request(device, { type: "device-lock" })
  await request(device, { type: "device-unlock", passphrase })
  check((await logins(device)).length === count, "immediate lock/unlock reopens the exclusive OPFS handle")
  check(await worker.evaluate(() => (globalThis as unknown as { nativeCalls: number }).nativeCalls) === 0, "no native messaging connection attempted")

  await context!.close()
  context = undefined
  const restarted = await launch()
  check(await state(restarted.device) === "locked", "browser restart starts locked")
  await request(restarted.device, { type: "device-unlock", passphrase })
  await until("encrypted vault survives browser restart", async () => (await logins(restarted.device)).length === count, 60_000)
  check(true, "encrypted vault survives browser restart")
  check(JSON.stringify((await devicePasskeys(restarted.device)).map((k) => k.credentialId).sort()) === JSON.stringify(keptPasskeys), "passkeys and deletions survive browser restart")
  console.log(smoke
    ? "PASS: standalone smoke: create, save, list, actual fill, subdomain fill, save and update offers, generated sign-up and change, passkeys, lock/unlock and restart, offline"
    : joinExisting
      ? "PASS: standalone joins existing CLI vault, cancel/retry, five logins, TOTP, actual fill, site and demo save/update/generate, identity and card fills with Strict re-auth, passkeys synced both ways, lock/unlock and restart"
      : "PASS: standalone create, pair, background sync both ways, quick answers during sync, actual fill, site and demo save/update/generate, identity and card fills with Strict re-auth, passkeys synced both ways, lock/unlock and restart")
} finally {
  if (suspended) process.kill(suspended, "SIGCONT")
  joining?.kill()
  await context?.close()
  // An explicitly supplied build may be reused by full/join runs. Restore its
  // install provenance instead of leaking this smoke-only fixture into them.
  if (cliMarker !== undefined) {
    if (cliMarker === null) await rm(join(dist, ".deadbolt-extension"), { force: true })
    else await writeFile(join(dist, ".deadbolt-extension"), cliMarker)
  }
  if (!smoke) await cli("agent", "stop").catch(() => {})
  server.stop(true)
  if (video && recordings.length) {
    await mkdir(video, { recursive: true })
    for (const [i, r] of recordings.entries()) {
      const file = join(video, `${String(i + 1).padStart(2, "0")}-${r.name}.webm`)
      await copyFile(r.path, file).then(() => console.log(`video: ${file}`), (e) => console.error(`video ${r.name} not saved: ${(e as Error).message}`))
    }
  }
  await rm(root, { recursive: true, force: true })
}
