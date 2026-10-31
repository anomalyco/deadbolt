// Universal sign-in through a provider: one trusted pick on acme.test follows
// "Continue with Google" to a fake Google (accounts.google.test, mapped to this
// server) in the same tab or a popup. Headless, disposable browser vault,
// synthetic accounts only (e2e/universal-fixture.ts).
//
//   bun scripts/build.ts --e2e <dir> --standalone   (.test provider hosts need an e2e build)
//   bun e2e/universal-providers.ts --dist <dir> [--video <dir>] [--skip-ttl]
//   bun scripts/build.ts --e2e <dir> --native
//   bun e2e/universal-providers.ts --native --deadbolt <deadbolt binary> --dist <dir> [...]
//
// Standalone uses the extension's own wasm vault; --native runs that real
// deadbolt binary as the browser host over a throwaway store (fast KDF,
// local network only), as e2e/run.ts's passkey run does. Both seed a real
// passkey for the fake Google through the extension's own save prompt, and
// the fake Google checks every ceremony with @simplewebauthn/server.
// --skip-ttl leaves out the real two-minute lifetime wait. The browser's
// popup blocker stays on (Playwright's --disable-popup-blocking is dropped).
import { chromium, type CDPSession, type Frame, type Page } from "playwright-core"
import { mkdtemp, mkdir, copyFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { getDomain } from "tldts"
import { universalFixture, providerLog, googlePasskey, GOOGLE_USER, GOOGLE_PASSWORD, OTP } from "./universal-fixture"

const arg = (name: string) => { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1] }
const dist = resolve(arg("--dist") ?? "dist")
const video = arg("--video")
const skipTtl = process.argv.includes("--skip-ttl")
const native = process.argv.includes("--native")
// Absolute: Chromium reads a relative host path in the manifest as relative to the manifest.
const deadbolt = arg("--deadbolt") && resolve(arg("--deadbolt")!)
if (native && !deadbolt) throw new Error("--native needs --deadbolt <path to the deadbolt binary>")
const mode = native ? "native" : "standalone"
const root = await mkdtemp(join(tmpdir(), "deadbolt-universal-providers-"))
/** The real agent's throwaway store (see e2e/run.ts deadboltStore). Short: the socket path must fit a sockaddr. */
const store = native ? await mkdtemp(process.platform === "darwin" ? "/tmp/dbup-" : join(tmpdir(), "dbup-")) : ""
const storeEnv: Record<string, string> = native ? {
  DEADBOLT_HOME: join(store, "home"), XDG_RUNTIME_DIR: join(store, "run"), XDG_STATE_HOME: join(store, "state"), XDG_CONFIG_HOME: join(store, "config"),
  DEADBOLT_NET: "local", DEADBOLT_KDF: "fast", DEADBOLT_PASSPHRASE: "universal providers synthetic store",
} : {}
const cli = (...args: string[]) => {
  const r = Bun.spawnSync([deadbolt!, ...args], { env: { ...process.env, ...storeEnv }, stdin: "ignore" })
  if (r.exitCode !== 0) throw new Error(`deadbolt ${args[0]} failed: ${r.stderr}`)
  return String(r.stdout).trim()
}
if (native) {
  cli("init", "--device-name", "universal-providers")
  await mkdir(join(root, "profile", "NativeMessagingHosts"), { recursive: true })
  await writeFile(join(root, "profile", "NativeMessagingHosts", "pw.deadbolt.browser.json"), JSON.stringify({
    name: "pw.deadbolt.browser", description: "deadbolt", path: deadbolt, type: "stdio", allowed_origins: ["chrome-extension://jhocodkhpifjndffenppfmdkmiolngal/"],
  }))
}
// idleTimeout 0: the lifetime case holds one response open for two minutes.
const server = Bun.serve({ hostname: "127.0.0.1", port: 0, idleTimeout: 0, fetch: universalFixture })
const port = server.port
const site = `http://acme.test:${port}`
const googleOrigin = `http://accounts.google.test:${port}`
const ID = "jhocodkhpifjndffenppfmdkmiolngal"
const LOOKALIKES = ["accounts.google.evil.test", "accounts.googl.test"]
const context = await chromium.launchPersistentContext(join(root, "profile"), {
  channel: "chromium", headless: true, viewport: { width: 1440, height: 900 },
  args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, "--host-resolver-rules=MAP acme.test 127.0.0.1, MAP *.test 127.0.0.1",
    // Real sites and providers are https: give the http fixtures a secure context (crypto.randomUUID and the like).
    `--unsafely-treat-insecure-origin-as-secure=${["acme.test", "accounts.google.test", ...LOOKALIKES].map((h) => `http://${h}:${port}`).join(",")}`,
    // The toolbar popup (passkey save prompt) is an extension target Playwright doesn't list: reach it over DevTools.
    "--remote-debugging-port=0"],
  // A real browser blocks a popup no person opened: keep that on.
  ignoreDefaultArgs: ["--disable-popup-blocking"],
  env: { ...process.env, ...storeEnv },
  ...(video ? { recordVideo: { dir: join(root, "video"), size: { width: 1440, height: 900 } } } : {}),
})
context.setDefaultTimeout(15_000)
const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker")
const recordings: Array<{ page: Page; name: string; start: number; clicks: Array<{ seconds: number; x: number; y: number }> }> = []
const check = (ok: unknown, label: string) => { if (!ok) throw new Error(label); console.log(`PASS ${label}`) }
async function until<T>(label: string, f: () => Promise<T>, ms = 15_000): Promise<NonNullable<T>> {
  const end = Date.now() + ms
  while (Date.now() < end) { const result = await f().catch(() => null); if (result) return result as NonNullable<T>; await Bun.sleep(100) }
  throw new Error(`Timed out: ${label}`)
}
const hits = (flow: string, f: (h: (typeof providerLog)[number]) => boolean = () => true) => providerLog.filter((h) => h.flow === flow && f(h))
const google = (h: (typeof providerLog)[number]) => h.host === "accounts.google.test"
const posts = (flow: string, path: string) => hits(flow, (h) => h.method === "POST" && h.path === path).length

async function fresh() {
  // Test isolation only: offer cooldowns and fill sessions. The provider chain
  // itself is memory-only and ends with its tab.
  await worker.evaluate(async () => {
    const all = await chrome.storage.session.get(null)
    await chrome.storage.session.remove(Object.keys(all).filter((k) => k.startsWith("signin-memory:") || k.startsWith("session:")))
  })
}
function record(p: Page, name: string) {
  p.on("pageerror", (e) => console.log(`page error (${name}): ${e.message}`))
  recordings.push({ page: p, name, start: performance.now(), clicks: [] })
}
async function open(name: string, query: Record<string, string>) {
  const p = await context.newPage()
  record(p, name)
  await p.goto(`${site}/signin?${new URLSearchParams({ flow: name, ...query })}`)
  return p
}
async function offer(p: Page): Promise<Frame> {
  return until("corner sign-in offer", async () => {
    for (const f of p.frames()) if (f.url().includes("/menu.html") && await f.locator(".universal").count()) return f
    return null
  })
}
/** The one trusted pick: the offer's "Sign in with Google" row, after the real dwell. */
async function pick(p: Page) {
  const f = await offer(p)
  check(await p.evaluate(() => document.activeElement === document.body), "the offer does not move page focus")
  await p.waitForTimeout(1400)
  const row = f.locator("button.row", { hasText: "Google" }).first()
  const target = await row.boundingBox()
  const recording = recordings.find((r) => r.page === p)
  if (target && recording) recording.clicks.push({ seconds: (performance.now() - recording.start) / 1000, x: target.x + target.width / 2, y: target.y + target.height / 2 })
  await row.click()
  return Date.now()
}

// db:provider-status is drawn by the content script, possibly in a closed
// shadow root: read it through CDP's piercing DOM rather than by class name.
const LABEL = /Signing in with|^Signed in$|Review access|Approve on your phone|Enter your code|Use your security key|Complete the verification/
interface Sample { at: number; url: string; text: string; box?: { x: number; y: number; width: number; height: number } }
interface Watch { samples: Sample[]; focus: string[]; stop(): void }
type Node = { nodeType: number; nodeValue?: string; backendNodeId: number; children?: Node[]; shadowRoots?: Array<Node & { shadowRootType?: string }>; contentDocument?: Node }
async function labels(cdp: CDPSession) {
  const { root } = await cdp.send("DOM.getDocument", { depth: -1, pierce: true }) as { root: Node }
  const found: Array<{ text: string; parent: number }> = []
  const walk = (n: Node, shadow: boolean, parent: number) => {
    if (n.nodeType === 3 && shadow && LABEL.test((n.nodeValue ?? "").trim())) found.push({ text: n.nodeValue!.trim(), parent })
    for (const s of n.shadowRoots ?? []) walk(s, shadow || s.shadowRootType !== "user-agent", n.backendNodeId)
    for (const c of n.children ?? []) walk(c, shadow, n.backendNodeId)
    if (n.contentDocument) walk(n.contentDocument, shadow, n.backendNodeId)
  }
  walk(root, false, root.backendNodeId)
  return Promise.all(found.map(async ({ text, parent }) => {
    const model = await cdp.send("DOM.getBoxModel", { backendNodeId: parent }).catch(() => null) as { model: { border: number[]; width: number; height: number } } | null
    return { text, ...(model ? { box: { x: model.model.border[0], y: model.model.border[1], width: model.model.width, height: model.model.height } } : {}) }
  }))
}
const watches: Watch[] = []
async function watch(p: Page): Promise<Watch> {
  const cdp = await context.newCDPSession(p)
  const w: Watch = { samples: [], focus: [], stop: () => { stopped = true } }
  watches.push(w)
  let stopped = false
  void (async () => {
    while (!stopped && !p.isClosed()) {
      try {
        const url = p.url()
        for (const l of await labels(cdp)) w.samples.push({ at: Date.now(), url, ...l })
        // Extension-frame status (if the pill is a menu.html frame instead).
        for (const f of p.frames()) if (f.url().startsWith(`chrome-extension://${ID}/`) && !await f.locator(".universal").count()) {
          const text = (await f.locator("body").innerText({ timeout: 200 })).trim()
          const box = await (await f.frameElement()).boundingBox()
          if (text && LABEL.test(text) && box) w.samples.push({ at: Date.now(), url, text, box })
        }
        const focused = await p.evaluate(() => {
          const a = document.activeElement
          if (!a || a === document.body) return ""
          if (a instanceof HTMLIFrameElement && a.src.startsWith("chrome-extension:")) return "extension frame"
          return a.tagName.includes("-") || (a.shadowRoot === null && !a.matches("input,button,a,select,textarea,iframe,[role=link],[tabindex]")) ? a.tagName : ""
        })
        if (focused) w.focus.push(`${focused} on ${new URL(url).pathname}`)
      } catch {}
      await Bun.sleep(100)
    }
  })()
  return w
}
/** The status pill on pages whose path is `path`: seen, quiet in the corner, and gone ~1.5 s after its last label. */
async function settles(w: Watch, path: string, label: string, optional = false) {
  const at = (s: Sample) => { try { return new URL(s.url).pathname === path } catch { return false } }
  const shown = await until(`${label}: status pill shows`, async () => w.samples.some(at), 6000).catch((err) => { if (!optional) throw err; return false })
  if (!shown) {
    await Bun.sleep(1500)
    check(!w.samples.some(at), `${label}: no status pill is left on the page`)
    return []
  }
  const first = w.samples.find(at)!
  await Bun.sleep(4000)
  const on = w.samples.filter(at)
  const last = on[on.length - 1]
  const recent = on.filter((s) => s.at > Date.now() - 1000)
  const texts = [...new Set(on.map((s) => s.text))]
  console.log(`INFO ${label}: pill ${JSON.stringify(texts)} for ${last.at - first.at} ms`)
  check(first.box && first.box.x > 900 && first.box.y < 120 && first.box.height < 80, `${label}: the status pill is a compact top-right corner pill`)
  check(!recent.length && last.at - first.at <= 3000, `${label}: the status pill goes away by itself (~1.5 s)`)
  return texts
}
const quietOn = (w: Watch, host: string) => !w.samples.some((s) => { try { return new URL(s.url).hostname === host } catch { return false } })
const noFocus = (w: Watch, label: string) => check(!w.focus.length, `${label}: nothing of Deadbolt's takes focus (${JSON.stringify(w.focus)})`)

const device = await context.newPage()
async function command(command: Record<string, unknown>) {
  const reply = await device.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command)
  if (!reply?.ok) throw new Error(`${command.type}: ${reply?.message ?? "no reply"}`)
  return reply
}
const setting = (on: boolean) => worker.evaluate((on) => chrome.storage.local.set({ offerToSignIn: on }), on)

/**
 * Seed a learned authenticator Flow for google.test, as the outcome judge
 * would leave it (bg/autofill.ts flowKey: the install's salt and the site).
 * The chain only submits a provider code for a learned code step.
 */
async function learnGoogle() {
  const siteName = getDomain("accounts.google.test", { allowPrivateDomains: true })!
  await worker.evaluate(async (site) => {
    let salt = (await chrome.storage.local.get("signinFlowsSalt")).signinFlowsSalt as string | undefined
    if (!salt) { salt = crypto.randomUUID().replaceAll("-", ""); await chrome.storage.local.set({ signinFlowsSalt: salt }) }
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${salt}\n${site}`))
    const key = Array.from(new Uint8Array(digest).slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("")
    const flows = ((await chrome.storage.local.get("signinFlows")).signinFlows ?? {}) as Record<string, unknown>
    flows[key] = { identifierFirst: true, code: true, navigates: true, seen: 3, codeSeen: 3, at: Date.now() }
    await chrome.storage.local.set({ signinFlows: flows })
  }, siteName)
}

/** One request to the real host, on its own native port (the extension's protocol: hello, then the request). */
async function hostRequest(body: Record<string, unknown>) {
  return worker.evaluate((body) => new Promise<unknown>((resolve, reject) => {
    const port = chrome.runtime.connectNative("pw.deadbolt.browser")
    const timer = setTimeout(() => { port.disconnect(); reject(new Error("the host didn't answer")) }, 10_000)
    port.onMessage.addListener((m: { id?: number }) => {
      if (m.id === 1) port.postMessage({ ...body, id: 2 })
      if (m.id === 2) { clearTimeout(timer); port.disconnect(); resolve(m) }
    })
    port.onDisconnect.addListener(() => reject(new Error(chrome.runtime.lastError?.message ?? "the host went away")))
    port.postMessage({ type: "hello", id: 1 })
  }), body)
}

/** The browser's DevTools targets and a minimal connection to one (as e2e/standalone.ts drives its toolbar popup). */
async function targets() {
  const port = (await Bun.file(join(root, "profile", "DevToolsActivePort")).text()).split("\n")[0]
  return await (await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(5000) })).json() as Array<{ id: string; url: string; webSocketDebuggerUrl: string }>
}
async function devtools(url: string) {
  const ws = new WebSocket(url)
  const waiting = new Map<number, (r: { result?: Record<string, unknown>; error?: { message: string } }) => void>()
  ws.onmessage = (e) => { const m = JSON.parse(String(e.data)); if (m.id !== undefined) waiting.get(m.id)?.(m) }
  await new Promise((ok, fail) => { ws.onopen = ok; ws.onerror = fail; setTimeout(() => fail(new Error("DevTools connection timed out")), 5000) })
  ws.onclose = () => { for (const reply of waiting.values()) reply({ error: { message: "DevTools target closed" } }) }
  let id = 0
  const send = (method: string, params: Record<string, unknown> = {}) => new Promise<Record<string, unknown>>((ok, fail) => {
    const request = ++id
    const timer = setTimeout(() => { waiting.delete(request); fail(new Error(`${method}: timed out`)) }, 5000)
    waiting.set(request, (r) => { clearTimeout(timer); waiting.delete(request); if (r.error) fail(new Error(r.error.message)); else ok(r.result ?? {}) })
    ws.send(JSON.stringify({ id: request, method, params }))
  })
  const evaluate = async <T>(expression: string) => ((await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result as { value: T }).value
  return { send, evaluate, close: () => ws.close() }
}
/** The toolbar badge on the tab showing `prefix`. */
const badge = (prefix: string) => worker.evaluate(async (prefix) => {
  for (const t of await chrome.tabs.query({})) {
    const frame = t.id === undefined ? null : await chrome.webNavigation.getFrame({ tabId: t.id, frameId: 0 }).catch(() => null)
    if (frame?.url.startsWith(prefix)) return chrome.action.getBadgeText({ tabId: t.id })
  }
  return ""
}, prefix)
const CARD = `document.querySelector(".passkey-prompt")`
/**
 * The passkey prompt a page's ceremony raises, as a person sees it: the
 * toolbar popup Deadbolt opens (over DevTools, with a trusted click), or,
 * where it only badges the toolbar button, the popup page pointed at that
 * tab (as e2e/run.ts opens it).
 */
async function passkeyPrompt(prefix: string, ms = 20_000): Promise<{ heading: string; press(label: string): Promise<void> } | null> {
  return until("the passkey prompt", async () => {
    const target = (await targets()).find((t) => t.url.startsWith(`chrome-extension://${ID}/popup.html`))
    if (target) {
      const popup = await devtools(target.webSocketDebuggerUrl)
      const heading = await popup.evaluate<string | null>(`${CARD}?.querySelector("h2")?.textContent ?? null`).catch(() => null)
      if (heading === null) return popup.close(), null
      return { heading, async press(label: string) {
        const at = await popup.evaluate<{ x: number; y: number } | null>(`(() => { const b = [...(${CARD}?.querySelectorAll("button") ?? [])].find((b) => b.textContent.trim() === ${JSON.stringify(label)}); if (!b) return null; const r = b.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 } })()`)
        if (!at) throw new Error(`the passkey prompt has no ${label} button`)
        for (const type of ["mousePressed", "mouseReleased"]) await popup.send("Input.dispatchMouseEvent", { type, ...at, button: "left", clickCount: 1 })
        await Bun.sleep(500)
        popup.close()
      } }
    }
    if (!await badge(prefix)) return null
    const p = await context.newPage()
    await p.setViewportSize({ width: 360, height: 420 })
    await p.goto(`chrome-extension://${ID}/popup.html`)
    await p.evaluate(async (prefix) => {
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
    }, prefix)
    const card = p.locator(".passkey-prompt")
    if (!await card.waitFor({ timeout: 3000 }).then(() => true, () => false)) return p.close(), null
    return { heading: (await card.locator("h2").textContent()) ?? "", async press(label: string) {
      await card.locator("button", { hasText: label }).first().click()
      await p.close().catch(() => {})
    } }
  }, ms)
}
/** That no passkey prompt shows for `prefix` within `ms`: no badge, no popup. */
async function noPasskeyPrompt(prefix: string, ms: number) {
  const end = Date.now() + ms
  while (Date.now() < end) {
    if (await badge(prefix)) return false
    if ((await targets()).some((t) => t.url.startsWith(`chrome-extension://${ID}/popup.html`))) return false
    await Bun.sleep(200)
  }
  return true
}

try {
  if (native) {
    // The real agent's vault, filled as a person would with the CLI.
    cli("new", "login", "--name", "Google", `url=${googleOrigin}`, `username=${GOOGLE_USER}`, `password=${GOOGLE_PASSWORD}`, `otp=${OTP}`)
    const listed = JSON.stringify(await hostRequest({ type: "list", origin: googleOrigin }))
    const ref = listed.match(/"ref":"([^"]+)"/)?.[1]
    if (!ref) throw new Error(`the host lists no Google login: ${listed.slice(0, 200)}`)
    cli("new", "login", "--name", "Acme", `url=${site}`, "sign-in-with=google", `sign-in-account=${ref.split(":")[1]}`)
    // A Google-only login, as in the browser vault: `new login` generates a password, which would add a second row.
    cli("unset", "--field", "password", "Acme")
    await device.close()
  } else {
    await device.goto(`chrome-extension://${ID}/device.html`)
    await device.getByRole("button", { name: "Create a new vault", exact: true }).waitFor({ timeout: 60_000 })
    await command({ type: "device-create", passphrase: "universal providers synthetic browser vault", name: "universal-providers" })
    const login = async (name: string, fields: Array<{ name: string; value: string }>) => String((await command({ type: "device-item-save", kind: "login", name, fields })).reply.ref)
    const googleRef = await login("Google", [{ name: "url", value: googleOrigin }, { name: "username", value: GOOGLE_USER }, { name: "password", value: GOOGLE_PASSWORD }, { name: "otp", value: OTP }])
    await login("Acme", [{ name: "url", value: site }, { name: "sign-in-with", value: "google" }, { name: "sign-in-account", value: googleRef.split(":")[1] }])
  }
  check(true, `${mode}: the vault has a synthetic Google login and an Acme login that signs in with it`)

  // Off by default: no offer, and nothing on the provider either.
  {
    const p = await open("off", {})
    await p.waitForTimeout(2800)
    check(!(await Promise.all(p.frames().map((f) => f.locator(".universal").count().catch(() => 0)))).some(Boolean), "with the setting off, Acme gets no offer")
    await p.close()
  }
  await setting(true)

  // Unlearned code step: tile and password go, the TOTP is left to the person.
  await fresh()
  {
    const flow = "unlearned"
    const p = await open(flow, {})
    const w = await watch(p)
    await pick(p)
    await p.waitForURL(`${googleOrigin}/v3/signin/challenge/totp*`)
    check(hits(flow, (h) => google(h) && h.path === "/signin/select").map((h) => h.value).join() === GOOGLE_USER, "one pick clicks Acme's Google button and only the linked account's chooser tile")
    check(posts(flow, "/v3/signin/challenge/pwd") === 1, "the provider password is filled and submitted once")
    // The chain may hand off silently here (no label), so its pill need not show.
    await settles(w, "/v3/signin/challenge/totp", "unlearned code", true)
    check(posts(flow, "/v3/signin/challenge/totp") === 0, "an unlearned provider code step is never submitted")
    noFocus(w, "unlearned code")
    w.stop()
    await p.close()
  }
  await learnGoogle()

  // Same tab: chooser → password (a passkey option beside it) → TOTP → Acme.
  await fresh()
  {
    const flow = "same-tab"
    const p = await open(flow, {})
    const w = await watch(p)
    await pick(p)
    await p.waitForURL(`${site}/account*`)
    check(await p.locator("#who").textContent() === `Signed in as ${GOOGLE_USER} with Google`, "same tab: one trusted pick completes chooser, password and TOTP back to Acme")
    check(hits(flow, (h) => google(h) && h.path === "/o/oauth2/v2/auth").length === 1, "the site's provider button is clicked once")
    check(posts(flow, "/v3/signin/challenge/pwd") === 1 && posts(flow, "/v3/signin/challenge/totp") === 1, "password and code are each submitted exactly once")
    check(!hits(flow, (h) => h.path.startsWith("/v3/signin/challenge/pk") || h.path === "/v3/signin/challenge/selection").length, "the passkey option and Try another way are left alone")
    check(w.samples.some((s) => s.url.startsWith(googleOrigin) && /Signing in with Google/.test(s.text)), "the provider pages show a quiet progress pill")
    const texts = await settles(w, "/account", "same tab")
    check(texts.includes("Signed in"), "back on Acme the pill says Signed in")
    noFocus(w, "same tab")
    w.stop()
    await p.close()
  }

  // Popup: identifier → password → TOTP in a popup, which closes back to Acme.
  await fresh()
  {
    const flow = "popup"
    const p = await open(flow, { mode: "popup", chooser: "0" })
    const w = await watch(p)
    const popped = context.waitForEvent("page")
    await pick(p)
    const popup = await popped
    record(popup, "popup-window")
    const pw = await watch(popup)
    await popup.waitForEvent("close", { timeout: 20_000 })
    await p.waitForURL(`${site}/account*`)
    check(await p.locator("#who").textContent() === `Signed in as ${GOOGLE_USER} with Google`, "popup: one trusted pick completes identifier, password and TOTP back to Acme")
    check(hits(flow, (h) => h.method === "POST" && h.path === "/v3/signin/identifier").map((h) => h.value).join() === GOOGLE_USER, "the popup's identifier is the linked account, submitted once")
    check(posts(flow, "/v3/signin/challenge/pwd") === 1 && posts(flow, "/v3/signin/challenge/totp") === 1, "popup password and code are each submitted exactly once")
    check(pw.samples.some((s) => /Signing in with Google/.test(s.text)), "the popup shows the quiet progress pill")
    await settles(w, "/account", "popup")
    noFocus(w, "popup opener")
    noFocus(pw, "popup")
    w.stop()
    pw.stop()
    await p.close()
  }

  // Consent and phone prompts are handed back untouched.
  for (const [flow, query, path] of [["consent", { consent: "1" }, "/signin/oauth/consent"], ["phone", { phone: "1" }, "/v3/signin/challenge/ipp"], ["passkey-only", { pk: "1" }, "/v3/signin/challenge/pk"]] as const) {
    await fresh()
    const p = await open(flow, query)
    const w = await watch(p)
    await pick(p)
    await p.waitForURL(`${googleOrigin}${path}*`)
    // With no passkey saved, the chain may hand off silently (no label).
    await settles(w, path, flow, flow === "passkey-only")
    check(!hits(flow, (h) => h.method === "POST" && (h.path === path || h.path === "/signin/oauth/consent/approve")).length, `${flow}: the prompt is never submitted`)
    if (flow === "phone") check(await p.inputValue('input[name="phoneNumberId"]') === "", "phone: the phone number field is left empty")
    if (flow === "passkey-only") {
      check(!hits(flow, (h) => h.path.startsWith("/pk/") || h.path === "/v3/signin/challenge/selection" || h.path === "/v3/signin/challenge/pwd").length, "passkey with no saved passkey: neither Use your passkey nor Try another way is clicked")
      check(await noPasskeyPrompt(googleOrigin, 1500), "passkey with no saved passkey: no passkey prompt opens")
    }
    if (flow === "consent") {
      check(posts(flow, "/v3/signin/challenge/totp") === 1, "consent: reached after the one automatic code submission")
      await p.getByRole("button", { name: "Continue", exact: true }).click()
      await p.waitForURL(`${site}/account*`)
      check(true, "consent: the person's own Continue finishes the sign-in")
    }
    noFocus(w, flow)
    w.stop()
    await p.close()
  }

  // A real passkey: made by Deadbolt in Google's own enrollment ceremony, saved
  // in the extension's prompt by the person, verified by the fake Google.
  {
    const p = await context.newPage()
    record(p, "passkey-enroll")
    await p.goto(`${googleOrigin}/v3/signin/passkey/enroll?flow=enroll`)
    await p.evaluate(() => void (window as unknown as { enroll(): Promise<void> }).enroll())
    const save = await passkeyPrompt(googleOrigin)
    check(save?.heading === "Save a passkey for accounts.google.test?", `${mode}: the person is asked to save a passkey for accounts.google.test (${save?.heading})`)
    await save!.press("Save")
    await p.locator("#enroll-status", { hasText: /\S/ }).waitFor({ timeout: 20_000 })
    check(await p.locator("#enroll-status").textContent() === "Passkey created" && !!googlePasskey.credential, `${mode}: @simplewebauthn/server verifies Deadbolt's registration (AAGUID ${googlePasskey.aaguid})`)
    await p.close()
  }

  // One trusted pick: chooser → Google's passkey challenge, signed without a
  // second pick or prompt, verified by the server, back to Acme.
  await fresh()
  {
    const flow = "passkey"
    const before = googlePasskey.verified
    const p = await open(flow, { pk: "1" })
    const w = await watch(p)
    await pick(p)
    let prompted = false
    const end = Date.now() + 20_000
    while (Date.now() < end && !p.url().startsWith(`${site}/account`)) {
      if (p.url().startsWith(googleOrigin) && !await noPasskeyPrompt(googleOrigin, 1)) prompted = true
      await Bun.sleep(150)
    }
    await p.waitForURL(`${site}/account*`, { timeout: 1000 })
    check(await p.locator("#who").textContent() === `Signed in as ${GOOGLE_USER} with Google`, `${mode}: one trusted pick signs in with the saved passkey back to Acme`)
    check(googlePasskey.verified === before + 1 && hits(flow, (h) => h.path === "/pk/auth" && h.value === "verified").length === 1, `${mode}: exactly one assertion, verified by @simplewebauthn/server`)
    check(!prompted, `${mode}: no passkey prompt or second pick during the chain`)
    check(!hits(flow, (h) => h.path === "/v3/signin/challenge/pwd" || h.path === "/v3/signin/challenge/selection").length, `${mode}: the passkey is used instead of the password, Try another way untouched`)
    await settles(w, "/account", "passkey")
    noFocus(w, "passkey")
    w.stop()
    await p.close()
  }

  // Lookalike provider hosts and a cross-site embedded chooser get nothing.
  for (const gh of LOOKALIKES) {
    await fresh()
    const flow = `lookalike-${gh}`
    const p = await open(flow, { gh })
    const w = await watch(p)
    await pick(p)
    const reached = await until("lookalike chooser", async () => new URL(p.url()).hostname === gh, 5000).catch(() => false)
    if (!reached) await p.click("#google")
    await p.waitForURL(`http://${gh}:${port}/o/oauth2/v2/auth*`)
    await p.waitForTimeout(3000)
    check(!hits(flow, (h) => h.host === gh && h.path !== "/o/oauth2/v2/auth").length, `${gh}: no tile is clicked and nothing is submitted`)
    check(quietOn(w, gh), `${gh}: no status pill`)
    w.stop()
    await p.close()
  }
  await fresh()
  {
    const flow = "frame"
    const p = await open(flow, { frame: "1" })
    await pick(p)
    const reached = await until("embedded chooser", async () => p.frames().some((f) => f.url().startsWith(googleOrigin)), 5000).catch(() => false)
    if (!reached) await p.click("#google")
    const frame = await until("embedded chooser loads", async () => p.frames().find((f) => f.url().startsWith(googleOrigin)) ?? null)
    await frame.locator(`[data-identifier="${GOOGLE_USER}"]`).waitFor()
    await p.waitForTimeout(3000)
    check(!hits(flow, (h) => google(h) && h.frame && h.path !== "/o/oauth2/v2/auth").length, "a cross-site iframe chooser is never clicked or filled")
    await p.close()
  }

  // At most eight actions: a chooser that leads to another chooser, forever.
  await fresh()
  {
    const flow = "cap"
    const p = await open(flow, { loop: "1" })
    await pick(p)
    await until("the chain clicks several tiles", async () => hits(flow, (h) => h.path === "/signin/select").length >= 2)
    await p.waitForTimeout(6000)
    const count = () => hits(flow, (h) => google(h) && (h.path === "/o/oauth2/v2/auth" || h.path === "/signin/select")).length
    const actions = count()
    await p.waitForTimeout(3000)
    console.log(`INFO cap: ${actions} actions (provider button + tiles)`)
    check(actions <= 8 && count() === actions, "one pick takes at most eight actions, then stops")
    await p.close()
  }

  // The setting going off mid-chain stops it before the next step.
  await fresh()
  {
    const flow = "setting-off"
    const p = await open(flow, { delay: "4000" })
    await pick(p)
    await until("tile clicked", async () => hits(flow, (h) => h.path === "/signin/select").length === 1)
    await setting(false)
    await p.waitForURL(`${googleOrigin}/v3/signin/challenge/pwd*`, { timeout: 20_000 })
    await p.waitForTimeout(3000)
    check(await p.inputValue('input[name="Passwd"]') === "" && posts(flow, "/v3/signin/challenge/pwd") === 0, "turning the setting off mid-chain stops it: the password is never filled")
    await setting(true)
    await p.close()
  }

  // Two minutes after the pick, the chain is over (a real wait, no clock tricks).
  if (!skipTtl) {
    await fresh()
    const flow = "ttl"
    const p = await open(flow, { delay: "121000" })
    const picked = await pick(p)
    await until("tile clicked", async () => hits(flow, (h) => h.path === "/signin/select").length === 1)
    await p.waitForURL(`${googleOrigin}/v3/signin/challenge/pwd*`, { timeout: 150_000 })
    check(Date.now() - picked >= 120_000, "the password step arrives after the chain's two-minute lifetime")
    await p.waitForTimeout(3000)
    check(await p.inputValue('input[name="Passwd"]') === "" && posts(flow, "/v3/signin/challenge/pwd") === 0, "after two minutes the chain is over: nothing is filled")
    await p.close()
  }
  console.log(`PASS universal sign-in with a provider (${mode})`)
} catch (err) {
  // What the status pill said last, and where: enough to tell a fixture gap from a chain stop.
  for (const w of watches.slice(-2)) console.log(`DIAG pill ${JSON.stringify([...new Map(w.samples.map((s) => [`${new URL(s.url).pathname} ${s.text}`, 1])).keys()])}`)
  console.log(`DIAG last hits ${JSON.stringify(providerLog.slice(-6).map((h) => `${h.method} ${h.host}${h.path}`))}`)
  throw err
} finally {
  await context.close()
  if (video) {
    await mkdir(video, { recursive: true })
    for (const [i, { page, name, clicks }] of recordings.entries()) {
      const path = await page.video()?.path()
      const file = `providers-${mode}-${String(i + 1).padStart(2, "0")}-${name.replace(/[^a-z0-9.-]+/gi, "-")}`
      if (path) await copyFile(path, join(video, `${file}.webm`))
      await Bun.write(join(video, `${file}.cursor.json`), JSON.stringify(clicks))
    }
  }
  server.stop(true)
  if (native) {
    try { cli("agent", "stop") } catch {}
    await rm(store, { recursive: true, force: true })
  }
  await rm(root, { recursive: true, force: true })
}
