// The locked row's unlock in a real, headed browser with its real toolbar
// popup: what the headless e2e (e2e/standalone.ts) can't show, because a
// headless browser has no toolbar and draws no popup. Run it on a Mac with a
// desktop session, with a throwaway profile it makes and removes itself:
//
//   bun e2e/real/run.ts --browser "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
//
// It builds the standalone extension (or takes --dist <dir>), creates a vault
// with two logins, locks it, clicks the inline menu's real locked row on a
// real sign-in page, and checks that chrome.action.openPopup opened the real
// popup (not the tab fallback), that its first frame is the locked panel at
// its own size, that the passphrase typed into it unlocks, that the popup
// then closes itself, and that the menu by the field lists the logins.
//
// --dialog adds the same with macOS's own verification dialog up over the
// panel. That needs a platform passkey, which only a person (or a driver
// outside the browser) can make: the browser asks in its own dialog and
// macOS in another. Deadbolt's Touch ID slot is then set with a made-up PRF
// value, only so the panel asks for Touch ID and the dialog comes up; the
// passphrase typed under it is what unlocks.
//
// --driver <dir> hands the steps a script can't do from inside the browser
// to something outside it (we run this in a throwaway macOS VM driven over
// VNC): the run writes <dir>/need/<n>-<kind>-<name> and waits for the same
// name in <dir>/ack/. Kinds: "shot" (photograph the screen), "passkey"
// (answer the browser's and macOS's dialogs), "type" (type the vault's
// passphrase and Return on the real keyboard). Without a driver, "type" is
// sent to the popup over DevTools and the others are yours to do.
import { chromium, type BrowserContext, type Frame, type Page } from "playwright-core"
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { lines, menuStamps, PANEL_STAMPS, stampMenu, stampWorker, watchWindows, workerStamps, type Stamp } from "./timing"

const arg = (name: string) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : undefined }
const flag = (name: string) => process.argv.includes(name)
const browser = arg("--browser")
if (!browser) throw new Error("--browser <path to a Chromium browser's binary> is needed (Brave, Chromium; Google Chrome no longer loads unpacked extensions from the command line)")
const driver = arg("--driver")
const withDialog = flag("--dialog")
const root = await mkdtemp(join(tmpdir(), "deadbolt-real-"))
const profile = join(root, "profile")
/** The passphrase the vault is made with: a driver types the same (e2e/real/README.md). */
const passphrase = "correct horse battery staple 42"

let dist = arg("--dist") ? resolve(arg("--dist")!) : ""
if (!dist) {
  const built = Bun.spawnSync(["bun", join(import.meta.dir, "..", "..", "scripts", "build.ts"), "--standalone"], { stdout: "inherit", stderr: "inherit" })
  if (!built.success) throw new Error("the standalone build failed (it needs the wasm toolchain: scripts/wasm.sh); or pass --dist <dir>")
  dist = join(import.meta.dir, "..", "..", "dist")
}

const results: Array<{ ok: boolean; check: string }> = []
function check(ok: unknown, message: string) {
  results.push({ ok: !!ok, check: message })
  console.log(`${ok ? "ok" : "FAILED"}: ${message}`)
}
const sleep = (ms: number) => Bun.sleep(ms)
async function until<T>(label: string, probe: () => Promise<T | null | undefined | false>, ms = 30_000): Promise<T | null> {
  const deadline = Date.now() + ms
  do {
    const value = await probe().catch(() => null)
    if (value) return value
    await sleep(150)
  } while (Date.now() < deadline)
  console.log(`(timed out: ${label})`)
  return null
}

let needs = 0
/** Something outside the browser has to act: waits for it (a driver), or says what to do. */
async function need(kind: "shot" | "passkey" | "type", name: string, say: string): Promise<boolean> {
  if (!driver) {
    if (kind !== "shot") console.log(`>> ${say}`)
    return false
  }
  const file = `${String(++needs).padStart(2, "0")}-${kind}-${name}`
  await writeFile(join(driver, "need", file), "")
  const acked = await until(`the driver's ${file}`, async () => (await readdir(join(driver, "ack"))).includes(file), 120_000)
  return !!acked
}

if (driver) for (const d of ["need", "ack"]) await mkdir(join(driver, d), { recursive: true })
const server = Bun.serve({
  port: 0,
  fetch: () => new Response(`<!doctype html><meta charset=utf-8><title>Sign in · Acme</title><meta name=color-scheme content="light dark">
<style>body{font:15px -apple-system,system-ui;display:grid;place-items:center;height:100vh;margin:0}form{display:grid;gap:12px;width:300px}input{font:inherit;padding:9px 11px;border:1px solid #8886;border-radius:8px}button{font:inherit;padding:9px;border-radius:8px;border:0;background:#2f6feb;color:#fff}</style>
<form onsubmit="return false"><h2 style="margin:0 0 6px">Sign in to Acme</h2><input id=username name=username autocomplete=username placeholder=Email><input id=password name=password type=password autocomplete=current-password placeholder=Password><button>Sign in</button></form>`, { headers: { "content-type": "text/html" } }),
})
const origin = `http://localhost:${server.port}`

// The extension pinned to the toolbar, as a password manager is: the popup hangs off its icon.
await mkdir(join(profile, "Default"), { recursive: true })
await writeFile(join(profile, "Default", "Preferences"), JSON.stringify({ extensions: { pinned_extensions: ["jhocodkhpifjndffenppfmdkmiolngal"] } }))
const context: BrowserContext = await chromium.launchPersistentContext(profile, {
  executablePath: browser, headless: false, viewport: null, colorScheme: null,
  ignoreDefaultArgs: ["--enable-automation", "--disable-extensions"],
  args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, "--remote-debugging-port=0", "--window-size=1280,820", "--window-position=420,80", "--no-first-run", "--no-default-browser-check"],
})
context.setDefaultTimeout(20_000)
const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker")
const ID = new URL(worker.url()).host
const menuFrame = (page: Page): Frame | null => page.frames().find((frame) => frame.url().includes("menu.html")) ?? null
const send = (page: Page, command: Record<string, unknown>) => page.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command) as Promise<{ ok: boolean; status: { state: string }; reply: Record<string, unknown> }>
const state = async (page: Page) => (await send(page, { type: "device-status" })).status.state

type Target = { id: string; type: string; url: string; webSocketDebuggerUrl: string }
async function targets(): Promise<Target[]> {
  const port = (await Bun.file(join(profile, "DevToolsActivePort")).text()).split("\n")[0]
  return await (await fetch(`http://127.0.0.1:${port}/json/list`)).json() as Target[]
}
const popupTarget = async () => (await targets()).find((t) => t.url.startsWith(`chrome-extension://${ID}/popup.html`)) ?? null
/** One DevTools command to the real toolbar popup (it isn't one of Playwright's pages). */
async function toPopup(method: string, params: Record<string, unknown>): Promise<any> {
  const target = await popupTarget()
  if (!target) return null
  const ws = new WebSocket(target.webSocketDebuggerUrl)
  await new Promise((ok, no) => { ws.onopen = ok; ws.onerror = no })
  const reply = new Promise<any>((ok) => { ws.onmessage = (e) => ok(JSON.parse(String(e.data)).result); ws.onclose = () => ok(null) })
  ws.send(JSON.stringify({ id: 1, method, params }))
  const r = await Promise.race([reply, sleep(10_000).then(() => null)])
  ws.close()
  return r
}
const inPopup = async (expression: string) => (await toPopup("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }))?.result?.value
/** The passphrase and Return, on the real keyboard if a driver has one, else as key events sent to the popup. */
async function typePassphrase(name: string) {
  if (await need("type", name, "type the vault's passphrase into the popup and press Return")) return
  await toPopup("Input.insertText", { text: passphrase })
  for (const type of ["keyDown", "keyUp"]) await toPopup("Input.dispatchKeyEvent", { type, key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13, text: type === "keyDown" ? "\r" : undefined })
}

const device = await context.newPage()
await device.goto(`chrome-extension://${ID}/device.html`)
await device.getByRole("button", { name: "Create a new vault", exact: true }).click()
await device.getByLabel("Passphrase", { exact: true }).fill(passphrase)
await device.getByLabel("Passphrase again", { exact: true }).fill(passphrase)
await device.getByRole("button", { name: "Create vault", exact: true }).click()
await device.getByRole("searchbox", { name: "Search the vault" }).waitFor({ timeout: 120_000 })
for (const [title, user] of [["Acme", "kit@example.test"], ["Acme (work)", "kit@work.example.test"]] as const) {
  await device.getByRole("button", { name: "Add an item", exact: true }).click()
  await device.getByRole("button", { name: "Login", exact: true }).click()
  await device.getByLabel("Website", { exact: true }).fill(origin)
  await device.getByLabel("Title", { exact: true }).fill(title)
  await device.getByLabel("Username", { exact: true }).fill(user)
  await device.getByLabel("Password", { exact: true }).fill("hunter2-not-real")
  await device.getByRole("button", { name: "Save", exact: true }).click()
  await device.getByRole("button", { name: "Edit", exact: true }).waitFor()
  await device.getByRole("button", { name: "Back", exact: true }).click()
}
const page = await context.newPage()
check(true, `${(await context.browser()?.version()) ?? "the browser"} is up, headed, with the built extension and a vault of two logins`)

// ---- 0. Where the time goes, from a press on the row to the panel on screen (--timing <presses>) ----
const presses = Number(arg("--timing") ?? 0)
if (presses > 0) {
  const windows = watchWindows()
  await stampWorker(worker)
  const after: number[] = []
  for (let i = 1; i <= presses; i++) {
    await send(device, { type: "device-lock" })
    await page.bringToFront()
    await page.goto(origin)
    await sleep(1200)
    await page.locator("#username").click()
    const menu = await until("the inline menu", async () => { const f = menuFrame(page); return f && (await f.locator("button.row.unlock").count()) ? f : null })
    const box = await menu?.locator("button.row.unlock").boundingBox()
    if (!menu || !box) break
    // The menu takes a press only once it has sat still.
    await sleep(1500)
    await stampMenu(menu)
    await workerStamps(worker)
    const from = Date.now()
    // A person's click: the button is down for about 90 ms.
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
    await sleep(150)
    await page.mouse.down()
    await sleep(90)
    await page.mouse.up()
    if (!(await until("the toolbar popup", () => popupTarget(), 10_000))) break
    await sleep(900)
    const panel = JSON.parse((await inPopup(PANEL_STAMPS)) ?? "[]") as Stamp[]
    const awake = (await workerStamps(worker)) as Stamp[]
    const all = [...((await menuStamps(menu)) as Stamp[]), ...awake, ...panel, ...(windows?.stamps().filter(([, t]) => t >= from) ?? [])]
    const { text, click, shown } = lines(all)
    console.log(`note: press ${i} (the worker ${awake.length ? "was awake" : "had to wake"}), in ms after the click:\n${text}`)
    if (shown !== null) after.push(shown - click)
    await inPopup("window.close()")
    await until("the popup closing", async () => !(await popupTarget()), 5000)
    await sleep(600)
  }
  windows?.stop()
  const median = [...after].sort((a, b) => a - b)[Math.floor(after.length / 2)] ?? NaN
  check(after.length === presses, `timing: the panel was on screen after each of ${presses} presses: ${after.map((t) => Math.round(t)).join(", ")} ms after the click (median ${Math.round(median)} ms)`)
}

/** Locks, opens the sign-in page afresh, and clicks the menu's real locked row: the real popup should come up. */
async function lockAndClickRow(name: string): Promise<boolean> {
  await send(device, { type: "device-lock" })
  check(await state(device) === "locked", `${name}: Deadbolt is locked`)
  await page.bringToFront()
  await page.goto(origin)
  await sleep(1200)
  await page.locator("#username").click()
  const menu = await until("the inline menu", async () => { const f = menuFrame(page); return f && (await f.locator("button.row").count()) ? f : null })
  const rows = menu ? await menu.locator("button.row").allInnerTexts() : []
  check(rows.length === 1 && rows[0]!.startsWith("Unlock Deadbolt"), `${name}: the menu by the field has the one locked row (${JSON.stringify(rows)})`)
  if (!menu) return false
  // The menu takes a press only once it has sat still.
  await sleep(1500)
  const tabs = context.pages().length
  await menu.getByRole("button", { name: /Unlock Deadbolt/ }).click()
  const popup = await until("the toolbar popup", () => popupTarget(), 10_000)
  check(!!popup, `${name}: chrome.action.openPopup opened the real toolbar popup (${popup?.url ?? "none"})`)
  // When it hears Deadbolt is unlocked, when it closes itself, and when it goes: kept where the device page can read them once it's gone.
  await inPopup(`(() => {
    for (const k of ["ready", "closed", "gone"]) localStorage.removeItem("deadbolt.real." + k)
    const note = (k) => localStorage.getItem("deadbolt.real." + k) ?? localStorage.setItem("deadbolt.real." + k, String(Date.now()))
    const close = window.close.bind(window)
    window.close = () => { note("closed"); close() }
    chrome.runtime.onMessage.addListener((m) => { if (m?.type === "db:status" && m.status?.state === "ready") note("ready") })
    addEventListener("pagehide", () => note("gone"))
  })()`)
  check(context.pages().length === tabs && !context.pages().some((p) => p.url().includes("device.html#unlock")), `${name}: no tab opened instead`)
  return !!popup
}
/** After the unlock: the popup has closed itself, and the same menu lists the logins without filling. */
async function closedAndListed(name: string) {
  check(await until("unlocked", async () => await state(device) === "ready", 30_000), `${name}: Deadbolt is unlocked`)
  check(await until("the popup closing", async () => !(await popupTarget()), 8000), `${name}: the popup closed`)
  const times = await device.evaluate(() => Object.fromEntries(["ready", "closed", "gone"].map((k) => [k, Number(localStorage.getItem(`deadbolt.real.${k}`) ?? 0)]))) as { ready: number; closed: number; gone: number }
  check(times.closed > 0, `${name}: it closed itself, not the browser under it`)
  check(times.ready > 0 && times.gone - times.ready >= 600, `${name}: it stayed for its unlock moment (${times.gone - times.ready} ms from unlocked to gone)`)
  const listed = await until("the logins in the menu", async () => { const rows = await menuFrame(page)?.locator("button.row").allInnerTexts(); return rows && rows.length === 2 ? rows : null }, 8000)
  check(listed?.[0]?.startsWith("Acme") && listed[1]!.startsWith("Acme (work)"), `${name}: the menu by the field now lists the logins (${JSON.stringify(listed)})`)
  check(await page.inputValue("#username") === "" && await page.inputValue("#password") === "", `${name}: nothing was filled`)
}

// ---- 1. The passphrase, typed into the real popup ----
if (await lockAndClickRow("passphrase")) {
  await sleep(600)
  const first = JSON.parse((await inPopup(`JSON.stringify({ w: innerWidth, h: innerHeight, title: document.querySelector("h2")?.textContent, focus: document.activeElement?.getAttribute("aria-label"), hash: location.hash, scrolls: document.documentElement.scrollHeight > innerHeight })`)) ?? "{}")
  check(first.w === 360 && first.h < 300 && !first.scrolls, `passphrase: the popup is the locked panel's size, 360 wide and as tall as its form, with no scrollbar (${first.w} × ${first.h})`)
  check(first.hash === "#locked,menu", `passphrase: its address says it's locked and the row asked, so its first frame is already the locked panel (${first.hash})`)
  check(first.title === "Unlock Deadbolt" && first.focus === "Passphrase", `passphrase: it shows the lock and the title, the passphrase field focused (${JSON.stringify(first)})`)
  check((await menuFrame(page)?.locator("button.row .sub").innerText()) === "Waiting in the toolbar ↗", "passphrase: the row waits by its field while the popup is up")
  await need("shot", "popup-open", "")
  // Whether a page can round the browser's popup: a see-through page with round corners, photographed, then taken back.
  if (flag("--corners")) {
    await inPopup(`(() => { const s = document.createElement("style"); s.id = "corners"; s.textContent = "html,body{background:transparent!important}main{border-radius:14px;overflow:hidden;background:var(--bg)}"; document.head.append(s) })()`)
    await sleep(300)
    await need("shot", "popup-corners", "")
    await inPopup(`document.getElementById("corners")?.remove()`)
  }
  await typePassphrase("passphrase")
  await closedAndListed("passphrase")
  await need("shot", "menu-lists-logins", "")
}

// ---- 2. The same with macOS's own dialog up over the panel ----
if (withDialog) {
  await device.bringToFront()
  await device.evaluate(() => {
    const rnd = () => crypto.getRandomValues(new Uint8Array(32))
    const hex = (b: ArrayBuffer | Uint8Array) => Array.from(new Uint8Array(b as ArrayBuffer), (x) => x.toString(16).padStart(2, "0")).join("")
    const w = window as unknown as { made: string }
    w.made = "pending"
    navigator.credentials.create({ publicKey: { challenge: rnd(), rp: { name: "Deadbolt unlock" }, user: { id: rnd(), name: "Deadbolt", displayName: "Deadbolt on this browser" }, pubKeyCredParams: [{ type: "public-key", alg: -7 }], authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" }, attestation: "none", timeout: 120_000, extensions: { prf: { eval: { first: rnd() } } } as AuthenticationExtensionsClientInputs } })
      .then((c) => { const p = c as PublicKeyCredential; w.made = JSON.stringify({ id: hex(p.rawId), salt: hex(rnd()), prf: (p.getClientExtensionResults() as { prf?: { enabled?: boolean } }).prf?.enabled === true }) }, (e) => { w.made = `ERR ${e.name}: ${e.message}` })
  })
  await sleep(2500)
  await need("shot", "browser-asks-to-create-passkey", "")
  await need("passkey", "create", "in the browser's dialog choose Continue, then answer macOS's dialog (Touch ID, or the Mac's password)")
  const made = await until("the platform passkey", async () => { const m = await device.evaluate(() => (window as unknown as { made: string }).made); return m !== "pending" ? m : null }, 120_000)
  check(!!made && !made.startsWith("ERR"), `dialog: a platform passkey was made on the extension's own origin (${made})`)
  if (made && !made.startsWith("ERR")) {
    const { id, salt, prf } = JSON.parse(made) as { id: string; salt: string; prf: boolean }
    console.log(`note: this browser's platform passkey ${prf ? "has" : "has no"} PRF (Deadbolt's real Touch ID setup ${prf ? "would work" : "would stop with “doesn't support PRF unlock”"} here)`)
    await send(device, { type: "device-unlock", passphrase })
    // A made-up PRF value: the slot can't unlock anything, it only makes the panel ask for Touch ID.
    const set = await send(device, { type: "device-biometric-set", token: JSON.stringify({ id, salt }), prf: "ab".repeat(32), passphrase })
    await device.evaluate(() => { localStorage.setItem("deadbolt.touch", "1"); return chrome.storage.local.set({ "deadbolt.unlockMethod": "touch-id" }) })
    check(set.ok, "dialog: Deadbolt's Touch ID slot is set (with a made-up key: only so the panel asks)")
    if (await lockAndClickRow("dialog")) {
      const asking = await until("the panel asking", async () => await inPopup(`document.querySelector(".unlock-touch.asking .unlock-touch-label")?.dataset.text ?? ""`), 8000)
      check(asking === "Waiting for macOS…", `dialog: the panel asked at once and only says it's waiting (${asking})`)
      check((await inPopup(`document.activeElement?.getAttribute("aria-label")`)) === "Passphrase", "dialog: its passphrase field has the keyboard while macOS asks")
      await sleep(1500)
      await need("shot", "macos-dialog-over-panel", "")
      check(!!(await popupTarget()), "dialog: the popup stays open under macOS's dialog")
      await typePassphrase("under-dialog")
      await closedAndListed("dialog")
      await sleep(800)
      await need("shot", "after-dialog", "")
    }
  }
}

const failed = results.filter((r) => !r.ok)
if (driver) await writeFile(join(driver, "result.json"), JSON.stringify({ browser: await context.browser()?.version(), failed: failed.length, results }, null, 1))
console.log(failed.length ? `FAILED: ${failed.length} of ${results.length} checks` : `PASS: ${results.length} checks, in a real headed browser`)
await context.close().catch(() => {})
server.stop(true)
await rm(root, { recursive: true, force: true })
process.exit(failed.length ? 1 : 0)
