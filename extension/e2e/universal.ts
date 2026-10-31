// Headless, disposable browser vault. --dist <standalone build> [--video dir]
// --demo exercises Acme with a fresh account; --demo-seed <private JSON> uses its seeded MFA account.
import { chromium, type Frame, type Page } from "playwright-core"
import { mkdtemp, mkdir, copyFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { universalFixture, USER, PASSWORD, OTP } from "./universal-fixture"

const arg = (name: string) => { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1] }
const dist = resolve(arg("--dist") ?? "dist")
const video = arg("--video")
const demoSeed = arg("--demo-seed")
const root = await mkdtemp(join(tmpdir(), "deadbolt-universal-"))
const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: universalFixture })
const origin = `http://localhost:${server.port}`
const ID = "jhocodkhpifjndffenppfmdkmiolngal"
const context = await chromium.launchPersistentContext(join(root, "profile"), {
  channel: "chromium", headless: true, viewport: { width: 1440, height: 900 },
  args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
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
async function fresh() {
  // Test isolation only: don't reset another tab's real state in production.
  await worker.evaluate(async () => {
    const all = await chrome.storage.session.get(null)
    await chrome.storage.session.remove(Object.keys(all).filter((k) => k.startsWith("signin-memory:") || k.startsWith("session:")))
  })
}
async function page(name: string, path: string) {
  const p = await context.newPage()
  p.on("pageerror", (e) => console.log(`page error (${name}): ${e.message}`))
  recordings.push({ page: p, name, start: performance.now(), clicks: [] })
  await p.goto(path.startsWith("http") ? path : origin + path)
  return p
}
async function offer(p: Page): Promise<Frame> {
  return until("corner sign-in offer", async () => {
    for (const f of p.frames()) if (f.url().includes("/menu.html") && await f.locator(".universal").count()) return f
    return null
  })
}
async function quiet(p: Page, label: string) {
  await p.waitForTimeout(2800)
  check(!(await Promise.all(p.frames().map((f) => f.locator(".universal").count().catch(() => 0)))).some(Boolean), label)
}
async function choose(p: Page) {
  const f = await offer(p)
  // The real dwell, including the frame's font/layout settling.
  await p.waitForTimeout(1400)
  const box = await (await f.frameElement()).boundingBox()
  check(box && box.x > 600 && box.y < 40 && box.height < 80, "offer stays compact in the top-right corner")
  if (video) await p.screenshot({ path: join(root, "corner.png") })
  const row = f.locator("button.row").first()
  const target = await row.boundingBox()
  const recording = recordings.find((r) => r.page === p)
  // Render the pointer in post, never over the live surface: painted DOM cursors
  // correctly trip the visibility guard even with pointer-events:none.
  if (target && recording) recording.clicks.push({ seconds: (performance.now() - recording.start) / 1000, x: target.x + target.width / 2, y: target.y + target.height / 2 })
  await row.click()
}
const device = await context.newPage()
async function command(command: Record<string, unknown>) {
  const reply = await device.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command)
  if (!reply?.ok) throw new Error(`${command.type}: ${reply?.message ?? "no reply"}`)
  check(true, `${command.type} succeeds`)
  return reply
}
try {
  await device.goto(`chrome-extension://${ID}/device.html`)
  await device.getByRole("button", { name: "Create a new vault", exact: true }).waitFor({ timeout: 60_000 })
  await command({ type: "device-create", passphrase: "universal synthetic browser vault", name: "universal-fixture" })
  await command({ type: "device-save", entry: { title: "Universal fixture", url: origin, username: USER, password: PASSWORD, otp: OTP } })
  const off = await page("01-default-off", "/")
  await quiet(off, "default-off offers nothing")
  await off.close()
  await device.reload()
  await device.getByRole("button", { name: "Settings", exact: true }).click()
  const setting = device.getByRole("switch", { name: "Offer to sign in", exact: true })
  check(!await setting.isChecked(), "Settings exposes the feature default off")
  await setting.check()
  const home = await page("02-corner-to-dashboard", "/")
  await offer(home)
  check(await home.evaluate(() => document.activeElement === document.body), "proactive offer does not move page focus")
  if (video) await home.screenshot({ path: join(root, "corner.png") })
  await choose(home)
  await home.waitForURL("**/code")
  await until("unlearned authenticator code is filled", async () => (await home.inputValue("#code")).length === 6)
  await home.waitForTimeout(500)
  check(new URL(home.url()).pathname === "/code", "an unlearned code step waits for manual submission")
  await home.getByRole("button", { name: "Verify", exact: true }).click()
  await home.waitForURL("**/dashboard")
  check(true, "one pick completes identifier/password and fills the code for confirmation")
  await quiet(home, "no offer on dashboard with a stray Google sign-in button")
  await until("existing outcome judge learns the flow after the page settles", () => worker.evaluate(async () => Object.keys((await chrome.storage.local.get("signinFlows")).signinFlows ?? {}).length > 0), 10_000)
  check(true, "automatic sign-in teaches the existing Flow model")
  await home.close()
  await fresh()
  const learned = await page("02-learned-corner-to-dashboard", "/")
  await choose(learned)
  await learned.waitForURL("**/dashboard")
  check(true, "a learned authenticator flow completes all three steps after one pick")
  await learned.close()
  await fresh()
  const signedIn = await page("03-signed-in-suppresses", "/dashboard")
  await quiet(signedIn, "signed-in controls suppress the stray provider offer")
  await signedIn.close()
  await fresh()
  const email = await page("03-free-text-is-not-an-oracle", "/email")
  await offer(email)
  await email.evaluate(() => {
    document.querySelector("p")!.textContent = "someone-else@example.test"
    document.querySelector("main")!.insertAdjacentHTML("beforeend", '<a href="/logout">Sign out</a>')
  })
  await email.waitForTimeout(1200)
  await offer(email)
  check(true, "free text does not select account visibility and an open offer is not re-probed")
  await email.close()
  await fresh()
  const spa = await page("04-spa-logout", "/spa")
  await quiet(spa, "SPA signed-in state is quiet")
  await spa.locator("#out").click()
  await offer(spa)
  check(true, "SPA logout clears signed-in memory without a navigation")
  await spa.close()
  for (const route of ["wrapped-logout", "large-logout", "overflow-logout"]) {
    await fresh()
    const fake = await page(`04-${route}`, `/${route}`)
    await quiet(fake, "signed-in memory is established before the false sign-out click")
    if (route === "overflow-logout") {
      const box = await fake.locator("#out").boundingBox()
      check(box && box.width <= 320 && box.height <= 96, "the overflowing sign-out control itself fits the size bound")
    }
    await fake.locator(route === "overflow-logout" ? "#out span" : "#out").click()
    await quiet(fake, `${route} does not invalidate signed-in memory`)
    await fake.close()
  }
  await fresh()
  const modal = await page("05-modal", "/modal")
  await choose(modal)
  await modal.waitForURL("**/dashboard")
  check(true, "one pick opens and fills a modal, then submits password and code")
  await modal.close()
  await fresh()
  const framed = await page("06-cross-site-frame", "/frame")
  await quiet(framed, "cross-site iframe login receives no offer")
  await framed.close()
  await fresh()
  const dismissed = await page("07-not-now", "/")
  const surface = await offer(dismissed)
  await dismissed.waitForTimeout(1400)
  await surface.getByRole("button", { name: "Not now for this site" }).click()
  await dismissed.reload()
  await quiet(dismissed, "Not now for this site survives navigation")
  await dismissed.close()
  await fresh()
  const cross = await page("08-cross-origin-submit-blocked", "/cross-action")
  let posted = false
  cross.on("request", (r) => { if (r.method() === "POST") posted = true })
  await choose(cross)
  await cross.waitForTimeout(2500)
  check(!posted, "a cross-origin form action is never automatically submitted")
  await cross.close()
  await fresh()
  const failed = await page("09-error-suppresses", "/failed")
  await quiet(failed, "an error state is uncertain and offers nothing")
  await failed.close()
  await fresh()
  const delayed = await page("10-escape-in-surface", "/delayed")
  const waiting = await offer(delayed)
  await choose(delayed)
  await waiting.locator(".pill", { hasText: "Continuing sign-in" }).waitFor()
  await waiting.locator("body").press("Escape")
  await delayed.locator("dialog[open]").waitFor()
  await delayed.waitForTimeout(1500)
  check(await delayed.inputValue("#password") === "" && await delayed.inputValue("#email") === "", "Escape inside the consumed offer cancels the pending flow")
  await delayed.close()
  await fresh()
  const override = await page("11-submitter-override-blocked", "/override")
  let overridden = false
  override.on("request", (r) => { if (r.method() === "POST") overridden = true })
  await choose(override)
  await override.waitForTimeout(2500)
  check(!overridden, "a cross-origin submitter override is never automatically submitted")
  await override.close()
  for (const mode of ["sms", "email", "auto"]) {
    await fresh()
    const codes = await page(`13-${mode}-code`, `/${mode}-login`)
    let posts = 0
    codes.on("request", (r) => { if (r.method() === "POST" && new URL(r.url()).pathname === `/${mode}-code`) posts++ })
    await choose(codes)
    if (mode === "auto") {
      await until("site-submitted code dashboard", async () => new URL(codes.url()).pathname === "/dashboard")
      check(posts === 1, "a site that submits on fill receives exactly one code submission")
    } else {
      // A code the person brings (SMS or email) is theirs to type: never filled, never submitted.
      await codes.waitForURL(`**/${mode}-code`)
      await codes.waitForTimeout(2500)
      check(await codes.inputValue("#code") === "", `a delivered ${mode} code prompt is left empty`)
      check(posts === 0, `a learned flow never auto-submits a ${mode} code prompt`)
    }
    await codes.close()
  }
  if (process.argv.includes("--demo") || demoSeed) {
    const demo = process.env.DEADBOLT_DEMO_URL
    if (!demo) throw new Error("Set DEADBOLT_DEMO_URL to the demo origin")
    // Consume the seed directly; never print its contents or include them in assertion labels.
    const seed = demoSeed ? await Bun.file(demoSeed).json().catch(() => { throw new Error("Cannot read valid JSON from --demo-seed") }) as { url: string; username: string; password: string; otpauth: string } : undefined
    if (seed) check(new URL(seed.url).origin === demo && !!seed.username && !!seed.password && seed.otpauth.startsWith("otpauth://"), "seed is an Acme MFA account")
    const username = seed?.username ?? `universal-${Date.now()}@example.test`
    const password = seed?.password ?? PASSWORD
    if (!seed) {
      const created = await context.request.post(`${demo}/signup`, { form: { name: "Universal synthetic account", email: username, password, confirm: password } })
      check(new URL(created.url()).pathname === "/app", "Acme demo creates a synthetic account")
    }
    await context.request.get(`${demo}/logout`)
    await command({ type: "device-save", entry: { title: "Acme demo", url: demo, username, password, ...(seed ? { otp: seed.otpauth } : {}) } })
    await fresh()
    const live = await page("12-acme-demo-one-pick", demo)
    const steps: string[] = []
    let authenticated = false
    live.on("response", (response) => {
      const url = new URL(response.url())
      if (url.origin === demo && url.pathname === "/app" && response.status() === 200) authenticated = true
    })
    live.on("request", (request) => {
      if (request.method() !== "POST" || new URL(request.url()).origin !== demo) return
      const step = new URLSearchParams(request.postData() ?? "").get("step")
      if (step) steps.push(step)
    })
    await choose(live)
    // Automatic steps can supersede intermediate /login loads. Wait for the
    // successful dashboard response rather than a navigation wait that aborts.
    await until("live Acme authenticated dashboard", async () => authenticated && new URL(live.url()).pathname === "/app")
    check(steps.includes("email") && steps.includes("password"), "one pick on the live Acme home submits identifier and password")
    if (seed) check(steps.includes("code"), "the same pick submits Acme TOTP and the server accepts it")
    if (seed) check(steps.filter((step) => step === "code").length === 1, "Acme receives exactly one code submission")
    await quiet(live, "live Acme signed-in dashboard receives no offer")
    await live.close()
  }
  console.log("PASS universal sign-in prototype")
} finally {
  await context.close()
  if (video) {
    await mkdir(video, { recursive: true })
    for (const { page, name, clicks } of recordings) {
      const path = await page.video()?.path()
      if (path) await copyFile(path, join(video, `${name}.webm`))
      await Bun.write(join(video, `${name}.cursor.json`), JSON.stringify(clicks))
    }
    if (await Bun.file(join(root, "corner.png")).exists()) await copyFile(join(root, "corner.png"), join(video, "corner.png"))
  }
  server.stop(true)
  await rm(root, { recursive: true, force: true })
}
