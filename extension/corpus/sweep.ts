// The real-site sweep: the extension itself, loaded in headless Chromium,
// on real sign-in pages. Where crawl.ts runs the detector alone, this checks
// what a person gets: whether the content script reports a login form,
// whether clicking its field opens the Deadbolt menu with logins (in the top
// page or for a same-site frame), whether picking the login fills the right
// fields, and on identifier-first sign-ins, the step after "Continue".
//
//   bun corpus/sweep.ts [--urls corpus/sweep-sites.txt] [--standalone]
//                       [--dist <dir>] [--out <dir>] [--concurrency 6]
//                       [--timeout 75] [--only <substring>] [--retry]
//                       [--no-step2]
//   bun corpus/sweep.ts --report [--out <dir>] [--against <other out dir>]
//
// Nothing real is ever typed or submitted. The native build talks to
// e2e/fake-host.py, which lists a made-up login for every site; the
// standalone build gets the same login saved for each site in a throwaway
// vault. Its username is the reserved, undeliverable address step2.ts uses
// (RFC 2606) and its password is made up. Step 2: the only submit is step 1's
// "Continue", with that address in the identifier field, as a person would
// after picking the login; a password step that follows is filled (by the
// sign-in session, or a second pick) and never submitted.
//
// Results go to <out>/results.jsonl (resumable: pages already there are
// skipped; --retry redoes errors and timeouts), screenshots of every failure
// to <out>/shots/, and `--report` writes <out>/sweep.md: rates, failures by
// pattern, and (with --against) the change from an earlier run.

import { chromium, type BrowserContext, type ElementHandle, type Frame, type Page, type Worker } from "playwright-core"
import { existsSync } from "node:fs"
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Clock, hostOf, loginish, probeFrames, settle, site, sleep, summarize, within, frameOf, type CapturedFrame } from "./crawl"
import type { EntryCandidate } from "./probe"
import { DEFAULT_OUT } from "./sites"
import { PROBE_ADDRESS } from "./step2"

const arg = (name: string) => {
  const i = process.argv.indexOf(name)
  return i > 0 ? process.argv[i + 1] : undefined
}
const root = join(import.meta.dir, "..")
const standalone = process.argv.includes("--standalone")
const out = arg("--out") ?? join(DEFAULT_OUT, standalone ? "sweep-standalone" : "sweep")
const urlsFile = arg("--urls") ?? join(import.meta.dir, "sweep-sites.txt")
const concurrency = Number(arg("--concurrency") ?? 6)
const doStep2 = !process.argv.includes("--no-step2")
const timeoutMs = Number(arg("--timeout") ?? (doStep2 ? 75 : 45)) * 1000
const only = arg("--only")
const retry = process.argv.includes("--retry")

const ID = "jhocodkhpifjndffenppfmdkmiolngal"
/** The made-up login every site gets. */
const USERNAME = PROBE_ADDRESS
/** No spaces: some password boxes drop them as they're typed. */
const PASSWORD = "Deadbolt-sweep-not-a-password-7"
const SEED_PASSPHRASE = "sweep synthetic passphrase"
const IDENT = new Set(["username", "email", "phone"])

export type MenuOutcome = "rows" | "empty" | "none"
export type FillOutcome = "ok" | "partial" | "wrong-field" | "nothing" | "pill-failed" | "phone-box" | "not-tried"

export interface SweepResult {
  url: string
  section: string
  status: "ok" | "no-fields" | "challenge" | "unreachable" | "timeout" | "error"
  error?: string
  finalUrl?: string
  /** The page's markup asks for a password, or an identifier with no password. */
  page?: "password" | "identifier" | "otp" | null
  /** What the content scripts reported (db:page), the last word of each frame. */
  verdicts?: Array<{ frame: number; url: string; kind: string | null; roles: string[] }>
  /** Some frame reported a login form with a field the menu serves. */
  detected?: boolean
  /** The frame the probe found the sign-in fields in: top, a same-site frame or a cross-site one. */
  where?: "top" | "same-site frame" | "cross-site frame"
  shadow?: boolean
  /** The field clicked, and what the markup and the detector say it is. */
  target?: { label: string | null; role: string | null; type: string; frame: number }
  /** The click landed on the field (false: something over it took it, so the field was only focused). */
  clicked?: boolean
  /** A consent banner over the field was answered first. */
  banner?: boolean
  menu?: MenuOutcome
  menuRows?: number
  fill?: FillOutcome
  /** Fields the fill should have landed in and didn't, and fields it landed in that it shouldn't. */
  missed?: string[]
  stray?: string[]
  /** After a fill that didn't land: the menu's last word, and the page-side facts of each field (see diagnose). */
  foot?: string
  diag?: Array<{ role: string; name: string; op: number; size: string; top: string; ro: boolean }>
  step2?: {
    outcome: "password-autofilled" | "password-picked" | "password-menu-no-fill" | "password-no-menu" | "password-not-detected" | "sign-up" | "no-password-step" | "not-tried"
    detail?: string
    finalUrl?: string
  }
  screenshot?: string
  ms: number
  at: string
}

// ---- The build and the browser -------------------------------------------------------

async function build(): Promise<string> {
  const prebuilt = arg("--dist")
  if (prebuilt) return prebuilt
  const dist = await mkdtemp(join(tmpdir(), "deadbolt-sweep-dist-"))
  const built = Bun.spawnSync(["bun", join(root, "scripts", "build.ts"), "--e2e", dist, standalone ? "--standalone" : "--native"], { stdout: "inherit", stderr: "inherit" })
  if (!built.success) throw new Error("the extension build failed")
  return dist
}

interface Browser {
  context: BrowserContext
  worker: Worker
  dir: string
  /** Sites the standalone vault has the login for. */
  seeded: Set<string>
  device?: Page
}

async function launch(dist: string, ua: string): Promise<Browser> {
  const dir = await mkdtemp(join(tmpdir(), "deadbolt-sweep-"))
  if (!standalone) {
    await mkdir(join(dir, "NativeMessagingHosts"))
    await writeFile(
      join(dir, "NativeMessagingHosts", "pw.deadbolt.browser.json"),
      JSON.stringify({ name: "pw.deadbolt.browser", description: "fake", path: join(root, "e2e", "fake-host.py"), type: "stdio", allowed_origins: [`chrome-extension://${ID}/`] }),
    )
  }
  const context = await chromium.launchPersistentContext(dir, {
    channel: "chromium",
    headless: true,
    viewport: { width: 1280, height: 800 },
    userAgent: ua,
    locale: "en-US",
    timezoneId: "America/New_York",
    extraHTTPHeaders: { "Accept-Language": "en-US,en;q=0.9" },
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
    env: { ...process.env, DEADBOLT_FAKE_STATUS: "ready", DEADBOLT_FAKE_USERNAME: USERNAME, DEADBOLT_FAKE_PASSWORD: PASSWORD },
  })
  context.setDefaultTimeout(10_000)
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"))
  // What the content scripts say about each page, by frame.
  await worker.evaluate(() => {
    const verdicts: unknown[] = []
    ;(globalThis as unknown as { __verdicts: unknown[] }).__verdicts = verdicts
    chrome.runtime.onMessage.addListener((m: { type?: string; kind?: unknown; roles?: unknown }, s) => {
      if (s.tab && s.url && m?.type === "db:page") verdicts.push({ frame: s.frameId, url: s.url, kind: m.kind ?? null, roles: m.roles ?? [] })
    })
  })
  const b: Browser = { context, worker, dir, seeded: new Set() }
  if (standalone) {
    b.device = await context.newPage()
    await b.device.goto(`chrome-extension://${ID}/device.html`)
    await device(b, { type: "device-create", passphrase: SEED_PASSPHRASE, name: "personal" })
  }
  return b
}

async function device(b: Browser, command: Record<string, unknown>) {
  const r = (await b.device!.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command)) as { ok: boolean; message?: string; reply?: Record<string, unknown> }
  if (!r?.ok) throw new Error(`vault: ${command.type}: ${r?.message}`)
  return r.reply!
}

/** Standalone: the made-up login, saved for the site of `url` (the native build's fake host lists it everywhere). */
async function seed(b: Browser, url: string) {
  if (!standalone) return
  const key = site(hostOf(url))
  if (!key || b.seeded.has(key)) return
  b.seeded.add(key)
  const origin = new URL(url).origin
  await device(b, { type: "device-item-save", kind: "login", name: key, fields: [{ name: "url", value: origin }, { name: "username", value: USERNAME }, { name: "password", value: PASSWORD }] })
}

async function closeBrowser(b: Browser) {
  await within(b.context.close(), 10_000, undefined)
  await rm(b.dir, { recursive: true, force: true })
}

const verdictsOf = (b: Browser) => b.worker.evaluate(() => (globalThis as unknown as { __verdicts: SweepResult["verdicts"] }).__verdicts) as Promise<NonNullable<SweepResult["verdicts"]>>
const resetVerdicts = (b: Browser) => b.worker.evaluate(() => void ((globalThis as unknown as { __verdicts: unknown[] }).__verdicts.length = 0))

/** The last thing each frame said: a frame that reported a form and then lost it says kind null. */
function lastWord(all: NonNullable<SweepResult["verdicts"]>) {
  const by = new Map<string, (typeof all)[number]>()
  for (const v of all) by.set(`${v.frame} ${v.url.split("#")[0]}`, v)
  return [...by.values()]
}
const serves = (v: { kind: string | null; roles: string[] }) => !!v.kind && v.kind !== "reset" && v.roles.some((r) => IDENT.has(r) || r === "password" || r === "new-password" || r === "otp")

// ---- The menu ---------------------------------------------------------------------

const menuFrame = (page: Page) => page.frames().find((f) => f.url().startsWith(`chrome-extension://${ID}/menu.html`)) ?? null

async function waitMenu(page: Page, ms: number): Promise<{ menu: Frame | null; rows: number }> {
  const end = Date.now() + ms
  let seen: Frame | null = null
  while (Date.now() < end) {
    const f = menuFrame(page)
    if (f) {
      seen = f
      const rows = await within(f.locator("button.row").count(), 800, 0)
      if (rows > 0) return { menu: f, rows }
    }
    await sleep(200)
  }
  return { menu: seen, rows: 0 }
}

/** The menu takes a pick once it has sat still and visible for half a second. */
async function settled(menu: Frame) {
  const el = await within(menu.frameElement(), 1000, null)
  const start = Date.now()
  let last = ""
  let still = Date.now()
  while (el && Date.now() - start < 5000 && Date.now() - still < 300) {
    const box = JSON.stringify(await within(el.boundingBox(), 500, null))
    if (box !== last) [last, still] = [box, Date.now()]
    await sleep(50)
  }
  await sleep(700)
}

async function pick(menu: Frame): Promise<"ok" | "failed" | "none"> {
  const row = menu.locator("button.row", { hasText: USERNAME }).first()
  if (!(await within(row.count(), 1000, 0))) return "none"
  await row.click({ timeout: 3000 }).catch(() => {})
  const end = Date.now() + 8000
  while (Date.now() < end) {
    if (await within(menu.locator(".pill.ok").count(), 500, 0)) return "ok"
    if (await within(menu.locator(".pill.failed").count(), 500, 0)) return "failed"
    if (menu.isDetached()) return "ok"
    await sleep(150)
  }
  return "failed"
}

// ---- One page ---------------------------------------------------------------------

/** The sign-in field to click: the detector's identifier, else its password or code box, else what the markup says. */
function chooseTarget(frames: CapturedFrame[]): { f: number; i: number } | null {
  const order: Array<(x: CapturedFrame["inputs"][number]) => boolean> = [
    (x) => !!x.role && IDENT.has(x.role) && x.role !== "phone",
    // Apple's "Email or Phone Number" is a phone box to the detector; its password box waits, collapsed, for step 2.
    (x) => x.role === "phone",
    (x) => x.role === "password",
    (x) => x.role === "new-password",
    (x) => x.role === "otp",
    (x) => x.type === "password",
    (x) => x.type === "email" || /username|email/.test(x.autocomplete),
  ]
  for (const test of order)
    for (let f = 0; f < frames.length; f++) {
      const hit = frames[f].inputs.find((x) => x.visible && test(x))
      if (hit) return { f, i: hit.i }
    }
  return null
}

async function inputHandle(frame: Frame, code: string, i: number): Promise<ElementHandle<HTMLInputElement> | null> {
  await within(frame.evaluate(`${code}\n;globalThis.__deadboltCorpus.run(); 0`), 3000, undefined)
  const h = await within(frame.evaluateHandle(`globalThis.__deadboltCorpus.input(${i})`), 2000, null)
  return (h?.asElement() as ElementHandle<HTMLInputElement> | null) ?? null
}

/** Visible inputs of a frame with their value, role and markup label, for checking where a fill went. */
async function valuesIn(frame: Frame, code: string) {
  return (await within(
    frame.evaluate(`${code}\n;(() => { const p = globalThis.__deadboltCorpus.run(); return p.inputs.filter((x) => x.visible).map((x) => ({ i: x.i, type: x.type, role: x.role, ac: x.autocomplete, name: x.name || x.id, value: globalThis.__deadboltCorpus.input(x.i).value })) })()`),
    4000,
    [],
  )) as Array<{ i: number; type: string; role: string | null; ac: string; name: string; value: string }>
}

/** Where a fill went: the values must sit in the identifier and password boxes and nowhere else. */
function judgeFill(rows: Awaited<ReturnType<typeof valuesIn>>, expect: { identifier: boolean; password: boolean }): { fill: FillOutcome; missed: string[]; stray: string[] } {
  const missed: string[] = []
  const stray: string[] = []
  const isPw = (r: (typeof rows)[number]) => r.type === "password" || r.role === "password" || r.role === "new-password"
  const isId = (r: (typeof rows)[number]) => (!!r.role && IDENT.has(r.role)) || (!isPw(r) && (r.type === "email" || /username|email/.test(r.ac)))
  let gotId = false
  let gotPw = false
  for (const r of rows) {
    const name = `${r.name || r.type}`
    if (r.value === USERNAME) {
      if (isId(r)) gotId = true
      else stray.push(`username → ${name}`)
    } else if (r.value === PASSWORD) {
      if (isPw(r)) gotPw = true
      else stray.push(`password → ${name}`)
    }
  }
  if (expect.identifier && !gotId) missed.push("identifier")
  if (expect.password && !gotPw) missed.push("password")
  const fill: FillOutcome = stray.length ? "wrong-field" : !gotId && !gotPw ? "nothing" : missed.length ? "partial" : "ok"
  return { fill, missed, stray }
}

/**
 * Why a fill may have stayed out of a field, from the page's side: how
 * transparent the field is through its ancestors (opacity and filter), what
 * is under its middle, and its size.
 */
async function diagnose(frame: Frame, code: string) {
  return (await within(
    frame.evaluate(`${code}\n;(() => { const p = globalThis.__deadboltCorpus.run(); return p.inputs.filter((x) => x.visible && x.role).map((x) => {
      const el = globalThis.__deadboltCorpus.input(x.i); const r = el.getBoundingClientRect(); let op = 1
      for (let n = el; n; n = n.parentElement) { const s = getComputedStyle(n); const f = /opacity\\(([\\d.]+)(%?)\\)/.exec(s.filter); op *= Number(s.opacity) * (f ? Number(f[1]) / (f[2] ? 100 : 1) : 1) }
      const hit = (el.getRootNode().elementFromPoint ? el.getRootNode() : document).elementFromPoint(r.left + r.width / 2, r.top + r.height / 2)
      const on = !!hit && (hit === el || el.contains(hit) || (hit.closest && hit.closest("label") && hit.closest("label").control === el))
      return { role: x.role, name: x.name || x.id, op: Math.round(op * 100) / 100, size: Math.round(r.width) + "x" + Math.round(r.height), top: on ? "field" : hit ? hit.tagName.toLowerCase() + (hit.className && typeof hit.className === "string" ? "." + hit.className.split(" ")[0] : "") : "none", ro: el.readOnly || el.disabled }
    }) })()`),
    4000,
    [],
  )) as Array<{ role: string; name: string; op: number; size: string; top: string; ro: boolean }>
}

/** Consent banners' own buttons (OneTrust, TrustArc, Didomi, Cookiebot, Usercentrics and plain ones), "reject" first. */
const BANNER_BUTTONS = [
  "#onetrust-reject-all-handler",
  "#onetrust-accept-btn-handler",
  "#truste-consent-required",
  "#didomi-notice-disagree-button",
  "#CybotCookiebotDialogBodyButtonDecline",
  "[data-testid=uc-deny-all-button]",
]
const BANNER_TEXT = /^(reject( all| optional)?( cookies)?|decline( all)?|deny( all)?|only (essential|necessary)( cookies)?|necessary cookies only|accept( all)?( cookies)?|agree|i agree|allow( all)?( cookies)?|got it|ok|okay|close)$/i

/** Answers a cookie or consent banner, if one shows: true if it clicked something. */
async function dismissBanner(page: Page): Promise<boolean> {
  for (const sel of BANNER_BUTTONS) {
    const b = page.locator(sel).first()
    if (await within(b.isVisible(), 800, false)) return b.click({ timeout: 2000 }).then(() => sleep(600).then(() => true), () => false)
  }
  const b = page.locator("[id*=cookie i] button, [class*=cookie i] button, [id*=consent i] button, [class*=consent i] button, [aria-label*=cookie i] button, [role=dialog] button").filter({ hasText: BANNER_TEXT }).first()
  if (await within(b.isVisible(), 800, false)) return b.click({ timeout: 2000 }).then(() => sleep(600).then(() => true), () => false)
  return false
}

async function shot(page: Page, name: string): Promise<string | undefined> {
  const file = `shots/${name}.png`
  const ok = await within(page.screenshot({ path: join(out, file), timeout: 5000, animations: "disabled" }).then(() => true), 6000, false)
  return ok ? file : undefined
}

const nameOf = (url: string) => {
  const u = new URL(url)
  return `${(u.hostname + u.pathname).replace(/[^a-z0-9.-]+/gi, "_").slice(0, 70)}-${Bun.hash(url).toString(36).slice(0, 6)}`
}

async function sweepPage(b: Browser, url: string, section: string, code: string): Promise<SweepResult> {
  const started = Date.now()
  const r: SweepResult = { url, section, status: "error", ms: 0, at: new Date().toISOString() }
  const clock = new Clock(started + timeoutMs)
  let page: Page | undefined
  const work = (async () => {
    await b.context.clearCookies()
    await resetVerdicts(b)
    await seed(b, url)
    page = await b.context.newPage()
    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: clock.cap(20_000) })
    } catch (e) {
      r.status = "unreachable"
      r.error = String(e).split("\n")[0].slice(0, 200)
      return
    }
    await settle(page, clock)
    let frames = await probeFrames(page, code, clock)
    if (frames[0]?.challenge) return void (r.status = "challenge")
    // One hop to a clear "Sign in" control when the page has no fields, as crawl.ts --urls does.
    if (!frames.some((f) => f.inputs.some((x) => x.visible && (x.type === "password" || x.role || x.type === "email")))) {
      const entries = ((await within(page.evaluate(`${code}\n;globalThis.__deadboltCorpus.entries()`), 3000, [])) as EntryCandidate[]).filter((c) => c.score >= 12)
      const hop = entries[0]
      if (hop) {
        if (hop.href) await within(page.goto(hop.href, { waitUntil: "domcontentloaded", timeout: clock.cap(15_000) }), clock.cap(16_000), null)
        else {
          const popup = b.context.waitForEvent("page", { timeout: 3000 }).catch(() => null)
          await within(page.evaluate(`globalThis.__deadboltCorpus.clickEntry(${hop.i})`), 2000, undefined)
          const opened = await Promise.race([popup, sleep(3000).then(() => null)])
          if (opened) page = opened
        }
        await settle(page, clock)
        frames = await probeFrames(page, code, clock)
        if (frames[0]?.challenge) return void (r.status = "challenge")
      }
    }
    r.finalUrl = page.url()
    if (standalone && site(hostOf(r.finalUrl)) !== site(hostOf(url))) {
      await seed(b, r.finalUrl)
      // The page asked for its logins before they were there: load it again.
      await within(page.reload({ waitUntil: "domcontentloaded", timeout: clock.cap(15_000) }), clock.cap(16_000), null)
      await settle(page, clock)
      frames = await probeFrames(page, code, clock)
    }
    const summary = summarize(frames)
    const otpOnly = !summary.hasPassword && !summary.hasIdentifier && summary.fields.some((f) => f.label?.role === "otp" || f.role === "otp")
    // An identifier box alone counts only on a page that's about signing in (as crawl.ts judges it): not a newsletter box.
    const signingIn = loginish(frames, page.url(), await within(page.title(), 2000, ""))
    r.page = summary.hasPassword ? "password" : summary.identifierFirst && signingIn ? "identifier" : otpOnly ? "otp" : null
    if (!r.page) {
      r.status = "no-fields"
      return
    }
    r.status = "ok"
    r.shadow = summary.shadowFields > 0
    // The content script scans every 750 ms: give it a moment to report.
    const end = Date.now() + Math.min(4000, clock.left() - 20_000)
    let verdicts = lastWord(await verdictsOf(b))
    while (!verdicts.some(serves) && Date.now() < end) {
      await sleep(400)
      verdicts = lastWord(await verdictsOf(b))
    }
    r.verdicts = verdicts.map((v) => ({ ...v, url: v.url.slice(0, 160) }))
    r.detected = verdicts.some(serves)

    const t = chooseTarget(frames)
    if (!t) return
    const fr = frames[t.f]
    const frame = frameOf(fr)
    if (!frame) return
    const fact = fr.inputs[t.i]
    const label = summary.fields.find((x) => x.frame === t.f && x.i === t.i)?.label?.role ?? null
    r.target = { label, role: fact.role, type: fact.type, frame: t.f }
    r.where = t.f === 0 ? "top" : site(hostOf(fr.url)) === site(hostOf(page.url())) ? "same-site frame" : "cross-site frame"
    // Before anything opens over them: which sign-in fields a person can see (a password box the page keeps transparent until a later step isn't one).
    const shown = (await diagnose(frame, code)).filter((d) => d.op >= 0.1 && d.top === "field")
    const el = await inputHandle(frame, code, t.i)
    if (!el) return
    await el.scrollIntoViewIfNeeded({ timeout: 2000 }).catch(() => {})
    const click = () => el.click({ timeout: 3000 }).then(() => true, () => false)
    r.clicked = await click()
    // Something over the field took the click: a cookie or consent banner, as a person would answer it.
    if (!r.clicked && (await dismissBanner(page))) {
      r.banner = true
      await el.scrollIntoViewIfNeeded({ timeout: 2000 }).catch(() => {})
      r.clicked = await click()
    }
    if (!r.clicked) await el.focus().catch(() => {})
    const { menu, rows } = await waitMenu(page, Math.min(6000, clock.left() - 12_000))
    r.menu = rows > 0 ? "rows" : menu ? "empty" : "none"
    r.menuRows = rows
    if (!menu || rows === 0) {
      r.fill = "not-tried"
      return
    }
    await settled(menu)
    const picked = await pick(menu)
    if (picked === "none") {
      r.fill = "not-tried"
      return
    }
    await sleep(400)
    const want = { identifier: shown.some((d) => IDENT.has(d.role) && d.role !== "phone"), password: shown.some((d) => d.role === "password") }
    const judged = judgeFill(await valuesIn(frame, code), want)
    r.fill = picked === "failed" && judged.fill === "nothing" ? "pill-failed" : judged.fill
    // A phone box with a mask takes no email address: the made-up login's username is one.
    if (r.fill === "nothing" && fact.role === "phone" && !want.password) r.fill = "phone-box"
    if (judged.missed.length) r.missed = judged.missed
    if (judged.stray.length) r.stray = judged.stray
    if (r.fill !== "ok") {
      r.diag = await diagnose(frame, code)
      r.foot = ((await within(menu.locator(".pill .pill-label").first().getAttribute("title"), 800, null)) || (await within(menu.locator("#foot").textContent(), 800, null)))?.trim() || undefined
    }

    // Step 2 of an identifier-first sign-in: Continue with the address the pick filled.
    if (!doStep2 || r.page !== "identifier") return
    if (r.fill !== "ok" || clock.left() < 25_000) {
      r.step2 = { outcome: "not-tried", detail: r.fill !== "ok" ? "step 1 did not fill" : "no time" }
      return
    }
    await within(frame.evaluate(`${code}\n;globalThis.__deadboltCorpus.run(); 0`), 3000, undefined)
    const submit = (await within(frame.evaluateHandle("globalThis.__deadboltCorpus.submitEl()"), 2000, null))?.asElement() as ElementHandle<Element> | null
    const popup = b.context.waitForEvent("page", { timeout: 8000 }).catch(() => null)
    let opened: Page | null = null
    void popup.then((p) => (opened = p))
    try {
      if (!submit) throw new Error("no submit")
      await submit.click({ timeout: 3000 })
    } catch {
      await el.press("Enter").catch(() => {})
    }
    // Wait for a password box anywhere (or a new page), then for the session's own fill.
    const until = Date.now() + Math.min(12_000, clock.left() - 12_000)
    let pw: { frame: Frame; i: number } | null = null
    while (Date.now() < until && !pw) {
      await sleep(600)
      if (opened) page = opened
      for (const f of page.frames().slice(0, 15)) {
        if (f.isDetached() || !/^https?:/.test(f.url())) continue
        const hit = (await within(
          f.evaluate(`${code}\n;(() => { const p = globalThis.__deadboltCorpus.run(); const x = p.inputs.find((x) => x.visible && x.type === "password"); return x ? x.i : -1 })()`),
          1500,
          -1,
        )) as number
        if (hit >= 0) {
          pw = { frame: f, i: hit }
          break
        }
      }
    }
    r.step2 = { outcome: "no-password-step", finalUrl: page.url() }
    if (!pw) return
    await sleep(2500)
    const pwEl = await inputHandle(pw.frame, code, pw.i)
    const filled = async () => (pwEl ? await within(pwEl.evaluate((e) => e.value), 1000, "") : "") === PASSWORD
    if (await filled()) return void (r.step2 = { outcome: "password-autofilled", finalUrl: page.url() })
    const role = (await valuesIn(pw.frame, code)).find((x) => x.i === pw!.i)?.role
    if (!role) {
      r.step2 = { outcome: "password-not-detected", finalUrl: page.url() }
      return
    }
    // An address the site doesn't know gets its sign-up: a new password there is the generator's, not a fill.
    if (role === "new-password") return void (r.step2 = { outcome: "sign-up", finalUrl: page.url() })
    await pwEl?.click({ timeout: 3000 }).catch(() => pwEl?.focus().catch(() => {}))
    const second = await waitMenu(page, 6000)
    if (!second.menu || !second.rows) return void (r.step2 = { outcome: "password-no-menu", detail: second.menu ? "empty menu" : undefined, finalUrl: page.url() })
    await settled(second.menu)
    await pick(second.menu)
    await sleep(400)
    r.step2 = { outcome: (await filled()) ? "password-picked" : "password-menu-no-fill", finalUrl: page.url() }
  })()

  const timedOut = await Promise.race([
    work.then(
      () => false,
      (e) => {
        r.status = "error"
        r.error = String(e).split("\n")[0].slice(0, 300)
        return false
      },
    ),
    sleep(timeoutMs).then(() => true),
  ])
  if (timedOut) {
    r.error = `timed out after ${timeoutMs / 1000}s`
    if (r.status !== "ok") r.status = "timeout"
  }
  const failed = r.status === "ok" && (!r.detected || r.menu !== "rows" || (r.fill && r.fill !== "ok") || (r.step2 && /no-menu|no-fill|not-detected/.test(r.step2.outcome)))
  if (page && (failed || r.status === "no-fields")) r.screenshot = await shot(page, nameOf(url))
  for (const p of b.context.pages()) if (p !== b.device) await within(p.close(), 3000, undefined)
  r.ms = Date.now() - started
  return r
}

// ---- The run ------------------------------------------------------------------------

async function sweep() {
  await mkdir(join(out, "shots"), { recursive: true })
  const built = await Bun.build({ entrypoints: [join(import.meta.dir, "probe.ts")], target: "browser", format: "iife" })
  if (!built.success) throw new AggregateError(built.logs, "probe bundle failed")
  const code = await built.outputs[0].text()
  const dist = await build()

  let section = ""
  const pages: Array<{ url: string; section: string }> = []
  for (const line of (await readFile(urlsFile, "utf8")).split(/\r?\n/).map((l) => l.trim())) {
    if (line.startsWith("#")) section = line.replace(/^#\s*/, "")
    else if (/^https?:\/\//.test(line) && (!only || line.includes(only))) pages.push({ url: line, section })
  }
  const resultsFile = join(out, "results.jsonl")
  const done = new Map<string, SweepResult>()
  if (existsSync(resultsFile))
    for (const line of (await readFile(resultsFile, "utf8")).split("\n"))
      if (line)
        try {
          const r = JSON.parse(line) as SweepResult
          done.set(r.url, r)
        } catch {}
  const redo = (r: SweepResult) => retry && (r.status === "error" || r.status === "timeout")
  const queue = pages.filter((p) => !done.has(p.url) || redo(done.get(p.url)!))
  console.log(`${pages.length} pages, ${pages.length - queue.length} already done, ${queue.length} to sweep (${standalone ? "standalone" : "native"}) -> ${out}`)

  const plain = await chromium.launch({ channel: "chromium", headless: true })
  const ua = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${plain.version()} Safari/537.36`
  await plain.close()

  let writes = Promise.resolve()
  let n = 0
  const total = queue.length
  const t0 = Date.now()
  const busy = new Set<string>()
  async function next() {
    while (queue.length) {
      const i = queue.findIndex((p) => !busy.has(site(hostOf(p.url))))
      if (i >= 0) return queue.splice(i, 1)[0]
      await sleep(200)
    }
    return undefined
  }
  async function worker() {
    let b: Browser | undefined
    let uses = 0
    for (let p = await next(); p; p = await next()) {
      const key = site(hostOf(p.url))
      busy.add(key)
      let r: SweepResult
      try {
        // A fresh browser every 25 pages, or after one stopped answering.
        if (b && uses >= 25) {
          await closeBrowser(b)
          b = undefined
          uses = 0
        }
        b ??= await launch(dist, ua)
        uses++
        r = await sweepPage(b, p.url, p.section, code)
        if (r.status === "timeout" || r.status === "error") {
          await closeBrowser(b)
          b = undefined
          uses = 0
        }
      } catch (e) {
        r = { url: p.url, section: p.section, status: "error", error: String(e).split("\n")[0].slice(0, 300), ms: 0, at: new Date().toISOString() }
        if (b) await closeBrowser(b)
        b = undefined
      }
      if (uses >= 25 && b) {
        await closeBrowser(b)
        b = undefined
        uses = 0
      }
      busy.delete(key)
      writes = writes.then(() => appendFile(resultsFile, JSON.stringify(r) + "\n"))
      n++
      const pace = ((Date.now() - t0) / n / 1000) * (total - n)
      console.log(
        `[${n}/${total}] ${p.url.slice(0, 80)} ${r.status}` +
          (r.page ? ` page=${r.page} det=${r.detected ? 1 : 0} where=${r.where ?? "-"} menu=${r.menu ?? "-"} fill=${r.fill ?? "-"}` : "") +
          (r.step2 ? ` step2=${r.step2.outcome}` : "") +
          (r.error ? ` (${r.error.slice(0, 80)})` : "") +
          ` ${(r.ms / 1000).toFixed(1)}s ~${Math.round(pace / 60)}m left`,
      )
    }
    if (b) await closeBrowser(b)
  }
  await Promise.all(Array.from({ length: concurrency }, worker))
  await writes
  console.log(`done in ${Math.round((Date.now() - t0) / 1000)}s; \`bun corpus/sweep.ts --report${standalone ? " --standalone" : ""}\` for the report`)
}

// ---- The report -------------------------------------------------------------------

async function load(dir: string): Promise<SweepResult[]> {
  const file = join(dir, "results.jsonl")
  if (!existsSync(file)) return []
  const by = new Map<string, SweepResult>()
  for (const line of (await readFile(file, "utf8")).split("\n"))
    if (line)
      try {
        const r = JSON.parse(line) as SweepResult
        by.set(r.url, r)
      } catch {}
  return [...by.values()]
}

/** One failure pattern per failing page, the first that applies. */
export function pattern(r: SweepResult): string | null {
  if (r.status !== "ok") return null
  if (!r.detected) {
    const t = r.target
    if (r.where === "cross-site frame") return "not detected: form in a cross-site frame"
    if (r.shadow) return "not detected: fields in shadow DOM"
    if (r.verdicts?.some((v) => v.kind === "reset")) return "not detected: judged a reset form"
    if (r.verdicts?.some((v) => v.kind)) return `not detected: judged ${r.verdicts.find((v) => v.kind)!.kind} without a served role`
    if (t && !t.role) return `not detected: ${r.page} page, ${t.label ?? t.type} field has no role`
    return `not detected: ${r.page} page`
  }
  if (r.menu !== "rows") {
    if (!r.target) return "detected, no field to click"
    if (r.clicked === false) return "menu none: the click didn't reach the field (a banner or overlay over it)"
    if (r.where === "cross-site frame") return "menu: field in a cross-site frame"
    if (r.where === "same-site frame") return `menu ${r.menu}: field in a same-site frame`
    if (!r.target.role) return `menu ${r.menu}: clicked ${r.target.label ?? r.target.type} field has no role`
    return `menu ${r.menu}: on a ${r.target.role} field`
  }
  if (r.fill && r.fill !== "ok" && r.fill !== "phone-box") return `fill ${r.fill}${r.missed ? ` (missed ${r.missed.join(", ")})` : ""}${r.stray ? ` (${r.stray[0]})` : ""}`
  if (r.step2 && /no-menu|no-fill|not-detected/.test(r.step2.outcome)) return `step 2: ${r.step2.outcome}`
  return null
}

const pct = (a: number, b: number) => (b ? `${((100 * a) / b).toFixed(1)}%` : "-")

export function rates(rs: SweepResult[]) {
  const ok = rs.filter((r) => r.status === "ok")
  const detected = ok.filter((r) => r.detected)
  const menu = ok.filter((r) => r.menu === "rows")
  const filled = ok.filter((r) => r.fill === "ok")
  const step2 = ok.filter((r) => r.step2 && r.step2.outcome !== "not-tried" && r.step2.outcome !== "no-password-step")
  const step2ok = step2.filter((r) => /autofilled|picked/.test(r.step2!.outcome))
  return { all: rs.length, ok: ok.length, detected: detected.length, menu: menu.length, filled: filled.length, step2: step2.length, step2ok: step2ok.length }
}

async function report() {
  const rs = await load(out)
  const against = arg("--against")
  const before = against ? await load(against) : []
  const count = (xs: string[]) => [...xs.reduce((m, x) => m.set(x, (m.get(x) ?? 0) + 1), new Map<string, number>())].sort((a, b) => b[1] - a[1])
  const lines: string[] = []
  const row = (name: string, now: string, then?: string) => lines.push(`| ${name} | ${then !== undefined ? `${then} | ` : ""}${now} |`)
  const a = rates(rs)
  const b = rates(before)
  lines.push(`# Real-site sweep (${standalone ? "standalone" : "native"})`, "", `${new Date().toISOString()} · ${rs.length} pages · \`${out}\``, "")
  lines.push(against ? "| Measure | Before | After |\n| --- | --- | --- |" : "| Measure | Value |\n| --- | --- |")
  const cell = (x: ReturnType<typeof rates>, k: keyof ReturnType<typeof rates>, of: keyof ReturnType<typeof rates>) => `${x[k]} (${pct(x[k], x[of])})`
  row("Pages swept", String(a.all), against ? String(b.all) : undefined)
  row("Sign-in fields on the page", cell(a, "ok", "all"), against ? cell(b, "ok", "all") : undefined)
  row("**Detected** (a frame reports a login form)", cell(a, "detected", "ok"), against ? cell(b, "detected", "ok") : undefined)
  row("**Menu opens with logins** on the field", cell(a, "menu", "ok"), against ? cell(b, "menu", "ok") : undefined)
  row("Fill lands in the right fields", cell(a, "filled", "ok"), against ? cell(b, "filled", "ok") : undefined)
  row("Step 2 reached a password box", String(a.step2), against ? String(b.step2) : undefined)
  row("Step 2 password filled (session or pick)", cell(a, "step2ok", "step2"), against ? cell(b, "step2ok", "step2") : undefined)
  lines.push("")
  lines.push("## Outcomes", "", "| Status | Pages |", "| --- | --- |")
  for (const [s, n] of count(rs.map((r) => r.status))) lines.push(`| ${s} | ${n} |`)
  lines.push("", "| Where the fields are | Pages | Detected | Menu |", "| --- | --- | --- | --- |")
  for (const [w] of count(rs.filter((r) => r.status === "ok").map((r) => r.where ?? "no target"))) {
    const g = rs.filter((r) => r.status === "ok" && (r.where ?? "no target") === w)
    lines.push(`| ${w} | ${g.length} | ${g.filter((r) => r.detected).length} | ${g.filter((r) => r.menu === "rows").length} |`)
  }
  lines.push("", "| Step 2 outcome | Pages |", "| --- | --- |")
  for (const [s, n] of count(rs.filter((r) => r.step2).map((r) => r.step2!.outcome))) lines.push(`| ${s} | ${n} |`)
  lines.push("", "## Failures by pattern", "", "| Pattern | Pages | Examples |", "| --- | --- | --- |")
  const failing = rs.map((r) => ({ r, p: pattern(r) })).filter((x) => x.p)
  for (const [p, n] of count(failing.map((x) => x.p!)))
    lines.push(`| ${p} | ${n} | ${failing.filter((x) => x.p === p).slice(0, 5).map((x) => hostOf(x.r.finalUrl ?? x.r.url)).join(", ")} |`)
  if (against) {
    const old = new Map(before.map((r) => [r.url, r]))
    const fixed = rs.filter((r) => !pattern(r) && r.status === "ok" && old.get(r.url) && pattern(old.get(r.url)!))
    const broke = rs.filter((r) => pattern(r) && old.get(r.url)?.status === "ok" && !pattern(old.get(r.url)!))
    lines.push("", `## Changed since \`${against}\``, "", `Fixed (${fixed.length}): ${fixed.map((r) => hostOf(r.finalUrl ?? r.url)).join(", ") || "none"}`, "", `Now failing (${broke.length}): ${broke.map((r) => `${hostOf(r.finalUrl ?? r.url)} (${pattern(r)})`).join(", ") || "none"}`)
  }
  lines.push("", "## Every failing page", "")
  for (const { r, p } of failing) lines.push(`- ${r.finalUrl?.slice(0, 120) ?? r.url} — ${p}${r.screenshot ? ` — \`${join(out, r.screenshot)}\`` : ""}`)
  await writeFile(join(out, "sweep.md"), lines.join("\n") + "\n")
  console.log(lines.slice(0, 14).join("\n"))
  console.log(`\n${join(out, "sweep.md")}`)
}

if (import.meta.main) await (process.argv.includes("--report") ? report() : sweep())
