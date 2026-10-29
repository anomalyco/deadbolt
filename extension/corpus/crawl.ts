// Crawl real sites' sign-in pages and run Deadbolt's form detector on them.
//
//   bun corpus/crawl.ts [--top 1000] [--sites file.txt] [--urls file.txt]
//                       [--step2] [--concurrency 6] [--timeout 30]
//                       [--out <dir>] [--retry]
//
// `--urls` opens each listed page directly instead of finding the sign-in
// page from the homepage (one hop to a clear "Sign in" link or button if the
// page has no fields). `--step2` also tries the second step of
// identifier-first sign-ins once per site (see step2.ts).
//
// For each site: the homepage, then at most two candidate sign-in pages (a
// "Sign in" link or button, else /login and /signin). On the page it ends on
// it saves a screenshot, the HTML, facts about every input and the
// detector's verdict, in every frame it can reach. It never types, submits
// or accepts anything. Results are appended to <out>/results.jsonl, and sites
// already there are skipped, so a run can be stopped and resumed (--retry
// redoes the ones that ended in an error or timeout).

import { chromium, type Browser, type BrowserContext, type Frame, type Page } from "playwright-core"
import { getDomain } from "tldts"
import { existsSync } from "node:fs"
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { coarse, visibleRows, type FieldRow } from "./labels"
import type { EntryCandidate, FrameProbe } from "./probe"
import { DEFAULT_OUT, loadSites, type Site } from "./sites"
import { step2, type Step2 } from "./step2"

const arg = (name: string) => {
  const i = process.argv.indexOf(name)
  return i > 0 ? process.argv[i + 1] : undefined
}
const out = arg("--out") ?? DEFAULT_OUT
const top = Number(arg("--top") ?? 1000)
const concurrency = Number(arg("--concurrency") ?? 6)
const urlsFile = arg("--urls")
const doStep2 = process.argv.includes("--step2")
const timeoutMs = Number(arg("--timeout") ?? (doStep2 ? 45 : 30)) * 1000
const retry = process.argv.includes("--retry")

/** Hosts other sites send their sign-in to. Following a link to one is allowed. */
export const AUTH_HOSTS =
  /(^|\.)(accounts\.google\.com|login\.microsoftonline\.com|login\.live\.com|appleid\.apple\.com|idmsa\.apple\.com|auth0\.com|okta\.com|oktapreview\.com|onelogin\.com|signin\.aws\.amazon\.com|id\.atlassian\.com|login\.yahoo\.com|b2clogin\.com|ciamlogin\.com|pingone\.com|duosecurity\.com|cognito\.\w+|amazoncognito\.com|login\.gov|id\.me|clerk\.accounts\.dev|stytch\.com|fusionauth\.io|keycloak\.\w+|accounts\.firefox\.com|passport\.yandex\.\w+)$/i
const LOGIN_URL = /log-?in|log_in|logon|sign-?in|sign_in|signon|auth|sso|saml|oauth|session|identifier|account/i
const LOGIN_TITLE = /sign ?in|log ?in|login|anmelden|connexion|iniciar|entrar|accedi|войти|ログイン|登录|로그인|account/i

export interface Visit {
  via: "home" | "direct" | "link" | "click" | "fallback"
  url: string
  finalUrl?: string
  status?: number
  text?: string
  loginish: boolean
  error?: string
}

export interface CapturedFrame extends FrameProbe {
  /** Where the frame sits in the screenshot. */
  offset: { x: number; y: number }
  crossOrigin: boolean
  /** The frame's size on the page (a subframe's element box). */
  size?: { w: number; h: number }
  /** The index of the frame it's in, among the captured frames (0: the top page; -1: one not captured). */
  parent?: number
  /** Its frame element's `sandbox` attribute, read from the page around it (null: none). */
  sandbox?: string | null
}

export interface Summary {
  hasPassword: boolean
  hasIdentifier: boolean
  identifierFirst: boolean
  primaryFrame: number
  kind: string | null
  /** Any frame's kind, when the primary frame's is null. */
  anyKind: string | null
  submitFound: boolean
  shadowFields: number
  shadowRoots: number
  passwordInIframe: boolean
  crossOriginLoginIframe: string | null
  ssoOnly: boolean
  ssoButtons: number
  fields: FieldRow[]
}

export interface SiteResult {
  rank: number
  domain: string
  /** The page opened directly (--urls). Results are keyed by this, else by domain. */
  target?: string
  status: "ok" | "no-entry" | "challenge" | "unreachable" | "timeout" | "error" | "skipped"
  error?: string
  visits: Visit[]
  page?: {
    url: string
    title: string
    host: string
    sameSite: boolean
    authHost: boolean
    via: Visit["via"]
    screenshot?: string
    html?: string
    /** The engine's Snapshot JSON for the page (crates/autofill). */
    snapshot?: string
    shot?: { w: number; h: number }
    frames: CapturedFrame[]
  }
  summary?: Summary
  step2?: Step2
  ms: number
  at: string
}

// ---- The probe bundle -----------------------------------------------------------

async function buildProbe(): Promise<string> {
  const built = await Bun.build({ entrypoints: [join(import.meta.dir, "probe.ts")], target: "browser", format: "iife" })
  if (!built.success) throw new AggregateError(built.logs, "probe bundle failed")
  const code = await built.outputs[0].text()
  await writeFile(join(out, "probe.js"), code)
  return code
}

// ---- Helpers --------------------------------------------------------------------

export const site = (host: string) => getDomain(host) ?? host
export const resultKey = (r: { target?: string; domain: string }) => r.target ?? r.domain
export const hostOf = (url: string) => {
  try {
    return new URL(url).hostname
  } catch {
    return ""
  }
}
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
export const within = <T>(p: Promise<T>, ms: number, fallback: T): Promise<T> =>
  Promise.race([p.catch(() => fallback), sleep(ms).then(() => fallback)])

export class Clock {
  constructor(private readonly end: number) {}
  left = () => Math.max(0, this.end - Date.now())
  cap = (ms: number) => Math.max(500, Math.min(ms, this.left() - 3000))
}

export async function settle(page: Page, clock: Clock) {
  await within(page.waitForLoadState("networkidle", { timeout: clock.cap(4000) }), clock.cap(4500), undefined)
  // Single-page apps often draw the form after the load settles.
  await within(page.waitForSelector("input[type=password], input[type=email], input[autocomplete~=username]", { timeout: clock.cap(2000), state: "attached" }), clock.cap(2500), null)
  await sleep(Math.min(700, clock.left()))
}

/** The live frame each probe came from (never serialized). */
const frameObjects = new WeakMap<CapturedFrame, Frame>()
export const frameOf = (f: CapturedFrame) => frameObjects.get(f)

export async function probeFrames(page: Page, code: string, clock: Clock): Promise<CapturedFrame[]> {
  const topOrigin = new URL(page.url()).origin
  const frames: CapturedFrame[] = []
  const scroll = await within(page.evaluate(() => ({ x: scrollX, y: scrollY })), 2000, { x: 0, y: 0 })
  const index = new Map<Frame, number>()
  for (const frame of page.frames().slice(0, 25)) {
    if (clock.left() < 2500) break
    if (frame.isDetached() || !/^https?:/.test(frame.url())) continue
    let offset = { x: 0, y: 0 }
    let size: CapturedFrame["size"]
    let sandbox: string | null = null
    if (frame !== page.mainFrame()) {
      const element = await within(frame.frameElement(), 1500, null)
      const box = element ? await within(element.boundingBox(), 1500, null) : null
      if (!element || !box || box.width < 10 || box.height < 10) continue
      offset = { x: Math.round(box.x + scroll.x), y: Math.round(box.y + scroll.y) }
      size = { w: Math.round(box.width), h: Math.round(box.height) }
      sandbox = await within(element.getAttribute("sandbox"), 1500, null)
    }
    const probe = await within(runProbe(frame, code), Math.min(4000, clock.left() - 1000), null)
    if (!probe) continue
    const up = frame.parentFrame()
    const captured = { ...probe, offset, crossOrigin: probe.origin !== topOrigin, ...(size ? { size, parent: up ? (index.get(up) ?? -1) : -1, sandbox } : {}) }
    index.set(frame, frames.length)
    frameObjects.set(captured, frame)
    frames.push(captured)
  }
  return frames
}

const runProbe = (frame: Frame, code: string) =>
  frame.evaluate(`${code}\n;globalThis.__deadboltCorpus.run()`) as Promise<FrameProbe>

const loginish = (frames: FrameProbe[], url: string, title: string) => {
  const inputs = frames.flatMap((f) => f.inputs.filter((i) => i.visible))
  if (inputs.some((i) => i.type === "password")) return true
  // The detector's word counts only with a field behind it: a "Sign in with Google" button frame has none.
  if (frames.some((f) => (f.kind === "login" || f.kind === "mfa") && f.inputs.some((i) => i.visible && i.role))) return true
  const ident = inputs.some((i) => i.type === "email" || /username|email/.test(i.autocomplete) || i.role === "username" || i.role === "email" || i.role === "phone")
  return ident && (LOGIN_URL.test(url) || LOGIN_TITLE.test(title))
}

export function summarize(frames: CapturedFrame[]): Summary {
  const rows = visibleRows(frames)
  const visible = (f: CapturedFrame) => f.inputs.filter((i) => i.visible)
  let primary = frames.findIndex((f) => visible(f).some((i) => i.type === "password"))
  if (primary < 0) {
    let best = 0
    frames.forEach((f, idx) => {
      const n = rows.filter((r) => r.frame === idx && coarse(r.label?.role) === "identifier").length
      if (n > best) {
        best = n
        primary = idx
      }
    })
  }
  if (primary < 0) primary = 0
  const hasPassword = frames.some((f) => visible(f).some((i) => i.type === "password"))
  const hasIdentifier = rows.some((r) => {
    const label = coarse(r.label?.role)
    return (label === "identifier" && r.label?.role !== "phone") || coarse(r.role) === "identifier"
  })
  const p = frames[primary]
  const loginFrame = frames.find((f) => f.crossOrigin && visible(f).some((i) => i.type === "password"))
  const anyInputs = rows.some((r) => r.label || r.role)
  return {
    hasPassword,
    hasIdentifier,
    identifierFirst: !hasPassword && hasIdentifier,
    primaryFrame: primary,
    kind: p?.kind ?? null,
    anyKind: frames.find((f) => f.kind)?.kind ?? null,
    submitFound: !!p?.submit,
    shadowFields: frames.reduce((n, f) => n + visible(f).filter((i) => i.inShadow).length, 0),
    shadowRoots: frames.reduce((n, f) => n + f.shadowRoots, 0),
    passwordInIframe: frames.some((f, i) => i > 0 && visible(f).some((x) => x.type === "password")),
    crossOriginLoginIframe: loginFrame ? new URL(loginFrame.url).hostname : null,
    ssoOnly: !anyInputs && frames.some((f) => f.ssoButtons.length > 0),
    ssoButtons: frames.reduce((n, f) => n + f.ssoButtons.length, 0),
    fields: rows,
  }
}

/** File name for a site's or page's screenshot and HTML. */
function shotName(s: Site): string {
  if (!s.target) return s.domain.replace(/[^a-z0-9.-]/gi, "_")
  const u = new URL(s.target)
  const slug = (u.hostname + u.pathname).replace(/[^a-z0-9.-]+/gi, "_").slice(0, 80)
  return `${slug}-${Bun.hash(s.target).toString(36).slice(0, 6)}`
}

// ---- One site -------------------------------------------------------------------

async function crawl(browser: Browser, ua: string, s: Site, code: string, step2Sites: Set<string>): Promise<SiteResult> {
  const started = Date.now()
  const result: SiteResult = { rank: s.rank, domain: s.domain, target: s.target, status: "error", visits: [], ms: 0, at: new Date().toISOString() }
  if (s.skip) return { ...result, status: "skipped", error: s.skip, ms: 0 }
  const clock = new Clock(started + timeoutMs)
  let context: BrowserContext | undefined
  const work = (async () => {
    context = await browser.newContext({
      viewport: { width: 1280, height: 800 },
      userAgent: ua,
      locale: "en-US",
      timezoneId: "America/New_York",
      extraHTTPHeaders: { "Accept-Language": "en-US,en;q=0.9" },
    })
    let page = await context.newPage()
    const home = s.target ?? `https://${s.domain}/`
    const visit: Visit = { via: s.target ? "direct" : "home", url: home, loginish: false }
    result.visits.push(visit)
    try {
      const res = await page.goto(home, { waitUntil: "domcontentloaded", timeout: clock.cap(15000) })
      visit.status = res?.status()
    } catch (e) {
      visit.error = String(e).split("\n")[0].slice(0, 200)
      result.status = "unreachable"
      result.error = visit.error
      return
    }
    await settle(page, clock)
    visit.finalUrl = page.url()
    let frames = await probeFrames(page, code, clock)
    let title = await within(page.title(), 2000, "")
    if (frames[0]?.challenge) {
      result.status = "challenge"
      await capture(page, frames, visit.via, clock)
      return
    }
    visit.loginish = loginish(frames, page.url(), title)
    let via: Visit["via"] = visit.via

    if (!visit.loginish) {
      const homeSite = site(hostOf(page.url()) || s.domain)
      const allowed = (url: string) => {
        const h = hostOf(url)
        return !!h && (site(h) === homeSite || site(h) === s.domain || AUTH_HOSTS.test(h))
      }
      const candidates = ((await within(page.evaluate(`${code}\n;globalThis.__deadboltCorpus.entries()`), 3000, [])) as EntryCandidate[]).filter(
        (c) => !c.href || allowed(c.href),
      )
      // Links are visited directly; a button that has no link is clicked, once, first.
      const seen = new Set<string>()
      const plan: Array<{ via: Visit["via"]; url: string; text?: string; click?: number }> = []
      // A listed page gets one hop, and only to a clear "Sign in" control.
      for (const c of s.target ? candidates.filter((c) => c.score >= 12).slice(0, 1) : candidates) {
        if (c.href) {
          const key = c.href.replace(/#.*$/, "")
          if (seen.has(key) || key === page.url().replace(/#.*$/, "")) continue
          seen.add(key)
          plan.push({ via: "link", url: c.href, text: c.text })
        } else if (plan.length === 0) plan.push({ via: "click", url: page.url(), text: c.text, click: c.i })
      }
      const base = page.url()
      if (!s.target) for (const path of ["/login", "/signin"]) plan.push({ via: "fallback", url: new URL(path, base).href })

      let tries = 0
      for (const step of plan) {
        if (tries >= (s.target ? 1 : 2) || clock.left() < 8000) break
        tries++
        const v: Visit = { via: step.via, url: step.url, text: step.text, loginish: false }
        result.visits.push(v)
        try {
          if (step.click !== undefined) {
            const popup = context.waitForEvent("page", { timeout: 3000 }).catch(() => null)
            const nav = page.waitForNavigation({ timeout: 3000 }).catch(() => null)
            await page.evaluate(`globalThis.__deadboltCorpus.clickEntry(${step.click})`)
            const opened = await Promise.race([popup, nav.then(() => null), sleep(3000).then(() => null)])
            if (opened) page = opened
          } else {
            const res = await page.goto(step.url, { waitUntil: "domcontentloaded", timeout: clock.cap(12000) })
            v.status = res?.status()
          }
        } catch (e) {
          v.error = String(e).split("\n")[0].slice(0, 200)
          continue
        }
        await settle(page, clock)
        v.finalUrl = page.url()
        const f = await probeFrames(page, code, clock)
        const t = await within(page.title(), 2000, "")
        if (f[0]?.challenge) {
          result.status = "challenge"
          await capture(page, f, step.via, clock)
          return
        }
        v.loginish = (v.status ?? 200) < 400 && loginish(f, page.url(), t)
        if (v.loginish) {
          frames = f
          title = t
          via = step.via
          break
        }
      }
      if (!result.visits.some((v) => v.loginish)) {
        result.status = "no-entry"
        // Keep the last page anyway, for the contact sheet.
        await capture(page, await probeFrames(page, code, clock), result.visits.at(-1)!.via, clock)
        return
      }
    }
    result.status = "ok"
    await capture(page, frames, via, clock)
    void title
    const key = site(s.domain)
    // Only where the detector says sign-in, as the extension would: never a newsletter or search box.
    if (doStep2 && result.summary?.identifierFirst && result.summary.kind === "login" && !step2Sites.has(key)) {
      if (clock.left() < 16000) result.step2 = { skipped: "no time" }
      else {
        step2Sites.add(key)
        result.step2 = await step2(context, page, frames, result.summary, code, clock, out, shotName(s)).catch((e) => ({ error: String(e).split("\n")[0].slice(0, 200) }))
      }
    }
  })()

  async function capture(page: Page, frames: CapturedFrame[], via: Visit["via"], clock: Clock) {
    const url = page.url()
    const host = hostOf(url)
    result.page = {
      url,
      title: await within(page.title(), 2000, ""),
      host,
      sameSite: site(host) === site(s.domain),
      authHost: AUTH_HOSTS.test(host),
      via,
      frames,
    }
    result.summary = summarize(frames)
    const name = shotName(s)
    // The engine's input, one file per page; results.jsonl keeps only the probe's facts.
    const snapshot = {
      url,
      title: result.page.title,
      // Index-aligned with page.frames: a frame whose collection failed is empty.
      frames: frames.map((f, i) => ({
        ...(f.snapshot ?? { url: f.url, title: "", dir: "ltr", headings: [], bodyHints: [], forms: [], fields: [] }),
        frameRef: String(i),
      })),
    }
    for (const f of frames) delete f.snapshot
    await writeFile(join(out, "snapshots", `${name}.json`), JSON.stringify(snapshot))
    result.page.snapshot = `snapshots/${name}.json`
    if (clock.left() > 1500) {
      const height = await within(page.evaluate(() => Math.min(2400, Math.max(document.documentElement.scrollHeight, innerHeight))), 1500, 800)
      const file = join(out, "shots", `${name}.png`)
      const ok = await within(
        page.screenshot({ path: file, fullPage: true, clip: { x: 0, y: 0, width: 1280, height }, timeout: clock.cap(6000), animations: "disabled" }).then(() => true),
        clock.cap(6500),
        false,
      )
      if (ok) {
        result.page.screenshot = `shots/${name}.png`
        result.page.shot = { w: 1280, h: height }
      }
    }
    if (clock.left() > 800) {
      const html = await within(page.content(), clock.cap(3000), "")
      if (html) {
        await writeFile(join(out, "html", `${name}.html`), html)
        result.page.html = `html/${name}.html`
      }
    }
  }

  const timedOut = await Promise.race([
    work.then(
      () => false,
      (e) => {
        result.status = "error"
        result.error = String(e).split("\n")[0].slice(0, 300)
        return false
      },
    ),
    sleep(timeoutMs).then(() => true),
  ])
  if (timedOut) {
    result.error = `timed out after ${timeoutMs / 1000}s` + (result.page ? " (page captured)" : "")
    // A page that was found and captured before the clock ran out still counts.
    if (!result.page || result.status === "error") result.status = "timeout"
  }
  await within((context as BrowserContext | undefined)?.close() ?? Promise.resolve(), 5000, undefined)
  result.ms = Date.now() - started
  return result
}

// ---- The run --------------------------------------------------------------------

async function main() {
  await mkdir(join(out, "shots"), { recursive: true })
  await mkdir(join(out, "html"), { recursive: true })
  await mkdir(join(out, "snapshots"), { recursive: true })
  const code = await buildProbe()
  const sites: Site[] = urlsFile
    ? (await readFile(urlsFile, "utf8"))
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => /^https?:\/\//.test(l))
        .map((target, i) => ({ rank: i + 1, domain: hostOf(target), target }))
    : await loadSites({ top, sitesFile: arg("--sites"), out })
  const resultsFile = join(out, "results.jsonl")
  const done = new Map<string, SiteResult>()
  const step2Sites = new Set<string>()
  if (existsSync(resultsFile)) {
    for (const line of (await readFile(resultsFile, "utf8")).split("\n")) {
      if (!line) continue
      try {
        const r = JSON.parse(line) as SiteResult
        done.set(resultKey(r), r)
        if (r.step2 && !r.step2.skipped) step2Sites.add(site(r.domain))
      } catch {}
    }
  }
  const redo = (r: SiteResult) => retry && (r.status === "error" || r.status === "timeout")
  const queue = sites.filter((s) => !done.has(resultKey(s)) || redo(done.get(resultKey(s))!))
  console.log(`${sites.length} ${urlsFile ? "pages" : "sites"}, ${sites.length - queue.length} already done, ${queue.length} to crawl -> ${out}`)

  let browser = await chromium.launch({ channel: "chromium", headless: true })
  const version = browser.version()
  const ua = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36`
  let writes = Promise.resolve()
  let n = 0
  const total = queue.length
  const t0 = Date.now()

  // Never two visits to the same site at once: take the next page whose site is free.
  const busy = new Set<string>()
  async function next(): Promise<Site | undefined> {
    while (queue.length) {
      const i = queue.findIndex((s) => !busy.has(site(s.domain)))
      if (i >= 0) return queue.splice(i, 1)[0]
      await sleep(200)
    }
    return undefined
  }

  async function worker() {
    for (let s = await next(); s; s = await next()) {
      busy.add(site(s.domain))
      if (!browser.isConnected()) browser = await chromium.launch({ channel: "chromium", headless: true })
      let r: SiteResult
      try {
        r = await crawl(browser, ua, s, code, step2Sites)
      } catch (e) {
        r = { rank: s.rank, domain: s.domain, target: s.target, status: "error", error: String(e).slice(0, 300), visits: [], ms: 0, at: new Date().toISOString() }
      }
      busy.delete(site(s.domain))
      const line = JSON.stringify(r) + "\n"
      writes = writes.then(() => appendFile(resultsFile, line))
      n++
      const sm = r.summary
      const pace = ((Date.now() - t0) / n / 1000) * (total - n)
      console.log(
        `[${n}/${total}] #${r.rank} ${r.target ?? r.domain} ${r.status}` +
          (sm ? ` kind=${sm.kind ?? "-"} pw=${sm.hasPassword ? 1 : 0} id=${sm.hasIdentifier ? 1 : 0}` : "") +
          (r.step2 ? ` step2=${r.step2.outcome ?? r.step2.skipped ?? r.step2.error}${r.step2.outcome ? `/${r.step2.dom}/${r.step2.origin}/${r.step2.carry}` : ""}` : "") +
          (r.error && r.status !== "skipped" ? ` (${r.error.slice(0, 80)})` : "") +
          ` ${(r.ms / 1000).toFixed(1)}s, ~${Math.round(pace / 60)}m left`,
      )
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker))
  await writes
  await browser.close().catch(() => {})
  console.log(`done in ${Math.round((Date.now() - t0) / 1000)}s; run \`bun corpus/report.ts\` for the report`)
}

if (import.meta.main) await main()
