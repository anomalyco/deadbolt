// Step 2 of an identifier-first sign-in (crawl.ts --step2): type a reserved,
// undeliverable address into the identifier field, press the detected
// submit control once, and record what the site shows next. Nothing on step
// 2 is ever typed into or submitted, and a site gets one attempt.

import type { BrowserContext, ElementHandle, Frame, Page } from "playwright-core"
import { join } from "node:path"
import { AUTH_HOSTS, frameOf, hostOf, probeFrames, settle, site, sleep, summarize, within, type CapturedFrame, type Clock, type Summary } from "./crawl"
import { coarse } from "./labels"

/** RFC 2606 reserved domain: no mailbox can exist there. Never a real address, never a password. */
export const PROBE_ADDRESS = "deadbolt.corpus@example.com"

export type Step2Outcome =
  | "password"
  | "otp"
  | "passkey"
  | "magic-link"
  | "sign-up"
  | "invalid-address"
  | "not-found/error"
  | "challenge"
  | "sso-redirect"
  | "other-change"
  | "no-change"

export interface Step2 {
  outcome?: Step2Outcome
  skipped?: string
  field?: { role: string | null; type: string; frame: "top" | "iframe"; by: "detector" | "markup" }
  typed?: boolean
  action?: "click" | "enter"
  submitText?: string
  /** How step 2 relates to step 1's document. */
  dom?: "field kept" | "replaced in place" | "navigated" | "popup" | "iframe"
  origin?: "same-origin" | "same-site" | "cross-site"
  /** The address bar changed, with or without a new document. */
  urlChanged?: boolean
  finalUrl?: string
  finalHost?: string
  /** Where the typed address is on step 2. */
  carry?: "editable field" | "read-only field" | "hidden field" | "shown as text" | "re-asked" | "not shown"
  passwordWhere?: "top" | "same-origin iframe" | "cross-origin iframe"
  kind?: string | null
  passkeyCalls?: number
  /** Short new lines of text that decided the outcome. */
  evidence?: string[]
  screenshot?: string
  frames?: CapturedFrame[]
  summary?: Summary
  error?: string
  ms?: number
}

const CHALLENGE_SRC = /recaptcha\/(api2|enterprise)\/bframe|hcaptcha\.com\/.*(challenge|frame=challenge)|challenges\.cloudflare\.com|arkoselabs|funcaptcha|captcha-delivery|px-cdn|perimeterx|geetest/i
const MAGIC = /check your (e-?mail|inbox)|we('ve| have)? (just )?sent (you )?(an? )?(e-?mail|link|message)|sent (a|an) (sign-?in|log-?in|login|magic|verification)? ?(link|e-?mail)|magic link|link to sign in|email.{0,40}link/i
const PASSKEY = /\bpasskey\b|face id|touch id|windows hello|security key|use your (device|phone)/i
const SIGNUP = /create (an|your) account|let'?s (create|get you|set up)|looks like you'?re new|new to \w+|set up your account|finish (creating|signing up)|sign up|join \w+|complete your (profile|registration)/i
const NOT_FOUND =
  /ingen konto|kein(en)? konto|aucun compte|no (encontramos|existe)|nessun account|geen account|nie znaleziono|не найден|(couldn'?t|could not|can'?t|cannot|unable to) find|no account|not (registered|recogni[sz]ed|found|valid)|doesn'?t exist|does not exist|isn'?t registered|invalid|enter a valid|please (enter|provide|use) (a |an |your )?(valid|correct|work|business)|don'?t recognize|try again|something went wrong|not allowed|not supported|error/i
const CHALLENGE_TEXT =
  /verify (that )?you('re| are) (a )?human|are you a robot|security check|complete the (captcha|puzzle)|press (and|&) hold|unusual (traffic|activity)|browser or app may not be secure|try using a different browser|automated (queries|requests)/i
/** A short heading or label that asks for the password, before its box is visible. */
const PASSWORD_TEXT = /^(enter (your )?)?(password|passcode|passwort|kennwort|contraseña|mot de passe|senha|wachtwoord|lösenord|hasło|пароль|パスワード|密码)\s*[:*]?$/i
/** The site turned the crawler away rather than answering about the address. */
const BLOCKED = /network address|ip address|access (is )?denied|been blocked|request (was )?blocked|unusual activity/i

/**
 * What an otherwise unexplained change is, from its new lines of text and
 * where it ended. Also applied by report.ts to results that only kept a few
 * lines as evidence.
 */
export function refine(lines: string[], finalHost: string, startHost: string, summary: Summary | undefined): Step2Outcome | undefined {
  if (lines.some((l) => BLOCKED.test(l))) return "challenge"
  if (lines.some((l) => l.length <= 40 && PASSWORD_TEXT.test(l))) return "password"
  if (lines.some((l) => NOT_FOUND.test(l))) return "not-found/error"
  if (finalHost && finalHost !== startHost && !summary?.hasIdentifier && !summary?.hasPassword) return "sso-redirect"
  return undefined
}

/** The site refused the address itself (example.com is reserved, so some sites reject the domain). */
const INVALID_ADDRESS = /(isn'?t|is not|not) a valid (e-?mail|address|domain)|valid e-?mail|e-?mail (address )?(is )?(invalid|not valid)|invalid e-?mail|e-?mail domain|domain (is )?not (allowed|supported|valid)|use (a |your )?(work|business|company) e-?mail/i

const CREDENTIALS_HOOK = `(() => {
  const c = navigator.credentials
  if (!c || c.__deadboltHooked) return
  c.__deadboltHooked = true
  const get = c.get.bind(c)
  window.__deadboltPasskeyCalls = 0
  c.get = (options) => {
    if (options && options.publicKey && options.mediation !== "conditional") window.__deadboltPasskeyCalls++
    return get(options)
  }
})()`

type Sig = { password: number; otp: number; inputs: number; text: number; redirecting?: boolean }

async function signatures(page: Page): Promise<Sig[]> {
  const out: Sig[] = []
  for (const f of page.frames().slice(0, 15)) {
    if (f.isDetached() || !/^https?:/.test(f.url())) continue
    const s = await within(f.evaluate("globalThis.__deadboltCorpus ? globalThis.__deadboltCorpus.signature() : null") as Promise<Sig | null>, 800, null)
    if (s) out.push(s)
  }
  return out
}

const total = (sigs: Sig[]) =>
  sigs.reduce(
    (a, s) => ({ password: a.password + s.password, otp: a.otp + s.otp, inputs: a.inputs + s.inputs, text: a.text + s.text, redirecting: a.redirecting || !!s.redirecting }),
    { password: 0, otp: 0, inputs: 0, text: 0, redirecting: false } as Sig,
  )

async function linesOf(page: Page): Promise<string[]> {
  const out: string[] = []
  for (const f of page.frames().slice(0, 15)) {
    if (f.isDetached() || !/^https?:/.test(f.url())) continue
    const lines = await within(f.evaluate("globalThis.__deadboltCorpus ? globalThis.__deadboltCorpus.visibleLines() : []") as Promise<string[]>, 1500, [])
    out.push(...lines)
  }
  return out
}

/**
 * Runs step 2 from the page as step 1 left it. `frames` is step 1's probe.
 * Returns the new page if step 2 opened a popup.
 */
export async function step2(
  context: BrowserContext,
  start: Page,
  frames: CapturedFrame[],
  step1: Summary,
  code: string,
  clock: Clock,
  out: string,
  name: string,
): Promise<Step2> {
  const t0 = Date.now()
  const result: Step2 = {}
  let page = start

  // The identifier field: the detector's choice, else what the markup says.
  const fr = frames[step1.primaryFrame]
  const frame = fr && frameOf(fr)
  if (!fr || !frame) return { skipped: "no frame" }
  const rows = step1.fields.filter((f) => f.frame === step1.primaryFrame)
  const pick =
    rows.find((r) => r.role === "email") ??
    rows.find((r) => r.role === "username") ??
    rows.find((r) => !r.role && (r.label?.role === "email" || r.label?.role === "username"))
  if (!pick) return { skipped: rows.some((r) => r.role === "phone") ? "phone only" : "no identifier field" }
  const input = fr.inputs[pick.i]
  result.field = { role: pick.role, type: input.type, frame: frame === page.mainFrame() ? "top" : "iframe", by: pick.role ? "detector" : "markup" }
  if (input.type === "tel" || input.type === "number") return { ...result, skipped: "phone only" }

  // Refresh the probe in that frame so its input numbering is current.
  await frame.evaluate(`${code}\n;globalThis.__deadboltCorpus.run(); 0`)
  const el = (await frame.evaluateHandle(`globalThis.__deadboltCorpus.input(${pick.i})`)).asElement() as ElementHandle<HTMLInputElement> | null
  if (!el) return { ...result, skipped: "field gone" }
  const submit = (await frame.evaluateHandle("globalThis.__deadboltCorpus.submitEl()")).asElement() as ElementHandle<Element> | null
  if (submit) result.submitText = fr.submit?.text

  const before = { url: page.url(), lines: new Set(await linesOf(page)), sig: total(await signatures(page)) }
  await context.addInitScript(CREDENTIALS_HOOK)
  for (const f of page.frames()) await within(f.evaluate(`${CREDENTIALS_HOOK}; window.__deadboltStep1 = true`), 800, undefined)

  // Type like a person: focus, then key by key.
  try {
    await el.click({ timeout: 3000 }).catch(() => el.focus())
    await el.fill("")
    await el.type(PROBE_ADDRESS, { delay: 15 })
    result.typed = (await el.evaluate((e) => e.value.trim().toLowerCase())) === PROBE_ADDRESS
  } catch (e) {
    return { ...result, skipped: "could not type", error: String(e).split("\n")[0].slice(0, 160) }
  }
  await sleep(300)

  const popup = context.waitForEvent("page", { timeout: 8000 }).catch(() => null)
  let navigated = false
  const onNav = (f: Frame) => {
    if (f === page.mainFrame()) navigated = true
  }
  page.on("framenavigated", onNav)
  // The last page the top frame asked for, for redirects that end on an error page.
  let lastNav = ""
  page.on("request", (r) => {
    if (r.isNavigationRequest() && r.frame() === page.mainFrame()) lastNav = r.url()
  })
  try {
    if (submit) {
      await submit.click({ timeout: 3000 })
      result.action = "click"
    } else throw new Error("no submit")
  } catch {
    await el.press("Enter").catch(() => {})
    result.action = "enter"
  }

  // Wait up to ~8 s for a new page, a password or code box, or the page to settle into something new.
  const until = Date.now() + Math.min(8000, clock.left() - 6000)
  let stableSince = 0
  let last = ""
  let opened = null as Page | null
  void popup.then((p) => (opened = p))
  while (Date.now() < until) {
    await sleep(500)
    if (opened) break
    if (navigated) {
      await within(page.waitForLoadState("domcontentloaded", { timeout: 4000 }), 4500, undefined)
      break
    }
    const sig = total(await signatures(page))
    if (sig.password > before.sig.password || sig.otp > before.sig.otp) break
    // "Taking you to your organization's sign-in page": keep waiting for the navigation.
    if (sig.redirecting && !before.sig.redirecting) continue
    const key = JSON.stringify(sig)
    if (key !== JSON.stringify(before.sig)) {
      if (key === last && Date.now() - stableSince > 1500) break
      if (key !== last) {
        last = key
        stableSince = Date.now()
      }
    }
  }
  page.off("framenavigated", onNav)
  if (opened) {
    page = opened
    result.dom = "popup"
  }
  await settle(page, clock)

  const step2Frames = await probeFrames(page, code, clock)
  const summary = summarize(step2Frames)
  result.frames = step2Frames
  result.summary = summary
  result.kind = summary.kind
  result.finalUrl = page.url().startsWith("chrome-error:") && lastNav ? lastNav : page.url()
  result.finalHost = hostOf(result.finalUrl)
  result.urlChanged = result.finalUrl !== before.url
  const sameDoc = (await within(page.evaluate("window.__deadboltStep1 === true") as Promise<boolean>, 1500, false)) && !result.dom
  const fromOrigin = new URL(before.url).origin
  result.origin = new URL(result.finalUrl).origin === fromOrigin ? "same-origin" : site(result.finalHost) === site(hostOf(before.url)) ? "same-site" : "cross-site"
  result.passkeyCalls = Number(await within(page.evaluate("window.__deadboltPasskeyCalls || 0") as Promise<number>, 1000, 0))

  // Where step 2 asks for the password, if it does.
  const pwFrame = step2Frames.findIndex((f) => f.inputs.some((i) => i.visible && i.type === "password"))
  if (pwFrame >= 0) result.passwordWhere = pwFrame === 0 ? "top" : step2Frames[pwFrame].crossOrigin ? "cross-origin iframe" : "same-origin iframe"

  if (!result.dom) {
    const connected = await within(el.evaluate((e) => e.isConnected && e.getClientRects().length > 0), 1000, false)
    if (!sameDoc) result.dom = "navigated"
    else if (pwFrame > 0 && step2Frames[pwFrame].url !== fr.url) result.dom = "iframe"
    else result.dom = connected ? "field kept" : "replaced in place"
  }

  // Is the address carried to step 2?
  const carry = { editable: 0, readonly: 0, hidden: 0, text: false }
  for (const f of page.frames().slice(0, 15)) {
    if (f.isDetached() || !/^https?:/.test(f.url())) continue
    const c = await within(f.evaluate(`globalThis.__deadboltCorpus ? globalThis.__deadboltCorpus.carried(${JSON.stringify(PROBE_ADDRESS)}) : null`) as Promise<typeof carry | null>, 1500, null)
    if (!c) continue
    carry.editable += c.editable
    carry.readonly += c.readonly
    carry.hidden += c.hidden
    carry.text ||= c.text
  }
  const reAsked = summary.fields.some((f) => coarse(f.role) === "identifier" && f.role !== "phone")
  result.carry =
    carry.readonly > 0
      ? "read-only field"
      : carry.text && carry.editable === 0
        ? "shown as text"
        : carry.editable > 0
          ? "editable field"
          : carry.hidden > 0
            ? "hidden field"
            : reAsked
              ? "re-asked"
              : "not shown"
  // A kept field with the address in it is just the same form, still showing it.

  // What's new on the page.
  const fresh = (await linesOf(page)).filter((l) => !before.lines.has(l) && !l.toLowerCase().includes(PROBE_ADDRESS))
  const text = fresh.join("\n")
  const hit = (re: RegExp) => fresh.filter((l) => re.test(l)).slice(0, 3).map((l) => l.slice(0, 140))
  const visibleChallenge = step2Frames.some((f) => f.iframes.some((i) => i.visible && i.rect.w > 100 && i.rect.h > 100 && CHALLENGE_SRC.test(i.src))) || step2Frames.some((f) => f.challenge)
  const otp = summary.fields.some((f) => f.role === "otp" || f.label?.role === "otp")
  const changed = page.url() !== before.url || !sameDoc || fresh.length > 0 || JSON.stringify(total(await signatures(page))) !== JSON.stringify(before.sig)
  const offSite = site(result.finalHost) !== site(hostOf(before.url)) || (AUTH_HOSTS.test(result.finalHost) && !AUTH_HOSTS.test(hostOf(before.url)))

  const decide = (o: Step2Outcome, ev: string[] = []) => {
    result.outcome = o
    result.evidence = ev
  }
  if (visibleChallenge || CHALLENGE_TEXT.test(text)) decide("challenge", hit(CHALLENGE_TEXT))
  else if (pwFrame >= 0 && summary.fields.some((f) => f.role === "new-password") && !summary.fields.some((f) => f.role === "password")) decide("sign-up", hit(SIGNUP))
  else if (pwFrame >= 0) decide("password")
  else if (otp) decide("otp")
  else if (result.passkeyCalls > 0 || (PASSKEY.test(text) && !NOT_FOUND.test(text))) decide("passkey", hit(PASSKEY))
  else if (MAGIC.test(text)) decide("magic-link", hit(MAGIC))
  else if (offSite && !summary.hasIdentifier) decide("sso-redirect", [result.finalHost])
  else if (SIGNUP.test(text) && !NOT_FOUND.test(text)) decide("sign-up", hit(SIGNUP))
  else if (INVALID_ADDRESS.test(text)) decide("invalid-address", hit(INVALID_ADDRESS))
  else if (NOT_FOUND.test(text)) decide("not-found/error", hit(NOT_FOUND))
  else if (await within(el.evaluate((e) => e.getAttribute("aria-invalid") === "true"), 800, false)) decide("not-found/error", fresh.slice(0, 3).map((l) => l.slice(0, 140)))
  else if (offSite) decide("sso-redirect", [result.finalHost])
  else if (/taking you to|redirecting/i.test(text)) decide("sso-redirect", [lastNav ? hostOf(lastNav) : result.finalHost, ...hit(/taking you to|redirecting/i)])
  else if (changed) {
    const refined = refine(fresh, result.finalHost, hostOf(before.url), summary)
    decide(refined ?? "other-change", fresh.filter((l) => !refined || l.length <= 140).slice(0, 3).map((l) => l.slice(0, 140)))
  }
  else decide("no-change")

  if (clock.left() > 1500) {
    const file = `shots/${name}.step2.png`
    const ok = await within(page.screenshot({ path: join(out, file), timeout: clock.cap(4000), animations: "disabled" }).then(() => true), clock.cap(4500), false)
    if (ok) result.screenshot = file
  }
  result.ms = Date.now() - t0
  return result
}
