// What the top page shows after a sign-in was submitted, for the background
// to judge whether it worked (see bg/save.ts). Text is read only to be
// matched in memory; the answer is booleans, never page text or values.
//
// Every walk is bounded in elements, characters and time, so a huge or
// hostile page costs a few milliseconds at most and can only make the answer
// less sure, which offers less.

import type { PageFacts, SurfaceKind } from "../messages"
import { LOGIN_URL, controlText, isVisible, type Field } from "./detect"
import { deepQueryAll, openRoots } from "./shadow"

const BUDGET_MS = 30
const MAX_ELEMENTS = 400
const MAX_TEXT = 200
const MAX_TEXT_NODES = 3000

/** Words that say a sign-in failed wherever they show, in English, French, German and Spanish. */
const FAILURE =
  /\b(incorrect|invalid|wrong|not recogni[sz]ed|(doesn't|does not|didn't|did not) match|too many|unable to (sign|log) ?in|(couldn't|could not|can't|cannot) (sign|log) ?in)\b|incorrecte|invalide|erron[ée]|trop de tentatives|falsch|ungültig|zu viele|incorrect[ao]|inválid[ao]|erróne[ao]|demasiados intentos/
/** Words that mean a failed sign-in only by the login form ("Your trial expired" elsewhere doesn't). */
const FAILURE_NEAR_FORM = /\b(try again|locked|failed|not found|expired)\b|réessayer|bloqué|fehlgeschlagen|erneut versuchen|gesperrt|inténtalo de nuevo|bloquead[ao]/
const SIGN_OUT = /^(sign ?out|log ?out|logout|signout|sign off|log off|se déconnecter|déconnexion|abmelden|ausloggen|cerrar sesión)\b/
const CHALLENGE_TITLE = /just a moment|attention required|verify you are human|are you a robot/i
const CHALLENGE_FRAME = /recaptcha\/(api2|enterprise)\/(anchor|bframe)|hcaptcha\.com|challenges\.cloudflare\.com|arkoselabs|funcaptcha/i
const CHALLENGE_BOX = "#challenge-form, #challenge-running, #challenge-stage, .cf-turnstile, .g-recaptcha, .h-captcha, #FunCaptcha"
/** Where sites put sign-in errors. `rror` and `nvalid` match either case of their first letter. */
const ERROR_BOX = "[role=alert], [aria-live=assertive], [id*=rror], [class*=rror], [id*=nvalid], [class*=nvalid]"
/** Boxes that hold all sorts of notices: they count only short, and by the login form. */
const NOTICE_BOX = "[aria-live=polite], [id*=lert], [class*=lert]"
/** A box with this much text or this many elements is a page section, not an error message. */
const MAX_BOX_TEXT = 2 * MAX_TEXT
const MAX_BOX_CHILDREN = 12
const CONTROLS = "a, button, [role=button], [role=menuitem], input[type=submit], input[type=button]"

const normalize = (text: string) => text.replace(/[\u2018\u2019]/g, "'").replace(/\s+/g, " ").trim().toLowerCase()

function inViewport(el: Element): boolean {
  if (!isVisible(el)) return false
  const r = el.getBoundingClientRect()
  return r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth
}

/** Text of an element, cut short before it's normalized. */
const textOf = (el: Element) => normalize(((el as HTMLElement).innerText ?? el.textContent ?? "").slice(0, MAX_TEXT))

/**
 * What the page shows now. `kind` and `fields` are the content script's last
 * scan; `username` the one just submitted, if any. Never throws: anything
 * that goes wrong reads as "not seen".
 */
export function pageFacts(kind: SurfaceKind | null, fields: Field[], username?: string): PageFacts {
  const deadline = performance.now() + BUDGET_MS
  const late = () => performance.now() > deadline
  const loginForm = kind === "login" || kind === "signup" || kind === "change-password"
  const passwords = fields.filter((f) => f.role === "password" || f.role === "new-password")
  const facts: PageFacts = {
    loginForm,
    passwordEmpty: loginForm && passwords.length > 0 && passwords.every((f) => !f.el.value),
    mfa: kind === "mfa",
    error: false,
    // A captcha box counts only on a login form; elsewhere it's a search or contact form's.
    challenge: loginForm && fields.some((f) => f.role === "captcha"),
    account: false,
    signOut: false,
    loginish: LOGIN_URL.test(location.pathname),
  }
  const step = (name: keyof PageFacts, check: () => boolean) => {
    if (facts[name] || late()) return
    try {
      facts[name] = check()
    } catch {}
  }
  const roots = (() => {
    try {
      return openRoots()
    } catch {
      return [document]
    }
  })()
  const form = fields.map((f) => f.owner.form).find(Boolean) ?? null
  step("error", () => fields.some((f) => f.el.getAttribute("aria-invalid") === "true" && isVisible(f.el)) || errorShown(roots, loginForm, form, late))
  step("challenge", () => challengeShown(roots, late))
  if (username) step("account", () => accountShown(roots, username, late))
  step("signOut", () => signOutShown(roots, late))
  return facts
}

/** Inside the login form, or beside it under the same parent. */
const nearForm = (el: Element, form: HTMLFormElement | null) => !!form && (form.contains(el) || !!form.parentElement?.contains(el))

function errorShown(roots: Array<Document | ShadowRoot>, loginForm: boolean, form: HTMLFormElement | null, late: () => boolean): boolean {
  const boxes = (selector: string) => deepQueryAll(selector, roots).slice(0, MAX_ELEMENTS)
  const looked = new Set<Element>()
  const failed = (el: Element, notice: boolean) => {
    if (looked.has(el)) return false
    looked.add(el)
    // Cheap tests first, before innerText makes the browser lay out the page.
    const length = el.textContent?.length ?? 0
    if (!length || length > (notice ? MAX_TEXT : MAX_BOX_TEXT) || el.childElementCount > MAX_BOX_CHILDREN) return false
    const byForm = loginForm || nearForm(el, form)
    if (notice && !byForm) return false
    const text = textOf(el)
    return !!text && (FAILURE.test(text) || (byForm && FAILURE_NEAR_FORM.test(text))) && inViewport(el)
  }
  for (const el of boxes(ERROR_BOX)) {
    if (late()) return false
    if (failed(el, false)) return true
  }
  for (const el of boxes(NOTICE_BOX)) {
    if (late()) return false
    if (failed(el, true)) return true
  }
  return false
}

function challengeShown(roots: Array<Document | ShadowRoot>, late: () => boolean): boolean {
  if (CHALLENGE_TITLE.test(document.title)) return true
  for (const frame of deepQueryAll<HTMLIFrameElement>("iframe", roots).slice(0, MAX_ELEMENTS)) {
    if (late()) return false
    // reCAPTCHA v3 and invisible widgets sit on ordinary pages too, signed-in ones included.
    if (CHALLENGE_FRAME.test(frame.src) && !/size=invisible/.test(frame.src) && isVisible(frame)) return true
  }
  return deepQueryAll(CHALLENGE_BOX, roots)
    .slice(0, 20)
    .some((el) => el.getAttribute("data-size") !== "invisible" && isVisible(el))
}

/** The submitted username, or an email's part before the @ when it's long enough to mean something. */
function accountShown(roots: Array<Document | ShadowRoot>, username: string, late: () => boolean): boolean {
  const full = normalize(username)
  if (full.length < 4) return false
  const local = full.includes("@") ? full.slice(0, full.indexOf("@")) : ""
  const needles = local.length >= 4 && local !== full ? [full, local] : [full]
  // Whole words only: "admin" isn't in "Administrator", nor "kitsune" in "kitsunes".
  const word = /[\p{L}\p{N}]/u
  const at = (t: string, n: string) => {
    for (let i = t.indexOf(n); i >= 0; i = t.indexOf(n, i + 1)) if (!word.test(t[i - 1] ?? "") && !word.test(t[i + n.length] ?? "")) return true
    return false
  }
  const has = (text: string) => {
    const t = normalize(text)
    return needles.some((n) => at(t, n))
  }
  for (const el of deepQueryAll("[aria-label], [title], img[alt]", roots).slice(0, MAX_ELEMENTS)) {
    if (late()) return false
    const label = [el.getAttribute("aria-label"), el.getAttribute("title"), el.getAttribute("alt")].filter(Boolean).join(" ").slice(0, MAX_TEXT)
    if (label && has(label) && isVisible(el)) return true
  }
  let seen = 0
  for (const root of roots) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (++seen > MAX_TEXT_NODES || late()) return false
      const text = node.nodeValue
      if (!text || text.length > 2000) continue
      const parent = node.parentElement
      if (parent && !parent.closest("script, style, noscript, template, input, textarea") && has(text) && isVisible(parent)) return true
    }
  }
  return false
}

function signOutShown(roots: Array<Document | ShadowRoot>, late: () => boolean): boolean {
  for (const el of deepQueryAll(CONTROLS, roots).slice(0, MAX_ELEMENTS)) {
    if (late()) return false
    const text = normalize(controlText(el))
    if (text && text.length <= 40 && SIGN_OUT.test(text) && isVisible(el)) return true
  }
  return false
}
