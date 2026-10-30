// Login-form detection. Ported from Foyer (github.com/R44VC0RP/foyer,
// src/detect.ts, by Ryan Vogel). Deadbolt keeps the field and form scoring
// and the sign-in-provider buttons, and drops what served Foyer's sign-in
// recipes: selectors, passkey and magic-link controls.
//
// Fields and forms are scored with weighted clues (see clues.ts): labels,
// placeholders, ids, autocomplete, input type, neighbouring fields and the
// text around the form all add or subtract points. Text is read only to be
// matched in memory; nothing here leaves the page.

import type { FieldRole, SurfaceKind } from "../messages"
import { bestRole, FIELD_THRESHOLD, FORM_KINDS, hasPhrase, providerFromLabel, scoreField, scoreFormText, squash, words, type FieldFacts, type FormKind, type Provider } from "./clues"
import { deepQueryAll, openRoots } from "./shadow"

export const LOGIN_URL = /log-?in|log_in|logon|sign-?in|sign_in|signon|auth|sso|saml|oauth|session|identifier|challenge|mfa|2fa|two-factor|verify|webauthn|passkey/i
const SIGNUP_URL = /sign-?up|sign_up|register|registration|join|create-account|onboard/i
const RESET_URL = /forgot|reset|recover/i
const CHANGE_PASSWORD_URL = /change-?password|password-?change|update-?password|settings\/security/i
const SUBMIT_TEXT = /^\s*(sign ?in|log ?in|login|sign ?on|continue|next|submit|verify|confirm|go)\b/i
const PROCEED_TEXT = /^\s*(continue|next)\b/i
const AUTH_HREF = /oauth|auth|login|signin|sign_in|sso|saml|connect/i
const PROVIDER_ATTR = /\b(google|apple|microsoft|github|facebook|twitter|linkedin|gitlab|slack|discord|amazon|okta)\b/i
/** Embedded provider widgets: Google Identity Services and Sign in with Apple. */
const PROVIDER_WIDGETS = ".g_id_signin, #g_id_onload, iframe[src*='accounts.google.com/gsi'], #appleid-signin, iframe[src*='appleid.apple.com']"

const CLICKABLE = "a[href], button, [role=button], input[type=submit], input[type=button], input[type=image]"
const SKIP_INPUT_TYPES = new Set([
  "hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file", "range", "color", "date",
  "datetime-local", "month", "week", "time", "search",
])

/**
 * Marks sites put on fields, forms or <body> to keep password managers away:
 * 1Password's, LastPass's, Bitwarden's, Dashlane's and Deadbolt's own.
 */
function optedOut(el: Element | null | undefined): boolean {
  if (!el) return false
  const on = (name: string) => el.hasAttribute(name) && el.getAttribute(name)?.toLowerCase() !== "false"
  return (
    on("data-1p-ignore") ||
    on("data-op-ignore") ||
    on("data-bwignore") ||
    on("data-deadbolt-ignore") ||
    el.getAttribute("data-lpignore")?.toLowerCase() === "true" ||
    el.getAttribute("data-form-type")?.toLowerCase() === "other"
  )
}

/** An input, select or textarea: what identity and payment forms are made of. */
export type FormControl = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement

/** The site asked password managers to leave this field alone, on it, its form or the page. */
export const ignored = (el: FormControl) => optedOut(el) || optedOut(el.form ?? el.closest("form")) || optedOut(document.body)

/** Minimum score for the page to count as a given kind of form. */
const FORM_THRESHOLD = 3

export function isVisible(el: Element): boolean {
  const rect = el.getBoundingClientRect()
  if (rect.width < 2 || rect.height < 2) return false
  const style = getComputedStyle(el)
  return style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity || 1) > 0.05
}

const innerText = (el: Element | null | undefined) => ((el as HTMLElement | null)?.innerText ?? el?.textContent ?? "").trim()

/** Label of a button. Matched against vocabularies only, never stored. */
export function controlText(el: Element): string {
  const input = el instanceof HTMLInputElement && (el.type === "submit" || el.type === "button") ? el.value : ""
  const text = el.getAttribute("aria-label") || innerText(el) || input || el.getAttribute("title") || ""
  return text.replace(/\s+/g, " ").trim().slice(0, 120)
}

// ---- Field facts ---------------------------------------------------------------

/** Closest preceding text when a field has no <label>, e.g. a <span> above it. */
function nearbyText(el: Element): string {
  let node: Element | null = el
  for (let depth = 0; node && depth < 3; depth++) {
    let sibling = node.previousElementSibling
    for (let i = 0; sibling && i < 2; i++, sibling = sibling.previousElementSibling) {
      if (sibling.matches("input, select, textarea") || sibling.querySelector("input, select, textarea")) return ""
      const text = innerText(sibling)
      if (text) return text.length <= 80 ? text : ""
    }
    node = node.parentElement
  }
  return ""
}

/** A field's labels, aria label, placeholder and title, or the text just before it. */
export function labelText(el: FormControl): string {
  const parts: string[] = []
  for (const label of Array.from(el.labels ?? [])) parts.push(innerText(label))
  const labelledBy = el.getAttribute("aria-labelledby")
  const root = el.getRootNode() as Document | ShadowRoot
  if (labelledBy) for (const id of labelledBy.split(/\s+/)) parts.push(innerText(root.getElementById?.(id)))
  const placeholder = el.getAttribute("placeholder") ?? ""
  parts.push(el.getAttribute("aria-label") ?? "", placeholder, el.getAttribute("title") ?? "")
  if (!parts.some(Boolean)) parts.push(nearbyText(el))
  // "you@example.com" as a placeholder means an email box.
  if (placeholder.includes("@")) parts.push("email")
  return parts.filter(Boolean).join(" ").slice(0, 300)
}

function factsFor(el: HTMLInputElement): FieldFacts {
  const code = [el.id, el.name, el.getAttribute("class"), el.getAttribute("data-testid"), el.getAttribute("data-test")]
    .filter((v): v is string => typeof v === "string" && v.length > 0)
    .join(" ")
  const label = labelText(el)
  return {
    type: (el.getAttribute("type") || "text").toLowerCase(),
    autocomplete: (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/).filter(Boolean),
    display: words(label),
    question: /[?？]\s*$/.test(Array.from(el.labels ?? [], (l) => innerText(l)).join(" ") || label),
    code: squash(words(code.slice(0, 300))),
    maxLength: el.maxLength > 0 ? el.maxLength : 0,
    inputMode: (el.getAttribute("inputmode") || "").toLowerCase(),
  }
}

function eligible(el: Element): el is HTMLInputElement {
  return el instanceof HTMLInputElement && !SKIP_INPUT_TYPES.has((el.getAttribute("type") || "text").toLowerCase())
}

/** Role of a single field on its own, without page context. */
export function classifyInput(el: Element): FieldRole | null {
  if (!eligible(el)) return null
  return bestRole(scoreField(factsFor(el)))
}

// ---- The page ------------------------------------------------------------------

interface ScannedField {
  el: HTMLInputElement
  facts: FieldFacts
  score: Record<FieldRole, number>
  role: FieldRole | null
}

export interface Field {
  el: HTMLInputElement
  role: FieldRole
  /** Set on each box of a code split into one box per digit: how many boxes. */
  split?: number
  /** Where the field was when the page was scanned. A fill skips a field that has moved since. */
  owner: FieldOwner
}

/** A field's place in the page: its form, and the node it's a child of. */
export interface FieldOwner {
  form: HTMLFormElement | null
  parent: Node | null
}

export const ownerOf = (el: HTMLInputElement): FieldOwner => ({ form: el.form ?? el.closest("form"), parent: el.parentNode })

/** The field is still where it was scanned. */
export const inPlace = (f: Field) => {
  const now = ownerOf(f.el)
  return f.el.isConnected && now.form === f.owner.form && now.parent === f.owner.parent
}

export interface ScanResult {
  kind: SurfaceKind | null
  fields: Field[]
  submit?: Element
  /** The page shows a sign-in-provider button ("Continue with Google"). */
  provider: boolean
}

function collectFields(roots: Array<Document | ShadowRoot>): { fields: ScannedField[]; otpBoxes: HTMLInputElement[] } {
  const fields: ScannedField[] = []
  const otpBoxes: HTMLInputElement[] = []
  for (const el of deepQueryAll<HTMLInputElement>("input", roots).slice(0, 200)) {
    if (!eligible(el) || !isVisible(el) || ignored(el)) continue
    // One-character boxes for codes are grouped into a single split OTP field.
    if (el.maxLength === 1) {
      otpBoxes.push(el)
      continue
    }
    const facts = factsFor(el)
    fields.push({ el, facts, score: scoreField(facts), role: null })
  }

  // Context: a password field right after another one is a confirmation,
  // unless it's really a PIN or token box.
  let previousPassword: HTMLInputElement | null = null
  for (const f of fields) {
    if (f.facts.type !== "password" || f.score.otp >= FIELD_THRESHOLD) continue
    if (previousPassword && previousPassword.form === f.el.form) {
      f.score["new-password"] += 4
      f.score.password -= 4
    }
    previousPassword = f.el
  }
  for (const f of fields) f.role = bestRole(f.score)
  return { fields, otpBoxes: otpBoxes.length >= 4 && otpBoxes.length <= 8 ? otpBoxes : [] }
}

/** The form that holds the most important field, if the page uses <form>. */
function primaryForm(fields: ScannedField[]): HTMLFormElement | null {
  const anchor =
    fields.find((f) => f.role === "password" || f.role === "new-password") ??
    fields.find((f) => f.role === "username" || f.role === "email" || f.role === "phone") ??
    fields.find((f) => f.role === "otp")
  return anchor ? (anchor.el.form ?? anchor.el.closest("form")) : null
}

function contextText(form: HTMLFormElement | null): string {
  const parts = [document.title]
  for (const h of Array.from(document.querySelectorAll("h1, h2, h3, [role=heading]")).slice(0, 6)) parts.push(innerText(h))
  if (form) {
    parts.push(innerText(form).slice(0, 3000))
    for (const input of Array.from(form.querySelectorAll<HTMLInputElement>("input[type=submit], input[type=button]")))
      parts.push(input.value)
  }
  return words(parts.join(" \n "))
}

/** The provider a button signs in with, if it's a sign-in-provider button. */
export function providerForControl(el: Element, text: string): Provider | null {
  // Some sites label provider buttons explicitly; trust that over the text.
  const attr = el.getAttribute("data-provider") || el.getAttribute("data-social") || ""
  const fromAttr = PROVIDER_ATTR.exec(attr)?.[1]?.toLowerCase()
  if (fromAttr) return (fromAttr === "twitter" ? "x" : fromAttr) as Provider
  const match = text ? providerFromLabel(text) : null
  if (!match) return null
  // A footer "GitHub" link is not a sign-in button; links need a connector
  // ("Continue with GitHub") or an auth-looking destination.
  if (el instanceof HTMLAnchorElement && !match.connector && !AUTH_HREF.test(el.getAttribute("href") || "")) return null
  return match.provider
}

function collectControls(form: HTMLFormElement | null, roots: Array<Document | ShadowRoot>) {
  let submit: Element | undefined
  let provider = false
  const buttonText: string[] = []
  // The login form's own buttons first, so a huge nav can't push them past the cap.
  const candidates = new Set<Element>(form ? Array.from(form.querySelectorAll(CLICKABLE)) : [])
  for (const el of deepQueryAll(CLICKABLE, roots)) {
    if (candidates.size >= 500) break
    candidates.add(el)
  }
  for (const el of candidates) {
    if (!isVisible(el)) continue
    const text = controlText(el)
    if (!provider && providerForControl(el, text)) {
      provider = true
      continue
    }
    if (!text || text.length > 40 || el instanceof HTMLAnchorElement) continue
    if (form && !form.contains(el)) continue
    buttonText.push(text)
    const isSubmitType = (el as HTMLButtonElement).type === "submit"
    if (!submit && (SUBMIT_TEXT.test(text) || (isSubmitType && form))) submit = el
  }
  if (!provider) provider = deepQueryAll(PROVIDER_WIDGETS, roots).length > 0
  return { submit, buttonText, provider }
}

function decideKind(fields: ScannedField[], otpBoxes: number, text: string, controls: ReturnType<typeof collectControls>): FormKind | null {
  const { buttonText, provider } = controls
  const count = (...roles: FieldRole[]) => fields.filter((f) => f.role && roles.includes(f.role)).length
  const pw = count("password")
  const npw = count("new-password")
  const ident = count("username", "email", "phone")
  const otp = count("otp") + (otpBoxes ? 1 : 0)
  const ac = new Set(fields.flatMap((f) => f.facts.autocomplete))
  const url = location.hostname + location.pathname

  const score = scoreFormText(text + words(buttonText.join(" ")))
  // Shape of the form.
  if (pw === 1 && npw === 0) score.login += 5
  if (pw === 0 && npw === 0 && ident > 0) score.login += 1
  if (pw >= 2) score.login -= 3
  // With a single password box, autocomplete=new-password is a weak hint
  // (sites use it to block autofill on logins); wording has to confirm it.
  const single = pw + npw === 1
  if (npw > 0 && !single && !ac.has("current-password")) score.login -= 3
  if (provider) score.login += 2
  // An email-first step: an identifier and a Continue button.
  if (pw + npw === 0 && ident > 0 && buttonText.some((t) => PROCEED_TEXT.test(t))) score.login += 2
  if (ac.has("webauthn")) score.login += 3
  if (ac.has("current-password")) score.login += 3
  if (ac.has("username") && pw === 0) score.login += 2

  if (npw > 0 && pw === 0) score.signup += single ? 1 : 3
  if (pw + npw >= 2) score.signup += 3
  if (ac.has("new-password")) score.signup += single ? 1 : 3
  if (single && npw === 1) score.login += 2
  if (pw === 1 && npw === 0) score.signup -= 2
  // A "Create account" link next to an email-first sign-in doesn't make it a sign-up.
  if (pw + npw === 0 && !SIGNUP_URL.test(url)) score.signup = Math.min(score.signup, 2)

  // Shape alone is weak here (two password boxes can be password + PIN); the
  // "current / new password" wording does most of the work.
  if ((pw >= 1 && npw >= 1) || pw + npw >= 3) score["change-password"] += 2
  if (ac.has("current-password") && ac.has("new-password")) score["change-password"] += 4

  if (ident > 0 && pw + npw === 0) score.reset += 1
  if (pw + npw > 0) score.reset -= 6

  if (otp > 0 && pw === 0) score.mfa += 6
  if (otp > 0 && pw > 0) score.mfa += 1

  if (ident > 0 && pw + npw === 0 && !provider) score.newsletter += 1
  if (pw + npw > 0) score.newsletter -= 8
  if (provider) score.newsletter -= 5

  // Where we are.
  if (LOGIN_URL.test(url)) {
    score.login += 2
    score.mfa += 1
  }
  if (SIGNUP_URL.test(url)) score.signup += 2
  if (RESET_URL.test(url)) score.reset += 2
  if (CHANGE_PASSWORD_URL.test(url)) score["change-password"] += 2

  let best: FormKind | null = null
  for (const kind of FORM_KINDS) if (score[kind] >= FORM_THRESHOLD && (!best || score[kind] > score[best])) best = kind
  return best
}

/** Once the form's kind is known, settle password roles that depend on it. */
function adjustRoles(fields: ScannedField[], kind: FormKind) {
  const passwords = fields.filter((f) => f.facts.type === "password" && (f.role === "password" || f.role === "new-password"))
  if (kind === "signup") {
    for (const f of passwords) if (!f.facts.autocomplete.includes("current-password")) f.role = "new-password"
  } else if (kind === "change-password") {
    passwords.forEach((f, i) => {
      if (f.facts.autocomplete.includes("new-password")) f.role = "new-password"
      else if (f.facts.autocomplete.includes("current-password")) f.role = "password"
      else f.role = i === 0 ? "password" : "new-password"
    })
  } else if (kind === "login") {
    // Sites sometimes set autocomplete=new-password on a login box to block autofill.
    if (passwords.length === 1) passwords[0].role = "password"
    else for (const f of passwords) if (f.role === "new-password" && !f.facts.autocomplete.includes("new-password")) f.role = "password"
  }
}

// One-time codes Deadbolt holds are an authenticator app's (TOTP). A code
// the site sent by text message or email, or a backup or recovery code, is
// one the user brings: its box gets no menu and no fill. The field's own
// label says which first; else the page does, an authenticator winning over
// a code it sent; else it's taken for an authenticator's, as before.
const CODE_AUTHENTICATOR = ["authenticator", "authentication app", "authenticator app", "totp", "app generated", "authenticator application"]
const CODE_SENT = [
  "we sent", "we ve sent", "we have sent", "we just sent", "sent a", "sent you", "sent to", "text message", "texted", "sms",
  "resend", "send a new code", "send again", "send another", "didn t get", "didn t receive", "did not receive",
  "check your email", "check your inbox", "check your phone", "by email", "via email", "emailed", "email code",
  "phone ending", "number ending",
]
const CODE_BACKUP = ["backup code", "back up code", "backup codes", "recovery code", "recovery codes", "recovery key", "scratch code", "emergency code"]
const prepared = (list: string[]) => list.map((p) => words(p).trim())
const [AUTHENTICATOR, SENT, BACKUP] = [prepared(CODE_AUTHENTICATOR), prepared(CODE_SENT), prepared(CODE_BACKUP)]

/** Whether a code box with this label (words()) on this page takes the login's authenticator code. */
export function heldCode(label: string, page: () => string): boolean {
  const any = (text: string, list: string[]) => list.some((p) => hasPhrase(text, p))
  if (any(label, BACKUP)) return false
  if (any(label, AUTHENTICATOR)) return true
  if (any(label, SENT)) return false
  const text = page()
  if (any(text, AUTHENTICATOR)) return true
  return !any(text, SENT) && !any(text, BACKUP)
}

/** What the page says around its code box: title, headings and the start of its text. */
function codePageText(form: HTMLFormElement | null): string {
  const heads = Array.from(document.querySelectorAll("h1, h2, h3, [role=heading]")).slice(0, 6).map((h) => innerText(h))
  return words([document.title, ...heads, innerText(form), innerText(document.body).slice(0, 3000)].join(" \n "))
}

export function scanPage(): ScanResult {
  const roots = openRoots()
  const { fields: all, otpBoxes } = collectFields(roots)
  const form = primaryForm(all)
  // Judge and report the primary form only, so a sign-up form or newsletter
  // box elsewhere on the page doesn't change what the login form is.
  const inScope = (el: Element) => !form || form.contains(el)
  const scanned = all.filter((f) => inScope(f.el))
  const controls = collectControls(form, roots)
  const formKind = decideKind(scanned, otpBoxes.length, contextText(form), controls)
  if (formKind) adjustRoles(scanned, formKind)

  // Codes the user brings themselves (sent, or backup) aren't the login's to fill.
  let page: string | undefined
  const pageText = () => (page ??= codePageText(form))
  let brought = 0
  for (const f of scanned)
    if (f.role === "otp" && !heldCode(f.facts.display, pageText)) {
      f.role = null
      brought++
    }
  const boxes = otpBoxes.length && inScope(otpBoxes[0]) ? otpBoxes : []
  const split = boxes.length && heldCode(words(labelText(boxes[0])), pageText) ? boxes : []
  if (boxes.length && !split.length) brought++

  const fields: Field[] = scanned.filter((f) => f.role).map((f) => ({ el: f.el, role: f.role!, owner: ownerOf(f.el) }))
  for (const el of split) fields.push({ el, role: "otp", split: split.length, owner: ownerOf(el) })

  // Sign-in wording with no fields to fill isn't a form; a code step whose
  // code the user brings still is one (a sign-in that isn't over), with
  // nothing in it to fill.
  const kind = formKind === "newsletter" || (!fields.length && !(formKind === "mfa" && brought)) ? null : formKind
  return { kind, fields, submit: controls.submit, provider: controls.provider }
}

// Pages between sign-in steps: an authenticator picker, a CAPTCHA, a
// "verify it's you" check. They have no form to fill, but the sign-in hasn't
// finished.
const STEP_PHRASES = [
  "select an authenticator", "choose an authenticator", "verify with", "verify it s you", "confirm it s you", "it s really you",
  "choose a verification method", "choose how you want to sign in", "try another way", "2 step verification", "two step verification",
  "security check", "i m not a robot", "verify you are human", "are you a robot", "checking your browser", "complete the captcha",
  "signing you in", "redirecting",
].map((p) => words(p).trim())
const CAPTCHA = ".g-recaptcha, .h-captcha, .cf-turnstile, iframe[src*='recaptcha'], iframe[src*='hcaptcha'], iframe[src*='challenges.cloudflare.com']"
const BUSY = "[role=progressbar], [aria-busy=true]"

/**
 * Whether a page with no login form still looks like part of a sign-in: its
 * path says so (never its host, so sso.example.com/dashboard is done), it
 * offers sign-in-provider buttons, it's a step between sign-in pages, or
 * it's a spinner with next to nothing else on it.
 */
export function signingIn(provider: boolean): boolean {
  if (LOGIN_URL.test(location.pathname) || provider) return true
  const roots = openRoots()
  if (deepQueryAll(CAPTCHA, roots).length) return true
  const text = words(innerText(document.body).slice(0, 2000))
  if (STEP_PHRASES.some((p) => hasPhrase(text, p))) return true
  return squash(text).length < 40 && deepQueryAll(BUSY, roots).some(isVisible)
}

// ---- "Sign in with …" ------------------------------------------------------------

/** What a sign-in-with button says around the provider's name; anything else counts against it. */
const SIGN_IN_WORDS = new Set(["continue", "sign", "in", "signin", "up", "signup", "log", "login", "connect", "use", "with", "using", "via", "through", "your", "account", "to", "id"])
const VERB = /\b(continue|sign\s?in|sign\s?up|log\s?in|login|signin|signup|connect)\b/

/**
 * Whether a control's text (or label) asks to sign in with this provider:
 * a sign-in verb, the provider's name, and at most one other word ("Sign in
 * with Google", "Continue with your Apple ID", "Log in via GitHub"). Longer
 * text is a sentence about the provider, not its button ("Sign in with
 * Google to sync your calendar"); no verb is a share or follow button.
 */
export function signInWithText(text: string, p: { words: string[] }): boolean {
  const t = text
    .toLowerCase()
    .replace(/[“”"'’()[\]{}.,!?:·|—–-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
  if (!t || t.length > 60 || !VERB.test(t)) return false
  // The provider's name, as whole words (longest first: "apple id" before "apple").
  const words = [...p.words].sort((a, b) => b.length - a.length)
  const name = words.find((w) => new RegExp(`(^| )${w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}( |$)`).test(t))
  if (!name) return false
  const rest = ` ${t} `.replace(` ${name} `, " ").trim().split(" ").filter((w) => w && !SIGN_IN_WORDS.has(w))
  return rest.length <= 1
}

const BUTTONS = 'button, a[href], [role=button], [role=link], input[type=submit], input[type=button]'
/** Provider widgets with no text of their own to read: Google Identity Services, Sign in with Apple. */
const WIDGETS: Record<string, string> = {
  google: '.g_id_signin, #g_id_signin, iframe[src*="accounts.google.com/gsi/button"], div[id^="gsi_"][role=button]',
  apple: "#appleid-signin, [data-type=sign-in][data-color]",
}

/**
 * The site's own button for signing in with the provider, if one shows: a
 * provider widget, or a control whose text, label or data attributes say
 * "sign in with <provider>" and little else (see signInWithText). Deadbolt
 * only points at it; the user clicks it.
 */
export function findProviderButton(p: { id: string; words: string[] }): Element | null {
  const roots = openRoots()
  const widget = WIDGETS[p.id]
  if (widget) for (const el of deepQueryAll(widget, roots)) if (isVisible(el)) return el
  const candidates = deepQueryAll(BUTTONS, roots).slice(0, 600)
  let best: Element | null = null
  for (const el of candidates) {
    if (!isVisible(el)) continue
    const img = el.querySelector("img[alt]")?.getAttribute("alt") ?? ""
    const data = [el.getAttribute("data-provider"), el.getAttribute("data-testid"), el.getAttribute("data-test")].filter(Boolean).join(" ").toLowerCase()
    const named = signInWithText(controlText(el), p) || signInWithText(img, p)
    const tagged = !!data && p.words.some((w) => data.split(/[\s_-]+/).includes(w)) && /(sign|log)\s?in|login|signin|sso|oauth|social|continue/.test(data)
    const providerOnly = el.getAttribute("data-provider")?.toLowerCase() === p.id
    if (!named && !tagged && !providerOnly) continue
    // The innermost match: the button itself, not a wrapper around it.
    if (!best || best.contains(el)) best = el
  }
  return best
}

/**
 * On the provider's account chooser, the tile for `account` (an email or
 * username), by the attribute Google's tiles carry it in. Never by text: a
 * page's own text could name anyone.
 */
export function findAccountTile(account: string): Element | null {
  const want = account.trim().toLowerCase()
  if (!want) return null
  const roots = openRoots()
  for (const el of deepQueryAll("[data-identifier], [data-email]", roots)) {
    const id = (el.getAttribute("data-identifier") ?? el.getAttribute("data-email") ?? "").trim().toLowerCase()
    if (id === want && isVisible(el)) return el.closest('[role=link], [role=button], li, a, button') ?? el
  }
  return null
}
