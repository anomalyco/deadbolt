// Login-form detection. Ported from Foyer (github.com/R44VC0RP/foyer,
// src/detect.ts, by Ryan Vogel). Deadbolt keeps the field and form scoring
// and drops what served Foyer's sign-in recipes: selectors, provider buttons,
// passkey and magic-link controls.
//
// Fields and forms are scored with weighted clues (see clues.ts): labels,
// placeholders, ids, autocomplete, input type, neighbouring fields and the
// text around the form all add or subtract points. Text is read only to be
// matched in memory; nothing here leaves the page.

import type { FieldRole, SurfaceKind } from "../messages"
import { bestRole, FIELD_THRESHOLD, FORM_KINDS, scoreField, scoreFormText, squash, words, type FieldFacts, type FormKind } from "./clues"
import { deepQueryAll, openRoots } from "./shadow"

export const LOGIN_URL = /log-?in|log_in|logon|sign-?in|sign_in|signon|auth|sso|saml|oauth|session|identifier|challenge|mfa|2fa|two-factor|verify|webauthn|passkey/i
const SIGNUP_URL = /sign-?up|sign_up|register|registration|join|create-account|onboard/i
const RESET_URL = /forgot|reset|recover/i
const CHANGE_PASSWORD_URL = /change-?password|password-?change|update-?password|settings\/security/i
const SUBMIT_TEXT = /^\s*(sign ?in|log ?in|login|sign ?on|continue|next|submit|verify|confirm|go)\b/i

const CLICKABLE = "button, [role=button], input[type=submit], input[type=button], input[type=image]"
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

/** The site asked password managers to leave this field alone, on it, its form or the page. */
export const ignored = (el: HTMLInputElement) => optedOut(el) || optedOut(el.form ?? el.closest("form")) || optedOut(document.body)

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

function labelText(el: HTMLInputElement): string {
  const parts: string[] = []
  for (const label of Array.from(el.labels ?? [])) parts.push(innerText(label))
  const labelledBy = el.getAttribute("aria-labelledby")
  const root = el.getRootNode() as Document | ShadowRoot
  if (labelledBy) for (const id of labelledBy.split(/\s+/)) parts.push(innerText(root.getElementById?.(id)))
  parts.push(el.getAttribute("aria-label") ?? "", el.placeholder ?? "", el.getAttribute("title") ?? "")
  if (!parts.some(Boolean)) parts.push(nearbyText(el))
  // "you@example.com" as a placeholder means an email box.
  if (el.placeholder?.includes("@")) parts.push("email")
  return parts.filter(Boolean).join(" ").slice(0, 300)
}

function factsFor(el: HTMLInputElement): FieldFacts {
  const code = [el.id, el.name, el.getAttribute("class"), el.getAttribute("data-testid"), el.getAttribute("data-test")]
    .filter((v): v is string => typeof v === "string" && v.length > 0)
    .join(" ")
  return {
    type: (el.getAttribute("type") || "text").toLowerCase(),
    autocomplete: (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/).filter(Boolean),
    display: words(labelText(el)),
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

function collectControls(form: HTMLFormElement | null, roots: Array<Document | ShadowRoot>) {
  let submit: Element | undefined
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
    if (!text || text.length > 40) continue
    if (form && !form.contains(el)) continue
    buttonText.push(text)
    const isSubmitType = (el as HTMLButtonElement).type === "submit"
    if (!submit && (SUBMIT_TEXT.test(text) || (isSubmitType && form))) submit = el
  }
  return { submit, buttonText }
}

function decideKind(fields: ScannedField[], otpBoxes: number, text: string, buttonText: string[]): FormKind | null {
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
  if (npw > 0 && !ac.has("current-password")) score.login -= 3
  if (ac.has("webauthn")) score.login += 3
  if (ac.has("current-password")) score.login += 3
  if (ac.has("username") && pw === 0) score.login += 2

  // With a single password box, autocomplete=new-password is a weak hint
  // (sites use it to block autofill on logins); wording has to confirm it.
  const single = pw + npw === 1
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

  if (ident > 0 && pw + npw === 0) score.newsletter += 1
  if (pw + npw > 0) score.newsletter -= 8

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

export function scanPage(): ScanResult {
  const roots = openRoots()
  const { fields: all, otpBoxes } = collectFields(roots)
  const form = primaryForm(all)
  // Judge and report the primary form only, so a sign-up form or newsletter
  // box elsewhere on the page doesn't change what the login form is.
  const inScope = (el: Element) => !form || form.contains(el)
  const scanned = all.filter((f) => inScope(f.el))
  const controls = collectControls(form, roots)
  const formKind = decideKind(scanned, otpBoxes.length, contextText(form), controls.buttonText)
  if (formKind) adjustRoles(scanned, formKind)

  const fields: Field[] = scanned.filter((f) => f.role).map((f) => ({ el: f.el, role: f.role!, owner: ownerOf(f.el) }))
  if (otpBoxes.length && inScope(otpBoxes[0])) for (const el of otpBoxes) fields.push({ el, role: "otp", split: otpBoxes.length, owner: ownerOf(el) })

  return { kind: formKind === "newsletter" ? null : formKind, fields, submit: controls.submit }
}
