// An automatic sign-in session's submit (db:signin-submit): after the
// background filled a step, it asks this script to submit it, and the checks
// here decide. A step is either a form that posts to this origin, in this tab,
// or a form-less step (Google's: no <form>, a <button type="button"> Next
// whose click the page's own script handles) whose fields and one Next share
// a dialog or main region. Either way the button reads sign in, next,
// continue, verify or the like, every field still holds its value and shows,
// nothing on the page is a CAPTCHA, no error shows, and a code step's prompt
// doesn't say the code came by text or email. A step is submitted at most
// once, after a short settle that checks all of it again.

import { IDENTIFIER_ROLES, type SurfaceKind } from "../messages"
import { CAPTCHA, controlText, deliveredCode, isVisible, sole, type Field } from "./detect"
import { fillable } from "./fill"
import { deepQueryAll, openRoots } from "./shadow"

/** A step's submit button: signing in, going on, or confirming a code. */
export const SUBMIT_LABEL = /^(sign\s?in|log\s?in|login|continue|next|verify|confirm(?: code)?|submit)$/i
/** A first automatic step's button: signing in or going on, never confirming something. */
const FIRST_LABEL = /^(sign\s?in|log\s?in|login|continue|next)$/i
/** Words of re-authentication or of an action to confirm, which a sign-in's first step doesn't carry. */
const NOT_SIGN_IN = /\b(confirm (?:your )?(?:access|identity|password)|re-?enter|re-?authenticat\w*|sudo|delete|deleting|remove|close (?:your )?account|deactivate|withdraw\w*|transfer|payment|disable|turn off|unlink)\b/i
const REGION = "dialog, [role=dialog], main, [role=main]"
const BUTTONS = "button, input[type=submit], input[type=button], input[type=image], [role=button]"
/** How long a filled step settles before its submit: the page may still be taking the values in, or swapping the step away. */
export const SETTLE_MS = 150

/** Whether the scope, or the page's title and headings, say it's for something other than signing in. */
function notSignIn(scope: Element | null | undefined): boolean {
  const text = [document.title, ...Array.from(document.querySelectorAll<HTMLElement>("h1, h2, h3, [role=heading]"), (el) => el.innerText), (scope as HTMLElement | null)?.innerText ?? ""]
  return text.some((t) => t.length > 20_000 || NOT_SIGN_IN.test(t))
}

/**
 * `account`, when the page shows it as its account chip: every visible
 * [data-profile-identifier] (Google's) says exactly that account. Only then
 * may a code prompt's line that is the account and nothing else be read past
 * (see deliveredCode); anything else stays strict.
 */
export function accountChip(account: string | undefined): string | undefined {
  const want = account?.trim().toLowerCase()
  if (!want) return undefined
  const chips = deepQueryAll<HTMLElement>("[data-profile-identifier]", openRoots()).filter(isVisible)
  return chips.length && chips.every((c) => c.innerText.trim().toLowerCase() === want) ? account : undefined
}

export interface SubmitStep {
  kind: SurfaceKind | null
  fields: Field[]
  /** The scan's submit control (see scanPage). */
  submit: Element | undefined
  /** An automatic session's first step: a sign-in's own, with a username box. */
  first: boolean
  /** The session's username, for its account chip. */
  account?: string
}
export interface SubmitPlan {
  form: HTMLFormElement | null
  button: HTMLElement
}
export type Refusal = "kind" | "button" | "scope" | "destination" | "captcha" | "values" | "first" | "error" | "delivered"

/** The form a step's fields and button post with, checked: a POST to this origin, in this tab. */
function formScope(form: HTMLFormElement, fields: Field[], button: HTMLElement): Refusal | null {
  if (!fields.every((f) => f.el.form === form && form.contains(f.el))) return "scope"
  const control = button instanceof HTMLButtonElement || button instanceof HTMLInputElement ? button : null
  // A sign-in posts; a GET form puts what it sends in the URL.
  const method = control?.hasAttribute("formmethod") ? control.formMethod : form.method
  const destination = button.getAttribute("formaction") ?? form.getAttribute("action") ?? location.href
  // The browsing context it goes to: the submitter's, the form's, else the document's <base target>.
  const target = button.getAttribute("formtarget") ?? form.getAttribute("target") ?? document.querySelector("base[target]")?.getAttribute("target") ?? ""
  try {
    if (method !== "post" || new URL(destination, document.baseURI).origin !== location.origin || (target && target !== "_self")) return "destination"
  } catch {
    return "destination"
  }
  return null
}

/**
 * A form-less step's region: the one dialog or main region holding every
 * field (else the body), and the button in it the only control there that
 * reads like a submit. The button is a real button no form owns, so its
 * click is the page's own script's to handle and leaves nothing to post.
 */
function regionOf(fields: Field[], button: HTMLElement): Element | null {
  if (fields.some((f) => f.el.form) || !(button instanceof HTMLButtonElement || (button instanceof HTMLInputElement && ["button", "submit"].includes(button.type)))) return null
  if (button.form) return null
  const regions = new Set(fields.map((f) => f.el.closest(REGION)))
  if (regions.size !== 1) return null
  const region = [...regions][0] ?? document.body
  if (!region?.contains(button)) return null
  const candidates = Array.from(region.querySelectorAll(BUTTONS)).filter((el) => isVisible(el) && SUBMIT_LABEL.test(controlText(el)))
  return sole(candidates) === button ? region : null
}

/** An error the page shows beside the step (a wrong password, say), or a field it marked invalid. */
function errorShown(scope: Element, fields: Field[]): boolean {
  if (fields.some((f) => f.el.getAttribute("aria-invalid") === "true")) return true
  return Array.from(scope.querySelectorAll<HTMLElement>("[role=alert], [aria-live=assertive]")).some((el) => isVisible(el) && el.innerText.trim().length > 0)
}

/** What an automatic session may submit of the step the scan found, or why not. */
export function submitPlan(step: SubmitStep): SubmitPlan | Refusal {
  const { kind, fields, submit } = step
  if ((kind !== "login" && kind !== "mfa") || !fields.length) return "kind"
  const button = submit
  if (!(button instanceof HTMLElement) || !isVisible(button) || button.matches(":disabled, [aria-disabled=true]")) return "button"
  const label = controlText(button)
  if (!SUBMIT_LABEL.test(label)) return "button"
  const control = button instanceof HTMLButtonElement || button instanceof HTMLInputElement ? button : null
  const form = control?.form ?? fields[0].el.form
  let scope: Element
  if (form) {
    const refused = formScope(form, fields, button)
    if (refused) return refused
    scope = form
  } else {
    const region = regionOf(fields, button)
    if (!region) return "scope"
    scope = region
  }
  if (fields.some((f) => f.role === "captcha") || deepQueryAll(CAPTCHA, openRoots()).some(isVisible)) return "captcha"
  // The fields passed the full check, paint included, as each was written;
  // this one is about submitting, so it leaves the costly paint check out.
  if (!fields.every((f) => !!f.el.value && fillable(f.el, null, false))) return "values"
  // An automatic session's first step must be a sign-in's own: a username
  // box, a sign-in or continue button, and no words of re-authentication or
  // of something else to confirm (Confirm access, delete, withdraw, turn off
  // two-factor) on the form or the page's headings.
  if (step.first && !(FIRST_LABEL.test(label) && fields.some((f) => IDENTIFIER_ROLES.includes(f.role)) && !notSignIn(scope))) return "first"
  if (errorShown(scope, fields)) return "error"
  // A code step's prompt that describes delivery by SMS or email takes a
  // code the person brings, never the login's authenticator code.
  if (deliveredCode(fields, scope, accountChip(step.account))) return "delivered"
  return { form, button }
}
