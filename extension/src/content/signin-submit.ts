// An automatic sign-in session's submit (db:signin-submit): after the
// background filled a step, it asks this script to submit it, and the checks
// here decide. A step is either a form that posts to this origin, in this tab,
// or a form-less step (Google's: no <form>, a <button type="button"> Next
// whose click the page's own script handles) whose fields and one Next share
// a dialog or main region. Either way the button reads sign in, next,
// continue, verify or the like, every field still holds its value and shows,
// nothing on the page is a CAPTCHA, no error shows, and a code step's prompt
// doesn't say the code came by text or email. Nothing is submitted on a page
// that isn't a secure context. A step is submitted at most once, after a
// short settle that checks all of it again.
//
// A React <form onSubmit> has no method and no action of its own, so to the
// browser it's a GET of this page, which would put every field in the URL.
// Its submit is the page script's to handle: it may go, but never natively
// (see holdNativeSubmit). A form that says GET itself, names a route to GET,
// or searches is never submitted.

import { IDENTIFIER_ROLES, type SurfaceKind } from "../messages"
import { CAPTCHA, controlText, deliveredCode, isVisible, sole, visibleLabel, type Field } from "./detect"
import { fillable } from "./fill"
import { deepQueryAll, openRoots } from "./shadow"

declare const DEADBOLT_E2E: boolean | undefined

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

/** How many times the user pressed Esc in this page (see noteStop). */
let stops = 0

/** The user pressed Esc themselves (a trusted keydown): a submit waiting out its settle doesn't go. */
export function noteStop() {
  stops++
}

/**
 * Waits out SETTLE_MS after a plan, then makes it again: the plan to submit,
 * or null if the user pressed Esc meanwhile, the step can't be submitted any
 * more, or its button changed.
 */
export async function settledPlan(before: SubmitPlan, plan: () => SubmitPlan | null): Promise<SubmitPlan | null> {
  const seen = stops
  await new Promise((resolve) => setTimeout(resolve, SETTLE_MS))
  if (stops !== seen) return null
  const after = plan()
  return after && after.button === before.button && stops === seen ? after : null
}

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
  /** The form's submit is its page script's (see scriptHandled): its native submit is held (see holdNativeSubmit). */
  scripted?: true
}
export type Refusal = "insecure" | "kind" | "button" | "scope" | "destination" | "captcha" | "values" | "first" | "purpose" | "error" | "delivered"

/** An action that goes nowhere of its own: none, empty, "#", or React 19's javascript: placeholder. */
const noAction = (action: string | null | undefined) => action == null || /^\s*#?\s*$/.test(action) || /^\s*javascript:/i.test(action)

/**
 * Whether a form's submit is only its page script's: no method on the form
 * or its button, and no action of its own on either (a `formaction="#"`
 * on a form that names a route still goes there). React's <form onSubmit>.
 */
export function scriptHandled(form: HTMLFormElement, control: HTMLButtonElement | HTMLInputElement | null): boolean {
  if (form.hasAttribute("method") || control?.hasAttribute("formmethod")) return false
  return noAction(control?.getAttribute("formaction")) && noAction(form.getAttribute("action"))
}

/** A search form: a search landmark, or a search box among its fields. */
export function searchLike(form: HTMLFormElement): boolean {
  if (form.closest("[role=search], search")) return true
  return !!form.querySelector("input[type=search], input[name=q], input[name=query], input[name=search], input[name=s]")
}

/** How long a script-handled form's native submit stays held after its plan: past the settle and the click. */
export const HOLD_MS = SETTLE_MS + 2000
/** Each held form: until when, the timer that lets it go then, and how (its listener removed). */
const held = new WeakMap<HTMLFormElement, { until: number; timer: ReturnType<typeof setTimeout>; release: () => void }>()

/**
 * For a moment after a plan to submit a script-handled form (each check
 * before the click, see submitPlan, holds it again from then), a submit of
 * it that the page's script didn't take (no preventDefault: its script
 * failed to load, or it isn't React's after all) goes nowhere: Deadbolt
 * prevents it, so the browser never GETs the fields into the URL. Every
 * submit in that time is held, a page's own synthetic one included, so one
 * can't spend the hold before the real one comes; but only while the form
 * and its submitter are still script-handled: a form its script turned into
 * a POST for its next step goes. Listened for last, on the window (or the
 * form's shadow root, which a submit event doesn't leave), after the page's
 * own handlers, and only until the hold runs out.
 */
export function holdNativeSubmit(form: HTMLFormElement) {
  const until = performance.now() + HOLD_MS
  const prior = held.get(form)
  // Held again: one listener still, its time from now, and one timer to let it go.
  if (prior) {
    clearTimeout(prior.timer)
    held.set(form, { ...prior, until, timer: setTimeout(prior.release, HOLD_MS + 50) })
    return
  }
  const root = form.getRootNode()
  const on: EventTarget = root instanceof ShadowRoot ? root : window
  const release = () => {
    held.delete(form)
    on.removeEventListener("submit", guard)
  }
  const guard = (event: Event) => {
    if (event.target !== form || event.defaultPrevented || performance.now() > (held.get(form)?.until ?? 0)) return
    const submitter = (event as SubmitEvent).submitter
    const control = submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement ? submitter : null
    if (scriptHandled(form, control)) event.preventDefault()
  }
  on.addEventListener("submit", guard)
  held.set(form, { until, timer: setTimeout(release, HOLD_MS + 50), release })
}

/**
 * The form a step's fields and button post with, checked: a POST to this
 * origin, or a script-handled form (see scriptHandled) that isn't a
 * search, in this tab.
 */
function formScope(form: HTMLFormElement, fields: Field[], button: HTMLElement): Refusal | null {
  if (!fields.every((f) => f.el.form === form && form.contains(f.el))) return "scope"
  const control = button instanceof HTMLButtonElement || button instanceof HTMLInputElement ? button : null
  const method = control?.hasAttribute("formmethod") ? control.formMethod : form.method
  // The browsing context it goes to: the submitter's, the form's, else the document's <base target>.
  const target = button.getAttribute("formtarget") ?? form.getAttribute("target") ?? document.querySelector("base[target]")?.getAttribute("target") ?? ""
  if (target && target !== "_self") return "destination"
  // A sign-in posts; a GET form puts what it sends in the URL, unless its page's script submits it.
  if (method !== "post") return method === "get" && scriptHandled(form, control) && !searchLike(form) ? null : "destination"
  const destination = button.getAttribute("formaction") ?? form.getAttribute("action") ?? location.href
  try {
    if (new URL(destination, document.baseURI).origin !== location.origin) return "destination"
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
  const candidates = Array.from(region.querySelectorAll(BUTTONS)).filter((el) => isVisible(el) && (SUBMIT_LABEL.test(controlText(el)) || SUBMIT_LABEL.test(visibleLabel(el))))
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
  // Over plain http anyone on the network can rewrite the page; an e2e build serves its sites that way.
  if (!window.isSecureContext && !(typeof DEADBOLT_E2E !== "undefined" && DEADBOLT_E2E === true)) return "insecure"
  if ((kind !== "login" && kind !== "mfa") || !fields.length) return "kind"
  const button = submit
  // A button inside a link would follow it too.
  if (!(button instanceof HTMLElement) || !isVisible(button) || button.matches(":disabled, [aria-disabled=true]") || button.closest("a[href]")) return "button"
  // What the button shows, which an aria-label must agree with.
  const label = visibleLabel(button)
  if (!SUBMIT_LABEL.test(label)) return "button"
  const control = button instanceof HTMLButtonElement || button instanceof HTMLInputElement ? button : null
  // A button that names, or sits in, a form it doesn't belong to submits nothing of these fields.
  const named = control?.getAttribute("form")
  if (control && (named != null ? control.form?.id !== named : !control.form && control.closest("form"))) return "scope"
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
  // A code step is held to the same words: a code that confirms a transfer or a deletion isn't a sign-in's.
  if (fields.some((f) => f.role === "otp") && notSignIn(scope)) return "purpose"
  if (errorShown(scope, fields)) return "error"
  // A code step's prompt that describes delivery by SMS or email takes a
  // code the person brings, never the login's authenticator code.
  if (deliveredCode(fields, scope, accountChip(step.account))) return "delivered"
  if (form && form.method !== "post" && scriptHandled(form, control)) {
    holdNativeSubmit(form)
    return { form, button, scripted: true }
  }
  return { form, button }
}
