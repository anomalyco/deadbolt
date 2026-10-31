// Content script, in every frame of http(s) pages: finds login forms, opens
// the inline menu on their fields, applies fills, and hands what the user
// submitted to the background so it can offer to save it. Scheduling and
// submit tracking are ported from Foyer (github.com/R44VC0RP/foyer,
// src/content.ts, by Ryan Vogel), without its sign-in recording.

import { isVisible, scanPage, type Field } from "./content/detect"
import { SIGNIN_SETTING } from "./auth-state"
import { authReport, SIGN_OUT, takeSignInAction } from "./content/auth-state"
import { initFrameChecks } from "./content/embed"
import { scanForms, type FormField } from "./content/forms"
import { fillable, ownValue, rendered, trackUserInput } from "./content/fill"
import { generatedId } from "./content/generate"
import { initMenu, markSubmitted, noteSubmitGesture, refreshMenu, send, stepped } from "./content/inline"
import { initLearn, learnScanned } from "./content/learn"
import { pageFacts } from "./content/outcome"
import { initPasskeyChannel } from "./content/passkeys"
import { deepActiveElement, eventTarget, openRoots } from "./content/shadow"
import { IDENTIFIER_ROLES, type SurfaceKind, type ToContent } from "./messages"

const isTop = window === window.top
let offerSignIn = false
if (isTop) {
  void chrome.storage.local.get(SIGNIN_SETTING).then((s) => { offerSignIn = s[SIGNIN_SETTING] === true; if (offerSignIn) scheduleScan() })
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && SIGNIN_SETTING in changes) { offerSignIn = changes[SIGNIN_SETTING].newValue === true; scheduleScan() }
  })
}
const SCAN_INTERVAL_MS = 750
const QUIET_AFTER_MS = 2500
/** A submitted form still showing this long after means the sign-in failed. */
const FAILED_AFTER_MS = 5000

/** Live fields of the current login form. Never sent anywhere. */
let fields: Field[] = []
let submitControl: Element | undefined
let kind: SurfaceKind | null = null
/** The page shows a sign-in-provider button. */
let provider = false
/** Bumped whenever the set of fields changes, so a fill can't land on a different form. */
let formId = 0
/** Live identity and payment fields (see content/forms.ts), and their snapshot, as for logins. */
let formFields: FormField[] = []
let formsId = 0
let formsReported = ""
let lastSignature = ""
/** Whether the background was last told of a form here, so it hears when it goes. */
let reported = false
let lastUrl = location.href
let quietTimer: number | undefined
/** The URL (and step) the background was last told settled for, so it's told once. */
let settledFor = ""
let afterSubmitTimer: number | undefined
let lastSubmitAt = 0
/** This document's submits so far: a failure names the one it's about. */
let submission = 0
let failureTimer: number | undefined
/** A site may submit itself when the last digit fills. Suppress only our duplicate click. */
let submittedForm: HTMLFormElement | undefined

const sameFields = (a: Field[], b: Field[]) =>
  a.length === b.length && a.every((f, i) => f.el === b[i].el && f.role === b[i].role && f.owner.form === b[i].owner.form && f.owner.parent === b[i].owner.parent)

/** Finds the login form's fields now. */
function refresh() {
  if (!document.body) return
  // One walk of the page's shadow roots serves the whole scan: nothing in it
  // runs page script. A discovery walk: fills are checked on a full one.
  const roots = openRoots(document, undefined, true)
  watchShadowRoots(roots)
  const result = scanPage(roots)
  kind = result.kind
  provider = result.provider
  // A reset form's email box isn't something to fill.
  const next = kind && kind !== "reset" ? result.fields : []
  if (!sameFields(fields, next)) formId++
  fields = next
  submitControl = kind ? result.submit : undefined
  // A field a login form claims (its email box) is the login's.
  const forms = scanForms(roots).filter((f) => !fields.some((l) => l.el === f.el))
  const same = forms.length === formFields.length && forms.every((f, i) => f.el === formFields[i].el && f.role === formFields[i].role && f.section === formFields[i].section && f.form === formFields[i].form && f.parent === formFields[i].parent)
  if (!same) formsId++
  formFields = forms
}

/** Tells the background which kinds of form this frame has, when that changes (card fills span frames). */
function reportForms() {
  const kinds = [...new Set(formFields.map((f) => f.kind))].sort()
  const signature = JSON.stringify([location.href, kinds, formsId])
  if (signature === formsReported || (!kinds.length && !formsReported)) return
  formsReported = kinds.length ? signature : ""
  void send({ type: "db:forms-page", kinds, form: formsId })
}

function scan() {
  if (document.hidden || !document.body) return
  if (location.href !== lastUrl) {
    lastUrl = location.href
    lastSignature = ""
  }
  refresh()
  void report(false)
  reportForms()
  learnScanned()
  if (offerSignIn && isTop) void send({ type: "db:signin-check" })

  // Autofocused login fields get the menu once the form is recognised.
  const active = deepActiveElement()
  if (active instanceof HTMLInputElement && fields.some((f) => f.el === active)) refreshMenu(active)

  // The top page showing no login form for a moment, or a code step, is
  // where a sign-in may have finished or moved on. The background then asks
  // what the page shows (db:probe) and decides whether to offer a save.
  if (!isTop) return
  window.clearTimeout(quietTimer)
  if (kind === "mfa" && settledFor !== `mfa ${location.href}`) {
    settledFor = `mfa ${location.href}`
    send({ type: "db:settled" })
  } else if (!kind && settledFor !== location.href) {
    const url = location.href
    quietTimer = window.setTimeout(() => {
      if (!kind && location.href === url) {
        settledFor = url
        send({ type: "db:settled" })
      }
    }, QUIET_AFTER_MS)
  }
}

/**
 * A moment after a submit in the top page, whatever it shows: an error or
 * the form back with its password emptied tells the background the sign-in
 * failed, and a page that kept its form settles a retry.
 */
function settleAfterSubmit() {
  if (!isTop) return
  window.clearTimeout(afterSubmitTimer)
  const url = location.href
  afterSubmitTimer = window.setTimeout(() => {
    if (location.href === url && kind) send({ type: "db:settled" })
  }, QUIET_AFTER_MS)
}

/**
 * Tells the background about the login form when it changes, and once when
 * it goes away; with `always`, now whatever it was told before. Resolves once
 * the background has it.
 */
async function report(always: boolean) {
  const roles = [...new Set(fields.map((f) => f.role))].sort()
  const moved = stepped()
  // An empty username box says nothing of its value, only that it's empty
  // (a "Use a different account" step ends a sign-in session).
  const identifier = fields.find((f) => IDENTIFIER_ROLES.includes(f.role))
  const idEmpty = !!identifier && !identifier.el.value
  // Which of them are drawn, wherever the page is scrolled: a password box a step uncollapses in place (Apple's) is news.
  const shown = fields.map((f) => rendered(f.el))
  // A password box that says it wants a new password (autocomplete), whatever
  // the detector made of the form: a sign-in session doesn't fill it (see Autofill.page).
  const asksNew = fields.some((f) => f.el.type === "password" && /\bnew-password\b/.test(f.el.autocomplete))
  const signature = JSON.stringify([location.href, kind, roles, formId, moved, idEmpty, shown, asksNew])
  const tell = always || (kind ? signature !== lastSignature : reported)
  lastSignature = kind ? signature : ""
  reported = !!kind
  if (tell) await send({ type: "db:page", kind, roles, form: formId, stepped: moved, idEmpty, asksNew })
}

chrome.runtime.onMessage.addListener((message: ToContent, _sender, respond) => {
  if (message?.type === "db:fill" && message.automatic) submittedForm = undefined
  if (message?.type === "db:auth-probe") {
    if (!isTop || !offerSignIn) return void respond(null)
    return void respond(authReport(state, message.fresh === true))
  }
  if (message?.type === "db:signin-go") {
    const action = isTop && offerSignIn ? takeSignInAction(message.action, state) : null
    respond(!!action)
    // Answer before a navigation unloads the asking document.
    if (action) setTimeout(() => "element" in action ? action.element.click() : void report(true), 0)
    return
  }
  if (message?.type === "db:signin-submit") {
    refresh()
    const button = submitControl
    const form = button instanceof HTMLButtonElement || button instanceof HTMLInputElement ? button.form : fields[0]?.el.form
    const label = button?.textContent?.trim() || (button instanceof HTMLInputElement ? button.value : "")
    const destination = button?.getAttribute("formaction") ?? form?.getAttribute("action") ?? location.href
    const target = button?.getAttribute("formtarget") ?? form?.getAttribute("target") ?? ""
    // A remembered code step is not permission to send a TOTP into a prompt
    // that currently describes delivery by SMS or email.
    const codeContext = form?.closest<HTMLElement>("dialog, [role=dialog], main, [role=main]") ?? document.body
    const codePrompts = fields.some((f) => f.role === "otp") ? [
      ...fields.flatMap((f) => [f.el.getAttribute("aria-label") ?? "", f.el.placeholder, ...Array.from(f.el.labels ?? []).map((label) => label.innerText)]),
      document.title, ...Array.from(document.querySelectorAll<HTMLElement>("h1, h2, h3, [role=heading]")).map((el) => el.innerText),
      codeContext.innerText,
    ] : []
    // Check each specific hint before the surrounding copy. Oversized context
    // is unknown, not permission to truncate away a delivery warning.
    const deliveredCode = codePrompts.some((text) => text.length > 12000 || /\b(?:sms|text(?:ed| message)?|e-?mail|phone|mobile|inbox|sent|messages?|deliver(?:ed|y)?|call|voice|whatsapp|push|notifications?|approve)\b|@|[•*]{2,}|\+\d/i.test(text))
    // The fields passed the full check, paint included, as each was written;
    // this one is about submitting, so it leaves the costly paint check out.
    const safe = isTop && offerSignIn && !document.hidden && formId === message.form &&
      (kind === "login" || kind === "mfa") && button instanceof HTMLElement && isVisible(button) &&
      !button.matches(":disabled, [aria-disabled=true]") && /^(sign\s?in|log\s?in|login|continue|next|verify|confirm(?: code)?|submit)$/i.test(label) &&
      form instanceof HTMLFormElement && fields.length > 0 &&
      !fields.some((f) => f.role === "captcha") && fields.every((f) => f.el.form === form && form.contains(f.el) && !!f.el.value && fillable(f.el, null, false)) &&
      !deliveredCode &&
      new URL(destination, document.baseURI).origin === location.origin && (!target || target === "_self")
    respond(!!safe)
    if (safe) {
      // The guarded extension pick explicitly authorized this submit. Other
      // script-generated submit events still cannot advance a session.
      captured()
      stepSubmitted()
      if (submittedForm !== form) button.click()
    }
    return
  }
  if (message?.type === "db:probe") {
    if (!isTop) return void respond(null)
    try {
      refresh()
      respond(pageFacts(kind, fields, typeof message.username === "string" ? message.username : undefined, provider))
    } catch {
      respond(null)
    }
    return
  }
  if (message?.type !== "db:report") return
  refresh()
  report(true).then(() => respond(true), () => respond(false))
  return true
})

// ---- Scheduling -------------------------------------------------------------

let scheduled = false
let lastScanAt = 0
function scheduleScan() {
  if (scheduled) return
  scheduled = true
  const wait = Math.max(0, SCAN_INTERVAL_MS - (Date.now() - lastScanAt))
  window.setTimeout(() => {
    scheduled = false
    lastScanAt = Date.now()
    scan()
  }, wait)
}

const OBSERVE: MutationObserverInit = {
  childList: true,
  subtree: true,
  attributes: true,
  attributeFilter: ["type", "class", "hidden", "autocomplete", "aria-hidden", "style"],
}
let observer: MutationObserver | null = null

function start() {
  scheduleScan()
  observer = new MutationObserver(scheduleScan)
  observer.observe(document.documentElement, OBSERVE)
  // SPA navigations that don't touch the DOM much.
  window.setInterval(() => {
    if (location.href !== lastUrl) scheduleScan()
  }, 1000)
  document.addEventListener("visibilitychange", scheduleScan)
  // A box that slides open (Apple's password box) is drawn in full only once
  // its transition ends, which no mutation says: scan again then.
  const moved = (e: Event) => {
    if (e.target instanceof HTMLInputElement || (e.target instanceof Element && e.target.querySelector("input"))) scheduleScan()
  }
  document.addEventListener("transitionend", moved, true)
  document.addEventListener("animationend", moved, true)
  // Back from the back/forward cache: the background forgot this document's form.
  window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return
    lastSignature = ""
    formsReported = ""
    scheduleScan()
  })
}

// Shadow roots need their own observer, and their own submit listener:
// "submit" doesn't cross shadow boundaries the way click and keydown do.
const watchedRoots = new WeakSet<ShadowRoot>()
function watchShadowRoots(roots: Array<Document | ShadowRoot>) {
  for (const root of roots) {
    if (!(root instanceof ShadowRoot) || watchedRoots.has(root)) continue
    watchedRoots.add(root)
    observer?.observe(root, OBSERVE)
    root.addEventListener("submit", onSubmit, true)
  }
}

// ---- Submits ------------------------------------------------------------------

/**
 * The only place the extension reads what was typed: right as the user
 * submits a login form. The background keeps it in memory for a few minutes
 * to offer a save once the sign-in goes through, and drops it after.
 */
async function submitted() {
  const now = Date.now()
  if (now - lastSubmitAt < 800 || !fields.length) return
  lastSubmitAt = now
  const matches = (f: Field, role: Field["role"] | Field["role"][]) => (Array.isArray(role) ? role.includes(f.role) : f.role === role)
  // Usernames are often filled in by the site itself; passwords count only
  // if they're what was last typed or filled (see ownValue). Values are read
  // now, at the submit, and compared after.
  const username = fields.find((f) => matches(f, IDENTIFIER_ROLES) && f.el.value)?.el.value
  const read = (role: Field["role"]) => {
    const f = fields.find((x) => matches(x, role) && x.el.value)
    return f ? ownValue(f.el, f.el.value) : undefined
  }
  // Sign-up and change-password forms: the new password (first box; the
  // confirmation must match it or the site rejects the form anyway).
  const [password, newPassword] = await Promise.all([read("password"), read("new-password")])
  // A username alone still counts: email-first sign-ins submit it a step
  // before the password, and no check runs without one.
  if (!username && !password && !newPassword) return
  const roles = [...new Set(fields.map((f) => f.role))]
  // A generated password stays with the agent: name it instead.
  const generated = generatedId(newPassword)
  const attempt = ++submission
  send({ type: "db:capture", username, password, newPassword: generated ? undefined : newPassword, generated, title: document.title, kind, roles, submission: attempt })
  watchForFailure(kind, roles, attempt)
}

/**
 * Five seconds after a submit, the same kind of form on the same page with a
 * password or code box showing means the site turned it down (1Password's
 * check): the background then offers nothing. A newer submit takes over: the
 * form showing still after a retry says nothing about the retry.
 */
function watchForFailure(submittedKind: SurfaceKind | null, roles: Field["role"][], attempt: number) {
  window.clearTimeout(failureTimer)
  const secret: Field["role"][] = roles.filter((r) => r === "password" || r === "new-password" || r === "otp")
  if (!submittedKind || !secret.length) return
  const page = location.origin + location.pathname
  failureTimer = window.setTimeout(() => {
    if (location.origin + location.pathname !== page || attempt !== submission) return
    refresh()
    if (kind === submittedKind && fields.some((f) => secret.includes(f.role) && isVisible(f.el))) send({ type: "db:failed", submission: attempt })
  }, FAILED_AFTER_MS)
}

const realTarget = (event: Event) => eventTarget(event)

// Only the user's own clicks and keypresses count: pages can dispatch
// synthetic ones. Two things hang off a submit, with two different bars:
//
// - Saving (captured): a trusted click on the submit control, Enter in a
//   field, or a trusted submit event. That filters out pages that drive
//   their own forms; it doesn't prove the user chose the values, and nothing
//   relies on it doing so: a capture only ever leads to an offer the user
//   has to accept, after the outcome judge (bg/save.ts).
// - A sign-in session's next step (stepped, db:submitted): only the user's
//   own click on a submit control or Enter in a field, or a submit event
//   right after one. A page's form.requestSubmit() fires a submit event the
//   browser marks trusted, so a submit event alone doesn't count here.
const GESTURE_WINDOW_MS = 1000
let submitGestureAt = -Infinity

/** What was submitted goes to the background, to offer to save it if the sign-in works. */
function captured() {
  scheduleScan()
  void submitted()
  settleAfterSubmit()
}

/** The user themselves submitted: a sign-in session may move on to its next step. */
function stepSubmitted() {
  markSubmitted()
  void send({ type: "db:submitted" })
}

/** The user's own click on a submit control or Enter in a field. */
function gesture() {
  submitGestureAt = performance.now()
  noteSubmitGesture()
}

const SUBMITS = 'button:not([type]), button[type="submit"], input[type="submit"], input[type="image"]'

function onClick(event: MouseEvent) {
  if (!event.isTrusted) return
  let node = realTarget(event) as Element | null
  const control = node?.closest("a, button")
  if (offerSignIn && isTop && control instanceof HTMLElement && isVisible(control) &&
      !control.matches(":disabled, [aria-disabled=true]") && SIGN_OUT.test((control.getAttribute("aria-label") || control.textContent || "").trim())) {
    const box = control.getBoundingClientRect()
    const hit = event.detail === 0 ? deepActiveElement() === control :
      event.clientX >= box.left && event.clientX <= box.right && event.clientY >= box.top && event.clientY <= box.bottom &&
      control.contains(document.elementFromPoint(event.clientX, event.clientY))
    if (box.width > 0 && box.width <= 320 && box.height > 0 && box.height <= 96 &&
        box.top >= 0 && box.left >= 0 && box.bottom <= innerHeight && box.right <= innerWidth && hit)
      void send({ type: "db:signin-signout" })
  }
  for (let depth = 0; node instanceof Element && depth < 6; depth++, node = node.parentElement) {
    if (submitControl && node === submitControl) {
      gesture()
      captured()
      return stepSubmitted()
    }
    // Any submit button of the login form lets the submit event that follows count as the user's.
    if (node.matches(SUBMITS) && fields.some((f) => (node as Element).closest("form")?.contains(f.el))) return gesture()
  }
}

function onSubmit(event: Event) {
  if (!event.isTrusted) return
  const form = realTarget(event)
  if (!(form instanceof HTMLFormElement) || !fields.some((f) => form.contains(f.el))) return
  submittedForm = form
  captured()
  if (performance.now() - submitGestureAt <= GESTURE_WINDOW_MS) stepSubmitted()
}

function onKeydown(event: KeyboardEvent) {
  if (event.isTrusted && event.key === "Escape" && isTop && offerSignIn) void send({ type: "db:signin-stop" })
  if (!event.isTrusted || event.key !== "Enter") return
  const target = realTarget(event)
  if (!fields.some((f) => f.el === target)) return
  gesture()
  captured()
  stepSubmitted()
}

// First, while it's still document_start: the hook is waiting for its port.
initPasskeyChannel(send)
const state = { targets: () => fields, form: () => formId, kind: () => kind, rescan: refresh, formFields: () => formFields, formsForm: () => formsId }
initMenu(state)
initFrameChecks(state)
initLearn()
// On window, in the capture phase, from document_start: these run before any
// listener a page script can add, so a page can't swap a value in first.
window.addEventListener("input", trackUserInput, true)
window.addEventListener("click", onClick, true)
window.addEventListener("submit", onSubmit, true)
window.addEventListener("keydown", onKeydown, true)
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true })
else start()
