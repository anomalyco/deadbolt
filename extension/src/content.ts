// Content script, in every frame of http(s) pages: finds login forms, opens
// the inline menu on their fields, applies fills, and hands what the user
// submitted to the background so it can offer to save it. Scheduling and
// submit tracking are ported from Foyer (github.com/R44VC0RP/foyer,
// src/content.ts, by Ryan Vogel), without its sign-in recording.

import { scanPage, type Field } from "./content/detect"
import { initFrameChecks } from "./content/embed"
import { ownValue, trackUserInput } from "./content/fill"
import { initMenu, markSubmitted, noteSubmitGesture, refreshMenu, send, stepped } from "./content/inline"
import { pageFacts } from "./content/outcome"
import { initPasskeyChannel } from "./content/passkeys"
import { deepActiveElement, openRoots } from "./content/shadow"
import { IDENTIFIER_ROLES, type SurfaceKind, type ToContent } from "./messages"

const isTop = window === window.top
const SCAN_INTERVAL_MS = 750
const QUIET_AFTER_MS = 2500

/** Live fields of the current login form. Never sent anywhere. */
let fields: Field[] = []
let submitControl: Element | undefined
let kind: SurfaceKind | null = null
/** Bumped whenever the set of fields changes, so a fill can't land on a different form. */
let formId = 0
let lastSignature = ""
/** Whether the background was last told of a form here, so it hears when it goes. */
let reported = false
let lastUrl = location.href
let quietTimer: number | undefined
/** The URL (and step) the background was last told settled for, so it's told once. */
let settledFor = ""
let afterSubmitTimer: number | undefined
let lastSubmitAt = 0

const sameFields = (a: Field[], b: Field[]) =>
  a.length === b.length && a.every((f, i) => f.el === b[i].el && f.role === b[i].role && f.owner.form === b[i].owner.form && f.owner.parent === b[i].owner.parent)

/** Finds the login form's fields now. */
function refresh() {
  if (!document.body) return
  watchShadowRoots()
  const result = scanPage()
  kind = result.kind
  // A reset form's email box isn't something to fill.
  const next = kind && kind !== "reset" ? result.fields : []
  if (!sameFields(fields, next)) formId++
  fields = next
  submitControl = kind ? result.submit : undefined
}

function scan() {
  if (document.hidden || !document.body) return
  if (location.href !== lastUrl) {
    lastUrl = location.href
    lastSignature = ""
  }
  refresh()
  void report(false)

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
  const signature = JSON.stringify([location.href, kind, roles, formId, moved, idEmpty])
  const tell = always || (kind ? signature !== lastSignature : reported)
  lastSignature = kind ? signature : ""
  reported = !!kind
  if (tell) await send({ type: "db:page", kind, roles, form: formId, stepped: moved, idEmpty })
}

chrome.runtime.onMessage.addListener((message: ToContent, _sender, respond) => {
  if (message?.type === "db:probe") {
    if (!isTop) return void respond(null)
    try {
      refresh()
      respond(pageFacts(kind, fields, typeof message.username === "string" ? message.username : undefined))
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
  // Back from the back/forward cache: the background forgot this document's form.
  window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return
    lastSignature = ""
    scheduleScan()
  })
}

// Shadow roots need their own observer, and their own submit listener:
// "submit" doesn't cross shadow boundaries the way click and keydown do.
const watchedRoots = new WeakSet<ShadowRoot>()
function watchShadowRoots() {
  for (const root of openRoots()) {
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
  send({ type: "db:capture", username, password, newPassword, title: document.title })
}

const realTarget = (event: Event) => event.composedPath()[0] ?? event.target

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
  captured()
  if (performance.now() - submitGestureAt <= GESTURE_WINDOW_MS) stepSubmitted()
}

function onKeydown(event: KeyboardEvent) {
  if (!event.isTrusted || event.key !== "Enter") return
  const target = realTarget(event)
  if (!fields.some((f) => f.el === target)) return
  gesture()
  captured()
  stepSubmitted()
}

// First, while it's still document_start: the hook is waiting for its port.
initPasskeyChannel(send)
const state = { targets: () => fields, form: () => formId, rescan: refresh }
initMenu(state)
initFrameChecks(state)
// On window, in the capture phase, from document_start: these run before any
// listener a page script can add, so a page can't swap a value in first.
window.addEventListener("input", trackUserInput, true)
window.addEventListener("click", onClick, true)
window.addEventListener("submit", onSubmit, true)
window.addEventListener("keydown", onKeydown, true)
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true })
else start()
