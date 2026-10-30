// The page side of a provider sign-in chain (bg/provider-chain.ts): after
// the person's one guarded pick, the background walks a site's "Continue
// with <provider>" button, the provider's account chooser, its sign-in form
// or its "Use a passkey" option, one step per document, and asks this script
// what the top page shows (db:provider-probe) and to do the one thing it
// found (db:provider-act). Everything else stops the chain untouched: OAuth
// consent, phone or SMS steps, security keys, captchas and anything
// unrecognised. Nothing here is clicked on a guess: every control must be
// the only candidate, enabled, and fully on screen and on top.
//
// Replies carry no page text or values, only a kind, the form's roles and an
// opaque handle. Values come only with an act on a form handle, and are
// written only when every field can take one, or not at all.
//
// While a chain is active (db:provider-status), a quiet pill in the corner
// says so, and the person's own pointer press, click, typing or Escape
// anywhere stops it here at once, before telling the background
// (db:signin-stop): a step already on its way can't land after that. A
// stopped session stays stopped in this document; only another session (a
// new pick) can start again.

import { SIGNIN_SETTING } from "../auth-state"
import { IDENTIFIER_ROLES, type FieldRole, type FillValues, type ProviderReport, type ToContent } from "../messages"
import { isAccountPage, isChooserPage, isProviderPage, provider as providerById, type Provider } from "../signin"
import { reducedMotion, timing } from "../ui/motion"
import { signedInHint } from "./auth-state"
import { hasPhrase, words } from "./clues"
import { BUSY, CAPTCHA, controlText, deliveredCode, findAccountTile, findProviderButton, inPlace, isVisible, sole, type Field } from "./detect"
import { clippedBox, fillable, fillFields, fits, hiddenByStyle } from "./fill"
import { send, type PageState } from "./inline"
import { deepActiveElement, deepQueryAll, markOwnHost, openRoots } from "./shadow"

export interface ChainHooks {
  /** The top page, with "Offer to sign in" on. */
  enabled(): boolean
  /** Submits after a complete fill, as the guarded db:signin-submit does: `form` is null for a form-less step. */
  submit(form: HTMLFormElement | null, button: HTMLElement): void
}

type Reason = NonNullable<ProviderReport["reason"]>
type Probe = Extract<ToContent, { type: "db:provider-probe" }>
type Act = Extract<ToContent, { type: "db:provider-act" }>
type Status = Extract<ToContent, { type: "db:provider-status" }>

/** How long a probe's handle may be acted on. */
const HANDLE_MS = 15_000
/** A probe on a page still loading or redirecting waits this long for it to settle, then stops. */
const SETTLE_MS = 2000
const SETTLE_STEP_MS = 150
/** Between a complete fill and its submit: the page's own handlers run (and may submit by themselves). */
const SUBMIT_DELAY_MS = 150
/** A finished chain's last word stays this long, then fades (within 1.5 s in all). */
const DONE_HOLD_MS = 900
const INSET = 12

const SUBMIT_LABEL = /^(sign\s?in|log\s?in|login|continue|next|verify|confirm(?: code)?|submit)$/i
const PASSKEY_LABEL = /^(?:use (?:a|your) passkey|sign in with (?:a|your) passkey)$/i
/**
 * OAuth consent on a provider page: hard evidence that stops the chain before
 * any chooser, form or passkey step, and again before each act and submit.
 * ("to continue to" is not: Google's own chooser says it.)
 */
const STRONG_CONSENT_LABEL = /^(allow|authori[sz]e|grant|accept|continue as)\b/i
/** Buttons on a provider page with no form, tile or passkey option left: an interstitial, never clicked. */
const CONSENT_LABEL = /^(continue|confirm|yes|agree|approve)\b/i
const phrases = (list: string[]) => list.map((p) => words(p).trim())
// Not "share your": Google's chooser and password pages carry the sign-in
// disclosure "To continue, Google will share your name, email address…".
const STRONG_CONSENT = phrases(["wants to access", "would like to access", "wants access", "is requesting access", "requesting permission", "grant access", "allow access", "access your", "will allow", "permissions requested"])
/** Page text longer than this is unknown: a warning past a cut-off must not be missed. */
const TEXT_LIMIT = 20_000
const SECURITY_KEY = phrases(["security key", "insert your key", "touch your key", "usb key", "hardware key"])
const SMS = phrases(["text message", "sms", "we sent", "sent a code", "sent you a code", "check your email", "check your inbox", "email code", "emailed"])
const PHONE = phrases(["check your phone", "on your phone", "tap yes", "approve the request", "approve this sign in", "open the app", "phone number", "verify your phone", "number on your", "notification"])
const LOADING = phrases(["redirecting", "signing you in", "one moment", "please wait", "loading"])
const FIELDS = "input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=image]):not([type=reset]):not([type=checkbox]):not([type=radio]):not([type=file]), select, textarea"

// Prototype methods, so a page can't clobber them with a field named "action" or "contains".
const attr = (el: Element, name: string) => Element.prototype.getAttribute.call(el, name)
const within = (outer: Node, inner: Node) => Node.prototype.contains.call(outer, inner)
const formAction = (form: HTMLFormElement) => Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "action")!.get!.call(form) as string
const formElements = (form: HTMLFormElement) => Array.from(Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "elements")!.get!.call(form) as HTMLFormControlsCollection)
const queryIn = (root: Element, selector: string) => Array.from(Element.prototype.querySelectorAll.call(root, selector))
const nativeValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

interface Scope {
  form: HTMLFormElement | null
  root: Element
}
interface FormPlan {
  fields: Field[]
  scope: Scope
  button: HTMLElement
}
/** `provider`: minted on the provider's page, where consent is checked again before acting. `account`: the linked account the probe named. */
type Handle =
  | { kind: "click"; session: string; url: string; at: number; provider: boolean; el: HTMLElement; find: () => HTMLElement | null }
  | { kind: "form"; session: string; url: string; at: number; provider: true; form: number; plan: FormPlan; account?: string }

let page: PageState
let hooks: ChainHooks
/** The chain this document serves now, from its latest active status. */
let session: string | null = null
let active = false
/** Sessions stopped or ended in this document: a late status can't bring them back. */
const cancelled = new Set<string>()
/** Bumped on every stop and session change: work begun before it is void. */
let generation = 0
const handles = new Map<string, Handle>()

const live = (id: string) => active && id === session && !cancelled.has(id) && hooks.enabled() && !document.hidden

function mint(h: Handle): string {
  const id = crypto.randomUUID()
  handles.set(id, h)
  for (const old of handles.keys()) if (handles.size > 4) handles.delete(old)
  return id
}

const stop = (reason: Reason): ProviderReport => ({ kind: "stop", reason })

// ---- Can the person see it? ------------------------------------------------------

const SAMPLES = [[0.5, 0.5], [0.15, 0.2], [0.85, 0.2], [0.15, 0.8], [0.85, 0.8]]

/**
 * Enabled, unhidden, wholly inside the viewport and every clipping ancestor,
 * and what's under it at the middle and corners. Deadbolt's own pill counts
 * as a cover too: a page can move its host.
 */
function fullyShown(el: Element | null): el is HTMLElement {
  if (!(el instanceof HTMLElement) || !el.isConnected || !isVisible(el) || hiddenByStyle(el)) return false
  if (el.matches(":disabled, [aria-disabled=true]") || el.closest("[inert], [aria-hidden=true]")) return false
  const r = el.getBoundingClientRect()
  if (r.width < 8 || r.height < 8 || r.left < 0 || r.top < 0 || r.right > innerWidth || r.bottom > innerHeight) return false
  const box = clippedBox(el)
  if (!box || box.right - box.left < r.width - 1 || box.bottom - box.top < r.height - 1) return false
  const root = el.getRootNode() as Document | ShadowRoot
  return SAMPLES.every(([fx, fy]) => {
    const hit = root.elementFromPoint?.(r.left + r.width * fx, r.top + r.height * fy)
    return !!hit && (hit === el || within(el, hit))
  })
}

/** A control Deadbolt may click: fully shown, and a link or submit that stays in this tab. */
function clickable(el: HTMLElement, sameOrigin: boolean): boolean {
  if (!fullyShown(el)) return false
  const base = document.querySelector("base[target]")?.getAttribute("target") ?? ""
  const self = (t: string | null) => !t || t === "_self"
  const link = el.closest("a")
  if (link) {
    if (link.hasAttribute("download") || !self(attr(link, "target") ?? base)) return false
    try {
      const url = new URL(link.href)
      if (url.protocol !== "https:" && url.protocol !== "http:") return false
      if (sameOrigin && url.origin !== location.origin) return false
    } catch {
      return false
    }
  }
  if ((el instanceof HTMLButtonElement || el instanceof HTMLInputElement) && el.type === "submit" && el.form)
    return self(attr(el, "formtarget") ?? attr(el.form, "target") ?? base)
  return true
}

// ---- What the page shows ----------------------------------------------------------

/** The page's title, headings and text, or null when there's too much to read whole. */
function pageWords(): string | null {
  const body = document.body?.innerText ?? ""
  if (body.length > TEXT_LIMIT) return null
  const heads = Array.from(document.querySelectorAll<HTMLElement>("h1, h2, h3, [role=heading]")).slice(0, 8).map((h) => h.innerText)
  return ` ${words([document.title, ...heads, body].join(" \n "))} `
}
const any = (text: string, list: string[]) => list.some((p) => hasPhrase(text, p))

function loading(text: string): boolean {
  return document.readyState !== "complete" || deepQueryAll(BUSY, openRoots()).some(isVisible) || any(text, LOADING)
}

function entryControl(p: Provider): HTMLElement | null {
  const el = findProviderButton(p, true)
  return el instanceof HTMLElement && !(el instanceof HTMLIFrameElement) && clickable(el, false) ? el : null
}

function tileFor(p: Provider, account: string): HTMLElement | null {
  if (!isChooserPage(p, location.href)) return null
  const el = findAccountTile(account, true)
  return el instanceof HTMLElement && clickable(el, true) ? el : null
}

function passkeyControl(): HTMLElement | null {
  const found = deepQueryAll("button, [role=button], a[href], [role=link]", openRoots()).filter((el) => isVisible(el) && PASSKEY_LABEL.test(controlText(el)))
  const el = sole(found)
  return el instanceof HTMLElement && clickable(el, true) ? el : null
}

const labelled = (label: RegExp) =>
  deepQueryAll("button, [role=button], input[type=submit], input[type=button], a[href], [role=link]", openRoots()).some((el) => isVisible(el) && label.test(controlText(el)))
const strongConsent = (text: string) => any(text, STRONG_CONSENT) || labelled(STRONG_CONSENT_LABEL)
/** Consent showing now, or a page too long to tell: either stops a provider-page act. */
function consentNow(): boolean {
  const text = pageWords()
  return text === null || strongConsent(text)
}

/** The fields' one form, or for a form-less step (Google's password page) the one dialog or main region holding them all. */
function scopeOf(fields: Field[]): Scope | null {
  const forms = new Set(fields.map((f) => f.el.form))
  if (forms.size !== 1) return null
  const form = [...forms][0]
  if (form) return fields.every((f) => inPlace(f) && f.owner.form === form && within(form, f.el)) ? { form, root: form } : null
  const regions = new Set(fields.map((f) => f.el.closest("dialog, [role=dialog], main, [role=main]")))
  if (regions.size !== 1) return null
  const root = [...regions][0] ?? document.body
  return root && fields.every((f) => inPlace(f) && f.owner.form === null && within(root, f.el)) ? { form: null, root } : null
}

/** The step's one submit control: none showing yet (null), or several (ambiguous). */
function submitterOf(scope: Scope): HTMLElement | null | "ambiguous" {
  const labelled = (el: Element) => isVisible(el) && SUBMIT_LABEL.test(controlText(el).trim())
  const candidates = scope.form
    ? formElements(scope.form).filter((el) => (el instanceof HTMLButtonElement || el instanceof HTMLInputElement) && el.form === scope.form && (el instanceof HTMLButtonElement || ["submit", "image", "button"].includes(el.type)) && labelled(el))
    : // Form-less: every such button on the page counts, and the one must sit with the fields.
      deepQueryAll<HTMLButtonElement>("button", openRoots()).filter((el) => !el.form && labelled(el))
  if (!candidates.length) return null
  const el = sole(candidates)
  if (!(el instanceof HTMLElement)) return "ambiguous"
  return within(scope.root, el) ? el : "ambiguous"
}

/** The effective destination: this origin (action and formaction, raw and resolved), in this tab. */
function destinationOk(scope: Scope, button: HTMLElement): boolean {
  const form = scope.form
  if (!form) return true
  const submits = (button instanceof HTMLButtonElement || button instanceof HTMLInputElement) && ["submit", "image"].includes(button.type)
  const override = submits && button.hasAttribute("formaction")
  const raw = override ? attr(button, "formaction") : attr(form, "action")
  const resolved = override ? (button as HTMLButtonElement).formAction : formAction(form)
  try {
    for (const url of [resolved, raw ? new URL(raw, document.baseURI).href : location.href])
      if (new URL(url, location.href).origin !== location.origin) return false
  } catch {
    return false
  }
  const target = (submits ? attr(button, "formtarget") : null) ?? attr(form, "target") ?? document.querySelector("base[target]")?.getAttribute("target") ?? ""
  return !target || target === "_self"
}

/**
 * The sign-in form as a whole: its every field classified (identifier,
 * password or authenticator code), in one form or region, nothing else to
 * type there, no other password box on the page, one submit control and a
 * same-origin destination. Null when there is no form.
 */
/**
 * The linked account, when the provider's own account page (Google's)
 * shows it as its account chip: every visible [data-profile-identifier] says
 * exactly that account. Only then may a code prompt's standalone line naming
 * it be read past (see deliveredCode); anything else stays strict.
 */
function chipAccount(account: string | undefined): string | undefined {
  if (!account || !isAccountPage(location.href)) return undefined
  const want = account.trim().toLowerCase()
  const chips = deepQueryAll<HTMLElement>("[data-profile-identifier]", openRoots()).filter(isVisible)
  return want && chips.length && chips.every((c) => c.innerText.trim().toLowerCase() === want) ? account : undefined
}

function inspectForm(account?: string): FormPlan | { stop: Reason } | "wait" | null {
  const kind = page.kind()
  const fields = page.targets()
  if (kind !== "login" && kind !== "mfa") return kind ? { stop: "unknown" } : null
  // A code step whose code the person brings (sent by SMS or email, or a backup code).
  if (!fields.length) return kind === "mfa" ? { stop: "sms" } : null
  if (fields.some((f) => f.role === "captcha")) return { stop: "captcha" }
  if (fields.some((f) => f.role === "phone")) return { stop: "phone" }
  if (fields.some((f) => !IDENTIFIER_ROLES.includes(f.role) && f.role !== "password" && f.role !== "otp")) return { stop: "unknown" }
  const scope = scopeOf(fields)
  if (!scope) return { stop: "unknown" }
  if (deliveredCode(fields, scope.form, chipAccount(account))) return { stop: "sms" }
  const own = new Set<Element>(fields.map((f) => f.el))
  const strays = queryIn(scope.root, FIELDS).filter((el) => !own.has(el) && isVisible(el) && !hiddenByStyle(el) && !!clippedBox(el))
  if (strays.length) return { stop: "unknown" }
  if (deepQueryAll<HTMLInputElement>("input[type=password]", openRoots()).some((el) => !own.has(el) && isVisible(el) && !hiddenByStyle(el))) return { stop: "unknown" }
  const button = submitterOf(scope)
  if (button === "ambiguous") return { stop: "unknown" }
  if (button && !destinationOk(scope, button)) return { stop: "unknown" }
  if (!button || !fullyShown(button) || !fields.every((f) => fillable(f.el))) return "wait"
  return { fields: [...fields], scope, button }
}

function evaluate(message: Probe): ProviderReport | "wait" {
  const p = providerById(message.provider)
  // Only providers Deadbolt knows by their sign-in hosts (signin.ts KNOWN).
  if (!p.hosts.length || document.hidden || window !== window.top) return stop("unknown")
  page.rescan()
  const onProvider = isProviderPage(p, location.href)
  const base = { session: message.session, url: location.href, at: Date.now() }
  if (message.entry) {
    // The site's own page: its one provider button, nothing else. No account is sent here.
    if (onProvider || message.account !== undefined) return stop("unknown")
    const el = entryControl(p)
    if (el) return { kind: "entry", action: mint({ kind: "click", ...base, provider: false, el, find: () => entryControl(p) }) }
    if (signedInHint(page)) return { kind: "success" }
    const text = pageWords()
    return text !== null && loading(text) ? "wait" : stop("unknown")
  }
  if (!onProvider) return stop("unknown")
  if (deepQueryAll(CAPTCHA, openRoots()).some(isVisible)) return stop("captcha")
  const text = pageWords()
  if (text === null) return stop("unknown")
  if (strongConsent(text)) return stop("consent")
  const account = message.account
  const tile = account ? tileFor(p, account) : null
  if (tile && account) return { kind: "chooser", action: mint({ kind: "click", ...base, provider: true, el: tile, find: () => tileFor(p, account) }) }
  const form = inspectForm(account)
  if (form && form !== "wait" && "stop" in form) return stop(form.stop)
  if (form && form !== "wait") {
    const roles = [...new Set(form.fields.map((f) => f.role))].sort()
    return { kind: "form", form: page.form(), roles, action: mint({ kind: "form", ...base, provider: true, form: page.form(), plan: form, ...(account ? { account } : {}) }) }
  }
  if (form === "wait") return "wait"
  if (any(text, SECURITY_KEY)) return stop("security-key")
  const passkey = passkeyControl()
  if (passkey) return { kind: "passkey", action: mint({ kind: "click", ...base, provider: true, el: passkey, find: passkeyControl }) }
  if (any(text, SMS)) return stop("sms")
  if (any(text, PHONE)) return stop("phone")
  // Signed straight in on the provider's own site (it is the site picked).
  if (signedInHint(page)) return { kind: "success" }
  if (labelled(CONSENT_LABEL)) return stop("consent")
  return loading(text) ? "wait" : stop("unknown")
}

async function probe(message: Probe): Promise<ProviderReport> {
  const deadline = performance.now() + SETTLE_MS
  for (;;) {
    if (!live(message.session)) return stop("unknown")
    const report = evaluate(message)
    if (report !== "wait") return report
    if (performance.now() > deadline) return stop("unknown")
    await sleep(SETTLE_STEP_MS)
  }
}

// ---- Acting ---------------------------------------------------------------------------

function actClick(h: Extract<Handle, { kind: "click" }>, gen: number): boolean {
  const el = h.find()
  if (el !== h.el || (h.provider && consentNow())) return false
  // Answer before a navigation unloads the asking document. At the click
  // itself, the control is found afresh: still the only one, and fully shown.
  setTimeout(() => {
    if (gen === generation && live(h.session) && h.find() === el && !(h.provider && consentNow())) el.click()
  }, 0)
  return true
}

const sameFields = (a: Field[], b: Field[]) => a.length === b.length && a.every((f, i) => f.el === b[i].el && f.role === b[i].role)

/** The value a field takes: the account's, a digit of the code for one box of a split code. */
function valueFor(f: Field, values: FillValues, boxes: Field[]): string | undefined {
  if (IDENTIFIER_ROLES.includes(f.role)) return values.username
  if (f.role === "password") return values.password
  if (f.role !== "otp" || !values.totp) return undefined
  return f.split ? values.totp[boxes.indexOf(f)] : values.totp
}

/** A field already holding exactly this value is left alone; any other value means the person (or page) has its own: no fill. */
function matches(f: Field, value: string): boolean {
  return IDENTIFIER_ROLES.includes(f.role) ? f.el.value.trim().toLowerCase() === value.trim().toLowerCase() : f.el.value === value
}

/** Empties a box Deadbolt wrote, without focusing it. */
function clear(el: HTMLInputElement) {
  nativeValue.call(el, "")
  el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "deleteContentBackward" }))
  el.dispatchEvent(new Event("change", { bubbles: true }))
}

/** Back where the person was, unless they or the page moved focus during the fill; never onto a login field (its menu would open). */
function restoreFocus(prior: Element | null, written: HTMLInputElement[]) {
  const now = deepActiveElement()
  if (!(now instanceof HTMLInputElement) || !written.includes(now)) return
  const field = page.targets().some((f) => f.el === prior)
  if (prior instanceof HTMLElement && prior !== document.body && prior.isConnected && !field && !(prior instanceof HTMLInputElement && written.includes(prior))) prior.focus({ preventScroll: true })
  else now.blur()
}

async function actForm(h: Extract<Handle, { kind: "form" }>, values: FillValues | undefined, gen: number): Promise<boolean> {
  const halted = () => gen !== generation || !live(h.session)
  page.rescan()
  if (!values || values.newPassword !== undefined || page.form() !== h.form || location.href !== h.url || consentNow()) return false
  const now = inspectForm(h.account)
  if (!now || now === "wait" || "stop" in now || !sameFields(now.fields, h.plan.fields) || now.button !== h.plan.button || now.scope.root !== h.plan.scope.root) return false
  const { fields, scope, button } = now
  const roles = new Set<string>(fields.map((f) => (IDENTIFIER_ROLES.includes(f.role) ? "username" : f.role === "otp" ? "totp" : f.role)))
  // Nothing beyond the form's own roles, and a value for every field.
  if ((Object.keys(values) as Array<keyof FillValues>).some((k) => values[k] !== undefined && !roles.has(k))) return false
  const boxes = fields.filter((f) => f.role === "otp" && f.split).sort((a, b) => (a.el.compareDocumentPosition(b.el) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1))
  if (boxes.length && (!values.totp || values.totp.length !== boxes.length || !/^\d+$/.test(values.totp))) return false
  const plan: Array<{ f: Field; value: string }> = []
  for (const f of fields) {
    const value = valueFor(f, values, boxes)
    if (!value) return false
    if (f.el.value) {
      if (!matches(f, value)) return false
      continue
    }
    if (!fits(f.el, f.role, value) || !fillable(f.el)) return false
    plan.push({ f, value })
  }
  // A split code fills as a whole or not at all.
  const planned = plan.filter((p) => p.f.split).length
  if (planned && planned !== boxes.length) return false
  if (halted()) return false

  const prior = deepActiveElement()
  const fill: FillValues = {}
  for (const { f } of plan) {
    if (IDENTIFIER_ROLES.includes(f.role)) fill.username = values.username
    else if (f.role === "password") fill.password = values.password
    else fill.totp = values.totp
  }
  const result = plan.length ? await fillFields(plan.map((p) => p.f), fill, (el) => !halted() && fillable(el)) : { filled: [] as FieldRole[], written: [] as HTMLInputElement[] }
  // Which planned field each write went to: the field itself, or the box a re-render put in its place.
  const entryOf = (el: HTMLInputElement) =>
    plan.find((p) => p.f.el === el) ?? plan.find((p) => !p.f.el.isConnected && p.f.el.name === el.name && p.f.el.id === el.id && p.f.el.type === el.type)
  const complete = !halted() && plan.every((p) => result.written.some((el) => entryOf(el) === p && el.isConnected && el.value === p.value))
  if (!complete) {
    // No half fill: take back what this fill wrote, unless the person has changed it since.
    for (const el of result.written) {
      const p = entryOf(el)
      if (p && el.isConnected && el.value === p.value) clear(el)
    }
    restoreFocus(prior, result.written)
    return false
  }
  restoreFocus(prior, result.written)
  // What the submit sends: the act's own fields (or the box a re-render put
  // in place of one this fill wrote), each holding exactly its value.
  const expected = new Map<HTMLInputElement, { role: FieldRole; value: string }>()
  for (const f of fields) {
    const p = plan.find((x) => x.f === f)
    const el = p ? result.written.find((w) => entryOf(w) === p) : f.el
    if (!el) return false
    expected.set(el, { role: f.role, value: p ? p.value : f.el.value })
  }
  setTimeout(() => {
    if (halted()) return
    page.rescan()
    const again = consentNow() ? null : inspectForm(h.account)
    // A stale snapshot (consent, a field swapped, added or changed since, the
    // control moved) declines the submit and ends the chain now. The filled
    // form stays as it is; nothing else is touched.
    const fresh = location.href === h.url && !!again && again !== "wait" && !("stop" in again) && again.button === button && again.scope.root === scope.root &&
      again.fields.length === expected.size && again.fields.every((f) => {
        const want = expected.get(f.el)
        return !!want && want.role === f.role && f.el.value === want.value && fillable(f.el)
      })
    if (fresh) hooks.submit(scope.form, button)
    else stopHere(true)
  }, SUBMIT_DELAY_MS)
  return true
}

async function act(message: Act): Promise<boolean> {
  const h = handles.get(message.action)
  handles.delete(message.action)
  const gen = generation
  if (!h || h.session !== message.session || !live(message.session) || Date.now() - h.at > HANDLE_MS || location.href !== h.url) return false
  return h.kind === "click" ? actClick(h, gen) : actForm(h, message.values, gen)
}

// ---- The pill -----------------------------------------------------------------------------

let host: HTMLElement | null = null
let label: HTMLElement | null = null
let fadeTimer: ReturnType<typeof setTimeout> | undefined
/** The pill is on its way out: a new status makes a new one rather than revive it. */
let fading = false

const STYLE = `
.pill{position:fixed;top:${INSET}px;right:${INSET}px;display:flex;align-items:center;gap:6px;height:28px;padding:0 4px 0 10px;border-radius:14px;font:500 12px/16px "Inter",-apple-system,BlinkMacSystemFont,system-ui,sans-serif;white-space:nowrap;pointer-events:auto;user-select:none;background:#fff;color:#161616;box-shadow:0 0 0 0.5px rgb(0 0 0 / 12%),0 4px 12px rgb(0 0 0 / 12%)}
.x{position:relative;display:grid;place-items:center;width:20px;height:20px;padding:0;border:0;border-radius:10px;background:transparent;color:inherit;opacity:.6;cursor:default;transition:background-color 100ms ease-out,opacity 100ms ease-out}
.x::before{content:"";position:absolute;inset:-12px}
.x[hidden]{display:none}
@media (hover:hover) and (pointer:fine){.x:hover{transition:none;opacity:1;background:rgb(0 0 0 / 6%)}}
@media (prefers-color-scheme:dark){.pill{background:#161616;color:#fafafa;box-shadow:0 0 0 0.5px rgb(255 255 255 / 14%),0 4px 12px rgb(0 0 0 / 50%)}@media (hover:hover) and (pointer:fine){.x:hover{background:rgb(255 255 255 / 10%)}}}
`
const CROSS = `<svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`

function removePill() {
  clearTimeout(fadeTimer)
  host?.remove()
  host = label = null
  fading = false
}

/** Fades the pill out now (a declined step), then removes it. */
function fadePill(after = 0) {
  const leaving = host
  if (!leaving) return
  fading = true
  clearTimeout(fadeTimer)
  fadeTimer = setTimeout(() => {
    const anim = leaving.animate(reducedMotion() ? [{ opacity: 1 }, { opacity: 0 }] : [{ opacity: 1 }, { opacity: 0, filter: "blur(3px)" }], { ...timing(0.25), fill: "forwards" })
    // Gone within the budget even if the animation never finishes.
    const gone = () => { if (host === leaving) removePill() }
    anim.finished.then(gone, gone)
    fadeTimer = setTimeout(gone, 350)
  }, after)
}

/** The pill saying `text`, made if need be. It never takes focus: its button is out of the tab order and a press on it doesn't focus. */
function showPill(text: string, done: boolean) {
  clearTimeout(fadeTimer)
  if (!host || !host.isConnected || fading) {
    removePill()
    host = document.createElement("div")
    host.style.cssText = "all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483647;display:block;"
    markOwnHost(host)
    const root = host.attachShadow({ mode: "closed" })
    const style = document.createElement("style")
    style.textContent = STYLE
    const pill = document.createElement("div")
    pill.className = "pill"
    label = document.createElement("span")
    label.setAttribute("role", "status")
    const x = document.createElement("button")
    x.className = "x"
    x.type = "button"
    x.tabIndex = -1
    x.setAttribute("aria-label", "Stop signing in")
    x.innerHTML = CROSS
    // The guard (onGesture) stops the chain on this press; it just mustn't move focus.
    x.addEventListener("pointerdown", (e) => e.preventDefault())
    x.addEventListener("mousedown", (e) => e.preventDefault())
    pill.append(label, x)
    root.append(style, pill)
    document.documentElement.append(host)
    pill.animate(reducedMotion() ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, transform: "translateY(-4px)" }, { opacity: 1, transform: "none" }], timing(0.25))
  }
  if (label!.textContent !== text) label!.textContent = text
  const x = label!.nextElementSibling as HTMLElement
  x.hidden = done
  if (done) fadePill(DONE_HOLD_MS)
}

function status(message: Status): boolean {
  if (cancelled.has(message.session)) return false
  if (message.done) {
    // An ended session is over here for good: a late active status can't rearm it.
    cancelled.add(message.session)
    // An older session's end never takes down a newer one's pill.
    if (message.session !== session) return true
    active = false
    generation++
    handles.clear()
    if (message.label) showPill(message.label, true)
    else removePill()
    return true
  }
  if (!hooks.enabled()) return false
  if (message.session !== session) {
    session = message.session
    generation++
    handles.clear()
  }
  active = true
  showPill(message.label, false)
  return true
}

/** Between a pick and its first status, stops repeat at most this often (one press is a pointerdown and a click). */
const STOP_EVERY_MS = 300
let stopSentAt = -Infinity

/**
 * "Offer to sign in", for a frame below the top page: there a gesture only
 * forwards a stop, since the top page can't see clicks inside a cross-site
 * frame. A frame never takes status, probes or acts.
 */
let frameOffer = false

/**
 * The person's own press, click, typing or Escape, in this page or a frame
 * of it: an active chain stops here first, then in the background. With
 * none active yet (or in a frame), the background still hears it, so a pick
 * whose first status is still on its way is stopped too. The event itself
 * goes on to the page untouched. Focus moving away (a provider's popup) is
 * not a stop.
 */
function onGesture(event: Event) {
  if (!event.isTrusted) return
  if (event instanceof KeyboardEvent && event.key !== "Escape") return
  const top = window === window.top
  if (top ? !hooks.enabled() : !frameOffer) return
  if (top && active && session) return stopHere(false)
  if (performance.now() - stopSentAt < STOP_EVERY_MS) return
  stopSentAt = performance.now()
  void send({ type: "db:signin-stop" })
}

/** Ends the active session here at once, then tells the background; `fade` lets the pill fade rather than vanish. */
function stopHere(fade: boolean) {
  if (session) cancelled.add(session)
  active = false
  generation++
  handles.clear()
  if (fade) fadePill()
  else removePill()
  stopSentAt = performance.now()
  void send({ type: "db:signin-stop" })
}

export function initProviderChain(state: PageState, chainHooks: ChainHooks) {
  page = state
  hooks = chainHooks
  for (const type of ["pointerdown", "click", "keydown", "input"]) window.addEventListener(type, onGesture, true)
  void chrome.storage.local.get(SIGNIN_SETTING).then((s) => { frameOffer = s[SIGNIN_SETTING] === true }, () => {})
  chrome.storage.onChanged?.addListener((changes, area) => {
    if (area === "local" && SIGNIN_SETTING in changes) frameOffer = changes[SIGNIN_SETTING].newValue === true
  })
  chrome.runtime.onMessage.addListener((message: ToContent, sender, respond) => {
    const type = message?.type
    if (type !== "db:provider-probe" && type !== "db:provider-act" && type !== "db:provider-status") return
    // Only the service worker drives a chain: not a page's frame or an extension page.
    const fromWorker = sender.id === chrome.runtime.id && !sender.tab && sender.url === chrome.runtime.getURL("background.js")
    if (!fromWorker || window !== window.top || typeof message.session !== "string" || !message.session) return void respond(type === "db:provider-probe" ? stop("unknown") : false)
    if (message.type === "db:provider-status") return void respond(status(message))
    if (message.type === "db:provider-probe") {
      probe(message).then(respond, () => respond(stop("unknown")))
      return true
    }
    act(message).then(respond, () => respond(false))
    return true
  })
}
