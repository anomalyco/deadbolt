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
import { bestRole, FORM_KINDS, hasPhrase, providerFromLabel, scoreField, scoreFormText, squash, words, type FieldFacts, type FormKind, type Provider } from "./clues"
import { graphOf, innerText, isVisible, within, type FormCluster, type FormGraph, type ScanSource } from "./graph"
import { clusterFeatures, confirmations, decoyCluster, LOGIN_TOKENS, loginOdds, notLogin, rationalize, unclaimedBoxes, type PageFacts, type ScannedField } from "./rationalize"
import { deepQueryAll, openRoots } from "./shadow"

export { ignored, isVisible, labelText, type FormControl } from "./graph"

/** A password box that asks for a new password by autocomplete, whatever the detector made of its form: a sign-up, never a sign-in step to submit. */
export const asksNewPassword = (fields: Field[]) => fields.some((f) => f.el.type === "password" && /\bnew-password\b/.test(f.el.autocomplete))

export const LOGIN_URL = /log-?in|log_in|logon|sign-?in|sign_in|signon|auth|sso|saml|oauth|session|identifier|challenge|mfa|2fa|two-factor|two-step|2-step|totp|\botp\b|verify|webauthn|passkey/i
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

/** Minimum score for the page to count as a given kind of form. */
const FORM_THRESHOLD = 3

/** Label of a button. Matched against vocabularies only, never stored. */
export function controlText(el: Element): string {
  const input = el instanceof HTMLInputElement && (el.type === "submit" || el.type === "button") ? el.value : ""
  const text = el.getAttribute("aria-label") || innerText(el) || input || el.getAttribute("title") || ""
  return text.replace(/\s+/g, " ").trim().slice(0, 120)
}

/**
 * Label a button shows: its text, or an input's value. An aria-label that
 * says something else makes it none, so a button that reads "Delete account"
 * can't pass as "Continue" (or the other way round).
 */
export function visibleLabel(el: Element): string {
  const input = el instanceof HTMLInputElement ? (el.type === "submit" || el.type === "button" ? el.value : "") : innerText(el)
  const shown = input.replace(/\s+/g, " ").trim()
  const aria = (el.getAttribute("aria-label") ?? "").replace(/\s+/g, " ").trim()
  return aria && aria.toLowerCase() !== shown.toLowerCase() ? "" : shown.slice(0, 120)
}

// ---- Field facts ---------------------------------------------------------------

/**
 * A password box, or a text box the page masks with CSS
 * (`-webkit-text-security`) to keep the browser's own password handling away.
 */
export function masked(el: HTMLInputElement, style: (el: Element) => CSSStyleDeclaration = getComputedStyle): boolean {
  if (el.type === "password") return true
  if (el.type !== "text") return false
  const security = style(el).getPropertyValue("-webkit-text-security")
  return !!security && security !== "none"
}

function factsFor(el: HTMLInputElement, graph: FormGraph, isMasked: boolean): FieldFacts {
  const code = [el.id, el.name, el.getAttribute("class"), el.getAttribute("data-testid"), el.getAttribute("data-test")]
    .filter((v): v is string => typeof v === "string" && v.length > 0)
    .join(" ")
  const label = graph.label(el)
  return {
    type: isMasked ? "password" : (el.getAttribute("type") || "text").toLowerCase(),
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

// ---- The page ------------------------------------------------------------------

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

/** Login inputs read per scan. */
const MAX_INPUTS = 200

/** The scan's login fields, scored and settled, and each cluster's one-digit code boxes, where there are a code's worth. */
function collectFields(graph: FormGraph): { fields: ScannedField[]; codeGroups: HTMLInputElement[][] } {
  const fields: ScannedField[] = []
  const boxes = new Map<FormCluster | undefined, HTMLInputElement[]>()
  let read = 0
  for (const el of graph.controls) {
    if (!eligible(el)) continue
    if (++read > MAX_INPUTS) break
    const isMasked = masked(el, graph.style)
    // A secret the page shows (an API key), not one it asks for.
    if (isMasked && el.readOnly) continue
    const cluster = graph.clusterOf(el)
    // One-character boxes for codes are grouped, per cluster, into a single split OTP field.
    if (el.maxLength === 1) {
      const group = boxes.get(cluster)
      if (group) group.push(el)
      else boxes.set(cluster, [el])
      continue
    }
    const facts = factsFor(el, graph, isMasked)
    fields.push({ el, facts, score: scoreField(facts), role: null, cluster })
  }
  confirmations(fields)
  for (const f of fields) f.role = bestRole(f.score)
  rationalize(fields)
  return { fields, codeGroups: [...boxes.values()].filter((g) => g.length >= 4 && g.length <= 8) }
}

/** A cluster the rules gave a login role, judged as a whole (rationalize.ts, clusterFeatures). */
export interface ClusterVerdict {
  cluster: FormCluster
  /** Gift card and coupon wording set it aside before the model is asked (decoyCluster). */
  offer: boolean
  features: string[]
  /** The model's log-odds that it's a login form. */
  odds: number
}

const BUTTON = "button, [role=button], input[type=submit], input[type=button]"
const SETTINGS_URL = /settings|preferences|admin|console|dashboard|developers?\b|projects?\b/i

/** What the page says around every cluster: its path and title, and how many of its forms ask for a code. */
function pageFacts(fields: ScannedField[], codeGroups: HTMLInputElement[][], graph: FormGraph): PageFacts {
  const url = location.pathname
  const paths = ([["login", LOGIN_URL], ["signup", SIGNUP_URL], ["reset", RESET_URL], ["change-password", CHANGE_PASSWORD_URL], ["settings", SETTINGS_URL]] as const).filter(([, re]) => re.test(url)).map(([p]) => p)
  const title = scoreFormText(words(document.title))
  const codes = new Set([...fields.filter((f) => f.role === "otp").map((f) => f.cluster), ...codeGroups.map((g) => graph.clusterOf(g[0]))])
  return { paths, title: FORM_KINDS.filter((k) => title[k] >= FORM_THRESHOLD), codeClusters: codes.size }
}

/** Every cluster in a form or container whose fields the rules gave a login role, with the model's verdict on it. */
function judge(graph: FormGraph, collected: ReturnType<typeof collectFields>): ClusterVerdict[] {
  // Nothing claimed in a form or container: no page facts or buttons to read.
  if (!collected.fields.some((f) => f.role && f.cluster?.root)) return []
  const page = pageFacts(collected.fields, collected.codeGroups, graph)
  const buttons = deepQueryAll(BUTTON, graph.roots).slice(0, 500)
  const out: ClusterVerdict[] = []
  for (const cluster of graph.clusters) {
    const root = cluster.root
    const fields = collected.fields.filter((f) => f.cluster === cluster)
    if (!root || !fields.some((f) => f.role)) continue
    const labels = buttons.filter((el) => within(root, el) && graph.visible(el)).map(controlText).filter((t) => t && t.length <= 40)
    const features = clusterFeatures(cluster, fields, graph, page, labels)
    out.push({ cluster, offer: decoyCluster(cluster, fields, graph), features, odds: loginOdds(features) })
  }
  return out
}

/** The model's verdict on each of the page's login-like clusters: what corpus/train-weights.ts learns from. */
export function clusterVerdicts(source: ScanSource = openRoots()): ClusterVerdict[] {
  const graph = graphOf(source)
  return judge(graph, collectFields(graph))
}

/**
 * The cluster that holds the most important field: a password, else who
 * you are, else a code; else the first group of one-digit code boxes whose
 * code Deadbolt holds, else the first such group.
 */
function primaryCluster(fields: ScannedField[], codeGroups: HTMLInputElement[][], graph: FormGraph): FormCluster | undefined {
  const anchor =
    fields.find((f) => f.role === "password" || f.role === "new-password") ??
    fields.find((f) => f.role === "username" || f.role === "email" || f.role === "phone") ??
    fields.find((f) => f.role === "otp")
  if (anchor) return anchor.cluster
  const clusterOf = (group: HTMLInputElement[]) => graph.clusterOf(group[0])
  const held = codeGroups.find((g) => heldCode(words(graph.label(g[0])), () => codePageText(clusterOf(g)?.root ?? null)))
  return (held ?? codeGroups[0]) && clusterOf(held ?? codeGroups[0])
}

function contextText(root: Element | null): string {
  const parts = [document.title]
  for (const h of Array.from(document.querySelectorAll("h1, h2, h3, [role=heading]")).slice(0, 6)) parts.push(innerText(h))
  if (root) {
    parts.push(innerText(root).slice(0, 3000))
    for (const input of Array.from(root.querySelectorAll<HTMLInputElement>("input[type=submit], input[type=button]")))
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

function collectControls(cluster: FormCluster | undefined, graph: FormGraph) {
  let submit: Element | undefined
  let provider = false
  const buttonText: string[] = []
  const root = cluster?.root ?? null
  const form = cluster?.form ?? null
  // The login form's own buttons first, so a huge nav can't push them past the cap.
  const candidates = new Set<Element>(root ? Array.from(root.querySelectorAll(CLICKABLE)) : [])
  for (const el of deepQueryAll(CLICKABLE, graph.roots)) {
    if (candidates.size >= 500) break
    candidates.add(el)
  }
  for (const el of candidates) {
    if (!graph.visible(el)) continue
    const text = controlText(el)
    if (!provider && providerForControl(el, text)) {
      provider = true
      continue
    }
    if (!text || text.length > 40 || el instanceof HTMLAnchorElement) continue
    // Through shadow hosts: a form's button may be inside a web component (<my-button>).
    if (root && !within(root, el)) continue
    buttonText.push(text)
    const isSubmitType = (el as HTMLButtonElement).type === "submit"
    if (!submit && (SUBMIT_TEXT.test(text) || (isSubmitType && form))) submit = el
  }
  if (!provider) provider = deepQueryAll(PROVIDER_WIDGETS, graph.roots).length > 0
  return { submit, buttonText, provider }
}

function decideKind(fields: ScannedField[], otpBoxes: number, text: string, controls: ReturnType<typeof collectControls>, unclaimed: number): FormKind | null {
  const { buttonText, provider } = controls
  const count = (...roles: FieldRole[]) => fields.filter((f) => f.role && roles.includes(f.role)).length
  const pw = count("password")
  const npw = count("new-password")
  const ident = count("username", "email", "phone")
  const otp = count("otp") + (otpBoxes ? 1 : 0)
  const ac = new Set(fields.flatMap((f) => f.facts.autocomplete))
  // The path only: a host like author.example.com or sso.example.com says nothing of the page.
  const url = location.pathname

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
  // New passwords and no box for who you are: someone signed in setting a
  // password (a change or a reset), not a sign-up, which asks who you are.
  if (npw > 0 && pw === 0 && ident === 0 && !SIGNUP_URL.test(url)) {
    score.signup -= 3
    score["change-password"] += 3
  }

  // Shape alone is weak here (two password boxes can be password + PIN); the
  // "current / new password" wording does most of the work.
  if ((pw >= 1 && npw >= 1) || pw + npw >= 3) score["change-password"] += 2
  if (ac.has("current-password") && ac.has("new-password")) score["change-password"] += 4

  if (ident > 0 && pw + npw === 0) score.reset += 1
  if (pw + npw > 0) score.reset -= 6

  if (otp > 0 && pw === 0) score.mfa += 6
  if (otp > 0 && pw > 0) score.mfa += 1

  // No password, no sign-in autocomplete, and two or more boxes no login
  // role claims: more likely a transfer, a registration or a comment than a
  // sign-in, though a sign-in's own wording and path can still say it is one
  // (a workspace, a region and a work email).
  if (pw + npw === 0 && unclaimed >= 2 && !LOGIN_TOKENS.some((t) => ac.has(t))) {
    score.mfa -= 6
    score.signup -= 4
    score.login -= 2
  }

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
function codePageText(root: Element | null): string {
  const heads = Array.from(document.querySelectorAll("h1, h2, h3, [role=heading]")).slice(0, 6).map((h) => innerText(h))
  return words([document.title, ...heads, innerText(root), innerText(document.body).slice(0, 3000)].join(" \n "))
}

/**
 * The page's login form: its kind, its fields and its submit button. Takes
 * a scan's graph (graph.ts), shared with scanForms, or the roots to make one.
 */
export function scanPage(source: ScanSource = openRoots()): ScanResult {
  const graph = graphOf(source)
  const collected = collectFields(graph)
  // Gift card and coupon forms, and clusters the model says aren't a login
  // (an environment variable's key and value, a Wi-Fi password), are set
  // aside first, so one above the real sign-in never stands for it.
  const verdicts = new Map(judge(graph, collected).map((v) => [v.cluster, v]))
  const decoys = new Set(
    graph.clusters.filter((c) => {
      const v = verdicts.get(c)
      return v ? v.offer || notLogin(v.odds, v.features) : decoyCluster(c, collected.fields.filter((f) => f.cluster === c), graph)
    }),
  )
  const all = collected.fields.filter((f) => !f.cluster || !decoys.has(f.cluster))
  const codeGroups = collected.codeGroups.filter((g) => !decoys.has(graph.clusterOf(g[0])!))
  const cluster = primaryCluster(all, codeGroups, graph)
  // Judge and report the primary cluster only, so a sign-up form or newsletter
  // box elsewhere on the page doesn't change what the login form is.
  const inScope = (el: Element) => !cluster || graph.clusterOf(el) === cluster
  const scanned = all.filter((f) => inScope(f.el))
  const controls = collectControls(cluster, graph)
  const root = cluster?.root ?? null
  const formKind = decideKind(scanned, codeGroups.some((g) => inScope(g[0])) ? 1 : 0, contextText(root), controls, unclaimedBoxes(cluster, scanned))
  // Every cluster asking for a code, counted before codes the user brings lose their role below.
  const codeClusters = new Set([...codeGroups.map((g) => graph.clusterOf(g[0])), ...all.filter((f) => f.role === "otp").map((f) => f.cluster)])
  if (formKind) adjustRoles(scanned, formKind)

  // Codes the user brings themselves (sent, or backup) aren't the login's to fill.
  let page: string | undefined
  const pageText = () => (page ??= codePageText(root))
  let brought = 0
  for (const f of scanned)
    if (f.role === "otp" && !heldCode(f.facts.display, pageText)) {
      f.role = null
      brought++
    }
  const boxes = codeGroups.find((g) => inScope(g[0])) ?? []
  const split = boxes.length && heldCode(words(graph.label(boxes[0])), pageText) ? boxes : []
  if (boxes.length && !split.length) brought++

  const fields: Field[] = scanned.filter((f) => f.role).map((f) => ({ el: f.el, role: f.role!, owner: ownerOf(f.el) }))
  for (const el of split) fields.push({ el, role: "otp", split: split.length, owner: ownerOf(el) })

  // Sign-in wording with no fields to fill isn't a form; a code step whose
  // code the user brings still is one (a sign-in that isn't over), with
  // nothing in it to fill. A sign-in asks for one code: a page asking for
  // codes in several forms, none of them Deadbolt's, is verifying contact
  // details.
  const stepOnly = formKind === "mfa" && brought > 0 && codeClusters.size < 2
  const kind = formKind === "newsletter" || (!fields.length && !stepOnly) ? null : formKind
  return { kind, fields, submit: controls.submit, provider: controls.provider }
}

// Pages between sign-in steps: an authenticator picker, a CAPTCHA, a
// "verify it's you" check. They have no form to fill, but the sign-in hasn't
// finished.
export const STEP_PHRASES = [
  "select an authenticator", "choose an authenticator", "verify with", "verify it s you", "confirm it s you", "it s really you",
  "choose a verification method", "choose how you want to sign in", "try another way", "2 step verification", "two step verification",
  "security check", "i m not a robot", "verify you are human", "are you a robot", "checking your browser", "complete the captcha",
  "signing you in", "redirecting",
].map((p) => words(p).trim())
export const CAPTCHA = ".g-recaptcha, .h-captcha, .cf-turnstile, iframe[src*='recaptcha'], iframe[src*='hcaptcha'], iframe[src*='challenges.cloudflare.com']"
export const BUSY = "[role=progressbar], [aria-busy=true]"

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
 * points at it for the user to click. With `unique`, the one such control
 * (innermost, so a wrapper and its button are one), or null when there are
 * several: something Deadbolt clicks itself must not be a guess.
 */
export function findProviderButton(p: { id: string; words: string[] }, unique = false): Element | null {
  const roots = openRoots()
  const widget = WIDGETS[p.id]
  const found: Element[] = []
  if (widget) for (const el of deepQueryAll(widget, roots)) if (isVisible(el)) { if (!unique) return el; found.push(el) }
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
    found.push(el)
    // The innermost match: the button itself, not a wrapper around it.
    if (!best || best.contains(el)) best = el
  }
  return unique ? sole(found) : best
}

/** The one element left once wrappers of another candidate are dropped, or null for none or several. */
export function sole(found: Element[]): Element | null {
  const inner = [...new Set(found)].filter((el, _, all) => !all.some((other) => other !== el && el.contains(other)))
  return inner.length === 1 ? inner[0] : null
}

/**
 * On the provider's account chooser, the tile for `account` (an email or
 * username), by the attribute Google's tiles carry it in. Never by text: a
 * page's own text could name anyone. With `unique`, null unless exactly one
 * tile carries it.
 */
export function findAccountTile(account: string, unique = false): Element | null {
  const want = account.trim().toLowerCase()
  if (!want) return null
  const roots = openRoots()
  const found: Element[] = []
  for (const el of deepQueryAll("[data-identifier], [data-email]", roots)) {
    const id = (el.getAttribute("data-identifier") ?? el.getAttribute("data-email") ?? "").trim().toLowerCase()
    if (id !== want || !isVisible(el)) continue
    const tile = el.closest('[role=link], [role=button], li, a, button') ?? el
    if (!unique) return tile
    found.push(tile)
  }
  const tiles = [...new Set(found)]
  return tiles.length === 1 ? tiles[0] : null
}

/**
 * Whether a code step's prompt describes a code delivered by SMS, email,
 * a call or a push approval, or is too long to judge: a remembered or
 * automatic code step never sends an authenticator code into such a prompt.
 * Each specific hint is checked before the surrounding copy; oversized
 * context is unknown, not permission to truncate away a delivery warning.
 */
export function deliveredCode(fields: Field[], within: Element | null | undefined, chipAccount?: string): boolean {
  if (!fields.some((f) => f.role === "otp")) return false
  // The step's form or region, read out to the dialog or main region around it.
  const context = within?.closest<HTMLElement>("dialog, [role=dialog], main, [role=main]") ?? document.body
  // `chipAccount`: on a provider's own account page whose account chip shows
  // exactly the linked account (see provider-chain.ts chipAccount), a line of
  // the surrounding copy that is that account and nothing else is its chip,
  // not a delivery address. Labels, the title and headings stay strict.
  const chip = chipAccount?.trim().toLowerCase()
  const copy = (context?.innerText ?? "").split("\n").filter((line) => !chip || line.trim().toLowerCase() !== chip).join("\n")
  const prompts = [
    ...fields.flatMap((f) => [f.el.getAttribute("aria-label") ?? "", f.el.placeholder, ...Array.from(f.el.labels ?? []).map((label) => label.innerText)]),
    document.title, ...Array.from(document.querySelectorAll<HTMLElement>("h1, h2, h3, [role=heading]")).map((el) => el.innerText),
    copy,
  ]
  return prompts.some((text) => text.length > 12000 || /\b(?:sms|text(?:ed| message)?|e-?mail|phone|mobile|inbox|sent|messages?|deliver(?:ed|y)?|call|voice|whatsapp|push|notifications?|approve)\b|@|[•*]{2,}|\+\d/i.test(text))
}
