// Page text never leaves this isolated world and is never compared with vault
// data. Only boolean evidence and an opaque action handle go back to the
// background. No cookies are inspected.
import { authState, type AuthReport, type AuthSignals } from "../auth-state"
import { isChooserPage, providerForPage } from "../signin"
import { controlText, isVisible, LOGIN_URL, providerForControl } from "./detect"
import { pageFacts } from "./outcome"
import { deepQueryAll, openRoots } from "./shadow"
import type { PageState } from "./inline"

const ENTRY = /^(sign\s?in|log\s?in|login)(?:\s+to\s+.{1,60})?$/i
export const SIGN_OUT = /^(sign\s?out|log\s?out|logout|signout|sign off|log off|se déconnecter|déconnexion|abmelden|ausloggen|cerrar sesión)\b/i
const ACCOUNT = /^(my account|your account|account menu|profile menu|user menu|avatar)$/i
/** How long a page's scan answers repeat checks while its URL and form stay put. */
const REPORT_MS = 2000
const actions = new Map<string, { element?: HTMLElement; form: number; url: string; at: number }>()
let last: { key: string; at: number; signals: AuthSignals; entry?: HTMLElement } | undefined

function shown(el: Element): boolean {
  if (!isVisible(el)) return false
  const r = el.getBoundingClientRect()
  return r.width > 0 && r.height > 0 && r.top >= 0 && r.left >= 0 && r.bottom <= innerHeight && r.right <= innerWidth
}

function safeEntry(el: Element): el is HTMLElement {
  if (!(el instanceof HTMLElement) || !shown(el) || !ENTRY.test(controlText(el).trim()) || el.matches(":disabled, [aria-disabled=true]")) return false
  if (el instanceof HTMLAnchorElement) {
    try { return new URL(el.href).origin === location.origin && !el.target && !el.download } catch { return false }
  }
  return el instanceof HTMLButtonElement || el.getAttribute("role") === "button"
}

function scan(state: PageState): { signals: AuthSignals; entry?: HTMLElement } {
  const facts = pageFacts(state.kind(), state.targets())
  const signals: AuthSignals = {
    loginForm: state.kind() === "login" && state.targets().some((f) => shown(f.el)),
    loginRoute: LOGIN_URL.test(location.pathname), entry: false,
    signOut: facts.signOut, accountMenu: false,
    appShell: location.hostname === "mail.google.com", challenge: facts.challenge,
    uncertain: document.hidden || window !== window.top || facts.error || !!state.kind() && state.kind() !== "login",
  }
  const deadline = performance.now() + 25
  const controls = deepQueryAll("a, button, [role=button], [role=menuitem], [aria-label], img[alt]", openRoots())
  let entry: HTMLElement | undefined
  /** A visible "Continue with <known provider>" button: an entry, though not one the opaque go action clicks. */
  let providerEntry = false
  for (const el of controls.slice(0, 400)) {
    if (performance.now() > deadline) { signals.uncertain = true; break }
    if (!signals.accountMenu && ACCOUNT.test(controlText(el).trim()) && shown(el)) signals.accountMenu = true
    if (!entry && safeEntry(el)) entry = el
    if (!providerEntry && el.matches("a, button, [role=button]")) {
      const p = providerForControl(el, controlText(el))
      providerEntry = !!p && p !== "sso" && shown(el)
    }
  }
  if (controls.length > 400) signals.uncertain = true
  // A known provider's own account chooser, by its tiles' attributes only: no username is read or compared.
  const chooserPage = providerForPage(location.href)
  const chooser = !!chooserPage && isChooserPage(chooserPage, location.href) &&
    deepQueryAll("[data-identifier], [data-email]", openRoots()).some(shown)
  // A dashboard's stray provider button is not a sign-in entry.
  signals.entry = !!entry || (!signals.signOut && !signals.accountMenu && (providerEntry || chooser))
  return { signals, entry }
}

/**
 * Positive signed-in evidence (a visible sign-out control) with no login
 * form, challenge or uncertainty, from a fresh scan. An account menu is
 * uncertainty, not success.
 */
export function signedInHint(state: PageState): boolean {
  state.rescan()
  const { signals } = scan(state)
  return authState(signals) === "signed-in" && !signals.loginForm && !signals.challenge && !signals.uncertain
}

/**
 * Repeat checks on the same URL and form reuse the last scan for a moment;
 * `fresh` (the guarded pick) always scans. Each call mints its own action.
 */
export function authReport(state: PageState, fresh = false): AuthReport {
  state.rescan()
  const key = `${location.href}\n${state.form()}\n${state.kind() ?? ""}\n${document.hidden}`
  const reuse = !fresh && last && last.key === key && Date.now() - last.at < REPORT_MS && (!last.entry || last.entry.isConnected && safeEntry(last.entry))
  if (!reuse) last = { key, at: Date.now(), ...scan(state) }
  const { signals, entry } = last!
  const result: AuthReport = { ...signals }
  // A provider button or chooser counts too: the offer's pick needs an
  // action, and takeSignInAction still finds nothing to do with one that has
  // neither a login form nor a sign-in entry element.
  if (signals.loginForm || entry || signals.entry) {
    const id = crypto.randomUUID()
    if (actions.size >= 8) actions.delete(actions.keys().next().value!)
    actions.set(id, { ...(signals.loginForm ? {} : { element: entry }), form: state.form(), url: location.href, at: Date.now() })
    result.action = id
  }
  return result
}

/** Consumes a fresh probe once, after the extension frame's guarded pick. */
export function takeSignInAction(id: string, state: PageState): { form: true } | { element: HTMLElement } | null {
  const a = actions.get(id)
  actions.delete(id)
  if (!a || Date.now() - a.at > 5000 || a.url !== location.href || document.hidden || window !== window.top) return null
  state.rescan()
  if (a.element) return a.element.isConnected && safeEntry(a.element) ? { element: a.element } : null
  return a.form === state.form() && state.kind() === "login" ? { form: true } : null
}
