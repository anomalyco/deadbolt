// Page text never leaves this isolated world. Only boolean evidence and an
// opaque action handle go back to the background. No cookies are inspected.
import { matchesAccount, type AuthReport } from "../auth-state"
import { controlText, isVisible, LOGIN_URL } from "./detect"
import { pageFacts } from "./outcome"
import { deepQueryAll, openRoots } from "./shadow"
import type { PageState } from "./inline"

const ENTRY = /^(sign\s?in|log\s?in|login)(?:\s+to\s+.{1,60})?$/i
export const SIGN_OUT = /^(sign\s?out|log\s?out|logout|signout|sign off|log off|se déconnecter|déconnexion|abmelden|ausloggen|cerrar sesión)\b/i
const ACCOUNT = /^(my account|your account|account menu|profile menu|user menu|avatar)$/i
const actions = new Map<string, { element?: HTMLElement; form: number; url: string; at: number }>()

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

export function authReport(state: PageState, usernames: string[]): AuthReport {
  state.rescan()
  const facts = pageFacts(state.kind(), state.targets())
  const loginForm = state.kind() === "login" && state.targets().some((f) => shown(f.el))
  const result: AuthReport = {
    loginForm, loginRoute: LOGIN_URL.test(location.pathname), entry: false,
    signOut: facts.signOut, account: false, accountMenu: false,
    appShell: location.hostname === "mail.google.com", challenge: facts.challenge,
    uncertain: document.hidden || window !== window.top || facts.error || !!state.kind() && state.kind() !== "login",
  }
  const deadline = performance.now() + 25
  const roots = openRoots()
  const controls = deepQueryAll("a, button, [role=button], [role=menuitem], [aria-label], img[alt]", roots)
  let entry: HTMLElement | undefined
  for (const el of controls.slice(0, 400)) {
    if (performance.now() > deadline) { result.uncertain = true; break }
    const label = controlText(el).trim()
    if (ACCOUNT.test(label) && shown(el)) result.accountMenu = true
    if (!entry && safeEntry(el)) entry = el
    if (matchesAccount([el.getAttribute("aria-label"), el.getAttribute("title"), el.getAttribute("alt")].join(" "), usernames) && shown(el)) result.account = true
  }
  if (controls.length > 400) result.uncertain = true
  let seen = 0
  for (const root of roots) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (++seen > 3000 || performance.now() > deadline) { result.uncertain = true; break }
      const parent = node.parentElement
      // A chooser or a prefilled login does not prove authentication. Counting
      // its text still suppresses an offer (safe false negative), never fills.
      if (parent && !parent.closest("script, style, noscript, template, input, textarea") &&
          matchesAccount((node.nodeValue ?? "").slice(0, 2000), usernames) && shown(parent)) result.account = true
    }
  }
  result.entry = !!entry
  if (loginForm || entry) {
    const id = crypto.randomUUID()
    if (actions.size >= 8) actions.delete(actions.keys().next().value!)
    actions.set(id, { ...(loginForm ? {} : { element: entry }), form: state.form(), url: location.href, at: Date.now() })
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
