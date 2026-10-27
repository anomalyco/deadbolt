// Content-script side of the inline menu: opens the account menu under a
// focused login field and applies fills sent by the background. Ported from
// Foyer (github.com/R44VC0RP/foyer, src/autofill/inline.ts, by Ryan Vogel),
// without SSO buttons, auto-submit and the fill shortcut.
//
// The menu is an extension page in an iframe inside a closed shadow root on a
// plain div (a page can define a custom element's class and reach its shadow
// root, but not a div's). The page can't read the account list (cross-origin
// frame) and can't click it for the user (synthetic events don't cross into
// the frame). It can see that a menu appeared, which says only that the site
// has logins or Deadbolt is locked, and the values written into its own fields
// after the user picks an account.

import { GENERATE_KINDS, MENU_ROLES, type FillAck, type QueryReply, type SurfaceKind, type ToBackground, type ToContent } from "../messages"
import { approvals } from "./approvals"
import type { Field } from "./detect"
import { fillFields } from "./fill"
import { fieldRules, fitsPattern, keptGenerated, rememberGenerated } from "./generate"
import { deepActiveElement } from "./shadow"

export interface PageState {
  targets(): Field[]
  /** Which form snapshot `targets` is; it changes whenever the fields do. */
  form(): number
  kind(): SurfaceKind | null
  /** Scan again now, so `targets` and `form` are current. */
  rescan(): void
}

export const MENU_ROW = 52
const MENU_CHROME = 38
const MENU_WIDTH = 300
const SHADOW =
  "0 16px 48px -6px rgb(0 0 0 / 14%), 0 6px 12px -2px rgb(0 0 0 / 6%), 0 0 0 1px rgb(0 0 0 / 10%)"

let state: PageState
let host: HTMLElement | null = null
let frame: HTMLIFrameElement | null = null
let anchor: HTMLInputElement | null = null
let token: string | null = null
/** Handed to the menu with its token; only this script can say "the user pressed ↓" over it. */
let port: MessagePort | null = null
let raf = 0
let menuHeight = 0
let dismissedFor: HTMLInputElement | null = null
/** The origin the menu frame said it's on, and where its frame last was on screen. */
let menuOrigin = ""
let lastRect = ""
/** The fields the last fill in this document wrote, and whether the user submitted since. */
let lastFilled: HTMLInputElement[] = []
let submittedSinceFill = false
/**
 * The menu only opens right after a real click or keypress. A page can focus a
 * field from script (focus() fires a trusted focusin) and slide it under the
 * user's next click; it can't fake the user's own input event.
 */
let lastGestureAt = 0
const GESTURE_WINDOW_MS = 1000
const recentGesture = () => Date.now() - lastGestureAt < GESTURE_WINDOW_MS
/**
 * The menu opens only in the top page. A frame's position, size and style are
 * up to the page around it, which the menu inside can't watch; frames' forms
 * fill from the toolbar popup instead (see Autofill.popupFill).
 */
const isTop = window === window.top
const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches

export function send<T>(message: ToBackground): Promise<T | null> {
  try {
    return chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>
  } catch {
    // The extension was reloaded; this page's script is orphaned.
    return Promise.resolve(null)
  }
}

function targetFor(el: Element): Field | undefined {
  return state.targets().find((t) => t.el === el)
}

function position() {
  if (!host || !anchor) return
  if (!anchor.isConnected) return closeMenu()
  const r = anchor.getBoundingClientRect()
  const width = Math.max(MENU_WIDTH, Math.min(r.width, 420))
  const below = r.bottom + 6
  const fitsBelow = below + menuHeight < innerHeight
  const top = fitsBelow ? below : Math.max(4, r.top - menuHeight - 6)
  const left = Math.min(Math.max(4, r.left), innerWidth - width - 4)
  host.style.cssText = `all:initial;position:fixed;top:${top}px;left:${left}px;width:${width}px;height:${menuHeight}px;z-index:2147483647;display:block;`
  // The menu only takes a pick once it has sat still for a moment (see
  // Dwell). From inside its frame it can't tell it was moved, so say so: the
  // page can restyle the host, and the field it follows can move.
  if (frame) {
    const f = frame.getBoundingClientRect()
    const rect = [f.left, f.top, f.width, f.height].map(Math.round).join()
    if (rect !== lastRect && menuOrigin) frame.contentWindow?.postMessage({ type: "db:menu-moved" }, menuOrigin)
    lastRect = rect
  }
  raf = requestAnimationFrame(position)
}

function openMenu(el: HTMLInputElement, t: string, rows: number) {
  closeMenu()
  anchor = el
  token = t
  menuHeight = Math.min(Math.max(rows, 1), 5) * MENU_ROW + MENU_CHROME
  host = document.createElement("div")
  const root = host.attachShadow({ mode: "closed" })
  frame = document.createElement("iframe")
  // No token in the URL: the menu asks for it (see onMenuReady).
  frame.src = chrome.runtime.getURL("menu.html")
  frame.setAttribute("allow", "")
  frame.style.cssText = `all:initial;width:100%;height:100%;border:0;border-radius:12px;box-shadow:${SHADOW};background:transparent;color-scheme:normal;`
  root.append(frame)
  document.documentElement.append(host)
  position()
  // Settles in from just under the field. Only a translation and a fade: the
  // menu's visibility guard refuses picks while it's scaled or see-through.
  frame.animate(
    reducedMotion()
      ? [{ opacity: 0 }, { opacity: 1 }]
      : [
          { opacity: 0, transform: "translateY(-4px)" },
          { opacity: 1, transform: "translateY(0)" },
        ],
    { duration: 140, easing: "cubic-bezier(0.2, 0.9, 0.3, 1)" },
  )
}

/** The element the open menu hangs from, if one is open. */
export const menuHost = (): HTMLElement | null => host

export function closeMenu(refocus = false, dismissed = false) {
  cancelAnimationFrame(raf)
  if (token) void send({ type: "db:menu-close", token, dismissed })
  port?.close()
  port = null
  const field = anchor
  host?.remove()
  host = frame = anchor = null
  token = null
  menuOrigin = lastRect = ""
  if (refocus) field?.focus({ preventScroll: true })
}

let querying: Promise<void> | null = null
/** Fields recently found to have no accounts, so rescans don't re-ask. */
const emptyUntil = new WeakMap<Element, number>()

async function maybeOpen(el: HTMLInputElement) {
  if (!isTop || querying || dismissedFor === el || !recentGesture()) return
  if ((emptyUntil.get(el) ?? 0) > Date.now()) return
  const t = targetFor(el)
  if (!t || !MENU_ROLES.includes(t.role)) return
  const kind = state.kind()
  const generating = t.role === "new-password"
  if (generating && !(kind && GENERATE_KINDS.includes(kind))) return
  if (anchor === el && host) return
  querying = (async () => {
    const roles = [...new Set(state.targets().map((x) => x.role))]
    // A pattern outside what generate.ts reads, or lengths that can't meet: no generated password.
    const rules = generating ? fieldRules(state.targets()) : undefined
    const reply = rules === null ? null : await send<QueryReply>({ type: "db:query", roles, focused: t.role, form: state.form(), kind, rules })
    if (reply?.token && reply.rows > 0) {
      if (deepActiveElement() === el) openMenu(el, reply.token, reply.rows)
    } else emptyUntil.set(el, Date.now() + 15_000)
  })().finally(() => (querying = null))
}

function onFocusIn(event: FocusEvent) {
  const el = event.composedPath()[0]
  if (el instanceof HTMLInputElement) void maybeOpen(el)
}

function onPointerDown(event: PointerEvent) {
  if (!event.isTrusted) return
  lastGestureAt = Date.now()
  const target = event.composedPath()[0]
  // Clicking a field that already has focus (e.g. autofocus) opens the menu too.
  if (target instanceof HTMLInputElement && target === deepActiveElement() && !host) {
    if (dismissedFor === target) dismissedFor = null
    void maybeOpen(target)
  }
  if (!host) return
  const path = event.composedPath()
  if (path.includes(host) || path.includes(anchor as EventTarget)) return
  closeMenu()
}

function onKeyDown(event: KeyboardEvent) {
  if (!event.isTrusted) return
  lastGestureAt = Date.now()
  const target = event.composedPath()[0]
  if (!host) {
    // ↓ in a field that has no menu (dismissed, or focused from script) asks for one.
    if (event.key === "ArrowDown" && target instanceof HTMLInputElement && targetFor(target)) {
      dismissedFor = null
      emptyUntil.delete(target)
      void maybeOpen(target)
    }
    return
  }
  if (target !== anchor) return
  if (event.key === "Escape") {
    dismissedFor = anchor
    closeMenu(false, true)
  } else if (event.key === "ArrowDown") {
    event.preventDefault()
    port?.postMessage({ type: "db:menu-enter" })
    frame?.focus()
    frame?.contentWindow?.focus()
  }
}

/**
 * Fills only the form the login was chosen for (if the fields were replaced,
 * added or removed since, nothing is written), and in it only the fields the
 * background's db:approve fixed for this fill. Answers with what was written.
 */
async function applyFill(message: Extract<ToContent, { type: "db:fill" }>): Promise<FillAck> {
  closeMenu()
  // Filling focuses each field. Without this, the keypress that chose the
  // login would reopen the menu on the first field, covering the next one.
  lastGestureAt = 0
  state.rescan()
  if (state.form() !== message.form) return { filled: [] }
  // A generated password the boxes' pattern won't take (the page changed it since the menu opened).
  const approved = approvals.get(String(message.approval), message.form)
  if (message.values.newPassword && approved && !fitsPattern(approved, message.values.newPassword)) return { filled: [], rejected: true }
  // Only the fields approved for this fill, never one that became fillable since.
  const targets = approvals.take(String(message.approval), message.form, state.targets())
  if (!targets?.length) return { filled: [] }
  const { filled, last } = await fillFields(targets, message.values)
  if (filled.includes("new-password") && message.values.newPassword && typeof message.generated === "string")
    rememberGenerated(message.generated, message.values.newPassword)
  if (filled.length) {
    lastFilled = targets.filter((t) => filled.includes(t.role)).map((t) => t.el)
    submittedSinceFill = false
  }
  last?.focus({ preventScroll: true })
  return { filled }
}

export function markSubmitted() {
  if (lastFilled.length) submittedSinceFill = true
}

/**
 * Whether the page has moved on since the last fill here: the user submitted,
 * or none of the filled fields is still in the login form. Only then does the
 * background fill an email-first sign-in's next step into this document.
 */
export function stepped(): boolean {
  if (!lastFilled.length) return false
  if (submittedSinceFill) return true
  const now = state.targets()
  return lastFilled.every((el) => !el.isConnected || !now.some((t) => t.el === el))
}

/**
 * The menu frame says it's ready; hand it the token. Only that frame's own
 * window can be the source, and the target origin keeps the token from a page
 * that navigated the frame elsewhere. The background accepts the token only
 * from a menu whose parent is this document's origin.
 */
function onMenuReady(event: MessageEvent<{ type?: unknown }>) {
  const win = frame?.contentWindow
  if (!frame || !token || port || !win || event.source !== win || event.data?.type !== "db:menu-ready") return
  // getURL gives the per-session dynamic URL, but Chrome may load the frame
  // under the extension id's origin.
  if (event.origin !== new URL(frame.src).origin && event.origin !== `chrome-extension://${chrome.runtime.id}`) return
  event.stopImmediatePropagation()
  menuOrigin = event.origin
  const channel = new MessageChannel()
  port = channel.port1
  win.postMessage({ type: "db:menu-token", token }, event.origin, [channel.port2])
}

export function initMenu(page: PageState) {
  state = page
  window.addEventListener("message", onMenuReady, true)
  document.addEventListener("focusin", onFocusIn, true)
  document.addEventListener("pointerdown", onPointerDown, true)
  document.addEventListener("keydown", onKeyDown, true)
  // Leaving the page (or entering the back/forward cache) takes the menu
  // along; coming back is a new visit.
  window.addEventListener("pagehide", () => {
    closeMenu()
    dismissedFor = null
    lastGestureAt = 0
    lastFilled = []
    submittedSinceFill = false
  })
  // Answering tells the background the message reached a live document.
  chrome.runtime.onMessage.addListener((message: ToContent, _sender, respond) => {
    switch (message?.type) {
      case "db:fill":
        applyFill(message).then(respond, () => respond({ filled: [] }))
        return true
      case "db:generated":
        keptGenerated(String(message.generated))
        return void respond(true)
      case "db:close-menu":
        if (message.token === token) {
          dismissedFor = anchor
          closeMenu(true)
        }
        return void respond(true)
      case "db:resize-menu":
        if (message.token === token) menuHeight = message.height
        return void respond(true)
    }
  })
}

/** Called after each page scan: offer the menu on an already-focused field. */
export function refreshMenu(focused: HTMLInputElement) {
  if (!host) void maybeOpen(focused)
}
