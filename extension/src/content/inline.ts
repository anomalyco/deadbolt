// Content-script side of the inline menu: opens the account menu under a
// focused login field and applies fills sent by the background. Ported from
// Foyer (github.com/R44VC0RP/foyer, src/autofill/inline.ts, by Ryan Vogel),
// without SSO buttons, auto-submit and the fill shortcut.
//
// The menu is an extension page in an iframe inside a closed shadow root. The
// page can't read the account list (cross-origin frame) and can't click it for
// the user (synthetic events don't cross into the frame). It can see that a
// menu appeared, which says only that the site has logins or Deadbolt is
// locked, the values written into its own fields after the user picks an
// account, and that a save offer appeared (see the threat model in
// docs/autofill.md).
//
// The host element has a fresh random custom-element name each time, so page
// CSS can't aim at it, and inline `!important` styles, which beat any page
// rule. A page that defines that name afterwards upgrades the element but
// can't reach a shadow root attached before. The host is a manual popover,
// shown in the top layer above everything the page has, and inside the
// field's modal dialog or full-screen element when there is one.
// Whatever the page puts in the top layer after it (a popover, a modal
// dialog, full screen) is answered by raising the surface back on top, a few
// times; a page that keeps at it gets the surface closed.
//
// The same frame is Deadbolt's one surface in the page, in three modes it
// morphs between: the account list under a field, a pill on the field while
// it fills, and, after a confirmed sign-in, the save offer in the top right
// corner (see bg/save.ts): a small pill that opens on approach and shrinks to
// a dot when it's not wanted. This script owns the frame's place and size: the frame
// says what size its mode needs (db:menu-resize) and the host springs there,
// so no transparent area is left over the page to swallow its clicks.

import { GENERATE_KINDS, IDENTIFIER_ROLES, MENU_ROLES, type Box, type FillAck, type FormsAck, type QueryReply, type SurfaceKind, type SurfaceMode, type ToBackground, type ToContent } from "../messages"
import { epochNow, reducedMotion, Spring, timing } from "../ui/motion"
import { approvals } from "./approvals"
import { findAccountTile, findProviderButton, type Field, type FormControl } from "./detect"
import { approvedForms, approveForms, fillCheck, fillForm, onScreen, takeApproved, type FormsState } from "./formfill"
import { sectionFields, type FormField } from "./forms"
import { hideRing, showRing } from "./ring"
import { isAccountPage, pageAccountOf, provider } from "../signin"
import { fillable, fillFields, ownValue, visibleBox } from "./fill"
import { fieldRules, fitsPattern, keptGenerated, rememberGenerated } from "./generate"
import { learning } from "./learn"
import { deepActiveElement } from "./shadow"

export interface PageState {
  targets(): Field[]
  /** Which form snapshot `targets` is; it changes whenever the fields do. */
  form(): number
  kind(): SurfaceKind | null
  /** Scan again now, so `targets` and `form` are current. */
  rescan(): void
  /** Identity and payment fields (see forms.ts), and which snapshot they are. */
  formFields(): FormField[]
  formsForm(): number
}

export const MENU_ROW = 44
/** The list's 6px padding, top and bottom. */
const MENU_CHROME = 12
/** The site's caption, over two or more rows. */
const MENU_CAPTION = 22
const MENU_WIDTH = 300
/** The save offer's place: the top right corner, near the toolbar button. */
const SAVE_INSET = 12
/** The offer's compact pill, before its frame says its size. */
const SAVE_GUESS = { width: 220, height: 36 }
const RADIUS = 14
const light = () => !matchMedia("(prefers-color-scheme: dark)").matches
/** A hairline, then soft layers: close and crisp, wide and faint. */
const SHADOW = () =>
  light()
    ? "0 0 0 0.5px rgb(0 0 0 / 12%), 0 1px 2px rgb(0 0 0 / 5%), 0 6px 14px -4px rgb(0 0 0 / 8%), 0 22px 44px -14px rgb(0 0 0 / 16%)"
    : "0 0 0 0.5px rgb(255 255 255 / 14%), 0 1px 2px rgb(0 0 0 / 40%), 0 6px 14px -4px rgb(0 0 0 / 45%), 0 22px 44px -14px rgb(0 0 0 / 60%)"
/** How many times one menu goes back on top of the top layer before it gives up and closes. */
export const MAX_RAISES = 3
/** Where the menu checks that a click there would land on it, as fractions of its box. */
const SAMPLES = [
  [0.5, 0.5],
  [0.08, 0.12],
  [0.92, 0.12],
  [0.08, 0.88],
  [0.92, 0.88],
]

let state: PageState
let host: HTMLElement | null = null
let frame: HTMLIFrameElement | null = null
let anchor: FormControl | null = null
/**
 * For a field in a frame below: where it showed in this page when the menu
 * opened, and the page's scroll then. The menu follows the page's scrolling.
 */
let anchorBox: { box: Box; x: number; y: number } | null = null
let token: string | null = null
/** Handed to the menu with its token; only this script can say "the user pressed ↓" over it. */
let port: MessagePort | null = null
let raf = 0
let menuHeight = 0
let raises = 0
/** Set while Deadbolt itself hides and shows the host. */
let raising = false
/** The surface is out of the top layer for a moment, while frames below are measured (see hold). */
let held = false
/** Which mode the surface is in, and the size the frame asked for in it. */
let mode: SurfaceMode = "accounts"
let wanted = { width: 0, height: 0 }
/** The host's place is its mode's target plus these, which spring to 0 when the mode or size changes. */
const offset = { left: new Spring(0), top: new Spring(0), width: new Spring(0), height: new Spring(0) }
let lastTarget: Rect | null = null
/** Where this script last put the host: what it must still be for the host to be taken as Deadbolt's own (see ownPill). */
let written: Rect | null = null
let closing = false
/** The save offer's fallbacks: it goes if its frame never loads, and in any case after a while. */
let saveTimers: ReturnType<typeof setTimeout>[] = []
const SAVE_LOAD_MS = 3000
const SAVE_CAP_MS = 60_000
/** The largest a pill can be. */
const PILL_MAX = { width: 260, height: 32 }
let dismissedFor: Element | null = null
/**
 * Fields whose typing narrowed the menu to nothing (or that the user typed a
 * password into by hand): the menu doesn't come back on focus until the field
 * is cleared, clicked again, or ↓.
 */
const quiet = new WeakSet<Element>()
/**
 * Forms the user is filling by hand: the identifier they typed matched no
 * saved login. Their other fields don't open the menu on focus or click
 * either, only on ↓ or a second click.
 */
const byHand = new WeakSet<Node>()
const formOf = (el: FormControl): Node => el.form ?? el.closest("form") ?? el.getRootNode()
/** Whether the pointer is near the save offer, as last told to its frame (it pauses the offer's bar). */
let near = false

/** The origin the menu frame said it's on, and where its frame last was on screen. */
let menuOrigin = ""
let lastRect = ""
/** Where a frame's field is in this page now (see anchorBox). */
function boxNow(): DOMRect | null {
  if (!anchorBox) return null
  const { box, x, y } = anchorBox
  return new DOMRect(box.left - (scrollX - x), box.top - (scrollY - y), box.right - box.left, box.bottom - box.top)
}

/**
 * How much the browser resized the viewport since the frame was last placed
 * (an infobar such as "started debugging this browser" came or went, or the
 * window was resized). A page can't send a trusted resize event, nor resize a
 * tab's viewport (only a popup's, with resizeTo).
 */
let resized: { dw: number; dh: number } | null = null
let viewport = { w: innerWidth, h: innerHeight }
/** The fields the last fill in this document wrote, and whether the user submitted since. */
let lastFilled: HTMLInputElement[] = []
let submittedSinceFill = false
/**
 * The menu only opens right after a real click or keypress. A page can focus a
 * field from script (focus() fires a trusted focusin) and slide it under the
 * user's next click; it can't fake the user's own input event.
 */
let lastGestureAt = 0
/** What the user's last pointerdown landed on: a click into a field asks for the menu outright. */
let lastPointer: EventTarget | null = null
const GESTURE_WINDOW_MS = 1000
const recentGesture = () => Date.now() - lastGestureAt < GESTURE_WINDOW_MS
/**
 * The menu opens only in the top page. A frame's position, size and style are
 * up to the page around it, which the menu inside can't watch; frames' forms
 * fill from the toolbar popup instead (see Autofill.popupFill).
 */
const isTop = window === window.top

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

/** A random valid custom-element name, such as `kqzvt-hmwbe`. */
function hostTag(): string {
  const letters = () => Array.from(crypto.getRandomValues(new Uint8Array(5)), (b) => String.fromCharCode(97 + (b % 26))).join("")
  return `${letters()}-${letters()}`
}

/** Inline declarations a page's stylesheets can't override. */
const important = (css: Record<string, string>) =>
  Object.entries(css)
    .map(([k, v]) => `${k}:${v} !important`)
    .join(";")

/** `node` is `ancestor` or inside it, across shadow roots. */
function within(node: Node | null, ancestor: Node): boolean {
  for (let n = node; n; n = n.parentNode ?? (n instanceof ShadowRoot ? n.host : null)) if (n === ancestor) return true
  return false
}

/**
 * Where the menu mounts when the field is in a modal dialog or the
 * full-screen element: inside the innermost one, as outside a modal dialog
 * it's inert and outside the full-screen element it isn't drawn. When that
 * element is a shadow host and the field is in its shadow tree, the menu
 * goes in that shadow root: a host's own children aren't drawn unless a slot
 * takes them.
 */
function modalAround(el: Element): Element | ShadowRoot | null {
  let from: Node | null = null
  for (let n: Node | null = el; n; from = n, n = n.parentNode ?? (n instanceof ShadowRoot ? n.host : null))
    if (n instanceof Element && n.matches(":modal, :fullscreen")) return from instanceof ShadowRoot ? from : n
  return null
}

/** The menu said it moved: it waits its half second again before it takes a pick (see Dwell). */
function tellMoved() {
  if (frame && menuOrigin) frame.contentWindow?.postMessage({ type: "db:menu-moved" }, menuOrigin)
}

/** Puts the host at the top of the top layer. */
function show(el: HTMLElement) {
  raising = true
  try {
    if (el.matches(":popover-open")) el.hidePopover()
    el.showPopover()
  } catch {
    // Not connected, or the page broke the popover: position() will find it.
  } finally {
    raising = false
  }
}

/**
 * Something went into the top layer after the menu, or covers it: raise the
 * menu over it again, and the menu waits again before it takes a pick. Past
 * MAX_RAISES the page is fighting for the top, and the menu closes.
 */
function raise() {
  if (!host) return
  if (++raises > MAX_RAISES) return closeMenu()
  show(host)
  if (!host.matches(":popover-open")) return closeMenu()
  tellMoved()
}

/**
 * Whether something other than the menu would take a click on it. Only
 * things in the top layer can be over it; ones that let clicks through don't
 * show here, but the menu's own visibility readings see them.
 */
function covered(el: HTMLElement): boolean {
  const root = el.getRootNode() as Document | ShadowRoot
  const r = el.getBoundingClientRect()
  return SAMPLES.some(([fx, fy]) => {
    const hit = root.elementFromPoint?.(r.left + r.width * fx, r.top + r.height * fy)
    return !!hit && hit !== el
  })
}

interface Rect {
  left: number
  top: number
  width: number
  height: number
}

/** Where the surface goes in its mode, in the viewport. */
function targetRect(): Rect | null {
  if (mode === "save") return corner(wanted.width || SAVE_GUESS.width, wanted.height || SAVE_GUESS.height)
  // The saved pill stays in the same corner.
  // So does a pill for a frame's field: on the field, it would cover what the frame's checks read.
  if (mode === "pill" && !anchor) return corner(Math.min(wanted.width || 180, 320), 32)
  const r = anchor ? anchor.getBoundingClientRect() : boxNow()
  if (!r) return null
  if (mode === "pill") {
    // On the field, at its end: beside the text the user sees being filled, not over the next field.
    const height = 32
    const width = Math.min(wanted.width || 140, 260)
    const inside = r.width >= width + 48
    const left = inside ? r.right - width - (r.height - height) / 2 : Math.min(r.right + 6, innerWidth - width - 4)
    return { left, top: r.top + (r.height - height) / 2, width, height }
  }
  const width = Math.max(MENU_WIDTH, Math.min(r.width, 420))
  const below = r.bottom + 6
  const fitsBelow = below + menuHeight < innerHeight
  const top = fitsBelow ? below : Math.max(4, r.top - menuHeight - 6)
  const left = Math.min(Math.max(4, r.left), innerWidth - width - 4)
  return { left, top, width, height: menuHeight }
}

/**
 * The save offer's place: the top right corner, 12 px in, whatever its size.
 * It grows from there, down and to the left, as it opens.
 */
function corner(width: number, height: number): Rect {
  return { left: Math.max(4, innerWidth - width - SAVE_INSET), top: SAVE_INSET, width, height }
}

/**
 * The mode or the asked-for size changed: from where the host is now, spring
 * to the new place (`duration` seconds). Following the field as the page
 * scrolls isn't animated: the target moves and the host with it, 1:1.
 */
function retarget(duration: number) {
  const from = lastTarget
  const to = targetRect()
  if (!from || !to) return
  for (const k of ["left", "top", "width", "height"] as const) offset[k].shift(from[k] - to[k], duration)
  lastTarget = to
}

function position() {
  if (!host) return
  if ((anchor && !anchor.isConnected) || !host.isConnected) return closeMenu()
  const to = targetRect()
  if (!to) return closeMenu()
  lastTarget = to
  const at = { left: to.left + offset.left.value, top: to.top + offset.top.value, width: Math.max(1, to.width + offset.width.value), height: Math.max(1, to.height + offset.height.value) }
  written = at
  host.style.cssText = important({
    all: "initial",
    position: "fixed",
    inset: "auto",
    top: `${at.top}px`,
    left: `${at.left}px`,
    width: `${at.width}px`,
    height: `${at.height}px`,
    margin: "0",
    display: "block",
    "z-index": "2147483647",
    ...(closing ? { "pointer-events": "none" } : {}),
  })
  // The menu only takes a pick once it has sat still for a moment (see
  // Dwell). From inside its frame it can't tell it was moved, so say so: the
  // page can restyle the host, and the field it follows can move.
  if (frame) {
    const f = frame.getBoundingClientRect()
    const rect = [f.left, f.top, f.width, f.height].map(Math.round).join()
    if (rect !== lastRect && !followedResize(lastRect, rect)) tellMoved()
    resized = null
    lastRect = rect
  }
  // While it fades out it lets clicks through (and anything under it would
  // read as a cover): only a surface still in use goes back on top.
  if (!closing && !held && covered(host)) raise()
  if (host) raf = requestAnimationFrame(position)
}

/**
 * Whether the frame's move from `from` to `to` is only the page reflowing for
 * a viewport resize the browser made: the same size, shifted no further than
 * the viewport changed, in a normal tabbed window (whose size the page can't
 * set). A centred login form moves by half an infobar when one comes or goes;
 * that isn't the page moving the menu, so the dwell isn't restarted for it.
 */
function followedResize(from: string, to: string): boolean {
  if (!resized || !from || !window.toolbar.visible) return false
  const [fl, ft, fw, fh] = from.split(",").map(Number)
  const [tl, tt, tw, th] = to.split(",").map(Number)
  return fw === tw && fh === th && Math.abs(tl - fl) <= Math.abs(resized.dw) && Math.abs(tt - ft) <= Math.abs(resized.dh)
}

function onResize(event: Event) {
  if (!event.isTrusted) return
  const now = { w: innerWidth, h: innerHeight }
  resized = { dw: (resized?.dw ?? 0) + now.w - viewport.w, dh: (resized?.dh ?? 0) + now.h - viewport.h }
  viewport = now
}

function frameStyle(radius: number) {
  return `all:initial;width:100%;height:100%;border:0;border-radius:${radius}px;box-shadow:${SHADOW()};background:transparent;color-scheme:normal;`
}

/** Opens the surface: under `el` with the account list, or with no field, the save offer. */
function openMenu(el: FormControl | null, t: string, rows: number, as: SurfaceMode = "accounts", at?: Box) {
  closeMenu()
  anchor = el
  anchorBox = at ? { box: at, x: scrollX, y: scrollY } : null
  token = t
  mode = as
  closing = false
  typedSinceOpen = false
  wanted = { width: 0, height: 0 }
  for (const s of Object.values(offset)) s.jump(0)
  lastTarget = null
  const shown = Math.min(Math.max(rows, 1), 5)
  menuHeight = shown * MENU_ROW + MENU_CHROME + (rows >= 2 ? MENU_CAPTION : 0)
  raises = 0
  const box = (host = document.createElement(hostTag()))
  box.setAttribute("popover", "manual")
  // Hidden by the page, or by the browser for a modal dialog or full screen:
  // that counts as a raise like any other.
  box.addEventListener("beforetoggle", (e) => {
    if (e.isTrusted && (e as ToggleEvent).newState === "closed" && !raising) queueMicrotask(() => host === box && raise())
  })
  const root = box.attachShadow({ mode: "closed" })
  frame = document.createElement("iframe")
  // No token in the URL: the menu asks for it (see onMenuReady).
  frame.src = chrome.runtime.getURL("menu.html")
  frame.setAttribute("allow", "")
  frame.style.cssText = frameStyle(RADIUS)
  root.append(frame)
  ;((el && modalAround(el)) ?? document.documentElement).append(box)
  show(box)
  position()
  if (as === "save") {
    // From the corner, where the toolbar button is: 24 px of travel and a fade.
    frame.style.borderRadius = `${SAVE_GUESS.height / 2}px`
    frame.animate(
      reducedMotion()
        ? [{ opacity: 0 }, { opacity: 1 }]
        : [
            { opacity: 0, transform: "translate(17px, -17px)" },
            { opacity: 1, transform: "none" },
          ],
      timing(0.4),
    )
    return
  }
  // Grows from the field: scale .96 → 1 from the edge that faces it. Only
  // while it opens: the menu's visibility guard refuses picks while it's
  // scaled or see-through, so they wait until it's at rest.
  const r = el ? el.getBoundingClientRect() : boxNow()!
  const below = ((lastTarget as Rect | null)?.top ?? r.bottom) >= r.bottom
  frame.style.transformOrigin = below ? "top left" : "bottom left"
  frame.animate(
    reducedMotion()
      ? [{ opacity: 0 }, { opacity: 1 }]
      : [
          { opacity: 0, transform: "scale(0.96)" },
          { opacity: 1, transform: "none" },
        ],
    timing(0.25),
  )
}

/**
 * The frame asked for a size, and maybe a new mode. It can only fold either
 * surface into a pill: the account list and the save offer are different
 * surfaces with different tokens, and neither turns into the other.
 */
function resize(height: number, width: number | undefined, next: SurfaceMode | undefined) {
  if (next !== undefined && next !== mode && next !== "pill") return
  const changed = next !== undefined && next !== mode
  const first = wanted.height === 0
  if (changed) mode = next!
  if (mode === "accounts") menuHeight = height
  const same = !changed && wanted.width === (width ?? wanted.width) && wanted.height === height
  wanted = { width: width ?? wanted.width, height }
  if (same || !lastTarget) return
  // The offer's first size isn't a change anyone made: it lands there.
  if (first && mode === "save") return void (lastTarget = targetRect())
  retarget(changed ? 0.38 : 0.37)
  // The pill inside keeps its place on the page while the frame moves around
  // it: hand the frame the springs, which it steps on its own clock.
  if (mode === "pill" && lastTarget)
    port?.postMessage({
      type: "db:fold",
      width: lastTarget.width,
      at: epochNow(),
      springs: { left: offset.left.snapshot(), top: offset.top.snapshot(), width: offset.width.snapshot(), height: offset.height.snapshot() },
    })
  if (changed && frame) {
    const radius = (targetRect()?.height ?? 2 * RADIUS) / 2
    const anim = frame.animate([{ borderRadius: getComputedStyle(frame).borderRadius }, { borderRadius: `${radius}px` }], { ...timing(0.38), fill: "forwards" })
    anim.finished.then(
      () => {
        if (frame) frame.style.borderRadius = `${radius}px`
        anim.cancel()
      },
      () => {},
    )
  }
}

/**
 * Fades the surface out, then removes it. `travel`: a saved login leaves
 * toward the toolbar button at the top right, where it now lives.
 */
function leave(travel = false) {
  if (closing) return
  if (!host || !frame) return closeMenu()
  closing = true
  const f = frame
  const done = () => {
    if (frame === f) closeMenu()
  }
  if (typeof f.animate !== "function") return done()
  const keyframes = reducedMotion()
    ? [{ opacity: 1 }, { opacity: 0 }]
    : travel
      ? [
          { opacity: 1, transform: "none" },
          { opacity: 0, transform: `translate(${Math.min(40, innerWidth - (lastTarget?.left ?? 0) - (lastTarget?.width ?? 0))}px, -36px) scale(0.6)` },
        ]
      : [
          { opacity: 1, transform: "none" },
          { opacity: 0, transform: "scale(0.96)" },
        ]
  f.style.transformOrigin = travel ? "top right" : "center"
  const anim = f.animate(keyframes, { ...timing(travel ? 0.5 : 0.25), fill: "forwards" })
  anim.finished.then(done, done)
  // In case the page stops the animation from finishing (a hidden tab).
  setTimeout(done, 900)
}

/**
 * Takes the pill out of the top layer (`on`), or puts it back. While
 * anything shows in the top layer, Chromium's visibility readings say no
 * field anywhere is fully visible, so the checks of a frame's fields (see
 * Forms.menuPick) run with it put away for a moment. Only a pill.
 */
function hold(on: boolean): boolean {
  if (!host || mode !== "pill" || closing) return false
  held = on
  raising = true
  try {
    if (on) host.hidePopover()
  } catch {
    // Not shown: nothing to put away.
  } finally {
    raising = false
  }
  if (!on) show(host)
  return true
}

/** The element the open menu hangs from, if one is open. */
export const menuHost = (): HTMLElement | null => host

export function closeMenu(refocus = false, dismissed = false) {
  cancelAnimationFrame(raf)
  if (token) void send({ type: "db:menu-close", token, dismissed })
  port?.close()
  port = null
  const field = anchor
  const el = host
  host = frame = anchor = null
  anchorBox = null
  held = false
  el?.remove()
  token = null
  mode = "accounts"
  closing = false
  lastTarget = null
  written = null
  near = false
  for (const t of saveTimers) clearTimeout(t)
  saveTimers = []
  menuOrigin = lastRect = ""
  if (refocus) field?.focus({ preventScroll: true })
}

/** The save offer, opened by the background after a confirmed sign-in. Top page only. */
export function openSaveSurface(t: string) {
  if (!isTop || document.hidden) return false
  closeMenu()
  openMenu(null, t, 0, "save")
  // A frame that never says its size never loaded the offer (it expired, or
  // the page got in the way): it doesn't stay. Nor does any offer for long,
  // even one whose bar is paused under the pointer.
  saveTimers = [
    setTimeout(() => token === t && wanted.height === 0 && leave(), SAVE_LOAD_MS),
    setTimeout(() => token === t && leave(), SAVE_CAP_MS),
  ]
  return true
}

/**
 * The pill's host, if it's still exactly where and as big as this script put
 * it, and no bigger than a pill: then it's Deadbolt's own and doesn't count
 * as covering a field. The host is an element of the page, which can restyle
 * it (a stylesheet with !important, say) to cover a field; then it counts as
 * a cover like anything else, and the fill writes nothing there.
 */
export function ownPill(): Element | null {
  if (!host || mode !== "pill" || !written || closing) return null
  const r = host.getBoundingClientRect()
  const near = (a: number, b: number) => Math.abs(a - b) <= 1
  const placed = near(r.left, written.left) && near(r.top, written.top) && near(r.width, written.width) && near(r.height, written.height)
  return placed && r.width <= PILL_MAX.width + 1 && r.height <= PILL_MAX.height + 1 ? host : null
}

/** Resolves once the surface has folded into its pill (or after `ms`, whatever happens). */
function pillSettled(ms: number): Promise<void> {
  const until = performance.now() + ms
  return new Promise((resolve) => {
    const check = () => {
      const still = mode === "pill" && Object.values(offset).every((s) => s.done)
      if (still || !host || performance.now() > until) return resolve()
      requestAnimationFrame(check)
    }
    check()
  })
}

let querying: Promise<void> | null = null
/** Fields recently found to have no accounts, so rescans don't re-ask. */
const emptyUntil = new WeakMap<Element, number>()

/**
 * How the field asks: it got focus ("focus"), the user clicked into it
 * ("click"), or the user pressed ↓ in it or clicked it again while it had
 * focus ("again"). A click or more counts as explicit for the locked row
 * (see Autofill.query).
 */
type Asked = "focus" | "click" | "again"

async function maybeOpen(el: FormControl, how: Asked = "focus") {
  if (!(el instanceof HTMLInputElement) || !targetFor(el)) return maybeOpenForms(el, how)
  // While the tab learns its site, the user signs in by hand.
  if (!isTop || querying || dismissedFor === el || !recentGesture() || learning()) return
  // The save offer stays until it's answered or its time runs out.
  if (host && mode === "save") return
  const explicit = how !== "focus"
  if (!explicit && (emptyUntil.get(el) ?? 0) > Date.now()) return
  // Out of the way while the user types for themselves (see onInput).
  if (quiet.has(el) ? how === "focus" : byHand.has(formOf(el)) && how !== "again") return
  const t = targetFor(el)
  if (!t || !MENU_ROLES.includes(t.role)) return
  const kind = state.kind()
  const generating = t.role === "new-password"
  if (generating && !(kind && GENERATE_KINDS.includes(kind))) return
  if (anchor === el && host) return
  querying = (async () => {
    const roles = [...new Set(state.targets().map((x) => x.role))]
    // On a later step's field, the username the form holds: the menu narrows
    // to the login it names, or stays away when it names none (see Autofill.query).
    // Only a username the user typed (or Deadbolt filled) counts: one the
    // page put there itself mustn't decide whether a menu shows.
    const later = t.role === "password" || t.role === "otp"
    const box = later ? state.targets().find((x) => IDENTIFIER_ROLES.includes(x.role))?.el : undefined
    const named = box ? (await ownValue(box, box.value))?.slice(0, 500) : undefined
    // On a provider's own password step (accounts.google.com), the account
    // it shows narrows the menu too; the background checks the host again
    // and never hides the menu for it.
    const onPage = later && !named ? pageAccount(el) : undefined
    // A pattern outside what generate.ts reads, or lengths that can't meet: no generated password.
    const rules = generating ? fieldRules(state.targets()) : undefined
    const reply =
      rules === null
        ? null
        : await send<QueryReply>({ type: "db:query", roles, focused: t.role, form: state.form(), kind, rules, explicit, again: how === "again", ...(named ? { identifier: named } : {}), ...(onPage ? { pageAccount: onPage } : {}) })
    if (reply?.token && reply.rows > 0) {
      if (deepActiveElement() === el) openMenu(el, reply.token, reply.rows)
    } else emptyUntil.set(el, Date.now() + 15_000)
  })().finally(() => (querying = null))
}

/**
 * The account a provider's own password step shows, on a provider host whose
 * page-set account is trusted (see isAccountPage): its visible account chip,
 * else the hidden username its form carries. Google's: a chip with
 * `data-profile-identifier`, and `<input name="identifier" id="hiddenEmail">`.
 */
function pageAccount(field: HTMLInputElement): string | undefined {
  if (!isAccountPage(location.href)) return undefined
  const chip = [...document.querySelectorAll("[data-profile-identifier]")].find((c) => c.getClientRects().length > 0)
  const shown = pageAccountOf(chip?.textContent?.slice(0, 501))
  if (shown) return shown
  const hidden = (field.form ?? document).querySelector<HTMLInputElement>('input[name="identifier"], input#hiddenEmail')
  return pageAccountOf(hidden?.value)
}

/**
 * An identity or card field: the identities or cards to fill its section
 * with, on the same gesture rules as a login field. In a frame, the
 * background opens the menu in the top page, under where the field shows
 * (see Forms.query); the frame only says where that is.
 */
async function maybeOpenForms(el: FormControl, how: Asked) {
  if (querying || dismissedFor === el || !recentGesture() || learning()) return
  if (host && mode === "save") return
  const explicit = how !== "focus"
  if (!explicit && (emptyUntil.get(el) ?? 0) > Date.now()) return
  if (quiet.has(el) && how === "focus") return
  const f = state.formFields().find((x) => x.el === el)
  if (!f || (anchor === el && host)) return
  querying = (async () => {
    const box = isTop ? undefined : fillable(el) ? visibleBox(el) : null
    if (box === null) return
    // What the menu says an identity fills: only the fields it would fill now, those on screen.
    const fillsNow = (x: FormField) => f.kind !== "identity" || x.el === el || onScreen(x.el)
    const roles = [...new Set(sectionFields(state.formFields(), f.section, f.kind).filter(fillsNow).map((x) => x.role))]
    const reply = await send<QueryReply>({ type: "db:forms-query", kind: f.kind, form: state.formsForm(), section: f.section, roles, explicit, ...(box ? { box } : {}) })
    if (!reply?.rows) emptyUntil.set(el, Date.now() + 15_000)
    else if (isTop && reply.token && deepActiveElement() === el) openMenu(el, reply.token, reply.rows)
  })().finally(() => (querying = null))
}

const isControl = (el: unknown): el is FormControl => el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement

function onFocusIn(event: FocusEvent) {
  const el = event.composedPath()[0]
  if (!isControl(el)) return
  const clicked = recentGesture() && (lastPointer === el || (lastPointer instanceof HTMLLabelElement && lastPointer.control === el))
  void maybeOpen(el, clicked ? "click" : "focus")
}

/**
 * The user's own typing (trusted input only; Deadbolt's fills dispatch
 * untrusted events). In the field the menu is open on, an identifier narrows
 * the list: the frame filters its rows by the text over the channel only it
 * and this script hold, and says how many match (see onPortMessage). A
 * password typed by hand puts the menu away.
 */
function onInput(event: Event) {
  if (!event.isTrusted) return
  const el = event.composedPath()[0]
  if (!(el instanceof HTMLInputElement)) return
  if (!el.value) {
    quiet.delete(el)
    byHand.delete(formOf(el))
  }
  if (!host || mode !== "accounts" || el !== anchor || closing) return
  typedSinceOpen = true
  const role = targetFor(el)?.role
  if (role && IDENTIFIER_ROLES.includes(role)) return void port?.postMessage({ type: "db:filter", query: el.value.slice(0, 200) })
  quiet.add(el)
  leave()
}

/** When the offer was last told the pointer is in the page, not over it. */
let awaySaidAt = 0

/**
 * The pointer moving in the page: it isn't over the offer (the page gets no
 * events over the frame), which the offer needs to know to close again (see
 * menu.ts). Coming near pauses its bar, as being on it does.
 */
function onPointerMove(event: PointerEvent) {
  if (!host || mode !== "save" || !lastTarget || !event.isTrusted) return
  if (event.timeStamp - awaySaidAt > 120) {
    awaySaidAt = event.timeStamp
    port?.postMessage({ type: "db:away" })
  }
  const r = lastTarget
  const dx = Math.max(r.left - event.clientX, 0, event.clientX - (r.left + r.width))
  const dy = Math.max(r.top - event.clientY, 0, event.clientY - (r.top + r.height))
  const now = Math.hypot(dx, dy) < 72
  if (now === near) return
  near = now
  port?.postMessage({ type: "db:near", near })
}

function onPointerDown(event: PointerEvent) {
  if (!event.isTrusted) return
  lastGestureAt = Date.now()
  const target = event.composedPath()[0]
  lastPointer = target ?? null
  // Clicking a field that already has focus (e.g. autofocus) opens the menu too.
  if (isControl(target) && target === deepActiveElement() && !host) {
    if (dismissedFor === target) dismissedFor = null
    void maybeOpen(target, "again")
  }
  if (!host) return
  // A click in the page while the offer shows: the user is getting on with
  // it. The offer shrinks to a dot in the corner (as when its time runs
  // out), still there to reopen for a while.
  if (mode === "save") {
    port?.postMessage({ type: "db:away" })
    return port ? void port.postMessage({ type: "db:tuck" }) : leave(true)
  }
  const path = event.composedPath()
  if (path.includes(host) || path.includes(anchor as EventTarget)) return
  if (mode === "pill") return leave()
  closeMenu()
}

function onKeyDown(event: KeyboardEvent) {
  if (!event.isTrusted) return
  lastGestureAt = Date.now()
  lastPointer = null
  const target = event.composedPath()[0]
  if (!host) {
    // ↓ in a field that has no menu (dismissed, or focused from script) asks for one.
    if (event.key === "ArrowDown" && target instanceof HTMLInputElement && (targetFor(target) || state.formFields().some((f) => f.el === target))) {
      dismissedFor = null
      emptyUntil.delete(target)
      quiet.delete(target)
      void maybeOpen(target, "again")
    }
    return
  }
  if (target !== anchor || mode !== "accounts") return
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
  // A sign-in session's step (no pick) fills nothing while the tab learns: the user signs in by hand.
  if (message.notice && learning()) return { filled: [] }
  // A pick from the menu folded it into a pill on the field, which stays to
  // say how the fill went and goes by itself. Any other fill (the popup's,
  // an email-first step) closes what's open.
  if (mode !== "pill") closeMenu()
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
  // Nothing is written while the surface is still folding over the form:
  // only the settled pill, where this script put it, isn't taken for a cover
  // (see ownPill). Each write checks again.
  if (mode === "pill") await pillSettled(700)
  if (state.form() !== message.form) return { filled: [] }
  const { filled, last } = await fillFields(targets, message.values, (el) => fillable(el, ownPill()))
  if (filled.includes("new-password") && message.values.newPassword && typeof message.generated === "string")
    rememberGenerated(message.generated, message.values.newPassword)
  if (filled.length) {
    lastFilled = targets.filter((t) => filled.includes(t.role)).map((t) => t.el)
    submittedSinceFill = false
  }
  last?.focus({ preventScroll: true })
  // A sign-in session's step, filled without a pick: a pill on the field
  // says so ("Password filled"), then goes (see menu.ts showNotice).
  // On the last field written: for a code in one box per digit, beside the last box.
  const on = [...lastFilled].reverse().find((el) => el.isConnected)
  if (filled.length && typeof message.notice === "string" && isTop && on && !host) openMenu(on, message.notice, 0, "pill")
  return { filled }
}

const formsState = (): FormsState => ({ fields: () => state.formFields(), form: () => state.formsForm(), rescan: () => state.rescan() })

/**
 * Writes an identity or card into the fields db:forms-approve fixed for
 * this fill, in the snapshot it was chosen for, as applyFill does for a login.
 */
async function applyFormsFill(message: Extract<ToContent, { type: "db:forms-fill" }>): Promise<FormsAck> {
  if (mode !== "pill") closeMenu()
  lastGestureAt = 0
  const values = message.values && typeof message.values === "object" ? message.values : {}
  const targets = takeApproved(formsState(), String(message.approval), message.form)
  if (!targets?.length) return { filled: [] }
  if (mode === "pill") await pillSettled(700)
  if (state.formsForm() !== message.form) return { filled: [] }
  const { filled } = await fillForm(targets, values, (el) => fillCheck(targets[0].kind, ownPill())(el))
  return { filled }
}

export function markSubmitted() {
  if (lastFilled.length) submittedSinceFill = true
}

/** When the user last clicked a submit control or pressed Enter in a field themselves (content.ts). */
let submitGestureAt = -Infinity
const GONE_COUNTS_MS = 2000
export function noteSubmitGesture() {
  submitGestureAt = performance.now()
}

/**
 * Whether the page has moved on since the last fill here: the user submitted
 * (content.ts counts only their own click or Enter), or, right after their
 * own click or Enter, none of the filled fields is still in the login form.
 * Only then does the background fill a sign-in session's next step into this
 * document.
 */
export function stepped(): boolean {
  if (!lastFilled.length) return false
  if (submittedSinceFill) return true
  // The filled fields going away counts only right after the user's own
  // click or Enter: a page's script can take them away itself.
  if (performance.now() - submitGestureAt > GONE_COUNTS_MS) return false
  const now = state.targets()
  return lastFilled.every((el) => !el.isConnected || !now.some((t) => t.el === el))
}

/** Springs the frame's corners to `radius`, from wherever they are now. */
function roundTo(radius: number) {
  const f = frame
  if (!f) return
  const anim = f.animate([{ borderRadius: getComputedStyle(f).borderRadius }, { borderRadius: `${radius}px` }], { ...timing(0.37), fill: "forwards" })
  anim.finished.then(
    () => {
      f.style.borderRadius = `${radius}px`
      anim.cancel()
    },
    () => {},
  )
}

/** Whether the user typed in the menu's field since it opened. */
let typedSinceOpen = false

/** The frame, over the private channel: its pill or offer is done, or how many rows match what was typed. */
function onPortMessage(e: MessageEvent<{ type?: unknown; travel?: unknown; count?: unknown; radius?: unknown }>) {
  if (e.data?.type === "db:surface-done") return leave(e.data.travel === true)
  // The offer changing shape (pill, card, dot): its corners follow its frame's size.
  if (e.data?.type === "db:radius" && mode === "save" && frame && typeof e.data.radius === "number") return roundTo(Math.min(Math.max(e.data.radius, 0), 20))
  if (e.data?.type !== "db:matches" || mode !== "accounts" || !anchor || e.data.count !== 0) return
  // Nothing saved matches what the user is typing: they're signing in by
  // hand. Out of the way, here and on the rest of the form.
  quiet.add(anchor)
  byHand.add(formOf(anchor))
  leave()
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
  // The frame's own word that its pill or offer is done, over the channel only it and this script hold.
  port.onmessage = onPortMessage
  // Typed before the frame was ready: narrow it now.
  const typed = anchor && mode === "accounts" && anchor.value && typedSinceOpen ? anchor.value : ""
  if (typed) port.postMessage({ type: "db:filter", query: typed.slice(0, 200) })
  win.postMessage({ type: "db:menu-token", token }, event.origin, [channel.port2])
}

/** The page showed a popover, or a dialog through `beforetoggle`: once it's in the top layer, go back over it. */
function onBeforeToggle(event: Event) {
  if (host && event.isTrusted && event.target !== host && (event as ToggleEvent).newState === "open") queueMicrotask(raise)
}

/**
 * A dialog opened. A modal one makes everything outside it inert, so a menu
 * outside it closes; one the menu is in gets raised over again.
 */
function onDialogs(records: MutationRecord[]) {
  for (const r of records) {
    const dialog = r.target
    if (!host || !(dialog instanceof HTMLDialogElement) || !dialog.matches(":modal")) continue
    if (!within(host, dialog)) return closeMenu()
    raise()
  }
}

/**
 * Full screen draws only the full-screen element. A menu outside it closes
 * (the next focus opens one inside it); one inside it goes back on top.
 */
function onFullscreen() {
  const full = document.fullscreenElement
  if (!host || !full) return
  if (!within(host, full)) return closeMenu()
  raise()
}

export function initMenu(page: PageState) {
  state = page
  if (isTop) {
    document.addEventListener("beforetoggle", onBeforeToggle, true)
    addEventListener("resize", onResize, true)
    document.addEventListener("fullscreenchange", onFullscreen)
    new MutationObserver(onDialogs).observe(document, { subtree: true, attributes: true, attributeFilter: ["open"] })
  }
  window.addEventListener("message", onMenuReady, true)
  document.addEventListener("focusin", onFocusIn, true)
  document.addEventListener("pointerdown", onPointerDown, true)
  document.addEventListener("keydown", onKeyDown, true)
  document.addEventListener("input", onInput, true)
  window.addEventListener("pointermove", onPointerMove, { capture: true, passive: true })
  // Leaving the page (or entering the back/forward cache) takes the menu
  // along; coming back is a new visit.
  window.addEventListener("pagehide", () => {
    closeMenu()
    hideRing()
    clearInterval(tileTimer)
    dismissedFor = null
    lastGestureAt = 0
    lastPointer = null
    lastFilled = []
    submittedSinceFill = false
  })
  // Answering tells the background the message reached a live document.
  chrome.runtime.onMessage.addListener((message: ToContent, _sender, respond) => {
    switch (message?.type) {
      case "db:fill":
        applyFill(message).then(respond, () => respond({ filled: [] }))
        return true
      case "db:forms-fill":
        applyFormsFill(message).then(respond, () => respond({ filled: [] }))
        return true
      case "db:forms-approve":
        approveForms(formsState(), message.form, message.kind === "card" ? "card" : "identity", typeof message.section === "string" ? message.section : undefined, message.measure === true, menuHost()).then(respond, () => respond(null))
        return true
      case "db:forms-approved":
        approvedForms(formsState(), String(message.approval)).then((boxes) => respond(boxes ? { boxes } : null), () => respond(null))
        return true
      case "db:forms-open":
        return void respond(openForFrame(String(message.token), Number(message.rows), message.box))
      case "db:forms-hold":
        if (message.token !== token) return void respond(false)
        if (!message.hold) return void respond(hold(false))
        pillSettled(900).then(() => respond(hold(true)))
        return true
      case "db:generated":
        keptGenerated(String(message.generated))
        return void respond(true)
      case "db:close-menu":
        if (message.token === token) {
          if (mode === "accounts") {
            dismissedFor = anchor
            closeMenu(true)
          } else leave()
        }
        return void respond(true)
      case "db:resize-menu":
        if (message.token === token) resize(message.height, message.width, message.mode)
        return void respond(true)
      case "db:surface":
        return void respond(openSaveSurface(String(message.token)))
      case "db:point":
        return void respond(pointAtProvider(String(message.provider)))
      case "db:chooser":
        if (isTop) pointAtTile(String(message.account))
        return void respond(true)
    }
  })
}

/**
 * "Sign in with <provider>": ring the site's own button for it, if one
 * shows, and say whether it did. The user clicks it; Deadbolt doesn't.
 */
function pointAtProvider(id: string): boolean {
  if (!isTop) return false
  const p = provider(id)
  const button = findProviderButton(p)
  if (!button) return false
  closeMenu()
  showRing(button, `Your ${p.name} sign-in`)
  return true
}

let tileTimer: ReturnType<typeof setInterval> | undefined
/**
 * On the provider's account chooser: ring the tile for the linked account
 * once it shows (choosers draw late), with a pill that names no one (the
 * page shows the account itself). The user picks it.
 */
function pointAtTile(account: string) {
  clearInterval(tileTimer)
  let tries = 0
  const look = () => {
    const tile = findAccountTile(account)
    if (tile) {
      clearInterval(tileTimer)
      showRing(tile, "Your linked account")
    } else if (++tries > 25) clearInterval(tileTimer)
  }
  look()
  tileTimer = setInterval(look, 300)
}

/** The forms menu for a field in a frame below, at `box` in this page (see Forms.query). Top page only. */
function openForFrame(t: string, rows: number, box: Box): boolean {
  if (!isTop || document.hidden || (host && mode === "save") || !Number.isFinite(rows) || rows < 1) return false
  if (!box || ![box.left, box.top, box.right, box.bottom].every(Number.isFinite)) return false
  openMenu(null, t, rows, "accounts", box)
  return true
}

/** Called after each page scan: offer the menu on an already-focused field. */
export function refreshMenu(focused: HTMLInputElement) {
  if (!host) void maybeOpen(focused, "focus")
}
