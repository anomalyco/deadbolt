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


import { GENERATE_KINDS, IDENTIFIER_ROLES, MENU_ROLES, type Box, type QueryReply, type SurfaceKind, type SurfaceMode, type ToContent } from "../messages"
import { epochNow, gridBox, inFrame, MENU_MOTION, reducedMotion, Spring, timing } from "../ui/motion"
import { asksNewPassword, ownerOf, type Field, type FieldOwner, type FormControl } from "./detect"
import { approvedForms, approveForms, onScreen } from "./formfill"
import { sectionFields, type FormField } from "./forms"
import { hideRing } from "./ring"
import { readPageIcon } from "./site-icon"
import { fillable, ownValue, successor, visibleBox } from "./fill"
import { fieldRules, keptGenerated } from "./generate"
import { learning } from "./learn"
import { deepActiveElement, eventTarget, markOwnHost } from "./shadow"
import {
  boxNow, corner, covered, formOf, frameAround, frameStyle, GESTURE_WINDOW_MS, hostTag, important, isControl,
  MAX_RAISES, MENU_CAPTION, MENU_CHROME, MENU_MARGIN, MENU_MIN_WIDTH, MENU_ROW, menuPlace, modalAround, pageAccount, PILL_MAX,
  RADIUS, REVEAL_LATEST_MS, SAVE_CAP_MS, SAVE_GUESS, SAVE_LOAD_MS, send, SHADOW, unzoom, within,
  type AnchorBox, type MenuSide, type Rect,
} from "./inline/dom"
import {
  applyFill, applyFormsFill, formsStateOf, markSubmitted, noteSubmitGesture, resetFillState, stepped as steppedWith,
} from "./inline/fill"
import {
  clearTileTimer, framedGone, getFramedFor, onFrameScroll, pointAtProvider, pointAtTile, trackFramed,
} from "./inline/framed"
import { createPlacementGuard } from "./inline/guard"

export { markSubmitted, MAX_RAISES, MENU_ROW, noteSubmitGesture, send }

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
  /** The user asked to fill `el` (see manualOpen): take it as a login field if the scan didn't. Whether it is one now. */
  manual?(el: HTMLInputElement): boolean
}


let state: PageState
let host: HTMLElement | null = null
let frame: HTMLIFrameElement | null = null
let anchor: FormControl | null = null
/** Where the anchor was when the surface opened on it: a pill follows a box the page re-rendered in its place (see successor). */
let anchorOwner: FieldOwner | null = null
/**
 * For a field in a frame below: where it showed in this page when the menu
 * opened, the page's scroll then, and the frame element it shows in (if
 * this page has it) and where that was. The menu follows the frame element
 * as the page moves it (scrolling, or a reflow), else the page's scrolling.
 */
let anchorBox: AnchorBox | null = null
let token: string | null = null
/** Handed to the menu with its token; only this script can say "the user pressed ↓" over it. */
let port: MessagePort | null = null
let raf = 0
let menuHeight = 0
/** A login field's list goes above it when there's room (see menuPlace); the side it took stays while it fits. */
let preferAbove = false
let side: MenuSide | null = null
let raises = 0
/** Set while Deadbolt itself hides and shows the host. */
let raising = false
/** The surface is out of the top layer for a moment, while frames below are measured (see hold). */
let held = false
/** Which mode the surface is in, and the size the frame asked for in it. */
let mode: SurfaceMode = "accounts"
let wanted = { width: 0, height: 0 }
/** The host's place is its mode's target plus these, which spring to 0 when the mode or size changes. */
const offset = { left: new Spring(0, undefined, epochNow), top: new Spring(0, undefined, epochNow), width: new Spring(0, undefined, epochNow), height: new Spring(0, undefined, epochNow) }
let lastTarget: Rect | null = null
/** Where this script last put the host: what it must still be for the host to be taken as Deadbolt's own (see ownPill). */
let written: Rect | null = null
let closing = false
/** The save offer's fallbacks: it goes if its frame never loads, and in any case after a while. */
let saveTimers: ReturnType<typeof setTimeout>[] = []
let dismissedFor: Element | null = null
/**
 * Fields whose typing narrowed the menu to nothing (or that the user typed a
 * password into by hand, or pressed Enter in): the menu doesn't come back on
 * focus until the field is cleared, clicked again, or ↓.
 */
const quiet = new WeakSet<Element>()
/**
 * Forms the user is filling by hand: the identifier they typed matched no
 * saved login. Their other fields don't open the menu on focus or click
 * either, only on ↓ or a second click.
 */
const byHand = new WeakSet<Node>()
/** Whether the pointer is near the save offer, as last told to its frame (it pauses the offer's bar). */
let near = false
/** The origin the menu frame said it's on. */
let menuOrigin = ""
/**
 * The menu only opens right after a real click or keypress. A page can focus a
 * field from script (focus() fires a trusted focusin) and slide it under the
 * user's next click; it can't fake the user's own input event.
 */
let lastGestureAt = 0
/** What the user's last pointerdown landed on: a click into a field asks for the menu outright. */
let lastPointer: EventTarget | null = null
/** The field the user last opened the context menu on, and when: "Fill with Deadbolt" is for it. */
let contextTarget: { el: EventTarget | null; at: number } | null = null
/** How long after its context menu opened "Fill with Deadbolt" is still about that field. */
const CONTEXT_MS = 60_000
const recentGesture = () => Date.now() - lastGestureAt < GESTURE_WINDOW_MS
/**
 * The menu opens only in the top page. A frame's position, size and style are
 * up to the page around it, which a menu inside can't watch. A field in a
 * frame only says where it shows; the background opens the menu in the top
 * page under it, for a login field only when every frame up to the top page
 * is the same site (see Autofill.query and Forms.query).
 */
const isTop = window === window.top

const guard = createPlacementGuard({
  host: () => host,
  frame: () => frame,
  port: () => port,
  written: () => written,
  held: () => held,
  closing: () => closing,
  raising: () => raising,
  tellMoved,
  raise,
})

const fillHost = {
  state: () => state,
  mode: () => mode,
  isTop,
  host: () => host,
  closeMenu: () => closeMenu(),
  clearGesture: () => { lastGestureAt = 0 },
  pillSettled,
  ownPill,
  openPill: (el: FormControl, t: string) => openMenu(el, t, 0, "pill"),
}

export function stepped(): boolean {
  return steppedWith(state)
}

function targetFor(el: Element): Field | undefined {
  return state.targets().find((t) => t.el === el)
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

/** Where the surface goes in its mode, in the viewport. */
function targetRect(): Rect | null {
  if (mode === "save" || mode === "signin") return corner(wanted.width || SAVE_GUESS.width, wanted.height || SAVE_GUESS.height)
  // The saved pill stays in the same corner. A pill for a frame's field sits
  // on where the field shows (anchorBox), out of sight while the frame's
  // fields are checked (see hold).
  if (mode === "pill" && !anchor && !anchorBox) return corner(Math.min(wanted.width || 180, 320), 32)
  const r = anchor ? anchor.getBoundingClientRect() : boxNow(anchorBox)
  if (!r) return null
  if (mode === "pill") {
    // On the field, at its end: beside the text the user sees being filled, not over the next field.
    const height = 32
    const width = Math.min(wanted.width || 140, 260)
    const inside = r.width >= width + 48
    const left = inside ? r.right - width - (r.height - height) / 2 : Math.min(r.right + 6, innerWidth - width - 4)
    return { left, top: r.top + (r.height - height) / 2, width, height }
  }
  // As wide as the field (or the frame's box), left-aligned with it, within
  // the viewport; a login list above the field, clear of the browser's own
  // autofill list below it (see menuPlace).
  const width = Math.min(Math.max(r.width, MENU_MIN_WIDTH), innerWidth - 2 * MENU_MARGIN)
  const left = Math.min(Math.max(MENU_MARGIN, r.left), innerWidth - width - MENU_MARGIN)
  const placed = menuPlace(r, menuHeight, innerHeight, preferAbove, side, preferAbove ? fieldsUnder(left, width) : [])
  side = placed.side
  return { left, top: placed.top, width, height: menuHeight }
}

/** The page's other login fields that show between `left` and `left + width`: what a list above its field mustn't cover (see menuPlace). */
function fieldsUnder(left: number, width: number): DOMRect[] {
  if (!anchor) return []
  return state
    .targets()
    .filter((t) => t.el !== anchor && t.el.isConnected)
    .map((t) => t.el.getBoundingClientRect())
    .filter((b) => b.width >= 2 && b.height >= 2 && b.right > left && b.left < left + width)
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
  // A pill's field re-rendered by the page as it filled: the pill moves to the box now in its place.
  if (anchor instanceof HTMLInputElement && !anchor.isConnected && mode === "pill" && anchorOwner) anchor = successor({ el: anchor, owner: anchorOwner }) ?? anchor
  if ((anchor && !anchor.isConnected) || !host.isConnected || (!held && !host.matches(":popover-open"))) return closeMenu()
  guard.beforePosition()
  const to = targetRect()
  if (!to) return closeMenu()
  lastTarget = to
  const at = gridBox(to, offset)
  written = at
  host.style.cssText = important({
    all: "initial",
    // Undoes a CSS zoom the page put on an element the host is in (<html>,
    // or the field's dialog): zoom multiplies down the tree, top layer or
    // not, so the place and size written here, which are in the viewport's
    // pixels, would be scaled and land elsewhere, and the list with them.
    zoom: String(unzoom(host)),
    position: "fixed",
    inset: "auto",
    top: `${at.top}px`,
    left: `${at.left}px`,
    width: `${at.width}px`,
    height: `${at.height}px`,
    margin: "0",
    // Held, it isn't drawn at all: it may sit on a frame's field being checked (see hold).
    display: held ? "none" : "block",
    "z-index": "2147483647",
    ...(closing ? { "pointer-events": "none" } : {}),
  })
  guard.afterStyleWrite()
  // While it fades out it lets clicks through (and anything under it would
  // read as a cover): only a surface still in use goes back on top.
  if (!closing && !held && covered(host)) raise()
  if (host) raf = requestAnimationFrame((time) => inFrame(time, position))
}

/**
 * Opens the surface: under `el` with the account list, or with no field, the
 * save offer. `captioned` for an identity or card list, which says where a pick goes.
 */
function openMenu(el: FormControl | null, t: string, rows: number, as: SurfaceMode = "accounts", at?: Box, captioned = false) {
  closeMenu()
  anchor = el
  anchorOwner = el instanceof HTMLInputElement ? ownerOf(el) : null
  anchorBox = at ? { box: at, x: scrollX, y: scrollY, frame: frameAround(at) } : null
  token = t
  mode = as
  closing = false
  typedSinceOpen = false
  wanted = { width: 0, height: 0 }
  for (const s of Object.values(offset)) s.jump(0)
  lastTarget = null
  const shown = Math.min(Math.max(rows, 1), 5)
  menuHeight = shown * MENU_ROW + MENU_CHROME + (captioned ? MENU_CAPTION : 0)
  // An identity or card list stays below its field; a login list goes above.
  // Not for a frame's field: this page can't see the frame's other fields,
  // which a list above might cover (see fieldsUnder).
  preferAbove = as === "accounts" && !captioned && !!el
  side = null
  raises = 0
  const box = (host = document.createElement(hostTag()))
  box.setAttribute("popover", "manual")
  // Hidden by the page, or by the browser for a modal dialog or full screen:
  // that counts as a raise like any other.
  box.addEventListener("beforetoggle", guard.onHostToggle)
  markOwnHost(box)
  const root = box.attachShadow({ mode: "closed" })
  // A closed popover isn't drawn, whatever its inline display says:
  // important declarations from a shadow tree beat the light tree's, inline
  // ones included. Out of the top layer the host would be an ordinary fixed
  // box, which an ancestor's transform can move (see watchPaint).
  const sheet = new CSSStyleSheet()
  sheet.replaceSync(":host(:not(:popover-open)) { display: none !important }")
  root.adoptedStyleSheets = [sheet]
  frame = document.createElement("iframe")
  // No token in the URL: the menu asks for it (see onMenuReady).
  frame.src = chrome.runtime.getURL("menu.html")
  frame.setAttribute("allow", "")
  // A screen reader names the frame by this; it's all the page side says (nothing of the vault).
  frame.title = "Deadbolt"
  frame.style.cssText = frameStyle(RADIUS)
  root.append(frame)
  ;((el && modalAround(el)) ?? document.documentElement).append(box)
  show(box)
  guard.startPlacementObserver()
  position()
  guard.startScaleObserver(box)
  const cornerOffer = as === "save" || as === "signin"
  if (cornerOffer) frame.style.borderRadius = `${SAVE_GUESS.height / 2}px`
  // Shown once its frame first says its size (see reveal): until then it's
  // blank, and an early entry played on an empty or guessed box.
  const f = frame
  f.style.opacity = "0"
  revealTimer = setTimeout(() => reveal?.(), REVEAL_LATEST_MS)
  reveal = () => {
    reveal = null
    clearTimeout(revealTimer)
    if (frame !== f) return
    cancelAnimationFrame(raf)
    guard.clearLastRect()
    position()
    if (frame !== f) return
    f.style.opacity = ""
    // Entry runs inside the frame and on a temporary shadow layer so the
    // frame itself stays opaque and still while the visibility dwell runs.
    const r = anchor ? anchor.getBoundingClientRect() : boxNow(anchorBox)
    const origin = !r || (lastTarget?.top ?? r.bottom) >= r.bottom ? "top left" : "bottom left"
    port?.postMessage(cornerOffer ? { type: "db:reveal", corner: true } : { type: "db:reveal", origin })
    const radius = cornerOffer ? SAVE_GUESS.height / 2 : RADIUS
    const shadow = document.createElement("div")
    shadow.style.cssText = `all:initial;position:absolute;inset:0;border-radius:${radius}px;box-shadow:${SHADOW()};pointer-events:none;${cornerOffer ? "" : `transform-origin:${origin};`}`
    root.insertBefore(shadow, f)
    f.style.boxShadow = "none"
    const anim = shadow.animate(
      reducedMotion()
        ? [{ opacity: 0 }, { opacity: 1 }]
        : cornerOffer
          ? [
              { opacity: 0, transform: "translate(17px, -17px)" },
              { opacity: 1, transform: "none" },
            ]
          : [
              { opacity: 0, transform: "scale(0.96)" },
              { opacity: 1, transform: "none" },
            ],
      timing(cornerOffer ? MENU_MOTION.openCorner : MENU_MOTION.open),
    )
    const restore = () => {
      revealAnim = null
      shadow.remove()
      if (frame === f) f.style.boxShadow = SHADOW()
    }
    revealAnim = anim
    anim.finished.then(restore, restore)
  }
}

/** Plays the open surface's grow-in, while its frame hasn't shown yet (see openMenu). */
let reveal: (() => void) | null = null
let revealAnim: Animation | null = null
let revealTimer: ReturnType<typeof setTimeout> | undefined

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
  // The surface's first size, before anything of it showed: it lands there,
  // no spring from the guess, and enters now that it has its content.
  if (reveal && (mode === "accounts" || first)) {
    lastTarget = targetRect()
    return reveal()
  }
  reveal?.()
  if (same || !lastTarget) return
  // The offer's first size isn't a change anyone made: it lands there.
  if (first && (mode === "save" || mode === "signin")) return void (lastTarget = targetRect())
  retarget(changed ? MENU_MOTION.frameMode : MENU_MOTION.frameSize)
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
    const anim = frame.animate([{ borderRadius: getComputedStyle(frame).borderRadius }, { borderRadius: `${radius}px` }], { ...timing(MENU_MOTION.frameMode), fill: "forwards" })
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
  revealAnim?.cancel()
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
  const anim = f.animate(keyframes, { ...timing(travel ? MENU_MOTION.leaveTravel : MENU_MOTION.leave), fill: "forwards" })
  anim.finished.then(done, done)
  // In case the page stops the animation from finishing (a hidden tab).
  setTimeout(done, 900)
}

/**
 * Takes the pill out of the top layer and out of sight (`on`), or puts it
 * back. While anything shows in the top layer, Chromium's visibility
 * readings say no field anywhere is fully visible, and a pill on a frame's
 * field covers it, so the checks of a frame's fields (see Forms.menuPick and
 * Autofill.measured) run with it put away for a moment. Only a pill.
 */
function hold(on: boolean): boolean {
  if (!host || mode !== "pill" || closing) return false
  held = on
  raising = true
  try {
    if (on) {
      host.hidePopover()
      host.style.setProperty("display", "none", "important")
    }
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
  guard.reset()
  reveal = null
  revealAnim = null
  clearTimeout(revealTimer)
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
  menuOrigin = ""
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

/** Never replaces a menu, a save, or the person's typing; never focuses. */
function openSignInSurface(t: string) {
  const active = deepActiveElement()
  if (!isTop || document.hidden || host || learning() || (active instanceof HTMLInputElement && active.value)) return false
  // It stays until it's answered, dismissed or the page moves on: past its
  // minute the background renews it on use while the page still qualifies,
  // or takes it away (bg/universal.ts token).
  openMenu(null, t, 0, "signin")
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

/**
 * Resolves once the surface has folded into its pill (or after `ms`, whatever
 * happens): Deadbolt's own pill (see ownPill), within a pixel of its place.
 * Its springs' last sub-pixel tail isn't waited out; that left the pill
 * sitting there, landed, before anything was written.
 */
function pillSettled(ms: number): Promise<void> {
  const until = performance.now() + ms
  return new Promise((resolve) => {
    const check = () => {
      const still = mode === "pill" && Object.values(offset).every((s) => Math.abs(s.value - s.target) < 1) && ownPill() !== null
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
  // The form as it is now, not as the last scan (up to 750 ms ago) saw it:
  // a password box the page just showed, say. A menu opened on an older
  // scan would fill nothing ("The page changed") once the next one runs.
  if (el instanceof HTMLInputElement && !querying && !(anchor === el && host)) state.rescan()
  if (!(el instanceof HTMLInputElement) || !targetFor(el)) return maybeOpenForms(el, how)
  // While the tab learns its site, the user signs in by hand.
  if (querying || dismissedFor === el || !recentGesture() || learning()) return
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
  // Open already; in a frame, the background opened it in the top page (a rescan mustn't open it again).
  if ((anchor === el && host) || (getFramedFor() === el && how === "focus")) return
  querying = (async () => {
    // In a frame, the background opens the menu in the top page, under where the field shows (see Autofill.query).
    const at = isTop ? undefined : fillable(el) ? visibleBox(el) : null
    if (at === null) return
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
    const onPage = later && !named ? pageAccount(el, box) : undefined
    // A pattern outside what generate.ts reads, or lengths that can't meet: no generated password.
    const rules = generating ? fieldRules(state.targets()) : undefined
    const reply =
      rules === null
        ? null
        : await send<QueryReply>({ type: "db:query", roles, focused: t.role, form: state.form(), kind, rules, explicit, again: how === "again", ...(named ? { identifier: named } : {}), ...(onPage ? { pageAccount: onPage } : {}), ...(at ? { box: at } : {}), ...(asksNewPassword(state.targets()) ? { asksNew: true } : {}) })
    if (!reply?.rows) emptyUntil.set(el, Date.now() + 15_000)
    else if (!isTop) trackFramed(el)
    else if (reply.token && deepActiveElement() === el) openMenu(el, reply.token, reply.rows)
  })().finally(() => (querying = null))
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
    else if (isTop && reply.token && deepActiveElement() === el) openMenu(el, reply.token, reply.rows, "accounts", undefined, true)
  })().finally(() => (querying = null))
}


function onFocusIn(event: FocusEvent) {
  const el = eventTarget(event)
  // Focus moved on from the menu's field, by the user or the page's own
  // script (an identifier-first sign-in focusing the password box it just
  // opened below): the list for the field it left goes, so it never sits
  // over the field the user is about to type into. Not for focus going into
  // the menu itself (↓), or into the frame its field is in.
  if (!isTop && getFramedFor() && el !== getFramedFor()) framedGone(true)
  if (isTop && host && mode === "accounts" && !closing && el !== anchor && !event.composedPath().includes(host) && (anchor ? true : isControl(el))) closeMenu()
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
  const el = eventTarget(event)
  if (!(el instanceof HTMLInputElement)) return
  if (!el.value) {
    quiet.delete(el)
    byHand.delete(formOf(el))
  }
  // In a frame, the menu in the top page can't narrow as the user types: it
  // goes, and stays away while they type (the rescan their typing sets off
  // would otherwise bring the whole list back) until the field is cleared,
  // clicked again, or ↓.
  if (!isTop && el === getFramedFor()) {
    quiet.add(el)
    return framedGone(true)
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
  const target = eventTarget(event)
  lastPointer = target ?? null
  if (!isTop && getFramedFor() && target !== getFramedFor()) framedGone(true)
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
  if (path.includes(host) || path.includes(anchor as EventTarget) || target === anchor) return
  if (mode === "pill") return leave()
  closeMenu()
}

function onKeyDown(event: KeyboardEvent) {
  if (!event.isTrusted) return
  if (mode === "signin" && event.key === "Escape") return closeMenu(false, true)
  lastGestureAt = Date.now()
  lastPointer = null
  const target = eventTarget(event)
  // Enter in a login field goes on with its form (Continue, sign in). The
  // page's next step can open right below it, so a rescan doesn't bring the
  // list back on the field while it still has focus.
  if (event.key === "Enter" && !event.isComposing && target instanceof HTMLInputElement && targetFor(target)) quiet.add(target)
  if (!isTop && event.key === "Escape" && getFramedFor() && target === getFramedFor()) {
    dismissedFor = getFramedFor()
    return framedGone(true, true)
  }
  // Enter in the field goes on with the form (Continue, sign in): the list
  // isn't what the user is answering, and the next step may open under it.
  if (!isTop && event.key === "Enter" && !event.isComposing && getFramedFor() && target === getFramedFor()) return framedGone(true)
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
  // Esc also when the page moved focus off the field onto nothing (Zoom's
  // sign-in leaves it on <body>): the user is still answering this menu.
  // The field isn't focused, so clicking it again is a fresh focus that
  // opens the menu: it isn't marked dismissed.
  // Like Esc in the field, it answers the menu only: the page doesn't also get it.
  if (event.key === "Escape" && mode === "accounts" && (target === document.body || target === document.documentElement)) {
    event.preventDefault()
    event.stopPropagation()
    return closeMenu(false, true)
  }
  if (target !== anchor || mode !== "accounts") return
  if (event.key === "Escape") {
    // Esc answers the menu only, as with the browser's own autofill: the
    // page doesn't also get it, so a sign-in dialog doesn't close with it.
    event.preventDefault()
    event.stopPropagation()
    dismissedFor = anchor
    closeMenu(false, true)
  } else if (event.key === "Enter" && !event.isComposing) {
    // Enter in the field submits its form (Continue, sign in): the list goes
    // with it, not left over the step that opens next.
    closeMenu()
  } else if (event.key === "ArrowDown") {
    event.preventDefault()
    port?.postMessage({ type: "db:menu-enter" })
    frame?.focus()
    frame?.contentWindow?.focus()
  }
}

/** Springs the frame's corners to `radius`, from wherever they are now. */
function roundTo(radius: number) {
  const f = frame
  if (!f) return
  const anim = f.animate([{ borderRadius: getComputedStyle(f).borderRadius }, { borderRadius: `${radius}px` }], { ...timing(MENU_MOTION.frameSize), fill: "forwards" })
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
function onPortMessage(e: MessageEvent<{ type?: unknown; travel?: unknown; count?: unknown; radius?: unknown; version?: unknown; check?: unknown }>) {
  if (e.data?.type === "db:menu-check") {
    const ok = guard.checkPlacement(e.data.version)
    port?.postMessage({ type: "db:menu-checked", check: e.data.check, ok })
    return
  }
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
  guard.tellGeometry()
  if (!reveal) port.postMessage(mode === "save" || mode === "signin" ? { type: "db:reveal", corner: true } : { type: "db:reveal" })
  // Typed before the frame was ready: narrow it now.
  const typed = anchor && mode === "accounts" && anchor.value && typedSinceOpen ? anchor.value : ""
  if (typed) port.postMessage({ type: "db:filter", query: typed.slice(0, 200) })
  win.postMessage({ type: "db:menu-token", token }, event.origin, [channel.port2])
}

/**
 * The top window lost focus. A click into one of the page's own frames (an
 * ad, a captcha, an embedded panel) gives the page no pointerdown, only
 * this: the user is elsewhere, and the account list goes, as for a click in
 * the page. Not for the frame the menu's own field is in (that frame tells
 * the background), nor when focus went into the menu itself.
 */
function onWindowBlur(event: FocusEvent) {
  if (event.target !== window || !host || mode !== "accounts" || closing) return
  const into = document.activeElement
  if (!(into instanceof HTMLIFrameElement || into instanceof HTMLFrameElement)) return
  const r = into.getBoundingClientRect()
  const b = boxNow(anchorBox)
  if (b && r.left <= b.left + 1 && r.top <= b.top + 1 && r.right >= b.right - 1 && r.bottom >= b.bottom - 1) return
  closeMenu()
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
  // Before any page script: see onHostToggle.
  window.addEventListener("beforetoggle", guard.onHostToggle, true)
  window.addEventListener("toggle", guard.onHostToggle, true)
  if (isTop) {
    document.addEventListener("beforetoggle", onBeforeToggle, true)
    addEventListener("resize", guard.onResize, true)
    addEventListener("blur", onWindowBlur)
    document.addEventListener("fullscreenchange", onFullscreen)
    new MutationObserver(onDialogs).observe(document, { subtree: true, attributes: true, attributeFilter: ["open"] })
  }
  window.addEventListener("message", onMenuReady, true)
  document.addEventListener("focusin", onFocusIn, true)
  document.addEventListener("pointerdown", onPointerDown, true)
  document.addEventListener("keydown", onKeyDown, true)
  document.addEventListener("input", onInput, true)
  document.addEventListener("contextmenu", onContextMenu, true)
  window.addEventListener("pointermove", onPointerMove, { capture: true, passive: true })
  if (!isTop) window.addEventListener("scroll", onFrameScroll, { capture: true, passive: true })
  // Leaving the page (or entering the back/forward cache) takes the menu
  // along; coming back is a new visit.
  window.addEventListener("pagehide", () => {
    closeMenu()
    hideRing()
    clearTileTimer()
    dismissedFor = null
    lastGestureAt = 0
    lastPointer = null
    resetFillState()
  })
  // Answering tells the background the message reached a live document.
  chrome.runtime.onMessage.addListener((message: ToContent, _sender, respond) => {
    switch (message?.type) {
      case "db:fill":
        applyFill(fillHost, message).then(respond, () => respond({ filled: [] }))
        return true
      case "db:forms-fill":
        applyFormsFill(fillHost, message).then(respond, () => respond({ filled: [] }))
        return true
      case "db:forms-approve":
        approveForms(formsStateOf(state), message.form, message.kind === "card" ? "card" : "identity", typeof message.section === "string" ? message.section : undefined, message.measure === true, menuHost()).then(respond, () => respond(null))
        return true
      case "db:forms-approved":
        approvedForms(formsStateOf(state), String(message.approval)).then((boxes) => respond(boxes ? { boxes } : null), () => respond(null))
        return true
      case "db:open-at":
        return void respond(openAt(String(message.token), Number(message.rows), message.box, message.mode === "pill" ? "pill" : "accounts", message.captioned === true))
      case "db:move-at":
        return void respond(moveAt(String(message.token), message.box))
      case "db:hold":
        // Only the surface the asker owns. Asked about another, it says
        // whether nothing of Deadbolt's shows, which the measuring needs.
        if (message.token !== token) return void respond(!host)
        if (!message.hold) return void respond(hold(false))
        pillSettled(900).then(() => {
          const ok = hold(true)
          if (!ok || document.hidden) return respond(ok)
          requestAnimationFrame(() => requestAnimationFrame(() => respond(ok)))
        })
        return true
      case "db:generated":
        keptGenerated(String(message.generated))
        return void respond(true)
      case "db:menu-gone":
        framedGone(false)
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
      case "db:signin-offer":
        return void respond(openSignInSurface(String(message.token)))
      case "db:manual-open": {
        // The shortcut goes to every frame: only the one with focus takes it.
        // The context menu's goes to the frame it opened in, about its field.
        if (message.context !== true && !document.hasFocus()) return
        const context = message.context === true && contextTarget && Date.now() - contextTarget.at < CONTEXT_MS ? contextTarget.el : null
        contextTarget = null
        return void respond(manualOpen(context))
      }
      case "db:menu-resumed":
        return void respond(resumed(String(message.token)))
      case "db:point":
        return void respond(pointAtProvider(isTop, String(message.provider), () => closeMenu()))
      case "db:chooser":
        if (isTop) pointAtTile(String(message.account))
        return void respond(true)
      case "db:site-icon":
        if (!isTop) return void respond(null)
        readPageIcon().then(respond, () => respond(null))
        return true
    }
  })
}


/**
 * The menu for a field in a frame below, at `box` in this page (see
 * Autofill.query and Forms.query), or a session step's pill on it (`as`
 * "pill", see Autofill.fill). `captioned` for an identity or card list. Top page only.
 */
function openAt(t: string, rows: number, box: Box, as: "accounts" | "pill", captioned: boolean): boolean {
  if (!isTop || document.hidden || (host && (mode === "save" || as === "pill"))) return false
  if (as === "accounts" && !(Number.isFinite(rows) && rows >= 1)) return false
  if (!box || ![box.left, box.top, box.right, box.bottom].every(Number.isFinite)) return false
  openMenu(null, t, as === "pill" ? 0 : rows, as, box, captioned)
  return true
}

/**
 * The frame's field the open list is for moved inside its frame: it now
 * shows at `box` in this page (see Autofill.menuMove). The list follows it
 * there, and waits its dwell again before it takes a pick, as for any move.
 * Top page only.
 */
function moveAt(t: string, box: Box): boolean {
  if (!isTop || !host || t !== token || mode !== "accounts" || closing || !anchorBox) return false
  if (!box || ![box.left, box.top, box.right, box.bottom].every(Number.isFinite)) return false
  anchorBox = { box, x: scrollX, y: scrollY, frame: frameAround(box) }
  guard.placementChanged()
  return true
}

/**
 * The user asked for the account menu on a field (the fill shortcut, or
 * "Fill with Deadbolt" in its context menu, see bg/doors.ts): it opens on
 * that field (`at`, else the focused one) even where the scan passed over
 * it, with the checks a click gets (the field shows and is on top, see
 * manualFields; in a frame, only of the top page's site, see
 * Autofill.query). The browser's shortcut and context menu are the user's
 * own gesture: a page can make neither, nor send this message.
 */
function manualOpen(at: EventTarget | null): boolean {
  const el = isControl(at) ? at : deepActiveElement()
  if (!(el instanceof HTMLInputElement) || learning() || !state.manual?.(el)) return false
  // The focus's own focusin isn't this ask: it opens nothing on its own.
  if (deepActiveElement() !== el) {
    lastGestureAt = 0
    el.focus({ preventScroll: true })
  }
  lastGestureAt = Date.now()
  dismissedFor = null
  quiet.delete(el)
  byHand.delete(formOf(el))
  emptyUntil.delete(el)
  void maybeOpen(el, "again")
  return true
}

function onContextMenu(event: MouseEvent) {
  if (event.isTrusted) contextTarget = { el: eventTarget(event) ?? null, at: Date.now() }
}

/**
 * The vault unlocked from this open menu, and it now lists the site's
 * logins (bg/unlock.ts): keyboard focus goes into it as for ↓, so the
 * user's next Enter picks its first login rather than submitting the form.
 */
function resumed(t: string): boolean {
  if (!host || t !== token || mode !== "accounts" || closing) return false
  port?.postMessage({ type: "db:menu-enter" })
  frame?.focus()
  frame?.contentWindow?.focus()
  return true
}

/** Called after each page scan: offer the menu on an already-focused field. */
export function refreshMenu(focused: HTMLInputElement) {
  if (!host) void maybeOpen(focused, "focus")
}

