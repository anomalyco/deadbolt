// Stateless DOM, geometry, and messaging helpers for the inline menu host.

import type { Box, ToBackground } from "../../messages"
import { isAccountPage, pageAccountOf } from "../../signin"
import type { FormControl } from "../detect"

/** A row's height: the app's list rows (menu.css .row). */
export const MENU_ROW = 46
/** The list's 6px padding, top and bottom. */
export const MENU_CHROME = 12
/** The caption over an identity or card list: where a pick goes. Login lists have none. */
export const MENU_CAPTION = 22
/** The narrowest the menu gets under a narrow field: an avatar, a title and username. */
export const MENU_MIN_WIDTH = 240
/** The menu's gap to each side of the viewport. */
export const MENU_MARGIN = 4
/** The account list's gap to its field. */
export const MENU_GAP = 6
/** The save offer's place: the top right corner, near the toolbar button. */
export const SAVE_INSET = 12
/** The offer's compact pill, before its frame says its size. */
export const SAVE_GUESS = { width: 220, height: 36 }
export const RADIUS = 12
const light = () => !matchMedia("(prefers-color-scheme: dark)").matches
/** Rune's floating elevation (theme.json v2-elevation-floating), as the app's quick panel: a hairline and two soft layers. */
export const SHADOW = () =>
  light()
    ? "0 0 0 0.5px #0000001f, 0 4px 8px #00000014, 0 8px 16px #0000000a"
    : "0 0 0 0.5px #ffffff29, 0 -0.5px 0 #ffffff0f, 0 4px 8px #0000004d, 0 8px 16px #0000004d"
/** How many times one menu goes back on top of the top layer before it gives up and closes. */
export const MAX_RAISES = 3
/** Where the menu checks that a click there would land on it, as fractions of its box. */
export const SAMPLES = [
  [0.5, 0.5],
  [0.08, 0.12],
  [0.92, 0.12],
  [0.08, 0.88],
  [0.92, 0.88],
]
export const SAVE_LOAD_MS = 3000
export const SAVE_CAP_MS = 60_000
/** The largest a pill can be. */
export const PILL_MAX = { width: 260, height: 32 }
/** A frame that never says its size grows in anyway after this long. */
export const REVEAL_LATEST_MS = 500
export const GESTURE_WINDOW_MS = 1000
export const GONE_COUNTS_MS = 2000

export interface Rect {
  left: number
  top: number
  width: number
  height: number
}

export interface AnchorBox {
  box: Box
  x: number
  y: number
  frame: { el: Element; left: number; top: number } | null
}

export const formOf = (el: FormControl): Node => el.form ?? el.closest("form") ?? el.getRootNode()
export const isControl = (el: unknown): el is FormControl =>
  el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement

export function send<T>(message: ToBackground): Promise<T | null> {
  try {
    return chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>
  } catch {
    // The extension was reloaded; this page's script is orphaned.
    return Promise.resolve(null)
  }
}

/** Where a frame's field is in this page now (see anchorBox). */
export function boxNow(anchorBox: AnchorBox | null): DOMRect | null {
  if (!anchorBox) return null
  const { box, x, y, frame } = anchorBox
  let dx = x - scrollX
  let dy = y - scrollY
  if (frame) {
    // The frame is gone: so is the field.
    if (!frame.el.isConnected) return null
    const f = frame.el.getBoundingClientRect()
    dx = f.left - frame.left
    dy = f.top - frame.top
  }
  return new DOMRect(box.left + dx, box.top + dy, box.right - box.left, box.bottom - box.top)
}

/**
 * The frame element of this page a frame's field at `box` shows in: the
 * smallest one around it. Not one in a shadow root; then the menu follows
 * the page's scrolling only.
 */
export function frameAround(box: Box): { el: Element; left: number; top: number } | null {
  let best: { el: Element; left: number; top: number } | null = null
  let area = Infinity
  for (const el of Array.from(document.querySelectorAll("iframe, frame"))) {
    const r = el.getBoundingClientRect()
    if (r.left > box.left + 1 || r.top > box.top + 1 || r.right < box.right - 1 || r.bottom < box.bottom - 1 || r.width * r.height >= area) continue
    area = r.width * r.height
    best = { el, left: r.left, top: r.top }
  }
  return best
}

/** Which side of its field the account list is on. */
export type MenuSide = "above" | "below"

/**
 * Where the account list of `height` goes over field `r` in a viewport
 * `viewport` tall: its side, and its top. A login field's list goes above
 * it whenever it fits there (`above`), `MENU_GAP` over the field's top:
 * the browser's own autofill list for that field opens below it, and a page
 * can't cover that list, so the two never overlap. Near the top of the
 * viewport, and for any other list, it goes below, else above anyway.
 *
 * `was`, the side it's on already, keeps it there while it still fits, so a
 * list that grows (`db:menu-resize`) grows away from its field with its
 * near edge pinned, rather than jumping across the field.
 *
 * `others`: the form's other fields under the list's width. Above never
 * covers one of them (a password box's list would sit on the username box
 * over it, taking the click meant for it); then it goes below.
 */
export function menuPlace(
  r: { top: number; bottom: number },
  height: number,
  viewport: number,
  above: boolean,
  was: MenuSide | null = null,
  others: Array<{ top: number; bottom: number }> = [],
): { side: MenuSide; top: number } {
  const aboveTop = r.top - height - MENU_GAP
  const fitsAbove = r.top >= height + MENU_MARGIN + MENU_GAP && !others.some((o) => o.bottom > aboveTop && o.top < r.top)
  const fitsBelow = r.bottom + MENU_GAP + height < viewport
  const side: MenuSide = was === "above" && fitsAbove ? "above" : was === "below" && fitsBelow ? "below" : above && fitsAbove ? "above" : fitsBelow ? "below" : "above"
  return { side, top: side === "above" ? Math.max(MENU_MARGIN, r.top - height - MENU_GAP) : r.bottom + MENU_GAP }
}

/** A random valid custom-element name, such as `kqzvt-hmwbe`. */
export function hostTag(): string {
  const letters = () => Array.from(crypto.getRandomValues(new Uint8Array(5)), (b) => String.fromCharCode(97 + (b % 26))).join("")
  return `${letters()}-${letters()}`
}

/** Inline declarations a page's stylesheets can't override. */
export const important = (css: Record<string, string>) =>
  Object.entries(css)
    .map(([k, v]) => `${k}:${v} !important`)
    .join(";")

/** `node` is `ancestor` or inside it, across shadow roots. */
export function within(node: Node | null, ancestor: Node): boolean {
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
export function modalAround(el: Element): Element | ShadowRoot | null {
  let from: Node | null = null
  for (let n: Node | null = el; n; from = n, n = n.parentNode ?? (n instanceof ShadowRoot ? n.host : null))
    if (n instanceof Element && n.matches(":modal, :fullscreen")) return from instanceof ShadowRoot ? from : n
  return null
}

/**
 * Whether something other than the menu would take a click on it. Only
 * things in the top layer can be over it; ones that let clicks through don't
 * show here, but the menu's own visibility readings see them.
 */
export function covered(el: HTMLElement): boolean {
  const root = el.getRootNode() as Document | ShadowRoot
  const r = el.getBoundingClientRect()
  return SAMPLES.some(([fx, fy]) => {
    const hit = root.elementFromPoint?.(r.left + r.width * fx, r.top + r.height * fy)
    return !!hit && hit !== el
  })
}

/**
 * The save offer's place: the top right corner, 12 px in, whatever its size.
 * It grows from there, down and to the left, as it opens.
 */
export function corner(width: number, height: number): Rect {
  return { left: Math.max(4, innerWidth - width - SAVE_INSET), top: SAVE_INSET, width, height }
}

/**
 * The zoom that undoes the CSS zoom in effect where `el` is mounted (the
 * product of the page's zooms above it, read each frame), or 1 when that
 * can't be read or its inverse isn't a finite number.
 */
export function unzoom(el: Element): number {
  const parent = el.parentNode instanceof ShadowRoot ? el.parentNode.host : el.parentElement
  const zoom = (parent as (Element & { currentCSSZoom?: number }) | null)?.currentCSSZoom
  if (typeof zoom !== "number" || !(zoom > 0)) return 1
  const inverse = 1 / zoom
  return Number.isFinite(inverse) && inverse > 0 ? inverse : 1
}

export function frameStyle(radius: number) {
  return `all:initial;position:relative;width:100%;height:100%;border:0;border-radius:${radius}px;box-shadow:${SHADOW()};background:transparent;color-scheme:normal;`
}

/**
 * The account a provider's own password step shows, on a provider host whose
 * page-set account is trusted (see isAccountPage): its visible account chip,
 * else the hidden username box beside the field, else the form's own
 * username box (`box`) the page filled in itself. Google's: a chip with
 * `data-profile-identifier`, and `<input name="identifier" id="hiddenEmail">`
 * in the same `<main>` as the password field (the page has no `<form>`).
 * Apple's (idmsa.apple.com): the account box stays above the password box,
 * holding the Apple Account it remembered.
 */
export function pageAccount(field: HTMLInputElement, box?: HTMLInputElement): string | undefined {
  if (!isAccountPage(location.href)) return undefined
  const chip = [...document.querySelectorAll("[data-profile-identifier]")].find((c) => c.getClientRects().length > 0)
  const shown = pageAccountOf(chip?.textContent?.slice(0, 501))
  if (shown) return shown
  const hidden = (field.closest("main") ?? document).querySelector<HTMLInputElement>('input[name="identifier"], input#hiddenEmail')
  return pageAccountOf(hidden?.value) ?? pageAccountOf(box?.value.slice(0, 501))
}
