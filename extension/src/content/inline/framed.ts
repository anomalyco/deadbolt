// Framed-field tracking and provider/chooser ring helpers for the inline menu.

import { provider } from "../../signin"
import { findAccountTile, findProviderButton } from "../detect"
import { visibleBox } from "../fill"
import { showRing } from "../ring"
import { send, type Rect } from "./dom"

/** In a frame: the field the background last opened the menu for in the top page, which can't see the frame's events (see db:menu-away). */
let framedFor: Element | null = null
/** Where that field was in this frame's viewport, and how big: the menu follows it when that changes (see onFrameScroll). */
let framedAt: Rect | null = null
/** A new box for that field is on its way to the top page (see onFrameScroll). */
let framedMoving = false
/** Which menu for a field here that is: a move's answer for an earlier one says nothing of the one open now. */
let framedSeq = 0
let framedRaf = 0

export function getFramedFor(): Element | null {
  return framedFor
}

export function trackFramed(el: Element) {
  framedFor = el
  const r = el.getBoundingClientRect()
  framedAt = { left: r.left, top: r.top, width: r.width, height: r.height }
  framedMoving = false
  framedSeq++
  watchFramed()
}

/** In a frame: the menu the background opened in the top page for one of its fields goes (or went), with `tell`, by the user's doing here. */
export function framedGone(tell: boolean, dismissed = false) {
  if (!framedFor) return
  framedFor = framedAt = null
  if (tell) void send({ type: "db:menu-away", ...(dismissed ? { dismissed } : {}) })
}

/**
 * In a frame: a scroll, or the frame's own layout changing (it was resized,
 * a hint came in above the field, the box around it opened), that moved the
 * field the menu is for in this frame, or changed its size. The top page
 * can't see that, so the frame says where the field shows now, one move at
 * a time; the background checks it through every frame above, and the menu
 * follows it there or goes (see Autofill.menuMove).
 */
export function onFrameScroll() {
  if (!framedFor || !framedAt || framedMoving) return
  const el = framedFor
  const r = el.getBoundingClientRect()
  const at = { left: r.left, top: r.top, width: r.width, height: r.height }
  if ((["left", "top", "width", "height"] as const).every((k) => Math.abs(at[k] - framedAt![k]) <= 2)) return
  const box = visibleBox(el)
  if (!box) return framedGone(true)
  framedMoving = true
  const seq = framedSeq
  void send<boolean>({ type: "db:menu-move", box }).then((moved) => {
    if (seq !== framedSeq) return
    framedMoving = false
    if (framedFor !== el) return
    if (moved === true) framedAt = at
    // The background closed it already.
    else framedGone(false)
  })
}

/** In a frame: checks every frame, for as long as the top page's menu is for a field here, that the field hasn't moved (see onFrameScroll). */
function watchFramed() {
  cancelAnimationFrame(framedRaf)
  const tick = () => {
    onFrameScroll()
    if (framedFor) framedRaf = requestAnimationFrame(tick)
  }
  framedRaf = requestAnimationFrame(tick)
}

/**
 * "Sign in with <provider>": ring the site's own button for it, if one
 * shows, and say whether it did. The user clicks it; Deadbolt doesn't.
 */
export function pointAtProvider(isTop: boolean, id: string, closeMenu: () => void): boolean {
  if (!isTop) return false
  const p = provider(id)
  const button = findProviderButton(p)
  if (!button) return false
  closeMenu()
  showRing(button, `Your ${p.name} sign-in`)
  return true
}

let tileTimer: ReturnType<typeof setInterval> | undefined

export function clearTileTimer() {
  clearInterval(tileTimer)
}

/**
 * On the provider's account chooser: ring the tile for the linked account
 * once it shows (choosers draw late), with a pill that names no one (the
 * page shows the account itself). The user picks it.
 */
export function pointAtTile(account: string) {
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
