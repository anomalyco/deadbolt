// The panel's padlock, drawn as a real one works. Its shackle has a long leg
// that runs down into the body and a short one whose foot sits in a hole in
// the body's top. To open, the shackle slides straight up: the long leg
// slides out of the body (never clear of it) and the short foot comes free.
// It never tilts in the plane of the screen: a shackle doesn't bend. Once up,
// it can turn on its long leg, out of the screen, as a real one does.
//
// The shackle is an <svg> of its own, behind a window that ends at the body's
// top edge: what's below that edge is inside the body and doesn't show. (An
// HTML-level element, because a turn out of the screen is a 3D transform,
// which SVG's own children don't take.) Everything is in the glyph's 24-unit
// box, so the panel's lock and the inline menu's small one are one glyph and
// one set of keyframes; one animation writes the shackle's transform.

import { reducedMotion } from "./motion"

/** The body's top edge, in the 24-unit box: the shackle's window ends here. */
const TOP = 13
/** The long leg, as a share of the box's width: what the shackle turns on. */
const HINGE = ((15.8 / 24) * 100).toFixed(3)
/** How far the shackle rises to open, in units: the short foot ends 2.3 units clear of the body, the long leg 1 unit still in it. */
export const RISE = 5
/** Units up, as the shackle's transform takes them (a share of its own height). */
const up = (units: number) => `translateY(${((-units / 24) * 100).toFixed(3)}%)`
const pose = (units: number, turn = 0) => `${up(units)} rotateY(${turn}deg)`
/** Up, and turned on the long leg with the short one gone round behind: where "turn" rests. */
const TURNED = -48

/**
 * A closed padlock, `size` px square, to stand where an icon would: the
 * panel's disc (36) and the inline menu's locked row (14) draw the same one.
 * Its layout is set here, on the elements, so the two can't drift apart: the
 * shackle's window starts a third of the box above it (room to rise) and
 * ends at the body's top edge, and gives the turn on the long leg its depth.
 * Small, its line is a touch heavier and it has no keyhole (a speck at that
 * size).
 */
export function padlock(size = 36): HTMLElement {
  const small = size < 24
  const line = `fill="none" stroke="currentColor" stroke-width="${small ? 1.8 : 1.5}" stroke-linecap="round" aria-hidden="true"`
  const room = size / 3
  const svg = `position:absolute;left:0;width:${size}px;height:${size}px;overflow:visible`
  const lock = document.createElement("span")
  lock.className = "padlock"
  lock.setAttribute("aria-hidden", "true")
  // A little above centre: closed, the lock sits low in its box (its middle is 1.8 units under the box's) to leave the shackle room to rise.
  lock.style.cssText = `position:relative;display:block;width:${size}px;height:${size}px;margin-top:${((-1.8 / 24) * size).toFixed(2)}px`
  lock.innerHTML =
    `<span class="padlock-window" style="position:absolute;left:0;right:0;top:${-room}px;height:${room + (TOP / 24) * size}px;overflow:hidden;perspective:${size * 2.5}px;perspective-origin:${HINGE}% 40%">` +
    `<svg class="padlock-shackle" viewBox="0 0 24 24" ${line} style="${svg};top:${room}px;transform-origin:${HINGE}% 50%"><path d="M8.2 14.2v-3.8a3.8 3.8 0 0 1 7.6 0V19"/></svg></span>` +
    `<svg class="padlock-body" viewBox="0 0 24 24" ${line} style="${svg};top:0"><rect x="5" y="${TOP}" width="14" height="8" rx="2"/>${small ? "" : `<circle cx="12" cy="16.3" r="1.1" fill="currentColor" stroke="none"/><path d="M12 17v1.4"/>`}</svg>`
  return lock
}

const shackleOf = (lock: Element) => lock.querySelector<SVGSVGElement>(".padlock-shackle")

/** Open already, with nothing moving (reduced motion: the open lock fades in whole). */
export function setOpen(lock: Element, turn: boolean) {
  const s = shackleOf(lock)
  if (s) s.style.transform = pose(RISE, turn ? TURNED : 0)
}

/**
 * The shackle opens, starting after `delay` ms: pushed in a touch, then
 * straight up past where it rests and back onto it. With `turn` it then turns
 * on its long leg, the short one going round behind. Returns how long until
 * the short foot is clear of the body, in ms.
 */
export function slideOpen(lock: Element, turn: boolean, delay = 0): number {
  const s = shackleOf(lock)
  if (!s || typeof s.animate !== "function") return 0
  if (reducedMotion()) {
    setOpen(lock, turn)
    return 0
  }
  const rise = [
    { transform: pose(0), easing: "ease-out" },
    { transform: pose(-0.9), easing: "cubic-bezier(0.3, 0, 0.2, 1)" },
    { transform: pose(RISE + 0.55), easing: "ease-in-out" },
    { transform: pose(RISE - 0.12), easing: "ease-in-out" },
    { transform: pose(RISE) },
  ]
  if (!turn) {
    const at = [0, 0.16, 0.6, 0.82, 1]
    s.animate(rise.map((k, i) => ({ ...k, offset: at[i] })), { duration: 520, delay, fill: "both" })
    return delay + 230
  }
  const at = [0, 0.1, 0.38, 0.5, 0.56]
  s.animate(
    [
      ...rise.map((k, i) => ({ ...k, offset: at[i], ...(i === 4 ? { easing: "cubic-bezier(0.3, 0, 0.2, 1)" } : {}) })),
      { transform: pose(RISE, TURNED - 8), offset: 0.86, easing: "ease-in-out" },
      { transform: pose(RISE, TURNED) },
    ],
    { duration: 780, delay, fill: "both" },
  )
  return delay + 210
}

/** A wrong passphrase: the shackle is pulled and holds. Up a fraction and caught, twice, dying away; the short foot never leaves its hole. */
export function tug(lock: Element) {
  const s = shackleOf(lock)
  if (!s || reducedMotion() || typeof s.animate !== "function") return
  s.animate(
    [
      { transform: pose(0), easing: "cubic-bezier(0.2, 0.7, 0.3, 1)" },
      { transform: pose(1), offset: 0.2, easing: "ease-in" },
      { transform: pose(0), offset: 0.4, easing: "cubic-bezier(0.2, 0.7, 0.3, 1)" },
      { transform: pose(0.55), offset: 0.58, easing: "ease-in" },
      { transform: pose(0), offset: 0.76, easing: "ease-out" },
      { transform: pose(0.15), offset: 0.88, easing: "ease-in" },
      { transform: pose(0) },
    ],
    { duration: 440 },
  )
}
