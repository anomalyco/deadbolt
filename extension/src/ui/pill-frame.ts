// The pill keeping its place on the page while the frame springs around it
// (menu.ts fold). The content script hands over its springs for the frame
// (db:fold), and the pill, what fades, what travels into it and its check all
// step on them, on one clock with the frame and on its pixel grid.

import { devicePx, inFrame, MENU_MOTION, Spring, timing, type SpringState } from "./motion"

/**
 * The host's springs as the content script last handed them over (see
 * db:fold): how far the frame still is from the pill's place on the page.
 * The pill is laid out at that place from the first frame and stays there
 * while the frame contracts onto it, so it never rides along with the frame.
 */
export type Edge = "left" | "top" | "width" | "height"
export const host = { springs: null as Record<Edge, Spring> | null, width: 0, raf: 0, waiters: [] as Array<{ width: number | null; go: () => void }> }

/**
 * What the fold moves on the host's springs, so it keeps one clock with the
 * frame. What fades stays where it was across the page while the frame closes
 * over it, riding only its rise; what travels into the pill
 * goes the same share of its way as the frame has, so the frame's edge never
 * passes it; and the label fades in once the frame's edges are clear of it.
 */
export const folding = {
  fading: [] as HTMLElement[],
  travellers: [] as Array<{ el: HTMLElement; dx: number; dy: number; scale: number }>,
  label: null as HTMLElement | null,
  /** The frame's offsets when what fades was last pinned, and how far it had been moved back by then (across: up, it rides the frame). */
  pin: null as { left: number; x: number } | null,
  /** The frame's longest way still to go when the travel last began. */
  edge: "left" as Edge,
  from: 0,
}

/** How much of the way the frame has come since the travel last began, 0 to 1. */
function foldProgress(s: Record<Edge, Spring>): number {
  if (Math.abs(folding.from) < 1) return 1
  return Math.min(1, Math.max(0, 1 - s[folding.edge].value / folding.from))
}

function stepFold(s: Record<Edge, Spring>, moving: boolean) {
  const pin = folding.pin
  if (pin) {
    // Across, it stays put (riding the frame's left edge would slide it sideways);
    // up, it rides the frame's top as it goes.
    const x = pin.x + pin.left - s.left.value
    for (const el of folding.fading) el.style.translate = `${x}px 0`
  }
  const rest = moving ? 1 - foldProgress(s) : 0
  for (const t of folding.travellers) t.el.style.transform = rest > 0 ? `translate(${t.dx * rest}px, ${t.dy * rest}px) scale(${1 + (t.scale - 1) * rest})` : ""
  if (!moving) folding.travellers = []
  // Fit before fading: the label comes in once the frame's edges are clear of it.
  const label = folding.label
  if (!label) return
  const r = label.getBoundingClientRect()
  const fits = r.left >= -1 && r.top >= -1 && r.right <= innerWidth + 1 && r.bottom <= innerHeight + 1
  if (moving && !fits) return void (label.style.opacity = "0")
  folding.label = null
  label.style.opacity = ""
  label.animate([{ opacity: 0, filter: "blur(3px)", transform: "scale(0.96)" }, { opacity: 1, filter: "none", transform: "none" }], timing(MENU_MOTION.pillLabel))
}

/** The pill's frame at rest (inline.ts targetRect), and the pill itself (menu.css .pill). */
export const PILL_HEIGHT = 32
/** The check (menu.css .pill-mark): its width, its pull-in while closed, and the room it takes open (its 14px, the gap, less its pull-in). */
const MARK_WIDTH = 14
const MARK_PULL = -8
export const MARK_ROOM = 20
/**
 * What moves with the frame besides the pill's place: the check opening
 * (till the frame stops), and a pill shrinking into its circle (menu.ts toCircle).
 */
export const riding = { opening: null as HTMLElement | null, closingUp: null as HTMLElement | null }

export function placePill() {
  const pill = document.querySelector<HTMLElement>(".pill")
  const s = host.springs
  if (!pill) return
  // The frame is the pill's place plus these offsets: undo them, anchored at the right
  // (pills grow leftward from the end of the field, and from the top right of the page).
  // On the pixel grid, as the host's box is (inline.ts position), so the two cancel exactly.
  // The middle is the pill's own (32 px tall at rest), not innerHeight's, which the browser rounds.
  const ox = s ? devicePx(s.left.value) : 0
  const oy = s ? devicePx(s.top.value) : 0
  const ow = s ? devicePx(s.width.value) : 0
  pill.style.right = `${ox + ow}px`
  pill.style.top = `${PILL_HEIGHT / 2 - oy}px`
  const moving = !!s && !(s.left.done && s.top.done && s.width.done && s.height.done)
  // A check opening takes exactly the room the frame has gained so far, so the
  // tile stays at the frame's left edge, on the frame's own clock.
  const opening = riding.opening
  if (opening) {
    const k = Math.min(1, Math.max(0, 1 + ow / MARK_ROOM))
    opening.style.width = `${MARK_WIDTH * k}px`
    opening.style.marginLeft = `${MARK_PULL + (MARK_ROOM - MARK_WIDTH) * k}px`
    if (!moving) {
      opening.style.width = ""
      opening.style.marginLeft = ""
      riding.opening = null
    }
  }
  // Shrinking into its circle, the pill is exactly as wide as the frame is now.
  if (riding.closingUp?.isConnected) riding.closingUp.style.width = `${PILL_HEIGHT + Math.max(0, ow)}px`

  if (s) stepFold(s, moving)
  // One loop, however often this is called directly.
  if (moving && !host.raf)
    host.raf = requestAnimationFrame((time) => {
      host.raf = 0
      inFrame(time, placePill)
    })
}

/** The content script's springs for the frame, as it starts or changes the fold. */
export function onFold(data: { width?: unknown; at?: unknown; springs?: Record<string, SpringState> }) {
  if (typeof data.at !== "number" || !data.springs) return
  const resume = (k: Edge) => Spring.resume(data.springs![k], data.at as number)
  const old = host.springs
  const next = { left: resume("left"), top: resume("top"), width: resume("width"), height: resume("height") }
  // Carry on from where everything is now: what travels keeps what it has
  // left of its way, and what fades keeps its place on the page.
  if (old) {
    const rest = 1 - foldProgress(old)
    for (const t of folding.travellers) Object.assign(t, { dx: t.dx * rest, dy: t.dy * rest, scale: 1 + (t.scale - 1) * rest })
  }
  const pin = folding.pin
  folding.pin = {
    left: next.left.value,
    x: pin && old ? pin.x + pin.left - old.left.value : 0,
  }
  folding.edge = (["left", "top", "width", "height"] as const).reduce((a, k) => (Math.abs(next[k].value) > Math.abs(next[a].value) ? k : a))
  folding.from = next[folding.edge].value
  host.springs = next
  host.width = typeof data.width === "number" ? data.width : host.width
  placePill()
  // Whatever waited for the frame to take this width goes now (see whenWide).
  const ready = host.waiters.filter((w) => w.width === null || Math.abs(w.width - host.width) < 2)
  host.waiters = host.waiters.filter((w) => !ready.includes(w))
  for (const w of ready) w.go()
}

/**
 * Runs `go` once the content script has started the frame toward `width`
 * (null: toward the pill at all), or after a moment, whatever happens.
 */
export function whenWide(width: number | null, go: () => void) {
  let ran = false
  const once = () => {
    if (ran) return
    ran = true
    go()
  }
  host.waiters.push({ width, go: once })
  setTimeout(once, 150)
}
