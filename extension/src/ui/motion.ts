// Motion for the extension's own pages and the in-page surface, after
// Anomaly's UI rules: springs given as duration / bounce with bounce 0, that
// retarget from where they are instead of restarting, and a short fade in
// place of travel when the system asks for reduced motion.
//
// Two forms of the same spring: `springEasing` is a CSS linear() curve for
// WAAPI (element.animate), and `Spring` is a numeric value stepped every
// frame, for geometry that follows a moving target and carries its speed
// when the target changes.

/** ω for a spring that settles in `duration` seconds (Kit's: ω = 2π / duration, ζ = 1 − bounce). */
const omega = (duration: number) => (2 * Math.PI) / duration

/** How far a critically damped spring has gone at time t (0 → 1). */
const progress = (w: number, t: number) => 1 - (1 + w * t) * Math.exp(-w * t)

/**
 * A spring as WAAPI timing: a linear() easing sampled from the spring's
 * curve and how long to run it. The curve runs a little past `duration`, so
 * the last step that snaps to 1 is too small to see.
 */
export function spring(duration: number, bounce = 0): { easing: string; duration: number } {
  void bounce // product UI uses bounce 0; the curve below is the critically damped one.
  const w = omega(duration)
  const total = duration * 1.15
  const points: string[] = []
  const steps = 24
  for (let i = 0; i <= steps; i++) {
    const t = (total * i) / steps
    points.push((i === steps ? 1 : progress(w, t)).toFixed(4))
  }
  return { easing: `linear(${points.join(", ")})`, duration: Math.round(total * 1000) }
}

/**
 * The inline menu's springs, in seconds (bounce 0), by what moves: the list
 * (menu.ts) and the frame around it (content/inline.ts). Labels roll as
 * everywhere else (rollLabel). What the user moves, the highlight under a key
 * or the pointer, moves at once and isn't here.
 */
export const MENU_MOTION = {
  /** The list growing in under its field. */
  open: 0.25,
  /** The save offer and the corner offer sliding in from the corner. */
  openCorner: 0.4,
  /** Rows sliding into the gap a row left as the list narrows, and the highlight riding on its row. */
  reflow: 0.4,
  /** A row that stops matching fading where it is. */
  rowOut: 0.25,
  /** A row that matches again coming back. */
  rowIn: 0.3,
  /** What doesn't go into the pill fading where it is, as the list folds. */
  foldOut: 0.25,
  /** The picked row's avatar (or the Save label) travelling into the pill, when the frame's springs never came (it goes with them otherwise). */
  foldIn: 0.38,
  /** The pill's label fading in. */
  pillLabel: 0.3,
  /** The ring round a picked avatar coming in, its comet's tail growing as it turns (ui/ring.ts). */
  ringIn: 0.45,
  /** The ring going when the fill doesn't land: the tail draws back into the head as it fades. */
  ringOut: 0.3,
  /** The tile's ground flashing green and cooling as the ring closes. */
  ringFlash: 0.9,
  /** The frame springing to a new mode's place, size and corners. */
  frameMode: 0.38,
  /** The frame springing to a new size in the same mode, and the offer's corners. */
  frameSize: 0.37,
  /** The surface going, in place. */
  leave: 0.25,
  /** A saved login's surface going toward the toolbar button. */
  leaveTravel: 0.5,
}

/** The fade that stands in for travel, scale and blur when motion is reduced. */
export const REDUCED_FADE = { easing: "ease-out", duration: 180 }

export const reducedMotion = () => typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches

/** Timing for a spring, or the reduced fade. */
export const timing = (duration: number): { easing: string; duration: number } => (reducedMotion() ? REDUCED_FADE : spring(duration))

/**
 * Animates `el` to `to` from wherever it is now: running animations are
 * read where they are (computed style), committed, and cancelled, so a
 * reversal carries on from the current state rather than jumping back. With
 * reduced motion only opacity moves; other properties land at once.
 */
export function animateTo(el: HTMLElement, to: Keyframe, duration: number, options: { from?: Keyframe; fill?: boolean } = {}): Animation | null {
  if (typeof el.animate !== "function") {
    Object.assign(el.style, to)
    return null
  }
  const reduced = reducedMotion()
  const props = Object.keys(to).filter((k) => k !== "offset" && k !== "easing" && k !== "composite")
  const style = getComputedStyle(el)
  const from: Keyframe = {}
  for (const p of props) from[p] = options.from?.[p] ?? (style as unknown as Record<string, string>)[p]
  for (const a of el.getAnimations()) {
    a.commitStyles?.()
    a.cancel()
  }
  const target: Keyframe = { ...to }
  if (reduced) {
    for (const p of props) {
      if (p === "opacity") continue
      ;(el.style as unknown as Record<string, unknown>)[p] = to[p]
      delete from[p]
      delete target[p]
    }
    if (!("opacity" in target)) return null
  }
  const anim = el.animate([from, target], { ...timing(duration), fill: "forwards" })
  // Land on the final style and let go of the animation, so nothing is left
  // transformed or translucent (the visibility guard refuses both).
  anim.finished.then(
    () => {
      Object.assign(el.style, options.fill === false ? {} : stringify(target))
      anim.cancel()
    },
    () => {},
  )
  return anim
}

const stringify = (k: Keyframe) => Object.fromEntries(Object.entries(k).map(([p, v]) => [p, String(v)]))

export interface SpringState {
  x: number
  v: number
  w: number
}

/** The frame being drawn, in ms since the epoch, while inFrame runs. */
let drawing: number | null = null

/**
 * Milliseconds since the epoch, comparable between documents. Inside
 * inFrame it's the frame's own instant, so two documents that move one
 * picture between them (the host and the pill inside it) read their springs
 * at the same moment, not whenever each one's turn in the frame came: off
 * by a millisecond, a fast fold put the pill a pixel either way, a jiggle.
 */
export const epochNow = () => drawing ?? performance.timeOrigin + performance.now()

/**
 * `v` CSS pixels, on the screen's pixel grid. The host's box and the pill's
 * offset inside it are both put on it, so the frame's edge (which the
 * browser snaps to whole device pixels anyway) and the pill's counter-move
 * cancel exactly, instead of each rounding its own way.
 */
export const devicePx = (v: number) => Math.round(v * devicePixelRatio) / devicePixelRatio

type Edges<T> = { left: T; top: T; width: T; height: T }
/** `box` moved by springs `by`, its edges and the offsets alike on the pixel grid (content/inline.ts position), so a pill (ui/pill-frame.ts placePill) can undo the same numbers. */
export function gridBox(box: Edges<number>, by: Edges<{ value: number }>): Edges<number> {
  const left = devicePx(box.left)
  const top = devicePx(box.top)
  return {
    left: left + devicePx(by.left.value),
    top: top + devicePx(by.top.value),
    width: Math.max(1, devicePx(box.left + box.width) - left + devicePx(by.width.value)),
    height: Math.max(1, devicePx(box.top + box.height) - top + devicePx(by.height.value)),
  }
}

/** Runs `go` for the frame at `time` (a requestAnimationFrame time), reading epochNow as that frame's instant. */
export function inFrame(time: number, go: () => void) {
  drawing = performance.timeOrigin + time
  try {
    go()
  } finally {
    drawing = null
  }
}

/**
 * A number that springs toward a target, stepped once per frame. Changing
 * the target mid-flight keeps the current value and speed (critically damped:
 * x(t) = (x₀ + (v₀ + ωx₀)t)·e^(−ωt), with x the distance to the target).
 */
export class Spring {
  private x0 = 0
  private v0 = 0
  private start = 0
  private w: number
  target: number

  constructor(
    value: number,
    duration = 0.3,
    private now: () => number = () => performance.now(),
  ) {
    this.target = value
    this.w = omega(duration)
  }

  /** Where it is now, and how fast it's going (units per second). */
  private state(): { x: number; v: number } {
    const t = (this.now() - this.start) / 1000
    const b = this.v0 + this.w * this.x0
    const e = Math.exp(-this.w * t)
    return { x: (this.x0 + b * t) * e, v: (b - this.w * (this.x0 + b * t)) * e }
  }

  get value(): number {
    return this.target + this.state().x
  }

  get done(): boolean {
    const { x, v } = this.state()
    return Math.abs(x) < 0.25 && Math.abs(v) < 2
  }

  /** Spring to `target` from where it is now, keeping its speed. `duration` changes how quickly. */
  to(target: number, duration?: number) {
    const { x, v } = this.state()
    const current = this.target + x
    if (duration) this.w = omega(duration)
    if (reducedMotion()) return this.jump(target)
    this.target = target
    this.x0 = current - target
    this.v0 = v
    this.start = this.now()
  }

  /** Move the value by `by` at once, keeping its speed, and spring from there. */
  shift(by: number, duration?: number) {
    if (reducedMotion()) return this.jump(this.target)
    const { x, v } = this.state()
    if (duration) this.w = omega(duration)
    this.x0 = x + by
    this.v0 = v
    this.start = this.now()
  }

  /** Where it is now relative to its target, its speed, and its ω: enough for another document to carry on the same motion. */
  snapshot(): SpringState {
    const { x, v } = this.state()
    return { x, v, w: this.w }
  }

  /**
   * The same motion, from a snapshot another document took at `at` (ms since
   * the epoch), stepped by this document's clock: the surface frame follows
   * the host's springs without a message per frame.
   */
  static resume(state: SpringState, at: number, clock: () => number = epochNow): Spring {
    const s = new Spring(0, 1, clock)
    s.x0 = state.x
    s.v0 = state.v
    s.w = state.w
    s.start = at
    return s
  }

  /** Land on `value` now, at rest. */
  jump(value: number) {
    this.target = value
    this.x0 = 0
    this.v0 = 0
    this.start = this.now()
  }
}

/** How long a shrinking label's width waits for its old word to start going (rollLabel). */
export const SHRINK_WAITS_MS = 120

/**
 * Rolls a label to new text: the letters both words start with stay still
 * and only the rest rolls up, while the label's width springs ahead of the
 * roll. `el` holds the label and nothing else. Returns how much wider the
 * label ends up, for a container that sizes itself around it.
 */
export function rollLabel(el: HTMLElement, text: string): number {
  const current = el.dataset.text ?? el.textContent ?? ""
  if (current === text) return 0
  el.dataset.text = text
  if (reducedMotion() || typeof el.animate !== "function" || !el.isConnected) {
    el.replaceChildren(rollParts(text, "", ""))
    if (el.isConnected && typeof el.animate === "function") el.animate([{ opacity: 0.2 }, { opacity: 1 }], REDUCED_FADE)
    return 0
  }
  let same = 0
  while (same < current.length && same < text.length && current[same] === text[same]) same++
  // Roll whole words when they share only a letter or two.
  if (same < 3) same = 0
  const before = el.getBoundingClientRect().width
  // A roll still under way: carry on from its current width, measured above.
  for (const a of el.getAnimations()) a.cancel()
  el.style.width = ""
  const old = current.slice(same)
  el.replaceChildren(rollParts(text, old, text.slice(same), same))
  const after = el.getBoundingClientRect().width
  // Width leads a growing label: a slightly shorter spring than the roll. A
  // shrinking one waits a beat, so the old word lifts and fades before its
  // end is cut at the side.
  if (Math.abs(after - before) > 0.5) {
    const anim = el.animate([{ width: `${before}px` }, { width: `${after}px` }], { ...spring(0.37), delay: after < before ? SHRINK_WAITS_MS : 0, fill: "backwards" })
    anim.finished.then(() => anim.cancel(), () => {})
  }
  // A growing label lets its width get a head start, so the new word is
  // never readable while it's still cut off at the side.
  // No window clips the roll: a hard edge slices the letters mid-move and
  // cuts descenders off the moment it starts. Each part travels under half a
  // line and blurs out of the way instead.
  const roll = { ...spring(0.45), delay: after > before + 0.5 ? 100 : 0 }
  const out = el.querySelector<HTMLElement>(".roll-out")
  const into = el.querySelector<HTMLElement>(".roll-in")
  out?.animate([{ transform: "translateY(0)", opacity: 1, filter: "blur(0)" }, { transform: "translateY(-45%)", opacity: 0, filter: "blur(2px)" }], { ...roll, fill: "both" }).finished.then(() => out.remove(), () => {})
  into?.animate([{ transform: "translateY(45%)", opacity: 0, filter: "blur(2px)" }, { transform: "translateY(0)", opacity: 1, filter: "blur(0)" }], { ...roll, fill: "backwards" })
  return after - before
}

function rollParts(text: string, old: string, fresh: string, same = text.length - fresh.length): DocumentFragment {
  const f = document.createDocumentFragment()
  const span = (cls: string, t: string) => {
    const s = document.createElement("span")
    s.className = cls
    s.textContent = t
    return s
  }
  if (!old && !fresh) {
    f.append(span("roll-still", text))
    return f
  }
  // The rolling parts are only seen; a screen reader reads the label whole
  // from a copy of its own (split around the window, it would read "Delet e").
  const still = span("roll-still", text.slice(0, same))
  const win = span("roll-window", "")
  win.append(span("roll-in", fresh))
  if (old) win.append(span("roll-out", old))
  still.setAttribute("aria-hidden", "true")
  win.setAttribute("aria-hidden", "true")
  f.append(still, win, span("roll-text", text))
  return f
}

/** The styles rollLabel needs, for pages that use it. */
export const ROLL_CSS = `.roll-text{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}.roll-still{white-space:pre}.roll-window{position:relative;display:inline-block;height:1lh;vertical-align:bottom;white-space:pre}.roll-in{display:inline-block}.roll-out{position:absolute;left:0;top:0}`
