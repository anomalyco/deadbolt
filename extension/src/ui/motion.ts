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

/** Milliseconds since the epoch, comparable between documents. */
export const epochNow = () => performance.timeOrigin + performance.now()

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
  // Width leads: a slightly shorter spring than the roll.
  if (Math.abs(after - before) > 0.5) {
    const anim = el.animate([{ width: `${before}px` }, { width: `${after}px` }], spring(0.37))
    anim.finished.then(() => anim.cancel(), () => {})
  }
  // A growing label lets its width get a head start, so the new word is
  // never readable while it's still cut off at the side.
  const roll = { ...spring(0.45), delay: after > before + 0.5 ? 100 : 0 }
  const out = el.querySelector<HTMLElement>(".roll-out")
  const into = el.querySelector<HTMLElement>(".roll-in")
  out?.animate([{ transform: "translateY(0)", opacity: 1 }, { transform: "translateY(-100%)", opacity: 0 }], { ...roll, fill: "both" }).finished.then(() => out.remove(), () => {})
  into?.animate([{ transform: "translateY(100%)", opacity: 0 }, { transform: "translateY(0)", opacity: 1 }], { ...roll, fill: "backwards" })
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
export const ROLL_CSS = `.roll-text{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}.roll-still{white-space:pre}.roll-window{position:relative;display:inline-block;overflow:hidden;height:1lh;vertical-align:bottom;white-space:pre}.roll-in{display:inline-block}.roll-out{position:absolute;left:0;top:0}`
