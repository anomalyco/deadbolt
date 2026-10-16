// Curves for stories. Every value is a pure function of the scene clock (seconds), so any frame renders the
// same in any order and scrubbing is exact.

export type Point = readonly [number, number]
export type Box = readonly [number, number, number, number]

export const clamp01 = (x: number) => Math.min(1, Math.max(0, x))
export const span = (t: number, a: number, b: number) => clamp01((t - a) / (b - a))
export const mix = (a: number, b: number, t: number) => a + (b - a) * t
export const smoothstep = (x: number) => { const t = clamp01(x); return t * t * (3 - 2 * t) }
export const cubicOut = (x: number) => 1 - Math.pow(1 - clamp01(x), 3)

/** Minimum-jerk travel: continuous velocity and acceleration into rest. */
export const smootherstep = (x: number) => { const t = clamp01(x); return t * t * t * (t * (t * 6 - 15) + 10) }

/** The time fraction at which smootherstep reaches `y`. */
export function smootherInverse(y: number) {
  let lo = 0, hi = 1
  for (let i = 0; i < 24; i++) { const m = (lo + hi) / 2; if (smootherstep(m) < y) lo = m; else hi = m }
  return (lo + hi) / 2
}

/** CSS cubic-bezier as a function. */
export function bezier(x1: number, y1: number, x2: number, y2: number) {
  const at = (a: number, b: number, s: number) => 3 * a * s * (1 - s) * (1 - s) + 3 * b * s * s * (1 - s) + s * s * s
  return (x: number) => {
    const p = clamp01(x)
    if (p === 0 || p === 1) return p
    let lo = 0, hi = 1
    for (let i = 0; i < 22; i++) { const m = (lo + hi) / 2; if (at(x1, x2, m) < p) lo = m; else hi = m }
    return at(y1, y2, (lo + hi) / 2)
  }
}

export const ease = {
  enter: bezier(.2, .8, .2, 1),
  exit: bezier(.4, 0, 1, 1),
  draw: bezier(.45, 0, .2, 1),
}

export type Spring = { duration: number; bounce: number }

/** Kit's palette, as visual duration and bounce (bounce 0 by default). */
export const springs = {
  instant: { duration: .1, bounce: 0 },
  snappy: { duration: .25, bounce: 0 },
  default: { duration: .3, bounce: 0 },
  calm: { duration: .4, bounce: 0 },
  smooth: { duration: .45, bounce: 0 },
  morph: { duration: .42, bounce: .16 },
  settle: { duration: .55, bounce: .12 },
  slow: { duration: .85, bounce: 0 },
} satisfies Record<string, Spring>

/** Closed-form step response (0 → 1) of a spring `seconds` after it starts. ω = 2π / duration, ζ = 1 − bounce. */
export function springAt(seconds: number, s: Spring = springs.default) {
  if (seconds <= 0) return 0
  const w = (2 * Math.PI) / Math.max(.01, s.duration)
  const z = Math.max(.05, 1 - s.bounce)
  const raw = z >= 1
    ? 1 - (1 + w * seconds) * Math.exp(-w * seconds)
    : (() => {
      const wd = w * Math.sqrt(1 - z * z)
      return 1 - Math.exp(-z * w * seconds) * (Math.cos(wd * seconds) + ((z * w) / wd) * Math.sin(wd * seconds))
    })()
  return seconds > s.duration && Math.abs(1 - raw) < .0008 ? 1 : raw
}

/** A belt with mass, driven at `speed` (units per second) during each `[from, to]` run. Its speed follows the drive
 *  through a zero-bounce spring of `duration` seconds, so it spins up and coasts to a stop instead of starting and
 *  stopping dead, and how far it has moved is the exact integral of that speed. Both are closed-form in t (the runs
 *  superpose), so any frame is exact when scrubbed. */
export function belt(t: number, runs: readonly (readonly [number, number])[], speed: number, duration = .6) {
  const w = (2 * Math.PI) / duration
  // The spring's step response S(s) = 1 − (1 + ws)·e^(−ws), and its integral.
  const response = (s: number) => s <= 0 ? 0 : 1 - (1 + w * s) * Math.exp(-w * s)
  const integral = (s: number) => s <= 0 ? 0 : s - 2 * (1 - Math.exp(-w * s)) / w + s * Math.exp(-w * s)
  let travel = 0, velocity = 0
  for (const [from, to] of runs) {
    travel += speed * (integral(t - from) - integral(t - to))
    velocity += speed * (response(t - from) - response(t - to))
  }
  return { travel, speed: velocity }
}

/** Below this a light or a heat is under one 8-bit step on every ink, so a decay can stop here with no visible end. */
export const DARK = .001

/** Newton's-law cooling, e^(−age/τ), from an instant attack at age 0. It never reaches zero by itself (its log falls
 *  at a steady rate, so it never seems to switch off); it stops once it's DARK, about 7τ in. */
export const cooling = (age: number, tau: number) => {
  if (age < 0) return 0
  const k = Math.exp(-age / tau)
  return k < DARK ? 0 : k
}

/** Filament / flashbulb cooling: instant attack at `age` 0, then exponential decay with a little longer half-life
 *  than the (1 − age/decay)² it replaced. Instead of hitting zero at `decay`, about 10% is still glowing then, 1% at
 *  twice that, and it sinks under an ink step near three times that. */
export const flash = (age: number, decay = 1.2) => cooling(age, .45 * decay)

/** Hot stamp / ink soaking into paper: a fast exponential drop with a long, faint tail. */
export const inkFlash = (age: number) => cooling(age, .234)

/** The brightest of several flashes. */
export const flashes = (t: number, times: readonly number[], decay = 1.2) =>
  times.reduce((heat, at) => Math.max(heat, flash(t - at, decay)), 0)

/** Sliding plate / shutter wipe: linear across the plate's travel window, softened at the stops. */
export const wipe = (t: number, from: number, duration = .32) => smoothstep(span(t, from, from + duration))

const CHARS = "0123456789abcdef"
const hashNoise = (n: number) => { const x = Math.sin(n * 91.345) * 47453.5453; return x - Math.floor(x) }

/** Cipher wheel / odometer: characters lock in left to right between `from` and `to`. */
export function working(final: string, t: number, from: number, to: number, seed = 1, previous = final) {
  if (t < from) return null
  if (t >= to) return final
  // The board widens or narrows from the old text's length over the roll, so the label never snaps in width.
  const length = Math.round(previous.length + (final.length - previous.length) * (t - from) / (to - from))
  return Array.from({ length }, (_, i) => {
    const c = final[i]
    if (c === " " || c === "·" || c === ":") return c
    return c !== undefined && t >= from + (to - from) * (i + 1) / final.length
      ? c
      : CHARS[Math.floor(hashNoise(Math.floor(t * 28) * 13 + i * 7 + seed) * 16)]
  }).join("")
}

/** A label that changes over time, from `[time, text]` states in order: each new text rolls in like an odometer
 *  over `roll` seconds instead of swapping in one frame. */
export function rolling(t: number, states: readonly (readonly [number, string])[], seed = 1, roll = .32) {
  let index = 0
  states.forEach(([at], i) => { if (t >= at) index = i })
  const [at, text] = states[index]!
  return index === 0 ? text : working(text, t, at, at + roll, seed + index, states[index - 1]![1]) ?? text
}

const rgb = (color: string) => color.startsWith("rgb(")
  ? color.slice(4, -1).split(" ").map(Number)
  : [1, 3, 5].map(i => parseInt(color.slice(i, i + 2), 16))

/** A colour (#rrggbb, or an `rgb(r g b)` from shade) mixed toward each layer in turn: `shade(base, [toward, amount], …)`. */
export function shade(base: string, ...layers: (readonly [string, number])[]) {
  let color = rgb(base)
  for (const [toward, amount] of layers) {
    const target = rgb(toward), k = clamp01(amount)
    color = color.map((v, i) => v + (target[i]! - v) * k)
  }
  return `rgb(${color.map(Math.round).join(" ")})`
}
