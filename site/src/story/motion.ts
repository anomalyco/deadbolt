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

/** Filament / flashbulb cooling: instant attack at `age` 0, then convex decay over `decay` seconds. */
export const flash = (age: number, decay = 1.2) => age < 0 ? 0 : Math.pow(1 - clamp01(age / decay), 2)

/** Hot stamp / ink soaking into paper: fast exponential drop with a bounded tail over 0.75s. */
export const inkFlash = (age: number) =>
  age < 0 ? 0 : Math.exp(-age / .234) * (1 - Math.min(1, Math.pow(age / .75, 2)))

/** The brightest of several flashes. */
export const flashes = (t: number, times: readonly number[], decay = 1.2) =>
  times.reduce((heat, at) => Math.max(heat, flash(t - at, decay)), 0)

/** Sliding plate / shutter wipe: linear across the plate's travel window, softened at the stops. */
export const wipe = (t: number, from: number, duration = .32) => smoothstep(span(t, from, from + duration))

const CHARS = "0123456789abcdef"
const hashNoise = (n: number) => { const x = Math.sin(n * 91.345) * 47453.5453; return x - Math.floor(x) }

/** Cipher wheel / odometer: characters lock in left to right between `from` and `to`. */
export function working(final: string, t: number, from: number, to: number, seed = 1) {
  if (t < from) return null
  if (t >= to) return final
  return [...final].map((c, i) => {
    if (c === " " || c === "·" || c === ":") return c
    return t >= from + (to - from) * (i + 1) / final.length
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
  return index === 0 ? text : working(text, t, at, at + roll, seed + index) ?? text
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
