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

/** Kit's palette, as visual duration and bounce. */
export const springs = {
  snappy: { duration: .25, bounce: 0 },
  calm: { duration: .4, bounce: 0 },
  smooth: { duration: .45, bounce: 0 },
  slow: { duration: .85, bounce: 0 },
} satisfies Record<string, Spring>

/** Closed-form step response (0 → 1) of a spring `seconds` after it starts. ω = 2π / duration, ζ = 1 − bounce. */
export function springAt(seconds: number, s: Spring) {
  if (seconds <= 0) return 0
  const w = (2 * Math.PI) / Math.max(.01, s.duration)
  const z = Math.max(.05, 1 - s.bounce)
  if (z >= 1) return 1 - (1 + w * seconds) * Math.exp(-w * seconds)
  const wd = w * Math.sqrt(1 - z * z)
  return 1 - Math.exp(-z * w * seconds) * (Math.cos(wd * seconds) + ((z * w) / wd) * Math.sin(wd * seconds))
}

/** A flash: instant attack at `age` 0, then a convex decay over `decay` seconds. */
export const flash = (age: number, decay = 1.2) => age < 0 ? 0 : Math.pow(1 - clamp01(age / decay), 2)

/** The brightest of several flashes. */
export const flashes = (t: number, times: readonly number[], decay = 1.2) => times.reduce((heat, at) => Math.max(heat, flash(t - at, decay)), 0)

const rgb = (hex: string) => [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16))

/** A #rrggbb colour mixed toward each layer in turn: `shade(base, [toward, amount], …)`. */
export function shade(base: string, ...layers: (readonly [string, number])[]) {
  let color = rgb(base)
  for (const [toward, amount] of layers) {
    const target = rgb(toward), k = clamp01(amount)
    color = color.map((v, i) => v + (target[i]! - v) * k)
  }
  return `rgb(${color.map(Math.round).join(" ")})`
}
