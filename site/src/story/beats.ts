import type { Light, Tone } from "./light"
import type { Flight, SceneCue } from "../sound"
import { DARK, clamp01, cooling, ease, flash, smootherInverse, smootherstep, smoothstep, span, type Box, type Point } from "./motion"
import { coolingScale, shutter } from "./tuning"

// The story vocabulary (explainer-motion's Send & Connect): light gathers at a port, a head flies along a path
// leaving a trail that cools behind it, an ember cools where it left, it lands as a small opening ring, and
// wicks into whatever it reached. Every function takes the scene time and pushes lights; none keeps state.

export type Path = {
  d: string
  length: number
  /** Flattened points and their fractions of the length. */
  points: Point[]
  fractions: number[]
  at(u: number): Point
}

function buildPath(raw: Point[], d: string): Path {
  const lengths = [0]
  for (let i = 1; i < raw.length; i++) lengths.push(lengths[i - 1]! + Math.hypot(raw[i]![0] - raw[i - 1]![0], raw[i]![1] - raw[i - 1]![1]))
  const length = Math.max(1e-3, lengths[lengths.length - 1]!)
  const fractions = lengths.map(l => l / length)
  const at = (u: number): Point => {
    const target = clamp01(u)
    let i = 1
    while (i < fractions.length - 1 && fractions[i]! < target) i++
    const a = raw[i - 1]!, b = raw[i]!, f = (target - fractions[i - 1]!) / Math.max(1e-6, fractions[i]! - fractions[i - 1]!)
    return [a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f]
  }
  return { d, length, points: raw, fractions, at }
}

/** A cubic Bézier, flattened for the light layer. */
export function cubic(p0: Point, c1: Point, c2: Point, p3: Point, samples = 18): Path {
  const raw: Point[] = Array.from({ length: samples + 1 }, (_, i) => {
    const s = i / samples, r = 1 - s
    return [0, 1].map(k => r * r * r * p0[k]! + 3 * r * r * s * c1[k]! + 3 * r * s * s * c2[k]! + s * s * s * p3[k]!) as unknown as Point
  })
  const n = (p: Point) => `${+p[0].toFixed(2)} ${+p[1].toFixed(2)}`
  return buildPath(raw, `M${n(p0)}C${n(c1)} ${n(c2)} ${n(p3)}`)
}

/** A straight or multi-segment polyline, subdivided so trail cooling is smooth along every segment. */
export function polyline(corners: readonly Point[], step = 18): Path {
  const raw: Point[] = [corners[0]!]
  for (let i = 0; i < corners.length - 1; i++) {
    const a = corners[i]!, b = corners[i + 1]!
    const segLen = Math.hypot(b[0] - a[0], b[1] - a[1])
    const n = Math.max(2, Math.ceil(segLen / step))
    for (let k = 1; k <= n; k++) {
      const f = k / n
      raw.push([a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f])
    }
  }
  const fmt = (p: Point) => `${+p[0].toFixed(2)} ${+p[1].toFixed(2)}`
  const d = corners.map((p, i) => `${i ? "L" : "M"}${fmt(p)}`).join("")
  return buildPath(raw, d)
}

/** A bridge between two points on the same side of a row, lifting `lift` units (negative bows downward). */
export const bridge = (from: Point, to: Point, lift: number) =>
  cubic(from, [from[0], from[1] - lift / .75], [to[0], to[1] - lift / .75], to)

/** An S-curve between rows: leaves and arrives vertically, so it never cuts across a box in either row. */
export function between(from: Point, to: Point, bend = .55) {
  const k = (to[1] - from[1]) * bend
  return cubic(from, [from[0], from[1] + k], [to[0], to[1] - k], to)
}

/** A horizontal S-curve between columns: leaves and arrives horizontally. */
export function across(from: Point, to: Point, bend = .52) {
  const k = (to[0] - from[0]) * bend
  return cubic(from, [from[0] + k, from[1]], [to[0] - k, to[1]], to)
}

export type Send = {
  path: Path
  /** When light starts gathering at the origin. */
  at: number
  gather?: number
  flight?: number
  /** Travel from the path's end back to its start. */
  reverse?: boolean
  tone?: Tone
  strength?: number
  /** Seconds a point of the trail takes to cool. */
  cool?: number
  /** The box the light floods into when it lands. */
  into?: { box: Box; tone?: Tone }
}

const GATHER = .34, LAND = .72, FLOOD = 1.2

export function timing(send: Send) {
  const gather = send.gather ?? GATHER
  const flight = send.flight ?? Math.min(1.3, Math.max(.5, .45 + send.path.length / 520))
  const launch = send.at + gather
  return { gather, flight, launch, lands: launch + flight }
}

/** How far along its path (in travel order) the head is at time t. */
export function travelled(send: Send, t: number) {
  const { flight, launch } = timing(send)
  return smootherstep((t - launch) / flight)
}

const inverses = new WeakMap<Path, number[]>()
function crossings(path: Path) {
  let cached = inverses.get(path)
  if (!cached) inverses.set(path, cached = path.fractions.map(smootherInverse))
  return cached
}

/** A trail drawn at this heat is under one ink step, so it can stop there. */
const TRAIL_DARK = .005
/** How long a trail point glows, in cooling times: until its heat is TRAIL_DARK. */
const TRAIL_END = Math.log(1 / TRAIL_DARK) / 3.4

/** A filament `a` cooling times after the head crossed it (Newton's law): it drops fast, then keeps a long dim tail
 *  that fades below an ink step (at TRAIL_END) instead of being cut to cold at a set time. */
export const temperature = (a: number) => {
  const k = Math.exp(-3.4 * Math.max(0, a))
  return k < TRAIL_DARK ? 0 : k
}

/** A flood's light `t` of its duration after it arrived. It rises over 7%, soaks at e^(−.9t) while the front spreads,
 *  then cools faster, at e^(−3.5t), easing between the two rates around t = .7. Its log only ever falls at a steady
 *  rate, so it never seems to switch off; it stops once DARK, about 2.5 durations in. */
function soaking(t: number) {
  const slow = .9, fast = 3.5, knee = .7, soft = .15
  const softplus = (x: number) => x > 20 ? x : Math.log1p(Math.exp(x))
  const k = Math.exp(-slow * t - (fast - slow) * soft * (softplus((t - knee) / soft) - softplus(-knee / soft))) * smoothstep(t / .07)
  return k < DARK ? 0 : k
}

/** Pushes the lights of one send at time t. */
export function send(light: Light, s: Send, t: number) {
  const { gather, flight, launch, lands } = timing(s)
  if (t < s.at) return
  const tone = s.tone ?? "ivory", k = s.strength ?? 1, cool = (s.cool ?? .55) * coolingScale()
  const point = (f: number) => s.path.at(s.reverse ? 1 - f : f)
  const origin = point(0)

  // Origin ember: the port's filament, heated by the launch, cooling (τ .5s) long after the head has gone.
  if (t >= launch) {
    const ember = .28 * Math.min((t - launch) / .055, 1) * cooling(t - launch, .5) * k
    if (ember > DARK) light.dots.push({ at: origin, radius: 2.2, intensity: ember, tone })
  }

  // The trail: each point heats white as the head crosses it, then cools through the signal's tone to dark.
  const inverse = crossings(s.path)
  const count = s.path.points.length
  const heat = (i: number) => {
    const f = s.reverse ? 1 - s.path.fractions[count - 1 - i]! : s.path.fractions[i]!
    const crossed = launch + flight * (s.reverse ? smootherInverse(f) : inverse[i]!)
    const age = t - crossed
    return age < 0 ? -1 : temperature(age / cool)
  }
  const ordered = s.reverse ? [...s.path.points].reverse() : s.path.points
  const progress = travelled(s, t)
  if (t > launch && t < lands + cool * TRAIL_END) {
    for (let i = 0; i < count - 1; i++) {
      const h0 = heat(i)
      if (h0 < 0) break
      let h1 = heat(i + 1), b = ordered[i + 1]!
      if (h1 < 0) { h1 = 1; b = point(progress) }
      if (h0 > 0 || h1 > 0) light.segments.push({ a: ordered[i]!, b, heat: [h0 * k, h1 * k], width: 1.6, tone })
    }
  }

  if (t < launch) {
    const g = 1 - Math.pow(1 - (t - s.at) / gather, 3)
    light.dots.push({ at: origin, radius: Math.max(.01, 3 * g), intensity: Math.pow(g, 1.5) * k, tone })
    light.rings.push({ at: origin, radius: 4 + 14 * (1 - g), width: 5, intensity: .5 * Math.sin(Math.PI * g) * k, tone })
    return
  }
  if (t < lands) {
    // Exposed over a short shutter, so a fast head smears along its path instead of strobing.
    light.dots.push({ at: point(progress), from: point(travelled(s, t - shutter())), radius: 3, intensity: k, tone })
    return
  }
  // Landing: the head's light stays where it hit and cools in a blink (τ 70ms), so its bloom and the border it lit
  // don't switch off on the frame it lands; meanwhile the dot opens into a ring that keeps spreading as it fades.
  const age = t - lands, q = age / LAND, end = point(1)
  const impact = cooling(age, .07) * k
  if (impact > DARK) light.dots.push({ at: end, radius: 3, intensity: impact, tone })
  const opening = smoothstep(q / .24)
  const splash = (1 - .734 * opening) * cooling(q, .345) * k
  if (splash > DARK) {
    light.rings.push({ at: end, radius: 2 + 2 * opening + 9.8 * (1 - Math.exp(-2.2 * q)), width: 4 + (1.5 - 4) * opening, intensity: splash, tone })
  }
  if (s.into) flood(light, s.into.box, end, age, s.into.tone ?? tone, k)
}

/** How much of a wire drawn by `drawOn` is drawn at time t. */
export const drawProgress = (t: number, at: number, duration = .55) => ease.draw(span(t, at, at + duration))

/** Draws a wire on `cubic-bezier(.45, 0, .2, 1)` and pushes a bright bead at the leading tip while drawing. */
export function drawOn(light: Light, path: Path, t: number, at: number, duration = .55, tone: Tone = "ivory", strength = .85) {
  const raw = span(t, at, at + duration)
  const p = drawProgress(t, at, duration)
  if (raw > 0 && raw < 1) {
    const bead = smoothstep(p / .08) * (1 - smoothstep((p - .92) / .08))
    const from = path.at(ease.draw(span(t - shutter(), at, at + duration)))
    if (bead > .01) light.dots.push({ at: path.at(p), from, radius: 2.3, intensity: bead * strength, tone })
  }
  return p
}

/** Light wicking into a box from a point on its edge, `age` seconds after it arrived. Like ink into paper
 *  (Washburn), the wet front advances as √t until it has crossed most of the card (at .8 of `duration`), and the
 *  stain soaks, then cools with a long tail (see `soaking`). */
export function flood(light: Light, box: Box, from: Point, age: number, tone: Tone, strength = 1, duration = FLOOD) {
  const t = age / duration
  if (t < 0) return
  const intensity = .9 * soaking(t) * strength
  if (intensity < DARK) return
  const reach = (.06 + .66 * Math.sqrt(Math.min(1, t / .8))) * Math.max(box[2], box[3])
  light.floods.push({ box, from, reach, intensity, tone })
}

/** Sealed ciphertext printed in a card's free band. It clears from `open.from` as light wicks in, and its bits
 *  change while `churn` changes. */
export function cipher(light: Light, box: Box, options: { tone?: Tone; level?: number; seed?: number; open?: { from: Point; radius: number }; churn?: number } = {}) {
  light.prints.push({ box, kind: "cipher", tone: options.tone ?? "ivory", level: options.level ?? 1, seed: options.seed ?? 1, open: options.open, churn: options.churn })
}

/** Hatched noise printed in a card's free band; `churn` is how far it has moved to the right (see `belt`). */
export function hatch(light: Light, box: Box, options: { tone?: Tone; level?: number; seed?: number; churn?: number } = {}) {
  light.prints.push({ box, kind: "hatch", tone: options.tone ?? "ivory", level: options.level ?? 1, seed: options.seed ?? 1, churn: options.churn })
}

/** A spark: instant attack, then it cools like a filament while its ring keeps spreading as it fades. For a seal
 *  stamping down or a gate refusal. */
export function spark(light: Light, at: Point, age: number, tone: Tone, strength = 1) {
  const k = flash(age, .55) * strength
  if (k <= DARK) return
  light.dots.push({ at, radius: 2.4, intensity: k, tone })
  const q = age / .5, ring = .6 * cooling(q, .42) * strength
  if (ring > DARK) light.rings.push({ at, radius: 3 + 9.7 * (1 - Math.exp(-2.2 * q)), width: 1.5, intensity: ring, tone })
}

/** Stereo pan (−0.85..0.85) from a scene x coordinate. */
export const panX = (x: number, width = 940) => +(((x / width) * 2 - 1) * .85).toFixed(2)

/** Sound cues (`send` + `land`) and continuous `Flight` for a `Send` beat. */
export function soundOfSend(s: Send, width = 940, gain = .85): { cues: SceneCue[]; flight: Flight } {
  const { launch, lands } = timing(s)
  const start = s.path.at(s.reverse ? 1 : 0)
  const end = s.path.at(s.reverse ? 0 : 1)
  const pan0 = panX(start[0], width), pan1 = panX(end[0], width)
  return {
    cues: [
      { at: launch, cue: "send", detail: { pan: pan0, gain: gain * (s.strength ?? 1) } },
      { at: lands, cue: "land", detail: { pan: pan1, gain: gain * (s.strength ?? 1) } },
    ],
    flight: { from: launch, to: lands, pan: [pan0, pan1], gain: gain * (s.strength ?? 1) },
  }
}
