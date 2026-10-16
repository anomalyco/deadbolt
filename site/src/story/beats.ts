import type { Light, Tone } from "./light"
import { clamp01, ease, flash, smootherInverse, smootherstep, smoothstep, span, type Box, type Point } from "./motion"

// The story vocabulary (explainer-motion's Send & Connect): light gathers at a port, a head flies along a path
// leaving a trail that cools behind it, an ember cools where it left, it lands as a small opening ring, and
// floods into whatever it reached. Every function takes the scene time and pushes lights; none keeps state.

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

/** Pushes the lights of one send at time t. */
export function send(light: Light, s: Send, t: number) {
  const { gather, flight, launch, lands } = timing(s)
  if (t < s.at) return
  const tone = s.tone ?? "ivory", k = s.strength ?? 1, cool = s.cool ?? .42
  const point = (f: number) => s.path.at(s.reverse ? 1 - f : f)
  const origin = point(0)

  // Origin ember: hot port filament cooling over 1.1s after launch.
  if (t >= launch && t < launch + 1.1) {
    const e = (t - launch) / 1.1
    const ember = .28 * Math.min(e / .05, 1) * Math.pow(1 - e, 1.4) * k
    if (ember > .01) light.dots.push({ at: origin, radius: 2.2, intensity: ember, tone })
  }

  // The trail: each point heats as the head crosses it and cools after.
  const inverse = crossings(s.path)
  const count = s.path.points.length
  const heat = (i: number) => {
    const f = s.reverse ? 1 - s.path.fractions[count - 1 - i]! : s.path.fractions[i]!
    const crossed = launch + flight * (s.reverse ? smootherInverse(f) : inverse[i]!)
    const age = t - crossed
    return age < 0 ? -1 : .8 * Math.pow(1 - clamp01(age / cool), 1.7)
  }
  const ordered = s.reverse ? [...s.path.points].reverse() : s.path.points
  const progress = travelled(s, t)
  if (t > launch && t < lands + cool) {
    for (let i = 0; i < count - 1; i++) {
      const h0 = heat(i)
      if (h0 < 0) break
      let h1 = heat(i + 1), b = ordered[i + 1]!
      if (h1 < 0) { h1 = .8; b = point(progress) }
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
    light.dots.push({ at: point(progress), radius: 3, intensity: k, tone })
    return
  }
  const q = (t - lands) / LAND, end = point(1)
  if (q < 1) {
    const opening = smoothstep(q / .24)
    light.rings.push({
      at: end, radius: 2 + 2 * opening + 9.1 * (1 - (1 - q) * (1 - q)), width: 4 + (1.5 - 4) * opening,
      intensity: (1 - .734 * opening) * Math.pow(1 - q, 2.52) * k, tone,
    })
  }
  if (s.into) flood(light, s.into.box, end, t - lands, s.into.tone ?? tone, k)
}

/** Draws a wire on `cubic-bezier(.45, 0, .2, 1)` and pushes a bright bead at the leading tip while drawing. */
export function drawOn(light: Light, path: Path, t: number, at: number, duration = .55, tone: Tone = "ivory", strength = .85) {
  const raw = span(t, at, at + duration)
  const p = ease.draw(raw)
  if (raw > 0 && raw < 1) {
    const bead = smoothstep(p / .08) * (1 - smoothstep((p - .92) / .08))
    if (bead > .01) light.dots.push({ at: path.at(p), radius: 2.3, intensity: bead * strength, tone })
  }
  return p
}

/** Light seeping into a box from a point on its edge, `age` seconds after it arrived. */
export function flood(light: Light, box: Box, from: Point, age: number, tone: Tone, strength = 1, duration = FLOOD) {
  const t = age / duration
  if (t < 0 || t >= 1) return
  const travel = 1 - Math.pow(1 - t, 4)
  const reach = (.07 + .6 * Math.sqrt(travel)) * Math.max(box[2], box[3])
  const fade = Math.exp(-.9 * t) * (1 - smoothstep((t - .65) / .35)) * smoothstep(t / .07)
  light.floods.push({ box, from, reach, intensity: .9 * fade * strength, tone })
}

/** A spark: instant attack, convex decay. For a seal stamping down or a gate refusal. */
export function spark(light: Light, at: Point, age: number, tone: Tone, strength = 1) {
  const k = flash(age, .55) * strength
  if (k <= 0) return
  light.dots.push({ at, radius: 2.4, intensity: k, tone })
  const q = clamp01(age / .5)
  light.rings.push({ at, radius: 3 + 9 * (1 - (1 - q) * (1 - q)), width: 1.5, intensity: .6 * Math.pow(1 - q, 2) * strength, tone })
}
