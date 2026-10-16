import type { Light, Tone } from "../story/light"
import { DARK, type Box, type Point } from "../story/motion"

// A story's light as motion-lint sees it: every light entry becomes a channel (one number per frame) or an element
// (a moving dot, an opening ring), named after the card it belongs to. Values are what reaches the screen: times
// the scene's fade, and absent below light.ts's LIVE threshold, as `pack` drops them.
//
//   flood <card> <tone>[ (n)].intensity / .reach   light wicking into a card, and how far its front has got (one
//                                                  channel per flood: a second landing in the card is (2))
//   catch <card>                             the card's border catching nearby heads, as the shader lit it before
//                                            BorderLight (a card that draws its own is measured from its SVG: `glow`)
//   trail <n> from <card>.heat               the hottest stretch of one trail
//   print <card> <tone>.level, .churn, .open, .visible   a printed band: its ink, a hatch's scroll, its cleared disc
//   light:dot, light:ring elements           heads, embers, sparks; rings opening and closing
//
// Used by the clock sweep (motion-sweep.ts) and the live recorder (motion-lint-live.ts). The channel and element
// shapes match motion-lint's trace writer; this file doesn't import motion-lint so it builds without it.
//
// It reads a frame the way light.ts's pack does (a mirror: pack keeps its budget private): nothing at or under
// DARK, and over budget only the brightest of each kind, so a light the budget drops vanishes here too.

export type ElementSample = {
  x: number; y: number; w: number; h: number; a: number
  meta?: { cls: string; nm?: string; view?: string; host?: string; parent?: string }
}
export type ChannelSample = number | {
  v: number; kind?: "level" | "phase" | "position"; unit?: string; owner?: string; gate?: string; passive?: boolean
}
export type Card = { box: Box; name: string }
export type LightSample = { elements: [string, ElementSample][]; channels: [string, ChannelSample][] }

/** What a report calls a story's component: its card id, or its shot's. */
export const storyNameOf = (_: string, props: any): string | undefined =>
  [props?.id, props?.shot?.id, props?.["data-motion-id"]].find(v => typeof v === "string")

/** Collects a frame's cards while motion-lint's walker renders it: a box drawn by a component with an id, or inside
 *  one (a log entry's BorderLight). Also notes whether any card draws its own border light. */
export function cardCollector() {
  const cards: Card[] = []
  const named: [string, string][] = []
  const seen = { borderLight: false }
  const visit = (component: string, props: any, key: string) => {
    if (component === "BorderLight") seen.borderLight = true
    const id = storyNameOf(component, props)
    if (id && /^[A-Z]/.test(component)) named.push([key, id])
    if (!Array.isArray(props?.box) || props.box.length !== 4) return
    const owner = id ?? named.filter(([k]) => key.startsWith(k)).sort((a, b) => b[0].length - a[0].length)[0]?.[1]
    if (owner) cards.push({ box: props.box, name: owner })
  }
  return { cards, visit, seen }
}

/** Light at or below this never shows (light.ts's LIVE). */
const LIVE = DARK
/** light.ts's MAX: how many of each kind it packs. */
const BUDGET = { segments: 96, dots: 20, rings: 12, floods: 12, prints: 6 }

function brightest<T>(list: T[], max: number, level: (item: T) => number) {
  const live = list.filter(item => level(item) > LIVE)
  return live.length <= max ? live : live.sort((a, b) => level(b) - level(a)).slice(0, max)
}
/** The shader's border catch: falloff over 80 units, 0.6 × the reflection knob. */
const CATCH_RADIUS = 80, CATCH = .6

function falloff(r: number) {
  if (r >= 1) return 0
  if (r < .3) return 1 + (.65 - 1) * (r / .3)
  if (r < .7) return .65 + (.16 - .65) * ((r - .3) / .4)
  return .16 * (1 - (r - .7) / .3)
}

/** Distance from a point to a box's outline, inside or out. */
function toOutline(p: Point, b: Box, inset = .5) {
  const [x, y, w, h] = [b[0] + inset, b[1] + inset, b[2] - 2 * inset, b[3] - 2 * inset]
  const dx = Math.abs(p[0] - (x + w / 2)) - w / 2, dy = Math.abs(p[1] - (y + h / 2)) - h / 2
  return Math.abs(Math.hypot(Math.max(dx, 0), Math.max(dy, 0)) + Math.min(Math.max(dx, dy), 0))
}

const sameBox = (a: Box, b: Box) => a.every((v, i) => Math.abs(v - b[i]!) < .01)
const inside = (p: Point, b: Box) => p[0] >= b[0] - 1 && p[0] <= b[0] + b[2] + 1 && p[1] >= b[1] - 1 && p[1] <= b[1] + b[3] + 1
const key = (p: Point) => `${p[0].toFixed(2)},${p[1].toFixed(2)}`

/** Keeps identities across frames: heads by the nearest alike dot, floods by their box and entry point (a front
 *  only advances), trails by the path points they share. */
export function createLightProbe(options: {
  host?: string
  maxStep?: number
  reflection?: number
  flood?: number
  ink?: number
  /** Model the shader's border catch as `catch <card>` (for stories whose frames don't draw it themselves). */
  catch?: () => boolean
} = {}) {
  const host = options.host ?? "story"
  const maxStep = options.maxStep ?? 30
  let heads: { id: number; at: Point; tone: Tone; radius: number; intensity: number; name: string }[] = []
  let trails: { id: number; tone: Tone; points: Set<string>; name: string }[] = []
  let floods: { place: string; tone: Tone; reach: number; intensity: number; name: string }[] = []
  const floodsSeen = new Map<string, number>()
  let next = 1

  /** The card a box is, or the smallest one containing a point, or the nearest one. */
  const cardOf = (cards: readonly Card[], box?: Box, at?: Point): string => {
    if (box) {
      const exact = cards.find(c => sameBox(c.box, box))
      if (exact) return exact.name
      at = [box[0] + box[2] / 2, box[1] + box[3] / 2]
    }
    if (!at) return "scene"
    const containing = cards.filter(c => inside(at!, c.box)).sort((a, b) => a.box[2] * a.box[3] - b.box[2] * b.box[3])[0]
    if (containing) return containing.name
    let best: Card | undefined, bestD = Infinity
    for (const c of cards) {
      const d = toOutline(at, c.box, 0)
      if (d < bestD) { bestD = d; best = c }
    }
    return best ? `near ${best.name}` : "scene"
  }

  return {
    sample(light: Light, fade: number, cards: readonly Card[]): LightSample {
      const elements: [string, ElementSample][] = []
      const channels: [string, ChannelSample][] = []
      const level = (name: string, v: number) => {
        if (v > LIVE) channels.push([name, { v, kind: "level" }])
      }

      // Heads, embers and sparks: tracked dots, matched to last frame's cheapest pair first (distance, and
      // differences of size and brightness, so a head leaving its ember behind keeps its name).
      const dots = brightest(light.dots, BUDGET.dots, d => d.intensity * fade)
      const pairs: [number, number, number][] = []
      dots.forEach((d, j) => heads.forEach((h, i) => {
        const dist = Math.hypot(h.at[0] - d.at[0], h.at[1] - d.at[1])
        if (h.tone === d.tone && dist <= maxStep) pairs.push([dist + 4 * Math.abs(h.radius - d.radius) + 4 * Math.abs(h.intensity - d.intensity * fade), i, j])
      }))
      pairs.sort((a, b) => a[0] - b[0])
      const matched = new Map<number, number>(), taken = new Set<number>()
      for (const [, i, j] of pairs) {
        if (taken.has(i) || matched.has(j)) continue
        taken.add(i)
        matched.set(j, i)
      }
      const nextHeads: typeof heads = []
      dots.forEach((d, j) => {
        const was = matched.get(j)
        const seen = { at: d.at, radius: d.radius, intensity: d.intensity * fade }
        const head = was !== undefined ? { ...heads[was]!, ...seen } : { id: next++, tone: d.tone, name: `dot from ${cardOf(cards, undefined, d.at)}`, ...seen }
        nextHeads.push(head)
        elements.push([`light:dot#${head.id}`, {
          x: d.at[0] - d.radius, y: d.at[1] - d.radius, w: 2 * d.radius, h: 2 * d.radius, a: Math.min(1, d.intensity * fade),
          meta: { cls: "light:dot", nm: `${head.name}#${head.id}`, view: "light", host },
        }])
      })
      heads = nextHeads

      // Rings: keyed by their centre.
      for (const r of brightest(light.rings, BUDGET.rings, r => r.intensity * fade)) {
        const outer = r.radius + r.width / 2
        elements.push([`light:ring ${r.tone} ${key(r.at)}`, {
          x: r.at[0] - outer, y: r.at[1] - outer, w: 2 * outer, h: 2 * outer, a: Math.min(1, r.intensity * fade),
          meta: { cls: "light:ring", nm: `ring at ${cardOf(cards, undefined, r.at)}`, view: "light", host },
        }])
      }

      // Floods: by card, tone and where the light came in, and nearest in reach and brightness; a front that falls
      // back is a new flood.
      const live = brightest(light.floods, BUDGET.floods, f => f.intensity * fade)
      const card = live.map(f => cardOf(cards, f.box))
      const places = live.map((f, j) => `${card[j]} ${key(f.from)}`)
      const floodPairs: [number, number, number][] = []
      live.forEach((f, j) => floods.forEach((was, i) => {
        if (was.tone === f.tone && was.place === places[j] && f.reach >= was.reach - 1e-6) floodPairs.push([f.reach - was.reach + 100 * Math.abs(f.intensity - was.intensity), i, j])
      }))
      floodPairs.sort((a, b) => a[0] - b[0])
      const floodOf = new Map<number, number>(), floodTaken = new Set<number>()
      for (const [, i, j] of floodPairs) if (!floodTaken.has(i) && !floodOf.has(j)) { floodTaken.add(i); floodOf.set(j, i) }
      const nextFloods: typeof floods = []
      live.forEach((f, j) => {
        const was = floodOf.get(j)
        let name = was !== undefined ? floods[was]!.name : ""
        if (was === undefined) {
          const base = `flood ${card[j]} ${f.tone}`
          const n = (floodsSeen.get(base) ?? 0) + 1
          floodsSeen.set(base, n)
          name = n === 1 ? base : `${base} (${n})`
        }
        nextFloods.push({ place: places[j]!, tone: f.tone, reach: f.reach, intensity: f.intensity, name })
        const v = f.intensity * fade * (options.flood ?? 1)
        level(`${name}.intensity`, v)
        channels.push([`${name}.reach`, { v: f.reach, kind: "position", unit: "u", gate: `${name}.intensity` }])
      })
      floods = nextFloods

      // Border catch: only while some head is lit (pack sent frames only with dots).
      if (dots.length && options.catch?.()) {
        for (const box of light.frames) {
          let v = 0
          for (const d of dots) v += d.intensity * falloff(toOutline(d.at, box) / CATCH_RADIUS) * CATCH * (options.reflection ?? 1)
          level(`catch ${cardOf(cards, box)}`, v * fade)
        }
      }

      // Trails: chains of segments, matched to last frame's by the path points they share.
      const chains: { tone: Tone; points: Set<string>; heat: number; first: Point; end: string }[] = []
      const packed = new Set(brightest(light.segments, BUDGET.segments, s => Math.max(s.heat[0], s.heat[1]) * fade))
      for (const s of light.segments.filter(s => packed.has(s))) {
        const last = chains[chains.length - 1]
        const heat = Math.max(s.heat[0], s.heat[1])
        if (last && last.tone === s.tone && last.end === key(s.a)) {
          last.points.add(key(s.a))
          last.heat = Math.max(last.heat, heat)
          last.end = key(s.b)
        } else {
          chains.push({ tone: s.tone, points: new Set([key(s.a)]), heat, first: s.a, end: key(s.b) })
        }
      }
      const nextTrails: typeof trails = []
      const used = new Set<number>()
      for (const c of chains) {
        let best = -1, overlap = 0
        trails.forEach((t, i) => {
          if (used.has(i) || t.tone !== c.tone) return
          let n = 0
          for (const p of c.points) if (t.points.has(p)) n++
          if (n > overlap) { overlap = n; best = i }
        })
        if (best >= 0) used.add(best)
        const trail = best >= 0 ? { ...trails[best]!, points: c.points } : { id: next++, tone: c.tone, points: c.points, name: `trail ${next - 1} from ${cardOf(cards, undefined, c.first)}` }
        nextTrails.push(trail)
        level(`${trail.name}.heat`, c.heat * fade)
      }
      trails = nextTrails

      // Prints: a card's band of ink.
      for (const p of brightest(light.prints, BUDGET.prints, p => p.level * fade)) {
        const name = `print ${cardOf(cards, p.box)}`
        const v = p.level * fade * (options.ink ?? 1)
        channels.push([`${name}.visible`, { v, kind: "level", passive: true }])
        level(`${name} ${p.tone}.level`, v)
        // A cipher's churn counts sets of bits (each whole number a new one), so it steps; a hatch's is a distance.
        if (p.churn !== undefined && p.kind === "hatch") channels.push([`${name}.churn`, { v: p.churn, kind: "phase", unit: "u", gate: `${name}.visible` }])
        if (p.open) channels.push([`${name}.open`, { v: p.open.radius, kind: "position", unit: "u", gate: `${name}.visible` }])
      }
      return { elements, channels }
    },
  }
}
