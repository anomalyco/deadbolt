import type { Light, Tone } from "../../story/light"
import type { SceneCue } from "../../sound"
import { between, bridge, drawOn, drawProgress, flood, panX, send, soundOfSend, spark, timing, travelled, type Path, type Send } from "../../story/beats"
import { BorderLight, Carried, DeviceGlyph, type DeviceKind } from "../../story/devices"
import { clamp01, flashes, inkFlash, shade, span, springAt, springs, working, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// Two devices (desktop and laptop), one log each. An entry is a card; when it's written, light runs back along its
// deps to the entries its author had seen, and they light up as it lands. Membership entries (red) only ever point
// at membership. The laptop gets in through the desktop's add, which carries its signed consent; its first entry
// points at that add. Later, rewriting one entry breaks every entry that saw it.

const W = 940, H = 400
const LANE = { desktop: 140, laptop: 290 } as const
type Lane = keyof typeof LANE
const GLYPH: Record<Lane, DeviceKind> = { desktop: "desktop", laptop: "laptop" }
const EW = 68, EH = 30

type Id = "d0" | "d1" | "d2" | "l0" | "d3" | "l1" | "d4"
type Entry = { lane: Lane; x: number; label: string; deps: Id[]; membership?: boolean; at: number }

const consent: Send = {
  path: between([112, LANE.laptop], [412, LANE.desktop + EH / 2], .5),
  at: 6.3, tone: "ivory", strength: .85,
}

const ENTRIES: Record<Id, Entry> = {
  d0: { lane: "desktop", x: 196, label: "create", deps: [], membership: true, at: 0 },
  d1: { lane: "desktop", x: 304, label: "3f9a", deps: ["d0"], at: 3 },
  d2: { lane: "desktop", x: 412, label: "add", deps: ["d0"], membership: true, at: timing(consent).lands },
  l0: { lane: "laptop", x: 522, label: "c41e", deps: ["d1", "d2"], at: 10.3 },
  d3: { lane: "desktop", x: 640, label: "7b20", deps: ["d1", "d2"], at: 13.5 },
  l1: { lane: "laptop", x: 640, label: "e95d", deps: ["l0"], at: 13.7 },
  d4: { lane: "desktop", x: 780, label: "1a6c", deps: ["d3", "l1"], at: 17.1 },
}
const IDS = Object.keys(ENTRIES) as Id[]

const top = (id: Id, dx = 0) => [ENTRIES[id].x + dx, LANE[ENTRIES[id].lane] - EH / 2] as const
const bottom = (id: Id, dx = 0) => [ENTRIES[id].x + dx, LANE[ENTRIES[id].lane] + EH / 2] as const
const box = (id: Id): Box => [ENTRIES[id].x - EW / 2, LANE[ENTRIES[id].lane] - EH / 2, EW, EH]
const tone = (id: Id): Tone => ENTRIES[id].membership ? "red" : "ivory"
const lift = (a: readonly [number, number], b: readonly [number, number]) => 16 + .13 * Math.abs(a[0] - b[0])

// Each link runs from an entry back to one of its deps. Bridges stay on their own side of the row and nest, so
// a link never cuts through a card.
const link = (from: readonly [number, number], to: readonly [number, number], side: 1 | -1) => bridge(from, to, side * lift(from, to))
const LINKS: Record<string, Path> = {
  "d1>d0": link(top("d1", -14), top("d0", 16), 1),
  "d2>d0": link(top("d2", -14), top("d0", 4), 1),
  "l0>d1": between(top("l0", -12), bottom("d1")),
  "l0>d2": between(top("l0"), bottom("d2")),
  "d3>d2": link(top("d3", -18), top("d2", 14), 1),
  "d3>d1": link(top("d3", -6), top("d1", 14), 1),
  "l1>l0": link(bottom("l1", -14), bottom("l0", 8), -1),
  "d4>d3": link(top("d4", -14), top("d3", 16), 1),
  "d4>l1": between(bottom("d4", -8), top("l1", 14)),
}
const linkKeys = (id: Id) => ENTRIES[id].deps.map(dep => [`${id}>${dep}`, dep] as const)
const dependents = (id: Id) => IDS.filter(other => ENTRIES[other].deps.includes(id)).map(other => [`${other}>${id}`, other] as const)

type Shot = Send & { key?: string; to: Id; kind: "see" | "ripple" | "hash" | "break" | "consent"; label?: string }

// When an entry is written, its light runs back to every dep.
const sees: Shot[] = IDS.flatMap(id => linkKeys(id).map(([key, dep]) => ({
  key, kind: "see" as const, to: dep, path: LINKS[key]!, at: ENTRIES[id].at + .35, tone: tone(id), into: { box: box(dep), tone: tone(dep) },
})))

/** Light that keeps travelling from each entry it reaches, one hop at a time, each hop dimmer. */
function cascade(start: [Id, number][], next: (id: Id) => (readonly [string, Id])[], make: (key: string, to: Id, at: number, depth: number) => Shot) {
  const shots: Shot[] = [], reached = new Set<Id>()
  let frontier: (readonly [Id, number, number])[] = start.map(([id, at]) => [id, at, 0])
  while (frontier.length) {
    const following: (readonly [Id, number, number])[] = []
    for (const [id, at, depth] of frontier) {
      if (reached.has(id)) continue
      reached.add(id)
      for (const [key, to] of next(id)) {
        const shot = make(key, to, at, depth)
        shots.push(shot)
        following.push([to, timing(shot).lands, depth + 1])
      }
    }
    frontier = following
  }
  return shots
}

// Step 6: the entry that saw both has, through them, seen everything. The light keeps going back through history.
const ripple = cascade(
  sees.filter(s => s.key?.startsWith("d4>")).map(s => [s.to, timing(s).lands] as [Id, number]),
  linkKeys,
  (key, to, at, depth) => ({ key, kind: "ripple", to, path: LINKS[key]!, at: at - .1, gather: .14, strength: .62 * Math.pow(.8, depth), cool: .5, tone: tone(key.split(">")[0] as Id), into: { box: box(to), tone: tone(to) } }),
)

// Step 7: the deps' hashes go into the new entry's hash.
const HASH_AT = 21.5
const hashes: Shot[] = (["d3", "l1"] as const).map((dep, i) => ({
  key: `d4>${dep}`, kind: "hash", to: "d4", path: LINKS[`d4>${dep}`]!, reverse: true, at: HASH_AT + i * .12, label: ENTRIES[dep].label,
  tone: "ivory", strength: .85, into: { box: box("d4") },
}))
const hashed = Math.max(...hashes.map(s => timing(s).lands))
const SIGNED = hashed + .75

// Step 8: rewrite d1 and the break runs forward to everything that saw it.
const TAMPER_AT = 25.8, TAMPERED = TAMPER_AT + .5
const breaks = cascade([["d1", TAMPERED + .05]], dependents,
  (key, to, at, depth) => ({ key, kind: "break", to, path: LINKS[key]!, reverse: true, at, gather: depth ? .12 : .3, tone: "amber", strength: .9, into: { box: box(to), tone: "amber" } }))

const SHOTS: Shot[] = [{ ...consent, kind: "consent", to: "d2", label: "consent" }, ...sees, ...ripple, ...hashes, ...breaks]
const arrivals = Object.fromEntries(IDS.map(id => [id, SHOTS.filter(s => s.to === id && s.kind !== "consent").map(s => [timing(s).lands, s.strength ?? 1] as const)])) as Record<Id, (readonly [number, number])[]>
const brokenAt = Object.fromEntries(breaks.map(s => [s.to, timing(s).lands])) as Partial<Record<Id, number>>
brokenAt.d1 = TAMPERED

const DESKTOP_IMPULSES = [ENTRIES.d1.at, ENTRIES.d2.at, ENTRIES.d3.at, ENTRIES.d4.at, SIGNED]
const LAPTOP_IMPULSES = [consent.at, ENTRIES.l0.at, ENTRIES.l1.at]

const ALL_LINKS = Object.fromEntries(Object.keys(LINKS).map(key => [key, .35]))
const LOG_SOUNDS: SceneCue[] = [
  ...IDS.filter(id => ENTRIES[id].at > 0).flatMap((id): SceneCue[] => [
    { at: ENTRIES[id].at, cue: "write", detail: { pan: panX(ENTRIES[id].x, W) } },
    { at: ENTRIES[id].at + .24, cue: "seal", detail: { pan: panX(ENTRIES[id].x + EW / 2, W), gain: .75 } },
  ]),
  ...sees.map((s): SceneCue => ({ at: s.at, cue: "link", detail: { pan: panX(s.path.at(0)[0], W), gain: .7 } })),
  ...soundOfSend(consent, W, .8).cues,
  { at: SIGNED, cue: "seal", detail: { pan: panX(ENTRIES.d4.x + EW / 2, W) } },
  { at: TAMPERED, cue: "break", detail: { pan: panX(ENTRIES.d1.x, W) } },
]
const LOG_FLIGHTS = [consent, ...hashes].map(s => soundOfSend(s, W, .75).flight)

export const logsScene: StoryScene = {
  label: "Two devices (desktop and laptop) each append signed entries to their own log. Each entry points back at the entries its author had seen.",
  width: W, height: H, duration: 32.5, poster: 6,
  sounds: LOG_SOUNDS,
  flights: LOG_FLIGHTS,
  steps: [
    { at: 0, focus: { d0: 1, desktop: 1 },
      caption: { text: "the desktop creates the vault", anchor: top("d0"), place: [196, 58], align: "above", delay: 0 } },
    { at: 2.7, focus: { d1: 1, d0: .7, "d1>d0": 1, desktop: 1 },
      caption: { text: "each entry points back at what it saw", anchor: top("d1"), place: [304, 58], align: "above", delay: .5 } },
    { at: 5.8, focus: { d2: 1, d0: .7, "d2>d0": 1, d1: .18, "d1>d0": .1, laptop: 1, desktop: 1 },
      caption: { text: "the laptop signs consent, the desktop writes the add", anchor: top("d2"), place: [412, 48], align: "above", delay: 2.3 } },
    { at: 10, focus: { l0: 1, d1: .7, d2: .7, "l0>d1": 1, "l0>d2": 1, laptop: 1 },
      caption: { text: "the laptop's first entry has seen the add", anchor: bottom("l0"), place: [522, 352], align: "below", delay: .5 } },
    { at: 13.2, focus: { d3: 1, l1: 1, d1: .5, d2: .5, l0: .5, "d3>d1": .9, "d3>d2": .9, "l1>l0": .9, desktop: 1, laptop: 1 },
      caption: { text: "neither has seen the other", anchor: [640, 215], place: [676, 215], align: "start", delay: 1.4 } },
    { at: 16.8, focus: { ...ALL_LINKS, d0: .55, d1: .55, d2: .55, l0: .55, d3: .75, l1: .75, d4: 1, "d4>d3": 1, "d4>l1": 1, desktop: 1, laptop: 1 },
      caption: { text: "one entry sees both, and the logs rejoin", anchor: top("d4"), place: [780, 52], align: "end", delay: 1.2 } },
    { at: 21.3, focus: { d4: 1, d3: .6, l1: .6, "d4>d3": .8, "d4>l1": .8, desktop: 1 },
      caption: { text: "signed, over a hash of its deps", anchor: [ENTRIES.d4.x + EW / 2 + 4, LANE.desktop - 4], place: [826, 64], align: "end", delay: SIGNED - 21.3 - .2 } },
    { at: 25.6, focus: { d1: 1, l0: .7, d3: .7, l1: .7, d4: .7, d0: .2, d2: .2, "d3>d1": .55, "l0>d1": .55, "l1>l0": .55, "d4>d3": .55, "d4>l1": .55 },
      caption: { text: "rewrite one, and everything that saw it breaks", anchor: top("d1"), place: [304, 44], align: "above", delay: .4 } },
  ],
  draw: (t, light, story) => {
    logsLights(t, light)
    return <Logs t={t} light={light} story={story} />
  },
}

function logsLights(t: number, light: Light) {
  for (const shot of SHOTS) send(light, shot, t)
  for (const key of Object.keys(LINKS)) {
    const see = SHOTS.find(s => s.kind === "see" && s.key === key)!
    drawOn(light, LINKS[key]!, t, see.at, .55, ENTRIES[key.split(">")[0] as Id].membership ? "red" : "ivory", .6)
  }
  for (const id of IDS) {
    const e = ENTRIES[id], y = LANE[e.lane], age = t - e.at
    if (age < 0) continue
    const red = e.membership
    // The seal: the author's signature, stamped on the right edge once the entry is written.
    const seal: readonly [number, number] = [e.x + EW / 2, y]
    if (e.at > 0 && age < 1.6) spark(light, seal, age - .3, red ? "red" : "hot", .7)
    if (id === "d4") spark(light, seal, t - SIGNED, "hot", 1)
    if (brokenAt[id] !== undefined) spark(light, seal, t - brokenAt[id]!, "amber", .8)
    if (e.at > 0) flood(light, box(id), [e.x, y], age, red ? "red" : "ivory", .55, .9)
    light.frames.push(box(id))
  }
}

/** Light in an entry's ink: hot-stamp flash when written, then filament cooling each time light lands in it. */
function heat(id: Id, t: number) {
  const e = ENTRIES[id]
  const written = e.at === 0 ? 0 : inkFlash(t - e.at)
  return Math.min(1, Math.max(written, ...arrivals[id].map(([at, k]) => flashes(t, [at], 1.2) * Math.min(1, k * 1.2))))
}

function Card({ id, t, story, light }: { id: Id; t: number; story: StoryApi; light: Light }) {
  const e = ENTRIES[id], y = LANE[e.lane], age = t - e.at
  if (age < 0) return null
  // First entry rests on first paint; later entries settle in on a calm zero-bounce spring.
  const appear = e.at === 0 ? 1 : clamp01(age / .16)
  const scale = e.at === 0 ? 1 : 1.036 - .036 * springAt(age, springs.calm)
  const level = story.focus(t, id), lit = clamp01((level - .32) / .68), dim = clamp01((.32 - level) / .32) * .6
  const hot = heat(id, t)
  const broken = brokenAt[id] === undefined ? 0 : span(t, brokenAt[id]!, brokenAt[id]! + .3)
  const red = e.membership
  const frame = shade(red ? "#5a1c1c" : "#383838", [red ? "#ff2a2a" : "#a8a49c", lit], ["#000000", dim], ["#ffb347", broken * .85], [red ? "#ff6a4a" : "#fff1dc", hot * .8])
  const ink = shade(red ? "#8a2a2a" : "#6a6a6a", [red ? "#ff4a3a" : "#e8e4dc", lit], ["#000000", dim], ["#ffb347", broken * .9], ["#fff1dc", hot * .9])

  let label = e.label
  if (id === "d4") label = working(e.label, t, hashed - .05, hashed + .45, 4) ?? label
  if (id === "d1") label = working("d07e", t, TAMPER_AT, TAMPERED, 9) ?? label

  // The seal: the author's signature, stamped on the right edge once the entry is written (its spark is in logsLights).
  const sealAge = e.at === 0 ? 99 : age - .24
  const sealScale = sealAge < 0 ? 0 : e.at === 0 ? 1 : 1.65 - .65 * springAt(sealAge, springs.snappy)

  const [x0, y0] = box(id)
  return <g opacity={appear} transform={scale === 1 ? undefined : `translate(${e.x} ${y}) scale(${scale}) translate(${-e.x} ${-y})`}>
    <rect x={x0 + .5} y={y0 + .5} width={EW - 1} height={EH - 1} fill="#050505" stroke={frame} />
    <rect x={x0 + 3.5} y={y0 + 3.5} width={EW - 7} height={EH - 7} fill="none" stroke={shade("#262626", ["#000000", dim])} />
    <BorderLight light={light} box={box(id)} />
    <text x={e.x} y={y + .5} textAnchor="middle" dominantBaseline="middle" className="story-entry" fill={ink}>{label}</text>
    {sealScale > 0 && <rect x={-3.6} y={-3.6} width={7.2} height={7.2} fill={shade(red ? "#ff2a2a" : "#c8231f", ["#000000", dim * .6], ["#000000", broken])}
      stroke={shade("#000000", ["#ffb347", broken])} strokeWidth={1.5 - .3 * broken}
      transform={`translate(${e.x + EW / 2} ${y}) rotate(45) scale(${sealScale})`} opacity={e.at === 0 ? 1 : clamp01(sealAge / .08)} />}
  </g>
}

function Link({ id, t, story }: { id: string; t: number; story: StoryApi }) {
  const see = SHOTS.find(s => s.kind === "see" && s.key === id)!
  const path = LINKS[id]!
  const red = ENTRIES[id.split(">")[0] as Id].membership
  const drawn = drawProgress(t, see.at, .55)
  if (drawn <= 0) return null
  const level = story.focus(t, id, .2), lit = clamp01((level - .2) / .8)
  const stroke = shade(red ? "#3a1414" : "#262626", [red ? "#c4302a" : "#8d8a84", lit])
  const crack = SHOTS.find(s => s.kind === "break" && s.key === id)
  const broken = crack ? travelled(crack, t) : 0
  return <>
    <path d={path.d} fill="none" stroke={stroke} pathLength={1} strokeDasharray={`${drawn} 2`} />
    {broken > 0 && <path d={path.d} fill="none" stroke="#ffb347" strokeOpacity={.4 + .45 * lit} pathLength={1} strokeDasharray={`${broken} 2`} strokeDashoffset={broken - 1} />}
  </>
}

function Lanes({ t, story }: { t: number; story: StoryApi }) {
  return <>{(Object.keys(LANE) as Lane[]).map(lane => {
    const age = lane === "desktop" ? 99 : t - 5.8
    if (age < 0) return null
    const appear = lane === "desktop" ? 1 : springAt(age, springs.calm)
    const lit = clamp01((story.focus(t, lane, .5) - .5) / .5)
    const ink = shade("#626262", ["#e8e4dc", lit])
    const impulses = lane === "desktop" ? DESKTOP_IMPULSES : LAPTOP_IMPULSES
    return <g key={lane} opacity={appear}>
      <line x1={124} x2={124 + (W - 154) * appear} y1={LANE[lane]} y2={LANE[lane]} stroke="#1f1f1f" strokeDasharray="1 5" />
      <DeviceGlyph kind={GLYPH[lane]} cx={32} cy={LANE[lane]} t={t} impulses={impulses} stroke={ink} />
      <text x={48} y={LANE[lane] + .5} dominantBaseline="middle" className="story-lane" fill={ink}>{lane}</text>
    </g>
  })}</>
}

function Logs({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  return <>
    <Lanes t={t} story={story} />
    {Object.keys(LINKS).map(id => <Link key={id} id={id} t={t} story={story} />)}
    {IDS.map(id => <Card key={id} id={id} t={t} story={story} light={light} />)}
    {SHOTS.map((shot, i) => <Carried key={i} shot={shot} t={t} label={shot.label} />)}
  </>
}

export function LogsStory() {
  return <Story scene={logsScene} />
}
