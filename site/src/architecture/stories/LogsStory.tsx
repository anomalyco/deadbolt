import type { Light, Tone } from "../../story/light"
import { between, bridge, drawOn, flood, send, spark, timing, travelled, type Path, type Send } from "../../story/beats"
import { Carried, Solid, type DeviceKind } from "../../story/devices"
import { clamp01, flashes, inkFlash, shade, span, springAt, springs, working, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// Two devices (cube and pyramid), one log each. An entry is a card; when it's written, light runs back along its
// deps to the entries its author had seen, and they light up as it lands. Membership entries (red) only ever point
// at membership. The pyramid gets in through the cube's add, which carries its signed consent; its first entry
// points at that add. Later, rewriting one entry breaks every entry that saw it.

const W = 940, H = 400
const LANE = { cube: 140, pyramid: 290 } as const
type Lane = keyof typeof LANE
const GLYPH: Record<Lane, DeviceKind> = { cube: "cube", pyramid: "pyramid" }
const EW = 68, EH = 30

type Id = "c0" | "c1" | "c2" | "p0" | "c3" | "p1" | "c4"
type Entry = { lane: Lane; x: number; label: string; deps: Id[]; membership?: boolean; at: number }

const consent: Send = {
  path: between([112, LANE.pyramid], [410, LANE.cube + EH / 2], .5),
  at: 6.3, tone: "ivory", strength: .85,
}

const ENTRIES: Record<Id, Entry> = {
  c0: { lane: "cube", x: 196, label: "create", deps: [], membership: true, at: 0 },
  c1: { lane: "cube", x: 304, label: "3f9a", deps: ["c0"], at: 3 },
  c2: { lane: "cube", x: 412, label: "add", deps: ["c0"], membership: true, at: timing(consent).lands },
  p0: { lane: "pyramid", x: 522, label: "c41e", deps: ["c1", "c2"], at: 10.3 },
  c3: { lane: "cube", x: 640, label: "7b20", deps: ["c1", "c2"], at: 13.5 },
  p1: { lane: "pyramid", x: 640, label: "e95d", deps: ["p0"], at: 13.7 },
  c4: { lane: "cube", x: 780, label: "1a6c", deps: ["c3", "p1"], at: 17.1 },
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
  "c1>c0": link(top("c1", -14), top("c0", 16), 1),
  "c2>c0": link(top("c2", -14), top("c0", 4), 1),
  "p0>c1": between(top("p0", -12), bottom("c1")),
  "p0>c2": between(top("p0"), bottom("c2")),
  "c3>c2": link(top("c3", -18), top("c2", 14), 1),
  "c3>c1": link(top("c3", -6), top("c1", 14), 1),
  "p1>p0": link(bottom("p1", -14), bottom("p0", 8), -1),
  "c4>c3": link(top("c4", -14), top("c3", 16), 1),
  "c4>p1": between(bottom("c4", -8), top("p1", 14)),
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
  sees.filter(s => s.key?.startsWith("c4>")).map(s => [s.to, timing(s).lands] as [Id, number]),
  linkKeys,
  (key, to, at, depth) => ({ key, kind: "ripple", to, path: LINKS[key]!, at: at - .1, gather: .14, strength: .62 * Math.pow(.8, depth), cool: .5, tone: tone(key.split(">")[0] as Id), into: { box: box(to), tone: tone(to) } }),
)

// Step 7: the deps' hashes go into the new entry's hash.
const HASH_AT = 21.5
const hashes: Shot[] = (["c3", "p1"] as const).map((dep, i) => ({
  key: `c4>${dep}`, kind: "hash", to: "c4", path: LINKS[`c4>${dep}`]!, reverse: true, at: HASH_AT + i * .12, label: ENTRIES[dep].label,
  tone: "ivory", strength: .85, into: { box: box("c4") },
}))
const hashed = Math.max(...hashes.map(s => timing(s).lands))
const SIGNED = hashed + .75

// Step 8: rewrite c1 and the break runs forward to everything that saw it.
const TAMPER_AT = 25.8, TAMPERED = TAMPER_AT + .5
const breaks = cascade([["c1", TAMPERED + .05]], dependents,
  (key, to, at, depth) => ({ key, kind: "break", to, path: LINKS[key]!, reverse: true, at, gather: depth ? .12 : .3, tone: "amber", strength: .9, into: { box: box(to), tone: "amber" } }))

const SHOTS: Shot[] = [{ ...consent, kind: "consent", to: "c2", label: "consent" }, ...sees, ...ripple, ...hashes, ...breaks]
const arrivals = Object.fromEntries(IDS.map(id => [id, SHOTS.filter(s => s.to === id && s.kind !== "consent").map(s => [timing(s).lands, s.strength ?? 1] as const)])) as Record<Id, (readonly [number, number])[]>
const brokenAt = Object.fromEntries(breaks.map(s => [s.to, timing(s).lands])) as Partial<Record<Id, number>>
brokenAt.c1 = TAMPERED

const CUBE_IMPULSES = [ENTRIES.c1.at, ENTRIES.c2.at, ENTRIES.c3.at, ENTRIES.c4.at, SIGNED]
const PYRAMID_IMPULSES = [consent.at, ENTRIES.p0.at, ENTRIES.p1.at]

const ALL_LINKS = Object.fromEntries(Object.keys(LINKS).map(key => [key, .35]))
export const logsScene: StoryScene = {
  label: "Two devices (cube and pyramid) each append signed entries to their own log. Each entry points back at the entries its author had seen.",
  width: W, height: H, duration: 32.5, poster: 6,
  steps: [
    { at: 0, focus: { c0: 1, cube: 1 },
      caption: { text: "the cube creates the vault", anchor: top("c0"), place: [196, 58], align: "above", delay: 0 } },
    { at: 2.7, focus: { c1: 1, c0: .7, "c1>c0": 1, cube: 1 },
      caption: { text: "each entry points back at what it saw", anchor: top("c1"), place: [304, 58], align: "above", delay: .5 } },
    { at: 5.8, focus: { c2: 1, c0: .7, "c2>c0": 1, c1: .18, "c1>c0": .1, pyramid: 1, cube: 1 },
      caption: { text: "the pyramid signs consent, the cube writes the add", anchor: top("c2"), place: [412, 48], align: "above", delay: 2.3 } },
    { at: 10, focus: { p0: 1, c1: .7, c2: .7, "p0>c1": 1, "p0>c2": 1, pyramid: 1 },
      caption: { text: "the pyramid's first entry has seen the add", anchor: bottom("p0"), place: [522, 352], align: "below", delay: .5 } },
    { at: 13.2, focus: { c3: 1, p1: 1, c1: .5, c2: .5, p0: .5, "c3>c1": .9, "c3>c2": .9, "p1>p0": .9, cube: 1, pyramid: 1 },
      caption: { text: "neither has seen the other", anchor: [640, 215], place: [676, 215], align: "start", delay: 1.4 } },
    { at: 16.8, focus: { ...ALL_LINKS, c0: .55, c1: .55, c2: .55, p0: .55, c3: .75, p1: .75, c4: 1, "c4>c3": 1, "c4>p1": 1, cube: 1, pyramid: 1 },
      caption: { text: "one entry sees both, and the logs rejoin", anchor: top("c4"), place: [780, 52], align: "end", delay: 1.2 } },
    { at: 21.3, focus: { c4: 1, c3: .6, p1: .6, "c4>c3": .8, "c4>p1": .8, cube: 1 },
      caption: { text: "signed, over a hash of its deps", anchor: [ENTRIES.c4.x + EW / 2 + 4, LANE.cube - 4], place: [826, 64], align: "end", delay: SIGNED - 21.3 - .2 } },
    { at: 25.6, focus: { c1: 1, p0: .7, c3: .7, p1: .7, c4: .7, c0: .2, c2: .2, "c3>c1": .55, "p0>c1": .55, "p1>p0": .55, "c4>c3": .55, "c4>p1": .55 },
      caption: { text: "rewrite one, and everything that saw it breaks", anchor: top("c1"), place: [304, 44], align: "above", delay: .4 } },
  ],
  draw: (t, light, story) => <Logs t={t} light={light} story={story} />,
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
  if (id === "c4") label = working(e.label, t, hashed - .05, hashed + .45, 4) ?? label
  if (id === "c1") label = working("d07e", t, TAMPER_AT, TAMPERED, 9) ?? label

  // The seal: the author's signature, stamped on the right edge once the entry is written.
  const sealAge = e.at === 0 ? 99 : age - .24
  const sealScale = sealAge < 0 ? 0 : e.at === 0 ? 1 : 1.65 - .65 * springAt(sealAge, springs.snappy)
  const seal: readonly [number, number] = [e.x + EW / 2, y]
  if (e.at > 0 && age < 1.6) spark(light, seal, sealAge - .06, red ? "red" : "hot", .7)
  if (id === "c4") spark(light, seal, t - SIGNED, "hot", 1)
  if (brokenAt[id] !== undefined) spark(light, seal, t - brokenAt[id]!, "amber", .8)
  if (e.at > 0) flood(light, box(id), [e.x, y], age, red ? "red" : "ivory", .55, .9)
  light.frames.push(box(id))

  return <g opacity={appear} transform={`translate(${e.x} ${y}) scale(${scale})`}>
    <rect x={-EW / 2 + .5} y={-EH / 2 + .5} width={EW - 1} height={EH - 1} fill="#050505" stroke={frame} />
    <rect x={-EW / 2 + 3.5} y={-EH / 2 + 3.5} width={EW - 7} height={EH - 7} fill="none" stroke={shade("#262626", ["#000000", dim])} />
    <text y={.5} textAnchor="middle" dominantBaseline="middle" className="story-entry" fill={ink}>{label}</text>
    {sealScale > 0 && <rect x={-3.6} y={-3.6} width={7.2} height={7.2} fill={broken ? "#000" : shade(red ? "#ff2a2a" : "#c8231f", ["#000000", dim * .6])}
      stroke={broken ? shade("#000000", ["#ffb347", broken]) : "#000"} strokeWidth={broken ? 1.2 : 1.5}
      transform={`translate(${EW / 2} 0) rotate(45) scale(${sealScale})`} opacity={e.at === 0 ? 1 : clamp01(sealAge / .08)} />}
  </g>
}

function Link({ id, t, story, light }: { id: string; t: number; story: StoryApi; light: Light }) {
  const see = SHOTS.find(s => s.kind === "see" && s.key === id)!
  const path = LINKS[id]!
  const red = ENTRIES[id.split(">")[0] as Id].membership
  const drawn = drawOn(light, path, t, see.at, .55, red ? "red" : "ivory", .6)
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
    const age = lane === "cube" ? 99 : t - 5.8
    if (age < 0) return null
    const appear = lane === "cube" ? 1 : springAt(age, springs.calm)
    const lit = clamp01((story.focus(t, lane, .5) - .5) / .5)
    const ink = shade("#626262", ["#e8e4dc", lit])
    const impulses = lane === "cube" ? CUBE_IMPULSES : PYRAMID_IMPULSES
    return <g key={lane} opacity={appear}>
      <line x1={124} x2={124 + (W - 154) * appear} y1={LANE[lane]} y2={LANE[lane]} stroke="#1f1f1f" strokeDasharray="1 5" />
      <Solid kind={GLYPH[lane]} cx={32} cy={LANE[lane]} r={7.8} t={t} impulses={impulses} stroke={ink} reduced={story.reduced} />
      <text x={48} y={LANE[lane] + .5} dominantBaseline="middle" className="story-lane" fill={ink}>{lane}</text>
    </g>
  })}</>
}

function Logs({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  for (const shot of SHOTS) send(light, shot, t)
  return <>
    <Lanes t={t} story={story} />
    {Object.keys(LINKS).map(id => <Link key={id} id={id} t={t} story={story} light={light} />)}
    {IDS.map(id => <Card key={id} id={id} t={t} story={story} light={light} />)}
    {SHOTS.map((shot, i) => <Carried key={i} shot={shot} t={t} label={shot.label} />)}
  </>
}

export function LogsStory() {
  return <Story scene={logsScene} />
}
