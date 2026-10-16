import type { Light, Tone } from "../../story/light"
import { between, bridge, flood, send, spark, timing, travelled, type Path, type Send } from "../../story/beats"
import { clamp01, flashes, shade, span, springAt, springs, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// Two devices, one log each. An entry is a card; when it's written, light runs back along its deps to the
// entries its author had seen, and they light up as it lands. Membership entries (red) only ever point at
// membership. The pro gets in through studio's add, which carries its signed consent; its first entry points at
// that add. Later, rewriting one entry breaks every entry that saw it.

const W = 940, H = 400
const LANE = { studio: 140, pro: 290 } as const
type Lane = keyof typeof LANE
const EW = 64, EH = 30

type Id = "s0" | "s1" | "s2" | "p0" | "s3" | "p1" | "s4"
type Entry = { lane: Lane; x: number; label: string; deps: Id[]; membership?: boolean; at: number }

const consent: Send = {
  path: between([92, LANE.pro], [410, LANE.studio + EH / 2], .5),
  at: 6.3, tone: "ivory", strength: .8,
}

const ENTRIES: Record<Id, Entry> = {
  s0: { lane: "studio", x: 190, label: "create", deps: [], membership: true, at: .5 },
  s1: { lane: "studio", x: 300, label: "3f9a", deps: ["s0"], at: 3 },
  s2: { lane: "studio", x: 410, label: "add pro", deps: ["s0"], membership: true, at: timing(consent).lands },
  p0: { lane: "pro", x: 520, label: "c41e", deps: ["s1", "s2"], at: 10.3 },
  s3: { lane: "studio", x: 640, label: "7b20", deps: ["s1", "s2"], at: 13.5 },
  p1: { lane: "pro", x: 640, label: "e95d", deps: ["p0"], at: 13.7 },
  s4: { lane: "studio", x: 780, label: "1a6c", deps: ["s3", "p1"], at: 17.1 },
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
  "s1>s0": link(top("s1", -14), top("s0", 16), 1),
  "s2>s0": link(top("s2", -14), top("s0", 4), 1),
  "p0>s1": between(top("p0", -12), bottom("s1")),
  "p0>s2": between(top("p0"), bottom("s2")),
  "s3>s2": link(top("s3", -18), top("s2", 14), 1),
  "s3>s1": link(top("s3", -6), top("s1", 14), 1),
  "p1>p0": link(bottom("p1", -14), bottom("p0", 8), -1),
  "s4>s3": link(top("s4", -14), top("s3", 16), 1),
  "s4>p1": between(bottom("s4", -8), top("p1", 14)),
}
const linkKeys = (id: Id) => ENTRIES[id].deps.map(dep => [`${id}>${dep}`, dep] as const)
const dependents = (id: Id) => IDS.filter(other => ENTRIES[other].deps.includes(id)).map(other => [`${other}>${id}`, other] as const)

type Shot = Send & { key?: string; to: Id; kind: "see" | "ripple" | "hash" | "break" | "consent"; label?: string }

// When an entry is written, its light runs back to every dep.
const sees: Shot[] = IDS.flatMap(id => linkKeys(id).map(([key, dep]) => ({
  key, kind: "see" as const, to: dep, path: LINKS[key]!, at: ENTRIES[id].at + .4, tone: tone(id), into: { box: box(dep), tone: tone(dep) },
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
  sees.filter(s => s.key?.startsWith("s4>")).map(s => [s.to, timing(s).lands] as [Id, number]),
  linkKeys,
  (key, to, at, depth) => ({ key, kind: "ripple", to, path: LINKS[key]!, at: at - .1, gather: .14, strength: .62 * Math.pow(.8, depth), cool: .5, tone: tone(key.split(">")[0] as Id), into: { box: box(to), tone: tone(to) } }),
)

// Step 7: the deps' hashes go into the new entry's hash.
const HASH_AT = 21.5
const hashes: Shot[] = (["s3", "p1"] as const).map((dep, i) => ({
  key: `s4>${dep}`, kind: "hash", to: "s4", path: LINKS[`s4>${dep}`]!, reverse: true, at: HASH_AT + i * .12, label: ENTRIES[dep].label,
  tone: "ivory", strength: .85, into: { box: box("s4") },
}))
const hashed = Math.max(...hashes.map(s => timing(s).lands))
const SIGNED = hashed + .75

// Step 8: rewrite s1 and the break runs forward to everything that saw it.
const TAMPER_AT = 25.8, TAMPERED = TAMPER_AT + .5
const breaks = cascade([["s1", TAMPERED + .05]], dependents,
  (key, to, at, depth) => ({ key, kind: "break", to, path: LINKS[key]!, reverse: true, at, gather: depth ? .12 : .3, tone: "amber", strength: .9, into: { box: box(to), tone: "amber" } }))

const SHOTS: Shot[] = [{ ...consent, kind: "consent", to: "s2", label: "consent" }, ...sees, ...ripple, ...hashes, ...breaks]
const arrivals = Object.fromEntries(IDS.map(id => [id, SHOTS.filter(s => s.to === id && s.kind !== "consent").map(s => [timing(s).lands, s.strength ?? 1] as const)])) as Record<Id, (readonly [number, number])[]>
const brokenAt = Object.fromEntries(breaks.map(s => [s.to, timing(s).lands])) as Partial<Record<Id, number>>
brokenAt.s1 = TAMPERED

const ALL_LINKS = Object.fromEntries(Object.keys(LINKS).map(key => [key, .35]))
export const logsScene: StoryScene = {
  label: "Two devices each append signed entries to their own log. Each entry points back at the entries its author had seen.",
  width: W, height: H, duration: 32.5, poster: 6,
  steps: [
    { at: 0, focus: { s0: 1, studio: 1 },
      caption: { text: "studio creates the vault", anchor: top("s0"), place: [190, 58], align: "above", delay: .6 } },
    { at: 2.7, focus: { s1: 1, s0: .7, "s1>s0": 1, studio: 1 },
      caption: { text: "each entry points back at what it saw", anchor: top("s1"), place: [300, 58], align: "above", delay: .5 } },
    { at: 5.8, focus: { s2: 1, s0: .7, "s2>s0": 1, s1: .18, "s1>s0": .1, pro: 1, studio: 1 },
      caption: { text: "the pro signs consent, studio writes the add", anchor: top("s2"), place: [410, 48], align: "above", delay: 2.3 } },
    { at: 10, focus: { p0: 1, s1: .7, s2: .7, "p0>s1": 1, "p0>s2": 1, pro: 1 },
      caption: { text: "the pro's first entry has seen the add", anchor: bottom("p0"), place: [520, 352], align: "below", delay: .5 } },
    { at: 13.2, focus: { s3: 1, p1: 1, s1: .5, s2: .5, p0: .5, "s3>s1": .9, "s3>s2": .9, "p1>p0": .9, studio: 1, pro: 1 },
      caption: { text: "neither has seen the other", anchor: [640, 215], place: [676, 215], align: "start", delay: 1.4 } },
    { at: 16.8, focus: { ...ALL_LINKS, s0: .55, s1: .55, s2: .55, p0: .55, s3: .75, p1: .75, s4: 1, "s4>s3": 1, "s4>p1": 1, studio: 1, pro: 1 },
      caption: { text: "one entry sees both, and the logs rejoin", anchor: top("s4"), place: [780, 52], align: "end", delay: 1.2 } },
    { at: 21.3, focus: { s4: 1, s3: .6, p1: .6, "s4>s3": .8, "s4>p1": .8 },
      caption: { text: "signed, over a hash of its deps", anchor: [ENTRIES.s4.x + EW / 2 + 4, LANE.studio - 4], place: [826, 64], align: "end", delay: SIGNED - 21.3 - .2 } },
    { at: 25.6, focus: { s1: 1, p0: .7, s3: .7, p1: .7, s4: .7, s0: .2, s2: .2, "s3>s1": .55, "p0>s1": .55, "p1>p0": .55, "s4>s3": .55, "s4>p1": .55 },
      caption: { text: "rewrite one, and everything that saw it breaks", anchor: top("s1"), place: [300, 44], align: "above", delay: .4 } },
  ],
  draw: (t, light, story) => <Logs t={t} light={light} story={story} />,
}

const HEX = "0123456789abcdef"
const noise = (n: number) => { const x = Math.sin(n * 91.345) * 47453.5453; return x - Math.floor(x) }
/** A hash being worked out: characters settle left to right between `from` and `to`. */
function working(final: string, t: number, from: number, to: number, seed: number) {
  if (t < from) return null
  return [...final].map((c, i) => t >= from + (to - from) * (i + 1) / final.length ? c : HEX[Math.floor(noise(Math.floor(t * 30) * 13 + i * 7 + seed) * 16)]).join("")
}

/** Light in an entry's ink: the settle-in flash when it's written, then a flash each time light lands in it. */
function heat(id: Id, t: number) {
  const age = t - ENTRIES[id].at
  const written = age < 0 ? 0 : Math.exp(-age / .234) * (1 - Math.min(1, Math.pow(age / .75, 2)))
  return Math.min(1, Math.max(written, ...arrivals[id].map(([at, k]) => flashes(t, [at], 1.2) * Math.min(1, k * 1.2))))
}

function Card({ id, t, story, light }: { id: Id; t: number; story: StoryApi; light: Light }) {
  const e = ENTRIES[id], y = LANE[e.lane], age = t - e.at
  if (age < 0) return null
  const appear = clamp01(age / .18), scale = 1.04 - .04 * springAt(age, springs.calm)
  const level = story.focus(t, id), lit = clamp01((level - .32) / .68), dim = clamp01((.32 - level) / .32) * .6
  const hot = heat(id, t)
  const broken = brokenAt[id] === undefined ? 0 : span(t, brokenAt[id]!, brokenAt[id]! + .3)
  const red = e.membership
  const frame = shade(red ? "#5a1c1c" : "#383838", [red ? "#ff2a2a" : "#a8a49c", lit], ["#000000", dim], ["#ffb347", broken * .85], [red ? "#ff6a4a" : "#fff1dc", hot * .8])
  const ink = shade(red ? "#8a2a2a" : "#6a6a6a", [red ? "#ff4a3a" : "#e8e4dc", lit], ["#000000", dim], ["#ffb347", broken * .9], ["#fff1dc", hot * .9])

  let label = e.label
  if (id === "s4") label = working(e.label, t, hashed - .05, hashed + .45, 4) ?? label
  if (id === "s1") label = working("d07e", t, TAMPER_AT, TAMPERED, 9) ?? label

  // The seal: the author's signature, stamped on the right edge once the entry is written.
  const sealAge = age - .25
  const sealScale = sealAge < 0 ? 0 : 1.7 - .7 * springAt(sealAge, springs.snappy)
  const seal: readonly [number, number] = [e.x + EW / 2, y]
  if (age < 1.6) spark(light, seal, sealAge - .08, red ? "red" : "hot", .7)
  if (id === "s4") spark(light, seal, t - SIGNED, "hot", 1)
  if (brokenAt[id] !== undefined) spark(light, seal, t - brokenAt[id]!, "amber", .8)
  // Light it was written in.
  flood(light, box(id), [e.x, y], age, red ? "red" : "ivory", .55, .9)
  light.frames.push(box(id))

  return <g opacity={appear} transform={`translate(${e.x} ${y}) scale(${scale})`}>
    <rect x={-EW / 2 + .5} y={-EH / 2 + .5} width={EW - 1} height={EH - 1} fill="#000" stroke={frame} />
    <rect x={-EW / 2 + 3.5} y={-EH / 2 + 3.5} width={EW - 7} height={EH - 7} fill="none" stroke={shade("#262626", ["#000000", dim])} />
    <text y={.5} textAnchor="middle" dominantBaseline="middle" className="story-entry" fill={ink}>{label}</text>
    {sealScale > 0 && <rect x={-3.6} y={-3.6} width={7.2} height={7.2} fill={broken ? "#000" : shade(red ? "#ff2a2a" : "#c8231f", ["#000000", dim * .6])}
      stroke={broken ? shade("#000000", ["#ffb347", broken]) : "#000"} strokeWidth={broken ? 1.2 : 1.5}
      transform={`translate(${EW / 2} 0) rotate(45) scale(${sealScale})`} opacity={clamp01(sealAge / .08)} />}
  </g>
}

function Link({ id, t, story }: { id: string; t: number; story: StoryApi }) {
  const see = SHOTS.find(s => s.kind === "see" && s.key === id)!
  const drawn = travelled(see, t)
  if (drawn <= 0) return null
  const path = LINKS[id]!
  const level = story.focus(t, id, .2), lit = clamp01((level - .2) / .8)
  const red = ENTRIES[id.split(">")[0] as Id].membership
  const stroke = shade(red ? "#3a1414" : "#262626", [red ? "#c4302a" : "#8d8a84", lit])
  const crack = SHOTS.find(s => s.kind === "break" && s.key === id)
  const broken = crack ? travelled(crack, t) : 0
  return <>
    <path d={path.d} fill="none" stroke={stroke} pathLength={1} strokeDasharray={`${drawn} 2`} />
    {broken > 0 && <path d={path.d} fill="none" stroke="#ffb347" strokeOpacity={.35 + .4 * lit} pathLength={1} strokeDasharray={`${broken} 2`} strokeDashoffset={broken - 1} />}
  </>
}

function Lanes({ t, story }: { t: number; story: StoryApi }) {
  return <>{(Object.keys(LANE) as Lane[]).map(lane => {
    const appear = lane === "studio" ? 1 : span(t, 5.8, 6.3)
    if (appear <= 0) return null
    const lit = clamp01((story.focus(t, lane, .5) - .5) / .5)
    return <g key={lane} opacity={appear}>
      <line x1={112} x2={W - 30} y1={LANE[lane]} y2={LANE[lane]} stroke="#1c1c1c" strokeDasharray="1 5" />
      <text x={48} y={LANE[lane]} dominantBaseline="middle" className="story-lane" fill={shade("#5e5e5e", ["#cfcac1", lit])}>{lane}</text>
    </g>
  })}</>
}

/** Words riding a head: the consent on its way to studio, the deps' hashes on their way into the new hash. */
function Carried({ shot, t }: { shot: Shot; t: number }) {
  const { launch, lands } = timing(shot)
  if (!shot.label || t < launch - .1 || t > lands + .3) return null
  const f = travelled(shot, t), [x, y] = shot.path.at(shot.reverse ? 1 - f : f)
  const opacity = Math.min(span(t, launch - .1, launch + .15), 1 - span(t, lands - .1, lands + .2))
  return <text x={x} y={y - 10} textAnchor="middle" className="story-carried" fill="#e8e4dc" opacity={opacity}>{shot.label}</text>
}

function Logs({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  for (const shot of SHOTS) send(light, shot, t)
  return <>
    <Lanes t={t} story={story} />
    {Object.keys(LINKS).map(id => <Link key={id} id={id} t={t} story={story} />)}
    {IDS.map(id => <Card key={id} id={id} t={t} story={story} light={light} />)}
    {SHOTS.map((shot, i) => <Carried key={i} shot={shot} t={t} />)}
  </>
}

export function LogsStory() {
  return <Story scene={logsScene} />
}
