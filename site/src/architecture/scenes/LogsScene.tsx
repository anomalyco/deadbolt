import { motion, useTransform } from "motion/react"
import { Scene } from "../../scene/Scene"
import { Note, Wire, clamp01, ink, type Clock } from "../../scene/kit"

// Three devices, three logs. Each square is an entry; lines point back at the entries its author had seen.
// Red squares are membership entries, ivory are data.

const LANES = { studio: 70, pro: 150, laptop: 230 } as const
type Lane = keyof typeof LANES
type Entry = { id: string; lane: Lane; x: number; at: number; deps: string[]; membership?: boolean; tag?: string }

// Membership entries only ever depend on membership entries, so the membership graph can always sync first.
// A device is admitted by an Add the inviting member writes (carrying the newcomer's signed consent).
const ENTRIES: Entry[] = [
  { id: "s0", lane: "studio", x: 160, at: .3, deps: [], membership: true, tag: "create" },
  { id: "s1", lane: "studio", x: 230, at: 1.4, deps: ["s0"] },
  { id: "s2", lane: "studio", x: 300, at: 2.6, deps: ["s0"], membership: true, tag: "add pro" },
  { id: "p0", lane: "pro", x: 370, at: 3.6, deps: ["s1", "s2"] },
  { id: "s3", lane: "studio", x: 430, at: 4.6, deps: ["s1"] },
  { id: "p1", lane: "pro", x: 450, at: 4.8, deps: ["p0"] },
  { id: "s4", lane: "studio", x: 530, at: 6.2, deps: ["s3", "p1"] },
  { id: "s5", lane: "studio", x: 600, at: 7.4, deps: ["s2"], membership: true, tag: "add laptop" },
  { id: "l0", lane: "laptop", x: 660, at: 8.6, deps: ["s4", "s5"] },
  { id: "p2", lane: "pro", x: 710, at: 9.8, deps: ["p1", "l0"] },
]
const byId = Object.fromEntries(ENTRIES.map(e => [e.id, e]))
const S = 22

function Arrow({ clock, from, to }: { clock: Clock; from: Entry; to: Entry }) {
  const x1 = from.x - S / 2, y1 = LANES[from.lane], x2 = to.x + S / 2, y2 = LANES[to.lane]
  const length = Math.hypot(x2 - x1, y2 - y1)
  const offset = useTransform(clock, t => length * (1 - clamp01((t - from.at) / .5)))
  const opacity = useTransform(clock, t => (t < from.at ? 0 : .55))
  return <motion.line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#8d8d8d" strokeDasharray={length} style={{ strokeDashoffset: offset, opacity }} />
}

function Square({ clock, entry }: { clock: Clock; entry: Entry }) {
  const opacity = useTransform(clock, t => clamp01((t - entry.at) / .25))
  const scale = useTransform(clock, t => t < entry.at ? .4 : 1 + .5 * Math.pow(1 - clamp01((t - entry.at) / .6), 2))
  const color = entry.membership ? ink.red : ink.light
  const y = LANES[entry.lane]
  return <motion.g style={{ opacity }}>
    <motion.rect x={entry.x - S / 2} y={y - S / 2} width={S} height={S} fill="#000" stroke={color} style={{ scale, originX: `${entry.x}px`, originY: `${y}px` }} />
    {entry.tag && <text x={entry.x} y={y - 18} textAnchor="middle" className="scene-packet" fill={color}>{entry.tag}</text>}
  </motion.g>
}

function Logs({ clock }: { clock: Clock }) {
  return <>
    {(Object.keys(LANES) as Lane[]).map(lane => <g key={lane}>
      <Wire points={[[120, LANES[lane]], [740, LANES[lane]]]} />
      <Note x={20} y={LANES[lane] + 4} tone="label">{lane}</Note>
    </g>)}
    {ENTRIES.flatMap(entry => entry.deps.map(dep => <Arrow key={`${entry.id}-${dep}`} clock={clock} from={entry} to={byId[dep]!} />))}
    {ENTRIES.map(entry => <Square key={entry.id} clock={clock} entry={entry} />)}
    <Note x={740} y={275} anchor="end">time is only "who saw what". there are no clocks.</Note>
  </>
}

export function LogsScene() {
  return <Scene duration={11} height={290} label="Three devices each append signed entries to their own log; each entry points back at the entries its author had seen."
    beats={[
      { at: 0, text: "studio creates the vault. every device writes only to its own logs and never changes an entry once written." },
      { at: 1.4, text: "each entry names, by hash, the entries its author had already seen: its deps. that's the only order there is." },
      { at: 2.6, text: "red entries are membership: create, add, remove, rename. they only point at other membership entries, so membership can always sync first." },
      { at: 3.6, text: "the pro was admitted by studio's add. its first entry has seen that add, so nobody can accept it without knowing the pro is a member." },
      { at: 4.6, text: "studio and the pro then write without seeing each other. concurrent entries are normal, not an error." },
      { at: 6.2, text: "a later entry that has seen both knits the logs back together." },
      { at: 9.8, text: "every entry is signed by its author, and its hash covers its deps. rewriting history would break the signatures that follow." },
    ]}>
    {clock => <Logs clock={clock} />}
  </Scene>
}
