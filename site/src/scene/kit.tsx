import type { ReactNode } from "react"
import { motion, useTransform, type MotionValue } from "motion/react"

// Drawing primitives for the scenes. Every scene is one SVG in a fixed viewBox, driven by one clock (scene
// seconds). Structure stays quiet grey; what moves carries the light (ivory); what's secret or refused is red.

export const ink = {
  frame: "#383838", inset: "#262626", wire: "#2c2c2c", label: "#aaa", detail: "#7a7a7a", dim: "#555",
  light: "#e8e4dc", red: "#ff2a2a", hot: "#ffffff",
} as const

export type Point = readonly [number, number]
export type Clock = MotionValue<number>

export const clamp01 = (x: number) => Math.min(1, Math.max(0, x))
export const span = (t: number, a: number, b: number) => clamp01((t - a) / (b - a))
export const easeInOut = (x: number) => x < .5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2

/** A point a fraction of the way along a polyline, by length. */
export function pointAt(points: readonly Point[], p: number): Point {
  if (points.length === 1) return points[0]!
  const lengths = points.slice(1).map((q, i) => Math.hypot(q[0] - points[i]![0], q[1] - points[i]![1]))
  let rest = clamp01(p) * lengths.reduce((a, b) => a + b, 0)
  for (let i = 0; i < lengths.length; i++) {
    const length = lengths[i]!
    if (rest <= length || i === lengths.length - 1) {
      const a = points[i]!, b = points[i + 1]!, f = length ? rest / length : 0
      return [a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f]
    }
    rest -= length
  }
  return points[points.length - 1]!
}

const pathOf = (points: readonly Point[]) => points.map((p, i) => `${i ? "L" : "M"}${p[0]} ${p[1]}`).join("")

/** 0..1: flashes to 1 at each time and decays over `decay` seconds. */
export function useFlash(clock: Clock, times: readonly number[], decay = 1.2) {
  return useTransform(clock, t => {
    let heat = 0
    for (const at of times) if (t >= at) heat = Math.max(heat, Math.pow(1 - clamp01((t - at) / decay), 2))
    return heat
  })
}

/** 0..1: on between `from` and `to` (fading .3s each way). */
export function useWindow(clock: Clock, from: number, to = Infinity, fade = .3) {
  return useTransform(clock, t => Math.min(span(t, from, from + fade), to === Infinity ? 1 : 1 - span(t, to, to + fade)))
}

/** The diagram card: an outer frame and an inset rule 3 units in, a label, an optional detail on the right. */
export function Card({ x, y, w, h, label, detail, heat, tone = "light", dashed, children }: {
  x: number; y: number; w: number; h: number; label?: ReactNode; detail?: ReactNode
  heat?: MotionValue<number>; tone?: "light" | "red"; dashed?: boolean; children?: ReactNode
}) {
  const hot = tone === "red" ? ink.red : "#8d8d8d"
  const zero = useTransform(() => 0)
  const h0 = heat ?? zero
  const frame = useTransform(h0, [0, 1], [ink.frame, hot])
  const text = useTransform(h0, [0, 1], [ink.label, tone === "red" ? ink.red : ink.hot])
  return <g>
    <motion.rect x={x + .5} y={y + .5} width={w - 1} height={h - 1} fill="#ffffff03" style={{ stroke: frame }} strokeDasharray={dashed ? "3 4" : undefined} />
    <rect x={x + 3.5} y={y + 3.5} width={w - 7} height={h - 7} fill="none" stroke={ink.inset} strokeDasharray={dashed ? "3 4" : undefined} />
    {label != null && <motion.text x={x + 14} y={y + Math.min(h / 2, 26)} dominantBaseline="middle" className="scene-label" style={{ fill: text }}>{label}</motion.text>}
    {detail != null && <text x={x + w - 14} y={y + Math.min(h / 2, 26)} dominantBaseline="middle" textAnchor="end" className="scene-detail">{detail}</text>}
    {children}
  </g>
}

/** A resting connector. */
export function Wire({ points, dashed, lit }: { points: readonly Point[]; dashed?: boolean; lit?: MotionValue<number> }) {
  const zero = useTransform(() => 0)
  const stroke = useTransform(lit ?? zero, [0, 1], [ink.wire, "#777"])
  return <motion.path d={pathOf(points)} fill="none" strokeWidth={1} strokeDasharray={dashed ? "2 5" : undefined} style={{ stroke }} />
}

/** Something travelling along a path between `from` and `to` seconds. `sealed` packets are ciphertext. */
export function Packet({ clock, path, from, to, label, sealed, tone = "light" }: {
  clock: Clock; path: readonly Point[]; from: number; to: number; label?: string; sealed?: boolean; tone?: "light" | "red"
}) {
  const x = useTransform(clock, t => pointAt(path, easeInOut(span(t, from, to)))[0])
  const y = useTransform(clock, t => pointAt(path, easeInOut(span(t, from, to)))[1])
  const opacity = useTransform(clock, t => t < from - .05 ? 0 : t <= to ? 1 : 1 - span(t, to, to + .35))
  const color = tone === "red" ? ink.red : ink.light
  return <motion.g style={{ x, y, opacity }}>
    {sealed
      ? <><rect x={-6} y={-6} width={12} height={12} fill="#000" stroke={ink.red} /><path d="M-3 -2h6M-3 1h4M-3 4h5" stroke={ink.red} strokeWidth={1} /></>
      : <><circle r={9} fill={color} opacity={.12} /><circle r={4.5} fill={color} /></>}
    {label && <text y={-13} textAnchor="middle" className="scene-packet" fill={color}>{label}</text>}
  </motion.g>
}

/** Children shown between `from` and `to` seconds. */
export function Show({ clock, from, to, children }: { clock: Clock; from: number; to?: number; children: ReactNode }) {
  const opacity = useWindow(clock, from, to)
  return <motion.g style={{ opacity }}>{children}</motion.g>
}

/** A small text label in the diagram's voice. */
export function Note({ x, y, children, anchor = "start", tone = "dim", size }: {
  x: number; y: number; children: ReactNode; anchor?: "start" | "middle" | "end"; tone?: "dim" | "label" | "red" | "light"; size?: number
}) {
  const fill = tone === "red" ? ink.red : tone === "light" ? ink.light : tone === "label" ? ink.label : ink.detail
  return <text x={x} y={y} textAnchor={anchor} className="scene-note" fill={fill} style={size ? { fontSize: size } : undefined}>{children}</text>
}

/** A red refusal mark at a point, flashing at `at`. */
export function Refusal({ clock, at, x, y, label }: { clock: Clock; at: number; x: number; y: number; label?: string }) {
  const opacity = useTransform(clock, t => t < at ? 0 : t < at + .15 ? 1 : .35 + .65 * Math.pow(1 - clamp01((t - at - .15) / 1.5), 2))
  return <motion.g style={{ opacity }}>
    <circle cx={x} cy={y} r={11} fill="#000" stroke={ink.red} />
    <path d={`M${x - 5} ${y - 5}L${x + 5} ${y + 5}M${x + 5} ${y - 5}L${x - 5} ${y + 5}`} stroke={ink.red} strokeWidth={1.5} />
    {label && <text x={x} y={y + 26} textAnchor="middle" className="scene-note" fill={ink.red}>{label}</text>}
  </motion.g>
}
