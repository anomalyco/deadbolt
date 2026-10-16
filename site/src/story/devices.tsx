import type { ReactNode } from "react"
import type { Light, Tone } from "./light"
import { timing, travelled, type Send } from "./beats"
import { clamp01, flashes, inkFlash, shade, span, springAt, springs, type Box, type Point } from "./motion"
import type { StoryApi } from "./Story"

// Consistent device identities across the site: each device has a 3D wireframe polyhedron and a short matching
// name ("cube", "pyramid", "octahedron"). The solid idles very slowly at rest and turns with momentum on a
// zero-bounce spring whenever the device acts (writing, signing, sending, receiving).

export type DeviceKind = "cube" | "pyramid" | "octahedron" | "prism"

type Vec3 = readonly [number, number, number]
type Mesh = { verts: readonly Vec3[]; edges: readonly (readonly [number, number])[]; baseYaw: number; pitch: number }

const MESHES: Record<DeviceKind, Mesh> = {
  cube: {
    verts: [
      [-1, -1, -1], [1, -1, -1], [1, 1, -1], [-1, 1, -1],
      [-1, -1, 1], [1, -1, 1], [1, 1, 1], [-1, 1, 1],
    ],
    edges: [
      [0, 1], [1, 2], [2, 3], [3, 0],
      [4, 5], [5, 6], [6, 7], [7, 4],
      [0, 4], [1, 5], [2, 6], [3, 7],
    ],
    baseYaw: .62,
    pitch: .44,
  },
  pyramid: {
    verts: [
      [0, -1.22, 0],
      [-1.08, .82, -1.08], [1.08, .82, -1.08], [1.08, .82, 1.08], [-1.08, .82, 1.08],
    ],
    edges: [
      [0, 1], [0, 2], [0, 3], [0, 4],
      [1, 2], [2, 3], [3, 4], [4, 1],
    ],
    baseYaw: .48,
    pitch: .38,
  },
  octahedron: {
    verts: [
      [0, -1.32, 0], [0, 1.32, 0],
      [-1.18, 0, 0], [0, 0, -1.18], [1.18, 0, 0], [0, 0, 1.18],
    ],
    edges: [
      [0, 2], [0, 3], [0, 4], [0, 5],
      [1, 2], [1, 3], [1, 4], [1, 5],
      [2, 3], [3, 4], [4, 5], [5, 2],
    ],
    baseYaw: .36,
    pitch: .42,
  },
  prism: {
    verts: [
      [0, -1.1, -1], [-1.05, .8, -1], [1.05, .8, -1],
      [0, -1.1, 1], [-1.05, .8, 1], [1.05, .8, 1],
    ],
    edges: [
      [0, 1], [1, 2], [2, 0],
      [3, 4], [4, 5], [5, 3],
      [0, 3], [1, 4], [2, 5],
    ],
    baseYaw: .52,
    pitch: .4,
  },
}

/** Deterministic rotation angle: slow drift at rest + critically-damped momentum turns on each action impulse. */
export function solidYaw(kind: DeviceKind, t: number, impulses: readonly number[] = [], reduced = false) {
  const base = MESHES[kind].baseYaw
  if (reduced) return base
  let angle = base + t * .12
  for (const at of impulses) {
    if (t > at) angle += .78 * springAt(t - at, springs.smooth)
  }
  return angle
}

export function Solid({ kind, cx, cy, r = 7.5, t, impulses = [], stroke = "#e8e4dc", reduced = false }: {
  kind: DeviceKind
  cx: number
  cy: number
  r?: number
  t: number
  impulses?: readonly number[]
  stroke?: string
  reduced?: boolean
}) {
  const mesh = MESHES[kind]
  const yaw = solidYaw(kind, t, impulses, reduced)
  const cyaw = Math.cos(yaw), syaw = Math.sin(yaw)
  const cp = Math.cos(mesh.pitch), sp = Math.sin(mesh.pitch)

  const projected = mesh.verts.map(([x, y, z]) => {
    const x1 = x * cyaw + z * syaw
    const z1 = -x * syaw + z * cyaw
    const y2 = y * cp - z1 * sp
    const z2 = y * sp + z1 * cp
    const perspective = 1 / (1 - z2 * .12)
    return [cx + x1 * r * .58 * perspective, cy + y2 * r * .58 * perspective, z2] as const
  })

  return <g stroke={stroke} strokeWidth={1.05} strokeLinecap="round" strokeLinejoin="round" fill="none">
    {mesh.edges.map(([i, j], idx) => {
      const a = projected[i]!, b = projected[j]!
      const depth = (a[2] + b[2]) * .5
      return <line key={idx} x1={a[0].toFixed(2)} y1={a[1].toFixed(2)} x2={b[0].toFixed(2)} y2={b[1].toFixed(2)}
        strokeOpacity={depth < -.15 ? .38 : .95} />
    })}
  </g>
}

/** A double-ruled card that registers with the GPU light layer and responds to focus, flashes, and tone. */
export function Frame({ id, box, t, story, light, label, detail, glyph, impulses, tone = "ivory", heat = 0, broken = 0, dashed, appearAt, headerY, children }: {
  id: string
  box: Box
  t: number
  story: StoryApi
  light: Light
  label?: string
  detail?: string
  glyph?: DeviceKind
  impulses?: readonly number[]
  tone?: Tone
  heat?: number
  broken?: number
  dashed?: boolean
  appearAt?: number
  headerY?: number
  children?: ReactNode
}) {
  const [x, y, w, h] = box
  const age = appearAt === undefined ? 99 : t - appearAt
  if (age < 0) return null

  // Rigid-panel settle-in: small scale correction on a calm zero-bounce spring, fast opacity.
  const appear = appearAt === undefined ? 1 : clamp01(age / .16)
  const scale = appearAt === undefined ? 1 : 1.032 - .032 * springAt(age, springs.calm)
  const enterFlash = appearAt === undefined ? 0 : inkFlash(age)
  const hot = Math.min(1, Math.max(heat, enterFlash))

  const level = story.focus(t, id)
  const lit = clamp01((level - .32) / .68)
  const dim = clamp01((.32 - level) / .32) * .6

  const isRed = tone === "red"
  const isAmber = tone === "amber"
  const baseFrame = isRed ? "#5a1c1c" : isAmber ? "#5a3d18" : "#383838"
  const litFrame = isRed ? "#ff2a2a" : isAmber ? "#ffb347" : "#a8a49c"
  const hotTint = isRed ? "#ff6a4a" : isAmber ? "#ffd08a" : "#fff1dc"

  const frameColor = shade(baseFrame, [litFrame, lit], ["#000000", dim], ["#ffb347", broken * .85], [hotTint, hot * .78])
  const insetColor = shade("#242424", ["#383838", lit * .4], ["#000000", dim], ["#5a3d18", broken * .5])
  const labelColor = shade(isRed ? "#9a3434" : "#767676", [isRed ? "#ff4a3a" : isAmber ? "#ffb347" : "#e8e4dc", lit], ["#000000", dim], ["#ffb347", broken * .9], ["#fff1dc", hot * .85])
  const detailColor = shade("#5e5e5e", ["#9e9a92", lit], ["#000000", dim], ["#ffb347", broken * .85], ["#e8e4dc", hot * .5])

  light.frames.push(box)
  const cx = x + w / 2, cy = y + h / 2
  const hy = headerY ?? (h <= 60 ? y + h / 2 : y + 24)
  const labelX = glyph ? x + 36 : x + 14

  return <g opacity={appear} transform={scale === 1 ? undefined : `translate(${cx} ${cy}) scale(${scale}) translate(${-cx} ${-cy})`}>
    <rect x={x + .5} y={y + .5} width={w - 1} height={h - 1} fill="#050505" stroke={frameColor} strokeDasharray={dashed ? "3 4" : undefined} />
    <rect x={x + 3.5} y={y + 3.5} width={w - 7} height={h - 7} fill="none" stroke={insetColor} strokeDasharray={dashed ? "3 4" : undefined} />
    {glyph && <Solid kind={glyph} cx={x + 20} cy={hy} r={7.2} t={t} impulses={impulses} stroke={labelColor} reduced={story.reduced} />}
    {label && <text x={labelX} y={hy + .5} dominantBaseline="middle" className="story-card-label" fill={labelColor}>{label}</text>}
    {detail && <text x={x + w - 14} y={hy + .5} dominantBaseline="middle" textAnchor="end" className="story-card-detail" fill={detailColor}>{detail}</text>}
    {children}
  </g>
}

/** Words riding a packet head along a path. */
export function Carried({ shot, t, label, dy = -10 }: { shot: Send; t: number; label?: string; dy?: number }) {
  const { launch, lands } = timing(shot)
  if (!label || t < launch - .08 || t > lands + .26) return null
  const f = travelled(shot, t), [x, y] = shot.path.at(shot.reverse ? 1 - f : f)
  const opacity = Math.min(span(t, launch - .08, launch + .14), 1 - span(t, lands - .08, lands + .18))
  const fill = shot.tone === "red" ? "#ff5242" : shot.tone === "amber" ? "#ffb347" : "#e8e4dc"
  return <text x={x} y={y + dy} textAnchor="middle" className="story-carried" fill={fill} opacity={opacity}>{label}</text>
}

/** A refusal stamp on a gate or keyset: slams down on a snappy spring and cools from hot red. */
export function RefusalMark({ x, y, t, at, light, label }: { x: number; y: number; t: number; at: number; light: Light; label?: string }) {
  const age = t - at
  if (age < 0) return null
  const scale = 1.45 - .45 * springAt(age, springs.snappy)
  const opacity = clamp01(age / .09)
  const hot = flashes(t, [at], 1.1)
  if (age < .9) {
    const k = Math.pow(1 - clamp01(age / .6), 2)
    light.dots.push({ at: [x, y], radius: 3, intensity: k * .9, tone: "red" })
    light.rings.push({ at: [x, y], radius: 4 + 10 * (1 - Math.pow(1 - clamp01(age / .55), 2)), width: 1.8, intensity: k * .7, tone: "red" })
  }
  const stroke = shade("#c8231f", ["#ff6a4a", hot])
  return <g opacity={opacity} transform={`translate(${x} ${y}) scale(${scale})`}>
    <circle r={9.5} fill="#050505" stroke={stroke} strokeWidth={1.3} />
    <path d="M-3.8 -3.8L3.8 3.8M3.8 -3.8L-3.8 3.8" stroke={stroke} strokeWidth={1.4} />
    {label && <text y={22} textAnchor="middle" className="story-carried" fill={stroke}>{label}</text>}
  </g>
}

/** Point on a box's edge. */
export const edge = {
  left: (b: Box, dy = 0): Point => [b[0], b[1] + b[3] / 2 + dy],
  right: (b: Box, dy = 0): Point => [b[0] + b[2], b[1] + b[3] / 2 + dy],
  top: (b: Box, dx = 0): Point => [b[0] + b[2] / 2 + dx, b[1]],
  bottom: (b: Box, dx = 0): Point => [b[0] + b[2] / 2 + dx, b[1] + b[3]],
}
