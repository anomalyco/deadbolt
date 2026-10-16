import { useMemo } from "react"
import { useControls } from "knobs/react"
import { header } from "./tuning"

/** The page is printed, not rendered: one static displacement for the still type, and grain over everything.
 *  From opentunnel's website. */
export function Ink() {
  const { bleed, bleedScale, grain } = useControls(header)
  return <>
    <svg width="0" height="0" className="ink-defs" aria-hidden="true">
      <filter id="ink" x="-3%" y="-3%" width="106%" height="106%" colorInterpolationFilters="sRGB">
        <feTurbulence type="fractalNoise" baseFrequency={`${bleedScale} ${+(bleedScale * 1.3).toFixed(5)}`} numOctaves="2" seed="3" result="n" />
        <feDisplacementMap in="SourceGraphic" in2="n" scale={bleed} xChannelSelector="R" yChannelSelector="G" />
      </filter>
    </svg>
    <div className="ink-grain" aria-hidden="true" style={{ opacity: grain }} />
  </>
}

/** A seeded spray of black droplets that knocks ink out of the wordmark. */
const rng = (seed: number) => () => {
  seed = (seed * 1664525 + 1013904223) >>> 0
  return seed / 4294967296
}

const drops = (seed: number, count: number, size: number, spread: number) => {
  const r = rng(seed)
  const out: { x: number; y: number; rx: number; ry: number; a: number }[] = []
  for (let i = 0; i < count; i++) {
    const t = Math.pow(r(), 1.5), angle = r() * Math.PI * 2, dist = t * spread
    const radius = (1 - t) * size + 0.8 + r() * 1.5
    out.push({ x: 180 + Math.cos(angle) * dist, y: 150 + Math.sin(angle) * dist * 0.8, rx: radius, ry: radius * (0.6 + r() * 0.6), a: (angle * 180) / Math.PI + r() * 40 })
  }
  for (let i = 0; i < count / 4; i++) out.push({ x: r() * 360, y: r() * 300, rx: 0.8 + r() * 2, ry: 0.8 + r() * 2, a: 0 })
  return out
}

export function Splatter() {
  const v = useControls(header)
  const spray = useMemo(() => drops(v.splatSeed, v.splatCount, v.splatSize, v.splatSpread), [v.splatSeed, v.splatCount, v.splatSize, v.splatSpread])
  if (!v.splatter) return null
  return <svg className="splatter" viewBox="0 0 360 300" aria-hidden="true" style={{ left: `${v.splatAt.x * 100}%`, top: `${v.splatAt.y * 100}%`, width: `${v.splatWidth}cqw` }}>
    <filter id="splat-edge"><feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" seed="2" /><feDisplacementMap in="SourceGraphic" scale={v.splatEdge} /></filter>
    <g fill="#000" filter="url(#splat-edge)">
      {spray.map((d, i) => <ellipse key={i} cx={d.x} cy={d.y} rx={d.rx} ry={d.ry} transform={`rotate(${d.a.toFixed(1)} ${d.x.toFixed(1)} ${d.y.toFixed(1)})`} />)}
    </g>
  </svg>
}
