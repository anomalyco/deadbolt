import { useEffect, useRef } from "react"
import { useReducedMotion } from "motion/react"
import { onFrame } from "../../story/ticker"
import { keyhole, printed } from "./shapes"

// 04 heartbeat: a solid red keyhole with a pulse. On each beat (a lub-dub, as the print's) the keyhole gives a small
// thump and sends out a hairline ring of dark red that slows and thins as it goes.

const RATE = 0.45, DUB = 0.16, LIFE = 2
const hole = keyhole(50, 50, 1.12)
// A ring per thump, two thumps a beat, at most two beats alive at once.
const RINGS = 4

export function Heartbeat({ className }: { className?: string }) {
  const still = useReducedMotion()
  const mark = useRef<SVGPathElement>(null)
  const rings = useRef<(SVGCircleElement | null)[]>([])
  useEffect(() => {
    if (still) return
    let start = -1
    return onFrame(now => {
      if (start < 0) start = now
      // The first beat lands a moment after load.
      const t = (now - start) / 1000 - 0.5
      const beats = t * RATE
      const phase = beats - Math.floor(beats)
      const thump = t < 0 ? 0 : Math.exp(-phase * 9) + (phase > DUB ? 0.6 * Math.exp(-(phase - DUB) * 9) : 0)
      mark.current?.setAttribute("transform", `translate(50 50) scale(${1 + 0.035 * thump}) translate(-50 -50)`)
      rings.current.forEach((ring, i) => {
        if (!ring) return
        const beat = Math.floor(beats) - Math.floor(i / 2), strong = i % 2 === 0
        const age = t - (beat + (strong ? 0 : DUB)) / RATE
        if (beat < 0 || age < 0 || age > LIFE) { ring.setAttribute("opacity", "0"); return }
        const r = 15 + 44 * (1 - Math.exp(-age * 1.9))
        const fade = 1 - age / LIFE
        ring.setAttribute("r", r.toFixed(2))
        ring.setAttribute("opacity", ((strong ? 0.55 : 0.33) * fade * fade).toFixed(3))
      })
    })
  }, [still])
  return <svg className={className} style={printed} viewBox="0 0 100 100" aria-hidden="true">
    <g fill="none" stroke="var(--red)" strokeWidth={1}>
      {still
        ? [26, 38].map((r, i) => <circle key={r} cx={50} cy={50} r={r} opacity={0.3 - i * 0.12} vectorEffect="non-scaling-stroke" />)
        : Array.from({ length: RINGS }, (_, i) => <circle key={i} ref={el => { rings.current[i] = el }} cx={50} cy={50} r={15} opacity={0} vectorEffect="non-scaling-stroke" />)}
    </g>
    <path ref={mark} d={hole} fill="var(--red)" />
  </svg>
}
