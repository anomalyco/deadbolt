import { motion, useReducedMotion } from "motion/react"
import { padlock, printed } from "./shapes"

// 01 frame: a solid red padlock, keyhole knocked out, inside a hairline square. The square draws itself in from
// the corners, then the lock settles into it.

const lock = padlock({ x: 30, y: 47, w: 40, h: 30, r: 3.5, reach: 0.31, stroke: 0.16, rise: 0.33, hole: 0.38 })
const out = [0.22, 1, 0.36, 1] as const
// Each side grows from the corner it starts at, clockwise from the top left.
const sides = [
  { x1: 0.5, y1: 0.5, x2: 99.5, y2: 0.5, origin: "0% 50%", axis: "scaleX" },
  { x1: 99.5, y1: 0.5, x2: 99.5, y2: 99.5, origin: "50% 0%", axis: "scaleY" },
  { x1: 99.5, y1: 99.5, x2: 0.5, y2: 99.5, origin: "100% 50%", axis: "scaleX" },
  { x1: 0.5, y1: 99.5, x2: 0.5, y2: 0.5, origin: "50% 100%", axis: "scaleY" },
] as const

export function Frame({ className }: { className?: string }) {
  const still = useReducedMotion()
  return <svg className={className} style={printed} viewBox="0 0 100 100" aria-hidden="true">
    <g stroke="var(--red)" strokeOpacity={0.32} strokeWidth={1} vectorEffect="non-scaling-stroke">
      {sides.map((side, i) => <motion.line key={i} x1={side.x1} y1={side.y1} x2={side.x2} y2={side.y2} vectorEffect="non-scaling-stroke"
        style={{ transformBox: "fill-box", transformOrigin: side.origin }}
        initial={still ? false : { [side.axis]: 0 }} animate={{ [side.axis]: 1 }}
        transition={{ duration: 0.7, ease: out, delay: 0.1 + i * 0.12 }} />)}
    </g>
    <motion.g fill="var(--red)" stroke="var(--red)"
      initial={still ? false : { opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}
      transition={{ opacity: { duration: 0.35, ease: "easeOut", delay: 0.45 }, y: { type: "spring", visualDuration: 0.55, bounce: 0, delay: 0.45 } }}>
      <path d={lock.shackle} fill="none" strokeWidth={lock.stroke} />
      <path d={lock.body + lock.hole} fillRule="evenodd" stroke="none" />
    </motion.g>
  </svg>
}
