import { useId } from "react"
import { motion, useReducedMotion } from "motion/react"
import { box, keyhole, printed } from "./shapes"

// 10 plate: a keyhole cut through a dark, barely-there escutcheon plate with four screws, lit red from behind. The
// light warms up on load and then breathes very slowly, spilling a little onto the plate.

const hole = keyhole(50, 50, 1.05)
const screws = [[14, 14], [86, 14], [86, 86], [14, 86]] as const
const warm = [0.25, 0.1, 0.25, 1] as const

export function Plate({ className }: { className?: string }) {
  const still = useReducedMotion()
  const id = useId().replace(/:/g, "")
  return <svg className={className} style={printed} viewBox="0 0 100 100" aria-hidden="true">
    <defs>
      <linearGradient id={`${id}-face`} x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stopColor="#1c0808" /><stop offset="1" stopColor="#0a0303" />
      </linearGradient>
      <linearGradient id={`${id}-edge`} x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stopColor="var(--red)" stopOpacity={0.32} /><stop offset="0.5" stopColor="var(--red)" stopOpacity={0.06} /><stop offset="1" stopColor="#000" stopOpacity={0} />
      </linearGradient>
      <filter id={`${id}-glow`} x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="4.5" /></filter>
    </defs>
    <path d={box(3, 3, 94, 94, 5)} fill={`url(#${id}-face)`} />
    <path d={box(3, 3, 94, 94, 5)} fill="none" stroke={`url(#${id}-edge)`} strokeWidth={1} vectorEffect="non-scaling-stroke" />
    {screws.map(([x, y]) => <g key={`${x}${y}`}>
      <circle cx={x} cy={y} r={2.6} fill="#160606" stroke="var(--red)" strokeOpacity={0.14} strokeWidth={1} vectorEffect="non-scaling-stroke" />
      <line x1={x - 1.8} y1={y + 1.2} x2={x + 1.8} y2={y - 1.2} stroke="#000" strokeWidth={0.8} />
    </g>)}
    {/* The light behind: a soft spill on the plate, then the hole itself. */}
    <motion.g initial={still ? false : { opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 1.1, ease: warm, delay: 0.35 }}>
      <motion.path d={hole} fill="var(--red)" filter={`url(#${id}-glow)`}
        initial={{ opacity: 0.4 }} animate={still ? undefined : { opacity: [0.4, 0.22, 0.4] }}
        transition={{ duration: 5, ease: "easeInOut", repeat: Infinity, delay: 1.4 }} />
      <path d={hole} fill="var(--red)" />
    </motion.g>
  </svg>
}
