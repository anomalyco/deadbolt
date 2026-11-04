import { motion, useReducedMotion } from "motion/react"
import { keyhole, printed } from "./shapes"

// 07 register: a red keyhole printed like a proof, with crop ticks at the corners and registration targets at the
// sides in dark-red hairline. On load a second pass of ink lands off register and slides into place over the first.

const hole = keyhole(50, 50, 1.2)
const out = [0.22, 1, 0.36, 1] as const
const T = 12, G = 4, L = 9
// Crop ticks: two per corner of the trim box (T..100-T), held off it by G.
const ticks = [[T, T, -1, -1], [100 - T, T, 1, -1], [100 - T, 100 - T, 1, 1], [T, 100 - T, -1, 1]].flatMap(([x, y, sx, sy]) => [
  { x1: x! + sx! * G, y1: y!, x2: x! + sx! * (G + L), y2: y!, origin: sx! < 0 ? "100% 50%" : "0% 50%", axis: "scaleX" },
  { x1: x!, y1: y! + sy! * G, x2: x!, y2: y! + sy! * (G + L), origin: sy! < 0 ? "50% 100%" : "50% 0%", axis: "scaleY" },
])
const target = (cx: number, cy: number) => <>
  <circle cx={cx} cy={cy} r={2.4} vectorEffect="non-scaling-stroke" />
  <line x1={cx - 4} y1={cy} x2={cx + 4} y2={cy} vectorEffect="non-scaling-stroke" />
  <line x1={cx} y1={cy - 4} x2={cx} y2={cy + 4} vectorEffect="non-scaling-stroke" />
</>

export function Registration({ className }: { className?: string }) {
  const still = useReducedMotion()
  return <svg className={className} style={printed} viewBox="0 0 100 100" aria-hidden="true">
    <g fill="none" stroke="var(--red)" strokeWidth={1} strokeOpacity={0.4}>
      {ticks.map((tick, i) => <motion.line key={i} x1={tick.x1} y1={tick.y1} x2={tick.x2} y2={tick.y2} vectorEffect="non-scaling-stroke"
        style={{ transformBox: "fill-box", transformOrigin: tick.origin }}
        initial={still ? false : { [tick.axis]: 0 }} animate={{ [tick.axis]: 1 }} transition={{ duration: 0.6, ease: out, delay: 0.1 + (i >> 1) * 0.06 }} />)}
      <motion.g initial={still ? false : { opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.5, ease: "easeOut", delay: 0.35 }}>
        {target(5, 50)}{target(95, 50)}
      </motion.g>
    </g>
    <motion.g initial={still ? false : { opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.25, ease: "easeOut", delay: 0.45 }}>
      <path d={hole} fill="var(--red)" />
      <motion.path d={hole} fill="var(--red)"
        initial={still ? false : { opacity: 0.5, x: 5, y: -3.5 }} animate={{ opacity: 1, x: 0, y: 0 }}
        transition={{ type: "spring", visualDuration: 1, bounce: 0, delay: 0.75 }} />
    </motion.g>
  </svg>
}
