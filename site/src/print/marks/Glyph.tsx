import { motion, useReducedMotion } from "motion/react"
import { padlock, printed } from "./shapes"

// 09 glyph: no square at all, just a small solid red padlock in the middle of where the square was, the size of
// an icon. It sets down into place on load.

const lock = padlock({ x: 37, y: 48, w: 26, h: 20, r: 2.5, reach: 0.29, stroke: 0.16, rise: 0.3, hole: 0.24 })

export function Glyph({ className }: { className?: string }) {
  const still = useReducedMotion()
  return <svg className={className} style={printed} viewBox="0 0 100 100" aria-hidden="true">
    <motion.g fill="var(--red)" stroke="var(--red)"
      initial={still ? false : { opacity: 0, y: -5 }} animate={{ opacity: 1, y: 0 }}
      transition={{ opacity: { duration: 0.3, ease: "easeOut", delay: 0.35 }, y: { type: "spring", visualDuration: 0.5, bounce: 0, delay: 0.35 } }}>
      <path d={lock.shackle} fill="none" strokeWidth={lock.stroke} />
      <path d={lock.body + lock.hole} fillRule="evenodd" stroke="none" />
    </motion.g>
  </svg>
}
