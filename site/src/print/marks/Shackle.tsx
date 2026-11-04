import { motion, useReducedMotion } from "motion/react"
import { box, keyhole, printed, shackle } from "./shapes"

// 03 shackle: a padlock drawn in a heavy red outline, with a solid keyhole. It loads open, then the shackle falls
// shut under its own weight and the body takes the knock.

const W = 5
const body = box(26 + W / 2, 48 + W / 2, 48 - W, 34 - W, 4)
const arc = shackle(50, 38, 13.5, 48)
const hole = keyhole(50, 65, 0.36)
const LIFT = 15, DROP = 0.65, FALL = 0.34

export function Shackle({ className }: { className?: string }) {
  const still = useReducedMotion()
  return <svg className={className} style={printed} viewBox="0 0 100 100" aria-hidden="true">
    {/* The knock: the body dips under the impact and settles, a single small rebound. */}
    <motion.g fill="none" stroke="var(--red)" strokeWidth={W}
      initial={still ? false : { y: 0 }} animate={{ y: [0, 1.8, 0] }}
      transition={{ duration: 0.42, times: [0, 0.22, 1], ease: [[0.2, 0.8, 0.4, 1], [0.3, 0, 0.2, 1]], delay: DROP + FALL }}>
      <motion.g initial={still ? false : { opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4, ease: "easeOut" }}>
        <path d={body} />
        <path d={hole} fill="var(--red)" stroke="none" />
      </motion.g>
      {/* Falling: it gathers speed all the way down. */}
      <motion.path d={arc} strokeLinecap="butt"
        initial={still ? false : { y: -LIFT, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
        transition={{ y: { duration: FALL, ease: [0.55, 0, 1, 0.45], delay: DROP }, opacity: { duration: 0.4, ease: "easeOut" } }} />
    </motion.g>
  </svg>
}
