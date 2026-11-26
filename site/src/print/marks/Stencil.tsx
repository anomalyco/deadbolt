import { useId } from "react"
import { motion, useReducedMotion } from "motion/react"
import { box, keyhole, shackle, printed } from "./shapes"

// 05 stencil: a heavy, square-shouldered padlock cut as a stencil to stand up to Anton: the shackle broken at the
// top and lifted off the body by bridges. It's sprayed on, top to bottom, leaving a faint overspray around it.

const body = box(17, 47, 66, 46, 1.5)
const hole = keyhole(50, 70, 0.62)
const arc = shackle(50, 32, 20, 43.5)
const STROKE = 14

export function Stencil({ className }: { className?: string }) {
  const still = useReducedMotion()
  const id = useId().replace(/:/g, "")
  const shape = <g fill="var(--red)">
    <path d={arc} fill="none" stroke="var(--red)" strokeWidth={STROKE} strokeLinecap="butt" mask={`url(#${id}-bridge)`} />
    <path d={body + hole} fillRule="evenodd" />
  </g>
  return <svg className={className} style={printed} viewBox="0 0 100 100" aria-hidden="true">
    <defs>
      <mask id={`${id}-bridge`} maskUnits="userSpaceOnUse" x="0" y="0" width="100" height="100">
        <rect width="100" height="100" fill="#fff" />
        <rect x="48.4" y="0" width="3.2" height="20" fill="#000" />
      </mask>
      <filter id={`${id}-spray`} x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="4" result="soft" />
        <feTurbulence type="fractalNoise" baseFrequency="1.4" numOctaves="1" seed="7" result="speck" />
        <feComponentTransfer in="speck" result="dots"><feFuncA type="discrete" tableValues="0 0 0 1 1 1" /></feComponentTransfer>
        <feComposite in="soft" in2="dots" operator="in" />
      </filter>
      <linearGradient id={`${id}-wipe`} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stopColor="#fff" /><stop offset="0.85" stopColor="#fff" /><stop offset="1" stopColor="#000" />
      </linearGradient>
      <mask id={`${id}-paint`} maskUnits="userSpaceOnUse" x="-10" y="-10" width="120" height="120">
        <motion.rect x="-10" width="120" height="140" fill={`url(#${id}-wipe)`}
          initial={still ? false : { y: -140 }} animate={{ y: -10 }} transition={{ duration: 1.25, ease: [0.3, 0.1, 0.25, 1], delay: 0.3 }} />
      </mask>
    </defs>
    <g mask={`url(#${id}-paint)`}>
      <g opacity={0.55} filter={`url(#${id}-spray)`}>{shape}</g>
      {shape}
    </g>
  </svg>
}

