import { useId } from "react"
import { motion, useReducedMotion, type TargetAndTransition } from "motion/react"
import { box, keyhole, printed } from "./shapes"

// 06 bolt: the lock as the thing it's named for. A red cylinder with its keyhole, and a red bolt behind it; the
// strike plate it shoots into is only a hairline. On load the key turns a quarter, the bolt throws home, and the
// key turns back.

const THROW = 38
const hole = keyhole(0, 0, 0.62)
// Seconds from mount: the key turns, the bolt flies, it lands, the key is let go.
const TURN = 0.5, FLY = 0.9, LAND = 1.14, BACK = 1.5
const turn = [0.45, 0, 0.2, 1] as const

export function Bolt({ className }: { className?: string }) {
  const still = useReducedMotion()
  const id = useId().replace(/:/g, "")
  const from = (values: TargetAndTransition) => still ? false as const : values
  return <svg className={className} style={printed} viewBox="0 0 100 100" aria-hidden="true">
    <defs><clipPath id={`${id}-door`}><rect x={30} width={70} height={100} /></clipPath></defs>
    <motion.g initial={from({ x: 0 })} animate={{ x: [0, 0.9, 0] }}
      transition={{ duration: 0.32, times: [0, 0.25, 1], ease: [[0.2, 0.8, 0.4, 1], [0.3, 0, 0.2, 1]], delay: LAND }}>
      <motion.g fill="none" stroke="var(--red)" strokeWidth={1}
        initial={from({ opacity: 0.32 })} animate={{ opacity: [0.32, 0.8, 0.32] }}
        transition={{ duration: 0.95, times: [0, 0.04, 1], ease: [[0.3, 0, 1, 1], [0.16, 1, 0.3, 1]], delay: LAND - 0.04 }}>
        <path d={box(73, 27, 20, 46, 2.5)} vectorEffect="non-scaling-stroke" />
        <path d={box(77, 41, 12, 18, 1)} vectorEffect="non-scaling-stroke" />
        <circle cx={83} cy={33} r={1.6} vectorEffect="non-scaling-stroke" />
        <circle cx={83} cy={67} r={1.6} vectorEffect="non-scaling-stroke" />
      </motion.g>
      {/* The bolt slides out of the door, so it's clipped to the door's side of the cylinder. Thrown by a spring,
          it leaves fast and stops dead in the strike. */}
      <g clipPath={`url(#${id}-door)`}>
        <motion.path d={box(30, 43, 55, 14, 1.5)} fill="var(--red)"
          initial={from({ x: -THROW })} animate={{ x: 0 }} transition={{ duration: LAND - FLY, ease: [0.4, 0, 0.9, 0.6], delay: FLY }} />
      </g>
      <circle cx={30} cy={50} r={21} fill="var(--red)" />
      <g transform="translate(30 50)">
        <motion.path d={hole} fill="#000"
          initial={from({ rotate: 0 })} animate={{ rotate: [0, 90, 90, 0] }}
          transition={{ duration: BACK + 0.5 - TURN, times: [0, (FLY - TURN) / 1.5, (BACK - TURN) / 1.5, 1], ease: [turn, "linear", turn], delay: TURN }} />
      </g>
    </motion.g>
  </svg>
}
