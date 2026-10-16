import { motion, useTransform } from "motion/react"
import { Scene } from "../../scene/Scene"
import { Card, Note, Packet, Refusal, Show, Wire, ink, useFlash, type Clock, type Point } from "../../scene/kit"

// studio ──┐                 ┊
//   │      ├──────────────── ┊ ──▶ laptop (removed)
// pro ─────┘                 ┊ membership gate

const STUDIO = { x: 20, y: 40, w: 220, h: 56 }, PRO = { x: 20, y: 200, w: 220, h: 56 }, LAPTOP = { x: 520, y: 120, w: 220, h: 56 }
const GATE = 440
const sToL: Point[] = [[STUDIO.x + STUDIO.w, 68], [330, 68], [330, 140], [LAPTOP.x, 140]]
const pToL: Point[] = [[PRO.x + PRO.w, 228], [330, 228], [330, 156], [LAPTOP.x, 156]]
const sToP: Point[] = [[130, STUDIO.y + STUDIO.h], [130, PRO.y]]
const lToP: Point[] = [[LAPTOP.x, 156], [GATE + 8, 156]]
const lToS: Point[] = [[LAPTOP.x, 140], [GATE + 8, 140]]

const T = { normal: [.4, 1.6], remove: 2.6, spread: [3.6, 4.8], closed: 5.0, tryPro: [6.4, 7.4], tryStudio: [8.2, 9.2], keeps: 10.2 } as const

function Gate({ clock }: { clock: Clock }) {
  const opacity = useTransform(clock, t => t < T.remove ? .25 : 1)
  return <motion.g style={{ opacity }}>
    <line x1={GATE} y1={30} x2={GATE} y2={270} stroke={ink.red} strokeDasharray="2 5" />
    <text x={GATE} y={22} textAnchor="middle" className="scene-note" fill={ink.red}>membership gate</text>
  </motion.g>
}

function Remove({ clock }: { clock: Clock }) {
  const studio = useFlash(clock, [T.remove], 1.6)
  const pro = useFlash(clock, [T.spread[1]], 1.6)
  const laptop = useFlash(clock, [T.normal[1], T.tryPro[1], T.tryStudio[1]])
  return <>
    <Wire points={sToP} />
    <Show clock={clock} from={0} to={T.remove}><Wire points={sToL} /></Show>
    <Show clock={clock} from={T.remove}><Wire points={sToL} dashed /></Show>
    <Show clock={clock} from={0} to={T.closed}><Wire points={pToL} /></Show>
    <Show clock={clock} from={T.closed}><Wire points={pToL} dashed /></Show>
    <Gate clock={clock} />
    <Card {...STUDIO} label="studio" detail="member" heat={studio} tone="red" />
    <Card {...PRO} label="macbook pro" detail="member" heat={pro} tone="red" />
    <Show clock={clock} from={0} to={T.remove}><Card {...LAPTOP} label="laptop" detail="member" heat={laptop} /></Show>
    <Show clock={clock} from={T.remove}><Card {...LAPTOP} label="laptop" detail="removed" heat={laptop} tone="red" /></Show>
    <Show clock={clock} from={T.remove}><Note x={STUDIO.x} y={STUDIO.y - 10} tone="red">signs Remove(laptop) · closes its connection</Note></Show>
    <Show clock={clock} from={T.closed}><Note x={PRO.x} y={PRO.y + PRO.h + 18} tone="red">learns the removal · closes its connection</Note></Show>
    <Show clock={clock} from={T.keeps}>
      <Note x={LAPTOP.x} y={LAPTOP.y + LAPTOP.h + 20}>keeps what it already had.</Note>
      <Note x={LAPTOP.x} y={LAPTOP.y + LAPTOP.h + 36}>rotate the passwords it saw.</Note>
    </Show>
    <Packet clock={clock} path={sToL} from={T.normal[0]} to={T.normal[1]} label="entry" />
    <Packet clock={clock} path={sToP} from={T.spread[0]} to={T.spread[1]} label="Remove(laptop)" tone="red" />
    <Packet clock={clock} path={lToP} from={T.tryPro[0]} to={T.tryPro[1]} label="sync?" />
    <Packet clock={clock} path={lToS} from={T.tryStudio[0]} to={T.tryStudio[1]} label="sync?" />
    <Refusal clock={clock} at={T.tryPro[1]} x={GATE} y={156} />
    <Refusal clock={clock} at={T.tryStudio[1]} x={GATE} y={140} label="refused before a single byte" />
  </>
}

export function RemoveScene() {
  return <Scene duration={11.4} height={290} label="Studio removes the laptop; the removal spreads to the pro; the laptop's attempts to sync are refused at the membership gate."
    beats={[
      { at: 0, text: "the laptop is a member and syncs like everyone else." },
      { at: T.remove, text: "studio signs Remove(laptop) and closes its open connection to the laptop at once, not just future ones." },
      { at: T.spread[0], text: "the removal is a membership entry, so it goes first on the next sync. the pro learns it and closes its connection too." },
      { at: T.tryPro[0], text: "the laptop can still dial. every member checks the membership set before connecting and again right after the handshake, so it's refused before a byte of data moves." },
      { at: T.keeps, text: "what the laptop already had, it keeps. no system can take back data a device has seen, so rotate the passwords it could read." },
    ]}>
    {clock => <Remove clock={clock} />}
  </Scene>
}
