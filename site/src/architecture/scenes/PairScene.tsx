import { motion, useTransform } from "motion/react"
import { Scene } from "../../scene/Scene"
import { Card, Note, Packet, Show, Wire, ink, useFlash, type Clock, type Point } from "../../scene/kit"

// laptop (new, listening)                       studio (member, dialing)
//   deadbolt join → ticket + qr    ── you ──▶    deadbolt pair <ticket>
//            ◀────────── proofs · code · offer / join · entries · result ──────────▶

const NEW = { x: 20, y: 40, w: 260, h: 230 }, OLD = { x: 480, y: 40, w: 260, h: 230 }
const wire = (y: number): Point[] => [[OLD.x, y], [NEW.x + NEW.w, y]]
const toOld = (y: number): Point[] => [[NEW.x + NEW.w, y], [OLD.x, y]]
const carry: Point[] = [[150, NEW.y + 6], [150, 18], [610, 18], [610, OLD.y + 6]]

const T = { ticket: .5, carry: [1.8, 3.2], dial: [3.6, 4.6], proofs: [4.9, 5.9], code: 6.2, offer: [7.6, 8.4], consent: [8.6, 9.4], add: 9.7, entries: [10.1, 11.6], member: 12.4 } as const

/** A seeded square of modules standing in for the ticket's qr code. */
const modules = (() => {
  let seed = 9
  const r = () => (seed = (seed * 1664525 + 1013904223) >>> 0) / 4294967296
  const out: [number, number][] = []
  for (let y = 0; y < 21; y++) for (let x = 0; x < 21; x++) {
    const finder = (a: number, b: number) => a < 7 && b < 7 && (a === 0 || a === 6 || b === 0 || b === 6 || (a > 1 && a < 5 && b > 1 && b < 5))
    const inCorner = (x < 7 && y < 7) || (x > 13 && y < 7) || (x < 7 && y > 13)
    const on = inCorner ? finder(x % 14, y % 14) : r() < .48
    if (on) out.push([x, y])
  }
  return out
})()

function Qr({ clock, x, y }: { clock: Clock; x: number; y: number }) {
  const opacity = useTransform(clock, t => t < T.ticket ? 0 : t < T.dial[1] ? 1 : .25)
  return <motion.g style={{ opacity }}>
    {modules.map(([mx, my]) => <rect key={`${mx}-${my}`} x={x + mx * 3.4} y={y + my * 3.4} width={3.4} height={3.4} fill={ink.light} />)}
  </motion.g>
}

function Pair({ clock }: { clock: Clock }) {
  const fresh = useFlash(clock, [T.ticket, T.code, T.member], 1.6)
  const member = useFlash(clock, [T.carry[1], T.code, T.add])
  return <>
    <Wire points={carry} dashed />
    {[110, 150, 190].map(y => <Wire key={y} points={wire(y)} />)}
    <Show clock={clock} from={0} to={T.member}><Card {...NEW} label="laptop" detail="new · listening" heat={fresh} /></Show>
    <Show clock={clock} from={T.member}><Card {...NEW} label="laptop" detail="member" heat={fresh} /></Show>
    <Card {...OLD} label="studio" detail="member · dials" heat={member} />
    <Note x={NEW.x + 20} y={NEW.y + 54} tone="light">$ deadbolt join</Note>
    <Qr clock={clock} x={NEW.x + 20} y={NEW.y + 70} />
    <Show clock={clock} from={T.ticket} to={T.code}>
      <Note x={NEW.x + 105} y={NEW.y + 90}>public key</Note>
      <Note x={NEW.x + 105} y={NEW.y + 108}>one-time secret</Note>
      <Note x={NEW.x + 105} y={NEW.y + 126}>address hint</Note>
    </Show>
    <Show clock={clock} from={T.carry[1]}><Note x={OLD.x + 20} y={OLD.y + 54} tone="light">$ deadbolt pair DBPAIR…</Note></Show>
    <Note x={380} y={12} anchor="middle">you copy or scan the ticket</Note>
    <Show clock={clock} from={T.code}>
      <text x={NEW.x + 20} y={NEW.y + 190} className="scene-code" fill={ink.light}>411 308</text>
      <text x={OLD.x + 20} y={OLD.y + 190} className="scene-code" fill={ink.light}>411 308</text>
      <Note x={OLD.x + 20} y={OLD.y + 212}>match? [y/N] y</Note>
    </Show>
    <Show clock={clock} from={T.add}><Note x={OLD.x + 20} y={OLD.y + 84} tone="red">signs Add(laptop)</Note></Show>
    <Show clock={clock} from={T.consent[0]}><Note x={NEW.x + 105} y={NEW.y + 84} tone="light">signs consent</Note><Note x={NEW.x + 105} y={NEW.y + 100}>to join "personal"</Note></Show>
    <Packet clock={clock} path={carry} from={T.carry[0]} to={T.carry[1]} label="ticket" />
    <Packet clock={clock} path={wire(150)} from={T.dial[0]} to={T.dial[1]} label="dial · deadbolt/pair/1" />
    <Packet clock={clock} path={wire(110)} from={T.proofs[0]} to={T.proofs[1]} label="proof" />
    <Packet clock={clock} path={toOld(190)} from={T.proofs[0] + .2} to={T.proofs[1] + .2} label="proof" />
    <Packet clock={clock} path={wire(110)} from={T.offer[0]} to={T.offer[1]} label="offer: personal" />
    <Packet clock={clock} path={toOld(150)} from={T.consent[0]} to={T.consent[1]} label="join + consent" />
    <Packet clock={clock} path={wire(110)} from={T.entries[0]} to={T.entries[0] + 1} label="membership" tone="red" />
    <Packet clock={clock} path={wire(150)} from={T.entries[0] + .4} to={T.entries[1]} label="entries" />
    <Packet clock={clock} path={toOld(190)} from={T.entries[1] + .1} to={T.entries[1] + .7} label="result" />
  </>
}

export function PairScene() {
  return <Scene duration={13} height={290} label="A new device shows a ticket; a member dials it, both prove the one-time secret, you compare codes, and the member admits the new device."
    beats={[
      { at: 0, text: "on the new device, `deadbolt join` shows a ticket and a qr code: its public key, a one-time secret, and a hint for reaching it." },
      { at: T.carry[0], text: "you take the ticket to a device that's already a member and run `deadbolt pair` with it." },
      { at: T.dial[0], text: "the member dials the new device directly. the pairing protocol only answers while a ticket is outstanding." },
      { at: T.proofs[0], text: "each side proves it knows the secret with an hmac over the connection, so neither can be impersonated by someone who only saw the qr code." },
      { at: T.code, text: "both screens show the same six digits. you confirm on the member that they match." },
      { at: T.offer[0], text: "the member offers the vault; the new device signs its consent to join that vault and no other." },
      { at: T.add, text: "the member signs Add, then sends the membership log and the data over the same connection." },
      { at: T.member, text: "the new device is a member now, and syncs like any other." },
    ]}>
    {clock => <Pair clock={clock} />}
  </Scene>
}
