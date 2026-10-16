import { Scene } from "../scene/Scene"
import { Card, Packet, Show, Wire, Note, useFlash, type Clock, type Point } from "../scene/kit"

// this machine ──────────────┬─▶ macbook pro
//        ╲                   ├─▶ studio
//         ╲─▶ n0 relay ──────┘   laptop (offline, catches up from pro)
//
// No server of ours: entries go device to device. When two devices can't reach each other directly, an n0
// relay forwards the encrypted QUIC stream; it sees only ciphertext.

const ME = { x: 20, y: 120, w: 190, h: 52 }
const RELAY = { x: 280, y: 30, w: 190, h: 52 }
const DEVICES = [{ y: 70, name: "macbook pro", detail: "member" }, { y: 140, name: "studio", detail: "member" }, { y: 210, name: "laptop", detail: "member" }]
const DX = 530, DW = 200, DH = 52
const mid = (y: number) => y + DH / 2

const out: Point = [ME.x + ME.w, ME.y + ME.h / 2]
const direct = (i: number): Point[] => [out, [490, out[1]], [490, mid(DEVICES[i]!.y)], [DX, mid(DEVICES[i]!.y)]]
const toRelay: Point[] = [out, [245, out[1]], [245, RELAY.y + 26], [RELAY.x, RELAY.y + 26]]
const fromRelay: Point[] = [[RELAY.x + RELAY.w, RELAY.y + 26], [505, RELAY.y + 26], [505, mid(DEVICES[1]!.y)], [DX, mid(DEVICES[1]!.y)]]
const catchUp: Point[] = [[DX, mid(DEVICES[0]!.y)], [514, mid(DEVICES[0]!.y)], [514, mid(DEVICES[2]!.y)], [DX, mid(DEVICES[2]!.y)]]

export const meshTimes = { pro: [.4, 1.8], studio: [2.2, 3.6], relayIn: [4.4, 5.4], relayOut: [6.0, 7.0], online: 8.2, catchUp: [8.8, 10.2] } as const
const T = meshTimes

function Mesh({ clock }: { clock: Clock }) {
  const meHeat = useFlash(clock, [T.pro[0], T.studio[0], T.relayIn[0]], .8)
  const proHeat = useFlash(clock, [T.pro[1], T.catchUp[0]])
  const studioHeat = useFlash(clock, [T.studio[1], T.relayOut[1]])
  const relayHeat = useFlash(clock, [T.relayIn[1]], 1.6)
  const laptopHeat = useFlash(clock, [T.catchUp[1]])
  return <>
    {DEVICES.map((_, i) => <Wire key={i} points={direct(i)} />)}
    <Wire points={toRelay} dashed />
    <Wire points={fromRelay} dashed />
    <Note x={ME.x} y={ME.y - 12}>this machine</Note>
    <Card {...ME} label="deadbolt" detail="vault" heat={meHeat} />
    <Card {...RELAY} label="n0 relay" detail="if direct fails" heat={relayHeat} dashed />
    <Note x={RELAY.x} y={RELAY.y + RELAY.h + 18}>forwards ciphertext. can't read it.</Note>
    <rect x={510.5} y={40.5} width={239} height={239} fill="none" stroke="#262626" />
    <Note x={510} y={30}>your other devices</Note>
    <Card x={DX} y={DEVICES[0]!.y} w={DW} h={DH} label={DEVICES[0]!.name} detail="member" heat={proHeat} />
    <Card x={DX} y={DEVICES[1]!.y} w={DW} h={DH} label={DEVICES[1]!.name} detail="member" heat={studioHeat} />
    <Show clock={clock} from={0} to={T.online}><Card x={DX} y={DEVICES[2]!.y} w={DW} h={DH} label="laptop" detail="asleep" dashed /></Show>
    <Show clock={clock} from={T.online}><Card x={DX} y={DEVICES[2]!.y} w={DW} h={DH} label="laptop" detail="catching up" heat={laptopHeat} /></Show>
    <Packet clock={clock} path={direct(0)} from={T.pro[0]} to={T.pro[1]} label="entry" />
    <Packet clock={clock} path={direct(1)} from={T.studio[0]} to={T.studio[1]} label="entry" />
    <Packet clock={clock} path={toRelay} from={T.relayIn[0]} to={T.relayIn[1]} sealed />
    <Packet clock={clock} path={fromRelay} from={T.relayOut[0]} to={T.relayOut[1]} sealed />
    <Packet clock={clock} path={catchUp} from={T.catchUp[0]} to={T.catchUp[1]} label="missed" />
  </>
}

const short = [
  { at: 0, text: "a change on this machine goes straight to your other devices." },
  { at: T.relayIn[0], text: "when they can't reach each other, an n0 relay forwards the encrypted stream." },
  { at: T.online, text: "a device that was asleep catches up from any member when it wakes." },
]
const long = [
  { at: 0, text: "every device holds the whole vault. a change on this machine is sent straight to the others, device to device." },
  { at: T.studio[0], text: "devices find each other by their public key; iroh punches through nats to connect directly when it can." },
  { at: T.relayIn[0], text: "when it can't, an n0 relay forwards the quic stream. the stream is end-to-end encrypted, so the relay sees only ciphertext." },
  { at: T.online, text: "a device that was asleep isn't stuck: it catches up from whichever member it reaches first. there's no server to catch up from." },
]

export function MeshScene({ quiet }: { quiet?: boolean }) {
  return <Scene duration={11} height={290} label="This machine syncs entries directly with your other devices, through an n0 relay only when it has to." quiet={quiet}
    fields={() => [{ x: RELAY.x + 4, y: RELAY.y + 4, w: RELAY.w - 8, h: RELAY.h - 8, density: .45 }]}
    beats={quiet ? short : long}>
    {clock => <Mesh clock={clock} />}
  </Scene>
}
