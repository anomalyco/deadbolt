import { Scene } from "../../scene/Scene"
import { Card, Note, Packet, Show, Wire, useFlash, type Clock, type Point } from "../../scene/kit"

// studio ═══ iroh · quic ═══ macbook pro
// 1. HEADS both ways  2. missing entries both ways, membership first  3. apply  4. RESULT

const A = { x: 20, y: 40, w: 250, h: 220 }, B = { x: 490, y: 40, w: 250, h: 220 }
const lane = (y: number): Point[] => [[A.x + A.w, y], [B.x, y]]
const back = (y: number): Point[] => [[B.x, y], [A.x + A.w, y]]

const T = { heads: [.6, 2.0], diff: 2.5, send: 4.0, apply: 6.4, result: [7.2, 8.4] } as const

function Rows({ x, y, rows }: { x: number; y: number; rows: readonly (readonly [string, string, boolean?])[] }) {
  return <>{rows.map(([log, seq, red], i) => <g key={log}>
    <Note x={x} y={y + i * 18} tone={red ? "red" : "label"}>{log}</Note>
    <Note x={x + 200} y={y + i * 18} anchor="end" tone="light">{seq}</Note>
  </g>)}</>
}

function Device({ clock, box, name, before, after, missing, heat }: {
  clock: Clock; box: typeof A; name: string; heat: ReturnType<typeof useFlash>
  before: readonly (readonly [string, string, boolean?])[]; after: readonly (readonly [string, string, boolean?])[]; missing: string
}) {
  return <Card {...box} label={name} detail="heads" heat={heat}>
    <Show clock={clock} from={0} to={T.apply}><Rows x={box.x + 22} y={box.y + 64} rows={before} /></Show>
    <Show clock={clock} from={T.apply}><Rows x={box.x + 22} y={box.y + 64} rows={after} /></Show>
    <Show clock={clock} from={T.diff} to={T.apply}><Note x={box.x + 22} y={box.y + 170} tone="light">peer is missing:</Note><Note x={box.x + 22} y={box.y + 188} tone="light">{missing}</Note></Show>
    <Show clock={clock} from={T.apply}><Note x={box.x + 22} y={box.y + 188}>checked · applied</Note></Show>
  </Card>
}

function Sync({ clock }: { clock: Clock }) {
  const a = useFlash(clock, [T.heads[1], T.send + 2, T.result[1]])
  const b = useFlash(clock, [T.heads[1], T.send + 2])
  return <>
    {[110, 150, 190].map(y => <Wire key={y} points={lane(y)} />)}
    <Note x={380} y={84} anchor="middle">iroh · quic · encrypted</Note>
    <Device clock={clock} box={A} name="studio" heat={a} missing="studio 3, 4"
      before={[["studio · membership", "1", true], ["studio · data", "4"], ["pro · membership", "0", true], ["pro · data", "1"]]}
      after={[["studio · membership", "1", true], ["studio · data", "4"], ["pro · membership", "1", true], ["pro · data", "3"]]} />
    <Device clock={clock} box={B} name="macbook pro" heat={b} missing="pro membership 1, pro 2, 3"
      before={[["studio · membership", "1", true], ["studio · data", "2"], ["pro · membership", "1", true], ["pro · data", "3"]]}
      after={[["studio · membership", "1", true], ["studio · data", "4"], ["pro · membership", "1", true], ["pro · data", "3"]]} />
    <Packet clock={clock} path={lane(110)} from={T.heads[0]} to={T.heads[1]} label="heads" />
    <Packet clock={clock} path={back(150)} from={T.heads[0]} to={T.heads[1]} label="heads" />
    <Packet clock={clock} path={back(110)} from={T.send} to={T.send + 1.2} label="membership" tone="red" />
    <Packet clock={clock} path={back(150)} from={T.send + .5} to={T.send + 1.7} label="pro 2" />
    <Packet clock={clock} path={back(190)} from={T.send + .9} to={T.send + 2.1} label="pro 3" />
    <Packet clock={clock} path={lane(150)} from={T.send + .2} to={T.send + 1.4} label="studio 3" />
    <Packet clock={clock} path={lane(190)} from={T.send + .6} to={T.send + 1.8} label="studio 4" />
    <Packet clock={clock} path={back(150)} from={T.result[0]} to={T.result[1]} label="result: ok" />
  </>
}

export function SyncScene() {
  return <Scene duration={9} height={290} label="Two devices exchange heads, then send each other the entries the other is missing, membership first, then confirm."
    beats={[
      { at: 0, text: "studio dials the pro over iroh. the connection is encrypted, and both ends have proven they hold their device keys." },
      { at: T.heads[0], text: "first each side sends its heads: for every log it holds, the highest entry number." },
      { at: T.diff, text: "comparing heads tells each side exactly what the other is missing. nothing else is sent." },
      { at: T.send, text: "missing entries flow both ways at once, membership entries first, so data never arrives before the membership it depends on." },
      { at: T.apply, text: "each side checks signatures and deps, then applies. now both hold the same logs, and so the same vault." },
      { at: T.result[0], text: "the side that was dialed answers with a result, so a finished sync means both sides processed everything." },
    ]}>
    {clock => <Sync clock={clock} />}
  </Scene>
}
