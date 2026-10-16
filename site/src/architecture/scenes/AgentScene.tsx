import { Scene } from "../../scene/Scene"
import { Card, Note, Packet, Wire, useFlash, type Clock, type Point } from "../../scene/kit"

// terminal ─▶ deadbolt (cli) ─▶ agent.sock ─▶ ┌ agent ──────────────┐
//                                            │ vault state   core  │
//                                            │ store.redb    store │
//                                            │ iroh node     net   │──▶ other devices
//                                            └─────────────────────┘

const TERM = { x: 20, y: 124, w: 150, h: 52 }, CLI = { x: 200, y: 124, w: 140, h: 52 }
const AGENT = { x: 410, y: 24, w: 300, h: 252 }
const CORE = { x: 430, y: 56, w: 260, h: 52 }, STORE = { x: 430, y: 124, w: 260, h: 52 }, NET = { x: 430, y: 192, w: 260, h: 52 }
const SOCK: Point = [376, 150]
const midY = (b: { y: number; h: number }) => b.y + b.h / 2

const toCli: Point[] = [[TERM.x + TERM.w, 150], [CLI.x, 150]]
const toCore: Point[] = [[CLI.x + CLI.w, 150], SOCK, [395, 150], [395, midY(CORE)], [CORE.x, midY(CORE)]]
const coreToStore: Point[] = [[575, CORE.y + CORE.h], [575, STORE.y]]
const storeToCore: Point[] = [[605, STORE.y], [605, CORE.y + CORE.h]]
const out: Point[] = [[NET.x + NET.w, midY(NET)], [760, midY(NET)]]

const T = { ask: [.3, 1.2], request: [1.5, 2.7], read: [3.0, 3.7], open: [3.8, 4.5], reply: [5.0, 6.2], answer: [6.4, 7.2], sync: [7.8, 9.0] } as const

function Agent({ clock }: { clock: Clock }) {
  const cli = useFlash(clock, [T.ask[1], T.answer[0]])
  const core = useFlash(clock, [T.request[1], T.open[1]])
  const store = useFlash(clock, [T.read[1]], 1.4)
  const net = useFlash(clock, [T.sync[0]], 1.6)
  const term = useFlash(clock, [T.answer[1]])
  return <>
    <Wire points={toCli} />
    <Wire points={toCore} />
    <Wire points={[[395, midY(CORE)], [395, midY(NET)], [NET.x, midY(NET)]]} />
    <Wire points={[[395, midY(STORE)], [STORE.x, midY(STORE)]]} />
    <Wire points={out} dashed />
    <Note x={TERM.x} y={TERM.y - 12}>you, or an ai agent</Note>
    <Card {...TERM} label="terminal" heat={term} />
    <Card {...CLI} label="deadbolt" detail="cli" heat={cli} />
    <circle cx={SOCK[0]} cy={SOCK[1]} r={4} fill="#000" stroke="#777" />
    <Note x={SOCK[0]} y={SOCK[1] + 24} anchor="middle">agent.sock</Note>
    <Note x={SOCK[0]} y={SOCK[1] + 38} anchor="middle">user-only</Note>
    <rect x={AGENT.x + .5} y={AGENT.y + .5} width={AGENT.w - 1} height={AGENT.h - 1} fill="none" stroke="#262626" />
    <Note x={AGENT.x} y={AGENT.y - 8}>deadbolt agent · background process</Note>
    <Card {...CORE} label="vault state" detail="deadbolt-core" heat={core} />
    <Card {...STORE} label="store.redb" detail="deadbolt-store" heat={store} tone="red" />
    <Card {...NET} label="iroh node" detail="deadbolt-net" heat={net} />
    <Note x={758} y={midY(NET) - 10} anchor="end">devices</Note>
    <Packet clock={clock} path={toCli} from={T.ask[0]} to={T.ask[1]} label="get github" />
    <Packet clock={clock} path={toCore} from={T.request[0]} to={T.request[1]} label="item-get" />
    <Packet clock={clock} path={coreToStore} from={T.read[0]} to={T.read[1]} sealed />
    <Packet clock={clock} path={storeToCore} from={T.open[0]} to={T.open[1]} />
    <Packet clock={clock} path={[...toCore].reverse()} from={T.reply[0]} to={T.reply[1]} label="item" />
    <Packet clock={clock} path={[...toCli].reverse()} from={T.answer[0]} to={T.answer[1]} label="password" />
    <Packet clock={clock} path={out} from={T.sync[0]} to={T.sync[1]} label="sync" />
  </>
}

export function AgentScene() {
  return <Scene duration={9.6} height={300} label="The cli sends one request over a unix socket to the background agent, which alone opens the store and runs the iroh node."
    fields={() => [{ x: STORE.x + 100, y: STORE.y + 6, w: 40, h: STORE.h - 12, density: .5 }]}
    beats={[
      { at: 0, text: "you type `deadbolt get github`. the cli is a thin client: it never opens the store itself." },
      { at: T.request[0], text: "it sends one line of json over a unix socket that only your user can open. if no agent is running, the cli starts one." },
      { at: T.read[0], text: "the agent is the only process that opens store.redb. it holds the vault unlocked in memory and opens records as needed." },
      { at: T.reply[0], text: "the answer goes back the same way. a secret leaves the agent only when a command asks for it." },
      { at: T.sync[0], text: "while unlocked, the agent also runs the iroh node that syncs with your other devices. lock it and both stop." },
    ]}>
    {clock => <Agent clock={clock} />}
  </Scene>
}
