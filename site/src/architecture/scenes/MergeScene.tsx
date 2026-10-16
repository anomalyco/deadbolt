import { Scene } from "../../scene/Scene"
import { Card, Note, Packet, Show, Wire, useFlash, type Clock, type Point } from "../../scene/kit"

// Two devices edit the same field while apart. Both edits replace v1, so neither saw the other: the edit whose
// entry hash is higher wins on every device, and the other value goes into the item's history.

const ITEM = { x: 230, y: 20, w: 300, h: 120 }
const L = { x: 20, y: 170, w: 250, h: 100 }, R = { x: 490, y: 170, w: 250, h: 100 }
const cross: Point[] = [[L.x + L.w, 210], [R.x, 210]]
const crossBack: Point[] = [[R.x, 240], [L.x + L.w, 240]]
const up = (x: number): Point[] => [[x, L.y], [x, ITEM.y + ITEM.h]]

const T = { edits: .6, sync: [2.0, 3.4], concurrent: 3.8, compare: 5.0, settle: 6.6, next: 8.4, nextLand: 9.8 } as const

function Merge({ clock }: { clock: Clock }) {
  const item = useFlash(clock, [T.settle, T.nextLand], 1.4)
  const left = useFlash(clock, [T.edits, T.sync[1], T.next])
  const right = useFlash(clock, [T.edits + .2, T.sync[1]])
  return <>
    <Wire points={cross} /><Wire points={crossBack} />
    <Wire points={up(145)} dashed /><Wire points={up(615)} dashed />
    <Card {...ITEM} label="github" detail="login" heat={item}>
      <Note x={ITEM.x + 20} y={ITEM.y + 62} tone="label">username</Note><Note x={ITEM.x + 120} y={ITEM.y + 62} tone="light">kit</Note>
      <Note x={ITEM.x + 20} y={ITEM.y + 82} tone="label">password</Note>
      <Show clock={clock} from={0} to={T.settle}><Note x={ITEM.x + 120} y={ITEM.y + 82} tone="light">v1 · ••••••</Note></Show>
      <Show clock={clock} from={T.settle} to={T.nextLand}><Note x={ITEM.x + 120} y={ITEM.y + 82} tone="light">blue-whale</Note></Show>
      <Show clock={clock} from={T.nextLand}><Note x={ITEM.x + 120} y={ITEM.y + 82} tone="light">green-fox</Note></Show>
      <Show clock={clock} from={T.settle}><Note x={ITEM.x + 20} y={ITEM.y + 104}>history: red-panda (concurrent)</Note></Show>
    </Card>
    <Card {...L} label="studio" heat={left}>
      <Show clock={clock} from={T.edits} to={T.next}>
        <Note x={L.x + 18} y={L.y + 54} tone="light">set password = red-panda</Note>
        <Note x={L.x + 18} y={L.y + 72}>based on v1 · hash 7c1e…</Note>
      </Show>
      <Show clock={clock} from={T.next}>
        <Note x={L.x + 18} y={L.y + 54} tone="light">set password = green-fox</Note>
        <Note x={L.x + 18} y={L.y + 72}>based on blue-whale</Note>
      </Show>
    </Card>
    <Card {...R} label="macbook pro" heat={right}>
      <Show clock={clock} from={T.edits + .2}>
        <Note x={R.x + 18} y={R.y + 54} tone="light">set password = blue-whale</Note>
        <Note x={R.x + 18} y={R.y + 72}>based on v1 · hash a94b…</Note>
      </Show>
    </Card>
    <Show clock={clock} from={T.concurrent} to={T.next}>
      <Note x={380} y={168} anchor="middle" tone="label">neither saw the other</Note>
    </Show>
    <Show clock={clock} from={T.compare} to={T.next}>
      <Note x={380} y={290} anchor="middle" tone="light">a94b… &gt; 7c1e… → blue-whale wins, everywhere</Note>
    </Show>
    <Packet clock={clock} path={cross} from={T.sync[0]} to={T.sync[1]} label="edit" />
    <Packet clock={clock} path={crossBack} from={T.sync[0] + .2} to={T.sync[1] + .2} label="edit" />
    <Packet clock={clock} path={up(145)} from={T.next + .2} to={T.nextLand} label="replaces" />
  </>
}

export function MergeScene() {
  return <Scene duration={10.6} height={300} label="Two concurrent edits to the same field: the higher entry hash wins on every device and the other value goes to history."
    beats={[
      { at: 0, text: "an item is a set of typed fields. every edit records which value it replaces." },
      { at: T.edits, text: "studio and the pro both change the password while apart. both edits replace v1." },
      { at: T.sync[0], text: "when they sync, each device ends up with two edits, neither of which had seen the other." },
      { at: T.compare, text: "every device picks the same winner: the edit whose entry has the higher hash. no clocks, no coin flips, the same answer in any order." },
      { at: T.settle, text: "the losing value isn't thrown away. it stays in the item's history." },
      { at: T.next, text: "an edit made after seeing the current value just replaces it. conflicts only happen when edits are truly concurrent." },
    ]}>
    {clock => <Merge clock={clock} />}
  </Scene>
}
