import { Scene } from "../../scene/Scene"
import { Card, Note, Packet, Refusal, Show, Wire, useFlash, type Clock, type Point } from "../../scene/kit"

// passphrase ─▶ argon2id ─▶ unlock key
//                               │
//  store.redb ◀── data key ◀─ keyset (sealed) ─▶ device key ─▶ signs entries · iroh id

const PASS = { x: 20, y: 30, w: 150, h: 52 }, KDF = { x: 200, y: 30, w: 230, h: 52 }, UNLOCK = { x: 460, y: 30, w: 210, h: 52 }
const KEYSET = { x: 360, y: 124, w: 270, h: 52 }
const DATA = { x: 360, y: 222, w: 130, h: 52 }, DEVICE = { x: 500, y: 222, w: 130, h: 52 }
const STORE = { x: 20, y: 222, w: 290, h: 52 }
const my = (b: { y: number; h: number }) => b.y + b.h / 2

const p1: Point[] = [[PASS.x + PASS.w, my(PASS)], [KDF.x, my(KDF)]]
const p2: Point[] = [[KDF.x + KDF.w, my(KDF)], [UNLOCK.x, my(UNLOCK)]]
const p3: Point[] = [[535, UNLOCK.y + UNLOCK.h], [535, KEYSET.y]]
const p4: Point[] = [[DATA.x, my(DATA)], [STORE.x + STORE.w, my(STORE)]]
const wrong: Point[] = [[PASS.x + PASS.w, my(PASS)], [KDF.x, my(KDF)], [KDF.x + KDF.w, my(KDF)], [UNLOCK.x, my(UNLOCK)], [UNLOCK.x + 50, my(UNLOCK)], [UNLOCK.x + 50, KEYSET.y]]

const T = { pass: [.3, 1.4], stretch: 1.4, key: [3.0, 3.9], open: [4.2, 5.1], reveal: 5.3, seal: [6.4, 7.5], sign: 8.0, wrong: [9.5, 11.2] } as const

function Keys({ clock }: { clock: Clock }) {
  const kdf = useTransform01(clock)
  const unlock = useFlash(clock, [T.key[1]], 2)
  const keyset = useFlash(clock, [T.open[1], T.wrong[1]], 1.6)
  const data = useFlash(clock, [T.seal[0]])
  const store = useFlash(clock, [T.seal[1]], 1.6)
  const device = useFlash(clock, [T.sign], 2)
  return <>
    <Wire points={p1} /><Wire points={p2} /><Wire points={p3} /><Wire points={p4} />
    <Wire points={[[DATA.x + 65, KEYSET.y + KEYSET.h], [DATA.x + 65, DATA.y]]} />
    <Wire points={[[DEVICE.x + 65, KEYSET.y + KEYSET.h], [DEVICE.x + 65, DEVICE.y]]} />
    <Card {...PASS} label="passphrase" />
    <Card {...KDF} label="argon2id" detail="64 MiB · 3 passes" heat={kdf} />
    <Card {...UNLOCK} label="unlock key" detail="never stored" heat={unlock} tone="red" />
    <Card {...KEYSET} label="keyset" detail="sealed" heat={keyset} tone="red" />
    <Show clock={clock} from={T.reveal}>
      <Card {...DATA} label="data key" heat={data} tone="red" />
      <Card {...DEVICE} label="device key" heat={device} tone="red" />
    </Show>
    <Card {...STORE} label="store.redb" detail="log · index · meta" heat={store} />
    <Show clock={clock} from={T.sign}>
      <Note x={DEVICE.x + DEVICE.w + 14} y={my(DEVICE) - 6}>signs entries</Note>
      <Note x={DEVICE.x + DEVICE.w + 14} y={my(DEVICE) + 10}>= iroh id</Note>
    </Show>
    <Packet clock={clock} path={p1} from={T.pass[0]} to={T.pass[1]} label="passphrase" />
    <Packet clock={clock} path={p2} from={T.key[0]} to={T.key[1]} label="256-bit key" />
    <Packet clock={clock} path={p3} from={T.open[0]} to={T.open[1]} />
    <Packet clock={clock} path={p4} from={T.seal[0]} to={T.seal[1]} label="seal · open" />
    <Packet clock={clock} path={wrong} from={T.wrong[0]} to={T.wrong[1]} label="wrong passphrase" tone="red" />
    <Refusal clock={clock} at={T.wrong[1]} x={UNLOCK.x + 50} y={KEYSET.y - 2} />
    <Show clock={clock} from={T.wrong[1]}><Note x={KEYSET.x + KEYSET.w + 12} y={my(KEYSET) + 4} tone="red">aead fails</Note></Show>
  </>
}

/** Argon2id is slow on purpose: it glows for the whole stretch. */
function useTransform01(clock: Clock) {
  return useFlash(clock, [T.pass[1], T.pass[1] + .4, T.pass[1] + .8, T.pass[1] + 1.2, T.wrong[0] + 1.2], .6)
}

export function KeysScene() {
  return <Scene duration={12.4} height={290} label="The passphrase is stretched by Argon2id into the unlock key, which opens the keyset holding the data key and the device key."
    fields={() => [{ x: KEYSET.x + 120, y: KEYSET.y + 6, w: 90, h: 40, density: .6 }, { x: STORE.x + 100, y: STORE.y + 6, w: 55, h: 40, density: .5 }]}
    beats={[
      { at: 0, text: "your passphrase goes through argon2id: slow and memory-hard on purpose, so every guess costs real time and memory." },
      { at: T.key[0], text: "out comes the local unlock key. it only ever lives in memory." },
      { at: T.open[0], text: "the unlock key opens the keyset: one sealed record holding a random data key and this device's key." },
      { at: T.seal[0], text: "the data key seals every record in the store. on disk there's only ciphertext and keyed hashes, not even entry ids." },
      { at: T.sign, text: "the device key signs everything this device writes, and its public half is the device's address on iroh." },
      { at: T.wrong[0], text: "a wrong passphrase just fails to open the keyset. there's no password hash on disk to compare against or attack." },
    ]}>
    {clock => <Keys clock={clock} />}
  </Scene>
}
