import type { Light } from "../../story/light"
import { across, between, drawOn, panX, polyline, send, soundOfSend, spark, timing, type Send } from "../../story/beats"
import { Carried, Frame, RefusalMark, edge } from "../../story/devices"
import { clamp01, flashes, shade, working, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// Two keys on the desktop: the passphrase stretches through Argon2id (64 MiB, 3 passes) into the local unlock key,
// which opens the sealed keyset holding the random data key (seals store.redb) and the Ed25519 device key (the
// desktop's identity for signing entries and dialing over iroh). A wrong passphrase fails AEAD on the keyset.

const W = 940, H = 330

const PASS: Box = [44, 38, 168, 54]
const KDF: Box = [254, 38, 236, 54]
const UNLOCK: Box = [532, 38, 212, 54]
const KEYSET: Box = [416, 134, 284, 54]
const STORE: Box = [44, 232, 276, 54]
const DATA: Box = [372, 232, 168, 54]
const DEVICE: Box = [564, 232, 216, 54]

const toKdf = across(edge.right(PASS), edge.left(KDF))
const toUnlock = across(edge.right(KDF), edge.left(UNLOCK))
const toKeyset = between([596, UNLOCK[1] + UNLOCK[3]], [596, KEYSET[1]])
const toData = between([478, KEYSET[1] + KEYSET[3]], [478, DATA[1]])
const toDevice = between([636, KEYSET[1] + KEYSET[3]], [636, DEVICE[1]])
const dataToStore = across(edge.left(DATA), edge.right(STORE))
const wrongPath = polyline([
  edge.right(PASS), edge.left(KDF), edge.right(KDF), edge.left(UNLOCK),
  [652, UNLOCK[1] + UNLOCK[3] / 2], [652, KEYSET[1]],
])

type Shot = Send & { id: string; label?: string }

const sPass: Shot = { id: "toKdf", path: toKdf, at: .25, flight: .75, label: "passphrase", into: { box: KDF } }
const sKey: Shot = { id: "toUnlock", path: toUnlock, at: 2.8, flight: .8, label: "256-bit key", tone: "red", into: { box: UNLOCK, tone: "red" } }
const sOpen: Shot = { id: "toKeyset", path: toKeyset, at: 5.2, flight: .7, label: "unseal", tone: "red", into: { box: KEYSET, tone: "red" } }
const REVEAL = timing(sOpen).lands + .1
const sSeal: Shot = { id: "dataToStore", path: dataToStore, at: 8.2, flight: .85, label: "xchacha20", tone: "red", into: { box: STORE } }
const SIGN_AT = 11.2
const sWrong: Shot = { id: "wrong", path: wrongPath, at: 14.0, flight: 1.45, label: "wrong passphrase", tone: "amber" }
const REFUSED = timing(sWrong).lands

const SHOTS: readonly Shot[] = [sPass, sKey, sOpen, sSeal, sWrong]
const DESKTOP_IMPULSES = [REVEAL, SIGN_AT]

export const keysScene: StoryScene = {
  label: "Your passphrase is stretched by Argon2id into the unlock key, which opens the sealed keyset holding the data key and the desktop's device key.",
  width: W, height: H, duration: 18.0, poster: 4,
  sounds: [
    ...soundOfSend(sPass, W, .8).cues,
    ...soundOfSend(sKey, W, .8).cues,
    { at: timing(sOpen).lands, cue: "unlock", detail: { pan: panX(KEYSET[0] + KEYSET[2] / 2, W) } },
    ...soundOfSend(sSeal, W, .8).cues,
    { at: SIGN_AT, cue: "seal", detail: { pan: panX(DEVICE[0] + DEVICE[2] / 2, W) } },
    { at: timing(sWrong).launch, cue: "send", detail: { pan: panX(PASS[0] + PASS[2], W), gain: .75 } },
    { at: REFUSED, cue: "refuse", detail: { pan: panX(652, W) } },
  ],
  flights: [sPass, sKey, sOpen, sSeal, sWrong].map(s => soundOfSend(s, W, .75).flight),
  steps: [
    {
      at: 0,
      focus: { pass: 1, kdf: 1, toKdf: 1 },
      caption: { text: "argon2id stretches the passphrase across 64 MiB and 3 passes", anchor: [KDF[0] + KDF[2] / 2, KDF[1] + KDF[3]], place: [372, 118], align: "below", delay: 0 },
    },
    {
      at: 2.6,
      focus: { kdf: .8, unlock: 1, toUnlock: 1 },
      caption: { text: "the local unlock key lives only in memory", anchor: [UNLOCK[0] + UNLOCK[2] / 2, UNLOCK[1] + UNLOCK[3]], place: [764, 65], align: "start", delay: .25 },
    },
    {
      at: 5.0,
      focus: { unlock: .8, keyset: 1, data: 1, device: 1, toKeyset: 1, toData: 1, toDevice: 1 },
      caption: { text: "it opens the sealed keyset holding the data key and device key", anchor: [KEYSET[0], KEYSET[1] + KEYSET[3] / 2], place: [380, 161], align: "end", delay: .25 },
    },
    {
      at: 8.0,
      focus: { data: 1, store: 1, dataToStore: 1, keyset: .5 },
      caption: { text: "the data key seals every record and keyed hash in store.redb", anchor: [STORE[0] + STORE[2] / 2, STORE[1]], place: [182, 194], align: "above", delay: .25 },
    },
    {
      at: 11.0,
      focus: { device: 1, data: .6, store: .6, keyset: .5 },
      caption: { text: "the device key signs entries and is the desktop's iroh address", anchor: [DEVICE[0] + DEVICE[2], DEVICE[1] + DEVICE[3] / 2], place: [796, 259], align: "start", delay: .2 },
    },
    {
      at: 13.8,
      focus: { pass: .8, kdf: .8, unlock: .8, keyset: 1, toKdf: .7, toUnlock: .7, toKeyset: .9 },
      caption: { text: "a wrong passphrase simply fails to open the keyset", anchor: [652, KEYSET[1]], place: [736, 146], align: "start", delay: .4 },
    },
  ],
  draw: (t, light, story) => <Keys t={t} light={light} story={story} />,
}

function Wire({ id, d, t, story, drawn = 1 }: { id: string; d: string; t: number; story: StoryApi; drawn?: number }) {
  if (drawn <= 0) return null
  const level = story.focus(t, id, .22)
  const lit = clamp01((level - .22) / .78)
  return <path d={d} fill="none" stroke={shade("#252525", ["#7c7972", lit])} pathLength={1} strokeDasharray={`${drawn} 2`} />
}

function Keys({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  for (const shot of SHOTS) send(light, shot, t)

  const kdfPulses = [timing(sPass).lands, timing(sPass).lands + .45, timing(sPass).lands + .9, sWrong.at + .55]
  const kdfHeat = flashes(t, kdfPulses, .75)
  const unlockHeat = flashes(t, [timing(sKey).lands], 1.3)
  const keysetHeat = flashes(t, [timing(sOpen).lands, REFUSED], 1.3)
  const dataHeat = flashes(t, [REVEAL + .3, sSeal.at + .25], 1.1)
  const storeHeat = flashes(t, [timing(sSeal).lands], 1.3)
  const deviceHeat = flashes(t, [REVEAL + .35, SIGN_AT], 1.3)

  if (t >= SIGN_AT && t < SIGN_AT + 1.2) {
    spark(light, [DEVICE[0] + DEVICE[2], DEVICE[1] + DEVICE[3] / 2], t - SIGN_AT, "red", .85)
  }

  const dData = drawOn(light, toData, t, REVEAL, .45, "red", .7)
  const dDevice = drawOn(light, toDevice, t, REVEAL + .06, .45, "red", .7)

  const kdfDetail = (t >= timing(sPass).lands && t < sKey.at)
    ? working("64 MiB · 3 passes", t, timing(sPass).lands, sKey.at - .1, 7) ?? "64 MiB · 3 passes"
    : "64 MiB · 3 passes"
  const keysetDetail = t < REVEAL ? "sealed" : t >= REFUSED ? "aead tag failed" : "opened"

  return <>
    <Wire id="toKdf" d={toKdf.d} t={t} story={story} />
    <Wire id="toUnlock" d={toUnlock.d} t={t} story={story} />
    <Wire id="toKeyset" d={toKeyset.d} t={t} story={story} />
    <Wire id="toData" d={toData.d} t={t} story={story} drawn={dData} />
    <Wire id="toDevice" d={toDevice.d} t={t} story={story} drawn={dDevice} />
    <Wire id="dataToStore" d={dataToStore.d} t={t} story={story} drawn={dData} />

    <Frame id="pass" box={PASS} t={t} story={story} light={light} label="passphrase" detail="secret" />
    <Frame id="kdf" box={KDF} t={t} story={story} light={light} label="argon2id" detail={kdfDetail} heat={kdfHeat} />
    <Frame id="unlock" box={UNLOCK} t={t} story={story} light={light} label="unlock key" detail="in memory" tone="red" heat={unlockHeat} />
    <Frame id="keyset" box={KEYSET} t={t} story={story} light={light} label="keyset" detail={keysetDetail}
      tone="red" heat={keysetHeat} broken={t >= REFUSED ? clamp01((t - REFUSED) / .25) : 0} />

    <Frame id="store" box={STORE} t={t} story={story} light={light} label="store.redb" detail="log · index · meta" heat={storeHeat} />
    <Frame id="data" box={DATA} t={t} story={story} light={light} label="data key" detail="256-bit" tone="red" heat={dataHeat} appearAt={REVEAL} />
    <Frame id="device" box={DEVICE} t={t} story={story} light={light} glyph="desktop" impulses={DESKTOP_IMPULSES}
      label="device key" detail="ed25519 · iroh id" tone="red" heat={deviceHeat} appearAt={REVEAL + .06} />

    <RefusalMark x={652} y={KEYSET[1]} t={t} at={REFUSED} light={light} />

    {SHOTS.map(shot => <Carried key={shot.id} shot={shot} t={t} label={shot.label} />)}
  </>
}

export function KeysStory() {
  return <Story scene={keysScene} />
}
