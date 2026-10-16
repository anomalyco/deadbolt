import type { Light } from "../../story/light"
import { across, between, cipher, drawOn, panX, send, soundOfSend, spark, timing, type Send } from "../../story/beats"
import { Carried, Frame, RefusalMark, edge } from "../../story/devices"
import { clamp01, flashes, shade, span, wipe, working, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// Two keys on the desktop: the passphrase stretches through Argon2id (64 MiB, 3 passes) into the local unlock key,
// which opens the sealed keyset holding the random data key (seals store.redb) and the Ed25519 device key (the
// desktop's identity for signing entries and dialing over iroh). A wrong passphrase fails AEAD on the keyset.
//
// Composition: the derivation runs left to right along the top, the keyset sits under the unlock key, and the two
// keys it holds come out beneath it. The keyset and the store print their ciphertext; the unseal wicks the
// keyset's band clear from the socket it arrived at, and sealing churns the store's bits.

const W = 940, H = 330

const PASS: Box = [36, 40, 160, 54]
const KDF: Box = [228, 40, 220, 54]
const UNLOCK: Box = [480, 40, 200, 54]
const KEYSET: Box = [364, 124, 316, 78]
const STORE: Box = [36, 236, 276, 54]
const DATA: Box = [344, 236, 152, 54]
const DEVICE: Box = [520, 236, 250, 54]
const KEYSET_BAND: Box = [KEYSET[0] + 8, KEYSET[1] + 38, KEYSET[2] - 16, 30]
const STORE_BAND: Box = [STORE[0] + 102, STORE[1] + 12, STORE[2] - 112, 30]
const SOCKET = edge.top(KEYSET, 58)

const toKdf = across(edge.right(PASS), edge.left(KDF))
const toUnlock = across(edge.right(KDF), edge.left(UNLOCK))
const toKeyset = between(edge.bottom(UNLOCK), SOCKET)
const toData = between([420, KEYSET[1] + KEYSET[3]], edge.top(DATA))
const toDevice = between([624, KEYSET[1] + KEYSET[3]], [624, DEVICE[1]])
const dataToStore = across(edge.left(DATA), edge.right(STORE))

type Shot = Send & { id: string; label?: string; side?: "left" | "right" }

const sPass: Shot = { id: "toKdf", path: toKdf, at: .25, flight: .7, label: "passphrase", into: { box: KDF } }
const sKey: Shot = { id: "toUnlock", path: toUnlock, at: 2.8, flight: .7, label: "256-bit key", tone: "red", into: { box: UNLOCK, tone: "red" } }
const sOpen: Shot = { id: "toKeyset", path: toKeyset, at: 5.2, flight: .55, label: "unseal", side: "right", tone: "red", into: { box: KEYSET, tone: "red" } }
const OPENED = timing(sOpen).lands
const REVEAL = OPENED + .35
const sSeal: Shot = { id: "dataToStore", path: dataToStore, at: 8.2, flight: .55, label: "xchacha20", tone: "red", into: { box: STORE } }
const SEALED = timing(sSeal).lands
const SIGN_AT = 11.2

// A wrong passphrase goes through the same pipeline, card by card, and dies at the keyset.
const RESEAL = 13.9
const sWrong: Shot = { id: "wrongKdf", path: toKdf, at: 14.2, flight: .7, label: "wrong passphrase", tone: "amber", into: { box: KDF, tone: "amber" } }
const sWrongKey: Shot = { id: "wrongUnlock", path: toUnlock, at: timing(sWrong).lands + .35, gather: .2, flight: .6, label: "wrong key", tone: "amber", into: { box: UNLOCK, tone: "amber" } }
const sWrongOpen: Shot = { id: "wrongKeyset", path: toKeyset, at: timing(sWrongKey).lands + .15, gather: .2, flight: .5, tone: "amber" }
const REFUSED = timing(sWrongOpen).lands

const SHOTS: readonly Shot[] = [sPass, sKey, sOpen, sSeal, sWrong, sWrongKey, sWrongOpen]
const DESKTOP_IMPULSES = [REVEAL, SIGN_AT]

export const keysScene: StoryScene = {
  label: "Your passphrase is stretched by Argon2id into the unlock key, which opens the sealed keyset holding the data key and the desktop's device key.",
  width: W, height: H, duration: REFUSED + 2.3, poster: 4,
  sounds: [
    ...soundOfSend(sPass, W, .8).cues,
    ...soundOfSend(sKey, W, .8).cues,
    { at: OPENED, cue: "unlock", detail: { pan: panX(SOCKET[0], W) } },
    ...soundOfSend(sSeal, W, .8).cues,
    { at: SIGN_AT, cue: "seal", detail: { pan: panX(DEVICE[0] + DEVICE[2] / 2, W) } },
    ...soundOfSend(sWrong, W, .75).cues,
    { at: timing(sWrongKey).launch, cue: "send", detail: { pan: panX(KDF[0] + KDF[2], W), gain: .7 } },
    { at: REFUSED, cue: "refuse", detail: { pan: panX(SOCKET[0], W) } },
  ],
  flights: [sPass, sKey, sOpen, sSeal, sWrong, sWrongKey, sWrongOpen].map(s => soundOfSend(s, W, .75).flight),
  steps: [
    {
      at: 0,
      focus: { pass: 1, kdf: 1, toKdf: 1 },
      caption: { text: "argon2id stretches the passphrase with 64 MiB of memory and 3 passes", width: 34, anchor: edge.bottom(KDF, -78), place: [212, 114], align: "below", delay: 0 },
    },
    {
      at: 2.6,
      focus: { kdf: .8, unlock: 1, toUnlock: 1 },
      caption: { text: "the local unlock key lives only in memory", anchor: edge.right(UNLOCK), place: [698, 67], align: "start", delay: .25 },
    },
    {
      at: 5.0,
      focus: { unlock: .8, keyset: 1, data: 1, device: 1, toKeyset: 1, toData: 1, toDevice: 1 },
      caption: { text: "it opens the keyset, which holds the data and device keys", anchor: edge.left(KEYSET), place: [344, 163], align: "end", delay: .25 },
    },
    {
      at: 8.0,
      focus: { data: 1, store: 1, dataToStore: 1, keyset: .5 },
      caption: { text: "the data key seals every record and keyed hash in store.redb", width: 32, anchor: edge.top(STORE), place: [174, 220], align: "above", delay: .25 },
    },
    {
      at: 11.0,
      focus: { device: 1, data: .6, store: .6, keyset: .5 },
      caption: { text: "the device key signs entries and is the iroh address", width: 28, anchor: [DEVICE[0] + DEVICE[2] - 30, DEVICE[1]], place: [806, 226], align: "above", delay: .2 },
    },
    {
      at: 13.8,
      focus: { pass: .8, kdf: .8, unlock: .8, keyset: 1, toKdf: .7, toUnlock: .7, toKeyset: .9, data: .2, device: .2, store: .3 },
      caption: { text: "a wrong passphrase simply fails to open the keyset", anchor: [SOCKET[0] + 12, SOCKET[1] - 6], place: [700, 112], align: "start", delay: .4 },
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

  const kdfPulses = [timing(sPass).lands, timing(sPass).lands + .45, timing(sPass).lands + .9, timing(sWrong).lands, timing(sWrong).lands + .3]
  const kdfHeat = flashes(t, kdfPulses, .75)
  const unlockHeat = flashes(t, [timing(sKey).lands, timing(sWrongKey).lands], 1.3)
  const keysetHeat = flashes(t, [OPENED, REFUSED], 1.3)
  const dataHeat = flashes(t, [REVEAL + .3, sSeal.at + .25], 1.1)
  const storeHeat = flashes(t, [SEALED], 1.3)
  const deviceHeat = flashes(t, [REVEAL + .35, SIGN_AT], 1.3)

  if (t >= SIGN_AT && t < SIGN_AT + 1.2) {
    spark(light, edge.right(DEVICE), t - SIGN_AT, "red", .85)
  }

  // The keyset's ciphertext wicks clear from the socket the unseal arrived at (√t). When the vault locks again
  // the clearing closes back over it like an iris, before the wrong passphrase arrives.
  const clearing = Math.sqrt(span(t, OPENED, OPENED + 1.1)) * (1 - wipe(t, RESEAL, .6))
  cipher(light, KEYSET_BAND, { tone: "red", level: .8, seed: 3, open: clearing > .005 ? { from: SOCKET, radius: 250 * clearing } : undefined })
  // Sealing spins the store's bits like a cipher wheel for a moment, then they lock.
  const spinning = t >= SEALED && t < SEALED + .7
  cipher(light, STORE_BAND, { level: .7, seed: 11, churn: spinning ? 1 + Math.floor((t - SEALED) * 24) : t >= SEALED + .7 ? 40 : 0 })

  const dData = drawOn(light, toData, t, REVEAL, .45, "red", .7)
  const dDevice = drawOn(light, toDevice, t, REVEAL + .06, .45, "red", .7)

  const kdfDetail = (t >= timing(sPass).lands && t < sKey.at)
    ? working("64 MiB · 3 passes", t, timing(sPass).lands, sKey.at - .1, 7) ?? "64 MiB · 3 passes"
    : (t >= timing(sWrong).lands && t < sWrongKey.at)
      ? working("64 MiB · 3 passes", t, timing(sWrong).lands, sWrongKey.at - .05, 9) ?? "64 MiB · 3 passes"
      : "64 MiB · 3 passes"
  const keysetDetail = t < OPENED
    ? "sealed"
    : t < RESEAL
      ? working("opened", t, OPENED, OPENED + .3, 2) ?? "opened"
      : t < REFUSED
        ? working("sealed", t, RESEAL, RESEAL + .3, 4) ?? "sealed"
        : working("aead tag failed", t, REFUSED, REFUSED + .4, 6) ?? "aead tag failed"

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
    <Frame id="keyset" box={KEYSET} t={t} story={story} light={light} label="keyset" detail={keysetDetail} headerY={KEYSET[1] + 22}
      tone="red" heat={keysetHeat} broken={t >= REFUSED ? clamp01((t - REFUSED) / .25) : 0} />

    <Frame id="store" box={STORE} t={t} story={story} light={light} label="store.redb" heat={storeHeat} />
    <Frame id="data" box={DATA} t={t} story={story} light={light} label="data key" detail="256-bit" tone="red" heat={dataHeat} appearAt={REVEAL} />
    <Frame id="device" box={DEVICE} t={t} story={story} light={light} glyph="desktop" impulses={DESKTOP_IMPULSES}
      label="device key" detail="ed25519 · iroh id" tone="red" heat={deviceHeat} appearAt={REVEAL + .06} />

    <RefusalMark x={SOCKET[0]} y={SOCKET[1]} t={t} at={REFUSED} light={light} />

    {SHOTS.map(shot => <Carried key={shot.id} shot={shot} t={t} label={shot.label} side={shot.side} />)}
  </>
}

export function KeysStory() {
  return <Story scene={keysScene} />
}
