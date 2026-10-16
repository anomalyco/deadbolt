import type { Light } from "../../story/light"
import { across, cubic, hatch, panX, send, soundOfSend, timing, type Send } from "../../story/beats"
import { Carried, Frame, edge } from "../../story/devices"
import { belt, clamp01, flashes, rolling, shade, wipe, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// No server: entries move directly between your devices (desktop, laptop, tablet, phone). When two devices
// cannot reach each other directly, an n0 relay forwards the encrypted QUIC stream and sees only ciphertext.
// A device that was asleep catches up from whichever member it reaches first.
//
// Composition: the desktop on the left, your other devices stacked in a group on the right, the relay above the
// direct line. Every wire is either straight or a single S-curve, and none crosses another.

const W = 940, H = 330

const DESKTOP: Box = [44, 141, 212, 56]
const RELAY: Box = [356, 58, 216, 66]
const GROUP: Box = [656, 40, 244, 258]
const TABLET: Box = [676, 64, 196, 54]
const LAPTOP: Box = [676, 142, 196, 54]
const PHONE: Box = [676, 220, 196, 54]
/** The relay's hatched band, under its header: the stream passing through, unreadable. */
const RELAY_BAND: Box = [RELAY[0] + 8, RELAY[1] + 38, RELAY[2] - 16, 20]

const toLaptop = across(edge.right(DESKTOP), edge.left(LAPTOP))
const toRelay = across(edge.right(DESKTOP, -12), edge.left(RELAY), .48)
const fromRelay = across(edge.right(RELAY), edge.left(TABLET))
// Missed entries come round the outside of the group, from the laptop's right side to the phone's.
const catchUp = cubic(edge.right(LAPTOP, 12), [LAPTOP[0] + LAPTOP[2] + 26, LAPTOP[1] + 39], [PHONE[0] + PHONE[2] + 26, PHONE[1] + 15], edge.right(PHONE, -12))

type Shot = Send & { id: string; label?: string }

const sDirect: Shot = { id: "toLaptop", path: toLaptop, at: .35, label: "entry", into: { box: LAPTOP } }
const sRelayIn: Shot = { id: "toRelay", path: toRelay, at: 3.55, label: "ciphertext", tone: "red", into: { box: RELAY, tone: "red" } }
const RELAYING = timing(sRelayIn).lands
const sRelayOut: Shot = { id: "fromRelay", path: fromRelay, at: RELAYING + .3, gather: .2, label: "ciphertext", tone: "red", into: { box: TABLET, tone: "ivory" } }
const WAKE = 7.4
const sCatchUp: Shot = { id: "catchUp", path: catchUp, at: WAKE + .45, flight: .7, label: "missed entries", into: { box: PHONE } }
const SYNCED = timing(sCatchUp).lands

const SHOTS: readonly Shot[] = [sDirect, sRelayIn, sRelayOut, sCatchUp]
/** The relay's belt runs while ciphertext is passing through: from its arrival until it has left again. */
const RELAY_DRIVE = [RELAYING, timing(sRelayOut).launch + .25] as const
const BELT_SPEED = 70

const DESKTOP_IMPULSES = [sDirect.at, sRelayIn.at]
const LAPTOP_IMPULSES = [timing(sDirect).lands, sCatchUp.at]
const TABLET_IMPULSES = [timing(sRelayOut).lands]
const PHONE_IMPULSES = [WAKE, SYNCED]

export const meshScene: StoryScene = {
  label: "Devices hold the vault and sync entries directly over iroh, using an n0 relay for encrypted ciphertext only when direct connection fails.",
  width: W, height: H, duration: 11.4, poster: 2,
  sounds: [
    ...SHOTS.flatMap(s => soundOfSend(s, W, .8).cues),
    { at: WAKE, cue: "write", detail: { pan: panX(PHONE[0] + PHONE[2] / 2, W), gain: .7 } },
  ],
  flights: SHOTS.map(s => soundOfSend(s, W, .75).flight),
  steps: [
    {
      at: 0,
      focus: { desktop: 1, laptop: 1, toLaptop: 1, group: .7 },
      caption: { text: "a change on the desktop goes straight to the laptop", anchor: toLaptop.at(.5), place: [466, 184], align: "below", delay: 0 },
    },
    {
      at: 3.35,
      focus: { desktop: .9, relay: 1, tablet: 1, toRelay: 1, fromRelay: 1, group: .6 },
      caption: { text: "if direct fails, a relay forwards ciphertext it can't read", width: 34, anchor: edge.top(RELAY), place: [464, 50], align: "above", delay: .25 },
    },
    {
      at: 7.2,
      focus: { laptop: 1, phone: 1, catchUp: 1, group: .85, desktop: .5, tablet: .5 },
      caption: { text: "a phone that was asleep catches up from any member", anchor: edge.left(PHONE), place: [646, 247], align: "end", delay: .35 },
    },
  ],
  draw: (t, light, story) => {
    meshLights(t, light)
    return <Mesh t={t} light={light} story={story} />
  },
}

function meshLights(t: number, light: Light) {
  for (const shot of SHOTS) send(light, shot, t)

  // The relay's band: hatched noise on a belt under a fixed window. From the moment the ciphertext arrives until it
  // has left again, the belt is driven along the stream (left to right); it has mass, so it spins up and coasts to a
  // stop on a zero-bounce spring, and its ink warms from ivory to red with its speed.
  const { travel, speed } = belt(t, [RELAY_DRIVE], BELT_SPEED, .6)
  const running = clamp01(speed / BELT_SPEED)
  hatch(light, RELAY_BAND, { tone: "ivory", level: .55 * (1 - running), seed: 4, churn: travel })
  hatch(light, RELAY_BAND, { tone: "red", level: 1.15 * running, seed: 4, churn: travel })
}

function Wire({ id, d, t, story, dashed }: { id: string; d: string; t: number; story: StoryApi; dashed?: boolean }) {
  const level = story.focus(t, id, .22)
  const lit = clamp01((level - .22) / .78)
  const stroke = shade("#252525", ["#7c7972", lit])
  return <path d={d} fill="none" stroke={stroke} strokeDasharray={dashed ? "2 5" : undefined} />
}

function Mesh({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  const desktopHeat = flashes(t, [sDirect.at + .3, sRelayIn.at + .3], .9)
  const laptopHeat = flashes(t, [timing(sDirect).lands, sCatchUp.at + .3], 1.1)
  const tabletHeat = flashes(t, [timing(sRelayOut).lands], 1.1)
  const relayHeat = flashes(t, [RELAYING], 1.3)
  const phoneHeat = flashes(t, [WAKE, SYNCED], 1.2)

  // The phone keeps its card: it wakes (its dashes close up like a zip) and its detail rolls over to synced.
  const asleep = 1 - wipe(t, WAKE, .4)
  const phoneDetail = rolling(t, [[0, "asleep"], [WAKE, "waking…"], [SYNCED, "member · synced"]], 3)

  const groupLit = clamp01((story.focus(t, "group", .3) - .3) / .7)

  return <>
    <Wire id="toLaptop" d={toLaptop.d} t={t} story={story} />
    <Wire id="toRelay" d={toRelay.d} t={t} story={story} dashed />
    <Wire id="fromRelay" d={fromRelay.d} t={t} story={story} dashed />
    <Wire id="catchUp" d={catchUp.d} t={t} story={story} />

    <text x={DESKTOP[0]} y={DESKTOP[1] - 10} className="story-note" fill="#7a7a7a">this device</text>
    <Frame id="desktop" box={DESKTOP} t={t} story={story} light={light} glyph="desktop" impulses={DESKTOP_IMPULSES}
      label="desktop" detail="member" heat={desktopHeat} />

    <Frame id="relay" box={RELAY} t={t} story={story} light={light} label="n0 relay" detail="if direct fails"
      tone="red" toned={relayHeat} heat={relayHeat} dashed headerY={RELAY[1] + 21} />

    <rect x={GROUP[0] + .5} y={GROUP[1] + .5} width={GROUP[2] - 1} height={GROUP[3] - 1}
      fill="none" stroke={shade("#1f1f1f", ["#383838", groupLit])} />
    <text x={GROUP[0]} y={GROUP[1] - 10} className="story-note" fill={shade("#666666", ["#a8a49c", groupLit])}>your other devices</text>

    <Frame id="tablet" box={TABLET} t={t} story={story} light={light} glyph="tablet" impulses={TABLET_IMPULSES}
      label="tablet" detail="member" heat={tabletHeat} />
    <Frame id="laptop" box={LAPTOP} t={t} story={story} light={light} glyph="laptop" impulses={LAPTOP_IMPULSES}
      label="laptop" detail="member" heat={laptopHeat} />
    <Frame id="phone" box={PHONE} t={t} story={story} light={light} glyph="phone" impulses={PHONE_IMPULSES}
      label="phone" detail={phoneDetail} heat={phoneHeat} dashed={asleep} />

    {SHOTS.map(shot => <Carried key={shot.id} shot={shot} t={t} label={shot.label} />)}
  </>
}

export function MeshStory() {
  return <Story scene={meshScene} />
}
