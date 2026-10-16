import type { Light } from "../../story/light"
import { across, bridge, panX, send, soundOfSend, timing, type Send } from "../../story/beats"
import { Carried, Frame, edge } from "../../story/devices"
import { clamp01, flashes, shade, span, working, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// No server: entries move directly between your devices (desktop, laptop, tablet, phone). When two devices
// cannot reach each other directly, an n0 relay forwards the encrypted QUIC stream and sees only ciphertext.
// A device that was asleep catches up from whichever member it reaches first.

const W = 940, H = 330

const DESKTOP: Box = [44, 152, 212, 56]
const RELAY: Box = [356, 42, 216, 56]
const GROUP: Box = [656, 34, 248, 258]
const LAPTOP: Box = [676, 66, 208, 54]
const TABLET: Box = [676, 142, 208, 54]
const PHONE: Box = [676, 218, 208, 54]

const toLaptop = across(edge.right(DESKTOP, -8), edge.left(LAPTOP))
const toTablet = across(edge.right(DESKTOP), edge.left(TABLET))
const toRelay = across(edge.right(DESKTOP, -14), edge.left(RELAY), .48)
const fromRelay = across(edge.right(RELAY), edge.left(TABLET, -8), .48)
const peerCatchup = bridge(edge.left(LAPTOP, 12), edge.left(PHONE, -12), 42)

type Shot = Send & { id: string; label?: string }

const sDirect1: Shot = {
  id: "toLaptop", path: toLaptop, at: .35, label: "entry",
  tone: "ivory", into: { box: LAPTOP },
}
const sDirect2: Shot = {
  id: "toTablet", path: toTablet, at: 3.6, label: "entry",
  tone: "ivory", into: { box: TABLET },
}
const sRelayIn: Shot = {
  id: "toRelay", path: toRelay, at: 6.8, label: "ciphertext",
  tone: "red", into: { box: RELAY, tone: "red" },
}
const sRelayOut: Shot = {
  id: "fromRelay", path: fromRelay, at: timing(sRelayIn).lands + .08, label: "ciphertext",
  tone: "red", into: { box: TABLET, tone: "ivory" },
}
const WAKE = 11.2
const sCatchup: Shot = {
  id: "catchUp", path: peerCatchup, at: WAKE + .35, label: "missed entries",
  tone: "ivory", into: { box: PHONE },
}

const SHOTS: readonly Shot[] = [sDirect1, sDirect2, sRelayIn, sRelayOut, sCatchup]

const DESKTOP_IMPULSES = [sDirect1.at, sDirect2.at, sRelayIn.at]
const LAPTOP_IMPULSES = [timing(sDirect1).lands, sCatchup.at]
const TABLET_IMPULSES = [timing(sDirect2).lands, timing(sRelayOut).lands]
const PHONE_IMPULSES = [WAKE, timing(sCatchup).lands]

export const meshScene: StoryScene = {
  label: "Devices hold the vault and sync entries directly over iroh, using an n0 relay for encrypted ciphertext only when direct connection fails.",
  width: W, height: H, duration: 15.2, poster: 3,
  sounds: [
    ...SHOTS.flatMap(s => soundOfSend(s, W, .8).cues),
    { at: WAKE, cue: "write", detail: { pan: panX(PHONE[0] + PHONE[2] / 2, W), gain: .7 } },
  ],
  flights: SHOTS.map(s => soundOfSend(s, W, .75).flight),
  steps: [
    {
      at: 0,
      focus: { desktop: 1, laptop: 1, tablet: .65, toLaptop: 1, group: .7 },
      caption: { text: "a change on the desktop goes straight to your other devices", anchor: toLaptop.at(.46), place: [440, 122], align: "above", delay: 0 },
    },
    {
      at: 3.4,
      focus: { desktop: 1, tablet: 1, laptop: .6, toTablet: 1, group: .7 },
      caption: { text: "iroh connects devices directly by public key", anchor: toTablet.at(.5), place: [452, 214], align: "below", delay: .25 },
    },
    {
      at: 6.6,
      focus: { desktop: .9, relay: 1, tablet: 1, toRelay: 1, fromRelay: 1, group: .6 },
      caption: { text: "when direct fails, an n0 relay forwards ciphertext it can't read", anchor: [RELAY[0] + RELAY[2] / 2, RELAY[1] + RELAY[3]], place: [464, 126], align: "below", delay: .3 },
    },
    {
      at: 11.0,
      focus: { laptop: 1, phone: 1, catchUp: 1, group: .85, desktop: .5, tablet: .5 },
      caption: { text: "a phone that was asleep catches up from any member", anchor: [PHONE[0], PHONE[1] + PHONE[3] / 2], place: [590, 262], align: "end", delay: .35 },
    },
  ],
  draw: (t, light, story) => <Mesh t={t} light={light} story={story} />,
}

function Wire({ id, d, t, story, dashed }: { id: string; d: string; t: number; story: StoryApi; dashed?: boolean }) {
  const level = story.focus(t, id, .22)
  const lit = clamp01((level - .22) / .78)
  const stroke = shade("#252525", ["#7c7972", lit])
  return <path d={d} fill="none" stroke={stroke} strokeDasharray={dashed ? "2 5" : undefined} />
}

function Mesh({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  for (const shot of SHOTS) send(light, shot, t)

  const desktopHeat = flashes(t, [sDirect1.at + .3, sDirect2.at + .3, sRelayIn.at + .3], .9)
  const laptopHeat = flashes(t, [timing(sDirect1).lands, sCatchup.at + .3], 1.1)
  const tabletHeat = flashes(t, [timing(sDirect2).lands, timing(sRelayOut).lands], 1.1)
  const relayHeat = flashes(t, [timing(sRelayIn).lands], 1.3)
  const phoneHeat = flashes(t, [WAKE, timing(sCatchup).lands], 1.2)

  // Continuous state change on the phone: same card wakes and syncs without cross-fading copies.
  const awake = span(t, WAKE, WAKE + .35)
  const synced = t >= timing(sCatchup).lands
  const phoneDetail = t < WAKE
    ? "asleep"
    : synced
      ? working("member · synced", t, timing(sCatchup).lands, timing(sCatchup).lands + .35, 3) ?? "member · synced"
      : "waking…"

  const groupLit = clamp01((story.focus(t, "group", .3) - .3) / .7)
  const cipherSample = working("9f0c·e41a·7b20", t, sRelayIn.at + .2, timing(sRelayOut).lands, 11)

  return <>
    <Wire id="toLaptop" d={toLaptop.d} t={t} story={story} />
    <Wire id="toTablet" d={toTablet.d} t={t} story={story} />
    <Wire id="toRelay" d={toRelay.d} t={t} story={story} dashed />
    <Wire id="fromRelay" d={fromRelay.d} t={t} story={story} dashed />
    <Wire id="catchUp" d={peerCatchup.d} t={t} story={story} />

    <text x={DESKTOP[0]} y={DESKTOP[1] - 10} className="story-note" fill="#7a7a7a">this device</text>
    <Frame id="desktop" box={DESKTOP} t={t} story={story} light={light} glyph="desktop" impulses={DESKTOP_IMPULSES}
      label="desktop" detail="member" heat={desktopHeat} />

    <Frame id="relay" box={RELAY} t={t} story={story} light={light}
      label="n0 relay" detail={relayHeat > .08 && cipherSample ? cipherSample : "if direct fails"}
      tone={relayHeat > .08 ? "red" : "ivory"} heat={relayHeat} dashed />

    <rect x={GROUP[0] + .5} y={GROUP[1] + .5} width={GROUP[2] - 1} height={GROUP[3] - 1}
      fill="none" stroke={shade("#1f1f1f", ["#383838", groupLit])} />
    <text x={GROUP[0]} y={GROUP[1] - 10} className="story-note" fill={shade("#666666", ["#a8a49c", groupLit])}>your other devices</text>

    <Frame id="laptop" box={LAPTOP} t={t} story={story} light={light} glyph="laptop" impulses={LAPTOP_IMPULSES}
      label="laptop" detail="member" heat={laptopHeat} />
    <Frame id="tablet" box={TABLET} t={t} story={story} light={light} glyph="tablet" impulses={TABLET_IMPULSES}
      label="tablet" detail="member" heat={tabletHeat} />
    <Frame id="phone" box={PHONE} t={t} story={story} light={light} glyph="phone" impulses={PHONE_IMPULSES}
      label="phone" detail={phoneDetail} heat={phoneHeat} dashed={awake < .5} />

    {SHOTS.map(shot => <Carried key={shot.id} shot={shot} t={t} label={shot.label} />)}
  </>
}

export function MeshStory() {
  return <Story scene={meshScene} />
}
