import type { Light } from "../../story/light"
import { across, between, panX, polyline, send, soundOfSend, spark, timing, type Send } from "../../story/beats"
import { Carried, Frame, RefusalMark, edge, refusal } from "../../story/devices"
import { clamp01, ease, flashes, shade, span, wipe, working, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// Removal and the membership gate: the desktop signs Remove(phone) and immediately closes its connection. The
// removal syncs first to the laptop, which closes its connection too. When the removed phone dials either member,
// the gate (before_connect + after_handshake) refuses it before a single application byte moves.

const W = 940, H = 330

const DESKTOP: Box = [54, 48, 232, 58]
const LAPTOP: Box = [54, 218, 232, 58]
const PHONE: Box = [680, 133, 226, 58]
const GATE_X = 566

const deskToPhone = across(edge.right(DESKTOP), edge.left(PHONE, -10), .48)
const lapToPhone = across(edge.right(LAPTOP), edge.left(PHONE, 10), .48)
const deskToLap = between([170, DESKTOP[1] + DESKTOP[3]], [170, LAPTOP[1]])
const tryLapPath = polyline([edge.left(PHONE, 10), [GATE_X, PHONE[1] + PHONE[3] / 2 + 10]])
const tryDeskPath = polyline([edge.left(PHONE, -10), [GATE_X, PHONE[1] + PHONE[3] / 2 - 10]])

type Shot = Send & { id: string; label?: string; side?: "left" | "right" }

const sNormal: Shot = { id: "normal", path: deskToPhone, at: .25, flight: .95, label: "entry", into: { box: PHONE } }
const REMOVE_AT = 3.2
const sSpread: Shot = { id: "spread", path: deskToLap, at: 6.0, flight: .8, label: "Remove(phone)", side: "right", tone: "red", into: { box: LAPTOP, tone: "red" } }
const SPREAD_LANDS = timing(sSpread).lands
const sTryLap: Shot = { id: "tryLap", path: tryLapPath, at: 9.0, flight: .7, label: "sync?", tone: "amber" }
const REFUSE_LAP = timing(sTryLap).lands
const sTryDesk: Shot = { id: "tryDesk", path: tryDeskPath, at: 10.2, flight: .7, label: "sync?", tone: "amber" }
const REFUSE_DESK = timing(sTryDesk).lands
const NEW_ENTRY_AT = 12.8
const sNewEntry: Shot = { id: "newEntry", path: deskToLap, at: NEW_ENTRY_AT, flight: .8, label: "new entry", side: "right", into: { box: LAPTOP } }

const SHOTS: readonly Shot[] = [sNormal, sSpread, sTryLap, sTryDesk, sNewEntry]

const DESKTOP_IMPULSES = [sNormal.at, REMOVE_AT, NEW_ENTRY_AT]
const LAPTOP_IMPULSES = [SPREAD_LANDS, timing(sNewEntry).lands]
const PHONE_IMPULSES = [timing(sNormal).lands, sTryLap.at, sTryDesk.at]

export const removeScene: StoryScene = {
  label: "The desktop removes the phone; the removal spreads to the laptop; the phone's attempts to sync are refused at the membership gate.",
  width: W, height: H, duration: 16.0, poster: 3,
  sounds: [
    ...soundOfSend(sNormal, W, .8).cues,
    { at: REMOVE_AT, cue: "remove", detail: { pan: panX(DESKTOP[0] + DESKTOP[2] / 2, W) } },
    ...soundOfSend(sSpread, W, .85).cues,
    { at: timing(sTryLap).launch, cue: "send", detail: { pan: panX(PHONE[0], W), gain: .75 } },
    { at: REFUSE_LAP, cue: "refuse", detail: { pan: panX(GATE_X, W) } },
    { at: timing(sTryDesk).launch, cue: "send", detail: { pan: panX(PHONE[0], W), gain: .75 } },
    { at: REFUSE_DESK, cue: "refuse", detail: { pan: panX(GATE_X, W) } },
    ...soundOfSend(sNewEntry, W, .8).cues,
  ],
  flights: [sNormal, sSpread, sTryLap, sTryDesk, sNewEntry].map(s => soundOfSend(s, W, .75).flight),
  steps: [
    {
      at: 0,
      focus: { desktop: 1, laptop: .65, phone: 1, wDesk: 1, gate: .45 },
      caption: { text: "while the phone is a member, entries cross the gate", anchor: deskToPhone.at(.36), place: [400, 136], align: "below", delay: 0 },
    },
    {
      at: 3.0,
      focus: { desktop: 1, phone: 1, wDesk: 1, gate: 1 },
      caption: { text: "the desktop signs Remove(phone) and closes the connection", width: 31, anchor: [DESKTOP[0] + DESKTOP[2], DESKTOP[1] + 14], place: [298, 40], align: "start", delay: .2 },
    },
    {
      at: 5.8,
      focus: { desktop: .85, laptop: 1, wSpread: 1, wLap: 1, gate: 1 },
      caption: { text: "the laptop gets the removal and closes its connection too", anchor: [LAPTOP[0] + LAPTOP[2], LAPTOP[1] + 44], place: [298, 277], align: "start", delay: .25 },
    },
    {
      at: 8.8,
      focus: { phone: 1, gate: 1, desktop: .7, laptop: .7 },
      caption: { text: "the gate refuses the phone before a single byte moves", anchor: [GATE_X, PHONE[1] + PHONE[3] / 2], place: [550, 162], align: "end", delay: .4 },
    },
    {
      at: 12.6,
      focus: { desktop: 1, laptop: 1, wSpread: 1, phone: .85, gate: .8 },
      caption: { text: "the phone keeps its old copy; new entries stay among members", anchor: [PHONE[0] + PHONE[2] / 2, PHONE[1] + PHONE[3]], place: [793, 206], align: "below", delay: .25 },
    },
  ],
  draw: (t, light, story) => {
    for (const shot of SHOTS) send(light, shot, t)
    if (t >= REMOVE_AT && t < REMOVE_AT + 1.1) {
      spark(light, edge.right(DESKTOP), t - REMOVE_AT, "red", .9)
    }
    refusal(light, [GATE_X, PHONE[1] + PHONE[3] / 2 + 10], t, REFUSE_LAP)
    refusal(light, [GATE_X, PHONE[1] + PHONE[3] / 2 - 10], t, REFUSE_DESK)
    return <Remove t={t} light={light} story={story} />
  },
}

function SeverableWire({ id, d, t, story, cutAt }: { id: string; d: string; t: number; story: StoryApi; cutAt: number }) {
  const level = story.focus(t, id, .22)
  const lit = clamp01((level - .22) / .78)
  const cut = story.reduced ? (t >= cutAt ? 1 : 0) : ease.exit(span(t, cutAt, cutAt + .36))
  return <>
    <path d={d} fill="none" stroke={shade("#252525", ["#7c7972", lit * (1 - cut * .6)])} strokeDasharray={cut > 0 ? "2 6" : undefined} strokeOpacity={1 - cut * .45} />
    {cut < 1 && <path d={d} fill="none" stroke={shade("#383838", ["#8d8a84", lit])} pathLength={1} strokeDasharray={`${1 - cut} 2`} />}
  </>
}

function Remove({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  const deskHeat = flashes(t, [REMOVE_AT, NEW_ENTRY_AT + .2], 1.2)
  const lapHeat = flashes(t, [SPREAD_LANDS, timing(sNewEntry).lands], 1.2)
  const phoneHeat = flashes(t, [timing(sNormal).lands, REFUSE_LAP, REFUSE_DESK], 1.1)

  const gateLit = clamp01((story.focus(t, "gate", .35) - .35) / .65)
  const gateColor = shade("#5a1c1c", ["#ff2a2a", gateLit])

  // Continuous identity on the phone: it keeps its card and glyph, blushes red and its frame opens into dashes.
  // The members blush red when they apply the removal and cool back.
  const removed = wipe(t, REMOVE_AT, .35)
  const phoneDetail = t < REMOVE_AT
    ? "member"
    : t >= NEW_ENTRY_AT
      ? working("removed · old copy", t, NEW_ENTRY_AT, NEW_ENTRY_AT + .4, 8) ?? "removed · old copy"
      : working("removed", t, REMOVE_AT, REMOVE_AT + .32, 6) ?? "removed"
  const deskDetail = t < REMOVE_AT
    ? "member"
    : t < SPREAD_LANDS
      ? working("signed Remove", t, REMOVE_AT, REMOVE_AT + .32, 3) ?? "signed Remove"
      : working("member", t, SPREAD_LANDS, SPREAD_LANDS + .3, 5) ?? "member"
  const lapDetail = t < SPREAD_LANDS
    ? "member"
    : t < REFUSE_LAP
      ? working("applied Remove", t, SPREAD_LANDS, SPREAD_LANDS + .32, 4) ?? "applied Remove"
      : working("member", t, REFUSE_LAP, REFUSE_LAP + .3, 2) ?? "member"

  const spreadLit = clamp01((story.focus(t, "wSpread", .22) - .22) / .78)

  return <>
    <path d={deskToLap.d} fill="none" stroke={shade("#252525", ["#8d8a84", spreadLit])} />
    <SeverableWire id="wDesk" d={deskToPhone.d} t={t} story={story} cutAt={REMOVE_AT} />
    <SeverableWire id="wLap" d={lapToPhone.d} t={t} story={story} cutAt={SPREAD_LANDS} />

    <line x1={GATE_X} y1={22} x2={GATE_X} y2={292} stroke={gateColor} strokeDasharray="2 5" />
    <text x={GATE_X} y={308} textAnchor="middle" className="story-note" fill={gateColor}>membership gate</text>

    <Frame id="desktop" box={DESKTOP} t={t} story={story} light={light} glyph="desktop" impulses={DESKTOP_IMPULSES}
      label="desktop" detail={deskDetail} tone="red" toned={flashes(t, [REMOVE_AT], 2.8)} heat={deskHeat} />

    <Frame id="laptop" box={LAPTOP} t={t} story={story} light={light} glyph="laptop" impulses={LAPTOP_IMPULSES}
      label="laptop" detail={lapDetail} tone="red" toned={flashes(t, [SPREAD_LANDS], 2.6)} heat={lapHeat} />

    <Frame id="phone" box={PHONE} t={t} story={story} light={light} glyph="phone" impulses={PHONE_IMPULSES}
      label="phone" detail={phoneDetail} tone="red" toned={removed} heat={phoneHeat} dashed={removed} />

    <RefusalMark x={GATE_X} y={PHONE[1] + PHONE[3] / 2 + 10} t={t} at={REFUSE_LAP} />
    <RefusalMark x={GATE_X} y={PHONE[1] + PHONE[3] / 2 - 10} t={t} at={REFUSE_DESK} />

    {SHOTS.map(shot => <Carried key={shot.id} shot={shot} t={t} label={shot.label} side={shot.side} />)}
  </>
}

export function RemoveStory() {
  return <Story scene={removeScene} />
}
