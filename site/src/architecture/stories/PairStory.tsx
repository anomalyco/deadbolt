import type { Light } from "../../story/light"
import { across, bridge, panX, send, soundOfSend, spark, timing, type Send } from "../../story/beats"
import { Carried, Frame } from "../../story/devices"
import { clamp01, flashes, shade, span, springAt, springs, wipe, working, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// Pairing (`deadbolt/pair/1`): a new phone shows a ticket + QR code; you give the ticket to the desktop (already a
// member), which dials the phone. Both prove the ticket's secret, both show the same 6-digit code, the phone signs
// consent to join "personal", and the desktop signs Add(phone) and streams the vault over the same connection.

const W = 940, H = 330

const PHONE: Box = [54, 48, 276, 236]
const DESKTOP: Box = [610, 48, 276, 236]

const carryTicket = bridge([PHONE[0] + PHONE[2] / 2, PHONE[1]], [DESKTOP[0] + DESKTOP[2] / 2, DESKTOP[1]], 34)
const lane1 = across([DESKTOP[0], 124], [PHONE[0] + PHONE[2], 124], .35)
const lane2 = across([PHONE[0] + PHONE[2], 166], [DESKTOP[0], 166], .35)
const lane3 = across([DESKTOP[0], 208], [PHONE[0] + PHONE[2], 208], .35)

type Shot = Send & { id: string; lane: string; label?: string }

const sCarry: Shot = { id: "carry", lane: "carry", path: carryTicket, at: 2.7, flight: .95, label: "ticket · DBPAIR…", into: { box: DESKTOP } }
const sDial: Shot = { id: "dial", lane: "l1", path: lane1, at: 4.1, flight: .85, label: "dial · pair/1", into: { box: PHONE } }
const sProofA: Shot = { id: "proofA", lane: "l1", path: lane1, at: 5.8, flight: .85, label: "hmac proof", into: { box: PHONE } }
const sProofB: Shot = { id: "proofB", lane: "l2", path: lane2, at: 5.95, flight: .85, label: "hmac proof", into: { box: DESKTOP } }
const CODE_AT = 8.5
const sOffer: Shot = { id: "offer", lane: "l1", path: lane1, at: 11.5, flight: .8, label: "offer · personal", into: { box: PHONE } }
const sConsent: Shot = { id: "consent", lane: "l2", path: lane2, at: timing(sOffer).lands + .12, flight: .85, label: "signed consent", into: { box: DESKTOP } }
const ADD_AT = 14.5
const sMem: Shot = { id: "mem", lane: "l1", path: lane1, at: ADD_AT + .25, flight: .85, label: "Add(phone) + mem", tone: "red", into: { box: PHONE, tone: "red" } }
const sEntries: Shot = { id: "entries", lane: "l3", path: lane3, at: ADD_AT + .6, flight: .9, label: "vault entries", into: { box: PHONE } }
const ADMITTED = timing(sEntries).lands

const SHOTS: readonly Shot[] = [sCarry, sDial, sProofA, sProofB, sOffer, sConsent, sMem, sEntries]

const PHONE_IMPULSES = [.15, timing(sDial).lands, CODE_AT, sConsent.at, ADMITTED]
const DESKTOP_IMPULSES = [timing(sCarry).lands, sDial.at, CODE_AT, ADD_AT]

/** Seeded 17×17 QR modules for the pairing ticket. */
const QR_MODULES = (() => {
  let seed = 19
  const rand = () => (seed = (seed * 1664525 + 1013904223) >>> 0) / 4294967296
  const out: [number, number][] = []
  for (let y = 0; y < 17; y++) for (let x = 0; x < 17; x++) {
    const finder = (a: number, b: number) => a < 5 && b < 5 && (a === 0 || a === 4 || b === 0 || b === 4 || (a === 2 && b === 2))
    const corner = (x < 5 && y < 5) || (x > 11 && y < 5) || (x < 5 && y > 11)
    if (corner ? finder(x > 11 ? x - 12 : x, y > 11 ? y - 12 : y) : rand() < .46) out.push([x, y])
  }
  return out
})()

export const pairScene: StoryScene = {
  label: "A new phone shows a ticket; the desktop dials it, both prove the secret, you compare six-digit codes, and the desktop admits the phone.",
  width: W, height: H, duration: 18.2, poster: 5,
  sounds: [
    { at: .15, cue: "write", detail: { pan: panX(PHONE[0] + PHONE[2] / 2, W) } },
    ...soundOfSend(sCarry, W, .8).cues,
    ...soundOfSend(sDial, W, .8).cues,
    ...soundOfSend(sProofA, W, .75).cues,
    { at: CODE_AT, cue: "codeMatch", detail: { pan: 0 } },
    ...soundOfSend(sConsent, W, .8).cues,
    { at: ADD_AT, cue: "seal", detail: { pan: panX(DESKTOP[0] + DESKTOP[2] / 2, W) } },
    { at: ADMITTED, cue: "join", detail: { pan: panX(PHONE[0] + PHONE[2] / 2, W) } },
  ],
  flights: [sCarry, sDial, sProofA, sConsent, sMem].map(s => soundOfSend(s, W, .75).flight),
  steps: [
    {
      at: 0,
      focus: { phone: 1, desktop: .5 },
      caption: { text: "the new phone shows its ticket as text and a qr code", anchor: [PHONE[0] + PHONE[2], 100], place: [346, 100], align: "start", delay: 0 },
    },
    {
      at: 2.5,
      focus: { phone: .9, desktop: 1, carry: 1, l1: 1 },
      caption: { text: "you pass the ticket to the desktop, which dials the phone", anchor: carryTicket.at(.5), place: [470, 54], align: "below", delay: .25 },
    },
    {
      at: 5.6,
      focus: { phone: 1, desktop: 1, l1: 1, l2: 1 },
      caption: { text: "each side proves it holds the ticket's secret", anchor: lane2.at(.5), place: [470, 220], align: "below", delay: .25 },
    },
    {
      at: 8.3,
      focus: { phone: 1, desktop: 1 },
      caption: { text: "both screens show the same six digits; you confirm they match", anchor: [DESKTOP[0] + 16, DESKTOP[1] + 194], place: [594, DESKTOP[1] + 194], align: "end", delay: .25 },
    },
    {
      at: 11.3,
      focus: { phone: 1, desktop: 1, l1: 1, l2: 1 },
      caption: { text: "the phone signs its consent to join that vault", anchor: lane2.at(.48), place: [470, 108], align: "above", delay: .3 },
    },
    {
      at: 14.3,
      focus: { phone: 1, desktop: 1, l1: 1, l3: 1 },
      caption: { text: "the desktop signs Add(phone) and streams the vault", anchor: lane3.at(.5), place: [470, 220], align: "below", delay: .25 },
    },
  ],
  draw: (t, light, story) => <Pair t={t} light={light} story={story} />,
}

function QrTicket({ x, y, t, story }: { x: number; y: number; t: number; story: StoryApi }) {
  // Sliding plate wipe: prints top-to-bottom on first step, dims softly once the code takes focus.
  const print = story.reduced ? 1 : wipe(t, .05, .42)
  const dim = 1 - .78 * springAt(t - CODE_AT, springs.calm)
  return <g opacity={dim}>
    <clipPath id="pair-qr-wipe">
      <rect x={x} y={y} width={64} height={64 * print} />
    </clipPath>
    <g clipPath="url(#pair-qr-wipe)">
      {QR_MODULES.map(([mx, my]) => <rect key={`${mx}-${my}`} x={x + mx * 3.4} y={y + my * 3.4} width={3.1} height={3.1} fill="#e8e4dc" />)}
    </g>
  </g>
}

function Wire({ id, d, t, story, dashed }: { id: string; d: string; t: number; story: StoryApi; dashed?: boolean }) {
  const level = story.focus(t, id, .22)
  const lit = clamp01((level - .22) / .78)
  return <path d={d} fill="none" stroke={shade("#252525", ["#7c7972", lit])} strokeDasharray={dashed ? "2 5" : undefined} />
}

function Pair({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  for (const shot of SHOTS) send(light, shot, t)

  const phoneHeat = flashes(t, [timing(sDial).lands, timing(sProofA).lands, CODE_AT, timing(sOffer).lands, ADMITTED], 1.15)
  const deskHeat = flashes(t, [timing(sCarry).lands, timing(sProofB).lands, CODE_AT, timing(sConsent).lands, ADD_AT], 1.15)

  if (t >= ADD_AT && t < ADD_AT + 1.2) {
    spark(light, [DESKTOP[0] + 24, DESKTOP[1] + 132], t - ADD_AT, "red", .85)
  }

  // Same phone card keeps its identity from listening newcomer to admitted member.
  const phoneDetail = t < timing(sDial).lands
    ? "new · listening"
    : t < ADMITTED
      ? "pairing…"
      : working("member · synced", t, ADMITTED, ADMITTED + .35, 3) ?? "member · synced"

  const codeText = working("411 308", t, CODE_AT, CODE_AT + .38, 7)
  const phoneNote = t < sConsent.at
    ? "public key · secret · hint"
    : t < ADMITTED
      ? "signed consent · personal"
      : "vault history applied"
  const deskNote = t < timing(sCarry).lands
    ? "waiting for ticket"
    : t < ADD_AT
      ? "$ deadbolt pair DBPAIR…"
      : "signed Add(phone)"

  return <>
    <Wire id="carry" d={carryTicket.d} t={t} story={story} dashed />
    <Wire id="l1" d={lane1.d} t={t} story={story} />
    <Wire id="l2" d={lane2.d} t={t} story={story} />
    <Wire id="l3" d={lane3.d} t={t} story={story} />

    <Frame id="phone" box={PHONE} t={t} story={story} light={light} glyph="phone" impulses={PHONE_IMPULSES}
      label="phone" detail={phoneDetail} heat={phoneHeat} dashed={1 - wipe(t, ADMITTED, .4)} headerY={PHONE[1] + 23}>
      <line x1={PHONE[0] + 14} x2={PHONE[0] + PHONE[2] - 14} y1={PHONE[1] + 44} y2={PHONE[1] + 44} stroke="#1f1f1f" />
      <text x={PHONE[0] + 18} y={PHONE[1] + 64} dominantBaseline="middle" className="story-entry" fill="#cfcac1">$ deadbolt join</text>
      <QrTicket x={PHONE[0] + 18} y={PHONE[1] + 82} t={t} story={story} />
      <text x={PHONE[0] + 92} y={PHONE[1] + 104} dominantBaseline="middle" className="story-note" fill="#8d8a84">{phoneNote}</text>
      {codeText && <>
        <text x={PHONE[0] + 18} y={PHONE[1] + 194} dominantBaseline="middle" className="story-code" fill="#e8e4dc">{codeText}</text>
        <text x={PHONE[0] + 18} y={PHONE[1] + 220} dominantBaseline="middle" className="story-note" fill="#7a7a7a">derived from tls + keys</text>
      </>}
    </Frame>

    <Frame id="desktop" box={DESKTOP} t={t} story={story} light={light} glyph="desktop" impulses={DESKTOP_IMPULSES}
      label="desktop" detail="member" heat={deskHeat} headerY={DESKTOP[1] + 23}>
      <line x1={DESKTOP[0] + 14} x2={DESKTOP[0] + DESKTOP[2] - 14} y1={DESKTOP[1] + 44} y2={DESKTOP[1] + 44} stroke="#1f1f1f" />
      <text x={DESKTOP[0] + 18} y={DESKTOP[1] + 64} dominantBaseline="middle" className="story-entry"
        fill={shade("#cfcac1", ["#ff5242", span(t, ADD_AT, ADD_AT + .15)])}>{deskNote}</text>
      {codeText && <>
        <text x={DESKTOP[0] + 18} y={DESKTOP[1] + 194} dominantBaseline="middle" className="story-code" fill="#e8e4dc">{codeText}</text>
        <text x={DESKTOP[0] + 18} y={DESKTOP[1] + 220} dominantBaseline="middle" className="story-note" fill="#9e9a92">match? [y/N] y</text>
      </>}
    </Frame>

    {SHOTS.map(shot => <Carried key={shot.id} shot={shot} t={t} label={shot.label} />)}
  </>
}

export function PairStory() {
  return <Story scene={pairScene} />
}
