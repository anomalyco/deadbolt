import type { Light } from "../../story/light"
import { across, panX, send, soundOfSend, timing, type Send } from "../../story/beats"
import { Carried, Frame } from "../../story/devices"
import { clamp01, flashes, shade, wipe, working, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// Sync (`deadbolt/sync/1`): the desktop and the laptop exchange their heads, work out what the other is missing,
// send membership entries first, then stream missing data entries both ways and finish with a result confirmation.

const W = 940, H = 330

const DESKTOP: Box = [54, 44, 272, 238]
const LAPTOP: Box = [614, 44, 272, 238]

const lane1 = across([DESKTOP[0] + DESKTOP[2], 122], [LAPTOP[0], 122], .35)
const lane2 = across([DESKTOP[0] + DESKTOP[2], 164], [LAPTOP[0], 164], .35)
const lane3 = across([DESKTOP[0] + DESKTOP[2], 206], [LAPTOP[0], 206], .35)

type Shot = Send & { id: string; lane: "l1" | "l2" | "l3"; label?: string }

const sHeadsA: Shot = { id: "headsA", lane: "l1", path: lane1, at: .3, flight: .95, label: "heads", into: { box: LAPTOP } }
const sHeadsB: Shot = { id: "headsB", lane: "l2", path: lane2, reverse: true, at: .42, flight: .95, label: "heads", into: { box: DESKTOP } }
const DIFF_AT = 3.1

const sMem: Shot = {
  id: "mem", lane: "l1", path: lane1, reverse: true, at: 5.5, flight: .95,
  label: "laptop · mem 1", tone: "red", into: { box: DESKTOP, tone: "red" },
}
const MEM_LANDS = timing(sMem).lands

const sDeskData: Shot = {
  id: "deskData", lane: "l2", path: lane2, at: 8.3, flight: 1.0,
  label: "desktop · data 3, 4", into: { box: LAPTOP },
}
const sLapData: Shot = {
  id: "lapData", lane: "l3", path: lane3, reverse: true, at: 8.55, flight: 1.0,
  label: "laptop · data 2, 3", into: { box: DESKTOP },
}
const DESK_DATA_LANDS = timing(sDeskData).lands
const LAP_DATA_LANDS = timing(sLapData).lands

const sResult: Shot = {
  id: "result", lane: "l1", path: lane1, reverse: true, at: 12.1, flight: .9,
  label: "result · ok", into: { box: DESKTOP },
}
const DONE_AT = timing(sResult).lands

const SHOTS: readonly Shot[] = [sHeadsA, sHeadsB, sMem, sDeskData, sLapData, sResult]

const DESKTOP_IMPULSES = [sHeadsA.at, timing(sHeadsB).lands, MEM_LANDS, sDeskData.at, LAP_DATA_LANDS, DONE_AT]
const LAPTOP_IMPULSES = [sHeadsB.at, timing(sHeadsA).lands, sMem.at, sLapData.at, DESK_DATA_LANDS, sResult.at]

export const syncScene: StoryScene = {
  label: "The desktop and the laptop exchange log heads, send missing membership entries first, then exchange missing data entries and confirm.",
  width: W, height: H, duration: 15.6, poster: 4,
  sounds: [
    ...soundOfSend(sHeadsA, W, .75).cues,
    { at: DIFF_AT, cue: "write", detail: { pan: 0, gain: .65 } },
    ...soundOfSend(sMem, W, .85).cues,
    ...soundOfSend(sDeskData, W, .8).cues,
    { at: LAP_DATA_LANDS, cue: "write", detail: { pan: panX(DESKTOP[0] + DESKTOP[2] / 2, W), gain: .7 } },
    ...soundOfSend(sResult, W, .8).cues,
  ],
  flights: [sHeadsA, sMem, sDeskData, sResult].map(s => soundOfSend(s, W, .75).flight),
  steps: [
    {
      at: 0,
      focus: { desktop: 1, laptop: 1, l1: 1, l2: 1 },
      caption: { text: "each device sends the highest entry it holds for every log", anchor: lane1.at(.5), place: [470, 108], align: "above", delay: 0 },
    },
    {
      at: 2.9,
      focus: { desktop: 1, laptop: 1, l1: .4, l2: .4 },
      caption: { text: "comparing heads tells each side what the peer is missing", anchor: [DESKTOP[0] + DESKTOP[2], DESKTOP[1] + 214], place: [342, DESKTOP[1] + 214], align: "start", delay: .2 },
    },
    {
      at: 5.3,
      focus: { desktop: 1, laptop: 1, l1: 1 },
      caption: { text: "membership entries always go first", anchor: lane1.at(.48), place: [470, 108], align: "above", delay: .25 },
    },
    {
      at: 8.1,
      focus: { desktop: 1, laptop: 1, l2: 1, l3: 1 },
      caption: { text: "missing data entries flow both ways at once", anchor: lane3.at(.5), place: [470, 220], align: "below", delay: .25 },
    },
    {
      at: 11.9,
      focus: { desktop: 1, laptop: 1, l1: 1 },
      caption: { text: "the dialed peer answers ok once every entry is verified", anchor: lane1.at(.5), place: [470, 108], align: "above", delay: .25 },
    },
  ],
  draw: (t, light, story) => <Sync t={t} light={light} story={story} />,
}

type LogRow = { name: string; value: string; red?: boolean; flashAt?: number }

function Ledger({ box, rows, footer, footerAt, t, story, clipId }: {
  box: Box
  rows: readonly LogRow[]
  footer: string
  footerAt: number
  t: number
  story: StoryApi
  clipId: string
}) {
  const [x, y, w] = box
  const level = story.focus(t, clipId, .35)
  const lit = clamp01((level - .35) / .65)
  const reveal = story.reduced ? 1 : wipe(t, footerAt, .34)

  return <g>
    <line x1={x + 14} x2={x + w - 14} y1={y + 44} y2={y + 44} stroke="#1f1f1f" />
    {rows.map((r, i) => {
      const ry = y + 72 + i * 28
      const rowHot = r.flashAt !== undefined ? flashes(t, [r.flashAt], 1.1) : 0
      const nameFill = shade(r.red ? "#9a3434" : "#6c6c6c", [r.red ? "#ff4a3a" : "#b8b4ac", lit], ["#fff1dc", rowHot * .85])
      const valFill = shade(r.red ? "#c43830" : "#9a968e", [r.red ? "#ff5242" : "#e8e4dc", lit], ["#ffffff", rowHot * .95])
      return <g key={r.name}>
        <text x={x + 18} y={ry} dominantBaseline="middle" className="story-note" fill={nameFill}>{r.name}</text>
        <text x={x + w - 18} y={ry} dominantBaseline="middle" textAnchor="end" className="story-entry" fill={valFill}>{r.value}</text>
      </g>
    })}
    <line x1={x + 14} x2={x + w - 14} y1={y + 190} y2={y + 190} stroke="#1f1f1f" />
    <clipPath id={`wipe-${clipId}`}>
      <rect x={x + 14} y={y + 196} width={(w - 28) * reveal} height={34} />
    </clipPath>
    <g clipPath={`url(#wipe-${clipId})`}>
      <text x={x + 18} y={y + 214} dominantBaseline="middle" className="story-note" fill={shade("#6e6e6e", ["#e8e4dc", lit])}>{footer}</text>
    </g>
  </g>
}

function Wire({ id, d, t, story }: { id: string; d: string; t: number; story: StoryApi }) {
  const level = story.focus(t, id, .22)
  const lit = clamp01((level - .22) / .78)
  return <path d={d} fill="none" stroke={shade("#252525", ["#7c7972", lit])} />
}

function Sync({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  for (const shot of SHOTS) send(light, shot, t)

  const deskHeat = flashes(t, [timing(sHeadsB).lands, MEM_LANDS, LAP_DATA_LANDS, DONE_AT], 1.1)
  const lapHeat = flashes(t, [timing(sHeadsA).lands, DESK_DATA_LANDS], 1.1)

  // Continuous odometer-style updates on the same rows (never cross-fading two tables).
  const deskLapMem = t < MEM_LANDS ? "0" : "1"
  const deskLapData = t < LAP_DATA_LANDS ? "1" : t < LAP_DATA_LANDS + .18 ? "2" : "3"
  const lapDeskData = t < DESK_DATA_LANDS ? "2" : t < DESK_DATA_LANDS + .18 ? "3" : "4"

  const deskRows: readonly LogRow[] = [
    { name: "desktop · membership", value: "1", red: true },
    { name: "desktop · data", value: "4" },
    { name: "laptop · membership", value: deskLapMem, red: true, flashAt: MEM_LANDS },
    { name: "laptop · data", value: deskLapData, flashAt: LAP_DATA_LANDS },
  ]
  const lapRows: readonly LogRow[] = [
    { name: "desktop · membership", value: "1", red: true },
    { name: "desktop · data", value: lapDeskData, flashAt: DESK_DATA_LANDS },
    { name: "laptop · membership", value: "1", red: true },
    { name: "laptop · data", value: "3" },
  ]

  const deskFooter = t < DIFF_AT
    ? "heads ready"
    : t < LAP_DATA_LANDS
      ? "send desktop data 3, 4"
      : working("all logs at head · ok", t, LAP_DATA_LANDS, LAP_DATA_LANDS + .35, 2) ?? "all logs at head · ok"
  const deskFooterAt = t < DIFF_AT ? 0 : t < LAP_DATA_LANDS ? DIFF_AT : LAP_DATA_LANDS

  const lapFooter = t < DIFF_AT
    ? "heads ready"
    : t < DESK_DATA_LANDS
      ? "send mem 1, then data 2, 3"
      : working("all logs at head · ok", t, DESK_DATA_LANDS, DESK_DATA_LANDS + .35, 6) ?? "all logs at head · ok"
  const lapFooterAt = t < DIFF_AT ? 0 : t < DESK_DATA_LANDS ? DIFF_AT : DESK_DATA_LANDS

  return <>
    <Wire id="l1" d={lane1.d} t={t} story={story} />
    <Wire id="l2" d={lane2.d} t={t} story={story} />
    <Wire id="l3" d={lane3.d} t={t} story={story} />
    <text x={W / 2} y={30} textAnchor="middle" className="story-note" fill="#5e5e5e">iroh · quic · deadbolt/sync/1</text>

    <Frame id="desktop" box={DESKTOP} t={t} story={story} light={light} glyph="desktop" impulses={DESKTOP_IMPULSES}
      label="desktop" detail="heads" heat={deskHeat} headerY={DESKTOP[1] + 23}>
      <Ledger box={DESKTOP} rows={deskRows} footer={deskFooter} footerAt={deskFooterAt} t={t} story={story} clipId="desktop" />
    </Frame>

    <Frame id="laptop" box={LAPTOP} t={t} story={story} light={light} glyph="laptop" impulses={LAPTOP_IMPULSES}
      label="laptop" detail="heads" heat={lapHeat} headerY={LAPTOP[1] + 23}>
      <Ledger box={LAPTOP} rows={lapRows} footer={lapFooter} footerAt={lapFooterAt} t={t} story={story} clipId="laptop" />
    </Frame>

    {SHOTS.map(shot => <Carried key={shot.id} shot={shot} t={t} label={shot.label} />)}
  </>
}

export function SyncStory() {
  return <Story scene={syncScene} />
}
