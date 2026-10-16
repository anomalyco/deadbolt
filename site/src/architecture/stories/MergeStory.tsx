import type { Light } from "../../story/light"
import { across, between, panX, send, soundOfSend, timing, type Send } from "../../story/beats"
import { Carried, Frame } from "../../story/devices"
import { clamp01, flashes, shade, span, springAt, springs, wipe, working, type Box } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// Concurrent edits: the desktop and the laptop both change the `github` password while apart. Both edits replace
// v1, so neither saw the other. Every device picks the edit with the higher entry hash (`a94b… > 7c1e…`), and the
// losing value moves into the item's history (the item card grows on a calm spring to hold it).

const W = 940, H = 330

const DESKTOP: Box = [54, 188, 286, 108]
const LAPTOP: Box = [600, 188, 286, 108]
const ITEM_BASE: Box = [270, 40, 400, 100]
// The item grows upward to hold its history row, so its bottom edge, where the wires land, stays put.
const GROWN: Box = [270, 12, 400, 128]

const crossAB = across([DESKTOP[0] + DESKTOP[2], 228], [LAPTOP[0], 228], .36)
const crossBA = across([LAPTOP[0], 260], [DESKTOP[0] + DESKTOP[2], 260], .36)
const deskToItem = between([196, DESKTOP[1]], [350, ITEM_BASE[1] + ITEM_BASE[3]], .5)
const lapToItem = between([744, LAPTOP[1]], [590, ITEM_BASE[1] + ITEM_BASE[3]], .5)

type Shot = Send & { id: string; lane: string; label?: string }

const EDIT_AT = .35
const sSyncAB: Shot = { id: "ab", lane: "cross", path: crossAB, at: 3.2, flight: .95, label: "7c1e · red-panda", into: { box: LAPTOP } }
const sSyncBA: Shot = { id: "ba", lane: "cross", path: crossBA, at: 3.38, flight: .95, label: "a94b · blue-whale", into: { box: DESKTOP } }
const SYNC_LANDS = Math.max(timing(sSyncAB).lands, timing(sSyncBA).lands)

const COMPARE_AT = 6.2
const sWinToItem: Shot = { id: "win", lane: "lapUp", path: lapToItem, at: COMPARE_AT + .25, flight: .8, label: "a94b > 7c1e", into: { box: ITEM_BASE } }
const SETTLE_AT = timing(sWinToItem).lands

const NEXT_AT = 10.2
const sNextToItem: Shot = { id: "next", lane: "deskUp", path: deskToItem, at: NEXT_AT + .35, flight: .85, label: "replaces blue-whale", into: { box: GROWN } }
const NEXT_LANDS = timing(sNextToItem).lands

const SHOTS: readonly Shot[] = [sSyncAB, sSyncBA, sWinToItem, sNextToItem]

const DESKTOP_IMPULSES = [EDIT_AT, timing(sSyncBA).lands, NEXT_AT]
const LAPTOP_IMPULSES = [EDIT_AT + .16, timing(sSyncAB).lands, COMPARE_AT + .25]

export const mergeScene: StoryScene = {
  label: "Two concurrent edits to the same field: the higher entry hash wins on every device, and the other value moves to history.",
  width: W, height: H, duration: 14.2, poster: 2,
  sounds: [
    { at: EDIT_AT, cue: "write", detail: { pan: panX(DESKTOP[0] + DESKTOP[2] / 2, W) } },
    { at: EDIT_AT + .16, cue: "write", detail: { pan: panX(LAPTOP[0] + LAPTOP[2] / 2, W) } },
    ...soundOfSend(sSyncAB, W, .8).cues,
    ...soundOfSend(sWinToItem, W, .85).cues,
    { at: NEXT_AT, cue: "write", detail: { pan: panX(DESKTOP[0] + DESKTOP[2] / 2, W) } },
    ...soundOfSend(sNextToItem, W, .85).cues,
  ],
  flights: [sSyncAB, sWinToItem, sNextToItem].map(s => soundOfSend(s, W, .75).flight),
  steps: [
    {
      at: 0,
      focus: { item: .85, desktop: 1, laptop: 1 },
      caption: { text: "the desktop and laptop both replace v1 while apart", anchor: [DESKTOP[0] + DESKTOP[2], 212], place: [470, 144], align: "below", delay: 0 },
    },
    {
      at: 3.0,
      focus: { desktop: 1, laptop: 1, cross: 1, item: .55 },
      caption: { text: "when they sync, neither edit has seen the other", anchor: crossAB.at(.5), place: [470, 214], align: "above", delay: .2 },
    },
    {
      at: 6.0,
      focus: { item: 1, desktop: .85, laptop: 1, lapUp: 1 },
      caption: { text: "the higher entry hash wins; the other value moves to history", width: 26, anchor: [670, 90], place: [686, 90], align: "start", delay: .35 },
    },
    {
      at: 10.0,
      focus: { item: 1, desktop: 1, laptop: .55, deskUp: 1 },
      caption: { text: "a later edit that saw blue-whale replaces it cleanly", anchor: deskToItem.at(.6), place: [258, 132], align: "end", delay: .25 },
    },
  ],
  draw: (t, light, story) => <Merge t={t} light={light} story={story} />,
}

function Wire({ id, d, t, story, dashed }: { id: string; d: string; t: number; story: StoryApi; dashed?: boolean }) {
  const level = story.focus(t, id, .22)
  const lit = clamp01((level - .22) / .78)
  return <path d={d} fill="none" stroke={shade("#252525", ["#7c7972", lit])} strokeDasharray={dashed ? "2 5" : undefined} />
}

function Merge({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  for (const shot of SHOTS) send(light, shot, t)

  // The item card grows upward on a calm zero-bounce spring when the concurrent loser moves into history.
  const expand = story.reduced ? 1 : springAt(t - SETTLE_AT, springs.calm)
  const grow = Math.round(28 * expand * 10) / 10
  const itemBox: Box = [ITEM_BASE[0], ITEM_BASE[1] - grow, ITEM_BASE[2], ITEM_BASE[3] + grow]

  const itemHeat = flashes(t, [SETTLE_AT, NEXT_LANDS], 1.2)
  const deskHeat = flashes(t, [EDIT_AT, timing(sSyncBA).lands, NEXT_AT], 1.1)
  const lapHeat = flashes(t, [EDIT_AT + .16, timing(sSyncAB).lands], 1.1)

  const passwordVal = t < SETTLE_AT
    ? "v1 · ••••••••"
    : t < NEXT_LANDS
      ? working("blue-whale", t, SETTLE_AT, SETTLE_AT + .35, 4) ?? "blue-whale"
      : working("green-fox", t, NEXT_LANDS, NEXT_LANDS + .35, 8) ?? "green-fox"

  const deskLine1 = t < NEXT_AT
    ? "password = red-panda"
    : working("password = green-fox", t, NEXT_AT, NEXT_AT + .32, 5) ?? "password = green-fox"
  const deskLine2 = t < NEXT_AT
    ? "replaces v1 · hash 7c1e…"
    : working("replaces blue-whale · hash c30a…", t, NEXT_AT, NEXT_AT + .4, 6) ?? "replaces blue-whale · hash c30a…"
  const deskEntry = t < NEXT_AT ? "entry 7c1e" : working("entry c30a", t, NEXT_AT, NEXT_AT + .3, 2) ?? "entry c30a"

  const itemLit = clamp01((story.focus(t, "item", .35) - .35) / .65)
  const deskLit = clamp01((story.focus(t, "desktop", .35) - .35) / .65)
  const lapLit = clamp01((story.focus(t, "laptop", .35) - .35) / .65)
  const histWipe = story.reduced ? 1 : wipe(t, SETTLE_AT + .06, .34)
  // The comparison between the wires is printed when both edits have arrived, and lifts off once a later edit
  // makes it moot.
  const compared = span(t, SYNC_LANDS, SYNC_LANDS + .25) * (1 - span(t, NEXT_AT, NEXT_AT + .2))

  return <>
    <Wire id="cross" d={crossAB.d} t={t} story={story} />
    <Wire id="cross" d={crossBA.d} t={t} story={story} />
    <Wire id="deskUp" d={deskToItem.d} t={t} story={story} dashed />
    <Wire id="lapUp" d={lapToItem.d} t={t} story={story} dashed />

    <Frame id="item" box={itemBox} t={t} story={story} light={light} label="github" detail="login" heat={itemHeat} headerY={itemBox[1] + 22}>
      <line x1={itemBox[0] + 14} x2={itemBox[0] + itemBox[2] - 14} y1={itemBox[1] + 40} y2={itemBox[1] + 40} stroke="#1f1f1f" />
      <text x={itemBox[0] + 18} y={itemBox[1] + 60} dominantBaseline="middle" className="story-note" fill={shade("#6a6a6a", ["#a8a49c", itemLit])}>username</text>
      <text x={itemBox[0] + 124} y={itemBox[1] + 60} dominantBaseline="middle" className="story-entry" fill={shade("#8a867e", ["#e8e4dc", itemLit])}>kit</text>
      <text x={itemBox[0] + 18} y={itemBox[1] + 82} dominantBaseline="middle" className="story-note" fill={shade("#6a6a6a", ["#a8a49c", itemLit])}>password</text>
      <text x={itemBox[0] + 124} y={itemBox[1] + 82} dominantBaseline="middle" className="story-entry" fill={shade("#9a968e", ["#fff1dc", Math.max(itemLit, itemHeat)])}>{passwordVal}</text>
      {expand > .02 && <>
        <clipPath id="merge-history-wipe">
          <rect x={itemBox[0] + 14} y={itemBox[1] + 94} width={(itemBox[2] - 28) * histWipe} height={28} />
        </clipPath>
        <g clipPath="url(#merge-history-wipe)" opacity={expand}>
          <text x={itemBox[0] + 18} y={itemBox[1] + 108} dominantBaseline="middle" className="story-note" fill="#7a7a7a">history</text>
          <text x={itemBox[0] + 124} y={itemBox[1] + 108} dominantBaseline="middle" className="story-note" fill={shade("#6e6e6e", ["#cfcac1", itemLit])}>red-panda (concurrent · 7c1e)</text>
        </g>
      </>}
    </Frame>

    <Frame id="desktop" box={DESKTOP} t={t} story={story} light={light} glyph="desktop" impulses={DESKTOP_IMPULSES}
      label="desktop" detail={deskEntry} heat={deskHeat} headerY={DESKTOP[1] + 22}>
      <line x1={DESKTOP[0] + 14} x2={DESKTOP[0] + DESKTOP[2] - 14} y1={DESKTOP[1] + 40} y2={DESKTOP[1] + 40} stroke="#1f1f1f" />
      <text x={DESKTOP[0] + 18} y={DESKTOP[1] + 62} dominantBaseline="middle" className="story-entry" fill={shade("#7a7a7a", ["#e8e4dc", deskLit])}>{deskLine1}</text>
      <text x={DESKTOP[0] + 18} y={DESKTOP[1] + 84} dominantBaseline="middle" className="story-note" fill={shade("#585858", ["#9e9a92", deskLit])}>{deskLine2}</text>
    </Frame>

    <Frame id="laptop" box={LAPTOP} t={t} story={story} light={light} glyph="laptop" impulses={LAPTOP_IMPULSES}
      label="laptop" detail="entry a94b" heat={lapHeat} headerY={LAPTOP[1] + 22}>
      <line x1={LAPTOP[0] + 14} x2={LAPTOP[0] + LAPTOP[2] - 14} y1={LAPTOP[1] + 40} y2={LAPTOP[1] + 40} stroke="#1f1f1f" />
      <text x={LAPTOP[0] + 18} y={LAPTOP[1] + 62} dominantBaseline="middle" className="story-entry" fill={shade("#7a7a7a", ["#e8e4dc", lapLit])}>password = blue-whale</text>
      <text x={LAPTOP[0] + 18} y={LAPTOP[1] + 84} dominantBaseline="middle" className="story-note" fill={shade("#585858", ["#9e9a92", lapLit])}>replaces v1 · hash a94b…</text>
    </Frame>

    {compared > 0 && <text x={W / 2} y={246} textAnchor="middle" className="story-note" fill="#8d8a84" opacity={compared}>a94b… &gt; 7c1e…</text>}

    {SHOTS.map(shot => <Carried key={shot.id} shot={shot} t={t} label={shot.label} />)}
  </>
}

export function MergeStory() {
  return <Story scene={mergeScene} />
}
