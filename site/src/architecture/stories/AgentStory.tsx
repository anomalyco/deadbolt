import type { Light } from "../../story/light"
import { across, between, polyline, send, timing, type Send } from "../../story/beats"
import { Carried, Frame, Solid, edge } from "../../story/devices"
import { clamp01, flashes, shade, working, type Box, type Point } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// On one device (the cube), the `deadbolt` command is a thin client. It talks over a user-only Unix socket to
// the background agent, which alone opens store.redb, keeps the vault unlocked in memory, and runs the iroh node.

const W = 940, H = 330

const TERM: Box = [36, 136, 152, 54]
const CLI: Box = [226, 136, 148, 54]
const SOCK: Point = [416, 163]
const AGENT: Box = [456, 32, 304, 260]
const CORE: Box = [478, 66, 260, 54]
const STORE: Box = [478, 136, 260, 54]
const NET: Box = [478, 206, 260, 54]
const PEER: Box = [792, 206, 116, 54]

const toCli = across(edge.right(TERM), edge.left(CLI))
const cliToSock = across(edge.right(CLI), SOCK)
const sockToCore = polyline([SOCK, [444, SOCK[1]], [444, CORE[1] + CORE[3] / 2], edge.left(CORE)])
const toCore = polyline([edge.right(CLI), SOCK, [444, SOCK[1]], [444, CORE[1] + CORE[3] / 2], edge.left(CORE)])
const coreToStore = between([592, CORE[1] + CORE[3]], [592, STORE[1]])
const storeToCore = between([624, STORE[1]], [624, CORE[1] + CORE[3]])
const coreToNet = between([608, CORE[1] + CORE[3]], [608, NET[1]])
const netToPeer = across(edge.right(NET), edge.left(PEER))

type Shot = Send & { id: string; label?: string }

const sAsk: Shot = { id: "toCli", path: toCli, at: .25, flight: .75, label: "get github", into: { box: CLI } }
const sReq: Shot = { id: "toCore", path: toCore, at: 2.7, flight: 1.05, label: "item-get", into: { box: CORE } }
const sRead: Shot = { id: "toStore", path: coreToStore, at: 5.7, flight: .65, label: "read", tone: "red", into: { box: STORE, tone: "red" } }
const sUnseal: Shot = { id: "fromStore", path: storeToCore, at: timing(sRead).lands + .18, flight: .65, label: "unseal", into: { box: CORE } }
const sReply: Shot = { id: "replyCore", path: toCore, reverse: true, at: 8.9, flight: 1.0, label: "item", into: { box: CLI } }
const sAnswer: Shot = { id: "replyCli", path: toCli, reverse: true, at: timing(sReply).lands + .12, flight: .75, label: "Xk2mv9…", into: { box: TERM } }
const sNetWake: Shot = { id: "toNet", path: coreToNet, at: 12.3, flight: .65, into: { box: NET } }
const sSync: Shot = { id: "toPeer", path: netToPeer, at: timing(sNetWake).lands + .05, flight: .85, label: "sync", into: { box: PEER } }

const SHOTS: readonly Shot[] = [sAsk, sReq, sRead, sUnseal, sReply, sAnswer, sNetWake, sSync]

const CUBE_IMPULSES = [sAsk.at, sReq.at, sRead.at, sReply.at, sSync.at]
const PYRAMID_IMPULSES = [timing(sSync).lands]

export const agentScene: StoryScene = {
  label: "The cli sends one JSON line over a user-only Unix socket to the background agent, which alone opens store.redb and runs the iroh node.",
  width: W, height: H, duration: 15.6, poster: 2,
  steps: [
    {
      at: 0,
      focus: { term: 1, cli: 1, toCli: 1, agent: .5 },
      caption: { text: "the cli is a thin client; it never opens the store", anchor: [CLI[0] + CLI[2] / 2, CLI[1]], place: [300, 74], align: "above", delay: 0 },
    },
    {
      at: 2.5,
      focus: { cli: .9, sock: 1, core: 1, toCore: 1, agent: .9 },
      caption: { text: "one json request crosses a user-only unix socket", anchor: [SOCK[0], SOCK[1] - 6], place: [416, 74], align: "above", delay: .2 },
    },
    {
      at: 5.5,
      focus: { core: 1, store: 1, toStore: 1, agent: 1 },
      caption: { text: "only the background agent opens store.redb", anchor: [STORE[0], STORE[1] + STORE[3] / 2], place: [396, 232], align: "end", delay: .2 },
    },
    {
      at: 8.7,
      focus: { core: .9, cli: 1, term: 1, toCore: 1, toCli: 1, agent: .7 },
      caption: { text: "the secret leaves the agent only when a command asks", anchor: [TERM[0] + TERM[2] / 2, TERM[1] + TERM[3]], place: [180, 246], align: "below", delay: .25 },
    },
    {
      at: 12.1,
      focus: { core: .7, net: 1, peer: 1, toPeer: 1, agent: .9 },
      caption: { text: "while unlocked, the agent also runs the iroh node", anchor: [NET[0] + NET[2] / 2, NET[1] + NET[3]], place: [608, 304], align: "below", delay: .25 },
    },
  ],
  draw: (t, light, story) => <Agent t={t} light={light} story={story} />,
}

function Wire({ id, d, t, story, dashed }: { id: string; d: string; t: number; story: StoryApi; dashed?: boolean }) {
  const level = story.focus(t, id, .22)
  const lit = clamp01((level - .22) / .78)
  return <path d={d} fill="none" stroke={shade("#252525", ["#7c7972", lit])} strokeDasharray={dashed ? "2 5" : undefined} />
}

function Agent({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  for (const shot of SHOTS) send(light, shot, t)

  const termHeat = flashes(t, [sAsk.at + .2, timing(sAnswer).lands], 1.0)
  const cliHeat = flashes(t, [timing(sAsk).lands, timing(sReply).lands], 1.0)
  const coreHeat = flashes(t, [timing(sReq).lands, timing(sUnseal).lands], 1.1)
  const storeHeat = flashes(t, [timing(sRead).lands], 1.3)
  const netHeat = flashes(t, [timing(sNetWake).lands, sSync.at + .3], 1.2)
  const peerHeat = flashes(t, [timing(sSync).lands], 1.1)

  const agentLit = clamp01((story.focus(t, "agent", .35) - .35) / .65)
  const sockLit = clamp01((story.focus(t, "sock", .3) - .3) / .7)
  const termDetail = t >= timing(sAnswer).lands
    ? working("Xk2mv9Qp…", t, timing(sAnswer).lands, timing(sAnswer).lands + .35, 5) ?? "Xk2mv9Qp…"
    : "$ get github"

  return <>
    <Wire id="toCli" d={toCli.d} t={t} story={story} />
    <Wire id="toCore" d={cliToSock.d} t={t} story={story} />
    <Wire id="toCore" d={sockToCore.d} t={t} story={story} />
    <Wire id="toStore" d={coreToStore.d} t={t} story={story} />
    <Wire id="toStore" d={storeToCore.d} t={t} story={story} />
    <Wire id="toPeer" d={coreToNet.d} t={t} story={story} />
    <Wire id="toPeer" d={netToPeer.d} t={t} story={story} dashed />

    <text x={TERM[0]} y={TERM[1] - 10} className="story-note" fill="#7a7a7a">you, or an ai agent</text>
    <Frame id="term" box={TERM} t={t} story={story} light={light} label="terminal" detail={termDetail} heat={termHeat} />
    <Frame id="cli" box={CLI} t={t} story={story} light={light} label="deadbolt" detail="cli" heat={cliHeat} />

    <circle cx={SOCK[0]} cy={SOCK[1]} r={4.2} fill="#050505" stroke={shade("#555555", ["#e8e4dc", sockLit])} />
    <text x={SOCK[0]} y={SOCK[1] + 20} textAnchor="middle" className="story-note" fill={shade("#5e5e5e", ["#cfcac1", sockLit])}>agent.sock</text>

    <rect x={AGENT[0] + .5} y={AGENT[1] + .5} width={AGENT[2] - 1} height={AGENT[3] - 1}
      fill="none" stroke={shade("#222222", ["#444444", agentLit])} />
    <Solid kind="cube" cx={AGENT[0] + 10} cy={AGENT[1] - 12} r={6.8} t={t} impulses={CUBE_IMPULSES}
      stroke={shade("#666666", ["#e8e4dc", agentLit])} reduced={story.reduced} />
    <text x={AGENT[0] + 24} y={AGENT[1] - 11.5} dominantBaseline="middle" className="story-note"
      fill={shade("#666666", ["#cfcac1", agentLit])}>cube · background agent</text>

    <Frame id="core" box={CORE} t={t} story={story} light={light} label="vault state" detail="deadbolt-core" heat={coreHeat} />
    <Frame id="store" box={STORE} t={t} story={story} light={light} label="store.redb" detail="deadbolt-store" tone="red" heat={storeHeat} />
    <Frame id="net" box={NET} t={t} story={story} light={light} label="iroh node" detail="deadbolt-net" heat={netHeat} />

    <Frame id="peer" box={PEER} t={t} story={story} light={light} glyph="pyramid" impulses={PYRAMID_IMPULSES}
      label="pyramid" heat={peerHeat} />

    {SHOTS.map(shot => <Carried key={shot.id} shot={shot} t={t} label={shot.label} />)}
  </>
}

export function AgentStory() {
  return <Story scene={agentScene} />
}
