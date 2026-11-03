import type { Light } from "../../story/light"
import { across, between, cipher, send, soundOfSend, timing, type Send } from "../../story/beats"
import { Carried, DeviceGlyph, Frame, edge } from "../../story/devices"
import { clamp01, flashes, shade, smoothstep, span, working, type Box, type Point } from "../../story/motion"
import { Story, type StoryApi, type StoryScene } from "../../story/Story"

// On one device (the desktop), the `deadbolt` command is a thin client. It talks over a user-only Unix socket to
// the background daemon, which alone opens store.redb, keeps the vault unlocked in memory, and runs the iroh node.
//
// Composition: the request runs along one straight line (terminal, cli, socket, vault state). Inside the daemon
// the store sits above the vault state and the iroh node below it, so every hop is a short vertical one and no
// wire crosses a card. The store's band is its sealed ciphertext; a read clears a window in it, which seals again.

const W = 940, H = 330

const TERM: Box = [28, 146, 180, 54]
const CLI: Box = [240, 146, 140, 54]
const SOCK: Point = [418, 173]
const DAEMON: Box = [456, 22, 304, 284]
const STORE: Box = [478, 44, 260, 72]
const CORE: Box = [478, 146, 260, 54]
const NET: Box = [478, 230, 260, 54]
const PEER: Box = [792, 230, 116, 54]
const STORE_BAND: Box = [STORE[0] + 8, STORE[1] + 40, STORE[2] - 16, 24]

const toCli = across(edge.right(TERM), edge.left(CLI))
const cliToSock = across(edge.right(CLI), SOCK)
const sockToCore = across(SOCK, edge.left(CORE))
const toCore = across(edge.right(CLI), edge.left(CORE))
const coreToStore = between([592, CORE[1]], [592, STORE[1] + STORE[3]])
const storeToCore = between([624, STORE[1] + STORE[3]], [624, CORE[1]])
const coreToNet = between([608, CORE[1] + CORE[3]], [608, NET[1]])
const netToPeer = across(edge.right(NET), edge.left(PEER))

type Shot = Send & { id: string; label?: string; side?: "left" | "right" }

const sAsk: Shot = { id: "toCli", path: toCli, at: .25, flight: .6, label: "get github", into: { box: CLI } }
const sReq: Shot = { id: "toCore", path: toCore, at: 2.7, flight: .8, label: "item-get", into: { box: CORE } }
const sRead: Shot = { id: "toStore", path: coreToStore, at: 5.7, flight: .55, label: "read", side: "left", tone: "red", into: { box: STORE, tone: "red" } }
const READ = timing(sRead).lands
const sUnseal: Shot = { id: "fromStore", path: storeToCore, at: READ + .45, flight: .55, label: "unseal", side: "right", into: { box: CORE } }
const sReply: Shot = { id: "replyCore", path: toCore, reverse: true, at: 8.9, flight: .8, label: "item", into: { box: CLI } }
const sAnswer: Shot = { id: "replyCli", path: toCli, reverse: true, at: timing(sReply).lands + .12, flight: .6, label: "Xk2mv9…", into: { box: TERM } }
const sNetWake: Shot = { id: "toNet", path: coreToNet, at: 12.3, flight: .55, into: { box: NET } }
const sSync: Shot = { id: "toPeer", path: netToPeer, at: timing(sNetWake).lands + .05, flight: .7, label: "sync", into: { box: PEER } }

const SHOTS: readonly Shot[] = [sAsk, sReq, sRead, sUnseal, sReply, sAnswer, sNetWake, sSync]

const DESKTOP_IMPULSES = [sAsk.at, sReq.at, sRead.at, sReply.at, sSync.at]
const LAPTOP_IMPULSES = [timing(sSync).lands]

export const daemonScene: StoryScene = {
  label: "The cli sends one JSON line over a user-only Unix socket to the background daemon, which alone opens store.redb and runs the iroh node.",
  width: W, height: H, duration: 15.6, poster: 2,
  sounds: [sAsk, sReq, sRead, sAnswer, sSync].flatMap(s => soundOfSend(s, W, .8).cues),
  flights: [sAsk, sReq, sReply, sSync].map(s => soundOfSend(s, W, .75).flight),
  steps: [
    {
      at: 0,
      focus: { term: 1, cli: 1, toCli: 1, daemon: .5 },
      caption: { text: "the cli is a thin client; it never opens the store", anchor: edge.top(CLI), place: [262, 124], align: "above", delay: 0 },
    },
    {
      at: 2.5,
      focus: { cli: .9, sock: 1, core: 1, toCore: 1, daemon: .9 },
      caption: { text: "one json request crosses a user-only unix socket", anchor: [SOCK[0], SOCK[1] + 6], place: [424, 236], align: "end", delay: .2 },
    },
    {
      at: 5.5,
      focus: { core: 1, store: 1, toStore: 1, daemon: 1 },
      caption: { text: "only the background daemon opens store.redb", anchor: edge.left(STORE), place: [448, 80], align: "end", delay: .2 },
    },
    {
      at: 8.7,
      focus: { core: .9, cli: 1, term: 1, toCore: 1, toCli: 1, daemon: .7 },
      caption: { text: "the secret leaves the daemon only when a command asks", anchor: edge.bottom(TERM), place: [118, 214], align: "below", delay: .25 },
    },
    {
      at: 12.1,
      focus: { core: .7, net: 1, peer: 1, toPeer: 1, daemon: .9 },
      caption: { text: "while unlocked, the daemon also runs the iroh node", anchor: edge.left(NET), place: [448, 257], align: "end", delay: .25 },
    },
  ],
  draw: (t, light, story) => {
    for (const shot of SHOTS) send(light, shot, t)
    // The read clears a window in the sealed band where it lands, wicking open (√t); once the record has gone back
    // up to the vault state, the seal closes over it again.
    const opening = Math.sqrt(span(t, READ, READ + .5)) * (1 - smoothstep(span(t, timing(sUnseal).launch + .15, timing(sUnseal).launch + .95)))
    cipher(light, STORE_BAND, { tone: "red", level: .75, seed: 7, open: opening > .01 ? { from: [592, STORE[1] + STORE[3]], radius: 36 * opening } : undefined })
    return <Daemon t={t} light={light} story={story} />
  },
}

function Wire({ id, d, t, story, dashed }: { id: string; d: string; t: number; story: StoryApi; dashed?: boolean }) {
  const level = story.focus(t, id, .22)
  const lit = clamp01((level - .22) / .78)
  return <path d={d} fill="none" stroke={shade("#252525", ["#7c7972", lit])} strokeDasharray={dashed ? "2 5" : undefined} />
}

function Daemon({ t, light, story }: { t: number; light: Light; story: StoryApi }) {
  const termHeat = flashes(t, [sAsk.at + .2, timing(sAnswer).lands], 1.0)
  const cliHeat = flashes(t, [timing(sAsk).lands, timing(sReply).lands], 1.0)
  const coreHeat = flashes(t, [timing(sReq).lands, timing(sUnseal).lands], 1.1)
  const storeHeat = flashes(t, [READ], 1.3)
  const netHeat = flashes(t, [timing(sNetWake).lands, sSync.at + .3], 1.2)
  const peerHeat = flashes(t, [timing(sSync).lands], 1.1)

  const daemonLit = clamp01((story.focus(t, "daemon", .35) - .35) / .65)
  const sockLit = clamp01((story.focus(t, "sock", .3) - .3) / .7)
  const termDetail = t >= timing(sAnswer).lands
    ? working("Xk2mv9Qp…", t, timing(sAnswer).lands, timing(sAnswer).lands + .35, 5, "$ get github") ?? "Xk2mv9Qp…"
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
    <text x={SOCK[0]} y={SOCK[1] - 14} textAnchor="middle" className="story-note" fill={shade("#5e5e5e", ["#cfcac1", sockLit])}>daemon.sock</text>

    <rect x={DAEMON[0] + .5} y={DAEMON[1] + .5} width={DAEMON[2] - 1} height={DAEMON[3] - 1}
      fill="none" stroke={shade("#222222", ["#444444", daemonLit])} />
    <DeviceGlyph kind="desktop" cx={DAEMON[0] + 10} cy={DAEMON[1] - 12} t={t} impulses={DESKTOP_IMPULSES}
      stroke={shade("#666666", ["#e8e4dc", daemonLit])} />
    <text x={DAEMON[0] + 24} y={DAEMON[1] - 11.5} dominantBaseline="middle" className="story-note"
      fill={shade("#666666", ["#cfcac1", daemonLit])}>desktop · background daemon</text>

    <Frame id="store" box={STORE} t={t} story={story} light={light} label="store.redb" detail="deadbolt-store" tone="red" heat={storeHeat} headerY={STORE[1] + 22} />
    <Frame id="core" box={CORE} t={t} story={story} light={light} label="vault state" detail="deadbolt-core" heat={coreHeat} />
    <Frame id="net" box={NET} t={t} story={story} light={light} label="iroh node" detail="deadbolt-net" heat={netHeat} />

    <Frame id="peer" box={PEER} t={t} story={story} light={light} glyph="laptop" impulses={LAPTOP_IMPULSES}
      label="laptop" heat={peerHeat} />

    {SHOTS.map(shot => <Carried key={shot.id} shot={shot} t={t} label={shot.label} side={shot.side} />)}
  </>
}

export function DaemonStory() {
  return <Story scene={daemonScene} />
}
