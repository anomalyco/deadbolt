import type { ReactNode } from "react"
import { Ink } from "../print/Ink"
import { Masthead } from "../print/Masthead"
import { MeshStory } from "./stories/MeshStory"
import { AgentStory } from "./stories/AgentStory"
import { KeysStory } from "./stories/KeysStory"
import { LogsStory } from "./stories/LogsStory"
import { SyncStory } from "./stories/SyncStory"
import { MergeStory } from "./stories/MergeStory"
import { PairStory } from "./stories/PairStory"
import { RemoveStory } from "./stories/RemoveStory"

const repo = "https://github.com/anomalyco/deadbolt/blob/main/"
const Src = ({ path, children }: { path: string; children?: ReactNode }) =>
  <a className="link" href={repo + path} target="_blank" rel="noopener"><code>{children ?? path}</code></a>

type Chapter = { id: string; title: string; body: ReactNode; scene: ReactNode; why?: ReactNode; code: [string, string][] }

const chapters: Chapter[] = [
  {
    id: "shape", title: "no server",
    body: <>
      <p>deadbolt is a password manager where your devices are the whole system. each one holds a full copy of the vault, and they sync with each other directly. there's no account and no deadbolt server, so there's nothing of ours to breach and nothing to keep running.</p>
      <p>networking is <a className="link" href="https://www.iroh.computer">iroh</a>: a device's public key is its address, and iroh connects two devices directly when it can. when it can't, one of n0's public relays forwards the stream. that stream is end-to-end encrypted, so the relay only ever sees ciphertext.</p>
    </>,
    scene: <MeshStory />,
    why: <p>the cost of no server: there's no recovery. lose every device and the vault is gone. that was a deliberate call for v1.</p>,
    code: [["docs/design.md", "the v1 design, two pages"], ["crates/net/src/node.rs", "NodeConfig: relays, address lookup, port mapping"]],
  },
  {
    id: "device", title: "one device, four crates",
    body: <>
      <p>on each machine there are two processes. the <code>deadbolt</code> command you type is a thin client. the work happens in a background agent that the cli starts on first use. the agent is the only process that ever opens the store, it keeps the vault unlocked in memory, and while unlocked it runs the iroh node.</p>
      <p>the code splits along the same lines: <code>deadbolt-core</code> is the pure model (entries, membership, items, merging) with no io at all; <code>deadbolt-store</code> is the encrypted file on disk; <code>deadbolt-net</code> is iroh, sync and pairing; <code>deadbolt-cli</code> is the binary, holding both the client and the agent.</p>
    </>,
    scene: <AgentStory />,
    why: <p>the cli was built agent-first: every command works from flags, env and stdin, and it never waits on a human without a terminal. an ai agent can drive it the same way you do.</p>,
    code: [["crates/cli/src/main.rs", "the commands"], ["crates/cli/src/client.rs", "starts, replaces and talks to the agent"], ["crates/cli/src/protocol.rs", "the socket protocol: one json line per request"], ["crates/cli/src/agent/mod.rs", "the agent: lock, unlock, the membership gate"], ["crates/cli/src/paths.rs", "where the socket, store and logs live"]],
  },
  {
    id: "keys", title: "two keys",
    body: <>
      <p>each device has exactly two keys. the <b>device key</b> (ed25519) is the device's identity: it signs everything the device writes, and its public half is the device's iroh address. the <b>local unlock key</b> comes from your passphrase through argon2id, and it's what seals the device key and the database on disk.</p>
      <p>there's no shared vault key in v1. data only moves over encrypted iroh connections between current members, and at rest each device seals its own copy under its own unlock key.</p>
    </>,
    scene: <KeysStory />,
    why: <p>why not separate keys for signing and networking? neither could live in the secure enclave (it only does p-256), and both have to be in memory while the agent runs. two keys there would add a key without adding protection.</p>,
    code: [["crates/store/src/lib.rs", "the file layout, keys and integrity, documented at the top"], ["crates/store/src/kdf.rs", "argon2id parameters"], ["crates/store/src/crypto.rs", "xchacha20-poly1305 sealing"]],
  },
  {
    id: "logs", title: "signed logs",
    body: <>
      <p>the vault isn't stored as a table of passwords. it's stored as history: every change is an entry appended to its author's own log, and the current state is computed from all the logs together.</p>
      <p>entries never refer to the time. each one lists the entries its author had already seen, by hash. that's enough to tell, for any two changes, whether one saw the other or they happened apart, and it gives every device the same answer whatever order entries arrive in.</p>
      <p>membership entries (create, add, remove and rename, red in the diagram) only list other membership entries, so membership can always sync first. a new device doesn't add itself. an existing member writes an <code>Add</code> that carries the newcomer's signed consent, and the newcomer's first entry lists that add. every entry is signed by its author and its hash covers its deps, so changing an old entry would break every entry that saw it.</p>
    </>,
    scene: <LogsStory />,
    why: <p>each entry has exactly one valid encoding (hand-rolled, length-prefixed, deps sorted), so its hash and signature mean the same thing on every device.</p>,
    code: [["crates/core/src/lib.rs", "the model and the wire format, documented at the top"], ["crates/core/src/entry.rs", "entries, ops and signing"], ["crates/core/src/vault.rs", "applying entries, heads, what a peer is missing"]],
  },
  {
    id: "sync", title: "sync",
    body: <>
      <p>sync is one simple exchange: "here's what i have, send me what i'm missing". each side sends its heads (the latest entry it holds from every log), works out from the other's heads what to send, and sends it. the protocol in <code>deadbolt-net</code> treats all of this as opaque bytes; the agent decides what heads and entries mean.</p>
      <p>membership always goes first. when the agent unlocks, it first syncs membership with every member it can reach, and only sends membership entries until that round is done. that shrinks the window in which a device that was offline for a while still trusts a device someone removed.</p>
    </>,
    scene: <SyncStory />,
    code: [["crates/net/src/sync.rs", "the deadbolt/sync/1 protocol"], ["crates/cli/src/agent/sync.rs", "what the agent puts in heads and how it orders entries"]],
  },
  {
    id: "merge", title: "concurrent edits",
    body: <>
      <p>an item (a login or a card) is a set of typed fields. each field behaves like a register: an edit replaces the value it was based on. if two edits were made apart and both replace the same value, the one in the entry with the higher hash wins. the other isn't lost: it goes into the item's history.</p>
      <p>the core also enforces the item rules on every device: an item is created with all its required fields in one entry, a known field always keeps its type, required fields can't be removed and the type can't change. a device refuses to write an entry that breaks them, and when one arrives anyway it skips just the bad ops, in the same way on every device.</p>
    </>,
    scene: <MergeStory />,
    code: [["crates/core/src/data.rs", "items, versions and history"], ["crates/core/src/item.rs", "item types, field types and the rules"]],
  },
  {
    id: "pairing", title: "pairing",
    body: <>
      <p>the only way into a vault is through a device that's already in it. the new device listens and shows a ticket. a member dials it with that ticket, both prove they know the ticket's secret, and both show a six-digit code derived from the connection and both keys. once you confirm the code matches, the new device signs its consent to join that particular vault, the member signs <code>Add</code>, and the vault's history flows over the same connection.</p>
    </>,
    scene: <PairStory />,
    why: <p>the code check is what stops a man in the middle. someone who only saw the qr code can't produce matching digits on both screens.</p>,
    code: [["crates/net/src/pair.rs", "the deadbolt/pair/1 protocol, step by step"], ["crates/cli/src/agent/pairing.rs", "offer, join and welcome"], ["crates/net/src/qr.rs", "the terminal qr code"]],
  },
  {
    id: "removal", title: "removal and the gate",
    body: <>
      <p>removal rests on one small, security-critical check: is this device in the current member set? the network layer runs it before dialing a peer and again right after the tls handshake on both sides, and a refused connection is closed before the application reads or writes a byte. when a removal arrives, open connections to that device are closed immediately.</p>
      <p>a removed device keeps whatever it already had; no system can take that back. what it can't do is get anything new.</p>
    </>,
    scene: <RemoveStory />,
    why: <p>the trade-off: without a shared vault key there's nothing to re-key, so removal has no ciphertext backstop. if the membership check had a bug, there'd be nothing behind it. the design accepts that and asks for dedicated tests of the gate.</p>,
    code: [["crates/net/src/node.rs", "the gate: before_connect and after_handshake hooks, revoke"], ["crates/core/src/membership.rs", "add, remove, and concurrent removals"]],
  },
]

const crates: [string, string, string][] = [
  ["deadbolt-core", "the model: device ids, signed entries, membership, typed items, merging, heads. no io, no async.", "crates/core"],
  ["deadbolt-store", "one encrypted redb file per device: argon2id, xchacha20-poly1305, keyed hashes, zeroized keys.", "crates/store"],
  ["deadbolt-net", "iroh endpoint, the membership gate, deadbolt/sync/1 and deadbolt/pair/1, qr rendering.", "crates/net"],
  ["deadbolt-cli", "the deadbolt binary: commands, the background agent, the socket protocol, bitwarden import.", "crates/cli"],
]

export function Architecture() {
  return <div className="site">
    <Ink />
    <main>
      <nav className="nav"><a href="/">← deadbolt</a><span>architecture</span></nav>
      <Masthead />
      <p className="description">how deadbolt works, one moving diagram at a time. each diagram loops while it's on screen; hover the bar under it to hold, click a segment to jump, or drag to scrub.</p>
      <ol className="toc">
        {chapters.map(c => <li key={c.id}><a href={`#${c.id}`}>{c.title}</a></li>)}
        <li><a href="#code">the code</a></li>
      </ol>

      {chapters.map((c, i) => <section key={c.id} id={c.id} className="chapter">
        <span className="chapter-number">{String(i + 1).padStart(2, "0")}</span>
        <h2>{c.title}</h2>
        {c.body}
        <div className="bleed">{c.scene}</div>
        {c.why && <div className="callout">{c.why}</div>}
        <dl className="in-code"><dt>in the code</dt>{c.code.map(([path, note]) => <dd key={path}><Src path={path} /> <span className="dim">{note}</span></dd>)}</dl>
      </section>)}

      <section id="code" className="chapter">
        <span className="chapter-number">{String(chapters.length + 1).padStart(2, "0")}</span>
        <h2>the code</h2>
        <table>
          <thead><tr><th>crate</th><th>what it does</th></tr></thead>
          <tbody>{crates.map(([name, what, path]) => <tr key={name}><td><Src path={path}>{name}</Src></td><td>{what}</td></tr>)}</tbody>
        </table>

        <h3>build and test</h3>
        <pre>{`$ cargo build -j 2
$ cargo test -j 2            `}<span className="output">{"# core, store, net and multi-device cli tests"}</span>{`
$ cargo build --release -j 2 `}<span className="output">{"# target/release/deadbolt"}</span></pre>
        <p className="dim">the cli tests run real agents for several devices on localhost, with <code>DEADBOLT_NET=local</code> and a fast kdf.</p>

        <h3>rough edges</h3>
        <ul className="plain">
          <li>the readme still says "no code yet", and there's no install section, ci or release workflow.</li>
          <li>no recovery: lose every device, lose the vault. a paper "recovery device" is designed for later.</li>
          <li>no compaction: history, including deleted items, grows forever on every device.</li>
          <li>importing the same bitwarden export twice imports everything twice.</li>
          <li>the os keychain unlock (biometrics instead of the passphrase) is designed but not built.</li>
          <li><code>deadbolt agent stop</code> followed straight away by another command could fail with "the agent is already running". fixed locally in <Src path="crates/cli/src/client.rs" />, not yet in main.</li>
        </ul>

        <h3>good first things</h3>
        <ol className="plain">
          <li>fix the readme and add install instructions.</li>
          <li>add ci: fmt, clippy and the test suite.</li>
          <li>dedicated tests for the membership gate, as the design asks.</li>
          <li>the keychain unlock slot in <code>deadbolt-store</code>.</li>
          <li>the convenience commands the design defers: picker, history, totp codes, clipboard, json output.</li>
        </ol>
      </section>

      <footer>deadbolt · <a className="link" href="/">home</a> · <a className="link" href="https://github.com/anomalyco/deadbolt">github</a></footer>
    </main>
  </div>
}
