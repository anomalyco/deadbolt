// The receive page, /r#<ticket>: fetches a Deadbolt Send share straight from the sender's
// computer over iroh (WebAssembly, relay only) and decrypts it here.
//
// The ticket in the fragment holds the access secret and the content key. Browsers never send
// a fragment to a server; this page reads it once, then removes it from the address bar and
// history, keeps it only in memory, and never logs it. The page sets no-referrer and loads
// nothing from third parties (see public/_headers).
import { StrictMode, useEffect, useState } from "react"
import { createRoot } from "react-dom/client"
import "../styles.css"
import "./receive.css"
import { type Bundle, type Entry, type Failure, type Node, type Step, count, dotenv, isValue, messages, size, text } from "./model"

type Phase =
  | { kind: "ready" }
  | { kind: "missing" }
  | { kind: "working"; step: Step; received: number; total: number }
  | { kind: "done"; bundle: Bundle }
  | { kind: "failed"; failure: Failure }

function takeLink(): string | undefined {
  const fragment = window.location.hash.slice(1)
  if (fragment) window.history.replaceState(null, "", window.location.pathname)
  return fragment || undefined
}

async function fetchBundle(link: string, onStep: (step: Step, received: number, total: number) => void): Promise<Bundle> {
  const wasm = await import("./wasm/deadbolt_send_web.js")
  await wasm.default()
  return (await wasm.receive(link, onStep)) as Bundle
}

function asFailure(error: unknown): Failure {
  if (error && typeof error === "object" && "kind" in error && "message" in error) return error as Failure
  return { kind: "failed", message: String(error) }
}

// Read once, before React renders anything, so the fragment is gone from the address bar at once.
const link = takeLink()

function Receive() {
  const [phase, setPhase] = useState<Phase>(link ? { kind: "ready" } : { kind: "missing" })

  const start = () => {
    if (!link) return
    setPhase({ kind: "working", step: "connecting", received: 0, total: 0 })
    fetchBundle(link, (step, received, total) => setPhase({ kind: "working", step, received, total }))
      .then(bundle => setPhase({ kind: "done", bundle }))
      .catch(error => setPhase({ kind: "failed", failure: asFailure(error) }))
  }

  return <main className="receive">
    <p className="brand"><a href="/">deadbolt</a> <span className="dim">send</span></p>
    {phase.kind === "missing" && <Missing />}
    {phase.kind === "ready" && <Ready onStart={start} />}
    {phase.kind === "working" && <Working {...phase} />}
    {phase.kind === "failed" && <Failed failure={phase.failure} onRetry={start} />}
    {phase.kind === "done" && <Received bundle={phase.bundle} />}
  </main>
}

function Missing() {
  return <section className="state" data-state="missing">
    <h2>No link here</h2>
    <p className="dim">Open the whole link you were sent. Once read, this page removes it from the address bar, so reloading won't bring it back.</p>
  </section>
}

function Ready({ onStart }: { onStart: () => void }) {
  return <section className="state" data-state="ready">
    <h2>Someone sent you something</h2>
    <p className="dim">It comes straight from the sender's computer, end-to-end encrypted, and is decrypted here in your browser. The link may only open once.</p>
    <button type="button" className="cta" onClick={onStart} autoFocus>Receive</button>
  </section>
}

const stepText: Record<Step, string> = {
  connecting: "Connecting to the sender…",
  proving: "Proving the link…",
  downloading: "Downloading…",
  decrypting: "Decrypting…",
}

function Working({ step, received, total }: { step: Step; received: number; total: number }) {
  return <section className="state" data-state={step} aria-live="polite">
    <h2>{stepText[step]}</h2>
    {step === "downloading" && total > 0 && <>
      <progress max={total} value={received} />
      <p className="dim">{size(received)} of {size(total)}</p>
    </>}
    {step === "connecting" && <p className="dim">The sender's computer must be on, with Deadbolt running.</p>}
  </section>
}

function Failed({ failure, onRetry }: { failure: Failure; onRetry: () => void }) {
  const known = messages[failure.kind]
  return <section className="state" data-state="failed" data-kind={failure.kind}>
    <h2>{known?.title ?? "Something went wrong"}</h2>
    <p className="dim">{known?.body ?? failure.message}</p>
    {(known?.retry ?? !known) && <button type="button" className="cta" onClick={onRetry}>Try again</button>}
  </section>
}

function Received({ bundle }: { bundle: Bundle }) {
  const env = dotenv(bundle.entries)
  return <section className="state" data-state="done">
    <h2>{bundle.title || "Received"}</h2>
    {bundle.note && <p className="note">{bundle.note}</p>}
    <p className="dim">{count(bundle.entries)} item{count(bundle.entries) === 1 ? "" : "s"}, decrypted in this browser. Nothing was stored; save what you need before closing this page.</p>
    {env && <CopyButton label="copy as .env" value={env} />}
    <Tree entries={bundle.entries} />
  </section>
}

function Tree({ entries }: { entries: Node[] }) {
  return <ul className="tree">
    {entries.map((node, i) => <li key={i}>{node.kind === "group" ? <GroupView group={node.entries} name={node.name} /> : <EntryView entry={node} />}</li>)}
  </ul>
}

function GroupView({ group, name }: { group: Node[]; name: string | null | undefined }) {
  const env = dotenv(group)
  return <div className="group">
    <div className="row">
      <span className="name">{name || "group"}/</span>
      {env && <CopyButton label="copy as .env" value={env} />}
    </div>
    <Tree entries={group} />
  </div>
}

function EntryView({ entry }: { entry: Entry }) {
  const [revealed, setRevealed] = useState(false)
  const value = text(entry)
  const inline = isValue(entry) || (value !== undefined && !entry.sensitive && entry.data.length <= 64 * 1024)
  return <div className="entry" data-sensitive={entry.sensitive || undefined}>
    <div className="row">
      <span className="name">{entry.name}</span>
      {!isValue(entry) && <span className="dim">{size(entry.data.length)}</span>}
      <span className="actions">
        {entry.sensitive && value !== undefined && <button type="button" onClick={() => setRevealed(!revealed)}>{revealed ? "hide" : "reveal"}</button>}
        {value !== undefined && <CopyButton label="copy" value={value} />}
        {!isValue(entry) && <DownloadButton entry={entry} />}
      </span>
    </div>
    {value !== undefined && inline && (
      entry.sensitive && !revealed
        ? <div className="value masked" aria-label="hidden value">••••••••••••</div>
        : <pre className="value">{value}</pre>
    )}
  </div>
}

function CopyButton({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const timer = setTimeout(() => setCopied(false), 1500)
    return () => clearTimeout(timer)
  }, [copied])
  return <button type="button" onClick={() => navigator.clipboard.writeText(value).then(() => setCopied(true))}>{copied ? "copied" : label}</button>
}

function DownloadButton({ entry }: { entry: Entry }) {
  const download = () => {
    const blob = new Blob([entry.data as BlobPart], { type: entry.mime || "application/octet-stream" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = entry.name.replace(/[/\\]/g, "_") || "download"
    a.click()
    setTimeout(() => URL.revokeObjectURL(url), 10_000)
  }
  return <button type="button" onClick={download}>download</button>
}

const root = document.getElementById("root")
if (root) createRoot(root).render(<StrictMode><Receive /></StrictMode>)
