import { StrictMode, useEffect, useState } from "react"
import { createRoot } from "react-dom/client"
import { Ink } from "../print/Ink"
import { Masthead, type Mark } from "../print/Masthead"
import { marks } from "../print/marks"
import "../styles.css"
import "./marks.css"

// The masthead once per candidate mark, numbered (dev only: not in the build's inputs). `?v=<n>` shows one alone,
// centred on black, for captures; `&hold=<ms>` leaves the square empty that long before the mark mounts, so a
// recording catches its whole load-in.

const params = new URLSearchParams(location.search)
const only = params.get("v")
const hold = Number(params.get("hold") ?? 0)
const pad = (n: number) => String(n).padStart(2, "0")
const Empty: Mark = () => null

function Held({ mark, label }: { mark: Mark; label: string }) {
  const [ready, setReady] = useState(hold <= 0)
  useEffect(() => {
    // Captures read when the mark mounted to know where its load-in starts.
    if (ready) { document.documentElement.dataset.mounted = String(performance.now()); return }
    const timer = setTimeout(() => setReady(true), hold)
    return () => clearTimeout(timer)
  }, [ready])
  return <Masthead mark={ready ? mark : Empty} markLabel={label} />
}

function Gallery() {
  if (only !== null) {
    const entry = marks[Number(only)]
    if (!entry) return <p className="marks-missing">no mark {only}</p>
    return <div className="marks-single"><div className="marks-capture" id="capture"><Held mark={entry.Mark} label={entry.label} /></div></div>
  }
  return <main className="marks">
    {marks.map((entry, n) => <section key={entry.name} className="marks-entry">
      <a className="marks-title" href={`?v=${n}`}><b>{pad(n)}</b> {entry.name}<span>{entry.idea}</span></a>
      <Masthead mark={entry.Mark} markLabel={entry.label} />
    </section>)}
  </main>
}

createRoot(document.getElementById("root")!).render(<StrictMode><Ink /><Gallery /></StrictMode>)
