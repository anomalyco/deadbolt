import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { entries } from "virtual:changelog"
import { Ink } from "../print/Ink"
import { Masthead } from "../print/Masthead"
import { anchor } from "./feed"
import "../styles.css"
import "./changelog.css"

const github = "https://github.com/anomalyco/deadbolt"

/** "november 25, 2026": the day as written, whatever the reader's time zone. */
const day = (date: string) =>
  new Date(`${date}T00:00:00Z`).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" }).toLowerCase()

function Changelog() {
  return <div className="site">
    <Ink />
    <main>
      <nav className="nav"><a href="/">← deadbolt</a><span>changelog</span></nav>
      <Masthead />
      <p className="description">what's new in deadbolt, newest first. follow it with <a className="link" href="/changelog/atom.xml">atom</a> or <a className="link" href="/changelog/feed.json">json feed</a>, or read every release as <a className="link" href="/changelog.md">markdown</a>.</p>

      {entries.map(entry => <section key={entry.version} id={anchor(entry)} className="release">
        <header className="release-head">
          {entry.icon && <img className="release-icon" src={`/changelog/icons/${entry.icon}`} alt="" width={24} height={24} />}
          <h2><a href={`#${anchor(entry)}`}>{entry.version}</a></h2>
          <time dateTime={entry.date}>{day(entry.date)}</time>
        </header>
        <p className="release-summary">{entry.summary}</p>
        {/* Rendered at build time from the repo's own changelog/ files, with every text run escaped (feed.ts). */}
        <div className="release-body" dangerouslySetInnerHTML={{ __html: entry.html }} />
      </section>)}

      <footer>deadbolt · <a className="link" href="/">home</a> · <a className="link" href="/architecture/">architecture</a> · <a className="link" href={github}>github</a></footer>
    </main>
  </div>
}

createRoot(document.getElementById("root")!).render(<StrictMode><Changelog /></StrictMode>)
