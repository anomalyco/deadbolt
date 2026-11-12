import type { ComponentType, CSSProperties } from "react"
import { LockSimple, Skull } from "@phosphor-icons/react"
import { colorHex } from "knobs"
import { Knobs, useControls } from "knobs/react"
import { SoundToggle } from "../sound"
import { KeyholePrint } from "./KeyholePrint"
import { Splatter } from "./Ink"
import { header } from "./tuning"

// The lockup: a square print the mark's height, the wordmark in Anton stretched to a 4.6:1 box, a splatter
// knocking ink out of it, and under the square a two-line caption with dotted leaders. In development a chip on it
// opens the header's knobs (tuning.ts). The square's mark is a prop: the keyhole print by default, or any of the
// candidates in marks/ (shown side by side at /marks/).

const WIDTH = 1000, ASPECT = 4.6, CAP = .867
const height = WIDTH / ASPECT

export function Wordmark({ className }: { className: string }) {
  return <svg className={className} viewBox={`0 0 ${WIDTH} ${height}`} preserveAspectRatio="none" aria-hidden="true" focusable="false">
    <text x={0} y={height} textLength={WIDTH} lengthAdjust="spacingAndGlyphs" fontSize={height / CAP} fill="currentColor">DEADBOLT</text>
  </svg>
}

/** What fills the square: absolutely positioned over it, given the class that does that. */
export type Mark = ComponentType<{ className?: string }>

export function Masthead({ subtitle, mark: Print = KeyholePrint, markLabel = "A keyhole" }: { subtitle?: string; mark?: Mark; markLabel?: string }) {
  const { ink } = useControls(header)
  return <Knobs controls={header}><header className="masthead" style={{ "--red": colorHex(ink) } as CSSProperties}>
    <div className="masthead-print" role="img" aria-label={markLabel}><Print className="masthead-canvas" /></div>
    <Wordmark className="wordmark" />
    <Splatter />
    <h1 aria-label={subtitle ?? "deadbolt: secrets kept for ever"}>
      <b><span>secrets</span><i className="fill" /><span>kept</span><LockSimple size={11} className="tail" /></b>
      <b><span>for</span><i className="fill" /><span>ever</span><Skull size={11} className="tail" /></b>
    </h1>
    <SoundToggle className="masthead-sound" />
  </header></Knobs>
}
