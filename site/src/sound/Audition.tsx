import { useEffect, useRef, useState } from "react"
import { KnobsPanel } from "knobs/react"
import { audition, flight } from "./audition"
import { cues, describe, type Cue } from "./recipes"
import { SoundToggle } from "./SoundToggle"
import { soundTuning } from "./tuning"
import "./sound.css"

// A page section for hearing and tuning the palette: every cue as a button with what it's for, a
// "play all", the send voice's flight, and (in development) the sound's knobs panel.

export function Audition() {
  const [playing, setPlaying] = useState<Cue | null>(null)
  const stop = useRef<(() => void) | null>(null)
  useEffect(() => () => stop.current?.(), [])
  const run = (list: readonly Cue[]) => {
    stop.current?.()
    stop.current = audition(list, setPlaying)
  }
  return (
    <section className="sound-audition" aria-label="sound palette">
      <div className="sound-audition-head">
        <h2>sound palette</h2>
        <SoundToggle />
        <button type="button" onClick={() => run(cues)}>play all</button>
        <button type="button" onClick={() => { stop.current?.(); stop.current = flight() }}>send voice</button>
      </div>
      <ol>
        {cues.map((cue) => (
          <li key={cue}>
            <button type="button" data-playing={playing === cue || undefined} onClick={() => run([cue])}>
              <b>{cue}</b>
              <span>{describe[cue]}</span>
            </button>
          </li>
        ))}
      </ol>
      <KnobsPanel controls={soundTuning} />
    </section>
  )
}
