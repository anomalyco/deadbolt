import { useEffect, useRef, useState, type ReactNode } from "react"
import { motion, useMotionValue, useMotionValueEvent, useTransform, type MotionValue } from "motion/react"
import { Pause, Play } from "@phosphor-icons/react"
import { SealField } from "../print/SealField"
import type { Clock } from "./kit"

// One diagram with its own clock. It plays while on screen, holds the last pose a moment, then loops. Under
// reduced motion it shows the last pose and nothing moves unless you pick a beat. The beats underneath are the
// narration: the current one is lit, and picking one jumps the diagram there.

export type Beat = { at: number; text: string }
export type Field = { x: number; y: number; w: number; h: number; heat?: MotionValue<number>; ink?: readonly [number, number, number]; density?: number }

const reducedQuery = () => matchMedia("(prefers-reduced-motion: reduce)")

export function useSceneClock(duration: number, hold = 2.5) {
  const host = useRef<HTMLElement>(null)
  const [reduced] = useState(() => reducedQuery().matches)
  const elapsed = useMotionValue(reduced ? duration : 0)
  const clock = useTransform(elapsed, e => Math.min(e, duration))
  const [playing, setPlaying] = useState(!reduced)
  const [visible, setVisible] = useState(false)
  const [hidden, setHidden] = useState(() => document.hidden)
  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => setVisible(entry!.isIntersecting), { threshold: .25 })
    if (host.current) observer.observe(host.current)
    const visibility = () => setHidden(document.hidden)
    document.addEventListener("visibilitychange", visibility)
    return () => { observer.disconnect(); document.removeEventListener("visibilitychange", visibility) }
  }, [])
  useEffect(() => {
    if (!playing || !visible || hidden) return
    let raf = 0, previous = performance.now()
    const tick = (now: number) => {
      let next = elapsed.get() + Math.min(.1, (now - previous) / 1000)
      previous = now
      if (next > duration + hold) next = 0
      elapsed.set(next)
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [playing, visible, hidden, duration, hold, elapsed])
  return { host, clock, elapsed, playing, setPlaying, reduced, seek: (t: number) => elapsed.set(t) }
}

function Progress({ elapsed, duration }: { elapsed: MotionValue<number>; duration: number }) {
  const scaleX = useTransform(elapsed, e => Math.min(1, e / duration))
  return <div className="scene-progress"><motion.div style={{ scaleX }} /></div>
}

export function Scene({ duration, height, width = 760, beats, label, fields, quiet, children }: {
  duration: number; height: number; width?: number; beats: readonly Beat[]; label: string
  /** Just the current beat as a caption: no controls, no list. */
  quiet?: boolean
  fields?: (clock: Clock) => readonly Field[]
  children: (clock: Clock) => ReactNode
}) {
  const { host, clock, elapsed, playing, setPlaying, reduced, seek } = useSceneClock(duration)
  const [current, setCurrent] = useState(() => reduced ? beats.length - 1 : 0)
  useMotionValueEvent(clock, "change", t => {
    let index = 0
    beats.forEach((beat, i) => { if (t >= beat.at) index = i })
    setCurrent(index)
  })
  return <figure className="scene" ref={host}>
    <div className="scene-stage">
      <div className="scene-canvas" style={{ aspectRatio: `${width} / ${height}` }}>
        {fields?.(clock).map((field, i) => <div key={i} className="scene-field" style={boxStyle(field, width, height)}>
          <SealField heat={field.heat} ink={field.ink} density={field.density} />
        </div>)}
        <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>{children(clock)}</svg>
      </div>
    </div>
    {quiet ? <p className="scene-caption" aria-live="polite">{beats[current]?.text}</p> : <>
    <div className="scene-controls">
      <button type="button" onClick={() => setPlaying(!playing)} aria-label={playing ? "pause" : "play"}>
        {playing ? <Pause size={12} weight="fill" /> : <Play size={12} weight="fill" />}
      </button>
      <Progress elapsed={elapsed} duration={duration} />
    </div>
    <ol className="beats">
      {beats.map((beat, i) => <li key={i} data-current={i === current || undefined} data-past={i < current || undefined}>
        <button type="button" onClick={() => { seek(beat.at + .01); setCurrent(i) }}>{beat.text}</button>
      </li>)}
    </ol></>}
  </figure>
}

// The fields sit in an HTML layer over the SVG, placed in percentages of the viewBox so they track it exactly.
function boxStyle(field: Field, width: number, height: number) {
  return {
    left: `${(field.x / width) * 100}%`, top: `${(field.y / height) * 100}%`,
    width: `${(field.w / width) * 100}%`, height: `${(field.h / height) * 100}%`,
  }
}
