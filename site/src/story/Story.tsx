import { useEffect, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent, type PointerEvent, type ReactNode } from "react"
import { useCues, type Flight, type SceneCue } from "../sound"
import { createRenderer, emptyLight, pack, packedLength, type Light, type Renderer } from "./light"
import { clamp01, ease, smoothstep, span, springAt, springs, type Point } from "./motion"
import { onFrame } from "./ticker"
import "./story.css"

// A story: one diagram that tells itself. Each step plays one action and puts one short caption beside the thing
// it's about, joined by a leader line. Under the stage there's a thin step bar with no text: one tick per step.
// Hovering the bar holds the story, clicking a tick plays that step, dragging scrubs the clock 1:1. Every frame
// is a pure function of the clock, so scrubbing and replaying are exact.
//
// The SVG carries everything crisp (frames, text, wires, 3D device solids). Light is a WebGPU canvas over it.

export type Caption = {
  text: string
  /** The point on the element the caption is about. */
  anchor: Point
  /** Where the leader line ends and the text begins. */
  place: Point
  /** Which way the text runs from `place`. */
  align?: "start" | "end" | "above" | "below"
  /** Seconds after the step starts. Step 0 defaults to 0 (resting on first paint). */
  delay?: number
}

export type Step = {
  at: number
  caption: Caption
  /** How lit each element is during this step (0..1); elements not listed rest dim. */
  focus?: Readonly<Record<string, number>>
}

export type StoryScene = {
  label: string
  width: number
  height: number
  /** When the last step ends. The story then fades out and starts again. */
  duration: number
  steps: readonly Step[]
  /** The step whose settled pose is shown under reduced motion. Defaults to the last. */
  poster?: number
  /** Discrete sound cues along the scene clock. */
  sounds?: readonly SceneCue[]
  /** Continuous send-voice flights along the scene clock. */
  flights?: readonly Flight[]
  /** Draws the scene at time `t` as SVG and pushes its lights into `light`. Must be pure. */
  draw(t: number, light: Light, story: StoryApi): ReactNode
}

/** What a scene can ask the story while drawing. */
export type StoryApi = {
  /** How lit an element is at time t, settling on a calm zero-bounce spring between steps' focus maps. */
  focus(t: number, id: string, rest?: number): number
  /** Index of the step playing at time t. */
  step(t: number): number
  /** True when prefers-reduced-motion is active. */
  reduced: boolean
}

const FADE = .8
const reducedQuery = () => matchMedia("(prefers-reduced-motion: reduce)")

export function storyApi(scene: StoryScene, reduced = false): StoryApi {
  const step = (t: number) => {
    let index = 0
    scene.steps.forEach((s, i) => { if (t >= s.at) index = i })
    return index
  }
  return {
    step,
    reduced,
    focus(t, id, rest = .32) {
      const k = step(t)
      const level = (i: number) => i < 0 ? (scene.steps[0]?.focus?.[id] ?? rest) : scene.steps[i]!.focus?.[id] ?? rest
      if (reduced || k === 0) return level(k)
      return level(k - 1) + (level(k) - level(k - 1)) * springAt(t - scene.steps[k]!.at, springs.calm)
    },
  }
}

const stepEnd = (scene: StoryScene, i: number) => scene.steps[i + 1]?.at ?? scene.duration
/** A step's settled pose: just before the next one starts. */
const settled = (scene: StoryScene, i: number) => stepEnd(scene, i) - .05

type Mode = "auto" | "held" | "step"

export function Story({ scene }: { scene: StoryScene }) {
  const [reduced, setReduced] = useState(() => reducedQuery().matches)
  const poster = scene.poster ?? scene.steps.length - 1
  const [t, setT] = useState(() => reduced ? settled(scene, poster) : 0)
  const clock = useRef({ t, mode: "auto" as Mode, stopAt: 0, hover: false, previous: 0 })
  const [live, setLive] = useState(false)
  const host = useRef<HTMLElement>(null)
  const stage = useRef<HTMLDivElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  const bar = useRef<HTMLDivElement>(null)
  const drag = useRef<{ x: number; moved: boolean } | null>(null)
  const [renderer, setRenderer] = useState<Renderer | null | "pending">("pending")
  const story = useMemo(() => storyApi(scene, reduced), [scene, reduced])
  const stepTimes = useMemo(() => scene.steps.map(s => s.at), [scene])

  useCues(t, scene.sounds ?? [], {
    host,
    duration: scene.duration,
    steps: stepTimes,
    flights: scene.flights,
    scrubbing: () => Boolean(drag.current?.moved),
  })

  const seek = (time: number) => { clock.current.t = time; setT(time) }

  useEffect(() => {
    const media = reducedQuery()
    const change = () => {
      setReduced(media.matches)
      clock.current.mode = "auto"
      seek(media.matches ? settled(scene, poster) : 0)
    }
    media.addEventListener("change", change)
    let visible = false
    const update = () => setLive(visible && !document.hidden)
    const observer = new IntersectionObserver(([entry]) => { visible = entry!.isIntersecting; update() }, { threshold: .3 })
    if (host.current) observer.observe(host.current)
    document.addEventListener("visibilitychange", update)
    return () => { media.removeEventListener("change", change); observer.disconnect(); document.removeEventListener("visibilitychange", update) }
  }, [scene, poster])

  // The shared frame loop, only while the story is on screen in a visible tab.
  useEffect(() => {
    if (!live || reduced) return
    const c = clock.current
    c.previous = performance.now()
    return onFrame(now => {
      const dt = Math.min(.1, (now - c.previous) / 1000)
      c.previous = now
      if (c.mode === "held" || (c.mode === "auto" && c.hover)) return
      let next = c.t + dt
      if (c.mode === "step" && next >= c.stopAt) { next = c.stopAt; c.mode = "held" }
      if (next > scene.duration + FADE) next = 0
      seek(next)
    })
  }, [live, reduced, scene])

  useEffect(() => {
    const element = canvas.current
    if (!element) return
    let alive = true, made: Renderer | null = null
    createRenderer(element).then(r => {
      made = r
      if (alive) setRenderer(r)
      else r?.dispose()
    })
    return () => { alive = false; made?.dispose() }
  }, [])

  const light = emptyLight()
  const fade = 1 - smoothstep(span(t, scene.duration, scene.duration + FADE))
  const drawn = scene.draw(Math.min(t, scene.duration), light, story)
  const frame = useRef({ light, fade })
  frame.current = { light, fade }
  const data = useRef(new Float32Array(packedLength))

  const cleared = useRef(false)
  const paint = () => {
    const element = canvas.current, r = renderer
    if (!element || !r || r === "pending") return
    const scale = Math.min(window.devicePixelRatio || 1, 2)
    const width = Math.max(1, Math.round(element.clientWidth * scale)), height = Math.max(1, Math.round(element.clientHeight * scale))
    const resized = element.width !== width || element.height !== height
    if (resized) { element.width = width; element.height = height }
    const packed = pack(frame.current.light, data.current, { width, height, scale: width / scene.width }, frame.current.fade)
    // Quiet at rest: once the canvas is clear, leave it until something lights up again.
    if (!packed && cleared.current && !resized) return
    cleared.current = !packed
    r.draw(packed)
  }
  const painter = useRef(paint)
  painter.current = paint
  useLayoutEffect(paint)
  useEffect(() => {
    if (!stage.current) return
    const observer = new ResizeObserver(() => painter.current())
    observer.observe(stage.current)
    return () => observer.disconnect()
  }, [])

  const current = story.step(Math.min(t, scene.duration))

  const playStep = (i: number) => {
    const index = Math.max(0, Math.min(scene.steps.length - 1, i))
    if (reduced) { seek(settled(scene, index)); return }
    clock.current.mode = "step"
    clock.current.stopAt = settled(scene, index)
    seek(scene.steps[index]!.at)
  }

  const timeAt = (x: number) => {
    const ticks = [...(bar.current?.children ?? [])]
    for (let i = 0; i < ticks.length; i++) {
      const rect = ticks[i]!.getBoundingClientRect(), last = i === ticks.length - 1
      if (x < rect.right + 2 || last) return { index: i, time: scene.steps[i]!.at + clamp01((x - rect.left) / rect.width) * (stepEnd(scene, i) - scene.steps[i]!.at) }
    }
    return { index: 0, time: 0 }
  }

  // Hover pauses only on the step bar; dragging scrubs 1:1 without spring lag ("don't animate my own hand").
  const bindings = {
    onPointerEnter: () => { clock.current.hover = true },
    onPointerLeave: () => { clock.current.hover = false; if (!drag.current) clock.current.mode = "auto" },
    onPointerDown: (event: PointerEvent<HTMLDivElement>) => {
      event.currentTarget.setPointerCapture(event.pointerId)
      drag.current = { x: event.clientX, moved: false }
      clock.current.mode = "held"
    },
    onPointerMove: (event: PointerEvent<HTMLDivElement>) => {
      const d = drag.current
      if (!d) return
      if (Math.abs(event.clientX - d.x) > 3) d.moved = true
      if (d.moved) seek(reduced ? settled(scene, timeAt(event.clientX).index) : timeAt(event.clientX).time)
    },
    onPointerUp: (event: PointerEvent<HTMLDivElement>) => {
      const d = drag.current
      drag.current = null
      if (d && !d.moved) playStep(timeAt(event.clientX).index)
    },
    onKeyDown: (event: KeyboardEvent<HTMLDivElement>) => {
      const keys: Record<string, () => void> = {
        ArrowRight: () => playStep(current + 1), ArrowDown: () => playStep(current + 1),
        ArrowLeft: () => playStep(current - 1), ArrowUp: () => playStep(current - 1),
        Home: () => playStep(0), End: () => playStep(scene.steps.length - 1),
        " ": () => { clock.current.mode = clock.current.mode === "auto" ? "held" : "auto" },
      }
      const action = keys[event.key]
      if (!action) return
      event.preventDefault()
      action()
    },
  }

  const backend = renderer === "pending" ? undefined : renderer?.backend ?? "svg"

  return <figure className="story" ref={host} data-reduced={reduced || undefined} data-light={backend}>
    <div className="story-scroll">
      <div className="story-stage" ref={stage} style={{ aspectRatio: `${scene.width} / ${scene.height}` }}>
        <svg viewBox={`0 0 ${scene.width} ${scene.height}`} role="img" aria-label={scene.label}>
          <g opacity={fade}>
            {drawn}
            {scene.steps.map((_, i) => <Leader key={i} scene={scene} index={i} t={t} reduced={reduced} current={current} />)}
            {backend === "svg" && <FallbackLight light={light} />}
          </g>
        </svg>
        <canvas ref={canvas} className="story-light" aria-hidden="true" />
        {scene.steps.map((_, i) => <CaptionText key={i} scene={scene} index={i} t={t} reduced={reduced} current={current} />)}
      </div>
    </div>
    <div ref={bar} className="story-bar" role="slider" tabIndex={0} aria-label="step" aria-valuemin={1} aria-valuemax={scene.steps.length}
      aria-valuenow={current + 1} aria-valuetext={scene.steps[current]!.caption.text} {...bindings}>
      {scene.steps.map((step, i) => {
        const length = stepEnd(scene, i) - step.at
        const fill = t >= scene.duration ? 1 : clamp01((t - step.at) / length)
        return <span key={i} className="story-tick" data-state={i < current ? "past" : i === current ? "current" : undefined} style={{ flexGrow: length }}>
          <i style={{ transform: `scaleX(${i < current ? 1 : i === current ? fill : 0})` }} />
        </span>
      })}
    </div>
  </figure>
}

/** How far a caption has entered (0..1) and left (0..1) at time t. Exits run 25% shorter than entrances. */
function captionPhase(scene: StoryScene, index: number, t: number, reduced: boolean, current: number) {
  const step = scene.steps[index]!
  const delay = step.caption.delay ?? (index === 0 ? 0 : .18)
  const at = step.at + delay, end = stepEnd(scene, index)
  if (reduced) return { at, enter: index === current ? 1 : 0, scaleIn: index === current ? 1 : 0, exit: 0 }
  const firstAtRest = index === 0 && delay === 0
  return {
    at,
    enter: firstAtRest ? 1 : span(t, at, at + .28),
    scaleIn: firstAtRest ? 1 : springAt(t - at, springs.default),
    exit: index === scene.steps.length - 1 ? 0 : span(t, end, end + .21),
  }
}

function Leader({ scene, index, t, reduced, current }: { scene: StoryScene; index: number; t: number; reduced: boolean; current: number }) {
  const { anchor, place } = scene.steps[index]!.caption
  const phase = captionPhase(scene, index, t, reduced, current)
  const firstAtRest = index === 0 && (scene.steps[0]!.caption.delay ?? 0) === 0
  const drawn = (reduced || firstAtRest ? phase.enter : ease.draw(span(t, phase.at - .1, phase.at + .22))) * (1 - ease.exit(phase.exit))
  if (!reduced && drawn <= 0) return null
  const x = anchor[0] + (place[0] - anchor[0]) * drawn, y = anchor[1] + (place[1] - anchor[1]) * drawn
  return <g className="story-leader" style={{ opacity: reduced ? phase.enter : Math.min(1, drawn * 4) }}>
    <line x1={anchor[0]} y1={anchor[1]} x2={x} y2={y} />
    <circle cx={anchor[0]} cy={anchor[1]} r={1.8} />
  </g>
}

function CaptionText({ scene, index, t, reduced, current }: { scene: StoryScene; index: number; t: number; reduced: boolean; current: number }) {
  const { text, place, align = "start" } = scene.steps[index]!.caption
  const { enter, scaleIn, exit } = captionPhase(scene, index, t, reduced, current)
  const e = reduced ? enter : ease.enter(enter), x = reduced ? 0 : ease.exit(exit)
  const opacity = e * (1 - x)
  const style: CSSProperties = {
    left: `${(place[0] / scene.width) * 100}%`, top: `${(place[1] / scene.height) * 100}%`, opacity,
    visibility: opacity <= 0 && !reduced ? "hidden" : undefined,
  }
  if (!reduced) {
    style.filter = `blur(${(3.5 * (1 - e) + 3 * x).toFixed(2)}px)`
    style.scale = String((.96 + .04 * scaleIn - .035 * x).toFixed(4))
  }
  return <p className="story-caption" data-align={align} style={style} aria-hidden={index !== current || undefined}>{text}</p>
}

const TONE = { ivory: "#e8e4dc", red: "#ff2a2a", amber: "#ffb347", hot: "#fff1dc" } as const

/** Without WebGPU or WebGL2: the same lights as plain SVG under one soft glow. */
function FallbackLight({ light }: { light: Light }) {
  return <g className="story-fallback" filter="url(#story-glow)">
    <defs><filter id="story-glow" x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur stdDeviation={2.4} result="blur" />
      <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
    </filter></defs>
    {light.floods.map((f, i) => <circle key={`f${i}`} cx={f.from[0]} cy={f.from[1]} r={f.reach * 1.4} fill={TONE[f.tone]} opacity={f.intensity * .25} />)}
    {light.segments.map((s, i) => <line key={`s${i}`} x1={s.a[0]} y1={s.a[1]} x2={s.b[0]} y2={s.b[1]} stroke={TONE[s.tone]} strokeWidth={s.width} strokeOpacity={Math.max(s.heat[0], s.heat[1])} />)}
    {light.rings.map((r, i) => <circle key={`r${i}`} cx={r.at[0]} cy={r.at[1]} r={r.radius} fill="none" stroke={TONE[r.tone]} strokeWidth={r.width} opacity={Math.min(1, r.intensity)} />)}
    {light.dots.map((d, i) => <circle key={`d${i}`} cx={d.at[0]} cy={d.at[1]} r={d.radius} fill={TONE.hot} opacity={Math.min(1, d.intensity)} />)}
  </g>
}
