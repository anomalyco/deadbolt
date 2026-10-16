import * as React from "react"
import { emptyLight } from "../story/light"
import type { StoryApi, StoryScene } from "../story/Story"
import { cardCollector, createLightProbe, storyNameOf, type ChannelSample, type ElementSample } from "./light-channels"

// The stories' live recorder (development only; motion-lint.ts loads it for `?motion-lint`). motion-lint's DOM
// recorder samples every shape and caption of each story on the page, every frame, by its DOM node; this adds what
// the DOM can't show: the canvas's light (heads, floods, prints: light-channels.ts) and each card's border glow, in
// page pixels, and the clock of the story being drawn on every frame. Needs motion-lint checked out beside deadbolt.
//
//   ?motion-lint            shapes, captions and lights → <launch>.jsonl
//   ?motion-lint=hitches    late frames only, charged to the step playing → <launch>.hitches.jsonl
//   ?motion-lint=both       both (sampling layout every frame costs frames of its own)
//
// Stop with the button in the corner (or `__motionLint.stop()`), move the files into a folder, then:
//   motion-lint analyze <folder> --config site/src/dev/motion-lint.config.json
//   motion-lint hitches <folder>

type Recorder = {
  channels(source: string, values: Iterable<[string, ChannelSample]>): void
  elements(source: string, values: Iterable<[string, ElementSample]>): void
  note(text: string): void
  beginInterval(name: string): { end(): void }
  readonly frames: number
  download(): void
}
type LiveModule = { startLiveRecorder(options: Record<string, unknown>): Recorder }
type WalkModule = { walkReactSvg(root: unknown, options: Record<string, unknown>): { channels: Map<string, ChannelSample> } }

const motionLint = import.meta.glob(["../../../../motion-lint/src/web/live.ts", "../../../../motion-lint/src/web/react-svg.ts"])
const stories = import.meta.glob<Record<string, unknown>>("../architecture/stories/*Story.tsx", { eager: true })

async function load<T>(file: string): Promise<T> {
  const entry = Object.entries(motionLint).find(([path]) => path.endsWith(file))
  if (!entry) throw new Error(`motion-lint: no motion-lint/src/web/${file} beside deadbolt`)
  return await entry[1]() as T
}

/** Shapes that are never drawn themselves. */
const UNDRAWN = /^(defs|clipPath|mask|filter|pattern|marker|linearGradient|radialGradient|symbol)$/
/** A story that hasn't drawn for this long is paused or off screen: its lights hold. */
const IDLE_MS = 250

type Tracked = {
  name: string
  scene: StoryScene
  draw: StoryScene["draw"]
  probe: ReturnType<typeof createLightProbe>
  seen?: { t: number; story: StoryApi; at: number }
  channels: [string, ChannelSample][]
  lights: [string, ElementSample][]
  step?: { index: number; interval: { end(): void } }
}

export async function install(query: string) {
  const [{ startLiveRecorder }, { walkReactSvg }] = await Promise.all([load<LiveModule>("live.ts"), load<WalkModule>("react-svg.ts")])
  const mode = query === "hitches" ? "hitches" : query === "both" ? "both" : "layers"

  // Each scene's draw, wrapped to note the clock and story it last drew with (Story calls `scene.draw` every render).
  const tracked: Tracked[] = []
  for (const module of Object.values(stories)) {
    for (const [key, value] of Object.entries(module)) {
      const scene = value as StoryScene
      if (!scene || typeof scene.draw !== "function" || typeof scene.duration !== "number") continue
      const entry: Tracked = { name: key.replace(/Scene$/, ""), scene, draw: scene.draw, probe: createLightProbe({ host: key.replace(/Scene$/, "") }), channels: [], lights: [] }
      scene.draw = (t, light, story) => {
        if (entry.seen && t < entry.seen.t - 1) recorder?.note(`${entry.name} loops`)
        entry.seen = { t, story, at: performance.now() }
        return entry.draw(t, light, story)
      }
      tracked.push(entry)
    }
  }

  let current: Tracked | undefined
  const figures = () => {
    const out = new Map<string, Element>()
    for (const svg of document.querySelectorAll("figure.story svg[aria-label]")) out.set(svg.getAttribute("aria-label")!, svg)
    return out
  }

  const sample = (recorder: Recorder, now: number) => {
    const svgs = figures()
    current = undefined
    for (const s of tracked) {
      const svg = svgs.get(s.scene.label)
      const r = svg?.getBoundingClientRect()
      const drawing = svg && r && s.seen && now - s.seen.at < IDLE_MS && r.bottom > 0 && r.top < innerHeight
      if (drawing) {
        current ??= s
        const index = s.seen!.story.step(s.seen!.t)
        if (s.step?.index !== index) {
          s.step?.interval.end()
          s.step = { index, interval: recorder.beginInterval(`${s.name} step ${index + 1}`) }
        }
      }
      if (drawing && mode !== "hitches") {
        // The frame again, into a light of our own: draw is pure, and walking its tree renders the components.
        const fade = Number(svg.querySelector(":scope > g")?.getAttribute("opacity") ?? 1)
        const light = emptyLight()
        const { cards, visit } = cardCollector()
        const walk = walkReactSvg(s.draw(s.seen!.t, light, s.seen!.story), {
          host: s.name, name: storyNameOf, react: React, opacity: fade, ink: false, text: false, visit,
          aggregate: (component: string) => component === "BorderLight" ? "glow" : undefined,
        })
        const lights = s.probe.sample(light, fade, cards)
        const k = r.width / s.scene.width, x0 = r.left + scrollX, y0 = r.top + scrollY
        s.lights = lights.elements.map(([key, e]) => [`${s.name} ${key}`, { ...e, x: x0 + e.x * k, y: y0 + e.y * k, w: e.w * k, h: e.h * k }])
        const prefix = `${s.name}: `
        s.channels = [...walk.channels, ...lights.channels].map(([name, c]) =>
          [prefix + name, typeof c === "object" && c.gate ? { ...c, gate: prefix + c.gate } : c])
      }
      // A story that isn't drawing holds its last light rather than going dark.
      recorder.channels(s.name, s.channels)
      recorder.elements(s.name, s.lights)
    }
    if (recorder.frames % 30 === 0) badge.textContent = `motion-lint ● ${mode === "hitches" ? "hitches" : `${recorder.frames} frames`} · stop and save`
  }

  const badge = Object.assign(document.createElement("button"), { type: "button", textContent: "motion-lint ● recording · stop and save" })
  Object.assign(badge.style, {
    position: "fixed", right: "12px", bottom: "12px", zIndex: "2147483647", padding: "6px 10px", cursor: "pointer",
    font: "12px ui-monospace, monospace", color: "#e8e4dc", background: "#111", border: "1px solid #444", borderRadius: "4px",
  })

  const recorder: Recorder = startLiveRecorder({
    launch: `deadbolt${location.pathname.replace(/\W+/g, "-").replace(/-$/, "")}-${new Date().toISOString().slice(0, 19).replace(/\D/g, "")}`,
    mode,
    select: "figure.story svg :is(rect, circle, ellipse, line, path, polyline, polygon, text), figure.story .story-caption",
    skip: (el: Element) => UNDRAWN.test(el.tagName),
    name: (el: Element) => {
      const label = el.closest("figure.story")?.querySelector("svg")?.getAttribute("aria-label")
      const cls = el.getAttribute("class")?.split(/\s+/)[0]
      return `${tracked.find(s => s.scene.label === label)?.name ?? "story"} ${el.tagName.toLowerCase()}${cls ? `.${cls}` : ""}`
    },
    clock: () => current?.seen?.t,
    beforeSample: sample,
  })

  let stopped = false
  const stop = () => {
    if (stopped) return
    stopped = true
    for (const s of tracked) { s.step?.interval.end(); s.scene.draw = s.draw }
    recorder.download()
    badge.textContent = "motion-lint: saved"
    setTimeout(() => badge.remove(), 2000)
  }
  badge.onclick = stop
  document.body.append(badge)
  Object.assign(window, { __motionLint: { recorder, stop } })
}
