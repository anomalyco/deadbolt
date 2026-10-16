// @ts-nocheck: a Bun script; the site's tsconfig has no Node or Bun types.
//
// A deterministic motion sweep of every architecture story. Each scene is a pure function of its clock, so this steps
// the clock at a fixed dt over the whole story, its dim-out and the loop seam, renders each step's React tree without
// a browser (motion-lint's React SVG walker), records every light entry as a channel, and runs motion-lint's rules.
// No timing noise: the same commit gives the same report, so it can gate CI with --check.
//
//   bun run motion-sweep [--scene mesh] [--dt 0.008333] [--top 10] [--out <dir>] [--check] [--json]
//                        [--config <file>] [--commit <label>] [--hold-at-end]
//
// --check exits 1 when any candidate scores global.checkMinScore or more. --commit names a tree that isn't a git
// checkout (an old commit's `git archive`); --hold-at-end draws the dim-out at the last step, as before f715c1c.
//
// Needs motion-lint checked out beside deadbolt (~/code/open-source/motion-lint), or MOTION_LINT_DIR.
// Traces go to <out> (default: a temp dir) as a motion-lint sweep: `motion-lint analyze <out> --config site/src/dev/motion-lint.config.json`.
import { spawnSync } from "node:child_process"
import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import * as React from "react"
import { emptyLight } from "../story/light"
import { smoothstep, span } from "../story/motion"
import { storyApi } from "../story/Story"
import { cardCollector, createLightProbe, storyNameOf } from "./light-channels"

const site = resolve(import.meta.dir, "../..")
const motionLint = process.env.MOTION_LINT_DIR ?? resolve(site, "../../motion-lint")
if (!existsSync(join(motionLint, "src/web/index.ts"))) {
  console.error(`motion-sweep: no motion-lint at ${motionLint} (clone github.com/kitlangton/motion-lint beside deadbolt, or set MOTION_LINT_DIR)`)
  process.exit(2)
}
const { sweepClock, walkReactSvg } = await import(join(motionLint, "src/web/index.ts"))
const { lint, loadConfig } = await import(join(motionLint, "src/lint.ts"))

const args = process.argv.slice(2)
const flag = (name: string) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined }
const has = (name: string) => args.includes(`--${name}`)
const dt = Number(flag("dt") ?? 1 / 120)
const top = Number(flag("top") ?? 10)
const only = flag("scene")
const configPath = flag("config") ?? join(import.meta.dir, "motion-lint.config.json")
const { config } = loadConfig(configPath)

// Story.tsx's loop (not exported): the scene dims out over FADE after its last step while its clock keeps running,
// then comes back up at its first pose over REFADE, from negative clock time. Keep in step with Story.tsx.
// `--hold-at-end` draws the dim-out at the last step's time instead, as Story.tsx did before f715c1c.
const FADE = .8, REFADE = .5
const sceneFade = (t: number, duration: number) => t < 0 ? smoothstep(span(t, -REFADE, 0)) : 1 - smoothstep(span(t, duration, duration + FADE))
const sceneClock = (t: number, duration: number) => has("hold-at-end") ? Math.max(0, Math.min(t, duration)) : Math.max(0, t)
const SEAM = .6

/** Font sizes of story.css's scene type, in scene units. */
const FONT: Record<string, number> = {
  "story-entry": 11, "story-lane": 12, "story-carried": 9.5, "story-card-label": 12.5, "story-card-detail": 10.5, "story-note": 10.5, "story-code": 23,
}
const fontSize = (props: any, inherited: number) => FONT[String(props.className ?? "").split(" ")[0]] ?? (typeof props.fontSize === "number" ? props.fontSize : inherited)

const git = (...a: string[]) => spawnSync("git", a, { cwd: site, encoding: "utf8" }).stdout.trim()
const head = flag("commit") ?? (git("rev-parse", "--short", "HEAD") || "unknown")
const dirty = git("status", "--porcelain", "--", "src/story", "src/architecture").split("\n").filter(Boolean).length
const out = resolve(flag("out") ?? join(tmpdir(), "deadbolt-motion-sweep", head))
rmSync(out, { recursive: true, force: true })

type Scene = { label: string; width: number; height: number; duration: number; steps: { at: number }[]; draw: Function }
const storiesDir = join(site, "src/architecture/stories")
const scenes: [string, Scene][] = []
for (const file of readdirSync(storiesDir).filter(f => f.endsWith("Story.tsx")).sort()) {
  const module = await import(join(storiesDir, file))
  for (const [name, value] of Object.entries(module)) {
    if (value && typeof (value as Scene).draw === "function" && typeof (value as Scene).duration === "number") scenes.push([name.replace(/Scene$/, ""), value as Scene])
  }
}

const report: any[] = []
for (const [name, scene] of scenes) {
  if (only && name !== only) continue
  const story = storyApi(scene, false)
  // Cards that draw their own border light (BorderLight) are measured from their SVG; before it, the shader lit
  // borders from the light's frames, and the probe models that as `catch <card>`.
  let svgBorders = false
  const probe = createLightProbe({ host: name, catch: () => !svgBorders })
  const started = performance.now()
  const writer = sweepClock({
    launch: name, width: scene.width, height: scene.height, dt,
    segments: [[0, scene.duration + FADE], [-REFADE, SEAM]],
    header: { units: "scene", scene: name, commit: head },
    sample: (t: number) => {
      const light = emptyLight()
      const fade = sceneFade(t, scene.duration)
      const { cards, visit, seen } = cardCollector()
      const tree = scene.draw(sceneClock(t, scene.duration), light, story)
      // Walking the tree renders the scene's components (some still push lights as they render).
      const walk = walkReactSvg(tree, {
        host: name, name: storyNameOf, fontSize, react: React, opacity: fade, visit,
        aggregate: (component: string) => component === "BorderLight" ? "glow" : undefined,
      })
      if (seen.borderLight) svgBorders = true
      const lights = probe.sample(light, fade, cards)
      return { elements: [...walk.elements, ...lights.elements], channels: [...walk.channels, ...lights.channels] }
    },
  })
  const text = writer.text()
  mkdirSync(join(out, "runs", name, "trace"), { recursive: true })
  writeFileSync(join(out, "runs", name, "trace", `${name}.jsonl`), text)
  const { candidates, traces } = lint(`deadbolt/${name}`, [text], config)
  const frames = traces.get(name)?.frames.length ?? 0
  report.push({ scene: name, duration: scene.duration, frames, ms: Math.round(performance.now() - started), candidates })
}

if (has("json")) {
  console.log(JSON.stringify({ commit: head, dirty, dt, out, scenes: report }, null, 1))
} else {
  console.log(`motion-sweep: ${report.length} stories at ${Math.round(1 / dt)} steps/s, deadbolt ${head}${dirty ? ` with ${dirty} uncommitted story file${dirty === 1 ? "" : "s"}` : ""}`)
  console.log(`  traces: ${out}  (motion-lint analyze ${out} --config ${configPath})`)
  for (const r of report) {
    const byRule: Record<string, number> = {}
    for (const c of r.candidates) byRule[c.rule] = (byRule[c.rule] ?? 0) + 1
    console.log(`\n${r.scene}  ${+r.duration.toFixed(3)} s + ${FADE} s fade + seam · ${r.frames} frames · ${r.candidates.length} candidates${r.candidates.length ? ` (${Object.entries(byRule).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", ")})` : ""} · ${r.ms} ms`)
    for (const c of r.candidates.slice(0, top)) {
      const at = c.clock !== undefined ? `${c.clock.toFixed(3).padStart(7)} s` : "".padStart(9)
      const times = c.occurrences > 1 ? ` ×${c.occurrences}` : ""
      console.log(`  ${c.score.toFixed(2).padStart(5)}  ${c.rule.padEnd(13)} ${at}  ${(c.label + times).slice(0, 44).padEnd(44)}  ${c.detail}`)
    }
  }
}

if (has("check")) {
  const min = config.global.checkMinScore ?? 0
  const failing = report.flatMap(r => r.candidates.filter((c: any) => c.score >= min && config.rules[c.rule]?.check !== false))
  console.log(failing.length ? `\nmotion-sweep check: ${failing.length} candidate${failing.length === 1 ? "" : "s"} at score ${min} or more` : "\nmotion-sweep check: passed")
  if (failing.length) process.exit(1)
}
