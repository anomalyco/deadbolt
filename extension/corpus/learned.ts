// Summarize "Learn this site" logs (docs/autofill.md, "Learning a site"): for
// every field the user typed into while signing in by hand, the role their
// typing shows (ground truth, unlike the crawl's weak labels) against the
// detector's, plus whether the detector found the page and its submit control.
//
//   bun corpus/learned.ts [--dir <learn dir>] [--out report-learned.md]
//
// The default dir is $XDG_STATE_HOME/deadbolt/learn, else ~/.local/state/deadbolt/learn.

import { readdir, readFile, writeFile } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"
import type { LearnInput, LearnStep } from "../src/learn"
import { coarse } from "./labels"

const arg = (name: string) => {
  const i = process.argv.indexOf(name)
  return i > 0 ? process.argv[i + 1] : undefined
}
const dir = arg("--dir") ?? join(process.env.XDG_STATE_HOME || join(homedir(), ".local", "state"), "deadbolt", "learn")
const out = arg("--out")

type Line =
  | { event: "start"; site: string; origin: string; path: string; at: string; savedLogins: number }
  | ({ event: "step"; seq: number; frameId: number; sameSite: boolean } & LearnStep)
  | { event: "end"; reason: string; steps: number; durationMs: number }

interface Session {
  id: string
  site: string
  at: string
  steps: Array<Extract<Line, { event: "step" }>>
  end?: Extract<Line, { event: "end" }>
}

type Verdict = "match" | "coarse" | "wrong" | "missed"

interface Row {
  session: Session
  step: Extract<Line, { event: "step" }>
  input: LearnInput
  verdict: Verdict
}

function verdict(truth: string, role: string | null): Verdict {
  if (!role) return "missed"
  if (truth === role) return "match"
  return coarse(truth) === coarse(role) ? "coarse" : "wrong"
}

// ---- Load -----------------------------------------------------------------------

const sessions: Session[] = []
let files: string[] = []
try {
  files = (await readdir(dir)).filter((f) => f.endsWith(".jsonl")).sort()
} catch {
  console.error(`No learning logs in ${dir}. Use "Learn this site" in the extension's popup first.`)
  process.exit(1)
}
for (const file of files) {
  const s: Session = { id: file.replace(/\.jsonl$/, ""), site: "", at: "", steps: [] }
  for (const raw of (await readFile(join(dir, file), "utf8")).split("\n")) {
    if (!raw) continue
    let line: Line
    try {
      line = JSON.parse(raw)
    } catch {
      continue
    }
    if (line.event === "start") Object.assign(s, { site: line.site, at: line.at })
    else if (line.event === "step") s.steps.push(line)
    else if (line.event === "end") s.end = line
  }
  if (s.site) sessions.push(s)
}

// ---- Rows: each typed field once, as last seen (its submit step, usually) --------

const rows: Row[] = []
for (const session of sessions) {
  const last = new Map<string, Row>()
  for (const step of session.steps) {
    for (const input of step.inputs ?? []) {
      const t = input.typed
      if (!t || t.truth === "other") continue
      const key = `${step.frameId}|${step.frame.path}|${t.order}`
      const prior = last.get(key)
      // A submit step is the one that counts; otherwise the latest.
      if (prior && prior.step.trigger === "submit" && step.trigger !== "submit") continue
      last.set(key, { session, step, input, verdict: verdict(t.truth, input.role) })
    }
  }
  rows.push(...last.values())
}

// ---- Report -----------------------------------------------------------------------

const lines: string[] = []
const pct = (n: number, d: number) => (d ? `${Math.round((100 * n) / d)}%` : "–")
const count = <T>(items: T[], f: (t: T) => boolean) => items.filter(f).length

const outcomes = new Map<string, number>()
for (const s of sessions) outcomes.set(s.end?.reason ?? "unfinished", (outcomes.get(s.end?.reason ?? "unfinished") ?? 0) + 1)
lines.push("# Learned sign-ins", "")
lines.push(
  `${sessions.length} sessions on ${new Set(sessions.map((s) => s.site)).size} sites (${[...outcomes].map(([k, v]) => `${v} ${k}`).join(", ")}), ${rows.length} typed fields, from ${dir}.`,
  "",
)

lines.push("## Fields by what the user typed", "", "| Truth | Fields | Match | Same kind | Wrong | Missed |", "|---|---:|---:|---:|---:|---:|")
for (const truth of ["username", "email", "phone", "password", "otp"]) {
  const r = rows.filter((x) => x.input.typed!.truth === truth)
  if (!r.length) continue
  const n = (v: Verdict) => `${count(r, (x) => x.verdict === v)} (${pct(count(r, (x) => x.verdict === v), r.length)})`
  lines.push(`| ${truth} | ${r.length} | ${n("match")} | ${n("coarse")} | ${n("wrong")} | ${n("missed")} |`)
}
lines.push("")

const inFrame = rows.filter((r) => r.step.frame.depth > 0)
const inShadow = rows.filter((r) => r.input.inShadow)
lines.push("## Where the fields were", "")
lines.push(`- In a frame: ${inFrame.length} fields, ${count(inFrame, (r) => r.verdict === "missed")} missed`)
lines.push(`- In a shadow root: ${inShadow.length} fields, ${count(inShadow, (r) => r.verdict === "missed")} missed`)
lines.push(`- Outside a <form>: ${count(rows, (r) => !r.input.inForm)} fields`)
lines.push("")

lines.push("## Sessions", "", "| Site | Ended | Steps | Typed | Page kind at submits | Submit control found | Problems |", "|---|---|---:|---:|---|---|---|")
for (const s of sessions) {
  const mine = rows.filter((r) => r.session === s)
  const submits = s.steps.filter((st) => st.trigger === "submit" && st.submitted && st.inputs.some((i) => i.typed))
  const kinds = [...new Set(submits.map((st) => st.kind ?? "none"))].join(", ") || "–"
  const found = submits.length ? `${count(submits, (st) => !!st.submitted?.detected)}/${submits.length}` : "–"
  const problems = mine
    .filter((r) => r.verdict === "wrong" || r.verdict === "missed")
    .map((r) => `${r.input.typed!.truth} ${r.verdict === "missed" ? "missed" : `as ${r.input.role}`}${r.step.frame.depth ? " (frame)" : ""}`)
  lines.push(`| ${s.site} | ${s.end?.reason ?? "–"} | ${s.steps.length} | ${mine.length} | ${kinds} | ${found} | ${problems.join("; ") || "none"} |`)
}
lines.push("")

const bad = rows.filter((r) => r.verdict === "wrong" || r.verdict === "missed")
if (bad.length) {
  lines.push("## Fields the detector got wrong", "", "| Site | Frame | Field | Typed | Detector | Page kind |", "|---|---|---|---|---|---|")
  for (const r of bad) {
    const f = r.input
    const field = [`type=${f.type}`, f.id && `#${f.id}`, f.name && `name=${f.name}`, f.autocomplete && `ac="${f.autocomplete}"`, !f.visible && "hidden", f.inShadow && "shadow"].filter(Boolean).join(" ")
    const frame = `${r.step.frame.depth ? `depth ${r.step.frame.depth} ` : ""}${new URL(r.step.frame.origin).host}${r.step.frame.path}`
    lines.push(`| ${r.session.site} | ${frame} | ${field} | ${f.typed!.truth} (${f.typed!.shape}${f.typed!.savedUsername ? ", saved username" : ""}) | ${f.role ?? "–"} | ${r.step.kind ?? "none"} |`)
  }
  lines.push("")
}

const report = lines.join("\n")
if (out) {
  await writeFile(out, report)
  console.log(`Wrote ${out}`)
} else console.log(report)
