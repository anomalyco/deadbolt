// Compare the autofill engine (crates/autofill) with the extension's detector
// (src/content/detect.ts) on a crawl, and both with the pages' own markup.
//
//   bun corpus/compare.ts [--out <dir>]
//
// Replays <out>/snapshots/*.json with `cargo run -p deadbolt-autofill --bin
// replay`, then compares per page: the primary frame's kind (engine vs the
// recorded scanPage() verdict vs a kind read from the markup) and every
// visible field's role (engine vs detector vs the weak labels of labels.ts).
// Writes compare.md, compare.json and engine.jsonl to the output dir.

import { readFile, writeFile } from "node:fs/promises"
import { basename, join } from "node:path"
import type { CapturedFrame, SiteResult } from "./crawl"
import { agreement, coarse, weakLabel, type Agreement, type WeakLabel } from "./labels"
import { DEFAULT_OUT } from "./sites"

const arg = (name: string) => {
  const i = process.argv.indexOf(name)
  return i > 0 ? process.argv[i + 1] : undefined
}
const out = arg("--out") ?? DEFAULT_OUT
const repo = join(import.meta.dir, "..", "..")

// ---- Engine replay ----------------------------------------------------------------

interface EngineField {
  id: number
  role: string | null
  split: number | null
  group: number | null
  score: number
}
interface EngineFrame {
  frameRef: string
  kind: string | null
  primaryGroup: number | null
  groups: Array<{ form: number | null; kind: string; score: number; fields: number[] }>
  fields: EngineField[]
}
interface EngineLine {
  file: string
  frames?: EngineFrame[]
  error?: string
}

const replay = Bun.spawnSync(["cargo", "run", "-q", "-p", "deadbolt-autofill", "--bin", "replay", "--", join(out, "snapshots")], {
  cwd: repo,
  stdout: "pipe",
  stderr: "inherit",
})
if (replay.exitCode !== 0) throw new Error(`replay failed with exit code ${replay.exitCode}`)
const engineText = replay.stdout.toString()
await writeFile(join(out, "engine.jsonl"), engineText)
const engine = new Map<string, EngineLine>()
for (const line of engineText.split("\n")) if (line) {
  const l = JSON.parse(line) as EngineLine
  engine.set(l.file, l)
}

// ---- Crawl results -----------------------------------------------------------------

const byKey = new Map<string, SiteResult>()
for (const line of (await readFile(join(out, "results.jsonl"), "utf8")).split("\n")) {
  if (!line) continue
  try {
    const r = JSON.parse(line) as SiteResult
    byKey.set(r.target ?? r.domain, r)
  } catch {}
}
const results = [...byKey.values()].sort((a, b) => a.rank - b.rank)
const nameOf = (r: SiteResult) => {
  if (!r.target) return r.domain
  const u = new URL(r.target)
  return (u.hostname + u.pathname).replace(/\/$/, "").slice(0, 60)
}

/** What a page should be, from its own markup alone (null: nothing to sign in to). */
function markupKind(r: SiteResult, frame: CapturedFrame | undefined): string | null | undefined {
  if (r.status === "no-entry") return null
  if (!frame) return undefined
  const vis = frame.inputs.filter((i) => i.visible)
  const pw = vis.filter((i) => i.type === "password")
  if (pw.length) {
    const ac = pw.map((i) => i.autocomplete)
    if (ac.some((a) => a.includes("current-password"))) return "login"
    if (pw.length >= 2 || ac.every((a) => a.includes("new-password"))) return "signup"
    return "login"
  }
  if (vis.some((i) => i.autocomplete.includes("one-time-code"))) return "mfa"
  if (vis.some((i) => coarse(weakLabel(i)?.role) === "identifier")) return "login"
  return undefined
}

// ---- Compare -----------------------------------------------------------------------

/** `primary`: the engine's role only in the group it judged primary, as scanPage() reports only its form. */
type Who = "engine" | "primary" | "detect"
interface FieldCompare {
  page: string
  frame: number
  name: string
  label: WeakLabel | null
  detect: string | null
  engine: string | null
  primary: string | null
  agree: Record<Who, Agreement>
}
interface PageCompare {
  page: string
  status: string
  markup: string | null | undefined
  detect: string | null
  engine: string | null
  shot?: string
}

const pages: PageCompare[] = []
const fields: FieldCompare[] = []
let missing = 0
let errors = 0
for (const r of results) {
  if (!r.page?.snapshot || !r.summary) continue
  const line = engine.get(basename(r.page.snapshot))
  if (!line) {
    missing++
    continue
  }
  if (!line.frames) {
    errors++
    continue
  }
  const p = r.summary.primaryFrame
  const frame = r.page.frames[p]
  const ef = line.frames[p]
  pages.push({
    page: nameOf(r),
    status: r.status,
    markup: markupKind(r, frame),
    detect: frame?.kind ?? null,
    engine: ef?.kind ?? null,
    shot: r.page.screenshot ? join(out, r.page.screenshot) : undefined,
  })
  r.page.frames.forEach((fr, fi) => {
    const ef = line.frames![fi]
    const eFields = new Map((ef?.fields ?? []).map((f) => [f.id, f]))
    for (const input of fr.inputs) {
      if (!input.visible) continue
      const label = weakLabel(input)
      const detect = input.role
      const e = input.fid !== undefined ? eFields.get(input.fid) : undefined
      const engineRole = e?.role ?? null
      const primaryRole = e && e.group !== null && e.group === ef?.primaryGroup ? engineRole : null
      if (!label && !detect && !engineRole) continue
      const dAgree: Agreement = input.outOfScope && !detect && label ? "out-of-scope" : agreement(label, detect)
      fields.push({
        page: nameOf(r),
        frame: fi,
        name: input.name || input.id || input.autocomplete || input.type,
        label,
        detect,
        engine: engineRole,
        primary: primaryRole,
        agree: {
          detect: dAgree,
          engine: agreement(label, engineRole),
          primary: !primaryRole && engineRole && label ? "out-of-scope" : agreement(label, primaryRole),
        },
      })
    }
  })
}

// ---- Numbers -----------------------------------------------------------------------

const pct = (n: number, d: number) => (d ? `${((100 * n) / d).toFixed(1)}%` : "–")
const tally = (xs: string[]) => {
  const m: Record<string, number> = {}
  for (const x of xs) m[x] = (m[x] ?? 0) + 1
  return Object.fromEntries(Object.entries(m).sort((a, b) => b[1] - a[1]))
}
const k = (x: string | null | undefined) => x ?? "null"

const reached = pages.filter((p) => p.status === "ok")
const labelled = reached.filter((p) => p.markup !== undefined)
const noEntry = pages.filter((p) => p.status === "no-entry")
const kindAgree = reached.filter((p) => p.detect === p.engine).length
const right = (who: "engine" | "detect") => labelled.filter((p) => p[who] === p.markup).length
const kindDisagree = reached.filter((p) => p.detect !== p.engine)
const kindWinner = (p: PageCompare) =>
  p.markup === undefined ? "no label" : p.engine === p.markup ? "engine" : p.detect === p.markup ? "detect" : "neither"

const withLabel = fields.filter((f) => f.label)
const isMatch = (a: Agreement) => a === "match"
const fieldMatch = (who: Who) => withLabel.filter((f) => isMatch(f.agree[who])).length
const roleDisagree = fields.filter((f) => f.detect !== f.engine)
const roleWinner = (f: FieldCompare) => {
  if (!f.label) return "no label"
  const e = isMatch(f.agree.engine)
  const d = isMatch(f.agree.detect)
  return e && !d ? "engine" : d && !e ? "detect" : e && d ? "both" : "neither"
}

const summary = {
  pages: pages.length,
  reached: reached.length,
  replayErrors: errors,
  missingFromReplay: missing,
  kind: {
    agree: kindAgree,
    agreeShare: pct(kindAgree, reached.length),
    labelled: labelled.length,
    engineRight: right("engine"),
    detectRight: right("detect"),
    disagreementsWonBy: tally(kindDisagree.map(kindWinner)),
    confusion: tally(reached.map((p) => `${k(p.detect)} → ${k(p.engine)}`)),
    noEntryPages: noEntry.length,
    noEntryWithKind: { engine: noEntry.filter((p) => p.engine).length, detect: noEntry.filter((p) => p.detect).length },
  },
  fields: {
    rows: fields.length,
    labelled: withLabel.length,
    engineMatch: fieldMatch("engine"),
    primaryMatch: fieldMatch("primary"),
    detectMatch: fieldMatch("detect"),
    engine: tally(fields.map((f) => f.agree.engine)),
    primary: tally(fields.map((f) => f.agree.primary)),
    detect: tally(fields.map((f) => f.agree.detect)),
    disagreements: roleDisagree.length,
    disagreementsWonBy: tally(roleDisagree.map(roleWinner)),
  },
}

// ---- Report ------------------------------------------------------------------------

const md: string[] = []
md.push(`# Engine vs detect.ts`, "", `${new Date().toISOString()} · \`${out}\``, "")
md.push("## Page kind (primary frame)", "")
md.push("| Measure | Engine | detect.ts |", "| --- | --- | --- |")
md.push(`| Sign-in pages reached | ${reached.length} | ${reached.length} |`)
md.push(`| Same kind as the other | ${kindAgree} (${pct(kindAgree, reached.length)}) | |`)
md.push(`| Matches the markup kind (${labelled.length} labelled) | ${right("engine")} (${pct(right("engine"), labelled.length)}) | ${right("detect")} (${pct(right("detect"), labelled.length)}) |`)
md.push(`| Pages with no sign-in found that still get a kind (${noEntry.length}) | ${summary.kind.noEntryWithKind.engine} | ${summary.kind.noEntryWithKind.detect} |`)
md.push("", "Markup kind: a password page is login unless its passwords say `new-password` (or there are two or more), a page with `one-time-code` is mfa, an identifier-only sign-in page is login. Weak: it's what the markup says, not ground truth.", "")
md.push("Disagreements won by (who matches the markup kind):", "")
md.push("| Winner | Pages |", "| --- | --- |")
for (const [w, n] of Object.entries(summary.kind.disagreementsWonBy)) md.push(`| ${w} | ${n} |`)
md.push("", "Kind confusion (detect → engine):", "", "| detect → engine | Pages |", "| --- | --- |")
for (const [c, n] of Object.entries(summary.kind.confusion)) md.push(`| ${c} | ${n} |`)

md.push("", "## Field roles (visible fields with a label or a role)", "")
md.push("Engine (all groups) gives a role to fields in every form; engine (primary form) only in the form it judged primary, as `scanPage()` reports only its form.", "")
md.push("| Agreement with weak label | Engine (all groups) | Engine (primary form) | detect.ts |", "| --- | --- | --- | --- |")
const ags = ["match", "coarse", "miss", "wrong", "extra", "out-of-scope"]
for (const a of ags) md.push(`| ${a} | ${summary.fields.engine[a] ?? 0} | ${summary.fields.primary[a] ?? 0} | ${summary.fields.detect[a] ?? 0} |`)
md.push(
  `| **match share of labelled (${withLabel.length})** | **${pct(fieldMatch("engine"), withLabel.length)}** | **${pct(fieldMatch("primary"), withLabel.length)}** | **${pct(fieldMatch("detect"), withLabel.length)}** |`,
)
md.push("", `Role disagreements: ${roleDisagree.length}.`, "", "| Matches the weak label | Fields |", "| --- | --- |")
for (const [w, n] of Object.entries(summary.fields.disagreementsWonBy)) md.push(`| ${w} | ${n} |`)

md.push("", "## Kind disagreements", "", "| Page | Markup | detect | engine | Winner |", "| --- | --- | --- | --- | --- |")
for (const p of kindDisagree) md.push(`| ${p.page} | ${p.markup === undefined ? "?" : k(p.markup)} | ${k(p.detect)} | ${k(p.engine)} | ${kindWinner(p)} |`)
const noEntryKinds = noEntry.filter((p) => p.engine || p.detect)
if (noEntryKinds.length) {
  md.push("", "## No sign-in page, but a kind", "", "| Page | detect | engine |", "| --- | --- | --- |")
  for (const p of noEntryKinds) md.push(`| ${p.page} | ${k(p.detect)} | ${k(p.engine)} |`)
}
md.push("", "## Role disagreements", "", "| Page | Field | Label | detect | engine | Winner |", "| --- | --- | --- | --- | --- | --- |")
for (const f of roleDisagree)
  md.push(`| ${f.page} | ${f.name.slice(0, 30)} | ${f.label ? `${f.label.role} (${f.label.source})` : "–"} | ${k(f.detect)} | ${k(f.engine)} | ${roleWinner(f)} |`)

await writeFile(join(out, "compare.md"), md.join("\n") + "\n")
await writeFile(join(out, "compare.json"), JSON.stringify({ summary, pages, fields }, null, 1))
console.log(JSON.stringify(summary, null, 2))
console.log(`report: ${join(out, "compare.md")}`)
