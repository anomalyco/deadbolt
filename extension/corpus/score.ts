// The detection gate: Deadbolt's own scanPage() and scanForms() on every
// frozen corpus page (freeze.ts), in happy-dom with the layout Chromium
// measured, scored against corpus/gold-labels.jsonl. No network, no browser,
// a few seconds. `bun run check` runs it as `bun run test:corpus`.
//
//   bun corpus/score.ts [--gate] [--update-gate [--allow-regress]] [--verbose] [--json <file>] [--only <id substring>]
//
// Every page is in one split, by its site (registrable domain): "train",
// which corpus/train-weights.ts fits the cluster model on, or "holdout",
// which nothing is fit on. A site in both splits fails the run. The report
// gives every metric for the whole corpus and for the holdout alone.
//
// It checks every page's SHA-256 against corpus/frozen.lock.json first, scores
// the corpus twice and requires the same predictions (by SHA-256) both
// times, then prints per-role precision, recall and F1, how often the page's
// kind is right, and the decoy false-trigger rate: decoy pages (search,
// promo codes, newsletters, invites, admin forms…) on which a login menu
// would open. `--gate` fails when any of them falls past corpus/gate.json,
// the baseline, or a page that scored exactly there now doesn't.
// `--update-gate` rewrites that baseline from this run; it only ratchets
// (floors up, ceilings down, exact pages kept) unless given `--allow-regress`.

import { createHash } from "node:crypto"
import { readFileSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { getDomain } from "tldts"
import { controlKey, load, register } from "./replay"

const here = import.meta.dir
const args = process.argv.slice(2)
const flag = (name: string) => args.includes(name)
const opt = (name: string) => {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : undefined
}
const LOCK = opt("--lock") ?? join(here, "frozen.lock.json")
const LABELS = opt("--labels") ?? join(dirname(LOCK), "gold-labels.jsonl")
const GATE = opt("--gate-file") ?? join(dirname(LOCK), "gate.json")
const MAX_SECONDS = 2

export const ROLE_CLASSES = ["identifier", "password", "new-password", "otp", "card", "address"] as const
export type RoleClass = (typeof ROLE_CLASSES)[number]

export interface LockPage {
  id: string
  /** Relative to the lock's directory. */
  file: string
  url: string
  sha256: string
  bytes: number
  /** "modeled" (written to match a real page's structure), "crawl" or "live". */
  source: string
}
export interface Lock {
  version: 1
  viewport: string
  pages: LockPage[]
}
export type Split = "train" | "holdout"
export interface Gold {
  id: string
  /** What the page is modeled on, or what it tests. */
  pattern: string
  /** Whether the cluster model may learn from the page (train) or only be measured on it (holdout). Every page of a site is in the same one. */
  split: Split
  decoy: boolean
  /** The login detector's kind for the page (scanPage), null for none. */
  kind: string | null
  /** Controls the login detector should claim, by controlKey (replay.ts), with their roles. */
  login: Record<string, string>
  /** Identity and payment controls (scanForms), by controlKey, with their roles. */
  forms: Record<string, string>
}
export interface Prediction {
  id: string
  kind: string | null
  login: Record<string, string>
  forms: Record<string, string>
}

const ADDRESS = new Set(["street-address", "address-line1", "address-line2", "address-line3", "address-level1", "address-level2", "address-level3", "postal-code", "country"])
/** A login role's class: username, email and phone are all the identifier. */
export function loginClass(role: string | undefined): RoleClass | null {
  if (role === "username" || role === "email" || role === "phone") return "identifier"
  if (role === "password" || role === "new-password" || role === "otp") return role
  return null
}
/** A form role's class: any card field, or any address field; names, emails and phones aren't scored here. */
export function formClass(role: string | undefined): RoleClass | null {
  if (!role) return null
  if (role.startsWith("cc-")) return "card"
  return ADDRESS.has(role) ? "address" : null
}
const classOf = (p: { login: Record<string, string>; forms: Record<string, string> }, key: string) => loginClass(p.login[key]) ?? formClass(p.forms[key])

const sha = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex")
const sorted = (o: Record<string, string>) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))

export function readLock(): { lock: Lock; html: Map<string, string>; problems: string[] } {
  const lock = JSON.parse(readFileSync(LOCK, "utf8")) as Lock
  const html = new Map<string, string>()
  const problems: string[] = []
  for (const p of lock.pages) {
    let bytes: Buffer
    try {
      bytes = readFileSync(join(dirname(LOCK), p.file))
    } catch {
      problems.push(`${p.id}: ${p.file} is missing`)
      continue
    }
    const got = sha(bytes)
    if (got !== p.sha256) problems.push(`${p.id}: sha256 ${got.slice(0, 12)}… isn't the lock's ${p.sha256.slice(0, 12)}… (refreeze it, or bun corpus/freeze.ts --relock after a deliberate edit)`)
    html.set(p.id, bytes.toString("utf8"))
  }
  return { lock, html, problems }
}

/** The site a page belongs to, for the split: its registrable domain (www.shop.example.com and shop.example.com are one). */
export const siteOf = (url: string) => getDomain(url) ?? new URL(url).hostname

/** Of the sites, the share whose pages are holdout. */
export const HOLDOUT_SHARE = 0.35
/** A new site's split, by a hash of its name: the same for every page of it, and no one's choice. */
export function splitFor(site: string): Split {
  return parseInt(sha(`deadbolt-corpus-split:${site}`).slice(0, 8), 16) / 2 ** 32 < HOLDOUT_SHARE ? "holdout" : "train"
}

/** Pages without a label, labels without a page, a split that isn't one, and sites in both splits. */
export function corpusProblems(lock: Lock, gold: Gold[]): string[] {
  const problems: string[] = []
  const goldIds = new Set(gold.map((g) => g.id))
  const lockIds = new Set(lock.pages.map((p) => p.id))
  for (const id of lockIds) if (!goldIds.has(id)) problems.push(`${id}: frozen but has no gold label`)
  for (const id of goldIds) if (!lockIds.has(id)) problems.push(`${id}: labelled but not in the lock`)
  const url = new Map(lock.pages.map((p) => [p.id, p.url]))
  const splits = new Map<string, Set<Split>>()
  for (const g of gold) {
    if (g.split !== "train" && g.split !== "holdout") problems.push(`${g.id}: split is ${JSON.stringify(g.split)}, not "train" or "holdout"`)
    const u = url.get(g.id)
    if (!u) continue
    const site = siteOf(u)
    splits.set(site, (splits.get(site) ?? new Set()).add(g.split))
  }
  for (const [site, s] of splits) if (s.size > 1) problems.push(`${site}: has pages in both splits; a holdout site must never be trained on`)
  return problems
}

export function readGold(): Gold[] {
  return readFileSync(LABELS, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Gold)
}

export type Detector = {
  scanPage: typeof import("../src/content/detect").scanPage
  scanForms: typeof import("../src/content/forms").scanForms
  scanGraph: typeof import("../src/content/graph").scanGraph
  openRoots: typeof import("../src/content/shadow").openRoots
}

/** What the extension makes of the page (content.ts, refresh): the login's fields, and the identity and payment fields the login doesn't claim. */
export function predict(d: Detector, id: string): Prediction {
  const graph = d.scanGraph(d.openRoots(document, undefined, true))
  const result = d.scanPage(graph)
  const fields = result.kind && result.kind !== "reset" ? result.fields : []
  const login: Record<string, string> = {}
  for (const f of fields) login[controlKey(f.el)] = f.role
  const forms: Record<string, string> = {}
  for (const f of d.scanForms(graph)) if (!fields.some((l) => l.el === f.el)) forms[controlKey(f.el)] = f.role
  return { id, kind: result.kind, login: sorted(login), forms: sorted(forms) }
}

export function runAll(d: Detector, lock: Lock, html: Map<string, string>, only?: (id: string) => boolean): Prediction[] {
  const out: Prediction[] = []
  for (const p of lock.pages) {
    if (only && !only(p.id)) continue
    load(html.get(p.id) ?? "", p.url)
    out.push(predict(d, p.id))
  }
  return out
}

/** The detector the gate scores, set up in the replay window. */
export async function loadDetector(): Promise<Detector> {
  register()
  return {
    ...(await import("../src/content/detect")),
    ...(await import("../src/content/forms")),
    ...(await import("../src/content/graph")),
    ...(await import("../src/content/shadow")),
  }
}

interface Counts {
  tp: number
  fp: number
  fn: number
}
export interface Scores {
  pages: number
  decoys: number
  roles: Record<RoleClass, { precision: number; recall: number; f1: number; support: number } & Counts>
  micro: { precision: number; recall: number; f1: number } & Counts
  pageKind: number
  decoyFalseTrigger: number
  decoyFormsFalseTrigger: number
  exactPages: string[]
  misses: Array<{ id: string; why: string[] }>
}

const ratio = (a: number, b: number) => (b ? a / b : 1)
const f1 = (p: number, r: number) => (p + r ? (2 * p * r) / (p + r) : 0)

export function score(gold: Gold[], predictions: Prediction[]): Scores {
  const byId = new Map(gold.map((g) => [g.id, g]))
  const counts = Object.fromEntries(ROLE_CLASSES.map((c) => [c, { tp: 0, fp: 0, fn: 0 }])) as Record<RoleClass, Counts>
  let kinds = 0
  let decoys = 0
  let loginTriggers = 0
  let formTriggers = 0
  const exactPages: string[] = []
  const misses: Scores["misses"] = []
  for (const p of predictions) {
    const g = byId.get(p.id)!
    const why: string[] = []
    if (g.kind === p.kind) kinds++
    else why.push(`kind ${g.kind ?? "none"}, got ${p.kind ?? "none"}`)
    const keys = [...new Set([...Object.keys(g.login), ...Object.keys(g.forms), ...Object.keys(p.login), ...Object.keys(p.forms)])].sort()
    for (const key of keys) {
      const want = classOf(g, key)
      const got = classOf(p, key)
      if (want && want === got) counts[want].tp++
      if (got && got !== want) counts[got].fp++
      if (want && want !== got) counts[want].fn++
      if (want !== got) why.push(`${key} ${want ?? "-"}, got ${got ?? "-"}`)
    }
    if (g.decoy) {
      decoys++
      if (Object.keys(p.login).length) loginTriggers++
      if (Object.entries(p.forms).some(([k, r]) => formClass(r) && formClass(r) !== classOf(g, k))) formTriggers++
    }
    if (why.length) misses.push({ id: p.id, why })
    else exactPages.push(p.id)
  }
  const roles = Object.fromEntries(
    ROLE_CLASSES.map((c) => {
      const { tp, fp, fn } = counts[c]
      const precision = ratio(tp, tp + fp)
      const recall = ratio(tp, tp + fn)
      return [c, { tp, fp, fn, precision, recall, f1: f1(precision, recall), support: tp + fn }]
    }),
  ) as Scores["roles"]
  const tot = ROLE_CLASSES.reduce((a, c) => ({ tp: a.tp + counts[c].tp, fp: a.fp + counts[c].fp, fn: a.fn + counts[c].fn }), { tp: 0, fp: 0, fn: 0 })
  const mp = ratio(tot.tp, tot.tp + tot.fp)
  const mr = ratio(tot.tp, tot.tp + tot.fn)
  return {
    pages: predictions.length,
    decoys,
    roles,
    micro: { ...tot, precision: mp, recall: mr, f1: f1(mp, mr) },
    pageKind: ratio(kinds, predictions.length),
    decoyFalseTrigger: decoys ? loginTriggers / decoys : 0,
    decoyFormsFalseTrigger: decoys ? formTriggers / decoys : 0,
    exactPages,
    misses,
  }
}

// ---- The gate ------------------------------------------------------------------

interface GateFile {
  comment: string
  /** Where the detector is headed; the floors below ratchet up toward it. */
  target: { precision: number; recall: number; decoyFalseTrigger: number }
  /** How far under the measured baseline a floor sits (and a ceiling over it). */
  margin: number
  floors: { micro: { precision: number; recall: number }; roles: Partial<Record<RoleClass, { precision: number; recall: number }>>; pageKind: number }
  ceilings: { decoyFalseTrigger: number; decoyFormsFalseTrigger: number }
  /** The same, for the holdout pages alone: what the cluster model makes of sites it never saw. */
  holdout?: { precision: number; recall: number; pageKind: number; decoyFalseTrigger: number }
  /** Pages whose kind and every role were right at the baseline: each must stay so. */
  exactPages: string[]
}

const round = (n: number) => Math.round(n * 10000) / 10000
const down = (n: number, m: number) => round(Math.max(0, n - m))
const up = (n: number, m: number) => round(Math.min(1, n + m))

function gateFrom(s: Scores, h: Scores, margin: number, old?: GateFile, allowRegress = false): GateFile {
  const pick = (now: number, before: number | undefined, higher: boolean) => (before === undefined || allowRegress ? now : higher ? Math.max(now, before) : Math.min(now, before))
  const roles: GateFile["floors"]["roles"] = {}
  for (const c of ROLE_CLASSES) {
    if (!s.roles[c].support) continue
    roles[c] = {
      precision: pick(down(s.roles[c].precision, margin), old?.floors.roles[c]?.precision, true),
      recall: pick(down(s.roles[c].recall, margin), old?.floors.roles[c]?.recall, true),
    }
  }
  return {
    comment: "Written by bun corpus/score.ts --update-gate: the detector's measured baseline less a margin. Raise it as detection improves; never lower it to pass.",
    target: old?.target ?? { precision: 0.98, recall: 0.95, decoyFalseTrigger: 0.02 },
    margin,
    floors: {
      micro: { precision: pick(down(s.micro.precision, margin), old?.floors.micro.precision, true), recall: pick(down(s.micro.recall, margin), old?.floors.micro.recall, true) },
      roles,
      pageKind: pick(down(s.pageKind, margin), old?.floors.pageKind, true),
    },
    ceilings: {
      decoyFalseTrigger: pick(up(s.decoyFalseTrigger, margin), old?.ceilings.decoyFalseTrigger, false),
      decoyFormsFalseTrigger: pick(up(s.decoyFormsFalseTrigger, margin), old?.ceilings.decoyFormsFalseTrigger, false),
    },
    holdout: {
      precision: pick(down(h.micro.precision, margin), old?.holdout?.precision, true),
      recall: pick(down(h.micro.recall, margin), old?.holdout?.recall, true),
      pageKind: pick(down(h.pageKind, margin), old?.holdout?.pageKind, true),
      decoyFalseTrigger: pick(up(h.decoyFalseTrigger, margin), old?.holdout?.decoyFalseTrigger, false),
    },
    exactPages: allowRegress || !old ? s.exactPages : [...new Set([...old.exactPages, ...s.exactPages])].sort(),
  }
}

function checkGate(s: Scores, h: Scores, gate: GateFile): string[] {
  const fails: string[] = []
  const below = (what: string, got: number, floor: number) => {
    if (got + 1e-9 < floor) fails.push(`${what} ${pct(got)} is under its floor ${pct(floor)}`)
  }
  below("precision (all roles)", s.micro.precision, gate.floors.micro.precision)
  below("recall (all roles)", s.micro.recall, gate.floors.micro.recall)
  for (const [c, f] of Object.entries(gate.floors.roles) as Array<[RoleClass, { precision: number; recall: number }]>) {
    below(`${c} precision`, s.roles[c].precision, f.precision)
    below(`${c} recall`, s.roles[c].recall, f.recall)
  }
  below("page kind", s.pageKind, gate.floors.pageKind)
  if (s.decoyFalseTrigger > gate.ceilings.decoyFalseTrigger + 1e-9) fails.push(`decoy false-trigger rate ${pct(s.decoyFalseTrigger)} is over its ceiling ${pct(gate.ceilings.decoyFalseTrigger)}`)
  if (s.decoyFormsFalseTrigger > gate.ceilings.decoyFormsFalseTrigger + 1e-9) fails.push(`decoy forms false-trigger rate ${pct(s.decoyFormsFalseTrigger)} is over its ceiling ${pct(gate.ceilings.decoyFormsFalseTrigger)}`)
  if (gate.holdout) {
    below("holdout precision", h.micro.precision, gate.holdout.precision)
    below("holdout recall", h.micro.recall, gate.holdout.recall)
    below("holdout page kind", h.pageKind, gate.holdout.pageKind)
    if (h.decoyFalseTrigger > gate.holdout.decoyFalseTrigger + 1e-9) fails.push(`holdout decoy false-trigger rate ${pct(h.decoyFalseTrigger)} is over its ceiling ${pct(gate.holdout.decoyFalseTrigger)}`)
  }
  const exact = new Set(s.exactPages)
  for (const id of gate.exactPages) if (!exact.has(id)) fails.push(`${id} was exact at the baseline and now isn't: ${s.misses.find((m) => m.id === id)?.why.join("; ") ?? "not scored"}`)
  return fails
}

// ---- Report ----------------------------------------------------------------------

export const pct = (n: number) => `${(n * 100).toFixed(1)}%`

/** One line per split: micro precision, recall and F1, page kind, decoy false triggers. */
export function splitTable(rows: Array<[string, Scores]>) {
  console.log("split      pages decoys  precision  recall     f1  page kind  decoy trigger")
  for (const [name, s] of rows)
    console.log(`${name.padEnd(9)} ${String(s.pages).padStart(6)} ${String(s.decoys).padStart(6)}  ${pct(s.micro.precision).padStart(9)}  ${pct(s.micro.recall).padStart(6)}  ${pct(s.micro.f1).padStart(5)}  ${pct(s.pageKind).padStart(9)}  ${pct(s.decoyFalseTrigger).padStart(13)}`)
}

function print(s: Scores, h: Scores, shaHex: string, seconds: number, verbose: boolean, gate?: GateFile) {
  console.log(`corpus: ${s.pages} frozen pages (${s.decoys} decoys, ${h.pages} of them holdout), scored twice in ${seconds.toFixed(2)} s, predictions sha256 ${shaHex.slice(0, 16)}`)
  console.log("")
  splitTable([["all", s], ["holdout", h]])
  console.log("")
  console.log("role            precision  recall     f1   tp  fp  fn")
  const row = (name: string, r: { precision: number; recall: number; f1: number } & Counts) =>
    console.log(`${name.padEnd(14)}  ${pct(r.precision).padStart(9)}  ${pct(r.recall).padStart(6)}  ${pct(r.f1).padStart(5)}  ${String(r.tp).padStart(3)} ${String(r.fp).padStart(3)} ${String(r.fn).padStart(3)}`)
  for (const c of ROLE_CLASSES) row(c === "identifier" ? "username/email" : c, s.roles[c])
  row("all roles", s.micro)
  console.log("")
  console.log(`page kind exact:              ${pct(s.pageKind)}`)
  console.log(`pages exact (kind and roles): ${s.exactPages.length}/${s.pages}`)
  console.log(`decoy false-trigger rate:     ${pct(s.decoyFalseTrigger)} (decoys on which a login menu would open)`)
  console.log(`decoy forms false-trigger:    ${pct(s.decoyFormsFalseTrigger)} (decoys offered a card or address)`)
  const t = gate?.target
  if (t) console.log(`target:                       precision >= ${pct(t.precision)}, recall >= ${pct(t.recall)}, decoy false-trigger <= ${pct(t.decoyFalseTrigger)}`)
  if (!s.misses.length) return
  console.log("")
  console.log(`misses (${s.misses.length} pages):`)
  const held = new Set(h.misses.map((m) => m.id))
  for (const miss of s.misses) console.log(`  ${miss.id}${held.has(miss.id) ? " (holdout)" : ""}: ${verbose || miss.why.length <= 3 ? miss.why.join("; ") : `${miss.why.slice(0, 3).join("; ")} (+${miss.why.length - 3})`}`)
}

async function main() {
  const start = performance.now()
  const { lock, html, problems } = readLock()
  const gold = readGold()
  problems.push(...corpusProblems(lock, gold))
  if (problems.length) {
    for (const p of problems) console.error(`corpus: ${p}`)
    process.exit(1)
  }

  const d = await loadDetector()
  const only = opt("--only")
  const pick = only ? (id: string) => id.includes(only) : undefined
  const first = runAll(d, lock, html, pick)
  const second = runAll(d, lock, html, pick)
  const [a, b] = [sha(JSON.stringify(first)), sha(JSON.stringify(second))]
  const seconds = (performance.now() - start) / 1000
  const scores = score(gold, first)
  const holdoutIds = new Set(gold.filter((g) => g.split === "holdout").map((g) => g.id))
  const holdout = score(gold, first.filter((p) => holdoutIds.has(p.id)))

  let gate: GateFile | undefined
  try {
    gate = JSON.parse(readFileSync(GATE, "utf8")) as GateFile
  } catch {
    gate = undefined
  }
  print(scores, holdout, a, seconds, flag("--verbose"), gate)
  const json = opt("--json")
  if (json) writeFileSync(json, JSON.stringify({ scores, holdout, predictions: first }, null, 2))

  const fails: string[] = []
  if (a !== b) fails.push(`the two runs disagree (sha256 ${a.slice(0, 12)}… then ${b.slice(0, 12)}…): scoring isn't deterministic`)
  if (seconds > MAX_SECONDS) fails.push(`scoring took ${seconds.toFixed(1)} s, over ${MAX_SECONDS} s`)
  if (flag("--update-gate")) {
    if (only) throw new Error("--update-gate scores the whole corpus; drop --only")
    const next = gateFrom(scores, holdout, gate?.margin ?? 0.005, gate, flag("--allow-regress"))
    writeFileSync(GATE, JSON.stringify(next, null, 2) + "\n")
    console.log(`\nwrote ${GATE}`)
  } else if (flag("--gate")) {
    if (!gate) fails.push(`no ${GATE}: run with --update-gate first`)
    else if (!only) fails.push(...checkGate(scores, holdout, gate))
  }
  if (fails.length) {
    console.error("")
    for (const f of fails) console.error(`GATE FAIL: ${f}`)
    process.exit(1)
  }
  if (flag("--gate")) console.log("\ngate: pass")
}

if (import.meta.main) await main()
