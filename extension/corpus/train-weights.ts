// Fits the cluster model the login detector consults (rationalize.ts,
// loginOdds) and writes it to src/content/weights.gen.ts: a sparse logistic
// regression over each login-like cluster's value-free features
// (clusterFeatures: the roles the rules gave its fields, their shape and
// autocomplete tokens, the form kinds its words and buttons name, wording
// groups, the page's path and title), trained on the frozen corpus's
// "train" pages only. Holdout pages are scored, never learned from.
//
//   bun corpus/train-weights.ts            fit, print train and holdout scores, write weights.gen.ts
//   bun corpus/train-weights.ts --check    fit and fail unless weights.gen.ts is exactly what this writes
//   bun corpus/train-weights.ts --dry-run  fit and print, write nothing
//   --debug                                also print the 30 lowest-odds train clusters and their features
//
// A cluster is a login (1) when it holds a field the gold label gives a
// login role, or it's the code or reset step of a non-decoy page whose label
// claims no field; else 0 (decoys, and the footer newsletter beside a real
// sign-in). The fit is deterministic: full-batch proximal gradient descent
// on L2-regularised log loss with an L1 penalty, a fixed number of steps
// from zero, classes weighted equally, and weights rounded to 0.01. Each
// step projects every weight onto its sign (featureSign): sign-in wording
// never goes negative and other-purpose wording never positive, however
// collinear the features. Weights
// under MIN_WEIGHT are dropped and features seen on fewer than MIN_SUPPORT
// clusters never enter. The threshold sits under every train login's odds,
// halfway to the highest non-login below them, so the model gives up no
// train recall for precision.

import { readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { featureSign, withWeights } from "../src/content/rationalize"
import { controlKey, load } from "./replay"
import { corpusProblems, loadDetector, pct, readGold, readLock, runAll, score, splitTable, type Gold } from "./score"
import type { Weights } from "../src/content/weights.gen"

const OUT = join(import.meta.dir, "../src/content/weights.gen.ts")
const args = process.argv.slice(2)
const MIN_SUPPORT = 2
const MIN_WEIGHT = 0.05
const L1 = 0.002
const L2 = 0.01
const STEPS = 4000
const RATE = 0.5
/** How far under the lowest train login the threshold may sit when nothing non-login is near it. */
const MARGIN = 1

interface Example {
  page: string
  features: string[]
  y: 0 | 1
}

const round = (n: number) => Math.round(n * 100) / 100 || 0

async function examples(gold: Gold[], lock: ReturnType<typeof readLock>, d: Awaited<ReturnType<typeof loadDetector>>): Promise<Example[]> {
  const { clusterVerdicts } = await import("../src/content/detect")
  const out: Example[] = []
  const byId = new Map(gold.map((g) => [g.id, g]))
  for (const p of lock.lock.pages) {
    const g = byId.get(p.id)!
    if (g.split !== "train") continue
    load(lock.html.get(p.id) ?? "", p.url)
    const graph = d.scanGraph(d.openRoots(document, undefined, true))
    // A code the user brings, or a reset: a step of a sign-in with nothing in it to fill.
    const step = !g.decoy && g.kind !== null && !Object.keys(g.login).length
    for (const v of clusterVerdicts(graph)) {
      const login = !g.decoy && (step || v.cluster.controls.some((el) => controlKey(el) in g.login))
      out.push({ page: p.id, features: v.features, y: login ? 1 : 0 })
    }
  }
  return out
}

function odds(features: string[], w: Weights) {
  let z = w.bias
  for (const f of features) z += w.features[f]?.[0] ?? 0
  return z
}

/** Proximal gradient descent on class-weighted log loss + L2, soft-thresholded for L1. */
function fit(data: Example[]): Weights {
  const support = new Map<string, number>()
  for (const e of data) for (const f of e.features) support.set(f, (support.get(f) ?? 0) + 1)
  const vocab = [...support].filter(([, n]) => n >= MIN_SUPPORT).map(([f]) => f).sort()
  const index = new Map(vocab.map((f, i) => [f, i]))
  const rows = data.map((e) => e.features.map((f) => index.get(f)).filter((i): i is number => i !== undefined))
  const pos = data.filter((e) => e.y).length
  const scale = [data.length / (2 * (data.length - pos)), data.length / (2 * pos)]
  const signs = vocab.map(featureSign)
  const w = new Float64Array(vocab.length)
  let b = 0
  for (let step = 0; step < STEPS; step++) {
    const grad = new Float64Array(vocab.length)
    let gb = 0
    for (const [n, row] of rows.entries()) {
      let z = b
      for (const i of row) z += w[i]
      const err = (1 / (1 + Math.exp(-z)) - data[n].y) * scale[data[n].y]
      gb += err
      for (const i of row) grad[i] += err
    }
    b -= (RATE * gb) / data.length
    for (let i = 0; i < w.length; i++) {
      const next = w[i] - RATE * (grad[i] / data.length + L2 * w[i])
      const shrunk = Math.sign(next) * Math.max(0, Math.abs(next) - RATE * L1)
      w[i] = signs[i] > 0 ? Math.max(0, shrunk) : signs[i] < 0 ? Math.min(0, shrunk) : shrunk
    }
  }
  const features: Record<string, readonly [number, number]> = {}
  for (const [i, f] of vocab.entries()) if (Math.abs(round(w[i])) >= MIN_WEIGHT) features[f] = [round(w[i]), support.get(f)!]
  const weights: Weights = { version: 1, bias: round(b), threshold: 0, features }
  const logins = data.filter((e) => e.y).map((e) => odds(e.features, weights))
  const lowest = Math.min(...logins)
  const below = data.filter((e) => !e.y).map((e) => odds(e.features, weights)).filter((z) => z < lowest)
  const threshold = below.length ? Math.max(lowest - MARGIN, (Math.max(...below) + lowest) / 2) : lowest - MARGIN
  return { ...weights, threshold: round(threshold) }
}

function render(w: Weights, train: Example[]): string {
  const lines = Object.keys(w.features)
    .sort()
    .map((f) => `    ${JSON.stringify(f)}: [${w.features[f][0]}, ${w.features[f][1]}],`)
  const pos = train.filter((e) => e.y).length
  return `// Written by bun corpus/train-weights.ts: do not edit by hand. Retrain after
// changing clusterFeatures (rationalize.ts) or the corpus, and commit the diff.
//
// The cluster model: each feature's log-odds weight and how many train
// clusters showed it. Fit on ${train.length} clusters of the frozen corpus's train
// pages (${pos} logins, ${train.length - pos} not), L1 ${L1}, L2 ${L2}, weights under ${MIN_WEIGHT}
// dropped. A cluster whose summed odds fall under the threshold isn't a
// login form.

export interface Weights {
  version: 1
  bias: number
  threshold: number
  /** Feature id to [weight, train support]. */
  features: Readonly<Record<string, readonly [weight: number, support: number]>>
}

export const WEIGHTS: Weights = {
  version: 1,
  bias: ${w.bias},
  threshold: ${w.threshold},
  features: {
${lines.join("\n")}
  },
}
`
}

async function main() {
  const lock = readLock()
  const gold = readGold()
  const problems = [...lock.problems, ...corpusProblems(lock.lock, gold)]
  if (problems.length) {
    for (const p of problems) console.error(`train-weights: ${p}`)
    process.exit(1)
  }
  const d = await loadDetector()
  const train = await examples(gold, lock, d)
  const weights = fit(train)
  const text = render(weights, train)

  // What the whole detector makes of each split with these weights.
  const predictions = withWeights(weights, () => runAll(d, lock.lock, lock.html))
  const of = (split: string) => {
    const ids = new Set(gold.filter((g) => g.split === split).map((g) => g.id))
    return score(gold, predictions.filter((p) => ids.has(p.id)))
  }
  const [trainScores, holdScores] = [of("train"), of("holdout")]
  if (args.includes("--debug")) for (const e of [...train].sort((a, b) => odds(a.features, weights) - odds(b.features, weights)).slice(0, 30)) console.log(round(odds(e.features, weights)), e.y, e.page, e.features.join(" "))
  const wrong = train.filter((e) => (odds(e.features, weights) >= weights.threshold) !== !!e.y)
  console.log(`train-weights: ${train.length} train clusters (${train.filter((e) => e.y).length} logins), ${Object.keys(weights.features).length} weights, bias ${weights.bias}, threshold ${weights.threshold}, ${Buffer.byteLength(text)} bytes`)
  console.log("")
  splitTable([["train", trainScores], ["holdout", holdScores]])
  console.log("")
  const heaviest = Object.entries(weights.features).sort((a, b) => Math.abs(b[1][0]) - Math.abs(a[1][0])).slice(0, 12)
  console.log(`heaviest: ${heaviest.map(([f, [v]]) => `${f} ${v > 0 ? "+" : ""}${v}`).join(", ")}`)
  console.log(`train clusters on the wrong side: ${wrong.length ? wrong.map((e) => `${e.page} (${e.y ? "login" : "not"}, odds ${round(odds(e.features, weights))})`).join(", ") : "none"}`)
  const misses = [...trainScores.misses.map((m) => ({ ...m, split: "train" })), ...holdScores.misses.map((m) => ({ ...m, split: "holdout" }))]
  if (misses.length) console.log(`pages still wrong (${misses.length}):\n${misses.map((m) => `  ${m.id} (${m.split}): ${m.why.join("; ")}`).join("\n")}`)
  console.log(`holdout: precision ${pct(holdScores.micro.precision)}, recall ${pct(holdScores.micro.recall)}, decoy false-trigger ${pct(holdScores.decoyFalseTrigger)}`)

  if (args.includes("--check")) {
    if (readFileSync(OUT, "utf8") !== text) {
      console.error(`\ntrain-weights: ${OUT} isn't what training writes: run bun corpus/train-weights.ts and commit it`)
      process.exit(1)
    }
    console.log("\nweights.gen.ts: up to date")
  } else if (!args.includes("--dry-run")) {
    writeFileSync(OUT, text)
    console.log(`\nwrote ${OUT}`)
  }
}

if (import.meta.main) await main()
