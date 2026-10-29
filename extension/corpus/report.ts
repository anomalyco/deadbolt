// Summarize a crawl: report.md, report.json and contact.html in the output dir.
//
//   bun corpus/report.ts [--out <dir>]

import { readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import type { CapturedFrame, SiteResult } from "./crawl"
import { coarse, type FieldRow } from "./labels"
import { DEFAULT_OUT } from "./sites"
import { refine } from "./step2"

const arg = (name: string) => {
  const i = process.argv.indexOf(name)
  return i > 0 ? process.argv[i + 1] : undefined
}
const out = arg("--out") ?? DEFAULT_OUT

const DETECTED = new Set(["login", "signup", "mfa", "change-password"])

// ---- Load -----------------------------------------------------------------------

const byDomain = new Map<string, SiteResult>()
for (const line of (await readFile(join(out, "results.jsonl"), "utf8")).split("\n")) {
  if (!line) continue
  try {
    const r = JSON.parse(line) as SiteResult
    byDomain.set(r.target ?? r.domain, r) // later lines (retries) win
  } catch {}
}
const results = [...byDomain.values()].sort((a, b) => a.rank - b.rank)
// Older step-2 results kept their first new lines as evidence; sort the unexplained ones with today's rules.
for (const r of results) {
  const t = r.step2
  // Step 2 now runs only where step 1 was judged login (runs before that also tried mfa and reset pages).
  if (t?.outcome && r.summary?.kind !== "login") {
    r.step2 = { skipped: `step 1 judged ${r.summary?.kind ?? "nothing"}` }
    continue
  }
  if (t?.outcome !== "other-change" || !r.page) continue
  const refined = refine(t.evidence ?? [], t.finalHost ?? "", new URL(r.page.url).hostname, t.summary)
  if (refined) t.outcome = refined
}
const urlMode = results.some((r) => r.target)
/** How a site or listed page is named in the report: the domain, or host + path for --urls. */
const nameOf = (r: SiteResult) => {
  if (!r.target) return r.domain
  const u = new URL(r.target)
  return (u.hostname + u.pathname).replace(/\/$/, "").slice(0, 60)
}

// ---- Classify each site ---------------------------------------------------------

const pct = (n: number, d: number) => (d ? `${((100 * n) / d).toFixed(1)}%` : "–")
const fieldName = (r: SiteResult, row: FieldRow) => {
  const f = r.page!.frames[row.frame].inputs[row.i]
  return f.name || f.id || f.autocomplete || f.type
}

function netError(e = ""): string {
  const m = e.match(/net::(ERR_[A-Z_]+)/)
  if (m) return m[1]
  if (/Timeout/i.test(e)) return "NAV_TIMEOUT"
  return "OTHER"
}

/** What a password page should be, from its own markup. */
function expectedKind(frames: CapturedFrame[], primary: number): "login" | "signup" {
  const pw = frames[primary].inputs.filter((i) => i.visible && i.type === "password")
  const ac = pw.map((i) => i.autocomplete)
  if (ac.some((a) => a.includes("current-password"))) return "login"
  if (pw.length >= 2 || (ac.length > 0 && ac.every((a) => a.includes("new-password")))) return "signup"
  return "login"
}

interface Classified {
  r: SiteResult
  category: string
  /** Detection-relevant problems on the page, worst first. */
  problems: string[]
  badness: number
}

function classify(r: SiteResult): Classified {
  const c = (category: string, problems: string[] = [], badness = 0): Classified => ({ r, category, problems, badness })
  if (r.status === "skipped") return c(`skipped: ${r.error}`)
  if (r.status === "unreachable") return c(`unreachable: ${netError(r.error)}`)
  if (r.status === "timeout" && !r.page) return c("timeout")
  if (r.status === "error") return c("crawler error")
  if (r.status === "challenge") return c("bot challenge")
  const s = r.summary
  if (!r.page || !s) return c("no page")
  if (r.status === "no-entry") {
    const tried = r.visits.filter((v) => v.via !== "home")
    if (s.ssoButtons > 0 && !s.hasPassword) return c("no sign-in page: SSO buttons seen")
    if (!tried.length) return c("no sign-in page: nothing to follow")
    if (tried.every((v) => v.via === "fallback")) return c("no sign-in page: no link found, /login and /signin failed")
    return c("no sign-in page: link followed, no fields there")
  }

  const problems: string[] = []
  let badness = 0
  const primary = s.fields.filter((f) => f.frame === s.primaryFrame)
  for (const f of primary) {
    if (f.agreement === "miss") {
      problems.push(`field missed: ${f.label!.role} (${f.label!.source}) → none [${fieldName(r, f)}]`)
      badness += coarse(f.label!.role) === "password" ? 4 : 2
    } else if (f.agreement === "wrong") {
      problems.push(`field wrong: ${f.label!.role} (${f.label!.source}) → ${f.role} [${fieldName(r, f)}]`)
      badness += 3
    }
  }

  let category: string
  if (s.hasPassword) {
    const want = expectedKind(r.page.frames, s.primaryFrame)
    if (!s.kind) {
      category = "password page: no kind"
      badness += 6
    } else if (!DETECTED.has(s.kind)) {
      category = `password page: judged ${s.kind}`
      badness += 5
    } else if (want === "login" && s.kind !== "login") {
      category = `login page judged ${s.kind}`
      badness += 3
    } else if (want === "signup" && s.kind === "login") {
      category = "sign-up page judged login"
      badness += 2
    } else category = "password page: detected"
    const pwRoles = primary.filter((f) => coarse(f.label?.role) === "password" && f.label)
    if (pwRoles.length && pwRoles.every((f) => !f.role)) problems.unshift("password field not reported")
    const hasIdentLabel = primary.some((f) => coarse(f.label?.role) === "identifier")
    if (s.kind === "login" && hasIdentLabel && !primary.some((f) => coarse(f.role) === "identifier")) {
      problems.unshift("login without identifier role")
      badness += 2
    }
  } else if (s.identifierFirst) {
    if (s.kind === "login") category = "identifier-first: detected"
    else {
      category = `identifier-first: judged ${s.kind ?? "nothing"}`
      badness += 4
    }
  } else if (s.ssoOnly) category = "sign-in page: SSO buttons only"
  else if (s.crossOriginLoginIframe) category = "sign-in page: login in cross-origin iframe"
  else category = "sign-in page: no login fields"
  if (s.kind && !r.page.frames[s.primaryFrame]?.inputs.some((i) => i.visible && i.role)) problems.push(`kind ${s.kind} with no fields`)
  return { r, category, problems, badness }
}

const classified = results.map(classify)

// ---- Numbers --------------------------------------------------------------------

const count = (pred: (c: Classified) => boolean) => classified.filter(pred).length
const total = results.length
const skipped = count((c) => c.r.status === "skipped")
const crawled = total - skipped
const unreachable = count((c) => c.r.status === "unreachable")
const reachedHome = crawled - unreachable
const challenge = count((c) => c.r.status === "challenge")
const ok = classified.filter((c) => c.r.status === "ok" && c.r.summary)
const pwPages = ok.filter((c) => c.r.summary!.hasPassword)
const pwDetected = pwPages.filter((c) => DETECTED.has(c.r.summary!.kind ?? ""))
const idFirst = ok.filter((c) => c.r.summary!.identifierFirst)
const idFirstDetected = idFirst.filter((c) => c.r.summary!.kind === "login")
const kinds = (list: Classified[]) => tally(list.map((c) => c.r.summary!.kind ?? "null"))

function tally(xs: string[]): Record<string, number> {
  const m: Record<string, number> = {}
  for (const x of xs) m[x] = (m[x] ?? 0) + 1
  return Object.fromEntries(Object.entries(m).sort((a, b) => b[1] - a[1]))
}

// Field agreement, over every visible field on reached pages that has a label or a role.
const rows = ok.flatMap((c) => c.r.summary!.fields.filter((f) => f.label || f.role).map((f) => ({ c, f })))
const agreementTally = tally(rows.map((x) => x.f.agreement))
const confusion: Record<string, Record<string, number>> = {}
for (const { f } of rows) {
  if (f.agreement === "out-of-scope") continue
  const k = f.label ? `${f.label.role} (${f.label.source})` : "(no label)"
  confusion[k] ??= {}
  const role = f.role ?? "none"
  confusion[k][role] = (confusion[k][role] ?? 0) + 1
}
const roleCols = ["username", "email", "phone", "password", "new-password", "otp", "captcha", "none"]

// Failure patterns: site categories that are not successes, plus field-level problems.
const patterns = new Map<string, string[]>()
const note = (key: string, domain: string) => {
  const list = patterns.get(key) ?? []
  if (!list.includes(domain)) list.push(domain)
  patterns.set(key, list)
}
for (const c of classified) {
  if (/detected$|^skipped/.test(c.category)) {
    /* not a failure */
  } else note(c.category, nameOf(c.r))
  for (const p of c.problems) note(p.replace(/ \[.*\]$/, ""), nameOf(c.r))
}
const detectorPattern = (k: string) => !/^(unreachable|timeout|crawler error|bot challenge|no sign-in page|no page)/.test(k)
const sortedPatterns = [...patterns.entries()].sort((a, b) => b[1].length - a[1].length)
const topDetector = sortedPatterns.filter(([k]) => detectorPattern(k)).slice(0, 15)
const topCrawl = sortedPatterns.filter(([k]) => !detectorPattern(k)).slice(0, 10)
const worst = classified.filter((c) => c.badness > 0).sort((a, b) => b.badness - a.badness || a.r.rank - b.r.rank).slice(0, 30)

const ms = ok.flatMap((c) => c.r.page!.frames.map((f) => f.scanMs)).sort((a, b) => a - b)
const q = (p: number) => (ms.length ? ms[Math.min(ms.length - 1, Math.floor(p * ms.length))] : 0)

const summary = {
  out,
  total,
  skipped,
  crawled,
  unreachable,
  reachedHome,
  challenge,
  timeouts: count((c) => c.r.status === "timeout"),
  errors: count((c) => c.r.status === "error"),
  noEntry: count((c) => c.r.status === "no-entry"),
  signInPages: ok.length,
  reachRate: ok.length / Math.max(1, reachedHome),
  passwordPages: pwPages.length,
  passwordDetected: pwDetected.length,
  detectionRate: pwDetected.length / Math.max(1, pwPages.length),
  passwordKinds: kinds(pwPages),
  identifierFirst: idFirst.length,
  identifierFirstDetected: idFirstDetected.length,
  identifierFirstKinds: kinds(idFirst),
  ssoOnly: count((c) => c.category.includes("SSO buttons only")),
  shadowFieldPages: count((c) => (c.r.summary?.shadowFields ?? 0) > 0),
  shadowRootPages: count((c) => (c.r.summary?.shadowRoots ?? 0) > 0),
  passwordInIframe: count((c) => !!c.r.summary?.passwordInIframe),
  crossOriginLoginIframe: tally(classified.map((c) => c.r.summary?.crossOriginLoginIframe).filter((h): h is string => !!h)),
  offSiteSignIn: tally(ok.filter((c) => !c.r.page!.sameSite).map((c) => c.r.page!.host)),
  via: tally(ok.map((c) => c.r.page!.via)),
  scanMs: { p50: q(0.5), p90: q(0.9), p99: q(0.99), max: ms.at(-1) ?? 0 },
  categories: tally(classified.map((c) => c.category)),
  fieldAgreement: agreementTally,
  confusion,
  topDetectorPatterns: topDetector.map(([k, v]) => ({ pattern: k, sites: v.length, examples: v.slice(0, 6) })),
  topCrawlPatterns: topCrawl.map(([k, v]) => ({ pattern: k, sites: v.length, examples: v.slice(0, 6) })),
  worst: worst.map((c) => ({
    rank: c.r.rank,
    domain: nameOf(c.r),
    category: c.category,
    kind: c.r.summary?.kind ?? null,
    url: c.r.page?.url,
    problems: c.problems,
    screenshot: c.r.page?.screenshot ? join(out, c.r.page.screenshot) : null,
  })),
}
await writeFile(join(out, "report.json"), JSON.stringify(summary, null, 2))

// ---- report.md ------------------------------------------------------------------

const md: string[] = []
const table = (head: string[], body: Array<Array<string | number>>) => {
  md.push(`| ${head.join(" | ")} |`, `| ${head.map(() => "---").join(" | ")} |`)
  for (const row of body) md.push(`| ${row.map((x) => String(x).replace(/\|/g, "\\|")).join(" | ")} |`)
  md.push("")
}
md.push(`# Deadbolt detection corpus`, "", `${new Date().toISOString()} · ${total} ${urlMode ? "listed pages" : "sites"} · output \`${out}\``, "")
md.push("## Headline", "")
table(
  ["Measure", "Value"],
  [
    [urlMode ? "Pages in list" : "Sites in list", total],
    ["Skipped (infra / adult / gambling by name)", skipped],
    [urlMode ? "Page unreachable" : "Homepage unreachable", `${unreachable} (${pct(unreachable, crawled)} of crawled)`],
    ["Bot challenge", challenge],
    ["Timeouts / crawler errors", `${summary.timeouts} / ${summary.errors}`],
    [urlMode ? "No sign-in fields on the page (or one hop away)" : "No sign-in page found", summary.noEntry],
    ["**Sign-in page reached**", `**${ok.length}** (${pct(ok.length, reachedHome)} of reachable ${urlMode ? "pages" : "homepages"})`],
    ["Pages with a visible password field", pwPages.length],
    ["**Password pages detected** (login/signup/mfa/change-password)", `**${pwDetected.length}** (${pct(pwDetected.length, pwPages.length)})`],
    ["Identifier-first pages (identifier, no password)", idFirst.length],
    ["**Identifier-first judged login**", `**${idFirstDetected.length}** (${pct(idFirstDetected.length, idFirst.length)})`],
    ["SSO-only sign-in pages", summary.ssoOnly],
    ["Pages with fields in shadow DOM", summary.shadowFieldPages],
    ["Pages with any open shadow root", summary.shadowRootPages],
    ["Password field inside an iframe", summary.passwordInIframe],
    ["Detector time per frame (p50 / p90 / max ms)", `${summary.scanMs.p50} / ${summary.scanMs.p90} / ${summary.scanMs.max}`],
  ],
)
md.push("Kinds on password pages: " + Object.entries(summary.passwordKinds).map(([k, v]) => `${k} ${v}`).join(", ") + "  ")
md.push("Kinds on identifier-first pages: " + Object.entries(summary.identifierFirstKinds).map(([k, v]) => `${k} ${v}`).join(", ") + "  ")
md.push("Sign-in page reached via: " + Object.entries(summary.via).map(([k, v]) => `${k} ${v}`).join(", "), "")

md.push("## Field agreement with weak labels", "")
md.push(
  "Weak labels come from the page's own markup: autocomplete tokens first, then `type=password`/`type=email`, then name/id hints. " +
    "`match` = same role (any password role matches a bare `type=password`), `coarse` = same family (e.g. email vs username), " +
    "`miss` = labelled but no role, `wrong` = different family, `extra` = role without a label, `out-of-scope` = outside the form the detector judged.",
  "",
)
table(["Agreement", "Fields", "Share"], Object.entries(agreementTally).map(([k, v]) => [k, v, pct(v, rows.length)]))
md.push("### Confusion (weak label → detector role)", "")
table(
  ["Label", ...roleCols],
  Object.entries(confusion)
    .sort((a, b) => Object.values(b[1]).reduce((x, y) => x + y, 0) - Object.values(a[1]).reduce((x, y) => x + y, 0))
    .map(([k, v]) => [k, ...roleCols.map((r) => v[r] ?? "")]),
)

md.push("## Top detector failure patterns", "")
const shotOf = new Map(classified.filter((c) => c.r.page?.screenshot).map((c) => [nameOf(c.r), join(out, c.r.page!.screenshot!)]))
table(
  ["Pattern", "Sites", "Examples", "First screenshot"],
  topDetector.map(([k, v]) => [k, v.length, v.slice(0, 6).join(", "), shotOf.has(v[0]) ? `\`${shotOf.get(v[0])}\`` : ""]),
)
md.push("## Crawl outcomes that never reached the detector", "")
table(["Outcome", "Sites", "Examples"], topCrawl.map(([k, v]) => [k, v.length, v.slice(0, 6).join(", ")]))
md.push("## All categories", "")
table(["Category", "Sites"], Object.entries(summary.categories))
if (Object.keys(summary.crossOriginLoginIframe).length) {
  md.push("## Cross-origin login iframes", "")
  table(["Frame host", "Sites"], Object.entries(summary.crossOriginLoginIframe))
}
md.push("## Off-site sign-in hosts", "")
table(["Host", "Sites"], Object.entries(summary.offSiteSignIn).slice(0, 25))
md.push("## Worst mismatches", "")
for (const w of summary.worst) {
  md.push(`- **#${w.rank} ${w.domain}** — ${w.category}, kind \`${w.kind}\` — ${w.url ?? ""}`)
  for (const p of w.problems.slice(0, 4)) md.push(`  - ${p}`)
  if (w.screenshot) md.push(`  - screenshot: \`${w.screenshot}\``)
}
md.push("", `Contact sheet: \`${join(out, "contact.html")}\``, "")

// ---- Step 2 ---------------------------------------------------------------------

const s2 = results.filter((r) => r.step2)
const s2done = s2.filter((r) => r.step2!.outcome)
if (s2.length) {
  const outcomes = tally(s2done.map((r) => r.step2!.outcome!))
  const ex = (pred: (r: SiteResult) => boolean) =>
    s2done
      .filter(pred)
      .slice(0, 5)
      .map(nameOf)
      .join(", ")
  md.push("## Step 2 of identifier-first sign-ins", "")
  md.push(
    `Typed the reserved address \`deadbolt.corpus@example.com\` into the identifier field and pressed the detected submit control once (never a password, never anything on step 2). ` +
      `${s2.length} identifier-first pages, ${s2done.length} attempted; skipped: ${Object.entries(tally(s2.filter((r) => !r.step2!.outcome).map((r) => r.step2!.skipped ?? `error: ${(r.step2!.error ?? "").slice(0, 40)}`)))
        .map(([k, v]) => `${k} ${v}`)
        .join(", ") || "none"}.`,
    "",
  )
  table(
    ["Step 2 shows", "Pages", "Share", "Examples"],
    Object.entries(outcomes).map(([k, v]) => [k, v, pct(v, s2done.length), ex((r) => r.step2!.outcome === k)]),
  )
  const cross = (rows: SiteResult[], a: (r: SiteResult) => string, b: (r: SiteResult) => string, title: string) => {
    const cols = Object.keys(tally(rows.map(b)))
    const m = new Map<string, Record<string, number>>()
    for (const r of rows) {
      const row = m.get(a(r)) ?? {}
      row[b(r)] = (row[b(r)] ?? 0) + 1
      m.set(a(r), row)
    }
    md.push(`### ${title}`, "")
    table(["", ...cols], [...m.entries()].map(([k, row]) => [k, ...cols.map((c) => row[c] ?? "")]))
  }
  const st = (r: SiteResult) => r.step2!
  const domOf = (r: SiteResult) => (st(r).dom === "replaced in place" || st(r).dom === "field kept") && st(r).urlChanged ? `${st(r).dom} (URL changed)` : st(r).dom!
  cross(s2done, (r) => st(r).outcome!, domOf, "Outcome × how step 2 relates to step 1's document")
  cross(s2done, (r) => st(r).outcome!, (r) => st(r).origin!, "Outcome × origin of step 2")
  cross(s2done, (r) => st(r).outcome!, (r) => st(r).carry!, "Outcome × where the typed address is on step 2")
  const pw = s2done.filter((r) => st(r).outcome === "password")
  if (pw.length) {
    md.push("### Password steps", "")
    table(
      ["Measure", "Value"],
      [
        ["Password steps", pw.length],
        ["Same document (no navigation)", `${pw.filter((r) => st(r).dom === "field kept" || st(r).dom === "replaced in place").length} (URL changed in ${pw.filter((r) => st(r).urlChanged && (st(r).dom === "field kept" || st(r).dom === "replaced in place")).length})`],
        ["New document", pw.filter((r) => st(r).dom === "navigated").length],
        ["Popup / iframe", `${pw.filter((r) => st(r).dom === "popup").length} / ${pw.filter((r) => st(r).dom === "iframe").length}`],
        ["Origin: same / same site / other site", ["same-origin", "same-site", "cross-site"].map((o) => pw.filter((r) => st(r).origin === o).length).join(" / ")],
        ["Password box in: top / same-origin iframe / cross-origin iframe / not yet visible", [...["top", "same-origin iframe", "cross-origin iframe"].map((o) => pw.filter((r) => st(r).passwordWhere === o).length), pw.filter((r) => !st(r).passwordWhere).length].join(" / ")],
        ["Detector kind on step 2", Object.entries(tally(pw.map((r) => st(r).kind ?? "null"))).map(([k, v]) => `${k} ${v}`).join(", ")],
        ["Identifier carried: " + Object.keys(tally(pw.map((r) => st(r).carry!))).join(" / "), Object.values(tally(pw.map((r) => st(r).carry!))).join(" / ")],
      ],
    )
  }
  const sso = tally(s2done.filter((r) => st(r).outcome === "sso-redirect").map((r) => st(r).finalHost ?? ""))
  if (Object.keys(sso).length) {
    md.push("### SSO / IdP hosts after step 1", "")
    table(["Host", "Pages"], Object.entries(sso))
  }
  md.push("Submit: " + Object.entries(tally(s2done.map((r) => st(r).action ?? "?"))).map(([k, v]) => `${k} ${v}`).join(", ") + `; address typed and read back: ${s2done.filter((r) => st(r).typed).length}/${s2done.length}.`, "")
  md.push(`Step-2 contact sheet: \`${join(out, "step2.html")}\``, "")
}
await writeFile(join(out, "report.md"), md.join("\n"))

// ---- contact.html ---------------------------------------------------------------

const COLORS: Record<string, string> = {
  username: "#2563eb",
  email: "#0891b2",
  phone: "#7c3aed",
  password: "#dc2626",
  "new-password": "#ea580c",
  otp: "#ca8a04",
  captcha: "#6b7280",
}
const esc = (s: unknown) => String(s ?? "").replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[ch]!)

function overlay(p: { shot?: { w: number; h: number }; frames: CapturedFrame[] }, fields: FieldRow[]): string[] {
  const boxes: string[] = []
  if (p.shot) {
    const { w, h } = p.shot
    const box = (x: number, y: number, bw: number, bh: number, style: string, tag: string) =>
      x < w && y < h
        ? `<div class="b" style="left:${(100 * x) / w}%;top:${(100 * y) / h}%;width:${(100 * bw) / w}%;height:${(100 * bh) / h}%;${style}"><span>${esc(tag)}</span></div>`
        : ""
    for (const f of fields) {
      const fr = p.frames[f.frame]
      const input = fr.inputs[f.i]
      if (!f.label && !f.role) continue
      const color = f.role ? COLORS[f.role] ?? "#111" : "#9ca3af"
      const bad = f.agreement === "miss" || f.agreement === "wrong"
      const tag = `${f.label ? f.label.role : "?"}→${f.role ?? "none"}`
      boxes.push(box(input.rect.x + fr.offset.x, input.rect.y + fr.offset.y, input.rect.w, input.rect.h, `border:2px ${bad ? "dashed" : "solid"} ${bad ? "#f0f" : color};`, tag))
    }
    for (const fr of p.frames)
      if (fr.submit) {
        const s = fr.submit.rect
        boxes.push(box(s.x + fr.offset.x, s.y + fr.offset.y, s.w, s.h, "border:2px dotted #16a34a;", "submit"))
      }
  }
  return boxes
}

function card(c: Classified): string {
  const r = c.r
  const p = r.page
  const boxes = p?.screenshot ? overlay(p, r.summary?.fields ?? []) : []
  const good = /detected$/.test(c.category)
  const img = p?.screenshot ? `<div class="shot"><img loading="lazy" src="${esc(p.screenshot)}">${boxes.join("")}</div>` : `<div class="shot empty">no screenshot</div>`
  return `<figure data-cat="${esc(c.category)}" data-good="${good ? 1 : 0}" data-bad="${c.badness}">
${img}
<figcaption><b>#${r.rank} ${esc(nameOf(r))}</b> · <span class="${good ? "ok" : "bad"}">${esc(c.category)}</span> · kind <code>${esc(r.summary?.kind ?? "–")}</code>
${p ? `<br><a href="${esc(p.url)}">${esc(p.url.slice(0, 90))}</a> (${esc(p.via)})` : r.error ? `<br>${esc(r.error.slice(0, 120))}` : ""}
${c.problems.length ? `<ul>${c.problems.slice(0, 5).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}</figcaption></figure>`
}

const shown = classified.filter((c) => c.r.page?.screenshot).sort((a, b) => b.badness - a.badness || a.r.rank - b.r.rank)
const cats = Object.keys(tally(shown.map((c) => c.category)))
const html = `<!doctype html><meta charset="utf-8"><title>Deadbolt corpus contact sheet</title>
<style>
body{font:13px/1.4 -apple-system,system-ui,sans-serif;margin:16px;background:#f4f4f5;color:#18181b}
header{position:sticky;top:0;background:#f4f4f5;padding:8px 0;z-index:9}
main{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:14px}
figure{margin:0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px #0002}
.shot{position:relative;max-height:520px;overflow:hidden}.shot img{width:100%;display:block}.empty{padding:40px;text-align:center;color:#888}
.b{position:absolute;box-sizing:border-box}.b span{position:absolute;top:-15px;left:-2px;font:10px/13px ui-monospace,monospace;background:#000c;color:#fff;padding:0 3px;white-space:nowrap;border-radius:2px}
figcaption{padding:8px 10px}figcaption ul{margin:4px 0 0;padding-left:18px;color:#a21caf}.ok{color:#15803d}.bad{color:#b91c1c}
a{color:#2563eb;word-break:break-all}
</style>
<header><b>${shown.length} pages</b> · boxes: weak label→detector role, magenta dashed = disagreement, green dotted = submit ·
<select id="f"><option value="">all categories</option><option value="!good">all problems</option>${cats.map((k) => `<option>${esc(k)}</option>`).join("")}</select></header>
<main>${shown.map(card).join("\n")}</main>
<script>
document.getElementById("f").onchange = (e) => {
  const v = e.target.value
  for (const f of document.querySelectorAll("figure"))
    f.hidden = v === "!good" ? f.dataset.good === "1" && f.dataset.bad === "0" : !!v && f.dataset.cat !== v
}
</script>`
await writeFile(join(out, "contact.html"), html)

// ---- step2.html: step 1 and step 2 side by side ----------------------------------

if (s2done.length) {
  const order = ["password", "otp", "passkey", "magic-link", "sso-redirect", "sign-up", "invalid-address", "not-found/error", "challenge", "other-change", "no-change"]
  const rows2 = [...s2done].sort((a, b) => order.indexOf(a.step2!.outcome!) - order.indexOf(b.step2!.outcome!) || a.rank - b.rank)
  const pane = (shot: string | undefined, boxes: string[]) => (shot ? `<div class="shot"><img loading="lazy" src="${esc(shot)}">${boxes.join("")}</div>` : `<div class="shot empty">no screenshot</div>`)
  const cards = rows2.map((r) => {
    const t = r.step2!
    const one = r.page ? pane(r.page.screenshot, overlay(r.page, r.summary?.fields ?? [])) : pane(undefined, [])
    const two = pane(t.screenshot, t.frames ? overlay({ shot: { w: 1280, h: 800 }, frames: t.frames }, t.summary?.fields ?? []) : [])
    return `<figure data-cat="${esc(t.outcome)}"><div class="pair">${one}${two}</div><figcaption><b>#${r.rank} ${esc(nameOf(r))}</b> · <b>${esc(t.outcome)}</b> · ${esc(t.dom)}${t.urlChanged ? " (URL changed)" : ""} · ${esc(t.origin)} · address: ${esc(t.carry)} · step-2 kind <code>${esc(t.kind ?? "–")}</code>
<br><a href="${esc(t.finalUrl)}">${esc((t.finalUrl ?? "").slice(0, 100))}</a>${t.evidence?.length ? `<ul>${t.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : ""}</figcaption></figure>`
  })
  const outs = Object.keys(tally(rows2.map((r) => r.step2!.outcome!)))
  await writeFile(
    join(out, "step2.html"),
    `<!doctype html><meta charset="utf-8"><title>Deadbolt corpus: step 2</title>
<style>
body{font:13px/1.4 -apple-system,system-ui,sans-serif;margin:16px;background:#f4f4f5;color:#18181b}
header{position:sticky;top:0;background:#f4f4f5;padding:8px 0;z-index:9}
main{display:grid;grid-template-columns:repeat(auto-fill,minmax(760px,1fr));gap:14px}
figure{margin:0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px #0002}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:2px;background:#ddd}
.shot{position:relative;max-height:420px;overflow:hidden;background:#fff}.shot img{width:100%;display:block}.empty{padding:40px;text-align:center;color:#888}
.b{position:absolute;box-sizing:border-box}.b span{position:absolute;top:-13px;left:-2px;font:9px/12px ui-monospace,monospace;background:#000c;color:#fff;padding:0 3px;white-space:nowrap;border-radius:2px}
figcaption{padding:8px 10px}figcaption ul{margin:4px 0 0;padding-left:18px;color:#555}a{color:#2563eb;word-break:break-all}
</style>
<header><b>${rows2.length} step-2 attempts</b> · left: step 1, right: step 2 ·
<select id="f"><option value="">all outcomes</option>${outs.map((k) => `<option>${esc(k)}</option>`).join("")}</select></header>
<main>${cards.join("\n")}</main>
<script>
document.getElementById("f").onchange = (e) => { for (const f of document.querySelectorAll("figure")) f.hidden = !!e.target.value && f.dataset.cat !== e.target.value }
</script>`,
  )
}

console.log(md.slice(0, 40).join("\n"))
console.log(`\n${join(out, "report.md")}\n${join(out, "contact.html")}`)
