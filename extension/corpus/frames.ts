// Per-frame results of a crawl, and the frame-login regression check: for
// each page of a URL list (default corpus/frame-logins.txt) crawled with
// `crawl.ts --urls`, every frame the probe reached, with its host, size,
// whether it and every frame above it are the top page's site over https,
// any `sandbox` on the way, and the detector's kind and roles. A page passes
// when some frame below the top page is one the inline menu serves (see
// sameSiteTop in src/bg/frames.ts) and the detector finds a login with
// fields in it.
//
//   bun corpus/frames.ts [--out <dir>] [--urls corpus/frame-logins.txt] [--all]
//
// `--all` lists every crawled page's frames and checks nothing. Exits 1 when
// a listed page is missing, didn't load, or fails.

import { existsSync } from "node:fs"
import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { sameSiteChain } from "../src/bg/site"
import { resultKey, type CapturedFrame, type SiteResult } from "./crawl"
import { DEFAULT_OUT } from "./sites"

const arg = (name: string) => {
  const i = process.argv.indexOf(name)
  return i > 0 ? process.argv[i + 1] : undefined
}
const out = arg("--out") ?? DEFAULT_OUT
const all = process.argv.includes("--all")
const urlsFile = arg("--urls") ?? join(import.meta.dir, "frame-logins.txt")

const resultsFile = join(out, "results.jsonl")
if (!existsSync(resultsFile)) {
  console.error(`no crawl in ${out}: run crawl.ts --urls ${urlsFile} --out ${out} first`)
  process.exit(1)
}
const results = new Map<string, SiteResult>()
for (const line of (await readFile(resultsFile, "utf8")).split("\n")) {
  if (!line) continue
  try {
    const r = JSON.parse(line) as SiteResult
    results.set(resultKey(r), r)
  } catch {}
}

/** The frames from `i` up to the top page, by the probe's parent indexes; null if one wasn't captured. */
function chain(frames: CapturedFrame[], i: number): CapturedFrame[] | null {
  const up: CapturedFrame[] = []
  for (let at = i; ; at = frames[at].parent ?? -1) {
    if (at < 0 || at >= frames.length || up.length > 8) return null
    up.push(frames[at])
    if (at === 0) return up
  }
}

interface Row {
  frame: number
  where: string
  size: string
  sameSite: boolean
  sandbox: string
  kind: string
  roles: string
  /** A frame below the top page the inline menu serves, with a login the detector finds. */
  menu: boolean
}

function rows(r: SiteResult): Row[] {
  const frames = r.page?.frames ?? []
  return frames.map((f, i) => {
    const path = chain(frames, i)
    let urls: URL[] = []
    try {
      urls = path ? path.map((p) => new URL(p.url)) : []
    } catch {}
    const sameSite = i > 0 && !!path && urls.length === path.length && sameSiteChain(urls) && !path.some((p) => p.origin === "null")
    const sandboxed = path?.find((p) => p.sandbox !== null && p.sandbox !== undefined)
    const roles = [...new Set(f.inputs.filter((x) => x.visible && x.role).map((x) => x.role!))]
    let where = f.url
    try {
      const u = new URL(f.url)
      where = u.host + u.pathname
    } catch {}
    return {
      frame: i,
      where,
      size: f.size ? `${f.size.w}×${f.size.h}` : "top",
      sameSite,
      sandbox: sandboxed ? `sandbox="${sandboxed.sandbox}"` : f.origin === "null" ? "opaque" : "",
      kind: f.kind ?? "",
      roles: roles.join(","),
      menu: sameSite && !sandboxed && f.kind === "login" && roles.length > 0,
    }
  })
}

const listed = all
  ? [...results.keys()]
  : (await readFile(urlsFile, "utf8"))
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => /^https?:\/\//.test(l))

let failed = 0
for (const url of listed) {
  const r = results.get(url)
  if (!r?.page) {
    console.log(`\n${url}: ${r ? r.status : "not crawled"}${r?.error ? ` (${r.error})` : ""}`)
    if (!all) failed++
    continue
  }
  const table = rows(r)
  const pass = table.some((t) => t.menu) && table[0]?.kind !== "login"
  console.log(`\n${url}${r.page.url !== url ? ` → ${r.page.url}` : ""}${all ? "" : pass ? "  ok" : "  FAIL"}`)
  console.log("  frame  where                                              size      same site  sandbox  kind     roles")
  for (const t of table)
    console.log(`  ${String(t.frame).padEnd(5)}  ${t.where.slice(0, 50).padEnd(50)} ${t.size.padEnd(9)} ${(t.frame === 0 ? "-" : t.sameSite ? "yes" : "no").padEnd(10)} ${(t.sandbox || "-").padEnd(8)} ${(t.kind || "-").padEnd(8)} ${t.roles || "-"}${t.menu ? "  ← menu" : ""}`)
  if (!all && !pass) failed++
}
if (!all) console.log(failed ? `\n${failed} of ${listed.length} pages failed` : `\nall ${listed.length} pages have a frame login the menu serves`)
process.exit(failed ? 1 : 0)
