// Freezes pages for the detection gate (score.ts): each page is opened once
// in headless Chromium at 1280×800, every control and button gets the box
// Chromium laid it out in (data-db-box="x,y,w,h,vis"), the few computed
// styles the detector reads (display, visibility, opacity,
// -webkit-text-security) are written inline, shadow roots are kept as
// <template shadowrootmode> markup (closed ones too: attachShadow is made
// to record them), and then scripts, styles, frames' sources, images,
// event handlers, query strings and every value a field held are stripped.
// What's left is the page's structure and text, a few KB, replayable with no
// network and no browser. corpus/frozen.lock.json gets each page's SHA-256.
//
//   bun corpus/freeze.ts --html <dir>        pages written by hand, each naming its URL in <meta name="db-url" content="…">
//   bun corpus/freeze.ts --in <crawl out>    crawl.ts output (results.jsonl and html/): the DOM it saved, no scripts run
//   bun corpus/freeze.ts --urls <file>       live pages, one URL per line (network, once; never in CI)
//   bun corpus/freeze.ts --urls corpus/decoy-urls.txt --decoy
//   bun corpus/freeze.ts --relock            rehash corpus/frozen/*.html after a deliberate edit
//
// Other flags: --out <dir> (default corpus/frozen), --lock <file>, --only
// <substring>. Pages already in the lock and not frozen again stay. A page
// with no gold label gets a proposed one in corpus/gold-labels.proposed.jsonl
// (from its autocomplete tokens and input types) for a person to check and
// move into corpus/gold-labels.jsonl; score.ts refuses a page without one.

import { chromium, type Browser, type Page } from "playwright-core"
import { createHash } from "node:crypto"
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs"
import { basename, dirname, join, relative } from "node:path"
import { siteOf, splitFor, type Gold, type Lock, type LockPage } from "./score"

const here = import.meta.dir
const args = process.argv.slice(2)
const opt = (name: string) => {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : undefined
}
const OUT = opt("--out") ?? join(here, "frozen")
const LOCK = opt("--lock") ?? join(here, "frozen.lock.json")
const LABELS = join(dirname(LOCK), "gold-labels.jsonl")
const PROPOSED = join(dirname(LOCK), "gold-labels.proposed.jsonl")
const only = opt("--only")
const VIEWPORT = { width: 1280, height: 800 }

interface Source {
  id: string
  url: string
  /** The HTML to serve at url; none for a live page. */
  html?: string
  source: LockPage["source"]
  decoy: boolean
  /** Run the page's scripts while freezing (pages written by hand and live pages; never a crawl's saved DOM). */
  scripts: boolean
}

const sha = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex")
const slug = (s: string) => s.toLowerCase().replace(/^https?:\/\//, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 80)
const metaUrl = (html: string) => /<meta\s+name="db-url"\s+content="([^"]+)"/i.exec(html)?.[1]
/** A page's URL without its query or fragment, which can carry a session's tokens; the detector reads only the host and path. */
const bare = (url: string) => {
  const u = new URL(url)
  return u.origin + u.pathname
}

function sources(): Source[] {
  const html = opt("--html")
  const crawl = opt("--in")
  const urls = opt("--urls")
  const decoy = args.includes("--decoy")
  const out: Source[] = []
  if (html)
    for (const f of readdirSync(html).filter((f) => f.endsWith(".html")).sort()) {
      const text = readFileSync(join(html, f), "utf8")
      const url = metaUrl(text)
      if (!url) throw new Error(`${f}: no <meta name="db-url" content="…">`)
      out.push({ id: basename(f, ".html"), url: bare(url), html: text, source: "modeled", decoy: /^decoy-/.test(f), scripts: true })
    }
  if (crawl)
    for (const line of readFileSync(join(crawl, "results.jsonl"), "utf8").split("\n").filter(Boolean)) {
      const r = JSON.parse(line) as { domain: string; page?: { url: string; html?: string } }
      if (!r.page?.html) continue
      out.push({ id: slug(bare(r.page.url)), url: bare(r.page.url), html: readFileSync(join(crawl, r.page.html), "utf8"), source: "crawl", decoy, scripts: false })
    }
  if (urls)
    for (const url of readFileSync(urls, "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")))
      out.push({ id: `${decoy ? "decoy-" : ""}${slug(bare(url.split(/\s+/)[0]))}`, url: url.split(/\s+/)[0], source: "live", decoy, scripts: true })
  return out.filter((s) => !only || s.id.includes(only))
}

// Runs in the page before its own scripts: every shadow root is made open
// and serializable so it can be measured and written out; closed ones say so
// on their host.
const INIT = `(() => {
  const attach = Element.prototype.attachShadow
  Element.prototype.attachShadow = function (init) {
    if (init && init.mode === "closed") this.setAttribute("data-db-shadow", "closed")
    return attach.call(this, { ...init, mode: "open", serializable: true })
  }
})()`

/** In the page: measure, strip, and serialize. Returns the frozen document. */
function freezeInPage(): string {
  const roots: Array<Document | ShadowRoot> = [document]
  for (let i = 0; i < roots.length; i++)
    for (const el of Array.from(roots[i].querySelectorAll("*"))) if (el.shadowRoot) roots.push(el.shadowRoot)
  const all = () => roots.flatMap((r) => Array.from(r.querySelectorAll("*")))
  const STAMP = "input, select, textarea, button, a[href], [role=button], [role=link], iframe, label, form, dialog"
  for (const root of roots)
    for (const el of Array.from(root.querySelectorAll(STAMP))) {
      const r = el.getBoundingClientRect()
      const vis = r.width > 0 && r.height > 0 && el.checkVisibility({ opacityProperty: true, visibilityProperty: true }) ? 1 : 0
      el.setAttribute("data-db-box", [r.x, r.y, r.width, r.height].map((n) => Math.round(n)).join(",") + `,${vis}`)
    }
  // The computed styles the detector reads, inline; every other style goes with the stylesheets.
  const shown = () => [document.body, ...roots.slice(1)].flatMap((r) => Array.from(r.querySelectorAll("*")))
  for (const el of shown()) {
    const cs = getComputedStyle(el)
    const parent = el.parentElement ? getComputedStyle(el.parentElement) : null
    const keep: string[] = []
    if (cs.display === "none") keep.push("display:none")
    if (cs.visibility !== "visible" && parent?.visibility !== cs.visibility) keep.push(`visibility:${cs.visibility}`)
    if (Number(cs.opacity) < 1) keep.push(`opacity:${cs.opacity}`)
    const security = cs.getPropertyValue("-webkit-text-security")
    if (security && security !== "none" && (el as HTMLInputElement).type !== "password") keep.push(`-webkit-text-security:${security}`)
    if (keep.length) el.setAttribute("style", keep.join(";"))
    else el.removeAttribute("style")
  }
  const DROP = "script, noscript, style, link, base, object, embed, meta:not([charset]):not([name=db-url]), template:not([shadowrootmode]), source, track"
  for (const root of roots) for (const el of Array.from(root.querySelectorAll(DROP))) el.remove()
  const strip = (u: string | null) => {
    if (!u) return null
    if (/^\s*javascript:/i.test(u)) return "#"
    try {
      const p = new URL(u, location.href)
      return p.protocol.startsWith("http") ? p.origin + p.pathname : "#"
    } catch {
      return "#"
    }
  }
  for (const el of all()) {
    for (const a of Array.from(el.attributes)) {
      if (/^on/i.test(a.name) || ["nonce", "integrity", "srcset", "srcdoc", "poster", "ping", "formaction"].includes(a.name)) el.removeAttribute(a.name)
      else if (a.value.length > 300) el.setAttribute(a.name, a.value.slice(0, 300))
    }
    if (el.localName === "svg") el.replaceChildren()
    if (["img", "video", "audio", "iframe", "frame", "input"].includes(el.localName) && el.hasAttribute("src")) {
      if (el.localName === "iframe" || el.localName === "frame") el.setAttribute("data-db-src", strip(el.getAttribute("src")) ?? "")
      el.removeAttribute("src")
    }
    if (el.hasAttribute("href")) el.setAttribute("href", strip(el.getAttribute("href")) ?? "#")
    if (el.hasAttribute("action")) el.setAttribute("action", strip(el.getAttribute("action")) ?? "")
    // Nothing a field held: no CSRF tokens, prefilled emails or anything else of the session.
    if (el instanceof HTMLInputElement && !["submit", "button", "reset", "image", "checkbox", "radio"].includes(el.type)) el.removeAttribute("value")
    if (el instanceof HTMLTextAreaElement) el.textContent = ""
  }
  const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT)
  const comments: Node[] = []
  for (let n = walker.nextNode(); n; n = walker.nextNode()) comments.push(n)
  for (const n of comments) n.parentNode?.removeChild(n)
  const html = document.documentElement.getHTML({ serializableShadowRoots: true, shadowRoots: roots.slice(1) as ShadowRoot[] })
  const lang = document.documentElement.getAttribute("lang")
  return `<!doctype html><html${lang ? ` lang="${lang}"` : ""}>${html}</html>`
}

/** Collapses whitespace between tags (to one space, so words stay apart) and marks the page's URL and closed roots. */
function tidy(html: string, url: string): string {
  let out = html.replace(/>\s+</g, "> <").replace(/\s{2,}/g, " ")
  const named = `<meta name="db-url" content="${bare(url).replace(/"/g, "&quot;")}">`
  out = /<meta name="db-url"[^>]*>/.test(out) ? out.replace(/<meta name="db-url"[^>]*>/, named) : out.replace(/<head>/i, `<head>${named}`)
  // A closed root, made open to be serialized: its template says so again.
  out = out.replace(/(<[^>]+data-db-shadow="closed"[^>]*>\s*<template shadowrootmode=")open/g, "$1closed")
  return out.replace(/ shadowrootserializable=""/g, "").trim() + "\n"
}

async function freezeOne(browser: Browser, s: Source): Promise<string> {
  const context = await browser.newContext({ viewport: VIEWPORT, javaScriptEnabled: s.scripts, deviceScaleFactor: 1, locale: "en-US", serviceWorkers: "block" })
  try {
    await context.addInitScript(INIT)
    if (s.html !== undefined) {
      const served = s.html
      // Only the page itself: nothing else it asks for is fetched.
      await context.route("**/*", (route) => (route.request().url() === s.url && route.request().resourceType() === "document" ? route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: served }) : route.abort()))
    }
    const page: Page = await context.newPage()
    await page.goto(s.url, { waitUntil: "load", timeout: 30_000 })
    await page.waitForTimeout(s.source === "live" ? 2500 : 300)
    await page.evaluate(() => scrollTo(0, 0))
    return tidy(await page.evaluate(freezeInPage), s.url)
  } finally {
    await context.close()
  }
}

function readLock(): Lock {
  return existsSync(LOCK) ? (JSON.parse(readFileSync(LOCK, "utf8")) as Lock) : { version: 1, viewport: `${VIEWPORT.width}x${VIEWPORT.height}`, pages: [] }
}

function writeLock(pages: LockPage[]) {
  const lock: Lock = { version: 1, viewport: `${VIEWPORT.width}x${VIEWPORT.height}`, pages: [...pages].sort((a, b) => (a.id < b.id ? -1 : 1)) }
  writeFileSync(LOCK, JSON.stringify(lock, null, 1) + "\n")
  const kb = lock.pages.reduce((n, p) => n + p.bytes, 0) / 1024
  console.log(`lock: ${lock.pages.length} pages, ${kb.toFixed(0)} KB, in ${relative(process.cwd(), LOCK)}`)
}

function relock() {
  const old = new Map(readLock().pages.map((p) => [p.id, p]))
  const pages: LockPage[] = []
  for (const f of readdirSync(OUT).filter((f) => f.endsWith(".html")).sort()) {
    const bytes = readFileSync(join(OUT, f))
    const id = basename(f, ".html")
    const url = metaUrl(bytes.toString("utf8"))
    if (!url) throw new Error(`${f}: no <meta name="db-url">`)
    pages.push({ id, file: relative(dirname(LOCK), join(OUT, f)), url, sha256: sha(bytes), bytes: bytes.length, source: old.get(id)?.source ?? "modeled" })
  }
  writeLock(pages)
}

/** Proposed labels for pages that have none: what their autocomplete tokens and input types say, for a person to confirm. */
async function propose(fresh: Array<{ id: string; decoy: boolean; html: string; url: string }>) {
  const labelled = new Set(
    (existsSync(LABELS) ? readFileSync(LABELS, "utf8") : "")
      .split("\n")
      .filter(Boolean)
      .map((l) => (JSON.parse(l) as Gold).id),
  )
  const todo = fresh.filter((p) => !labelled.has(p.id))
  if (!todo.length) return
  const { load, controlKey } = await import("./replay")
  const { deepQueryAll, openRoots } = await import("../src/content/shadow")
  const LOGIN: Record<string, string> = { username: "username", email: "email", "current-password": "password", "new-password": "new-password", "one-time-code": "otp", tel: "phone" }
  const lines: string[] = []
  for (const p of todo) {
    load(p.html, p.url)
    const gold: Gold = { id: p.id, pattern: `TODO: what ${p.url} is`, split: splitFor(siteOf(p.url)), decoy: p.decoy, kind: null, login: {}, forms: {} }
    if (!p.decoy)
      for (const el of deepQueryAll<HTMLInputElement>("input, select, textarea", openRoots())) {
        const tokens = (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/).filter((t) => t && !/^(section-|shipping|billing|webauthn)/.test(t))
        const token = tokens.pop()
        const key = controlKey(el)
        if (token?.startsWith("cc-") || ["street-address", "address-line1", "address-line2", "address-level1", "address-level2", "postal-code", "country"].includes(token ?? "")) gold.forms[key] = token!
        else if (token && LOGIN[token]) gold.login[key] = LOGIN[token]
        else if (el.getAttribute("type") === "password") gold.login[key] = "password"
      }
    lines.push(JSON.stringify(gold))
  }
  writeFileSync(PROPOSED, lines.join("\n") + "\n", { flag: "a" })
  console.log(`${todo.length} pages have no gold label: proposals in ${relative(process.cwd(), PROPOSED)} (check each, set its kind, move it into gold-labels.jsonl)`)
}

async function main() {
  if (args.includes("--relock")) return relock()
  const list = sources()
  if (!list.length) throw new Error("nothing to freeze: pass --html <dir>, --in <crawl out> or --urls <file> (or --relock)")
  mkdirSync(OUT, { recursive: true })
  const lock = new Map(readLock().pages.map((p) => [p.id, p]))
  const browser = await chromium.launch({ headless: true })
  const fresh: Array<{ id: string; decoy: boolean; html: string; url: string }> = []
  try {
    for (const s of list) {
      try {
        const html = await freezeOne(browser, s)
        const file = join(OUT, `${s.id}.html`)
        writeFileSync(file, html)
        const bytes = Buffer.byteLength(html)
        lock.set(s.id, { id: s.id, file: relative(dirname(LOCK), file), url: bare(s.url), sha256: sha(html), bytes, source: s.source })
        fresh.push({ id: s.id, decoy: s.decoy, html, url: s.url })
        console.log(`froze ${s.id} (${(bytes / 1024).toFixed(1)} KB)`)
      } catch (e) {
        console.error(`skipped ${s.id}: ${String(e).split("\n")[0]}`)
      }
    }
  } finally {
    await browser.close()
  }
  writeLock([...lock.values()])
  await propose(fresh)
}

await main()
