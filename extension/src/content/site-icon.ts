// The page's own SVG icon, for the background to keep (bg/site-icons.ts).
// Asked only of a top page Deadbolt just filled a login on, or saw a
// sign-in go through on, at most once a month per host. The page's
// <link rel="icon" type="image/svg+xml"> first, else its Safari mask-icon
// (monochrome, with its colour), from an inline data: URL or the page's own
// origin only.
//
// Never a network request: the read is `cache: "only-if-cached"`, same
// origin, no cookies, no referrer, so it gets the icon only if the browser
// already loaded it for the page, and nothing at all otherwise. The page's
// own script could notice that read, but only after the fill or sign-in,
// when the site already knows this visitor has an account.

import { MAX_SVG_BYTES, sanitizeSvg } from "../ui/svg-safe"

export interface PageIcon {
  svg: string
  mask?: boolean
  color?: string
}

const isSvg = (l: HTMLLinkElement) => l.type.toLowerCase() === "image/svg+xml" || /\.svg(?:$|[?#])/i.test(l.getAttribute("href") ?? "") || /^data:image\/svg\+xml/i.test(l.href)

async function text(href: string): Promise<string | null> {
  let url: URL
  try {
    url = new URL(href, document.baseURI)
  } catch {
    return null
  }
  if (url.protocol === "data:") {
    const m = /^data:image\/svg\+xml(;base64)?,(.*)$/is.exec(url.href)
    if (!m || m[2].length > MAX_SVG_BYTES * 2) return null
    try {
      return m[1] ? atob(m[2]) : decodeURIComponent(m[2])
    } catch {
      return null
    }
  }
  // An icon on another origin (a CDN) is skipped: only-if-cached works only same-origin.
  if ((url.protocol !== "https:" && url.protocol !== "http:") || url.origin !== location.origin) return null
  try {
    const r = await fetch(url.href, { mode: "same-origin", credentials: "omit", cache: "only-if-cached", referrerPolicy: "no-referrer", redirect: "error", signal: AbortSignal.timeout(5000) })
    if (!r.ok || !/svg/i.test(r.headers.get("content-type") ?? "") || !r.body) return null
    if (Number(r.headers.get("content-length") ?? 0) > MAX_SVG_BYTES) return null
    return await capped(r.body)
  } catch {
    return null
  }
}

/** A body as text, read no further than MAX_SVG_BYTES: a longer one is null. */
async function capped(body: ReadableStream<Uint8Array>): Promise<string | null> {
  const reader = body.getReader()
  const parts: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > MAX_SVG_BYTES) {
      void reader.cancel().catch(() => {})
      return null
    }
    parts.push(value)
  }
  const all = new Uint8Array(size)
  let at = 0
  for (const p of parts) {
    all.set(p, at)
    at += p.byteLength
  }
  return new TextDecoder().decode(all)
}

/** A colour as CSS writes it: hex or a plain name, nothing else. */
const color = (c: string | null) => (c && /^(#[0-9a-f]{3,8}|[a-z]{3,20})$/i.test(c.trim()) ? c.trim() : undefined)

export async function readPageIcon(): Promise<PageIcon | null> {
  const links = Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel~="icon" i][href], link[rel~="mask-icon" i][href]')).slice(0, 20)
  const rel = (l: HTMLLinkElement) => l.rel.toLowerCase().split(/\s+/)
  for (const l of links.filter((l) => rel(l).includes("icon") && isSvg(l)).slice(0, 2)) {
    const svg = sanitizeSvg((await text(l.href)) ?? "")
    if (svg) return { svg }
  }
  const mask = links.find((l) => rel(l).includes("mask-icon"))
  if (mask) {
    const svg = sanitizeSvg((await text(mask.href)) ?? "")
    if (svg) return { svg, mask: true, ...(color(mask.getAttribute("color")) ? { color: color(mask.getAttribute("color")) } : {}) }
  }
  return null
}
