// The page's own SVG icon, for the background to keep (bg/site-icons.ts).
// Asked only of a top page on a site the user has a login for, and at most
// once a month per site. The page's <link rel="icon" type="image/svg+xml">
// first, else its Safari mask-icon (monochrome, with its colour).
//
// Read from here, not fetched by the background: this request is the
// page's own (its origin, its cache, no cookies sent, no referrer), to the
// address the page itself names for its icon, which the browser usually
// already loaded, so it most often comes from the cache. The background
// would need host permissions to fetch it, and would ask as the extension,
// telling the site that this visitor runs Deadbolt.

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
  if (url.protocol !== "https:" && url.protocol !== "http:") return null
  try {
    const r = await fetch(url.href, { credentials: "omit", cache: "force-cache", referrerPolicy: "no-referrer", signal: AbortSignal.timeout(5000) })
    if (!r.ok || !/svg/i.test(r.headers.get("content-type") ?? "")) return null
    if (Number(r.headers.get("content-length") ?? 0) > MAX_SVG_BYTES) return null
    const body = await r.text()
    return body.length <= MAX_SVG_BYTES ? body : null
  } catch {
    return null
  }
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
