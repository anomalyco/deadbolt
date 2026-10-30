// A login's site icon, in its letter tile. Where it comes from, first found
// first (none of them asks the network for anything):
//
// 1. the site's own SVG icon, kept when the user last visited it
//    (bg/site-icons.ts), sanitized again here (ui/svg-safe.ts);
// 2. the site's mark from the bundled Simple Icons subset
//    (static/site-icons/simple-icons.json, scripts/simple-icons.ts);
// 3. Chrome's own favicon cache (`_favicon/`, the `favicon` permission);
// 4. else the letter stays.
//
// Every source is drawn as an image into a canvas the size of the tile:
// SVG through an <img> from a blob: URL of this extension, so nothing in it
// can run or load anything, and _favicon/ is this extension's own URL, so
// neither taints the canvas. The icon resolves with an ordered-dither
// reveal: a Bayer 8×8 threshold sweeps across it one CSS pixel per cell,
// first in the tile's own ink, then in the icon's colours, while the letter
// dithers out under it. Reduced motion: the icon just appears.

import { avatar } from "./dom"
import { iconKey, storedIcon, type StoredIcon } from "./icon-store"
import { reducedMotion } from "./motion"
import { sanitizeSvg } from "./svg-safe"

export type IconKind = "svg" | "mask" | "brand" | "favicon"

export interface Resolved {
  kind: IconKind
  image: HTMLImageElement
  /** The image's own pixel size (rasters), for crisp upscaling. */
  natural: number
  /** Paint the icon's opaque pixels in this colour (mask-icons and Simple Icons). */
  tint?: string
}

const hostOf = (url: string) => {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname
  } catch {
    return ""
  }
}

function load(src: string): Promise<HTMLImageElement | null> {
  return new Promise((resolve) => {
    const img = new Image()
    img.decoding = "async"
    img.onload = () => resolve(img)
    img.onerror = () => resolve(null)
    img.src = src
  })
}

/** Sanitized SVG markup as an image: a blob: URL of this page, so the canvas it's drawn into stays readable. */
async function svgImage(markup: string): Promise<HTMLImageElement | null> {
  const clean = sanitizeSvg(markup)
  if (!clean) return null
  const url = URL.createObjectURL(new Blob([clean], { type: "image/svg+xml" }))
  const img = await load(url)
  URL.revokeObjectURL(url)
  return img
}

// ---- Simple Icons ---------------------------------------------------------------

interface SimpleIcons {
  domains: Record<string, string>
  brands: Record<string, [title: string, hex: string, path: string]>
}
let simple: Promise<SimpleIcons | null> | null = null

/** The bundled Simple Icons subset, loaded the first time a tile needs it. */
function simpleIcons(): Promise<SimpleIcons | null> {
  simple ??= fetch(chrome.runtime.getURL("site-icons/simple-icons.json"))
    .then((r) => (r.ok ? (r.json() as Promise<SimpleIcons>) : null))
    .catch(() => null)
  return simple
}

/**
 * A host's brand from Simple Icons: the host's own entry, else the nearest
 * parent domain's (accounts.google.com is google.com's). The subset only
 * names registrable domains, so a parent never reaches a public suffix.
 */
export function brandFor(icons: SimpleIcons, host: string): [string, string, string] | null {
  const labels = iconKey(host).split(".")
  for (let i = 0; i < labels.length - 1; i++) {
    const slug = icons.domains[labels.slice(i).join(".")]
    if (slug) return icons.brands[slug] ?? null
  }
  return null
}

// ---- Chrome's favicon cache ---------------------------------------------------------

const hasFavicon = () => {
  try {
    return chrome.runtime.getManifest().permissions?.includes("favicon") === true
  } catch {
    return false
  }
}

function faviconUrl(page: string, size: number) {
  const u = new URL(chrome.runtime.getURL("/_favicon/"))
  u.searchParams.set("pageUrl", page)
  u.searchParams.set("size", String(size))
  return u.toString()
}

/** A data URL of what `img` draws at 32 px: to tell Chrome's generic globe from a real icon. */
function fingerprint(img: HTMLImageElement): string {
  const c = document.createElement("canvas")
  c.width = c.height = 32
  c.getContext("2d")!.drawImage(img, 0, 0, 32, 32)
  return c.toDataURL()
}

let globe: Promise<string | null> | null = null

async function favicon(origin: string): Promise<Resolved | null> {
  if (!hasFavicon()) return null
  globe ??= load(faviconUrl("https://deadbolt.invalid/", 64)).then((g) => (g ? fingerprint(g) : null))
  const [img, generic] = await Promise.all([load(faviconUrl(origin, 64)), globe])
  if (!img || !img.naturalWidth) return null
  try {
    if (generic && fingerprint(img) === generic) return null
  } catch {
    return null
  }
  return { kind: "favicon", image: img, natural: img.naturalWidth }
}

// ---- Resolving ---------------------------------------------------------------------

const resolving = new Map<string, Promise<Resolved | null>>()

/**
 * The best icon for a login's `url`, or null for the letter. `stored`: the
 * kept icon, when the caller already has it (the menu gets it from the
 * background); undefined reads it here.
 */
export function resolveIcon(url: string, stored?: StoredIcon | null): Promise<Resolved | null> {
  const host = hostOf(url)
  if (!host) return Promise.resolve(null)
  const key = iconKey(host)
  let p = resolving.get(key)
  if (!p) {
    p = (async (): Promise<Resolved | null> => {
      const kept = stored === undefined ? await storedIcon(key) : stored
      if (kept?.svg) {
        const img = await svgImage(kept.svg)
        if (img) return { kind: kept.mask ? "mask" : "svg", image: img, natural: 0, ...(kept.mask ? { tint: kept.color ?? "" } : {}) }
      }
      const icons = await simpleIcons()
      const brand = icons ? brandFor(icons, host) : null
      if (brand) {
        const img = await svgImage(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="${brand[2]}"/></svg>`)
        if (img) return { kind: "brand", image: img, natural: 0, tint: `#${brand[1]}` }
      }
      return favicon(`https://${host}`)
    })()
    resolving.set(key, p)
  }
  return p
}

// ---- Drawing -----------------------------------------------------------------------

type RGBA = [number, number, number, number]

/** Any CSS colour as RGBA, the way a canvas reads it. */
function rgba(css: string): RGBA {
  const c = document.createElement("canvas")
  c.width = c.height = 1
  const ctx = c.getContext("2d", { willReadFrequently: true })!
  ctx.fillStyle = "#000"
  ctx.fillStyle = css
  ctx.fillRect(0, 0, 1, 1)
  const d = ctx.getImageData(0, 0, 1, 1).data
  return [d[0], d[1], d[2], d[3]]
}

const luminance = ([r, g, b]: RGBA) => {
  const f = (v: number) => ((v /= 255) <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
}
export const contrast = (a: RGBA, b: RGBA) => {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p)
  return (x + 0.05) / (y + 0.05)
}

/** Below this contrast with the tile, a one-colour icon is drawn in the tile's ink instead. */
const MIN_CONTRAST = 1.6

/**
 * The icon at its place in a `size`-pixel square, in its own colours, on
 * nothing: centred at 60% of the tile. Rasters smaller than half the box
 * scale by whole pixels, without smoothing, so a 16 px favicon stays crisp.
 * A one-colour icon (a mask-icon, a Simple Icon, a black logo) that would
 * vanish into the tile takes the tile's ink.
 */
export function drawIcon(icon: Resolved, size: number, ink: RGBA, tile: RGBA): ImageData {
  const c = document.createElement("canvas")
  c.width = c.height = size
  const ctx = c.getContext("2d", { willReadFrequently: true })!
  let box = Math.round(size * 0.6)
  if (icon.kind === "favicon" && icon.natural && icon.natural * 2 <= box) {
    box = Math.floor(box / icon.natural) * icon.natural
    ctx.imageSmoothingEnabled = false
  } else ctx.imageSmoothingQuality = "high"
  const at = Math.round((size - box) / 2)
  ctx.drawImage(icon.image, at, at, box, box)
  const tintWith = (css: string) => {
    ctx.globalCompositeOperation = "source-in"
    ctx.fillStyle = css
    ctx.fillRect(0, 0, size, size)
    ctx.globalCompositeOperation = "source-over"
  }
  const inkCss = `rgb(${ink[0]} ${ink[1]} ${ink[2]})`
  if (icon.tint !== undefined) {
    const tint = icon.tint ? rgba(icon.tint) : ink
    tintWith(contrast(tint, tile) < MIN_CONTRAST ? inkCss : `rgb(${tint[0]} ${tint[1]} ${tint[2]})`)
    return ctx.getImageData(0, 0, size, size)
  }
  const data = ctx.getImageData(0, 0, size, size)
  const one = oneColour(data.data)
  if (one && contrast(one, tile) < MIN_CONTRAST) {
    tintWith(inkCss)
    return ctx.getImageData(0, 0, size, size)
  }
  return data
}

/** The icon's colour, if all its solid pixels are about one colour. */
function oneColour(d: Uint8ClampedArray): RGBA | null {
  let n = 0
  const sum = [0, 0, 0]
  for (let i = 0; i < d.length; i += 4) {
    if (d[i + 3] < 128) continue
    n++
    sum[0] += d[i]
    sum[1] += d[i + 1]
    sum[2] += d[i + 2]
  }
  if (!n) return null
  const mean: RGBA = [sum[0] / n, sum[1] / n, sum[2] / n, 255]
  for (let i = 0; i < d.length; i += 4) {
    if (d[i + 3] < 128) continue
    if (Math.abs(d[i] - mean[0]) + Math.abs(d[i + 1] - mean[1]) + Math.abs(d[i + 2] - mean[2]) > 60) return null
  }
  return mean
}

/** Bayer's 8×8 ordered-dither matrix, 0–63. */
export const BAYER8 = [
  0, 32, 8, 40, 2, 34, 10, 42, 48, 16, 56, 24, 50, 18, 58, 26,
  12, 44, 4, 36, 14, 46, 6, 38, 60, 28, 52, 20, 62, 30, 54, 22,
  3, 35, 11, 43, 1, 33, 9, 41, 51, 19, 59, 27, 49, 17, 57, 25,
  15, 47, 7, 39, 13, 45, 5, 37, 63, 31, 55, 23, 61, 29, 53, 21,
]

/**
 * One frame of the reveal at `t` (0–1) into `out`: a pixel whose threshold
 * the sweep has passed shows the icon over the tile, first in `ink` (the
 * tile's own one tone), then in its colours; the rest stay clear, so the
 * letter under the canvas shows there. Thresholds are per CSS pixel
 * (`scale` device pixels), so the dots read at any pixel ratio.
 */
export function ditherFrame(out: Uint8ClampedArray, icon: Uint8ClampedArray, size: number, scale: number, t: number, ink: RGBA, tile: RGBA) {
  const mono = Math.min(1, t / 0.6)
  const colour = Math.max(0, (t - 0.4) / 0.6)
  const ta = tile[3] / 255
  for (let y = 0; y < size; y++) {
    const by = (Math.floor(y / scale) & 7) * 8
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4
      const b = (BAYER8[by + (Math.floor(x / scale) & 7)] + 0.5) / 64
      if (b >= mono) {
        out[i + 3] = 0
        continue
      }
      const sa = icon[i + 3] / 255
      const src = b < colour ? [icon[i], icon[i + 1], icon[i + 2]] : [ink[0], ink[1], ink[2]]
      // The icon over the tile, so the letter beneath is hidden here.
      const oa = sa + ta * (1 - sa)
      for (let k = 0; k < 3; k++) out[i + k] = oa ? (src[k] * sa + tile[k] * ta * (1 - sa)) / oa : 0
      out[i + 3] = oa * 255
    }
  }
}

/** How long a reveal takes. */
export const REVEAL_MS = 320

interface Tile {
  el: HTMLElement
  icon: Resolved
}
const live = new Set<Tile>()

/** Draws the icon at rest in `el` (no reveal), at the tile's size and the page's pixel ratio. */
function paint(tile: Tile, canvas: HTMLCanvasElement) {
  const css = tile.el.getBoundingClientRect().width || tile.el.offsetWidth
  if (!css) return false
  const size = Math.round(css * devicePixelRatio)
  canvas.width = canvas.height = size
  const style = getComputedStyle(tile.el)
  const data = drawIcon(tile.icon, size, rgba(style.color), rgba(style.backgroundColor))
  canvas.getContext("2d")!.putImageData(data, 0, 0)
  return true
}

// Light or dark: an icon drawn in the tile's ink follows it.
if (typeof matchMedia === "function")
  matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", () => {
    for (const t of live) {
      if (!t.el.isConnected) live.delete(t)
      else {
        const c = t.el.querySelector("canvas")
        if (c) paint(t, c)
      }
    }
  })

export interface TileOptions {
  /** Dither the icon in as it resolves; false (or reduced motion): it just appears. */
  reveal: boolean
  /** Wait this long before revealing: a list's rows reveal one after another. */
  delay?: number
  /** The kept icon, if the caller has it (see resolveIcon). */
  stored?: StoredIcon | null
  /** Asked every frame: true stops the reveal where it is and shows the icon at rest. */
  stop?: () => boolean
  /** Reveal only if the icon is ready by then (a performance.now() time); after, it just appears. */
  revealBy?: number
  /**
   * Reveal only the first time a tile with this key shows in this page. A
   * tile made again while that reveal runs (the list repainted) carries it
   * on from where it is; after it, the icon just appears.
   */
  once?: string
}

/** When each `once` key's reveal started. */
const firstShown = new Map<string, number>()

/**
 * A login's tile: its letter now, its site's icon once resolved (see the
 * top of this file). Answers the tile, which the caller places as the
 * letter avatar it replaces.
 */
export function siteTile(title: string, url: string, options: TileOptions): HTMLElement {
  const el = avatar(title)
  el.classList.add("site")
  if (!url) return el
  void resolveIcon(url, options.stored).then((icon) => {
    if (!icon) return
    const mount = (tries = 0) => {
      if (!el.isConnected) return tries < 30 ? void requestAnimationFrame(() => mount(tries + 1)) : undefined
      const tile = { el, icon }
      const canvas = document.createElement("canvas")
      canvas.className = "site-icon"
      canvas.setAttribute("aria-hidden", "true")
      if (!paint(tile, canvas)) return tries < 30 ? void requestAnimationFrame(() => mount(tries + 1)) : undefined
      live.add(tile)
      el.append(canvas)
      const now = performance.now()
      let startAt = now
      if (options.once) {
        const first = firstShown.get(options.once)
        if (first === undefined) firstShown.set(options.once, now)
        else if (now - first < REVEAL_MS + (options.delay ?? 0)) startAt = first
        else return void el.classList.add("resolved")
      }
      const late = options.revealBy !== undefined && now > options.revealBy
      if (!options.reveal || late || reducedMotion() || options.stop?.()) return void el.classList.add("resolved")
      reveal(el, canvas, options, startAt + (options.delay ?? 0))
    }
    mount()
  })
  return el
}

function reveal(el: HTMLElement, canvas: HTMLCanvasElement, options: TileOptions, start: number) {
  const ctx = canvas.getContext("2d", { willReadFrequently: true })!
  const size = canvas.width
  const icon = ctx.getImageData(0, 0, size, size)
  const style = getComputedStyle(el)
  const ink = rgba(style.color)
  const tile = rgba(style.backgroundColor)
  const frame = ctx.createImageData(size, size)
  const scale = Math.max(1, Math.round(devicePixelRatio))
  const finish = () => {
    ctx.putImageData(icon, 0, 0)
    el.classList.add("resolved")
  }
  const step = (now: number) => {
    if (!el.isConnected) return
    if (options.stop?.()) return finish()
    const t = Math.max(0, (now - start) / REVEAL_MS)
    if (t >= 1) return finish()
    // A little ease-out: most of the dots arrive early, the last few settle.
    ditherFrame(frame.data, icon.data, size, scale, 1 - (1 - t) ** 1.6, ink, tile)
    ctx.putImageData(frame, 0, 0)
    requestAnimationFrame(step)
  }
  // The first frame now (the letter, or a reveal carried on), then one per frame.
  step(performance.now())
}
