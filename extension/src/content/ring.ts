// Points at something on the page for the user to click themselves: the
// site's "Sign in with Google" button, or the account's tile on the
// provider's chooser. A ring around it and a small pill, drawn by Deadbolt in
// a closed shadow root on its own element (nothing of the page is changed;
// the page can see that an element appeared, not what it says). It lets
// clicks through, follows the target as the page lays out, and goes on any
// click, Escape, the target scrolling away, or after a few seconds.

import { reducedMotion, timing } from "../ui/motion"
import { markOwnHost } from "./shadow"

const STAYS_MS = 10_000
const BRAND = "#f02e29"

let host: HTMLElement | null = null
let raf = 0
let timer: ReturnType<typeof setTimeout> | undefined
let off: (() => void) | null = null

const KEYHOLE = `<svg viewBox="0 0 24 24" width="12" height="12" aria-hidden="true"><circle cx="12" cy="8.6" r="4.1" fill="${BRAND}"/><path d="M10.4 11.4h3.2l1.5 7.5H8.9Z" fill="${BRAND}"/></svg>`

export function hideRing() {
  cancelAnimationFrame(raf)
  clearTimeout(timer)
  off?.()
  off = null
  host?.remove()
  host = null
}

/** Rings `target` with a pill saying `label` (generic: the page may read nothing new from it). */
export function showRing(target: Element, label: string) {
  hideRing()
  const dark = matchMedia("(prefers-color-scheme: dark)").matches
  const r0 = target.getBoundingClientRect()
  if (r0.bottom < 0 || r0.top > innerHeight || r0.right < 0 || r0.left > innerWidth) target.scrollIntoView({ block: "center", behavior: reducedMotion() ? "auto" : "smooth" })

  host = document.createElement("div")
  host.style.cssText = "all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483647;display:block;"
  markOwnHost(host)
  const root = host.attachShadow({ mode: "closed" })
  const ring = document.createElement("div")
  const pill = document.createElement("div")
  const radius = Math.max(10, (parseFloat(getComputedStyle(target).borderTopLeftRadius) || 0) + 4)
  ring.style.cssText = `position:fixed;box-sizing:border-box;border:2px solid ${BRAND};border-radius:${radius}px;box-shadow:0 0 0 4px rgb(240 46 41 / ${dark ? 30 : 18}%);pointer-events:none;`
  pill.style.cssText = `position:fixed;display:flex;align-items:center;gap:6px;height:24px;padding:0 10px 0 8px;border-radius:12px;font:500 12px/16px "Inter",-apple-system,BlinkMacSystemFont,system-ui,sans-serif;white-space:nowrap;pointer-events:none;${dark ? "background:#161616;color:#fafafa;box-shadow:0 0 0 0.5px rgb(255 255 255 / 14%),0 4px 12px rgb(0 0 0 / 50%);" : "background:#fff;color:#161616;box-shadow:0 0 0 0.5px rgb(0 0 0 / 12%),0 4px 12px rgb(0 0 0 / 12%);"}`
  pill.innerHTML = KEYHOLE
  pill.append(document.createTextNode(label))
  root.append(ring, pill)
  document.documentElement.append(host)

  const startedAt = performance.now()
  const place = () => {
    if (!host) return
    if (!target.isConnected) return hideRing()
    const r = target.getBoundingClientRect()
    const gone = r.bottom < 0 || r.top > innerHeight || r.right < 0 || r.left > innerWidth
    // Once it has had a moment to scroll into view, the target scrolling away ends it.
    if (gone && performance.now() - startedAt > 1200) return hideRing()
    ring.style.left = `${r.left - 4}px`
    ring.style.top = `${r.top - 4}px`
    ring.style.width = `${r.width + 8}px`
    ring.style.height = `${r.height + 8}px`
    const above = r.top - 34 > 4
    pill.style.top = `${above ? r.top - 34 : r.bottom + 10}px`
    pill.style.left = `${Math.max(4, Math.min(r.right + 4 - pill.offsetWidth, innerWidth - pill.offsetWidth - 4))}px`
    raf = requestAnimationFrame(place)
  }
  place()
  const enter = reducedMotion() ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, transform: "scale(1.04)" }, { opacity: 1, transform: "none" }]
  ring.animate(enter, timing(0.25))
  pill.animate(reducedMotion() ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, transform: "translateY(4px)" }, { opacity: 1, transform: "none" }], timing(0.3))

  timer = setTimeout(hideRing, STAYS_MS)
  // Any click (the user's own, on the target or not) or Escape: done.
  const onDown = (e: Event) => e.isTrusted && hideRing()
  const onKey = (e: KeyboardEvent) => e.isTrusted && e.key === "Escape" && hideRing()
  addEventListener("pointerdown", onDown, true)
  addEventListener("keydown", onKey, true)
  off = () => {
    removeEventListener("pointerdown", onDown, true)
    removeEventListener("keydown", onKey, true)
  }
}

/** Whether a ring is showing (for tests and the content script). */
export const ringShown = () => host !== null
