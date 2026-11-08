// The ring round a picked avatar while its fill is on the way. It never
// appears or goes in one frame: its arc draws on from nothing as it starts
// turning, closes into a green circle when the fill lands (the tile's ground
// flashes green with it) and then cools away, or draws back to nothing when
// it doesn't.

import { MENU_MOTION, reducedMotion, spring, timing } from "./motion"

const NS = "http://www.w3.org/2000/svg"

/** How much of the circle the turning arc covers, out of 100. */
const ARC = 26
/** One turn of the arc, in milliseconds. */
const TURN_MS = 900
/** How long the closed green circle stays before it cools away. */
const RING_HOLDS_MS = 250

function el<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Record<string, string>): SVGElementTagNameMap[K] {
  const e = document.createElementNS(NS, tag)
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v)
  return e
}

export interface Ring {
  /** The fill landed: the arc closes into a green circle, the tile flashes green, and the ring cools away. */
  close(): void
  /** It didn't: the arc draws back to nothing and the ring goes. */
  stop(): void
}

/** Starts the ring on `avatar` (which must be positioned). */
export function ring(avatar: HTMLElement): Ring {
  const reduced = reducedMotion()
  const wrap = document.createElement("span")
  wrap.className = "ring"
  wrap.setAttribute("aria-hidden", "true")
  const svg = el("svg", { class: "ring-turn", viewBox: "0 0 40 40" })
  const circle = { cx: "20", cy: "20", r: "18.5", pathLength: "100" }
  const track = el("circle", { ...circle, class: "track" })
  const arc = el("circle", { ...circle, class: "arc" })
  svg.append(track, arc)
  wrap.append(svg)
  avatar.append(wrap)

  const dash = (n: number) => `${n} 100`
  arc.style.strokeDasharray = dash(reduced ? ARC : 0)
  const turn = reduced ? null : svg.animate([{ transform: "rotate(0deg)" }, { transform: "rotate(360deg)" }], { duration: TURN_MS, iterations: Infinity })
  wrap.animate(reduced ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, transform: "scale(0.9)" }, { opacity: 1, transform: "none" }], timing(MENU_MOTION.ringIn))
  // The arc grows from nothing as it turns, so it never pops in at full length.
  const draw = (to: number, duration: number) => {
    const from = getComputedStyle(arc).strokeDasharray
    for (const a of arc.getAnimations()) a.cancel()
    arc.style.strokeDasharray = dash(to)
    if (!reduced) arc.animate([{ strokeDasharray: from }, { strokeDasharray: dash(to) }], spring(duration))
  }
  if (!reduced) draw(ARC, MENU_MOTION.ringIn)

  // A fill that lands at once still lets the arc draw on first, so the ring
  // reads as a beat of its own instead of flashing straight to its end.
  const born = performance.now()
  const after = (go: () => void) => {
    const wait = born + MENU_MOTION.ringIn * 1000 - performance.now()
    if (wait > 0) setTimeout(go, wait)
    else go()
  }
  let ended = false
  return {
    close() {
      if (ended) return
      ended = true
      after(closeNow)
    },
    stop() {
      if (ended) return
      ended = true
      after(stopNow)
    },
  }

  function closeNow() {
    wrap.classList.add("ok")
    draw(100, MENU_MOTION.ringClose)
    const closed = spring(MENU_MOTION.ringClose).duration
    // The tile keeps its logo: its ground flashes green as the circle closes, and cools.
    const ground = getComputedStyle(avatar).backgroundColor
    avatar.animate(
      [{ backgroundColor: ground }, { backgroundColor: "color-mix(in srgb, var(--text-success) 32%, transparent)", offset: 0.3 }, { backgroundColor: ground }],
      { duration: MENU_MOTION.ringFlash * 1000, easing: "ease-out" },
    )
    // Whole and green for a moment, then the ring cools away; it stays in place, unseen.
    const out = wrap.animate(reduced ? [{ opacity: 1 }, { opacity: 0 }] : [{ opacity: 1, transform: "none" }, { opacity: 0, transform: "scale(0.96)" }], {
      ...timing(MENU_MOTION.ringOut),
      delay: closed + RING_HOLDS_MS,
      fill: "forwards",
    })
    out.finished.then(() => turn?.cancel(), () => {})
  }

  function stopNow() {
    if (!reduced) draw(0, MENU_MOTION.ringOut)
    const out = wrap.animate(reduced ? [{ opacity: 1 }, { opacity: 0 }] : [{ opacity: 1, transform: "none" }, { opacity: 0, transform: "scale(0.9)" }], { ...timing(MENU_MOTION.ringOut), fill: "forwards" })
    out.finished.then(() => {
      turn?.cancel()
      wrap.remove()
    }, () => {})
  }
}
