// The ring round a picked avatar while its fill is on the way: a comet, a
// bright head with a tail that fades behind it, turning round a faint track.
// It never appears or goes in one frame. When the fill lands it turns green
// as its head slows to rest on its tail, filling the ring in whole, a light
// runs once round it, and the tile's ground flashes green with it. When the
// fill doesn't land, it fades and shrinks away.
//
// While it turns, everything is rotate, scale and opacity, which the
// compositor runs, so it stays smooth while the menu's thread folds the
// frame. Green is a second comet that crossfades in. Only the closing, once
// the fold is over, draws its gradient anew each frame.

import { MENU_MOTION, reducedMotion, timing } from "./motion"

const span = (cls: string) => {
  const s = document.createElement("span")
  s.className = cls
  return s
}

/** One turn of the comet, in seconds. */
const TURN = 0.65
/** How much of the circle the comet's tail covers, in turns. */
const TAIL = 0.4

export interface Ring {
  /** The fill landed: the comet turns green and closes into a whole ring, and the tile flashes green. `then` runs as it starts. */
  close(then?: () => void): void
  /** It didn't: the ring fades and shrinks away. `then` runs as it starts going. */
  stop(then?: () => void): void
}

/** Starts the ring on `avatar` (which must be positioned). */
export function ring(avatar: HTMLElement): Ring {
  const reduced = reducedMotion()
  // wrap: comes and goes. spin: turns steadily. Two comets, crossfaded.
  const wrap = span("ring")
  wrap.setAttribute("aria-hidden", "true")
  const track = span("ring-track")
  const spin = span("ring-spin")
  const comet = span("ring-comet")
  const lit = span("ring-comet lit")
  for (const c of [comet, lit]) c.style.setProperty("--tail", `${TAIL}turn`)
  lit.style.opacity = "0"
  spin.append(comet, lit)
  wrap.append(track, spin)
  avatar.append(wrap)

  const turn = reduced ? null : spin.animate([{ rotate: "0turn" }, { rotate: "1turn" }], { duration: TURN * 1000, iterations: Infinity })
  wrap.animate(reduced ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, scale: "0.9" }, { opacity: 1, scale: "1" }], timing(MENU_MOTION.ringIn))

  // A fill that lands at once still lets the comet come in first, so the
  // ring reads as a beat of its own instead of flashing straight to its end.
  const born = performance.now()
  const after = (go: () => void) => {
    const wait = born + MENU_MOTION.ringIn * 1000 - performance.now()
    if (wait > 0) setTimeout(go, wait)
    else go()
  }
  let ended = false
  const end = (go: () => void, then?: () => void) => {
    if (ended) return
    ended = true
    after(() => {
      go()
      then?.()
    })
  }
  return { close: (then) => end(closeNow, then), stop: (then) => end(stopNow, then) }

  /**
   * The head catches its tail. The turning stops where it is and, from that
   * frame, the head and the tail are drawn by one animation on one thread: the
   * tail's end holds still while the head eases to rest on it, and what it
   * leaves behind fills in. Its length growing on the main thread while the
   * compositor turned it is what made it close unevenly and jitter.
   */
  function closeNow() {
    wrap.classList.add("ok")
    const period = TURN * 1000
    const at = turn ? (Number(turn.currentTime ?? 0) % period) / period : 0
    turn?.cancel()
    spin.style.rotate = `${at}turn`
    const gap = 1 - TAIL
    // At its own pace the head covers the gap in gap × period; easing to rest from that pace takes twice as long.
    const close = { duration: Math.round(gap * period * 2), easing: "cubic-bezier(.333,.667,.667,1)" }
    const arcs = [comet, lit]
    for (const c of arcs) {
      c.style.setProperty("--head", `${gap}turn`)
      c.style.setProperty("--tail", "1turn")
      c.style.setProperty("--solid", "1")
    }
    const swap = { duration: reduced ? 180 : close.duration * 0.7, easing: "ease-out", fill: "forwards" } as const
    lit.animate([{ opacity: 0 }, { opacity: 1 }], swap)
    comet.animate([{ opacity: 1 }, { opacity: 0 }], swap)
    track.animate([{ opacity: 1 }, { opacity: 0 }], { duration: reduced ? 180 : close.duration, fill: "forwards" })
    if (!reduced) {
      for (const c of arcs)
        c.animate(
          [
            { "--head": "0turn", "--tail": `${TAIL}turn`, "--solid": 0 },
            { "--head": `${gap}turn`, "--tail": "1turn", "--solid": 1 },
          ],
          close,
        )
      glint(close.duration)
    }
    flashTile()
  }

  /** The tile's ground flashes green and cools; it keeps its logo. */
  function flashTile() {
    const ground = getComputedStyle(avatar).backgroundColor
    avatar.animate(
      [{ backgroundColor: ground }, { backgroundColor: "color-mix(in srgb, var(--text-success) 32%, transparent)", offset: 0.3 }, { backgroundColor: ground }],
      { duration: MENU_MOTION.ringFlash * 1000, easing: "ease-out" },
    )
  }

  /** A short light runs once round the closed ring, and goes. */
  function glint(delay: number) {
    const light = span("ring-comet glint")
    light.style.setProperty("--tail", "0.22turn")
    light.style.opacity = "0"
    wrap.append(light)
    light
      .animate(
        [
          { rotate: "0turn", opacity: 0 },
          { opacity: 1, offset: 0.2 },
          { opacity: 1, offset: 0.65 },
          { rotate: "1turn", opacity: 0 },
        ],
        { duration: 750, delay, easing: "cubic-bezier(.45,0,.25,1)" },
      )
      .finished.then(() => light.remove(), () => light.remove())
  }

  function stopNow() {
    const out = wrap.animate(reduced ? [{ opacity: 1 }, { opacity: 0 }] : [{ opacity: 1, scale: "1" }, { opacity: 0, scale: "0.9" }], { ...timing(MENU_MOTION.ringOut), fill: "forwards" })
    out.finished.then(() => {
      turn?.cancel()
      wrap.remove()
    }, () => {})
  }
}
