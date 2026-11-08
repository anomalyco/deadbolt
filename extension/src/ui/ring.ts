// The ring round a picked avatar while its fill is on the way: a comet, a
// bright head with a tail that fades behind it, turning round a faint track.
// It never appears or goes in one frame. When the fill lands it turns green
// and its head catches its tail, filling the ring in whole (MENU_FEEL.ring
// adds a light running round it, or a ring of light sinking into the tile;
// "away" speeds it off and fades it instead). The tile's ground flashes green
// with it. When the fill doesn't land, it fades and shrinks away.
//
// While it turns, everything is rotate, scale and opacity, which the
// compositor runs, so it stays smooth while the menu's thread folds the
// frame. Green is a second comet that crossfades in. Only the closing, once
// the fold is over, draws its gradient anew each frame.

import { MENU_FEEL, MENU_MOTION, reducedMotion, spring, timing } from "./motion"

const span = (cls: string) => {
  const s = document.createElement("span")
  s.className = cls
  return s
}

export interface Ring {
  /** The fill landed: the comet turns green and closes into a whole ring (or speeds away), and the tile flashes green. `then` runs as it starts. */
  close(then?: () => void): void
  /** It didn't: the ring fades and shrinks away. `then` runs as it starts going. */
  stop(then?: () => void): void
}

/** Starts the ring on `avatar` (which must be positioned). */
export function ring(avatar: HTMLElement): Ring {
  const reduced = reducedMotion()
  const lands = MENU_FEEL.ring
  // wrap: comes and goes. spin: turns steadily. boost: the extra turn as it speeds away. Two comets, crossfaded.
  const wrap = span("ring")
  wrap.setAttribute("aria-hidden", "true")
  const track = span("ring-track")
  const spin = span("ring-spin")
  const boost = span("ring-spin")
  const comet = span("ring-comet")
  const lit = span("ring-comet lit")
  comet.style.setProperty("--tail", `${MENU_FEEL.tail}turn`)
  lit.style.setProperty("--tail", `${lands === "away" ? Math.min(0.85, MENU_FEEL.tail * 1.8) : MENU_FEEL.tail}turn`)
  lit.style.opacity = "0"
  boost.append(comet, lit)
  spin.append(boost)
  wrap.append(track, spin)
  avatar.append(wrap)

  const turn = reduced ? null : spin.animate([{ rotate: "0turn" }, { rotate: "1turn" }], { duration: MENU_FEEL.turn * 1000, iterations: Infinity })
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
  return { close: (then) => end(lands === "away" ? awayNow : closeNow, then), stop: (then) => end(stopNow, then) }

  /** The tile's ground flashes green and cools; it keeps its logo. */
  function flashTile(delay = 0) {
    const ground = getComputedStyle(avatar).backgroundColor
    avatar.animate(
      [{ backgroundColor: ground }, { backgroundColor: "color-mix(in srgb, var(--text-success) 32%, transparent)", offset: 0.3 }, { backgroundColor: ground }],
      { duration: MENU_MOTION.ringFlash * 1000, easing: "ease-out", delay, fill: "backwards" },
    )
  }

  /** The grey comet gives way to the green one. */
  function goGreen(duration: number) {
    const swap = { duration: reduced ? 180 : duration, easing: "ease-out", fill: "forwards" } as const
    lit.animate([{ opacity: 0 }, { opacity: 1 }], swap)
    comet.animate([{ opacity: 1 }, { opacity: 0 }], swap)
  }

  function closeNow() {
    wrap.classList.add("ok")
    goGreen(150)
    // The head runs on and catches its tail; what it leaves behind fills in.
    const whole = spring(MENU_MOTION.ringWhole)
    lit.style.setProperty("--tail", "1turn")
    lit.style.setProperty("--solid", "1")
    if (!reduced)
      lit.animate(
        [
          { "--tail": `${MENU_FEEL.tail}turn`, "--solid": 0 },
          { "--tail": "1turn", "--solid": 1 },
        ],
        whole,
      )
    track.animate([{ opacity: 1 }, { opacity: 0 }], { duration: reduced ? 180 : whole.duration, fill: "forwards" })
    // Whole, its turning can't be seen: it stops there.
    if (turn) setTimeout(() => turn.pause(), whole.duration)
    const closed = reduced ? 0 : whole.duration * 0.6
    if (lands === "glint" && !reduced) glint(closed)
    if (lands === "absorb" && !reduced) return absorb(closed)
    flashTile()
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

  /** A ring of light sinks from the closed ring into the tile, which nods as it takes it, and flashes. */
  function absorb(delay: number) {
    const ping = span("ring-ping")
    ping.style.opacity = "0"
    wrap.append(ping)
    const sink = 320
    ping
      .animate([{ scale: "1", opacity: 0.9 }, { scale: "0.7", opacity: 0 }], { duration: sink, delay, easing: "cubic-bezier(.5,0,.75,0)", fill: "backwards" })
      .finished.then(() => ping.remove(), () => ping.remove())
    const marks = Array.from(avatar.children).filter((c) => c !== wrap) as HTMLElement[]
    for (const m of marks)
      m.animate([{ scale: "1" }, { scale: "0.84", offset: 0.35, easing: "cubic-bezier(.2,.7,.3,1)" }, { scale: "1" }], { duration: 480, delay: delay + sink * 0.7, easing: "cubic-bezier(.4,0,.6,1)" })
    flashTile(delay + sink * 0.7)
  }

  function awayNow() {
    wrap.classList.add("ok")
    const away = MENU_MOTION.ringClose * 1000
    flashTile()
    goGreen(away * 0.35)
    // Speeding up from its own pace, never a jump: an extra turn that starts at rest and gathers speed.
    if (!reduced) boost.animate([{ rotate: "0turn" }, { rotate: `${MENU_FEEL.landTurns}turn` }], { duration: away, easing: "cubic-bezier(.4,0,.8,.5)", fill: "forwards" })
    // It fades on the move, a light cooling as it goes.
    const out = wrap.animate(reduced ? [{ opacity: 1 }, { opacity: 0 }] : [{ opacity: 1, scale: "1" }, { opacity: 0, scale: "1.04" }], {
      duration: reduced ? 300 : away * 0.7,
      delay: reduced ? 180 : away * 0.3,
      easing: "cubic-bezier(.4,0,.6,1)",
      fill: "forwards",
    })
    out.finished.then(() => turn?.cancel(), () => {})
  }

  function stopNow() {
    const out = wrap.animate(reduced ? [{ opacity: 1 }, { opacity: 0 }] : [{ opacity: 1, scale: "1" }, { opacity: 0, scale: "0.9" }], { ...timing(MENU_MOTION.ringOut), fill: "forwards" })
    out.finished.then(() => {
      turn?.cancel()
      wrap.remove()
    }, () => {})
  }
}
