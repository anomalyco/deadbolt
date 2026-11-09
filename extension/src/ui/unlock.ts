// The browser-only Deadbolt's locked row in the inline menu, and the panel
// side of unlocking from it. The row opens the toolbar panel (see
// bg/panel-unlock.ts) and waits by its field while the panel is up; once
// Deadbolt unlocks there, the same menu turns into the logins, so the next
// thing the user does is pick one. The passphrase is never typed here.

import { avatar, h, icon } from "./dom"
import { MENU_MOTION, reducedMotion, REDUCED_FADE, spring, timing } from "./motion"

/** How the row waits, how it turns, and the panel's part: each value is one of the choices still open. */
export const UNLOCK_FEEL = {
  /** The row while the panel it opened is up: "none" stays as it is, "soft" says where to look and its lock breathes, "light" sends a light toward the toolbar. */
  waiting: "soft" as "none" | "soft" | "light",
  /** The row turning into the logins: "crossfade" in place, "emerge" (the rest slide out from behind the first as the frame grows), "open" (its lock opens first). */
  turn: "open" as "crossfade" | "emerge" | "open",
  /** The panel's unlock on its first frame: "rest", or "rise" (fades up into place). */
  panelIn: "rest" as "rest" | "rise",
  /** The panel's lock as Deadbolt unlocks: "swing" (its shackle dips, springs up and swings open, the disc warms to green and a light runs once round it), "lift" (the shackle lifts and the disc warms, nothing else), "check" (the glyph gives way to a check). */
  moment: "swing" as "swing" | "lift" | "check",
  /** Seconds the panel says "Unlocked" before it closes itself; 0 closes it at once. The moment above takes about 0.7. */
  beat: 0.8,
}

const SUB = "Opens in the toolbar"
const WAITING = "Waiting in the toolbar ↗"
/** How long the lock shows open before it gives way to the first login. */
const OPEN_HOLDS = 0.3
/** One breath of the waiting lock, in and out, in ms. */
const BREATH_MS = 1400
/** One pass of the light toward the toolbar, and the pause after it, in ms. */
const LIGHT_MS = 1800

/**
 * Swaps `el`'s text (it holds nothing else) for `text` within its own line:
 * the old line slides up and out as the new one slides in from below, each
 * fading under a soft edge at the line's top and bottom, so the two never
 * show at once in the same place and none of the old is left. The width
 * leads on a slightly quicker spring; nothing is cut at the side.
 */
export function swapText(el: HTMLElement, text: string) {
  const old = el.dataset.text ?? el.textContent ?? ""
  if (old === text) return
  el.dataset.text = text
  if (reducedMotion() || typeof el.animate !== "function" || !el.isConnected) {
    el.textContent = text
    el.animate?.([{ opacity: 0.2 }, { opacity: 1 }], REDUCED_FADE)
    return
  }
  const line = (t: string) => {
    const s = document.createElement("span")
    s.textContent = t
    s.style.cssText = "grid-area:1/1;white-space:pre"
    return s
  }
  const out = line(old)
  const into = line(text)
  out.setAttribute("aria-hidden", "true")
  const win = document.createElement("span")
  win.style.cssText =
    "display:inline-grid;justify-items:start;vertical-align:top;overflow-x:visible;overflow-y:clip;" +
    "mask-image:linear-gradient(to bottom,transparent,#000 22%,#000 78%,transparent)"
  win.append(into, out)
  el.replaceChildren(win)
  // To the fraction of a pixel: a rounded width would let the line step sideways as it lands (it's centred in the panel).
  const [from, to] = [out.getBoundingClientRect().width, into.getBoundingClientRect().width]
  const roll = spring(0.45)
  // A longer line lets the width get ahead before it shows.
  const lead = to > from + 0.5 ? 80 : 0
  // The width holds where it lands until the line is plain text again: let go sooner, it would spring back to the wider of the two.
  if (Math.abs(to - from) > 0.5) win.animate([{ width: `${from}px` }, { width: `${to}px` }], { ...spring(0.37), fill: "forwards" })
  // The old line is gone by half way and the new one shows only from a third: only one is ever readable.
  out.animate([{ transform: "translateY(0)", opacity: 1 }, { opacity: 0, offset: 0.5 }, { transform: "translateY(-100%)", opacity: 0 }], { ...roll, fill: "forwards" })
  into
    .animate([{ transform: "translateY(100%)", opacity: 0 }, { opacity: 0, offset: 0.35 }, { transform: "translateY(0)", opacity: 1 }], { ...roll, delay: lead, fill: "backwards" })
    .finished.then(() => el.dataset.text === text && el.firstChild === win && (el.textContent = text), () => {})
}

/** The locked row: it unlocks in the toolbar panel. `press` runs on a pointer's own click (Enter goes through the menu's keys). */
export function lockedRow(press: () => void): HTMLElement {
  const r = h(
    "button",
    { class: "row unlock", type: "button" },
    avatar("", icon("lock")),
    h("span", { class: "text" }, h("span", { class: "title" }, "Unlock Deadbolt"), h("span", { class: "sub" }, SUB)),
  )
  r.addEventListener("click", (e) => e.isTrusted && e.detail > 0 && press())
  return r
}

/** The row waits on the panel it opened (`on`), or stops: the panel closed without unlocking. */
export function waitOnPanel(rows: HTMLElement, on: boolean) {
  const row = rows.querySelector<HTMLElement>(":scope > .row.unlock")
  if (!row || row.classList.contains("waiting") === on) return
  row.classList.toggle("waiting", on)
  const sub = row.querySelector<HTMLElement>(".sub")
  const feel = UNLOCK_FEEL.waiting
  if (feel === "soft" && sub) swapText(sub, on ? WAITING : SUB)
  if (!on) return cool(row)
  if (reducedMotion()) return
  if (feel === "soft") row.querySelector(".avatar svg")?.animate([{ opacity: 1 }, { opacity: 0.4 }], { duration: BREATH_MS / 2, direction: "alternate", iterations: Infinity, easing: "ease-in-out" })
  if (feel === "light") {
    const light = h("span", { class: "unlock-light", "aria-hidden": "true" })
    row.append(light)
    light.animate(
      [
        { transform: "translate(-30%, 6px)", opacity: 0, offset: 0 },
        { opacity: 1, offset: 0.2 },
        { transform: "translate(230%, -10px)", opacity: 0, offset: 0.62 },
        { transform: "translate(230%, -10px)", opacity: 0, offset: 1 },
      ],
      { duration: LIGHT_MS, iterations: Infinity, easing: "cubic-bezier(.45,0,.2,1)" },
    )
  }
}

/** Whatever the waiting row was doing comes to rest from where it is: the lock back to full, the light fading where it is. */
function cool(row: HTMLElement) {
  const glyph = row.querySelector<SVGElement>(".avatar svg")
  if (glyph?.getAnimations().length) {
    const opacity = getComputedStyle(glyph).opacity
    for (const a of glyph.getAnimations()) a.cancel()
    glyph.animate([{ opacity }, { opacity: 1 }], timing(MENU_MOTION.leave))
  }
  for (const light of Array.from(row.querySelectorAll<HTMLElement>(".unlock-light"))) {
    const opacity = getComputedStyle(light).opacity
    const transform = getComputedStyle(light).transform
    for (const a of light.getAnimations()) a.cancel()
    const out = light.animate([{ opacity, transform }, { opacity: 0, transform }], { duration: 200, easing: "ease-out", fill: "forwards" })
    out.finished.then(() => light.remove(), () => light.remove())
  }
}

let turning = -Infinity

/** Whether the menu is still turning into the logins: a reload meanwhile would cut it (see menu.ts load). */
export const turnInFlight = () => performance.now() < turning

/**
 * Deadbolt unlocked while the locked row `old` showed, and the logins have
 * just replaced it in `rows`: the turn from one to the other, as
 * UNLOCK_FEEL.turn says, on the frame's own height spring (the content
 * script springs the frame to the new size, MENU_MOTION.frameSize). `old`
 * stays where it was, over the first login, while it goes. Returns how long
 * until everything is at rest, in ms: the dwell counts from then.
 */
export function turnIntoLogins(old: HTMLElement, rows: HTMLElement, highlight: HTMLElement): number {
  const list = rows.parentElement
  const surface = rows.closest<HTMLElement>(".surface")
  const fresh = Array.from(rows.children) as HTMLElement[]
  if (!list || !surface || !fresh.length || typeof old.animate !== "function") return 0
  // The breathing lock and the light stop where they are; a line still rolling finishes.
  for (const a of old.querySelector(".avatar svg")?.getAnimations() ?? []) a.cancel()
  old.querySelector(".unlock-light")?.remove()
  old.classList.remove("waiting", "active")
  old.style.cssText = `position:absolute;left:${rows.offsetLeft}px;top:${rows.offsetTop}px;width:${rows.offsetWidth}px;margin:0;pointer-events:none;z-index:1`
  old.setAttribute("aria-hidden", "true")
  old.tabIndex = -1
  list.append(old)
  const feel = reducedMotion() ? "crossfade" : UNLOCK_FEEL.turn
  const hold = feel === "open" ? OPEN_HOLDS : 0
  const [first, ...later] = fresh
  const softIn = reducedMotion() ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, filter: "blur(4px)", transform: "scale(0.96)" }, { opacity: 1, filter: "blur(0px)", transform: "none" }]
  const softOut = reducedMotion() ? [{ opacity: 1 }, { opacity: 0 }] : [{ opacity: 1, filter: "blur(0px)", transform: "none" }, { opacity: 0, filter: "blur(4px)", transform: "scale(0.96)" }]
  // The rows that come in where they are: all of them for a crossfade, else only the one in the locked row's place.
  for (const r of feel === "crossfade" ? fresh : [first]) r.animate(softIn, { ...timing(MENU_MOTION.rowIn), delay: hold * 1000, fill: "backwards" })
  highlight.animate([{ opacity: 0 }, { opacity: 1 }], { ...timing(MENU_MOTION.rowIn), delay: hold * 1000, fill: "backwards" })
  const out = old.animate(softOut, { ...(reducedMotion() ? REDUCED_FADE : timing(MENU_MOTION.leave)), delay: hold * 1000, fill: "forwards" })
  out.finished.then(() => old.remove(), () => old.remove())
  if (feel === "open") {
    openLock(old)
    const line = old.querySelector<HTMLElement>(".sub")
    if (line) swapText(line, "Unlocked")
  }
  // The frame grows on its spring (content/inline.ts), and this document's
  // viewport with it: rows that travel ride its bottom edge and come out from
  // behind the locked row's place; a crossfade's rows are cut by a soft edge
  // just above it, never a hard one. A frame held short of the list (no room
  // under the field) lets go of them once it would have arrived.
  const target = surface.offsetHeight
  const until = performance.now() + MENU_MOTION.frameSize * 1150 + 200
  const riding = feel === "crossfade" ? [] : later
  const slot = rows.offsetTop + first.offsetHeight
  const grid = (v: number) => Math.round(v * 64) / 64
  const step = () => {
    const lift = performance.now() < until ? grid(Math.max(0, target - innerHeight)) : 0
    for (const r of riding) {
      r.style.transform = lift ? `translateY(${-lift}px)` : ""
      const cut = slot - (rows.offsetTop + r.offsetTop - lift)
      // The soft edge narrows to nothing as the row arrives, so letting go of it shows no change.
      r.style.maskImage = lift && cut > -8 ? `linear-gradient(to bottom, transparent ${grid(cut)}px, #000 ${grid(cut + Math.min(8, lift))}px)` : ""
    }
    if (!riding.length) {
      const edge = grid(innerHeight - rows.getBoundingClientRect().top)
      rows.style.maskImage = lift ? `linear-gradient(to bottom, #000 ${edge - 12}px, transparent ${edge}px)` : ""
    }
    if (lift) requestAnimationFrame(step)
  }
  if (!reducedMotion() && target > innerHeight) step()
  const ms = Math.max(MENU_MOTION.frameSize * 1150, (hold + Math.max(MENU_MOTION.rowIn, MENU_MOTION.leave)) * 1150)
  turning = performance.now() + ms
  return ms
}

/** The lock's shackle lifts and swings open on its right leg, and its tile glows green and cools. */
function openLock(row: HTMLElement) {
  const shackle = row.querySelector<SVGPathElement>(".avatar svg path")
  if (shackle) {
    shackle.style.transformBox = "view-box"
    shackle.style.transformOrigin = "15.8px 10.5px"
    shackle.animate([{ transform: "none" }, { transform: "translateY(-2.6px) rotate(-22deg)" }], { ...timing(OPEN_HOLDS), fill: "forwards" })
  }
  row.querySelector(".avatar")?.animate(
    [{}, { backgroundColor: "var(--success-bg)", color: "var(--success)", offset: 0.3 }, {}],
    { duration: 900, easing: "ease-out" },
  )
}
