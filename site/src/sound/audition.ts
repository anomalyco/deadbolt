import { cues, describe, type Cue, type CueDetail } from "./recipes"
import { isEnabled, play, setEnabled } from "./sound"
import { createSendVoice } from "./voice"

// Hearing the palette: every cue in turn, and a light's flight with the send voice. In development
// the page also gets `window.__deadboltSound` (play, audition, flight, cues) for the console.

/** Pauses after each cue in the audition (s): long enough for its tail. */
const after: Partial<Record<Cue, number>> = { unlock: 1.3, join: 1.2, heartbeat: 1.4, scrub: 0.5 }

/** The send voice following light from left to right over `seconds`, landing with `land`. */
export function flight(seconds = 1.4): () => void {
  if (!isEnabled()) setEnabled(true)
  const voice = createSendVoice()
  const start = performance.now()
  let raf = 0
  play("send", { pan: -0.8 })
  const tick = (now: number) => {
    const p = (now - start) / 1000 / seconds
    if (p >= 1) {
      voice.silence(true)
      play("land", { pan: 0.8 })
      setTimeout(() => voice.dispose(), 400)
      return
    }
    voice.follow({ progress: p, pan: -0.8 + 1.6 * p })
    raf = requestAnimationFrame(tick)
  }
  raf = requestAnimationFrame(tick)
  return () => {
    cancelAnimationFrame(raf)
    voice.dispose()
  }
}

/** A cue's audition: some play a short phrase so their detail is heard (pan, position). */
function phrase(cue: Cue, wait: (s: number, f: () => void) => void) {
  const at = (s: number, detail: CueDetail = {}, which: Cue = cue) => wait(s, () => play(which, detail))
  switch (cue) {
    case "step":
      ;[0, 0.25, 0.5, 0.75, 1].forEach((position, i) => at(i * 0.2, { position }))
      return 1
    case "scrub":
      for (let i = 0; i < 14; i++) at(i * 0.045, { position: i / 13 })
      return 0.63
    case "write":
      ;[-0.6, -0.2, 0.2, 0.6].forEach((pan, i) => at(i * 0.16, { pan }))
      return 0.64
    case "heartbeat":
      at(0)
      at(2.2)
      return 2.2
    default:
      at(0)
      return 0
  }
}

/** Plays every cue in turn (or those listed), with its name in the console. Returns a stop. */
export function audition(list: readonly Cue[] = cues, onCue?: (cue: Cue | null) => void): () => void {
  if (!isEnabled()) setEnabled(true)
  const timers: ReturnType<typeof setTimeout>[] = []
  const wait = (s: number, f: () => void) => timers.push(setTimeout(f, s * 1000))
  let t = 0.15
  for (const cue of list) {
    const start = t
    wait(start, () => {
      onCue?.(cue)
      console.info(`[sound] ${cue}: ${describe[cue]}`)
    })
    const length = phrase(cue, (s, f) => wait(start + s, f))
    t = start + length + (after[cue] ?? 0.9)
  }
  wait(t, () => onCue?.(null))
  return () => {
    for (const timer of timers) clearTimeout(timer)
    onCue?.(null)
  }
}

/** Puts the palette on `window.__deadboltSound` (development only). */
export function install() {
  ;(window as Window & { __deadboltSound?: unknown }).__deadboltSound = { play, audition, flight, cues, describe }
}
