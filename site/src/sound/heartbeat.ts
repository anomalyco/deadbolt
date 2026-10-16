import { play } from "./sound"

// The masthead's heartbeat, in step with the keyhole print's thump. The shader beats when
// `fract(time * pulseRate)` wraps (the lub), with the dub 0.16 of a beat later; this listens to the
// same clock and plays `heartbeat` on each wrap. Call it from the print's frame callback, so it only
// runs while the print is on screen and moving.

export interface HeartbeatFrame {
  /** The shader's beats per second of shader time (`pulseRate`). */
  readonly rate: number
  /** Shader seconds per real second (`speed`), so the dub lands where the print's does. */
  readonly speed?: number
  /** Level multiplier: the print's `beat` over its default (0 is silent). */
  readonly strength?: number
}

export function createHeartbeat() {
  let last: number | null = null
  return (clock: number, { rate, speed = 1, strength = 1 }: HeartbeatFrame) => {
    const prev = last
    last = clock
    if (prev === null || !(clock > prev) || clock - prev > 0.25 || rate <= 0 || speed <= 0 || strength <= 0) return
    if (Math.floor(clock * rate) !== Math.floor(prev * rate))
      play("heartbeat", { gain: Math.min(2, strength), gap: 0.16 / (rate * speed) })
  }
}
