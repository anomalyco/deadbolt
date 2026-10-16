import { play } from "./sound"

// The masthead's heartbeat, in step with the keyhole print's thump. The shader beats when its beat phase (the beats
// elapsed: `pulseRate` integrated over print time) wraps (the lub), with the dub 0.16 of a beat later; this listens
// to the same phase and plays `heartbeat` on each wrap. Call it from the print's frame callback, so it only runs
// while the print is on screen and moving.

export interface HeartbeatFrame {
  /** The shader's beats per second of print time (`pulseRate`, as it glides). */
  readonly rate: number
  /** Print seconds per real second (`speed`), so the dub lands where the print's does. */
  readonly speed?: number
  /** Level multiplier: the print's `beat` over its default (0 is silent). */
  readonly strength?: number
}

export function createHeartbeat() {
  let last: number | null = null
  return (beats: number, { rate, speed = 1, strength = 1 }: HeartbeatFrame) => {
    const prev = last
    last = beats
    if (prev === null || !(beats > prev) || beats - prev > 0.5 || rate <= 0 || speed <= 0 || strength <= 0) return
    if (Math.floor(beats) !== Math.floor(prev))
      play("heartbeat", { gain: Math.min(2, strength), gap: 0.16 / (rate * speed) })
  }
}
