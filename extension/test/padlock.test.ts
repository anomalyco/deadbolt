import { describe, expect, test } from "bun:test"
import { padlock, RISE, slideOpen, tug } from "../src/ui/padlock"

// The panel's padlock opens as a real one does: its shackle slides straight
// up (and may then turn on its long leg, out of the screen). It never tilts
// in the plane of the screen.

/** The keyframes the shackle is given, in place of running them. */
function framesOf(run: (lock: HTMLElement) => void): Array<{ transform: string }> {
  const lock = padlock()
  let frames: Array<{ transform: string }> = []
  ;(lock.querySelector(".padlock-shackle") as unknown as { animate: (k: Array<{ transform: string }>) => unknown }).animate = (k) => ((frames = k), {})
  run(lock)
  return frames
}
const parse = (t: string) => {
  const m = /^translateY\((-?[\d.]+)%\) rotateY\((-?[\d.]+)deg\)$/.exec(t)
  if (!m) throw new Error(`not a slide and a turn on the long leg: ${t}`)
  // Units up, in the glyph's 24-unit box, and degrees round the long leg.
  return { up: (-Number(m[1]) / 100) * 24 + 0, turn: Number(m[2]) + 0 }
}

describe("the padlock", () => {
  test("opens by sliding straight up until its short foot is clear, with no turn and no tilt", () => {
    const poses = framesOf((lock) => slideOpen(lock, false)).map((f) => parse(f.transform))
    expect(poses[0]).toEqual({ up: 0, turn: 0 })
    // Pushed in a touch first, then up past where it rests, and back onto it.
    expect(poses[1]!.up).toBeLessThan(0)
    expect(Math.max(...poses.map((p) => p.up))).toBeGreaterThan(RISE)
    expect(poses.at(-1)!.up).toBeCloseTo(RISE, 2)
    expect(poses.every((p) => p.turn === 0)).toBe(true)
    // The short foot's ink is 2.7 units deep in the body, the long leg's 6: one comes free, the other never does.
    expect(RISE - 2.7).toBeGreaterThan(2)
    expect(Math.max(...poses.map((p) => p.up))).toBeLessThan(6)
  })

  test("turns on its long leg only once it's up, when asked to", () => {
    const poses = framesOf((lock) => slideOpen(lock, true)).map((f) => parse(f.transform))
    const turning = poses.findIndex((p) => p.turn !== 0)
    expect(turning).toBeGreaterThan(0)
    expect(poses.slice(turning).every((p) => Math.abs(p.up - RISE) < 0.01)).toBe(true)
    expect(poses.at(-1)!.turn).toBeLessThan(0)
  })

  test("a wrong passphrase tugs it up a fraction and it holds: the short foot stays in its hole", () => {
    const poses = framesOf((lock) => tug(lock)).map((f) => parse(f.transform))
    expect(Math.max(...poses.map((p) => p.up))).toBeLessThanOrEqual(1.2)
    expect(poses.at(-1)).toEqual({ up: 0, turn: 0 })
    expect(poses.every((p) => p.turn === 0)).toBe(true)
  })
})
