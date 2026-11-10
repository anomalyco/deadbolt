import { describe, expect, test } from "bun:test"
import { padlock, RISE, slideOpen, tug } from "../src/ui/padlock"

// The panel's padlock opens as a real one does: its shackle slides straight
// up. It never tilts in the plane of the screen.

/** The keyframes the shackle is given, in place of running them. */
function framesOf(run: (lock: HTMLElement) => void): Array<{ transform: string }> {
  const lock = padlock()
  let frames: Array<{ transform: string }> = []
  ;(lock.querySelector(".padlock-shackle") as unknown as { animate: (k: Array<{ transform: string }>) => unknown }).animate = (k) => ((frames = k), {})
  run(lock)
  return frames
}
/** Units up, in the glyph's 24-unit box: the only way the shackle moves. */
const up = (t: string) => {
  const m = /^translateY\((-?[\d.]+)%\)$/.exec(t)
  if (!m) throw new Error(`not a straight slide: ${t}`)
  return (-Number(m[1]) / 100) * 24 + 0
}

describe("the padlock", () => {
  test("opens by sliding straight up until its short foot is clear", () => {
    const poses = framesOf((lock) => slideOpen(lock)).map((f) => up(f.transform))
    expect(poses[0]).toBe(0)
    // Pushed in a touch first, then up past where it rests, and back onto it.
    expect(poses[1]!).toBeLessThan(0)
    expect(Math.max(...poses)).toBeGreaterThan(RISE)
    expect(poses.at(-1)!).toBeCloseTo(RISE, 2)
    // The short foot's ink is 2.7 units deep in the body, the long leg's 6: one comes free, the other never does.
    expect(RISE - 2.7).toBeGreaterThan(2)
    expect(Math.max(...poses)).toBeLessThan(6)
  })

  test("a wrong passphrase tugs it up a fraction and it holds: the short foot stays in its hole", () => {
    const poses = framesOf((lock) => tug(lock)).map((f) => up(f.transform))
    expect(Math.max(...poses)).toBeLessThanOrEqual(1.2)
    expect(poses.at(-1)).toBe(0)
  })
})
