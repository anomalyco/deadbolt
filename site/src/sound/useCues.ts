import { useEffect, useLayoutEffect, useRef, useSyncExternalStore, type RefObject } from "react"
import type { MotionValue } from "motion/react"
import { isEnabled, play, subscribe, type Cue, type CueDetail } from "./sound"
import { createSendVoice, type SendVoice } from "./voice"

// Sounds for a diagram driven by a scrubbable clock. Each cue plays when the clock crosses its time
// while the diagram plays forward. A jump (a seek, a scrub, a step click, the loop starting over) is
// not playing: the cues it skips stay silent, and instead the step bar ticks (`step` landing on or
// crossing a step, `scrub` across the detents between). Nothing plays while the diagram is off screen.

/** A moment in a scene's clock (seconds) and the cue it plays. */
export type SceneCue = { readonly at: number; readonly cue: Cue; readonly detail?: CueDetail }

/** A stretch of the clock where the send voice follows light from `from` to `to` (seconds). */
export type Flight = {
  readonly from: number
  readonly to: number
  /** A fixed pan, or [pan at `from`, pan at `to`] (−1 left to 1 right). */
  readonly pan?: number | readonly [number, number]
  readonly gain?: number
  readonly pitch?: number
}

export interface CueOptions {
  /** The diagram's element: sounds play only while at least a quarter of it is on screen. */
  readonly host?: RefObject<Element | null>
  /**
   * When the scene's last step ends. The clock running past it is the end hold or fade, so a jump
   * from there back to the start is the loop restarting: silent. Also scales `scrub`'s pitch.
   */
  readonly duration?: number
  /** Step start times: a jump that lands on or crosses one ticks `step`, pitched by its index. */
  readonly steps?: readonly number[]
  /** Tick `scrub` on other jumps (on by default; needs `duration`). */
  readonly scrub?: boolean
  /** Where the send voice follows light. */
  readonly flights?: readonly Flight[]
  /** Level multiplier for the whole scene. */
  readonly gain?: number
  /** True while the user is dragging the clock, so a slow forward drag isn't taken for playing. */
  readonly scrubbing?: () => boolean
}

/** The longest clock step (s) that still counts as playing; the stories cap a frame at 0.1 s. */
export const PLAY_STEP = 0.12
/** How many `scrub` detents across the whole clock. */
const DETENTS = 40
/** With no forward frame for this long (ms), the voice lets go (the clock is held or paused). */
const STALL = 140

/** The cues whose time falls in [before, now): each played once as the clock runs forward. */
export function crossed(cues: readonly SceneCue[], before: number, now: number): SceneCue[] {
  if (!(now > before)) return []
  return cues.filter((c) => c.at >= before && c.at < now)
}

const lerp = (a: number, b: number, k: number) => a + (b - a) * k

/** The follower behind `useCues`, framework-free: call `observe(clock)` whenever the clock changes. */
export function createCueFollower(read: () => { cues: readonly SceneCue[]; options: CueOptions; onScreen: boolean }) {
  let last: { t: number; wall: number } | null = null
  let voice: SendVoice | null = null
  let stall: ReturnType<typeof setTimeout> | undefined
  const quiet = (fast = false) => {
    clearTimeout(stall)
    voice?.silence(fast)
  }

  return {
    observe(t: number, wall = performance.now()) {
      const prev = last
      last = { t, wall }
      if (!prev || t === prev.t) return
      const { cues, options, onScreen } = read()
      if (!isEnabled() || !onScreen) {
        quiet(true)
        return
      }
      const dt = t - prev.t
      const dWall = (wall - prev.wall) / 1000
      const gain = options.gain ?? 1
      const playing = dt > 0 && dt <= PLAY_STEP && dt <= dWall * 1.3 + 0.01 && !options.scrubbing?.()
      if (playing) {
        for (const c of crossed(cues, prev.t, t)) play(c.cue, { ...c.detail, gain: (c.detail?.gain ?? 1) * gain })
        const flight = options.flights?.find((f) => t >= f.from && t < f.to)
        if (flight) {
          const progress = (t - flight.from) / Math.max(1e-6, flight.to - flight.from)
          const pan = typeof flight.pan === "number" ? flight.pan : flight.pan ? lerp(flight.pan[0], flight.pan[1], progress) : 0
          voice ??= createSendVoice()
          voice.follow({ progress, pan, gain: (flight.gain ?? 1) * gain, pitch: flight.pitch ?? 1 })
          clearTimeout(stall)
          stall = setTimeout(() => voice?.silence(), STALL)
        } else quiet()
        return
      }
      // A jump.
      quiet(true)
      const { duration, steps } = options
      if (duration !== undefined && prev.t >= duration && t < prev.t) return
      if (steps?.length) {
        const lo = Math.min(prev.t, t)
        const hi = Math.max(prev.t, t)
        let hit = -1
        steps.forEach((s, i) => {
          if (s === t || (s > lo && s <= hi)) if (hit < 0 || Math.abs(s - t) < Math.abs(steps[hit]! - t)) hit = i
        })
        if (hit >= 0) {
          play("step", { position: steps.length > 1 ? hit / (steps.length - 1) : 0.5, gain })
          return
        }
      }
      if (options.scrub !== false && duration) {
        const cell = (x: number) => Math.floor((Math.min(x, duration) / duration) * DETENTS)
        if (cell(prev.t) !== cell(t)) play("scrub", { position: Math.min(1, t / duration), gain })
      }
    },
    /** Lets the voice go now (the clock stopped, the scene left the screen). */
    silence: () => quiet(true),
    dispose() {
      clearTimeout(stall)
      voice?.dispose()
      voice = null
    },
  }
}

const isMotionValue = (v: unknown): v is MotionValue<number> =>
  typeof v === "object" && v !== null && typeof (v as MotionValue<number>).on === "function"

/**
 * Plays `cues` as `clock` runs forward. `clock` is the scene's time in seconds: a motion value, or a
 * plain number passed on every render (as `Story` re-renders each frame).
 */
export function useCues(clock: MotionValue<number> | number, cues: readonly SceneCue[], options: CueOptions = {}): void {
  const latest = useRef({ cues, options, onScreen: !options.host })
  latest.current.cues = cues
  latest.current.options = options
  const follower = useRef<ReturnType<typeof createCueFollower> | null>(null)
  follower.current ??= createCueFollower(() => latest.current)

  // First, so a remount (React's strict mode runs effects twice) has a follower before it subscribes.
  useEffect(() => {
    follower.current ??= createCueFollower(() => latest.current)
    return () => {
      follower.current?.dispose()
      follower.current = null
    }
  }, [])

  const host = options.host
  useEffect(() => {
    const element = host?.current
    if (!element) {
      latest.current.onScreen = true
      return
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        latest.current.onScreen = Boolean(entry?.isIntersecting)
        if (!latest.current.onScreen) follower.current?.silence()
      },
      { threshold: 0.25 },
    )
    observer.observe(element)
    return () => observer.disconnect()
  }, [host])

  useEffect(() => {
    if (!isMotionValue(clock)) return
    follower.current?.observe(clock.get())
    return clock.on("change", (t) => follower.current?.observe(t))
  }, [clock])

  const value = isMotionValue(clock) ? undefined : clock
  useLayoutEffect(() => {
    if (value !== undefined) follower.current?.observe(value)
  }, [value])

}

/** Whether the visitor has sound on, as React state. */
export const useSoundEnabled = () => useSyncExternalStore(subscribe, isEnabled, () => false)
