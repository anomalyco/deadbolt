// Deadbolt's sound effects: a tiny Web Audio synth, no files (the cues are in recipes.ts).
//
// Off until the visitor turns it on; the choice is kept in localStorage and follows other tabs. One
// AudioContext, made on the first user gesture after sound is wanted (never before, so browsers don't
// warn), feeds one bus: the level and mute, a subsonic cut and a gentle compressor, with a small room
// the glass cues ring into. Voices are capped; a cue repeated faster than it can sound is dropped, and
// one repeated quickly plays lighter. A hidden tab is silent and its context suspended.

import { createLimiter, recipe, type Cue, type CueDetail, type Layer } from "./recipes"
import { master, playWith, soundTuning, tuned } from "./tuning"

export type { Cue, CueDetail, Layer } from "./recipes"
export { cues, describe } from "./recipes"

/** Where the visitor's choice is kept: "on" or "off". */
export const SOUND_KEY = "deadbolt:sound"
/** At most this many plays sound at once; the oldest fades for a new one. */
export const MAX_VOICES = 8
/** Most of a play's level: the recipes are written near full scale, this sets the page's level. */
const LEVEL = 0.5
const PAD = 0.04
const FADE = 0.015

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))
const hasWindow = typeof window !== "undefined"

const readPreference = () => {
  try {
    return hasWindow && window.localStorage.getItem(SOUND_KEY) === "on"
  } catch {
    return false
  }
}
/** Whether the page has had a user gesture yet (no context is made before one). */
const activated = () =>
  (navigator as Navigator & { userActivation?: { hasBeenActive: boolean } }).userActivation?.hasBeenActive !== false
const hidden = () => typeof document !== "undefined" && document.hidden

let enabled = readPreference()
let context: AudioContext | null = null
let bus: { input: GainNode; room: AudioNode; noise: AudioBuffer } | null = null
const voices: { gain: GainNode; end: number }[] = []
const listeners = new Set<() => void>()
const limit = createLimiter()
const notify = () => {
  for (const listener of listeners) listener()
}

function ensure(): AudioContext | null {
  if (context) return context
  if (!hasWindow || !activated()) return null
  const Ctor =
    window.AudioContext ?? (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
  if (!Ctor) return null
  try {
    context = new Ctor({ latencyHint: "interactive" })
  } catch {
    return null
  }
  return context
}

const level = () => (enabled && !hidden() ? master().volume : 0)

/** Ramps the bus to where it should be now; suspends the context once it's silent, to save the CPU. */
function settle() {
  if (!context || !bus) return
  const t = context.currentTime
  const target = level()
  const g = bus.input.gain
  g.cancelScheduledValues(t)
  g.setValueAtTime(g.value, t)
  g.linearRampToValueAtTime(target, t + FADE * 2)
  const ctx = context
  if (target > 0) {
    if (ctx.state === "suspended")
      try {
        void ctx.resume().catch(() => {})
      } catch {}
  } else
    setTimeout(() => {
      if (level() === 0 && ctx.state === "running") void ctx.suspend().catch(() => {})
    }, 80)
}

function build(ctx: AudioContext) {
  if (bus) return bus
  const input = ctx.createGain()
  input.gain.value = level()
  const subsonic = ctx.createBiquadFilter()
  subsonic.type = "highpass"
  subsonic.frequency.value = 38
  const squeeze = ctx.createDynamicsCompressor()
  squeeze.threshold.value = -22
  squeeze.knee.value = 12
  squeeze.ratio.value = 3
  squeeze.attack.value = 0.002
  squeeze.release.value = 0.12
  input.connect(subsonic).connect(squeeze).connect(ctx.destination)
  // A seeded second of noise that noise layers loop from a random point.
  const rate = ctx.sampleRate
  const noise = ctx.createBuffer(1, rate, rate)
  const data = noise.getChannelData(0)
  let s = 7
  for (let i = 0; i < data.length; i++) {
    s = (s * 1664525 + 1013904223) >>> 0
    data[i] = s / 2 ** 31 - 1
  }
  // A small room: a fifth of a second of decaying noise under a low-pass, for the glass cues.
  const len = Math.floor(rate * 0.2)
  const impulse = ctx.createBuffer(2, len, rate)
  for (let c = 0; c < 2; c++) {
    const ch = impulse.getChannelData(c)
    for (let i = Math.floor(rate * 0.006); i < len; i++)
      ch[i] = (data[(i * (c + 3)) % data.length]! * Math.exp((-6.9 * i) / len)) / 9
  }
  const verb = ctx.createConvolver()
  verb.normalize = false
  verb.buffer = impulse
  const walls = ctx.createBiquadFilter()
  walls.type = "lowpass"
  walls.frequency.value = 3800
  walls.connect(verb).connect(input)
  bus = { input, room: walls, noise }
  return bus
}

function render(ctx: AudioContext, layers: readonly Layer[], gain: number, room: number, pan: number) {
  const b = build(ctx)
  const t0 = ctx.currentTime + 0.002
  for (let i = voices.length - 1; i >= 0; i--) if (voices[i]!.end < t0) voices.splice(i, 1)
  while (voices.length >= MAX_VOICES) {
    const old = voices.shift()!
    old.gain.gain.cancelScheduledValues(t0)
    old.gain.gain.setValueAtTime(old.gain.gain.value, t0)
    old.gain.gain.linearRampToValueAtTime(0, t0 + FADE)
  }
  const out = ctx.createGain()
  out.gain.value = gain
  let panner: StereoPannerNode | undefined
  if (pan !== 0 && ctx.createStereoPanner) {
    panner = ctx.createStereoPanner()
    panner.pan.value = pan
    out.connect(panner).connect(b.input)
  } else out.connect(b.input)
  let send: GainNode | undefined
  if (room > 0) {
    send = ctx.createGain()
    send.gain.value = 0.1 * room
    ;(panner ?? out).connect(send).connect(b.room)
  }
  const nyquist = ctx.sampleRate / 2 - 100
  let end = t0
  for (const l of layers) {
    const t = t0 + (l.at ?? 0)
    const stop = t + l.a + l.d + PAD
    end = Math.max(end, stop)
    const g = ctx.createGain()
    g.gain.setValueAtTime(0, t)
    g.gain.linearRampToValueAtTime(l.p, t + l.a)
    g.gain.setTargetAtTime(0, t + l.a, l.d / 6.9)
    let source: AudioScheduledSourceNode
    let param: AudioParam
    if (l.wave) {
      const osc = ctx.createOscillator()
      osc.type = l.wave
      param = osc.frequency
      osc.connect(g)
      source = osc
    } else {
      const src = ctx.createBufferSource()
      src.buffer = b.noise
      src.loop = true
      const filter = ctx.createBiquadFilter()
      filter.type = l.filter ?? "bandpass"
      if (l.q !== undefined) filter.Q.value = l.q
      param = filter.frequency
      src.connect(filter).connect(g)
      source = src
    }
    param.setValueAtTime(clamp(l.f, 20, nyquist), t)
    if (l.to !== undefined) param.exponentialRampToValueAtTime(clamp(l.to, 20, nyquist), t + (l.glide ?? l.a + l.d))
    g.connect(out)
    // Each burst starts somewhere else in the noise.
    if (l.wave) source.start(t)
    else (source as AudioBufferSourceNode).start(t, Math.random() * 0.9)
    source.stop(stop)
  }
  voices.push({ gain: out, end })
  setTimeout(
    () => {
      out.disconnect()
      panner?.disconnect()
      send?.disconnect()
    },
    (end - ctx.currentTime + 0.1) * 1000,
  )
}

/** A recipe's layers with the tuning and the play's pitch applied. */
const shape = (layers: readonly Layer[], pitch: number, decay: number): Layer[] =>
  layers.map((l) => ({
    ...l,
    f: l.f * pitch,
    ...(l.to !== undefined ? { to: l.to * pitch } : {}),
    d: l.d * decay,
  }))

/**
 * Plays a cue, unless sound is off, the tab is hidden, or the page hasn't had a gesture yet (then
 * it's simply dropped: nothing queues up to play later).
 */
export function play(cue: Cue, detail: CueDetail = {}): void {
  if (!enabled || hidden()) return
  const gain = clamp(detail.gain ?? 1, 0, 2)
  if (gain === 0) return
  const speed = limit(cue, performance.now())
  if (speed === null) return
  const ctx = ensure()
  if (!ctx) return
  const tune = tuned(cue)
  const made = recipe(cue, detail, speed)
  const layers = shape(made.layers, clamp(detail.pitch ?? 1, 0.25, 4) * tune.pitch, tune.decay)
  const level = LEVEL * gain * (made.gain ?? 1) * tune.gain
  const room = (made.room ?? 0) * master().room
  const pan = clamp(detail.pan ?? 0, -1, 1)
  if (ctx.state === "running") render(ctx, layers, level, room, pan)
  else
    // Resumed in this gesture, it sounds a moment late rather than not at all.
    try {
      void ctx
        .resume()
        .then(() => {
          if (enabled && ctx.state === "running") render(ctx, layers, level, room, pan)
        })
        .catch(() => {})
    } catch {}
}

/** Whether the visitor has sound on. */
export const isEnabled = () => enabled

/**
 * Turns sound on or off and remembers it. Call it from the gesture that asked (a click), so the
 * context can start in it.
 */
export function setEnabled(on: boolean) {
  try {
    window.localStorage.setItem(SOUND_KEY, on ? "on" : "off")
  } catch {}
  apply(on)
}

function apply(on: boolean) {
  if (on === enabled) return
  enabled = on
  if (on) {
    const ctx = ensure()
    if (ctx) build(ctx)
    else prime()
  }
  settle()
  notify()
}

/** Called when sound is turned on or off; returns an unsubscribe. */
export function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/**
 * The shared context and the bus input to connect your own nodes to (the level, mute and compressor
 * apply), once there is one and sound is on; else null. Used by the send voice.
 */
export function output(): { readonly context: AudioContext; readonly destination: AudioNode } | null {
  if (!enabled || hidden()) return null
  const ctx = ensure()
  if (!ctx) return null
  const b = build(ctx)
  if (ctx.state === "suspended")
    try {
      void ctx.resume().catch(() => {})
    } catch {}
  return { context: ctx, destination: b.input }
}

/** For a visitor who already turned sound on: make the context on the page's first gesture. */
let primed = false
function prime() {
  if (!hasWindow || primed || context) return
  primed = true
  const kinds = ["pointerdown", "keydown", "touchend"] as const
  const unlock = () => {
    if (!enabled) return
    const ctx = ensure()
    if (!ctx) return
    build(ctx)
    settle()
    for (const k of kinds) window.removeEventListener(k, unlock, true)
  }
  for (const k of kinds) window.addEventListener(k, unlock, { capture: true, passive: true })
}

/** The page's sound, as one object. */
export const sound = {
  get enabled() {
    return enabled
  },
  setEnabled,
  play,
  subscribe,
  output,
}

if (hasWindow) {
  if (enabled) prime()
  document.addEventListener("visibilitychange", settle)
  soundTuning.subscribe(() => {
    if (enabled) settle()
  })
  window.addEventListener("storage", (event) => {
    if (event.key === SOUND_KEY || event.key === null) apply(readPreference())
  })
  playWith((cue) => {
    if (!enabled) apply(true)
    play(cue)
  })
  if (import.meta.env.DEV) void import("./audition").then((m) => m.install())
}
