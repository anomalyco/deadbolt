// The send voice: one sustained sound that follows light along a path. A breath of air through a
// band that opens as it goes, over a faint sine lifting from the voice's start pitch to its end
// pitch, panned with the light. `follow` retunes it each frame (it swells in on the first); `silence`
// lets it go. Nothing is built until the page's gesture has the context running with sound on.

import { output, subscribe } from "./sound"
import { voiceTuning } from "./tuning"

export interface VoiceFrame {
  /** 0–1 along the path. */
  readonly progress: number
  /** −1 (left) to 1 (right). */
  readonly pan?: number
  /** Level multiplier, 0–2. */
  readonly gain?: number
  /** Pitch multiplier. */
  readonly pitch?: number
}

export interface SendVoice {
  /** Where the light is now; call every frame while it travels. */
  follow(frame: VoiceFrame): void
  /** Fades it out (quickly with `fast`, for a seek). Safe to call every frame. */
  silence(fast?: boolean): void
  dispose(): void
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))
const IN = 0.06
const OUT = 0.07
const QUICK = 0.012
/** The voice's level at full: matched by ear to sit under the one-shot cues. */
const LEVEL = 0.06

export function createSendVoice(): SendVoice {
  let rig: {
    ctx: AudioContext
    nodes: AudioNode[]
    sources: AudioScheduledSourceNode[]
    band: BiquadFilterNode
    tone: OscillatorNode
    air: GainNode
    body: GainNode
    pan: StereoPannerNode
    env: GainNode
  } | null = null
  let sounding = false
  let reap: ReturnType<typeof setTimeout> | undefined

  const teardown = () => {
    clearTimeout(reap)
    reap = undefined
    if (!rig) return
    for (const s of rig.sources)
      try {
        s.stop()
      } catch {}
    for (const n of rig.nodes) n.disconnect()
    rig = null
    sounding = false
  }

  const make = () => {
    const out = output()
    if (!out || out.context.state !== "running") return null
    const ctx = out.context
    const noise = ctx.createBuffer(1, ctx.sampleRate * 2, ctx.sampleRate)
    const data = noise.getChannelData(0)
    let s = 1979
    for (let i = 0; i < data.length; i++) {
      s = (Math.imul(s, 1664525) + 1013904223) | 0
      data[i] = s / 2147483648
    }
    const src = ctx.createBufferSource()
    src.buffer = noise
    src.loop = true
    const band = ctx.createBiquadFilter()
    band.type = "bandpass"
    band.Q.value = 1.1
    const air = ctx.createGain()
    const tone = ctx.createOscillator()
    tone.type = "sine"
    const body = ctx.createGain()
    const pan = ctx.createStereoPanner()
    const env = ctx.createGain()
    env.gain.value = 0
    src.connect(band).connect(air).connect(pan)
    tone.connect(body).connect(pan)
    pan.connect(env).connect(out.destination)
    src.start()
    tone.start()
    return { ctx, nodes: [src, band, air, tone, body, pan, env], sources: [src, tone], band, tone, air, body, pan, env }
  }

  const stopListening = subscribe(() => teardown())

  return {
    follow({ progress, pan = 0, gain = 1, pitch = 1 }) {
      rig ??= make()
      if (!rig) return
      clearTimeout(reap)
      reap = undefined
      const tune = voiceTuning()
      const p = clamp(progress, 0, 1)
      const now = rig.ctx.currentTime
      const f = (tune.low * (tune.high / tune.low) ** p) * clamp(pitch, 0.25, 4)
      rig.tone.frequency.setTargetAtTime(f, now, 0.03)
      rig.band.frequency.setTargetAtTime(clamp(f * 2.2, 200, 9000), now, 0.03)
      rig.pan.pan.setTargetAtTime(clamp(pan, -1, 1), now, 0.03)
      // A little more air in the middle of the flight, a little more tone at its ends.
      const mid = Math.sin(Math.PI * p)
      rig.air.gain.setTargetAtTime((0.55 + 0.45 * mid) * tune.air, now, 0.03)
      rig.body.gain.setTargetAtTime(0.06 * (1 - 0.4 * mid), now, 0.03)
      const target = LEVEL * clamp(gain, 0, 2) * tune.gain
      if (!sounding) {
        rig.env.gain.cancelScheduledValues(now)
        rig.env.gain.setValueAtTime(rig.env.gain.value, now)
        rig.env.gain.linearRampToValueAtTime(target, now + IN)
        sounding = true
      } else rig.env.gain.setTargetAtTime(target, now, 0.03)
    },
    silence(fast = false) {
      if (!rig || !sounding) return
      sounding = false
      const now = rig.ctx.currentTime
      const g = rig.env.gain
      g.cancelScheduledValues(now)
      g.setValueAtTime(g.value, now)
      g.setTargetAtTime(0, now, (fast ? QUICK : OUT) / 3)
      clearTimeout(reap)
      // Kept a while for the next flight, then let go.
      reap = setTimeout(teardown, 2000)
    },
    dispose() {
      stopListening()
      teardown()
    },
  }
}
