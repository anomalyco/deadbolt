import { action, defineControls, knob } from "knobs"
import { cues, type Cue } from "./recipes"

// The sound's knobs: the master level and, per cue, its gain, pitch and decay (multipliers on the
// recipe), each group with a button that plays it. Explore in development (the audition mounts the
// panel), then fold what you like back into recipes.ts. Production builds lock every value to these
// defaults, so the recipes play as written.

let player: (cue: Cue) => void = () => {}
/** The engine registers how a group's play button sounds its cue (kept out of here to avoid a cycle). */
export const playWith = (play: (cue: Cue) => void) => {
  player = play
}

const perCue = Object.fromEntries(
  cues.flatMap((cue) => [
    [`${cue}Play`, action("Play", { group: cue, run: () => player(cue) })],
    [`${cue}Gain`, knob(1, { min: 0, max: 3, step: 0.01, unit: "×", label: "Gain", group: cue })],
    [`${cue}Pitch`, knob(1, { min: 0.5, max: 2, step: 0.01, unit: "×", label: "Pitch", group: cue })],
    [`${cue}Decay`, knob(1, { min: 0.3, max: 3, step: 0.01, unit: "×", label: "Decay", group: cue })],
  ]),
)

const schema = {
  volume: knob(1, { min: 0, max: 1, step: 0.01, label: "Volume", group: "master" }),
  room: knob(1, { min: 0, max: 3, step: 0.01, unit: "×", label: "Room", group: "master" }),
  voiceGain: knob(1, { min: 0, max: 3, step: 0.01, unit: "×", label: "Level", group: "voice" }),
  voiceLow: knob(330, { min: 110, max: 880, step: 1, unit: "Hz", label: "Start pitch", group: "voice" }),
  voiceHigh: knob(587, { min: 220, max: 1760, step: 1, unit: "Hz", label: "End pitch", group: "voice" }),
  voiceAir: knob(1, { min: 0, max: 3, step: 0.01, unit: "×", label: "Air", group: "voice" }),
  ...perCue,
}

export const soundTuning = defineControls("deadbolt-sound", schema, {
  enabled: import.meta.env.DEV,
  defaultLabel: "as written",
  groupLabels: { master: "Master", voice: "Send voice" },
  groupFolded: Object.fromEntries(cues.map((cue) => [cue, true])),
})

export type CueTuning = { gain: number; pitch: number; decay: number }

const number = (values: Record<string, unknown>, key: string, fallback: number) => {
  const v = values[key]
  return typeof v === "number" && Number.isFinite(v) ? v : fallback
}

/** The tuned multipliers for one cue (all 1 in production). */
export function tuned(cue: Cue): CueTuning {
  const values = soundTuning.get() as Record<string, unknown>
  return {
    gain: number(values, `${cue}Gain`, 1),
    pitch: number(values, `${cue}Pitch`, 1),
    decay: number(values, `${cue}Decay`, 1),
  }
}

export function master() {
  const values = soundTuning.get() as Record<string, unknown>
  return { volume: number(values, "volume", 1), room: number(values, "room", 1) }
}

export function voiceTuning() {
  const values = soundTuning.get() as Record<string, unknown>
  return {
    gain: number(values, "voiceGain", 1),
    low: number(values, "voiceLow", 330),
    high: number(values, "voiceHigh", 587),
    air: number(values, "voiceAir", 1),
  }
}
