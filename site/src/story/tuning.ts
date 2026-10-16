import { defineControls, knob } from "knobs"
import type { LightParams } from "./light"

// The diagrams' light, shared by every story. In development a chip on any story opens the panel; copy the values
// back as constants (⇧C) once they're right. Production builds lock every value to these defaults.

const schema = {
  exposure: knob(1.15, { min: .5, max: 2.5, step: .01, label: "Exposure", group: "light" }),
  bloom: knob(1, { min: 0, max: 2, step: .01, label: "Head bloom", group: "light" }),
  glow: knob(1, { min: 0, max: 2, step: .01, label: "Trail glow", group: "light" }),
  reflection: knob(1, { min: 0, max: 2, step: .01, label: "Border catch", group: "light" }),
  flood: knob(1, { min: 0, max: 2, step: .01, label: "Flood", group: "light" }),
  cooling: knob(1, { min: .4, max: 2.5, step: .01, unit: "×", label: "Trail length", group: "light" }),
  shutter: knob(1 / 90, { min: 0, max: 1 / 30, step: .001, unit: "s", label: "Shutter", group: "light" }),
  ink: knob(1, { min: 0, max: 2, step: .01, label: "Print ink", group: "paper" }),
  grain: knob(.22, { min: 0, max: .6, step: .01, label: "Paper tooth", group: "paper" }),
  bleed: knob(.5, { min: 0, max: 1.5, step: .01, label: "Ink bleed", group: "paper" }),
}

export const lightTuning = defineControls("story-light", schema, {
  enabled: import.meta.env.DEV,
  groupLabels: { light: "Light", paper: "Paper & ink" },
})

export const lightParams = (): LightParams => lightTuning.get()
/** How long trails stay warm, as a multiple of each send's cooling time. */
export const coolingScale = () => lightTuning.get().cooling
/** How long a moving head is exposed for its smear (seconds of scene time). */
export const shutter = () => lightTuning.get().shutter
