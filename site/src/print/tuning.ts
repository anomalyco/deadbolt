import { choice, color, defineControls, knob, point, seed, toggle, type Values } from "knobs"

// The masthead's knobs: the print's shader, the ink filter, the grain and the splatter. Explore in development
// (the panel grows out of a chip on the masthead), then copy the values back as constants (⇧C in the panel)
// and paste them over the defaults here. Production builds lock every value to these defaults.

export const dithers = ["stipple", "bayer", "noise", "shimmer"] as const

const schema = {
  rays: knob(23, { min: 3, max: 48, step: 1, label: "Rays", group: "rays" }),
  twist: knob(2, { min: 0, max: 6, step: 0.05, label: "Twist", group: "rays" }),
  waves: knob(7, { min: 1, max: 15, step: 1, label: "Twist waves", group: "rays" }),
  sway: knob(0.6, { min: 0, max: 2, step: 0.01, label: "Twist speed", group: "rays" }),
  spin: knob(0.22, { min: -0.6, max: 0.6, step: 0.01, label: "Spin", group: "rays" }),
  flicker: knob(0.5, { min: 0, max: 1.2, step: 0.01, label: "Flare", group: "rays" }),

  beat: knob(0.35, { min: 0, max: 1, step: 0.01, label: "Thump", group: "pulse" }),
  pulse: knob(0.55, { min: 0, max: 1.2, step: 0.01, label: "Rings", group: "pulse" }),
  pulseRate: knob(0.45, { min: 0.1, max: 2, step: 0.01, unit: "/s", label: "Beat rate", group: "pulse" }),
  pulseWidth: knob(0.09, { min: 0.02, max: 0.3, step: 0.005, label: "Ring width", group: "pulse" }),
  breathe: knob(0.06, { min: 0, max: 0.3, step: 0.005, label: "Breath", group: "pulse" }),
  breatheRate: knob(0.15, { min: 0.02, max: 1, step: 0.01, unit: "/s", label: "Breath rate", group: "pulse" }),

  reach: knob(1.15, { min: 0.7, max: 2, step: 0.01, label: "Falloff", group: "burst" }),
  depth: knob(0.35, { min: 0, max: 0.6, step: 0.01, label: "Ray depth", group: "burst" }),
  falloff: knob(1.4, { min: 0.5, max: 3.5, step: 0.05, label: "Softness", group: "burst" }),
  strength: knob(1, { min: 0.5, max: 1.6, step: 0.01, label: "Strength", group: "burst" }),
  centre: point({ x: 0, y: 0.1 }, { min: -0.4, max: 0.4, step: 0.005, label: "Centre", group: "burst" }),

  turbulence: knob(0.45, { min: 0, max: 1.2, step: 0.01, label: "Amount", group: "turbulence" }),
  turbulenceScale: knob(3, { min: 0.5, max: 10, step: 0.1, label: "Scale", group: "turbulence" }),
  drift: point({ x: 0.3, y: -0.25 }, { min: -1, max: 1, step: 0.01, label: "Drift", group: "turbulence" }),

  sparks: knob(0.012, { min: 0, max: 0.08, step: 0.001, label: "Density", group: "sparks" }),
  sparkRate: knob(8, { min: 0, max: 30, step: 0.5, unit: "/s", label: "Flicker", group: "sparks" }),
  sparkReach: knob(1.1, { min: 0.3, max: 2, step: 0.01, label: "Reach", group: "sparks" }),

  hole: toggle(true, { label: "Keyhole", group: "keyhole" }),
  holeSize: knob(1, { min: 0.6, max: 1.5, step: 0.01, label: "Size", group: "keyhole" }),
  holeOffset: point({ x: 0, y: 0 }, { min: -0.3, max: 0.3, step: 0.005, label: "Position", group: "keyhole" }),
  rim: knob(0.055, { min: 0, max: 0.16, step: 0.005, label: "Rim", group: "keyhole" }),
  rimInk: knob(0.93, { min: 0, max: 1, step: 0.01, label: "Rim ink", group: "keyhole" }),
  boil: knob(0.6, { min: 0, max: 1.5, step: 0.01, label: "Rim boil", group: "keyhole" }),

  cell: knob(1.75, { min: 0.75, max: 6, step: 0.05, unit: "px", label: "Dot", group: "ink" }),
  dither: choice("stipple", dithers, { label: "Dither", group: "ink" }),
  ink: color("#ff2a2a", { label: "Ink", group: "ink" }),

  splatter: toggle(true, { label: "Splatter", group: "splatter" }),
  splatSeed: seed(22, { min: 1, max: 999, label: "Seed", group: "splatter", random: true }),
  splatCount: knob(84, { min: 0, max: 220, step: 1, label: "Drops", group: "splatter" }),
  splatSize: knob(5.5, { min: 1, max: 14, step: 0.1, label: "Size", group: "splatter" }),
  splatSpread: knob(150, { min: 40, max: 180, step: 1, label: "Spread", group: "splatter" }),
  splatAt: point({ x: 0.77, y: -0.28 }, { min: { x: 0, y: -0.6 }, max: { x: 1, y: 1 }, step: 0.01, label: "Position", group: "splatter" }),
  splatWidth: knob(54, { min: 20, max: 90, step: 1, unit: "cqw", label: "Width", group: "splatter" }),
  splatEdge: knob(3, { min: 0, max: 8, step: 0.1, label: "Ragged edge", group: "splatter" }),

  bleed: knob(1.9, { min: 0, max: 8, step: 0.1, label: "Bleed", group: "print" }),
  bleedScale: knob(0.025, { min: 0.005, max: 0.08, step: 0.001, label: "Bleed frequency", group: "print" }),
  grain: knob(0.2, { min: 0, max: 0.5, step: 0.01, label: "Grain", group: "print" }),

  speed: knob(1, { min: 0, max: 3, step: 0.05, unit: "×", label: "Speed", group: "time" }),
  freeze: toggle(false, { label: "Freeze", group: "time" }),
}

export type HeaderValues = Values<typeof schema>

// Keys whose last change came from Random, a preset or undo: the print glides to them. Kit's own drags apply 1:1.
const gliding = new Set<string>()
export const glides = (key: string) => gliding.has(key)

export const header = defineControls("deadbolt-header", schema, {
  enabled: import.meta.env.DEV,
  defaultLabel: "current",
  groupLabels: { rays: "Rays", pulse: "Pulse", burst: "Burst", turbulence: "Turbulence", sparks: "Sparks", keyhole: "Keyhole", ink: "Dither & ink", splatter: "Splatter", print: "Print filter & grain", time: "Time" },
  groupFolded: { splatter: true, print: true },
  onChange(patch, _values, { source }) {
    for (const key of Object.keys(patch)) {
      if (source === "local" || source === "compare") gliding.delete(key)
      else gliding.add(key)
    }
  },
  presets: {
    // The first version: drifting rays only, no heartbeat.
    calm: {
      sway: 0.35, spin: 0.12, flicker: 0, beat: 0, pulse: 0, breathe: 0, boil: 0,
      drift: { x: 0.2, y: -0.15 }, sparkRate: 5,
    },
    // A fast, hard heartbeat: big thumps and tight rings racing out of the keyhole.
    heartbeat: {
      beat: 0.8, pulse: 1, pulseRate: 0.9, pulseWidth: 0.05, breathe: 0, flicker: 0.3, boil: 0.9, spin: 0.1,
    },
    // The original static canvas in mock.html: no motion, no turbulence, white-noise dither, a denser burst.
    "dax mock": {
      freeze: true, turbulence: 0, dither: "noise", strength: 1.15, centre: { x: 0, y: 0.11 },
      sparks: 0.05, sparkReach: 1, rimInk: 0.9, cell: 1.6,
    },
    // opentunnel's tunnel print: a fine one-pixel stipple, slow torn cloud drifting through the rays.
    "opentunnel print": {
      cell: 1, speed: 0.5, turbulence: 0.9, turbulenceScale: 2.4, drift: { x: 0.05, y: -0.6 },
      twist: 2.6, sway: 0.2, spin: 0.05, sparks: 0.004, strength: 1.05, grain: 0.24, bleed: 2.4,
    },
    still: { freeze: true },
    // Few broad rays, ordered dither in coarse dots, slowly turning.
    sunburst: {
      rays: 9, twist: 0, depth: 0.6, reach: 0.95, falloff: 0.8, spin: 0.25, turbulence: 0.15,
      sparks: 0.025, cell: 3, dither: "bayer", splatCount: 40,
    },
    // Everything turned up: a tight, writhing burst, crackling sparks, a reshuffling grain and a heavy splatter.
    riot: {
      rays: 41, twist: 4.5, waves: 3, sway: 1.2, spin: -0.4, turbulence: 1, turbulenceScale: 6,
      drift: { x: 0.8, y: -0.6 }, sparks: 0.06, sparkRate: 18, dither: "shimmer", speed: 1.6,
      splatCount: 160, splatSize: 8, grain: 0.35, bleed: 3.5,
    },
  },
})
