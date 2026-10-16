// Deadbolt's palette: what each cue is made of. Pure data, so the engine, the loudness check and the
// audition all read the same sound.
//
// Every cue is struck out of a few layers (a sine, a sine knocked sharp that drops to its pitch, a
// struck glass bar's modes, or a burst of filtered noise), each swelling in along a straight line and
// dying away exponentially. The materials are a lock's: brass tumblers and latches (narrow noise
// clicks over small knocks), a bolt (low thuds), paper and ink (muted low-passed thumps), and glass
// for light. Glass notes sit on D (D5, A5, D6, F♯6, A6), so anything that rings agrees with the rest.
//
// The approach (struck modes, the knock, cadence that lightens repeats) follows Cuelume
// (https://cuelume.dev, MIT) by way of knobs' panel sounds; the palette is Deadbolt's own.

export const cues = [
  "send",
  "land",
  "write",
  "seal",
  "link",
  "refuse",
  "break",
  "unlock",
  "join",
  "remove",
  "codeMatch",
  "step",
  "scrub",
  "toggle",
  "heartbeat",
] as const

export type Cue = (typeof cues)[number]

/** What a play knows about its moment. Every field is optional. */
export interface CueDetail {
  /** Stereo position, −1 (left) to 1 (right): where the thing is across the diagram. */
  readonly pan?: number
  /** 0–1: where a step or scrub sits along the story (its pitch), or how far a `send` has gone. */
  readonly position?: number
  /** Level multiplier, 0–2 (1 by default): how much the moment matters. */
  readonly gain?: number
  /** Pitch multiplier (1 by default; 2 is an octave up, 0.5 an octave down). */
  readonly pitch?: number
  /** `heartbeat` only: seconds from the lub to the dub (0.36 by default). */
  readonly gap?: number
}

/**
 * One layer of a sound: a tone (`wave`) or a burst of noise through a filter. Times are seconds;
 * `d` is how long it takes to die away by 60 dB.
 */
export interface Layer {
  readonly wave?: OscillatorType
  /** The noise's filter; `bandpass` by default. */
  readonly filter?: BiquadFilterType
  /** The tone's pitch, or the noise filter's frequency (Hz). */
  readonly f: number
  /** Glides `f` here over `glide` seconds. */
  readonly to?: number
  readonly glide?: number
  readonly q?: number
  /** Starts this long after the play. */
  readonly at?: number
  readonly a: number
  readonly d: number
  readonly p: number
}

export interface Recipe {
  readonly layers: readonly Layer[]
  /** The play's level, matched across cues by loudness (1 by default). */
  readonly gain?: number
  /** How much rings into the small shared room (0 by default: dry). */
  readonly room?: number
}

// ── Layers ───────────────────────────────────────────────────────────────────────────────────

/** Noise ringing narrowly at `f`: one resonance of a click. */
const click = (f: number, p: number, d = 0.005, q = 4, at = 0): Layer => ({ f, q, a: 0.0008, d, p, at })
/** A dull bump: noise under a low-pass, a part meeting its stop. */
const thud = (f: number, p: number, d: number, at = 0): Layer => ({
  filter: "lowpass",
  f,
  q: 0.7,
  a: 0.0015,
  d,
  p,
  at,
})
/** Air moving: noise sweeping from `f` to `to`. */
const air = (f: number, to: number, d: number, p: number, a = 0.012, at = 0): Layer => ({
  f,
  to,
  glide: a + d * 0.6,
  q: 1.4,
  a,
  d,
  p,
  at,
})
/** A small hollow part tapped: a sine struck 60% sharp that drops to `f` in 18 ms. */
const knock = (f: number, d: number, p: number, at = 0, sharp = 1.6): Layer => ({
  wave: "sine",
  f: f * sharp,
  to: f,
  glide: 0.018,
  a: 0.001,
  d,
  p,
  at,
})
/** A free glass bar's modes (1, 2.76, 5.4), each higher one dying sooner, under 5 kHz. */
const glass = (f: number, d: number, p: number, at = 0): Layer[] =>
  (
    [
      [1, 1],
      [2.76, 0.28],
      [5.4, 0.08],
    ] as const
  )
    .filter(([ratio]) => f * ratio <= 5000)
    .map(([ratio, level]) => ({
      wave: "sine" as const,
      f: f * ratio,
      a: 0.002,
      d: Math.max(0.028, d / ratio ** 0.75),
      p: p * level,
      at,
    }))
/** A plain sine, swelling for `a`. */
const tone = (f: number, d: number, p: number, a = 0.004, at = 0, to?: number, glide?: number): Layer => ({
  wave: "sine",
  f,
  ...(to !== undefined ? { to, glide: glide ?? a + d * 0.5 } : {}),
  a,
  d,
  p,
  at,
})

/** The glass notes, all on D. */
export const NOTE = { D5: 587.33, A5: 880, D6: 1174.66, Fs6: 1479.98, A6: 1760 } as const

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))

/** Repeats closer than FAST play fully lightened; slower than SLOW, not at all (ms). */
const FAST = 70
const SLOW = 240
/** 0 (unhurried) to 1 (as fast as it goes), from the time since the cue last played. */
export const cadence = (sinceMs: number) => clamp((SLOW - sinceMs) / (SLOW - FAST), 0, 1)

/**
 * A cue's layers for this play: `speed` from `cadence`, `random` for its small variations (a
 * tumbler's pitch). Pure.
 */
export function recipe(cue: Cue, detail: CueDetail = {}, speed = 0, random: () => number = Math.random): Recipe {
  const light = 1 - 0.45 * speed
  const vary = (amount: number) => 1 + (random() * 2 - 1) * amount
  const position = clamp(detail.position ?? 0.5, 0, 1)
  switch (cue) {
    case "send":
      // Light leaving: a breath of air drawn upward, a soft sine lifting under it. Further along
      // the path (`position`), a little higher.
      return {
        layers: [
          air(650, 2300, 0.16, 0.16, 0.05),
          tone(NOTE.A5 / 2, 0.14, 0.012, 0.04, 0, NOTE.D5 * (1 + position * 0.12), 0.12),
        ],
        gain: 0.7,
        room: 0.4,
      }
    case "land":
      // Arrival: a tiny dry tick of glass meeting glass, then the bar ringing on.
      return {
        layers: [click(4200, 0.18, 0.003, 2), ...glass(NOTE.D6, 0.42, 0.02, 0.003)],
        gain: 1.25,
        room: 0.8,
      }
    case "write": {
      // A tumbler pin dropping into its chamber: a click, a small brass knock and, 9 ms later, the
      // pin seating. Each one a little different, so a run of entries doesn't machine-gun.
      const k = vary(0.05)
      return {
        layers: [
          click(2500 * k, 0.42 * light, 0.005, 4),
          knock(560 * k, 0.022, 0.05 * light),
          click(3700 * k, 0.16 * light, 0.003, 3, 0.009),
        ],
        gain: 0.7,
      }
    }
    case "seal":
      // A signature stamped: a muted thump of a rubber stamp on paper, then a tiny latch as it lifts.
      return {
        layers: [
          thud(260, 0.9, 0.065),
          knock(120, 0.08, 0.1, 0, 1.3),
          thud(900, 0.12, 0.012),
          click(2900, 0.2, 0.004, 3, 0.062),
          knock(720, 0.016, 0.026, 0.062),
        ],
        gain: 1.15,
      }
    case "link":
      // A dependency drawn: a faint rising glint, like light catching a wire.
      return {
        layers: [
          air(2200, 4200, 0.05, 0.035, 0.02),
          tone(NOTE.A6, 0.14, 0.014, 0.018, 0, NOTE.A6 * 1.5, 0.07),
          tone(NOTE.A6 * 2.76, 0.05, 0.003, 0.02, 0.01),
        ],
        gain: 1.25,
        room: 0.6,
      }
    case "refuse":
      // The gate holds: a bolt shot into a locked strike, low and short, with a small rattle back.
      return {
        layers: [
          thud(340, 0.95, 0.05),
          knock(92, 0.075, 0.12, 0, 1.4),
          click(950, 0.28, 0.012, 2),
          thud(280, 0.28, 0.03, 0.068),
          knock(110, 0.03, 0.035, 0.068),
        ],
        gain: 1.05,
      }
    case "break":
      // Tampered history: a dry crack, a few splinters close together, high to low, no ring.
      return {
        layers: [
          click(4300, 0.55, 0.004, 1.2),
          { filter: "highpass", f: 2400, q: 0.7, a: 0.0006, d: 0.018, p: 0.22 },
          click(2600, 0.4, 0.006, 2, 0.007),
          click(3400, 0.25, 0.004, 2, 0.019),
          click(1700, 0.3, 0.008, 2.5, 0.027),
          knock(170, 0.04, 0.05, 0.004, 1.3),
        ],
        gain: 0.78,
      }
    case "unlock": {
      // The keyset opens: four tumblers falling into place, each a touch higher and sooner, then the
      // bolt drawn back (air, a thud, a brass knock) and a faint glass note: open.
      const layers: Layer[] = []
      const gaps = [0, 0.058, 0.108, 0.152]
      gaps.forEach((at, i) => {
        const k = 1 + i * 0.09
        layers.push(click(2300 * k, 0.34, 0.005, 4, at), knock(520 * k, 0.018, 0.035, at))
      })
      const bolt = 0.235
      layers.push(
        air(1500, 520, 0.05, 0.1, 0.025, bolt - 0.025),
        thud(420, 0.8, 0.045, bolt),
        knock(165, 0.06, 0.09, bolt, 1.4),
        click(1900, 0.3, 0.008, 3, bolt),
        ...glass(NOTE.D5, 0.5, 0.008, bolt + 0.03),
      )
      return { layers, gain: 1.1, room: 0.4 }
    }
    case "join":
      // Pairing done: two glass notes a fifth apart, the second blooming.
      return {
        layers: [
          click(3600, 0.12, 0.003, 2),
          ...glass(NOTE.A5, 0.45, 0.015),
          ...glass(NOTE.A5 * 1.5, 0.6, 0.016, 0.1),
        ],
        gain: 2.05,
        room: 1,
      }
    case "remove":
      // A device revoked: a latch let down in two steps, each lower, over a sine falling a fourth.
      return {
        layers: [
          air(1700, 650, 0.05, 0.07, 0.015),
          click(2700, 0.32, 0.005, 3),
          knock(340, 0.026, 0.05),
          click(1750, 0.32, 0.006, 3, 0.075),
          knock(225, 0.034, 0.06, 0.075),
          tone(NOTE.D6, 0.18, 0.006, 0.01, 0, NOTE.A5, 0.16),
        ],
        gain: 0.9,
        room: 0.3,
      }
    case "codeMatch": {
      // Two identical soft ticks: the same code, twice.
      const tick = (at: number) => [click(3200, 0.12, 0.003, 2, at), ...glass(NOTE.Fs6, 0.12, 0.012, at)]
      return { layers: [...tick(0), ...tick(0.11)], gain: 2.5, room: 0.5 }
    }
    case "step": {
      // A detent on the step bar, pitched by where it sits; a fast run ticks lighter. Noise through a
      // narrower band carries less, so lower ticks are lifted to match.
      const k = 2 ** (position * 0.9 - 0.35)
      const even = light / k ** 0.75
      const layers = [click(2800 * k, 0.45 * even, 0.004, 5), click(1250 * k, 0.2 * even, 0.009, 2.5)]
      if (speed < 0.6) layers.push(knock(400 * k, 0.018, 0.03 * light))
      return { layers, gain: 1.2 }
    }
    case "scrub": {
      // A fine ratchet under the finger while scrubbing: a single tight tick, pitched by position.
      const k = 2 ** (position * 0.9 - 0.35)
      return { layers: [click(3400 * k, 0.32 * light / k ** 0.75, 0.003, 5)], gain: 0.48 }
    }
    case "toggle":
      // The sound switch: a small brass lever leaving its detent, then snapping over 13 ms later.
      return {
        layers: [click(3300, 0.14, 0.003, 3), click(1850, 0.5, 0.012, 2, 0.013), knock(330, 0.03, 0.06, 0.013)],
        gain: 0.85,
      }
    case "heartbeat": {
      // The keyhole's lub-dub: two soft low thumps, the second lighter and a little higher. Mostly
      // under 120 Hz, so on small speakers it's barely there; a hint at 2× keeps it from vanishing.
      const gap = clamp(detail.gap ?? 0.36, 0.08, 1)
      const beat = (at: number, level: number, f: number) => [
        knock(f, 0.16, 0.5 * level, at, 1.25),
        tone(f * 2, 0.07, 0.04 * level, 0.004, at),
        thud(170, 0.35 * level, 0.05, at),
      ]
      return { layers: [...beat(0, 1, 62), ...beat(gap, 0.6, 70)], gain: 0.25 }
    }
  }
}

/** The shortest gap (ms) between two plays of a cue: closer ones are dropped. */
export const GAPS: Readonly<Record<Cue, number>> = {
  send: 60,
  land: 60,
  write: 30,
  seal: 90,
  link: 40,
  refuse: 120,
  break: 150,
  unlock: 300,
  join: 300,
  remove: 200,
  codeMatch: 250,
  step: 24,
  scrub: 22,
  toggle: 40,
  heartbeat: 200,
}

/** How a cue's plays are let through: too close are dropped; the rest report their cadence. */
export function createLimiter(gaps: Readonly<Record<string, number>> = GAPS) {
  const last = new Map<string, number>()
  return (cue: string, now: number): number | null => {
    const since = now - (last.get(cue) ?? Number.NEGATIVE_INFINITY)
    if (since < (gaps[cue] ?? 0)) return null
    last.set(cue, now)
    return cadence(since)
  }
}

/** One line per cue: what it is for and what it sounds like (the audition reads these). */
export const describe: Readonly<Record<Cue, string>> = {
  send: "light leaves: a breath of air drawn upward over a soft lifting sine",
  land: "light arrives: a tiny glass tick, then the bar rings (D6)",
  write: "an entry is appended: a tumbler pin drops and seats",
  seal: "a signature is stamped: a muted ink thump, a tiny latch as it lifts",
  link: "a dependency link draws: a faint rising glint",
  refuse: "the membership gate refuses: a bolt into a locked strike, low and short",
  break: "history is tampered with: a dry crack of splinters",
  unlock: "the keyset opens: four tumblers fall, the bolt draws back, a faint D5",
  join: "pairing completes: two glass notes a fifth apart (A5, E6)",
  remove: "a device is revoked: a latch let down in two steps, a sine falling",
  codeMatch: "the six-digit codes match: two identical soft glass ticks",
  step: "a step-bar detent, pitched by position",
  scrub: "a fine ratchet tick while scrubbing, pitched by position",
  toggle: "the sound switch: a small brass lever snapping over",
  heartbeat: "the keyhole's lub-dub: two soft low thumps, felt more than heard",
}
