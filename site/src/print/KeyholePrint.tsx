import { useRef } from "react"
import { colorHex, springMotion } from "knobs"
import { createHeartbeat } from "../sound"
import { ShaderCanvas, glslNoise } from "./ShaderCanvas"
import { dithers, glides, header, type HeaderValues } from "./tuning"

// The masthead's print, after the mock's canvas: a red burst of rays with a black keyhole knocked out of it and a
// solid rim around the hole, dithered to two inks. The rays drift, the burst breathes and sparks catch. Every
// constant is a uniform from the header's knobs (tuning.ts). Rates (sway, spin, beat, breath, spark flicker, drift)
// reach the shader as phases, integrated here frame by frame, so a rate gliding to a new value changes how fast
// things move, never where they are.

const fragment = `#version 300 es
precision highp float;
out vec4 color;
uniform vec2 resolution;
uniform float time, cell;
uniform vec3 ink;
uniform float rays, twist, waves, swayPhase, spinPhase;
uniform float reach, depth, falloff, strength;
uniform vec2 centre;
uniform float turbulence, turbulenceScale;
uniform vec2 driftOffset;
uniform float sparks, sparkPhase, sparkReach;
uniform float hole, holeSize, rim, rimInk;
uniform vec2 holeOffset;
uniform float beat, pulse, beatPhase, pulseWidth, breathe, breathPhase, flicker, boil;
uniform int dither;
${glslNoise}

// Signed distance-ish: negative inside a keyhole grown by g.
float keyhole(vec2 p, float g) {
  float circle = length(p - vec2(0.0, 0.2)) - (0.235 + g);
  float half_ = 0.085 + (0.11 - p.y) * 0.17 + g;
  float slot = max(abs(p.x) - half_, max(p.y - 0.11, -0.47 - g - p.y));
  return min(circle, slot);
}

float bayer(vec2 p) {
  vec2 c = mod(p, 4.0);
  int i = int(c.x) + int(c.y) * 4;
  int m[16] = int[16](0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5);
  return (float(m[i]) + 0.5) / 16.0;
}

float threshold(vec2 grain, float t) {
  if (dither == 1) return bayer(grain);
  if (dither == 2) return hash(grain * 0.731 + 3.1);
  if (dither == 3) return hash(grain * 0.731 + floor(t * 12.0) * 7.3);
  return ign(grain);
}

void main() {
  vec2 px = gl_FragCoord.xy;
  vec2 p = (px - 0.5 * resolution) / (0.5 * resolution.y);
  vec2 q = p - centre;
  float d = length(q), angle = atan(q.y, q.x), t = time;
  float ray = 0.5 + 0.5 * sin(angle * round(rays) + sin(angle * round(waves) + swayPhase) * twist + spinPhase);
  // The heartbeat: a double thump (lub-dub) once per beat, which swells the burst and sends a ring outward.
  float phase = fract(beatPhase);
  float thump = exp(-phase * 9.0) + 0.6 * exp(-max(0.0, phase - 0.16) * 9.0) * step(0.16, phase);
  float breath = sin(breathPhase * 6.2832);
  float r = reach - depth * ray - beat * thump * 0.3 - breathe * breath;
  float burst = pow(max(0.0, 1.0 - d * r), falloff) * strength;
  // Rays flare one at a time.
  float flare = noise(vec2(angle * round(rays) / 6.2832, t * 2.3));
  burst *= 1.0 + flicker * (flare - 0.45) * 1.6 * ray;
  // Rings of ink leave the keyhole on each beat, riding the rays and thinning as they go.
  for (int i = 0; i < 2; i++) {
    float age = fract(beatPhase - float(i) * 0.5);
    float front = 0.18 + age * 1.3;
    float band = exp(-pow((d - front) / pulseWidth, 2.0));
    burst += pulse * band * (1.0 - age) * (1.0 - age) * (0.45 + 0.55 * ray);
  }
  burst += (fbm(q * turbulenceScale + driftOffset) - 0.5) * turbulence * (1.0 - d);
  vec2 grain = floor(px / cell);
  float spark = step(1.0 - sparks * (1.0 + 2.0 * beat * thump), hash(grain + floor(sparkPhase) * 17.0)) * smoothstep(sparkReach, 0.2, d);
  float field = clamp(burst + spark, 0.0, 1.0);
  vec2 k = (p - holeOffset) / holeSize;
  float inside = hole * step(keyhole(k, 0.0), 0.0);
  float edge = rim * (1.0 + boil * (noise(k * 9.0 + vec2(t * 1.7, -t * 1.3)) - 0.5) * 2.0 + beat * thump * 0.5);
  float ring = hole * step(keyhole(k, edge / holeSize), 0.0) * (1.0 - inside);
  field = max(field, ring * rimInk) * (1.0 - inside);
  float printed = step(threshold(grain, t), field);
  color = vec4(ink * printed, printed);
}
`

const uniforms = ["rays", "twist", "waves", "reach", "depth", "falloff", "strength", "centre", "turbulence", "turbulenceScale", "sparks", "sparkReach", "hole", "holeSize", "holeOffset", "rim", "rimInk", "beat", "pulse", "pulseWidth", "breathe", "flicker", "boil", "cell", "ink"] as const satisfies readonly (keyof HeaderValues)[]
/** Rates, each with the phase uniform it's integrated into (per second of print time; drift is a vector). */
const rates = { sway: "swayPhase", spin: "spinPhase", pulseRate: "beatPhase", breatheRate: "breathPhase", sparkRate: "sparkPhase", drift: "driftOffset" } as const
type Key = (typeof uniforms)[number] | keyof typeof rates

const rgb = (value: string) => {
  const hex = colorHex(value)
  return [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
}

const numbers = (value: HeaderValues[Key]): number[] =>
  typeof value === "number" ? [value] : typeof value === "boolean" ? [value ? 1 : 0] : typeof value === "string" ? rgb(value) : [value.x, value.y]

const upload = (gl: WebGL2RenderingContext, at: WebGLUniformLocation | null, x: readonly number[]) => {
  if (x.length === 1) gl.uniform1f(at, x[0]!)
  else if (x.length === 2) gl.uniform2f(at, x[0]!, x[1]!)
  else gl.uniform3f(at, x[0]!, x[1]!, x[2]!)
}

const { omega } = springMotion({ duration: 0.5, bounce: 0 })
const reduced = matchMedia("(prefers-reduced-motion: reduce)")
const heartbeat = createHeartbeat()

type Glide = { x: number[]; v: number[]; to: number[]; from: unknown }

export function KeyholePrint({ className }: { className?: string }) {
  const state = useRef({ scale: 1, clock: 7, glide: new Map<string, Glide>(), phase: new Map<string, number[]>() })
  return <ShaderCanvas fragment={fragment} className={className} redraw={header.subscribe}
    setup={(_gl, _u, scale) => { state.current = { scale, clock: 7, glide: new Map(), phase: new Map() } }}
    frame={(gl, u, dt) => {
      const s = state.current, values = header.get()
      const step = values.freeze ? 0 : dt * values.speed
      s.clock += step
      gl.uniform1f(u("time"), s.clock)
      gl.uniform1i(u("dither"), Math.max(0, dithers.indexOf(values.dither)))
      for (const key of [...uniforms, ...Object.keys(rates) as (keyof typeof rates)[]]) {
        const value = values[key]
        let g = s.glide.get(key)
        if (!g || g.from !== value) {
          const to = numbers(value)
          if (!g) s.glide.set(key, g = { x: to.slice(), v: to.map(() => 0), to, from: value })
          g.to = to; g.from = value
        }
        if (glides(key) && !reduced.matches) {
          // A critically damped spring towards the new value, in small steps so a long frame stays stable.
          const steps = Math.ceil(dt * 240), h = dt / Math.max(1, steps)
          for (let i = 0; i < g.x.length; i++) {
            let x = g.x[i]!, v = g.v[i]!
            for (let n = 0; n < steps; n++) {
              v += (omega * omega * (g.to[i]! - x) - 2 * omega * v) * h
              x += v * h
            }
            g.x[i] = x; g.v[i] = v
          }
        } else {
          g.x = g.to.slice(); g.v.fill(0)
        }
        if (key in rates) {
          // The phase is the integral of the rate over print time: it starts where rate × clock would be, then
          // only ever moves by rate × step (a still frame under reduced motion is rate × clock again).
          let phase = s.phase.get(key)
          if (!phase || reduced.matches) s.phase.set(key, phase = g.x.map(r => r * s.clock))
          else phase.forEach((p, i) => { phase![i] = p + g.x[i]! * step })
          upload(gl, u(rates[key as keyof typeof rates]), phase)
        } else {
          upload(gl, u(key), key === "cell" ? [g.x[0]! * s.scale] : g.x)
        }
      }
      if (step > 0) heartbeat(s.phase.get("pulseRate")![0]!, { rate: s.glide.get("pulseRate")!.x[0]!, speed: values.speed, strength: values.beat / .35 })
    }} />
}
