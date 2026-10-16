import type { MotionValue } from "motion/react"
import { ShaderCanvas, glslNoise } from "./ShaderCanvas"

// Ciphertext you can see but not read: a churning dithered field inside a card. `heat` (0..1) brightens it while
// something is happening inside (a write sealed, a record opened, bytes forwarded). Shape, never text.

const fragment = `#version 300 es
precision highp float;
out vec4 color;
uniform vec2 resolution;
uniform float time, cell, heat, density;
uniform vec3 ink;
${glslNoise}

void main() {
  vec2 px = gl_FragCoord.xy;
  vec2 uv = px / resolution.y;
  float t = time;
  float warp = (fbm(vec2(uv.y * 4.0 + t * 0.7, uv.x * 1.5 - t * 0.3)) - 0.5) * 0.25;
  float churn = fbm(vec2(uv.x * 6.0 - t * (0.6 + heat * 2.0) + warp, uv.y * 5.0));
  float hatch = step(0.6, fract((uv.x + uv.y + warp) * 18.0));
  float field = density * (0.35 + 0.65 * churn) * (0.45 + 0.55 * hatch) * (0.35 + heat * 0.9);
  vec2 grain = floor(px / cell);
  float printed = step(ign(grain + floor(t * 12.0) * heat * 3.0), field);
  color = vec4(ink * printed, printed);
}
`

export function SealField({ heat, className, ink = [1, 42 / 255, 42 / 255], density = .55, cell = 1.5 }: {
  heat?: MotionValue<number>; className?: string; ink?: readonly [number, number, number]; density?: number; cell?: number
}) {
  return <ShaderCanvas fragment={fragment} className={className} setup={(gl, u, scale) => {
    gl.uniform1f(u("cell"), cell * scale)
    gl.uniform3f(u("ink"), ink[0], ink[1], ink[2])
    gl.uniform1f(u("density"), density)
  }} frame={(gl, u) => gl.uniform1f(u("heat"), heat?.get() ?? 0)} />
}
