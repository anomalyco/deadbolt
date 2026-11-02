import { useRef } from "react"
import { ShaderCanvas, glslNoise } from "../ShaderCanvas"
import { glslKeyhole, inkRgb, useIntro } from "./shader"

// 02 stipple: the print turned inside out. The keyhole is the ink now, stippled solid with a speckled edge; the
// burst of rays is still behind it, but dim, sparse and dark red. The keyhole develops out of the dither on load.

const fragment = `#version 300 es
precision highp float;
out vec4 color;
uniform vec2 resolution;
uniform float time, cell, intro;
uniform vec3 ink;
${glslNoise}
${glslKeyhole}

void main() {
  vec2 px = gl_FragCoord.xy;
  vec2 p = (px - 0.5 * resolution) / (0.5 * resolution.y);
  vec2 q = p - vec2(0.0, 0.1);
  float d = length(q), a = atan(q.y, q.x), t = time;
  float ray = 0.5 + 0.5 * sin(a * 23.0 + sin(a * 7.0 + t * 0.6) * 2.0 + t * 0.22);
  float burst = pow(max(0.0, 1.0 - d * (1.2 - 0.4 * ray)), 1.6);
  burst += (fbm(q * 3.0 + vec2(0.3, -0.25) * t) - 0.5) * 0.4 * (1.0 - d);
  float k = keyhole(p / 1.18, 0.0) * 1.18;
  float depth = -k;
  // Solid in the middle, speckling out over the last few dots of the edge.
  float lock = step(k, 0.0) * (1.0 - 0.5 * exp(-depth * 28.0));
  vec2 grain = floor(px / cell);
  float th = ign(grain);
  float grow = smoothstep(0.0, 1.0, intro);
  float on = step(th, lock * grow);
  // The burst stays out of a thin black moat around the keyhole.
  float field = clamp(burst, 0.0, 1.0) * 0.28 * smoothstep(0.25, 1.0, intro) * smoothstep(0.03, 0.07, k);
  float dim = step(th, field) * (1.0 - on);
  float alpha = on + dim * 0.42;
  color = vec4(ink * alpha, alpha);
}
`

export function Stipple({ className }: { className?: string }) {
  const intro = useIntro(1.6)
  const scale = useRef(1)
  return <ShaderCanvas fragment={fragment} className={className}
    setup={(gl, u, s) => { scale.current = s; gl.uniform3f(u("ink"), ...inkRgb); gl.uniform1f(u("cell"), 1.75 * s) }}
    frame={(gl, u, dt) => gl.uniform1f(u("intro"), intro(dt))} />
}
