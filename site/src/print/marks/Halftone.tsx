import { ShaderCanvas, glslNoise } from "../ShaderCanvas"
import { glslKeyhole, inkRgb, useIntro } from "./shader"

// 08 halftone: a padlock in a coarse 45° halftone screen. Inside the lock the dots are big and shaded, heavier to the lower left;
// outside, a faint halo of small dark dots that slowly breathes. On load the dots swell from the middle out.

const fragment = `#version 300 es
precision highp float;
out vec4 color;
uniform vec2 resolution;
uniform float time, cell, intro;
uniform vec3 ink;
${glslNoise}
${glslKeyhole}

float roundBox(vec2 p, vec2 b, float r) { vec2 q = abs(p) - b + r; return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r; }

float padlock(vec2 p) {
  p = p / 1.14 - vec2(0.0, 0.08);
  float body = roundBox(p - vec2(0.0, -0.3), vec2(0.46, 0.34), 0.06);
  vec2 s = p - vec2(0.0, 0.14);
  float arc = s.y > 0.0 ? abs(length(s) - 0.27) - 0.08 : max(abs(abs(s.x) - 0.27) - 0.08, -(s.y + 0.2));
  float hole = keyhole((p - vec2(0.0, -0.3)) / 0.52, 0.0) * 0.52;
  return max(min(body, arc), -hole) * 1.14;
}

void main() {
  vec2 px = gl_FragCoord.xy;
  const float c = 0.7071;
  mat2 turn = mat2(c, c, -c, c);
  vec2 g = turn * px / cell;
  vec2 id = floor(g) + 0.5;
  vec2 at = transpose(turn) * id * cell;
  vec2 p = (at - 0.5 * resolution) / (0.5 * resolution.y);
  float sd = padlock(p);
  float inside = step(sd, 0.0);
  float t = time;
  float halo = 0.2 * exp(-max(sd, 0.0) * 8.0) * (0.7 + 0.3 * sin(t * 0.9 - length(p) * 3.0));
  halo *= 0.85 + 0.3 * noise(p * 4.0 + vec2(t * 0.15, -t * 0.1));
  // The lock is shaded like a printed photo: heavier dots lower left, lighter upper right.
  float shade = clamp(0.5 - (p.x + p.y) * 0.45, 0.0, 1.0);
  float cover = inside > 0.5 ? 0.32 + 0.55 * shade : halo;
  // Dots swell outward from the middle of the lock, the halo a beat behind.
  float front = intro * 1.9 - length(p);
  cover *= smoothstep(0.0, 0.35, front - (1.0 - inside) * 0.25);
  float radius = sqrt(cover) * 0.62;
  float dist = length(g - id);
  float aa = fwidth(dist);
  float dot_ = 1.0 - smoothstep(radius - aa, radius + aa, dist);
  float alpha = dot_ * (inside > 0.5 ? 1.0 : 0.45);
  color = vec4(ink * alpha, alpha);
}
`

export function Halftone({ className }: { className?: string }) {
  const intro = useIntro(1.4)
  return <ShaderCanvas fragment={fragment} className={className}
    setup={(gl, u, s) => { gl.uniform3f(u("ink"), ...inkRgb); gl.uniform1f(u("cell"), 3.8 * s) }}
    frame={(gl, u, dt) => gl.uniform1f(u("intro"), intro(dt))} />
}
