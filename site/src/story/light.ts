import type { Box, Point } from "./motion"

// The light layer: one full-canvas fragment pass that sums every live emitter in the story's scene units as linear
// energy, tone-maps it (1 − e^−x) and writes premultiplied colour. The canvas sits over the crisp SVG and adds to it
// (mix-blend-mode: plus-lighter), so borders and text under a light catch it.
//
// The model, emitter by emitter:
// - Heads bloom; nothing else does. A head is smeared along its motion over a short shutter, like a photograph.
// - Trails are filaments cooling behind the head: white-hot where fresh, the signal's tone as they cool, then dark.
// - Floods wick into a card from the socket they arrived at, with a ragged front like ink soaking into paper; the
//   card's frame and inset rule catch the light where the front reaches them.
// - Borders near a head catch its light.
// - Prints are the card's own ink, not light: sealed ciphertext as a field of dithered bits, a relay as hatched
//   noise. They clear or churn on cue.
// - All light catches the paper's tooth (a static grain in scene units, so it never crawls).
//
// WebGPU first (one shared device for every story), then WebGL2 running the same shader in GLSL, then the caller's
// SVG fallback. Both GPU paths take the same packed vec4 array, and every value is a function of the scene clock.

export type Tone = "ivory" | "red" | "amber" | "hot"
const TONES: Record<Tone, number> = { ivory: 0, red: 1, amber: 2, hot: 3 }

export type Print = {
  box: Box
  /** "cipher": sealed bits in words. "hatch": diagonal hatching broken by noise. */
  kind: "cipher" | "hatch"
  tone: Tone
  /** Ink level, 0..1. */
  level: number
  seed: number
  /** A cleared disc growing from a point (the cipher unsealing from its socket). */
  open?: { from: Point; radius: number }
  /** Changes the bits (cipher) or scrolls the hatching (hatch). Derive it from the scene clock. */
  churn?: number
}

/** Everything lit in one frame, in scene units. */
export type Light = {
  /** A stretch of a trail: temperature at each end (0..1), core width. */
  segments: { a: Point; b: Point; heat: readonly [number, number]; width: number; tone: Tone }[]
  /** A packet head or a spark: a solid core that blooms, smeared back to `from` over the shutter. */
  dots: { at: Point; from?: Point; radius: number; intensity: number; tone: Tone }[]
  rings: { at: Point; radius: number; width: number; intensity: number; tone: Tone }[]
  /** Light wicking into a box from a point on its edge; its border catches it where the front reaches. */
  floods: { box: Box; from: Point; reach: number; intensity: number; tone: Tone }[]
  /** Frames whose borders catch light from nearby heads. */
  frames: Box[]
  prints: Print[]
}

export const emptyLight = (): Light => ({ segments: [], dots: [], rings: [], floods: [], frames: [], prints: [] })

/** The light's look, uniform across stories (tuned live in development; see tuning.ts). */
export type LightParams = {
  exposure: number
  bloom: number
  grain: number
  /** Halo on the hottest stretch of a trail, just behind the head. */
  glow: number
  reflection: number
  flood: number
  ink: number
  /** Ragged ink-bleed edge on trails and flood fronts, in scene units. */
  bleed: number
}

const MAX = { segments: 96, dots: 12, rings: 12, floods: 8, frames: 16, prints: 6 }
const HEAD = 5
const BASE = {
  segments: HEAD,
  dots: HEAD + MAX.segments * 2,
  rings: HEAD + MAX.segments * 2 + MAX.dots * 2,
  floods: HEAD + MAX.segments * 2 + MAX.dots * 2 + MAX.rings * 2,
  frames: HEAD + MAX.segments * 2 + MAX.dots * 2 + MAX.rings * 2 + MAX.floods * 3,
  prints: HEAD + MAX.segments * 2 + MAX.dots * 2 + MAX.rings * 2 + MAX.floods * 3 + MAX.frames,
}
const VEC4S = BASE.prints + MAX.prints * 3

/** Light below this never reaches a visible level after tone mapping and dithering. */
const LIVE = .004

const hotter = (a: Light["segments"][number], b: Light["segments"][number]) => Math.max(b.heat[0], b.heat[1]) - Math.max(a.heat[0], a.heat[1])

/** Packs a frame. Returns null when nothing is lit or printed, so the caller can clear once and rest. */
export function pack(light: Light, data: Float32Array, size: { width: number; height: number; scale: number }, params: LightParams, fade = 1) {
  data.fill(0)
  let segments = light.segments.filter(s => Math.max(s.heat[0], s.heat[1]) * fade > LIVE)
  // Over budget, the coolest stretches go first.
  if (segments.length > MAX.segments) segments = [...segments].sort(hotter).slice(0, MAX.segments)
  const dots = light.dots.filter(d => d.intensity * fade > LIVE).slice(0, MAX.dots)
  const rings = light.rings.filter(r => r.intensity * fade > LIVE).slice(0, MAX.rings)
  const floods = light.floods.filter(f => f.intensity * fade > LIVE).slice(0, MAX.floods)
  const prints = light.prints.filter(p => p.level * fade > LIVE).slice(0, MAX.prints)
  if (!segments.length && !dots.length && !rings.length && !floods.length && !prints.length) return null
  const frames = dots.length ? light.frames.slice(0, MAX.frames) : []
  data.set([
    size.width, size.height, size.scale, fade,
    segments.length, dots.length, rings.length, floods.length,
    frames.length, prints.length, 0, 0,
    params.exposure, params.bloom, params.grain, params.glow,
    params.reflection, params.flood, params.ink, params.bleed,
  ], 0)
  segments.forEach((s, i) => data.set([s.a[0], s.a[1], s.b[0], s.b[1], s.heat[0], s.heat[1], s.width, TONES[s.tone]], (BASE.segments + i * 2) * 4))
  dots.forEach((d, i) => data.set([d.at[0], d.at[1], d.radius, d.intensity, ...(d.from ?? d.at), TONES[d.tone]], (BASE.dots + i * 2) * 4))
  rings.forEach((r, i) => data.set([r.at[0], r.at[1], r.radius, r.width, r.intensity, TONES[r.tone]], (BASE.rings + i * 2) * 4))
  floods.forEach((f, i) => data.set([...f.box, f.from[0], f.from[1], f.reach, f.intensity, TONES[f.tone]], (BASE.floods + i * 3) * 4))
  frames.forEach((b, i) => data.set(b, (BASE.frames + i) * 4))
  prints.forEach((p, i) => data.set([
    ...p.box, p.kind === "hatch" ? 1 : 0, TONES[p.tone], p.level, p.seed,
    ...(p.open?.from ?? [0, 0]), p.open?.radius ?? 0, p.churn ?? 0,
  ], (BASE.prints + i * 3) * 4))
  return data
}

export const packedLength = VEC4S * 4

// The shader, written once as WGSL; the GLSL below is the same program line for line.
const WGSL = /* wgsl */ `
struct U { v: array<vec4f, ${VEC4S}> }
@group(0) @binding(0) var<uniform> u: U;

@vertex fn vs(@builtin(vertex_index) i: u32) -> @builtin(position) vec4f {
  let p = vec2f(f32((i << 1u) & 2u), f32(i & 2u));
  return vec4f(p * 2.0 - 1.0, 0.0, 1.0);
}

fn tone(c: f32) -> vec3f {
  if (c < 0.5) { return vec3f(0.91, 0.89, 0.86); }
  if (c < 1.5) { return vec3f(1.0, 0.17, 0.12); }
  if (c < 2.5) { return vec3f(1.0, 0.66, 0.26); }
  return vec3f(1.0, 0.945, 0.86);
}
// A cooling filament: white-hot at the top, the signal's tone as it cools, deeper still near the end.
fn temper(c: f32, t: f32) -> vec3f {
  let base = tone(c);
  return mix(mix(base * base, base, smoothstep(0.0, 0.45, t)), tone(3.0), smoothstep(0.55, 1.0, t));
}
fn ign(p: vec2f) -> f32 { return fract(52.9829189 * fract(0.06711056 * p.x + 0.00583715 * p.y)); }
fn hash(p: vec2f) -> f32 { var h = fract(p * vec2f(123.34, 456.21)); h += dot(h, h + 45.32); return fract(h.x * h.y); }
fn noise(p: vec2f) -> f32 {
  let i = floor(p);
  let f = fract(p);
  let w = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2f(1.0, 0.0)), w.x), mix(hash(i + vec2f(0.0, 1.0)), hash(i + vec2f(1.0, 1.0)), w.x), w.y);
}
// Paper: a fine tooth plus long fibres running across the sheet. In scene units, so it never crawls.
fn paper(q: vec2f) -> f32 { return noise(q * 1.9 + 3.1) * 0.55 + noise(q * vec2f(0.21, 1.7) + 9.7) * 0.45; }
fn sdBox(p: vec2f, b: vec4f) -> f32 {
  let d = abs(p - (b.xy + b.zw * 0.5)) - b.zw * 0.5;
  return length(max(d, vec2f(0.0))) + min(max(d.x, d.y), 0.0);
}
fn sdSegment(p: vec2f, a: vec2f, b: vec2f) -> f32 {
  let pa = p - a;
  let ba = b - a;
  let h = clamp(dot(pa, ba) / max(dot(ba, ba), 1e-4), 0.0, 1.0);
  return length(pa - ba * h);
}
// Reflection falloff: 1, .65, .16, 0 at 0, .3, .7, 1 of the radius.
fn falloff(r: f32) -> f32 {
  if (r >= 1.0) { return 0.0; }
  if (r < 0.3) { return mix(1.0, 0.65, r / 0.3); }
  if (r < 0.7) { return mix(0.65, 0.16, (r - 0.3) / 0.4); }
  return mix(0.16, 0.0, (r - 0.7) / 0.3);
}
fn rule(p: vec2f, b: vec4f, inset: f32, px: f32) -> f32 {
  let e = abs(sdBox(p, vec4f(b.xy + vec2f(inset), b.zw - vec2f(inset * 2.0))));
  return 1.0 - smoothstep(0.5 * px, 1.5 * px, e);
}

@fragment fn fs(@builtin(position) frag: vec4f) -> @location(0) vec4f {
  let head = u.v[0];
  let counts = u.v[1];
  let more = u.v[2];
  let look = u.v[3];
  let feel = u.v[4];
  let px = 1.0 / head.z;
  let q = frag.xy * px;
  let hot = tone(3.0);
  let grain = paper(q);
  let bleed = (grain - 0.5) * feel.w;
  var col = vec3f(0.0);

  // Trails: max, not sum, so joints don't bead. Only the hottest stretch, just behind the head, glows.
  var trail = vec3f(0.0);
  for (var i = 0; i < i32(counts.x); i++) {
    let a = u.v[${BASE.segments} + i * 2];
    let m = u.v[${BASE.segments} + i * 2 + 1];
    let w = m.z;
    let reach = w * 6.0;
    if (q.x < min(a.x, a.z) - reach || q.x > max(a.x, a.z) + reach || q.y < min(a.y, a.w) - reach || q.y > max(a.y, a.w) + reach) { continue; }
    let pa = q - a.xy;
    let ba = a.zw - a.xy;
    let h = clamp(dot(pa, ba) / max(dot(ba, ba), 1e-4), 0.0, 1.0);
    let d = length(pa - ba * h) + bleed;
    let t = mix(m.x, m.y, h);
    let core = 1.0 - smoothstep(w * 0.5 - px * 0.5, w * 0.5 + px, d);
    let halo = exp(-max(d, 0.0) / (2.2 * w)) * smoothstep(0.7, 1.0, t) * look.w;
    trail = max(trail, temper(m.w, t) * 0.85 * pow(max(t, 1e-4), 1.2) * (core + halo * 0.35));
  }
  col += trail;

  // Heads: a solid core smeared along its motion, and the only bloom in the scene.
  for (var i = 0; i < i32(counts.y); i++) {
    let a = u.v[${BASE.dots} + i * 2];
    let b = u.v[${BASE.dots} + i * 2 + 1];
    let r = a.z;
    let smear = length(a.xy - b.xy);
    let d = sdSegment(q, b.xy, a.xy);
    let k = a.w * mix(1.0, (2.0 * r) / (2.0 * r + smear), 0.6);
    let solid = 1.0 - smoothstep(r - px, r + px, d);
    col += hot * k * solid * 1.4;
    col += mix(tone(b.z), hot, 0.35) * k * look.y * (exp(-d / (1.2 * r)) * 0.45 + exp(-d / (4.0 * r)) * 0.1);
  }

  // Rings: a stroke that opens, thins and cools.
  for (var i = 0; i < i32(counts.z); i++) {
    let a = u.v[${BASE.rings} + i * 2];
    let b = u.v[${BASE.rings} + i * 2 + 1];
    let e = abs(length(q - a.xy) - a.z);
    let band = 1.0 - smoothstep(a.w * 0.5 - px * 0.5, a.w * 0.5 + px, e);
    col += temper(b.y, min(1.0, 0.45 + b.x * 0.6)) * b.x * band;
  }

  // Floods: light wicking in from the socket. The wet region grows from the socket with a ragged front and a
  // brighter tide line, brightest near the socket; it's printed mostly as a stipple over a faint wash, and the
  // frame and its inset rule catch it in proportion, so the border lights from the socket outward.
  for (var i = 0; i < i32(counts.w); i++) {
    let box = u.v[${BASE.floods} + i * 3];
    let s = u.v[${BASE.floods} + i * 3 + 1];
    let c = u.v[${BASE.floods} + i * 3 + 2];
    let sd = sdBox(q, box);
    if (sd > px * 2.0) { continue; }
    let inside = 1.0 - smoothstep(-px, px, sd);
    let r = length(q - s.xy) / max(s.z, 1e-3) + (grain - 0.5) * 0.3 + bleed * 0.02;
    let body = (1.0 - smoothstep(0.72, 1.0, r)) * (1.0 - 0.6 * clamp(r, 0.0, 1.0));
    let z = (r - 0.9) / 0.09;
    let tide = exp(-z * z);
    let wash = (body * 0.6 + tide * 0.4) * s.w * feel.y;
    let print = step(ign(floor(frag.xy / 2.0)), wash * 2.4);
    let edge = rule(q, box, 0.5, px) * 0.5 + rule(q, box, 3.5, px) * 0.3;
    col += tone(c.x) * (inside * (wash * 0.16 + print * wash * 0.2) + edge * (body * 0.55 + tide * 0.45) * s.w * feel.y * 0.8);
  }

  // Borders near a head catch its light.
  for (var f = 0; f < i32(more.x); f++) {
    let box = u.v[${BASE.frames} + f];
    let edge = rule(q, box, 0.5, px) + rule(q, box, 3.5, px) * 0.4;
    if (edge <= 0.0) { continue; }
    for (var i = 0; i < i32(counts.y); i++) {
      let a = u.v[${BASE.dots} + i * 2];
      let b = u.v[${BASE.dots} + i * 2 + 1];
      col += mix(tone(b.z), hot, 0.3) * a.w * falloff(length(q - a.xy) / 80.0) * 0.6 * feel.x * edge;
    }
  }

  // Prints: the card's own ink. Ciphertext is words of square bits; a hatch is diagonal strokes broken by noise.
  var ink = vec3f(0.0);
  for (var i = 0; i < i32(more.y); i++) {
    let box = u.v[${BASE.prints} + i * 3];
    let m = u.v[${BASE.prints} + i * 3 + 1];
    let o = u.v[${BASE.prints} + i * 3 + 2];
    if (sdBox(q, box) > 0.0) { continue; }
    let local = q - box.xy;
    var mark = 0.0;
    var front = 0.0;
    if (m.x < 0.5) {
      let cell = 2.6;
      let id = floor(local / cell);
      let f = fract(local / cell) - 0.5;
      let word = step(id.x - floor(id.x / 6.0) * 6.0, 4.5);
      let bit = step(0.46, hash(id + vec2f(m.w * 13.1 + o.w * 7.7, m.w * 3.3)));
      let square = (1.0 - smoothstep(0.32 - px / cell, 0.32 + px / cell, abs(f.x))) * (1.0 - smoothstep(0.32 - px / cell, 0.32 + px / cell, abs(f.y)));
      let dist = length(box.xy + (id + 0.5) * cell - o.xy);
      let open = step(0.5, o.z);
      mark = word * bit * square * mix(1.0, smoothstep(o.z - 3.0, o.z + 1.0, dist), open);
      front = word * bit * square * open * exp(-(dist - o.z) * (dist - o.z) / 12.25);
    } else {
      let s = (local.x + local.y + o.w) / 3.4;
      let stroke = 1.0 - smoothstep(0.16, 0.16 + px / 3.4 * 2.0, abs(fract(s) - 0.5));
      let broken = step(0.4, noise(vec2f(floor(s) * 1.7 + m.w, (local.y - local.x) * 0.16)));
      mark = stroke * broken;
    }
    ink += temper(m.y, 0.3) * m.z * feel.z * mark * 0.2;
    col += temper(m.y, 0.85) * m.z * feel.z * front * 0.9;
  }

  // Light (not ink) catches the paper's tooth.
  col *= 1.0 - look.z * (grain - 0.35);
  col = (1.0 - exp(-(col + ink) * look.x)) * head.w;
  col += (ign(frag.xy) - 0.5) / 255.0 * min(max(col.r, max(col.g, col.b)) * 60.0, 1.0);
  col = max(col, vec3f(0.0));
  let alpha = clamp(max(col.r, max(col.g, col.b)), 0.0, 1.0);
  return vec4f(min(col, vec3f(alpha)), alpha);
}
`

const GLSL_VS = /* glsl */ `#version 300 es
void main() {
  vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));
  gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}
`

const GLSL_FS = /* glsl */ `#version 300 es
precision highp float;
uniform vec4 v[${VEC4S}];
out vec4 outColor;

vec3 tone(float c) {
  if (c < 0.5) return vec3(0.91, 0.89, 0.86);
  if (c < 1.5) return vec3(1.0, 0.17, 0.12);
  if (c < 2.5) return vec3(1.0, 0.66, 0.26);
  return vec3(1.0, 0.945, 0.86);
}
vec3 temper(float c, float t) {
  vec3 base = tone(c);
  return mix(mix(base * base, base, smoothstep(0.0, 0.45, t)), tone(3.0), smoothstep(0.55, 1.0, t));
}
float ign(vec2 p) { return fract(52.9829189 * fract(0.06711056 * p.x + 0.00583715 * p.y)); }
float hash(vec2 p) { vec2 h = fract(p * vec2(123.34, 456.21)); h += dot(h, h + 45.32); return fract(h.x * h.y); }
float noise(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  vec2 w = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), w.x), mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), w.x), w.y);
}
float paper(vec2 q) { return noise(q * 1.9 + 3.1) * 0.55 + noise(q * vec2(0.21, 1.7) + 9.7) * 0.45; }
float sdBox(vec2 p, vec4 b) {
  vec2 d = abs(p - (b.xy + b.zw * 0.5)) - b.zw * 0.5;
  return length(max(d, vec2(0.0))) + min(max(d.x, d.y), 0.0);
}
float sdSegment(vec2 p, vec2 a, vec2 b) {
  vec2 pa = p - a;
  vec2 ba = b - a;
  float h = clamp(dot(pa, ba) / max(dot(ba, ba), 1e-4), 0.0, 1.0);
  return length(pa - ba * h);
}
float falloff(float r) {
  if (r >= 1.0) return 0.0;
  if (r < 0.3) return mix(1.0, 0.65, r / 0.3);
  if (r < 0.7) return mix(0.65, 0.16, (r - 0.3) / 0.4);
  return mix(0.16, 0.0, (r - 0.7) / 0.3);
}
float rule(vec2 p, vec4 b, float inset, float px) {
  float e = abs(sdBox(p, vec4(b.xy + vec2(inset), b.zw - vec2(inset * 2.0))));
  return 1.0 - smoothstep(0.5 * px, 1.5 * px, e);
}

void main() {
  // WebGL's origin is bottom-left; the scene's is top-left.
  vec2 fragXY = vec2(gl_FragCoord.x, v[0].y - gl_FragCoord.y);
  vec4 head = v[0];
  vec4 counts = v[1];
  vec4 more = v[2];
  vec4 look = v[3];
  vec4 feel = v[4];
  float px = 1.0 / head.z;
  vec2 q = fragXY * px;
  vec3 hot = tone(3.0);
  float grain = paper(q);
  float bleed = (grain - 0.5) * feel.w;
  vec3 col = vec3(0.0);

  vec3 trail = vec3(0.0);
  for (int i = 0; i < int(counts.x); i++) {
    vec4 a = v[${BASE.segments} + i * 2];
    vec4 m = v[${BASE.segments} + i * 2 + 1];
    float w = m.z;
    float reach = w * 6.0;
    if (q.x < min(a.x, a.z) - reach || q.x > max(a.x, a.z) + reach || q.y < min(a.y, a.w) - reach || q.y > max(a.y, a.w) + reach) continue;
    vec2 pa = q - a.xy;
    vec2 ba = a.zw - a.xy;
    float h = clamp(dot(pa, ba) / max(dot(ba, ba), 1e-4), 0.0, 1.0);
    float d = length(pa - ba * h) + bleed;
    float t = mix(m.x, m.y, h);
    float core = 1.0 - smoothstep(w * 0.5 - px * 0.5, w * 0.5 + px, d);
    float halo = exp(-max(d, 0.0) / (2.2 * w)) * smoothstep(0.7, 1.0, t) * look.w;
    trail = max(trail, temper(m.w, t) * 0.85 * pow(max(t, 1e-4), 1.2) * (core + halo * 0.35));
  }
  col += trail;

  for (int i = 0; i < int(counts.y); i++) {
    vec4 a = v[${BASE.dots} + i * 2];
    vec4 b = v[${BASE.dots} + i * 2 + 1];
    float r = a.z;
    float smear = length(a.xy - b.xy);
    float d = sdSegment(q, b.xy, a.xy);
    float k = a.w * mix(1.0, (2.0 * r) / (2.0 * r + smear), 0.6);
    float solid = 1.0 - smoothstep(r - px, r + px, d);
    col += hot * k * solid * 1.4;
    col += mix(tone(b.z), hot, 0.35) * k * look.y * (exp(-d / (1.2 * r)) * 0.45 + exp(-d / (4.0 * r)) * 0.1);
  }

  for (int i = 0; i < int(counts.z); i++) {
    vec4 a = v[${BASE.rings} + i * 2];
    vec4 b = v[${BASE.rings} + i * 2 + 1];
    float e = abs(length(q - a.xy) - a.z);
    float band = 1.0 - smoothstep(a.w * 0.5 - px * 0.5, a.w * 0.5 + px, e);
    col += temper(b.y, min(1.0, 0.45 + b.x * 0.6)) * b.x * band;
  }

  for (int i = 0; i < int(counts.w); i++) {
    vec4 box = v[${BASE.floods} + i * 3];
    vec4 s = v[${BASE.floods} + i * 3 + 1];
    vec4 c = v[${BASE.floods} + i * 3 + 2];
    float sd = sdBox(q, box);
    if (sd > px * 2.0) continue;
    float inside = 1.0 - smoothstep(-px, px, sd);
    float r = length(q - s.xy) / max(s.z, 1e-3) + (grain - 0.5) * 0.3 + bleed * 0.02;
    float body = (1.0 - smoothstep(0.72, 1.0, r)) * (1.0 - 0.6 * clamp(r, 0.0, 1.0));
    float z = (r - 0.9) / 0.09;
    float tide = exp(-z * z);
    float wash = (body * 0.6 + tide * 0.4) * s.w * feel.y;
    float print = step(ign(floor(fragXY / 2.0)), wash * 2.4);
    float edge = rule(q, box, 0.5, px) * 0.5 + rule(q, box, 3.5, px) * 0.3;
    col += tone(c.x) * (inside * (wash * 0.16 + print * wash * 0.2) + edge * (body * 0.55 + tide * 0.45) * s.w * feel.y * 0.8);
  }

  for (int f = 0; f < int(more.x); f++) {
    vec4 box = v[${BASE.frames} + f];
    float edge = rule(q, box, 0.5, px) + rule(q, box, 3.5, px) * 0.4;
    if (edge <= 0.0) continue;
    for (int i = 0; i < int(counts.y); i++) {
      vec4 a = v[${BASE.dots} + i * 2];
      vec4 b = v[${BASE.dots} + i * 2 + 1];
      col += mix(tone(b.z), hot, 0.3) * a.w * falloff(length(q - a.xy) / 80.0) * 0.6 * feel.x * edge;
    }
  }

  vec3 ink = vec3(0.0);
  for (int i = 0; i < int(more.y); i++) {
    vec4 box = v[${BASE.prints} + i * 3];
    vec4 m = v[${BASE.prints} + i * 3 + 1];
    vec4 o = v[${BASE.prints} + i * 3 + 2];
    if (sdBox(q, box) > 0.0) continue;
    vec2 local = q - box.xy;
    float mark = 0.0;
    float front = 0.0;
    if (m.x < 0.5) {
      float cell = 2.6;
      vec2 id = floor(local / cell);
      vec2 f = fract(local / cell) - 0.5;
      float word = step(id.x - floor(id.x / 6.0) * 6.0, 4.5);
      float bit = step(0.46, hash(id + vec2(m.w * 13.1 + o.w * 7.7, m.w * 3.3)));
      float square = (1.0 - smoothstep(0.32 - px / cell, 0.32 + px / cell, abs(f.x))) * (1.0 - smoothstep(0.32 - px / cell, 0.32 + px / cell, abs(f.y)));
      float dist = length(box.xy + (id + 0.5) * cell - o.xy);
      float open = step(0.5, o.z);
      mark = word * bit * square * mix(1.0, smoothstep(o.z - 3.0, o.z + 1.0, dist), open);
      front = word * bit * square * open * exp(-(dist - o.z) * (dist - o.z) / 12.25);
    } else {
      float s = (local.x + local.y + o.w) / 3.4;
      float stroke = 1.0 - smoothstep(0.16, 0.16 + px / 3.4 * 2.0, abs(fract(s) - 0.5));
      float broken = step(0.4, noise(vec2(floor(s) * 1.7 + m.w, (local.y - local.x) * 0.16)));
      mark = stroke * broken;
    }
    ink += temper(m.y, 0.3) * m.z * feel.z * mark * 0.2;
    col += temper(m.y, 0.85) * m.z * feel.z * front * 0.9;
  }

  col *= 1.0 - look.z * (grain - 0.35);
  col = (1.0 - exp(-(col + ink) * look.x)) * head.w;
  col += (ign(fragXY) - 0.5) / 255.0 * min(max(col.r, max(col.g, col.b)) * 60.0, 1.0);
  col = max(col, vec3(0.0));
  float alpha = clamp(max(col.r, max(col.g, col.b)), 0.0, 1.0);
  outColor = vec4(min(col, vec3(alpha)), alpha);
}
`

export type Renderer = {
  backend: "webgpu" | "webgl2"
  /** Draws a packed frame, or clears the canvas when given null. */
  draw(data: Float32Array | null): void
  dispose(): void
}

const BUFFER_UNIFORM = 0x40, BUFFER_COPY_DST = 0x8

type Shared = { device: GPUDevice; format: GPUTextureFormat; pipeline: GPURenderPipeline }
let shared: Promise<Shared | null> | undefined

/** One adapter, device and pipeline for every story on the page. */
function sharedGpu() {
  return shared ??= (async () => {
    const gpu = navigator.gpu as GPU | undefined
    if (!gpu || new URLSearchParams(location.search).get("light") === "webgl2") return null
    try {
      const adapter = await gpu.requestAdapter()
      const device = await adapter?.requestDevice()
      if (!device) return null
      const module = device.createShaderModule({ code: WGSL })
      const info = await module.getCompilationInfo?.()
      if (info?.messages.some(m => m.type === "error")) { console.warn(info.messages.map(m => m.message).join("\n")); return null }
      const format = gpu.getPreferredCanvasFormat()
      const pipeline = device.createRenderPipeline({
        layout: "auto",
        vertex: { module, entryPoint: "vs" },
        fragment: { module, entryPoint: "fs", targets: [{ format }] },
        primitive: { topology: "triangle-list" },
      })
      device.lost.then(() => { shared = undefined })
      return { device, format, pipeline }
    } catch (error) {
      console.warn(error)
      return null
    }
  })()
}

async function webgpu(canvas: HTMLCanvasElement): Promise<Renderer | null> {
  const gpu = await sharedGpu()
  const context = gpu && canvas.getContext("webgpu") as GPUCanvasContext | null
  if (!gpu || !context) return null
  const { device, format, pipeline } = gpu
  context.configure({ device, format, alphaMode: "premultiplied" })
  const buffer = device.createBuffer({ size: packedLength * 4, usage: BUFFER_UNIFORM | BUFFER_COPY_DST })
  const group = device.createBindGroup({ layout: pipeline.getBindGroupLayout(0), entries: [{ binding: 0, resource: { buffer } }] })
  return {
    backend: "webgpu",
    draw(data) {
      if (!canvas.width || !canvas.height) return
      if (data) device.queue.writeBuffer(buffer, 0, data.buffer, data.byteOffset, data.byteLength)
      const encoder = device.createCommandEncoder()
      const pass = encoder.beginRenderPass({
        colorAttachments: [{ view: context.getCurrentTexture().createView(), loadOp: "clear", storeOp: "store", clearValue: { r: 0, g: 0, b: 0, a: 0 } }],
      })
      if (data) { pass.setPipeline(pipeline); pass.setBindGroup(0, group); pass.draw(3) }
      pass.end()
      device.queue.submit([encoder.finish()])
    },
    dispose() { buffer.destroy() },
  }
}

function webgl2(canvas: HTMLCanvasElement): Renderer | null {
  const gl = canvas.getContext("webgl2", { antialias: false, alpha: true, premultipliedAlpha: true, powerPreference: "low-power" })
  if (!gl || gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS) < VEC4S) return null
  const compile = (type: number, source: string) => {
    const shader = gl.createShader(type)!
    gl.shaderSource(shader, source)
    gl.compileShader(shader)
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) { console.warn(gl.getShaderInfoLog(shader)); return null }
    return shader
  }
  const vs = compile(gl.VERTEX_SHADER, GLSL_VS), fs = compile(gl.FRAGMENT_SHADER, GLSL_FS)
  if (!vs || !fs) return null
  const program = gl.createProgram()!
  gl.attachShader(program, vs)
  gl.attachShader(program, fs)
  gl.linkProgram(program)
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) { console.warn(gl.getProgramInfoLog(program)); return null }
  const location = gl.getUniformLocation(program, "v")
  const vao = gl.createVertexArray()
  return {
    backend: "webgl2",
    draw(data) {
      gl.viewport(0, 0, canvas.width, canvas.height)
      gl.clearColor(0, 0, 0, 0)
      gl.clear(gl.COLOR_BUFFER_BIT)
      if (!data) return
      gl.useProgram(program)
      gl.bindVertexArray(vao)
      gl.uniform4fv(location, data)
      gl.drawArrays(gl.TRIANGLES, 0, 3)
    },
    dispose() { gl.deleteProgram(program); gl.deleteVertexArray(vao) },
  }
}

/** WebGPU, else WebGL2, else null (the story draws its SVG fallback). `?light=webgl2|svg` forces a path. */
export async function createRenderer(canvas: HTMLCanvasElement): Promise<Renderer | null> {
  const forced = new URLSearchParams(location.search).get("light")
  if (forced === "svg") return null
  return (await webgpu(canvas)) ?? webgl2(canvas)
}
