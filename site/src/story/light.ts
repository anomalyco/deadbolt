import type { Box, Point } from "./motion"

// The light layer: one full-canvas fragment pass that sums every live light in the story's scene units, then
// tone-maps (1 − e^−x), dithers against banding and writes premultiplied colour. The canvas sits over the crisp
// SVG and adds to it (mix-blend-mode: plus-lighter), so borders and text under a light catch it.
//
// WebGPU first (one shared device for every story), then WebGL2 running the same shader in GLSL, then the
// caller's SVG fallback. Both GPU paths take the same packed vec4 array.

export type Tone = "ivory" | "red" | "amber" | "hot"
const TONES: Record<Tone, number> = { ivory: 0, red: 1, amber: 2, hot: 3 }

/** Everything lit in one frame, in scene units. */
export type Light = {
  /** A stretch of a trail: heat at each end (0..1), core width. */
  segments: { a: Point; b: Point; heat: readonly [number, number]; width: number; tone: Tone }[]
  /** A packet head or a spark: a solid core that blooms. */
  dots: { at: Point; radius: number; intensity: number; tone: Tone }[]
  rings: { at: Point; radius: number; width: number; intensity: number; tone: Tone }[]
  /** Light flooding into a box from a point on its edge; its border catches some of it. */
  floods: { box: Box; from: Point; reach: number; intensity: number; tone: Tone }[]
  /** Frames whose borders catch light from nearby dots. */
  frames: Box[]
}

export const emptyLight = (): Light => ({ segments: [], dots: [], rings: [], floods: [], frames: [] })

const MAX = { segments: 72, dots: 10, rings: 10, floods: 8, frames: 12 }
const BASE = {
  segments: 4,
  dots: 4 + MAX.segments * 2,
  rings: 4 + MAX.segments * 2 + MAX.dots * 2,
  floods: 4 + MAX.segments * 2 + MAX.dots * 2 + MAX.rings * 2,
  frames: 4 + MAX.segments * 2 + MAX.dots * 2 + MAX.rings * 2 + MAX.floods * 3,
}
const VEC4S = BASE.frames + MAX.frames

/** Light below this never reaches a visible level after tone mapping and dithering. */
const LIVE = .004

/** Packs a frame. Returns null when nothing is lit, so the caller can clear once and rest. */
export function pack(light: Light, data: Float32Array, size: { width: number; height: number; scale: number }, fade = 1) {
  data.fill(0)
  const segments = light.segments.filter(s => Math.max(s.heat[0], s.heat[1]) * fade > LIVE).slice(0, MAX.segments)
  const dots = light.dots.filter(d => d.intensity * fade > LIVE).slice(0, MAX.dots)
  const rings = light.rings.filter(r => r.intensity * fade > LIVE).slice(0, MAX.rings)
  const floods = light.floods.filter(f => f.intensity * fade > LIVE).slice(0, MAX.floods)
  if (!segments.length && !dots.length && !rings.length && !floods.length) return null
  const frames = dots.length ? light.frames.slice(0, MAX.frames) : []
  data.set([size.width, size.height, size.scale, fade, segments.length, dots.length, rings.length, floods.length, frames.length], 0)
  segments.forEach((s, i) => data.set([s.a[0], s.a[1], s.b[0], s.b[1], s.heat[0], s.heat[1], s.width, TONES[s.tone]], (BASE.segments + i * 2) * 4))
  dots.forEach((d, i) => data.set([d.at[0], d.at[1], d.radius, d.intensity, TONES[d.tone]], (BASE.dots + i * 2) * 4))
  rings.forEach((r, i) => data.set([r.at[0], r.at[1], r.radius, r.width, r.intensity, TONES[r.tone]], (BASE.rings + i * 2) * 4))
  floods.forEach((f, i) => data.set([...f.box, f.from[0], f.from[1], f.reach, f.intensity, TONES[f.tone]], (BASE.floods + i * 3) * 4))
  frames.forEach((b, i) => data.set(b, (BASE.frames + i) * 4))
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
fn ign(p: vec2f) -> f32 { return fract(52.9829189 * fract(0.06711056 * p.x + 0.00583715 * p.y)); }
fn sdBox(p: vec2f, b: vec4f) -> f32 {
  let d = abs(p - (b.xy + b.zw * 0.5)) - b.zw * 0.5;
  return length(max(d, vec2f(0.0))) + min(max(d.x, d.y), 0.0);
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
  let px = 1.0 / head.z;
  let q = frag.xy * px;
  let hot = tone(3.0);
  var col = vec3f(0.0);

  // Trails: hot near-white where fresh, the signal's tone as they cool. Max, not sum, so joints don't bead.
  var trail = vec3f(0.0);
  for (var i = 0; i < i32(counts.x); i++) {
    let a = u.v[${BASE.segments} + i * 2];
    let m = u.v[${BASE.segments} + i * 2 + 1];
    let pa = q - a.xy;
    let ba = a.zw - a.xy;
    let h = clamp(dot(pa, ba) / max(dot(ba, ba), 1e-4), 0.0, 1.0);
    let d = length(pa - ba * h);
    let k = mix(m.x, m.y, h);
    let w = m.z;
    let core = 1.0 - smoothstep(w * 0.5 - px * 0.5, w * 0.5 + px, d);
    trail = max(trail, mix(tone(m.w), hot, k * k) * k * (core * 0.9 + exp(-d / (1.6 * w)) * 0.22));
  }
  col += trail;

  // Heads: a solid core that blooms. Only live things bloom.
  for (var i = 0; i < i32(counts.y); i++) {
    let a = u.v[${BASE.dots} + i * 2];
    let b = u.v[${BASE.dots} + i * 2 + 1];
    let d = length(q - a.xy);
    let r = a.z;
    let solid = 1.0 - smoothstep(r - px, r + px, d);
    col += hot * a.w * solid * 1.4;
    col += mix(tone(b.x), hot, 0.35) * a.w * (exp(-d / (1.2 * r)) * 0.45 + exp(-d / (4.0 * r)) * 0.1);
  }

  // Rings: a stroke that opens and thins.
  for (var i = 0; i < i32(counts.z); i++) {
    let a = u.v[${BASE.rings} + i * 2];
    let b = u.v[${BASE.rings} + i * 2 + 1];
    let e = abs(length(q - a.xy) - a.z);
    let band = 1.0 - smoothstep(a.w * 0.5 - px * 0.5, a.w * 0.5 + px, e);
    col += mix(tone(b.y), hot, 0.5) * b.x * (band + exp(-e / 2.0) * 0.12);
  }

  // Floods: a gaussian from the socket, clipped to the box and printed in a dithered stipple; the frame and
  // its inset rule catch part of it.
  for (var i = 0; i < i32(counts.w); i++) {
    let box = u.v[${BASE.floods} + i * 3];
    let s = u.v[${BASE.floods} + i * 3 + 1];
    let c = u.v[${BASE.floods} + i * 3 + 2];
    let inside = 1.0 - smoothstep(-px, px, sdBox(q, box));
    let d = length(q - s.xy);
    let g = exp(-d * d / (2.0 * s.z * s.z)) * s.w;
    let wash = g * inside;
    let print = step(ign(floor(frag.xy / 2.0)), wash * 2.2);
    let edge = rule(q, box, 0.5, px) * 0.45 + rule(q, box, 3.5, px) * 0.25;
    col += tone(c.x) * (wash * 0.32 + print * wash * 0.22 + g * edge);
  }

  // Borders near a head catch its light.
  for (var f = 0; f < i32(u.v[2].x); f++) {
    let box = u.v[${BASE.frames} + f];
    let edge = rule(q, box, 0.5, px) + rule(q, box, 3.5, px) * 0.4;
    if (edge <= 0.0) { continue; }
    for (var i = 0; i < i32(counts.y); i++) {
      let a = u.v[${BASE.dots} + i * 2];
      let b = u.v[${BASE.dots} + i * 2 + 1];
      col += mix(tone(b.x), hot, 0.3) * a.w * falloff(length(q - a.xy) / 80.0) * 0.6 * edge;
    }
  }

  col = (1.0 - exp(-col * 1.15)) * head.w;
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
float ign(vec2 p) { return fract(52.9829189 * fract(0.06711056 * p.x + 0.00583715 * p.y)); }
float sdBox(vec2 p, vec4 b) {
  vec2 d = abs(p - (b.xy + b.zw * 0.5)) - b.zw * 0.5;
  return length(max(d, vec2(0.0))) + min(max(d.x, d.y), 0.0);
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
  float px = 1.0 / head.z;
  vec2 q = fragXY * px;
  vec3 hot = tone(3.0);
  vec3 col = vec3(0.0);

  vec3 trail = vec3(0.0);
  for (int i = 0; i < int(counts.x); i++) {
    vec4 a = v[${BASE.segments} + i * 2];
    vec4 m = v[${BASE.segments} + i * 2 + 1];
    vec2 pa = q - a.xy;
    vec2 ba = a.zw - a.xy;
    float h = clamp(dot(pa, ba) / max(dot(ba, ba), 1e-4), 0.0, 1.0);
    float d = length(pa - ba * h);
    float k = mix(m.x, m.y, h);
    float w = m.z;
    float core = 1.0 - smoothstep(w * 0.5 - px * 0.5, w * 0.5 + px, d);
    trail = max(trail, mix(tone(m.w), hot, k * k) * k * (core * 0.9 + exp(-d / (1.6 * w)) * 0.22));
  }
  col += trail;

  for (int i = 0; i < int(counts.y); i++) {
    vec4 a = v[${BASE.dots} + i * 2];
    vec4 b = v[${BASE.dots} + i * 2 + 1];
    float d = length(q - a.xy);
    float r = a.z;
    float solid = 1.0 - smoothstep(r - px, r + px, d);
    col += hot * a.w * solid * 1.4;
    col += mix(tone(b.x), hot, 0.35) * a.w * (exp(-d / (1.2 * r)) * 0.45 + exp(-d / (4.0 * r)) * 0.1);
  }

  for (int i = 0; i < int(counts.z); i++) {
    vec4 a = v[${BASE.rings} + i * 2];
    vec4 b = v[${BASE.rings} + i * 2 + 1];
    float e = abs(length(q - a.xy) - a.z);
    float band = 1.0 - smoothstep(a.w * 0.5 - px * 0.5, a.w * 0.5 + px, e);
    col += mix(tone(b.y), hot, 0.5) * b.x * (band + exp(-e / 2.0) * 0.12);
  }

  for (int i = 0; i < int(counts.w); i++) {
    vec4 box = v[${BASE.floods} + i * 3];
    vec4 s = v[${BASE.floods} + i * 3 + 1];
    vec4 c = v[${BASE.floods} + i * 3 + 2];
    float inside = 1.0 - smoothstep(-px, px, sdBox(q, box));
    float d = length(q - s.xy);
    float g = exp(-d * d / (2.0 * s.z * s.z)) * s.w;
    float wash = g * inside;
    float print = step(ign(floor(fragXY / 2.0)), wash * 2.2);
    float edge = rule(q, box, 0.5, px) * 0.45 + rule(q, box, 3.5, px) * 0.25;
    col += tone(c.x) * (wash * 0.32 + print * wash * 0.22 + g * edge);
  }

  for (int f = 0; f < int(v[2].x); f++) {
    vec4 box = v[${BASE.frames} + f];
    float edge = rule(q, box, 0.5, px) + rule(q, box, 3.5, px) * 0.4;
    if (edge <= 0.0) continue;
    for (int i = 0; i < int(counts.y); i++) {
      vec4 a = v[${BASE.dots} + i * 2];
      vec4 b = v[${BASE.dots} + i * 2 + 1];
      col += mix(tone(b.x), hot, 0.3) * a.w * falloff(length(q - a.xy) / 80.0) * 0.6 * edge;
    }
  }

  col = (1.0 - exp(-col * 1.15)) * head.w;
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
