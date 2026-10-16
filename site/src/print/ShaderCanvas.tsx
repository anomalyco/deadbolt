import { useEffect, useRef } from "react"

// A full-screen fragment shader on a canvas, as opentunnel's prints do it: WebGL2, one triangle, rendered at the
// display's density (capped at 2x), paused offscreen and in hidden tabs, one still frame under reduced motion.

const vertex = `#version 300 es
in vec2 position;
void main() { gl_Position = vec4(position, 0.0, 1.0); }
`

/** Noise helpers shared by every print. */
export const glslNoise = `
float hash(vec2 p) { p = fract(p * vec2(123.34, 456.21)); p += dot(p, p + 45.32); return fract(p.x * p.y); }
float noise(vec2 p) {
  vec2 i = floor(p), f = fract(p);
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1, 0)), u.x), mix(hash(i + vec2(0, 1)), hash(i + vec2(1, 1)), u.x), u.y);
}
float fbm(vec2 p) {
  float v = 0.0, a = 0.5;
  mat2 rot = mat2(0.8, 0.6, -0.6, 0.8);
  for (int i = 0; i < 5; i++) { v += a * noise(p); p = rot * p * 2.03 + 11.7; a *= 0.5; }
  return v;
}
// Interleaved gradient noise: an ordered dither with a stipple rather than a checker.
float ign(vec2 px) { return fract(52.9829189 * fract(0.06711056 * px.x + 0.00583715 * px.y)); }
`

type Uniform = (name: string) => WebGLUniformLocation | null

export function ShaderCanvas({ fragment, className, setup, frame, redraw, still = 7 }: {
  fragment: string
  className?: string
  /** Once, after linking: constant uniforms. */
  setup?: (gl: WebGL2RenderingContext, uniform: Uniform, scale: number) => void
  /** Every frame, before drawing, with the seconds since the last one. */
  frame?: (gl: WebGL2RenderingContext, uniform: Uniform, dt: number) => void
  /** Subscribes to changes that need a fresh still frame while the loop isn't running (reduced motion). */
  redraw?: (draw: () => void) => () => void
  /** Scene time of the first frame and the reduced-motion still. */
  still?: number
}) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const callbacks = useRef({ setup, frame, redraw })
  callbacks.current = { setup, frame, redraw }

  useEffect(() => {
    const element = canvas.current
    if (!element) return
    const gl = element.getContext("webgl2", { antialias: false, alpha: true, premultipliedAlpha: true, powerPreference: "low-power" })
    if (!gl) { element.dataset.fallback = ""; return }
    const compile = (type: number, source: string) => {
      const object = gl.createShader(type)!
      gl.shaderSource(object, source); gl.compileShader(object)
      if (!gl.getShaderParameter(object, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(object) ?? "shader")
      return object
    }
    const program = gl.createProgram()!
    gl.attachShader(program, compile(gl.VERTEX_SHADER, vertex))
    gl.attachShader(program, compile(gl.FRAGMENT_SHADER, fragment))
    gl.linkProgram(program)
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program) ?? "program")
    gl.useProgram(program)
    const quad = gl.createBuffer()
    gl.bindBuffer(gl.ARRAY_BUFFER, quad)
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW)
    const position = gl.getAttribLocation(program, "position")
    gl.enableVertexAttribArray(position)
    gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0)
    const cache = new Map<string, WebGLUniformLocation | null>()
    const uniform: Uniform = name => {
      if (!cache.has(name)) cache.set(name, gl.getUniformLocation(program, name))
      return cache.get(name)!
    }
    const scale = Math.min(window.devicePixelRatio || 1, 2)
    callbacks.current.setup?.(gl, uniform, scale)

    let sized = ""
    const resize = () => {
      const width = Math.max(1, Math.round(element.clientWidth * scale)), height = Math.max(1, Math.round(element.clientHeight * scale))
      const size = `${width}x${height}`
      if (sized === size) return
      sized = size
      element.width = width; element.height = height
      gl.viewport(0, 0, width, height)
      gl.uniform2f(uniform("resolution"), width, height)
    }
    const media = matchMedia("(prefers-reduced-motion: reduce)")
    let visible = false, hidden = document.hidden, raf = 0, previous = performance.now(), time = still
    const draw = (now: number) => {
      const dt = Math.min(.1, (now - previous) / 1000)
      time += dt
      previous = now
      resize()
      gl.uniform1f(uniform("time"), time)
      callbacks.current.frame?.(gl, uniform, dt)
      gl.clearColor(0, 0, 0, 0)
      gl.clear(gl.COLOR_BUFFER_BIT)
      gl.drawArrays(gl.TRIANGLES, 0, 3)
    }
    const once = () => { previous = performance.now(); draw(previous) }
    const tick = (now: number) => { draw(now); raf = requestAnimationFrame(tick) }
    const run = () => {
      cancelAnimationFrame(raf)
      if (media.matches) { once(); return }
      if (visible && !hidden) { previous = performance.now(); raf = requestAnimationFrame(tick) }
    }
    const observer = new IntersectionObserver(([entry]) => { visible = entry!.isIntersecting; run() })
    observer.observe(element)
    const visibility = () => { hidden = document.hidden; run() }
    document.addEventListener("visibilitychange", visibility)
    media.addEventListener("change", run)
    const sizing = new ResizeObserver(() => { if (media.matches || !visible) once() })
    sizing.observe(element)
    const unsubscribe = callbacks.current.redraw?.(() => { if (media.matches) once() })
    once()
    return () => {
      cancelAnimationFrame(raf); observer.disconnect(); sizing.disconnect(); unsubscribe?.()
      document.removeEventListener("visibilitychange", visibility); media.removeEventListener("change", run)
      gl.deleteProgram(program); gl.deleteBuffer(quad)
    }
  }, [fragment, still])

  return <canvas ref={canvas} className={className} aria-hidden="true" />
}
