import { useRef } from "react"

// Pieces the shader marks share.

/** The keyhole KeyholePrint knocks out, as a signed distance (negative inside), in the print's units: y up, the
 *  square's half height is 1. */
export const glslKeyhole = `
float keyhole(vec2 p, float g) {
  float circle = length(p - vec2(0.0, 0.2)) - (0.235 + g);
  float half_ = 0.085 + (0.11 - p.y) * 0.17 + g;
  float slot = max(abs(p.x) - half_, max(p.y - 0.11, -0.47 - g - p.y));
  return min(circle, slot);
}
`

/** #ff2a2a, the site's ink. */
export const inkRgb = [1, 42 / 255, 42 / 255] as const

const reduced = matchMedia("(prefers-reduced-motion: reduce)")

/** Progress through a load-in, 0 to 1 over `seconds` of frames (1 at once under reduced motion). The shader eases it. */
export function useIntro(seconds: number) {
  const elapsed = useRef(0)
  return (dt: number) => {
    if (reduced.matches) return 1
    elapsed.current += dt
    return Math.min(1, elapsed.current / seconds)
  }
}
