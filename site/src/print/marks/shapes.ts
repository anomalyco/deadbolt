// The shapes the candidate marks share, in a 100×100 box with y down.

const f = (n: number) => +n.toFixed(3)

/** The keyhole the print knocks out (KeyholePrint's `keyhole`), as one outline: a circle over a slot that widens
 *  downward. At scale 1 it's 23.5 wide and 45.25 tall; (cx, cy) is the middle of its bounding box. */
export function keyhole(cx: number, cy: number, s = 1) {
  const x = (n: number) => f(cx + n * s), y = (n: number) => f(cy + (n - 0.875) * s), r = f(11.75 * s)
  return `M${x(-5.27)} ${y(0.5)}A${r} ${r} 0 1 1 ${x(5.27)} ${y(0.5)}L${x(9.18)} ${y(23.5)}H${x(-9.18)}Z`
}

/** A rounded rectangle as a path (so it can share a path, and an even-odd fill, with a keyhole). */
export function box(x: number, y: number, w: number, h: number, r = 0) {
  if (!r) return `M${f(x)} ${f(y)}h${f(w)}v${f(h)}h${f(-w)}Z`
  return `M${f(x + r)} ${f(y)}H${f(x + w - r)}A${r} ${r} 0 0 1 ${f(x + w)} ${f(y + r)}V${f(y + h - r)}A${r} ${r} 0 0 1 ${f(x + w - r)} ${f(y + h)}H${f(x + r)}A${r} ${r} 0 0 1 ${f(x)} ${f(y + h - r)}V${f(y + r)}A${r} ${r} 0 0 1 ${f(x + r)} ${f(y)}Z`
}

/** A shackle's centreline: two legs from `bottom` up to an arc of radius `r` centred at (cx, cy). */
export function shackle(cx: number, cy: number, r: number, bottom: number) {
  return `M${f(cx - r)} ${f(bottom)}V${f(cy)}A${r} ${r} 0 0 1 ${f(cx + r)} ${f(cy)}V${f(bottom)}`
}

/** A padlock's parts, laid out in proportion from the body's box. */
export function padlock({ x, y, w, h, r = 0, reach = 0.32, stroke = 0.15, rise = 0.62, hole = 0.38 }: {
  x: number; y: number; w: number; h: number; r?: number
  /** The shackle's centreline radius, as a fraction of the body's width. */
  reach?: number
  /** The shackle's thickness, as a fraction of the body's width. */
  stroke?: number
  /** How far the shackle's arc centre sits above the body, as a fraction of the body's height. */
  rise?: number
  /** The keyhole's scale. */
  hole?: number
}) {
  const cx = x + w / 2, R = w * reach, cy = y - h * rise
  return {
    body: box(x, y, w, h, r),
    hole: hole ? keyhole(cx, y + h / 2, hole) : "",
    shackle: shackle(cx, cy, R, y + Math.min(h * 0.2, 4)),
    stroke: w * stroke,
    top: cy - R - (w * stroke) / 2,
  }
}

/** The page's ink filter (Ink.tsx), which roughens the wordmark's edges, so a mark prints the same way. */
export const printed = { filter: "url(#ink)" } as const
