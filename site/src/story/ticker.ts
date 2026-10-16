// One requestAnimationFrame for every story on the page. It runs only while something is subscribed.

type Tick = (now: number) => void
const ticks = new Set<Tick>()
let raf = 0

function loop(now: number) {
  raf = 0
  for (const tick of [...ticks]) tick(now)
  if (ticks.size) raf = requestAnimationFrame(loop)
}

export function onFrame(tick: Tick) {
  ticks.add(tick)
  if (!raf) raf = requestAnimationFrame(loop)
  return () => { ticks.delete(tick) }
}
