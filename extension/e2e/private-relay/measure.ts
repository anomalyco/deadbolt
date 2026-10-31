// Only processes inside run.sh's PID namespace. Summed RSS double counts shared
// pages; sampled peak, not a heap high-water mark. Never sample a host browser.
import { readFileSync, readdirSync } from "node:fs"
import { run } from "./network"

type Sample = Map<string, { ticks: number; kb: number; kind: string }>
const hz = Number(run("getconf", "CLK_TCK")),
  pageKiB = Number(run("getconf", "PAGESIZE")) / 1024
function sample(): Sample {
  const s: Sample = new Map()
  for (const pid of readdirSync("/proc").filter((n) => /^\d+$/.test(n))) {
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8"),
        end = stat.lastIndexOf(")"),
        name = stat.slice(stat.indexOf("(") + 1, end)
      if (name !== "chrome" && name !== "iroh-relay" && name !== "deadbolt") continue
      const f = stat.slice(end + 2).split(" ")
      s.set(`${pid}:${f[19]}`, { ticks: Number(f[11]) + Number(f[12]), kb: Number(f[21]) * pageKiB, kind: name })
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err
    }
  }
  return s
}
export async function measure<T>(phase: string, fn: () => Promise<T>): Promise<T> {
  let prev = sample()
  const start = performance.now()
  const ticks: Record<string, number> = { chrome: 0, "iroh-relay": 0, deadbolt: 0 },
    peak = { ...ticks }
  function record() {
    const next = sample(),
      rss: Record<string, number> = {}
    for (const [pid, v] of next) {
      ticks[v.kind] += v.ticks - (prev.get(pid)?.ticks ?? 0)
      rss[v.kind] = (rss[v.kind] ?? 0) + v.kb
    }
    for (const k of Object.keys(peak)) peak[k] = Math.max(peak[k], rss[k] ?? 0)
    prev = next
  }
  record()
  const interval = setInterval(record, 250)
  try {
    return await fn()
  } finally {
    clearInterval(interval)
    record()
    console.log(
      "PHASE",
      JSON.stringify({
        phase,
        ms: Math.round(performance.now() - start),
        cpuSeconds: Object.fromEntries(Object.entries(ticks).map(([k, v]) => [k, v / hz])),
        peakRssKiB: peak,
      }),
    )
    if (peak.chrome > 3 * 1024 * 1024 || peak.deadbolt > 1024 * 1024 || peak["iroh-relay"] > 256 * 1024)
      throw new Error(`${phase}: fixture RSS budget exceeded`)
    if (
      (phase.startsWith("idle-") || phase === "blackhole-10s") &&
      Object.values(ticks).reduce((a, b) => a + b, 0) / hz > 2
    )
      throw new Error(`${phase}: exceeded two CPU-seconds in ten-second window`)
  }
}
