// Only processes inside run.sh's PID namespace. Summed RSS double counts shared
// pages; sampled peak, not a heap high-water mark. Never sample a host browser.
import { readFileSync, readdirSync, statSync } from "node:fs"
import { run } from "./network"

type Sample = Map<string, { ticks: number; kb: number; kind: string }>
const hz = Number(run("getconf", "CLK_TCK")),
  pageKiB = Number(run("getconf", "PAGESIZE")) / 1024
function exeId(path: string) {
  const { dev, ino } = statSync(path, { bigint: true })
  return `${dev}:${ino}`
}

// Match the image actually running, not TASK_COMM_LEN bytes of its basename.
export function meter(paths: { chrome: string; deadbolt: string; "iroh-relay": string }) {
  const images = new Map(Object.entries(paths).map(([kind, path]) => [exeId(path), kind]))
  if (images.size !== 3) throw new Error("Expected distinct browser, CLI and relay executables")
  return <T>(phase: string, fn: () => Promise<T>) => measure(images, phase, fn)
}
function sample(images: ReadonlyMap<string, string>): Sample {
  const s: Sample = new Map()
  for (const pid of readdirSync("/proc").filter((n) => /^\d+$/.test(n))) {
    try {
      const kind = images.get(exeId(`/proc/${pid}/exe`))
      if (!kind) continue
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8")
      const f = stat.slice(stat.lastIndexOf(")") + 2).split(" ")
      s.set(`${pid}:${f[19]}`, { ticks: Number(f[11]) + Number(f[12]), kb: Number(f[21]) * pageKiB, kind })
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err
    }
  }
  return s
}
async function measure<T>(images: ReadonlyMap<string, string>, phase: string, fn: () => Promise<T>): Promise<T> {
  let prev = sample(images)
  // All three images are alive at every phase boundary. Within a phase the
  // browser/relay can intentionally disappear, so do not invent a zero sample.
  function assertLive() {
    for (const kind of images.values()) {
      if (![...prev.values()].some((p) => p.kind === kind && p.kb > 0))
        throw new Error(`${phase}: no live RSS sample for ${kind}`)
    }
  }
  assertLive()
  const start = performance.now()
  const ticks: Record<string, number> = { chrome: 0, "iroh-relay": 0, deadbolt: 0 },
    peak = { ...ticks }
  function record() {
    const next = sample(images),
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
    const value = await fn()
    record()
    assertLive()
    return value
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
    const cpuSeconds = Object.values(ticks).reduce((a, b) => a + b, 0) / hz
    if (phase === "catch-up-with-restarts" && cpuSeconds > 120)
      throw new Error(`${phase}: fixture exceeded 120 active CPU-seconds (${cpuSeconds.toFixed(2)})`)
    if ((phase.startsWith("idle-") || phase === "blackhole-10s") && cpuSeconds > 2)
      throw new Error(`${phase}: exceeded two CPU-seconds in ten-second window`)
  }
}
