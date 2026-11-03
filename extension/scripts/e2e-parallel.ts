// Builds the extension once, then runs the full e2e suite as concurrent
// shards (`e2e/run.ts --shard i/n`), each with its own browsers, profiles and
// test server. Output lines are prefixed with the shard; exits non-zero if
// any shard fails.
//
//   bun run e2e:parallel [--jobs <n>] [any e2e/run.ts option, e.g. --deadbolt <path>]
//
// Alongside the shards, once per run: universal sign-in through a provider
// (e2e/universal-providers.ts) on the same build. The native build needs a
// real daemon for it (--deadbolt); without one it's skipped and says so.

import { mkdtemp, rm } from "node:fs/promises"
import { availableParallelism, tmpdir } from "node:os"
import { join } from "node:path"

const root = join(import.meta.dir, "..")
const argv = process.argv.slice(2)
const at = argv.indexOf("--jobs")
const jobs = at >= 0 ? Number(argv.splice(at, 2)[1]) : Math.min(6, availableParallelism())
if (!(jobs >= 1)) throw new Error("--jobs wants a positive number")

// One e2e build for every shard (`e2e/run.ts --dist`).
const dist = await mkdtemp(join(tmpdir(), "deadbolt-e2e-dist-"))
const build = Bun.spawnSync(["bun", "scripts/build.ts", "--e2e", dist, argv.includes("--standalone") ? "--standalone" : "--native"], { cwd: root, stdout: "inherit", stderr: "inherit" })
if (build.exitCode !== 0) process.exit(build.exitCode ?? 1)

const started = Date.now()
const failed: { shard: number; lines: string[] }[] = []

async function pipe(stream: ReadableStream<Uint8Array>, tag: string, lines: string[]) {
  let rest = ""
  const out = (line: string) => {
    lines.push(line)
    console.log(`${tag} ${line}`)
  }
  const decoder = new TextDecoder()
  for await (const chunk of stream) {
    const parts = (rest + decoder.decode(chunk, { stream: true })).split("\n")
    rest = parts.pop()!
    parts.forEach(out)
  }
  if (rest) out(rest)
}

const standalone = argv.includes("--standalone")
const deadboltAt = argv.indexOf("--deadbolt")
const deadbolt = deadboltAt >= 0 ? argv[deadboltAt + 1] : undefined
const providers = standalone ? ["--dist", dist] : deadbolt ? ["--dist", dist, "--native", "--deadbolt", deadbolt] : null
if (!providers) console.log("[providers] skip: the native build's provider run needs --deadbolt <path>")

await Promise.all([
  ...(providers ? [(async () => {
    const lines: string[] = []
    const proc = Bun.spawn(["bun", "e2e/universal-providers.ts", ...providers], { cwd: root, stdout: "pipe", stderr: "pipe" })
    await Promise.all([pipe(proc.stdout, "[providers]", lines), pipe(proc.stderr, "[providers]", lines)])
    if ((await proc.exited) !== 0) failed.push({ shard: 0, lines })
  })()] : []),
  ...Array.from({ length: jobs }, async (_, i) => {
    const shard = i + 1
    const tag = `[${shard}/${jobs}]`
    const lines: string[] = []
    const proc = Bun.spawn(["bun", "e2e/run.ts", "--shard", `${shard}/${jobs}`, "--dist", dist, ...argv], { cwd: root, stdout: "pipe", stderr: "pipe" })
    await Promise.all([pipe(proc.stdout, tag, lines), pipe(proc.stderr, tag, lines)])
    if ((await proc.exited) !== 0) failed.push({ shard, lines })
  }),
])

await rm(dist, { recursive: true, force: true })
const took = `${((Date.now() - started) / 1000).toFixed(0)} s`
if (!failed.length) {
  console.log(`\nall ${jobs} shards passed in ${took}`)
  process.exit(0)
}
console.log(`\n${failed.length} of ${jobs} shards failed in ${took}:`)
for (const { shard, lines } of failed.sort((a, b) => a.shard - b.shard)) {
  const fails = lines.filter((l) => /FAIL|threw|failed$/.test(l))
  console.log(shard ? `  shard ${shard}/${jobs}:` : "  universal-providers:")
  for (const l of fails.length ? fails : lines.slice(-10)) console.log(`    ${l}`)
}
process.exit(1)
