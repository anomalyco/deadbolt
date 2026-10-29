// Builds the extension once, then runs the full e2e suite as concurrent
// shards (`e2e/run.ts --shard i/n`), each with its own browsers, profiles and
// test server. Output lines are prefixed with the shard; exits non-zero if
// any shard fails.
//
//   bun run e2e:parallel [--jobs <n>] [any e2e/run.ts option, e.g. --deadbolt <path>]

import { availableParallelism } from "node:os"
import { join } from "node:path"

const root = join(import.meta.dir, "..")
const argv = process.argv.slice(2)
const at = argv.indexOf("--jobs")
const jobs = at >= 0 ? Number(argv.splice(at, 2)[1]) : Math.min(6, availableParallelism())
if (!(jobs >= 1)) throw new Error("--jobs wants a positive number")

const build = Bun.spawnSync(["bun", "scripts/build.ts"], { cwd: root, stdout: "inherit", stderr: "inherit" })
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

await Promise.all(
  Array.from({ length: jobs }, async (_, i) => {
    const shard = i + 1
    const tag = `[${shard}/${jobs}]`
    const lines: string[] = []
    const proc = Bun.spawn(["bun", "e2e/run.ts", "--shard", `${shard}/${jobs}`, ...argv], { cwd: root, stdout: "pipe", stderr: "pipe" })
    await Promise.all([pipe(proc.stdout, tag, lines), pipe(proc.stderr, tag, lines)])
    if ((await proc.exited) !== 0) failed.push({ shard, lines })
  }),
)

const took = `${((Date.now() - started) / 1000).toFixed(0)} s`
if (!failed.length) {
  console.log(`\nall ${jobs} shards passed in ${took}`)
  process.exit(0)
}
console.log(`\n${failed.length} of ${jobs} shards failed in ${took}:`)
for (const { shard, lines } of failed.sort((a, b) => a.shard - b.shard)) {
  const fails = lines.filter((l) => /FAIL|threw|failed$/.test(l))
  console.log(`  shard ${shard}/${jobs}:`)
  for (const l of fails.length ? fails : lines.slice(-10)) console.log(`    ${l}`)
}
process.exit(1)
