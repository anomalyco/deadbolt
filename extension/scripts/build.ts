// Builds the extension into dist/. Adapted from Foyer's build script
// (github.com/R44VC0RP/foyer, by Ryan Vogel).

import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises"
import { watch } from "node:fs"
import { join } from "node:path"

const root = join(import.meta.dir, "..")
const outdir = join(root, "dist")

const entries = ["background", "content", "passkey-hook", "popup", "menu"].map((name) => join(root, "src", `${name}.ts`))

async function build() {
  await rm(outdir, { recursive: true, force: true })
  await mkdir(outdir, { recursive: true })
  const result = await Bun.build({
    entrypoints: entries,
    outdir,
    target: "browser",
    // Content scripts can't be ES modules, so every entry is a self-contained IIFE.
    format: "iife",
    // Readable identifiers for debugging; whitespace stripped (content.js runs on every page).
    minify: { whitespace: true, syntax: true, identifiers: false },
    sourcemap: "none",
  })
  if (!result.success) {
    for (const log of result.logs) console.error(log)
    throw new Error("build failed")
  }
  await cp(join(root, "static"), outdir, { recursive: true })
  // The key fixes the extension id to the one `deadbolt browser install`
  // allows (docs/autofill.md), so the native host accepts it.
  const manifest = JSON.parse(await readFile(join(root, "static", "manifest.json"), "utf8"))
  manifest.key = (await readFile(join(root, "manifest-key.txt"), "utf8")).trim()
  const release = process.env.DEADBOLT_VERSION
  if (release) Object.assign(manifest, releaseVersion(release))
  await writeFile(join(outdir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n")
  console.log(`built ${entries.length} entries -> dist/`)
}

// Release builds (docs/releasing.md) stamp the release version. Chrome wants
// one to four dot-separated integers, so a dev build's 0.0.0-dev-<run> is
// version 0.0.0.<run> and X.Y.Z-beta.N is X.Y.Z.N, each shown as its release
// version.
function releaseVersion(release: string) {
  if (/^\d+\.\d+\.\d+$/.test(release)) return { version: release }
  const pre = /^(\d+\.\d+\.\d+)-(?:dev-|beta\.)(\d+)(?:\.\d+)?$/.exec(release)
  if (pre && Number(pre[2]) <= 65535) return { version: `${pre[1]}.${pre[2]}`, version_name: release }
  throw new Error(`DEADBOLT_VERSION ${release} has no extension version`)
}

await build()

if (process.argv.includes("--watch")) {
  let timer: Timer | undefined
  const rebuild = () => {
    clearTimeout(timer)
    timer = setTimeout(() => build().catch((err) => console.error(err)), 100)
  }
  watch(join(root, "src"), { recursive: true }, rebuild)
  watch(join(root, "static"), { recursive: true }, rebuild)
  console.log("watching src/ and static/")
}
