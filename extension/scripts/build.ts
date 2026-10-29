// Builds the extension into dist/. Adapted from Foyer's build script
// (github.com/R44VC0RP/foyer, by Ryan Vogel).

import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises"
import { watch } from "node:fs"
import { join } from "node:path"

const root = join(import.meta.dir, "..")
// `--e2e <dir>` builds for the e2e runs only (e2e/run.ts, e2e/demo.ts), into
// that dir: DEADBOLT_E2E is true there, which lets provider pages be served
// on `.test` hosts over http (src/signin.ts). Every other build has it false,
// and that code drops out.
const e2eArg = process.argv.indexOf("--e2e")
const e2e = e2eArg > 0 ? process.argv[e2eArg + 1] : undefined
const outdir = e2e ?? join(root, "dist")
// `--native` builds the extension that talks to `deadbolt browser-host`
// (bg/host.ts), as the e2e runs against e2e/fake-host.py do. Without it the
// extension is a Deadbolt device of its own (bg/standalone.ts), with the Rust
// vault from wasm/ (scripts/wasm.sh) in an offscreen worker.
const native = process.argv.includes("--native")
const wasm = join(root, "wasm")

const entries = ["background", "content", "passkey-hook", "popup", "menu", "device", "offscreen", "vault-worker"].map((name) => join(root, "src", `${name}.ts`))

async function build() {
  if (!native) {
    const compiled = Bun.spawn(["sh", join(root, "scripts", "wasm.sh")], { stdout: "inherit", stderr: "inherit" })
    if (await compiled.exited !== 0) throw new Error("standalone wasm build failed")
  }
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
    define: { DEADBOLT_E2E: e2e ? "true" : "false", DEADBOLT_NATIVE: native ? "true" : "false" },
  })
  if (!result.success) {
    for (const log of result.logs) console.error(log)
    throw new Error("build failed")
  }
  await cp(join(root, "static"), outdir, { recursive: true })
  if (!native) {
    await cp(wasm, join(outdir, "wasm"), { recursive: true })
  }
  // The key fixes the extension id to the one `deadbolt browser install`
  // allows (docs/autofill.md), so the native host accepts it.
  const manifest = JSON.parse(await readFile(join(root, "static", "manifest.json"), "utf8"))
  manifest.key = (await readFile(join(root, "manifest-key.txt"), "utf8")).trim()
  if (native) manifest.permissions.push("nativeMessaging")
  else {
    // The vault's worker lives in an offscreen document; alarms catch up the
    // idle lock and sync, idle sees the screen lock; the vault is WebAssembly.
    manifest.permissions.push("offscreen", "alarms", "idle")
    manifest.content_security_policy = { extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'" }
    manifest.options_ui = { page: "device.html", open_in_tab: true }
  }
  const release = process.env.DEADBOLT_VERSION
  if (release) Object.assign(manifest, releaseVersion(release))
  await writeFile(join(outdir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n")
  console.log(`built ${entries.length} entries -> ${e2e ? outdir : "dist/"}${e2e ? " (e2e)" : ""}${native ? " (native host)" : ""}`)
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
