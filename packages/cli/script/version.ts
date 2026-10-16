#!/usr/bin/env bun
// Runs after `changeset version`: the crates take this package's version, so the git tag, the binaries, and
// `deadbolt --version` always agree. Updates the workspace version and the lockfile entries for every
// workspace crate.

import pkg from "../package.json"

const root = new URL("../../../", import.meta.url)
const version = pkg.version

async function rewrite(path: string, edit: (text: string) => string) {
  const file = Bun.file(new URL(path, root))
  const before = await file.text()
  const after = edit(before)
  if (after === before) return
  await Bun.write(file, after)
  console.log(`${path} → ${version}`)
}

const crates: string[] = []
for await (const path of new Bun.Glob("crates/*/Cargo.toml").scan({ cwd: Bun.fileURLToPath(root) })) {
  const name = (await Bun.file(new URL(path, root)).text()).match(/\[package\]\nname = "([^"]+)"/)?.[1]
  if (!name) throw new Error(`${path}: no package name`)
  crates.push(name)
}

await rewrite("Cargo.toml", (text) =>
  text.replace(/(\[workspace\.package\][^[]*?\nversion = ")[^"]+"/, `$1${version}"`),
)
await rewrite("Cargo.lock", (text) =>
  text.replace(
    new RegExp(`(name = "(?:${crates.map(RegExp.escape).join("|")})"\\nversion = ")[^"]+"`, "g"),
    `$1${version}"`,
  ),
)
