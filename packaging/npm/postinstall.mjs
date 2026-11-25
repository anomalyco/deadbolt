#!/usr/bin/env node
// @deadbolt/cli's postinstall: points bin/deadbolt at this platform's
// `deadbolt` from its @deadbolt/cli-<platform> package (its bin/deadbolt), as
// @opencode/cli's postinstall does. Links, never copies: Deadbolt knows its own
// files by real path (the Touch ID helper beside it on macOS, the desktop app,
// deadbolt-ui, beside it on glibc Linux). On macOS the app is Deadbolt.app,
// installed apart, which `deadbolt app` finds in Applications.
//
// It never fails the install: a package manager that sees a failed script
// removes the package, and with it the user's `deadbolt`. When it can't link
// (npm doesn't serve this platform's package yet, say), it says so and leaves
// the placeholder bin/deadbolt, which runs this again on first use.

import childProcess from "node:child_process"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { createRequire } from "node:module"
import { fileURLToPath } from "node:url"

const directory = path.dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)
const packageJson = JSON.parse(fs.readFileSync(path.join(directory, "package.json"), "utf8"))
const target = path.join(directory, "bin", "deadbolt")
const dependencies = packageJson.optionalDependencies ?? {}
const platform = { darwin: "darwin", linux: "linux" }[os.platform()]
const arch = { x64: "x64", arm64: "arm64" }[os.arch()]
const base = `@deadbolt/cli-${platform}-${arch}`
const npm = process.env.npm_execpath?.endsWith("npm-cli.js") ? [process.execPath, process.env.npm_execpath] : ["npm"]

// The system's libc, as the install script tells it: musl (Alpine,
// /lib/ld-musl-*, or `ldd --version` says so), glibc older than 2.28 (too old
// for the build with the app), else glibc.
function libc() {
  if (fs.existsSync("/etc/alpine-release")) return "musl"
  try {
    if (fs.readdirSync("/lib").some((name) => name.startsWith("ld-musl-"))) return "musl"
  } catch {}
  const result = childProcess.spawnSync("ldd", ["--version"], { encoding: "utf8" })
  const text = `${result.stdout || ""}${result.stderr || ""}`
  if (text.toLowerCase().includes("musl")) return "musl"
  const version = text.split("\n")[0].trim().match(/(\d+)\.(\d+)$/)
  if (version && (Number(version[1]) < 2 || (Number(version[1]) === 2 && Number(version[2]) < 28))) return "old-glibc"
  return "glibc"
}

// On glibc only the build with the app (deadbolt-ui): never the static build
// quietly in its place. On musl the static build, else the glibc one (which runs where
// glibc compatibility is installed); on a glibc older than 2.28 only the
// static build.
function packageNames() {
  if (platform !== "linux") return [base]
  const names = { musl: [`${base}-musl`, base], "old-glibc": [`${base}-musl`], glibc: [base] }[libc()]
  return names.filter((name) => dependencies[name])
}

// `deadbolt` inside a platform package's directory.
function binaryIn(packageDir) {
  return path.join(packageDir, "bin", "deadbolt")
}

// Links bin/deadbolt to `source` once a link beside it runs, so a build that
// doesn't run here never replaces the placeholder.
function link(source) {
  if (!fs.existsSync(source)) throw new Error(`Binary not found at ${source}`)
  const staged = `${target}.link`
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.rmSync(staged, { force: true })
  fs.symlinkSync(path.relative(path.dirname(target), source), staged)
  if (childProcess.spawnSync(staged, ["--version"], { stdio: "ignore" }).status !== 0) {
    fs.rmSync(staged, { force: true })
    throw new Error(`${source} doesn't run here`)
  }
  fs.renameSync(staged, target)
}

function resolvePackage(name) {
  const packagePath = require.resolve(`${name}/package.json`)
  // Package managers keep an older platform package when the matching version is not yet on the registry,
  // which would silently install the previous release under the new launcher.
  const version = JSON.parse(fs.readFileSync(packagePath, "utf8")).version
  if (version !== dependencies[name]) throw new Error(`${name} is ${version}, expected ${dependencies[name]}`)
  return path.dirname(packagePath)
}

// When the package manager skipped the optional dependency: install it beside
// this package, where it stays (the link points into it).
function installPackage(name) {
  const prefix = path.join(directory, "platform")
  fs.rmSync(prefix, { recursive: true, force: true })
  const result = childProcess.spawnSync(
    npm[0],
    [
      ...npm.slice(1),
      "install",
      "--ignore-scripts",
      "--no-save",
      "--no-package-lock",
      "--loglevel=error",
      // npm refuses a package built for another libc or CPU unless forced.
      ...(name === packageNames()[0] ? [] : ["--force"]),
      "--prefix",
      prefix,
      `${name}@${dependencies[name]}`,
    ],
    { stdio: "inherit" },
  )
  if (result.status !== 0) return false
  link(binaryIn(path.join(prefix, "node_modules", name)))
  return true
}

function main() {
  if (!platform || !arch) return `Deadbolt has no build for ${os.platform()}-${os.arch()}`
  const names = packageNames()
  for (const name of names) {
    try {
      return link(binaryIn(resolvePackage(name)))
    } catch {
      try {
        if (installPackage(name)) return
      } catch {}
    }
  }
  const wanted = names.map((name) => `${name}@${dependencies[name]}`).join(" or ") || `a package for ${base}`
  return (
    `couldn't install ${wanted}; if it was just released, npm may not serve it yet. ` +
    "`deadbolt` finishes this when it next runs, or reinstall @deadbolt/cli."
  )
}

try {
  const problem = main()
  if (problem) console.error(`deadbolt: ${problem}`)
} catch (error) {
  console.error(`deadbolt: ${error instanceof Error ? error.message : String(error)}`)
}
