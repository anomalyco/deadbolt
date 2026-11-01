#!/usr/bin/env node
// @deadbolt/cli's postinstall: points bin/deadbolt at this platform's
// `deadbolt` from its @deadbolt/cli-<platform> package, as @opencode/cli's
// postinstall does. On macOS that's Deadbolt.app's Contents/Helpers/deadbolt
// (the package carries the signed app), so the command, the agent and the app
// are one install, and `deadbolt app` opens that Deadbolt.app. Links, never
// copies: Deadbolt knows its own files by real path (the Touch ID helper
// beside it, the app around it).

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
if (!platform || !arch) throw new Error(`Deadbolt has no build for ${os.platform()}-${os.arch()}`)
const base = `@deadbolt/cli-${platform}-${arch}`
const npm = process.env.npm_execpath?.endsWith("npm-cli.js") ? [process.execPath, process.env.npm_execpath] : ["npm"]

function isMusl() {
  if (platform !== "linux") return false
  try {
    if (fs.existsSync("/etc/alpine-release")) return true
    if (fs.readdirSync("/lib").some((name) => name.startsWith("ld-musl-"))) return true
    const result = childProcess.spawnSync("ldd", ["--version"], { encoding: "utf8" })
    return `${result.stdout || ""}${result.stderr || ""}`.toLowerCase().includes("musl")
  } catch {
    return false
  }
}

// The build with the app first; on musl, the static build first. Either runs
// a glibc system's CLI, so each falls back to the other.
function packageNames() {
  const names = platform === "linux" ? (isMusl() ? [`${base}-musl`, base] : [base, `${base}-musl`]) : [base]
  return names.filter((name) => dependencies[name])
}

// `deadbolt` inside a platform package's directory: Deadbolt.app's helper on
// macOS (bin/deadbolt in an unsigned build without the app), else bin/deadbolt.
function binaryIn(packageDir) {
  const helper = path.join(packageDir, "Deadbolt.app", "Contents", "Helpers", "deadbolt")
  return fs.existsSync(helper) ? helper : path.join(packageDir, "bin", "deadbolt")
}

function link(source) {
  if (!fs.existsSync(source)) throw new Error(`Binary not found at ${source}`)
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.rmSync(target, { force: true })
  fs.symlinkSync(path.relative(path.dirname(target), source), target)
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

function verify() {
  return childProcess.spawnSync(target, ["--version"], { stdio: "ignore" }).status === 0
}

// Says so when this system's first choice wasn't installable (a registry
// that doesn't serve the new version yet, say) and another build stands in:
// on glibc that's the static build, which has no desktop app.
function fellBack(name, names) {
  if (name === names[0]) return
  console.error(
    `deadbolt: installed ${name}, as ${names[0]}@${dependencies[names[0]]} couldn't be installed` +
      (name.endsWith("-musl") ? " (this build has no desktop app)" : "") +
      `. Reinstall @deadbolt/cli later to get ${names[0]}.`,
  )
}

function main() {
  const names = packageNames()
  for (const name of names) {
    try {
      link(binaryIn(resolvePackage(name)))
      if (verify()) return fellBack(name, names)
    } catch {
      if (installPackage(name) && verify()) return fellBack(name, names)
    }
  }
  throw new Error(
    `Failed to install Deadbolt. Try manually installing ${names.map((name) => JSON.stringify(name)).join(" or ")}.`,
  )
}

try {
  main()
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
}
