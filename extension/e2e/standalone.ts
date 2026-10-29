// Real standalone wasm device + real CLI, public iroh relays, no native host.
// Run: bun e2e/standalone.ts --deadbolt /absolute/path/to/deadbolt [--dist dir]
// Only synthetic credentials in disposable profiles/stores; headless Chromium.
import { chromium, type BrowserContext, type Page } from "playwright-core"
import { mkdtemp, rm, readdir } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import type { DeviceCommand, DeviceReply } from "../src/messages"

const arg = (name: string) => { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1] }
const binary = arg("--deadbolt")
if (!binary) throw new Error("--deadbolt must name the CLI built from this worktree")
const deadbolt = resolve(binary)
const root = await mkdtemp(join(tmpdir(), "db-ext-device-"))
const dist = arg("--dist") ? resolve(arg("--dist")!) : join(root, "extension")
const profile = join(root, "profile")
const ID = "jhocodkhpifjndffenppfmdkmiolngal"
const env = {
  ...process.env,
  DEADBOLT_HOME: join(root, "vault"), XDG_RUNTIME_DIR: join(root, "run"),
  XDG_STATE_HOME: join(root, "state"), XDG_CONFIG_HOME: join(root, "config"),
  DEADBOLT_NET: "relay", DEADBOLT_KDF: "fast", DEADBOLT_PASSPHRASE: "standalone cli fixture",
}
const passphrase = "standalone browser fixture with real argon2"
const browserPassword = "browser-only-synthetic-secret-83219"
const cliPassword = "cli-only-synthetic-secret-97264"
let context: BrowserContext | undefined
let joining: ReturnType<typeof Bun.spawn> | undefined
const server = Bun.serve({
  hostname: "127.0.0.1", port: 0,
  fetch: () => new Response(`<!doctype html><html><head><title>Standalone proof</title></head><body>
    <main style="width:320px;margin:80px auto;font:16px sans-serif"><h1>Sign in</h1><form>
    <label for="username">Email</label><input id="username" type="email" autocomplete="username" style="display:block;width:100%;height:36px">
    <label for="password">Password</label><input id="password" type="password" autocomplete="current-password" style="display:block;width:100%;height:36px">
    <button type="submit">Sign in</button></form></main></body></html>`, { headers: { "content-type": "text/html" } }),
})
const origin = `http://localhost:${server.port}`

function check(ok: unknown, message: string): asserts ok {
  if (!ok) throw new Error(message)
  console.log(`ok: ${message}`)
}
async function cli(...args: string[]) {
  const process = Bun.spawn([deadbolt, ...args], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const [out, error, exit] = await Promise.all([new Response(process.stdout).text(), new Response(process.stderr).text(), process.exited])
  if (exit !== 0) throw new Error(`deadbolt ${args[0]} failed: ${error}`)
  return out.trim()
}
async function until<T>(label: string, probe: () => Promise<T | null | undefined | false>, ms = 30_000): Promise<T> {
  const deadline = Date.now() + ms
  do {
    const value = await probe()
    if (value) return value
    await Bun.sleep(200)
  } while (Date.now() < deadline)
  throw new Error(`Timed out: ${label}`)
}
async function command(page: Page, command: DeviceCommand): Promise<DeviceReply> {
  return page.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command)
}
async function request(page: Page, body: DeviceCommand) {
  const result = await command(page, body)
  if (!result?.ok) throw new Error(`${body.type}: ${result?.message ?? "no response"}`)
  return result
}
async function launch() {
  context = await chromium.launchPersistentContext(profile, {
    channel: "chromium", headless: true, viewport: { width: 1000, height: 700 },
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
  })
  context.setDefaultTimeout(15_000)
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker")
  check(worker.url().startsWith(`chrome-extension://${ID}/`), "loaded standalone extension")
  await worker.evaluate(() => {
    const global = globalThis as unknown as { nativeCalls: number }
    global.nativeCalls = 0
    chrome.runtime.connectNative = () => { global.nativeCalls++; throw new Error("Native host forbidden by standalone proof") }
  })
  const device = await context.newPage()
  device.on("pageerror", (error) => console.error("device page error:", error.message))
  await device.goto(`chrome-extension://${ID}/device.html`)
  return { worker, device }
}
try {
  if (!arg("--dist")) {
    const build = Bun.spawnSync(["bun", "scripts/build.ts", "--e2e", dist], { cwd: join(import.meta.dir, ".."), stdout: "inherit", stderr: "inherit" })
    check(build.success, "standalone build succeeds")
  }
  const { worker, device } = await launch()
  check((await readdir(join(profile, "NativeMessagingHosts")).catch(() => [])).filter((name) => name.endsWith(".json")).length === 0, "profile has no native host manifest")
  await device.getByLabel("Passphrase", { exact: true }).fill(passphrase)
  await device.getByLabel("Passphrase again", { exact: true }).fill(passphrase)
  await device.getByRole("button", { name: "Create vault", exact: true }).click()
  await device.getByRole("heading", { name: "Add a login" }).waitFor()
  check((await request(device, { type: "device-status" })).status.state === "ready", "extension creates and opens its own vault")
  const add = device.locator("form").filter({ has: device.getByRole("heading", { name: "Add a login" }) })
  await add.getByLabel("Website", { exact: true }).fill(origin)
  await add.getByLabel("Title", { exact: true }).fill("From browser")
  await add.getByLabel("Username", { exact: true }).fill("browser@example.test")
  await add.getByLabel("Password", { exact: true }).fill(browserPassword)
  await add.getByRole("button", { name: "Save", exact: true }).click()
  await device.getByText(/^Saved in /).waitFor()
  check(((await request(device, { type: "list", origin })).reply.accounts as unknown[]).length === 1, "extension writes a login")
  const listing = device.locator("form").filter({ has: device.getByRole("heading", { name: "Logins for a site" }) })
  await listing.getByRole("textbox", { name: "Website" }).fill(origin)
  await listing.getByRole("button", { name: "Show", exact: true }).click()
  await until("device page retains its login list after submit", async () => (await listing.locator(".row").allTextContents()).some((text) => text.includes("From browser")))
  check(true, "device page displays the saved login")

  joining = Bun.spawn([deadbolt, "join", "--device-name", "proof-cli"], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const reader = (joining.stdout as ReadableStream<Uint8Array>).getReader()
  let output = ""
  const code = await Promise.race([
    (async () => {
      for (;;) {
        const part = await reader.read()
        if (part.done) throw new Error("CLI join ended before a code")
        output += new TextDecoder().decode(part.value)
        const match = /Code: ([a-z]+(?:-[a-z]+){3})/.exec(output)
        if (match) return match[1]
      }
    })(),
    Bun.sleep(45_000).then(() => { throw new Error("CLI join did not publish a code") }),
  ])
  // Keep draining so the child can finish after the code is consumed.
  const drained = (async () => { while (!(await reader.read()).done) {} })()
  const joinError = new Response(joining.stderr as ReadableStream<Uint8Array>).text()
  await request(device, { type: "device-pair", code })
  const joined = await joining.exited
  await joinError // Drain diagnostics without logging the one-time pairing code.
  check(joined === 0, "CLI joins the browser vault")
  await drained
  check(await cli("get", "From browser") === browserPassword, "browser-created login arrives on CLI through pairing")

  await cli("new", "login", "--name", "From CLI", `url=${origin}`, "username=cli@example.test", `password=${cliPassword}`)
  await until("CLI login syncs to extension", async () => {
    await request(device, { type: "device-sync" })
    const accounts = (await request(device, { type: "list", origin })).reply.accounts as Array<{ title: string }>
    return accounts.some((account) => account.title === "From CLI")
  }, 90_000)
  check(true, "CLI-created login appears in extension")
  await request(device, { type: "save", origin, entry: { title: "After pairing", url: origin, username: "after@example.test", password: browserPassword } })
  await request(device, { type: "device-sync" })
  check(await cli("get", "After pairing") === browserPassword, "post-pair browser write syncs to CLI")

  const page = await context!.newPage()
  await page.goto(origin)
  await page.locator("#username").click()
  const menu = await until("inline menu lists the synced login", async () => {
    const frame = page.frames().find((frame) => frame.url().includes("menu.html"))
    return frame && await frame.locator("button.row", { hasText: "From CLI" }).count() ? frame : null
  })
  await Bun.sleep(1000) // Production clickjacking gate requires the menu to settle visibly.
  await menu.locator("button.row", { hasText: "From CLI" }).click()
  await until("login filled", async () => await page.inputValue("#password") === cliPassword)
  check(await page.inputValue("#username") === "cli@example.test", "real content script fills synced login without a native host")

  await request(device, { type: "device-lock" })
  check((await request(device, { type: "device-status" })).status.state === "locked", "lock closes the vault")
  const encrypted = await device.evaluate(async (markers) => {
    const directory = await navigator.storage.getDirectory()
    const handle = await directory.getFileHandle("vault.redb")
    const bytes = await (await handle.getFile()).arrayBuffer()
    const text = new TextDecoder().decode(bytes)
    return bytes.byteLength > 0 && markers.every((marker) => !text.includes(marker))
  }, [browserPassword, cliPassword, "browser@example.test", "From CLI"])
  check(encrypted, "OPFS contains no plaintext credential or item-label markers")
  check(!(await command(device, { type: "list", origin })).ok, "locked vault refuses login listing")
  check(!(await command(device, { type: "device-unlock", passphrase: "wrong fixture passphrase" })).ok, "wrong passphrase is rejected")
  const unlocked = await request(device, { type: "device-unlock", passphrase })
  console.log(`MEASURE wasm unlock real Argon2id (64 MiB, 3 passes, 1 lane), RPC wall time: ${unlocked.ms.toFixed(1)} ms`)
  check(((await request(device, { type: "list", origin })).reply.accounts as unknown[]).length === 3, "unlock restores persisted signed log")
  check(await worker.evaluate(() => (globalThis as unknown as { nativeCalls: number }).nativeCalls) === 0, "no native messaging connection attempted")

  await context!.close()
  context = undefined
  const restarted = await launch()
  check((await request(restarted.device, { type: "device-status" })).status.state === "locked", "browser restart starts locked")
  await request(restarted.device, { type: "device-unlock", passphrase })
  check(((await request(restarted.device, { type: "list", origin })).reply.accounts as unknown[]).length === 3, "encrypted vault survives browser restart")
  console.log("PASS: standalone create, pair, bidirectional sync, actual fill, lock/unlock and restart")
} finally {
  joining?.kill()
  await context?.close()
  await cli("agent", "stop").catch(() => {})
  server.stop(true)
  await rm(root, { recursive: true, force: true })
}
