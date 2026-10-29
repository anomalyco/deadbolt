// The standalone (browser-only) device in headless Chromium, with no native
// host: a `--standalone` e2e build, its real wasm vault, real OPFS and the
// real content script. Three runs:
//
//   bun e2e/standalone.ts --smoke [--dist <dir>]
//     Offline: create, save, list, autofill, lock, wrong passphrase, unlock
//     and browser restart. Chromium reaches only loopback, so it needs no
//     public relay and no CLI (CI runs this one).
//   bun e2e/standalone.ts --deadbolt <path to deadbolt> [--dist <dir>]
//     Everything above with a real CLI over n0's public relays: pairing,
//     background sync both ways without asking the extension to sync, and
//     quick answers while a background sync waits on a suspended CLI.
//   bun e2e/standalone.ts --join --deadbolt <path to deadbolt>
//     Fresh extension joins an existing CLI vault of five logins (one with
//     TOTP), then lists, fills, locks and reopens its local encrypted replica.
//
// `--latency-ms <n>` is the limit for hello, list and fill over the vault's
// RPC (default 1000 ms, 1500 ms when CI is set). Only synthetic credentials,
// in a disposable profile and store, deleted at the end.
import { chromium, type BrowserContext, type Page, type Worker } from "playwright-core"
import { mkdtemp, rm, readdir } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import type { DeviceCommand, DeviceReply, VaultDevice } from "../src/messages"
import { VAULT_REQUEST, type VaultResponse } from "../src/bg/vault-messages"

const arg = (name: string) => { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1] }
const smoke = process.argv.includes("--smoke")
const joinExisting = process.argv.includes("--join")
if (smoke && joinExisting) throw new Error("--join requires the real CLI, not --smoke")
const binary = arg("--deadbolt")
if (smoke && binary) throw new Error("--smoke runs without the CLI; drop --deadbolt")
if (!smoke && !binary) throw new Error("--deadbolt must name the CLI built from this worktree (or pass --smoke)")
const deadbolt = binary ? resolve(binary) : ""
const limit = Number(arg("--latency-ms") ?? (process.env.CI ? 1500 : 1000))
if (!(limit > 0)) throw new Error("--latency-ms wants a positive number")
const root = await mkdtemp(join(tmpdir(), "db-ext-device-"))
const dist = arg("--dist") ? resolve(arg("--dist")!) : join(root, "extension")
const profile = join(root, "profile")
const ID = "jhocodkhpifjndffenppfmdkmiolngal"
/** The background's sync alarm (bg/standalone.ts). */
const SYNC_ALARM = "deadbolt-sync"
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
/** The CLI agent while it's suspended (SIGSTOP), to resume before stopping it. */
let suspended: number | undefined
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
    const value = await probe().catch(() => null)
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
/** Every login in the vault, as the device page lists them. */
async function logins(page: Page) {
  return (await request(page, { type: "device-logins" })).reply.accounts as Array<{ title: string; username?: string }>
}
async function state(page: Page) {
  return (await request(page, { type: "device-status" })).status.state
}
/** The device page's list of logins shows `title` by itself, without a click. */
async function shown(page: Page, title: string, ms = 15_000) {
  await page.locator(".list-view .vrow .title").getByText(title, { exact: true }).first().waitFor({ timeout: ms })
}
/** One request to the vault, as the service worker sends it to the offscreen document and its worker, timed there. */
async function vault(worker: Worker, body: Record<string, unknown> & { type: string }) {
  const { ms, response } = await worker.evaluate(async ([type, body]) => {
    const started = performance.now()
    const response = await chrome.runtime.sendMessage({ type, body })
    return { ms: performance.now() - started, response }
  }, [VAULT_REQUEST, body] as const)
  const reply = (response as VaultResponse | undefined)
  if (!reply || "error" in reply) throw new Error(`${body.type}: ${reply ? reply.error : "no response"}`)
  return { ms, reply: reply.reply as Record<string, unknown> }
}
/** hello, list and fill each answer within the limit; `during` says what else is going on. */
async function quick(worker: Worker, title: string, password: string, during: string) {
  const hello = await vault(worker, { type: "hello" })
  check(hello.reply.type === "hello" && hello.ms < limit, `hello answers in ${hello.ms.toFixed(0)} ms (< ${limit}) ${during}`)
  const list = await vault(worker, { type: "list", origin })
  const account = (list.reply.accounts as Array<{ ref: string; title: string }> | undefined)?.find((a) => a.title === title)
  check(account && list.ms < limit, `list answers in ${list.ms.toFixed(0)} ms (< ${limit}) ${during}`)
  const fill = await vault(worker, { type: "fill", origin, ref: account.ref, want: ["username", "password"] })
  check(fill.reply.password === password && fill.ms < limit, `fill answers in ${fill.ms.toFixed(0)} ms (< ${limit}) ${during}`)
}
async function launch() {
  context = await chromium.launchPersistentContext(profile, {
    channel: "chromium", headless: true, viewport: { width: 1000, height: 700 },
    args: [
      `--disable-extensions-except=${dist}`, `--load-extension=${dist}`,
      // The smoke reaches nothing but this machine: no name resolves, and
      // anything not on loopback goes to a proxy that isn't there.
      ...(smoke ? ["--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1", "--proxy-server=http://127.0.0.1:9"] : []),
    ],
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
/** Clicks into the page's username field and picks `title` from the real inline menu. */
async function autofill(title: string, username: string, password: string) {
  const page = await context!.newPage()
  await page.goto(origin)
  await page.locator("#username").click()
  const menu = await until(`inline menu lists ${title}`, async () => {
    const frame = page.frames().find((frame) => frame.url().includes("menu.html"))
    return frame && await frame.locator("button.row", { hasText: title }).count() ? frame : null
  })
  await Bun.sleep(1000) // Production clickjacking gate requires the menu to settle visibly.
  await menu.locator("button.row", { hasText: title }).click()
  await until(`${title} filled`, async () => await page.inputValue("#password") === password)
  check(await page.inputValue("#username") === username, `real content script fills ${title} without a native host`)
  await page.close()
}
async function addLogin(device: Page, title: string, username: string, password: string) {
  await device.getByRole("button", { name: "Add login", exact: true }).click()
  await device.getByLabel("Website", { exact: true }).fill(origin)
  await device.getByLabel("Title", { exact: true }).fill(title)
  await device.getByLabel("Username", { exact: true }).fill(username)
  await device.getByLabel("Password", { exact: true }).fill(password)
  await device.getByRole("button", { name: "Save", exact: true }).click()
  // Saved, it shows the new login; back to the list.
  await device.getByRole("button", { name: "Edit", exact: true }).waitFor()
  await device.getByRole("button", { name: "Back", exact: true }).click()
}
async function unlockOnPage(device: Page) {
  await device.reload()
  await device.getByLabel("Passphrase", { exact: true }).fill(passphrase)
  await device.getByRole("button", { name: "Unlock", exact: true }).click()
  await until("device page unlocks", async () => await state(device) === "ready", 60_000)
}
/** The CLI agent's pid, from `deadbolt agent status`. */
async function agentPid() {
  const pid = Number(/running pid (\d+)/.exec(await cli("agent", "status"))?.[1])
  if (!(pid > 0)) throw new Error("the CLI agent isn't running")
  return pid
}
/** Reads `deadbolt join`'s code, pairs the extension with it, and waits for the join to finish. */
async function pair(device: Page) {
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
}

/** The first-run direction: the browser shows a code; an existing CLI admits it. */
async function joinExistingVault(device: Page, worker: Worker) {
  await cli("init", "existing-demo", "--device-name", "existing-cli")
  const fixtures = [
    ["Acme", origin], ["Code Forge", "https://code.example.test"],
    ["Demo Mail", "https://mail.example.test"], ["Team Docs", "https://docs.example.test"],
    ["Status Board", "https://status.example.test"],
  ]
  for (const [title, url] of fixtures) {
    await cli("new", "login", "--name", title, `url=${url}`, "username=cli@example.test", `password=${cliPassword}`,
      ...(title === "Acme" ? ["otp=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"] : []))
  }
  const begin = async () => {
    await device.getByRole("button", { name: "Pair with an existing device", exact: true }).click()
    return until("extension publishes its join code", async () => {
      const r = (await request(device, { type: "device-join-status" })).reply
      return r.phase === "waiting" && typeof r.code === "string" ? r.code : null
    }, 60_000)
  }
  const abandoned = await begin()
  await device.getByRole("button", { name: "Cancel", exact: true }).click()
  await device.getByRole("button", { name: "Pair with an existing device", exact: true }).waitFor()
  check((await request(device, { type: "device-join-status" })).reply.phase === "idle", "cancel discards the pending join")
  check(await state(device) === "not-set-up", "cancel does not create a browser vault")

  const code = await begin()
  check(/^[a-z]+(?:-[a-z]+){3}$/.test(code) && code !== abandoned, "retry generates a new four-word code")
  await device.reload()
  await device.getByText(code, { exact: true }).first().waitFor()
  check((await request(device, { type: "device-join-status" })).reply.code === code, "waiting join survives device-page reload")
  // Never print the code or CLI argv to the test log.
  await cli("pair", code)
  await until("browser receives the existing vault", async () => (await request(device, { type: "device-join-status" })).reply.phase === "admitted", 60_000)
  check(await state(device) === "not-set-up", "admission alone does not publish an unencrypted local store")
  await device.getByLabel("Passphrase", { exact: true }).fill(passphrase)
  await device.getByLabel("Passphrase again", { exact: true }).fill(passphrase)
  await device.getByRole("button", { name: "Finish", exact: true }).click()
  await shown(device, "Acme", 60_000)
  check((await logins(device)).length === fixtures.length, "all existing CLI logins appear after browser join")
  const devices = (await request(device, { type: "device-devices" })).reply.devices as VaultDevice[]
  check(devices.length === 2 && devices.filter(d => d.current).length === 1 && devices.some(d => d.name === "existing-cli"), "joined vault lists both named devices")
  await quick(worker, "Acme", cliPassword, "after joining the existing CLI vault")
  await autofill("Acme", "cli@example.test", cliPassword)
  await until("joined TOTP matches the CLI", async () => {
    const listed = await vault(worker, { type: "list", origin })
    const account = (listed.reply.accounts as Array<{ ref: string; title: string; hasTotp: boolean }>).find(a => a.title === "Acme")!
    if (!account.hasTotp) return false
    const expected = await cli("code", "Acme")
    return (await vault(worker, { type: "fill", origin, ref: account.ref, want: ["totp"] })).reply.totp === expected
  })
  check(true, "joined OTP field fills the same current code as the CLI")
  check(!(await command(device, { type: "device-join-start" })).ok, "joining cannot replace an initialized browser vault")
  return fixtures.length
}

try {
  if (!arg("--dist")) {
    const build = Bun.spawnSync(["bun", "scripts/build.ts", "--e2e", dist, "--standalone"], { cwd: join(import.meta.dir, ".."), stdout: "inherit", stderr: "inherit" })
    check(build.success, "standalone build succeeds")
  }
  const { worker, device } = await launch()
  check((await readdir(join(profile, "NativeMessagingHosts")).catch(() => [])).filter((name) => name.endsWith(".json")).length === 0, "profile has no native host manifest")
  if (smoke) {
    const offline = await device.evaluate(() => fetch("https://example.com/", { mode: "no-cors" }).then(() => false, () => true))
    check(offline, "Chromium can't reach the network beyond loopback")
    await device.getByRole("button", { name: "Pair with an existing device", exact: true }).click()
    await device.getByRole("heading", { name: "Pairing didn't work", exact: true }).waitFor({ timeout: 60_000 })
    check(/relay/i.test(await device.locator(".notice .error").innerText()), "offline joining reports that no relay is reachable")
    await device.getByRole("button", { name: "Cancel", exact: true }).click()
  }
  let count = 1
  if (joinExisting) {
    count = await joinExistingVault(device, worker)
  } else {
  await device.getByRole("button", { name: "Create a new vault", exact: true }).click()
  await device.getByLabel("Passphrase", { exact: true }).fill(passphrase)
  await device.getByLabel("Passphrase again", { exact: true }).fill(passphrase)
  await device.getByRole("button", { name: "Create vault", exact: true }).click()
  await device.getByRole("searchbox", { name: "Search logins" }).waitFor({ timeout: 60_000 })
  check(await state(device) === "ready", "extension creates and opens its own vault")
  await addLogin(device, "From browser", "browser@example.test", browserPassword)
  await shown(device, "From browser")
  check(true, "device page lists the saved login without being asked")
  check((await logins(device)).length === 1, "extension writes a login")

  if (smoke) {
    await quick(worker, "From browser", browserPassword, "with no peers")
    await autofill("From browser", "browser@example.test", browserPassword)
  } else {
    await pair(device)
    check(await cli("get", "From browser") === browserPassword, "browser-created login arrives on CLI through pairing")
    const devices = (await request(device, { type: "device-devices" })).reply.devices as VaultDevice[]
    check(devices.length === 2 && devices.filter((d) => d.current).length === 1, "extension lists itself and the CLI as the vault's devices")

    // Browser to CLI: the extension answers the CLI's sync in the background.
    await addLogin(device, "After pairing", "after@example.test", browserPassword)
    await shown(device, "After pairing")
    await until("post-pair browser write reaches CLI", async () => {
      await cli("sync").catch(() => {})
      return await cli("get", "After pairing") === browserPassword
    }, 90_000)
    check(true, "post-pair browser write syncs to CLI")

    // CLI to browser: written while the extension is locked, fetched by the
    // sync that unlocking starts, and shown without a click.
    await request(device, { type: "device-lock" })
    check(await state(device) === "locked", "lock closes the vault")
    await cli("new", "login", "--name", "From CLI", `url=${origin}`, "username=cli@example.test", `password=${cliPassword}`, "otp=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    await unlockOnPage(device)
    await shown(device, "From CLI", 90_000)
    check(true, "CLI login written while the extension was locked appears after unlock, by background sync")
    await autofill("From CLI", "cli@example.test", cliPassword)
    await until("synced OTP field fills the current code", async () => {
      const listed = await vault(worker, { type: "list", origin })
      const account = (listed.reply.accounts as Array<{ ref: string; title: string; hasTotp: boolean }>).find(a => a.title === "From CLI")!
      check(account.hasTotp, "synced OTP field is reflected in hasTotp")
      const code = await cli("code", "From CLI")
      return (await vault(worker, { type: "fill", origin, ref: account.ref, want: ["totp"] })).reply.totp === code
    })
    check(true, "Rust core generates the same current TOTP as the CLI")
    count = 3

    // A peer that stops answering mid-connection (a sleeping laptop): the
    // sync alarm's background sync waits on it, and the vault still answers.
    suspended = await agentPid()
    process.kill(suspended, "SIGSTOP")
    await worker.evaluate((name) => chrome.alarms.create(name, { when: Date.now() + 50, periodInMinutes: 5 }), SYNC_ALARM)
    await until("sync alarm fires", () => worker.evaluate(async (name) => ((await chrome.alarms.get(name))?.scheduledTime ?? 0) > Date.now() + 60_000, SYNC_ALARM), 10_000)
    await Bun.sleep(500) // The background sync is now dialing the suspended CLI.
    await quick(worker, "From CLI", cliPassword, "while a background sync waits on a suspended CLI")
    const menuStarted = Date.now()
    await autofill("From CLI", "cli@example.test", cliPassword)
    console.log(`MEASURE inline menu pick and fill during background sync: ${Date.now() - menuStarted} ms (includes the 1 s menu settle)`)
    process.kill(suspended, "SIGCONT")
    suspended = undefined
  }
  }

  await request(device, { type: "device-lock" })
  check(await state(device) === "locked", "lock closes the vault")
  const encrypted = await device.evaluate(async (markers) => {
    const directory = await navigator.storage.getDirectory()
    const handle = await directory.getFileHandle("vault.redb")
    const bytes = await (await handle.getFile()).arrayBuffer()
    const text = new TextDecoder().decode(bytes)
    return bytes.byteLength > 0 && markers.every((marker) => !text.includes(marker))
  }, [browserPassword, cliPassword, "browser@example.test", "From CLI", "From browser"])
  check(encrypted, "OPFS contains no plaintext credential or item-label markers")
  check(!(await command(device, { type: "device-logins" })).ok, "locked vault refuses login listing")
  check(!(await command(device, { type: "device-unlock", passphrase: "wrong fixture passphrase" })).ok, "wrong passphrase is rejected")
  const unlocked = await request(device, { type: "device-unlock", passphrase })
  console.log(`MEASURE wasm unlock real Argon2id (64 MiB, 3 passes, 1 lane), RPC wall time: ${unlocked.ms.toFixed(1)} ms`)
  await until("unlock restores persisted signed log", async () => (await logins(device)).length === count, 60_000)
  check(true, "unlock restores persisted signed log")
  // No read or delay between lock and unlock: the old worker may still be
  // releasing its exclusive OPFS handle when the new one opens it.
  await request(device, { type: "device-lock" })
  await request(device, { type: "device-unlock", passphrase })
  check((await logins(device)).length === count, "immediate lock/unlock reopens the exclusive OPFS handle")
  check(await worker.evaluate(() => (globalThis as unknown as { nativeCalls: number }).nativeCalls) === 0, "no native messaging connection attempted")

  await context!.close()
  context = undefined
  const restarted = await launch()
  check(await state(restarted.device) === "locked", "browser restart starts locked")
  await request(restarted.device, { type: "device-unlock", passphrase })
  await until("encrypted vault survives browser restart", async () => (await logins(restarted.device)).length === count, 60_000)
  check(true, "encrypted vault survives browser restart")
  console.log(smoke
    ? "PASS: standalone smoke: create, save, list, actual fill, lock/unlock and restart, offline"
    : joinExisting
      ? "PASS: standalone joins existing CLI vault, cancel/retry, five logins, TOTP, actual fill, lock/unlock and restart"
      : "PASS: standalone create, pair, background sync both ways, quick answers during sync, actual fill, lock/unlock and restart")
} finally {
  if (suspended) process.kill(suspended, "SIGCONT")
  joining?.kill()
  await context?.close()
  if (!smoke) await cli("agent", "stop").catch(() => {})
  server.stop(true)
  await rm(root, { recursive: true, force: true })
}
