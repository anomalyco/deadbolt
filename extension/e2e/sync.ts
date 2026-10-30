// Real standalone replicas, not a fake host or a replacement sync protocol.
// bun e2e/sync.ts --deadbolt <debug CLI> --dist <standalone e2e build>
// Requires n0 relay WebSockets and HTTPS pkarr rendezvous on both devices.
// Only disposable profiles/stores and synthetic data; never builds or edits dist.
import { chromium, type BrowserContext, type Page } from "playwright-core"
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import type { DeviceCommand, DeviceReply, ItemSummary, VaultDevice } from "../src/messages"

const arg = (name: string) => { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1] }
if (!arg("--deadbolt") || !arg("--dist")) throw new Error("Usage: bun e2e/sync.ts --deadbolt <debug CLI> --dist <standalone e2e build>")
const deadbolt = resolve(arg("--deadbolt")!)
const dist = resolve(arg("--dist")!)
/** The opt-in Rust integration test reopens these encrypted copies to inspect history. */
const snapshots = arg("--snapshots") ? resolve(arg("--snapshots")!) : undefined
const root = await mkdtemp(join(tmpdir(), "db-ext-sync-"))
const passphrase = "synthetic browser sync fixture"
const env = {
  ...process.env,
  DEADBOLT_HOME: join(root, "vault"), XDG_RUNTIME_DIR: join(root, "run"),
  XDG_STATE_HOME: join(root, "state"), XDG_CONFIG_HOME: join(root, "config"),
  DEADBOLT_NET: "relay", DEADBOLT_KDF: "fast", DEADBOLT_PASSPHRASE: "synthetic cli sync fixture",
}
const contexts = new Set<BrowserContext>()
let suspended: number | undefined

class CliError extends Error {
  constructor(command: string, readonly exit: number, readonly out: string, readonly stderr: string) {
    super(`CLI ${command} exited ${exit}: ${stderr.trim()}`)
  }
}

function check(ok: unknown, label: string): asserts ok {
  if (!ok) throw new Error(label)
  console.log(`ok: ${label}`)
}
async function bounded<T>(label: string, work: Promise<T>, ms = 60_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([work, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Timed out: ${label}`)), ms)
    })])
  } finally { clearTimeout(timer) }
}
async function until(label: string, probe: () => Promise<boolean>, ms = 90_000) {
  const end = Date.now() + ms
  do {
    if (await probe()) return
    await Bun.sleep(250)
  } while (Date.now() < end)
  throw new Error(`Timed out: ${label}`)
}
async function cli(...args: string[]) {
  const child = Bun.spawn([deadbolt, ...args], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  try {
    const [out, error, exit] = await bounded(`CLI ${args[0]}`, Promise.all([
      new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
    ]))
    // Pairing diagnostics can include its one-time code. Never print argv or
    // successful output; redact the code but retain connection failure evidence.
    const detail = args[0] === "pair" ? error.replaceAll(args[1]!, "[pairing code]") : error
    if (exit !== 0) throw new CliError(args[0]!, exit, args[0] === "pair" ? out.replaceAll(args[1]!, "[pairing code]") : out, detail)
    return out.trim()
  } finally {
    if (child.exitCode === null) { child.kill(); await child.exited }
  }
}
async function command(page: Page, command: DeviceCommand): Promise<DeviceReply> {
  return bounded(command.type, page.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command))
}
async function request(page: Page, body: DeviceCommand) {
  const result = await command(page, body)
  if (!result?.ok) throw new Error(`${body.type}: ${result?.message ?? "no response"}`)
  return result
}
const state = async (page: Page) => (await request(page, { type: "device-status" })).status.state
const items = async (page: Page) => (await request(page, { type: "device-items" })).reply.items as ItemSummary[]
const devices = async (page: Page) => (await request(page, { type: "device-devices" })).reply.devices as VaultDevice[]
const secret = async (page: Page, ref: string) => (await request(page, { type: "device-secret", ref })).reply.value
const sync = async (page: Page) => { await request(page, { type: "device-sync", wait: true }) }
const unlock = async (page: Page) => { await request(page, { type: "device-unlock", passphrase }) }

async function launch(name: string, offline = false) {
  const context = await chromium.launchPersistentContext(join(root, name), {
    channel: "chromium", headless: true,
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`,
      // Restarting with a dead proxy cuts existing worker WebSockets as well as
      // new connections; page-only CDP offline emulation doesn't prove that.
      ...(offline ? ["--proxy-server=http://127.0.0.1:9", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1"] : [])],
  })
  contexts.add(context)
  context.setDefaultTimeout(15_000)
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker")
  check(worker.url().startsWith("chrome-extension://jhocodkhpifjndffenppfmdkmiolngal/"), `${name}: e2e extension loaded`)
  await worker.evaluate(() => {
    chrome.runtime.connectNative = () => { throw new Error("Native host forbidden by sync proof") }
  })
  const page = await context.newPage()
  await page.goto(new URL("device.html", worker.url()).href)
  if (offline) check(await page.evaluate(() => fetch("https://example.com", { mode: "no-cors" }).then(() => false, () => true)), `${name}: external network is blocked`)
  return { context, page }
}
async function close(browser: { context: BrowserContext }) {
  await browser.context.close()
  contexts.delete(browser.context)
}
async function admitted(page: Page) {
  const started = await request(page, { type: "device-join-start" })
  const code = started.reply.code
  check(started.reply.phase === "waiting" && typeof code === "string", "browser reaches its relay and publishes a join code")
  await cli("pair", code)
  await until("browser admission", async () => (await request(page, { type: "device-join-status" })).reply.phase === "admitted")
}
async function finish(page: Page) {
  await request(page, { type: "device-join-finish", passphrase })
  check(await state(page) === "ready", "joined replica is ready")
}
async function has(page: Page, title: string) { return (await items(page)).some(i => i.title === title) }

/** Capture durable replicas after locking; no plaintext or keys leave the browser. */
async function snapshot(a: Page, b: Page) {
  if (!snapshots) return
  await mkdir(snapshots) // Refuse an existing directory rather than overwrite anything.
  await cli("lock")
  for (const [name, page] of [["a", a], ["b", b]] as const) {
    await request(page, { type: "device-lock" })
    let bytes: number[] | undefined
    await until(`${name}: OPFS readable after lock for history snapshot`, async () => {
      bytes = await page.evaluate(async () => {
        try {
          const root = await navigator.storage.getDirectory()
          const handle = await root.getFileHandle("vault.redb")
          return Array.from(new Uint8Array(await (await handle.getFile()).arrayBuffer()))
        } catch (error) {
          if (error instanceof DOMException && ["NoModificationAllowedError", "NotReadableError"].includes(error.name)) return undefined
          throw error
        }
      })
      return !!bytes?.length
    })
    await mkdir(join(snapshots, name))
    await writeFile(join(snapshots, name, "store.redb"), Uint8Array.from(bytes!), { mode: 0o600, flag: "wx" })
  }
  await mkdir(join(snapshots, "cli"))
  await copyFile(join(root, "vault", "store.redb"), join(snapshots, "cli", "store.redb"))
  await cli("unlock")
  await Promise.all([unlock(a), unlock(b)])
  check(true, "encrypted snapshots preserve all three converged replicas for history verification")
}

try {
  // Distinguish actual unreachable-service behavior from the live prerequisite.
  let b = await launch("b", true)
  const unavailable = await command(b.page, { type: "device-join-start" })
  check(!unavailable.ok && /sync service/i.test(unavailable.message), "unreachable relay explains joining failure")
  await request(b.page, { type: "device-join-cancel" })
  check(await state(b.page) === "not-set-up", "failed join leaves no initialized vault")
  await close(b)

  await cli("init", "sync-fixture", "--device-name", "sync-cli")
  await cli("new", "login", "--name", "Shared", "url=https://sync.example.test", "username=original", "password=synthetic-original")
  let a = await launch("a")
  await admitted(a.page)
  await finish(a.page)
  const original = (await items(a.page)).find(i => i.title === "Shared")!
  check(original && await secret(a.page, original.ref) === "synthetic-original", "real CLI welcome reaches browser A")
  const initial = await devices(a.page)
  const cliId = initial.find(d => d.name === "sync-cli")!.id

  // Cut pairing after welcome, before the passphrase/persistence step. The
  // inviter deliberately retains the signed Add; the browser must retain no vault.
  b = await launch("b")
  await admitted(b.page)
  check(await state(b.page) === "not-set-up", "admission does not publish an unencrypted vault")
  await close(b)
  b = await launch("b")
  check(await state(b.page) === "not-set-up", "browser restart discards an admitted but unfinished join")
  check((await request(b.page, { type: "device-join-status" })).reply.phase === "idle", "interrupted join restarts idle")
  await sync(a.page)
  const ghost = (await devices(a.page)).filter(d => !initial.some(old => old.id === d.id))
  check(ghost.length === 1, "inviter retains the interrupted join's signed membership")
  await cli("devices", "remove", ghost[0]!.id)
  await until("abandoned member removal reaches browser", async () => {
    await sync(a.page)
    return !(await devices(a.page)).some(d => d.id === ghost[0]!.id)
  })
  check(true, "CLI removal of the abandoned member reaches the browser")
  await admitted(b.page)
  await finish(b.page)
  check(await secret(b.page, original.ref) === "synthetic-original", "retry after outage and interrupted join receives the original vault")
  const bId = (await devices(b.page)).find(d => d.current)!.id

  // Genuine concurrent edits: both replicas have the same starting log, then
  // every transport is cut BEFORE either writes (not merely simultaneous RPCs).
  await cli("agent", "stop")
  await close(a)
  await close(b)
  a = await launch("a", true)
  b = await launch("b", true)
  await unlock(a.page)
  await unlock(b.page)
  await Promise.all([
    request(a.page, { type: "device-item-save", ref: original.ref, fields: [{ name: "password", value: "synthetic-concurrent-a" }] }),
    request(b.page, { type: "device-item-save", ref: original.ref, fields: [{ name: "password", value: "synthetic-concurrent-b" }] }),
  ])
  check(await secret(a.page, original.ref) === "synthetic-concurrent-a" && await secret(b.page, original.ref) === "synthetic-concurrent-b", "offline peers retain distinct concurrent edits of the same field")
  await sync(a.page)
  check(await secret(a.page, original.ref) === "synthetic-concurrent-a", "sync with unreachable peers preserves the locally readable edit")
  await close(a)
  await close(b)
  await cli("unlock")
  a = await launch("a")
  b = await launch("b")
  await unlock(a.page)
  await unlock(b.page)
  let winner: unknown
  await until("concurrent edits converge", async () => {
    await Promise.all([sync(a.page), sync(b.page)])
    winner = await secret(a.page, original.ref)
    return ["synthetic-concurrent-a", "synthetic-concurrent-b"].includes(String(winner))
      && await secret(b.page, original.ref) === winner && await cli("get", "Shared") === winner
  })
  check(true, "both browsers and CLI converge on one concurrent value after reconnect")
  check(await cli("get", "Shared", "-f", "username") === "original", "concurrent password edits preserve untouched fields")
  await snapshot(a.page, b.page)
  if (!snapshots) console.log("NOTE: run the ignored standalone_sync_retains_conflict_history Rust test to verify history from encrypted snapshots")

  // The peer returns while the browser is locked. Unlock starts background sync;
  // don't use an explicit sync here to hide a missing wakeup.
  await request(a.page, { type: "device-lock" })
  await cli("agent", "stop")
  await cli("unlock")
  await cli("new", "login", "--name", "While locked", "password=synthetic-locked")
  check(await state(a.page) === "locked", "returning peer does not unlock the browser")
  await unlock(a.page)
  await until("unlock catches the returning peer", () => has(a.page, "While locked"))
  check(true, "unlock catches up with a peer that returned while the browser was locked")

  // Stop all alternative peers, then pause the CLI while an explicit sync waits.
  await close(b)
  await request(a.page, { type: "device-lock" })
  await cli("new", "login", "--name", "After restart", "password=synthetic-restart")
  suspended = Number(/running pid (\d+)/.exec(await cli("agent", "status"))?.[1])
  check(suspended > 0, "found only this fixture's CLI agent")
  process.kill(suspended, "SIGSTOP")
  await unlock(a.page)
  let settled = false
  const pending = command(a.page, { type: "device-sync", wait: true }).finally(() => { settled = true }).catch(() => null)
  check(!await has(a.page, "After restart"), "pending peer data has not arrived before browser restart")
  check(!settled, "sync request remains pending with peers unavailable")
  await close(a)
  await pending
  process.kill(suspended, "SIGCONT")
  suspended = undefined
  a = await launch("a")
  check(await state(a.page) === "locked", "browser restarted during sync starts locked")
  await unlock(a.page)
  await until("restart resumes synchronization", () => has(a.page, "After restart"))
  check(true, "unlock after mid-sync browser restart receives the pending peer data")

  // Removal in both clients. Removed devices keep old data, but cannot receive
  // causal descendants of the removal. A successful local sync is not evidence
  // of contact (device-sync also returns after its deadline), so also require a
  // still-authorized peer to receive the same post-removal item.
  b = await launch("b")
  await unlock(b.page)
  await cli("devices", "remove", bId)
  await cli("new", "login", "--name", "After CLI removal", "password=synthetic-cli-removal")
  await until("authorized browser receives post-removal data", async () => { await sync(a.page); return has(a.page, "After CLI removal") })
  await sync(b.page)
  check(!(await devices(a.page)).some(d => d.id === bId) && !await has(b.page, "After CLI removal"), "CLI removal reaches the remaining browser and prevents new data reaching the removed browser")
  await request(a.page, { type: "device-remove", id: cliId })
  await request(a.page, { type: "device-item-save", kind: "note", name: "After browser removal", fields: [{ name: "notes", value: "synthetic-browser-removal" }] })
  const refused = await cli("sync").then(() => false).catch(error => {
    // Exit 1 alone also covers a broken socket or unreachable relay. Require
    // positive evidence that a peer rejected membership, not just absent data.
    if (!(error instanceof CliError) || error.exit !== 1 || /^error:/m.test(error.stderr) || !/error: membership rejected by peer:/.test(error.out)) throw error
    return true
  })
  check(refused, "the browser explicitly rejects the removed CLI's membership")
  check(!(await devices(a.page)).some(d => d.id === cliId), "browser removes the CLI from its membership")
  check(!(await cli("ls")).includes("After browser removal"), "removed CLI receives no post-removal browser item")
  check(await secret(a.page, original.ref) === winner, "removal preserves the browser's converged item")
  console.log("PASS: relay outage/retry, admitted join interruption, offline concurrent edits/convergence, locked-peer catch-up, mid-sync restart, removal from CLI and browser")
} finally {
  if (suspended) process.kill(suspended, "SIGCONT")
  await Promise.allSettled([...contexts].map(c => c.close()))
  await cli("agent", "stop").catch(() => {})
  await rm(root, { recursive: true, force: true })
}
