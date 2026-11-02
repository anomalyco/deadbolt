// Live standalone relay loss/recovery in headless Chromium, with real CLI sync.
// bun e2e/network.ts --deadbolt <debug CLI> --dist <standalone e2e build>
// Requires public n0 relays and pkarr rendezvous. Uses only disposable synthetic
// profiles/stores; never builds or edits dist. Healing is driven by native sync,
// not an unlock or browser relaunch. Timings are NOT unattended background-sync
// latency: the test actively runs the ordinary native `deadbolt sync` command.
import { chromium, type BrowserContext, type Page } from "playwright-core"
import { createServer } from "node:http"
import { connect, type Socket } from "node:net"
import type { Duplex } from "node:stream"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

const arg = (name: string) => { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1] }
if (!arg("--deadbolt") || !arg("--dist")) throw new Error("Usage: bun e2e/network.ts --deadbolt <debug CLI> --dist <standalone e2e build>")
const deadbolt = resolve(arg("--deadbolt")!)
const dist = resolve(arg("--dist")!)
const root = await mkdtemp(join(tmpdir(), "db-ext-network-"))
const env = { ...process.env, DEADBOLT_HOME: join(root, "vault"), XDG_RUNTIME_DIR: join(root, "run"), XDG_STATE_HOME: join(root, "state"), XDG_CONFIG_HOME: join(root, "config"), DEADBOLT_NET: "relay", DEADBOLT_KDF: "fast", DEADBOLT_PASSPHRASE: "synthetic live-network CLI" }
const passphrase = "synthetic live-network browser"
let context: BrowserContext | undefined

function check(ok: unknown, label: string): asserts ok {
  if (!ok) throw new Error(label)
  console.log(`ok: ${label}`)
}
async function bounded<T>(label: string, work: Promise<T>, ms = 60_000) {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([work, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`Timed out: ${label}`)), ms) })])
  } finally { clearTimeout(timer) }
}
async function until(label: string, probe: () => Promise<boolean>, ms = 90_000) {
  const deadline = Date.now() + ms
  do {
    if (await probe()) return
    await Bun.sleep(250)
  } while (Date.now() < deadline)
  throw new Error(`Timed out: ${label}`)
}
async function cliResult(...args: string[]) {
  const child = Bun.spawn([deadbolt, ...args], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  try {
    const [out, error, exit] = await bounded(`CLI ${args[0]}`, Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]))
    const redact = (s: string) => args[0] === "approve" ? s.replaceAll(args[1]!, "[pairing code]") : s
    return { out: redact(out.trim()), error: redact(error.trim()), exit }
  } finally { if (child.exitCode === null) { child.kill(); await child.exited } }
}
async function cli(...args: string[]) {
  const result = await cliResult(...args)
  if (result.exit !== 0) throw new Error(`CLI ${args[0]} exited ${result.exit}: ${result.error}`)
  return result.out
}
async function request(page: Page, command: Record<string, unknown>, ms = 60_000) {
  const result = await bounded(String(command.type), page.evaluate(command => chrome.runtime.sendMessage({ type: "db:device", command }), command), ms)
  if (!result?.ok) throw new Error(`${command.type}: ${result?.message ?? "no response"}`)
  return result
}
const items = async (page: Page): Promise<Array<{ title: string; ref: string }>> => (await request(page, { type: "device-items" }, 5_000)).reply.items
const value = async (page: Page, ref: string) => (await request(page, { type: "device-secret", ref }, 5_000)).reply.value

// A blind TCP tunnel: never terminates TLS, reads payload contents, or logs URLs.
// Every browser HTTPS/WSS connection uses this proxy; QUIC is disabled below.
let online = true
const tunnels = new Set<{ client: Duplex; upstream: Socket; host: string; bytes: number }>()
const opened: string[] = []
const denied: string[] = []
const proxy = createServer((_, response) => { response.writeHead(503); response.end() })
proxy.on("connect", (request, client, head) => {
  const address = new URL(`http://${request.url}`)
  const host = address.hostname
  if (!online) {
    denied.push(host)
    client.on("error", () => client.destroy())
    client.end("HTTP/1.1 503 Offline\r\nConnection: close\r\n\r\n")
    return
  }
  const upstream = connect({ host, port: Number(address.port || 443) })
  const tunnel = { client, upstream, host, bytes: 0 }
  tunnels.add(tunnel)
  const close = () => { tunnels.delete(tunnel); client.destroy(); upstream.destroy() }
  client.on("error", close)
  upstream.on("error", close)
  client.on("close", close)
  upstream.on("close", close)
  client.on("data", bytes => { tunnel.bytes += bytes.length })
  upstream.on("data", bytes => { tunnel.bytes += bytes.length })
  upstream.on("connect", () => {
    if (!online) { close(); return }
    opened.push(host)
    client.write("HTTP/1.1 200 Connection Established\r\n\r\n")
    if (head.length) upstream.write(head)
    client.pipe(upstream)
    upstream.pipe(client)
  })
})

try {
  await new Promise<void>((resolve, reject) => {
    const failed = (error: Error) => reject(error)
    proxy.once("error", failed)
    proxy.listen(0, "127.0.0.1", () => { proxy.off("error", failed); resolve() })
  })
  const port = (proxy.address() as { port: number }).port
  await cli("init", "live-network", "--device-name", "live-network-cli")
  await cli("new", "login", "--name", "Network baseline", "password=synthetic-baseline")
  context = await chromium.launchPersistentContext(join(root, "browser"), {
    channel: "chromium", headless: true,
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, `--proxy-server=http://127.0.0.1:${port}`, "--disable-quic"],
  })
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker")
  await worker.evaluate(() => { chrome.runtime.connectNative = () => { throw new Error("Native host forbidden by network proof") } })
  const page = await context.newPage()
  await page.goto(new URL("device.html", worker.url()).href)
  const code = (await request(page, { type: "device-join-start" })).reply.code
  check(typeof code === "string", "browser reaches relay through CONNECT proxy")
  await cli("approve", code)
  await until("admission", async () => (await request(page, { type: "device-join-status" })).reply.phase === "admitted")
  await request(page, { type: "device-join-finish", passphrase })
  const baseline = (await items(page)).find(i => i.title === "Network baseline")!
  check(baseline && await value(page, baseline.ref) === "synthetic-baseline", "paired browser receives real CLI vault through proxy")
  await cli("sync")

  const cdp = await context.newCDPSession(page)
  await cdp.send("Target.setDiscoverTargets", { discover: true })
  const offscreen = (await cdp.send("Target.getTargets")).targetInfos.find(t => t.url.endsWith("/offscreen.html"))!
  check(offscreen, "offscreen document has an observable target identity")
  // Dedicated workers aren't in top-level discovery until their owning target
  // is attached. Observe that child without pausing it or touching its state.
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId: offscreen.targetId, flatten: false })
  let dedicated: { targetId: string; type: string; url: string } | undefined
  const destroyed = new Set<string>()
  cdp.on("Target.targetDestroyed", event => destroyed.add(event.targetId))
  cdp.on("Target.receivedMessageFromTarget", event => {
    if (event.sessionId !== sessionId) return
    const message = JSON.parse(event.message)
    if (message.method === "Target.attachedToTarget" && message.params.targetInfo.url.endsWith("/vault-worker.js")) dedicated ??= message.params.targetInfo
    if (message.method === "Target.detachedFromTarget" && message.params.targetId) destroyed.add(message.params.targetId)
  })
  await cdp.send("Target.sendMessageToTarget", { sessionId, message: JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true, waitForDebuggerOnStart: false, flatten: false } }) })
  await until("dedicated vault worker discovery", async () => Boolean(dedicated), 5_000)
  check(dedicated, "dedicated vault worker has an observable target identity")
  const alive = async () => !destroyed.has(dedicated!.targetId) && (await cdp.send("Target.getTargetInfo", { targetId: dedicated!.targetId })).targetInfo.url.endsWith("/vault-worker.js")

  const active = [...tunnels].filter(t => !t.upstream.destroyed && t.bytes > 0)
  check(active.some(t => /\.relay\./.test(t.host)), "live relay TLS tunnel carried bytes before isolation")
  online = false
  for (const tunnel of tunnels) { tunnel.client.destroy(); tunnel.upstream.destroy() }
  check([...tunnels].every(t => t.client.destroyed && t.upstream.destroyed), "outage closes every established browser proxy tunnel")
  check(await page.evaluate(() => fetch("https://example.com", { cache: "no-store", mode: "no-cors" }).then(() => false, () => true)), "same live browser cannot reach external HTTPS during outage")

  const localStart = performance.now()
  const saved = await request(page, { type: "device-item-save", kind: "login", name: "Offline browser", fields: [{ name: "password", value: "synthetic-browser-offline" }] }, 5_000)
  check(await value(page, saved.reply.ref) === "synthetic-browser-offline", "local browser write/read remains usable with relay cut")
  console.log(`MEASURE offline browser write+read: ${(performance.now() - localStart).toFixed(1)} ms`)
  await cli("new", "login", "--name", "Offline CLI", "password=synthetic-cli-offline")
  const failed = await cliResult("sync")
  check(failed.exit === 1 && /error:/.test(failed.out), "real CLI sync cannot contact isolated browser")
  console.log("ISOLATED_SYNC", failed.out.replace(/[a-f0-9]{8,64}/g, "[device]"))
  await until("relay reconnect denied by proxy", async () => denied.some(h => /\.relay\./.test(h)), 45_000)
  check(!(await items(page)).some(i => i.title === "Offline CLI") && !(await cli("ls")).includes("Offline browser"), "writes remain isolated on both peers before restoration")
  check((await request(page, { type: "device-status" })).status.state === "ready", "outage does not lock the browser")
  check(await alive(), "same dedicated worker survives the outage")

  const openedBefore = opened.length
  const restored = performance.now()
  online = true
  // Drive the ordinary native sync command, never unlock, relaunch or explicitly
  // restart browser networking. The same browser worker must reconnect its relay.
  await until("bidirectional sync after live reconnect", async () => {
    const result = await cliResult("sync")
    if (result.exit !== 0) return false
    const fromCLI = (await items(page)).find(i => i.title === "Offline CLI")
    if (!fromCLI || await value(page, fromCLI.ref) !== "synthetic-cli-offline") return false
    const fromBrowser = await cliResult("get", "Offline browser")
    return fromBrowser.exit === 0 && fromBrowser.out === "synthetic-browser-offline"
  }, 120_000)
  check(opened.slice(openedBefore).some(h => /\.relay\./.test(h)), "proxy observes a fresh live relay tunnel after restoration")
  check((await request(page, { type: "device-status" })).status.state === "ready", "restored browser remains unlocked without an unlock command")
  check(await alive(), "same dedicated worker receives and sends offline writes after reconnect")
  console.log(`MEASURE restored network to bidirectional convergence: ${(performance.now() - restored).toFixed(1)} ms`)
  console.log("PASS: live-worker relay loss/heal, no browser restart or unlock; real bidirectional sync")
} finally {
  online = false
  try { await context?.close() } finally {
    for (const tunnel of tunnels) { tunnel.client.destroy(); tunnel.upstream.destroy() }
    await new Promise<void>(resolve => proxy.close(() => resolve()))
    await cli("debug", "daemon", "stop").catch(() => {})
    await rm(root, { recursive: true, force: true })
  }
}
