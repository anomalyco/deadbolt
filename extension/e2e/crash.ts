// A real WebAssembly trap inside the live vault worker, under every lock preset.
// bun e2e/crash.ts --dist <standalone e2e build>
// Headless and offline: a disposable profile, synthetic data, no production hooks.
// The trap reaches the dedicated worker through the offscreen document's CDP
// target (Target.setAutoAttach there), never by killing the browser or worker.
import { chromium, type CDPSession, type Page } from "playwright-core"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import type { DeviceCommand, DeviceReply, ItemSummary, LockPreset } from "../src/messages"

const arg = (name: string) => { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1] }
if (!arg("--dist")) throw new Error("Usage: bun e2e/crash.ts --dist <standalone e2e build>")
const dist = resolve(arg("--dist")!)
const profile = await mkdtemp(join(tmpdir(), "db-ext-crash-"))
const passphrase = "synthetic crash fixture"
const value = "synthetic-crash-password"
// (module (func (export "trap") unreachable))
const trap = [0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 7, 8, 1, 4, 116, 114, 97, 112, 0, 0, 10, 5, 1, 3, 0, 0, 11]

function check(ok: unknown, label: string): asserts ok {
  if (!ok) throw new Error(label)
  console.log(`ok: ${label}`)
}
async function bounded<T>(label: string, work: Promise<T>, ms = 15_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([work, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Timed out: ${label}`)), ms)
    })])
  } finally { clearTimeout(timer) }
}
const command = (page: Page, command: DeviceCommand): Promise<DeviceReply> =>
  bounded(command.type, page.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command))
async function request(page: Page, body: DeviceCommand) {
  const result = await command(page, body)
  if (!result?.ok) throw new Error(`${body.type}: ${result?.message ?? "no response"}`)
  return result
}
const state = async (page: Page) => (await request(page, { type: "device-status" })).status.state

/** Inject a fault into the dedicated worker owned by this offscreen document. */
async function inject(cdp: CDPSession, offscreen: string, expression: string) {
  const { targetInfos } = await cdp.send("Target.getTargets")
  const target = targetInfos.filter(t => t.url === offscreen)
  check(target.length === 1, "exactly one offscreen vault owner")
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId: target[0]!.targetId, flatten: false })
  let receive: ((event: { sessionId: string; message: string }) => void) | undefined
  try {
    const worker = bounded("vault worker attachment", new Promise<string>(resolve => {
      receive = event => {
        if (event.sessionId !== sessionId) return
        const m = JSON.parse(event.message)
        if (m.method === "Target.attachedToTarget" && m.params.targetInfo.type === "worker" && m.params.targetInfo.url.endsWith("/vault-worker.js")) resolve(m.params.sessionId)
      }
      cdp.on("Target.receivedMessageFromTarget", receive)
    }), 5_000)
    await cdp.send("Target.sendMessageToTarget", { sessionId, message: JSON.stringify({ id: 1, method: "Target.setAutoAttach", params: { autoAttach: true, waitForDebuggerOnStart: false, flatten: false } }) })
    const workerSession = await worker
    check(workerSession, "live dedicated vault worker attached")
    if (receive) cdp.off("Target.receivedMessageFromTarget", receive)
    const evaluated = bounded("worker fault injection", new Promise<void>((resolve, reject) => {
      receive = event => {
        if (event.sessionId !== sessionId) return
        const outer = JSON.parse(event.message)
        if (outer.method !== "Target.receivedMessageFromTarget" || outer.params.sessionId !== workerSession) return
        const inner = JSON.parse(outer.params.message)
        if (inner.id !== 1) return
        if (inner.error || inner.result?.exceptionDetails) reject(new Error("Worker fault injection failed"))
        else resolve()
      }
      cdp.on("Target.receivedMessageFromTarget", receive)
    }))
    await cdp.send("Target.sendMessageToTarget", { sessionId, message: JSON.stringify({ id: 2, method: "Target.sendMessageToTarget", params: { sessionId: workerSession, message: JSON.stringify({ id: 1, method: "Runtime.evaluate", params: { expression } }) } }) })
    await evaluated
  } finally {
    if (receive) cdp.off("Target.receivedMessageFromTarget", receive)
    await cdp.send("Target.detachFromTarget", { sessionId }).catch(() => {})
  }
}

const context = await chromium.launchPersistentContext(profile, {
  channel: "chromium", headless: true,
  args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`,
    "--proxy-server=http://127.0.0.1:9", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1"],
})
try {
  context.setDefaultTimeout(15_000)
  const sw = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker")
  const id = new URL(sw.url()).host
  check(sw.url().startsWith("chrome-extension://") && id, `extension loaded (${id})`)
  await sw.evaluate(() => { chrome.runtime.connectNative = () => { throw new Error("Native host forbidden by crash proof") } })
  const page = await context.newPage()
  await page.goto(new URL("device.html", sw.url()).href)
  check(await page.evaluate(() => fetch("https://example.com", { mode: "no-cors" }).then(() => false, () => true)), "external network is blocked")
  check(WebAssembly.validate(Uint8Array.from(trap)), "trap module is valid wasm")

  await request(page, { type: "device-create", passphrase, name: "crash-fixture" })
  await request(page, { type: "device-item-save", kind: "login", name: "Crash fixture", fields: [{ name: "password", value }] })
  const ref = ((await request(page, { type: "device-items" })).reply.items as ItemSummary[]).find(i => i.title === "Crash fixture")?.ref
  check(ref, "synthetic login saved")
  const cdp = await context.newCDPSession(page)
  try {
    for (const preset of ["comfortable", "relaxed", "strict"] as LockPreset[]) {
      await request(page, { type: "device-preset", preset })
      check(await state(page) === "ready", `${preset}: vault ready before the trap`)
      // Throw outside the CDP evaluation as a background wasm task would.
      await inject(cdp, `chrome-extension://${id}/offscreen.html`, `setTimeout(() => new WebAssembly.Instance(new WebAssembly.Module(Uint8Array.from(${JSON.stringify(trap)}))).exports.trap(), 0)`)
      await page.waitForFunction(async () => (await chrome.runtime.sendMessage({ type: "db:device", command: { type: "device-status" } })).status.state === "locked", undefined, { timeout: 10_000 })
      check(true, `${preset}: a real wasm trap locks the vault`)
      const listed = await command(page, { type: "device-items" })
      const revealed = await command(page, { type: "device-secret", ref })
      check(!listed.ok && listed.code === "locked" && !revealed.ok && revealed.code === (preset === "strict" ? "passphrase_needed" : "locked"), `${preset}: reads are refused after the trap`)
      await request(page, { type: "device-unlock", passphrase })
      check(await state(page) === "ready", `${preset}: passphrase unlock reopens the vault`)
      check(((await request(page, { type: "device-items" })).reply.items as ItemSummary[]).some(i => i.ref === ref), `${preset}: item survives the trap`)
      if (preset === "strict") {
        const refused = await command(page, { type: "device-secret", ref })
        check(!refused.ok && refused.code === "passphrase_needed", `${preset}: reveal still requires a fresh passphrase`)
      }
      const shown = await request(page, { type: "device-secret", ref, ...(preset === "strict" ? { passphrase } : {}) })
      check(shown.reply.value === value, `${preset}: secret value survives the trap`)
    }
    // Lose the ack after redb's second (root switch) flush actually completes.
    // The saved edit is durable but the worker must not serve the prior view.
    await inject(cdp, `chrome-extension://${id}/offscreen.html`, `(() => {
      const proto = FileSystemSyncAccessHandle.prototype, flush = proto.flush;
      let count = 0;
      proto.flush = function() {
        flush.call(this);
        if (++count === 2) throw new DOMException('Synthetic lost flush ack', 'UnknownError');
      };
    })()`)
    const edited = await command(page, { type: "device-item-save", ref, fields: [], name: "Saved despite lost ack" })
    check(!edited.ok && await state(page) === "locked", "an unconfirmed signed append ends the worker")
    const refused = await command(page, { type: "device-items" })
    check(!refused.ok && refused.code === "locked", "the stale live view cannot serve reads")
    await request(page, { type: "device-unlock", passphrase })
    check(((await request(page, { type: "device-items" })).reply.items as ItemSummary[]).some(i => i.ref === ref && i.title === "Saved despite lost ack"), "unlock recovers the committed edit without replay")
  } finally { await cdp.detach().catch(() => {}) }
  console.log("PASS: wasm traps and an unconfirmed signed append lock the worker; unlock recovers the durable vault")
} finally {
  await context.close()
  await rm(profile, { recursive: true, force: true })
}
