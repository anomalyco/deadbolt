// Headless standalone performance probe. Synthetic data only; no native host.
// bun e2e/performance.ts --dist dist --out /tmp/perf --runs 5 [--deadbolt <binary>]
// --sizes 50,500,2000 selects ascending fixture sizes; --skip-ui skips the
// fixed-size tab measurements, not the real toolbar or runtime measurements.
import { chromium, type Page } from "playwright-core"
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { join, resolve } from "node:path"
import { tmpdir } from "node:os"

const arg = (key: string) => { const at = process.argv.indexOf(key); return at < 0 ? undefined : process.argv[at + 1] }
const dist = resolve(arg("--dist") ?? "dist")
const out = resolve(arg("--out") ?? "/tmp/deadbolt-performance")
const runs = Number(arg("--runs") ?? 5)
const sizes = (arg("--sizes") ?? "50,500,2000").split(",").map(Number)
if (!Number.isInteger(runs) || runs < 1) throw new Error("--runs must be a positive integer")
if (!sizes.every((n, i) => Number.isInteger(n) && n > (sizes[i - 1] ?? 0))) throw new Error("--sizes must be positive, ascending integers")
const manifest = JSON.parse(await readFile(join(dist, "manifest.json"), "utf8"))
if (manifest.permissions?.includes("nativeMessaging") || !manifest.permissions?.includes("offscreen")) throw new Error("--dist must be a standalone build; native-host builds are forbidden")
const root = await mkdtemp(join(tmpdir(), "db-perf-"))
const ID = "jhocodkhpifjndffenppfmdkmiolngal"
const base = `chrome-extension://${ID}`
const passphrase = "synthetic performance fixture real argon2"
const binary = arg("--deadbolt") ? resolve(arg("--deadbolt")!) : undefined
let joiner: ReturnType<typeof Bun.spawn> | undefined
const env = { ...process.env, DEADBOLT_HOME: join(root, "vault"), XDG_RUNTIME_DIR: join(root, "run"), XDG_STATE_HOME: join(root, "state"), XDG_CONFIG_HOME: join(root, "config"), DEADBOLT_NET: "relay", DEADBOLT_KDF: "fast", DEADBOLT_PASSPHRASE: "synthetic CLI fixture" }
async function cli(...args: string[]) {
  const p = Bun.spawn([binary!, ...args], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const [text, , code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited])
  if (code) throw new Error(`CLI ${args[0]} exited ${code}`)
  return text
}
const samples: Record<string, number[]> = {}
function record(name: string, ms: number) { (samples[name] ??= []).push(ms) }
async function results() {
  const summary = Object.fromEntries(Object.entries(samples).map(([k, v]) => [k, { median: [...v].sort((a, b) => a - b)[Math.floor(v.length / 2)], samples: v }]))
  await writeFile(join(out, "results.json"), JSON.stringify(summary, null, 2))
  console.log(JSON.stringify(summary, null, 2))
}
async function rpc(page: Page, command: Record<string, unknown>) {
  const r = await page.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command)
  if (!r?.ok) throw new Error(`${command.type}: ${r?.message}`)
  return r
}
async function frame(page: Page) { await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())))) }

// Flat CDP sessions also reach the offscreen document's dedicated worker.
class CDP {
  next = 0
  sessions = new Map<string, string>()
  pending = new Map<number, { resolve: (r: any) => void; reject: (e: Error) => void }>()
  constructor(readonly ws: WebSocket) {
    ws.onmessage = (e) => {
      const r = JSON.parse(String(e.data))
      if (r.method === "Target.attachedToTarget") this.sessions.set(r.params.targetInfo.targetId, r.params.sessionId)
      const p = this.pending.get(r.id)
      if (!p) return
      this.pending.delete(r.id)
      if (r.error) p.reject(new Error(JSON.stringify(r.error))); else p.resolve(r.result)
    }
  }
  send(method: string, params: any = {}, sessionId?: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const id = ++this.next
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP timed out: ${method}`)) }, 30000)
      this.pending.set(id, { resolve: (r) => { clearTimeout(timer); resolve(r) }, reject: (e) => { clearTimeout(timer); reject(e) } })
      this.ws.send(JSON.stringify({ id, method, params, sessionId }))
    })
  }
  async profile(url: string) {
    const { targetInfos } = await this.send("Target.getTargets")
    const offscreen = targetInfos.find((t: any) => t.url.endsWith("/offscreen.html"))
    const target = targetInfos.find((t: any) => t.url.endsWith(url) || (url === "/vault-worker.js" && t.type === "worker" && t.parentId === offscreen?.targetId))
    if (!target) throw new Error(`No CDP target ${url}: ${JSON.stringify(targetInfos)}`)
    let sessionId: string
    if (url === "/vault-worker.js") {
      // Dedicated workers must be attached through their owning document.
      // Direct attach leaves a worker with an empty URL unable to answer.
      let parent = this.sessions.get(offscreen.targetId)
      parent ??= (await this.send("Target.attachToTarget", { targetId: offscreen.targetId, flatten: true })).sessionId
      await this.send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }, parent)
      sessionId = this.sessions.get(target.targetId)!
      if (!sessionId) throw new Error("Offscreen worker did not attach")
    } else {
      sessionId = (await this.send("Target.attachToTarget", { targetId: target.targetId, flatten: true })).sessionId
    }
    await this.send("Profiler.enable", {}, sessionId)
    await this.send("Profiler.setSamplingInterval", { interval: 500 }, sessionId)
    await this.send("Profiler.start", {}, sessionId)
    return async (name: string) => {
      const { profile } = await this.send("Profiler.stop", {}, sessionId)
      await writeFile(join(out, `${name}.cpuprofile`), JSON.stringify(profile))
      if (url !== "/vault-worker.js") await this.send("Target.detachFromTarget", { sessionId })
    }
  }
}

await mkdir(out, { recursive: true })
const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response('<!doctype html><title>Performance fixture</title><form><label>Username<input id="username" autocomplete="username"></label><label>Password<input id="password" type="password" autocomplete="current-password"></label><button>Sign in</button></form>', { headers: { "content-type": "text/html" } }) })
const origin = `http://localhost:${server.port}`
const started = performance.now()
const launch = () => chromium.launchPersistentContext(join(root, "profile"), {
  channel: "chromium", headless: true, viewport: { width: 420, height: 600 },
  args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, "--remote-debugging-port=0"],
})
let context = await launch()
try {
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker")
  await worker.evaluate(() => { chrome.runtime.connectNative = () => { throw new Error("Native host forbidden") } })
  const page = await context.newPage()
  await page.goto(`${base}/device.html`)
  await rpc(page, { type: "device-status" })
  record("cold launch to initial status", performance.now() - started)
  const [port, path] = (await readFile(join(root, "profile/DevToolsActivePort"), "utf8")).trim().split("\n")
  const ws = new WebSocket(`ws://127.0.0.1:${port}${path}`)
  await new Promise<void>((resolve) => ws.onopen = () => resolve())
  const cdp = new CDP(ws)
  const create = performance.now()
  await rpc(page, { type: "device-create", name: "performance-fixture", passphrase })
  record("create real KDF", performance.now() - create)
  // Stop the device UI from repainting on each seed write; this is still its
  // trusted URL and the production management route and encrypted store.
  await page.reload()
  await page.evaluate(() => { document.body.replaceChildren(); window.stop() })
  // A fresh document with no app listeners, but the same trusted path.
  await page.route("**/device.js", (route) => route.fulfill({ body: "", contentType: "text/javascript" }))
  await page.reload()
  let count = 0
  for (const size of sizes) {
    const seed = performance.now()
    for (; count < size; count++) {
      await rpc(page, { type: "device-save", entry: { title: `Fixture ${String(count).padStart(4, "0")}`, username: `user${count}@example.test`, password: "synthetic-only-password", url: count === 0 ? origin : `https://site${count}.example.test` } })
      if (count % 250 === 0) console.log(`seeded ${count}`)
    }
    console.log(`seed ${size}: ${Math.round(performance.now() - seed)}ms`)
    for (let n = 0; !process.argv.includes("--skip-ui") && n < runs; n++) {
      const popup = await context.newPage()
      const t = performance.now()
      await popup.goto(`${base}/popup.html`)
      await popup.locator(".vrow-main").first().waitFor()
      await frame(popup)
      record(`popup ${size} interactive`, performance.now() - t)
      const paint = await popup.evaluate(() => performance.getEntriesByName("first-contentful-paint")[0]?.startTime)
      if (paint !== undefined) record(`popup ${size} first paint`, paint)
      // Broad searches are deliberate: every row still matches the first keys.
      if (size === 2000) {
        const stop = n === 0 ? await cdp.profile("/popup.html") : null
        const search = popup.locator("input.search")
        await search.evaluate((el) => el.addEventListener("keydown", () => {
          const start = performance.now()
          ;(globalThis as any).keyPaint = new Promise<number>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve(performance.now() - start))))
        }, { capture: true }))
        await search.focus()
        for (const key of "Fixture 199") {
          await search.press(key === " " ? "Space" : key)
          record("search 2000 key to paint", await popup.evaluate(() => (globalThis as any).keyPaint))
        }
        if (stop) await stop("popup-search")
        if (n === 0) {
          await search.fill("")
          await search.focus()
          for (let i = 0; i < 35; i++) await popup.keyboard.press("ArrowDown")
          const focused = await popup.evaluate(() => document.activeElement?.getAttribute("aria-label"))
          if (!focused?.startsWith("Fixture 0034")) throw new Error(`Arrow navigation lost its row: ${focused}`)
          await popup.locator(".vrow-main").last().scrollIntoViewIfNeeded()
          await popup.locator(".vrow-main").last().click()
          await popup.getByRole("heading", { name: "Fixture 1999", exact: true }).waitFor()
          await popup.getByRole("button", { name: "Back", exact: true }).click()
        }
        await search.fill("Fixture 1999")
        await popup.locator(".vrow-main").first().click()
        await popup.getByRole("heading", { name: "Fixture 1999", exact: true }).waitFor()
      }
      await popup.close()
    }
    // Also time the real toolbar window (the fixed-size popup.html navigations
    // above make the size comparison and keyboard driving repeatable).
    for (let n = 0; n < runs; n++) {
      const start = performance.now()
      await worker.evaluate(async () => {
        const [tab] = await chrome.tabs.query({ active: true })
        await chrome.windows.update(tab.windowId, { focused: true })
        await chrome.action.openPopup({ windowId: tab.windowId })
      })
      const { targetInfos } = await cdp.send("Target.getTargets")
      const popup = targetInfos.find((t: any) => t.url === `${base}/popup.html`)
      if (!popup) throw new Error("Toolbar popup did not open")
      const { sessionId } = await cdp.send("Target.attachToTarget", { targetId: popup.targetId, flatten: true })
      const { result, exceptionDetails } = await cdp.send("Runtime.evaluate", {
        expression: `new Promise(resolve => {
          const ready = () => {
            if (!document.querySelector('.vrow-main')) return setTimeout(ready, 10);
            requestAnimationFrame(() => requestAnimationFrame(() => resolve({paint: performance.getEntriesByName('first-contentful-paint')[0]?.startTime})));
          }; ready();
        })`, awaitPromise: true, returnByValue: true,
      }, sessionId)
      if (exceptionDetails) throw new Error("Toolbar measurement failed")
      record(`toolbar ${count} interactive`, performance.now() - start)
      if (result.value.paint !== undefined) record(`toolbar ${count} first paint`, result.value.paint)
      await cdp.send("Target.closeTarget", { targetId: popup.targetId })
    }
    await results()
  }
  const stopWorker = await cdp.profile("/vault-worker.js")
  for (let n = 0; n < runs; n++) {
    const t = performance.now()
    await rpc(page, { type: "device-items" })
    record(`list RPC ${count}`, performance.now() - t)
  }
  await stopWorker("worker-list")
  for (let n = 0; n < runs; n++) {
    const t = performance.now()
    await rpc(page, { type: "device-biometric-check", passphrase })
    record("KDF check real parameters", performance.now() - t)
  }
  for (let n = 0; n < runs; n++) {
    await rpc(page, { type: "device-lock" })
    // Status starts the replacement worker without unlocking it. Profile its
    // whole unlock. Release wasm profiles retain stripped function indices.
    await rpc(page, { type: "device-status" })
    const stop = n === 0 ? await cdp.profile("/vault-worker.js") : null
    const t = performance.now()
    await rpc(page, { type: "device-unlock", passphrase })
    record(`unlock ${count} real KDF`, performance.now() - t)
    if (stop) await stop("worker-unlock")
  }
  for (let n = 0; n < runs; n++) {
    const web = await context.newPage()
    await web.goto(origin)
    await web.waitForTimeout(500) // form scan, not part of focus latency
    const t = performance.now()
    await web.locator("#username").click()
    const menu = await new Promise<import("playwright-core").Frame>((resolve, reject) => {
      const deadline = Date.now() + 15000
      const check = () => { const f = web.frames().find((f) => f.url().includes("menu.html")); if (f) resolve(f); else if (Date.now() > deadline) reject(new Error("No menu")); else setTimeout(check, 20) }
      check()
    })
    await menu.locator("button.row").first().waitFor()
    record("inline focus to visible", performance.now() - t)
    await web.waitForTimeout(1000) // unchanged clickjacking stability gate
    const pick = performance.now()
    await menu.locator("button.row").first().click()
    await web.waitForFunction(() => (document.querySelector("#password") as HTMLInputElement).value === "synthetic-only-password")
    record("inline pick to filled fields", performance.now() - pick)
    await menu.getByText("Filled", { exact: true }).waitFor()
    record("inline pick to Filled", performance.now() - pick)
    await web.close()
  }
  if (binary) {
    const joining = Bun.spawn([binary, "join", "--device-name", "perf-cli"], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
    joiner = joining
    const diagnostics = new Response(joining.stderr).text()
    const reader = joining.stdout.getReader()
    let text = ""
    const code = await Promise.race([
      (async () => {
        for (;;) {
          const chunk = await reader.read()
          if (chunk.done) throw new Error("CLI join ended before its code")
          text += new TextDecoder().decode(chunk.value)
          const code = /Code: ([a-z]+(?:-[a-z]+){3})/.exec(text)?.[1]
          if (code) return code
        }
      })(),
      Bun.sleep(45000).then(() => { throw new Error("CLI join did not publish a code") }),
    ])
    const drained = (async () => { while (!(await reader.read()).done) {} })()
    await rpc(page, { type: "device-pair", code })
    if (await joining.exited) throw new Error("CLI join failed")
    await Promise.all([drained, diagnostics])
    await cli("ls") // starts the joined peer's agent
    for (let n = 0; n < runs; n++) {
      const t = performance.now()
      await rpc(page, { type: "device-sync", wait: true })
      record("sync one CLI peer", performance.now() - t)
    }
    await cli("agent", "stop")
    for (let n = 0; n < runs; n++) {
      const t = performance.now()
      await rpc(page, { type: "device-sync", wait: true })
      record("sync offline CLI peer", performance.now() - t)
    }
  }
  // Separate fetch and instantiate in a fresh page each time; the extension
  // is unpacked, so 'download' means a local resource read, not network RTT.
  for (let n = 0; n < runs; n++) {
    const blank = await context.newPage()
    await blank.goto(`${base}/offscreen.html`)
    const timing = await blank.evaluate(async () => {
      const start = performance.now()
      const bytes = await (await fetch("wasm/deadbolt_ext_core_bg.wasm", { cache: "no-store" })).arrayBuffer()
      const fetched = performance.now()
      const glue = await import(chrome.runtime.getURL("wasm/deadbolt_ext_core.js"))
      const before = performance.now()
      await glue.default({ module_or_path: bytes })
      return { size: bytes.byteLength, fetch: fetched - start, instantiate: performance.now() - before }
    })
    record("wasm bytes", timing.size); record("wasm local fetch", timing.fetch); record("wasm instantiate", timing.instantiate)
    await blank.close()
  }
  ws.close()
  for (let n = 0; n < runs; n++) {
    await context.close()
    const t = performance.now()
    context = await launch()
    const device = await context.newPage()
    await device.goto(`${base}/device.html`)
    const state = await rpc(device, { type: "device-status" })
    if (state.status.state !== "locked") throw new Error("Restart must lock")
    record("cold browser to locked status", performance.now() - t)
    await rpc(device, { type: "device-unlock", passphrase })
    record("cold browser to ready with automatic passphrase", performance.now() - t)
  }
  await results()
} finally {
  await results()
  if (joiner?.exitCode === null) joiner.kill()
  if (binary) await cli("agent", "stop").catch(() => {})
  await context.close()
  server.stop()
  await rm(root, { recursive: true, force: true })
}
