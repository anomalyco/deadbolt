// Linux, private network/PID namespaces only. See run.sh and docs/extension-device.md.
import { chromium, type BrowserContext, type Page } from "playwright-core"
import { meter } from "./measure"
import { mkdir, copyFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { stallAuthority, initShape, privateServices, proxy, run, shape } from "./network"
import type { DeviceCommand, DeviceReply, ItemSummary, VaultDevice } from "../../src/messages"

const [root, dist, relay, store, pin, deadbolt, mode] = process.argv.slice(2)
const measure = meter({ chrome: chromium.executablePath(), "iroh-relay": relay, deadbolt })
const passphrase = "synthetic-relay-fixture"
function check(ok: unknown, why: string): asserts ok {
  if (!ok) throw new Error(why)
  console.log(`ok: ${why}`)
}
async function until(why: string, probe: () => Promise<boolean>, ms = 90_000) {
  const start = performance.now()
  do {
    if (await probe()) return
    await Bun.sleep(100)
  } while (performance.now() - start < ms)
  throw new Error(`Timed out: ${why}`)
}
const command = (p: Page, command: DeviceCommand): Promise<DeviceReply> =>
  p.evaluate((command) => chrome.runtime.sendMessage({ type: "db:device", command }), command)
async function request(p: Page, cmd: DeviceCommand) {
  const r = await command(p, cmd)
  if (!r?.ok) throw new Error(`${cmd.type}: ${r?.message ?? "no reply"}`)
  return r
}
const state = async (p: Page) => (await request(p, { type: "device-status" })).status.state
const items = async (p: Page) => (await request(p, { type: "device-items" })).reply.items as ItemSummary[]
const has = async (p: Page, name: string) => (await items(p)).some((i) => i.title === name)
const devices = async (p: Page) => (await request(p, { type: "device-devices" })).reply.devices as VaultDevice[]
const unlock = (p: Page) => request(p, { type: "device-unlock", passphrase })
const sync = (p: Page) => request(p, { type: "device-sync" })
const read = async (p: Page, ref: string) => (await request(p, { type: "device-secret", ref })).reply.value
const edit = (p: Page, ref: string, value: string) =>
  request(p, { type: "device-item-save", ref, fields: [{ name: "password", value }] })
const login = async (p: Page, name: string) =>
  String(
    (
      await request(p, {
        type: "device-item-save",
        kind: "login",
        name,
        fields: [{ name: "password", value: "initial" }],
      })
    ).reply.ref,
  )
const contexts = new Set<BrowserContext>()
async function launch(name: string, port: number) {
  const ctx = await chromium.launchPersistentContext(join(root, `profile-${name}`), {
    channel: "chromium",
    headless: true,
    args: [
      `--load-extension=${dist}`,
      `--disable-extensions-except=${dist}`,
      `--proxy-server=http://127.0.0.1:${port}`,
      `--ignore-certificate-errors-spki-list=${pin}`,
      "--disable-quic",
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
    ],
  })
  contexts.add(ctx)
  const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent("serviceworker"))
  const page = await ctx.newPage()
  await page.goto(new URL("device.html", sw.url()).href)
  check(
    await page.evaluate(() => !chrome.runtime.getManifest().permissions?.includes("nativeMessaging")),
    `${name}: standalone manifest`,
  )
  return {
    ctx,
    page,
    close: async () => {
      await ctx.close()
      contexts.delete(ctx)
    },
  }
}
async function pair(b: Page) {
  const { code } = (await request(b, { type: "device-join-start" })).reply
  if (typeof code !== "string") throw new Error("no synthetic pairing code")
  await cli("approve", code)
  await until(
    "join admitted",
    async () => (await request(b, { type: "device-join-status" })).reply.phase === "admitted",
  )
  await request(b, { type: "device-join-finish", passphrase })
}
async function snapshot(p: Page, dir: string) {
  await request(p, { type: "device-lock" })
  await mkdir(dir)
  let data = ""
  await until("OPFS handle released", async () => {
    data = await p.evaluate(async () => {
      try {
        const f = await (await (await navigator.storage.getDirectory()).getFileHandle("vault.redb")).getFile()
        const reader = new FileReader()
        const url = await new Promise<string>((ok, fail) => {
          reader.onerror = () => fail(reader.error)
          reader.onload = () => ok(String(reader.result))
          reader.readAsDataURL(f)
        })
        return url.split(",")[1]
      } catch (e) {
        if (e instanceof DOMException && ["NotReadableError", "NoModificationAllowedError"].includes(e.name)) return ""
        throw e
      }
    })
    return !!data
  })
  const bytes = Buffer.from(data, "base64")
  await writeFile(join(dir, "store.redb"), bytes, { flag: "wx", mode: 0o600 })
  return bytes.length
}
const native = join(root, "native")
async function cliResult(...args: string[]) {
  const p = Bun.spawn([deadbolt, ...args], {
    env: {
      ...process.env,
      DEADBOLT_HOME: native,
      DEADBOLT_NET: "relay",
      DEADBOLT_RELAY_FIXTURE_CA: join(root, "cert.der"),
      DEADBOLT_KDF: "fast",
      DEADBOLT_PASSPHRASE: passphrase,
    },
    stdout: "pipe",
    stderr: "pipe",
    stdin: "ignore",
  })
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited])
  return { out, err, code }
}
async function cli(...args: string[]) {
  const { out, err, code } = await cliResult(...args)
  if (code !== 0) throw new Error(`CLI ${args[0]}: ${args[0] === "approve" ? err.replaceAll(args[1], "[code]") : err}`)
  return out.trim()
}
const nativeLogin = (name: string) => cli("new", "login", "--name", name, "password=initial")
initShape()
const services = await privateServices(root, relay)
const [pb, pc] = await Promise.all([proxy("b"), proxy("c")])

async function exercise() {
  await cli("init", "private-relay-fixture", "--device-name", "Native A")
  await nativeLogin("Shared")
  await nativeLogin("Probe")
  let b = await launch("b", pb.port)
  await pair(b.page)
  const rows = await items(b.page),
    shared = rows.find((i) => i.title === "Shared")!.ref,
    probe = rows.find((i) => i.title === "Probe")!.ref
  check(
    services.records.size > 0 && (await read(b.page, shared)) === "initial",
    "private signed-record rendezvous and real relay welcome",
  )
  for (const mode of ["clean", "lossy"] as const) {
    shape(mode)
    await measure(`${mode}-edits`, async () => {
      for (let i = 0; i < 3; i++) {
        const start = performance.now(),
          before = pb.bytes(),
          value = `${mode}-${i}`
        await edit(b.page, probe, value)
        const local = performance.now() - start
        await until(`probe ${value}`, async () => (await cli("get", "Probe")) === value)
        console.log(
          "MEASURE",
          JSON.stringify({
            mode,
            localMs: local,
            convergeMs: performance.now() - start,
            relayBytes: pb.bytes() - before,
          }),
        )
      }
    })
  }
  shape("clean")
  await measure("idle-clean-10s", async () => {
    await Bun.sleep(10_000)
  }) // matched observation window
  // Same live profiles and two *distinct* edits. 100% packet drop, not an
  // immediate WebSocket error: both directions blackhole even existing sockets.
  shape("blackhole")
  await Promise.all([cli("set", "Shared", "password=isolated-a"), edit(b.page, shared, "isolated-b")])
  await measure("blackhole-10s", async () => {
    await Bun.sleep(10_000)
  }) // observation window
  check(
    (await cli("get", "Shared")) === "isolated-a" && (await read(b.page, shared)) === "isolated-b",
    "isolated reads/writes and distinct concurrent field versions",
  )
  for (let i = 0; i < 2; i++) {
    shape("blackhole")
    const name = `Flap ${i}`
    await nativeLogin(name)
    await sync(b.page)
    check(!(await has(b.page, name)), `flap ${i}: peer write absent while cut`)
    shape("clean")
    await sync(b.page)
    await until(`flap ${i} heals`, () => has(b.page, name))
  }
  const winner = await read(b.page, shared)
  await until("A has the concurrent winner", async () => (await cli("get", "Shared")) === winner)
  check(
    (winner === "isolated-a" || winner === "isolated-b") && (await cli("get", "Shared")) === winner,
    "same concurrent field winner after live healing",
  )

  if (mode === "smoke") {
    console.log("PASS private standalone relay smoke (no backlog, lifecycle or removal cases)")
    return
  }

  // Generate the backlog on the locked, synthetic native store. Neither the simulator
  // nor a privileged read/write command is linked into the extension build.
  shape("blackhole")
  await cli("lock")
  console.log(run(store, "backlog", native))
  await mkdir(join(root, "source"))
  await copyFile(join(native, "store.redb"), join(root, "source", "store.redb"))
  await cli("unlock")
  check((await cli("ls")).includes("File 1") && !(await has(b.page, "Backlog 0")), "only A has the offline backlog")
  const bytes = pb.bytes()
  await measure("catch-up-with-restarts", async () => {
    shape("limited")
    await sync(b.page)
    await until("catch-up traffic", async () => pb.bytes() - bytes >= 96 * 1024)
    const cdp = await b.ctx.newCDPSession(b.page)
    const targets = async () => (await cdp.send("Target.getTargets")).targetInfos
    const sw = (await targets()).find((t) => t.type === "service_worker" && t.url.endsWith("/background.js"))
    const owner = (await targets()).find((t) => t.url.endsWith("/offscreen.html"))
    check(sw && owner, "service worker and offscreen owner discovered")
    let versionId: string | undefined,
      swStopped = false
    cdp.on("ServiceWorker.workerVersionUpdated", ({ versions }) => {
      for (const v of versions)
        if (v.scriptURL === sw.url) {
          if (v.runningStatus === "running") versionId = v.versionId
          if (v.runningStatus === "stopped" && v.versionId === versionId) swStopped = true
        }
    })
    await cdp.send("ServiceWorker.enable")
    await until("active background version", async () => !!versionId, 5000)
    await cdp.send("ServiceWorker.stopWorker", { versionId: versionId! })
    await until("background version stopped", async () => swStopped, 5000)
    check(swStopped, "Chromium acknowledged mid-transfer service worker stop")
    check(
      (await read(b.page, shared)) === winner && (await targets()).some((t) => t.targetId === owner.targetId),
      "replacement service worker can use original unlocked offscreen vault",
    )
    const sw2 =
      b.ctx.serviceWorkers().find((w) => w.url().endsWith("/background.js")) ??
      (await b.ctx.waitForEvent("serviceworker"))
    await sw2.evaluate(() => chrome.offscreen.closeDocument())
    await until("offscreen discarded", async () => !(await targets()).some((t) => t.targetId === owner.targetId))
    const blocked = await command(b.page, { type: "device-items" })
    check(!blocked.ok && blocked.code === "locked", "offscreen loss refuses reads; no key restored")
    await unlock(b.page)
    check((await read(b.page, shared)) === winner, "authenticated OPFS reopen retains converged browser write")
    await cdp.detach()
    const resumed = pb.bytes()
    await sync(b.page)
    await until("backlog transfer after offscreen restart", async () => pb.bytes() - resumed >= 96 * 1024)
    // Capture a lower bound on committed state, not an exact cut index. The
    // live browser may commit more entries before its process actually exits.
    let prefix: string[] = []
    await until("an incomplete backlog is visible before browser restart", async () => {
      const rows = await items(b.page)
      if (rows.some((i) => i.title === "File 1")) throw new Error("schedule precondition: tail arrived before restart")
      prefix = rows.filter((i) => i.title.startsWith("Backlog ")).map((i) => i.ref)
      return prefix.length > 0
    })
    const prefixBytes = pb.bytes()
    await until(
      "fresh relay traffic after observing the incomplete prefix",
      async () => pb.bytes() - prefixBytes >= 16 * 1024,
    )
    console.log(
      `live restart cut: ${prefix.length} backlog refs, no tail at capture, ${pb.bytes() - prefixBytes} subsequent relay bytes`,
    )
    await b.close() // Browser shutdown interrupts the live link, not a prior proxy cut.
    pb.isolate(true) // No B process now; forbid even new tunnels throughout authenticated reopen.
    const cutBytes = pb.bytes()
    await services.restart()
    b = await launch("b", pb.port)
    check((await state(b.page)) === "locked", "browser restart during catch-up starts locked")
    await unlock(b.page)
    const reopened = await items(b.page),
      refs = new Set(reopened.map((i) => i.ref))
    check(
      prefix.every((ref) => refs.has(ref)) && !reopened.some((i) => i.title === "File 1") && pb.bytes() === cutBytes,
      `authenticated OPFS reopen retained all ${prefix.length} pre-restart backlog refs without peer traffic`,
    )
    pb.isolate(false)
    // Request a real sync, not a synthetic retransmission. Waiting for list
    // state (not an RPC acknowledgment) proves the tail actually arrived.
    try {
      await until(
        "1 Mbit/s backlog tail",
        async () => {
          const attempt = await cliResult("sync")
          if (attempt.code !== 0 && !(attempt.code === 1 && attempt.out.includes("error:")))
            throw new Error(`unexpected native sync failure: ${attempt.err}`)
          const rows = await items(b.page)
          console.log(`B round items=${rows.length}, bytes=${pb.bytes() - bytes}`)
          return rows.some((i) => i.title === "File 1")
        },
        210_000,
      ) // 38.4s payload minimum; bounded retries, including startup and gaps
    } catch (error) {
      const cut = join(root, "cutoff")
      await snapshot(b.page, cut)
      console.log(run(store, "heads", cut))
      throw error
    }
  })
  console.log("catch-up B TLS bytes incl handshakes/retries", pb.bytes() - bytes)
  shape("clean")
  const c = await launch("c", pc.port)
  await pair(c.page)
  await until("B knows C", async () => {
    await sync(b.page)
    return (await devices(b.page)).length === 3
  })
  const cId = (await devices(c.page)).find((d) => d.current)!.id
  async function verifyDisks(phase: "verify" | "removed") {
    const end = join(root, phase)
    await mkdir(end)
    await cli("lock")
    await mkdir(join(end, "a"))
    await copyFile(join(native, "store.redb"), join(end, "a", "store.redb"))
    await Promise.all(
      (
        [
          ["b", b],
          ["c", c],
        ] as const
      ).map(([id, browser]) => snapshot(browser.page, join(end, id))),
    )
    console.log(run(store, phase, end))
  }
  await verifyDisks("verify")
  await Promise.all([cli("unlock"), unlock(b.page), unlock(c.page)])
  await until("A/B/C initially caught up", async () =>
    (
      await Promise.all([b, c].map((x) => command(x.page, { type: "device-rename", name: "private-relay-fixture" })))
    ).every((r) => r.ok),
  )

  // B returns with stale membership and a never-replicated item. Stall the
  // still-authorized authority A, keeping stale C online and actively dialing B.
  const bId = (await devices(b.page)).find((d) => d.current)!.id
  shape("blackhole")
  pb.isolate(true) // no buffered sentinel from a formerly authorized connection can be replayed on heal
  await login(b.page, "B private before refresh")
  await b.close()
  check(!(await has(c.page, "B private before refresh")), "C did not have B's sentinel before removal")
  await cli("devices", "remove", cId)
  await nativeLogin("After removal")
  const priorSeen = (await devices(c.page)).find((d) => d.id === bId)?.lastSeen ?? 0
  await until("next observable lastSeen second", async () => Math.floor(Date.now() / 1000) > priorSeen, 2000)
  const returned = Math.floor(Date.now() / 1000)
  await until("native authority advertised its relay", async () => services.nativeHomePublished(), 15000)
  stallAuthority(true)
  pb.isolate(false)
  shape("clean")
  b = await launch("b", pb.port)
  const beforeUnlock = performance.now()
  try {
    await unlock(b.page)
    const barrier = async () => {
      const r = await command(b.page, { type: "device-rename", name: "private-relay-fixture" })
      return !r.ok && /catching up/i.test(r.message)
    }
    check(await barrier(), "B's production startup membership barrier is engaged")
    await sync(c.page)
    await until(
      "C confirms direct sync with B during B startup",
      async () =>
        ((await devices(c.page)).find((d) => d.id === bId)?.lastSeen ?? 0) >= Math.max(returned, priorSeen + 1),
      8000,
    )
    const stillRefreshing = await barrier(),
      cSawSentinel = await has(c.page, "B private before refresh"),
      bStillTrustsC = (await devices(b.page)).some((d) => d.id === cId)
    console.log("B membership after C contact", {
      stillRefreshing,
      cSawSentinel,
      bStillTrustsC,
    })
    check(bStillTrustsC && stillRefreshing && !cSawSentinel, "stale C cannot fetch B's offline sentinel during startup")
  } finally {
    stallAuthority(false)
    const restoredMs = performance.now() - beforeUnlock
    check(
      restoredMs < 10_000,
      `schedule precondition: A restored ${Math.round(restoredMs)} ms after B began unlocking (must be <10000 ms, before its 15 s dial budget)`,
    )
  }
  await sync(b.page)
  await until(
    "authorized survivors exchange data after removal",
    async () => (await has(b.page, "After removal")) && (await cli("ls")).includes("B private before refresh"),
  )
  await request(c.page, { type: "device-sync", wait: true })
  check(
    !(await devices(b.page)).some((d) => d.id === cId) &&
      !(await has(c.page, "B private before refresh")) &&
      !(await has(c.page, "After removal")),
    "B learned C's removal; neither marker reached C while survivors converged",
  )
  await cli("sync") // A now has just one authorized peer; wait for the complete final exchange.
  await verifyDisks("removed")
  console.log("PASS private standalone relay faults")
}
try {
  await exercise()
} finally {
  await Promise.allSettled([...contexts].map((c) => c.close()))

  await cli("debug", "daemon", "stop").catch(() => {})
  for (const p of [pb, pc]) p.close()
  await services.close()
}
