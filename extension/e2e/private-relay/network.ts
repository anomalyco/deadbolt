// The browser sees its normal relay and signed-packet APIs. CONNECT is routed by
// exact name to a private socket; never resolve or forward the supplied name.
import { createServer } from "node:http"
import { connect, type Socket } from "node:net"
import type { Duplex } from "node:stream"
import { join } from "node:path"
import { writeFile } from "node:fs/promises"

export function run(...argv: string[]) {
  const p = Bun.spawnSync(argv, { stdout: "pipe", stderr: "pipe" })
  if (p.exitCode !== 0) throw new Error(`${argv[0]} ${argv[1]}: ${p.stderr.toString().trim()}`)
  return p.stdout.toString().trim()
}
const tc = (...args: string[]) => run("sudo", "-n", "tc", ...args)
export function initShape() {
  if (
    !/^1: lo:/.test(run("ip", "-o", "link")) ||
    run("ip", "-o", "link").includes("\n") ||
    run("ip", "route", "show", "default")
  )
    throw new Error("Requires isolated loopback-only netns; use run.sh")
  tc("qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio", "bands", "5", "priomap", ...Array(16).fill("0"))
  for (const [dir, band] of [
    ["src", "2"],
    ["dst", "3"],
  ]) {
    tc(
      "filter",
      "add",
      "dev",
      "lo",
      "parent",
      "1:",
      "protocol",
      "ip",
      "prio",
      band,
      "u32",
      "match",
      "ip",
      dir,
      "127.0.0.12/32",
      "flowid",
      `1:${band}`,
    )
    tc("qdisc", "add", "dev", "lo", "parent", `1:${band}`, "handle", `${band}0:`, "netem")
  }
  for (const [src, dst, band] of [
    ["127.0.0.1", "127.0.0.2", 4],
    ["127.0.0.2", "127.0.0.1", 5],
  ]) {
    tc(
      "filter",
      "add",
      "dev",
      "lo",
      "parent",
      "1:",
      "protocol",
      "ip",
      "prio",
      String(band),
      "u32",
      "match",
      "ip",
      "src",
      `${src}/32`,
      "match",
      "ip",
      "dst",
      `${dst}/32`,
      "flowid",
      `1:${band}`,
    )
    tc("qdisc", "add", "dev", "lo", "parent", `1:${band}`, "handle", `${band}0:`, "netem")
  }
}
// Hold packets on the already advertised native relay path until C has made contact.
export function stallAuthority(on: boolean) {
  for (const band of [4, 5])
    tc(
      "qdisc",
      "change",
      "dev",
      "lo",
      "parent",
      `1:${band}`,
      "handle",
      `${band}0:`,
      "netem",
      "loss",
      on ? "100%" : "0%",
    )
}
export function shape(mode: "clean" | "lossy" | "limited" | "blackhole") {
  const args = {
    clean: ["delay", "0ms"],
    lossy: ["delay", "150ms", "loss", "2%"],
    limited: ["rate", "1mbit"],
    blackhole: ["loss", "100%"],
  }[mode]
  for (const band of [2, 3])
    tc("qdisc", "change", "dev", "lo", "parent", `1:${band}`, "handle", `${band}0:`, "netem", ...args)
  console.log(`NET B=${mode}`, run("tc", "-s", "qdisc", "show", "dev", "lo").replace(/\n/g, " "))
}
export async function privateServices(root: string, relayBin: string) {
  const records = new Map<string, ArrayBuffer>()
  let nativeHomePublished = false
  const resolver = Bun.serve({
    hostname: "127.0.0.3",
    port: 443,
    maxRequestBodySize: 8192,
    tls: { key: Bun.file(join(root, "key.pem")), cert: Bun.file(join(root, "cert.pem")) },
    async fetch(req, server) {
      const path = new URL(req.url).pathname
      if (!/^\/pkarr\/[a-z0-9]{52}$/.test(path)) return new Response(null, { status: 404 })
      const headers = {
        "Cache-Control": "no-store",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "PUT,GET,OPTIONS",
        "Access-Control-Allow-Headers": "*",
      }
      if (req.method === "OPTIONS") return new Response(null, { headers })
      if (req.method === "PUT" && records.size < 64) {
        const payload = await req.arrayBuffer()
        records.set(path, payload)
        // Native A is the only direct HTTPS publisher; B/C come from .12/.13.
        // Observe its DNS TXT relay hint, not a key or a readiness surrogate.
        if (server.requestIP(req)?.address === "127.0.0.1")
          nativeHomePublished = Buffer.from(payload).includes("relay=https://use1-1.relay.n0.iroh.link")
        return new Response(null, { headers })
      }
      const bytes = records.get(path)
      return req.method === "GET" && bytes
        ? new Response(bytes, { headers })
        : new Response(null, { status: 404, headers })
    },
  })
  const conf = join(root, "relay.toml")
  await writeFile(
    conf,
    `http_bind_addr="127.0.0.2:7080"\nenable_metrics=false\nenable_quic_addr_discovery=true\n[tls]\ncert_mode="Manual"\nhttps_bind_addr="127.0.0.2:443"\nmanual_cert_path=${JSON.stringify(join(root, "cert.pem"))}\nmanual_key_path=${JSON.stringify(join(root, "key.pem"))}\n`,
  )
  const spawn = () => Bun.spawn([relayBin, "-c", conf], { stdout: "ignore", stderr: "inherit" })
  let relay = spawn()
  const ready = async () => {
    const end = performance.now() + 5000
    while (performance.now() < end && relay.exitCode === null) {
      if (
        await fetch("http://127.0.0.2:7080/", { signal: AbortSignal.timeout(500) }).then(
          () => true,
          () => false,
        )
      )
        return
      await Bun.sleep(30)
    }
    throw new Error(`private iroh-relay failed to listen: ${relay.exitCode}`)
  }
  await ready()
  return {
    records,
    nativeHomePublished: () => nativeHomePublished,
    restart: async () => {
      relay.kill("SIGKILL")
      await relay.exited
      relay = spawn()
      await ready()
    },
    close: async () => {
      resolver.stop(true)
      relay.kill()
      await relay.exited
    },
  }
}
export async function proxy(id: "b" | "c") {
  const localAddress = `127.0.0.${{ b: 12, c: 13 }[id]}`
  let isolated = false
  let relayBytes = 0
  const sockets = new Map<Duplex, Socket>()
  const proxy = createServer((_, res) => {
    res.writeHead(403)
    res.end()
  })
  proxy.on("connect", (req, client, head) => {
    client.on("error", () => client.destroy())
    const dest = req.url?.toLowerCase().replace(".:443", ":443")
    const relay = dest === "use1-1.relay.n0.iroh.link:443"
    if (isolated || (!relay && dest !== "dns.iroh.link:443")) {
      client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
      return
    }
    const upstream = connect({ host: relay ? "127.0.0.2" : "127.0.0.3", port: 443, localAddress })
    const close = () => {
      sockets.delete(client)
      client.destroy()
      upstream.destroy()
    }
    sockets.set(client, upstream)
    upstream.on("error", close)
    upstream.on("close", close)
    client.on("close", close)
    upstream.on("connect", () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n")
      if (head.length) upstream.write(head)
      if (relay) {
        client.on("data", (b) => (relayBytes += b.length))
        upstream.on("data", (b) => (relayBytes += b.length))
      }
      client.pipe(upstream)
      upstream.pipe(client)
    })
  })
  await new Promise<void>((ok, fail) => {
    proxy.once("error", fail)
    proxy.listen(0, "127.0.0.1", ok)
  })
  return {
    port: (proxy.address() as { port: number }).port,
    bytes: () => relayBytes,
    isolate(on: boolean) {
      isolated = on
      if (on) {
        for (const [c, u] of sockets) {
          c.destroy()
          u.destroy()
        }
      }
    },
    close() {
      for (const [c, u] of sockets) {
        c.destroy()
        u.destroy()
      }
      proxy.close()
    },
  }
}
