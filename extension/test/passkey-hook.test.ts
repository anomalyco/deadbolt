// The page-world hook over a fake navigator.credentials: what the extension
// and the browser's own flow each get from the page's options.
import { afterEach, expect, test } from "bun:test"

const CHALLENGE = new Uint8Array(16)
const id = (n: number) => new Uint8Array([n, n >> 8, 7])
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")

/** What the browser's WebAuthn read from the options: every list, as WebIDL reads a sequence. */
type Seen = { kind: string; allow?: unknown[]; exclude?: unknown[]; params?: unknown[]; user?: unknown; signal?: unknown }
function read(list: unknown) {
  if (list === undefined) return undefined
  if (typeof list !== "object" || list === null || typeof (list as Iterable<unknown>)[Symbol.iterator] !== "function") throw new TypeError("not a sequence")
  return Array.from(list as Iterable<unknown>)
}

// happy-dom has no isSecureContext; the page is https.
Object.defineProperty(window, "isSecureContext", { value: true, configurable: true })

let copies = 0
const copiesListening: Array<() => MessagePort> = []
// Each copy takes the first port offered after it loads; offer every copy
// one, so none takes a later test's.
afterEach(() => {
  for (const offer of copiesListening.splice(0)) offer().close()
})
/** A fresh copy of the hook, as a page gets it, over a fake CredentialsContainer. */
async function hooked() {
  const native: Seen[] = []
  class CredentialsContainer {
    async get(o: any) {
      native.push({ kind: "get", allow: read(o.publicKey.allowCredentials), signal: o.signal })
      return "native"
    }
    async create(o: any) {
      native.push({ kind: "create", exclude: read(o.publicKey.excludeCredentials), params: read(o.publicKey.pubKeyCredParams), user: o.publicKey.user })
      return "native"
    }
  }
  const g = globalThis as { CredentialsContainer?: unknown }
  g.CredentialsContainer = CredentialsContainer
  // A query makes a new module instance; the hook installs on load.
  const path = `../src/passkey-hook.ts?copy=${++copies}`
  await import(path)
  delete g.CredentialsContainer
  const offer = () => {
    const channel = new MessageChannel()
    window.dispatchEvent(new MessageEvent("message", { data: { deadbolt: "passkey-port" }, source: window, ports: [channel.port2] }))
    return channel.port1
  }
  copiesListening.push(offer)
  return { credentials: new CredentialsContainer(), native, offer }
}

/** A list that can be read once, as a page's generator. */
function once<T>(items: T[]) {
  const reads = { count: 0 }
  const list = (function* () {
    reads.count++
    yield* items
  })()
  return { list, reads }
}

const descriptors = (n: number) => Array.from({ length: n }, (_, i) => ({ type: "public-key", id: id(i) }))
const user = { id: id(9), name: "kit", displayName: "Kit" }

test("with the channel down, the browser gets every entry of a list the page could read only once", async () => {
  const { credentials, native } = await hooked()
  const allow = once(descriptors(65))
  const exclude = once(descriptors(3))
  const params = once([{ type: "public-key", alg: -257 }])
  expect(await credentials.get({ publicKey: { challenge: CHALLENGE, allowCredentials: allow.list } })).toBe("native")
  expect(await credentials.create({ publicKey: { challenge: CHALLENGE, user, pubKeyCredParams: params.list, excludeCredentials: exclude.list } })).toBe("native")
  expect(native).toEqual([
    { kind: "get", allow: descriptors(65), signal: undefined },
    { kind: "create", exclude: descriptors(3), params: [{ type: "public-key", alg: -257 }], user },
  ])
  expect([allow.reads.count, exclude.reads.count, params.reads.count]).toEqual([1, 1, 1])
})

test("the extension and the browser get the same once-read list, whole", async () => {
  const { credentials, native, offer } = await hooked()
  const port = offer()
  const asked: any[] = []
  port.onmessage = (e) => {
    if (e.data.op === "ack") return
    asked.push(e.data)
    port.postMessage({ id: e.data.id, ok: true, result: { fallback: true } })
  }
  const allow = once(descriptors(65))
  const exclude = once([{ type: "public-key", id: id(1) }, { type: "future", id: id(2) }])
  const params = once([{ type: "public-key", alg: -7 }, { type: "other", alg: -7 }])
  const signal = new AbortController().signal
  expect(await credentials.get({ publicKey: { challenge: CHALLENGE, allowCredentials: allow.list }, signal })).toBe("native")
  expect(await credentials.create({ publicKey: { challenge: CHALLENGE, user, pubKeyCredParams: params.list, excludeCredentials: exclude.list } })).toBe("native")
  port.close()
  expect(asked.map((m) => m.op)).toEqual(["get", "create"])
  expect(asked[0].payload.allow).toEqual(descriptors(65).map((d) => b64(d.id)))
  expect(asked[1].payload.exclude).toEqual([b64(id(1)), null])
  expect(asked[1].payload.algorithms).toEqual([-7, null])
  // The browser's flow after Deadbolt passed: the same entries, and the page's own signal.
  expect(native).toEqual([
    { kind: "get", allow: descriptors(65), signal },
    {
      kind: "create",
      exclude: [{ type: "public-key", id: id(1) }, { type: "future", id: id(2) }],
      params: [{ type: "public-key", alg: -7 }, { type: "other", alg: -7 }],
      user,
    },
  ])
  expect([allow.reads.count, exclude.reads.count, params.reads.count]).toEqual([1, 1, 1])
})

test("options the hook can't read are the browser's to refuse", async () => {
  const { credentials, native } = await hooked()
  const boom = new Error("page iterator threw")
  const throwing = {
    *[Symbol.iterator]() {
      yield { type: "public-key", id: id(1) }
      throw boom
    },
  }
  expect(await credentials.get({ publicKey: { challenge: CHALLENGE, allowCredentials: throwing } }).catch((e: unknown) => e)).toBe(boom)
  expect(native).toEqual([])
  // Not iterable, or not an object: passed on as given, for the browser's TypeError.
  for (const allowCredentials of [{ length: 1, 0: { type: "public-key", id: id(1) } }, "AQID", 5]) expect(await credentials.get({ publicKey: { challenge: CHALLENGE, allowCredentials } }).catch((e: unknown) => e)).toBeInstanceOf(TypeError)
})
