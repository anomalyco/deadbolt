import { beforeEach, describe, expect, test } from "bun:test"
import { HostError } from "../src/bg/backend"
import { Host } from "../src/bg/host"
import { parseOptions, Passkeys, rpIdFor } from "../src/bg/passkeys"
import { initPasskeyChannel } from "../src/content/passkeys"
import "../src/passkey-hook"
import { serializeCreate, serializeGet } from "../src/passkey-options"
import type { HookReply, PasskeyPrompt, ToBackground } from "../src/messages"
import { parseHostMessage, PROTOCOL, type RequestBody as Request } from "../src/protocol"
import { ID, installChrome, pageSender, POPUP_URL, type FakeChrome } from "./chrome"

const REF = `${"a".repeat(64)}:${"7".repeat(32)}`
const OTHER = `${"a".repeat(64)}:${"8".repeat(32)}`
const CHALLENGE = "AAECAwQFBgcICQoLDA0ODw"
const tick = () => new Promise((r) => setTimeout(r, 0))

describe("rpIdFor", () => {
  const at = (url: string, rp?: string) => rpIdFor(new URL(url), rp)

  test("the host, or a parent on the same site", () => {
    expect(at("https://login.example.com")).toBe("login.example.com")
    expect(at("https://login.example.com", "example.com")).toBe("example.com")
    expect(at("https://login.example.com", "LOGIN.Example.com")).toBe("login.example.com")
    expect(at("https://a.b.example.co.uk", "example.co.uk")).toBe("example.co.uk")
    expect(at("http://localhost:3000")).toBe("localhost")
  })

  test("never a public suffix, the private section included", () => {
    expect(at("https://example.com", "com")).toBeNull()
    expect(at("https://example.co.uk", "co.uk")).toBeNull()
    expect(at("https://alice.github.io", "github.io")).toBeNull()
    expect(at("https://github.io")).toBeNull()
  })

  test("never another site, a lookalike, an IP or an insecure page", () => {
    expect(at("https://example.com", "evil.com")).toBeNull()
    expect(at("https://example.com", "login.example.com")).toBeNull()
    expect(at("https://evilexample.com", "example.com")).toBeNull()
    expect(at("https://example.com", "example.com.")).toBeNull()
    expect(at("https://example.com", "")).toBeNull()
    expect(at("https://192.168.1.10")).toBeNull()
    expect(at("http://example.com")).toBeNull()
  })
})

describe("parseOptions", () => {
  test("keeps what the agent needs and refuses what the browser should", () => {
    expect(parseOptions("get", { challenge: CHALLENGE, allow: ["AQ"], userVerification: "nonsense", timeout: 1 })).toEqual({
      kind: "get",
      challenge: CHALLENGE,
      rpId: undefined,
      allow: ["AQ"],
      userVerification: "preferred",
      mediation: undefined,
      timeout: 60_000,
    })
    expect(parseOptions("get", { challenge: "" })).toBeNull()
    expect(parseOptions("get", { challenge: CHALLENGE, rpId: 3 })).toBeNull()
    expect(parseOptions("create", { challenge: CHALLENGE, user: { id: "a".repeat(87), name: "kit" } })).toBeNull()
    expect(parseOptions("create", { challenge: CHALLENGE, user: { name: "kit" } })).toBeNull()
  })

  test("a credential list is whole or the browser's: never cut short or filtered", () => {
    const many = Array.from({ length: 65 }, (_, i) => `AQ${i}`)
    for (const list of [["AQ", 5], ["AQ", "not base64!"], ["AQ", null], many, "AQ", {}, null]) {
      expect(parseOptions("get", { challenge: CHALLENGE, allow: list })).toBeNull()
      expect(parseOptions("create", { challenge: CHALLENGE, user: { id: "a2l0", name: "kit" }, exclude: list })).toBeNull()
    }
    expect(parseOptions("get", { challenge: CHALLENGE, allow: many.slice(0, 64) })).toMatchObject({ allow: many.slice(0, 64) })
    expect(parseOptions("get", { challenge: CHALLENGE })).toMatchObject({ allow: [] })
  })

  test("so is the algorithm list: none read means the browser's, never any algorithm", () => {
    const at = (algorithms: unknown) => parseOptions("create", { challenge: CHALLENGE, user: { id: "a2l0", name: "kit" }, exclude: [], algorithms })
    for (const list of [[null], [-7, null], ["-7"], undefined, null, {}, Array(65).fill(-7)]) expect(at(list)).toBeNull()
    expect(at([])).toMatchObject({ algorithms: [] })
    expect(at([-257, -7])).toMatchObject({ algorithms: [-257, -7] })
  })
})

const b64 = (text: string) => btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
/** Client data as the agent builds it (crates/cli/src/webauthn.rs). */
const clientData = (type: string, origin: string, crossOrigin = false) => b64(JSON.stringify({ type, challenge: CHALLENGE, origin, crossOrigin }))
const GET_DATA = clientData("webauthn.get", "https://www.example.com")

/** Something to wait on until released. */
function gate() {
  let open = () => {}
  const wait = new Promise<void>((resolve) => (open = resolve))
  return { wait, open }
}

/** A host with one passkey (`REF`, credential "Y3JlZA") for example.com. */
function passkeyHost(canVerify = false) {
  const requests: Request[] = []
  let ceremony: { resolve: () => void; reject: (e: Error) => void } | null = null
  let hold = false
  const gates: { connect?: Promise<void>; list?: Promise<void> } = {}
  /** `logins`: how many logins the site has; `passkeys`: whether it has the passkey. */
  const answers: { crossOrigin?: boolean; createError?: HostError; logins?: number; passkeys?: boolean } = {}
  const host = {
    status: { state: "ready", version: "0.0.0" },
    capabilities: ["list", "fill", "check", "save", "passkeys"],
    connect: async () => void (await gates.connect),
    send: async (req: Request, { onId }: { onId?: (id: number) => void } = {}) => {
      requests.push(req)
      onId?.(40 + requests.length)
      if ((req.type === "passkey-create" || req.type === "passkey-get") && hold)
        await new Promise<void>((resolve, reject) => (ceremony = { resolve, reject }))
      switch (req.type) {
        case "passkey-list":
          await gates.list
          if (req.rpId === "elsewhere.com") throw new HostError("domain_mismatch", "no")
          return { type: "passkeys", rpId: req.rpId ?? "www.example.com", canVerify, passkeys: answers.passkeys === false ? [] : [{ ref: REF, vault: "Personal", credentialId: "Y3JlZA", username: "kit" }] }
        case "list":
          return { type: "list", site: "example.com", accounts: Array.from({ length: answers.logins ?? 0 }, (_, i) => ({ ref: `${"b".repeat(64)}:${i}`, username: "kit", hasPassword: true })) }
        case "passkey-create":
          if (answers.createError) throw answers.createError
          return { type: "passkey-created", ref: OTHER, credentialId: "bmV3", clientDataJSON: clientData("webauthn.create", req.origin, answers.crossOrigin), attestationObject: "YW8", authenticatorData: "YWQ", publicKey: "cGs", verified: false }
        case "passkey-get":
          return { type: "passkey-assertion", credentialId: "Y3JlZA", clientDataJSON: clientData("webauthn.get", req.origin, answers.crossOrigin), authenticatorData: "YWQ", signature: "c2ln", userHandle: "a2l0", verified: false }
        case "passkey-cancel":
          ceremony?.reject(new HostError("cancelled", "cancelled"))
          return { type: "passkey-cancelled", found: !!ceremony }
      }
      throw new Error(`unexpected ${req.type}`)
    },
  }
  return {
    host: host as unknown as Host,
    requests,
    /** Ceremonies wait until `release`. */
    hold: () => void (hold = true),
    release: () => ceremony?.resolve(),
    gates,
    answers,
  }
}

let fake: FakeChrome
let h: ReturnType<typeof passkeyHost>
let passkeys: Passkeys
let opened: number[]

beforeEach(() => {
  fake = installChrome()
  fake.frames["1:3"] = { url: "https://www.example.com/frame", documentId: "frame-doc", parentFrameId: 0 }
  fake.frames["1:4"] = { url: "https://ads.example.net/frame", documentId: "ads-doc", parentFrameId: 0 }
  h = passkeyHost()
  opened = []
  passkeys = new Passkeys(h.host, { openPopup: async (tabId) => void opened.push(tabId) })
})

const call = (kind: "get" | "create", sender: chrome.runtime.MessageSender, request: number, options: unknown, allowed: unknown = true) => passkeys.request(kind, sender, request, options, allowed)
const create = (over: Record<string, unknown> = {}) => ({ challenge: CHALLENGE, user: { id: "a2l0", name: "kit" }, algorithms: [-7, -257], exclude: [], ...over })
const get = (over: Record<string, unknown> = {}) => ({ challenge: CHALLENGE, allow: [], ...over })
const kinds = () => h.requests.map((r) => r.type)

/** Waits for the tab's popup prompt to show. */
async function prompted(tabId = 1): Promise<PasskeyPrompt> {
  for (let i = 0; i < 50; i++) {
    const p = passkeys.prompt(tabId)
    if (p) return p
    await tick()
  }
  throw new Error("no prompt")
}

describe("frames", () => {
  test("a sandboxed or opaque frame is refused before the host hears of it", async () => {
    const reply = await call("get", pageSender({ origin: "null" }), 1, get())
    expect(reply).toEqual({ error: { name: "NotAllowedError", message: expect.any(String) } })
    expect(h.requests).toEqual([])
  })

  test("a frame on another origin than the top page gets the browser's own flow", async () => {
    expect(await call("get", pageSender({ frameId: 4, url: "https://ads.example.net/frame", origin: "https://ads.example.net", documentId: "ads-doc" }), 1, get())).toEqual({ fallback: true })
    expect(h.requests).toEqual([])
  })

  test("a frame with another origin anywhere above it gets the browser's own flow", async () => {
    // www.example.com inside ads.example.net inside www.example.com: the top
    // page matches, but WebAuthn calls this cross-origin.
    fake.frames["1:6"] = { url: "https://www.example.com/inner", documentId: "inner-doc", parentFrameId: 4 }
    const sender = pageSender({ frameId: 6, url: "https://www.example.com/inner", documentId: "inner-doc" })
    expect(await call("get", sender, 1, get())).toEqual({ fallback: true })
    expect(await call("create", sender, 2, create())).toEqual({ fallback: true })
    expect(h.requests).toEqual([])
    expect(passkeys.prompt(1)).toBeUndefined()
  })

  test("a frame the browser's record can't place gets the browser's own flow", async () => {
    fake.frames["1:7"] = { url: "https://www.example.com/lost", documentId: "lost-doc", parentFrameId: 99 }
    expect(await call("get", pageSender({ frameId: 7, documentId: "lost-doc" }), 1, get())).toEqual({ fallback: true })
    // A document that's no longer its frame's.
    expect(await call("get", pageSender({ frameId: 3, documentId: "old-frame-doc" }), 2, get())).toEqual({ fallback: true })
    expect(h.requests).toEqual([])
  })

  test("a same-origin frame is Deadbolt's", async () => {
    const reply = call("create", pageSender({ frameId: 3, url: "https://www.example.com/frame", documentId: "frame-doc" }), 1, create())
    passkeys.choose(1, (await prompted()).id, { action: "save" })
    expect(await reply).toMatchObject({ credential: { credentialId: "bmV3" } })
  })

  test("where the frame's Permissions Policy doesn't allow the call, the browser's own flow", async () => {
    expect(await call("get", pageSender(), 1, get(), false)).toEqual({ fallback: true })
    expect(await call("create", pageSender(), 2, create(), null)).toEqual({ fallback: true })
    expect(await call("create", pageSender(), 3, create(), "yes")).toEqual({ fallback: true })
    expect(await passkeys.handle({ type: "pk:get", request: 4, options: get() } as unknown as ToBackground, pageSender())).toEqual({ fallback: true })
    expect(h.requests).toEqual([])
  })

  test("what the page gets is for its own origin, never cross-origin", async () => {
    h.answers.crossOrigin = true
    const reply = call("create", pageSender(), 1, create())
    passkeys.choose(1, (await prompted()).id, { action: "save" })
    expect(await reply).toMatchObject({ error: { name: "NotAllowedError" } })
  })

  test("the origin sent is the browser's, never the page's", async () => {
    const reply = call("create", pageSender(), 1, create({ origin: "https://evil.com", rpId: "example.com" }))
    passkeys.choose(1, (await prompted()).id, { action: "save" })
    expect(await reply).toMatchObject({ credential: { credentialId: "bmV3" } })
    const made = h.requests.find((r) => r.type === "passkey-create")
    expect(made).toMatchObject({ origin: "https://www.example.com", rpId: "example.com", challenge: CHALLENGE, user: { id: "a2l0", name: "kit" } })
  })
})

describe("rpId", () => {
  test("another site's rpId is a SecurityError, with nothing asked", async () => {
    expect(await call("create", pageSender(), 1, create({ rpId: "evil.com" }))).toEqual({ error: { name: "SecurityError", message: expect.any(String) } })
    expect(await call("get", pageSender(), 2, get({ rpId: "com" }))).toEqual({ error: { name: "SecurityError", message: expect.any(String) } })
    expect(h.requests).toEqual([])
    expect(passkeys.prompt(1)).toBeUndefined()
  })

  test("the agent's refusal is a SecurityError too", async () => {
    // A rule the extension's copy might miss still stops at the agent.
    fake.frames["1:0"] = { url: "https://www.elsewhere.com/", documentId: "top-doc" }
    const sender = pageSender({ url: "https://www.elsewhere.com/", origin: "https://www.elsewhere.com" })
    expect(await call("get", sender, 1, get({ rpId: "elsewhere.com" }))).toEqual({ error: { name: "SecurityError", message: expect.any(String) } })
  })
})

describe("host", () => {
  test("a host that doesn't do passkeys leaves them to the browser", async () => {
    ;(h.host as { capabilities: string[] }).capabilities = ["list", "fill", "check", "save"]
    expect(await call("get", pageSender(), 1, get())).toEqual({ fallback: true })
    expect(h.requests).toEqual([])
  })
})

describe("registration", () => {
  test("a site that doesn't take ES256 gets the browser's flow", async () => {
    expect(await call("create", pageSender(), 1, create({ algorithms: [-257, -8] }))).toEqual({ fallback: true })
    expect(await call("create", pageSender(), 2, create({ attachment: "cross-platform" }))).toEqual({ fallback: true })
    expect(h.requests).toEqual([])
  })

  test("asks in the popup, and Cancel or Use another device store nothing", async () => {
    const first = call("create", pageSender(), 1, create())
    const prompt = await prompted()
    expect(prompt).toMatchObject({ kind: "create", rpId: "www.example.com", username: "kit", registered: false, verify: false })
    expect(opened).toEqual([1])
    expect(fake.badges[1]).toBe("1")
    passkeys.choose(1, prompt.id, { action: "cancel" })
    expect(await first).toEqual({ error: { name: "NotAllowedError", message: expect.any(String) } })
    expect(fake.badges[1]).toBe("")

    const second = call("create", pageSender(), 2, create())
    passkeys.choose(1, (await prompted()).id, { action: "fallback" })
    expect(await second).toEqual({ fallback: true })
    expect(kinds()).toEqual(["passkey-list", "passkey-list"])
  })

  test("only the prompt shown is answered", async () => {
    const reply = call("create", pageSender(), 1, create())
    const prompt = await prompted()
    expect(passkeys.choose(1, "other", { action: "save" })).toEqual({ ok: false })
    expect(passkeys.choose(2, prompt.id, { action: "save" })).toEqual({ ok: false })
    expect(passkeys.choose(1, prompt.id, { action: "use", ref: "junk" })).toEqual({ ok: false })
    expect(await passkeys.handle({ type: "pk:popup-choose", tabId: 1, id: prompt.id, choice: { action: "save" } }, pageSender())).toEqual({ ok: false })
    expect(await passkeys.handle({ type: "pk:popup-choose", tabId: 1, id: prompt.id, choice: { action: "save" } }, { id: ID, url: POPUP_URL })).toEqual({ ok: true })
    expect(await reply).toMatchObject({ credential: { credentialId: "bmV3" } })
  })

  test("a passkey the site excluded is already saved: InvalidStateError", async () => {
    const reply = call("create", pageSender(), 1, create({ exclude: ["Y3JlZA"] }))
    const prompt = await prompted()
    expect(prompt).toMatchObject({ registered: true })
    passkeys.choose(1, prompt.id, { action: "save" })
    expect(await reply).toEqual({ error: { name: "InvalidStateError", message: expect.any(String) } })
    expect(kinds()).toEqual(["passkey-list"])
  })

  test("an algorithm list Deadbolt can't read whole is the browser's", async () => {
    expect(await call("create", pageSender(), 1, create({ algorithms: [-7, null] }))).toEqual({ fallback: true })
    expect(await call("create", pageSender(), 2, create({ algorithms: undefined }))).toEqual({ fallback: true })
    expect(h.requests).toEqual([])
  })

  test("an excluded passkey saved while the user was asked is still InvalidStateError", async () => {
    h.answers.createError = new HostError("exists", "this site already has a passkey here")
    const reply = call("create", pageSender(), 1, create({ exclude: ["bmV3"] }))
    passkeys.choose(1, (await prompted()).id, { action: "save" })
    expect(await reply).toEqual({ error: { name: "InvalidStateError", message: expect.any(String) } })
  })

  test("required verification without Touch ID is the browser's", async () => {
    expect(await call("create", pageSender(), 1, create({ userVerification: "required" }))).toEqual({ fallback: true })
    expect(kinds()).toEqual(["passkey-list"])
  })
})

describe("sign-in", () => {
  test("modal: the popup lists the site's passkeys and signs with the one picked", async () => {
    const reply = call("get", pageSender(), 1, get({ rpId: "example.com", userVerification: "required" }))
    await tick()
    // Required verification without Touch ID went to the browser; with it, Deadbolt asks.
    expect(await reply).toEqual({ fallback: true })
    h = passkeyHost(true)
    passkeys = new Passkeys(h.host, { openPopup: async () => {} })
    const again = call("get", pageSender(), 2, get({ rpId: "example.com", userVerification: "required" }))
    const prompt = await prompted()
    expect(prompt).toMatchObject({ kind: "get", rpId: "example.com", verify: true, passkeys: [{ ref: REF, username: "kit", vault: "Personal" }] })
    passkeys.choose(1, prompt.id, { action: "use", ref: REF })
    expect(await again).toEqual({ credential: { credentialId: "Y3JlZA", clientDataJSON: GET_DATA, authenticatorData: "YWQ", signature: "c2ln", userHandle: "a2l0" } })
    expect(h.requests[1]).toMatchObject({ type: "passkey-get", origin: "https://www.example.com", rpId: "example.com", ref: REF, challenge: CHALLENGE, userVerification: "required" })
  })

  test("no passkey the site allows: the browser's flow", async () => {
    expect(await call("get", pageSender(), 1, get({ allow: ["b3RoZXI"] }))).toEqual({ fallback: true })
  })

  test("an allow list with anything Deadbolt can't read is the browser's, never allow-all", async () => {
    for (const allow of [[null], ["Y3JlZA", null], Array.from({ length: 65 }, () => "Y3JlZA")]) expect(await call("get", pageSender(), 1, get({ allow }))).toEqual({ fallback: true })
    expect(h.requests).toEqual([])
    expect(passkeys.prompt(1)).toBeUndefined()
  })

  test("one prompt per tab at a time", async () => {
    const first = call("get", pageSender(), 1, get())
    await prompted()
    expect(await call("get", pageSender(), 2, get())).toEqual({ error: { name: "NotAllowedError", message: expect.any(String) } })
    passkeys.forgetTab(1)
    expect(await first).toMatchObject({ error: { name: "NotAllowedError" } })
  })
})

describe("aborts", () => {
  test("the page's AbortSignal ends the prompt", async () => {
    const reply = call("get", pageSender(), 9, get())
    await prompted()
    expect(passkeys.cancelFrom(pageSender({ documentId: "other-doc" }), 9)).toBe(false)
    expect(passkeys.cancelFrom(pageSender(), 9)).toBe(true)
    expect(await reply).toEqual({ error: { name: "AbortError", message: expect.any(String) } })
    expect(passkeys.prompt(1)).toBeUndefined()
  })

  test("an abort during Touch ID cancels the agent's ceremony", async () => {
    h.hold()
    const reply = call("get", pageSender(), 9, get())
    passkeys.choose(1, (await prompted()).id, { action: "use", ref: REF })
    await tick()
    passkeys.cancelFrom(pageSender(), 9)
    expect(await reply).toMatchObject({ error: { name: "AbortError" } })
    await tick()
    expect(h.requests.at(-1)).toEqual({ type: "passkey-cancel", request: 42 })
  })

  test("an abort while Deadbolt is still getting ready ends the call there", async () => {
    const connected = gate()
    h.gates.connect = connected.wait
    const reply = call("get", pageSender(), 9, get())
    await tick()
    expect(passkeys.cancelFrom(pageSender(), 9)).toBe(true)
    expect(await reply).toEqual({ error: { name: "AbortError", message: expect.any(String) } })
    connected.open()
    await tick()
    await tick()
    expect(h.requests).toEqual([])
    expect(passkeys.prompt(1)).toBeUndefined()
  })

  test("navigation or a closed tab while listing: no prompt", async () => {
    const listed = gate()
    h.gates.list = listed.wait
    const navigated = call("get", pageSender(), 1, get())
    for (let i = 0; i < 5; i++) await tick()
    expect(kinds()).toEqual(["passkey-list"])
    passkeys.navigated({ tabId: 1, frameId: 0, documentId: "next-doc" })
    expect(await navigated).toMatchObject({ error: { name: "NotAllowedError" } })
    const closed = call("get", pageSender(), 2, get())
    passkeys.forgetTab(1)
    expect(await closed).toMatchObject({ error: { name: "NotAllowedError" } })
    listed.open()
    for (let i = 0; i < 5; i++) await tick()
    expect(passkeys.prompt(1)).toBeUndefined()
    expect(opened).toEqual([])
  })

  test("a document that changed unseen gets no prompt and nothing delivered", async () => {
    const listed = gate()
    h.gates.list = listed.wait
    const before = call("get", pageSender(), 1, get())
    for (let i = 0; i < 5; i++) await tick()
    // The frame has a new document, and no navigation event said so.
    fake.frames["1:0"] = { ...fake.frames["1:0"], documentId: "next-doc" }
    listed.open()
    expect(await before).toMatchObject({ error: { name: "NotAllowedError" } })
    expect(opened).toEqual([])

    fake.frames["1:0"] = { ...fake.frames["1:0"], documentId: "top-doc" }
    h.hold()
    const during = call("get", pageSender(), 2, get())
    passkeys.choose(1, (await prompted()).id, { action: "use", ref: REF })
    for (let i = 0; i < 5; i++) await tick()
    fake.frames["1:0"] = { ...fake.frames["1:0"], documentId: "next-doc" }
    h.release()
    expect(await during).toMatchObject({ error: { name: "NotAllowedError" } })
  })

  test("a frame removed by its parent's navigation ends its calls", async () => {
    fake.frames["1:6"] = { url: "https://www.example.com/inner", documentId: "inner-doc", parentFrameId: 3 }
    const reply = call("get", pageSender({ frameId: 6, documentId: "inner-doc" }), 1, get())
    await prompted()
    delete fake.frames["1:6"]
    fake.frames["1:3"] = { ...fake.frames["1:3"], documentId: "new-frame-doc" }
    passkeys.navigated({ tabId: 1, frameId: 3, documentId: "new-frame-doc" })
    expect(await reply).toMatchObject({ error: { name: "NotAllowedError" } })
    expect(passkeys.prompt(1)).toBeUndefined()
  })

  test("navigating the frame ends its calls; another frame's stay", async () => {
    const top = call("get", pageSender(), 1, get())
    await prompted()
    passkeys.navigated({ tabId: 1, frameId: 3, documentId: "new-frame-doc" })
    expect(passkeys.prompt(1)).toBeDefined()
    passkeys.navigated({ tabId: 1, frameId: 0, documentId: "next-doc" })
    expect(await top).toMatchObject({ error: { name: "NotAllowedError" } })
    expect(passkeys.prompt(1)).toBeUndefined()
  })
})

/** A native port the test plays `deadbolt browser-host` on, for the real Host. */
class NativePort {
  sent: Array<Record<string, any>> = []
  private heard: Array<(m: unknown) => void> = []
  private gone: Array<() => void> = []
  onMessage = { addListener: (l: (m: unknown) => void) => this.heard.push(l) }
  onDisconnect = { addListener: (l: () => void) => this.gone.push(l) }
  constructor(private holdHello: boolean) {}
  postMessage(m: Record<string, any>) {
    this.sent.push(m)
    if (m.type === "hello" && !this.holdHello) this.hello()
    if (m.type === "passkey-list")
      queueMicrotask(() => this.push({ id: m.id, type: "passkeys", rpId: m.rpId ?? "www.example.com", canVerify: false, passkeys: [{ ref: REF, vault: "Personal", credentialId: "Y3JlZA", username: "kit" }] }))
  }
  /** Answers the hello. */
  hello() {
    const id = this.sent.find((m) => m.type === "hello")!.id
    queueMicrotask(() => this.push({ id, type: "hello", protocol: PROTOCOL, version: "0.0.0", status: "ready", capabilities: ["passkeys"] }))
  }
  push(m: unknown) {
    for (const l of this.heard) l(m)
  }
  exit() {
    for (const l of this.gone) l()
  }
}

describe("a ceremony waiting on a reconnect", () => {
  for (const [kind, end] of [
    ["create", "abort"],
    ["get", "navigation"],
    ["create", "navigation"],
    ["get", "abort"],
  ] as const)
    test(`${kind}: ${end} while the host reconnects, and the agent never hears of it`, async () => {
      const ports: NativePort[] = []
      const host = new Host(() => {
        const port = new NativePort(ports.length > 0)
        ports.push(port)
        return port as unknown as chrome.runtime.Port
      })
      passkeys = new Passkeys(host, { openPopup: async () => {} })
      const reply = call(kind, pageSender(), 1, kind === "create" ? create() : get())
      const prompt = await prompted()
      // The host goes away while the user is asked; the user approves.
      ports[0].exit()
      passkeys.choose(1, prompt.id, kind === "create" ? { action: "save" } : { action: "use", ref: REF })
      for (let i = 0; i < 20 && ports.length < 2; i++) await tick()
      expect(ports).toHaveLength(2)
      if (end === "abort") passkeys.cancelFrom(pageSender(), 1)
      else passkeys.navigated({ tabId: 1, frameId: 0, documentId: "next-doc" })
      expect(await reply).toMatchObject({ error: { name: end === "abort" ? "AbortError" : "NotAllowedError" } })
      ports[1].hello()
      for (let i = 0; i < 10; i++) await tick()
      expect(host.status.state).toBe("ready")
      expect(ports[1].sent.map((m) => m.type)).toEqual(["hello"])
    })
})

describe("limits", () => {
  test("a flooding page holds at most a tab's slots, and lists once", async () => {
    const listed = gate()
    h.gates.list = listed.wait
    const replies = Array.from({ length: 20 }, (_, i) => call(i % 2 ? "create" : "get", pageSender(), i + 1, i % 2 ? create() : get()))
    // Past the tab's slots, refused at once, before the host hears anything.
    const late = await Promise.all(replies.slice(8))
    expect(late.every((r) => "error" in r && r.error.name === "NotAllowedError")).toBe(true)
    listed.open()
    await prompted()
    expect(kinds()).toEqual(["passkey-list"])
    passkeys.forgetTab(1)
    await Promise.all(replies)
  })

  test("each document lists a few at once, then one a second", async () => {
    let now = 1_000_000
    passkeys = new Passkeys(h.host, { openPopup: async () => {}, now: () => now })
    // Nothing the site allows: each call lists, then goes to the browser.
    for (let i = 1; i <= 4; i++) expect(await call("get", pageSender(), i, get({ allow: ["b3RoZXI"] }))).toEqual({ fallback: true })
    expect(await call("get", pageSender(), 5, get({ allow: ["b3RoZXI"] }))).toMatchObject({ error: { name: "NotAllowedError" } })
    // Another document has its own.
    fake.frames["1:3"] = { url: "https://www.example.com/frame", documentId: "frame-doc", parentFrameId: 0 }
    expect(await call("get", pageSender({ frameId: 3, documentId: "frame-doc" }), 6, get({ allow: ["b3RoZXI"] }))).toEqual({ fallback: true })
    now += 1000
    expect(await call("get", pageSender(), 7, get({ allow: ["b3RoZXI"] }))).toEqual({ fallback: true })
    expect(kinds()).toEqual(Array(6).fill("passkey-list"))
  })

  test("the host's rate limit is the page's NotAllowedError", async () => {
    const send = h.host.send.bind(h.host)
    ;(h.host as { send: unknown }).send = async (req: Request, ...rest: unknown[]) => {
      if (req.type === "passkey-list") throw new HostError("rate_limited", "slow down")
      return (send as (...a: unknown[]) => unknown)(req, ...rest)
    }
    expect(await call("get", pageSender(), 1, get())).toMatchObject({ error: { name: "NotAllowedError" } })
  })
})

describe("autofill sign-in (conditional mediation)", () => {
  const target = { tabId: 1, frameId: 0, documentId: "top-doc", origin: "https://www.example.com" }

  test("offers the passkeys in that document's inline menu and signs with the pick", async () => {
    let answered: HookReply | null = null
    void call("get", pageSender(), 5, get({ mediation: "conditional" })).then((r) => (answered = r))
    for (let i = 0; i < 20 && !passkeys.menuPasskeys(target, "username").length; i++) await tick()
    expect(passkeys.menuPasskeys(target, "username")).toEqual([{ ref: REF, vault: "Personal", username: "kit" }])
    expect(passkeys.menuPasskeys(target, "otp")).toEqual([])
    expect(passkeys.menuPasskeys({ ...target, documentId: "other-doc" }, "username")).toEqual([])
    expect(passkeys.prompt(1)).toBeUndefined()
    expect(await passkeys.menuPick({ ...target, documentId: "other-doc" }, REF)).toBeNull()
    expect(await passkeys.menuPick(target, OTHER)).toBeNull()
    expect(await passkeys.menuPick(target, REF)).toEqual({ ok: true })
    await tick()
    expect(answered).toMatchObject({ credential: { credentialId: "Y3JlZA" } })
    expect(await passkeys.menuPick(target, REF)).toBeNull()
  })

  const conditional = get({ mediation: "conditional" })
  /** Apple's sign-in frame in App Store Connect: another origin of the top page's site. */
  const LOGIN_FRAME = { frameId: 8, url: "https://idmsa.example.com/signin", origin: "https://idmsa.example.com", documentId: "idmsa-doc" }
  const loginFrame = { tabId: 1, frameId: 8, documentId: "idmsa-doc", origin: "https://idmsa.example.com" }
  beforeEach(() => {
    fake.frames["1:8"] = { url: LOGIN_FRAME.url, documentId: LOGIN_FRAME.documentId, parentFrameId: 0 }
  })

  /** The call's answer so far: null while it's held. */
  function watch(sender: chrome.runtime.MessageSender, request = 5) {
    const seen: { reply: HookReply | null } = { reply: null }
    void call("get", sender, request, conditional).then((r) => (seen.reply = r))
    return seen
  }
  const settle = async () => {
    for (let i = 0; i < 20; i++) await tick()
  }

  // Where Deadbolt's menu opens, it holds the call (the browser's dropdown
  // would cover the menu) whenever it has logins or passkeys for the site.
  const cases: Array<[string, chrome.runtime.MessageSender, { logins: number; passkeys: boolean; locked?: boolean }, "held" | "fallback"]> = [
    ["top page, passkeys", pageSender(), { logins: 0, passkeys: true }, "held"],
    ["top page, logins only", pageSender(), { logins: 2, passkeys: false }, "held"],
    ["top page, neither", pageSender(), { logins: 0, passkeys: false }, "fallback"],
    ["top page, locked", pageSender(), { logins: 2, passkeys: true, locked: true }, "fallback"],
    ["same-origin frame, passkeys", pageSender({ frameId: 3, documentId: "frame-doc" }), { logins: 0, passkeys: true }, "held"],
    ["same-origin frame, neither", pageSender({ frameId: 3, documentId: "frame-doc" }), { logins: 0, passkeys: false }, "fallback"],
    ["same-site frame, logins", pageSender(LOGIN_FRAME), { logins: 1, passkeys: true }, "held"],
    ["same-site frame, passkeys only", pageSender(LOGIN_FRAME), { logins: 0, passkeys: true }, "fallback"],
    ["same-site frame, neither", pageSender(LOGIN_FRAME), { logins: 0, passkeys: false }, "fallback"],
    ["same-site frame, locked", pageSender(LOGIN_FRAME), { logins: 1, passkeys: true, locked: true }, "fallback"],
    ["cross-site frame, logins", pageSender({ frameId: 4, url: "https://ads.example.net/frame", origin: "https://ads.example.net", documentId: "ads-doc" }), { logins: 1, passkeys: true }, "fallback"],
  ]
  for (const [name, sender, has, expected] of cases)
    test(`${name}: ${expected}`, async () => {
      h.answers.logins = has.logins
      h.answers.passkeys = has.passkeys
      if (has.locked) (h.host as { status: { state: string } }).status = { state: "locked", version: "0.0.0" } as never
      const seen = watch(sender)
      await settle()
      expect(seen.reply).toEqual(expected === "held" ? null : { fallback: true })
      expect(passkeys.prompt(1)).toBeUndefined()
      // Only a frame on one origin all the way up lists passkeys: elsewhere the agent's client data wouldn't be true.
      if (sender.origin !== "https://www.example.com") expect(kinds()).not.toContain("passkey-list")
    })

  test("a held call in a same-site login frame offers its logins only, and a picked login leaves it waiting", async () => {
    h.answers.logins = 1
    const seen = watch(pageSender(LOGIN_FRAME))
    await settle()
    expect(passkeys.menuPasskeys(loginFrame, "username")).toEqual([])
    expect(await passkeys.menuPick(loginFrame, REF)).toBeNull()
    expect(seen.reply).toBeNull()
    // Another frame's navigation leaves it; the page's AbortSignal ends it.
    passkeys.navigated({ tabId: 1, frameId: 3, documentId: "new-frame-doc" })
    await settle()
    expect(seen.reply).toBeNull()
    expect(passkeys.cancelFrom(pageSender(LOGIN_FRAME), 5)).toBe(true)
    await settle()
    expect(seen.reply).toEqual({ error: { name: "AbortError", message: expect.any(String) } })
  })

  test("a held login frame's call ends when its frame or the top page navigates", async () => {
    h.answers.logins = 1
    const frameGone = watch(pageSender(LOGIN_FRAME), 5)
    await settle()
    fake.frames["1:8"] = { ...fake.frames["1:8"], documentId: "idmsa-next" }
    passkeys.navigated({ tabId: 1, frameId: 8, documentId: "idmsa-next" })
    await settle()
    expect(frameGone.reply).toMatchObject({ error: { name: "NotAllowedError" } })
    fake.frames["1:8"] = { ...fake.frames["1:8"], documentId: LOGIN_FRAME.documentId }
    const topGone = watch(pageSender(LOGIN_FRAME), 6)
    await settle()
    passkeys.navigated({ tabId: 1, frameId: 0, documentId: "next-doc" })
    await settle()
    expect(topGone.reply).toMatchObject({ error: { name: "NotAllowedError" } })
  })

  test("a same-origin frame's held call offers its passkeys and signs with the pick", async () => {
    const frame = { tabId: 1, frameId: 3, documentId: "frame-doc", origin: "https://www.example.com" }
    const seen = watch(pageSender({ frameId: 3, documentId: "frame-doc" }))
    await settle()
    expect(passkeys.menuPasskeys(frame, "password")).toEqual([{ ref: REF, vault: "Personal", username: "kit" }])
    expect(passkeys.menuPasskeys(target, "username")).toEqual([])
    expect(await passkeys.menuPick(frame, REF)).toEqual({ ok: true })
    await settle()
    expect(seen.reply).toMatchObject({ credential: { credentialId: "Y3JlZA" } })
  })

  test("a top page with logins but no passkeys is held without passkey rows, until aborted", async () => {
    h.answers.logins = 1
    h.answers.passkeys = false
    const seen = watch(pageSender())
    await settle()
    expect(passkeys.menuPasskeys(target, "username")).toEqual([])
    expect(seen.reply).toBeNull()
    expect(passkeys.cancelFrom(pageSender(), 5)).toBe(true)
    await settle()
    expect(seen.reply).toEqual({ error: { name: "AbortError", message: expect.any(String) } })
  })

  test("modal sign-in is unchanged: with logins but no passkeys, the browser's sheet", async () => {
    h.answers.logins = 1
    h.answers.passkeys = false
    expect(await call("get", pageSender(), 1, get())).toEqual({ fallback: true })
    expect(await call("get", pageSender(LOGIN_FRAME), 2, get())).toEqual({ fallback: true })
  })
})

describe("user verification", () => {
  test("the prompt says Touch ID comes next only when the agent will ask", async () => {
    h = passkeyHost(true)
    passkeys = new Passkeys(h.host, { openPopup: async () => {} })
    const discouraged = call("create", pageSender(), 1, create({ userVerification: "discouraged" }))
    const p1 = await prompted()
    expect(p1.verify).toBe(false)
    passkeys.choose(1, p1.id, { action: "save" })
    await discouraged
    const preferred = call("create", pageSender(), 2, create())
    const p2 = await prompted()
    expect(p2.verify).toBe(true)
    passkeys.choose(1, p2.id, { action: "save" })
    await preferred
    expect(h.requests.filter((r) => r.type === "passkey-create").map((r) => (r as { userVerification: string }).userVerification)).toEqual(["discouraged", "preferred"])
  })

  /** A provider chain owning the page's call, as bg/provider-chain.ts hooks in: `[]` ends it. */
  function chained(canVerify: boolean) {
    h = passkeyHost(canVerify)
    passkeys = new Passkeys(h.host, { openPopup: async () => {} })
    const session = new AbortController()
    const ended: boolean[] = []
    passkeys.automaticSession = () => (session.signal.aborted ? undefined : session.signal)
    passkeys.automatic = async (_target, keys) => {
      if (session.signal.aborted) return undefined
      if (!keys.length) { ended.push(true); session.abort(); return null }
      return { ref: keys[0].ref, signal: session.signal }
    }
    return ended
  }

  test("a provider chain signs without a prompt only where the agent verifies the person", async () => {
    const ended = chained(true)
    expect(await call("get", pageSender(), 1, get({ userVerification: "preferred" }))).toMatchObject({ credential: { credentialId: "Y3JlZA" } })
    expect(ended).toEqual([])
    expect(passkeys.prompt(1)).toBeUndefined()
  })

  test.each([[false, "preferred"], [true, "discouraged"], [false, "discouraged"]] as const)("canVerify %p and %s: the chain ends and the usual prompt asks", async (canVerify, userVerification) => {
    const ended = chained(canVerify)
    const reply = call("get", pageSender(), 1, get({ userVerification }))
    const prompt = await prompted()
    expect(ended).toEqual([true])
    expect(kinds()).not.toContain("passkey-get")
    passkeys.choose(1, prompt.id, { action: "use", ref: REF })
    expect(await reply).toMatchObject({ credential: { credentialId: "Y3JlZA" } })
  })
})

describe("host replies", () => {
  test("passkey replies keep only documented, well-formed fields", () => {
    expect(parseHostMessage({ id: 1, type: "passkeys", rpId: "example.com", canVerify: true, passkeys: [{ ref: REF, vault: "P", credentialId: "Y3JlZA", privateKey: "x" }, { ref: "bad" }] })).toEqual({
      kind: "reply",
      id: 1,
      reply: { type: "passkeys", rpId: "example.com", canVerify: true, passkeys: [{ ref: REF, vault: "P", credentialId: "Y3JlZA", username: undefined, created: undefined }] },
    })
    // Only a worker's own true says its preset asks for the passphrase.
    expect(parseHostMessage({ id: 1, type: "passkeys", rpId: "example.com", canVerify: false, asksPassphrase: true, passkeys: [] })).toMatchObject({ reply: { asksPassphrase: true } })
    expect(parseHostMessage({ id: 1, type: "passkeys", rpId: "example.com", canVerify: false, asksPassphrase: "yes", passkeys: [] })).not.toHaveProperty("reply.asksPassphrase")
    expect(parseHostMessage({ id: 2, type: "passkey-assertion", credentialId: "Y3JlZA", clientDataJSON: "e30", authenticatorData: "YQ", signature: "c2ln", userHandle: "a2l0" })?.kind).toBe("reply")
    expect(parseHostMessage({ id: 2, type: "passkey-assertion", credentialId: "Y3JlZA", clientDataJSON: "{}", authenticatorData: "YQ", signature: "c2ln", userHandle: "a2l0" })).toBeNull()
    expect(parseHostMessage({ id: 3, type: "error", code: "cancelled", message: "x" })).toMatchObject({ reply: { code: "cancelled" } })
  })
})

describe("the page channel", () => {
  test("one offer, and only the acknowledged port carries requests", async () => {
    const posted: MessagePort[] = []
    const original = window.postMessage
    window.postMessage = ((data: unknown, _origin: string, transfer?: Transferable[]) => {
      if ((data as { deadbolt?: string })?.deadbolt === "passkey-port") posted.push(transfer![0] as MessagePort)
    }) as typeof window.postMessage
    const sent: ToBackground[] = []
    try {
      initPasskeyChannel(async <T,>(m: ToBackground) => {
        sent.push(m)
        return { fallback: true } as T
      })
    } finally {
      window.postMessage = original
    }
    expect(posted.length).toBe(1)
    const port = posted[0]
    const replies: unknown[] = []
    port.onmessage = (e) => replies.push(e.data)
    // A request before the hook's ack goes nowhere.
    port.postMessage({ id: 1, op: "get", payload: get() })
    await Bun.sleep(5)
    expect(sent).toEqual([])
    port.postMessage({ op: "ack" })
    port.postMessage({ id: 2, op: "get", payload: get() })
    port.postMessage({ id: 2, op: "cancel" })
    await Bun.sleep(5)
    expect(sent).toEqual([
      { type: "pk:get", request: 2, options: get(), allowed: false },
      { type: "pk:cancel", request: 2 },
    ])
    expect(replies).toEqual([{ id: 2, ok: true, result: { fallback: true } }])
    port.close()
  })

  test("the content script reads the frame's Permissions Policy, per call", async () => {
    const posted: MessagePort[] = []
    const original = window.postMessage
    window.postMessage = ((data: unknown, _origin: string, transfer?: Transferable[]) => {
      if ((data as { deadbolt?: string })?.deadbolt === "passkey-port") posted.push(transfer![0] as MessagePort)
    }) as typeof window.postMessage
    const doc = document as unknown as { featurePolicy?: { allowsFeature(f: string): boolean } }
    doc.featurePolicy = { allowsFeature: (f) => f === "publickey-credentials-get" }
    const sent: ToBackground[] = []
    try {
      initPasskeyChannel(async <T,>(m: ToBackground) => {
        sent.push(m)
        return { fallback: true } as T
      })
      const port = posted[0]
      port.postMessage({ op: "ack" })
      port.postMessage({ id: 1, op: "get", payload: get() })
      port.postMessage({ id: 2, op: "create", payload: create() })
      await Bun.sleep(5)
      port.close()
    } finally {
      window.postMessage = original
      delete doc.featurePolicy
    }
    expect(sent.map((m) => "allowed" in m && m.allowed)).toEqual([true, false])
  })

  test("the hook sends credential lists whole, marking what isn't a credential id", () => {
    const id = new Uint8Array([1, 2, 3])
    const publicKey = { challenge: new Uint8Array(16), allowCredentials: [{ type: "public-key", id }, { type: "other", id }, { type: "public-key", id: "AQID" }] }
    expect(serializeGet({ publicKey }).allow).toEqual(["AQID", null, null])
    expect(serializeGet({ publicKey: { challenge: new Uint8Array(16) } }).allow).toBeUndefined()
    expect(serializeGet({ publicKey: { challenge: new Uint8Array(16), allowCredentials: 5 } }).allow).toBeNull()
    const many = Array.from({ length: 100 }, () => ({ type: "public-key", id }))
    expect(serializeCreate({ publicKey: { challenge: new Uint8Array(16), user: { id }, excludeCredentials: many } }).exclude).toHaveLength(100)
  })

  test("the hook keeps the first offered port, and the page never sees it", async () => {
    const offer = () => {
      const channel = new MessageChannel()
      const acks: unknown[] = []
      channel.port1.onmessage = (e) => acks.push(e.data)
      window.dispatchEvent(new MessageEvent("message", { data: { deadbolt: "passkey-port" }, source: window, ports: [channel.port2] }))
      return { acks, channel }
    }
    const seen: unknown[] = []
    const page = (e: MessageEvent) => seen.push(e.data)
    window.addEventListener("message", page)
    try {
      const first = offer()
      // A page offering its own port afterwards gets no ack.
      const second = offer()
      await Bun.sleep(5)
      expect(first.acks).toEqual([{ op: "ack" }])
      expect(second.acks).toEqual([])
      expect(seen).toEqual([{ deadbolt: "passkey-port" }])
      first.channel.port1.close()
      second.channel.port1.close()
    } finally {
      window.removeEventListener("message", page)
    }
  })
})
