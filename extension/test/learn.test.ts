import { beforeEach, describe, expect, test } from "bun:test"
import { Learner } from "../src/bg/learn"
import { lengthBand, scrub, shapeOf, truthOf, usernameDigest, type LearnSession, type LearnStep } from "../src/learn"
import type { RequestBody as Request } from "../src/protocol"
import { fakeHost, installChrome, pageSender, type FakeChrome } from "./chrome"

describe("what a typed value shows", () => {
  test("shapes", () => {
    expect(shapeOf("anything", "password")).toBe("secret")
    expect(shapeOf(" kit@example.com ", "text")).toBe("email")
    expect(shapeOf("492039", "text")).toBe("digits")
    expect(shapeOf("+1 (555) 010-2030", "tel")).toBe("phone")
    expect(shapeOf("5550102030", "text")).toBe("phone")
    expect(shapeOf("octocat", "text")).toBe("text")
  })

  test("truth", () => {
    expect(truthOf({ shape: "secret" })).toBe("password")
    expect(truthOf({ shape: "digits" })).toBe("otp")
    expect(truthOf({ shape: "digits", savedUsername: true })).toBe("username")
    expect(truthOf({ shape: "text" })).toBe("username")
    expect(truthOf({ shape: "email" })).toBe("email")
  })

  test("length bands", () => {
    expect(["ab", "abcd", "a".repeat(9), "a".repeat(17), "a".repeat(40)].map(lengthBand)).toEqual(["1-3", "4-8", "9-16", "17-32", "33+"])
  })

  test("page text loses what may be the user's", () => {
    expect(scrub("Welcome back, Octocat (kit@example.com), card 4242", ["octocat"])).toBe("Welcome back, <typed> (<email>), card <n>")
    expect(scrub("Enter the code sent to ••••1234")).toBe("Enter the code sent to ••••<n>")
    expect(scrub("a.b+c (1)", ["a.b+c"])).toBe("<typed> (1)")
  })
})

describe("Learner", () => {
  let fake: FakeChrome
  let lines: Array<Extract<Request, { type: "learn" }>>
  let learner: Learner
  let h: ReturnType<typeof fakeHost>

  beforeEach(() => {
    fake = installChrome()
    h = fakeHost()
    lines = []
    const list = h.host.send.bind(h.host)
    ;(h.host as unknown as { capabilities: string[] }).capabilities = ["list", "fill", "check", "save", "passkeys", "learn"]
    ;(h.host as unknown as { send: unknown }).send = async (req: Request) => {
      if (req.type !== "learn") return list(req as never)
      lines.push(req)
      return { type: "learned" }
    }
    learner = new Learner(h.host)
  })

  /** The service worker stops: its timers and memory go, storage stays. */
  function kill(l: Learner) {
    const tabs = (l as unknown as { tabs: Map<number, { timer: ReturnType<typeof setTimeout>; ending?: ReturnType<typeof setTimeout> }> }).tabs
    for (const a of tabs.values()) {
      clearTimeout(a.timer)
      clearTimeout(a.ending)
    }
    tabs.clear()
  }

  const broadcast = () => fake.delivered.filter((d) => d.message.type === "db:learn").map((d) => d.message.session as LearnSession | null)

  function step(typed: Record<string, unknown>, over: Partial<LearnStep> = {}): LearnStep {
    return {
      trigger: "submit",
      at: 1200,
      frame: { top: true, depth: 0, origin: "https://www.example.com", path: "/login", queryKeys: [] },
      title: "Sign in",
      kind: "login",
      submit: null,
      inputs: [
        { i: 0, type: "email", name: "email", id: "", autocomplete: "username", placeholder: "", ariaLabel: "", label: "Email", maxLength: 0, inputMode: "", visible: true, inShadow: false, inForm: true, formActionHost: "www.example.com", rect: { x: 0, y: 0, w: 240, h: 32 }, role: "email", typed: typed as never },
      ],
      shadowRoots: 0,
      iframes: [],
      ...over,
    }
  }

  test("starts in every frame of the tab and logs where", async () => {
    const reply = await learner.start(1)
    expect(reply).toMatchObject({ ok: true, learning: { site: "example.com", steps: 0 } })
    expect(lines[0].line).toMatchObject({ event: "start", site: "example.com", origin: "https://www.example.com", path: "/login", savedLogins: 2 })
    const [session] = broadcast()
    expect(session?.id).toBe(lines[0].session)
    expect(session?.salt).toMatch(/^[0-9a-f]{32}$/)
    // Sent to the whole tab, not one document.
    expect(fake.delivered.find((d) => d.message.type === "db:learn")?.options).toBeUndefined()
    expect(await learner.ask(pageSender({ frameId: 3, documentId: "frame-doc" }))).toEqual(session)
    expect(await learner.ask(pageSender({ tab: { id: 2 } as chrome.tabs.Tab }))).toBeNull()
  })

  test("a step says whether the typed value was a saved username, then drops the digest", async () => {
    await learner.start(1)
    const { id, salt } = broadcast()[0]!
    const saved = await usernameDigest(salt, "Kit@Example.com")
    expect(await learner.step(pageSender(), id, step({ order: 1, shape: "email", length: "9-16", digest: saved, truth: "email" }))).toBe(true)
    expect(await learner.step(pageSender({ frameId: 4, origin: "https://login.other.net", url: "https://login.other.net/" }), id, step({ order: 1, shape: "email", length: "9-16", digest: "0".repeat(64), truth: "email" }, { frame: { top: false, depth: 1, origin: "https://login.other.net", path: "/", queryKeys: [] } }))).toBe(true)
    // A frame on another site that says it's on the page's site isn't taken at its word.
    expect(await learner.step(pageSender({ frameId: 6, origin: "https://ads.other.net", url: "https://ads.other.net/x" }), id, step({}, { frame: { top: false, depth: 1, origin: "https://www.example.com", path: "/", queryKeys: [] } }))).toBe(true)
    const [, first, second, third] = lines.map((l) => l.line as { seq: number; frameId: number; sameSite: boolean; inputs: Array<{ typed: Record<string, unknown> }> })
    expect(first).toMatchObject({ event: "step", seq: 1, frameId: 0, sameSite: true })
    expect(first.inputs[0].typed).toEqual({ order: 1, shape: "email", length: "9-16", savedUsername: true, truth: "email" })
    expect(second).toMatchObject({ seq: 2, frameId: 4, sameSite: false })
    expect(second.inputs[0].typed.savedUsername).toBe(false)
    expect(third).toMatchObject({ seq: 3, frameId: 6, sameSite: false })
    expect((await learner.status(1))?.steps).toBe(3)
  })

  test("refuses steps of another session or tab", async () => {
    await learner.start(1)
    expect(await learner.step(pageSender(), "not-the-session", step({}))).toBe(false)
    expect(await learner.step(pageSender({ tab: { id: 2 } as chrome.tabs.Tab }), broadcast()[0]!.id, step({}))).toBe(false)
    expect(lines.length).toBe(1)
  })

  test("stopping logs the end and tells the frames", async () => {
    await learner.start(1)
    expect(await learner.stop(1, "stopped")).toEqual({ ok: true })
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", reason: "stopped", steps: 0 })
    expect(broadcast().at(-1)).toBeNull()
    expect(await learner.status(1)).toBeUndefined()
    expect(await learner.ask(pageSender())).toBeNull()
    expect(fake.session).toEqual({})
  })

  test("starting again replaces the session", async () => {
    await learner.start(1)
    const first = broadcast()[0]!.id
    await learner.start(1)
    expect(lines.map((l) => (l.line as { event: string }).event)).toEqual(["start", "end", "start"])
    expect(lines[1].line).toMatchObject({ reason: "replaced" })
    expect((await learner.ask(pageSender()))?.id).not.toBe(first)
  })

  test("a service worker that restarts picks the session up where it was", async () => {
    await learner.start(1)
    const { id, salt } = broadcast()[0]!
    await learner.step(pageSender(), id, step({}))
    await learner.signedIn(1, "example.com")
    kill(learner)
    const again = new Learner(h.host)
    expect(await again.ask(pageSender())).toEqual({ id, salt, until: expect.any(Number) })
    expect(await again.status(1)).toMatchObject({ site: "example.com", steps: 1 })
    const saved = await usernameDigest(salt, "admin")
    expect(await again.step(pageSender(), id, step({ order: 1, shape: "text", length: "4-8", digest: saved, truth: "username" }))).toBe(true)
    const last = lines.at(-1)!.line as { seq: number; inputs: Array<{ typed: Record<string, unknown> }> }
    expect(last.seq).toBe(2)
    expect(last.inputs[0].typed).toMatchObject({ savedUsername: true, truth: "username" })
    // The sign-in that worked still ends it.
    await new Promise((r) => setTimeout(r, 2600))
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", reason: "signed-in", steps: 2 })
    expect(fake.session).toEqual({})
  })

  test("a session that ran out while the service worker was gone ends when it comes back", async () => {
    await learner.start(1)
    const key = Object.keys(fake.session)[0]
    ;(fake.session[key] as { until: number }).until = Date.now() - 1
    kill(learner)
    const again = new Learner(h.host)
    expect(await again.ask(pageSender())).toBeNull()
    await new Promise((r) => setTimeout(r, 10))
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", reason: "timeout" })
    expect(await again.status(1)).toBeUndefined()
  })

  test("a host that can't log says so", async () => {
    ;(h.host as unknown as { capabilities: string[] }).capabilities = ["list", "fill"]
    const reply = await learner.start(1)
    expect(reply.ok).toBe(false)
    expect(lines.length).toBe(0)
  })

  test("only on pages that get logins", async () => {
    fake.frames["1:0"] = { url: "http://www.example.com/login", documentId: "top-doc", parentFrameId: -1 }
    expect((await learner.start(1)).ok).toBe(false)
  })
})
