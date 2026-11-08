import { beforeEach, describe, expect, test } from "bun:test"
import { Learner } from "../src/bg/learn"
import { frameOf, IDLE_MS, keyName, LEARN_TTL_MS, lengthBand, MAX_CROSS_EVENTS, MAX_EVENTS, scrub, shapeOf, truthOf, usernameDigest, wordDigest, type LearnSession, type LearnStep } from "../src/learn"
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

  test("keys go by name, never by the character", () => {
    expect(["Enter", "Tab", "ArrowDown", "Backspace", "Shift", "a", "Z", "7", "@", " ", "é"].map(keyName)).toEqual(["Enter", "Tab", "ArrowDown", "Backspace", "Shift", "char", "char", "char", "char", "char", "char"])
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
  let commands: Array<(command: string, tab?: chrome.tabs.Tab) => void>
  /** What a save offer would badge under REC. */
  let under = ""

  beforeEach(() => {
    fake = installChrome()
    commands = []
    ;(globalThis.chrome as unknown as { commands: unknown }).commands = { onCommand: { addListener: (f: (typeof commands)[number]) => commands.push(f) } }
    h = fakeHost()
    lines = []
    under = ""
    const list = h.host.send.bind(h.host)
    ;(h.host as unknown as { capabilities: string[] }).capabilities = ["list", "fill", "check", "save", "passkeys", "learn", "learn-files"]
    ;(h.host as unknown as { send: unknown }).send = async (req: Request) => {
      if (req.type === "learn-read") {
        const text = lines.filter((l) => l.session === req.session).map((l) => `${JSON.stringify(l.line)}\n`).join("")
        return { type: "learn-text", text, next: null }
      }
      if (req.type === "learn-delete") {
        const found = lines.some((l) => l.session === req.session)
        lines = lines.filter((l) => l.session !== req.session)
        return { type: "learn-deleted", found }
      }
      if (req.type !== "learn") return list(req as never)
      lines.push(req)
      return { type: "learned" }
    }
    learner = new Learner(h.host, { badgeUnder: () => under })
  })

  /** The service worker stops: its timers and memory go, storage stays. */
  function kill(l: Learner) {
    const tabs = (l as unknown as { tabs: Map<number, { timer: ReturnType<typeof setTimeout>; idle: ReturnType<typeof setTimeout>; flushing?: ReturnType<typeof setTimeout> }> }).tabs
    for (const a of tabs.values()) {
      clearTimeout(a.timer)
      clearTimeout(a.idle)
      clearTimeout(a.flushing)
    }
    tabs.clear()
  }

  /** A frame of `tabId` loads its document: the recording it's told to join, or null. */
  async function joins(l: Learner, tabId = 1): Promise<LearnSession | null> {
    const before = fake.delivered.length
    await l.loaded({ tabId, frameId: 3, documentId: "frame-doc" })
    const d = fake.delivered.slice(before).find((x) => x.message.type === "db:learn")
    return d ? (d.message.session as LearnSession) : null
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
    expect(reply).toEqual({ ok: true })
    expect(await learner.status(1)).toMatchObject({ state: "on", host: "www.example.com", steps: 0 })
    expect(lines[0].line).toMatchObject({ event: "start", site: "example.com", origin: "https://www.example.com", path: "/login", savedLogins: 2 })
    const [session] = broadcast()
    expect(session?.id).toBe(lines[0].session)
    expect(session?.salt).toMatch(/^[0-9a-f]{32}$/)
    expect(session!.until - session!.startedAt).toBe(LEARN_TTL_MS)
    expect(LEARN_TTL_MS).toBe(10 * 60_000)
    // Sent to the whole tab, not one document.
    expect(fake.delivered.find((d) => d.message.type === "db:learn")?.options).toBeUndefined()
    expect(session?.words).toEqual([])
    // A frame that loads later is told; one of another tab isn't, and a frame never asks.
    expect(await joins(learner)).toEqual(session)
    expect(fake.delivered.at(-1)?.options).toEqual({ documentId: "frame-doc" })
    expect(await joins(learner, 2)).toBeNull()
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
    expect(lines.length).toBe(4)
    // A frame doesn't get to say the background's fields.
    await learner.step(pageSender({ frameId: 6, origin: "https://ads.other.net", url: "https://ads.other.net/x" }), id, { ...step({}), seq: 99, frameId: 0, sameSite: true } as LearnStep)
    expect(lines.at(-1)?.line).toMatchObject({ seq: 4, frameId: 6, sameSite: false })
  })

  test("a keypad's keys keep no digits, text or place, however a frame sends them", async () => {
    await learner.start(1)
    const { id } = broadcast()[0]!
    await learner.events(pageSender(), id, [
      { t: 1, type: "click", target: { tag: "button", text: "1", path: "div#pad > button" }, x: 10, y: 10 },
      { t: 2, type: "click", target: { tag: "button", label: "9", path: "div.key-9" }, x: 40, y: 10 },
      { t: 3, type: "click", target: { tag: "img", keypad: true, id: "k8", path: "div > img.d8" }, x: 70, y: 10 },
      { t: 4, type: "click", target: { tag: "button", text: "Pay 1984 now", id: "pay-4", path: "form > button" }, x: 9, y: 9 },
    ])
    await learner.stop(1, "stopped")
    const events = lines.filter((l) => (l.line as { event: string }).event === "timeline").flatMap((l) => (l.line as { events: Array<Record<string, unknown>> }).events)
    expect(events.map((e) => e.target)).toEqual([
      { tag: "button", path: "div#pad > button", keypad: true },
      { tag: "button", path: "div.key-<n>", keypad: true },
      { tag: "img", id: "k<n>", path: "div > img.d<n>", keypad: true },
      { tag: "button", id: "pay-<n>", text: "Pay <n> now", path: "form > button" },
    ])
    expect(events.slice(0, 3).every((e) => e.x === undefined && e.y === undefined)).toBe(true)
    expect(JSON.stringify(lines)).not.toMatch(/1984|"[19]"/)
  })

  test("typed words scrub the addresses Chrome reports, and later pages are told them", async () => {
    await learner.start(1)
    const { id, salt } = broadcast()[0]!
    const typed = await wordDigest(salt, "Kittens")
    expect(await learner.events(pageSender(), id, [{ t: 1, type: "key", key: "Enter" }], [typed, "not-a-digest"])).toBe(true)
    learner.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/search/kittens?kittens=1&page=2", transitionType: "form_submit" })
    learner.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/reset/Zm9vYmFy0123/confirm", transitionType: "link" })
    expect((await joins(learner))?.words).toEqual([typed])
    await learner.stop(1, "stopped")
    const navs = lines.filter((l) => (l.line as { event: string }).event === "timeline").flatMap((l) => (l.line as { events: Array<{ type: string; frame?: { path: string; queryKeys: string[] } }> }).events.filter((e) => e.type === "navigate"))
    expect(navs.map((e) => e.frame)).toEqual([
      expect.objectContaining({ path: "/search/<typed>", queryKeys: ["<typed>", "page"] }),
      expect.objectContaining({ path: "/reset/<seg>/confirm", queryKeys: [] }),
    ])
    expect(JSON.stringify(lines).toLowerCase()).not.toContain("kittens")
    // Paths are decoded first: an encoded word is still the word.
    expect((await frameOf(new URL("https://x.test/search/%6Bittens/caf%C3%A9-list"), true, 0, [], { salt, digests: new Set([typed]) })).path).toBe("/search/<typed>/<seg>")
  })

  test("a page taken to another site by hand ends the recording; a provider's redirect doesn't", async () => {
    await learner.start(1)
    learner.navigated({ tabId: 1, frameId: 0, url: "https://accounts.google.com/o/oauth2/auth", transitionType: "link", transitionQualifiers: ["server_redirect"] })
    learner.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/callback", transitionType: "link", transitionQualifiers: ["client_redirect"] })
    learner.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/home", transitionType: "typed" })
    expect(await learner.status(1)).toMatchObject({ state: "on" })
    learner.navigated({ tabId: 1, frameId: 0, url: "https://news.other.net/", transitionType: "typed", transitionQualifiers: ["from_address_bar"] })
    await new Promise((r) => setTimeout(r, 10))
    expect(await learner.status(1)).toMatchObject({ state: "done" })
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", reason: "left" })
    expect(fake.badges[1]).toBe("")
  })

  test("two minutes without input end a recording", async () => {
    expect(IDLE_MS).toBe(2 * 60_000)
    await learner.start(1)
    const key = Object.keys(fake.session)[0]
    ;(fake.session[key] as { lastInput: number }).lastInput = Date.now() - IDLE_MS - 1
    kill(learner)
    const again = new Learner(h.host)
    await again.status(1)
    await new Promise((r) => setTimeout(r, 20))
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", reason: "idle" })
    expect(await again.status(1)).toMatchObject({ state: "done" })
  })

  test("a full cross-site frame is told so, and the page's frames go on", async () => {
    await learner.start(1)
    const { id } = broadcast()[0]!
    const ad = pageSender({ frameId: 9, origin: "https://ads.other.net", url: "https://ads.other.net/x" })
    const burst = () => Array.from({ length: 200 }, (_, t) => ({ t, type: "scroll", x: 0, y: t }))
    const answers = [await learner.events(ad, id, burst()), await learner.events(ad, id, burst()), await learner.events(ad, id, burst())]
    expect(answers).toEqual([true, true, "full"])
    expect(await learner.events(pageSender(), id, [{ t: 1, type: "click" }])).toBe(true)
    for (let i = 0; i < 25; i++) await learner.step(ad, id, step({}))
    expect(await learner.step(ad, id, step({}))).toBe("full")
    expect(await learner.step(pageSender(), id, step({}))).toBe(true)
    expect(await learner.status(1)).toMatchObject({ state: "on", steps: MAX_CROSS_EVENTS + 1 })
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
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", reason: "stopped", steps: 0, events: 0 })
    expect(broadcast().at(-1)).toBeNull()
    expect(await learner.status(1)).toEqual({ state: "done", host: "www.example.com", session: lines[0].session, steps: 0 })
    expect(await joins(learner)).toBeNull()
    expect(Object.keys(fake.session)).toEqual(["learned:1"])
  })

  test("the toolbar button says REC while the tab records, and what was under it after", async () => {
    await learner.start(1)
    expect(fake.badges[1]).toBe("REC")
    // An offer while recording leaves REC up; one still waiting shows once it stops.
    learner.badge(1, "1")
    expect(fake.badges[1]).toBe("REC")
    under = "1"
    await learner.stop(1, "stopped")
    expect(fake.badges[1]).toBe("1")
  })

  test("the record shortcut starts and stops recording the tab it's pressed in", async () => {
    learner.listen()
    expect(commands.length).toBe(1)
    commands[0]("record", { id: 1, windowId: 7 } as chrome.tabs.Tab)
    await new Promise((r) => setTimeout(r, 50))
    expect(await learner.status(1)).toMatchObject({ state: "on" })
    expect(fake.badges[1]).toBe("REC")
    // Started by the shortcut, the popup opens: a cue even when the button isn't pinned.
    expect(fake.popups).toEqual([7])
    commands[0]("something-else", { id: 1 } as chrome.tabs.Tab)
    commands[0]("record", { id: 1 } as chrome.tabs.Tab)
    await new Promise((r) => setTimeout(r, 50))
    expect(await learner.status(1)).toMatchObject({ state: "done" })
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", reason: "stopped" })
    expect(fake.badges[1]).toBe("")
    expect(fake.popups).toEqual([7])
  })

  test("the timeline: frames' events, checked and bounded, then Chrome's navigations and popups, in batches", async () => {
    await learner.start(1)
    const { id } = broadcast()[0]!
    const button = { tag: "button", type: "submit", text: "Continue", path: "form#login > button", value: "kit@example.com" }
    expect(
      await learner.events(pageSender(), id, [
        { t: 10, type: "click", target: button, x: 120.4, y: 80, secret: "correct horse" },
        { t: 20, type: "key", key: "Enter", mods: "shift" },
        // A frame that says which character was typed isn't believed.
        { t: 30, type: "key", key: "q" },
        { t: 40, type: "input", target: { tag: "input", type: "password", path: "input#pw" }, shape: "secret", length: "9-16", inputType: "insertFromPaste" },
        { t: 50, type: "not-a-thing" },
      ]),
    ).toBe(true)
    learner.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/next?token=s3cr3t&step=2#frag", transitionType: "form_submit" })
    learner.opened({ sourceTabId: 1, sourceFrameId: 0, url: "https://accounts.google.com/o/oauth2?client_id=quietzone" })
    await learner.signedIn(1, "example.com")
    expect(await learner.events(pageSender({ tab: { id: 2 } as chrome.tabs.Tab }), id, [{ t: 1, type: "click" }])).toBe(false)
    await learner.stop(1, "stopped")
    const timeline = lines.filter((l) => (l.line as { event: string }).event === "timeline").flatMap((l) => (l.line as { events: Array<Record<string, unknown>> }).events)
    expect(timeline).toEqual([
      { t: 10, type: "click", target: { tag: "button", type: "submit", text: "Continue", path: "form#login > button" }, x: 120, y: 80, frameId: 0, sameSite: true },
      { t: 20, type: "key", key: "Enter", mods: "shift", frameId: 0, sameSite: true },
      { t: 30, type: "key", frameId: 0, sameSite: true },
      { t: 40, type: "input", target: { tag: "input", type: "password", path: "input#pw" }, shape: "secret", inputType: "insertFromPaste", frameId: 0, sameSite: true },
      expect.objectContaining({ type: "navigate", frameId: 0, transition: "form_submit", frame: { top: true, depth: 0, origin: "https://www.example.com", path: "/next", queryKeys: ["token", "step"] } }),
      expect.objectContaining({ type: "popup", frame: expect.objectContaining({ origin: "https://accounts.google.com", path: "/o/<seg>", queryKeys: ["client_id"] }) }),
      expect.objectContaining({ type: "signed-in" }),
    ])
    const all = JSON.stringify(lines)
    for (const never of ["kit@example.com", "correct horse", "s3cr3t", "quietzone", "frag"]) expect(all).not.toContain(never)
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", events: 7 })
  })

  test("a busy page can't grow the timeline past its cap", async () => {
    await learner.start(1)
    const { id } = broadcast()[0]!
    for (let i = 0; i < MAX_EVENTS / 200 + 2; i++) await learner.events(pageSender(), id, Array.from({ length: 200 }, (_, t) => ({ t, type: "scroll", x: 0, y: t })))
    await learner.stop(1, "stopped")
    const kept = lines.filter((l) => (l.line as { event: string }).event === "timeline")
    expect(kept.flatMap((l) => (l.line as { events: unknown[] }).events).length).toBe(MAX_EVENTS)
    for (const l of kept) expect(JSON.stringify(l.line).length).toBeLessThan(56 * 1024)
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", events: MAX_EVENTS, dropped: 400 })
  })

  test("a finished recording downloads as one log, or is deleted", async () => {
    await learner.start(1)
    const session = lines[0].session
    await learner.stop(1, "stopped")
    const got = await learner.recorded(1, "download")
    expect(got.ok).toBe(true)
    const rows = (got as { text: string }).text.trim().split("\n").map((l) => JSON.parse(l))
    expect(rows.map((r) => [r.session, r.event])).toEqual([
      [session, "start"],
      [session, "end"],
    ])
    expect(await learner.recorded(1, "delete")).toEqual({ ok: true })
    expect(lines.length).toBe(0)
    expect(await learner.status(1)).toEqual({ state: "off" })
    expect(fake.session).toEqual({})
  })

  test("starting again replaces the session", async () => {
    await learner.start(1)
    const first = broadcast()[0]!.id
    await learner.start(1)
    expect(lines.map((l) => (l.line as { event: string }).event)).toEqual(["start", "end", "start"])
    expect(lines[1].line).toMatchObject({ reason: "replaced" })
    expect((await joins(learner))?.id).not.toBe(first)
  })

  test("a service worker that restarts picks the session up where it was", async () => {
    await learner.start(1)
    const { id, salt } = broadcast()[0]!
    await learner.step(pageSender(), id, step({}))
    kill(learner)
    const again = new Learner(h.host)
    expect(await joins(again)).toEqual({ id, salt, startedAt: expect.any(Number), until: expect.any(Number), words: [] })
    expect(await again.status(1)).toMatchObject({ state: "on", host: "www.example.com" })
    const saved = await usernameDigest(salt, "admin")
    expect(await again.step(pageSender(), id, step({ order: 1, shape: "text", length: "4-8", digest: saved, truth: "username" }))).toBe(true)
    const last = lines.at(-1)!.line as { seq: number; inputs: Array<{ typed: Record<string, unknown> }> }
    expect(last.seq).toBe(2)
    expect(last.inputs[0].typed).toMatchObject({ savedUsername: true, truth: "username" })
    // A sign-in that worked is a mark on the timeline; recording goes on.
    await again.signedIn(1, "example.com")
    expect(await again.status(1)).toMatchObject({ state: "on" })
    await again.stop(1, "stopped")
    expect(lines.at(-2)?.line).toMatchObject({ event: "timeline", events: [expect.objectContaining({ type: "signed-in" })] })
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", reason: "stopped", steps: 2 })
  })

  test("the time cap ends a recording", async () => {
    await learner.start(1)
    const key = Object.keys(fake.session)[0]
    ;(fake.session[key] as { until: number }).until = Date.now() + 50
    kill(learner)
    const again = new Learner(h.host)
    expect(await joins(again)).not.toBeNull()
    await new Promise((r) => setTimeout(r, 120))
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", reason: "timeout" })
    expect(broadcast().at(-1)).toBeNull()
    expect(fake.badges[1]).toBe("")
    expect(await again.status(1)).toMatchObject({ state: "done" })
  })

  test("a session that ran out while the service worker was gone ends when it comes back", async () => {
    await learner.start(1)
    const key = Object.keys(fake.session)[0]
    ;(fake.session[key] as { until: number }).until = Date.now() - 1
    kill(learner)
    const again = new Learner(h.host)
    expect(await joins(again)).toBeNull()
    await new Promise((r) => setTimeout(r, 10))
    expect(lines.at(-1)?.line).toMatchObject({ event: "end", reason: "timeout" })
    expect(await again.status(1)).toMatchObject({ state: "done" })
  })

  test("a host that can't log says so", async () => {
    ;(h.host as unknown as { capabilities: string[] }).capabilities = ["list", "fill"]
    const reply = await learner.start(1)
    expect(reply.ok).toBe(false)
    expect(lines.length).toBe(0)
  })

  test("records any web page, locked or not, but not the browser's own pages", async () => {
    // A plain-http page gets no logins, and Learn this site never showed there; Record does.
    fake.frames["1:0"] = { url: "http://intranet.example.com/login", documentId: "top-doc", parentFrameId: -1 }
    h.setStatus({ state: "locked" })
    expect(await learner.status(1)).toEqual({ state: "off" })
    expect(await learner.start(1)).toEqual({ ok: true })
    expect(lines[0].line).toMatchObject({ event: "start", site: "example.com", origin: "http://intranet.example.com", savedLogins: 0 })
    await learner.stop(1, "stopped")
    for (const url of ["chrome://settings/", "https://chromewebstore.google.com/detail/x", "chrome-extension://abc/popup.html"]) {
      fake.frames["2:0"] = { url, documentId: "other", parentFrameId: -1 }
      expect(await learner.status(2)).toMatchObject({ state: "blocked" })
      expect((await learner.start(2)).ok).toBe(false)
    }
  })
})
