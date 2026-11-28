import { beforeEach, describe, expect, test } from "bun:test"
import { Autofill } from "../src/bg/autofill"
import { AUTOMATIC_STEP_MS, AuthFlows, phaseOf, SESSION_GRACE_MS, SESSION_TTL_MS, transition, userNavigation, type AuthFlow, type FlowEvent, type FlowStart } from "../src/bg/flow"
import { ACCOUNTS, fakeHost, installChrome, menuSender, pageSender, SITE, type FakeChrome } from "./chrome"

const account = { ref: "r1", hasPassword: true, hasTotp: true }
const top = { origin: SITE, documentId: "doc-1" }
const T0 = 1_000_000

/** A pick's start, as a menu pick or the popup's Fill begins one. */
const start = (over: Partial<FlowStart> = {}): FlowStart => ({ ref: "r1", origin: SITE, filled: [], startedAt: T0, ...over })
const filled = (flow: AuthFlow | FlowStart | undefined, roles: AuthFlow["filled"], over: Partial<{ documentId: string; origin: string; now: number; navigates: boolean; ref: string }> = {}) =>
  transition(flow, { type: "filled", account: { ...account, ref: over.ref ?? "r1" }, site: "example.com", target: { origin: over.origin ?? SITE, documentId: over.documentId ?? "doc-1" }, filled: roles, now: over.now ?? T0, navigates: over.navigates ?? false })

describe("AuthFlow phases", () => {
  test("identifier, then secret, then mfa, then settled", () => {
    const entry: AuthFlow = { ...start(), site: "example.com", documentId: "doc-1", filledAt: T0, until: T0 + 20_000, automatic: true }
    expect(phaseOf(undefined)).toBe("idle")
    expect(phaseOf(entry)).toBe("identifier")
    const secret = filled(entry, ["email"])!
    expect(phaseOf(secret, account)).toBe("secret")
    const mfa = filled(secret, ["password"], { documentId: "doc-2", now: T0 + 5000 })!
    expect(phaseOf(mfa, account)).toBe("mfa")
    // The code was the last step: nothing more to fill, and the flow is over.
    expect(filled(mfa, ["otp"], { documentId: "doc-3" })).toBeUndefined()
    expect(phaseOf({ ...mfa, filled: ["email", "password", "otp"] })).toBe("settled")
  })

  test("a login without a code settles at its password; one without a password goes from its username to its code", () => {
    const noCode = { ...account, hasTotp: false }
    const s = filled(start(), ["email"])!
    expect(phaseOf(s, noCode)).toBe("secret")
    expect(transition(s, { type: "filled", account: noCode, site: "example.com", target: top, filled: ["password"], now: T0, navigates: false })).toBeUndefined()
    expect(phaseOf(s, { hasPassword: false, hasTotp: true })).toBe("mfa")
  })
})

describe("AuthFlow transitions", () => {
  test("each step carries the pick's start, origin and what it filled before", () => {
    const first = filled(start({ automatic: true, automaticSubmits: 1 }), ["email"])!
    expect(first).toMatchObject({ ref: "r1", site: "example.com", origin: SITE, documentId: "doc-1", filled: ["email"], startedAt: T0, until: T0 + SESSION_TTL_MS, automatic: true, automaticSubmits: 1 })
    const second = filled(first, ["password"], { documentId: "doc-2", origin: "https://login.example.com", now: T0 + 9000 })!
    expect(second).toMatchObject({ origin: SITE, documentId: "doc-2", filled: ["email", "password"], startedAt: T0, filledAt: T0 + 9000, until: T0 + SESSION_TTL_MS })
  })

  test("another login's fill never inherits an automatic flow's submits", () => {
    const auto = filled(start({ automatic: true, automaticSubmits: 2 }), ["email"])!
    expect(auto).toMatchObject({ automatic: true, automaticSubmits: 2 })
    const other = filled(auto, ["email"], { ref: "r2" })!
    expect(other.automatic).toBeUndefined()
    expect(other.automaticSubmits).toBeUndefined()
  })

  test("another login's fill starts afresh, from its own origin", () => {
    const first = filled(start(), ["email"])!
    const other = filled(first, ["email"], { ref: "r2", origin: "https://login.example.com", now: T0 + 1000 })!
    expect(other).toMatchObject({ ref: "r2", origin: "https://login.example.com", filled: ["email"], startedAt: T0 + 1000 })
  })

  test("a site whose steps come by navigation gets a grace period", () => {
    expect(filled(start(), ["email"], { navigates: true })!.until).toBe(T0 + SESSION_TTL_MS + SESSION_GRACE_MS)
  })

  test("a flow expires once its time is up", () => {
    const s = filled(start(), ["email"])!
    expect(transition(s, { type: "tick", now: s.until - 1 })).toBe(s)
    expect(transition(s, { type: "tick", now: s.until })).toBeUndefined()
  })

  test("Esc, a lock and a confirmed automatic sign-in end it", () => {
    const s = filled(start(), ["email"])!
    expect(transition(s, { type: "escape" })).toBeUndefined()
    expect(transition(s, { type: "lock" })).toBeUndefined()
    // A confirmed sign-in ends an automatic flow; one the user goes on with themselves keeps its next step.
    expect(transition(s, { type: "signed-in" })).toBe(s)
    expect(transition({ ...s, automatic: true }, { type: "signed-in" })).toBeUndefined()
  })

  test("navigation: the same site goes on, another site or the user's own navigation ends it", () => {
    const s = filled(start(), ["email"])!
    expect(transition(s, { type: "navigate", url: "https://login.example.com/password", transitionType: "link" })).toBe(s)
    expect(transition(s, { type: "navigate", url: "https://www.example.com/next", transitionType: "form_submit" })).toBe(s)
    expect(transition(s, { type: "navigate", url: "https://evil.test/login", transitionType: "link" })).toBeUndefined()
    expect(transition(s, { type: "navigate", url: "https://www.example.com/", transitionType: "typed" })).toBeUndefined()
    expect(transition(s, { type: "navigate", url: "https://www.example.com/", transitionType: "reload" })).toBeUndefined()
    expect(transition(s, { type: "navigate", url: "https://www.example.com/", transitionType: "link", transitionQualifiers: ["forward_back"] })).toBeUndefined()
    expect(transition(s, { type: "navigate", url: "not a url" })).toBeUndefined()
    expect(userNavigation({ transitionType: "auto_bookmark" })).toBe(true)
    expect(userNavigation({ transitionType: "link" })).toBe(false)
  })

  test("an automatic submit counts, shortens the wait for the next step, and lets a code follow a password", () => {
    const s = { ...filled(start({ automatic: true }), ["email", "password"])!, automaticSubmits: 1 }
    const now = T0 + 1000
    const next = transition(s, { type: "step-submitted", roles: ["email", "password"], now })!
    expect(next).toMatchObject({ automaticSubmits: 2, until: now + AUTOMATIC_STEP_MS, passwordSubmittedAt: now })
    expect(transition(s, { type: "step-submitted", roles: ["email"], now })!.passwordSubmittedAt).toBeUndefined()
  })

  test("the user's own submit of an automatic password step, in its document, lets its code step follow", () => {
    const s = { ...filled(start({ automatic: true }), ["email", "password"])! }
    expect(transition(s, { type: "user-submitted", documentId: "doc-1", at: T0 + 50 })!.passwordSubmittedAt).toBe(T0 + 50)
    expect(transition(s, { type: "user-submitted", documentId: "other", at: T0 + 50 })).toBe(s)
    const manual = filled(start(), ["email", "password"])!
    expect(transition(manual, { type: "user-submitted", documentId: "doc-1", at: T0 })).toBe(manual)
  })

  test("events other than a fill leave no flow out of nothing", () => {
    const events: FlowEvent[] = [{ type: "tick", now: T0 }, { type: "signed-in" }, { type: "navigate", url: SITE }, { type: "step-submitted", roles: [], now: T0 }, { type: "user-submitted", documentId: "d", at: T0 }]
    for (const event of events)
      expect(transition(undefined, event)).toBeUndefined()
  })
})

describe("AuthFlows, each tab's flow in session storage", () => {
  let fake: FakeChrome
  beforeEach(() => {
    fake = installChrome()
  })
  const live = (): AuthFlow => ({ ref: "r1", site: "example.com", origin: SITE, documentId: "d", filledAt: Date.now(), filled: ["email"], startedAt: Date.now(), until: Date.now() + 60_000 })

  test("a flow is kept per tab, and one that ran out is dropped when read", async () => {
    const flows = new AuthFlows()
    await flows.set(1, live())
    expect(Object.keys(fake.session)).toEqual(["session:1"])
    expect((await flows.get(1))?.ref).toBe("r1")
    expect(await flows.get(2)).toBeUndefined()
    ;(fake.session["session:1"] as AuthFlow).until = Date.now() - 1
    expect(await flows.get(1)).toBeUndefined()
    expect(fake.session).toEqual({})
  })

  test("its timer ends it when its time is up", async () => {
    const flows = new AuthFlows()
    await flows.set(1, { ...live(), until: Date.now() + 5 })
    await Bun.sleep(20)
    expect(fake.session).toEqual({})
  })

  test("cancel bumps the tab's generation, so work started before it arms nothing", async () => {
    const flows = new AuthFlows()
    await flows.set(1, live())
    const before = flows.generation(1)
    await flows.cancel(1)
    expect(flows.generation(1)).toBe(before + 1)
    expect(flows.generation(2)).toBe(0)
    expect(fake.session).toEqual({})
  })

  test("a lock changes every tab's generation, a tab with no flow stored yet included", async () => {
    const flows = new AuthFlows()
    const before = [flows.generation(1), flows.generation(42)]
    await flows.endAll()
    expect([flows.generation(1), flows.generation(42)].map((g, i) => g !== before[i])).toEqual([true, true])
  })

  test("a lock ends every tab's flow, ones a restarted worker never started included", async () => {
    const flows = new AuthFlows()
    await flows.set(1, live())
    fake.session["session:9"] = live()
    fake.session["unrelated"] = 1
    await flows.endAll()
    expect(fake.session).toEqual({ unrelated: 1 })
    // The tab's own end and the lock's, one each.
    expect(flows.generation(9)).toBe(2)
  })

  test("turning off Offer to sign in ends automatic flows only", async () => {
    const flows = new AuthFlows()
    await flows.set(1, { ...live(), automatic: true })
    await flows.set(2, live())
    await flows.endAutomatic()
    await flows.serial(1, async () => {})
    expect(Object.keys(fake.session)).toEqual(["session:2"])
  })

  test("work for a tab runs one piece at a time", async () => {
    const flows = new AuthFlows()
    const order: number[] = []
    await Promise.all([flows.serial(1, async () => { await Bun.sleep(5); order.push(1) }), flows.serial(1, async () => void order.push(2))])
    expect(order).toEqual([1, 2])
  })
})

describe("Autofill follows a flow across its steps", () => {
  let fake: FakeChrome
  let host: ReturnType<typeof fakeHost>
  let autofill: Autofill
  beforeEach(() => {
    fake = installChrome()
    host = fakeHost()
    autofill = new Autofill(host.host)
  })
  const fills = () => host.requests.filter((r) => r.type === "fill").map((r) => (r as { want: string[] }).want)
  /** The tab's top page, a new document at this URL. */
  const at = (url: string, documentId: string) => {
    fake.frames["1:0"] = { url, documentId, parentFrameId: -1 }
    return pageSender({ url, documentId, origin: new URL(url).origin })
  }
  async function pickIdentifier() {
    fake.fillAck = () => ({ filled: ["email"] })
    const { token } = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(token!, menuSender(), SITE)
    await autofill.menuPick(token!, ACCOUNTS[0].ref, menuSender())
    await autofill.submitted(pageSender())
  }

  test("identifier, then the password page, then the code page, from one pick", async () => {
    await pickIdentifier()
    expect(phaseOf(fake.session["session:1"] as AuthFlow, ACCOUNTS[0])).toBe("secret")
    fake.fillAck = () => ({ filled: ["password"] })
    await autofill.page(at("https://www.example.com/password", "pw-doc"), "login", ["password"], 2)
    expect(phaseOf(fake.session["session:1"] as AuthFlow, ACCOUNTS[0])).toBe("mfa")
    await autofill.submitted(at("https://www.example.com/password", "pw-doc"))
    fake.fillAck = () => ({ filled: ["otp"] })
    await autofill.page(at("https://www.example.com/code", "code-doc"), "mfa", ["otp"], 3)
    expect(fills()).toEqual([["username"], ["password"], ["totp"]])
    // The code was the last step: the flow settled, and nothing waits.
    expect(fake.session).toEqual({})
  })

  test("a lock between steps ends the flow: the next step fills nothing", async () => {
    await pickIdentifier()
    host.setStatus({ state: "locked" })
    host.setStatus({ state: "ready", version: "0" })
    for (let i = 0; i < 50 && fake.session["session:1"]; i++) await Bun.sleep(1)
    await autofill.page(at("https://www.example.com/password", "pw-doc"), "login", ["password"], 2)
    expect(fills()).toEqual([["username"]])
  })

  test("going to another site ends the flow, and coming back doesn't bring it back", async () => {
    await pickIdentifier()
    await autofill.navigated({ tabId: 1, frameId: 0, url: "https://evil.test/login", transitionType: "link" })
    expect(fake.session).toEqual({})
    await autofill.page(at("https://www.example.com/password", "pw-doc"), "login", ["password"], 2)
    expect(fills()).toEqual([["username"]])
  })

  test("locking while a pick's fill is on its way writes nothing, though no flow was stored yet", async () => {
    fake.fillAck = () => ({ filled: ["email"] })
    const { token } = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(token!, menuSender(), SITE)
    const release = host.holdFills()
    const picking = autofill.menuPick(token!, ACCOUNTS[0].ref, menuSender())
    for (let i = 0; i < 100 && !host.requests.some((r) => r.type === "fill"); i++) await Bun.sleep(1)
    expect(fake.session).toEqual({})
    host.setStatus({ state: "locked" })
    release()
    await picking
    expect(fake.delivered.filter((d) => d.message.type === "db:fill")).toHaveLength(0)
    expect(fake.session).toEqual({})
  })

  test("Esc while an automatic pick's fill is on its way: nothing is written or submitted", async () => {
    const account = { ...ACCOUNTS[0], urls: [SITE] }
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req) => (req.type === "list" ? { type: "list", site: "example.com", accounts: [account] } : send(req as never))) as typeof host.host.send
    autofill.signedOut = async () => true
    const release = host.holdFills()
    const target = { tabId: 1, frameId: 0, documentId: "top-doc", origin: SITE }
    const picking = autofill.startAutomatic(target, account, { form: 1, roles: ["email", "password"] })
    for (let i = 0; i < 100 && !host.requests.some((r) => r.type === "fill"); i++) await Bun.sleep(1)
    // The entry is stored before the fill, so Esc finds it.
    expect((fake.session["session:1"] as AuthFlow | undefined)?.automatic).toBe(true)
    const stopping = autofill.stopAutomatic(1)
    await Bun.sleep(1)
    release()
    expect((await picking).ok).toBe(false)
    await stopping
    expect(fake.delivered.filter((d) => d.message.type === "db:fill" || d.message.type === "db:signin-submit")).toHaveLength(0)
    expect(fake.session).toEqual({})
  })

  test("an automatic pick that fills nothing leaves no entry behind to fill a later form", async () => {
    const account = { ...ACCOUNTS[0], urls: [SITE] }
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req) => (req.type === "list" ? { type: "list", site: "example.com", accounts: [account] } : send(req as never))) as typeof host.host.send
    autofill.signedOut = async () => true
    fake.fillAck = () => ({ filled: [] })
    const target = { tabId: 1, frameId: 0, documentId: "top-doc", origin: SITE }
    expect((await autofill.startAutomatic(target, account, { form: 1, roles: ["email", "password"] })).ok).toBe(false)
    expect(fake.session).toEqual({})
  })

  test("a step that comes too late fills nothing", async () => {
    await pickIdentifier()
    ;(fake.session["session:1"] as AuthFlow).until = Date.now() - 1
    await autofill.page(at("https://www.example.com/password", "pw-doc"), "login", ["password"], 2)
    expect(fills()).toEqual([["username"]])
  })
})
