import { beforeEach, describe, expect, test } from "bun:test"
import { Autofill, FLOWS_KEY, menuAccounts, menuRowCount, namedBy, nextStep, resizeMessage, sameHost, sessionStep, stepLabel, stepRoles } from "../src/bg/autofill"
import { HostError } from "../src/bg/backend"
import { SIGNIN_SETTING } from "../src/auth-state"
import { SignInWith } from "../src/bg/signinwith"
import { ACCOUNTS, fakeHost, installChrome, menuSender, pageSender, POPUP_URL, SITE, type FakeChrome, type FakeHost } from "./chrome"

let fake: FakeChrome
let host: FakeHost
let autofill: Autofill

beforeEach(() => {
  fake = installChrome()
  host = fakeHost()
  autofill = new Autofill(host.host)
})

const fills = () => host.requests.filter((r) => r.type === "fill")
const delivered = (type: string) => fake.delivered.filter((d) => d.message.type === type)

describe("opt-in automatic sign-in session", () => {
  const target = { tabId: 1, frameId: 0, documentId: "top-doc", origin: SITE }
  const account = { ...ACCOUNTS[0], urls: [SITE] }
  beforeEach(() => {
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req) => req.type === "list" ? { type: "list", site: "example.com", accounts: [account] } : send(req as never)) as typeof host.host.send
  })
  test("off by default, and ordinary picks never submit", async () => {
    expect((await autofill.startAutomatic(target, account, "action")).ok).toBe(false)
    const token = await menu()
    await autofill.menuLoad(token, menuSender(), SITE)
    await autofill.menuPick(token, ACCOUNTS[0].ref, menuSender())
    expect(delivered("db:signin-submit")).toHaveLength(0)
  })
  test("a permitted pick reuses the session and submits each step once", async () => {
    fake.local[SIGNIN_SETTING] = true
    fake.fillAck = () => ({ filled: ["email"] })
    expect((await autofill.startAutomatic(target, account, "action")).ok).toBe(true)
    await autofill.page(pageSender(), "login", ["email"], 1)
    expect(delivered("db:signin-submit")).toHaveLength(1)
    await autofill.page(pageSender(), "login", ["email"], 1)
    expect(delivered("db:signin-submit")).toHaveLength(1)
    fake.fillAck = () => ({ filled: ["password"] })
    await autofill.page(pageSender(), "login", ["password"], 2, true)
    expect(delivered("db:signin-submit")).toHaveLength(2)
  })
  test("does not arm a subframe or a sibling origin", async () => {
    fake.local[SIGNIN_SETTING] = true
    expect((await autofill.startAutomatic({ ...target, frameId: 2 }, account, "action")).ok).toBe(false)
    expect((await autofill.startAutomatic({ ...target, origin: "https://other.example.com" }, account, "action")).ok).toBe(false)
    expect(fills()).toHaveLength(0)
  })
  test.each([undefined, false, true])("fills a code but submits it only with a learned code flow (%s)", async (code) => {
    if (code !== undefined) {
      await autofill.page(pageSender(), "login", ["email", "password"], 1)
      if (code) await autofill.page(pageSender(), "mfa", ["otp"], 2)
      await autofill.learnFlow(1, "example.com")
    }
    fake.local[SIGNIN_SETTING] = true
    await autofill.startAutomatic(target, account, "action")
    await autofill.page(pageSender(), "login", ["email", "password"], 1)
    fake.fillAck = () => ({ filled: ["otp"] })
    await autofill.page(pageSender(), "mfa", ["otp"], 2, true)
    expect(fills().map((r) => (r as { want: string[] }).want)).toEqual([["username", "password"], ["totp"]])
    expect(delivered("db:signin-submit").map((d) => d.message.form)).toEqual(code === true ? [1, 2] : [1])
    expect(fake.session).toEqual({})
  })
  test("ends after four submit attempts even when the password step keeps taking only the identifier", async () => {
    fake.local[SIGNIN_SETTING] = true
    fake.fillAck = () => ({ filled: ["email"] })
    await autofill.startAutomatic(target, account, "action")
    await autofill.page(pageSender(), "login", ["email"], 1)
    for (let form = 2; form <= 4; form++) {
      await autofill.page(pageSender(), "login", ["email", "password"], form, true, true)
      expect(delivered("db:signin-submit")).toHaveLength(form)
    }
    expect(fake.session).toEqual({})
    const requests = host.requests.length
    await autofill.page(pageSender(), "login", ["email", "password"], 5, true, true)
    expect(delivered("db:signin-submit")).toHaveLength(4)
    expect(fills()).toHaveLength(4)
    expect(host.requests).toHaveLength(requests)
  })
  test.each([false, true])("only manual sessions may refill the identifier after filling the password (automatic: %s)", async (automatic) => {
    if (automatic) {
      fake.local[SIGNIN_SETTING] = true
      await autofill.startAutomatic(target, account, "action")
      await autofill.page(pageSender(), "login", ["email", "password"], 1)
    } else {
      const token = await menu()
      await autofill.menuLoad(token, menuSender(), SITE)
      await autofill.menuPick(token, account.ref, menuSender())
    }
    fake.fillAck = () => ({ filled: ["email"] })
    await autofill.page(pageSender(), "login", ["email", "password"], 2, true, true)
    expect(fills().map((r) => (r as { want: string[] }).want)).toEqual(automatic ? [["username", "password"]] : [["username", "password"], ["username"]])
    expect(delivered("db:signin-submit")).toHaveLength(automatic ? 1 : 0)
  })
  test("turning the setting off after a fill prevents its submit", async () => {
    fake.local[SIGNIN_SETTING] = true
    await autofill.startAutomatic(target, account, "action")
    fake.fillAck = () => {
      fake.local[SIGNIN_SETTING] = false
      return { filled: ["email"] }
    }
    await autofill.page(pageSender(), "login", ["email"], 1)
    expect(delivered("db:fill")).toHaveLength(1)
    expect(delivered("db:signin-submit")).toHaveLength(0)
    expect(fake.session).toEqual({})
  })
  test.each(["cancel", "setting-off"])("stopping while the learned code flow is being read prevents submitting (%s)", async (stop) => {
    await autofill.page(pageSender(), "login", ["email", "password"], 1)
    await autofill.page(pageSender(), "mfa", ["otp"], 2)
    await autofill.learnFlow(1, "example.com")
    fake.local[SIGNIN_SETTING] = true
    await autofill.startAutomatic(target, account, "action")
    await autofill.page(pageSender(), "login", ["email", "password"], 1)
    fake.fillAck = () => ({ filled: ["otp"] })
    const local = (globalThis as unknown as { chrome: { storage: { local: { get: (key: string) => Promise<unknown> } } } }).chrome.storage.local
    const get = local.get
    let reading = false
    let release = () => {}
    local.get = async (key) => {
      if (key === FLOWS_KEY) {
        reading = true
        await new Promise<void>((resolve) => (release = resolve))
      }
      return get(key)
    }
    const filling = autofill.page(pageSender(), "mfa", ["otp"], 2, true)
    await waitFor(() => reading)
    const stopped = stop === "cancel" ? autofill.navigated({ tabId: 1, frameId: 0, url: `${SITE}/login`, transitionType: "typed" }) : Promise.resolve()
    if (stop === "setting-off") fake.local[SIGNIN_SETTING] = false
    local.get = get
    release()
    await Promise.all([filling, stopped])
    expect(delivered("db:fill")).toHaveLength(2)
    expect(delivered("db:signin-submit")).toHaveLength(1)
    expect(fake.session).toEqual({})
  })
  test("turning the setting off while credentials are pending writes and submits nothing", async () => {
    fake.local[SIGNIN_SETTING] = true
    await autofill.startAutomatic(target, account, "action")
    const release = host.holdFills()
    const filling = autofill.page(pageSender(), "login", ["email"], 1)
    await waitFor(() => fills().length > 0)
    fake.local[SIGNIN_SETTING] = false
    release()
    await filling
    expect(delivered("db:fill")).toHaveLength(0)
    expect(delivered("db:signin-submit")).toHaveLength(0)
  })
  test("Escape cancels a pending automatic fill", async () => {
    fake.local[SIGNIN_SETTING] = true
    await autofill.startAutomatic(target, account, "action")
    const release = host.holdFills()
    const filling = autofill.page(pageSender(), "login", ["email"], 1)
    await waitFor(() => fills().length > 0)
    const stopped = autofill.stopAutomatic(1)
    await Bun.sleep(1)
    release()
    await Promise.all([filling, stopped])
    expect(delivered("db:fill")).toHaveLength(0)
    expect(delivered("db:signin-submit")).toHaveLength(0)
  })
  test("an entry expires promptly instead of authorizing a later form", async () => {
    fake.local[SIGNIN_SETTING] = true
    await autofill.startAutomatic(target, account, "action")
    const s = fake.session["session:1"] as { until: number; startedAt: number }
    expect(s.until - s.startedAt).toBe(20_000)
    s.until = Date.now() - 1
    await autofill.page(pageSender(), "login", ["email"], 1)
    expect(fills()).toHaveLength(0)
  })
  test("a lock ends a waiting entry, not pauses it until unlock", async () => {
    fake.local[SIGNIN_SETTING] = true
    await autofill.startAutomatic(target, account, "action")
    host.setStatus({ state: "locked" })
    await waitFor(() => !fake.session["session:1"])
    host.setStatus({ state: "ready", version: "0.0.0" })
    await autofill.page(pageSender(), "login", ["email"], 1)
    expect(fills()).toHaveLength(0)
  })
})

async function waitFor(ok: () => boolean) {
  for (let i = 0; i < 100 && !ok(); i++) await Bun.sleep(1)
  expect(ok()).toBe(true)
}

async function menu(form = 1): Promise<string> {
  const reply = await autofill.query(pageSender(), ["email", "password"], "email", form)
  expect(reply.token).toBeString()
  return reply.token!
}

describe("menu tokens", () => {
  test("the menu frame handed the token by the asking page can use it", async () => {
    const token = await menu()
    expect((await autofill.menuLoad(token, menuSender(), SITE))?.kind).toBe("accounts")
    expect(await autofill.menuPick(token, ACCOUNTS[0].ref, menuSender())).toEqual({ ok: true })
    expect(delivered("db:fill")[0].message).toEqual({ type: "db:fill", values: { username: "kit@example.com", password: "correct horse" }, form: 1, approval: "ok-1" })
  })

  test("once picked, a token only resizes its pill: no second pick, load or dismiss", async () => {
    const token = await menu()
    await autofill.menuLoad(token, menuSender(), SITE)
    expect(await autofill.menuPick(token, ACCOUNTS[0].ref, menuSender())).toEqual({ ok: true })
    // The pill says how the fill went at its own width.
    await autofill.menuResize(token, 32, menuSender(), 101, "pill")
    expect(delivered("db:resize-menu").at(-1)?.message).toEqual({ type: "db:resize-menu", token, height: 32, width: 101, mode: "pill" })
    expect(await autofill.menuPick(token, ACCOUNTS[0].ref, menuSender())).toEqual({ ok: false, message: "This menu has expired." })
    expect(await autofill.menuLoad(token, menuSender(), SITE)).toBeNull()
    expect(fills()).toHaveLength(1)
  })

  test("a token used from another tab, another origin's frame, or another extension page is refused", async () => {
    const token = await menu()
    expect(await autofill.menuLoad(token, menuSender({ tab: { id: 2 } as chrome.tabs.Tab }), SITE)).toBeNull()
    expect(await autofill.menuLoad(token, menuSender(), "https://ads.example.net")).toBeNull()
    expect(await autofill.menuLoad(token, menuSender({ url: POPUP_URL }), SITE)).toBeNull()
    expect(await autofill.menuLoad(token, menuSender({ documentId: undefined }), SITE)).toBeNull()
    // A content script can't pose as the menu.
    expect(await autofill.menuLoad(token, pageSender(), SITE)).toBeNull()
    expect(fills()).toEqual([])
  })

  test("nothing works with a token before the menu loads it", async () => {
    const token = await menu()
    expect(await autofill.menuPick(token, ACCOUNTS[0].ref, menuSender())).toEqual({ ok: false, message: "This menu has expired." })
    expect(fills()).toEqual([])
  })

  test("not once the asking document is gone", async () => {
    const token = await menu()
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "replaced-doc" }
    expect(await autofill.menuLoad(token, menuSender(), SITE)).toBeNull()
  })

  test("a token is bound to the first menu document that loads it", async () => {
    const token = await menu()
    expect(await autofill.menuLoad(token, menuSender(), SITE)).not.toBeNull()
    const second = menuSender({ frameId: 8, documentId: "second" })
    expect(await autofill.menuLoad(token, second, SITE)).toBeNull()
    expect(await autofill.menuPick(token, ACCOUNTS[0].ref, second)).toEqual({ ok: false, message: "This menu has expired." })
    expect(fills()).toEqual([])
  })

  test("navigating the frame revokes its tokens", async () => {
    const token = await menu()
    await autofill.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/next", transitionType: "link" })
    expect(await autofill.menuLoad(token, menuSender(), SITE)).toBeNull()
  })

  test("a form snapshot id is required", async () => {
    expect(await autofill.query(pageSender(), ["email"], "email", "x")).toEqual({ rows: 0 })
  })
})

describe("filling from the popup", () => {
  test("needs a login form the current document reported", async () => {
    expect(await autofill.popupFill(1, ACCOUNTS[0].ref)).toEqual({ ok: false, message: "No login form to fill on this page." })
    expect(fills()).toEqual([])
  })

  test("never for an opaque-origin page, which can't report one", async () => {
    await autofill.page(pageSender({ origin: "null" }), "login", ["email", "password"], 1)
    expect(await autofill.popupFill(1, ACCOUNTS[0].ref)).toEqual({ ok: false, message: "No login form to fill on this page." })
    expect(fills()).toEqual([])
  })

  test("fills the reported form, with its snapshot id", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")[0]).toMatchObject({ options: { documentId: "top-doc" }, message: { form: 4 } })
  })

  test("not after the reporting document went away", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "new-doc" }
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: false, message: "The page changed. Try again." })
    expect(delivered("db:fill")).toEqual([])
  })

  test("not when the user cancels while the host is answering", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    const release = host.holdFills()
    const fill = autofill.popupFill(1, ACCOUNTS[1].ref)
    await waitFor(() => fills().length === 1)
    autofill.forgetTab(1)
    release()
    expect((await fill).ok).toBe(false)
    expect(delivered("db:fill")).toEqual([])
  })
})

/**
 * A page can make a field fillable after the check, such as a disabled
 * password it enables once the username is focused. The content script fixes
 * which fields may be filled before the host is asked; only those are asked
 * for and written.
 */
describe("filling only the fields approved before the host is asked", () => {
  const approve = (roles: string[] | null) => {
    fake.answer = (message) => (message.type === "db:approve" ? roles && { approval: "fixed", roles } : true)
  }

  test("a menu pick asks only for what was approved, and names the approval", async () => {
    approve(["email"])
    const token = await menu()
    await autofill.menuLoad(token, menuSender(), SITE)
    fake.fillAck = () => ({ filled: ["email"] })
    expect(await autofill.menuPick(token, ACCOUNTS[1].ref, menuSender())).toEqual({ ok: true })
    expect(fills()).toMatchObject([{ want: ["username"] }])
    expect(delivered("db:approve")).toMatchObject([{ options: { documentId: "top-doc" }, message: { form: 1, measure: false } }])
    expect(delivered("db:fill")).toMatchObject([{ message: { values: { username: "kit@example.com" }, approval: "fixed" } }])
    expect(delivered("db:fill")[0].message).not.toHaveProperty("values.password")
  })

  test("so does the popup", async () => {
    approve(["password"])
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    fake.fillAck = () => ({ filled: ["password"] })
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(fills()).toMatchObject([{ want: ["password"] }])
    expect(delivered("db:fill")).toMatchObject([{ message: { values: { password: "correct horse" }, approval: "fixed" } }])
  })

  test("roles the form didn't report stay out, whatever the page approves", async () => {
    approve(["email", "password", "otp"])
    const reply = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(reply.token!, menuSender(), SITE)
    await autofill.menuPick(reply.token!, ACCOUNTS[1].ref, menuSender())
    expect(fills()).toMatchObject([{ want: ["username"] }])
  })

  test("nothing approved, or no answer: the host isn't asked", async () => {
    for (const answer of [null, { approval: "x", roles: [] }, { roles: ["email"] }, { approval: "x", roles: ["email"], boxes: "nope" }]) {
      fake.answer = (message) => (message.type === "db:approve" ? answer : true)
      const token = await menu()
      await autofill.menuLoad(token, menuSender(), SITE)
      expect(await autofill.menuPick(token, ACCOUNTS[1].ref, menuSender())).toEqual({ ok: false, message: "The page changed. Try again." })
    }
    expect(fills()).toEqual([])
    expect(delivered("db:fill")).toEqual([])
  })
})

describe("generated passwords", () => {
  const approve = () => (fake.answer = (message) => (message.type === "db:approve" ? { approval: "fixed", roles: ["email", "new-password"] } : true))
  const generating = async (kind: string, rules?: unknown) => {
    const reply = await autofill.query(pageSender(), ["email", "new-password"], "new-password", 1, false, undefined, false, kind, rules)
    if (reply.token) await autofill.menuLoad(reply.token, menuSender(), SITE)
    return reply
  }

  test("a new-password box offers one only on sign-up and change-password forms", async () => {
    for (const kind of ["login", "mfa", null, "bogus"]) expect(await generating(kind as string)).toEqual({ rows: 0 })
    for (const kind of ["signup", "change-password"]) expect(await generating(kind)).toMatchObject({ rows: 1 })
    const reply = await autofill.query(pageSender(), ["email", "new-password"], "new-password", 1, false, undefined, false, "signup")
    expect(await autofill.menuLoad(reply.token!, menuSender(), SITE)).toEqual({ kind: "generate", site: "www.example.com" })
    expect(host.requests.filter((r) => r.type !== "generate-check")).toEqual([])
  })

  test("no row when the page's rules allow only weak passwords, locked or not", async () => {
    expect(await generating("signup", { maxLength: 8, allowed: "0123456789" })).toEqual({ rows: 0 })
    expect(host.requests.at(-1)).toEqual({ type: "generate-check", origin: "https://www.example.com", maxLength: 8, allowed: "0123456789" })
    host.setStatus({ state: "locked" })
    expect(await generating("signup", { maxLength: 8 })).toEqual({ rows: 0 })
    expect(await generating("signup", { maxLength: 20 })).toMatchObject({ rows: 1 })
  })

  test("the host makes it within the page's rules, kept to the documented ones, and it fills every new-password box by id", async () => {
    approve()
    const { token } = await generating("signup", { rules: "minlength: 12;", maxLength: 16, minLength: -1, allowed: 7, extra: "x" })
    fake.fillAck = () => ({ filled: ["new-password"] })
    expect(await autofill.menuGenerate(token!, menuSender())).toEqual({ ok: true })
    expect(host.requests.filter((r) => r.type === "generate")).toEqual([{ type: "generate", origin: "https://www.example.com", rules: "minlength: 12;", maxLength: 16 }])
    expect(delivered("db:fill")).toMatchObject([{ message: { values: { newPassword: "generated 1" }, approval: "fixed", generated: "g1" } }])
    // In the page, so the agent holds it as pending, and then the page names it by id.
    expect(host.requests.at(-1)).toEqual({ type: "generate-keep", origin: "https://www.example.com", generated: "g1" })
    expect(delivered("db:generated")).toMatchObject([{ message: { type: "db:generated", generated: "g1" } }])
    expect(await autofill.menuGenerate(token!, menuSender())).toMatchObject({ ok: false })
  })

  test("if the agent can't keep it, the page isn't told its id, so a submit sends it as typed", async () => {
    approve()
    const send = host.host.send.bind(host.host)
    for (const err of [new HostError("locked", "Locked."), new HostError("not_found", "Gone."), new Error("Disconnected.")]) {
      fake.delivered.length = 0
      host.host.send = (async (req: { type: string }) => {
        if (req.type === "generate-keep") {
          host.requests.push(req as never)
          throw err
        }
        return send(req as never)
      }) as typeof host.host.send
      const { token } = await generating("signup")
      fake.fillAck = () => ({ filled: ["new-password"] })
      // It's in the page all the same.
      expect(await autofill.menuGenerate(token!, menuSender())).toEqual({ ok: true })
      expect(host.requests.at(-1)).toMatchObject({ type: "generate-keep" })
      expect(delivered("db:fill")).toHaveLength(1)
      expect(delivered("db:generated")).toEqual([])
    }
  })

  test("one that doesn't go into the page is dropped, never kept, and not tried again", async () => {
    approve()
    const outcomes: Array<[() => unknown, string]> = [
      [() => ({ filled: [], rejected: true }), "No password fits this site's rules."],
      [() => ({ filled: [] }), "The page changed. Try again."],
      [() => ({ filled: ["email"] }), "The page changed. Try again."],
    ]
    for (const [ack, message] of outcomes) {
      host.requests.length = 0
      const { token } = await generating("signup")
      fake.fillAck = ack as typeof fake.fillAck
      expect(await autofill.menuGenerate(token!, menuSender())).toEqual({ ok: false, message })
      const made = host.requests.filter((r) => r.type === "generate")
      expect(made).toHaveLength(1)
      expect(host.requests.filter((r) => r.type === "generate-keep")).toEqual([])
      expect(host.requests.at(-1)).toEqual({ type: "generate-drop", origin: "https://www.example.com", generated: `g${made.length}` })
    }
  })

  test("so is one made while the user left", async () => {
    approve()
    const { token } = await generating("signup")
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req: { type: string }) => {
      const reply = await send(req as never)
      if (req.type === "generate") await autofill.navigated({ tabId: 1, frameId: 0, url: "https://elsewhere.net/", transitionType: "typed" })
      return reply
    }) as typeof host.host.send
    expect(await autofill.menuGenerate(token!, menuSender())).toEqual({ ok: false, message: "" })
    expect(delivered("db:fill")).toEqual([])
    expect(host.requests.at(-1)).toMatchObject({ type: "generate-drop" })
  })

  test("an account menu's token can't generate, a generator's can't pick, and nothing generates without an approved new-password box", async () => {
    const token = await menu()
    await autofill.menuLoad(token, menuSender(), SITE)
    expect(await autofill.menuGenerate(token, menuSender())).toMatchObject({ ok: false })
    fake.answer = (message) => (message.type === "db:approve" ? { approval: "fixed", roles: ["email"] } : true)
    const reply = await generating("signup")
    expect(await autofill.menuGenerate(reply.token!, menuSender())).toEqual({ ok: false, message: "The page changed. Try again." })
    expect(host.requests.filter((r) => r.type === "generate")).toEqual([])
    // Nor can a generated-password menu's token pick an account.
    const generator = await generating("signup")
    expect(await autofill.menuPick(generator.token!, ACCOUNTS[0].ref, menuSender())).toEqual({ ok: false, message: "This menu has expired." })
    expect(fills()).toEqual([])
  })
})

/**
 * The popup fills a frame's form only when it and every frame above it say
 * it shows. A login field in a frame gets the inline menu, in the top page,
 * only when every frame up to the top page is on its site.
 */
describe("filling a frame's form", () => {
  const NOT_SHOWN = { ok: false, message: "That login form isn't fully visible. Nothing was filled." }
  const BOX = { left: 10, top: 20, right: 210, bottom: 50 }
  const LOW = { left: 40, top: 300, right: 240, bottom: 330 }
  /** Content scripts by document: `${documentId} ${type}` to the answer, or a function of the message. */
  let scripts: Record<string, unknown>
  const asked = (documentId: string) => fake.delivered.filter((d) => (d.options as { documentId: string }).documentId === documentId).map((d) => d.message)

  beforeEach(async () => {
    // top-doc > mid-doc (frame 2) > frame-doc (frame 3), all on the site.
    fake.frames["1:2"] = { url: "https://www.example.com/shell", documentId: "mid-doc", parentFrameId: 0 }
    fake.frames["1:3"] = { url: "https://www.example.com/embed", documentId: "frame-doc", parentFrameId: 2 }
    scripts = {
      "frame-doc db:approve": { approval: "framed", roles: ["email", "password"], boxes: [BOX] },
      "frame-doc db:approved": { boxes: [BOX] },
      "frame-doc db:frame-announce": true,
      "mid-doc db:frame-child": { boxes: [LOW] },
      "mid-doc db:frame-announce": true,
      "top-doc db:frame-child": { boxes: [LOW] },
      // Nothing of Deadbolt's shows in the top page, or only the login pill it puts away.
      "top-doc db:hold": true,
    }
    fake.answer = (message, documentId) => {
      const key = `${documentId} ${message.type}`
      if (!(key in scripts)) throw new Error("no content script")
      const a = scripts[key]
      return typeof a === "function" ? a(message) : a
    }
    await autofill.page(pageSender({ frameId: 3, url: "https://www.example.com/embed", documentId: "frame-doc" }), "login", ["email", "password"], 2)
  })

  test("fills once the frame and every frame above it say it shows", async () => {
    // An email-first form: as in the top page, it arms the password step.
    fake.fillAck = () => ({ filled: ["email"] })
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "frame-doc" }, message: { form: 2 } }])
    // Each frame up is asked about the boxes the one below gave, through the element the one below names.
    const [mid] = asked("mid-doc").filter((m) => m.type === "db:frame-child")
    const [named] = asked("frame-doc").filter((m) => m.type === "db:frame-announce")
    expect(mid).toMatchObject({ boxes: [BOX], nonce: named.nonce })
    const [top] = asked("top-doc").filter((m) => m.type === "db:frame-child")
    const [midNamed] = asked("mid-doc").filter((m) => m.type === "db:frame-announce")
    expect(top).toMatchObject({ boxes: [LOW], nonce: midNamed.nonce })
    expect(top.nonce).not.toBe(mid.nonce)
    // Every frame up to the top page is on the site: the session goes on in the frame.
    expect(Object.keys(fake.session)).toEqual(["session:1"])
  })

  test("asks only for the fields that showed, and checks those same fields again", async () => {
    scripts["frame-doc db:approve"] = { approval: "framed", roles: ["email"], boxes: [BOX] }
    fake.fillAck = () => ({ filled: ["email"] })
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(fills()).toMatchObject([{ want: ["username"] }])
    expect(asked("frame-doc").filter((m) => m.type === "db:approve")).toEqual([{ type: "db:approve", form: 2, measure: true }])
    expect(asked("frame-doc").filter((m) => m.type === "db:approved")).toEqual([{ type: "db:approved", approval: "framed" }])
    expect(delivered("db:fill")).toMatchObject([{ message: { values: { username: "kit@example.com" }, approval: "framed" } }])
    expect(delivered("db:fill")[0].message).not.toHaveProperty("values.password")
  })

  test("not when the approved fields no longer all show once the values are in hand", async () => {
    scripts["frame-doc db:approved"] = null
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    expect(fills()).toHaveLength(1)
    expect(delivered("db:fill")).toEqual([])
  })

  test("not when the frame's own fields don't show, and the host isn't asked", async () => {
    scripts["frame-doc db:approve"] = null
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    expect(fills()).toEqual([])
  })

  test("not when any frame above says it doesn't show it", async () => {
    scripts["mid-doc db:frame-child"] = null
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    scripts["mid-doc db:frame-child"] = { boxes: [LOW] }
    scripts["top-doc db:frame-child"] = { boxes: [] }
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    expect(delivered("db:fill")).toEqual([])
  })

  test("not when a frame above can't answer", async () => {
    delete scripts["top-doc db:frame-child"]
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    scripts["top-doc db:frame-child"] = { boxes: [LOW] }
    // An about:blank or sandboxed frame in between runs no content script.
    delete scripts["mid-doc db:frame-child"]
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    scripts["mid-doc db:frame-child"] = { boxes: [LOW] }
    // Nor one whose child can't name the element it's in.
    delete scripts["frame-doc db:frame-announce"]
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    scripts["frame-doc db:frame-announce"] = true
    // Nor one the tab doesn't list.
    delete fake.frames["1:2"]
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual(NOT_SHOWN)
    expect(delivered("db:fill")).toEqual([])
  })

  test("checked again once the values are in hand", async () => {
    const release = host.holdFills()
    const fill = autofill.popupFill(1, ACCOUNTS[1].ref)
    await waitFor(() => fills().length === 1)
    scripts["top-doc db:frame-child"] = null
    release()
    expect(await fill).toEqual(NOT_SHOWN)
    expect(delivered("db:fill")).toEqual([])
  })

  test("not when more than one frame's form shows", async () => {
    fake.frames["1:4"] = { url: "https://www.example.com/other", documentId: "other-doc", parentFrameId: 0 }
    Object.assign(scripts, { "other-doc db:approve": { approval: "other", roles: ["password"], boxes: [BOX] }, "other-doc db:frame-announce": true })
    await autofill.page(pageSender({ frameId: 4, url: "https://www.example.com/other", documentId: "other-doc" }), "login", ["password"], 1)
    expect((await autofill.popupFill(1, ACCOUNTS[1].ref)).ok).toBe(false)
    // Only one of them showing is fine.
    scripts["other-doc db:approve"] = null
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "frame-doc" } }])
  })

  test("the top page's form wins, unchecked", async () => {
    scripts["top-doc db:approve"] = { approval: "top", roles: ["email", "password"] }
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "top-doc" }, message: { form: 4 } }])
    expect(fake.delivered.filter((d) => d.message.type.startsWith("db:frame-"))).toEqual([])
  })

  // A page can swap its form for a frame's without navigating.
  test("a top form that went away no longer wins", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    await autofill.page(pageSender(), null, [], 5)
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "frame-doc" } }])
  })

  test("the top page is asked for a fresh report before choosing", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    // Its form went a moment ago; its next scan hasn't said so yet.
    scripts["top-doc db:report"] = async () => (await autofill.page(pageSender(), null, [], 5), true)
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: true })
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "frame-doc" } }])
  })

  test("a frame whose form went away isn't one to fill", async () => {
    await autofill.page(pageSender({ frameId: 3, url: "https://www.example.com/embed", documentId: "frame-doc" }), null, [], 3)
    expect(await autofill.popupFill(1, ACCOUNTS[1].ref)).toEqual({ ok: false, message: "No login form to fill on this page." })
    expect(fake.delivered.filter((d) => d.message.type.startsWith("db:frame-") || d.message.type === "db:approve")).toEqual([])
  })

  const frameSender = () => pageSender({ frameId: 3, url: "https://www.example.com/embed", documentId: "frame-doc" })
  /** The menu for the frame's email field: opened in the top page, its token as the top page got it. */
  async function frameMenu(roles = ["email", "password"]): Promise<string | undefined> {
    Object.assign(scripts, { "top-doc db:open-at": true, "top-doc db:hold": true })
    const reply = await autofill.query(frameSender(), roles, "email", 2, true, undefined, false, "login", undefined, undefined, BOX)
    expect(reply.token).toBeUndefined()
    return delivered("db:open-at").at(-1)?.message.token as string | undefined
  }

  test("a same-site frame's field opens the menu in the top page, under where it shows there", async () => {
    const token = await frameMenu()
    expect(delivered("db:open-at")).toMatchObject([{ options: { documentId: "top-doc" }, message: { rows: 2, box: LOW } }])
    // The menu frame is the top page's child, handed the token by the top page.
    expect((await autofill.menuLoad(token!, menuSender(), SITE))?.kind).toBe("accounts")
    expect(await autofill.menuPick(token!, ACCOUNTS[1].ref, menuSender())).toEqual({ ok: true })
    // Only the frame fills, after its fields were checked through every frame above, with the top page's pill put away.
    expect(delivered("db:fill")).toMatchObject([{ options: { documentId: "frame-doc" }, message: { form: 2, approval: "framed" } }])
    // A same-site frame's fields get a top page's checks; each frame above reads the frame's own visibility.
    expect(asked("frame-doc").filter((m) => m.type === "db:approve")).toEqual([{ type: "db:approve", form: 2, measure: true, sameSite: true }])
    expect(asked("frame-doc").filter((m) => m.type === "db:approved")).toEqual([{ type: "db:approved", approval: "framed", sameSite: true }])
    const checks = delivered("db:frame-child").map((d) => d.message)
    // The menu's opening (no reading), then the pick's two checks (with one).
    expect(checks.map((m) => m.track === true)).toEqual([false, false, true, true, true, true])
    // Every frame up is asked to refuse a sandboxed frame element.
    expect(checks.every((m) => m.unsandboxed === true)).toBe(true)
    expect(delivered("db:hold").map((d) => d.message.hold)).toEqual([true, false, true, false])
    expect(fills()).toMatchObject([{ origin: SITE, want: ["username", "password"] }])
  })

  test("not when the frame's field doesn't show, or doesn't say where", async () => {
    Object.assign(scripts, { "top-doc db:open-at": true })
    expect(await autofill.query(frameSender(), ["email", "password"], "email", 2)).toEqual({ rows: 0 })
    scripts["top-doc db:frame-child"] = null
    expect(await autofill.query(frameSender(), ["email", "password"], "email", 2, true, undefined, false, "login", undefined, undefined, BOX)).toEqual({ rows: 0 })
    expect(delivered("db:open-at")).toEqual([])
  })

  test("not a sandboxed frame: one with an opaque origin, or one a frame above says is sandboxed", async () => {
    Object.assign(scripts, { "top-doc db:open-at": true })
    const opaque = pageSender({ frameId: 3, url: "https://www.example.com/embed", origin: "null", documentId: "frame-doc" })
    expect(await autofill.query(opaque, ["email", "password"], "email", 2, true, undefined, false, "login", undefined, undefined, BOX)).toEqual({ rows: 0 })
    // The middle frame's content script finds the frame element sandboxed: no boxes.
    scripts["mid-doc db:frame-child"] = (m: { unsandboxed?: boolean }) => (m.unsandboxed ? null : { boxes: [LOW] })
    expect(await frameMenu()).toBeUndefined()
    expect(delivered("db:open-at")).toEqual([])
  })

  test("not under a cross-site frame, even when the frame is on the top page's site", async () => {
    fake.frames["1:2"] = { url: "https://ads.example.net/shell", documentId: "mid-doc", parentFrameId: 0 }
    expect(await frameMenu()).toBeUndefined()
    expect(fake.delivered.filter((d) => d.message.type.startsWith("db:frame-"))).toEqual([])
  })

  test("typing, clicking elsewhere or esc in the frame closes its menu in the top page", async () => {
    const token = await frameMenu()
    // From another frame, nothing.
    await autofill.menuAway(pageSender({ frameId: 2, url: "https://www.example.com/shell", documentId: "mid-doc" }), false)
    expect(delivered("db:close-menu")).toEqual([])
    await autofill.menuAway(frameSender(), false)
    expect(delivered("db:close-menu")).toMatchObject([{ options: { documentId: "top-doc" }, message: { token } }])
    expect(await autofill.menuLoad(token!, menuSender(), SITE)).toBeNull()
  })

  test("a pick that no longer shows through every frame above fills nothing", async () => {
    const token = await frameMenu()
    await autofill.menuLoad(token!, menuSender(), SITE)
    scripts["mid-doc db:frame-child"] = null
    expect(await autofill.menuPick(token!, ACCOUNTS[1].ref, menuSender())).toEqual(NOT_SHOWN)
    expect(fills()).toEqual([])
  })

  test("the next step in the same frame fills from the login picked, with its pill in the top page", async () => {
    fake.fillAck = () => ({ filled: ["email"] })
    const token = await frameMenu(["email"])
    await autofill.menuLoad(token!, menuSender(), SITE)
    expect(await autofill.menuPick(token!, ACCOUNTS[1].ref, menuSender())).toEqual({ ok: true })
    expect(Object.keys(fake.session)).toEqual(["session:1"])
    // The user clicks Continue in the frame, and its password box shows.
    fake.fillAck = () => ({ filled: ["password"], box: BOX })
    await autofill.submitted(frameSender())
    // Its password box is still collapsed (Apple's opens it in place): not the step yet, and not used up.
    scripts["frame-doc db:approve"] = { approval: "framed", roles: ["email"], boxes: [BOX] }
    await autofill.page(frameSender(), "login", ["email", "password"], 3, true)
    expect(fills()).toHaveLength(1)
    scripts["frame-doc db:approve"] = { approval: "framed", roles: ["email", "password"], boxes: [BOX, BOX] }
    await autofill.page(frameSender(), "login", ["email", "password"], 3, true)
    expect(fills().map((r) => (r as { want: string[] }).want)).toEqual([["username"], ["password"]])
    expect(delivered("db:fill").at(-1)).toMatchObject({ options: { documentId: "frame-doc" }, message: { form: 3 } })
    const pill = delivered("db:fill").at(-1)!.message.notice
    expect(delivered("db:open-at").at(-1)).toMatchObject({ options: { documentId: "top-doc" }, message: { token: pill, rows: 0, box: LOW, mode: "pill" } })
    // The pill frame is the top page's.
    expect(await autofill.menuLoad(String(pill), menuSender({ documentId: "pill-doc" }), SITE)).toEqual({ kind: "notice", label: "Password filled", title: ACCOUNTS[1].title })
  })

  test("esc in the frame after the pick doesn't end the sign-in: the password step still fills", async () => {
    fake.fillAck = () => ({ filled: ["email"] })
    const token = await frameMenu(["email"])
    await autofill.menuLoad(token!, menuSender(), SITE)
    expect(await autofill.menuPick(token!, ACCOUNTS[1].ref, menuSender())).toEqual({ ok: true })
    await autofill.menuAway(frameSender(), true)
    expect(Object.keys(fake.session)).toEqual(["session:1"])
    fake.fillAck = () => ({ filled: ["password"], box: BOX })
    await autofill.submitted(frameSender())
    await autofill.page(frameSender(), "login", ["email", "password"], 3, true)
    expect(fills().map((r) => (r as { want: string[] }).want)).toEqual([["username"], ["password"]])
    // Esc on a menu still open does end it, as in the top page.
    const open = await frameMenu()
    await autofill.menuAway(frameSender(), true)
    expect(fake.session).toEqual({})
    expect(await autofill.menuLoad(open!, menuSender(), SITE)).toBeNull()
  })

  test("only the login pill is put away to measure: with another surface showing, nothing is measured or filled", async () => {
    const token = await frameMenu()
    await autofill.menuLoad(token!, menuSender(), SITE)
    // The top page says something not ours (a card's pill) shows.
    scripts["top-doc db:hold"] = false
    expect(await autofill.menuPick(token!, ACCOUNTS[1].ref, menuSender())).toEqual(NOT_SHOWN)
    expect(asked("frame-doc").filter((m) => m.type === "db:approve")).toEqual([])
    expect(fills()).toEqual([])
    // It was asked to put away this pick's own pill, by its token.
    expect(delivered("db:hold")[0].message).toEqual({ type: "db:hold", token, hold: true })
  })

  test("the frame hears when the top page closes its menu", async () => {
    const token = await frameMenu()
    await autofill.menuClose(token!, false, pageSender())
    expect(delivered("db:menu-gone")).toMatchObject([{ options: { documentId: "frame-doc" } }])
  })

  test("a sign-in's shape is learned from one frame's steps, not the top page's and a frame's mixed", async () => {
    // The top page shows a username box of its own; the frame shows the sign-in.
    await autofill.page(pageSender(), "login", ["email"], 1)
    await autofill.page(frameSender(), "login", ["email", "password"], 2)
    await autofill.learnFlow(1, "example.com")
    expect(Object.values(fake.local[FLOWS_KEY] as Record<string, object>)).toMatchObject([{ identifierFirst: false, navigates: false }])
  })

  test("not when a frame above it is on another site", async () => {
    fake.fillAck = () => ({ filled: ["email"] })
    const token = await frameMenu(["email"])
    await autofill.menuLoad(token!, menuSender(), SITE)
    await autofill.menuPick(token!, ACCOUNTS[1].ref, menuSender())
    fake.frames["1:2"] = { url: "https://ads.example.net/shell", documentId: "mid-doc", parentFrameId: 0 }
    await autofill.page(frameSender(), "login", ["email", "password"], 3, true)
    expect(fills()).toHaveLength(1)
  })
})

describe("sign-in sessions", () => {
  const passwordPage = () => autofill.page(pageSender({ url: "https://www.example.com/password", documentId: "pw-doc" }), "login", ["password"], 1)
  const toPasswordPage = () => void (fake.frames["1:0"] = { url: "https://www.example.com/password", documentId: "pw-doc" })

  /** Holds the content script's answers to db:fill until released. */
  function holdFills(ack: string[]) {
    const held: Array<() => void> = []
    fake.fillAck = () => new Promise((resolve) => held.push(() => resolve({ filled: ack })))
    return held
  }

  beforeEach(() => {
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "top-doc" }
  })

  /** Picks a login on the email step, then the user submits it themselves. */
  async function fillEmail(ack: string[], account = ACCOUNTS[1]) {
    fake.fillAck = () => ({ filled: ack })
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    const reply = await autofill.menuPick(token.token!, account.ref, menuSender())
    await autofill.submitted(pageSender())
    return reply
  }

  test("nextStep follows what was actually filled", () => {
    expect(nextStep(["email"], { hasPassword: true, hasTotp: true })).toBe("password")
    expect(nextStep(["password"], { hasPassword: true, hasTotp: true })).toBe("otp")
    expect(nextStep(["password"], { hasPassword: true, hasTotp: false })).toBeUndefined()
    expect(nextStep([], { hasPassword: true, hasTotp: true })).toBeUndefined()
  })

  test("a new document isn't a step without the user's own submit in the last one", async () => {
    fake.fillAck = () => ({ filled: ["email"] })
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    await autofill.menuPick(token.token!, ACCOUNTS[1].ref, menuSender())
    toPasswordPage()
    await passwordPage()
    expect(fills()).toHaveLength(1)
    // A submit from some other document doesn't count either.
    await autofill.submitted(pageSender({ documentId: "elsewhere-doc" }))
    await passwordPage()
    expect(fills()).toHaveLength(1)
  })

  test("a fill the page didn't take arms nothing", async () => {
    expect(await fillEmail([])).toEqual({ ok: false, message: "The page changed. Try again." })
    expect(fake.session).toEqual({})
  })

  test("the next step fills once", async () => {
    await fillEmail(["email"])
    fake.frames["1:0"] = { url: "https://www.example.com/password", documentId: "pw-doc" }
    // The page doesn't take it this time.
    fake.fillAck = () => ({ filled: [] })
    await passwordPage()
    expect(fills().map((r) => (r as { want: string[] }).want)).toEqual([["username"], ["password"]])
    // Reporting the step again doesn't fill again; the session waits for the next step.
    await passwordPage()
    expect(fills()).toHaveLength(2)
    expect(Object.keys(fake.session)).toEqual(["session:1"])
  })

  test("a page without the next step doesn't use it up, another step's page doesn't fill", async () => {
    await fillEmail(["email"])
    fake.frames["1:0"] = { url: "https://www.example.com/mfa", documentId: "mfa-doc" }
    await autofill.page(pageSender({ url: "https://www.example.com/mfa", documentId: "mfa-doc" }), "mfa", ["otp"], 1)
    expect(fills()).toHaveLength(1)
    expect(Object.keys(fake.session)).toEqual(["session:1"])
  })

  test("typing an address, or going to another site, ends it; another origin of the site doesn't", async () => {
    await fillEmail(["email"])
    await autofill.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/password", transitionType: "typed" })
    expect(fake.session).toEqual({})
    await fillEmail(["email"])
    await autofill.navigated({ tabId: 1, frameId: 0, url: "https://accounts.example.com/password", transitionType: "form_submit" })
    expect(Object.keys(fake.session)).toEqual(["session:1"])
    await autofill.navigated({ tabId: 1, frameId: 0, url: "https://elsewhere.net/", transitionType: "form_submit" })
    expect(fake.session).toEqual({})
  })

  test("submitting to the next step on the same origin keeps it", async () => {
    await fillEmail(["email"])
    await autofill.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/password", transitionType: "form_submit" })
    expect(Object.keys(fake.session)).toEqual(["session:1"])
  })

  test("a matching form in the same document isn't a step until the user submits or the filled fields go", async () => {
    await fillEmail(["email"])
    // The page shows a password box next to the email box it just got.
    await autofill.page(pageSender(), "login", ["email", "password"], 2)
    expect(fills()).toHaveLength(1)
    expect(Object.keys(fake.session)).toEqual(["session:1"])
    await autofill.page(pageSender(), "login", ["password"], 3, true)
    expect(fills()).toHaveLength(2)
    expect(delivered("db:fill")[1]).toMatchObject({ options: { documentId: "top-doc" }, message: { form: 3 } })
  })

  test("two reports of the next step at once fill it once", async () => {
    await fillEmail(["email"])
    toPasswordPage()
    await Promise.all([passwordPage(), passwordPage(), passwordPage()])
    expect(fills()).toHaveLength(2)
  })

  test("a same-site frame's form is a step only if its fields show through every frame above", async () => {
    await fillEmail(["email"])
    fake.frames["1:3"] = { url: "https://www.example.com/embed", documentId: "frame-doc", parentFrameId: 0 }
    // fillEmail's submit in the top page, but the default content script measures no boxes: not shown to be visible.
    await autofill.page(pageSender({ frameId: 3, url: "https://www.example.com/embed", documentId: "frame-doc" }), "login", ["password"], 1, true)
    expect(fills()).toHaveLength(1)
    expect(fake.delivered.filter((d) => d.message.type === "db:approve").at(-1)).toMatchObject({ options: { documentId: "frame-doc" }, message: { measure: true } })
  })

  test("a pick cancelled while the host is answering fills nothing", async () => {
    const release = host.holdFills()
    const token = await autofill.query(pageSender(), ["email", "password"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    const pick = autofill.menuPick(token.token!, ACCOUNTS[1].ref, menuSender())
    await waitFor(() => fills().length === 1)
    // Esc in the field's next menu.
    const other = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuClose(other.token!, true, pageSender())
    release()
    expect((await pick).ok).toBe(false)
    expect(delivered("db:fill")).toEqual([])
    expect(fake.session).toEqual({})
  })

  test("a fill that finishes after the menu was dismissed arms nothing", async () => {
    const acks = holdFills(["email"])
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    const pick = autofill.menuPick(token.token!, ACCOUNTS[1].ref, menuSender())
    await waitFor(() => acks.length === 1)
    const other = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuClose(other.token!, true, pageSender())
    acks[0]()
    expect(await pick).toEqual({ ok: true })
    expect(fake.session).toEqual({})
  })

  test("a fill that finishes after the tab left the origin arms nothing", async () => {
    const acks = holdFills(["email"])
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    const pick = autofill.menuPick(token.token!, ACCOUNTS[1].ref, menuSender())
    await waitFor(() => acks.length === 1)
    fake.frames["1:0"] = { url: "https://elsewhere.net/", documentId: "other" }
    acks[0]()
    await pick
    expect(fake.session).toEqual({})
  })

  test("a step reported just before a cancel doesn't fill", async () => {
    await fillEmail(["email"])
    toPasswordPage()
    // Hold the report's read of the step, so the cancel lands while it's in progress.
    const session = (globalThis as unknown as { chrome: { storage: { session: { get: (key: string) => Promise<unknown> } } } }).chrome.storage.session
    const get = session.get
    let release = () => {}
    let reading = false
    session.get = async (key) => {
      reading = true
      await new Promise<void>((resolve) => (release = resolve))
      return get(key)
    }
    const report = passwordPage()
    await waitFor(() => reading)
    session.get = get
    const cancel = autofill.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/password", transitionType: "link", transitionQualifiers: ["forward_back"] })
    release()
    await Promise.all([report, cancel])
    expect(fills()).toHaveLength(1)
    expect(fake.session).toEqual({})
  })

  test("the next step's fill, cancelled while on its way, arms no further step", async () => {
    // kit@example.com has a code too, so the password step would arm the code step.
    await fillEmail(["email"], ACCOUNTS[0])
    toPasswordPage()
    const acks = holdFills(["password"])
    const report = passwordPage()
    await waitFor(() => acks.length === 1)
    const cancel = autofill.navigated({ tabId: 1, frameId: 0, url: "https://www.example.com/x", transitionType: "typed" })
    acks[0]()
    await Promise.all([report, cancel])
    expect(fills()).toHaveLength(2)
    expect(fake.session).toEqual({})
  })

  test("dismissing the menu cancels it", async () => {
    await fillEmail(["email"])
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuClose(token.token!, true, pageSender())
    expect(fake.session).toEqual({})
  })
})

describe("a sign-in session across steps", () => {
  const at = (url: string, documentId: string) => {
    fake.frames["1:0"] = { url, documentId }
    return pageSender({ url, origin: new URL(url).origin, documentId })
  }
  const notices = () => delivered("db:fill").map((d) => d.message.notice).filter(Boolean) as string[]
  async function pick(account = ACCOUNTS[0], ack = ["email"]) {
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "top-doc" }
    fake.fillAck = () => ({ filled: ack })
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    const reply = await autofill.menuPick(token.token!, account.ref, menuSender())
    await autofill.submitted(pageSender())
    return reply
  }
  /** The user submits the step in `documentId` themselves. */
  const submit = (url: string, documentId: string) => autofill.submitted(pageSender({ url, origin: new URL(url).origin, documentId }))
  /** The login, with these saved URLs. */
  function withUrls(urls: string[], account = ACCOUNTS[0]) {
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req: { type: string }) =>
      req.type === "list" ? { type: "list", site: "example.com", accounts: [{ ...account, urls }, ...ACCOUNTS.filter((a) => a !== account)] } : send(req as never)) as typeof host.host.send
  }

  test("step roles, labels and the username a form names", () => {
    expect(sameHost("https://accounts.example.com/login", "https://accounts.example.com")).toBe(true)
    expect(sameHost("accounts.example.com", "https://accounts.example.com")).toBe(true)
    expect(sameHost("https://example.com", "https://accounts.example.com")).toBe(false)
    expect(sameHost("http://accounts.example.com", "https://accounts.example.com")).toBe(false)
    const both = { hasPassword: true, hasTotp: true }
    expect(stepRoles(["email", "password"], both, false)).toEqual(["password"])
    expect(stepRoles(["email", "password"], both, true)).toEqual(["password", "email"])
    expect(stepRoles(["otp"], both, false)).toEqual(["otp"])
    expect(stepRoles(["otp"], { hasPassword: true, hasTotp: false }, false)).toEqual([])
    expect(stepRoles(["email"], both, true)).toEqual([])
    // A session fills sign-in steps only: a sign-up ends it, an unsure login fills nothing.
    expect(sessionStep("login", ["email", "password"], false)).toContain("password")
    expect(sessionStep("login", ["email", "password"], true)).toEqual([])
    expect(sessionStep("login", ["password", "new-password"], false)).toEqual([])
    expect(sessionStep("signup", ["email", "new-password"], false)).toBe("end")
    expect(sessionStep("change-password", ["password", "new-password"], false)).toBe("end")
    expect(sessionStep("mfa", ["otp"], false)).toEqual(["otp"])
    expect(sessionStep("reset", ["email"], false)).toEqual([])
    expect(stepLabel(["password"])).toBe("Password filled")
    expect(stepLabel(["otp"])).toBe("Code filled")
    expect(namedBy(ACCOUNTS, " ADMIN ").map((a) => a.ref)).toEqual([ACCOUNTS[1].ref])
    expect(namedBy(ACCOUNTS, "adm")).toEqual([])
  })

  test("email, then password on another origin a saved URL names, then the code: each step fills from the same login, with its pill", async () => {
    withUrls(["https://accounts.example.com/login"])
    await pick()
    fake.fillAck = () => ({ filled: ["password"] })
    await autofill.page(at("https://accounts.example.com/password", "pw-doc"), "login", ["password"], 1)
    await submit("https://accounts.example.com/password", "pw-doc")
    fake.fillAck = () => ({ filled: ["otp"] })
    await autofill.page(at("https://accounts.example.com/verify", "code-doc"), "mfa", ["otp"], 1)
    expect(fills().map((r) => [(r as { origin: string }).origin, (r as { want: string[] }).want])).toEqual([
      ["https://www.example.com", ["username"]],
      ["https://accounts.example.com", ["password"]],
      ["https://accounts.example.com", ["totp"]],
    ])
    // The two steps filled without a pick say so (the pick folded its own menu);
    // a pill whose page is gone gets nothing.
    expect(notices()).toHaveLength(2)
    expect(await autofill.menuLoad(notices()[0], menuSender({ documentId: "pill-1" }), "https://accounts.example.com")).toBeNull()
    // Done: nothing waits for another step.
    expect(fake.session).toEqual({})
  })

  test("a step's pill frame gets its label, and picks nothing", async () => {
    await pick()
    fake.fillAck = () => ({ filled: ["password"] })
    await autofill.page(at("https://www.example.com/password", "pw-doc"), "login", ["password"], 1)
    const token = notices()[0]
    const sender = menuSender({ documentId: "pill-doc" })
    expect(await autofill.menuLoad(token, sender, SITE)).toEqual({ kind: "notice", label: "Password filled", title: "Example" })
    expect(await autofill.menuPick(token, ACCOUNTS[0].ref, sender)).toEqual({ ok: false, message: "This menu has expired." })
  })

  test("an origin of the site the login doesn't match gets nothing, and the session waits", async () => {
    await pick()
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req: { type: string; origin?: string }) =>
      req.type === "list" && req.origin === "https://shop.example.com" ? { type: "list", site: "example.com", accounts: [] } : send(req as never)) as typeof host.host.send
    await autofill.page(at("https://shop.example.com/password", "shop-doc"), "login", ["password"], 1)
    expect(fills()).toHaveLength(1)
    expect(Object.keys(fake.session)).toEqual(["session:1"])
  })

  test("a sibling subdomain the agent lists the login for, but no saved URL names, gets nothing", async () => {
    // The agent lists a login on every subdomain of its site; the session holds to exact hosts.
    withUrls(["https://www.example.com/login"])
    await pick()
    await autofill.page(at("https://user-content.example.com/phish", "uc-doc"), "login", ["password"], 1)
    expect(fills()).toHaveLength(1)
  })

  test("the username asked again beside the password is filled too", async () => {
    await pick(ACCOUNTS[1])
    fake.fillAck = () => ({ filled: ["email", "password"] })
    await autofill.page(at("https://www.example.com/again", "again-doc"), "login", ["email", "password"], 1, false, true)
    expect((fills()[1] as { want: string[] }).want).toEqual(["username", "password"])
  })

  test("\"Use a different account\": an empty username step ends the session, whatever was filled", async () => {
    await pick()
    await autofill.page(at("https://www.example.com/login", "back-doc"), "login", ["email"], 1, false, true)
    expect(fake.session).toEqual({})
    await autofill.page(at("https://www.example.com/password", "pw-doc"), "login", ["password"], 1)
    expect(fills()).toHaveLength(1)
    // Picked on the password step: an empty username step after ends it too.
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "top-doc" }
    fake.fillAck = () => ({ filled: ["password"] })
    const token = await autofill.query(pageSender(), ["password"], "password", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    await autofill.menuPick(token.token!, ACCOUNTS[0].ref, menuSender())
    await autofill.submitted(pageSender())
    expect(Object.keys(fake.session)).toEqual(["session:1"])
    await autofill.page(at("https://www.example.com/login", "back-2"), "login", ["email"], 1, false, true)
    expect(fake.session).toEqual({})
  })

  test("locking ends sessions a restarted worker didn't start, from session storage", async () => {
    fake.session["session:7"] = { ref: ACCOUNTS[0].ref, site: "example.com", origin: SITE, documentId: "x", filledAt: Date.now(), filled: ["email"], startedAt: Date.now(), until: Date.now() + 60_000 }
    host.setStatus({ state: "locked" })
    await waitFor(() => !("session:7" in fake.session))
  })

  test("a session ends when Deadbolt locks, and when its time is up", async () => {
    await pick()
    host.setStatus({ state: "locked" })
    host.setStatus({ state: "ready", version: "0" })
    await waitFor(() => !("session:1" in fake.session))
    await pick()
    ;(fake.session["session:1"] as { until: number }).until = Date.now() - 1
    await autofill.page(at("https://www.example.com/password", "pw-doc"), "login", ["password"], 1)
    expect(fills()).toHaveLength(2)
  })

  test("a password field's menu narrows to the login the form's username names, or stays away", async () => {
    const ask = (identifier?: string, again = false) => autofill.query(pageSender(), ["email", "password"], "password", 1, true, identifier, again)
    const named = await ask("Admin")
    expect(named.rows).toBe(1)
    const reply = await autofill.menuLoad(named.token!, menuSender(), SITE)
    expect(reply?.kind === "accounts" && reply.accounts.map((a) => a.username)).toEqual(["admin"])
    expect(await autofill.menuPick(named.token!, ACCOUNTS[0].ref, menuSender())).toMatchObject({ ok: false })
    // A username no login has: no menu on focus, the full list on ↓.
    expect(await ask("nobody@example.com")).toEqual({ rows: 0 })
    expect((await ask("nobody@example.com", true)).rows).toBe(2)
    expect((await ask()).rows).toBe(2)
  })

  test("with no username box on the step, the one submitted before names the login", async () => {
    autofill = new Autofill(host.host, undefined, (tabId, site) => (tabId === 1 && site === "example.com" ? "admin" : undefined))
    expect((await autofill.query(pageSender(), ["password"], "password", 1)).rows).toBe(1)
  })

  test("a sign-in that worked teaches the site's shape; one login on an identifier-first site says Continue as", async () => {
    await autofill.page(at("https://www.example.com/login", "id-doc"), "login", ["email"], 1)
    await autofill.page(at("https://www.example.com/password", "pw-doc"), "login", ["password"], 2)
    await autofill.page(at("https://www.example.com/verify", "code-doc"), "mfa", ["otp"], 3)
    await autofill.learnFlow(1, "example.com")
    const flows = fake.local[FLOWS_KEY] as Record<string, object>
    expect(Object.values(flows)).toMatchObject([{ identifierFirst: true, code: true, navigates: true, seen: 1 }])
    // Kept under a salted hash of the site, with no usernames.
    expect(JSON.stringify(fake.local)).not.toContain("example.com")
    expect(JSON.stringify(fake.local)).not.toContain("@")
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req: { type: string }) => (req.type === "list" ? { type: "list", site: "example.com", accounts: [ACCOUNTS[0]] } : send(req as never))) as typeof host.host.send
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "top-doc" }
    const token = await autofill.query(pageSender(), ["email"], "email", 1)
    expect(await autofill.menuLoad(token.token!, menuSender(), SITE)).toMatchObject({ kind: "accounts", continueAs: true })
  })
})

describe("while Deadbolt is locked", () => {
  test("a focused field shows the locked row once per site; a click or ↓ always does; locking again starts over", async () => {
    host.setStatus({ state: "locked" })
    const ask = (explicit = false, sender = pageSender()) => autofill.query(sender, ["email", "password"], "email", 1, explicit)
    expect((await ask()).rows).toBe(1)
    expect(await ask()).toEqual({ rows: 0 })
    expect((await ask(true)).rows).toBe(1)
    // Another site has its own once; another page of this site doesn't.
    fake.frames["1:0"] = { url: "https://other.test/login", documentId: "other", parentFrameId: -1 }
    expect((await ask(false, pageSender({ url: "https://other.test/login", origin: "https://other.test", documentId: "other" }))).rows).toBe(1)
    fake.frames["1:0"] = { url: "https://app.example.com/login", documentId: "app", parentFrameId: -1 }
    expect(await ask(false, pageSender({ url: "https://app.example.com/login", origin: "https://app.example.com", documentId: "app" }))).toEqual({ rows: 0 })
    host.setStatus({ state: "ready", version: "0" })
    host.setStatus({ state: "locked" })
    fake.frames["1:0"] = { url: "https://www.example.com/login", documentId: "top-doc", parentFrameId: -1 }
    expect((await ask()).rows).toBe(1)
  })

  test("the locked row's unlock is taken only from its own menu frame, only while locked, and closes the menu", async () => {
    host.setStatus({ state: "locked" })
    const token = (await autofill.query(pageSender(), ["email", "password"], "email", 1, true)).token!
    expect((await autofill.menuLoad(token, menuSender(), SITE))?.kind).toBe("status")
    // Not the page, another tab or another extension page.
    expect(await autofill.menuUnlock(token, pageSender())).toBe(false)
    expect(await autofill.menuUnlock(token, menuSender({ tab: { id: 2 } as chrome.tabs.Tab }))).toBe(false)
    expect(await autofill.menuUnlock(token, menuSender({ documentId: "other-menu" }))).toBe(false)
    expect(await autofill.menuUnlock("made-up", menuSender())).toBe(false)
    host.setStatus({ state: "ready", version: "0" })
    expect(await autofill.menuUnlock(token, menuSender())).toBe(false)
    host.setStatus({ state: "locked" })
    expect(await autofill.menuUnlock(token, menuSender())).toBe(true)
    expect(delivered("db:close-menu").at(-1)?.message).toEqual({ type: "db:close-menu", token, unlock: true })
    expect(delivered("db:unlock-wait")).toHaveLength(1)
    expect(host.requests).toEqual([])
  })
})

describe("surface sizes", () => {
  test("a frame's asked-for size is kept within bounds, and it may only fold into a pill", () => {
    expect(resizeMessage("t", 2000, 9000, "save")).toEqual({ type: "db:resize-menu", token: "t", height: 400, width: 420 })
    expect(resizeMessage("t", 1, 1, "pill")).toEqual({ type: "db:resize-menu", token: "t", height: 28, width: 28, mode: "pill" })
    expect(resizeMessage("t", Number.NaN, "wide")).toEqual({ type: "db:resize-menu", token: "t", height: 40 })
  })
})

describe("sign in with a provider", () => {
  const google = { ref: `${"a".repeat(64)}:${"3".repeat(32)}`, vault: "Personal", title: "Example", hasPassword: false, hasTotp: false, urls: [], signIn: { provider: "google", account: "kit@gmail.com" } }
  const both = { ...ACCOUNTS[1], signIn: { provider: "github" } }
  const providerLogin = { ...ACCOUNTS[0], ref: `${"a".repeat(64)}:${"4".repeat(32)}`, title: "Google", username: "kit@gmail.com" }
  let withs: SignInWith

  beforeEach(() => {
    withs = new SignInWith(host.host)
    autofill = new Autofill(host.host, undefined, undefined, withs)
    const send = host.host.send.bind(host.host)
    host.host.send = (async (req: { type: string }) =>
      req.type === "list" ? { type: "list", site: "example.com", accounts: [ACCOUNTS[0], both, google, providerLogin] } : send(req as never)) as typeof host.host.send
  })

  test("a sign-in-with login shows on password fields too, never on code fields, and one with a password too is two rows", () => {
    expect(menuAccounts([google, ACCOUNTS[0]], "password")).toEqual([google, ACCOUNTS[0]])
    expect(menuAccounts([google], "otp")).toEqual([])
    expect(menuRowCount([google, both, ACCOUNTS[0]], "email")).toBe(4)
  })

  test("a phone box lists only logins whose username is a phone number", () => {
    const phone = { ...ACCOUNTS[0], username: "+1 415 555 0123" }
    expect(menuAccounts([ACCOUNTS[0], phone, google], "phone")).toEqual([phone])
  })

  test("picking it starts following the sign-in and points at the page's button; it never fills", async () => {
    fake.answer = (m) => (m.type === "db:point" ? true : m.type === "db:approve" ? { approval: "x", roles: ["email"] } : true)
    const token = await autofill.query(pageSender(), ["email", "password"], "email", 1)
    await autofill.menuLoad(token.token!, menuSender(), SITE)
    expect(await autofill.menuPick(token.token!, google.ref, menuSender())).toEqual({ ok: false, message: "This login signs in with another account." })
    expect(await autofill.menuSignIn(token.token!, google.ref, menuSender())).toEqual({ ok: true, found: true, provider: "google" })
    expect(delivered("db:point")[0].message).toEqual({ type: "db:point", provider: "google" })
    expect(fills()).toEqual([])
    expect(await autofill.menuSignIn(token.token!, ACCOUNTS[0].ref, menuSender())).toMatchObject({ ok: false })
  })

  test("the popup never fills one with no password", async () => {
    await autofill.page(pageSender(), "login", ["email", "password"], 4)
    expect(await autofill.popupFill(1, google.ref)).toEqual({ ok: false, message: "This login signs in with another account." })
    expect(fills()).toEqual([])
  })

  test("only Google's chooser, over https, gets the account; other providers' pages never do", async () => {
    withs.start(1, { provider: "github", account: "kit" }, "example.com")
    await withs.loaded({ tabId: 1, frameId: 0, url: "https://github.com/login", documentId: "g-doc" })
    withs.start(1, google.signIn, "example.com")
    await withs.loaded({ tabId: 1, frameId: 0, url: "http://accounts.google.com/signin", documentId: "g-doc" })
    expect(delivered("db:chooser")).toEqual([])
    expect(withs.accountFor(1, "http://accounts.google.com")).toBeUndefined()
  })

  test("on the provider's page with no login for the linked account, the name on the form narrows as usual", async () => {
    withs.start(1, { provider: "google", account: "nobody@gmail.com" }, "example.com")
    const sender = pageSender({ url: "https://accounts.google.com/signin", origin: "https://accounts.google.com", documentId: "g-doc" })
    // "admin" only: its fill row and its own sign-in-with row, not all five.
    expect((await autofill.query(sender, ["password"], "password", 1, false, "admin")).rows).toBe(2)
  })

  test("on Google's own password step, the account the page shows narrows the menu, and never hides it", async () => {
    const GOOGLE = "https://accounts.google.com"
    const sender = pageSender({ url: `${GOOGLE}/v3/signin/challenge/pwd`, origin: GOOGLE, documentId: "g-doc" })
    fake.frames["1:0"] = { url: `${GOOGLE}/v3/signin/challenge/pwd`, documentId: "g-doc" }
    const ask = (pageAccount: unknown, s = sender, identifier?: string) => autofill.query(s, ["password"], "password", 1, false, identifier, false, undefined, undefined, pageAccount)
    const named = await ask(" Kit@Gmail.com ")
    expect(named.rows).toBe(1)
    const reply = await autofill.menuLoad(named.token!, menuSender(), GOOGLE)
    expect(reply?.kind === "accounts" && reply.accounts.map((a) => a.ref)).toEqual([providerLogin.ref])
    expect(await autofill.menuPick(named.token!, ACCOUNTS[0].ref, menuSender())).toMatchObject({ ok: false })
    // Naming no login, or not an account at all: the whole list, as if it weren't sent.
    expect((await ask("nobody@gmail.com")).rows).toBe(5)
    expect((await ask("<b>kit@gmail.com</b>")).rows).toBe(5)
    expect((await ask(`${"k".repeat(500)}@gmail.com`)).rows).toBe(5)
    // The username the user typed comes first.
    expect((await ask("kit@gmail.com", sender, "admin")).rows).toBe(2)
    // Anywhere but Google's sign-in host, a page-set account is ignored.
    expect((await ask("kit@gmail.com", pageSender())).rows).toBe(5)
    expect((await ask("kit@gmail.com", pageSender({ url: "https://github.com/login", origin: "https://github.com" }))).rows).toBe(5)
    // Only on a later step's field.
    expect((await autofill.query(sender, ["email", "password"], "email", 1, false, undefined, false, undefined, undefined, "kit@gmail.com")).rows).toBe(5)
  })

  test("on the provider's chooser, only its top page gets the account; the menu there narrows to its login", async () => {
    withs.start(1, google.signIn, "example.com")
    withs.navigated(1, "https://accounts.google.com/signin")
    expect(withs.accountFor(1, "https://accounts.google.com")).toBe("kit@gmail.com")
    expect(withs.accountFor(1, "https://evil.example.net")).toBeUndefined()
    fake.frames["1:0"] = { url: "https://accounts.google.com/signin", documentId: "g-doc" }
    await withs.loaded({ tabId: 1, frameId: 0, url: "https://accounts.google.com/signin", documentId: "g-doc" })
    await withs.loaded({ tabId: 1, frameId: 0, url: "https://evil.example.net/", documentId: "g-doc" })
    await withs.loaded({ tabId: 1, frameId: 2, url: "https://accounts.google.com/frame", documentId: "f-doc" })
    expect(delivered("db:chooser").map((d) => [d.message, d.options])).toEqual([[{ type: "db:chooser", account: "kit@gmail.com" }, { documentId: "g-doc" }]])
    const sender = pageSender({ url: "https://accounts.google.com/signin", origin: "https://accounts.google.com", documentId: "g-doc" })
    const menu = await autofill.query(sender, ["email"], "email", 1)
    expect(menu.rows).toBe(1)
  })

  test("a popup follows the sign-in; coming back to the site, closing the tab or locking ends it", async () => {
    withs.start(1, google.signIn, "example.com")
    withs.opened(1, 2)
    expect(withs.accountFor(2, "https://accounts.google.com")).toBe("kit@gmail.com")
    withs.navigated(1, "https://accounts.google.com/x")
    withs.navigated(1, "https://www.example.com/home")
    expect(withs.accountFor(1, "https://accounts.google.com")).toBeUndefined()
    host.setStatus({ state: "locked" })
    expect(withs.accountFor(2, "https://accounts.google.com")).toBeUndefined()
  })
})
