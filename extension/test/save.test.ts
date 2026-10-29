import { beforeEach, describe, expect, test } from "bun:test"
import { HostError } from "../src/bg/host"
import { Saver } from "../src/bg/save"
import type { RequestBody } from "../src/protocol"
import { fakeHost, installChrome, pageSender, type FakeChrome, type FakeHost } from "./chrome"

let fake: FakeChrome
let host: FakeHost
let saver: Saver

beforeEach(() => {
  fake = installChrome()
  host = fakeHost()
  saver = new Saver(host.host, { capture: 60_000, offer: 60_000 })
})

const HOME = { url: "https://www.example.com/home", documentId: "home-doc" }

const signIn = async (username: string, password: string) => {
  await saver.capture(pageSender(), { username, password, title: "Sign in to Example" })
  fake.frames["1:0"] = HOME
  await saver.quiet(pageSender(HOME), false)
}

const requests = (type: string) => host.requests.filter((r) => r.type === type)

/** Holds the host's replies to `type` until released, in order. */
function hold(type: RequestBody["type"]) {
  const held: Array<() => void> = []
  const send = host.host.send.bind(host.host)
  host.host.send = (async (req: RequestBody) => {
    if (req.type === type) await new Promise<void>((resolve) => held.push(resolve))
    return send(req)
  }) as typeof host.host.send
  return held
}

async function waitFor(ok: () => boolean) {
  for (let i = 0; i < 100 && !ok(); i++) await Bun.sleep(1)
  expect(ok()).toBe(true)
}

describe("offers", () => {
  test("a new login is offered in the toolbar, never in the page", async () => {
    await signIn("new@example.com", "a new password")
    expect(saver.pending(1)).toMatchObject({ site: "example.com", username: "new@example.com", update: false })
    expect(saver.pending(1)?.id).toBeString()
    expect(fake.badges[1]).toBe("1")
    expect(fake.popups).toEqual([7])
    // Nothing went to the page, and nothing was saved yet.
    expect(fake.delivered).toEqual([])
    expect(host.requests.map((r) => r.type)).toEqual(["check"])
  })

  test("the popup isn't opened over another tab", async () => {
    fake.tabs[1].active = false
    await signIn("new@example.com", "a new password")
    expect(fake.popups).toEqual([])
    expect(fake.badges[1]).toBe("1")
  })

  test("a changed password is offered as an update; an unchanged one isn't offered", async () => {
    await signIn("admin", "changed")
    expect(saver.pending(1)?.update).toBe(true)
    await saver.choose(1, saver.pending(1)!.id, "later")
    await signIn("admin", "hunter2")
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1]).toBe("")
  })

  test("save only after the user says so, then the offer is gone", async () => {
    await signIn("new@example.com", "a new password")
    const { id } = saver.pending(1)!
    expect(await saver.choose(1, id, "save")).toEqual({ ok: true, message: "Saved to Deadbolt" })
    const save = requests("save")[0] as unknown as { entry: Record<string, string> }
    expect(save.entry).toEqual({ title: "Sign in to Example", url: "https://www.example.com/login", username: "new@example.com", password: "a new password" })
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1]).toBe("")
    expect(await saver.choose(1, id, "save")).toEqual({ ok: false, message: "This offer has expired.", gone: true })
  })
})

describe("answering an offer", () => {
  test("Save and Not now answer only the offer the popup showed", async () => {
    await signIn("new@example.com", "a new password")
    const shown = saver.pending(1)!.id
    // Another sign-in in the tab replaces it while the popup still shows the first.
    await signIn("admin", "changed")
    const waiting = saver.pending(1)!
    expect(waiting.id).not.toBe(shown)
    expect(await saver.choose(1, shown, "save")).toMatchObject({ ok: false, gone: true })
    expect(await saver.choose(1, shown, "later")).toMatchObject({ ok: false, gone: true })
    expect(requests("save")).toEqual([])
    expect(saver.pending(1)).toEqual(waiting)
    expect(await saver.choose(1, waiting.id, "save")).toEqual({ ok: true, message: "Password updated" })
    expect((requests("save")[0] as { entry: { username: string } }).entry.username).toBe("admin")
  })

  test("a second Save while the first is on its way saves nothing more", async () => {
    const saves = hold("save")
    await signIn("new@example.com", "a new password")
    const { id } = saver.pending(1)!
    const first = saver.choose(1, id, "save")
    await waitFor(() => saves.length === 1)
    expect(await saver.choose(1, id, "save")).toEqual({ ok: false, message: "Saving…" })
    expect(await saver.choose(1, id, "later")).toEqual({ ok: false, message: "Saving…" })
    saves[0]()
    expect(await first).toMatchObject({ ok: true })
    expect(requests("save")).toHaveLength(1)
  })

  test("a save that finishes after a newer offer arrived leaves the newer one", async () => {
    const saves = hold("save")
    await signIn("new@example.com", "a new password")
    const first = saver.choose(1, saver.pending(1)!.id, "save")
    await waitFor(() => saves.length === 1)
    await signIn("admin", "changed")
    const newer = saver.pending(1)!
    saves[0]()
    expect(await first).toMatchObject({ ok: true })
    expect(saver.pending(1)).toEqual(newer)
    expect(fake.badges[1]).toBe("1")
  })

  test("Save checks the tab is still on the offer's site", async () => {
    await signIn("new@example.com", "a new password")
    // The tab has moved on and the navigation event hasn't arrived yet.
    fake.frames["1:0"] = { url: "https://elsewhere.net/", documentId: "other" }
    expect(await saver.choose(1, saver.pending(1)!.id, "save")).toMatchObject({ ok: false, gone: true })
    expect(requests("save")).toEqual([])
  })
})

describe("a check that finishes late", () => {
  async function lateCheck(meanwhile: () => void) {
    const checks = hold("check")
    await saver.capture(pageSender(), { username: "new@example.com", password: "pw", title: "" })
    fake.frames["1:0"] = HOME
    const quiet = saver.quiet(pageSender(HOME), false)
    await waitFor(() => checks.length === 1)
    meanwhile()
    checks[0]()
    await quiet
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1]).toBeUndefined()
    expect(fake.popups).toEqual([])
  }

  test("offers nothing once the tab is on another site", () =>
    lateCheck(() => {
      fake.frames["1:0"] = { url: "https://elsewhere.net/", documentId: "other" }
      saver.navigated(1, "https://elsewhere.net/")
    }))

  test("or went to another site and came back", () =>
    lateCheck(() => {
      saver.navigated(1, "https://www.example.com/home")
      saver.navigated(1, "https://elsewhere.net/")
      saver.navigated(1, "https://www.example.com/home")
    }))

  test("or before the navigation event arrives", () => lateCheck(() => void (fake.frames["1:0"] = { url: "https://elsewhere.net/", documentId: "other" })))

  test("or after Deadbolt locked, even once it's unlocked again", () =>
    lateCheck(() => {
      host.setStatus({ state: "locked" })
      host.setStatus({ state: "ready", version: "0" })
    }))

  test("or after the tab closed", () => lateCheck(() => saver.forgetTab(1)))

  test("a capture that lands after the tab left the site is dropped", async () => {
    const capture = saver.capture(pageSender(), { username: "new@example.com", password: "pw", title: "" })
    saver.navigated(1, "https://elsewhere.net/")
    await capture
    saver.navigated(1, "https://www.example.com/home")
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toEqual([])
  })
})

describe("opening the popup by itself", () => {
  // A page can see focus leave it when the popup opens, so this is the one bit
  // a check can leak: at most once per site every ten minutes, across tabs.
  test("happens once per site every ten minutes, across tabs; other offers only badge", async () => {
    let now = 1_000_000
    saver = new Saver(host.host, { capture: 60_000, offer: 60_000 }, () => now)
    const signInOn = async (tabId: number, url: string) => {
      const tab = { id: tabId, incognito: false } as chrome.tabs.Tab
      const origin = new URL(url).origin
      fake.tabs[tabId] = { active: true, windowId: 7 }
      fake.frames[`${tabId}:0`] = { url, documentId: `login-${tabId}`, parentFrameId: -1 }
      await saver.capture(pageSender({ tab, url, origin, documentId: `login-${tabId}` }), { username: "new@example.com", password: "pw", title: "" })
      fake.frames[`${tabId}:0`] = { url: `${origin}/home`, documentId: `home-${tabId}`, parentFrameId: -1 }
      await saver.quiet(pageSender({ tab, url: `${origin}/home`, origin, documentId: `home-${tabId}` }), false)
      expect(saver.pending(tabId)).toBeDefined()
    }

    await signInOn(1, "https://www.example.com/login")
    expect(fake.popups).toHaveLength(1)
    // Another tab on the same site (another subdomain too) a few minutes later: badge only.
    now += 4 * 60_000
    await signInOn(2, "https://app.example.com/login")
    expect(fake.popups).toHaveLength(1)
    expect(fake.badges[2]).toBe("1")
    // Another site has its own turn.
    await signInOn(3, "https://other.test/login")
    expect(fake.popups).toHaveLength(2)
    // Just under ten minutes after the first: still badge only.
    now += 6 * 60_000 - 1
    await signInOn(1, "https://www.example.com/login")
    expect(fake.popups).toHaveLength(2)
    // Ten minutes on, example.com gets its next turn.
    now += 1
    await signInOn(2, "https://app.example.com/login")
    expect(fake.popups).toHaveLength(3)
  })

  test("two tabs offering at once share one turn", async () => {
    saver = new Saver(host.host, { capture: 60_000, offer: 60_000 }, () => 5_000_000)
    fake.tabs[2] = { active: true, windowId: 8 }
    fake.frames["2:0"] = { url: "https://www.example.com/login", documentId: "other-login", parentFrameId: -1 }
    const tab2 = { id: 2, incognito: false } as chrome.tabs.Tab
    await saver.capture(pageSender(), { username: "a@example.com", password: "x", title: "" })
    await saver.capture(pageSender({ tab: tab2, documentId: "other-login" }), { username: "b@example.com", password: "y", title: "" })
    fake.frames["1:0"] = HOME
    fake.frames["2:0"] = { url: "https://www.example.com/home", documentId: "other-home" }
    await Promise.all([saver.quiet(pageSender(HOME), false), saver.quiet(pageSender({ tab: tab2, url: "https://www.example.com/home", documentId: "other-home" }), false)])
    expect([saver.pending(1), saver.pending(2)].every(Boolean)).toBe(true)
    expect(fake.popups).toHaveLength(1)
  })

  // Otherwise a page could submit guesses until the popup opens: every
  // "same" before the first opening would be free.
  test("a check that says the login is already saved uses the turn too", async () => {
    await signIn("admin", "hunter2")
    expect(saver.pending(1)).toBeUndefined()
    await signIn("new@example.com", "a new password")
    expect(saver.pending(1)).toBeDefined()
    expect(fake.badges[1]).toBe("1")
    expect(fake.popups).toEqual([])
  })

  test("so does a rate-limited check", async () => {
    const send = host.host.send.bind(host.host)
    let limited = true
    host.host.send = (async (req: RequestBody) => {
      if (req.type === "check" && limited) {
        limited = false
        throw new HostError("rate_limited", "slow down")
      }
      return send(req)
    }) as typeof host.host.send
    await signIn("new@example.com", "first")
    expect(saver.pending(1)).toBeUndefined()
    await signIn("new@example.com", "second")
    expect(saver.pending(1)).toBeDefined()
    expect(fake.popups).toEqual([])
  })
})

describe("plaintext lifetime", () => {
  test("a capture expires on its own", async () => {
    saver = new Saver(host.host, { capture: 20, offer: 60_000 })
    await saver.capture(pageSender(), { username: "new@example.com", password: "x", title: "" })
    await Bun.sleep(40)
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(host.requests).toEqual([])
  })

  test("a username on its own doesn't keep an older password longer; a new password starts over", async () => {
    let now = 1_000_000
    saver = new Saver(host.host, { capture: 3 * 60_000, offer: 60_000 }, () => now)
    await saver.capture(pageSender(), { password: "old", title: "" })
    now += 2 * 60_000
    await saver.capture(pageSender(), { username: "new@example.com", title: "" })
    now += 90_000
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toEqual([])

    await saver.capture(pageSender(), { username: "new@example.com", password: "old", title: "" })
    now += 2 * 60_000
    await saver.capture(pageSender(), { password: "fresh", title: "" })
    now += 90_000
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toMatchObject([{ username: "new@example.com", password: "fresh" }])
  })

  test("an offer, and the password in it, expires on its own", async () => {
    saver = new Saver(host.host, { capture: 60_000, offer: 20 })
    await signIn("new@example.com", "a new password")
    expect(saver.pending(1)).toBeDefined()
    await Bun.sleep(40)
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1]).toBe("")
  })

  test("locking drops captures and offers", async () => {
    await signIn("new@example.com", "a new password")
    await saver.capture(pageSender(), { username: "b@example.com", password: "y", title: "" })
    host.setStatus({ state: "locked" })
    expect(saver.pending(1)).toBeUndefined()
    host.setStatus({ state: "ready", version: "0" })
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toHaveLength(1)
  })

  test("another site's page drops the capture and the offer; the same site's keeps them", async () => {
    await signIn("new@example.com", "a new password")
    saver.navigated(1, "https://app.example.com/dashboard")
    expect(saver.pending(1)).toBeDefined()
    saver.navigated(1, "https://elsewhere.net/")
    expect(saver.pending(1)).toBeUndefined()
    await saver.capture(pageSender(), { username: "b@example.com", password: "y", title: "" })
    saver.navigated(1, "https://elsewhere.net/")
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toHaveLength(1)
  })
})

describe("new passwords", () => {
  const submit = async (fields: Record<string, string>, kind: string) => {
    await saver.capture(pageSender(), { ...fields, title: "Example", kind, roles: ["email", "password", "new-password"] })
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
  }
  const on = (url: string, documentId: string) => pageSender({ url, origin: new URL(url).origin, documentId })

  test("a password goes to the origin it was submitted on, and is saved with that page; an email step's username carries across", async () => {
    // Email on one of the site's hosts, the generated password on another.
    await saver.capture(on("https://id.example.com/start", "id-doc"), { username: "new@example.com", title: "Example ID", kind: "login", roles: ["email"], submission: 1 })
    await saver.capture(on("https://accounts.example.com/signup", "accounts-doc"), { generated: "g4", title: "Create an account", kind: "signup", roles: ["new-password"], submission: 1 })
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toEqual([{ type: "check", origin: "https://accounts.example.com", username: "new@example.com", generated: "g4" }])
    await saver.choose(1, saver.pending(1)!.id, "save")
    expect(requests("save")[0]).toMatchObject({
      origin: "https://accounts.example.com",
      entry: { title: "Create an account", url: "https://accounts.example.com/signup", username: "new@example.com", generated: "g4" },
    })
  })

  test("only a sign-in's own username step on the top page carries to another host", async () => {
    const steps: Array<[chrome.runtime.MessageSender, Record<string, unknown>]> = [
      // A form that isn't a sign-in, such as a newsletter box.
      [on("https://news.example.com/", "n"), { username: "news@example.com", title: "News", kind: null, roles: ["email"], submission: 1 }],
      // A sign-in step in a frame.
      [pageSender({ url: "https://id.example.com/frame", origin: "https://id.example.com", documentId: "f", frameId: 2 }), { username: "framed@example.com", title: "", kind: "login", roles: ["email"], submission: 1 }],
    ]
    for (const [sender, step] of steps) {
      host.requests.length = 0
      fake.frames["1:0"] = { url: "https://www.example.com/", documentId: "top" }
      await saver.capture(sender, step)
      await saver.capture(on("https://accounts.example.com/signup", "a"), { generated: "g7", title: "Sign up", kind: "signup", roles: ["new-password"], submission: 1 })
      fake.frames["1:0"] = HOME
      await saver.quiet(pageSender(HOME), false)
      expect(requests("check")).toEqual([])
    }
    // Nor to a password in a frame.
    fake.frames["1:0"] = { url: "https://id.example.com/start", documentId: "id-doc" }
    await saver.capture(on("https://id.example.com/start", "id-doc"), { username: "new@example.com", title: "", kind: "login", roles: ["email"], submission: 1 })
    await saver.capture(pageSender({ url: "https://accounts.example.com/pw", origin: "https://accounts.example.com", documentId: "f2", frameId: 2 }), { password: "framed", title: "", kind: "login", roles: ["password"], submission: 1 })
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toEqual([])
  })

  test("a username joining a password from its own origin pairs with it, and the password's form still owns the failure check", async () => {
    await saver.capture(on("https://accounts.example.com/signup", "a"), { generated: "g10", title: "Sign up", kind: "signup", roles: ["new-password"], submission: 1 })
    await saver.capture(on("https://accounts.example.com/name", "a2"), { username: "new@example.com", title: "", kind: "signup", roles: ["email"], submission: 1 })
    saver.failed(on("https://accounts.example.com/signup", "a"), 1)
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toEqual([])

    await saver.capture(on("https://accounts.example.com/signup", "a"), { generated: "g11", title: "Sign up", kind: "signup", roles: ["new-password"], submission: 2 })
    await saver.capture(on("https://accounts.example.com/name", "a2"), { username: "new@example.com", title: "", kind: "signup", roles: ["email"], submission: 1 })
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toEqual([{ type: "check", origin: "https://accounts.example.com", username: "new@example.com", generated: "g11" }])
  })

  test("passwords held for one username never go with another's", async () => {
    // A sign-in as admin, then a sign-up as someone else on the same page.
    await saver.capture(pageSender(), { username: "admin", password: "hunter2", title: "", kind: "login", roles: ["username", "password"], submission: 1 })
    await saver.capture(pageSender(), { username: "new@example.com", generated: "g12", title: "", kind: "signup", roles: ["email", "new-password"], submission: 2 })
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toEqual([{ type: "check", origin: "https://www.example.com", username: "new@example.com", generated: "g12" }])
  })

  test("a password from another of the site's hosts replaces the earlier ones and their username, never mixes with them", async () => {
    // A generated sign-up on one host, then a sign-in with a typed password on another.
    await saver.capture(on("https://accounts.example.com/signup", "a"), { username: "new@example.com", generated: "g5", title: "Sign up", kind: "signup", roles: ["email", "new-password"], submission: 1 })
    await saver.capture(on("https://login.example.com/", "b"), { password: "typed", title: "Sign in", kind: "login", roles: ["password"], submission: 1 })
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    // No username of its own: nothing to offer.
    expect(requests("check")).toEqual([])
    expect(JSON.stringify(host.requests)).not.toContain("g5")
  })

  test("a username from another host after the password never joins it, replaces its own, or takes over its failure check", async () => {
    // Without a username: one from another host doesn't join it.
    await saver.capture(on("https://accounts.example.com/signup", "a"), { generated: "g6", title: "Sign up", kind: "signup", roles: ["new-password"], submission: 1 })
    await saver.capture(on("https://profile.example.com/name", "p"), { username: "someone@example.com", title: "Profile", kind: "login", roles: ["email"], submission: 1 })
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toEqual([])

    // With one: it stays, whatever another host or its own sends on its own.
    for (const later of ["https://profile.example.com/name", "https://accounts.example.com/invite"]) {
      host.requests.length = 0
      await saver.capture(on("https://accounts.example.com/signup", "a"), { username: "new@example.com", generated: "g8", title: "Sign up", kind: "signup", roles: ["email", "new-password"], submission: 2 })
      await saver.capture(on(later, "p"), { username: "someone@example.com", title: "", kind: "login", roles: ["email"], submission: 1 })
      await saver.quiet(pageSender(HOME), false)
      expect(requests("check")).toEqual([{ type: "check", origin: "https://accounts.example.com", username: "new@example.com", generated: "g8" }])
      await saver.choose(1, saver.pending(1)!.id, "later")
    }

    // And the sign-up failing is still seen: the username's page didn't take over the failure check.
    host.requests.length = 0
    await saver.capture(on("https://accounts.example.com/signup", "a"), { username: "new@example.com", generated: "g9", title: "Sign up", kind: "signup", roles: ["email", "new-password"], submission: 3 })
    await saver.capture(on("https://profile.example.com/name", "p"), { username: "someone@example.com", title: "", kind: "login", roles: ["email"], submission: 1 })
    saver.failed(on("https://accounts.example.com/signup", "a"), 3)
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toEqual([])
  })
  const entry = () => (requests("save")[0] as unknown as { ref?: string; entry: Record<string, string> })

  test("a generated password is named by its id, never sent, and saved only when the user says so", async () => {
    await submit({ username: "new@example.com", generated: "g1", newPassword: "ignored" }, "signup")
    expect(requests("check")[0]).toMatchObject({ username: "new@example.com", generated: "g1" })
    expect(requests("check")[0]).not.toHaveProperty("password")
    expect(requests("save")).toEqual([])
    await saver.choose(1, saver.pending(1)!.id, "save")
    expect(entry().entry).toEqual({ title: "Example", url: "https://www.example.com/login", username: "new@example.com", generated: "g1" })
  })

  test("a change-password form with no username updates the login whose password is the current one", async () => {
    await submit({ password: "hunter2", generated: "g2" }, "change-password")
    expect(requests("check")[0]).not.toHaveProperty("username")
    expect(saver.pending(1)).toMatchObject({ username: "admin", update: true })
    await saver.choose(1, saver.pending(1)!.id, "save")
    expect(entry()).toMatchObject({ ref: "a".repeat(64) + ":" + "2".repeat(32), entry: { username: "admin", generated: "g2" } })
  })

  test("or the only login here, and nothing when there are several", async () => {
    await submit({ password: "forgotten", newPassword: "a new one" }, "change-password")
    expect(saver.pending(1)).toBeUndefined()
    expect(requests("save")).toEqual([])
    const list = host.host.send.bind(host.host)
    host.host.send = (async (req: RequestBody) =>
      req.type === "list" ? { type: "list", site: "example.com", accounts: [{ ...(await list(req) as { accounts: object[] }).accounts[0] }] } : list(req)) as typeof host.host.send
    await submit({ password: "forgotten", newPassword: "a new one" }, "change-password")
    expect(saver.pending(1)).toMatchObject({ username: "kit@example.com", update: true })
  })

  test("a change-password form with a username asks the host the same whether or not the current password matched", async () => {
    const changes: Array<[string, string, object]> = [
      // The saved password: an update of that login.
      ["admin", "hunter2", { username: "admin", update: true }],
      // Another current password: the saved login still updates.
      ["admin", "forgotten", { username: "admin", update: true }],
      // No login here for the username: a new one.
      ["new@example.com", "anything", { username: "new@example.com", update: false }],
    ]
    for (const [username, password, offer] of changes) {
      host.requests.length = 0
      await submit({ username, password, newPassword: "a new one" }, "change-password")
      expect(requests("check")).toEqual([
        { type: "check", origin: "https://www.example.com", username, password },
        { type: "check", origin: "https://www.example.com", username, password: "a new one" },
      ])
      expect(requests("list")).toEqual([])
      expect(saver.pending(1)).toMatchObject(offer)
      await saver.choose(1, saver.pending(1)!.id, "later")
    }
    host.requests.length = 0
    await submit({ username: "admin", password: "hunter2", newPassword: "a new one" }, "change-password")
    await saver.choose(1, saver.pending(1)!.id, "save")
    expect(entry()).toMatchObject({ ref: "a".repeat(64) + ":" + "2".repeat(32), entry: { username: "admin", password: "a new one" } })
  })

  test("a new password that's the current one offers nothing", async () => {
    const forms: Array<Record<string, string>> = [{ username: "admin", password: "hunter2", newPassword: "hunter2" }, { password: "hunter2", newPassword: "hunter2" }, { username: "admin", password: "other", newPassword: "other" }]
    for (const fields of forms) {
      await submit(fields, "change-password")
      expect(saver.pending(1)).toBeUndefined()
      expect(fake.badges[1] ?? "").toBe("")
    }
    expect(requests("save")).toEqual([])
  })

  test("a generated sign-up whose form still shows offers nothing", async () => {
    await saver.capture(pageSender(), { username: "new@example.com", generated: "g3", title: "", kind: "signup", roles: ["email", "new-password"], submission: 1 })
    saver.failed(pageSender(), 1)
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(host.requests).toEqual([])
  })
})

describe("failed and abandoned sign-ins", () => {
  const login = { username: "new@example.com", password: "wrong", title: "", kind: "login", roles: ["email", "password"], submission: 1 }

  test("the form still showing in place offers nothing", async () => {
    await saver.capture(pageSender(), login)
    saver.failed(pageSender(), 1)
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toHaveLength(0)
  })

  test("a failure counts only for the submit and document it's about", async () => {
    // A retry after a wrong password: the first submit's failure arrives after it.
    await saver.capture(pageSender(), login)
    await saver.capture(pageSender(), { ...login, password: "right", submission: 2 })
    saver.failed(pageSender(), 1)
    // Another document on the same page, such as a frame or a page posted back, can't fail it either.
    saver.failed(pageSender({ documentId: "other-doc" }), 2)
    saver.failed(pageSender(), "2")
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toMatchObject([{ username: "new@example.com", password: "right" }])
    // The retry's own failure does.
    await saver.capture(pageSender(), { ...login, submission: 3 })
    saver.failed(pageSender(), 3)
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toHaveLength(1)
  })

  test("the form posted back to its page offers nothing; the same document reporting it again doesn't count", async () => {
    await saver.capture(pageSender(), login)
    saver.page(pageSender(), "login", ["email", "password"])
    saver.page(pageSender({ url: "https://www.example.com/login/next", documentId: "next" }), "login", ["password"])
    saver.page(pageSender({ documentId: "mfa" }), "mfa", ["otp"])
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toHaveLength(1)

    await saver.capture(pageSender(), login)
    saver.page(pageSender({ documentId: "posted-back" }), "login", ["email", "password"])
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toHaveLength(1)
  })

  test("a typed address or a bookmark ends the sign-in; a link doesn't", async () => {
    await saver.capture(pageSender(), login)
    saver.navigated(1, "https://www.example.com/mfa", "form_submit")
    saver.navigated(1, HOME.url, "link")
    fake.frames["1:0"] = HOME
    await saver.quiet(pageSender(HOME), false)
    expect(requests("check")).toHaveLength(1)
    for (const how of ["typed", "auto_bookmark"]) {
      await saver.capture(pageSender(), login)
      saver.navigated(1, HOME.url, how)
      await saver.quiet(pageSender(HOME), false)
    }
    expect(requests("check")).toHaveLength(1)
  })

  test("so does one on the same site while the check is on its way, and an offer waiting", async () => {
    saver.navigated(1, "https://www.example.com/login", "link")
    const held = hold("check")
    await saver.capture(pageSender(), login)
    fake.frames["1:0"] = HOME
    const quiet = saver.quiet(pageSender(HOME), false)
    await waitFor(() => held.length === 1)
    saver.navigated(1, "https://www.example.com/settings", "typed")
    held[0]()
    await quiet
    expect(saver.pending(1)).toBeUndefined()
    expect(fake.badges[1] ?? "").toBe("")

    const signedIn = signIn("new@example.com", "a new password")
    await waitFor(() => held.length === 2)
    held[1]()
    await signedIn
    expect(saver.pending(1)).toBeDefined()
    saver.navigated(1, "https://www.example.com/settings", "auto_bookmark")
    expect(saver.pending(1)).toBeUndefined()
  })

  test("an offer waits for the five seconds a failure takes to show", async () => {
    saver = new Saver(host.host, { capture: 60_000, offer: 60_000, settle: 60 })
    await saver.capture(pageSender(), login)
    fake.frames["1:0"] = HOME
    const quiet = saver.quiet(pageSender(HOME), false)
    await Bun.sleep(20)
    saver.failed(pageSender(), 1)
    await quiet
    expect(requests("check")).toHaveLength(0)
  })
})
