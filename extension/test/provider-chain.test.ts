import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test"
import { SIGNIN_SETTING } from "../src/auth-state"
import { Passkeys } from "../src/bg/passkeys"
import { ProviderChain, PROVIDER_CHAIN_ACTIONS, PROVIDER_CHAIN_TTL_MS } from "../src/bg/provider-chain"
import { SignInWith } from "../src/bg/signinwith"
import type { ProviderReport } from "../src/messages"
import { ACCOUNTS, fakeHost, installChrome, pageSender, SITE, type FakeChrome, type FakeHost } from "./chrome"

const GOOGLE = "https://accounts.google.com"
const home = { tabId: 1, frameId: 0, documentId: "top-doc", origin: SITE }
const providerAccount = { ...ACCOUNTS[0], urls: [GOOGLE] }
const linked = { ...ACCOUNTS[1], urls: [SITE], signIn: { provider: "google", account: providerAccount.username } }
let fake: FakeChrome, host: FakeHost, chain: ProviderChain, keys: Passkeys
let report: ProviderReport
let storageChanged: (changes: Record<string, chrome.storage.StorageChange>, area: string) => void
const actions = () => fake.delivered.filter((d) => d.message.type === "db:provider-act")
const fills = () => host.requests.filter((r) => r.type === "fill")

beforeEach(() => {
  fake = installChrome()
  Object.assign(chrome.storage, { onChanged: { addListener: (fn: typeof storageChanged) => { storageChanged = fn } } })
  fake.local[SIGNIN_SETTING] = true
  host = fakeHost()
  const send = host.host.send.bind(host.host)
  host.host.send = (async (req) => req.type === "list" ? { type: "list", site: "google.com", accounts: [providerAccount] } : send(req as never)) as typeof host.host.send
  keys = new Passkeys(host.host)
  chain = new ProviderChain(host.host, keys, new SignInWith(host.host))
  report = { kind: "entry", action: "entry" }
  fake.answer = (m) => m.type === "db:provider-probe" ? report : true
})
afterEach(() => chain.stop(1))

function commit(origin = GOOGLE, documentId = "provider-doc", tabId = 1, path = "/v3/signin/identifier") {
  fake.frames[`${tabId}:0`] = { url: `${origin}${path}`, documentId, parentFrameId: -1 }
  chain.navigated({ tabId, frameId: 0, url: `${origin}${path}`, documentId, transitionType: "link" })
  return pageSender({ tab: { id: tabId } as chrome.tabs.Tab, url: `${origin}${path}`, origin, documentId })
}
async function until(test: () => boolean) {
  for (let i = 0; i < 100 && !test(); i++) await Bun.sleep(1)
  expect(test()).toBe(true)
}

describe("provider chain authority", () => {
  test("setting off and a non-exact saved site do nothing", async () => {
    fake.local[SIGNIN_SETTING] = false
    await chain.start(home, linked)
    fake.local[SIGNIN_SETTING] = true
    await chain.start(home, { ...linked, urls: ["https://example.com"] })
    expect(actions()).toHaveLength(0)
    expect(chain.active(1)).toBe(false)
  })
  test("only the browser's committed provider document receives a credential", async () => {
    await chain.start(home, linked)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    // A sender cannot turn the site's current document into a provider page.
    await chain.check(pageSender({ origin: GOOGLE, url: GOOGLE + "/v3/signin/identifier" }))
    expect(fills()).toHaveLength(0)
    expect(actions()).toHaveLength(1)
  })
  test.each(["https://accounts.google.com.evil.test", "https://login.example.com", "http://accounts.google.com", "https://accounts.google.com:8443"])("unexpected origin %s ends it without disclosure", async (origin) => {
    await chain.start(home, linked)
    const sender = commit(origin)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check(sender)
    expect(chain.active(1)).toBe(false)
    expect(fills()).toHaveLength(0)
    expect(fake.delivered.filter((d) => d.message.account)).toHaveLength(0)
  })
  test("provider iframe reports and unrelated tabs never inherit a pick", async () => {
    await chain.start(home, linked)
    const sender = commit()
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check({ ...sender, frameId: 2 })
    await chain.check({ ...sender, tab: { id: 9 } as chrome.tabs.Tab })
    expect(fills()).toHaveLength(0)
    await chain.check(sender)
    expect(fills()).toHaveLength(1)
    expect(actions().at(-1)?.message.values).toMatchObject({ password: "correct horse" })
  })
  test.each(["consent", "phone", "sms", "security-key", "captcha", "unknown"] as const)("%s stops before asking for values or acting", async (reason) => {
    await chain.start(home, linked)
    const sender = commit()
    report = { kind: "stop", reason }
    await chain.check(sender)
    expect(chain.active(1)).toBe(false)
    expect(actions()).toHaveLength(1)
    expect(fills()).toHaveLength(0)
  })
  test.each(["cancel", "lock", "setting", "navigate"])("%s revokes a delayed backend reply", async (stop) => {
    await chain.start(home, linked)
    const sender = commit()
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    const release = host.holdFills()
    const pending = chain.check(sender)
    await until(() => fills().length === 1)
    if (stop === "cancel") chain.stop(1)
    if (stop === "lock") host.setStatus({ state: "locked" })
    if (stop === "setting") {
      fake.local[SIGNIN_SETTING] = false
      storageChanged({ [SIGNIN_SETTING]: { newValue: false } }, "local")
    }
    if (stop === "navigate") commit("https://unrelated.test")
    release()
    await pending
    expect(actions()).toHaveLength(1)
    expect(chain.active(1)).toBe(false)
  })
  test("an unlearned code step is left completely untouched", async () => {
    await chain.start(home, linked)
    const sender = commit()
    report = { kind: "form", form: 1, roles: ["otp"], action: "code" }
    await chain.check(sender)
    expect(fills()).toHaveLength(0)
    expect(actions()).toHaveLength(1)
    expect(chain.active(1)).toBe(false)
  })
  test("entry and chooser actions share the eight-action cap", async () => {
    await chain.start(home, linked)
    report = { kind: "chooser", action: "tile" }
    for (let i = 0; i < PROVIDER_CHAIN_ACTIONS; i++) await chain.check(commit(GOOGLE, `chooser-${i}`))
    expect(actions()).toHaveLength(PROVIDER_CHAIN_ACTIONS)
    expect(chain.active(1)).toBe(false)
  })
  test("the original two-minute deadline is not renewed by a step", async () => {
    const now = Date.now()
    await chain.start(home, linked)
    report = { kind: "chooser", action: "tile" }
    const clock = spyOn(Date, "now").mockReturnValue(now + PROVIDER_CHAIN_TTL_MS + 1)
    try { await chain.check(commit()) } finally { clock.mockRestore() }
    expect(actions()).toHaveLength(1)
    expect(chain.active(1)).toBe(false)
  })
  test("only one popup from the opening top document follows the chain", async () => {
    await chain.start(home, linked)
    fake.frames["2:0"] = { url: GOOGLE + "/v3/signin/identifier", documentId: "popup", parentFrameId: -1 }
    await chain.opened({ sourceTabId: 1, sourceFrameId: 2, tabId: 2 })
    expect(chain.active(2)).toBe(false)
    await chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 2 })
    expect(chain.active(2)).toBe(true)
    await chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 3 })
    expect(chain.active(3)).toBe(false)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check(commit(GOOGLE, "popup", 2))
    expect(fills()).toHaveLength(1)
    expect(actions().at(-1)?.tabId).toBe(2)
  })
  test("an unloading acted document does not revoke the next committed step", async () => {
    await chain.start(home, linked)
    report = { kind: "chooser", action: "tile" }
    const chooser = commit()
    await chain.check(chooser)
    const answer = fake.answer
    fake.answer = (m, doc) => m.type === "db:provider-probe" ? null : answer(m, doc)
    await chain.check(chooser)
    expect(chain.active(1)).toBe(true)
    expect(actions()).toHaveLength(2)
    fake.answer = answer
    report = { kind: "form", form: 2, roles: ["password"], action: "password" }
    await chain.check(commit(GOOGLE, "password-doc"))
    expect(fills()).toHaveLength(1)
  })
  test("the return document receives a status before the confirmed success", async () => {
    await chain.start(home, linked)
    commit()
    const sender = commit(SITE, "returned")
    const answer = fake.answer
    fake.answer = (m, doc) => m.type === "db:auth-probe" ? { signOut: true, loginForm: false, uncertain: false, challenge: false } : answer(m, doc)
    await chain.check(sender)
    await until(() => fake.delivered.some((d) => d.message.label === "Signed in"))
    const statuses = fake.delivered.filter((d) => d.message.type === "db:provider-status" && (d.options as { documentId: string }).documentId === "returned")
    expect(statuses.map((d) => d.message.done ?? false)).toEqual([false, true])
    expect(chain.active(1)).toBe(false)
  })
  test("unowned WebAuthn calls keep their ordinary authority and behavior", async () => {
    await chain.start(home, linked)
    expect(keys.automaticSession!(home)).toBeUndefined()
    expect(await keys.automatic!(home, [])).toBeUndefined()
    commit()
    const target = { ...home, origin: GOOGLE, documentId: "provider-doc" }
    expect(keys.automaticSession!({ ...target, frameId: 2 })).toBeUndefined()
    expect(keys.automaticSession!({ ...target, documentId: "old" })).toBeUndefined()
    expect(await keys.automatic!({ ...target, frameId: 2 }, [])).toBeUndefined()
    expect(await keys.automatic!(target, [], true)).toBeUndefined()
    expect(chain.active(1)).toBe(true)
    expect(keys.automaticSession!(target)?.aborted).toBe(false)
  })
  test("concurrent popup events reserve only the first target", async () => {
    await chain.start(home, linked)
    fake.frames["2:0"] = { url: GOOGLE + "/v3/signin/identifier", documentId: "popup", parentFrameId: -1 }
    fake.frames["3:0"] = { url: GOOGLE + "/v3/signin/identifier", documentId: "popup-other", parentFrameId: -1 }
    await Promise.all([
      chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 2 }),
      chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 3 }),
    ])
    expect(chain.active(2)).toBe(true)
    expect(chain.active(3)).toBe(false)
  })
  test("concurrent passkey calls can consume only one assertion", async () => {
    await chain.start(home, linked)
    commit()
    report = { kind: "passkey", action: "key" }
    const target = { ...home, origin: GOOGLE, documentId: "provider-doc" }
    const passkey = { ref: providerAccount.ref, vault: "Personal", credentialId: "YQ", username: providerAccount.username }
    const choices = await Promise.all([keys.automatic!(target, [passkey]), keys.automatic!(target, [passkey])])
    expect(choices.filter(Boolean)).toHaveLength(1)
    expect(choices.find(Boolean)?.ref).toBe(providerAccount.ref)
    chain.stop(1)
    expect(choices.find(Boolean)?.signal.aborted).toBe(true)
  })
  test("an incoming passkey cannot race a pending password fill", async () => {
    await chain.start(home, linked)
    const sender = commit()
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    const release = host.holdFills()
    const pending = chain.check(sender)
    await until(() => fills().length === 1)
    const choice = await keys.automatic!({ ...home, origin: GOOGLE, documentId: "provider-doc" }, [
      { ref: providerAccount.ref, vault: "Personal", credentialId: "YQ", username: providerAccount.username },
    ])
    release()
    await pending
    expect(choice).toBeNull()
    expect(chain.active(1)).toBe(false)
    expect(actions()).toHaveLength(1)
  })
  test.each([
    "/security/signinoptions/password",
    "/v3/signin/reauth/pwd",
    "/settings/passkeys",
    "/v3/signin/challenge/pwd?continue=https%3A%2F%2Fmyaccount.google.com%2Fsecurity",
    "/o/oauth2/v2/auth?redirect_uri=https%3A%2F%2Fevil.test%2Fcb",
    "/o/oauth2/v2/auth?redirect_uri=https%3A%2F%2Fwww.example.com.evil.test%2Fcb",
    "/v3/signin/identifier?continue=" + encodeURIComponent(GOOGLE + "/signin/oauth?redirect_uri=https://evil.test/cb"),
  ])("a site button pointing at %s ends it untouched", async (path) => {
    await chain.start(home, linked)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    const sender = commit(GOOGLE, "provider-doc", 1, path)
    await chain.check(sender)
    expect(chain.active(1)).toBe(false)
    expect(fills()).toHaveLength(0)
    expect(fake.delivered.filter((d) => d.message.type === "db:provider-probe" && d.message.account)).toHaveLength(0)
  })
  test.each([
    "/o/oauth2/v2/auth?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
    "/v3/signin/challenge/pwd?continue=" + encodeURIComponent(GOOGLE + "/signin/oauth?redirect_uri=https://www.example.com/cb"),
  ])("a sign-in page whose return URL leads home, %s, goes on", async (path) => {
    await chain.start(home, linked)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check(commit(GOOGLE, "provider-doc", 1, path))
    expect(fills()).toHaveLength(1)
    expect(fake.delivered.find((d) => d.message.type === "db:provider-probe" && d.message.account)?.message.site).toBe("example.com")
  })
  test("a popup re-navigated off the sign-in path ends it before any value", async () => {
    await chain.start(home, linked)
    fake.frames["2:0"] = { url: GOOGLE + "/v3/signin/identifier", documentId: "popup", parentFrameId: -1 }
    await chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 2 })
    expect(chain.active(2)).toBe(true)
    report = { kind: "form", form: 1, roles: ["password"], action: "password" }
    await chain.check(commit(GOOGLE, "settings", 2, "/security/signinoptions/password"))
    expect(chain.active(2)).toBe(false)
    expect(fills()).toHaveLength(0)
  })
  test("a popup that opens straight onto a settings page is never followed", async () => {
    await chain.start(home, linked)
    fake.frames["2:0"] = { url: GOOGLE + "/settings/security", documentId: "popup", parentFrameId: -1 }
    await chain.opened({ sourceTabId: 1, sourceFrameId: 0, tabId: 2 })
    expect(chain.active(1)).toBe(false)
    expect(chain.active(2)).toBe(false)
  })
  test("only a linked pick of a provider with known hosts starts a chain", async () => {
    await chain.start(home, { ...providerAccount, urls: [SITE] })
    expect(chain.active(1)).toBe(false)
    await chain.start(home, { ...linked, signIn: { provider: "okta", account: providerAccount.username } })
    expect(chain.active(1)).toBe(false)
    await chain.start(home, { ...linked, signIn: { provider: "google" } })
    expect(chain.active(1)).toBe(false)
    expect(actions()).toHaveLength(0)
  })
  test("no state can restore authority after a worker restart", async () => {
    await chain.start(home, linked)
    const restarted = new ProviderChain(host.host, keys, new SignInWith(host.host))
    expect(restarted.active(1)).toBe(false)
    expect(fake.session).toEqual({})
    await restarted.check(commit())
    expect(actions()).toHaveLength(1)
  })
})
