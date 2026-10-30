import { describe, expect, test } from "bun:test"
import { authState, exactSignInOrigin, matchesAccount, type AuthSignals } from "../src/auth-state"
import { authReport, takeSignInAction } from "../src/content/auth-state"
import type { PageState } from "../src/content/inline"

const blank: AuthSignals = { loginForm: false, loginRoute: false, entry: false, signOut: false, account: false, accountMenu: false, appShell: false, challenge: false, uncertain: false }
const state: PageState = { targets: () => [], form: () => 1, kind: () => null, rescan: () => {}, formFields: () => [], formsForm: () => 0 }

describe("auth state (suppression, not an authentication oracle)", () => {
  test("a login route alone and an empty app shell stay quiet", () => {
    expect(authState(blank)).toBe("unknown")
    expect(authState({ ...blank, loginRoute: true })).toBe("unknown")
    expect(authState({ ...blank, entry: true, appShell: true })).toBe("unknown")
  })
  test("a visible login form or explicit entry is actionable", () => {
    expect(authState({ ...blank, loginForm: true })).toBe("signed-out")
    expect(authState({ ...blank, entry: true })).toBe("signed-out")
  })
  test("signed-in evidence always beats even a visible login form", () => {
    for (const signal of ["signOut", "account"] as const)
      expect(authState({ ...blank, loginForm: true, entry: true, [signal]: true })).toBe("signed-in")
    expect(authState({ ...blank, loginForm: true }, true)).toBe("signed-in")
  })
  test("uncertainty, challenges and account controls veto offers", () => {
    for (const signal of ["uncertain", "challenge", "accountMenu"] as const)
      expect(authState({ ...blank, entry: true, [signal]: true })).toBe("unknown")
  })
  test("matching requires a full bounded username, never a partial email", () => {
    expect(matchesAccount("Welcome KIT@EXAMPLE.COM!", [" kit@example.com "])).toBe(true)
    expect(matchesAccount("Welcome kit", ["kit@example.com"])).toBe(false)
    expect(matchesAccount("notkit@example.com", ["kit@example.com"])).toBe(false)
    expect(matchesAccount("kit@example.com.evil", ["kit@example.com"])).toBe(false)
    expect(matchesAccount("kit@example.com", ["kit@example.co"])).toBe(false)
    expect(matchesAccount("Administrator", ["admin"])).toBe(false)
    expect(matchesAccount("my account", ["my"])).toBe(false)
  })
  test("only exact origins, not siblings, lookalikes, schemes or ports", () => {
    expect(exactSignInOrigin("https://example.com/login", "https://example.com")).toBe(true)
    for (const origin of ["https://accounts.example.com", "http://example.com", "https://example.com:444", "https://examp1e.com", "https://example.com.evil"])
      expect(exactSignInOrigin("https://example.com/login", origin)).toBe(false)
  })
  test("a dashboard's stray provider button is not a sign-in entry", () => {
    document.body.innerHTML = '<h1>Dashboard</h1><button>Sign in with Google</button><button>Sign out</button>'
    const facts = authReport(state, [])
    expect(facts.entry).toBe(false)
    expect(authState(facts)).toBe("signed-in")
  })
  test("visible matching account text suppresses; hidden and input values do not", () => {
    document.body.innerHTML = '<p>kit@example.com</p><a href="/login">Sign in</a>'
    expect(authReport(state, ["kit@example.com"]).account).toBe(true)
    document.body.innerHTML = '<p hidden>kit@example.com</p><input value="kit@example.com"><a href="/login">Sign in</a>'
    expect(authReport(state, ["kit@example.com"]).account).toBe(false)
  })
  test("a modal launcher can be an entry, but a cross-origin link cannot", () => {
    document.body.innerHTML = '<button>Sign in</button>'
    expect(authReport(state, []).entry).toBe(true)
    document.body.innerHTML = '<a href="https://evil.test/login">Sign in</a>'
    expect(authReport(state, []).entry).toBe(false)
  })
  test("a scan does not replace the picked probe's one-shot action", () => {
    document.body.innerHTML = '<button>Sign in</button>'
    const first = authReport(state, [])
    authReport(state, [])
    expect(takeSignInAction(first.action!, state)).not.toBeNull()
    expect(takeSignInAction(first.action!, state)).toBeNull()
  })
})
