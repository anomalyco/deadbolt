import { describe, expect, test } from "bun:test"
import { isRef, parseHostMessage } from "../src/protocol"

const REF = `${"a".repeat(64)}:${"b".repeat(32)}`

describe("parseHostMessage", () => {
  test("hello", () => {
    const m = parseHostMessage({ id: 1, type: "hello", protocol: 1, version: "0.4.0", status: "locked", detail: "Unlock Deadbolt", capabilities: ["list", "fill", "check", "save"] })
    expect(m).toEqual({
      kind: "reply",
      id: 1,
      reply: { type: "hello", protocol: 1, version: "0.4.0", status: "locked", detail: "Unlock Deadbolt", capabilities: ["list", "fill", "check", "save"] },
    })
  })

  test("hello with an unknown status is rejected", () => {
    expect(parseHostMessage({ id: 1, type: "hello", protocol: 1, version: "x", status: "sleepy", capabilities: [] })).toBeNull()
  })

  test("list keeps only well-formed accounts and documented fields", () => {
    const m = parseHostMessage({
      id: 2,
      type: "list",
      site: "github.com",
      accounts: [
        { ref: REF, vault: "Personal", title: "GitHub", username: "octocat", hasPassword: true, hasTotp: true, urls: ["https://github.com"], extra: "x" },
        { ref: "not-a-ref", title: "Bad" },
        { ref: REF, vault: "Work", title: "No user", hasPassword: "yes", urls: [1, "https://github.com/x"] },
      ],
    })
    expect(m?.kind).toBe("reply")
    if (m?.kind !== "reply" || m.reply.type !== "list") throw new Error("expected a list")
    expect(m.reply.accounts).toEqual([
      { ref: REF, vault: "Personal", title: "GitHub", username: "octocat", hasPassword: true, hasTotp: true, urls: ["https://github.com"] },
      { ref: REF, vault: "Work", title: "No user", username: undefined, hasPassword: false, hasTotp: false, urls: ["https://github.com/x"] },
    ])
  })

  test("fill, check, save", () => {
    expect(parseHostMessage({ id: "3", type: "fill", username: "octocat", password: "hunter2" })).toEqual({
      kind: "reply",
      id: "3",
      reply: { type: "fill", username: "octocat", password: "hunter2", totp: undefined },
    })
    const check = parseHostMessage({ id: 4, type: "check", status: "update", matches: [REF, "nope"] })
    expect(check).toEqual({ kind: "reply", id: 4, reply: { type: "check", status: "update", matches: [REF] } })
    expect(parseHostMessage({ id: 5, type: "save", ref: REF, created: true })).toEqual({ kind: "reply", id: 5, reply: { type: "save", ref: REF, created: true } })
    expect(parseHostMessage({ id: 5, type: "save", ref: "x", created: true })).toBeNull()
  })

  test("errors, including unknown codes and a null id", () => {
    expect(parseHostMessage({ id: null, type: "error", code: "bad_request", message: "nope" })).toEqual({
      kind: "reply",
      id: null,
      reply: { type: "error", code: "bad_request", message: "nope" },
    })
    expect(parseHostMessage({ id: 6, type: "error", code: "mystery", message: "?" })).toEqual({
      kind: "reply",
      id: 6,
      reply: { type: "error", code: "failed", message: "?" },
    })
  })

  test("changed pushes carry no id", () => {
    expect(parseHostMessage({ type: "changed", change: "locked" })).toEqual({ kind: "changed", change: "locked" })
    expect(parseHostMessage({ type: "changed", change: "exploded" })).toBeNull()
  })

  test("replies without an id, unknown types and non-objects are dropped", () => {
    expect(parseHostMessage({ type: "list", site: "x", accounts: [] })).toBeNull()
    expect(parseHostMessage({ id: 1, type: "generate" })).toBeNull()
    expect(parseHostMessage(null)).toBeNull()
    expect(parseHostMessage([1, 2])).toBeNull()
    expect(parseHostMessage("hello")).toBeNull()
  })

  test("oversized strings are dropped", () => {
    const m = parseHostMessage({ id: 7, type: "fill", password: "x".repeat(5000), totp: "1".repeat(40) })
    expect(m).toEqual({ kind: "reply", id: 7, reply: { type: "fill", username: undefined, password: undefined, totp: undefined } })
  })
})

test("isRef", () => {
  expect(isRef(REF)).toBe(true)
  expect(isRef(REF.toUpperCase())).toBe(false)
  expect(isRef(`${REF}x`)).toBe(false)
  expect(isRef(42)).toBe(false)
})
