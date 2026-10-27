import { describe, expect, test } from "bun:test"
import { Approvals } from "../src/content/approvals"
import type { Field } from "../src/content/detect"

const field = (role: Field["role"]): Field => {
  const el = document.createElement("input")
  return { el, role, owner: { form: null, parent: null } }
}

describe("Approvals", () => {
  const email = field("email")
  const password = field("password")

  test("a fill gets the approved fields, never one approved later or not at all", () => {
    const a = new Approvals()
    const id = a.grant(1, [email])
    expect(a.take(id, 1, [email, password])).toEqual([email])
  })

  test("only those still in the form", () => {
    const a = new Approvals()
    const id = a.grant(1, [email, password])
    expect(a.take(id, 1, [email])).toEqual([email])
  })

  test("the same element in another role isn't the approved field", () => {
    const a = new Approvals()
    const id = a.grant(1, [email])
    expect(a.take(id, 1, [{ ...email, role: "password" }])).toEqual([])
  })

  test("each approval fills once, for its own form snapshot", () => {
    const a = new Approvals()
    const id = a.grant(1, [email])
    expect(a.take(id, 1, [email])).toEqual([email])
    expect(a.take(id, 1, [email])).toBeNull()
    const other = a.grant(1, [email])
    expect(a.take(other, 2, [email])).toBeNull()
    expect(a.take("made-up", 1, [email])).toBeNull()
  })

  test("a later grant doesn't widen an earlier one", () => {
    const a = new Approvals()
    const first = a.grant(1, [email])
    a.grant(1, [email, password])
    expect(a.get(first, 1)).toEqual([email])
  })

  test("keeps only the latest few", () => {
    const a = new Approvals()
    const first = a.grant(1, [email])
    for (let i = 0; i < 4; i++) a.grant(1, [email])
    expect(a.get(first, 1)).toBeNull()
  })
})
