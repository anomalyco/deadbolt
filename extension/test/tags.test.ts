import { describe, expect, test } from "bun:test"
import type { ItemSummary } from "../src/messages"
import { matchesSearch, normalizeTag, sortItems } from "../src/vault/tags"

function item(title: string, opts: { favorite?: boolean; tags?: string[]; username?: string } = {}): ItemSummary {
  return {
    ref: `v:${title.toLowerCase()}`,
    kind: "login",
    title,
    username: opts.username,
    urls: [],
    search: [title.toLowerCase()],
    favorite: opts.favorite ?? false,
    tags: opts.tags ?? [],
  }
}

describe("vault favorites and nested tags", () => {
  test("normalizes slash hierarchies while preserving segment case", () => {
    expect(normalizeTag("  #Work / AWS ")).toBe("Work/AWS")
    expect(normalizeTag("Tax 2026")).toBe("Tax 2026")
    expect(normalizeTag("work//aws")).toBeNull()
    expect(normalizeTag("/work")).toBeNull()
    expect(normalizeTag("   ")).toBeNull()
  })

  test("sorts favorites ahead of non-favorites", () => {
    const sorted = sortItems([item("Zeta", { favorite: true }), item("Alpha"), item("Beta", { favorite: true })])
    expect(sorted.map((i) => i.title)).toEqual(["Beta", "Zeta", "Alpha"])
  })

  test("filters by #tag hierarchy, quoted tags, #tax-2026, and is:favorite", () => {
    const aws = item("GitHub", { favorite: true, tags: ["Work/AWS", "Tax 2026"] })
    const net = item("Router", { tags: ["network"] })
    const plain = item("Personal")

    expect(matchesSearch(aws, "#work", true)).toBe(true)
    expect(matchesSearch(net, "#work ", true)).toBe(false)
    expect(matchesSearch(aws, "#work/aws", true)).toBe(true)
    expect(matchesSearch(aws, '#"Tax 2026"', true)).toBe(true)
    expect(matchesSearch(aws, "#tax-2026", true)).toBe(true)
    expect(matchesSearch(aws, "is:favorite", true)).toBe(true)
    expect(matchesSearch(net, "is:favorite", true)).toBe(false)
    // Trailing bare `#` keeps tagged items visible while mid-typing.
    expect(matchesSearch(aws, "#", true)).toBe(true)
    expect(matchesSearch(plain, "#", true)).toBe(false)
    // Plain words also match tag names.
    expect(matchesSearch(aws, "aws", true)).toBe(true)
  })
})
