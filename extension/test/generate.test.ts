import { describe, expect, test } from "bun:test"
import { ownerOf, type Field } from "../src/content/detect"
import { fieldRules, fitsPattern, generatedId, keptGenerated, matches, parsePattern, patternShape, rememberGenerated } from "../src/content/generate"

function boxes(html: string): Field[] {
  document.body.innerHTML = `<form>${html}</form>`
  return [...document.querySelectorAll("input")].map((el) => ({ el, role: el.dataset.role as Field["role"], owner: ownerOf(el) }))
}

describe("fieldRules", () => {
  test("the strictest limits of the new-password boxes, and their passwordrules", () => {
    const fields = boxes(`<input data-role="password" maxlength="8"><input data-role="new-password" maxlength="20" minlength="8" passwordrules="required: digit;"><input data-role="new-password" maxlength="16">`)
    expect(fieldRules(fields)).toEqual({ maxLength: 16, minLength: 8, rules: "required: digit;" })
  })

  test("the characters and lengths a pattern takes, with the field's own limits", () => {
    expect(fieldRules(boxes(`<input data-role="new-password" pattern="[a-f0-9]{8,32}">`))).toEqual({ allowed: "0123456789abcdef", minLength: 8, maxLength: 32 })
    expect(fieldRules(boxes(`<input data-role="new-password" pattern="\\d{6}" maxlength="10">`))).toEqual({ minLength: 6, maxLength: 6, allowed: "0123456789" })
    expect(fieldRules(boxes(`<input data-role="new-password" pattern="^\\S{12,}$" maxlength="40" minlength="16">`))).toMatchObject({ minLength: 16, maxLength: 40 })
    // Two boxes: both patterns' characters, the tighter lengths.
    const two = boxes(`<input data-role="new-password" pattern="[a-z0-9]{8,64}"><input data-role="new-password" pattern="[0-9A-F]+" maxlength="30">`)
    expect(fieldRules(two)).toEqual({ allowed: "0123456789", minLength: 8, maxLength: 30 })
  })

  test("no generated password where the lengths can't meet, or a pattern is outside the subset or needs a mix", () => {
    const none = (html: string) => expect(fieldRules(boxes(html))).toBeNull()
    none(`<input data-role="new-password" pattern="\\d{6}" maxlength="4">`)
    none(`<input data-role="new-password" pattern="[a-z]{20,}" maxlength="16">`)
    none(`<input data-role="new-password" minlength="20" maxlength="16">`)
    none(`<input data-role="new-password" pattern="[a-z]+"><input data-role="new-password" pattern="[0-9]+">`)
    none(`<input data-role="new-password" pattern="(?=.*\\d)(?=.*[a-z]).{8,}">`)
    none(`<input data-role="new-password" pattern="[A-Z][a-z]{7,}">`)
    none(`<input data-role="new-password" pattern="[">`)
    none(`<input data-role="new-password" pattern="${"a".repeat(201)}">`)
    // An invalid pattern the browser ignores is still outside the subset.
    none(`<input data-role="new-password" pattern="[a-z-]{8,}">`)
  })
})

describe("patterns", () => {
  test("the subset: characters, classes, escapes, quantifiers and anchors", () => {
    expect(parsePattern("^[a-c]\\d{2,3}x*\\.?$")).toEqual([
      { chars: "abc", min: 1, max: 1 },
      { chars: "0123456789", min: 2, max: 3 },
      { chars: "x", min: 0, max: Infinity },
      { chars: ".", min: 0, max: 1 },
    ])
    expect(patternShape("[^a-z]+")?.chars).not.toMatch(/[a-z]/)
    expect(patternShape("[^a-z]+")?.chars).toContain("A")
    expect(patternShape("[\\w\\-!]{8,}")).toEqual({ chars: `!-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz`, min: 8, max: undefined })
    expect(patternShape(".{4}.{4,8}")).toMatchObject({ min: 8, max: 12 })
    expect(patternShape("a+?")).toEqual({ chars: "a", min: 1, max: undefined })
  })

  test("everything else is outside it", () => {
    for (const p of ["(a)", "a|b", "(?=a)", "a\\b", "\\1", "\\p{L}", "\\u0041", "\\x41", "a{2", "a{3,2}", "a{1001}", "a**", "^^a", "a$b", "[a&&b]", "[a--b]", "[[a]]", "[z-a]", "[\\d-z]", "[]", "a]", "a}", ""])
      expect(patternShape(p)).toBeNull()
  })

  test("a pattern built to backtrack forever is never run", () => {
    // Each of these takes a backtracking engine exponential time on a near miss.
    const evil = ["(a+)+$", "(a|a)*$", "(a|aa)+$", "(.*a){12}$", "^(\\w+\\s?)*$"]
    const real = RegExp
    const built: string[] = []
    // Nothing here may build a RegExp from the page's pattern (the DOM builds its own).
    ;(globalThis as { RegExp: unknown }).RegExp = new Proxy(real, {
      construct(target, args) {
        built.push(String(args[0]))
        return Reflect.construct(target, args)
      },
      apply(target, self, args) {
        built.push(String(args[0]))
        return Reflect.apply(target, self, args)
      },
    })
    try {
      const start = performance.now()
      for (const p of evil) {
        const fields = boxes(`<input data-role="new-password" pattern="${p}">`)
        expect(fieldRules(fields)).toBeNull()
        expect(fitsPattern(fields, `${"a".repeat(40)}!`)).toBe(false)
      }
      expect(performance.now() - start).toBeLessThan(200)
    } finally {
      ;(globalThis as { RegExp: unknown }).RegExp = real
    }
    expect(built.filter((source) => evil.some((p) => source.includes(p)))).toEqual([])
  })

  test("the matcher is the browser's on the subset", () => {
    const cases: Array<[string, string, boolean]> = [
      ["[a-f0-9]{8,32}", "deadbeef", true],
      ["[a-f0-9]{8,32}", "deadbee", false],
      ["[a-f0-9]{8,32}", "deadbeeg", false],
      ["\\d{6}", "123456", true],
      ["\\d{6}", "1234567", false],
      ["a*a*b", "aaab", true],
      ["a*a*b", "aaa", false],
      ["^\\S+$", "no spaces", false],
      [".{2,}x?", "ab", true],
    ]
    for (const [pattern, value, want] of cases) {
      expect(matches(parsePattern(pattern)!, value)).toBe(want)
      expect(new RegExp(`^(?:${pattern})$`, "v").test(value)).toBe(want)
    }
  })

  test("fitsPattern checks the whole value with every box's pattern", () => {
    const fields = boxes(`<input data-role="new-password" pattern="[a-z0-9]+"><input data-role="new-password">`)
    expect(fitsPattern(fields, "abc123")).toBe(true)
    expect(fitsPattern(fields, "abc123!")).toBe(false)
    expect(fitsPattern(boxes(`<input data-role="new-password" pattern="(?=.*\\d)[a-z0-9]+">`), "abc123")).toBe(false)
  })
})

test("only the value filled, once the agent kept it, names the generated password", () => {
  rememberGenerated("g1", "Generated-1")
  // Not kept yet: a submit sends it as typed.
  expect(generatedId("Generated-1")).toBeUndefined()
  keptGenerated("g0")
  expect(generatedId("Generated-1")).toBeUndefined()
  keptGenerated("g1")
  expect(generatedId("Generated-1")).toBe("g1")
  expect(generatedId("Generated-1 edited")).toBeUndefined()
  // A newer one the agent didn't keep yet names no id.
  rememberGenerated("g2", "Generated-2")
  expect(generatedId("Generated-2")).toBeUndefined()
  keptGenerated("g2")
  expect(generatedId("Generated-2")).toBe("g2")
})
