// Generated passwords on the page side: what a sign-up or change-password
// form's new-password boxes ask of a password (sent to the agent, which makes
// it), whether one fits their `pattern`, and which generated password was
// filled here, so a submit names it by id instead of sending it.
//
// A page's `pattern` is never run as a regular expression: a page can write
// one that takes forever. It's parsed instead, and only a small subset is
// understood: characters, character classes, `.`, `\d \w \s` and their
// opposites, the quantifiers `* + ? {n} {n,} {n,m}`, and `^` and `$` at the
// ends, in at most 200 characters. Anything else, such as groups,
// alternation or lookaheads, gets no generated password.

import type { FieldRules } from "../protocol"
import type { Field } from "./detect"

const PRINTABLE = Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)).join("")
const DIGIT = "0123456789"
const WORD = `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz${DIGIT}_`
const MAX_RULES = 1024
export const MAX_PATTERN = 200
const MAX_REPEAT = 1000
/** Characters an escape stands for themselves; outside a class, all but `/` must be escaped. */
const SYNTAX = "^$\\.*+?()[]{}|/"
/** Characters an escape inside a class stands for themselves (with the v flag). */
const CLASS_ESCAPES = `${SYNTAX}-&!#%,:;<=>@\`~`
/** Characters a class must escape, with the v flag. */
const CLASS_SYNTAX = "()[]{}/|"
/** Doubled, these are reserved inside a class with the v flag. */
const CLASS_DOUBLES = "&!#$%*+,.:;<=>?@^`~"

/** One step of a pattern: `min` to `max` characters, each one of `chars` (printable ASCII only). */
export interface Step {
  chars: string
  min: number
  max: number
}

const without = (all: string, out: string) => [...all].filter((c) => !out.includes(c)).join("")
const both = (a: string, b: string) => [...a].filter((c) => b.includes(c)).join("")

/** `\d`, `\w` and the rest, or null for an escape that isn't one. */
function classEscape(c: string | undefined): string | null {
  switch (c) {
    case "d":
      return DIGIT
    case "D":
      return without(PRINTABLE, DIGIT)
    case "w":
      return WORD
    case "W":
      return without(PRINTABLE, WORD)
    case "s":
      return " "
    case "S":
      return without(PRINTABLE, " ")
    default:
      return null
  }
}

/** The characters `[...]` takes, from just after the `[`, and where it ends; null outside the subset. */
function parseClass(p: string, i: number): { chars: string; next: number } | null {
  let negate = false
  if (p[i] === "^") {
    negate = true
    i++
  }
  const taken = new Set<string>()
  const add = (from: number, to: number) => {
    for (let code = Math.max(from, 32); code <= Math.min(to, 126); code++) taken.add(String.fromCharCode(code))
  }
  /** One character, or null for a class escape or something outside the subset. */
  const single = (): number | null => {
    const c = p[i]
    if (c === "\\") {
      if (!CLASS_ESCAPES.includes(p[i + 1] ?? "")) return null
      i += 2
      return p.charCodeAt(i - 1)
    }
    if (CLASS_SYNTAX.includes(c) || c === "-" || (CLASS_DOUBLES.includes(c) && p[i + 1] === c)) return null
    const code = p.codePointAt(i)!
    i += code > 0xffff ? 2 : 1
    return code
  }
  while (i < p.length && p[i] !== "]") {
    const set = p[i] === "\\" ? classEscape(p[i + 1]) : null
    if (set !== null) {
      for (const c of set) taken.add(c)
      i += 2
      continue
    }
    const lo = single()
    if (lo === null) return null
    if (p[i] === "-" && p[i + 1] !== "]") {
      i++
      const hi = single()
      if (hi === null || hi < lo) return null
      add(lo, hi)
    } else add(lo, lo)
  }
  if (p[i] !== "]") return null
  const chars = [...PRINTABLE].filter((c) => taken.has(c) !== negate).join("")
  return { chars, next: i + 1 }
}

/** The steps of a pattern in the subset (see the top of this file), or null for one outside it. */
export function parsePattern(pattern: string): Step[] | null {
  if (pattern.length > MAX_PATTERN) return null
  const steps: Step[] = []
  let i = pattern[0] === "^" ? 1 : 0
  while (i < pattern.length) {
    const c = pattern[i]
    let chars: string
    if (c === "$" && i === pattern.length - 1) break
    if (c === "[") {
      const set = parseClass(pattern, i + 1)
      if (!set) return null
      chars = set.chars
      i = set.next
    } else if (c === "\\") {
      const next = pattern[i + 1] ?? ""
      const set = classEscape(next) ?? (next && SYNTAX.includes(next) ? next : null)
      if (set === null) return null
      chars = set
      i += 2
    } else if (c === ".") {
      chars = PRINTABLE
      i++
    } else if (c >= " " && c <= "~" && (c === "/" || !SYNTAX.includes(c))) {
      chars = c
      i++
    } else return null
    let min = 1
    let max = 1
    const q = pattern[i]
    if (q === "*" || q === "+" || q === "?") {
      min = q === "+" ? 1 : 0
      max = q === "?" ? 1 : Infinity
      i++
    } else if (q === "{") {
      const m = /^\{(\d{1,4})(,(\d{0,4}))?\}/.exec(pattern.slice(i, i + 12))
      if (!m) return null
      min = Number(m[1])
      max = m[2] === undefined ? min : m[3] ? Number(m[3]) : Infinity
      if (min > MAX_REPEAT || max < min || (max !== Infinity && max > MAX_REPEAT)) return null
      i += m[0].length
    }
    // Lazy is the same set of strings.
    if (q && "*+?{".includes(q) && pattern[i] === "?") i++
    if (!chars) return null
    steps.push({ chars, min, max })
  }
  return steps
}

/** Whether `value` matches the steps, all of it: steps × length² work at most, and no value over 1000 characters. */
export function matches(steps: Step[], value: string): boolean {
  if (value.length > MAX_REPEAT) return false
  let at = new Set([0])
  for (const step of steps) {
    const next = new Set<number>()
    for (const start of at) {
      if (step.min === 0) next.add(start)
      for (let n = 1; n <= step.max && start + n <= value.length; n++) {
        if (!step.chars.includes(value[start + n - 1])) break
        if (n >= step.min) next.add(start + n)
      }
    }
    if (!next.size) return false
    at = next
  }
  return at.has(value.length)
}

/**
 * What a pattern asks of a password, when any password of those characters
 * and lengths matches it: every step takes the same characters (`\d{6}`,
 * `[A-Za-z0-9]{8,16}`, `.{8,}`). Null for one outside the subset, or one
 * that needs a mix, such as `[A-Z][a-z]+`.
 */
export function patternShape(pattern: string): { chars: string; min: number; max?: number } | null {
  const steps = parsePattern(pattern)
  if (!steps?.length || steps.some((s) => s.chars !== steps[0].chars)) return null
  const max = steps.reduce((n, s) => n + s.max, 0)
  return { chars: steps[0].chars, min: steps.reduce((n, s) => n + s.min, 0), max: max === Infinity ? undefined : max }
}

const limit = (n: number) => (n > 0 && n < 1000 ? n : undefined)

/**
 * What the new-password boxes ask of a password, the strictest of them, or
 * null when no generated password should be offered: a box's `pattern` is
 * outside the subset or needs a mix, or the lengths they allow don't meet.
 */
export function fieldRules(fields: Field[]): FieldRules | null {
  const boxes = fields.filter((f) => f.role === "new-password").map((f) => f.el)
  const rules: FieldRules = {}
  let lo = 0
  let hi = Infinity
  for (const el of boxes) {
    lo = Math.max(lo, limit(el.minLength) ?? 0)
    hi = Math.min(hi, limit(el.maxLength) ?? Infinity)
    const text = el.getAttribute("passwordrules")
    if (text && !rules.rules && text.length <= MAX_RULES) rules.rules = text
    const pattern = el.getAttribute("pattern")
    if (pattern === null || pattern === "") continue
    const shape = patternShape(pattern)
    if (!shape) return null
    lo = Math.max(lo, shape.min)
    hi = Math.min(hi, shape.max ?? Infinity)
    rules.allowed = rules.allowed === undefined ? shape.chars : both(rules.allowed, shape.chars)
    if (!rules.allowed) return null
  }
  if (lo > hi || hi === 0) return null
  if (lo > 0) rules.minLength = lo
  if (hi !== Infinity) rules.maxLength = hi
  return rules
}

/** Every new-password box's `pattern` takes `value`. One outside the subset takes nothing. */
export function fitsPattern(fields: Field[], value: string): boolean {
  return fields
    .filter((f) => f.role === "new-password")
    .every((f) => {
      const pattern = f.el.getAttribute("pattern")
      if (pattern === null || pattern === "") return true
      const steps = parsePattern(pattern)
      return !!steps && matches(steps, value)
    })
}

/**
 * The generated password last filled here and its id, and the last the agent
 * kept. Only in this content script's memory. Until the agent keeps one, a
 * submit sends it as typed: the agent couldn't resolve its id.
 */
let filled: { id: string; value: string } | null = null
let kept: { id: string; value: string } | null = null

export function rememberGenerated(id: string, value: string) {
  filled = { id, value }
}

/** The agent kept the generated password filled under `id`. */
export function keptGenerated(id: string) {
  if (filled?.id === id) kept = filled
}

/** The id of the generated password, if `value` is one the agent kept. */
export function generatedId(value: string | undefined): string | undefined {
  return kept && value === kept.value ? kept.id : undefined
}
