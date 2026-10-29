// "Learn this site": while the user signs in by hand, every frame of the tab
// records the shape of each step (the inputs, what the detector made of
// them, which fields the user typed into and how the step was submitted) and
// the native host appends it to a log, one JSON line per step, for building
// the detector. Values are never recorded: a typed field gets only the shape
// of its value (email, digits, …), its length band (not for a secret), and
// whether it was the username of a saved login for the site, which the
// background decides from a salted digest. See docs/autofill.md, "Learning a site".

/** How long a learning session lasts unless it's stopped or the sign-in works first. */
export const LEARN_TTL_MS = 5 * 60_000
/** Caps that keep one step well under the host's 64 KiB request limit. */
export const MAX_INPUTS = 80
export const MAX_FRAMES = 20
export const MAX_TEXT = 80
export const MAX_STEPS = 200

/** What a typed value looked like. "secret": typed into a password box. */
export type ValueShape = "secret" | "email" | "phone" | "digits" | "text"
/** The value's length, in bands only. */
export type LengthBand = "1-3" | "4-8" | "9-16" | "17-32" | "33+"
/** The role the user's typing shows a field had: the label the detector is judged against. */
export type Truth = "username" | "email" | "phone" | "password" | "otp" | "other"
export type LearnTrigger = "start" | "change" | "submit"
export type SubmitBy = "click" | "enter" | "submit"
export type LearnEnd = "stopped" | "signed-in" | "timeout" | "closed" | "replaced"

export interface LearnRect {
  x: number
  y: number
  w: number
  h: number
}

/** What a learning session's frames are told: its id, the salt for username digests and when it ends. */
export interface LearnSession {
  id: string
  salt: string
  until: number
}

export interface Typed {
  /** 1 for the first field the user typed into in this document, then 2, … */
  order: number
  shape: ValueShape
  /** Not for a secret: a password's length is left out. */
  length?: LengthBand
  /** The value is what the user typed into an earlier field of this document (a confirmation box, an echoed username). */
  sameAs?: number
  /** Set by the background from `digest`: the value is the username of a saved login for the site. */
  savedUsername?: boolean
  /** SHA-256 of the session's salt and the value, for that check only. The background drops it before logging. */
  digest?: string
  truth: Truth
}

/** One input, in the corpus probe's terms (extension/corpus/probe.ts), plus what the user did with it. */
export interface LearnInput {
  i: number
  type: string
  name: string
  id: string
  autocomplete: string
  placeholder: string
  ariaLabel: string
  label: string
  maxLength: number
  inputMode: string
  visible: boolean
  inShadow: boolean
  inForm: boolean
  formActionHost: string
  rect: LearnRect
  /** The detector's role, null when it skipped the field or found no role. */
  role: string | null
  split?: number
  /** Outside the form the detector judged. */
  outOfScope?: boolean
  typed?: Typed
}

export interface LearnFrame {
  top: boolean
  /** How many frames up to the top page. */
  depth: number
  origin: string
  path: string
  /** The query's parameter names, never their values. */
  queryKeys: string[]
}

/** A step, as a content script sends it. */
export interface LearnStep {
  trigger: LearnTrigger
  /** Milliseconds since the frame joined the session. */
  at: number
  frame: LearnFrame
  title: string
  kind: string | null
  submit: { tag: string; type: string; text: string; rect: LearnRect } | null
  submitted?: { by: SubmitBy; text: string; detected: boolean }
  inputs: LearnInput[]
  shadowRoots: number
  iframes: Array<{ host: string; path: string; visible: boolean; rect: LearnRect }>
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const PHONE = /^\+?[\d\s().-]{7,20}$/
const DIGITS = /^\d+$/

export function shapeOf(value: string, type: string): ValueShape {
  const v = value.trim()
  if (type === "password") return "secret"
  if (EMAIL.test(v)) return "email"
  if (DIGITS.test(v)) return v.length <= 8 ? "digits" : "phone"
  if (PHONE.test(v) && v.replace(/\D/g, "").length >= 7) return "phone"
  return "text"
}

export function lengthBand(value: string): LengthBand {
  const n = [...value].length
  return n <= 3 ? "1-3" : n <= 8 ? "4-8" : n <= 16 ? "9-16" : n <= 32 ? "17-32" : "33+"
}

/**
 * What the typing shows the field was. A password box that repeats an
 * earlier one is still "password" here; telling confirmation and new
 * passwords apart is left to the report, which sees `sameAs`.
 */
export function truthOf(t: Pick<Typed, "shape" | "savedUsername">): Truth {
  if (t.shape === "secret") return "password"
  if (t.savedUsername) return t.shape === "email" ? "email" : t.shape === "phone" ? "phone" : "username"
  switch (t.shape) {
    case "email":
      return "email"
    case "phone":
      return "phone"
    case "digits":
      return "otp"
    default:
      return "username"
  }
}

/** A line of page text, trimmed and clipped. */
export const clip = (s: string | null | undefined, n = MAX_TEXT) => (s ?? "").replace(/\s+/g, " ").trim().slice(0, n)

/**
 * Page text with anything that may be the user's own taken out: email
 * addresses, runs of four or more digits, and the values typed in this
 * document (a step 2 that says "Signed in as kit" names the username).
 */
export function scrub(text: string, typed: Iterable<string> = []): string {
  let out = text
  for (const value of typed) {
    const v = value.trim()
    if (v.length >= 3) out = out.replace(new RegExp(v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), "<typed>")
  }
  return out.replace(/[\w.+%'-]+@[\w-]+(?:\.[\w-]+)+/g, "<email>").replace(/\d{4,}/g, "<n>")
}

/** Where a frame is, without the query's values or the fragment, its path and parameter names scrubbed like page text. */
export function frameOf(url: URL, top: boolean, depth: number, typed: Iterable<string> = []): LearnFrame {
  const values = [...typed]
  return {
    top,
    depth,
    origin: url.origin,
    path: scrub(clip(url.pathname, 200), values),
    queryKeys: [...new Set(url.searchParams.keys())].slice(0, 30).map((k) => scrub(clip(k, 40), values)),
  }
}

export async function sha256(text: string): Promise<string> {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)))
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

/** The digest a typed value and a saved username are compared by. */
export const usernameDigest = (salt: string, value: string) => sha256(`${salt}\u0000${value.trim().toLowerCase()}`)
