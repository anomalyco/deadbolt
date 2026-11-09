// Record (once "Learn this site"): while the user uses a page by hand, every
// frame of the tab records the shape of each step (the inputs, what the
// detector made of them, which fields the user typed into and how the step
// was submitted) and a timeline of what the user did (clicks, named keys,
// focus, typing by shape, submits, scrolls, navigations), and the native host
// appends it to a log, one JSON line per step or batch of the timeline, for
// fixing the detector. Values are never recorded: a typed field gets only the
// shape of its value (email, digits, …), its length band (not for a secret),
// and whether it was the username of a saved login for the site, which the
// background decides from a salted digest. See docs/autofill.md, "Recording a site".

/** How long a recording lasts unless it's stopped first. */
export const LEARN_TTL_MS = 10 * 60_000
/** A recording with no trusted input from the user for this long ends. */
export const IDLE_MS = 2 * 60_000
/** Caps that keep one step well under the host's 64 KiB request limit. */
export const MAX_INPUTS = 80
export const MAX_FRAMES = 20
export const MAX_TEXT = 80
export const MAX_STEPS = 200
/** A recording's timeline holds at most this many events; later ones are counted, not kept. */
export const MAX_EVENTS = 4000
/** Frames on another site than the page (ads, chat widgets) share their own, smaller caps. */
export const MAX_CROSS_EVENTS = 500
export const MAX_CROSS_STEPS = 20
/** And each cross-site origin its own share of those events: the start page's ads don't use up the provider page's. */
export const MAX_ORIGIN_EVENTS = 200
/** Digests of typed words a recording keeps, to scrub later pages' addresses and titles. */
export const MAX_WORDS = 500
/** What a frame sends of its timeline at once, and how often. */
export const EVENTS_PER_BATCH = 50
export const BATCH_MS = 500

/** What a typed value looked like. "secret": typed into a password box. */
export type ValueShape = "secret" | "email" | "phone" | "digits" | "text"
/** The value's length, in bands only. */
export type LengthBand = "1-3" | "4-8" | "9-16" | "17-32" | "33+"
/** The role the user's typing shows a field had: the label the detector is judged against. */
export type Truth = "username" | "email" | "phone" | "password" | "otp" | "other"
export type LearnTrigger = "start" | "change" | "submit"
export type SubmitBy = "click" | "enter" | "submit"
/** `left`: the user took the tab to another site themselves; `idle`: no input for IDLE_MS. */
export type LearnEnd = "stopped" | "timeout" | "idle" | "left" | "closed" | "replaced"
/** What the background answers a frame's step or events: taken, refused (the recording is gone), or full (it goes on, this frame's share isn't kept). */
export type LearnTaken = true | false | "full"

export interface LearnRect {
  x: number
  y: number
  w: number
  h: number
}

/**
 * What a recording's frames are told: its id, the salt for username and
 * word digests, when it started (timeline times count from it), when it
 * ends, and the digests of the words typed in it so far, so a page that
 * loads later scrubs its own address and title of them.
 */
export interface LearnSession {
  id: string
  salt: string
  startedAt: number
  until: number
  words: string[]
}

/**
 * An element the user acted on, in the probe's terms: never its value, and
 * text only for a button or link (40 characters), scrubbed like page text.
 */
export interface Target {
  tag: string
  type?: string
  name?: string
  id?: string
  role?: string
  label?: string
  autocomplete?: string
  text?: string
  /** A short selector path, up to four elements: `form#login > div.row > input[name=email]`. */
  path: string
  inShadow?: boolean
  /** The detector's role for a field, as of the frame's last step. */
  detected?: string
  /** A key of a keypad (one or two characters, or one of a cluster of small same-size controls): its text and label, and the pointer's place, are left out. */
  keypad?: boolean
}

export type TimelineType =
  | "pointerdown"
  | "pointerup"
  | "click"
  | "dblclick"
  | "key"
  | "focus"
  | "blur"
  | "input"
  | "change"
  | "submit"
  | "scroll"
  | "unload"
  // From the background: what Chrome saw of the tab.
  | "navigate"
  | "popup"
  | "signed-in"

/** One thing the user did, or that happened to the tab, `t` ms after the recording started. */
export interface TimelineEvent {
  t: number
  type: TimelineType
  target?: Target
  /** Viewport coordinates of a pointer event. */
  x?: number
  y?: number
  /** A named key (`Enter`, `Tab`, `ArrowDown`, …), or `char` for any printable one. */
  key?: string
  /** Modifiers held, as `alt+ctrl+meta+shift` in that order. */
  mods?: string
  /** What the field holds after typing, by shape: never the value. */
  shape?: ValueShape
  length?: LengthBand
  /** The kind of input (`insertText`, `insertFromPaste`, `deleteContentBackward`, …), the last of those merged: typing in one field close together is one event, and how many keystrokes it was isn't kept (that would be the value's length). */
  inputType?: string
  /** A submit's control. */
  submitter?: Target
  /** Where a page or frame went: origin, path and the query's parameter names. */
  frame?: LearnFrame
  /** Set by the background: which frame it came from and whether that's on the page's site. */
  frameId?: number
  sameSite?: boolean
  transition?: string
  /** Events a frame couldn't send (too many, too fast). */
  dropped?: number
}

/** Keys recorded by name; any other key with a printable character is `char`. */
const NAMED_KEYS = new Set([
  "Enter", "Tab", "Escape", "Backspace", "Delete", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Home", "End", "PageUp", "PageDown",
  "Shift", "Control", "Alt", "Meta", "CapsLock", "Insert", "ContextMenu",
  "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
])

/** The name a keydown is recorded by: never which character it typed. */
export const keyName = (key: string) => (NAMED_KEYS.has(key) ? key : "char")

export const modsOf = (e: { altKey: boolean; ctrlKey: boolean; metaKey: boolean; shiftKey: boolean }) =>
  [e.altKey && "alt", e.ctrlKey && "ctrl", e.metaKey && "meta", e.shiftKey && "shift"].filter(Boolean).join("+")

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
  /** The page's title, on a frame's start step only, scrubbed of typed words. */
  title?: string
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
export const scrub = (text: string, typed: Iterable<string> = []): string => scrubber(typed)(text)

/** A target's text: scrubbed, then with every digit taken out, since a keypad's keys are digits one at a time. */
export const noDigits = (text: string) => text.replace(/\d+/g, "<n>").replace(DIGIT_WORDS, "<n>")

const DIGIT_WORDS = /\b(?:zero|one|two|three|four|five|six|seven|eight|nine)\b/gi

/**
 * Whether a control's text or label reads as a keypad's key: one or two
 * characters, a digit or a digit's word, a phone pad's letters ("2 ABC",
 * "PQRS"), or both. A PIN or a word typed on one would be its keys in order.
 */
export const keypadText = (text: string) => {
  const t = text.trim()
  return t !== "" && (t.length <= 2 || /^(?:\d|zero|one|two|three|four|five|six|seven|eight|nine)?\s*(?:abc|def|ghi|jkl|mno|pqrs|tuv|wxyz|\+|\*|#)?$/i.test(t))
}

/** A keypad key's selector path, tags only: an id or a class (`key-h`) would name the key. */
export const tagsOnly = (path: string) =>
  path
    .split(">")
    .map((p) => p.trim().match(/^[a-z][a-z0-9-]*/i)?.[0] ?? "")
    .filter(Boolean)
    .join(" > ")

/** `scrub` for many texts and the same typed values: their pattern is built once, longest first. */
export function scrubber(typed: Iterable<string> = []): (text: string) => string {
  const values = [...new Set([...typed].map((v) => v.trim()).filter((v) => v.length >= 3))].sort((a, b) => b.length - a.length)
  const own = values.length ? new RegExp(values.map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "gi") : null
  return (text) => (own ? text.replace(own, "<typed>") : text).replace(/[\w.+%'-]+@[\w-]+(?:\.[\w-]+)+/g, "<email>").replace(/\d{4,}/g, "<n>")
}

/** Typed words, by salted digest: `salt` is the recording's. */
export interface Words {
  salt: string
  digests: ReadonlySet<string>
}

/** The digest a typed word and a word of a later page's address or title are compared by. */
export const wordDigest = (salt: string, word: string) => sha256(`${salt}\u0002${word.toLowerCase()}`)

/** The words of a typed value worth a digest: three letters or digits or more, at most 20 of them. */
export const wordsOf = (value: string) => [...new Set(value.toLowerCase().match(/[\p{L}\p{N}]{3,}/gu) ?? [])].slice(0, 20)

/** A typed value's words of one or two letters, a to z: only a path segment that's one of them is scrubbed (`<seg>`). */
export const shortWordsOf = (value: string) => [...new Set(value.toLowerCase().match(/(?<![a-z0-9])[a-z]{1,2}(?![a-z0-9])/g) ?? [])].slice(0, 10)

/** `text` with each word whose digest is a typed word's replaced by `<typed>`. */
export async function scrubWords(text: string, words?: Words): Promise<string> {
  if (!words?.digests.size || !text) return text
  const found = text.match(/[\p{L}\p{N}]{3,}/gu) ?? []
  const typed = new Set<string>()
  for (const w of new Set(found.slice(0, 40))) if (words.digests.has(await wordDigest(words.salt, w))) typed.add(w)
  return typed.size ? text.replace(/[\p{L}\p{N}]{3,}/gu, (w) => (typed.has(w) ? "<typed>" : w)) : text
}

const decode = (s: string) => {
  try {
    return decodeURIComponent(s)
  } catch {
    return s
  }
}

/** A path segment is kept only if it reads as a route word; anything else (an id, a token, a search) is `<seg>`. */
export const ROUTE_WORD = /^[a-z_-]{1,24}$/

/**
 * Where a frame is, without the query's values or the fragment. The path is
 * decoded, then each segment kept only if it reads as a route word and isn't
 * a typed word; parameter names are scrubbed like page text and of typed words.
 */
export async function frameOf(url: URL, top: boolean, depth: number, typed: Iterable<string> = [], words?: Words): Promise<LearnFrame> {
  const values = [...typed]
  const own = scrubber(values)
  const short = new Set(values.flatMap(shortWordsOf))
  const segments = await Promise.all(
    url.pathname
      .split("/")
      .slice(0, 30)
      .map(async (raw, i) => {
        if (i === 0 || raw === "") return raw
        const seg = decode(raw)
        if (!ROUTE_WORD.test(seg) || own(seg) !== seg) return "<seg>"
        // A one- or two-letter word typed before: `/u/kv` names whoever typed "kv".
        if (/^[a-z]{1,2}$/.test(seg) && (short.has(seg) || (words && words.digests.has(await wordDigest(words.salt, seg))))) return "<seg>"
        return (await scrubWords(seg, words)) === seg ? seg : "<typed>"
      }),
  )
  const keys = [...new Set(url.searchParams.keys())].slice(0, 30)
  return {
    top,
    depth,
    origin: url.origin,
    path: segments.join("/").slice(0, 200),
    queryKeys: await Promise.all(keys.map(async (k) => noDigits(await scrubWords(own(clip(k, 40)), words)))),
  }
}

export async function sha256(text: string): Promise<string> {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)))
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

/** The digest a typed value and a saved username are compared by. */
export const usernameDigest = (salt: string, value: string) => sha256(`${salt}\u0000${value.trim().toLowerCase()}`)
