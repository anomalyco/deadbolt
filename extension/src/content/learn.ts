// Record, in each frame (see src/learn.ts). While the tab is recording, the
// frame records a step when the recording starts, when its inputs change and
// when the user submits, and sends it to the background. It finds submits on
// its own, not through the detector's form: a page the detector gets wrong is
// what recording is for. It also keeps a timeline of what the user does here
// (pointer, named keys, focus, typing by shape, submits, scrolls), sent in
// batches. Its listeners are only on while the tab records, passive, and do
// little per event: no layout reads beyond a scrolled element's offset and,
// for a click, the size of the controls around it (a keypad's). A frame
// sends nothing until the background tells it the tab records (on its
// DOMContentLoaded), so a page nobody records costs no message.
//
// Nothing typed leaves the frame. For each field the user typed into it keeps
// two digests from the last trusted keystroke (to tell a repeated value and,
// in the background, a saved username) and, for fields that aren't password
// boxes, the value itself in memory only, to scrub it out of page text. Both
// go when the session ends. A field that was a password box at any point of
// the session, or that the detector takes for one, stays secret: a
// show-password toggle doesn't turn it into a username. Words typed outside
// password boxes also go to the background as salted digests, so it, and
// the pages that load after, scrub addresses and titles of them.

import type { LearnSession, LearnStep, LearnInput, LearnTaken, LearnTrigger, SubmitBy, Target, TimelineEvent, TimelineType, Typed, Words } from "../learn"
import { BATCH_MS, clip, EVENTS_PER_BATCH, frameOf, keyName, keypadText, lengthBand, MAX_FRAMES, MAX_INPUTS, modsOf, noDigits, scrubber, scrubWords, sha256, shapeOf, shortWordsOf, truthOf, usernameDigest, wordDigest, wordsOf } from "../learn"
import type { ToBackground, ToContent } from "../messages"
import { controlText, isVisible, masked, scanPage } from "./detect"
import { deepQueryAll, eventTarget, openRoots, shadowRootOf } from "./shadow"

const SKIP = new Set(["hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file", "range", "color"])
const CLICKABLE = 'button, [role=button], input[type=submit], input[type=button], input[type=image], a[href^="javascript"], a[href="#"]'
const SUBMIT_DEDUPE_MS = 800
/** What a timeline names as the element acted on: the control around what was hit. */
const INTERACTIVE = 'a[href], button, input, select, textarea, label, summary, [role], [contenteditable=""], [contenteditable="true"], [tabindex]'
const TEXTUAL = new Set(["a", "button", "summary"])
const TEXT_ROLES = new Set(["button", "link", "tab", "menuitem", "option", "checkbox", "radio", "switch"])
/** Keys a password box gets recorded, unmodified: the rest would tell its length or where its capitals are. */
const SECRET_KEYS = new Set(["Enter", "Tab", "Escape"])
/** Typed text matched whole against page text, per field: this much. Its words are matched however long it is (MAX_KEPT). */
const MAX_TYPED = 256
const MAX_KEPT = 10_000
/** Text that may be what the user is typing, or what the page says back: never a label's. */
const LIVE = 'input, textarea, select, output, [contenteditable=""], [contenteditable="true"], [aria-live], [role="status"], [role="alert"], [role="log"]'
/** A keypad: at least this many small controls of one size in a row or pad around the one acted on, this many containers up. */
const KEYPAD_KEYS = 3
const KEYPAD_UP = 4
const KEYPAD_SIZE = 120
/** Typing in one field this close together is one input event. */
const INPUT_MERGE_MS = 1000
const SCROLL_EVERY_MS = 500
/** A frame's timeline: a burst, then a steady rate; the rest is counted as dropped. */
const RATE = { capacity: 60, perSecond: 20 }
const LISTEN = { capture: true, passive: true } as const

interface Keyed {
  order: number
  /** SHA-256 of the salt and the exact value: for `sameAs`, never sent. */
  exact: Promise<string>
  /** For the saved-username check; not kept for password boxes. */
  digest?: Promise<string>
}

let session: LearnSession | null = null
let joinedAt = 0
let typedCount = 0
let keyed = new WeakMap<HTMLInputElement, Keyed>()
/** Fields that were password boxes, or that the detector took for one, this session. */
let secrets = new WeakSet<HTMLInputElement>()
/** Values typed into fields that aren't password boxes, to scrub page text; and their pattern, built when they change. */
let identifiers = new Set<string>()
let scrubTyped: ((text: string) => string) | null = null
/** Which elements are a keypad's keys, as found (see inKeypad). */
let keypads = new WeakMap<Element, boolean>()
/** The frame's batches, sent one after another. */
let sending: Promise<void> = Promise.resolve()
/** Each field's latest typed value, and the salted digests of typed words (sent: the background has them). */
let latest = new Map<Element, string>()
let wordDigests = new Map<string, string>()
let sentWords = new Set<string>()
/** The background said the recording is full: this frame stops sending events, or steps. */
let eventsFull = false
let stepsFull = false
let lastSignature = ""
let lastSubmitAt = -Infinity
let timer: ReturnType<typeof setTimeout> | undefined
/** The detector's role for each field, as of the frame's last step. */
let detected = new WeakMap<Element, string>()
// The timeline: events waiting for their batch, typing waiting to be merged, the rate's tokens.
let queue: TimelineEvent[] = []
let typing: { el: Element; event: TimelineEvent; at: number; secret: boolean } | null = null
let flushTimer: ReturnType<typeof setTimeout> | undefined
let tokens = RATE.capacity
let refilledAt = 0
let dropped = 0
let lastScrollAt = -Infinity
let lastKeyTarget: Element | null = null
let listening = false

const isTop = window === window.top

/** The tab is learning: the inline menu stays away so the user signs in by hand. */
export const learning = () => session !== null && Date.now() < session.until

function send(message: ToBackground): Promise<unknown> {
  return chrome.runtime.sendMessage(message).catch(() => null)
}

function depth(): number {
  let w: Window = window
  let d = 0
  while (w !== w.top && d < 20) {
    w = w.parent
    d++
  }
  return d
}

function rectOf(el: Element) {
  const r = el.getBoundingClientRect()
  return { x: Math.round(r.left + scrollX), y: Math.round(r.top + scrollY), w: Math.round(r.width), h: Math.round(r.height) }
}

/** An element's own text, without what's in fields, editable or live parts of it: what the user typed, or the page echoes. */
function staticText(el: Element | null | undefined, max = 200): string {
  if (!el || el.matches(LIVE)) return ""
  let out = ""
  const walk = document.createTreeWalker(el, NodeFilter.SHOW_TEXT)
  for (let n = walk.nextNode(); n && out.length < max; n = walk.nextNode()) {
    const parent = n.parentElement
    if (parent && parent !== el && parent.closest(LIVE) && el.contains(parent.closest(LIVE))) continue
    out += n.nodeValue ?? ""
  }
  return out.slice(0, max)
}

/** A field's labels and the elements that label it, by their own text only (see staticText). */
function labelOf(el: Element): string {
  const parts: string[] = []
  for (const l of Array.from((el as HTMLInputElement).labels ?? [])) parts.push(staticText(l))
  const by = el.getAttribute("aria-labelledby")
  const root = el.getRootNode() as Document | ShadowRoot
  if (by) for (const id of by.split(/\s+/).slice(0, 3)) parts.push(staticText(root.getElementById?.(id)))
  return clip([...new Set(parts.map((p) => clip(p)).filter(Boolean))].join(" "))
}

function hostOf(url: string): string {
  try {
    return new URL(url, location.href).hostname
  } catch {
    return ""
  }
}

const eligible = (el: HTMLInputElement) => !SKIP.has((el.getAttribute("type") || "text").toLowerCase())

function inputsNow(): HTMLInputElement[] {
  const all = deepQueryAll<HTMLInputElement>("input", openRoots()).slice(0, 300).filter(eligible)
  if (session) for (const el of all) if (masked(el)) secrets.add(el)
  return all
}

/** Forgets what was kept of a field's value that turned out to be secret. */
function makeSecret(el: HTMLInputElement) {
  secrets.add(el)
  const k = keyed.get(el)
  if (k?.digest) keyed.set(el, { order: k.order, exact: k.exact })
  identifiers.delete(el.value.trim())
  latest.delete(el)
  // Words of it not sent yet stay here; sent ones only ever scrub.
  for (const w of wordsOf(el.value)) if (!sentWords.has(wordDigests.get(w) ?? "")) wordDigests.delete(w)
  scrubTyped = null
}

/**
 * A field's typed text, to scrub page text of and to send as word digests.
 * Typing on keeps only the newest value; one that doesn't go on from the last
 * (an edit) keeps both.
 */
function remember(el: Element, raw: string) {
  const value = raw.trim().slice(0, MAX_KEPT)
  const prev = latest.get(el)
  if (prev && prev.length >= 3 && !value.startsWith(prev)) identifiers.add(prev)
  latest.set(el, value)
  scrubTyped = null
  if (!session) return
  const salt = session.salt
  for (const w of [...wordsOf(value), ...shortWordsOf(value)]) if (!wordDigests.has(w)) void wordDigest(salt, w).then((d) => session?.salt === salt && wordDigests.set(w, d))
}

/** Every typed value still to scrub page text of: the fields' latest, and earlier ones edited away. */
const typedValues = () => [...identifiers, ...latest.values()].map((v) => v.slice(0, MAX_TYPED))

/**
 * Page text scrubbed of what was typed in this frame: each typed value whole,
 * then any word that's a typed word or the start of one (three letters or
 * more), however long the text typed: an echo cut short ("Send kit vogel
 * secr…") names it as well as a whole one.
 */
function ownScrubber(): (text: string) => string {
  const whole = scrubber(typedValues())
  const starts = new Set<string>()
  for (const v of [...identifiers, ...latest.values()])
    for (const w of new Set(v.toLowerCase().match(/[\p{L}\p{N}]{3,}/gu) ?? [])) for (let i = 3; i <= Math.min(w.length, 40); i++) starts.add(w.slice(0, i))
  if (!starts.size) return whole
  return (text) => whole(text).replace(/[\p{L}\p{N}]{3,}/gu, (w) => (starts.has(w.toLowerCase()) ? "<typed>" : w))
}

function onInput(event: Event) {
  if (!session || !event.isTrusted) return
  const el = eventTarget(event)
  typedInto(event, el)
  if (el instanceof HTMLTextAreaElement) return remember(el, el.value)
  if (el instanceof HTMLElement && el.isContentEditable) return remember(el, el.textContent ?? "")
  if (!(el instanceof HTMLInputElement) || !eligible(el)) return
  const salt = session.salt
  if (masked(el)) secrets.add(el)
  const secret = secrets.has(el)
  const order = keyed.get(el)?.order ?? ++typedCount
  const value = el.value
  keyed.set(el, {
    order,
    exact: sha256(`${salt}\u0001${value}`),
    ...(secret ? {} : { digest: usernameDigest(salt, value) }),
  })
  if (!secret) remember(el, value)
}

/** Whether the typed value repeats an earlier field's: the order of that field. */
async function repeated(el: HTMLInputElement, own: Keyed, typed: HTMLInputElement[]): Promise<number | undefined> {
  const mine = await own.exact
  for (const other of typed) {
    const k = keyed.get(other)
    if (!k || other === el || k.order >= own.order) continue
    if ((await k.exact) === mine) return k.order
  }
  return undefined
}

/** One step of this frame, or null when the frame has nothing worth a line. */
export async function snapshot(trigger: LearnTrigger, submitted?: { by: SubmitBy; control: Element | null }): Promise<LearnStep | null> {
  if (!session) return null
  const roots = openRoots()
  const all = inputsNow()
  const typedEls = all.filter((el) => keyed.has(el) && el.value)
  // Every typed field, then the rest, up to the cap.
  const picked = [...typedEls, ...all.filter((el) => !typedEls.includes(el))].slice(0, MAX_INPUTS)
  picked.sort((a, b) => all.indexOf(a) - all.indexOf(b))
  if (!isTop && trigger !== "submit" && !picked.some((el) => isVisible(el))) return null

  let result: ReturnType<typeof scanPage> | null = null
  try {
    result = scanPage()
  } catch {
    result = null
  }
  const roles = new Map(result?.fields.map((f) => [f.el, f]) ?? [])
  detected = new WeakMap()
  for (const f of result?.fields ?? []) if (f.role) detected.set(f.el, f.role)
  for (const f of result?.fields ?? []) if (f.role === "password" || f.role === "new-password") makeSecret(f.el)
  const form = result?.fields.find((f) => f.owner.form)?.owner.form ?? null
  const values = [...typedValues(), ...typedEls.filter((el) => !secrets.has(el)).map((el) => el.value)]
  const words = known()
  const own = (scrubTyped ??= ownScrubber())
  const scrubValues = scrubber(values)
  const text = (s: string | null | undefined, n?: number) => clip(own(scrubValues(clip(s, 1000))), n)

  const inputs: LearnInput[] = []
  for (const [i, el] of picked.entries()) {
    const type = (el.getAttribute("type") || "text").toLowerCase()
    const f = roles.get(el)
    const k = keyed.get(el)
    let typed: Typed | undefined
    if (k && el.value) {
      const secret = secrets.has(el)
      const shape = shapeOf(el.value, secret ? "password" : type)
      const sameAs = await repeated(el, k, typedEls)
      const digest = !secret && k.digest ? await k.digest : undefined
      typed = {
        order: k.order,
        shape,
        ...(secret ? {} : { length: lengthBand(el.value) }),
        ...(sameAs ? { sameAs } : {}),
        ...(digest ? { digest } : {}),
        truth: truthOf({ shape }),
      }
    }
    const owner = el.form ?? el.closest("form")
    inputs.push({
      i,
      type,
      name: text(el.getAttribute("name")),
      id: text(el.id),
      autocomplete: text(el.getAttribute("autocomplete")).toLowerCase(),
      placeholder: text(el.placeholder),
      ariaLabel: text(el.getAttribute("aria-label")),
      label: text(labelOf(el)),
      maxLength: el.maxLength > 0 ? el.maxLength : 0,
      inputMode: text(el.getAttribute("inputmode")),
      visible: isVisible(el),
      inShadow: el.getRootNode() instanceof ShadowRoot,
      inForm: !!owner,
      formActionHost: owner ? text(hostOf(owner.getAttribute("action") || location.href)) : "",
      rect: rectOf(el),
      role: f?.role ?? null,
      ...(f?.split ? { split: f.split } : {}),
      ...(form && !form.contains(el) ? { outOfScope: true } : {}),
      ...(typed ? { typed } : {}),
    })
  }

  const submit = result?.submit
  const iframes = deepQueryAll<HTMLIFrameElement>("iframe", roots)
    .slice(0, MAX_FRAMES)
    .map((f) => {
      let url: URL | null = null
      try {
        url = new URL(f.getAttribute("src") || "about:blank", location.href)
      } catch {
        url = null
      }
      return { url, visible: isVisible(f), rect: rectOf(f) }
    })
  const iframePaths = await Promise.all(iframes.map((f) => (f.url ? frameOf(f.url, false, 0, values, words) : null)))
  // A control's text, unless it's a keypad's key: one or two characters, digits out.
  const controlOf = (el: Element) => {
    const t = text(controlText(el), 40)
    return t.length <= 2 ? "" : noDigits(t)
  }

  return {
    trigger,
    at: Math.round(performance.now() - joinedAt),
    frame: await frameOf(new URL(location.href), isTop, depth(), values, words),
    // A later step's title may name what was just typed elsewhere: only the page's first.
    ...(trigger === "start" ? { title: await scrubWords(text(document.title, 120), words) } : {}),
    kind: result?.kind ?? null,
    submit: submit
      ? { tag: submit.tagName.toLowerCase(), type: clip(submit.getAttribute("type"), 20), text: controlOf(submit), rect: rectOf(submit) }
      : null,
    ...(submitted
      ? { submitted: { by: submitted.by, text: submitted.control ? controlOf(submitted.control) : "", detected: !!submitted.control && submitted.control === submit } }
      : {}),
    inputs,
    shadowRoots: roots.length - 1,
    iframes: iframes.map((f, i) => ({ host: text(f.url?.hostname), path: iframePaths[i]?.path ?? "", visible: f.visible, rect: f.rect })),
  }
}

/** The typed words this recording knows of, by digest: the background's (other pages') and this frame's. */
function known(): Words | undefined {
  if (!session) return undefined
  return { salt: session.salt, digests: new Set([...session.words, ...wordDigests.values()]) }
}

async function record(trigger: LearnTrigger, submitted?: { by: SubmitBy; control: Element | null }) {
  if (stepsFull) return
  const step = await snapshot(trigger, submitted).catch(() => null)
  if (!step || !session) return
  const id = session.id
  const taken = (await send({ type: "db:learn-step", session: id, step })) as LearnTaken | null
  // Full: the recording goes on, this frame's steps aren't kept.
  if (taken === "full") stepsFull = true
  // The background no longer has the session (it ended, or the service worker
  // lost it): end it here too, so the inline menu comes back.
  else if (taken !== true && session?.id === id) end()
}

/** The inputs that show and the detector's verdict: a new one is a new step. */
function signature(): string {
  const shown = inputsNow()
    .filter((el) => isVisible(el))
    .map((el) => `${el.type}#${el.id}.${el.name}`)
  let kind: string | null = null
  try {
    kind = scanPage().kind
  } catch {
    kind = null
  }
  return JSON.stringify([location.pathname, kind, shown])
}

/** Called after each of the content script's scans: records a step when what shows changed. */
export function learnScanned() {
  if (!learning()) return
  const sig = signature()
  if (sig === lastSignature) return
  lastSignature = sig
  void record("change")
}

function submittedBy(by: SubmitBy, control: Element | null) {
  if (!learning()) return
  const now = performance.now()
  if (now - lastSubmitAt < SUBMIT_DEDUPE_MS) return
  lastSubmitAt = now
  void record("submit", { by, control })
}

/** What the event is about, inside closed shadow roots too (see shadow.ts). */
const realTarget = (event: Event) => {
  const t = eventTarget(event)
  return t instanceof Element ? t : t instanceof Node ? t.parentElement : null
}

// ---- The timeline -------------------------------------------------------------

/** Page text in a timeline, scrubbed of what the user typed here and of every digit, then clipped (so no clipped address escapes). */
const said = (s: string | null | undefined, n = 80) => clip(noDigits((scrubTyped ??= ownScrubber())(clip(s, 1000))), n)

/** `form#login > div.row > input[name=email]`: up to four elements, in the element's own root. */
function pathOf(el: Element, keypad = false): string {
  const parts: string[] = []
  for (let e: Element | null = el; e && parts.length < 4; e = e.parentElement) {
    // A keypad key's path is tags only: an id or class (key-h) names the key.
    if (keypad) {
      parts.unshift(e.tagName.toLowerCase())
      continue
    }
    const tag = e.tagName.toLowerCase()
    const name = e.getAttribute("name")
    const cls = typeof e.className === "string" ? e.className.trim().split(/\s+/)[0] : ""
    parts.unshift(said(e.id ? `${tag}#${e.id}` : name ? `${tag}[name=${name}]` : cls ? `${tag}.${cls}` : tag, 40))
    if (e.id) break
  }
  return parts.join(" > ")
}

const labelText = (el: Element) => labelOf(el) || el.getAttribute("aria-label") || el.getAttribute("placeholder") || el.getAttribute("title") || el.getAttribute("alt") || ""

/**
 * Whether `el` is one of a cluster of small controls of its size: a row of
 * three or more, or a pad of rows, in a container a few levels up (keys in
 * wrappers, images for keys). Found once per element and recording.
 */
function inKeypad(el: Element): boolean {
  const known = keypads.get(el)
  if (known !== undefined) return known
  let found = false
  const r = el.getBoundingClientRect()
  if (r.width >= 2 && r.height >= 2 && r.width <= KEYPAD_SIZE && r.height <= KEYPAD_SIZE)
    for (let box = el.parentElement, up = 0; box && up < KEYPAD_UP && !found; box = box.parentElement, up++) {
      let same = 0
      for (const other of Array.from(box.querySelectorAll(el.tagName)).slice(0, 60)) {
        const o = other.getBoundingClientRect()
        if (Math.abs(o.width - r.width) <= 1 && Math.abs(o.height - r.height) <= 1) same++
      }
      found = same >= KEYPAD_KEYS
    }
  keypads.set(el, found)
  return found
}

/**
 * The element acted on, in the probe's terms: never its value, text only for
 * a button or link, every digit (and digit word) out. A keypad's key (its
 * text or label reads as one, see keypadText, or it's one of a cluster of
 * small same-size controls) keeps no text, label, id or name and a path of
 * tags, for every event (focus, blur, keys, pointer): a PIN or a word would
 * be its keys in order.
 */
function describe(node: EventTarget | null | undefined): Target | undefined {
  const hit = node instanceof Element ? node : node instanceof Node ? node.parentElement : null
  if (!hit) return undefined
  const el = hit.closest(INTERACTIVE) ?? hit
  const tag = el.tagName.toLowerCase()
  const t: Target = { tag, path: "" }
  const attr = (name: string) => said(el.getAttribute(name))
  const type = attr("type").toLowerCase()
  if (type) t.type = type
  const role = attr("role")
  if (role) t.role = role
  const autocomplete = attr("autocomplete").toLowerCase()
  if (autocomplete) t.autocomplete = autocomplete
  const button = el instanceof HTMLInputElement && (type === "submit" || type === "button" || type === "image")
  const rawLabel = clip(labelText(el))
  const rawText = TEXTUAL.has(tag) || TEXT_ROLES.has(role) || button ? clip(button ? (el as HTMLInputElement).value : staticText(el), 40) : ""
  if (keypadText(rawText) || keypadText(rawLabel) || inKeypad(el)) {
    t.keypad = true
    t.path = pathOf(el, true)
  } else {
    t.path = pathOf(el)
    const name = attr("name")
    if (name) t.name = name
    if (el.id) t.id = said(el.id)
    const label = said(rawLabel)
    if (label) t.label = label
    const text = said(rawText, 40)
    if (text) t.text = text
  }
  if (el.getRootNode() instanceof ShadowRoot) t.inShadow = true
  const role2 = detected.get(el)
  if (role2) t.detected = role2
  return t
}

/** What a field holds, by shape: never the value, and no length for a secret. */
function shapeFor(el: Element): Pick<TimelineEvent, "shape" | "length"> {
  if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) || !el.value) return {}
  const secret = el instanceof HTMLInputElement && (secrets.has(el) || masked(el))
  if (secret) secrets.add(el as HTMLInputElement)
  return secret ? { shape: "secret" } : { shape: shapeOf(el.value, el.getAttribute("type") || "text"), length: lengthBand(el.value) }
}

/**
 * A password box, or, failing closed, an element the keys go to that isn't
 * editable itself but hosts a shadow root (closed, perhaps, so what's in it
 * can't be seen): its keys are a password's until shown otherwise.
 */
const isSecret = (el: Element | null) =>
  (el instanceof HTMLInputElement && (secrets.has(el) || el.type === "password")) ||
  (el instanceof HTMLElement && !editable(el) && (shadowRootOf(el) !== null || el.tagName.includes("-")))
const editable = (el: Element | null) =>
  (el instanceof HTMLInputElement && eligible(el)) || el instanceof HTMLTextAreaElement || (el instanceof HTMLElement && el.isContentEditable)

/** A token for one more event, as the frame's rate allows. */
function take(): boolean {
  const now = performance.now()
  tokens = Math.min(RATE.capacity, tokens + ((now - refilledAt) / 1000) * RATE.perSecond)
  refilledAt = now
  if (tokens < 1) {
    dropped++
    return false
  }
  tokens--
  return true
}

/** What ends a password box's typing: the user moving on from it. */
const MOVES_ON = new Set<TimelineType>(["blur", "submit", "unload"])

function push(type: TimelineType, more: Omit<TimelineEvent, "t" | "type"> = {}) {
  if (!session || eventsFull) return
  commitTyping(MOVES_ON.has(type))
  if (!take()) return
  queue.push({ t: Date.now() - session.startedAt, type, ...more })
  schedule()
}

function schedule() {
  if (queue.length >= EVENTS_PER_BATCH) return void flush()
  flushTimer ??= setTimeout(flush, BATCH_MS)
}

/** Typing held back to be merged goes on the timeline; a password box's only once the user moves on (`force`), so it stays one event. */
function commitTyping(force = false) {
  if (!typing || (typing.secret && !force)) return
  const t = typing
  typing = null
  if (take()) queue.push(t.event)
}

/** Sends the frame's waiting events; `final` from pagehide, where nothing waits. */
function flush() {
  clearTimeout(flushTimer)
  flushTimer = undefined
  if (!session) return
  // Typing in one field merges until it pauses; a password box's until the user moves on.
  if (typing && !typing.secret && performance.now() - typing.at > INPUT_MERGE_MS) commitTyping()
  // The digests of words typed since, for the background to scrub addresses and titles of.
  const words = [...wordDigests.values()].filter((d) => !sentWords.has(d)).slice(0, 50)
  for (const d of words) sentWords.add(d)
  if (!queue.length && !words.length) return void (typing && schedule())
  const events = queue.splice(0)
  if (dropped && events.length) {
    events[0] = { ...events[0], dropped }
    dropped = 0
  }
  const id = session.id
  const wordsKnown = known()
  // Text that names a word typed on another page (known only by digest) goes too; batches stay in order.
  sending = sending.then(async () => {
    for (const e of events) for (const t of [e.target, e.submitter]) if (t) await scrubTarget(t, wordsKnown)
    const taken = await send({ type: "db:learn-events", session: id, events, ...(words.length ? { words } : {}) })
    if (taken === "full") eventsFull = true
    else if (taken !== true && session?.id === id) end()
  })
  if (typing || wordDigests.size > sentWords.size) schedule()
}

/** A target's text, label, id, name and path, of words whose digest is a typed word's. */
async function scrubTarget(t: Target, words?: Words) {
  for (const k of ["text", "label", "id", "name", "path"] as const) if (t[k]) t[k] = await scrubWords(t[k]!, words)
}

function typedInto(event: Event, el: EventTarget | null) {
  if (!(el instanceof Element) || !editable(el)) return
  const now = performance.now()
  const secret = isSecret(el) || (el instanceof HTMLInputElement && masked(el))
  const inputType = (event as InputEvent).inputType
  if (typing?.el === el && (secret || now - typing.at <= INPUT_MERGE_MS)) {
    Object.assign(typing.event, shapeFor(el), inputType ? { inputType } : {})
    typing.at = now
    return
  }
  commitTyping(true)
  if (!session || eventsFull) return
  typing = { el, at: now, secret, event: { t: Date.now() - session.startedAt, type: "input", target: describe(el), ...shapeFor(el), ...(inputType ? { inputType } : {}) } }
  schedule()
}

function onPointer(event: MouseEvent) {
  if (!event.isTrusted || !session || eventsFull) return
  const mods = modsOf(event)
  const target = describe(realTarget(event))
  // A keypad's key: where it was pressed would tell which.
  push(event.type as TimelineType, { target, ...(target?.keypad ? {} : { x: event.clientX, y: event.clientY }), ...(mods ? { mods } : {}) })
}

function onFocus(event: FocusEvent) {
  if (event.isTrusted) push(event.type === "focusin" ? "focus" : "blur", { target: describe(realTarget(event)) })
}

function onChange(event: Event) {
  if (!event.isTrusted) return
  const el = realTarget(event)
  push("change", { target: describe(el), ...(el ? shapeFor(el) : {}) })
}

function onScroll(event: Event) {
  if (!event.isTrusted) return
  const now = performance.now()
  if (now - lastScrollAt < SCROLL_EVERY_MS) return
  lastScrollAt = now
  const el = event.target
  if (el instanceof Element && el !== document.scrollingElement) push("scroll", { target: describe(el), x: Math.round(el.scrollLeft), y: Math.round(el.scrollTop) })
  else push("scroll", { x: Math.round(scrollX), y: Math.round(scrollY) })
}

function onPagehide(event: Event) {
  if (!event.isTrusted) return
  push("unload")
  commitTyping(true)
  flush()
}

/**
 * A key by its name only. Typing into a field is its input events; a
 * password box (see isSecret) gets only Enter, Tab and Escape, with no
 * Ctrl, Meta or Alt (AltGr is Ctrl and Alt, or its own state).
 */
function keyEvent(event: KeyboardEvent) {
  if (event.repeat) return
  const el = realTarget(event)
  const name = keyName(event.key)
  const shortcut = event.ctrlKey || event.metaKey
  if (isSecret(el)) {
    if (!SECRET_KEYS.has(name) || event.ctrlKey || event.metaKey || event.altKey || event.getModifierState?.("AltGraph")) return
  } else if (editable(el) && name === "char" && !shortcut) return
  const modifier = name === "Shift" || name === "Control" || name === "Alt" || name === "Meta"
  const mods = modifier ? "" : modsOf(event)
  // Enter or Tab in a password box ends its typing, as one event, before the key.
  if (typing?.secret && typing.el === el && (name === "Enter" || name === "Tab")) commitTyping(true)
  const target = el !== lastKeyTarget ? describe(el) : undefined
  lastKeyTarget = el
  push("key", { key: name, ...(mods ? { mods } : {}), ...(target ? { target } : {}), ...(el && editable(el) && SECRET_KEYS.has(name) ? shapeFor(el) : {}) })
}

// ---- Submits, for steps ------------------------------------------------------

function onClick(event: MouseEvent) {
  if (!learning() || !event.isTrusted) return
  onPointer(event)
  const target = realTarget(event)
  const control = target instanceof Element ? target.closest(CLICKABLE) : null
  if (!control) return
  // A button counts once the user has typed something here, or the page shows inputs.
  if (typedCount === 0 && !inputsNow().some((el) => isVisible(el))) return
  submittedBy("click", control)
}

function onKeydown(event: KeyboardEvent) {
  if (!learning() || !event.isTrusted) return
  keyEvent(event)
  if (event.key !== "Enter") return
  // Enter often leaves the page: what was typed goes to the background first.
  flush()
  const target = realTarget(event)
  if (target instanceof HTMLInputElement && eligible(target)) submittedBy("enter", null)
}

function onSubmit(event: Event) {
  if (!learning() || !event.isTrusted) return
  const form = realTarget(event)
  const submitter = (event as SubmitEvent).submitter ?? null
  push("submit", { target: describe(form), ...(submitter ? { submitter: describe(submitter) } : {}) })
  flush()
  if (form instanceof HTMLFormElement) submittedBy("submit", submitter)
}

const LISTENERS: Array<[string, (event: never) => void]> = [
  ["input", onInput],
  ["click", onClick],
  ["keydown", onKeydown],
  ["submit", onSubmit],
  ["pointerdown", onPointer],
  ["pointerup", onPointer],
  ["dblclick", onPointer],
  ["focusin", onFocus],
  ["focusout", onFocus],
  ["change", onChange],
  ["scroll", onScroll],
  ["pagehide", onPagehide],
]

/** The frame's listeners are on only while the tab records. */
function listen(on: boolean) {
  if (on === listening) return
  listening = on
  for (const [type, f] of LISTENERS) {
    if (on) window.addEventListener(type, f as EventListener, LISTEN)
    else window.removeEventListener(type, f as EventListener, LISTEN)
  }
}

function begin(next: LearnSession) {
  const fresh = session?.id !== next.id
  session = next
  clearTimeout(timer)
  timer = setTimeout(end, Math.max(0, next.until - Date.now()))
  listen(true)
  if (!fresh) return
  joinedAt = performance.now()
  typedCount = 0
  keyed = new WeakMap()
  secrets = new WeakSet()
  identifiers = new Set()
  scrubTyped = null
  keypads = new WeakMap()
  latest = new Map()
  wordDigests = new Map()
  sentWords = new Set()
  eventsFull = false
  stepsFull = false
  detected = new WeakMap()
  queue = []
  typing = null
  tokens = RATE.capacity
  refilledAt = performance.now()
  dropped = 0
  lastKeyTarget = null
  lastSubmitAt = -Infinity
  lastSignature = signature()
  void record("start")
}

function end() {
  // What waits is sent while the background may still take it.
  if (session) {
    commitTyping(true)
    flush()
  }
  session = null
  listen(false)
  clearTimeout(timer)
  clearTimeout(flushTimer)
  flushTimer = undefined
  queue = []
  typing = null
  keyed = new WeakMap()
  secrets = new WeakSet()
  identifiers = new Set()
  scrubTyped = null
  keypads = new WeakMap()
  latest = new Map()
  wordDigests = new Map()
  sentWords = new Set()
  detected = new WeakMap()
  typedCount = 0
  lastSignature = ""
}

/**
 * Joins the tab's recording when the background says so (to every frame as
 * it starts, and to each frame that loads while it runs, on its
 * DOMContentLoaded), and leaves it when it ends. A frame asks nothing: a page
 * nobody records sends no message.
 */
export function initLearn() {
  chrome.runtime.onMessage.addListener((message: ToContent) => {
    if (message?.type !== "db:learn") return
    const s = message.session
    if (s && typeof s.id === "string" && typeof s.salt === "string" && typeof s.until === "number" && typeof s.startedAt === "number") begin({ ...s, words: Array.isArray(s.words) ? s.words.filter((w) => typeof w === "string") : [] })
    else end()
  })
}
