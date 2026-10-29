// "Learn this site", in each frame (see src/learn.ts). While the tab is
// learning, the frame records a step when the session starts, when its inputs
// change and when the user submits, and sends it to the background. It finds
// submits on its own, not through the detector's form: a page the detector
// gets wrong is what learning is for.
//
// Nothing typed leaves the frame. For each field the user typed into it keeps
// two digests from the last trusted keystroke (to tell a repeated value and,
// in the background, a saved username) and, for fields that aren't password
// boxes, the value itself in memory only, to scrub it out of page text. Both
// go when the session ends.

import type { LearnSession, LearnStep, LearnInput, LearnTrigger, SubmitBy, Typed } from "../learn"
import { clip, frameOf, lengthBand, MAX_FRAMES, MAX_INPUTS, scrub, sha256, shapeOf, truthOf, usernameDigest } from "../learn"
import type { ToBackground, ToContent } from "../messages"
import { controlText, isVisible, scanPage } from "./detect"
import { deepQueryAll, openRoots } from "./shadow"

const SKIP = new Set(["hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file", "range", "color"])
const CLICKABLE = 'button, [role=button], input[type=submit], input[type=button], input[type=image], a[href^="javascript"], a[href="#"]'
const SUBMIT_DEDUPE_MS = 800

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
/** Values typed into fields that aren't password boxes, to scrub page text. */
let identifiers = new Set<string>()
let lastSignature = ""
let lastSubmitAt = -Infinity
let timer: ReturnType<typeof setTimeout> | undefined

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

function labelOf(el: HTMLInputElement): string {
  const parts: string[] = []
  for (const l of Array.from(el.labels ?? [])) parts.push((l as HTMLElement).innerText ?? l.textContent ?? "")
  const by = el.getAttribute("aria-labelledby")
  const root = el.getRootNode() as Document | ShadowRoot
  if (by) for (const id of by.split(/\s+/)) parts.push(root.getElementById?.(id)?.textContent ?? "")
  return clip(parts.filter(Boolean).join(" "))
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
  return deepQueryAll<HTMLInputElement>("input", openRoots()).slice(0, 300).filter(eligible)
}

function onInput(event: Event) {
  if (!session || !event.isTrusted) return
  const el = event.composedPath()[0]
  if (!(el instanceof HTMLInputElement) || !eligible(el)) return
  const salt = session.salt
  const secret = (el.getAttribute("type") || "").toLowerCase() === "password"
  const order = keyed.get(el)?.order ?? ++typedCount
  const value = el.value
  keyed.set(el, {
    order,
    exact: sha256(`${salt}\u0001${value}`),
    ...(secret ? {} : { digest: usernameDigest(salt, value) }),
  })
  if (!secret && value.trim().length >= 3) identifiers.add(value.trim())
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
  const form = result?.fields.find((f) => f.owner.form)?.owner.form ?? null
  const values = [...identifiers, ...typedEls.filter((el) => el.type !== "password").map((el) => el.value)]
  const text = (s: string | null | undefined, n?: number) => scrub(clip(s, n), values)

  const inputs: LearnInput[] = []
  for (const [i, el] of picked.entries()) {
    const type = (el.getAttribute("type") || "text").toLowerCase()
    const f = roles.get(el)
    const k = keyed.get(el)
    let typed: Typed | undefined
    if (k && el.value) {
      const shape = shapeOf(el.value, type)
      const sameAs = await repeated(el, k, typedEls)
      const digest = k.digest ? await k.digest : undefined
      typed = { order: k.order, shape, length: lengthBand(el.value), ...(sameAs ? { sameAs } : {}), ...(digest ? { digest } : {}), truth: truthOf({ shape }) }
    }
    const owner = el.form ?? el.closest("form")
    inputs.push({
      i,
      type,
      name: clip(el.getAttribute("name")),
      id: clip(el.id),
      autocomplete: clip(el.getAttribute("autocomplete")).toLowerCase(),
      placeholder: text(el.placeholder),
      ariaLabel: text(el.getAttribute("aria-label")),
      label: text(labelOf(el)),
      maxLength: el.maxLength > 0 ? el.maxLength : 0,
      inputMode: clip(el.getAttribute("inputmode")),
      visible: isVisible(el),
      inShadow: el.getRootNode() instanceof ShadowRoot,
      inForm: !!owner,
      formActionHost: owner ? hostOf(owner.getAttribute("action") || location.href) : "",
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
      return { host: url?.hostname ?? "", path: clip(url?.pathname, 120), visible: isVisible(f), rect: rectOf(f) }
    })

  return {
    trigger,
    at: Math.round(performance.now() - joinedAt),
    frame: frameOf(new URL(location.href), isTop, depth()),
    title: text(document.title, 120),
    kind: result?.kind ?? null,
    submit: submit
      ? { tag: submit.tagName.toLowerCase(), type: clip(submit.getAttribute("type"), 20), text: text(controlText(submit), 40), rect: rectOf(submit) }
      : null,
    ...(submitted
      ? { submitted: { by: submitted.by, text: submitted.control ? text(controlText(submitted.control), 40) : "", detected: !!submitted.control && submitted.control === submit } }
      : {}),
    inputs,
    shadowRoots: roots.length - 1,
    iframes,
  }
}

async function record(trigger: LearnTrigger, submitted?: { by: SubmitBy; control: Element | null }) {
  const step = await snapshot(trigger, submitted).catch(() => null)
  if (step && session) await send({ type: "db:learn-step", session: session.id, step })
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

const realTarget = (event: Event) => (event.composedPath()[0] ?? event.target) as Element | null

function onClick(event: MouseEvent) {
  if (!learning() || !event.isTrusted) return
  const target = realTarget(event)
  const control = target instanceof Element ? target.closest(CLICKABLE) : null
  if (!control) return
  // A button counts once the user has typed something here, or the page shows inputs.
  if (typedCount === 0 && !inputsNow().some((el) => isVisible(el))) return
  submittedBy("click", control)
}

function onKeydown(event: KeyboardEvent) {
  if (!learning() || !event.isTrusted || event.key !== "Enter") return
  const target = realTarget(event)
  if (target instanceof HTMLInputElement && eligible(target)) submittedBy("enter", null)
}

function onSubmit(event: Event) {
  if (!learning() || !event.isTrusted) return
  const form = realTarget(event)
  if (form instanceof HTMLFormElement) submittedBy("submit", (event as SubmitEvent).submitter ?? null)
}

function begin(next: LearnSession) {
  const fresh = session?.id !== next.id
  session = next
  clearTimeout(timer)
  timer = setTimeout(end, Math.max(0, next.until - Date.now()))
  if (!fresh) return
  joinedAt = performance.now()
  typedCount = 0
  keyed = new WeakMap()
  identifiers = new Set()
  lastSubmitAt = -Infinity
  lastSignature = signature()
  void record("start")
}

function end() {
  session = null
  clearTimeout(timer)
  keyed = new WeakMap()
  identifiers = new Set()
  typedCount = 0
  lastSignature = ""
}

/** Joins the tab's session, if it's learning, and follows it starting and ending. */
export function initLearn() {
  window.addEventListener("input", onInput, true)
  window.addEventListener("click", onClick, true)
  window.addEventListener("keydown", onKeydown, true)
  window.addEventListener("submit", onSubmit, true)
  chrome.runtime.onMessage.addListener((message: ToContent) => {
    if (message?.type !== "db:learn") return
    if (message.session) begin(message.session)
    else end()
  })
  void send({ type: "db:learn-ask" }).then((reply) => {
    const s = reply as LearnSession | null
    if (s && typeof s.id === "string" && typeof s.salt === "string" && typeof s.until === "number") begin(s)
  })
}
