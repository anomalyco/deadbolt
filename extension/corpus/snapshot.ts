// Collects one frame of the autofill engine's Snapshot (crates/autofill,
// src/snapshot.rs): the structure, labels and flags of every form control in
// document order, across open shadow roots. No values: only whether a field
// has one. The engine re-checks every cap, so these are a courtesy.
//
// Corpus-only for now; phase 2 moves it into the content script.

import { controlText, isVisible } from "../src/content/detect"
import { deepActiveElement } from "../src/content/shadow"

export type ElementKind =
  | "text" | "email" | "password" | "tel" | "number" | "search" | "url" | "textarea" | "select"
  | "checkbox" | "radio" | "button" | "hidden" | "other"

export interface SnapshotField {
  id: number
  form: number | null
  element: ElementKind
  htmlId: string
  name: string
  class: string
  autocomplete: string
  inputMode: string
  placeholder: string
  title: string
  ariaLabel: string
  labels: string[]
  labelBefore: string
  labelAfter: string
  /** Button text, for buttons only. */
  text: string
  maxLength: number | null
  minLength: number | null
  dataHints: Array<[string, string]>
  options: Array<[string, string]>
  flags: {
    visible: boolean
    readonly: boolean
    disabled: boolean
    active: boolean
    hasValue: boolean
    masked: boolean
    inShadow: boolean
    submit: boolean
  }
}

export interface SnapshotForm {
  id: number
  htmlId: string
  name: string
  method: string
  action: string
  headerText: string
  text: string
  dataHints: Array<[string, string]>
}

export interface SnapshotFrame {
  frameRef: string
  url: string
  title: string
  dir: "ltr" | "rtl"
  headings: string[]
  bodyHints: Array<[string, string]>
  forms: SnapshotForm[]
  fields: SnapshotField[]
}

/** Elements walked per frame; detect.ts's openRoots() walks the whole DOM too. */
const MAX_NODES = 500_000
const MAX_CONTROLS = 300
const MAX_BUTTONS = 150
const HINT_KEYS = [
  "data-1p-ignore", "data-op-ignore", "data-bwignore", "data-deadbolt-ignore", "data-lpignore", "data-form-type",
  "data-testid", "data-test", "data-qa",
]
const INPUT_KINDS = new Set(["text", "email", "password", "tel", "number", "search", "url", "checkbox", "radio", "hidden"])
const BUTTON_INPUTS = new Set(["submit", "button", "image", "reset"])
const CONTROL = "input, select, textarea"
const BUTTON = "button, [role=button]"

const clip = (s: unknown, n = 120) => (typeof s === "string" ? s : "").replace(/\s+/g, " ").trim().slice(0, n)
const innerText = (el: Element | null | undefined) => clip((el as HTMLElement | null)?.innerText ?? el?.textContent ?? "", 4000)

function hints(el: Element | null | undefined): Array<[string, string]> {
  if (!el) return []
  const out: Array<[string, string]> = []
  for (const key of HINT_KEYS) if (el.hasAttribute(key)) out.push([key, clip(el.getAttribute(key), 80)])
  return out
}

/** Nearest ancestor matching `selector`, crossing shadow-root boundaries. */
function closestAcross(el: Element, selector: string): Element | null {
  let node: Element | null = el
  while (node) {
    const hit = node.closest(selector)
    if (hit) return hit
    const root = node.getRootNode()
    node = root instanceof ShadowRoot ? root.host : null
  }
  return null
}

/** Closest text before (or after) a field, as detect.ts's nearbyText reads it. */
function nearby(el: Element, after: boolean): string {
  let node: Element | null = el
  for (let depth = 0; node && depth < 3; depth++) {
    let sibling = after ? node.nextElementSibling : node.previousElementSibling
    for (let i = 0; sibling && i < 2; i++, sibling = after ? sibling.nextElementSibling : sibling.previousElementSibling) {
      if (sibling.matches(CONTROL) || sibling.querySelector(CONTROL)) return ""
      const text = innerText(sibling)
      if (text) return text.length <= 80 ? text : ""
    }
    node = node.parentElement
  }
  return ""
}

function headerOf(form: Element): string {
  const inside = form.querySelector("h1, h2, h3, h4, legend, [role=heading]")
  if (inside) return clip(innerText(inside))
  let node: Element | null = form
  for (let depth = 0; node && depth < 4; depth++) {
    for (let s = node.previousElementSibling, i = 0; s && i < 3; s = s.previousElementSibling, i++) {
      const h = s.matches("h1, h2, h3, h4, [role=heading]") ? s : s.querySelector("h1, h2, h3, h4, [role=heading]")
      if (h) return clip(innerText(h))
    }
    node = node.parentElement
  }
  return ""
}

function elementKind(el: Element): ElementKind | "skip" {
  if (el instanceof HTMLSelectElement) return "select"
  if (el instanceof HTMLTextAreaElement) return "textarea"
  if (el instanceof HTMLInputElement) {
    // The property, not the attribute: an unknown type reads as "text", as the browser treats it.
    const t = el.type.toLowerCase()
    if (BUTTON_INPUTS.has(t)) return "button"
    if (t === "file" || t === "range" || t === "color") return "skip"
    return INPUT_KINDS.has(t) ? (t as ElementKind) : "other"
  }
  return "button"
}

/** Every control in document order, descending into open shadow roots where they sit. */
function controlsInOrder(): Element[] {
  const out: Element[] = []
  let visited = 0
  let controls = 0
  let buttons = 0
  const walk = (root: Document | ShadowRoot) => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT)
    for (let node = walker.nextNode() as Element | null; node; node = walker.nextNode() as Element | null) {
      if (++visited > MAX_NODES) return
      if (node.matches(CONTROL)) {
        const isButton = node instanceof HTMLInputElement && BUTTON_INPUTS.has((node.getAttribute("type") || "").toLowerCase())
        if (isButton ? buttons++ < MAX_BUTTONS : controls++ < MAX_CONTROLS) out.push(node)
      } else if (node.matches(BUTTON) && buttons < MAX_BUTTONS) {
        // A button inside another counted button adds nothing.
        if (!node.parentElement?.closest(BUTTON)) {
          buttons++
          out.push(node)
        }
      }
      const shadow = node.shadowRoot
      if (shadow && shadow.mode === "open") walk(shadow)
    }
  }
  walk(document)
  return out
}

export function collectFrame(): { frame: SnapshotFrame; index: Map<Element, number> } {
  const forms = new Map<Element, SnapshotForm>()
  const index = new Map<Element, number>()
  const fields: SnapshotField[] = []
  const active = deepActiveElement()
  const formOf = (el: Element): number | null => {
    const f = (el as HTMLInputElement).form ?? closestAcross(el, "form")
    if (!f) return null
    let entry = forms.get(f)
    if (!entry) {
      const action = f.getAttribute("action")
      let actionPath = ""
      try {
        const u = new URL(action || location.href, location.href)
        actionPath = clip(u.hostname + u.pathname, 200)
      } catch {}
      entry = {
        id: forms.size,
        // Attributes, not properties: <input name="id"> inside a form clobbers form.id.
        htmlId: clip(f.getAttribute("id")),
        name: clip(f.getAttribute("name")),
        method: clip(f.getAttribute("method")).toLowerCase(),
        action: actionPath,
        headerText: headerOf(f),
        text: innerText(f).slice(0, 3000),
        dataHints: hints(f),
      }
      forms.set(f, entry)
    }
    return entry.id
  }

  for (const el of controlsInOrder()) {
    const kind = elementKind(el)
    if (kind === "skip") continue
    const input = el as HTMLInputElement
    const visible = kind !== "hidden" && isVisible(el)
    const isText = kind !== "button" && kind !== "hidden" && kind !== "checkbox" && kind !== "radio" && kind !== "select"
    const labels: string[] = []
    if (kind !== "button" && kind !== "hidden") {
      for (const l of Array.from(input.labels ?? [])) labels.push(clip(innerText(l)))
      const by = el.getAttribute("aria-labelledby")
      const root = el.getRootNode() as Document | ShadowRoot
      if (by) for (const id of by.split(/\s+/).slice(0, 4)) labels.push(clip(innerText(root.getElementById?.(id))))
    }
    let masked = false
    if (visible && isText && kind !== "password") {
      const style = getComputedStyle(el) as CSSStyleDeclaration & { webkitTextSecurity?: string }
      const sec = style.getPropertyValue("-webkit-text-security") || style.webkitTextSecurity || ""
      masked = !!sec && sec !== "none"
    }
    const options: Array<[string, string]> = []
    if (el instanceof HTMLSelectElement) for (const o of Array.from(el.options).slice(0, 30)) options.push([clip(o.text, 40), clip(o.value, 40)])
    const id = fields.length
    index.set(el, id)
    fields.push({
      id,
      form: formOf(el),
      element: kind,
      htmlId: clip(el.getAttribute("id")),
      name: clip(el.getAttribute("name")),
      class: clip(el.getAttribute("class"), 200),
      autocomplete: clip(el.getAttribute("autocomplete")).toLowerCase(),
      inputMode: clip(el.getAttribute("inputmode")).toLowerCase(),
      placeholder: clip(el.getAttribute("placeholder")),
      title: clip(el.getAttribute("title")),
      ariaLabel: clip(el.getAttribute("aria-label")),
      labels: labels.filter(Boolean),
      labelBefore: kind === "button" || kind === "hidden" ? "" : nearby(el, false),
      labelAfter: kind === "button" || kind === "hidden" ? "" : nearby(el, true),
      text: kind === "button" ? controlText(el).slice(0, 80) : "",
      maxLength: input.maxLength > 0 ? input.maxLength : null,
      minLength: input.minLength > 0 ? input.minLength : null,
      dataHints: hints(el),
      options,
      flags: {
        visible,
        readonly: !!input.readOnly,
        disabled: !!input.disabled || el.getAttribute("aria-disabled") === "true",
        active: el === active,
        hasValue: kind !== "button" && kind !== "select" && typeof input.value === "string" && input.value.length > 0,
        masked,
        inShadow: el.getRootNode() instanceof ShadowRoot,
        submit: kind === "button" && ((el as HTMLButtonElement).type === "submit" || input.type === "image"),
      },
    })
  }

  const headings = Array.from(document.querySelectorAll("h1, h2, h3, [role=heading]"))
    .slice(0, 6)
    .map((h) => clip(innerText(h)))
    .filter(Boolean)
  const dir = (document.dir || getComputedStyle(document.documentElement).direction) === "rtl" ? "rtl" : "ltr"
  return {
    frame: {
      frameRef: "",
      url: clip(location.origin + location.pathname, 300),
      title: clip(document.title),
      dir,
      headings,
      bodyHints: hints(document.body),
      forms: [...forms.values()],
      fields,
    },
    index,
  }
}
