// Custom comboboxes: an input with role="combobox" whose choices are a list
// the page draws ([role=listbox] of [role=option]), as Base UI, Headless UI,
// React Aria, Downshift and the like render a country or state picker.
// Writing the input's value only filters the list, and many put the old
// text back on blur: a choice is made by clicking an option. So a fill
// types the name, waits for the list, clicks the option that matches and
// checks the input shows it. With no match, the field is put back as it was.
//
// The list is the page's own popup, often over the fields below: the input
// gets the field checks before anything is typed, and the option clicked
// has to be in the list the input names (aria-controls or aria-owns),
// drawn, on screen and what's under its middle.

import type { FormControl } from "./detect"
import { noteFilled, rendered, visibleBox } from "./fill"
import { optionScore, shows, type Choice } from "./transform"

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** How long a list has to show its options after the text goes in. */
const LIST_WAIT_MS = 800
/** How long the input has to show the option after it's clicked. */
const COMMIT_WAIT_MS = 400

export const isCombobox = (el: FormControl): el is HTMLInputElement => el instanceof HTMLInputElement && el.getAttribute("role") === "combobox"

/** The list the combobox names (aria-controls, aria-owns), or the one its active option is in. */
function listOf(el: HTMLInputElement): Element | null {
  const root = el.getRootNode() as Document | ShadowRoot
  const byId = (id: string) => root.getElementById?.(id) ?? document.getElementById(id)
  const ids = `${el.getAttribute("aria-controls") ?? ""} ${el.getAttribute("aria-owns") ?? ""}`.split(/\s+/).filter(Boolean)
  for (const id of ids) {
    const node = byId(id)
    if (node?.getAttribute("role") === "listbox") return node
    const inner = node?.querySelector("[role=listbox]")
    if (inner) return inner
  }
  const active = el.getAttribute("aria-activedescendant")
  return (active && byId(active)?.closest("[role=listbox]")) || null
}

/** The option in the list that best matches the choice. */
function bestOption(list: Element, c: Choice): Element | undefined {
  let best: Element | undefined
  let score = 0
  for (const o of Array.from(list.querySelectorAll("[role=option]"))) {
    if (o.getAttribute("aria-disabled") === "true") continue
    const s = optionScore(o.textContent ?? "", c)
    if (s > score) [best, score] = [o, s]
  }
  return best
}

/** The option is drawn, on screen, and what a click in its middle hits. */
function shown(opt: Element): boolean {
  if (!rendered(opt)) return false
  opt.scrollIntoView?.({ block: "nearest", inline: "nearest" })
  const box = visibleBox(opt)
  if (!box) return false
  const hit = (opt.getRootNode() as Document | ShadowRoot).elementFromPoint?.((box.left + box.right) / 2, (box.top + box.bottom) / 2)
  return !!hit && (hit === opt || opt.contains(hit))
}

const expanded = (el: Element) => el.getAttribute("aria-expanded") === "true"

function press(el: Element, key: string) {
  for (const type of ["keydown", "keyup"]) el.dispatchEvent(new KeyboardEvent(type, { key, code: key, bubbles: true, composed: true, cancelable: true }))
}

/** A mouse click on the option, as a pointer gives it: down, up, click. */
function click(opt: Element) {
  const r = opt.getBoundingClientRect()
  const at = { bubbles: true, cancelable: true, composed: true, clientX: (r.left + r.right) / 2, clientY: (r.top + r.bottom) / 2, button: 0 }
  const pointer = { ...at, pointerId: 1, pointerType: "mouse", isPrimary: true }
  const Pointer = typeof PointerEvent === "function" ? PointerEvent : MouseEvent
  opt.dispatchEvent(new Pointer("pointerdown", { ...pointer, buttons: 1 }))
  opt.dispatchEvent(new MouseEvent("mousedown", { ...at, buttons: 1 }))
  opt.dispatchEvent(new Pointer("pointerup", pointer))
  opt.dispatchEvent(new MouseEvent("mouseup", at))
  opt.dispatchEvent(new MouseEvent("click", { ...at, detail: 1 }))
}

function type(el: HTMLInputElement, text: string, restore = false) {
  if (!restore) noteFilled(el, text)
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(el, text)
  el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: restore ? "insertReplacementText" : "insertText", data: text }))
}

async function until<T>(find: () => T | undefined | null | false, ms: number, nudge?: () => void): Promise<T | undefined> {
  const start = Date.now()
  let nudged = !nudge
  for (;;) {
    const found = find()
    if (found) return found
    if (Date.now() - start >= ms) return undefined
    if (!nudged && Date.now() - start >= 150) {
      nudged = true
      nudge!()
    }
    await sleep(30)
  }
}

/**
 * Chooses the option `c` names in a combobox: `guard` checks the input
 * right after it's focused, `inPlace` again right before the click. True
 * once the input shows the option; otherwise what was typed is taken back
 * and the input holds its old text again.
 */
export async function chooseOption(el: HTMLInputElement, c: Choice, guard: (el: FormControl) => boolean, inPlace: () => boolean): Promise<boolean> {
  const old = el.value
  el.focus({ preventScroll: true })
  if (!guard(el)) return false
  for (const text of c.type) {
    type(el, text)
    // A list that doesn't open on typing usually does on the down arrow.
    const opt = await until(() => {
      const list = listOf(el)
      return list && bestOption(list, c)
    }, LIST_WAIT_MS, () => !expanded(el) && press(el, "ArrowDown"))
    if (!opt) continue
    if (!inPlace() || !shown(opt)) break
    click(opt)
    const label = opt.textContent ?? ""
    if (await until(() => el.isConnected && shows(el.value, c, label), COMMIT_WAIT_MS)) {
      noteFilled(el, el.value)
      if (expanded(el)) press(el, "Escape")
      return true
    }
    break
  }
  if (el.value !== old) type(el, old, true)
  if (expanded(el)) press(el, "Escape")
  return false
}
