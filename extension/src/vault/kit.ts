// The browser-only Deadbolt's own UI (the popup and device.html): what its
// views share. The parts are the popup's and the inline menu's (theme.css,
// popup.css), with vault.css for what only these views have.

import type { DeviceCommand, DeviceReply, Status } from "../messages"
import { h, icon, svg } from "../ui/dom"
import { reducedMotion, Spring, timing } from "../ui/motion"

const NO_ANSWER = "Deadbolt didn't answer. Reload the extension and try again."

/** Sends a command to the standalone device; never throws. */
export function run(command: DeviceCommand, status: () => Status): Promise<DeviceReply> {
  return (chrome.runtime.sendMessage({ type: "db:device", command }) as Promise<DeviceReply | null>).then(
    (r) => r ?? { ok: false, message: NO_ANSWER, status: status() },
    () => ({ ok: false, message: NO_ANSWER, status: status() }),
  )
}

/** Icons only these views use, drawn like the rest (24 px grid, 1.8 stroke). */
export const GLYPHS = {
  search: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="6.2"/><path d="m20 20-4.6-4.6"/></svg>`,
  plus: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M12 5.5v13M5.5 12h13"/></svg>`,
  back: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m14.5 6-6 6 6 6"/></svg>`,
  chevron: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9.5 6 6 6-6 6"/></svg>`,
  gear: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M4.5 8h6M15.5 8h4M4.5 16h4M13.5 16h6"/><circle cx="13" cy="8" r="2.4"/><circle cx="11" cy="16" r="2.4"/></svg>`,
  eye: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2.8 12S6.2 5.8 12 5.8 21.2 12 21.2 12 17.8 18.2 12 18.2 2.8 12 2.8 12Z"/><circle cx="12" cy="12" r="2.7"/></svg>`,
  eyeOff: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6a9.6 9.6 0 0 1 2-.2c5.8 0 9.2 6.2 9.2 6.2a16 16 0 0 1-2.4 3.1M6.4 7.6A15.6 15.6 0 0 0 2.8 12s3.4 6.2 9.2 6.2a9 9 0 0 0 4.5-1.2M4 4l16 16"/><path d="M10.1 10.2a2.7 2.7 0 0 0 3.7 3.7"/></svg>`,
  open: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M13.5 5.5H18.5V10.5M18.5 5.5l-7.5 7.5"/><path d="M17 14v3.3a1.7 1.7 0 0 1-1.7 1.7H6.7A1.7 1.7 0 0 1 5 17.3V8.7A1.7 1.7 0 0 1 6.7 7H10"/></svg>`,
  user: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8.5" r="3.7"/><path d="M5 19.5a7 7 0 0 1 14 0"/></svg>`,
  sync: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19.2 9.2A7.6 7.6 0 0 0 5.6 7.4M4.8 14.8a7.6 7.6 0 0 0 13.6 1.8"/><path d="M5.2 3.8v3.9h3.9M18.8 20.2v-3.9h-3.9"/></svg>`,
  dice: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4.5" y="4.5" width="15" height="15" rx="3.2"/><circle cx="9" cy="9" r=".9" fill="currentColor"/><circle cx="15" cy="15" r=".9" fill="currentColor"/><circle cx="15" cy="9" r=".9" fill="currentColor"/><circle cx="9" cy="15" r=".9" fill="currentColor"/></svg>`,
  link: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-.8.8M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l.8-.8"/></svg>`,
  laptop: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="5.5" width="14" height="9.5" rx="1.6"/><path d="M3 18.5h18"/></svg>`,
  browser: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="5" width="17" height="14" rx="2.4"/><path d="M3.5 9h17"/><circle cx="6.6" cy="7" r=".5" fill="currentColor"/><circle cx="8.6" cy="7" r=".5" fill="currentColor"/></svg>`,
  warning: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.4 4.6 3.3 17.2A1.8 1.8 0 0 0 4.9 20h14.2a1.8 1.8 0 0 0 1.6-2.8L13.6 4.6a1.8 1.8 0 0 0-3.2 0Z"/><path d="M12 9.5v4M12 16.6v.1"/></svg>`,
  trash: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 7h14M10 7V5.2h4V7M7 7l.8 11.3A1.8 1.8 0 0 0 9.6 20h4.8a1.8 1.8 0 0 0 1.8-1.7L17 7"/></svg>`,
} as const

export const glyph = (name: keyof typeof GLYPHS) => svg(GLYPHS[name])

type Child = Node | string | null | undefined | false

/** A button; `cls` is "btn", "btn primary", "link" or "icon-button". */
export function button(cls: string, label: Child | Child[], act: (b: HTMLButtonElement, event: MouseEvent) => void, attrs: Record<string, string> = {}): HTMLButtonElement {
  const b = h("button", { class: cls, type: "button", ...attrs }, ...(Array.isArray(label) ? label : [label]))
  b.addEventListener("click", (e) => act(b, e))
  return b
}

/** An icon-only button with a label for screen readers and a tooltip. */
export const iconButton = (glyphEl: Element, label: string, act: (b: HTMLButtonElement, event: MouseEvent) => void, extra = "") =>
  button(`icon-button${extra ? ` ${extra}` : ""}`, glyphEl, act, { title: label, "aria-label": label })

/** A text field with a visible label above it. */
export function field(label: string, attrs: Record<string, string> = {}, ...after: Node[]): { wrap: HTMLElement; input: HTMLInputElement } {
  const id = `f-${Math.random().toString(36).slice(2, 9)}`
  const input = h("input", { class: "input", id, autocomplete: "off", spellcheck: "false", ...attrs })
  const wrap = h("div", { class: "field" }, h("label", { for: id }, label), after.length ? h("div", { class: "input-wrap" }, input, ...after) : input)
  return { wrap, input }
}

export const para = (...parts: Array<Node | string>) => {
  const p = h("p", { class: "muted" })
  p.append(...parts)
  return p
}

/** The heading row of a view under the header: a way back, a title, and actions. */
export function toolbar(title: string, back: (() => void) | null, ...actions: Node[]): HTMLElement {
  return h(
    "div",
    { class: "toolbar" },
    back ? iconButton(glyph("back"), "Back", back, "back") : null,
    h("h2", {}, title),
    h("div", { class: "toolbar-actions" }, ...actions),
  )
}

/** Writes `text` and shows a check on `b` for a moment. Answers whether it was copied. */
export async function copied(b: HTMLElement, text: string, announce?: (message: string) => void, what = "Copied"): Promise<boolean> {
  const ok = await navigator.clipboard.writeText(text).then(
    () => true,
    () => false,
  )
  if (!ok) {
    announce?.("Couldn't copy.")
    return false
  }
  const was = [...b.childNodes]
  // A labelled button says so; an icon button shows the check alone.
  b.replaceChildren(icon("check"), ...(b.classList.contains("btn") ? ["Copied"] : []))
  b.classList.add("confirmed")
  announce?.(what)
  setTimeout(() => {
    b.replaceChildren(...was)
    b.classList.remove("confirmed")
  }, 1400)
  return true
}

/** "just now", "4 min ago", "3 h ago", "2 d ago": when something was, from `now` (both unix seconds). */
export function ago(at: number, now = Date.now() / 1000): string {
  const s = Math.max(0, now - at)
  if (s < 45) return "just now"
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} d ago`
}

/** A device counts as online if it synced within a background sync's period (five minutes) and a bit. */
export const ONLINE_SECS = 6 * 60

export function hostOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname
  } catch {
    return url
  }
}

/**
 * The menu's one highlight, which slides between a list's rows instead of
 * each row lighting up: under the pointer at once, and springing to the row
 * keyboard focus moves to.
 */
export function slidingHighlight(rows: HTMLElement): HTMLElement {
  const el = h("div", { class: "highlight", "aria-hidden": "true" })
  el.hidden = true
  rows.prepend(el)
  const y = new Spring(0, 0.28)
  const height = new Spring(0, 0.28)
  let frame = 0
  const step = () => {
    el.style.transform = `translateY(${y.value}px)`
    el.style.height = `${height.value}px`
    frame = y.done && height.done ? 0 : requestAnimationFrame(step)
  }
  const to = (row: HTMLElement | null, slide: boolean) => {
    if (!row) {
      el.hidden = true
      return
    }
    const top = row.offsetTop
    const tall = row.offsetHeight
    if (el.hidden || !slide || reducedMotion()) {
      y.jump(top)
      height.jump(tall)
    } else {
      y.to(top)
      height.to(tall)
    }
    el.hidden = false
    if (!frame) frame = requestAnimationFrame(step)
    step()
  }
  const rowOf = (t: EventTarget | null) => (t instanceof Element ? (t.closest(".vrow") as HTMLElement | null) : null)
  rows.addEventListener("pointerover", (e) => to(rowOf(e.target), false))
  rows.addEventListener("pointerleave", () => {
    const focused = rowOf(document.activeElement)
    to(focused && rows.contains(focused) ? focused : null, true)
  })
  rows.addEventListener("focusin", (e) => to(rowOf(e.target), true))
  rows.addEventListener("focusout", (e) => {
    if (!rows.contains(e.relatedTarget as Node | null) && !rows.matches(":hover")) to(null, false)
  })
  return el
}

/** A whole view coming in: from the side it's going (`dir`), softened like the popup's state changes. */
export function enter(el: HTMLElement, dir: -1 | 0 | 1) {
  if (typeof el.animate !== "function") return
  if (reducedMotion()) return void el.animate([{ opacity: 0 }, { opacity: 1 }], timing(0.3))
  const from = dir === 0 ? "scale(0.98)" : `translateX(${dir * 14}px)`
  el.animate([{ opacity: 0, transform: from, filter: "blur(3px)" }, { opacity: 1, transform: "none", filter: "blur(0px)" }], timing(0.32))
}

/** Shakes a field that was refused, gently; with reduced motion, nothing moves. */
export function refuse(el: HTMLElement) {
  el.classList.add("invalid")
  if (reducedMotion() || typeof el.animate !== "function") return
  el.animate([{ transform: "translateX(0)" }, { transform: "translateX(-4px)" }, { transform: "translateX(3px)" }, { transform: "translateX(-2px)" }, { transform: "translateX(0)" }], { duration: 320, easing: "ease-out" })
}
