// What the popup says about the tab's site besides its logins: "Learn this
// site" and the learning session it starts (src/learn.ts), and "Saving is
// off for acme.com", which undoes Never for this site. The native popup and
// the browser-only vault's popup show the same ones.

import type { LearnReply, Learning } from "../messages"
import { h } from "./dom"

const send = <T>(message: unknown): Promise<T | null> => chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>

const para = (...parts: Array<Node | string>) => {
  const p = h("p", { class: "muted" })
  p.append(...parts)
  return p
}

/** Starts or stops learning the tab's site; `changed` repaints. Starting closes the popup: the user signs in by hand next. */
async function learn(tabId: number | undefined, on: boolean, button: HTMLElement, status: HTMLElement, changed: () => void) {
  if (tabId === undefined) return
  button.setAttribute("disabled", "")
  const reply = await send<LearnReply>({ type: "db:popup-learn", tabId, on })
  button.removeAttribute("disabled")
  if (reply && !reply.ok) {
    status.textContent = reply.message || "Couldn't start learning."
    status.hidden = false
    return
  }
  // Learning starts with the user signing in by hand: out of the way.
  if (on) return window.close()
  changed()
}

/** "Learning acme.com": sign in by hand, Deadbolt records the form's shape. */
export function learningCard(l: Learning, tabId: number | undefined, changed: () => void): HTMLElement {
  const status = h("p", { class: "error", role: "status" })
  status.hidden = true
  const stop = h("button", { class: "btn primary", type: "button" }, "Stop")
  stop.addEventListener("click", () => void learn(tabId, false, stop, status, changed))
  const minutes = Math.max(1, Math.ceil((l.until - Date.now()) / 60_000))
  return h(
    "section",
    { class: "offer", "aria-label": "Learning this site" },
    h("h2", {}, `Learning ${l.site}`),
    para("Sign in by hand. Deadbolt records how the form is built and which fields you type into, never what you type."),
    para("Frames from other sites on the page, like chat widgets and ads, are logged too, by shape only."),
    h(
      "div",
      { class: "box" },
      h("div", { class: "line" }, h("span", { class: "muted" }, "Steps logged"), h("span", { class: "value" }, String(l.steps))),
      h("div", { class: "line" }, h("span", { class: "muted" }, "Stops"), h("span", { class: "value" }, `after you sign in, or in ${minutes} min`)),
    ),
    status,
    h("div", { class: "buttons" }, stop),
  )
}

/** "Form not filling here? Learn this site". */
export function learnLine(tabId: number | undefined, changed: () => void): HTMLElement {
  const status = h("p", { class: "error", role: "status" })
  status.hidden = true
  const start = h("button", { class: "link", type: "button" }, "Learn this site")
  start.addEventListener("click", () => void learn(tabId, true, start, status, changed))
  return h("div", {}, h("p", { class: "note saving-off" }, h("span", {}, "Deadbolt missing the form here?"), start), status)
}

/** "Saving is off for acme.com. Turn on": undoes Never for this site. */
export function savingOffLine(site: string, tabId: number | undefined, changed: () => void): HTMLElement {
  const on = h("button", { class: "link", type: "button" }, "Turn on")
  on.addEventListener("click", async () => {
    if (tabId === undefined) return
    on.setAttribute("disabled", "")
    await send<boolean>({ type: "db:popup-saving-on", tabId })
    changed()
  })
  return h("p", { class: "note saving-off" }, h("span", {}, `Saving is off for ${site}.`), on)
}
