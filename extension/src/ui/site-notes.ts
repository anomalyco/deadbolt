// What the popup says about the tab besides its logins: Record (src/learn.ts),
// its button in the header and the bar under it, and "Saving is off for
// acme.com", which undoes Never for this site. The native popup and the
// browser-only vault's popup show the same ones.

import type { LearnReply, RecordedReply, Recording } from "../messages"
import { h } from "./dom"

const send = <T>(message: unknown): Promise<T | null> => chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>

/** 0:42, 10:00. */
const clock = (ms: number) => {
  const s = Math.max(0, Math.floor(ms / 1000))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`
}

export interface RecordControl {
  /** The header's Record button: always there on a web page, disabled where Chrome lets no extension in. */
  button: HTMLButtonElement
  /** Under the header: "Recording · 0:42" and Stop, "Recorded 38 steps on …" with Download and Delete, or why it can't. */
  bar: HTMLElement
  refresh(): Promise<void>
}

/**
 * Record for the popup's tab (`tab()`), whatever the vault's state: it
 * follows the background once a second, so the shortcut, the time cap and a
 * closed tab show here too. Starting closes the popup: the user does what
 * they want recorded next.
 */
export function recordControl(tab: () => number | undefined, announce: (text: string) => void): RecordControl {
  const button = h("button", { class: "icon-button record", type: "button", "data-focus": "record" }, h("span", { class: "rec-dot", "aria-hidden": "true" }))
  const bar = h("div", { class: "record-bar", role: "group", "aria-label": "Recording" })
  bar.hidden = true
  const error = h("p", { class: "error", role: "alert" })
  let rec: Recording = { state: "off" }
  let shown = ""
  let shortcut = ""
  let time: HTMLElement | null = null

  const fail = (message: string) => {
    error.textContent = message
    if (!bar.contains(error)) bar.append(error)
    bar.hidden = false
    announce(message)
  }

  const act = async (b: HTMLButtonElement, message: unknown, then?: (reply: Extract<RecordedReply, { ok: true }>) => void) => {
    const tabId = tab()
    if (tabId === undefined) return
    b.disabled = true
    const reply = await send<LearnReply | RecordedReply>({ ...(message as object), tabId })
    b.disabled = false
    if (!reply?.ok) return fail(reply && "message" in reply && reply.message ? reply.message : "Deadbolt didn't answer. Try again.")
    then?.(reply as Extract<RecordedReply, { ok: true }>)
    await refresh()
  }

  const start = (b: HTMLButtonElement) => act(b, { type: "db:popup-learn", on: true }, () => window.close())
  const stop = (b: HTMLButtonElement) => act(b, { type: "db:popup-learn", on: false }, () => announce("Stopped recording."))
  button.addEventListener("click", () => void (rec.state === "on" ? stop(button) : start(button)))

  function paint() {
    const on = rec.state === "on"
    button.classList.toggle("recording", on)
    button.disabled = rec.state === "blocked"
    button.setAttribute("aria-pressed", String(on))
    const label = on ? "Stop recording" : "Record what you do on this page"
    button.setAttribute("aria-label", label)
    button.title = rec.state === "blocked" ? rec.message : `${label}${shortcut ? ` (${shortcut})` : ""}`
    time = null
    bar.dataset.state = rec.state
    bar.hidden = rec.state === "off"
    if (rec.state === "blocked") return bar.replaceChildren(h("span", {}, rec.message))
    if (rec.state === "on") {
      time = h("span", { class: "record-time" }, clock(Date.now() - rec.startedAt))
      const stopButton = h("button", { class: "btn", type: "button" }, "Stop")
      stopButton.addEventListener("click", () => void stop(stopButton))
      return bar.replaceChildren(h("div", { class: "record-row" }, h("span", { class: "rec-dot", "aria-hidden": "true" }), h("span", { class: "record-text" }, "Recording · ", time), stopButton))
    }
    if (rec.state === "done") {
      const done = rec
      const download = h("button", { class: "btn", type: "button" }, "Download")
      download.addEventListener("click", () =>
        // The recording stays, to share the file and still Delete it after.
        void act(download, { type: "db:popup-recorded", action: "download" }, (reply) => {
          save(reply.text ?? "", `deadbolt-recording-${done.host}-${new Date().toISOString().slice(0, 10)}.jsonl`)
          announce("Downloaded the recording.")
        }),
      )
      const remove = h("button", { class: "btn", type: "button" }, "Delete")
      remove.addEventListener("click", () => void act(remove, { type: "db:popup-recorded", action: "delete" }, () => announce("Deleted the recording.")))
      return bar.replaceChildren(
        h("span", { class: "record-text" }, `Recorded ${done.steps} ${done.steps === 1 ? "step" : "steps"} on `, h("span", { class: "mono" }, done.host)),
        h("span", { class: "record-actions" }, download, remove),
      )
    }
    bar.replaceChildren()
  }

  async function refresh() {
    const tabId = tab()
    const next = tabId === undefined ? null : await send<Recording>({ type: "db:popup-record", tabId })
    if (!next || typeof next.state !== "string") return
    rec = next
    if (time && rec.state === "on") time.textContent = clock(Date.now() - rec.startedAt)
    const key = JSON.stringify(rec.state === "on" ? [rec.state, rec.startedAt] : rec)
    if (key === shown) return
    shown = key
    paint()
  }

  void chrome.commands
    ?.getAll?.()
    .then((all) => {
      shortcut = all.find((c) => c.name === "record")?.shortcut ?? ""
      paint()
    })
    .catch(() => {})
  setInterval(() => void refresh(), 1000)
  paint()
  return { button, bar, refresh }
}

function save(text: string, name: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/x-ndjson" }))
  const a = h("a", { href: url, download: name })
  document.body.append(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
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
