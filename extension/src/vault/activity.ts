// Settings' Activity: what pages had Deadbolt fill, save, make or sign, and
// what this vault showed or copied, newest first, as the vault recorded it
// (docs/extension-device.md, "Activity"). Never values. As in the native
// app it's closed until asked for, so it costs the vault page nothing; open,
// it reads 50 entries at a time and pages back by id.

import type { ActivityEntry, DeviceReply } from "../messages"
import { h } from "../ui/dom"
import type { App } from "./app"
import { ago, button, hostOf } from "./kit"

/** Entries read at a time, as the native app shows. */
export const ACTIVITY_PAGE = 50
/** The most one read asks for, as the vault answers. */
const MAX_READ = 1000

const FIELD_WORDS: Record<string, string> = {
  otp: "one-time code",
  totp: "one-time code",
  cvv: "security code",
  number: "card number",
  expiry: "expiry date",
  pin: "PIN",
}

/** A field's name in words: "one-time code", "private key". */
const fieldWord = (name: string) => FIELD_WORDS[name] ?? name.replace(/[-_]+/g, " ")

/** "username", "username and password", "number, expiry and security code". */
export function fieldList(fields: string[]): string {
  const words = fields.map(fieldWord)
  return words.length <= 1 ? (words[0] ?? "") : `${words.slice(0, -1).join(", ")} and ${words.at(-1)}`
}

/** What happened, in plain words: "Filled username and password", "Copied password". */
export function activityWords(e: ActivityEntry): string {
  const fields = fieldList(e.fields)
  const what = (() => {
    switch (e.command) {
      case "site-fill":
      case "form-fill":
        return fields ? `Filled ${fields}` : "Filled"
      case "site-save":
        return e.fields.includes("username") ? "Saved a new login" : "Updated a password"
      // A card or identity saved from a form: its fields' names only.
      case "item-new":
        return e.fields.includes("number") ? "Saved a new card" : "Saved new details"
      case "item-set":
        return fields ? `Updated ${fields}` : "Updated"
      case "site-generate":
        return "Made a new password"
      case "site-generate-keep":
        return "Kept a new password to save"
      case "passkey-create":
        return "Saved a passkey"
      case "passkey-get":
        return "Signed in with a passkey"
      case "reveal":
        return fields ? `Showed ${fields}` : "Showed"
      case "copy":
        return fields ? `Copied ${fields}` : "Copied"
      case "more-past-budget":
        return `${e.more} older ${e.more === 1 ? "entry" : "entries"} removed to keep the log small`
      default:
        return e.command
    }
  })()
  if (e.outcome === "refused") return `${what}: refused`
  if (e.outcome === "failed") return `${what}: didn't finish`
  return what
}

/** Which item, on which site, and when: "GitHub · github.com · 4 min ago". */
export function activityDetail(e: ActivityEntry, now: number): string {
  const parts = e.items.map((i) => i.title)
  if (e.site) parts.push(hostOf(e.site))
  else if (e.caller === "vault") parts.push("in this vault")
  parts.push(ago(e.time, now))
  return parts.join(" · ")
}

function entryRow(e: ActivityEntry, now: number): HTMLElement {
  const when = new Date(e.time * 1000)
  return h(
    "div",
    { class: `vrow activity${e.outcome === "allowed" ? "" : " not-allowed"}`, "data-id": String(e.id) },
    h("span", { class: "text" }, h("span", { class: "title" }, activityWords(e)), h("span", { class: "sub", title: when.toLocaleString() }, activityDetail(e, now))),
  )
}

const isEntry = (v: unknown): v is ActivityEntry => {
  const e = v as ActivityEntry
  return typeof e === "object" && e !== null && typeof e.id === "number" && typeof e.time === "number" && typeof e.command === "string" && Array.isArray(e.items) && Array.isArray(e.fields)
}

/** The section: Show or Hide, and once shown, the newest entries, with Show older while there may be more. */
export function activitySection(app: App): { el: HTMLElement; update: () => void } {
  let open = false
  let entries: ActivityEntry[] = []
  let now = Date.now() / 1000
  let end = false
  let loading = false
  let error = ""
  /** The list asked for: an answer to an earlier ask is dropped. */
  let seq = 0

  const toggle = button("btn", "Show", () => {
    open = !open
    loading = false
    entries = []
    end = false
    error = ""
    seq++
    if (open) void load()
    paint()
  })
  toggle.setAttribute("aria-expanded", "false")
  const list = h("div", { class: "rows activity-list", id: "activity-list", role: "list", "aria-label": "Activity" })
  toggle.setAttribute("aria-controls", "activity-list")
  const older = button("btn", "Show older", () => void load(true))
  const more = h("div", { class: "buttons" }, older)
  const box = h("div", { class: "activity-box" }, list, more)
  // As the native app's Settings has it: a "Recent activity" row with Show.
  const row = h(
    "div",
    { class: "switch-row activity-row" },
    h("span", { class: "text" }, h("span", { class: "title" }, "Recent activity"), h("span", { class: "sub" }, "What Deadbolt filled, saved, showed or copied in this browser, never the values. Kept for 90 days.")),
    toggle,
  )
  row.addEventListener("click", (e) => {
    if (!toggle.contains(e.target as Node)) toggle.click()
  })
  const el = h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, "Activity")), row, box)

  const read = (before?: number, limit = ACTIVITY_PAGE): Promise<DeviceReply> => app.ask({ type: "device-activity", ...(before === undefined ? {} : { before }), limit })

  /** The newest entries again (as many as are shown), or (`older`) the page before the last shown. */
  async function load(older = false) {
    if (!open || (older && loading)) return
    const ask = ++seq
    loading = true
    if (older) paint()
    const last = entries.at(-1)
    const asked = older ? ACTIVITY_PAGE : Math.min(MAX_READ, Math.max(ACTIVITY_PAGE, entries.length))
    const r = older && last ? await read(last.id) : await read(undefined, asked)
    if (ask !== seq || !open) return
    loading = false
    if (!r.ok) {
      error = r.message
      return paint()
    }
    const got = (Array.isArray(r.reply.entries) ? r.reply.entries : []).filter(isEntry)
    if (typeof r.reply.now === "number") now = r.reply.now
    // A short page, or one ending with what went to stay in budget, is the oldest.
    end = got.length < asked || got.at(-1)?.command === "more-past-budget"
    entries = older ? [...entries, ...got] : got
    error = ""
    paint()
  }

  function paint() {
    toggle.textContent = open ? "Hide" : "Show"
    toggle.setAttribute("aria-expanded", String(open))
    box.hidden = !open
    if (!open) return list.replaceChildren()
    older.disabled = loading
    more.hidden = end || !entries.length || !!error
    if (error) return list.replaceChildren(h("p", { class: "hint error", role: "alert" }, error))
    if (!entries.length) return list.replaceChildren(h("p", { class: "hint" }, loading ? "Loading…" : "Nothing yet"))
    list.replaceChildren(...entries.map((e) => entryRow(e, now)))
  }

  // Back from filling in another tab: an open list shows what it did.
  const back = () => {
    if (!el.isConnected) return document.removeEventListener("visibilitychange", back)
    if (document.visibilityState === "visible") void load()
  }
  document.addEventListener("visibilitychange", back)
  paint()
  return { el, update: () => void load() }
}
