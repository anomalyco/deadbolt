// Items other than logins: secure notes, cards, identities, API
// credentials, SSH keys, documents and the rest of the core's types. Their
// details (secrets revealed and copied one at a time, a file downloaded),
// adding and editing them from the core's schema, deleting any item, and
// the type picker that New opens. Logins keep their own views (logins.ts).

import type { ItemDetail, ItemField, ItemInput, ItemKind, ItemSummary } from "../messages"
import { avatar, h, icon } from "../ui/dom"
import { rollLabel } from "../ui/motion"
import type { App, View } from "./app"
import { button, copied, glyph, iconButton, refuse, slidingHighlight, toolbar } from "./kit"

/** Names the agent and the app give fields, where its own name doesn't read well. */
const LABELS: Record<string, string> = {
  url: "Website",
  otp: "One-time password",
  cvv: "Security code",
  pin: "PIN",
  ssid: "Network name",
  iban: "IBAN",
  swift: "SWIFT / BIC",
  "address-line1": "Address",
  "address-line2": "Address line 2",
  "address-line3": "Address line 3",
  "postal-code": "Postal code",
  region: "State or region",
  "national-id": "National ID",
  "private-key": "Private key",
  "public-key": "Public key",
  "license-key": "License key",
  "connection-string": "Connection string",
  "admin-console": "Admin console",
  "rp-id": "Site",
  "credential-id": "Credential ID",
  "user-handle": "User handle",
  "recovery-phrase": "Recovery phrase",
}

/** Fields that link one item to another, which the editor doesn't offer. */
const LINKS = new Set(["sign-in-account", "billing"])

export const fieldLabel = (name: string) => LABELS[name] ?? (name.charAt(0).toUpperCase() + name.slice(1)).replace(/-/g, " ")

/** "secure note", "API credential": what the core calls one. */
const noun = (app: App, kind: string) => app.kinds?.find((k) => k.kind === kind)?.noun ?? kind

/** "Secure note", "API credential": the core's noun, capitalized. */
export function kindName(app: App, kind: string): string {
  const n = noun(app, kind)
  return n.charAt(0).toUpperCase() + n.slice(1)
}

/** A type's tile: its first letter, as a login's avatar is the title's. */
export const kindAvatar = (item: ItemSummary) => avatar(item.title)

/** A file's size as the agent writes it: "812 bytes", "1.2 MB". */
const size = (bytes: number) => (bytes < 1000 ? `${bytes} bytes` : bytes < 1e6 ? `${(bytes / 1e3).toFixed(1)} KB` : `${(bytes / 1e6).toFixed(1)} MB`)

/** One secret value of an item; Strict asks for the passphrase first (`reauth`). */
export async function secretOf(app: App, ref: string, field: string, passphrase?: string): Promise<{ value?: string; message?: string; reauth?: boolean }> {
  const r = await app.run({ type: "device-secret", ref, field, ...(passphrase ? { passphrase } : {}) })
  if (r.ok && typeof r.reply.value === "string") return { value: r.reply.value }
  return { message: r.ok ? "Deadbolt didn't answer." : r.message, reauth: !r.ok && r.code === "passphrase_needed" }
}

/** Saves `contents` (a file field's `name`, a line break, base64) as a download. */
function download(value: string) {
  const at = value.indexOf("\n")
  const name = at < 0 ? "file" : value.slice(0, at)
  const bytes = Uint8Array.from(atob(value.slice(at + 1)), (c) => c.charCodeAt(0))
  const url = URL.createObjectURL(new Blob([bytes]))
  const a = h("a", { href: url, download: name })
  document.body.append(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

/** New: the types the vault can add, Login first. */
export function kindsView(app: App): View {
  const rows = h("div", { class: "rows" })
  slidingHighlight(rows)
  const kinds = app.kinds ?? [{ kind: "login", noun: "login", fields: [] }]
  rows.append(
    ...kinds.map((k) => {
      const b = button("vrow-main", [avatar(kindName(app, k.kind)), h("span", { class: "text" }, h("span", { class: "title" }, kindName(app, k.kind)))], () => app.go({ name: "edit", kind: k.kind }))
      return h("div", { class: "vrow" }, b)
    }),
  )
  const el = h("section", { class: "view list-view" }, toolbar("New item", () => app.go({ name: "list" }, -1)), h("section", { class: "group" }, rows))
  return { el, focus: () => el.querySelector<HTMLElement>(".vrow-main")?.focus() }
}

/**
 * Delete, after a second press: on every device, once synced. Strict asks
 * for the passphrase to delete a passkey: the vault answers
 * `passphrase_needed`, and the passphrase is asked for under the button.
 */
export function deleteButton(app: App, ref: string, what: string): HTMLButtonElement {
  let armed = false
  let asking: HTMLFormElement | null = null
  /** Deletes it; what went wrong, or null (deleted, or the passphrase is asked for). */
  const remove = async (passphrase?: string): Promise<string | null> => {
    const r = await app.run(passphrase ? { type: "device-item-delete", ref, passphrase } : { type: "device-item-delete", ref })
    if (!r.ok) {
      if (r.code === "passphrase_needed" && !passphrase) {
        asking ??= reauthForm("Delete", (p) => remove(p))
        ;(b.parentElement ?? b).after(asking)
        return null
      }
      return r.message
    }
    await app.refresh()
    app.announce(`Deleted ${what}.`)
    app.go({ name: "list" }, -1)
    return null
  }
  const b = button("btn", [glyph("trash"), "Delete"], async () => {
    if (!armed) {
      armed = true
      b.classList.add("danger")
      b.replaceChildren(glyph("trash"), "Delete for good?")
      setTimeout(() => {
        armed = false
        b.classList.remove("danger")
        if (b.isConnected) b.replaceChildren(glyph("trash"), "Delete")
      }, 4000)
      return
    }
    b.disabled = true
    const failed = await remove()
    b.disabled = false
    if (failed) app.announce(failed)
  })
  b.setAttribute("aria-label", `Delete ${what}`)
  return b
}

/** The passphrase, once, before a secret shows or copies under Strict. */
function reauthForm(label: string, go: (passphrase: string) => Promise<string | null>): HTMLFormElement {
  const input = h("input", { class: "input", type: "password", autocomplete: "current-password", placeholder: "Passphrase", "aria-label": "Passphrase", spellcheck: "false" })
  const error = h("p", { class: "error" })
  error.hidden = true
  const submit = h("button", { class: "btn primary", type: "submit" }, label)
  const form = h("form", { class: "reauth", novalidate: "" }, h("p", { class: "muted small" }, `Strict: enter your passphrase to ${label.toLowerCase()} this.`), h("div", { class: "reauth-row" }, input, submit), error)
  form.addEventListener("submit", async (e) => {
    e.preventDefault()
    if (!input.value) return refuse(input)
    submit.disabled = true
    const passphrase = input.value
    input.value = ""
    const failed = await go(passphrase)
    submit.disabled = false
    if (failed) {
      error.textContent = failed
      error.hidden = false
      refuse(input)
      input.focus()
    }
  })
  queueMicrotask(() => input.focus())
  return form
}

/** Any item's details but a login's (logins.ts has those). */
export function itemDetailView(app: App, ref: string): View {
  const el = h("section", { class: "view detail" })
  let detail: ItemDetail | null = null
  const shown = new Map<string, string>()
  let hideTimer: ReturnType<typeof setTimeout> | undefined
  let tick: ReturnType<typeof setInterval> | undefined
  /** The field and action waiting on Strict's passphrase. */
  let asking: { field: string; action: "show" | "copy" | "download" } | null = null
  const say = (m: string) => app.announce(m)

  const act = async (field: string, action: "show" | "copy" | "download", passphrase?: string, b?: HTMLElement | null): Promise<string | null> => {
    if (action === "show" && shown.has(field) && !passphrase) {
      shown.delete(field)
      paint()
      return null
    }
    if (action !== "download") await app.offerClearing()
    const s = shown.has(field) && action === "copy" ? { value: shown.get(field) } : await secretOf(app, ref, field, passphrase)
    if (s.value === undefined) {
      if (s.reauth && !passphrase) {
        asking = { field, action }
        paint()
        return null
      }
      if (!passphrase) say(s.message ?? "Couldn't get that.")
      return s.message ?? "That passphrase isn't right."
    }
    asking = null
    if (action === "download") {
      download(s.value)
      paint()
    } else if (action === "show") {
      shown.set(field, s.value)
      paint()
      clearTimeout(hideTimer)
      hideTimer = setTimeout(() => {
        shown.clear()
        if (el.isConnected) paint()
      }, 30_000)
    } else {
      paint()
      const target = b?.isConnected ? b : el.querySelector<HTMLElement>(`[data-copy="${field}"]`)
      if (target && (await copied(target, s.value))) say(await app.copiedSecret(s.value))
      else say("Couldn't copy.")
    }
    return null
  }

  const line = (f: ItemField): Node[] => {
    const label = fieldLabel(f.name)
    const wrap = (value: Node, ...actions: Node[]) => h("div", { class: "line" }, h("span", { class: "line-label" }, label), h("span", { class: `value${f.type === "note" ? " lines" : ""}` }, value), h("span", { class: "line-actions" }, ...actions))
    const out: Node[] = []
    if (f.type === "file") {
      out.push(wrap(h("span", {}, f.value ?? "File", f.size !== undefined ? h("span", { class: "faint" }, ` · ${size(f.size)}`) : null), iconButton(glyph("open"), `Download ${f.value ?? "the file"}`, () => void act(f.name, "download"))))
    } else if (f.secret && f.type !== "otp") {
      const value = shown.get(f.name)
      const eye = iconButton(glyph(value !== undefined ? "eyeOff" : "eye"), value !== undefined ? `Hide ${label}` : `Show ${label}`, () => void act(f.name, "show"))
      const copy = iconButton(icon("copy"), `Copy ${label}`, (b) => void act(f.name, "copy", undefined, b))
      copy.dataset.copy = f.name
      out.push(wrap(value !== undefined ? h("span", { class: "mono secret" }, value) : h("span", { class: "dots" }, "••••••••••••"), eye, copy))
    } else if (f.type === "otp") {
      return out
    } else {
      const value = f.value ?? ""
      const actions: Node[] = [iconButton(icon("copy"), `Copy ${label}`, (b) => void copied(b, value, say, `Copied the ${label.toLowerCase()}`))]
      if (f.type === "url" && /^https?:\/\//.test(value)) actions.push(iconButton(glyph("open"), "Open", () => void chrome.tabs.create({ url: value })))
      out.push(wrap(h("span", {}, value), ...actions))
    }
    if (asking?.field === f.name) {
      const verb = asking.action === "download" ? "Download" : asking.action === "show" ? "Show" : "Copy"
      const action = asking.action
      out.push(reauthForm(verb, (p) => act(f.name, action, p)))
    }
    return out
  }

  const paint = () => {
    if (!detail) return
    clearInterval(tick)
    const d = detail
    const lines: Node[] = d.fields.flatMap(line)
    if (d.totp) {
      const t = d.totp
      const secs = h("span", { class: "secs mono" }, String(Math.ceil(Math.max(0, t.until - Date.now() / 1000))))
      lines.push(
        h(
          "div",
          { class: "line" },
          h("span", { class: "line-label" }, "One-time code"),
          h("span", { class: "value" }, h("span", { class: "totp" }, h("span", { class: "mono code-value" }, t.code), secs)),
          h("span", { class: "line-actions" }, iconButton(icon("copy"), "Copy one-time code", async (b) => {
            await app.offerClearing()
            if (await copied(b, t.code)) say(await app.copiedSecret(t.code))
          })),
        ),
      )
      tick = setInterval(() => {
        const left = t.until - Date.now() / 1000
        secs.textContent = String(Math.ceil(Math.max(0, left)))
        if (left <= 0) void load()
      }, 250)
    }
    const actions: Node[] = []
    if (d.editable) actions.push(button("btn", "Edit", () => app.go({ name: "edit", ref, kind: d.kind })))
    el.replaceChildren(
      toolbar("", () => app.go({ name: "list" }, -1), ...actions),
      h("div", { class: "detail-head" }, kindAvatar(d), h("div", { class: "text" }, h("h2", { class: "title" }, d.title), h("span", { class: "sub" }, [kindName(app, d.kind), d.detail].filter(Boolean).join(" · ")))),
      lines.length ? h("div", { class: "box" }, ...lines) : h("p", { class: "muted" }, "Nothing saved in it yet."),
      h("div", { class: "buttons end" }, deleteButton(app, ref, d.title)),
    )
  }

  const load = async () => {
    const r = await app.run({ type: "device-item", ref })
    if (!el.isConnected && detail) return
    if (!r.ok) {
      el.replaceChildren(toolbar("", () => app.go({ name: "list" }, -1)), h("p", { class: "error" }, r.message))
      return
    }
    detail = r.reply as unknown as ItemDetail
    paint()
  }

  void app.run({ type: "device-used" })
  el.append(toolbar("", () => app.go({ name: "list" }, -1)), h("div", { class: "skeleton" }, h("div", { class: "skeleton-row" }), h("div", { class: "skeleton-row" })))
  void load()
  return {
    el,
    update: () => void load(),
    leave: () => {
      shown.clear()
      clearTimeout(hideTimer)
      clearInterval(tick)
    },
    focus: () => queueMicrotask(() => el.querySelector<HTMLElement>(".back")?.focus()),
  }
}

/** The inputs a field type gets. */
function input(type: string, multiline: boolean, attrs: Record<string, string>): HTMLInputElement | HTMLTextAreaElement {
  if (multiline || type === "note") return h("textarea", { class: "input area", rows: "4", spellcheck: "false", ...attrs })
  const kinds: Record<string, string> = { secret: "password", otp: "password", email: "email", url: "url", date: "date", month: "month", file: "file" }
  return h("input", { class: "input", type: kinds[type] ?? "text", autocomplete: "off", spellcheck: "false", ...attrs })
}

/** A chosen file as a file field's value: its name, a line break, base64. */
async function fileValue(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer())
  let binary = ""
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return `${file.name}\n${btoa(binary)}`
}

interface Row {
  name: string
  type: string
  /** The value it had: plain values only. */
  was?: string
  /** It has a secret (or file) the form never saw: left empty, it stays. */
  kept: boolean
  el: HTMLInputElement | HTMLTextAreaElement
  required: boolean
}

/** Adding an item of `kind`, or editing `ref`: the core's fields for the type, then any others the item has. */
export function itemEditView(app: App, kind: string, ref?: string): View {
  const schema: ItemKind | undefined = app.kinds?.find((k) => k.kind === kind)
  const error = h("p", { class: "error", role: "alert" })
  error.hidden = true
  const label = h("span", { class: "roll-label" }, "Save")
  label.dataset.text = "Save"
  const save = h("button", { class: "btn primary", type: "submit" }, label)
  const back = () => (ref ? app.go({ name: "item", ref }, -1) : app.go({ name: "list" }, -1))
  const nameId = `f-${Math.random().toString(36).slice(2, 9)}`
  const name = h("input", { class: "input", id: nameId, autocomplete: "off", spellcheck: "false", maxlength: "128", placeholder: kindName(app, kind) })
  const fieldsBox = h("div", { class: "fields" })
  const form = h(
    "form",
    { class: "view edit", novalidate: "" },
    toolbar(ref ? `Edit ${noun(app, kind)}` : `New ${noun(app, kind)}`, back),
    h("div", { class: "field" }, h("label", { for: nameId }, "Name"), name),
    fieldsBox,
    error,
    h("div", { class: "buttons end" }, button("btn", "Cancel", back), save),
  )
  const rows: Row[] = []
  const fail = (message: string, el?: HTMLInputElement | HTMLTextAreaElement) => {
    error.textContent = message
    error.hidden = false
    if (el) {
      refuse(el as HTMLInputElement)
      el.focus()
    }
  }

  const paint = (d: ItemDetail | null) => {
    const saved = new Map((d?.fields ?? []).map((f) => [f.name, f]))
    const known = (schema?.fields ?? []).filter((f) => !LINKS.has(f.name))
    const extra = (d?.fields ?? []).filter((f) => !known.some((k) => k.name === f.name) && !LINKS.has(f.name))
    const all = [...known.map((f) => ({ ...f, has: saved.get(f.name) })), ...extra.map((f) => ({ name: f.name, type: f.type, required: false, multiline: f.type === "note", has: f as ItemField | undefined }))]
    fieldsBox.replaceChildren()
    for (const f of all) {
      const kept = !!f.has && (f.has.secret === true || f.type === "file")
      const id = `f-${Math.random().toString(36).slice(2, 9)}`
      const attrs: Record<string, string> = { id }
      if (kept) attrs.placeholder = f.type === "file" ? `${f.has?.value ?? "File"} (unchanged)` : "Unchanged"
      const el = input(f.type, f.multiline, attrs)
      if (!kept && f.has?.value !== undefined && f.type !== "file") el.value = f.has.value
      if (f.type === "otp") el.setAttribute("placeholder", kept ? "Unchanged" : "Secret or otpauth:// link")
      el.addEventListener("input", () => el.classList.remove("invalid"))
      rows.push({ name: f.name, type: f.type, was: kept ? undefined : f.has?.value, kept, el, required: f.required })
      if (f.required && !kept) {
        el.setAttribute("aria-required", "true")
        if (!el.getAttribute("placeholder")) el.setAttribute("placeholder", "Required")
      }
      fieldsBox.append(h("div", { class: "field" }, h("label", { for: id }, fieldLabel(f.name)), el))
    }
    if (d) name.value = d.name ?? ""
  }

  if (ref) {
    save.disabled = true
    void app.run({ type: "device-item", ref }).then((r) => {
      if (!r.ok) return fail(r.message)
      paint(r.reply as unknown as ItemDetail)
      save.disabled = false
    })
  } else paint(null)

  form.addEventListener("submit", async (e) => {
    e.preventDefault()
    error.hidden = true
    const fields: ItemInput[] = []
    const remove: string[] = []
    for (const r of rows) {
      const raw = r.el instanceof HTMLInputElement && r.el.type === "file" ? r.el.files?.[0] : undefined
      const value = raw ? await fileValue(raw) : r.el.value.trim() === "" ? "" : r.type === "note" || r.type === "secret" ? r.el.value : r.el.value.trim()
      if (!value) {
        // Empty: a kept secret stays; a plain value that was there goes.
        if (!r.kept && r.was !== undefined) remove.push(r.name)
        else if (!r.kept && !ref && r.required) return fail(`${fieldLabel(r.name)} is required.`, r.el)
        continue
      }
      if (value !== r.was) fields.push({ name: r.name, value })
    }
    if (!ref && !fields.length && !name.value.trim()) return fail("Give it a name or fill in a field.", name)
    save.disabled = true
    rollLabel(label, "Saving…")
    const r = await app.run(ref ? { type: "device-item-save", ref, name: name.value.trim(), fields, remove } : { type: "device-item-save", kind, name: name.value.trim(), fields })
    if (!r.ok) {
      save.disabled = false
      rollLabel(label, "Save")
      return fail(r.message)
    }
    for (const row of rows) row.el.value = ""
    await app.refresh()
    app.announce(ref ? "Saved." : `${kindName(app, kind)} added.`)
    app.go({ name: "item", ref: typeof r.reply.ref === "string" ? r.reply.ref : (ref ?? "") }, ref ? -1 : 1)
  })
  return { el: form, focus: () => name.focus(), leave: () => rows.forEach((r) => (r.el.value = "")) }
}
