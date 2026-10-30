// The vault's list (search across every item, this site's logins first),
// a login's details (reveal and copy, its one-time code counting down), and
// adding or editing one, with the password generator. Other types are in
// items.ts.

import type { ItemDetail, ItemSummary, PickReply } from "../messages"
import type { Account } from "../protocol"
import { avatar, h, icon } from "../ui/dom"
import { offerCard } from "../ui/offer"
import { learnLine, learningCard, savingOffLine } from "../ui/site-notes"
import { rollLabel } from "../ui/motion"
import { siteTile } from "../ui/site-icon"
import type { App, View } from "./app"
import { enrollment, verify } from "./biometric"
import { deleteButton, kindAvatar, kindName, secretOf } from "./items"
import { button, copied, field, glyph, hostOf, iconButton, keepFocus, para, refuse, slidingHighlight, toolbar } from "./kit"

const url = (a: Account) => a.urls.find(Boolean) ?? ""

/** Opens a login's site in a new tab; only web addresses. */
function openSite(link: string) {
  const u = link.includes("://") ? link : `https://${link}`
  if (!/^https?:\/\//.test(u)) return
  void chrome.tabs.create({ url: u })
}

/**
 * A login's tile: its site's icon with "Site icons in the vault" on (see
 * ui/site-icon.ts), else its letter. The icon dithers in the first time
 * this page shows it in `scope`, the list's rows one after another
 * (`index`); a repaint (a search, a sync) just shows it.
 */
function avatarFor(app: App, title: string, link: string, scope: "list" | "detail", index = 0): HTMLElement {
  if (!app.icons.vault || !link) return avatar(title)
  return siteTile(title, link, { reveal: true, once: `${scope}:${hostOf(link)}`, delay: Math.min(index, 8) * 28 })
}

/** A password to copy or reveal: Strict asks for the passphrase first, in the login's own view. */
async function secret(app: App, ref: string, passphrase?: string, prf?: string): Promise<{ password?: string; message?: string; reauth?: boolean }> {
  if (!prf) {
    const s = await secretOf(app, ref, "password", passphrase)
    return { password: s.value, message: s.message, reauth: s.reauth }
  }
  // Touch ID: the PRF output stands in for the passphrase, checked by the agent like one.
  const r = await app.run({ type: "device-secret", ref, field: "password", prf })
  if (r.ok && typeof r.reply.value === "string") return { password: r.reply.value }
  return { message: r.ok ? "Deadbolt didn't answer." : r.message, reauth: !r.ok && r.code === "passphrase_needed" }
}

/** Copies a password or one-time code; the background clears it in 30 s if Chrome lets it. */
async function copySecret(app: App, b: HTMLElement, value: string) {
  if (await copied(b, value)) app.announce(await app.copiedSecret(value))
  else app.announce("Couldn't copy.")
}

/** A login's row. `fill`: the popup's site, with Fill; `failed` shows why a fill didn't happen. `index`: its place in the list, for the reveal. */
function row(app: App, a: Account, fill: boolean, failed: (message: string) => void = () => {}, index = 0): HTMLElement {
  const link = url(a)
  const main = button("vrow-main", [avatarFor(app, a.title, link, "list", index), h("span", { class: "text" }, h("span", { class: "title" }, a.title), h("span", { class: "sub" }, a.username || hostOf(link) || "No username"))], () =>
    app.go({ name: "item", ref: a.ref }),
  )
  main.dataset.ref = a.ref
  const say = (m: string) => app.announce(m)
  const user = iconButton(glyph("user"), "Copy username", (b) => a.username && void copied(b, a.username, say, "Copied the username"))
  if (!a.username) user.disabled = true
  const pass = iconButton(icon("key"), "Copy password", async (b) => {
    await app.offerClearing()
    if (app.preset === "strict") return app.go({ name: "item", ref: a.ref, then: "copy" })
    const s = await secret(app, a.ref)
    if (s.password !== undefined) return void copySecret(app, b, s.password)
    if (s.reauth) return app.go({ name: "item", ref: a.ref, then: "copy" })
    say(s.message ?? "Couldn't copy.")
  })
  if (!a.hasPassword) pass.disabled = true
  const open = iconButton(glyph("open"), "Open site", () => openSite(link))
  if (!link) open.disabled = true
  const actions = h("span", { class: "vrow-actions" }, user, pass, open)
  if (fill && app.site) {
    // With a save offer showing, its Save is the one primary button, as in the native popup.
    const f = button(app.site.offer ? "btn fill" : "btn primary fill", "Fill", async (b) => {
      b.disabled = true
      failed("")
      const reply = (await chrome.runtime.sendMessage({ type: "db:popup-fill", tabId: app.site!.tabId, ref: a.ref }).catch(() => null)) as PickReply | null
      if (reply?.ok) return window.close()
      b.disabled = false
      failed(reply?.message || "Couldn't fill.")
    })
    f.setAttribute("aria-label", `Fill ${a.title}`)
    actions.append(f)
  }
  return h("div", { class: `vrow${fill ? " here" : ""}` }, main, actions)
}

/** Another type's row: its tile, label and detail, and a copy of the field it's for. */
function itemRow(app: App, item: ItemSummary): HTMLElement {
  const main = button("vrow-main", [kindAvatar(item), h("span", { class: "text" }, h("span", { class: "title" }, item.title), h("span", { class: "sub" }, item.detail ? `${kindName(app, item.kind)} · ${item.detail}` : kindName(app, item.kind)))], () =>
    app.go({ name: "item", ref: item.ref, kind: item.kind }),
  )
  main.dataset.ref = item.ref
  const actions = h("span", { class: "vrow-actions" })
  const primary = item.primary
  if (primary && item.kind !== "document") {
    const copy = iconButton(icon("copy"), `Copy ${primary.replace(/-/g, " ")}`, async (b) => {
      await app.offerClearing()
      const s = await secretOf(app, item.ref, primary)
      if (s.value !== undefined) {
        if (await copied(b, s.value)) app.announce(await app.copiedSecret(s.value))
        return
      }
      if (s.reauth) return app.go({ name: "item", ref: item.ref, kind: item.kind })
      // A plain field (an identity's email) isn't a secret: the details have it.
      const r = await app.run({ type: "device-item", ref: item.ref })
      const value = r.ok ? (r.reply as unknown as ItemDetail).fields.find((f) => f.name === primary)?.value : undefined
      if (value !== undefined) void copied(b, value, (m) => app.announce(m))
      else app.announce(s.message ?? "Couldn't copy.")
    })
    actions.append(copy)
  }
  return h("div", { class: "vrow" }, main, actions)
}

/** Every query word is in the item's title or its search words (never a secret), or a login's username or site. */
const matches = (a: ItemSummary, q: string) => {
  const texts = [a.title, a.username ?? "", ...a.urls.map(hostOf), ...a.search].map((s) => s.toLowerCase())
  return q.split(/\s+/).filter(Boolean).every((w) => texts.some((s) => s.includes(w)))
}

export function listView(app: App): View {
  const search = h("input", { class: "input search", type: "search", placeholder: "Search", "aria-label": "Search the vault", autocomplete: "off", spellcheck: "false", value: app.query })
  const add = button("btn add", [glyph("plus"), "Add"], () => app.go({ name: "new" }), { "aria-label": "Add an item", title: "Add an item" })
  const body = h("div", { class: "list-body" })
  const el = h("section", { class: "view list-view" }, h("div", { class: "search-row" }, h("span", { class: "search-wrap" }, glyph("search"), search), add), body)

  // Why the popup's Fill didn't fill, shown under this site's logins (and said), as the native popup shows it.
  const fillError = h("p", { class: "error", id: "error", role: "alert" })
  fillError.hidden = true
  const failed = (message: string) => {
    fillError.textContent = message
    fillError.hidden = !message
  }
  // The save offer's card stays the same element while it's the same offer,
  // and stays showing "Saved" until it puts itself away, though the save
  // changed the list under it.
  let offer: { id: string; el: HTMLElement } | null = null
  const offerEl = (): HTMLElement | null => {
    if (offer?.el.querySelector(".done")) return offer.el
    const o = app.site?.offer
    if (!o || !app.site) return (offer = null)
    if (offer?.id !== o.id) {
      offer = {
        id: o.id,
        el: offerCard(o, app.site.tabId, () => {
          offer = null
          void app.refresh()
        }),
      }
    }
    return offer.el
  }
  const section = (label: string, aside: string | null, items: ItemSummary[], fill: boolean) => {
    const rows = h("div", { class: "rows" })
    slidingHighlight(rows)
    rows.append(...items.map((a, i) => (a.kind === "login" ? row(app, a as Account, fill, failed, i) : itemRow(app, a))))
    return h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, label), aside ? h("span", { class: "mono muted" }, aside) : null), rows)
  }

  const paint = () => {
    const q = app.query.trim().toLowerCase()
    const all = app.items
    const parts: Node[] = []
    const card = q ? null : offerEl()
    if (app.site?.learning && !q) parts.push(learningCard(app.site.learning, app.site.tabId, () => void app.refresh()))
    if (card) parts.push(card)
    if (all === null) {
      parts.push(h("div", { class: "skeleton" }, ...[0, 1, 2].map(() => h("div", { class: "skeleton-row" }))))
    } else if (!all.length) {
      parts.push(
        h(
          "div",
          { class: "empty-state" },
          h("span", { class: "state-icon" }, icon("key")),
          h("h2", {}, "Nothing saved yet"),
          para("Sign in on a site and Deadbolt offers to save it, or add a login, note, card or key by hand."),
          button("btn primary", [glyph("plus"), "Add your first item"], () => app.go({ name: "new" })),
        ),
      )
    } else {
      const here = new Set((app.site?.accounts ?? []).map((a) => a.ref))
      const site = all.filter((a) => here.has(a.ref))
      if (q) {
        const found = [...site, ...all.filter((a) => !here.has(a.ref))].filter((a) => matches(a, q))
        parts.push(found.length ? section("Results", String(found.length), found, false) : h("div", { class: "empty" }, `Nothing matches “${app.query.trim()}”.`))
      } else {
        if (site.length) parts.push(section("This site", app.site!.host, site, true), fillError)
        else if (app.site) parts.push(h("p", { class: "site-none" }, `Nothing saved for `, h("span", { class: "mono" }, app.site.host), ` yet.`))
        const rest = all.filter((a) => !here.has(a.ref))
        if (rest.length) parts.push(section(site.length ? "Everything else" : "All items", String(all.length), rest, false))
      }
    }
    // Under the list, as in the native popup: undoing Never for this site, and Learn this site.
    if (app.site && !q) {
      if (app.site.savingOff && !app.site.offer) parts.push(savingOffLine(app.site.savingOff, app.site.tabId, () => void app.refresh()))
      if (!app.site.learning) parts.push(learnLine(app.site.tabId, () => void app.refresh()))
    }
    keepFocus(body, () => body.replaceChildren(...parts))
  }

  search.addEventListener("input", () => {
    app.query = search.value
    paint()
  })
  // ↑ ↓ move between rows (the search box is the row above the first); Escape clears the search.
  el.addEventListener("keydown", (e) => {
    const rows = [...el.querySelectorAll<HTMLElement>(".vrow-main")]
    const at = rows.indexOf(document.activeElement as HTMLElement)
    if (e.key === "ArrowDown" && (document.activeElement === search || at >= 0)) {
      e.preventDefault()
      rows[Math.min(rows.length - 1, at + 1)]?.focus()
    } else if (e.key === "ArrowUp" && at >= 0) {
      e.preventDefault()
      ;(at === 0 ? search : rows[at - 1]).focus()
    } else if (e.key === "Escape" && search.value) {
      e.preventDefault()
      search.value = app.query = ""
      paint()
      search.focus()
    } else if (e.key === "Enter" && document.activeElement === search) {
      rows[0]?.click()
    }
  })
  paint()
  const focus = () => {
    const ref = app.returnTo
    app.returnTo = null
    const back = ref ? [...el.querySelectorAll<HTMLElement>(".vrow-main")].find((r) => r.dataset.ref === ref) : undefined
    ;(back ?? search).focus()
  }
  return { el, update: paint, focus }
}

/** The one-time code's ring: it empties over the code's period, by CSS, so nothing ticks here but the seconds. */
function totpRing(period: number, left: number): SVGElement {
  const ns = "http://www.w3.org/2000/svg"
  const s = document.createElementNS(ns, "svg")
  s.setAttribute("viewBox", "0 0 20 20")
  s.setAttribute("class", "ring")
  s.setAttribute("aria-hidden", "true")
  const track = document.createElementNS(ns, "circle")
  const arc = document.createElementNS(ns, "circle")
  for (const c of [track, arc]) {
    c.setAttribute("cx", "10")
    c.setAttribute("cy", "10")
    c.setAttribute("r", "8")
  }
  track.setAttribute("class", "track")
  arc.setAttribute("class", "arc")
  arc.style.animationDuration = `${period}s`
  arc.style.animationDelay = `${-(period - left)}s`
  s.append(track, arc)
  return s
}

export function detailView(app: App, ref: string, then?: "reveal" | "copy"): View {
  const el = h("section", { class: "view detail" })
  let detail: ItemDetail | null = null
  let revealed: string | null = null
  let hideTimer: ReturnType<typeof setTimeout> | undefined
  let codeTimer: ReturnType<typeof setTimeout> | undefined
  let tick: ReturnType<typeof setInterval> | undefined
  let reauth: "reveal" | "copy" | null = app.preset === "strict" && then ? then : null
  const say = (m: string) => app.announce(m)

  /** Shows the password, out of sight again after half a minute. */
  const show = (password: string) => {
    revealed = password
    reauth = null
    paint()
    clearTimeout(hideTimer)
    hideTimer = setTimeout(() => {
      revealed = null
      if (el.isConnected) paint()
    }, 30_000)
  }

  const load = async () => {
    // Opening a login is use, once; its later reads (each new code) aren't.
    void app.run({ type: "device-used" })
    const r = await app.run({ type: "device-item", ref })
    if (!el.isConnected && detail) return
    if (!r.ok) {
      el.replaceChildren(toolbar("Login", () => app.go({ name: "list" }, -1)), h("p", { class: "error" }, r.message))
      return
    }
    detail = r.reply as unknown as ItemDetail
    paint()
    if (then === "copy" && !reauth) void copyPassword(el.querySelector<HTMLElement>(".copy-password"))
  }

  const copyPassword = async (b: HTMLElement | null, passphrase?: string) => {
    if (!detail || !b) return
    await app.offerClearing()
    const s = revealed !== null && !passphrase ? { password: revealed } : await secret(app, ref, passphrase)
    if (s.password === undefined) {
      if (s.reauth) {
        reauth = "copy"
        return paint()
      }
      return say(s.message ?? "Couldn't copy.")
    }
    await copySecret(app, b, s.password)
  }

  const reveal = async (passphrase?: string) => {
    if (revealed !== null) {
      revealed = null
      return paint()
    }
    const s = await secret(app, ref, passphrase)
    if (s.password === undefined) {
      if (s.reauth) {
        reauth = "reveal"
        return paint()
      }
      return say(s.message ?? "Couldn't show the password.")
    }
    show(s.password)
  }

  /** Strict: the passphrase, once per reveal or copy. */
  const reauthLine = (kind: "reveal" | "copy") => {
    const input = h("input", { class: "input", type: "password", autocomplete: "current-password", placeholder: "Passphrase", "aria-label": "Passphrase", spellcheck: "false" })
    const error = h("p", { class: "error" })
    error.hidden = true
    const go = h("button", { class: "btn primary", type: "submit" }, kind === "copy" ? "Copy" : "Show")
    const form = h("form", { class: "reauth", novalidate: "" }, h("p", { class: "muted small" }, kind === "copy" ? "Strict: enter your passphrase to copy this password." : "Strict: enter your passphrase to show this password."), h("div", { class: "reauth-row" }, input, go), error)
    const touch = button("btn primary", "Verify with Touch ID", async (b) => {
      b.disabled = true
      try {
        const s = await secret(app, ref, undefined, await verify(app))
        if (s.password === undefined) throw new Error(s.message || "Couldn't verify Touch ID.")
        if (kind === "reveal") show(s.password)
        else { reauth = null; paint(); await copySecret(app, el.querySelector<HTMLElement>(".copy-password")!, s.password) }
      } catch (e) { error.textContent = (e as Error).message; error.hidden = false; input.focus() }
      finally { b.disabled = false }
    })
    void enrollment(app).then((t) => { if (t && form.isConnected) { form.prepend(touch); touch.focus() } })
    form.addEventListener("submit", async (e) => {
      e.preventDefault()
      if (!input.value) return refuse(input)
      go.disabled = true
      const passphrase = input.value
      input.value = ""
      const s = await secret(app, ref, passphrase)
      go.disabled = false
      if (s.password === undefined) {
        error.textContent = s.message ?? "That passphrase isn't right."
        error.hidden = false
        refuse(input)
        return input.focus()
      }
      if (kind === "reveal") show(s.password)
      else {
        reauth = null
        paint()
        await copySecret(app, el.querySelector<HTMLElement>(".copy-password")!, s.password)
      }
    })
    queueMicrotask(() => input.focus())
    return form
  }

  const paint = () => {
    if (!detail) return
    clearInterval(tick)
    clearTimeout(codeTimer)
    const d = detail
    const host = hostOf(d.url ?? "")
    const line = (label: string, value: Node, ...actions: Node[]) => h("div", { class: "line" }, h("span", { class: "line-label" }, label), h("span", { class: "value" }, value), h("span", { class: "line-actions" }, ...actions))
    const lines: Node[] = []
    lines.push(line("Username", d.username ? h("span", {}, d.username) : h("span", { class: "faint" }, "None"), iconButton(icon("copy"), "Copy username", (b) => d.username && void copied(b, d.username, say, "Copied the username"))))
    if (d.hasPassword) {
      const eye = iconButton(glyph(revealed !== null ? "eyeOff" : "eye"), revealed !== null ? "Hide password" : "Show password", () => void reveal())
      const copy = iconButton(icon("copy"), "Copy password", (b) => void copyPassword(b), "copy-password")
      lines.push(line("Password", revealed !== null ? h("span", { class: "mono secret" }, revealed) : h("span", { class: "dots" }, "••••••••••••"), eye, copy))
      if (reauth) lines.push(reauthLine(reauth))
    }
    if (d.totp) {
      const t = d.totp
      const left = Math.max(0, t.until - Date.now() / 1000)
      const secs = h("span", { class: "secs mono" }, String(Math.ceil(left)))
      const code = `${t.code.slice(0, Math.ceil(t.code.length / 2))} ${t.code.slice(Math.ceil(t.code.length / 2))}`
      lines.push(
        line(
          "One-time code",
          h("span", { class: "totp" }, h("span", { class: "mono code-value" }, code), h("span", { class: `countdown${left <= 5 ? " ending" : ""}` }, totpRing(t.period, left), secs, h("span", { class: "sr-only" }, " seconds left"))),
          iconButton(icon("copy"), "Copy one-time code", async (b) => {
            await app.offerClearing()
            await copySecret(app, b, t.code)
          }),
        ),
      )
      tick = setInterval(() => {
        const l = Math.max(0, t.until - Date.now() / 1000)
        secs.textContent = String(Math.ceil(l))
        secs.parentElement?.classList.toggle("ending", l <= 5)
      }, 250)
      // The next code, a moment after this one ends.
      codeTimer = setTimeout(() => void refreshCode(), left * 1000 + 150)
    }
    const website = d.url
    if (website) lines.push(line("Website", h("span", {}, host), iconButton(glyph("open"), "Open site", () => openSite(website))))
    const notes = d.fields.find((f) => f.name === "notes")?.value
    if (notes) lines.push(h("div", { class: "line" }, h("span", { class: "line-label" }, "Notes"), h("span", { class: "value lines" }, notes), h("span", { class: "line-actions" }, iconButton(icon("copy"), "Copy notes", (b) => void copied(b, notes, say, "Copied the notes")))))
    keepFocus(el, () =>
      el.replaceChildren(
        toolbar("", () => app.go({ name: "list" }, -1), button("btn", "Edit", () => app.go({ name: "edit", ref, kind: "login" }))),
        h("div", { class: "detail-head" }, avatarFor(app, d.title, d.url ?? "", "detail"), h("div", { class: "text" }, h("h2", { class: "title" }, d.title), h("span", { class: "sub" }, host || "No website"))),
        h("div", { class: "box" }, ...lines),
        h("div", { class: "buttons end" }, deleteButton(app, ref, d.title)),
      ),
    )
  }

  const refreshCode = async () => {
    const r = await app.run({ type: "device-item", ref })
    if (!el.isConnected || !r.ok) return
    detail = r.reply as unknown as ItemDetail
    paint()
  }

  el.append(toolbar("", () => app.go({ name: "list" }, -1)), h("div", { class: "skeleton" }, h("div", { class: "skeleton-row" }), h("div", { class: "skeleton-row" })))
  void load()
  return {
    el,
    update: () => void refreshCode(),
    leave: () => {
      revealed = null
      clearTimeout(hideTimer)
      clearTimeout(codeTimer)
      clearInterval(tick)
    },
    focus: () => queueMicrotask(() => el.querySelector<HTMLElement>(".back")?.focus()),
  }
}

export function editView(app: App, ref?: string): View {
  // An edit shows what's saved: from the list if it's loaded, and from the vault either way.
  const existing = ref ? app.logins?.find((a) => a.ref === ref) : undefined
  const siteUrl = !ref && app.site ? `https://${app.site.host}` : ""
  const title = field("Title", { value: existing?.title ?? (app.site && !ref ? app.site.host : ""), maxlength: "500", placeholder: "Acme" })
  const site = field("Website", { inputmode: "url", value: existing ? url(existing) : siteUrl, placeholder: "https://example.com", maxlength: "2048" })
  const user = field("Username", { value: existing?.username ?? "", maxlength: "500", placeholder: "you@example.com" })
  const show = iconButton(glyph("eye"), "Show password", () => {
    const hidden = pass.input.type === "password"
    pass.input.type = hidden ? "text" : "password"
    show.replaceChildren(glyph(hidden ? "eyeOff" : "eye"))
    show.setAttribute("aria-label", hidden ? "Hide password" : "Show password")
  })
  const dice = iconButton(glyph("dice"), "Generate a password", () => toggleGenerator())
  const pass = field(ref ? "New password" : "Password", { type: "password", autocomplete: "new-password", maxlength: "4096", placeholder: ref ? "Unchanged" : "" }, show, dice)
  pass.input.classList.add("mono-input")
  // The one-time password's secret never comes back to the form: empty keeps it, Remove takes it off.
  let hadOtp = !!existing?.hasTotp
  let dropOtp = false
  const removeOtp = button("link", "Remove", () => {
    dropOtp = true
    otp.input.value = ""
    otp.input.placeholder = "Removed when you save"
    removeOtp.hidden = true
  })
  const otp = field("One-time password", { type: "password", autocomplete: "off", maxlength: "4096", placeholder: hadOtp ? "Unchanged" : "Secret or otpauth:// link" }, removeOtp)
  otp.input.classList.add("mono-input")
  removeOtp.hidden = !hadOtp
  otp.input.addEventListener("input", () => (dropOtp = false))
  const notesId = `f-${Math.random().toString(36).slice(2, 9)}`
  const notes = h("textarea", { class: "input area", id: notesId, rows: "3", maxlength: "65536", spellcheck: "false" })
  let savedNotes = ""

  // The generator: the core's (letters, digits and, if chosen, symbols, at least one of each).
  const length = h("input", { type: "range", min: "12", max: "48", value: "24", "aria-label": "Length" })
  const lengthOut = h("output", { class: "mono" }, "24")
  const symbols = h("input", { type: "checkbox", checked: "" })
  const preview = h("span", { class: "mono gen-value" })
  let asked = 0
  const regenerate = async () => {
    lengthOut.textContent = length.value
    const n = ++asked
    const r = await app.run({ type: "device-generate", length: Number(length.value), symbols: symbols.checked })
    // Only the latest slider position's password lands.
    if (n !== asked) return
    if (!r.ok || typeof r.reply.password !== "string") return fail(r.ok ? "Deadbolt didn't make a password." : r.message)
    preview.textContent = r.reply.password
    pass.input.value = r.reply.password
    pass.input.type = "text"
    show.replaceChildren(glyph("eyeOff"))
  }
  const generator = h(
    "div",
    { class: "generator", hidden: "" },
    h("div", { class: "gen-head" }, preview, iconButton(glyph("sync"), "Another password", () => void regenerate())),
    h("label", { class: "gen-length" }, h("span", {}, "Length"), length, lengthOut),
    h("div", { class: "gen-options" }, h("label", { class: "check" }, symbols, "Symbols")),
  )
  for (const c of [length, symbols]) c.addEventListener("input", () => void regenerate())
  const toggleGenerator = () => {
    generator.hidden = !generator.hidden
    dice.classList.toggle("on", !generator.hidden)
    if (!generator.hidden) void regenerate()
  }

  const error = h("p", { class: "error", role: "alert" })
  error.hidden = true
  const label = h("span", { class: "roll-label" }, "Save")
  label.dataset.text = "Save"
  const save = h("button", { class: "btn primary", type: "submit" }, label)
  const cancel = () => (ref ? app.go({ name: "item", ref }, -1) : app.go({ name: "list" }, -1))
  const form = h(
    "form",
    { class: "view edit", novalidate: "" },
    toolbar(ref ? "Edit login" : "New login", cancel),
    title.wrap,
    site.wrap,
    user.wrap,
    pass.wrap,
    generator,
    otp.wrap,
    h("div", { class: "field" }, h("label", { for: notesId }, "Notes"), notes),
    error,
    h("div", { class: "buttons end" }, button("btn", "Cancel", cancel), save),
  )
  const fail = (message: string, input?: HTMLInputElement) => {
    error.textContent = message
    error.hidden = false
    if (input) {
      refuse(input)
      input.focus()
    }
  }
  for (const i of [title.input, site.input, user.input, pass.input]) i.addEventListener("input", () => i.classList.remove("invalid"))
  // Editing: Save waits until the saved login is in the form, so an edit
  // opened before the list loaded never saves blanks over it.
  if (ref) {
    save.disabled = true
    void app.run({ type: "device-item", ref }).then((r) => {
      if (!r.ok) return fail(r.message)
      const d = r.reply as unknown as ItemDetail
      if (!title.input.value) title.input.value = d.title
      if (!site.input.value) site.input.value = d.url ?? ""
      if (!user.input.value) user.input.value = d.username ?? ""
      savedNotes = d.fields.find((f) => f.name === "notes")?.value ?? ""
      if (!notes.value) notes.value = savedNotes
      hadOtp = d.fields.some((f) => f.type === "otp")
      removeOtp.hidden = !hadOtp || dropOtp
      if (!dropOtp) otp.input.placeholder = hadOtp ? "Unchanged" : "Secret or otpauth:// link"
      save.disabled = false
    })
  }
  form.addEventListener("submit", async (e) => {
    e.preventDefault()
    const raw = site.input.value.trim()
    let origin: string
    try {
      const u = new URL(raw.includes("://") ? raw : `https://${raw}`)
      if (!raw || (u.protocol !== "https:" && u.protocol !== "http:")) throw new Error()
      origin = u.origin
    } catch {
      return fail("Enter the site's address, like https://example.com.", site.input)
    }
    if (!ref && !pass.input.value) return fail("Enter a password, or generate one.", pass.input)
    save.disabled = true
    rollLabel(label, "Saving…")
    const typedOtp = otp.input.value.trim()
    const entry = {
      title: title.input.value.trim() || new URL(origin).hostname,
      url: origin,
      username: user.input.value.trim(),
      password: pass.input.value,
      // Only what changed: empty removes, absent keeps.
      ...(typedOtp ? { otp: typedOtp } : dropOtp ? { otp: "" } : {}),
      ...(notes.value !== savedNotes ? { notes: notes.value } : {}),
    }
    const r = await app.run(ref ? { type: "device-save", ref, entry } : { type: "device-save", entry })
    if (!r.ok) {
      save.disabled = false
      rollLabel(label, "Save")
      return fail(r.message)
    }
    pass.input.value = ""
    otp.input.value = ""
    await app.refresh()
    app.announce(ref ? "Saved." : "Login added.")
    app.go({ name: "item", ref: typeof r.reply.ref === "string" ? r.reply.ref : (ref ?? "") }, ref ? -1 : 1)
  })
  return { el: form, focus: () => (ref ? pass.input : title.input).focus() }
}
