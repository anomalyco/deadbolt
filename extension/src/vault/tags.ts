// Favorites and nested `/` tags in the browser-only Deadbolt's vault UI:
// favorites-first sorting, `#tag` / `#"..."` / `is:favorite` search parsing,
// row star badges, toolbar star toggles, clickable `#tag` chips, and the form's
// tag chip editor.

import type { ItemDetail, ItemSummary } from "../messages"
import { h } from "../ui/dom"
import type { App } from "./app"
import { button, glyph, hostOf, iconButton } from "./kit"

const MAX_TAG_LEN = 128
const MAX_TAGS = 64

export const foldTag = (tag: string): string => tag.toLowerCase()

/** Cleans a user-typed tag, preserving case across non-empty `/` segments. */
export function normalizeTag(raw: string): string | null {
  const body = raw.trim().replace(/^#+/, "")
  if (!body || [...body].some((c) => c < " " || c === "\x7f")) return null
  const parts = body.split("/").map((p) => p.trim())
  if (!parts.length || parts.some((p) => !p)) return null
  const out = parts.join("/")
  return [...out].length >= 1 && [...out].length <= MAX_TAG_LEN && !out.startsWith("#") ? out : null
}

/** Formats `tag` as a vault search token (`#work/aws` or `#"Tax 2026"`). */
export const tagToken = (tag: string): string => (/\s/.test(tag) ? `#"${tag}"` : `#${tag}`)

/** Sorts favorites first, then alphabetically by title. */
export function sortItems<T extends { favorite?: boolean; title: string; ref: string }>(items: T[]): T[] {
  return [...items].sort((a, b) => (a.favorite ? 0 : 1) - (b.favorite ? 0 : 1) || a.title.localeCompare(b.title) || a.ref.localeCompare(b.ref))
}

/** Whether `itemTag` matches `filter` on `/` segment boundaries (or `#tax-2026` -> `Tax 2026`). */
export function tagMatches(itemTag: string, filter: string): boolean {
  const fl = foldTag(filter.trim().replace(/^#+/, "").replace(/^\/+|\/+$/g, ""))
  if (!fl) return false
  const it = foldTag(itemTag)
  const boundary = (needle: string) => it === needle || it.startsWith(`${needle}/`)
  if (boundary(fl)) return true
  if (!fl.includes(" ") && fl.includes("-") && it.includes(" ")) return boundary(fl.replace(/-/g, " "))
  return false
}

export interface ParsedQuery {
  words: string[]
  tags: string[]
  favorite: boolean
  anyTag: boolean
  typingTag: boolean
}

export function parseQuery(raw: string): ParsedQuery {
  const out: ParsedQuery = { words: [], tags: [], favorite: false, anyTag: false, typingTag: false }
  let i = 0
  while (i < raw.length) {
    while (i < raw.length && /\s/.test(raw[i]!)) i++
    if (i >= raw.length) break
    if (raw.startsWith('#"', i)) {
      const start = i + 2
      const close = raw.indexOf('"', start)
      const body = close < 0 ? raw.slice(start) : raw.slice(start, close)
      const cleaned = body.trim().replace(/^\/+|\/+$/g, "")
      if (cleaned) out.tags.push(cleaned)
      else out.anyTag = true
      if (close < 0) {
        out.typingTag = !!cleaned
        break
      }
      i = close + 1
      continue
    }
    let end = i
    while (end < raw.length && !/\s/.test(raw[end]!)) end++
    const tok = raw.slice(i, end)
    const lower = tok.toLowerCase()
    if (lower === "is:favorite" || lower === "is:fav" || lower === "is:starred") {
      out.favorite = true
    } else if (tok.startsWith("#")) {
      const cleaned = tok.slice(1).trim().replace(/^\/+|\/+$/g, "")
      if (cleaned) {
        out.tags.push(cleaned)
        if (end === raw.length) out.typingTag = true
      } else {
        out.anyTag = true
      }
    } else {
      out.words.push(lower)
    }
    i = end
  }
  return out
}

/** Matches an item against plain words, `#tag` hierarchy filters, and `is:favorite`. */
export function matchesSearch(item: ItemSummary, rawQuery: string, anyTagged: boolean): boolean {
  const q = parseQuery(rawQuery)
  const itemTags = item.tags ?? []
  if (q.favorite && !item.favorite) return false
  if (q.anyTag && anyTagged && !itemTags.length) return false
  for (let idx = 0; idx < q.tags.length; idx++) {
    const tf = q.tags[idx]!
    const typing = q.typingTag && idx === q.tags.length - 1
    const ok = itemTags.some((t) => tagMatches(t, tf) || (typing && foldTag(t).startsWith(foldTag(tf))))
    if (!ok) return false
  }
  if (!q.words.length) return true
  const texts = [item.title, item.username ?? "", ...item.urls.map(hostOf), ...item.search, ...itemTags].map((s) => s.toLowerCase())
  return q.words.every((w) => texts.some((s) => s.includes(w)))
}

/** Small quiet star shown beside a favorite item's title in list rows. */
export function starBadge(favorite?: boolean): HTMLElement | null {
  if (!favorite) return null
  const el = h("span", { class: "fav-star", "aria-hidden": "true" }, glyph("starFill"))
  return el
}

/** Toolbar star toggle on an item's detail page. */
export function starButton(app: App, detail: ItemDetail, onUpdated: (favorite: boolean) => void): HTMLButtonElement {
  const fav = !!detail.favorite
  const label = fav ? "Unfavorite" : "Favorite"
  const b = iconButton(glyph(fav ? "starFill" : "star"), label, async (btn) => {
    btn.disabled = true
    const next = !detail.favorite
    const r = await app.run({ type: "device-item-save", ref: detail.ref, fields: [], favorite: next })
    btn.disabled = false
    if (!r.ok) return app.announce(r.message)
    onUpdated(next)
    await app.refresh()
    app.announce(next ? "Added to favorites." : "Removed from favorites.")
  })
  b.setAttribute("aria-pressed", String(fav))
  return b
}

/** Clickable `#tag` chips under an item's detail heading. */
export function tagChips(app: App, tags?: string[]): HTMLElement | null {
  if (!tags?.length) return null
  return h(
    "div",
    { class: "tag-chips" },
    ...tags.map((t) =>
      button(
        "tag-chip",
        `#${t}`,
        () => {
          app.query = `${tagToken(t)} `
          app.go({ name: "list" }, -1)
        },
        { "aria-label": `Filter by #${t}` },
      ),
    ),
  )
}

/** Tag chip editor and favorite star control for login and item forms. */
export function metaEditor(app: App, initialFavorite = false, initialTags: string[] = []) {
  let favorite = initialFavorite
  let tags = [...initialTags]
  const favBtn = iconButton(glyph(favorite ? "starFill" : "star"), favorite ? "Unfavorite" : "Favorite", () => setFavorite(!favorite), "meta-fav")
  favBtn.setAttribute("aria-pressed", String(favorite))

  const setFavorite = (next: boolean) => {
    favorite = next
    favBtn.replaceChildren(glyph(favorite ? "starFill" : "star"))
    const label = favorite ? "Unfavorite" : "Favorite"
    favBtn.setAttribute("aria-label", label)
    favBtn.setAttribute("title", label)
    favBtn.setAttribute("aria-pressed", String(favorite))
  }

  const chips = h("div", { class: "tag-chips edit-chips" })
  const listId = `tags-${Math.random().toString(36).slice(2, 9)}`
  const inputId = `f-${Math.random().toString(36).slice(2, 9)}`
  const datalist = h("datalist", { id: listId })
  const input = h("input", { class: "input", id: inputId, list: listId, autocomplete: "off", spellcheck: "false", maxlength: String(MAX_TAG_LEN), placeholder: "Add tag (work/aws)" })

  const knownTags = () => {
    const seen = new Map<string, string>()
    for (const item of app.items ?? []) {
      for (const t of item.tags ?? []) {
        const parts = t.split("/")
        for (let n = 1; n <= parts.length; n++) {
          const p = parts.slice(0, n).join("/")
          const k = foldTag(p)
          if (!seen.has(k)) seen.set(k, p)
        }
      }
    }
    return [...seen.values()].filter((t) => !tags.some((e) => foldTag(e) === foldTag(t))).sort((a, b) => a.localeCompare(b))
  }

  const paintChips = () => {
    chips.hidden = !tags.length
    chips.replaceChildren(
      ...tags.map((t, i) =>
        h(
          "span",
          { class: "tag-chip editable" },
          `#${t}`,
          button(
            "tag-remove",
            "×",
            () => {
              tags.splice(i, 1)
              paintChips()
            },
            { "aria-label": `Remove tag ${t}` },
          ),
        ),
      ),
    )
    datalist.replaceChildren(...knownTags().map((t) => h("option", { value: t })))
  }

  const addRaw = (raw: string): string | null => {
    const clean = normalizeTag(raw)
    if (!clean) return "A tag is 1 to 128 characters, with non-empty / parts."
    const existing = tags.findIndex((t) => foldTag(t) === foldTag(clean))
    if (existing >= 0) tags[existing] = clean
    else {
      if (tags.length >= MAX_TAGS) return `An item can have at most ${MAX_TAGS} tags.`
      tags.push(clean)
    }
    tags.sort((a, b) => foldTag(a).localeCompare(foldTag(b)))
    return null
  }

  input.addEventListener("input", () => {
    input.classList.remove("invalid")
    if (!input.value.includes(",")) return
    const parts = input.value.split(",")
    const tail = parts.pop() ?? ""
    for (const part of parts) {
      if (part.trim().replace(/^#+/, "")) addRaw(part)
    }
    input.value = tail.trimStart()
    paintChips()
  })

  input.addEventListener("keydown", (e) => {
    if (e.key === "Backspace" && !input.value && tags.length) {
      tags.pop()
      paintChips()
    } else if (e.key === "Enter" && input.value.trim().replace(/^#+/, "")) {
      e.preventDefault()
      const err = addRaw(input.value)
      if (!err) {
        input.value = ""
        paintChips()
      }
    }
  })

  paintChips()
  const wrap = h("div", { class: "field" }, h("label", { for: inputId }, "Tags"), chips, input, datalist)
  return {
    favBtn,
    tagsWrap: wrap,
    input,
    setMeta: (fav: boolean, nextTags: string[]) => {
      setFavorite(fav)
      tags = [...nextTags]
      paintChips()
    },
    read: (): { favorite: boolean; tags: string[]; error?: string } => {
      if (input.value.trim().replace(/^#+/, "")) {
        const err = addRaw(input.value)
        if (err) return { favorite, tags, error: err }
        input.value = ""
        paintChips()
      }
      return { favorite, tags: [...tags] }
    },
  }
}
