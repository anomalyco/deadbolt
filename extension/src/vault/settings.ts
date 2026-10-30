// Settings: the vault's devices (pair another, remove one), the lock preset
// and the vault's name.

import { describePreset, PRESETS, VAULT_NAME } from "../device-rules"
import type { LockPreset, VaultDevice } from "../messages"
import { h } from "../ui/dom"
import { rollLabel } from "../ui/motion"
import type { App, View } from "./app"
import { CLIPBOARD_PERMISSIONS } from "../bg/clipboard"
import { ago, button, glyph, iconButton, para, refuse, toolbar } from "./kit"
import { aboutSection } from "./about"
import { appearanceRows } from "../ui/appearance"

function deviceRow(app: App, d: VaultDevice, repaint: () => void): HTMLElement {
  const now = Date.now() / 1000
  const sub = d.current ? "This browser" : d.lastSeen ? `Synced ${ago(d.lastSeen, now)}` : "Hasn't synced with this browser yet"
  const online = !d.current && !!d.lastSeen && now - d.lastSeen <= 6 * 60
  const row = h(
    "div",
    { class: "vrow device" },
    h("span", { class: "tile" }, glyph(d.current || /chrome|edge|brave|opera|vivaldi|chromium|browser/i.test(d.name) ? "browser" : "laptop"), online ? h("span", { class: "online", title: "Online" }) : null),
    h("span", { class: "text" }, h("span", { class: "title" }, d.name), h("span", { class: "sub" }, sub)),
  )
  if (!d.current) {
    const remove = iconButton(glyph("trash"), `Remove ${d.name}`, () => askRemove())
    row.append(h("span", { class: "vrow-actions" }, remove))
    const askRemove = () => {
      const no = button("btn", "Cancel", () => repaint())
      const label = h("span", { class: "roll-label" }, "Remove")
      label.dataset.text = "Remove"
      const yes = button("btn danger", label, async (b) => {
        b.disabled = true
        rollLabel(label, "Removing…")
        const r = await app.run({ type: "device-remove", id: d.id })
        if (!r.ok) {
          b.disabled = false
          rollLabel(label, "Remove")
          app.announce(r.message)
          row.querySelector(".confirm-text")!.textContent = r.message
          return
        }
        await app.refresh()
        app.announce(`Removed ${d.name}.`)
      })
      row.classList.add("confirming")
      row.replaceChildren(
        h("span", { class: "text" }, h("span", { class: "title" }, `Remove ${d.name}?`), h("span", { class: "sub confirm-text" }, "It stops syncing. What it already has stays on it.")),
        h("span", { class: "vrow-actions shown" }, no, yes),
      )
      no.focus()
    }
  }
  return row
}

export function settingsView(app: App): View {
  const el = h("section", { class: "view settings" })

  // Vault name: renaming is the vault's own, and syncs to the other devices.
  const name = h("input", { class: "input", value: app.vaultName, maxlength: "64", "aria-label": "Vault name", spellcheck: "false" })
  const rename = button("btn", "Rename", async (b) => {
    const value = name.value.trim()
    if (!VAULT_NAME.test(value)) {
      nameHint.textContent = "Start with a lowercase letter; then lowercase letters, digits, - or _."
      nameHint.classList.add("error")
      return refuse(name)
    }
    b.disabled = true
    const r = await app.run({ type: "device-rename", name: value })
    b.disabled = false
    if (!r.ok) {
      nameHint.textContent = r.message
      nameHint.classList.add("error")
      return
    }
    await app.refresh()
    app.announce("Renamed.")
  })
  const nameHint = h("p", { class: "hint" }, "Your other devices see this name.")
  const nameChanged = () => {
    rename.hidden = name.value.trim() === app.vaultName
    name.classList.remove("invalid")
    nameHint.classList.remove("error")
    nameHint.textContent = "Your other devices see this name."
  }
  name.addEventListener("input", nameChanged)
  name.addEventListener("keydown", (e) => {
    if (e.key === "Enter") rename.click()
  })

  // Devices, and pairing another one: it shows a code (`deadbolt join`), typed here.
  const devices = h("div", { class: "rows" })
  const pairArea = h("div", { class: "pair-area" })
  const pairStart = button("btn", [glyph("plus"), "Pair another device"], () => openPair())
  const openPair = () => {
    const code = h("input", { class: "input mono-input", placeholder: "word-word-word-word", "aria-label": "Pairing code", spellcheck: "false", autocomplete: "off" })
    const error = h("p", { class: "error", role: "alert" })
    error.hidden = true
    const label = h("span", { class: "roll-label" }, "Pair")
    label.dataset.text = "Pair"
    const go = h("button", { class: "btn primary", type: "submit" }, label)
    const form = h(
      "form",
      { class: "pair-form", novalidate: "" },
      para("On the other device, run ", h("code", {}, "deadbolt join"), " or choose Join in the Deadbolt app, then enter the code it shows."),
      h("div", { class: "reauth-row" }, code, go),
      error,
      h("div", { class: "buttons end" }, button("link", "Cancel", () => pairArea.replaceChildren(pairStart))),
    )
    form.addEventListener("submit", async (e) => {
      e.preventDefault()
      const value = code.value.trim().toLowerCase()
      if (!value) return refuse(code)
      go.disabled = true
      code.disabled = true
      rollLabel(label, "Pairing…")
      const r = await app.run({ type: "device-pair", code: value })
      if (!r.ok) {
        go.disabled = code.disabled = false
        rollLabel(label, "Pair")
        error.textContent = r.message
        error.hidden = false
        return code.focus()
      }
      pairArea.replaceChildren(pairStart)
      await app.refresh()
      app.announce("Paired.")
    })
    pairArea.replaceChildren(form)
    code.focus()
  }
  pairArea.append(pairStart)

  // The lock preset, as a radio group.
  const presets = h("div", { class: "presets", role: "radiogroup", "aria-label": "Lock" })
  const paintPresets = () => {
    presets.replaceChildren(
      ...(Object.keys(PRESETS) as LockPreset[]).map((p) => {
        const info = PRESETS[p]
        const input = h("input", { type: "radio", name: "preset", value: p, ...(p === app.preset ? { checked: "" } : {}) })
        input.addEventListener("change", async () => {
          // Strict clears copied passwords if Chrome allows it: ask now, from this click.
          const asking = info.reauth && !(await app.clears()) ? app.askClearing() : null
          const r = await app.run({ type: "device-preset", preset: p })
          if (r.ok) app.preset = p
          if (asking) clearing.checked = await asking
          paintPresets()
          app.announce(`${info.name}.`)
        })
        return h("label", { class: `preset${p === app.preset ? " on" : ""}` }, input, h("span", { class: "text" }, h("span", { class: "title" }, info.name, p === "comfortable" ? h("span", { class: "faint" }, " · default") : null), h("span", { class: "sub" }, describePreset(p))))
      }),
    )
  }

  // Clearing copied passwords needs Chrome's clipboard permissions, asked for here.
  const clearing = h("input", { type: "checkbox", role: "switch", "aria-describedby": "clearing-hint" })
  void app.clears().then((on) => (clearing.checked = on))
  clearing.addEventListener("change", async () => {
    if (clearing.checked) clearing.checked = await app.askClearing()
    else await chrome.permissions.remove({ permissions: CLIPBOARD_PERMISSIONS }).catch(() => false)
    app.announce(clearing.checked ? "Copied passwords clear after 30 seconds." : "Copied passwords stay until you copy something else.")
  })

  const paint = () => {
    // This browser first, then the others by name.
    const sorted = [...(app.devices ?? [])].sort((a, b) => Number(b.current) - Number(a.current) || a.name.localeCompare(b.name))
    devices.replaceChildren(...sorted.map((d) => deviceRow(app, d, paint)))
    if (document.activeElement !== name) {
      name.value = app.vaultName
      nameChanged()
    }
  }
  paintPresets()
  paint()
  el.append(
    toolbar("Settings", () => app.go({ name: "list" }, -1)),
    h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, "Devices")), devices, pairArea),
    h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, "Lock")), presets, h("p", { class: "hint" }, "Every preset locks when the browser quits.")),
    h(
      "section",
      { class: "group" },
      h("div", { class: "section-head" }, h("span", { class: "label" }, "Clipboard")),
      h(
        "label",
        { class: "switch-row" },
        h("span", { class: "text" }, h("span", { class: "title" }, "Clear copied passwords after 30 seconds"), h("span", { class: "sub", id: "clearing-hint" }, "Chrome asks to let Deadbolt read the clipboard, so it clears only what it copied.")),
        clearing,
      ),
    ),
    h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, "Appearance")), ...appearanceRows(app.icons, (m) => app.announce(m)), h("p", { class: "hint" }, "Well-known sites' marks come from Simple Icons, bundled; they're their owners' trademarks.")),
    h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, "Vault name")), h("div", { class: "reauth-row" }, name, rename), nameHint),
    aboutSection(app),
    app.surface !== "popup"
      ? ""
      : h("p", { class: "open-tab" }, button("link", ["Open Deadbolt in a tab", glyph("open")], () => {
          void chrome.tabs.create({ url: chrome.runtime.getURL("device.html") })
          window.close()
        })),
  )
  return { el, update: paint }
}
