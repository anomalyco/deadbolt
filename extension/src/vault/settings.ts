// Settings: the vault's devices (pair another, remove one), its passkeys
// (delete one), the lock preset, sites never offered to save, learning logs
// and the vault's name.

import { describePreset, PRESETS, VAULT_NAME } from "../device-rules"
import type { DevicePasskey, LockPreset, VaultDevice } from "../messages"
import { h, icon } from "../ui/dom"
import { rollLabel } from "../ui/motion"
import type { App, View } from "./app"
import { CLIPBOARD_PERMISSIONS } from "../bg/clipboard"
import { clearLearnLogs, learnExport, learnLogs } from "../bg/learn-log"
import { NEVER_KEY } from "../bg/save"
import { ago, button, glyph, iconButton, para, refuse, toolbar } from "./kit"
import { enroll, enrollment } from "./biometric"
import { aboutSection } from "./about"
import { appearanceRows } from "../ui/appearance"
import { SIGNIN_SETTING } from "../auth-state"

function signInSetting(app: App): HTMLElement {
  const toggle = h("input", { type: "checkbox", role: "switch", "aria-label": "Offer to sign in" })
  void chrome.storage.local.get(SIGNIN_SETTING).then((s) => { toggle.checked = s[SIGNIN_SETTING] === true })
  toggle.addEventListener("change", async () => {
    try {
      await chrome.storage.local.set({ [SIGNIN_SETTING]: toggle.checked })
      app.announce(toggle.checked ? "Sign-in offers on." : "Sign-in offers off.")
    } catch { toggle.checked = !toggle.checked; app.announce("Couldn't change sign-in offers.") }
  })
  return h("label", { class: "switch-row" }, h("span", { class: "text" },
    h("span", { class: "title" }, "Offer to sign in"),
    h("span", { class: "sub" }, "Experimental. A corner offer fills and submits after you pick an account. Escape stops it.")), toggle)
}

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

/**
 * A passkey: its account and site, and Delete (asked first). Its key never
 * leaves the vault. Strict asks for the passphrase to delete one, as the
 * vault itself does (device-delete answers `passphrase_needed` without it).
 */
function passkeyRow(app: App, k: DevicePasskey, repaint: () => void): HTMLElement {
  const name = k.username || "Passkey"
  const created = k.created ? new Date(k.created) : null
  const when = created && !Number.isNaN(created.getTime()) ? `Added ${created.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}` : ""
  const row = h(
    "div",
    { class: "vrow device" },
    h("span", { class: "tile" }, icon("passkey")),
    h("span", { class: "text" }, h("span", { class: "title" }, name), h("span", { class: "sub" }, [k.rpId, when].filter(Boolean).join(" · "))),
    h("span", { class: "vrow-actions" }, iconButton(glyph("trash"), `Delete passkey ${name} for ${k.rpId}`, () => askDelete(app.preset === "strict"))),
  )
  const askDelete = (strict: boolean) => {
    const no = button("btn", "Cancel", () => {
      row.classList.remove("confirming")
      repaint()
    })
    const label = h("span", { class: "roll-label" }, "Delete")
    label.dataset.text = "Delete"
    const passphrase = strict ? h("input", { class: "input", type: "password", autocomplete: "current-password", placeholder: "Passphrase", "aria-label": "Passphrase", spellcheck: "false" }) : null
    const yes = button("btn danger", label, async (b) => {
      const value = passphrase?.value ?? ""
      if (passphrase && !value) return refuse(passphrase)
      b.disabled = true
      if (passphrase) passphrase.value = ""
      rollLabel(label, "Deleting…")
      const r = await app.run(value ? { type: "device-delete", ref: k.ref, passphrase: value } : { type: "device-delete", ref: k.ref })
      if (!r.ok) {
        // The vault holds Strict even if this page didn't know: ask for the passphrase and try again.
        if (r.code === "passphrase_needed" && !passphrase) return askDelete(true)
        b.disabled = false
        rollLabel(label, "Delete")
        app.announce(r.message)
        row.querySelector(".confirm-text")!.textContent = r.code === "wrong_passphrase" ? "That passphrase isn't right." : r.message
        if (passphrase) {
          refuse(passphrase)
          passphrase.focus()
        }
        return
      }
      await app.refresh()
      app.announce(`Deleted the passkey for ${k.rpId}.`)
    })
    passphrase?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") yes.click()
    })
    const why = strict ? `Strict: enter your passphrase to delete it. You can't sign in to ${k.rpId} as ${name} with it again, on any device.` : `You can't sign in to ${k.rpId} as ${name} with it again, on any device.`
    row.classList.add("confirming")
    row.replaceChildren(
      h("span", { class: "text" }, h("span", { class: "title" }, `Delete passkey for ${k.rpId}?`), h("span", { class: "sub confirm-text" }, why), passphrase),
      h("span", { class: "vrow-actions shown" }, no, yes),
    )
    ;(passphrase ?? no).focus()
  }
  return row
}

/** The sites "Never for this site" turned saving off for (bg/save.ts keeps them in chrome.storage.local), each with Turn on. */
function neverRows(app: App): HTMLElement {
  const rows = h("div", { class: "rows" })
  const paint = async () => {
    const got = (await chrome.storage.local.get(NEVER_KEY).catch(() => ({}))) as Record<string, unknown>
    const sites = Array.isArray(got[NEVER_KEY]) ? (got[NEVER_KEY] as unknown[]).filter((s): s is string => typeof s === "string").sort() : []
    if (!sites.length) return rows.replaceChildren(h("p", { class: "hint" }, "Deadbolt offers to save on every site. “Never for this site” on an offer turns it off for that site."))
    rows.replaceChildren(
      ...sites.map((site) =>
        h(
          "div",
          { class: "vrow" },
          h("span", { class: "text" }, h("span", { class: "title mono" }, site), h("span", { class: "sub" }, "Never offered to save")),
          h("span", { class: "vrow-actions shown" }, button("btn", "Turn on", async () => {
            const now = (await chrome.storage.local.get(NEVER_KEY).catch(() => ({}))) as Record<string, unknown>
            const list = Array.isArray(now[NEVER_KEY]) ? (now[NEVER_KEY] as unknown[]).filter((s) => s !== site) : []
            await chrome.storage.local.set({ [NEVER_KEY]: list }).catch(() => {})
            app.announce(`Saving is on for ${site}.`)
            void paint()
          }, { "aria-label": `Turn saving on for ${site}` })),
        ),
      ),
    )
  }
  void paint()
  return rows
}

/** "Learn this site" logs (bg/learn-log.ts): how many, Download for `bun corpus/learned.ts --file`, Delete. */
function learnRows(app: App): HTMLElement {
  const box = h("div", {})
  const paint = async () => {
    const logs = await learnLogs().catch(() => [])
    if (!logs.length) return box.replaceChildren(h("p", { class: "hint" }, "None yet. “Learn this site” in the popup records how a sign-in form is built while you sign in by hand, never what you type."))
    const download = button("btn", [glyph("open"), "Download"], async () => {
      const url = URL.createObjectURL(new Blob([learnExport(await learnLogs())], { type: "application/x-ndjson" }))
      const a = h("a", { href: url, download: `deadbolt-learn-${new Date().toISOString().slice(0, 10)}.jsonl` })
      document.body.append(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 10_000)
    })
    const clear = button("btn", [glyph("trash"), "Delete"], async () => {
      await clearLearnLogs().catch(() => {})
      app.announce("Deleted the learning logs.")
      void paint()
    })
    box.replaceChildren(h("p", { class: "hint" }, `${logs.length} ${logs.length === 1 ? "session" : "sessions"} kept in this browser, the newest 50 for 30 days.`), h("div", { class: "buttons" }, download, clear))
  }
  void paint()
  return box
}

export function settingsView(app: App): View {
  const el = h("section", { class: "view settings" })
  const biometrics = h("section", { class: "group" })
  const paintBiometric = async () => {
    const enabled = !!(await enrollment(app))
    const error = h("p", { class: "error", role: "alert" })
    const action = button("btn", enabled ? "Reset Touch ID" : "Set up Touch ID", async (b) => {
      if (enabled) {
        b.disabled = true
        const r = await app.run({ type: "device-biometric-reset" })
        if (!r.ok) { error.textContent = r.message; b.disabled = false; return }
        await chrome.storage.local.set({ "deadbolt.unlockMethod": "passphrase" })
        return paintBiometric()
      }
      const pass = h("input", { class: "input", type: "password", autocomplete: "current-password", "aria-label": "Passphrase for Touch ID", placeholder: "Current passphrase" })
      const submit = h("button", { class: "btn primary", type: "submit" }, "Enable Touch ID")
      const form = h("form", { novalidate: "" }, h("div", { class: "reauth-row" }, pass, submit), error)
      form.addEventListener("submit", async (e) => {
        e.preventDefault()
        if (!pass.value || submit.disabled) return refuse(pass)
        submit.disabled = true
        const value = pass.value
        pass.value = ""
        try { await enroll(app, value); await paintBiometric() }
        catch (e) { error.textContent = (e as Error).message; submit.disabled = false }
      })
      action.replaceWith(form)
      pass.focus()
    })
    biometrics.replaceChildren(h("div", { class: "section-head" }, h("span", { class: "label" }, "Touch ID")),
      h("p", { class: "hint" }, enabled ? "Touch ID unlocks Deadbolt in this browser. Reset turns it off here; the passkey it made stays in your browser's settings until you remove it." : "Unlock with Touch ID instead of typing your passphrase. Your browser may ask for its PIN instead. Your passphrase always works."), action, error)
  }
  void paintBiometric()

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
          // What the vault answered, which keeps the preset it holds when the change didn't reach it.
          if (r.ok && typeof r.reply.preset === "string") app.preset = r.reply.preset as LockPreset
          if (asking) clearing.checked = await asking
          paintPresets()
          app.announce(r.ok ? `${PRESETS[app.preset].name}.` : r.message)
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

  // Passkeys, once the vault has listed them.
  const passkeys = h("div", { class: "rows" })
  const passkeysGroup = h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, "Passkeys")), passkeys)
  let passkeyRows = new Map<string, HTMLElement>()

  const paint = () => {
    passkeysGroup.hidden = app.passkeys === null
    // Refreshes can arrive while typing or awaiting the KDF. Keep that item's
    // confirmation in place, but remove it if the item disappeared from sync.
    passkeyRows = new Map((app.passkeys ?? []).map((k) => {
      const previous = passkeyRows.get(k.ref)
      return [k.ref, previous?.classList.contains("confirming") ? previous : passkeyRow(app, k, paint)]
    }))
    const rows = passkeyRows.size ? [...passkeyRows.values()] : [h("p", { class: "hint" }, "No passkeys yet. A site that offers one asks to save it in Deadbolt.")]
    for (const child of [...passkeys.children]) {
      if (!rows.includes(child as HTMLElement)) child.remove()
    }
    rows.forEach((row, i) => {
      if (passkeys.children[i] !== row) passkeys.insertBefore(row, passkeys.children[i] ?? null)
    })
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
    passkeysGroup,
    h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, "Lock")), presets, h("p", { class: "hint" }, "Every preset locks when the browser quits.")),
    biometrics,
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
    h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, "Saving")), neverRows(app)),
    h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, "Signing in")), signInSetting(app)),
    h("section", { class: "group" }, h("div", { class: "section-head" }, h("span", { class: "label" }, "Learning logs")), learnRows(app)),
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
