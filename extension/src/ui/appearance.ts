// Settings' Appearance: whether login rows show their site's icon, in the
// inline menu and in the vault. Shared by the standalone Settings and the
// native popup's settings.

import { h } from "./dom"
import { setIconSetting, type IconSettings } from "./icon-store"

/** The two switches, set from `icons`; each change is saved at once and every open page follows it. */
export function appearanceRows(icons: IconSettings, announce: (message: string) => void): HTMLElement[] {
  const row = (which: keyof IconSettings, title: string, sub: string, on: string, off: string) => {
    const id = `icons-${which}-hint`
    const input = h("input", { type: "checkbox", role: "switch", "aria-describedby": id, ...(icons[which] ? { checked: "" } : {}) })
    input.addEventListener("change", async () => {
      icons[which] = input.checked
      await setIconSetting(which, input.checked)
      announce(input.checked ? on : off)
    })
    return h("label", { class: "switch-row" }, h("span", { class: "text" }, h("span", { class: "title" }, title), h("span", { class: "sub", id }, sub)), input)
  }
  return [
    row("menu", "Site icons in the fill menu", "Every login there is for the page you're on, so it's off by default.", "The fill menu shows site icons.", "The fill menu shows titles and usernames only."),
    row("vault", "Site icons in the vault", "From the sites themselves as you visit them, or bundled. Deadbolt never looks them up.", "The vault shows site icons.", "The vault shows letters."),
  ]
}
