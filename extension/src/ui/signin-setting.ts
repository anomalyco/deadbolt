// Settings' "Offer to sign in": shared by the standalone Settings and the
// native popup's settings, so either build can turn it off.

import { SIGNIN_SETTING, signInOn } from "../auth-state"
import { h } from "./dom"

/** The switch, set from storage (on unless turned off); each change is saved at once and every page follows it. */
export function signInRow(announce: (message: string) => void): HTMLElement {
  const id = "signin-hint"
  const toggle = h("input", { type: "checkbox", role: "switch", "aria-label": "Offer to sign in", "aria-describedby": id })
  void chrome.storage.local.get(SIGNIN_SETTING).then((s) => { toggle.checked = signInOn(s[SIGNIN_SETTING]) })
  toggle.addEventListener("change", async () => {
    try {
      await chrome.storage.local.set({ [SIGNIN_SETTING]: toggle.checked })
      announce(toggle.checked ? "Picking an account signs you in." : "Picking an account only fills.")
    } catch {
      toggle.checked = !toggle.checked
      announce("Couldn't change signing in.")
    }
  })
  return h("label", { class: "switch-row" }, h("span", { class: "text" },
    h("span", { class: "title" }, "Offer to sign in"),
    h("span", { class: "sub", id }, "Picking an account fills it and signs you in: Deadbolt submits each sign-in step, and offers to sign in from the corner. Escape stops it. Off, a pick only fills.")), toggle)
}
