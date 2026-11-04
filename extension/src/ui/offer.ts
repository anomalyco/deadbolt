// The popup's save offer: "Save login for acme.com?", in browser UI where the
// page can't see it. The native popup and the browser-only vault show it.

import type { ChooseReply, OfferChoice, SaveOffer, SaveWhat } from "../messages"
import { h, icon } from "./dom"
import { reducedMotion, rollLabel, timing } from "./motion"

const send = <T>(message: unknown): Promise<T | null> => chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>

/** The words for each kind of form offer: the title's noun, and what its one line names. */
const FORM_WORDS: Record<SaveWhat, { noun: string; line: string }> = {
  card: { noun: "card", line: "Card" },
  address: { noun: "address", line: "Address" },
  details: { noun: "details", line: "Details" },
}

/** "Save login for acme.com?": browser UI, where the page can't see it. */
export function offerCard(offer: SaveOffer, tabId: number | undefined, render: (changed: true) => void): HTMLElement {
  const status = h("p", { class: "error", role: "status" })
  status.hidden = true
  const form = offer.what ? FORM_WORDS[offer.what] : null
  // A card or identity: its label ("Visa •••• 4242") and the site; never a number beyond the last four digits.
  const lines = form
    ? [h("div", { class: "line" }, h("span", { class: "muted" }, form.line), h("span", { class: "value" }, offer.username)), h("div", { class: "line" }, h("span", { class: "muted" }, "Site"), h("span", { class: "value" }, offer.site))]
    : [
        h("div", { class: "line" }, h("span", { class: "muted" }, offer.update ? "Site" : "Username"), h("span", { class: "value" }, offer.update ? offer.site : offer.username)),
        h("div", { class: "line" }, h("span", { class: "muted" }, offer.update ? "New password" : "Password"), h("span", { class: "value dots" }, "••••••••••")),
      ]
  const card = h(
    "section",
    { class: "offer", "aria-label": offerTitle(offer).slice(0, -1) },
    h("h2", {}, form ? `${offer.update ? "Update" : "Save"} ${form.noun} for ${offer.site}?` : offer.update ? `Update password for ${offer.username}?` : `Save login for ${offer.site}?`),
    h("div", { class: "box" }, ...lines),
    status,
  )
  const choose = async (choice: OfferChoice, button: HTMLElement) => {
    if (tabId === undefined) return
    card.classList.add("busy")
    button.setAttribute("disabled", "")
    if (choice === "save") rollLabel(saveLabel, "Saving…")
    const reply = await send<ChooseReply>({ type: "db:popup-offer", tabId, id: offer.id, choice })
    card.classList.remove("busy")
    button.removeAttribute("disabled")
    if (choice === "save" && !reply?.ok) rollLabel(saveLabel, "Save")
    // Another offer took this one's place: show that one instead.
    if (reply && !reply.ok && reply.gone) return void render(true)
    if (!reply?.ok) {
      status.textContent = reply?.message || "Couldn't save."
      status.hidden = false
      return
    }
    if (choice !== "save") return void render(true)
    const doneEl = h("div", { class: "done" }, h("span", { class: "done-mark" }, icon("check")), h("span", {}, reply.message))
    card.replaceChildren(doneEl)
    doneEl.animate(reducedMotion() ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, filter: "blur(4px)", transform: "scale(0.96)" }, { opacity: 1, filter: "none", transform: "none" }], timing(0.3))
    setTimeout(() => void render(true), 1200)
  }
  const never = h("button", { class: "link", type: "button" }, "Never for this site")
  const later = h("button", { class: "btn", type: "button" }, "Not now")
  const saveLabel = h("span", { class: "roll-label" }, "Save")
  saveLabel.dataset.text = "Save"
  const save = h("button", { class: "btn primary", type: "button" }, saveLabel)
  never.addEventListener("click", () => void choose("never", never))
  later.addEventListener("click", () => void choose("later", later))
  save.addEventListener("click", () => void choose("save", save))
  card.append(h("div", { class: "buttons" }, never, later, save))
  return card
}

/** "Save login?", or for a card or identity typed into a form, "Save card?", "Update address?". */
export function offerTitle(offer: { update: boolean; what?: SaveWhat }): string {
  switch (offer.what) {
    case "card":
      return offer.update ? "Update card?" : "Save card?"
    case "address":
      return offer.update ? "Update address?" : "Save address?"
    case "details":
      return offer.update ? "Update details?" : "Save details?"
  }
  return offer.update ? "Update password?" : "Save login?"
}
