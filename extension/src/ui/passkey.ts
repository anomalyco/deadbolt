// The passkey prompt: a page's passkey call, asked in Deadbolt's own UI rather
// than by the page. The native popup and the browser-only vault show it, and
// so does the in-page surface (ui/passkey-surface.ts), each with its own way
// to send the answer.

import type { PasskeyChoice, PasskeyPrompt } from "../messages"
import { h, icon } from "./dom"

const send = <T>(message: unknown): Promise<T | null> => chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>

export interface PasskeyCardHooks {
  /** The background took `choice`: the ceremony (Touch ID, the passphrase, or the page) takes it from here. */
  chosen: (choice: PasskeyChoice) => void
  /** The request had already ended: show what's current. */
  ended: () => void
}

/** Sends `choice` to the background: whether the prompt was still waiting for it. */
export type PasskeyAnswer = (choice: PasskeyChoice) => Promise<boolean>

/** The popup's (and the browser-only vault's) answer for the prompt waiting in tab `tabId`. */
export const popupAnswer =
  (prompt: PasskeyPrompt, tabId: number | undefined): PasskeyAnswer =>
  async (choice) =>
    tabId !== undefined && (await send<{ ok: boolean }>({ type: "pk:popup-choose", tabId, id: prompt.id, choice }))?.ok === true

export interface PasskeyCardOptions {
  /** The card's class names: the popup's offer card unless given. */
  className?: string
  /** Checks a press before it counts (the in-page surface's visibility guard); false leaves the card as it was. */
  guard?: (event: MouseEvent, button: HTMLElement) => Promise<boolean>
}

/** "Sign in to acme.com with a passkey?" or "Save a passkey for acme.com?". */
export function passkeyCard(prompt: PasskeyPrompt, answer: PasskeyAnswer, hooks: PasskeyCardHooks, options: PasskeyCardOptions = {}): HTMLElement {
  const status = h("p", { class: "error", role: "status" })
  status.hidden = true
  const card = h("section", { class: options.className ?? "offer passkey-prompt", "aria-label": prompt.kind === "get" ? "Sign in with a passkey" : "Save a passkey" })
  let busy = false
  const choose = async (choice: PasskeyChoice, button: HTMLElement, event: MouseEvent) => {
    if (busy) return
    // One press at a time, its checks included.
    busy = true
    if (options.guard && !(await options.guard(event, button))) return void (busy = false)
    card.classList.add("busy")
    button.setAttribute("disabled", "")
    if (await answer(choice)) return hooks.chosen(choice)
    status.textContent = "This request has ended."
    status.hidden = false
    setTimeout(hooks.ended, 1200)
  }
  const button = (label: string, choice: PasskeyChoice, primary = false) => {
    const b = h("button", { class: `btn${primary ? " primary" : ""}`, type: "button" }, label)
    b.addEventListener("click", (e) => void choose(choice, b, e))
    return b
  }
  const next = prompt.verify ? "Deadbolt asks for Touch ID next." : prompt.passphrase ? "Deadbolt asks for your passphrase next." : ""
  const note = next ? h("p", { class: "note" }, icon("lock"), h("span", {}, next)) : ""
  const other = button("Use another device", { action: "fallback" })
  if (prompt.kind === "get") {
    card.append(
      h("h2", {}, `Sign in to ${prompt.rpId} with a passkey?`),
      h(
        "div",
        { class: "list" },
        ...prompt.passkeys.map((k, i) =>
          h(
            "div",
            { class: "account" },
            h("span", { class: "tile", "aria-hidden": "true" }, icon("passkey")),
            h("div", { class: "account-text" }, h("div", { class: "account-title" }, k.username || "Passkey"), h("div", { class: "account-sub" }, `Passkey · ${k.vault}`)),
            button("Sign in", { action: "use", ref: k.ref }, i === 0),
          ),
        ),
      ),
      status,
      note,
      h("div", { class: "buttons" }, other, button("Cancel", { action: "cancel" })),
    )
  } else if (prompt.registered) {
    card.append(
      h("h2", {}, "This passkey is already saved"),
      h("p", { class: "muted" }, `Deadbolt already has a passkey for this account on ${prompt.rpId}.`),
      status,
      h("div", { class: "buttons" }, other, button("OK", { action: "cancel" }, true)),
    )
  } else {
    card.append(
      h("h2", {}, `Save a passkey for ${prompt.rpId}?`),
      h(
        "div",
        { class: "box" },
        h("div", { class: "line" }, h("span", { class: "muted" }, "Username"), h("span", { class: "value" }, prompt.username || "None")),
        h("div", { class: "line" }, h("span", { class: "muted" }, "Site"), h("span", { class: "value" }, prompt.rpId)),
      ),
      status,
      note,
      h("div", { class: "buttons" }, other, button("Cancel", { action: "cancel" }), button("Save", { action: "save" }, true)),
    )
  }
  return card
}
