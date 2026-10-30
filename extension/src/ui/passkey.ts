// The popup's passkey prompt: a page's passkey call, asked here rather than in
// the page. The native popup and the browser-only vault show it.

import type { PasskeyChoice, PasskeyPrompt } from "../messages"
import { h, icon } from "./dom"

const send = <T>(message: unknown): Promise<T | null> => chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>

export interface PasskeyCardHooks {
  /** The background took `choice`: the ceremony (Touch ID, the passphrase, or the page) takes it from here. */
  chosen: (choice: PasskeyChoice) => void
  /** The request had already ended: show what's current. */
  ended: () => void
}

/** "Sign in to acme.com with a passkey?" or "Save a passkey for acme.com?". */
export function passkeyCard(prompt: PasskeyPrompt, tabId: number | undefined, hooks: PasskeyCardHooks): HTMLElement {
  const status = h("p", { class: "error", role: "status" })
  status.hidden = true
  const card = h("section", { class: "offer passkey-prompt", "aria-label": prompt.kind === "get" ? "Sign in with a passkey" : "Save a passkey" })
  const choose = async (choice: PasskeyChoice, button: HTMLElement) => {
    if (tabId === undefined) return
    card.classList.add("busy")
    button.setAttribute("disabled", "")
    const reply = await send<{ ok: boolean }>({ type: "pk:popup-choose", tabId, id: prompt.id, choice })
    if (reply?.ok) return hooks.chosen(choice)
    status.textContent = "This request has ended."
    status.hidden = false
    setTimeout(hooks.ended, 1200)
  }
  const button = (label: string, choice: PasskeyChoice, primary = false) => {
    const b = h("button", { class: `btn${primary ? " primary" : ""}`, type: "button" }, label)
    b.addEventListener("click", () => void choose(choice, b))
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
