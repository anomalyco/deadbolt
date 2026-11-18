// A page's passkey call, asked in the page: the toolbar popup's card
// (ui/passkey.ts) in Deadbolt's one surface, near the top centre, where the
// user is looking when a site asks for a passkey. The surface is an extension
// page in an iframe inside a closed shadow root, so the page can neither read
// the card nor press its buttons, and every press waits for the menu's
// visibility guard (menu.ts guardPress), as a pick in the account list does.
// The toolbar popup keeps the same prompt meanwhile, and answering either
// answers both (bg/passkeys.ts).

import type { PasskeyChoice, PasskeyPrompt } from "../messages"
import { h, icon } from "./dom"
import { passkeyCard } from "./passkey"

/** The card's width in the page. */
export const PASSKEY_WIDTH = 360
/** What a press says when the guard turned it down because something covered the card. */
export const PASSKEY_COVERED = "This prompt is covered. Nothing was signed."

const send = <T>(message: unknown): Promise<T | null> => chrome.runtime.sendMessage(message).catch(() => null) as Promise<T | null>

export interface PasskeySurfaceHooks {
  /** The checks a press gets before it counts: a real press on a surface visible and still before and after it. */
  guard: (event: MouseEvent, button: HTMLElement) => Promise<boolean>
  /** Puts the surface away: answered (the ceremony takes it from here), or the request already ended. */
  done: () => void
}

/**
 * Shows `prompt` in `surface`, over the account list it replaces, with the
 * surface's quiet line (#foot) left under it for what the guard says. The
 * answer goes with `token`, which only the frame that loaded it may use.
 */
export function showPasskeyPrompt(surface: HTMLElement, prompt: PasskeyPrompt, token: string, hooks: PasskeySurfaceHooks): HTMLElement {
  document.body.classList.add("passkey")
  surface.querySelector<HTMLElement>("#list")?.setAttribute("hidden", "")
  const answer = async (choice: PasskeyChoice) => (await send<{ ok: boolean }>({ type: "pk:surface-choose", token, choice }))?.ok === true
  const card = passkeyCard(prompt, answer, { chosen: hooks.done, ended: hooks.done }, { className: "pk-card", guard: hooks.guard })
  // Whose card this is: the page can draw anything, but not inside this frame.
  card.prepend(h("div", { class: "pk-brand" }, icon("deadbolt"), h("span", {}, "Deadbolt")))
  surface.prepend(card)
  return card
}
