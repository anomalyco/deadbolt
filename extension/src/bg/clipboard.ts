// Clearing a copied password or one-time code off the clipboard, 30 seconds
// after it was copied or when Deadbolt locks, whichever is first: the
// offscreen document reads the clipboard and empties it, but only if it still
// holds what Deadbolt copied, so nothing the user copied since is lost.
//
// Neither the value nor anything that gives it back is kept: only a salted
// SHA-256 of it, in the service worker's memory and in chrome.storage.session
// (which a restarted service worker reads back, and which never reaches
// disk). Reading the clipboard needs the clipboardRead permission (and
// writing it from the offscreen document clipboardWrite); both are optional,
// asked for at runtime, because each adds an install warning. Without them
// nothing is cleared, and nothing is cleared blindly.

/** The one-shot alarm that clears it. */
export const CLIPBOARD_ALARM = "deadbolt-clipboard"
export const CLEAR_AFTER_MS = 30_000
export const COPIED_KEY = "deadbolt.copied"
/** What clearing needs, asked for together. */
export const CLIPBOARD_PERMISSIONS: chrome.runtime.ManifestPermission[] = ["clipboardRead", "clipboardWrite"]

/** What Deadbolt last copied, as a salted hash. */
export interface Copied {
  salt: string
  hash: string
}

const hex = (bytes: ArrayBuffer | Uint8Array) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("")

export async function digest(salt: string, value: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${salt}:${value}`)))
}

/** A fresh record of `value`, with its own random salt. */
export async function record(value: string): Promise<Copied> {
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)))
  return { salt, hash: await digest(salt, value) }
}

/** Whether `text` is what `copied` records. */
export async function holds(copied: Copied, text: string): Promise<boolean> {
  return (await digest(copied.salt, text)) === copied.hash
}

export const isCopied = (v: unknown): v is Copied =>
  typeof v === "object" && v !== null && typeof (v as Copied).salt === "string" && typeof (v as Copied).hash === "string"
