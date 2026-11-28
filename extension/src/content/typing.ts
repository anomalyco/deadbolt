// Fallbacks for fields that turn a one-shot write down: a strict mask (a
// card number, an expiry, a phone number formatted as it's typed) that keeps
// only what comes a character at a time, and a group of one-digit code boxes
// whose component takes a code only as a paste. Each runs only after a
// normal write didn't stick, on a field that has already passed every check,
// and checks it again before each character.

/** What a mask keeps of a value, whatever it puts between: its letters and digits, in order. */
export const essence = (value: string) => value.replace(/[^\p{L}\p{N}]/gu, "").toLowerCase()

/** Whether the field holds `value`, as written or as a mask formats it. */
export function holds(el: HTMLInputElement | HTMLTextAreaElement, value: string): boolean {
  return el.value === value || (!!essence(value) && essence(el.value) === essence(value))
}

/** Puts the caret at `at`, where the field has one (an email or number box has none). */
function caret(el: HTMLInputElement | HTMLTextAreaElement, at: number) {
  try {
    el.setSelectionRange(at, at)
  } catch {}
}

/**
 * Types `value` into the field a character at a time, as a keyboard
 * would, for a mask that turned the whole value down: the field is cleared
 * (deleteContentBackward), then each character is a cancelable beforeinput
 * (the page may refuse it, as a mask refuses a letter in a number), the
 * native setter putting it in at the caret, and an insertText input event,
 * so the mask formats as it goes. `guard` checks the field before each
 * character; failing, it stops. True if the field then holds the value.
 */
export function typeChars(el: HTMLInputElement | HTMLTextAreaElement, value: string, guard: () => boolean): boolean {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype
  const setter = Object.getOwnPropertyDescriptor(proto, "value")!.set!
  if (!guard()) return false
  setter.call(el, "")
  el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "deleteContentBackward" }))
  for (const ch of value) {
    if (!guard()) return false
    const before = new InputEvent("beforeinput", { bubbles: true, composed: true, cancelable: true, inputType: "insertText", data: ch })
    if (!el.dispatchEvent(before)) continue
    const start = el.selectionStart ?? el.value.length
    const end = el.selectionEnd ?? start
    setter.call(el, el.value.slice(0, start) + ch + el.value.slice(end))
    caret(el, start + ch.length)
    el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: ch }))
  }
  el.dispatchEvent(new Event("change", { bubbles: true }))
  return holds(el, value)
}

/**
 * Pastes `text` into the field, as a component that takes a code only from
 * its paste handler reads it: a paste event carrying it as plain text.
 * False where the browser can't make one (no ClipboardEvent or DataTransfer).
 */
export function pasteText(el: HTMLElement, text: string): boolean {
  if (typeof ClipboardEvent === "undefined" || typeof DataTransfer === "undefined") return false
  let data: DataTransfer
  try {
    data = new DataTransfer()
    data.setData("text/plain", text)
  } catch {
    return false
  }
  el.dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true, composed: true }))
  return true
}
