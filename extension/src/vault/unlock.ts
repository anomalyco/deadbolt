// Unlocking the browser-only Deadbolt, in the toolbar panel and on
// device.html: Touch ID when it's set up, and the passphrase. Touch ID's own
// prompt is the system's, drawn away from this panel (a dialog in the middle
// of the screen, the browser's own over the panel when it fails), and it says
// what to do; the panel only says it's waiting, and keeps the passphrase
// field ready under it. A cancelled prompt is not an error: the panel goes
// back to how it opened. The line under the field shows only while there is
// something wrong to say.

import { isLockedBy, lockedLine } from "../device-rules"
import { h, icon } from "../ui/dom"
import { reducedMotion, timing } from "../ui/motion"
import { swapText } from "../ui/unlock"
import type { App, View } from "./app"
import { enrollment, TouchDeclined, verify } from "./biometric"
import { glyph, refuse } from "./kit"

type TouchState = "idle" | "asking" | "failed"

const TOUCH_LABEL: Record<TouchState, string> = { idle: "Unlock with Touch ID", asking: "Waiting for Touch ID…", failed: "Try Touch ID again" }

export function unlockView(app: App): View {
  let timer: ReturnType<typeof setTimeout> | undefined
  let touchState: TouchState = "idle"
  let enrolled = false
  /** Ends the Touch ID prompt that's up, when the passphrase is used instead. */
  let asking: AbortController | undefined

  const input = h("input", { class: "input", type: "password", autocomplete: "current-password", "aria-label": "Passphrase", placeholder: "Passphrase", spellcheck: "false" })
  const submit = h("button", { class: "icon-button unlock-go", type: "submit", title: "Unlock", "aria-label": "Unlock" }, glyph("enter"))
  const fieldRow = h("div", { class: "unlock-field" }, input, submit)
  // The one line under the field: what went wrong. Its room opens only while it says something.
  const line = h("p", { class: "unlock-line", role: "alert" })
  const lineWrap = h("div", { class: "unlock-msg" }, h("div", {}, line))
  const say = (text: string) => {
    line.textContent = text
    lineWrap.classList.toggle("on", !!text)
  }

  const heading = h("h2", { class: "unlock-title" }, "Unlock Deadbolt")
  const mark = h("span", { class: "unlock-disc", "aria-hidden": "true" }, icon("lock"))
  const touchLabel = h("span", { class: "unlock-touch-label" }, TOUCH_LABEL.idle)
  touchLabel.dataset.text = TOUCH_LABEL.idle
  // Touch ID's control: the disc and its label are the button.
  const touch = h("button", { class: "unlock-touch", type: "button" }, h("span", { class: "unlock-disc", "aria-hidden": "true" }, glyph("fingerprint")), touchLabel)
  // Why it locked, quietly, when it wasn't the user's own doing. Its line is kept either way, so the panel doesn't grow once the service worker says.
  const why = h("p", { class: "lock-reason" })

  const head = h("div", { class: "unlock-hero" }, mark, heading)
  const form = h("form", { class: "view center unlock locked", novalidate: "" }, head, fieldRow, lineWrap, why)

  const setTouch = (state: TouchState) => {
    touchState = state
    touch.classList.toggle("asking", state === "asking")
    touch.setAttribute("aria-busy", String(state === "asking"))
    swapText(touchLabel, TOUCH_LABEL[state])
  }

  const backoff = (until: number) => {
    clearTimeout(timer)
    const seconds = Math.ceil((until - Date.now()) / 1000)
    submit.disabled = seconds > 0
    // Over: no longer an error. The red goes and the line closes; it's said rather than shown.
    if (seconds <= 0) {
      say("")
      input.classList.remove("invalid")
      app.announce("You can try your passphrase again.")
      return
    }
    say(`Too many wrong passphrases. Try again in ${seconds} s.`)
    timer = setTimeout(() => backoff(until), 250)
  }

  input.addEventListener("input", () => {
    input.classList.remove("invalid")
    if (line.textContent && !submit.disabled) say("")
  })

  // `pressed`: the user asked for it. Asked on its own (see below), a cancel doesn't make the passphrase their choice.
  const viaTouch = async (pressed: boolean) => {
    if (touchState === "asking") return
    setTouch("asking")
    if (!submit.disabled) say("")
    const mine = (asking = new AbortController())
    try {
      const r = await app.run({ type: "device-unlock", prf: await verify(app, pressed, mine.signal) })
      if (!r.ok) throw new Error(r.message)
      return app.opened()
    } catch (e) {
      // The passphrase took over, or the view is gone: nothing to say.
      if (mine.signal.aborted || !form.isConnected) return
      // Cancelled, timed out or turned down in the system's prompt, which said so itself: back to how the panel opened.
      if (e instanceof TouchDeclined) {
        setTouch("idle")
        app.announce("Touch ID didn't unlock Deadbolt. Use your passphrase.")
      } else {
        setTouch("failed")
        say((e as Error).message)
      }
      input.focus()
    } finally {
      if (asking === mine) asking = undefined
    }
  }
  touch.addEventListener("click", () => void viaTouch(true))

  void Promise.all([enrollment(app), chrome.storage.local.get("deadbolt.unlockMethod")]).then(([token, settings]) => {
    if (!form.isConnected || !token) return
    enrolled = true
    // The disc and its label are the button; the title stays for screen readers.
    head.replaceChildren(heading, touch)
    heading.classList.add("sr-only")
    // The inline menu's locked row opened this panel: Touch ID is asked at once, once, so unlocking is one step.
    if (app.fromMenu && !app.touchAsked && settings["deadbolt.unlockMethod"] !== "passphrase") {
      app.touchAsked = true
      void viaTouch(false)
    }
  })

  form.addEventListener("submit", async (e) => {
    e.preventDefault()
    if (submit.disabled) return
    // Return on the empty field asks Touch ID, when it's set up.
    if (!input.value) return enrolled && touchState !== "asking" ? void viaTouch(true) : refuse(input)
    submit.disabled = true
    submit.classList.add("busy")
    const r = await app.run({ type: "device-unlock", passphrase: input.value })
    input.value = ""
    submit.classList.remove("busy")
    if (r.ok || r.status.state !== "locked") {
      // Touch ID's prompt, still up, goes with it.
      asking?.abort()
      if (enrolled) setTouch("idle")
      return app.opened()
    }
    submit.disabled = false
    say(!r.ok && r.code === "wrong_passphrase" ? "That passphrase isn't right." : r.ok ? "" : r.message)
    if (!r.ok && r.retryAt) backoff(r.retryAt)
    refuse(input)
    input.focus()
  })

  void app.ask({ type: "device-settings" }).then((r) => {
    if (r.ok && typeof r.reply.retryAt === "number" && r.reply.retryAt > Date.now() && form.isConnected) backoff(r.reply.retryAt)
    if (r.ok && isLockedBy(r.reply.lockedBy)) {
      why.dataset.reason = r.reply.lockedBy.reason
      // A lock the user made needs no telling.
      if (r.reply.lockedBy.reason !== "manual") why.textContent = lockedLine(r.reply.lockedBy)
    }
  })

  // Unlocked for the menu's locked row: the panel says so for a moment before it closes (App.unlockedForMenu).
  const unlocked = () => {
    for (const el of [input, submit]) el.disabled = true
    // Nothing is left to press: no focus ring on the check.
    ;(document.activeElement as HTMLElement | null)?.blur()
    touch.classList.remove("asking")
    touch.setAttribute("aria-busy", "false")
    touch.setAttribute("aria-disabled", "true")
    say("")
    why.textContent = ""
    // What says the state now says Unlocked: the Touch ID label, or the title.
    swapText(enrolled ? touchLabel : heading, "Unlocked")
    // The lock (or the fingerprint) turns into a check, in place.
    const host = (enrolled ? touch.querySelector(".unlock-disc") : mark) as HTMLElement | null
    if (!host) return
    const was = host.firstElementChild as SVGElement | null
    const check = icon("check") as SVGElement
    host.style.display = "grid"
    host.style.color = "var(--success)"
    for (const el of [was, check]) if (el) el.style.gridArea = "1 / 1"
    host.append(check)
    const soft = reducedMotion() ? [{ opacity: 1 }, { opacity: 0 }] : [{ opacity: 1, transform: "none", filter: "blur(0px)" }, { opacity: 0, transform: "scale(0.8)", filter: "blur(3px)" }]
    was?.animate(soft, { ...timing(0.25), fill: "forwards" })
    check.animate([...soft].reverse(), { ...timing(0.3), fill: "backwards" })
  }

  // The field has the keyboard from the start and while Touch ID's prompt is up (the prompt is a window of its own): typing the passphrase is never a click away.
  return { el: form, focus: () => input.focus(), leave: () => { clearTimeout(timer); asking?.abort() }, unlocked }
}
