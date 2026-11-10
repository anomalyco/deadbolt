// Unlocking the browser-only Deadbolt, in the toolbar panel and on
// device.html: Touch ID when it's set up, and the passphrase. Touch ID's own
// prompt is the system's, drawn away from this panel (a dialog in the middle
// of the screen, the browser's own over the panel when it fails), and it says
// what to do: a finger where there's a sensor, the Mac's password where
// there isn't. The panel only says it's waiting, and keeps the passphrase
// field ready under it. A cancelled prompt is not an error: the panel goes
// back to how it opened.
//
// Nothing here moves the panel after its first frame. What it shows first
// comes from what this browser already knew (Touch ID set up or not, asked by
// the menu's row or not), the two ways in are the same size, and the one line
// under the field is always there: why it locked, or what went wrong.

import { isLockedBy, lockedLine } from "../device-rules"
import { h, icon } from "../ui/dom"
import { reducedMotion, timing } from "../ui/motion"
import { padlock, setOpen, slideOpen, tug } from "../ui/padlock"
import { swapText, UNLOCK_FEEL } from "../ui/unlock"
import type { App, View } from "./app"
import { enrollment, sawTouch, touchBefore, TouchDeclined, verify } from "./biometric"
import { glyph, refuse } from "./kit"

type TouchState = "idle" | "asking" | "failed"

// "Waiting for macOS…": true whether macOS asks for a finger or, with no sensor to offer, the Mac's password.
const TOUCH_LABEL: Record<TouchState, string> = { idle: "Unlock with Touch ID", asking: "Waiting for macOS…", failed: "Try Touch ID again" }

export function unlockView(app: App): View {
  let timer: ReturnType<typeof setTimeout> | undefined
  let touchState: TouchState = "idle"
  const before = touchBefore()
  let enrolled = before.enrolled
  /** Ends the Touch ID prompt that's up, when the passphrase is used instead. */
  let asking: AbortController | undefined

  const input = h("input", { class: "input", type: "password", autocomplete: "current-password", "aria-label": "Passphrase", placeholder: "Passphrase", spellcheck: "false" })
  const submit = h("button", { class: "icon-button unlock-go", type: "submit", title: "Unlock", "aria-label": "Unlock" }, glyph("enter"))
  const fieldRow = h("div", { class: "unlock-field" }, input, submit)
  // The one line under the field: that it's locked and why, quietly, or what went wrong in its place. It always says something.
  const why = h("p", { class: "lock-reason" }, "Locked")
  const line = h("p", { class: "unlock-line", role: "alert" })
  const under = h("div", { class: "unlock-under" }, why, line)
  const say = (text: string) => {
    if (text) line.textContent = text
    under.classList.toggle("wrong", !!text)
  }

  const heading = h("h2", { class: "unlock-title" }, "Unlock Deadbolt")
  const mark = h("span", { class: "unlock-disc", "aria-hidden": "true" }, padlock())
  const touchLabel = h("span", { class: "unlock-touch-label" }, TOUCH_LABEL.idle)
  touchLabel.dataset.text = TOUCH_LABEL.idle
  // Touch ID's control: the disc and its label are the button.
  const touch = h("button", { class: "unlock-touch", type: "button" }, h("span", { class: "unlock-disc", "aria-hidden": "true" }, glyph("fingerprint")), touchLabel)
  const head = h("div", { class: "unlock-hero" })
  /** The way in at the top: Touch ID's button (the title stays for screen readers), or the lock and the title. */
  const showHead = () => {
    heading.classList.toggle("sr-only", enrolled)
    head.replaceChildren(...(enrolled ? [heading, touch] : [mark, heading]))
  }
  showHead()
  const form = h("form", { class: "view center unlock locked", novalidate: "" }, head, fieldRow, under)

  /** `at once`: as the panel is built, before it has shown: nothing to animate from. */
  const setTouch = (state: TouchState, atOnce = false) => {
    touchState = state
    touch.classList.toggle("asking", state === "asking")
    touch.setAttribute("aria-busy", String(state === "asking"))
    if (atOnce) touchLabel.textContent = touchLabel.dataset.text = TOUCH_LABEL[state]
    else swapText(touchLabel, TOUCH_LABEL[state], true)
  }

  const backoff = (until: number) => {
    clearTimeout(timer)
    const seconds = Math.ceil((until - Date.now()) / 1000)
    submit.disabled = seconds > 0
    // Over: no longer an error. The red goes and the line is why it locked again; it's said rather than shown.
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
    if (under.classList.contains("wrong") && !submit.disabled) say("")
  })

  // `pressed`: the user asked for it. Asked on its own (see below), a cancel doesn't make the passphrase their choice.
  const viaTouch = async (pressed: boolean) => {
    if (asking) return
    if (touchState !== "asking") setTouch("asking")
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

  // The menu's locked row opened this panel (its address says so before the background can): it's waiting on Touch ID from its first frame.
  if (enrolled && app.hintedAsk && !app.touchAsked && !before.passphrase) setTouch("asking", true)
  void Promise.all([enrollment(app), chrome.storage.local.get("deadbolt.unlockMethod"), app.menuAsked]).then(([token, settings, asked]) => {
    if (!form.isConnected) return
    const passphrase = settings["deadbolt.unlockMethod"] === "passphrase"
    sawTouch(!!token, passphrase)
    // What this browser knew was out of date (Touch ID set up or reset since): the right way in comes in softly.
    if (!!token !== enrolled) {
      enrolled = !!token
      showHead()
      head.animate?.([{ opacity: 0 }, { opacity: 1 }], timing(0.2))
    }
    // The row asked: Touch ID is asked at once, once, so unlocking is one step.
    if (token && asked && !app.touchAsked && !passphrase) {
      app.touchAsked = true
      return void viaTouch(false)
    }
    if (touchState === "asking" && !asking) setTouch("idle")
  })

  form.addEventListener("submit", async (e) => {
    e.preventDefault()
    if (submit.disabled) return
    // Return on the empty field asks Touch ID, when it's set up.
    if (!input.value) return enrolled && !asking ? void viaTouch(true) : refuse(input)
    submit.disabled = true
    submit.classList.add("busy")
    const r = await app.run({ type: "device-unlock", passphrase: input.value })
    input.value = ""
    submit.classList.remove("busy")
    if (r.ok || r.status.state !== "locked") {
      // Touch ID's prompt, still up, goes with it.
      asking?.abort()
      return app.opened()
    }
    submit.disabled = false
    say(!r.ok && r.code === "wrong_passphrase" ? "That passphrase isn't right." : r.ok ? "" : r.message)
    if (!r.ok && r.retryAt) backoff(r.retryAt)
    refuse(input)
    if (!enrolled) tug(mark)
    input.focus()
  })

  let painted = false
  requestAnimationFrame(() => requestAnimationFrame(() => (painted = true)))
  void app.ask({ type: "device-settings" }).then((r) => {
    if (r.ok && typeof r.reply.retryAt === "number" && r.reply.retryAt > Date.now() && form.isConnected) backoff(r.reply.retryAt)
    if (r.ok && isLockedBy(r.reply.lockedBy)) {
      why.dataset.reason = r.reply.lockedBy.reason
      // A lock the user made needs no reason: "Locked" says it.
      if (r.reply.lockedBy.reason === "manual") return
      // Before the panel has shown, the reason is simply there; after, it rolls in (unless the panel is still coming in: its line is measured at rest).
      if (painted && !form.getAnimations?.().length) swapText(why, lockedLine(r.reply.lockedBy), true, 0.3)
      else why.textContent = lockedLine(r.reply.lockedBy)
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
    // It isn't locked any more, and nothing's wrong: the line under the field lets go.
    under.classList.add("over")
    // The lock opens (or the fingerprint gives way to one that does), and then what says the state says Unlocked: the Touch ID label, or the title.
    const disc = (enrolled ? touch.querySelector(".unlock-disc") : mark) as HTMLElement | null
    const lead = disc ? openDisc(disc) : 0
    setTimeout(() => swapText(enrolled ? touchLabel : heading, "Unlocked", true), lead)
  }

  const focus = () => {
    // As the panel is built its ring is simply there: a ring that grows in belongs to a field the user moved to.
    input.style.transition = "none"
    input.focus()
    requestAnimationFrame(() => (input.style.transition = ""))
  }
  return { el: form, focus, leave: () => { clearTimeout(timer); asking?.abort() }, unlocked }
}

/**
 * Deadbolt unlocked: the disc's padlock opens (ui/padlock.ts), as
 * UNLOCK_FEEL.moment says. Where a fingerprint showed, the padlock comes in
 * over it already opening: one beat, not a lock that arrives and then opens.
 * Each property has one animation that writes it, from where it is. Returns
 * how long until the shackle's foot is clear, in ms: the label says
 * "Unlocked" then.
 */
function openDisc(disc: HTMLElement): number {
  const feel = UNLOCK_FEEL.moment
  const reduced = reducedMotion()
  const was = disc.firstElementChild as HTMLElement | SVGElement | null
  // From as bright as it is: dimmed while it waited on Touch ID, it doesn't light up to leave.
  const dim = was ? getComputedStyle(was).opacity : "1"
  const out = reduced ? [{ opacity: dim }, { opacity: 0 }] : [{ opacity: dim, transform: "none", filter: "blur(0px)" }, { opacity: 0, transform: "scale(0.8)", filter: "blur(3px)" }]
  const into = reduced ? [{ opacity: 0 }, { opacity: 1 }] : [{ opacity: 0, transform: "scale(0.86)", filter: "blur(3px)" }, { opacity: 1, transform: "none", filter: "blur(0px)" }]
  /** `next` takes the glyph's place, softly. */
  const replace = (next: HTMLElement | SVGElement, seconds: number) => {
    for (const el of [was, next]) if (el) el.style.gridArea = "1 / 1"
    disc.append(next)
    was?.animate(out, { ...timing(seconds), fill: "forwards" })
    next.animate(into, { ...timing(seconds + 0.05), fill: "backwards" })
  }
  if (feel === "check") {
    const check = icon("check") as SVGElement
    check.style.color = "var(--success)"
    replace(check, 0.25)
    return 0
  }
  const turn = feel === "turn"
  let lock = disc.querySelector<HTMLElement>(".padlock")
  // No padlock there (a fingerprint), or nothing may travel (reduced motion: the open lock fades in whole).
  if (!lock || reduced) {
    lock = padlock()
    if (reduced) setOpen(lock, turn)
    replace(lock, 0.18)
  }
  const free = slideOpen(lock, turn, 30)
  disc.animate([{}, { backgroundColor: "var(--success-bg)", color: "var(--success)" }], { duration: 320, delay: reduced ? 0 : 150, easing: "ease-out", fill: "forwards" })
  if (reduced) return 0
  // One soft light round the disc's edge as it warms, as the menu's pick ring closes (ui/ring.ts): it comes up, goes once round, and cools.
  const glint = h("span", { class: "unlock-glint", "aria-hidden": "true" })
  disc.append(glint)
  const round = glint.animate(
    [
      { transform: "rotate(-110deg)", opacity: 0 },
      { opacity: 1, offset: 0.25 },
      { opacity: 1, offset: 0.6 },
      { transform: "rotate(250deg)", opacity: 0 },
    ],
    { duration: 640, delay: 150, easing: "cubic-bezier(0.3, 0.1, 0.2, 1)", fill: "both" },
  )
  round.finished.then(() => glint.remove(), () => glint.remove())
  return free
}
