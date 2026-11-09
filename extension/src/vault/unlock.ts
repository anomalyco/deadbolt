// Unlocking the browser-only Deadbolt, in the toolbar panel and on
// device.html: Touch ID when it's set up, and the passphrase. One thing to
// do: Touch ID, when it's there, is the way in and says what it's doing
// itself ("Touch the sensor…", "Try Touch ID again"); the passphrase is one
// field whose arrow submits it. An error shows under the field only while
// there is one. UNLOCK_FEEL.panel picks the arrangement while it's open.

import { describePreset, duration, isLockedBy, lockedLine, PRESETS } from "../device-rules"
import { h, icon } from "../ui/dom"
import { reducedMotion, timing } from "../ui/motion"
import { swapText, UNLOCK_FEEL } from "../ui/unlock"
import type { App, View } from "./app"
import { enrollment, verify } from "./biometric"
import { glyph, refuse } from "./kit"

type TouchState = "idle" | "asking" | "failed"

const TOUCH_LABEL: Record<TouchState, string> = { idle: "Unlock with Touch ID", asking: "Touch the sensor…", failed: "Try Touch ID again" }

export function unlockView(app: App): View {
  const layout = UNLOCK_FEEL.panel
  let timer: ReturnType<typeof setTimeout> | undefined
  let touchState: TouchState = "idle"
  let enrolled = false

  const input = h("input", { class: "input", type: "password", autocomplete: "current-password", "aria-label": "Passphrase", placeholder: "Passphrase", spellcheck: "false" })
  const submit = h("button", { class: "icon-button unlock-go", type: "submit", title: "Unlock", "aria-label": "Unlock" }, glyph("enter"))
  const fieldRow = h("div", { class: "unlock-field" }, input, submit)
  // The one line under the field: an error, or what Touch ID is doing when it has no label of its own. Its room opens only while it says something.
  const line = h("p", { class: "unlock-line" })
  const lineWrap = h("div", { class: "unlock-msg", "aria-live": "polite" }, h("div", {}, line))
  const say = (text: string, kind: "error" | "status" = "error") => {
    line.textContent = text
    line.classList.toggle("error", kind === "error")
    line.setAttribute("role", kind === "error" ? "alert" : "status")
    lineWrap.classList.toggle("on", !!text)
  }

  const heading = h("h2", { class: "unlock-title" }, "Unlock Deadbolt")
  const mark = h("span", { class: "unlock-disc", "aria-hidden": "true" }, icon("lock"))
  const touchLabel = h("span", { class: "unlock-touch-label" }, TOUCH_LABEL.idle)
  touchLabel.dataset.text = TOUCH_LABEL.idle
  // The Touch ID control, in the layout's own shape: the disc itself (hero), a button in the field (field), or a wide button (tidy).
  const touch =
    layout === "field"
      ? h("button", { class: "icon-button unlock-touch-mini", type: "button", title: TOUCH_LABEL.idle, "aria-label": TOUCH_LABEL.idle }, glyph("fingerprint"))
      : layout === "tidy"
        ? h("button", { class: "btn primary wide unlock-touch-wide", type: "button" }, glyph("fingerprint"), touchLabel)
        : h("button", { class: "unlock-touch", type: "button" }, h("span", { class: "unlock-disc", "aria-hidden": "true" }, glyph("fingerprint")), touchLabel)

  const preset = PRESETS[app.preset]
  const idle = h("p", { class: "preset-note", title: describePreset(app.preset) }, icon("clock"), h("span", {}, Number.isFinite(preset.idleMs) ? `${preset.name} · locks after ${duration(preset.idleMs)} idle` : preset.name))
  // Why it locked, quietly, once the service worker says.
  const why = h("p", { class: "preset-note lock-reason" })
  why.hidden = true

  const head = layout === "tidy" ? h("div", { class: "state" }, h("span", { class: "state-icon" }, icon("lock")), heading) : layout === "hero" ? h("div", { class: "unlock-hero" }, mark, heading) : heading
  const form = h("form", { class: `view center unlock unlock--${layout}`, novalidate: "" }, head, fieldRow, lineWrap, idle, why)

  /** Touch ID is set up: it becomes the way in, in the layout's place for it. */
  const showTouch = () => {
    enrolled = true
    if (layout === "hero") {
      // The disc and its label are the button; the title stays for screen readers.
      head.replaceChildren(heading, touch)
      heading.classList.add("sr-only")
    } else if (layout === "field") {
      fieldRow.insertBefore(touch, submit)
      fieldRow.classList.add("with-touch")
    } else form.insertBefore(touch, fieldRow)
  }

  const setTouch = (state: TouchState) => {
    touchState = state
    touch.classList.toggle("asking", state === "asking")
    touch.setAttribute("aria-busy", String(state === "asking"))
    if (layout === "field") {
      touch.title = TOUCH_LABEL[state]
      touch.setAttribute("aria-label", TOUCH_LABEL[state])
      if (state === "asking") say(TOUCH_LABEL.asking, "status")
      else if (line.getAttribute("role") === "status") say("")
    } else swapText(touchLabel, TOUCH_LABEL[state])
    if (state === "asking") app.announce("Touch the sensor to unlock.")
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
    if (line.classList.contains("error") && !submit.disabled) say("")
  })

  // `pressed`: the user asked for it. Asked on its own (see below), a cancel doesn't make the passphrase their choice.
  const viaTouch = async (pressed: boolean) => {
    if (touchState === "asking") return
    setTouch("asking")
    if (line.classList.contains("error")) say("")
    try {
      const r = await app.run({ type: "device-unlock", prf: await verify(app, pressed) })
      if (!r.ok) throw new Error(r.message)
      return app.opened()
    } catch (e) {
      setTouch("failed")
      say((e as Error).message)
      input.focus()
    }
  }
  touch.addEventListener("click", () => void viaTouch(true))

  void Promise.all([enrollment(app), chrome.storage.local.get("deadbolt.unlockMethod")]).then(([token, settings]) => {
    if (!form.isConnected) return
    if (!token) return input.focus()
    showTouch()
    if (settings["deadbolt.unlockMethod"] === "passphrase") return input.focus()
    touch.focus()
    // The inline menu's locked row opened this panel: Touch ID is asked at once, once, so unlocking is one step.
    if (app.fromMenu && !app.touchAsked) {
      app.touchAsked = true
      void viaTouch(false)
    }
  })

  form.addEventListener("submit", async (e) => {
    e.preventDefault()
    if (submit.disabled) return
    if (!input.value) return refuse(input)
    submit.disabled = true
    submit.classList.add("busy")
    const r = await app.run({ type: "device-unlock", passphrase: input.value })
    input.value = ""
    submit.classList.remove("busy")
    if (r.ok || r.status.state !== "locked") return app.opened()
    submit.disabled = false
    say(!r.ok && r.code === "wrong_passphrase" ? "That passphrase isn't right." : r.ok ? "" : r.message)
    if (!r.ok && r.retryAt) backoff(r.retryAt)
    refuse(input)
    input.focus()
  })

  void app.ask({ type: "device-settings" }).then((r) => {
    if (r.ok && typeof r.reply.retryAt === "number" && r.reply.retryAt > Date.now() && form.isConnected) backoff(r.reply.retryAt)
    if (r.ok && isLockedBy(r.reply.lockedBy)) {
      why.textContent = lockedLine(r.reply.lockedBy)
      why.hidden = false
    }
  })

  // Unlocked for the menu's locked row: the panel says so for a moment before it closes (App.unlockedForMenu).
  const unlocked = () => {
    for (const el of [input, submit]) el.disabled = true
    // Nothing is left to press: no focus ring on the check.
    ;(document.activeElement as HTMLElement | null)?.blur()
    touch.classList.remove("asking")
    touch.setAttribute("aria-disabled", "true")
    say("")
    // What says the state now says Unlocked: the Touch ID label, or the title.
    if (layout !== "field" && enrolled && layout === "hero") swapText(touchLabel, "Unlocked")
    else {
      heading.classList.remove("sr-only")
      swapText(heading, "Unlocked")
    }
    if (layout === "tidy" && enrolled) {
      touch.setAttribute("disabled", "")
      swapText(touchLabel, TOUCH_LABEL.idle)
    }
    // The lock (or the fingerprint) turns into a check, in place.
    const host = (layout === "hero" ? (enrolled ? touch.querySelector(".unlock-disc") : mark) : layout === "tidy" ? form.querySelector(".state-icon") : enrolled ? touch : submit) as HTMLElement | null
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

  return { el: form, focus: () => (enrolled && touchState !== "failed" ? touch.focus() : input.focus()), leave: () => clearTimeout(timer), unlocked }
}
