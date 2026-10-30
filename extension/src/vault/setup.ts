// First run and unlock. First run joins a vault another device has (this
// browser shows a code; that device admits it; then a passphrase for this
// browser) or creates a new one. The pairing code lives in the vault's
// worker, so a popup that closes, or a reloaded page, asks for it again and
// carries on where it was.

import { describePreset, duration, PRESETS, VAULT_NAME } from "../device-rules"
import type { JoinStatus, Reauth } from "../messages"
import { h, icon, ICONS, svg } from "../ui/dom"
import { rollLabel } from "../ui/motion"
import type { App, View } from "./app"
import { button, copied, field, glyph, para, refuse, toolbar } from "./kit"
import { enrollment, verify } from "./biometric"
import { fromCli } from "./about"

type Join =
  | { step: "choose" }
  | { step: "create" }
  | { step: "starting" }
  | { step: "waiting"; code: string }
  | { step: "admitted"; vault?: string }
  | { step: "failed"; message: string }
  | { step: "cancelling" }

const POLL_MS = 1500

export class Setup {
  private join: Join = { step: "choose" }
  /** Bumped by every change of step, so an answer to an older one (a poll, a start, a finish) never brings it back. */
  private gen = 0
  private timer: ReturnType<typeof setTimeout> | undefined
  /** The generation whose device-join-start is still awaited, if any. */
  private startedAt = -1

  constructor(private app: App) {}

  stop() {
    clearTimeout(this.timer)
    this.timer = undefined
  }

  /** Set up (or gone) under the page: a join's step means nothing now. */
  reset() {
    if (this.join.step !== "choose") this.set({ step: "choose" })
  }

  private polling() {
    this.stop()
    if (this.join.step === "waiting" || this.join.step === "starting") this.timer = setTimeout(() => void this.check(), POLL_MS)
  }

  private set(next: Join) {
    this.gen++
    this.join = next
    this.polling()
  }

  /** Shows `next`, redrawing only if the step changed, so a poll never throws away what's typed. */
  private to(next: Join, dir: -1 | 0 | 1 = 0) {
    if (JSON.stringify(next) === JSON.stringify(this.join)) return this.polling()
    this.set(next)
    this.app.show(dir)
  }

  private step(r: Record<string, unknown>): Join | null {
    const s = r as Partial<JoinStatus>
    if (s.type !== "device-join-status") return null
    const join = this.join
    switch (s.phase) {
      case "waiting":
        // No code yet: the vault is still reaching its relay.
        return typeof s.code === "string" && s.code ? { step: "waiting", code: s.code } : { step: "starting" }
      case "admitted":
        return typeof s.vault === "string" && s.vault ? { step: "admitted", vault: s.vault } : { step: "admitted" }
      case "failed":
        return { step: "failed", message: typeof s.message === "string" && s.message ? s.message : "Pairing didn't work." }
      case "idle":
        // Nothing to come back to. A create the user had opened stays open, as
        // does a start the vault hasn't taken up yet.
        if (join.step === "create" || (join.step === "starting" && this.startedAt === this.gen)) return join
        return join.step === "waiting" || join.step === "starting" || join.step === "admitted" ? { step: "failed", message: "The pairing was interrupted. Start again." } : { step: "choose" }
    }
    return null
  }

  /** Asks the vault how the join is going; while it's waiting, again shortly. */
  async check() {
    this.stop()
    const gen = this.gen
    const r = await this.app.run({ type: "device-join-status" })
    if (gen !== this.gen || this.app.status.state !== "not-set-up") return
    const next = r.ok ? this.step(r.reply) : { step: "failed" as const, message: r.message || "The pairing was interrupted. Start again." }
    if (next) this.to(next)
    else this.polling()
  }

  /** A status push while admitted: a screen lock or a lost worker can drop the welcome. */
  pushed() {
    if (this.join.step === "admitted") void this.check()
  }

  private async start() {
    this.set({ step: "starting" })
    this.app.show(1)
    const gen = (this.startedAt = this.gen)
    const r = await this.app.run({ type: "device-join-start" })
    if (gen !== this.gen) return
    this.startedAt = -1
    const code = r.ok && typeof r.reply.code === "string" ? r.reply.code : ""
    this.set(code ? { step: "waiting", code } : { step: "failed", message: r.ok ? "The vault didn't give a pairing code." : r.message })
    this.app.show()
  }

  /** Ends the join (its worker, and everything it held) and goes back to the first choice. */
  private async cancel() {
    this.set({ step: "cancelling" })
    this.app.show()
    const gen = this.gen
    const r = await this.app.run({ type: "device-join-cancel" })
    if (gen !== this.gen) return
    this.set({ step: "choose" })
    if (r.status.state !== "not-set-up") return this.app.render()
    this.app.show(-1)
    if (!r.ok) this.app.announce(r.message)
  }

  view(): View {
    const j = this.join
    switch (j.step) {
      case "choose":
        return this.choose()
      case "create":
        return this.create()
      case "starting":
        return this.code(null)
      case "waiting":
        return this.code(j.code)
      case "cancelling":
        return { el: h("section", { class: "view" }, toolbar("Pair with a device", null), para("Cancelling…")) }
      case "admitted":
        return this.finish(j.vault)
      case "failed":
        return this.failed(j.message)
    }
  }

  private choose(): View {
    // Named by its title, described by the line under it, both as shown.
    const choice = (glyphEl: Element, title: string, sub: string, act: () => void, primary = false) => {
      const id = `choice-${Math.random().toString(36).slice(2, 9)}`
      return button(
        `choice${primary ? " primary" : ""}`,
        [h("span", { class: "tile" }, glyphEl), h("span", { class: "choice-text" }, h("span", { class: "choice-title", id: `${id}-title` }, title), h("span", { class: "choice-sub", id: `${id}-sub` }, sub)), h("span", { class: "chevron" }, glyph("chevron"))],
        act,
        { "aria-labelledby": `${id}-title`, "aria-describedby": `${id}-sub` },
      )
    }
    const pair = choice(glyph("link"), "Pair with an existing device", "Use the vault you already have on your Mac, phone or another browser", () => void this.start(), true)
    // The Deadbolt CLI installed this copy, so Deadbolt is on this computer:
    // offer it by name. Pairing is the same either way (a code it admits).
    void fromCli().then(async (cli) => {
      if (!cli) return
      const mac = (await chrome.runtime.getPlatformInfo().catch(() => null))?.os === "mac"
      const title = `Pair with Deadbolt on this ${mac ? "Mac" : "computer"}`
      const sub = "Use the vault you already have here: this browser shows a code to run deadbolt pair with"
      pair.querySelector(".choice-title")!.textContent = title
      pair.querySelector(".choice-sub")!.textContent = sub
    })
    const create = choice(glyph("plus"), "Create a new vault", "Start fresh, with this browser as its first device", () => this.to({ step: "create" }, 1))
    return {
      el: h(
        "section",
        { class: "view setup" },
        h("div", { class: "hero" }, h("span", { class: "hero-logo" }, svg(ICONS.deadbolt)), h("h1", {}, "Set up Deadbolt"), para("Make this browser one of your Deadbolt devices. Your vault is encrypted here and synced only between your own devices.")),
        h("div", { class: "choices" }, pair, create),
      ),
      focus: () => pair.focus(),
    }
  }

  private code(code: string | null): View {
    const copy = button("btn", [icon("copy"), "Copy"], (b) => code && void copied(b, code, (m) => this.app.announce(m), "Copied the code"))
    if (!code) copy.disabled = true
    // The whole command, for a terminal on the other device (or this one).
    const command = code ? `deadbolt pair ${code}` : ""
    const copyCommand = button("link", "Copy the command", (b) => command && void copied(b, command, (m) => this.app.announce(m), "Copied the command"))
    // Long codes wrap between words, never inside one.
    const words = code ? code.split("-").flatMap((w, i) => (i ? ["-", h("wbr"), w] : [w])) : ["Getting a code…"]
    const shown = h("span", { class: `code${code ? "" : " pending"}`, id: "join-code" })
    shown.append(...words)
    if (code) shown.setAttribute("aria-label", code)
    return {
      el: h(
        "section",
        { class: "view" },
        toolbar("Pair with a device", () => void this.cancel()),
        para("On a device that has your vault, run ", h("code", {}, code ? command : "deadbolt pair"), code ? "" : " with this code", ", or choose Pair in the Deadbolt app."),
        h("div", { class: "code-box" }, shown, copy),
        code ? h("p", { class: "small" }, copyCommand) : null,
        h("div", { class: "waiting" }, h("span", { class: "sync-dot busy", "aria-hidden": "true" }), h("span", {}, code ? "Waiting for the other device…" : "Connecting to Deadbolt's sync service…")),
        h("p", { class: "faint small" }, "The code works once, for five minutes. Keep this open, or come back to it: it waits either way."),
        h("div", { class: "buttons end" }, button("btn", "Cancel", () => void this.cancel())),
      ),
    }
  }

  private failed(message: string): View {
    const again = button("btn primary", "Try again", () => void this.start())
    return {
      el: h(
        "section",
        { class: "view" },
        toolbar("Pairing didn't work", () => void this.cancel()),
        h("div", { class: "notice danger" }, glyph("warning"), h("p", { class: "error" }, message)),
        h("div", { class: "buttons end" }, button("btn", "Cancel", () => void this.cancel()), again),
      ),
      focus: () => again.focus(),
    }
  }

  /** Two passphrase fields that must match, with the form's error line. */
  private passphrases(): { pass: HTMLInputElement; again: HTMLInputElement; error: HTMLElement; fields: HTMLElement[]; valid(): boolean } {
    const pass = field("Passphrase", { type: "password", autocomplete: "new-password" })
    const again = field("Passphrase again", { type: "password", autocomplete: "new-password" })
    const error = h("p", { class: "error reserve", role: "alert" })
    error.hidden = true
    const valid = () => {
      const problem = !pass.input.value ? "Choose a passphrase." : pass.input.value !== again.input.value ? "The passphrases don't match." : ""
      error.textContent = problem
      error.hidden = !problem
      if (problem) refuse(problem.startsWith("Choose") ? pass.input : again.input)
      return !problem
    }
    // Typing again takes the complaint away, as the unlock form does.
    for (const f of [pass.input, again.input])
      f.addEventListener("input", () => {
        f.classList.remove("invalid")
        error.hidden = true
      })
    return { pass: pass.input, again: again.input, error, fields: [pass.wrap, again.wrap], valid }
  }

  private finish(vault?: string): View {
    const p = this.passphrases()
    const label = h("span", { class: "roll-label" }, "Finish")
    label.dataset.text = "Finish"
    const submit = h("button", { class: "btn primary wide", type: "submit" }, label)
    const form = h(
      "form",
      { class: "view", novalidate: "" },
      h("div", { class: "hero small" }, h("span", { class: "done-mark" }, icon("check")), h("h1", {}, vault ? `Joined ${vault}` : "Joined your vault"), para("Choose a passphrase for this browser. It unlocks Deadbolt here only; your other devices keep their own.")),
      ...p.fields,
      p.error,
      h("div", { class: "buttons stack" }, submit, button("link", "Cancel", () => void this.cancel())),
    )
    form.addEventListener("submit", async (e) => {
      e.preventDefault()
      if (!p.valid()) return
      submit.disabled = true
      rollLabel(label, "Finishing…")
      const gen = this.gen
      const r = await this.app.ask({ type: "device-join-finish", passphrase: p.pass.value })
      p.pass.value = p.again.value = ""
      // Cancelled meanwhile: that answer is for a join that's gone.
      if (gen !== this.gen && this.app.status.state === "not-set-up") return
      this.app.status = r.status
      if (r.ok) {
        this.set({ step: "choose" })
        return this.app.opened()
      }
      submit.disabled = false
      rollLabel(label, "Finish")
      p.error.textContent = r.message
      p.error.hidden = false
      // The join may be gone (expired, say): show what's left of it.
      void this.check()
    })
    return { el: form, focus: () => p.pass.focus() }
  }

  private create(): View {
    const name = field("Vault name", { value: "personal", maxlength: "64", pattern: "[a-z][a-z0-9_\\-]{0,63}", "aria-describedby": "name-hint" })
    const p = this.passphrases()
    name.input.addEventListener("input", () => {
      name.input.classList.remove("invalid")
      p.error.hidden = true
    })
    const label = h("span", { class: "roll-label" }, "Create vault")
    label.dataset.text = "Create vault"
    const submit = h("button", { class: "btn primary wide", type: "submit" }, label)
    const form = h(
      "form",
      { class: "view", novalidate: "" },
      toolbar("Create a vault", () => this.to({ step: "choose" }, -1)),
      name.wrap,
      h("p", { class: "hint", id: "name-hint" }, "Lowercase letters, digits, - and _. Your other devices see this name."),
      ...p.fields,
      h("p", { class: "hint" }, "This passphrase unlocks Deadbolt in this browser. There's no way to recover it, so pick words you'll remember."),
      p.error,
      h("div", { class: "buttons stack" }, submit),
    )
    form.addEventListener("submit", async (e) => {
      e.preventDefault()
      const vault = name.input.value.trim() || "personal"
      if (!VAULT_NAME.test(vault)) {
        p.error.textContent = "Start the name with a lowercase letter; then use lowercase letters, digits, - or _."
        p.error.hidden = false
        return refuse(name.input)
      }
      if (!p.valid()) return
      submit.disabled = true
      rollLabel(label, "Creating…")
      const r = await this.app.run({ type: "device-create", name: vault, passphrase: p.pass.value })
      p.pass.value = p.again.value = ""
      if (r.ok) {
        this.set({ step: "choose" })
        return this.app.opened()
      }
      submit.disabled = false
      rollLabel(label, "Create vault")
      p.error.textContent = r.message
      p.error.hidden = false
    })
    return { el: form, focus: () => p.pass.focus() }
  }
}

export function unlockView(app: App): View {
  let timer: ReturnType<typeof setTimeout> | undefined
  const backoff = (until: number) => {
    clearTimeout(timer)
    const seconds = Math.ceil((until - Date.now()) / 1000)
    submit.disabled = seconds > 0
    // Over: no longer an error. The red goes and the line clears; it's said rather than shown.
    if (seconds <= 0) {
      error.hidden = true
      input.classList.remove("invalid")
      app.announce("You can try your passphrase again.")
      return
    }
    error.hidden = false
    error.textContent = `Too many wrong passphrases. Try again in ${seconds} s.`
    timer = setTimeout(() => backoff(until), 250)
  }
  const input = h("input", { class: "input", type: "password", autocomplete: "current-password", "aria-label": "Passphrase", placeholder: "Passphrase", spellcheck: "false" })
  const error = h("p", { class: "error reserve", role: "alert" })
  error.hidden = true
  const label = h("span", { class: "roll-label" }, "Unlock")
  label.dataset.text = "Unlock"
  const submit = h("button", { class: "btn primary wide", type: "submit" }, label)
  const preset = PRESETS[app.preset]
  const form = h(
    "form",
    { class: "view center unlock", novalidate: "" },
    h("div", { class: "state" }, h("span", { class: "state-icon" }, icon("lock")), h("h2", {}, "Unlock Deadbolt"), para("Enter this browser's passphrase.")),
    input,
    error,
    submit,
    h("p", { class: "preset-note", title: describePreset(app.preset) }, icon("clock"), h("span", {}, `${preset.name} · locks after ${duration(preset.idleMs)} idle`)),
  )
  input.addEventListener("input", () => {
    input.classList.remove("invalid")
    error.hidden = true
  })
  const touch = button("btn primary wide", "Unlock with Touch ID", async (b) => {
    b.disabled = true
    error.hidden = true
    try {
      const r = await app.run({ type: "device-unlock", prf: await verify(app, true) })
      if (!r.ok) throw new Error(r.message)
      return app.opened()
    } catch (e) {
      error.textContent = (e as Error).message
      error.hidden = false
      input.focus()
    } finally { b.disabled = false }
  })
  void Promise.all([enrollment(app), chrome.storage.local.get("deadbolt.unlockMethod")]).then(([enrolled, settings]) => {
    if (!enrolled || !form.isConnected) return
    form.insertBefore(touch, input)
    if (settings["deadbolt.unlockMethod"] !== "passphrase") touch.focus()
  })
  form.addEventListener("submit", async (e) => {
    e.preventDefault()
    if (submit.disabled) return
    if (!input.value) return refuse(input)
    submit.disabled = true
    rollLabel(label, "Unlocking…")
    const r = await app.run({ type: "device-unlock", passphrase: input.value })
    input.value = ""
    if (r.ok || r.status.state !== "locked") return app.opened()
    submit.disabled = false
    rollLabel(label, "Unlock")
    if (!r.ok && r.code === "wrong_passphrase") error.textContent = "That passphrase isn't right."
    else error.textContent = r.ok ? "" : r.message
    error.hidden = false
    if (!r.ok && r.retryAt) backoff(r.retryAt)
    refuse(input)
    input.focus()
  })
  void app.ask({ type: "device-settings" }).then((r) => {
    if (r.ok && typeof r.reply.retryAt === "number" && r.reply.retryAt > Date.now() && form.isConnected) backoff(r.reply.retryAt)
  })
  return { el: form, focus: () => input.focus(), leave: () => clearTimeout(timer) }
}

/** What a request waiting on the passphrase says: its heading, why, and its button (and that button busy). */
function reauthText(reauth: Reauth): { title: string; why: string; act: string; busy: string } {
  switch (reauth.kind) {
    case "passkey-get":
      return { title: `Sign in to ${reauth.site}`, why: `Strict: enter your passphrase to sign in as ${reauth.title} with a passkey on `, act: "Sign in", busy: "Signing in…" }
    case "passkey-create":
      return { title: `Save a passkey for ${reauth.site}`, why: `Strict: enter your passphrase to save a passkey for ${reauth.title} on `, act: "Save", busy: "Saving…" }
    default:
      return { title: `Fill ${reauth.title}`, why: "Strict: enter your passphrase to fill this card on ", act: "Fill", busy: "Filling…" }
  }
}

/**
 * A page's request waiting on the passphrase under Strict (a card's number or
 * code to fill, or a passkey sign-in or save): asked here, in Deadbolt's own
 * popup or page, never in the page asking. The passphrase goes to the
 * background in one message, for that one request.
 */
export function reauthView(app: App, reauth: Reauth): View {
  const text = reauthText(reauth)
  const input = h("input", { class: "input", type: "password", autocomplete: "current-password", "aria-label": "Passphrase", placeholder: "Passphrase", spellcheck: "false" })
  const error = h("p", { class: "error reserve", role: "alert" })
  error.hidden = true
  const label = h("span", { class: "roll-label" }, text.act)
  label.dataset.text = text.act
  const submit = h("button", { class: "btn primary wide", type: "submit" }, label)
  const form = h(
    "form",
    { class: "view center unlock", novalidate: "" },
    h("div", { class: "state" }, h("span", { class: "state-icon" }, icon("lock")), h("h2", {}, text.title), para(text.why, h("span", { class: "mono" }, reauth.site), ".")),
    input,
    error,
    h("div", { class: "buttons stack" }, submit, button("link", "Cancel", () => void app.reauthCancel(reauth))),
  )
  input.addEventListener("input", () => {
    input.classList.remove("invalid")
    error.hidden = true
  })
  const touch = button("btn primary wide", "Verify with Touch ID", async (b) => {
    b.disabled = true
    try {
      const r = await app.run({ type: "device-reauth-confirm", id: reauth.id, prf: await verify(app) })
      if (!r.ok) throw new Error(r.message)
      return app.reauthDone()
    } catch (e) {
      error.textContent = (e as Error).message
      error.hidden = false
      input.focus()
    } finally { b.disabled = false }
  })
  // Touch ID may fill a card (no kind is a card); a passkey always takes the passphrase.
  const card = (reauth.kind ?? "card") === "card"
  if (card) void enrollment(app).then((t) => { if (t && form.isConnected) { form.insertBefore(touch, input); touch.focus() } })
  form.addEventListener("submit", async (e) => {
    e.preventDefault()
    if (!input.value) return refuse(input)
    submit.disabled = true
    rollLabel(label, text.busy)
    const passphrase = input.value
    input.value = ""
    const r = await app.run({ type: "device-reauth-confirm", id: reauth.id, passphrase })
    if (r.ok) return app.reauthDone()
    submit.disabled = false
    rollLabel(label, text.act)
    // Wrong, or too many wrong: the request waits for another try. Anything else ended it.
    if (r.code !== "wrong_passphrase" && r.code !== "backoff") return app.reauthDone(r.message)
    error.textContent = r.code === "wrong_passphrase" ? "That passphrase isn't right." : r.message
    error.hidden = false
    refuse(input)
    input.focus()
  })
  return { el: form, focus: () => input.focus() }
}
