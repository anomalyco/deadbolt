// The corner save/update offer surface: compact pill, expanded card, and tucked dot.

import type { ChooseReply, MenuLoadReply, OfferChoice, SurfaceMode, ToBackground } from "../messages"
import { h, ICONS, svg, type Dwell, type Entry } from "../ui/dom"
import { rollLabel } from "../ui/motion"
import { offerTitle } from "../ui/offer"

/** How long the save offer stays in the page before it leaves the offer to the toolbar. */
const OFFER_STAYS_MS = 12_000
/** After a save that failed once the offer's time was up, it stays this much longer. */
const OFFER_REARM_MS = 6000
/** The dot the offer shrinks to stays this long before leaving the offer to the toolbar. */
const DOT_STAYS_MS = 20_000
/** Reopened from the dot, the pill stays this long. */
const OFFER_REOPENED_MS = 8000
/** The offer's compact pill is this tall; its dot this wide. */
export const ROW = 36
const DOT = 28
/** The pointer resting on the pill this long opens it. */
const OPEN_AFTER_MS = 350
/** Leaving the open offer closes it after this grace. */
export const COLLAPSE_GRACE_MS = 300
/** Reopened from the dot under the pointer, it waits this long before opening further. */
const REOPEN_SETTLES_MS = 500
/** Pointer events this soon after the frame changed size may be the browser replaying an old position. */
export const REPLAY_MS = 150
/** The pill and the dot cross-fade over this long (menu.css). */
const CROSSFADE_MS = 260
/** How long a pill says how it went before it goes. */
export const FILLED_STAYS_MS = 900
/** "Saving…" stays in the Save button at least this long, so it can be read. */
const SAVING_READS_MS = 520

/**
 * The save offer's shape: a small pill in the corner ("compact"), opened on
 * approach to show who and the other choices ("open"), or just Deadbolt's
 * mark ("dot") once it's not wanted for now.
 */
export type OfferState = "compact" | "open" | "dot"

export interface OfferHost {
  surface: HTMLElement
  dwell: Dwell
  entry: Entry
  send<T>(message: ToBackground): Promise<T | null>
  token(): string
  port(): MessagePort | undefined
  report(grow?: number): void
  done(travel?: boolean): void
  leaveLikeSave(): void
  fold(persist: HTMLElement | null, text: string, opts?: { persistIsLabel?: boolean; lead?: HTMLElement; check?: boolean }): HTMLElement
  settle(label: HTMLElement, text: string, ok: boolean): void
  press(el: HTMLElement): void
  relax(): void
  announce(text: string): void
  confirmScale(at: number): Promise<boolean>
  isBusy(): boolean
  setBusy(value: boolean): void
  getMode(): SurfaceMode
  setMode(mode: SurfaceMode): void
  isPressedScale(): boolean
  getPressedAt(): number
  isPointerAway(): boolean
  setPointerAway(value: boolean): void
  getResizedAt(): number
}

export interface OfferHandles {
  state: () => OfferState
  size: () => { width: number; height: number }
  tuck: () => void
  away: () => void
}

/**
 * "Save login?" after a confirmed sign-in, in the top right corner of the
 * page. It shows the username and site only; the password stays in the
 * background.
 *
 * The whole card is laid out once, at its open size, anchored to the top
 * right corner; the frame shows only as much of it as the shape needs, so
 * opening and closing are the frame's clip and radius moving, with nothing
 * inside reflowing. The parent moving the frame restarts the dwell, so a
 * button that just came into view takes no press until it has sat still.
 */
export function renderOffer(o: OfferHost, offer: Extract<MenuLoadReply, { kind: "offer" }>): OfferHandles {
  let offerState = "compact" as OfferState
  let offerSize: () => { width: number; height: number } = () => ({ width: 0, height: 0 })
  let tuck = () => {}
  let away = () => {}

  o.setMode("save")
  const title = offerTitle(offer)
  document.body.classList.add("save")
  document.body.dataset.offer = offerState
  const status = h("p", { class: "offer-status" })
  // An update says so on its button.
  const primary = offer.update ? "Update" : "Save"
  const saveLabel = h("span", { class: "roll-label" }, primary)
  saveLabel.dataset.text = primary
  const save = h("button", { class: "btn primary", type: "button" }, saveLabel)
  const later = h("button", { class: "btn", type: "button" }, "Not now")
  const never = h("button", { class: "link never", type: "button" }, "Never for this site")
  // An update of a card or identity may be kept as a new one instead.
  const asNew = offer.saveNew ? h("button", { class: "btn new", type: "button" }, "Save as new") : null
  const bar = h("span", { class: "bar", "aria-hidden": "true" })
  const mark = h("span", { class: "offer-mark", "aria-hidden": "true" }, svg(ICONS.deadbolt))
  const row = h("div", { class: "offer-row" }, mark, h("h1", { class: "offer-title" }, title), save)
  const section = h(
    "section",
    { class: "offer", "aria-label": title.slice(0, -1) },
    row,
    h(
      "div",
      { class: "offer-more" },
      h("p", { class: "offer-user" }, h("span", { class: "value" }, offer.username), h("span", { class: "site" }, ` · ${offer.site}`)),
      // What an update changes, for a card: "Expires 08/28 → 09/30".
      offer.change ? h("p", { class: "offer-change" }, offer.change) : null,
      status,
      h("div", { class: "offer-actions" }, never, asNew, later),
    ),
    bar,
  )
  const dot = h("button", { class: "dot", type: "button", "aria-label": title }, svg(ICONS.deadbolt))
  o.surface.replaceChildren(section, dot)
  section.inert = offerState === "dot"
  dot.inert = offerState !== "dot"

  // The compact pill: the top row, from the mark (with the row's padding) to the corner.
  const compactWidth = () => Math.ceil(section.getBoundingClientRect().right - mark.getBoundingClientRect().left + 12)
  offerSize = () => {
    if (offerState === "dot") return { width: DOT, height: DOT }
    const box = section.getBoundingClientRect()
    if (offerState === "open") return { width: Math.ceil(box.width), height: Math.ceil(box.height) }
    const width = compactWidth()
    bar.style.width = `${width}px`
    return { width, height: ROW }
  }
  // The bar runs along the compact pill's bottom edge.
  bar.style.width = `${compactWidth()}px`

  // ---- Shape ----
  let grace: ReturnType<typeof setTimeout> | undefined
  let reopenedAt = -Infinity
  const shape = (next: OfferState) => {
    clearTimeout(grace)
    if (next === offerState || o.getMode() !== "save") return
    for (const a of o.surface.getAnimations()) a.cancel()
    const fromDot = offerState === "dot"
    offerState = next
    document.body.dataset.offer = next
    if (fromDot) reopenedAt = performance.now()
    // Only what shows takes focus: the dot alone, or the pill alone.
    section.inert = next === "dot"
    dot.inert = next !== "dot"
    o.port()?.postMessage({ type: "db:radius", radius: next === "open" ? 12 : next === "dot" ? DOT / 2 : ROW / 2 })
    // The pill and the dot cross-fade (inside the frame): the dwell counts
    // from when that's over, as after a move.
    if (fromDot || next === "dot") {
      o.dwell.moved(performance.now())
      setTimeout(() => o.dwell.moved(performance.now()), CROSSFADE_MS)
    }
    o.report()
  }
  // Where the pointer is, by real movement only. The browser's own idea
  // (:hover) goes stale once the pointer leaves for the page, and after the
  // frame changes size it replays the last position here as if the pointer
  // had moved; the content script says when the pointer is in the page
  // (db:away), and only movement after that counts.
  const pointer = { inside: false }
  const real = (e: PointerEvent) => e.isTrusted && (!o.isPointerAway() || e.movementX !== 0 || e.movementY !== 0 || e.timeStamp - o.getResizedAt() > REPLAY_MS)
  const wanted = () => pointer.inside || section.matches(":focus-within")
  // Approach opens it; leaving closes it again after a moment's grace.
  // Opening waits a moment under the pointer: a quick Save from the pill
  // goes ahead without the card opening (which, being a move, would make
  // the press wait out the dwell again).
  let opening: ReturnType<typeof setTimeout> | undefined
  const approach = (e: PointerEvent) => {
    if (!real(e)) return
    o.setPointerAway(false)
    pointer.inside = true
    if (offerState === "dot") return shape("compact")
    // Just reopened from the dot under the pointer: stay compact until the pointer moves on it.
    if (offerState !== "compact" || opening !== undefined || performance.now() - reopenedAt < REOPEN_SETTLES_MS) return
    opening = setTimeout(() => {
      opening = undefined
      if (pointer.inside && offerState === "compact" && !o.isBusy() && !document.body.classList.contains("held")) shape("open")
    }, OPEN_AFTER_MS)
  }
  const depart = () => {
    pointer.inside = false
    clearTimeout(opening)
    opening = undefined
    clearTimeout(grace)
    grace = setTimeout(() => offerState === "open" && !wanted() && !o.isBusy() && shape("compact"), COLLAPSE_GRACE_MS)
  }
  section.addEventListener("pointerenter", approach)
  section.addEventListener("pointermove", approach)
  section.addEventListener("pointerleave", depart)
  // Keyboard focus opens it; the focus a click gives a button doesn't (that
  // would move the frame under the press, and the press would be refused).
  section.addEventListener("focusin", (e) => offerState !== "dot" && e.target instanceof Element && e.target.matches(":focus-visible") && shape("open"))
  section.addEventListener("focusout", () => !pointer.inside && depart())
  dot.addEventListener("pointerenter", approach)
  dot.addEventListener("pointermove", approach)
  dot.addEventListener("pointerleave", () => (pointer.inside = false))
  dot.addEventListener("click", (e) => e.isTrusted && shape("compact"))
  // Tabbed onto, the dot is the pill again, and focus moves onto its Save (the dot leaves the tab order).
  dot.addEventListener("focus", () => {
    shape("compact")
    save.focus({ preventScroll: true })
  })
  away = () => {
    o.setPointerAway(true)
    if (pointer.inside || offerState === "open") depart()
  }

  // ---- Time ----
  // The pill's bar empties over twelve seconds, then it shrinks to the dot,
  // which stays twenty more before leaving the offer to the toolbar. Stepped
  // frame by frame, never animated (see menu.css), and paused while the offer
  // is open, under the pointer or focus, approached, or a press is checked.
  let barEnded = false
  const time = { total: OFFER_STAYS_MS, left: OFFER_STAYS_MS, last: performance.now(), shape: offerState }
  const tick = (now: number) => {
    if (!section.isConnected || o.getMode() !== "save") return
    if (time.shape !== offerState) {
      // The dot has its own time, and so does the pill reopened from it;
      // opening and closing the pill keeps the time it had.
      const from = time.shape
      time.shape = offerState
      if (offerState === "dot") Object.assign(time, { total: DOT_STAYS_MS, left: DOT_STAYS_MS })
      else if (from === "dot") Object.assign(time, { total: OFFER_REOPENED_MS, left: OFFER_REOPENED_MS })
    }
    const paused = offerState === "open" || wanted() || dot.matches(":focus") || document.body.matches(".near, .held, .busy")
    if (!paused) time.left = Math.max(0, time.left - (now - time.last))
    time.last = now
    if (offerState !== "dot") bar.style.transform = `scaleX(${time.left / time.total})`
    if (time.left > 0) return void requestAnimationFrame(tick)
    if (offerState === "dot") return o.leaveLikeSave()
    barEnded = true
    if (!o.isBusy()) shape("dot")
    requestAnimationFrame(tick)
  }
  requestAnimationFrame(tick)
  /** After a save that failed once the time was up: the pill stays a while longer. */
  const rearm = () => {
    if (!barEnded) return
    barEnded = false
    Object.assign(time, { total: OFFER_REARM_MS, left: OFFER_REARM_MS, last: performance.now(), shape: offerState })
  }
  // A click elsewhere in the page (the content script says so): the dot.
  tuck = () => !o.isBusy() && shape("dot")

  const say = (text: string) => {
    status.hidden = !text
    if (text) rollLabel(status, text)
    o.announce(text)
  }
  say("")
  // It shows in the corner, away from where the user is: a screen reader hears it came.
  // An update names what it changes: "Update phone for Alex Mercer?".
  o.announce(`${title.slice(0, -1)} for ${offer.what && offer.update ? offer.username : offer.site}? Deadbolt's offer is at the end of the page, and in the toolbar button.`)
  const answer = async (choice: OfferChoice, e: MouseEvent) => {
    // Real presses only.
    if (!e.isTrusted || o.isBusy() || offerState === "dot") return
    // Enter or Space count only once the user came into the surface themselves (see Entry): say where else to answer.
    if (e.detail === 0 && !o.entry.entered) return say("Click to answer here, or answer in Deadbolt's toolbar button.")
    if (!o.isPressedScale() || !o.dwell.settled(o.getPressedAt())) {
      o.relax()
      shape("open")
      return say(o.isPressedScale() && o.dwell.visible ? "Press again in a moment." : "This offer is covered. Nothing was saved.")
    }
    o.setBusy(true)
    if (e.currentTarget instanceof HTMLElement) o.press(e.currentTarget)
    if (!(await o.confirmScale(o.getPressedAt()))) {
      o.setBusy(false)
      o.relax()
      shape("open")
      return say("This offer is covered. Nothing was saved.")
    }
    document.body.classList.remove("held")
    // "Saving…" rolls in the button itself, and stays long enough to read.
    const shownAt = performance.now()
    const saving = choice === "save" || choice === "new"
    if (saving) {
      document.body.classList.add("busy")
      rollLabel(saveLabel, "Saving…")
    }
    const reply = await o.send<ChooseReply>({ type: "db:surface-choose", token: o.token(), choice })
    if (!saving) return o.leaveLikeSave()
    if (reply?.ok) {
      await new Promise((r) => setTimeout(r, Math.max(0, SAVING_READS_MS - (performance.now() - shownAt))))
      const label = o.fold(saveLabel, "Saving…", { persistIsLabel: true, lead: mark })
      // Once the pill has its place, its label rolls on to the result: "Saved"
      // for a new login and an update alike, so the pill is the same either way.
      return void setTimeout(() => {
        o.settle(label, "Saved", true)
        o.announce("Saved")
        setTimeout(() => o.done(true), FILLED_STAYS_MS + 450)
      }, 380)
    }
    if (!reply || ("gone" in reply && reply.gone)) return o.leaveLikeSave()
    // Locked or busy: open, say so in place, and let Save be pressed again, for a while.
    o.setBusy(false)
    o.relax()
    document.body.classList.remove("busy")
    rollLabel(saveLabel, primary)
    shape("open")
    say(reply.message)
    rearm()
  }
  // The press shows at once; what it does waits for the checks.
  for (const b of [save, later, never, ...(asNew ? [asNew] : [])]) b.addEventListener("pointerdown", (e) => e.isTrusted && e.button === 0 && !o.isBusy() && o.press(b))
  save.addEventListener("click", (e) => void answer("save", e))
  asNew?.addEventListener("click", (e) => void answer("new", e))
  later.addEventListener("click", (e) => void answer("later", e))
  never.addEventListener("click", (e) => void answer("never", e))
  o.report()

  return { state: () => offerState, size: offerSize, tuck, away }
}
