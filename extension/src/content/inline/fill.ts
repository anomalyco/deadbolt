// Applying approved login, identity, and card fills and tracking step progression.

import { signInEnabled } from "../../auth-state"
import type { FillAck, FormsAck, SurfaceMode, ToContent } from "../../messages"
import { approvals } from "../approvals"
import type { FormControl } from "../detect"
import { fillable, fillFields, visibleBox } from "../fill"
import { fillCheck, fillForm, offScreen, takeApproved, type FormsState } from "../formfill"
import { fitsPattern, rememberGenerated } from "../generate"
import { learning } from "../learn"
import type { PageState } from "../inline"
import { GONE_COUNTS_MS } from "./dom"
import { framedGone } from "./framed"

export interface FillHost {
  state(): PageState
  mode(): SurfaceMode
  isTop: boolean
  host(): HTMLElement | null
  closeMenu(): void
  clearGesture(): void
  pillSettled(ms: number): Promise<void>
  ownPill(): Element | null
  openPill(el: FormControl, token: string): void
}

/** The fields the last fill in this document wrote, and whether the user submitted since. */
let lastFilled: HTMLInputElement[] = []
let submittedSinceFill = false
/** When the user last clicked a submit control or pressed Enter in a field themselves (content.ts). */
let submitGestureAt = -Infinity

export function resetFillState() {
  lastFilled = []
  submittedSinceFill = false
}

export function formsStateOf(state: PageState): FormsState {
  return { fields: () => state.formFields(), form: () => state.formsForm(), rescan: () => state.rescan() }
}

/**
 * Fills only the form the login was chosen for (if the fields were replaced,
 * added or removed since, nothing is written), and in it only the fields the
 * background's db:approve fixed for this fill. Answers with what was written.
 */
export async function applyFill(h: FillHost, message: Extract<ToContent, { type: "db:fill" }>): Promise<FillAck> {
  if (message.automatic && (!h.isTop || document.hidden || !(await signInEnabled()))) return { filled: [] }
  // A sign-in session's step (no pick) fills nothing while the tab learns: the user signs in by hand.
  if (message.notice && learning()) return { filled: [] }
  // A pick from the menu folded it into a pill on the field, which stays to
  // say how the fill went and goes by itself. Any other fill (the popup's,
  // an email-first step) closes what's open.
  if (h.mode() !== "pill") h.closeMenu()
  // Filling focuses each field. Without this, the keypress that chose the
  // login would reopen the menu on the first field, covering the next one.
  h.clearGesture()
  // In a frame, the menu this fill was picked from is a pill now: Esc or a click here is about nothing of it.
  framedGone(false)
  const state = h.state()
  state.rescan()
  if (state.form() !== message.form) return { filled: [] }
  // A generated password the boxes' pattern won't take (the page changed it since the menu opened).
  const approved = approvals.get(String(message.approval), message.form)
  if (message.values.newPassword && approved && !fitsPattern(approved, message.values.newPassword)) return { filled: [], rejected: true }
  // Only the fields approved for this fill, never one that became fillable since.
  const targets = approvals.take(String(message.approval), message.form, state.targets())
  if (!targets?.length) return { filled: [] }
  // Nothing is written while the surface is still folding over the form:
  // only the settled pill, where this script put it, isn't taken for a cover
  // (see ownPill). Each write checks again.
  if (h.mode() === "pill") await h.pillSettled(700)
  if (state.form() !== message.form) return { filled: [] }
  const { filled, last, written } = await fillFields(targets, message.values, (el) => (!message.automatic || !document.hidden) && fillable(el, h.ownPill()))
  if (filled.includes("new-password") && message.values.newPassword && typeof message.generated === "string")
    rememberGenerated(message.generated, message.values.newPassword)
  if (filled.length) {
    lastFilled = written
    submittedSinceFill = false
  }
  last?.focus({ preventScroll: true })
  // A sign-in session's step, filled without a pick: a pill on the field
  // says so ("Password filled"), then goes (see menu.ts showNotice).
  // On the last field written: for a code in one box per digit, beside the last box.
  // In a frame, the background opens it in the top page, where the field shows (see Autofill.fill).
  const on = [...lastFilled].reverse().find((el) => el.isConnected)
  if (filled.length && typeof message.notice === "string" && on) {
    if (h.isTop && !h.host()) h.openPill(on, message.notice)
    const box = h.isTop ? null : visibleBox(on)
    if (box) return { filled, box }
  }
  return { filled }
}

/**
 * Writes an identity or card into the fields db:forms-approve fixed for
 * this fill, in the snapshot it was chosen for, as applyFill does for a login.
 */
export async function applyFormsFill(h: FillHost, message: Extract<ToContent, { type: "db:forms-fill" }>): Promise<FormsAck> {
  if (h.mode() !== "pill") h.closeMenu()
  h.clearGesture()
  const values = message.values && typeof message.values === "object" ? message.values : {}
  const state = h.state()
  const targets = takeApproved(formsStateOf(state), String(message.approval), message.form)
  if (!targets?.length) return { filled: [] }
  if (h.mode() === "pill") await h.pillSettled(700)
  if (state.formsForm() !== message.form) return { filled: [] }
  // An identity's fields below the fold were approved for this pick: each is scrolled to as it's written (see offScreen).
  const reach = targets[0].kind === "identity" && h.isTop ? (el: FormControl) => offScreen(el) : undefined
  const { filled } = await fillForm(targets, values, (el) => fillCheck(targets[0].kind, h.ownPill())(el), reach)
  return { filled }
}

export function markSubmitted() {
  if (lastFilled.length) submittedSinceFill = true
}

export function noteSubmitGesture() {
  submitGestureAt = performance.now()
}

/**
 * Whether the page has moved on since the last fill here: the user submitted
 * (content.ts counts only their own click or Enter), or, right after their
 * own click or Enter, none of the filled fields is still in the login form.
 * Only then does the background fill a sign-in session's next step into this
 * document.
 */
export function stepped(state: PageState): boolean {
  if (!lastFilled.length) return false
  if (submittedSinceFill) return true
  // The filled fields going away counts only right after the user's own
  // click or Enter: a page's script can take them away itself.
  if (performance.now() - submitGestureAt > GONE_COUNTS_MS) return false
  const now = state.targets()
  return lastFilled.every((el) => !el.isConnected || !now.some((t) => t.el === el))
}
