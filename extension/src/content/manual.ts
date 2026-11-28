// A field the user asked Deadbolt to fill where the scan found no login
// (the fill shortcut, or "Fill with Deadbolt" in its context menu, see
// bg/doors.ts): a login made of that field and the box of the other kind
// right beside it, for the account menu to open on.

import { ignored, masked, ownerOf, type Field } from "./detect"
import { onScreen } from "./formfill"
import type { FieldRole } from "../messages"

/** A box a login is typed into: text, email or phone, or a password (one the page masks with CSS included). */
const typable = (el: HTMLInputElement) => masked(el) || el.type === "text" || el.type === "email" || el.type === "tel"

const roleOf = (el: HTMLInputElement): FieldRole => (masked(el) ? "password" : el.type === "email" ? "email" : el.type === "tel" ? "phone" : "username")

const formOf = (el: HTMLInputElement): HTMLFormElement | null => el.form ?? el.closest("form")

/**
 * The inputs of `el`'s form, in order: its form's own elements (those
 * outside it that name it with `form=` included), or for a field in no form,
 * the inputs around it that are in no form either.
 */
function formInputs(el: HTMLInputElement): HTMLInputElement[] {
  if (el.form) return Array.from(el.form.elements).filter((x): x is HTMLInputElement => x instanceof HTMLInputElement)
  const owner = formOf(el)
  const scope = owner ?? el.parentElement?.parentElement ?? el.parentElement
  const inputs = scope ? Array.from(scope.querySelectorAll("input")) : [el]
  return inputs.filter((x) => formOf(x) === owner)
}

/**
 * The box of the other kind right beside `el`: the next visible login box
 * after a username (or before a password), if that one is of the other kind.
 * Boxes that don't show are passed over, a honeypot included; a box that
 * shows but is of the same kind ends the search, so a password a few boxes
 * on, behind other text boxes, never pairs. Only one on screen as it stands,
 * never scrolled to (see onScreen), and not one the site asked password
 * managers to leave alone.
 */
function partnerOf(el: HTMLInputElement): HTMLInputElement | undefined {
  const inputs = formInputs(el)
  const at = inputs.indexOf(el)
  if (at < 0) return undefined
  const password = masked(el)
  const order = password ? inputs.slice(0, at).reverse() : inputs.slice(at + 1)
  const next = order.find((x) => typable(x) && onScreen(x))
  return next && masked(next) !== password && !ignored(next) ? next : undefined
}

/**
 * The login fields for `el`, which the user asked to fill: it, as a
 * username (or a password, when it's masked), and the box of the other kind
 * right beside it in its own form (see partnerOf). Only a field that shows,
 * on top and enabled, without scrolling to it.
 */
export function manualFields(el: HTMLInputElement): Field[] {
  if (!typable(el) || !onScreen(el)) return []
  const partner = partnerOf(el)
  const pair = !partner ? [el] : masked(el) ? [partner, el] : [el, partner]
  return pair.map((x) => ({ el: x, role: roleOf(x), owner: ownerOf(x) }))
}

/**
 * The login form a scan gives, with the fields the user asked to fill
 * (`manual`): those, while they last and the scan's own login form isn't
 * where the user is (`active`) or doesn't take them in; else what the scan
 * found, and `manual` is done with.
 */
export function withManual(scanned: Field[], manual: Field[], active: Element | null): { fields: Field[]; manual: Field[] } {
  const live = manual.filter((f) => f.el.isConnected)
  const done = !live.length || scanned.some((f) => f.el === active || live.some((m) => m.el === f.el))
  return done ? { fields: scanned, manual: [] } : { fields: live, manual: live }
}
