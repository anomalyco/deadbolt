// A field the user asked Deadbolt to fill where the scan found no login
// (the fill shortcut, or "Fill with Deadbolt" in its context menu, see
// bg/doors.ts): a login made of that field and the box of the other kind
// beside it, for the account menu to open on.

import { masked, ownerOf, type Field } from "./detect"
import { fillable } from "./fill"
import type { FieldRole } from "../messages"

/** A box a login is typed into: text, email or phone, or a password (one the page masks with CSS included). */
const typable = (el: HTMLInputElement) => masked(el) || el.type === "text" || el.type === "email" || el.type === "tel"

const roleOf = (el: HTMLInputElement): FieldRole => (masked(el) ? "password" : el.type === "email" ? "email" : el.type === "tel" ? "phone" : "username")

/**
 * The login fields for `el`, which the user asked to fill: it, as a
 * username (or a password, when it's masked), and the nearest box of the
 * other kind in its form (or around it) after it (or, for a password, before
 * it). Only fields that show, on top and enabled (see fillable): nothing
 * hidden, covered, disabled or read-only, so a honeypot beside it never joins.
 */
export function manualFields(el: HTMLInputElement): Field[] {
  if (!typable(el) || !fillable(el)) return []
  const scope = el.form ?? el.closest("form") ?? el.parentElement?.parentElement ?? el.parentElement
  const inputs = scope ? Array.from(scope.querySelectorAll("input")) : [el]
  const at = inputs.indexOf(el)
  const partner = masked(el)
    ? inputs.slice(0, Math.max(at, 0)).reverse().find((x) => typable(x) && !masked(x) && fillable(x))
    : inputs.slice(at + 1).find((x) => masked(x) && fillable(x))
  return (partner && inputs.indexOf(partner) < at ? [partner, el] : partner ? [el, partner] : [el]).map((x) => ({ el: x, role: roleOf(x), owner: ownerOf(x) }))
}

/**
 * The login form a scan gives: the fields the user asked to fill while they
 * last (`manual`), unless the scan itself recognized that field; else what
 * the scan found.
 */
export function withManual(scanned: Field[], manual: Field[]): Field[] {
  const live = manual.filter((f) => f.el.isConnected)
  return live.length && !scanned.some((f) => f.el === live[0].el) ? live : scanned
}
