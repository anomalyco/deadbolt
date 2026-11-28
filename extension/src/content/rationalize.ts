// Settling a login scan's roles within each cluster (graph.ts), once every
// field has its own score: what a field's neighbours in the same form say
// about it, and whether the form is a login at all. Each rule here reads
// the form's shape (which boxes it has, in what order) or the words of the
// form itself, never one site's markup.

import type { FieldRole } from "../messages"
import { FIELD_THRESHOLD, hasPhrase, words, type FieldFacts } from "./clues"
import type { FormCluster, FormGraph } from "./graph"

export interface ScannedField {
  el: HTMLInputElement
  facts: FieldFacts
  score: Record<FieldRole, number>
  role: FieldRole | null
  cluster: FormCluster | undefined
}

const IDENTIFIER: ReadonlyArray<FieldRole | null> = ["username", "email", "phone"]
/** Autocomplete tokens a site puts only on a real sign-in, sign-up or code form. */
const LOGIN_TOKENS = ["current-password", "new-password", "username", "one-time-code", "webauthn"]
/** A code is a few characters; a box that takes more is a password the page calls a passcode. */
const MAX_CODE_LENGTH = 10
/** Words that make a form a gift card's, a coupon's or a balance check's, whatever its boxes look like. */
const DECOY_WORDS = ["gift card", "gift cards", "giftcard", "promo code", "promotion code", "coupon", "voucher", "discount code", "redeem", "check balance", "card balance"].map((p) => words(p).trim())
/** Boxes of a cluster no login role claims that make it something else: a transfer, a product registration, a comment. */
const OTHER_BOXES = 2

const textual = (f: ScannedField) => f.facts.type === "text" || f.facts.type === "email" || f.facts.type === "tel" || f.facts.type === ""

/**
 * Before roles: a password box after another in the same cluster is its
 * confirmation, unless it's a PIN or token box.
 */
export function confirmations(fields: ScannedField[]) {
  const seen = new Set<FormCluster | undefined>()
  for (const f of fields) {
    if (f.facts.type !== "password" || f.score.otp >= FIELD_THRESHOLD) continue
    if (seen.has(f.cluster)) {
      f.score["new-password"] += 4
      f.score.password -= 4
    }
    seen.add(f.cluster)
  }
}

/**
 * After roles, within each cluster: a masked box the page calls a passcode
 * or PIN but that takes a password's length, after a box for who you are,
 * is the password; and a login's one password with no box for who you are
 * takes the plain text box just before it as its username (a bank's
 * "Online ID").
 */
export function rationalize(fields: ScannedField[]) {
  for (const [i, f] of fields.entries()) {
    if (f.facts.type !== "password" || f.role !== "otp" || f.facts.autocomplete.includes("one-time-code")) continue
    const long = f.facts.maxLength ? f.facts.maxLength > MAX_CODE_LENGTH : f.score.password >= FIELD_THRESHOLD
    if (long && fields.slice(0, i).some((g) => g.cluster === f.cluster && textual(g))) f.role = "password"
  }
  for (const cluster of new Set(fields.map((f) => f.cluster))) {
    const own = fields.filter((f) => f.cluster === cluster)
    const passwords = own.filter((f) => f.role === "password")
    if (passwords.length !== 1 || own.some((f) => f.role === "new-password" || IDENTIFIER.includes(f.role))) continue
    const before = own.slice(0, own.indexOf(passwords[0])).reverse()
    const user = before.find((f) => f.role === null && textual(f) && f.score.username > -2)
    if (user && before[0] === user) user.role = "username"
  }
}

/**
 * Whether a cluster the scan would take for a login isn't one: nothing in it
 * asks for a password or says (by autocomplete) it's a sign-in, and either
 * its own words are a gift card's, coupon's or balance check's, or it has
 * boxes no login role claims, two or more (a bank transfer's
 * payee and amount, a product registration's model and serial number).
 */
export function decoyCluster(cluster: FormCluster, fields: ScannedField[], graph: FormGraph): boolean {
  // Page-wide controls (no form or container around them) are no one form: there's nothing to count.
  if (!cluster.root) return false
  if (fields.some((f) => f.role === "password" || f.role === "new-password" || f.facts.autocomplete.some((t) => LOGIN_TOKENS.includes(t)))) return false
  const claimed = new Set<Element>(fields.filter((f) => f.role).map((f) => f.el))
  const others = cluster.controls.filter((el) => !claimed.has(el) && !(el instanceof HTMLInputElement && (el.maxLength === 1 || el.type === "search"))).length
  if (others >= OTHER_BOXES) return true
  const text = graph.context(cluster)
  return DECOY_WORDS.some((p) => hasPhrase(text, p))
}
