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
export const LOGIN_TOKENS = ["current-password", "new-password", "username", "one-time-code", "webauthn"]
/** A code is a few characters; a box that takes more is a password the page calls a passcode. */
const MAX_CODE_LENGTH = 10
/** What type="password" alone gives a box's password score (clues.ts): more means its words say password too. */
const MASKED_BASELINE = 4
/** Words that make a form a gift card's, a coupon's or a balance check's, whatever its boxes look like. */
const DECOY_WORDS = ["gift card", "gift cards", "giftcard", "promo code", "promotion code", "coupon", "voucher", "discount code", "redeem", "check balance", "card balance"].map((p) => words(p).trim())

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
 * or PIN but that takes a password's length (or, with no maxlength, whose
 * words say password), after a box for who you are, in a cluster with no
 * password yet, is the password; and a login's one password with no box for who you are
 * takes the plain text box just before it as its username (a bank's
 * "Online ID").
 */
export function rationalize(fields: ScannedField[]) {
  for (const [i, f] of fields.entries()) {
    if (f.facts.type !== "password" || f.role !== "otp" || f.facts.autocomplete.includes("one-time-code")) continue
    // A masked code box beside a password is the second factor (a PIN or 2FA code), never another password.
    if (fields.some((g) => g.cluster === f.cluster && (g.role === "password" || g.role === "new-password"))) continue
    const long = f.facts.maxLength ? f.facts.maxLength > MAX_CODE_LENGTH : f.score.password > MASKED_BASELINE
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
 * Whether a cluster is a gift card's, coupon's or balance check's, by its
 * own words, with nothing in it asking for a password or saying (by
 * autocomplete) it's a sign-in. Its fields are no login's, and it's set
 * aside before the scan picks the login form, so one above a real sign-in
 * never hides it.
 */
export function decoyCluster(cluster: FormCluster, fields: ScannedField[], graph: FormGraph): boolean {
  if (!cluster.root) return false
  if (fields.some((f) => f.role === "password" || f.role === "new-password" || f.facts.autocomplete.some((t) => LOGIN_TOKENS.includes(t)))) return false
  const text = graph.context(cluster)
  return DECOY_WORDS.some((p) => hasPhrase(text, p))
}

/**
 * How many of a cluster's boxes no login role claims: a bank transfer's
 * payee and amount, a product registration's model and serial number. One
 * search box and one-digit code boxes don't count; page-wide controls (no
 * form or container around them) are no one form, so count none.
 */
export function unclaimedBoxes(cluster: FormCluster | undefined, fields: ScannedField[]): number {
  if (!cluster?.root) return 0
  const claimed = new Set<Element>(fields.filter((f) => f.role).map((f) => f.el))
  return cluster.controls.filter((el) => !claimed.has(el) && !(el instanceof HTMLInputElement && (el.maxLength === 1 || el.type === "search"))).length
}
