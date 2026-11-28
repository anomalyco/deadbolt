// Settling a login scan's roles within each cluster (graph.ts), once every
// field has its own score: what a field's neighbours in the same form say
// about it, and whether the form is a login at all. Each rule here reads
// the form's shape (which boxes it has, in what order) or the words of the
// form itself, never one site's markup.

import type { FieldRole } from "../messages"
import { FIELD_THRESHOLD, hasPhrase, namesRole, scoreFormText, words, type FieldFacts, type FormKind } from "./clues"
import type { FormCluster, FormGraph } from "./graph"
import { WEIGHTS, type Weights } from "./weights.gen"

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

// ---- Is the cluster a login at all? ------------------------------------------------
//
// A cluster the rules gave a login role is still judged as a whole: a
// sparse linear model (weights.gen.ts, fit by corpus/train-weights.ts on the
// frozen corpus's train split) adds up the weights of the value-free facts it
// shows, below, into the log-odds that it's a sign-in, sign-up, code or
// change-password form. Under the model's threshold it's set aside like a
// gift card form, if it also says what else it's for (saysOtherwise). The
// facts are the shape of the form, its own words and buttons, and the page's
// path; never a site's name or markup.

/** What the page around a cluster says, read once per scan (detect.ts). */
export interface PageFacts {
  /** Which kinds of page the path names: "login", "signup", "reset", "change-password", "settings". */
  paths: string[]
  /** Which form kinds the page's title names (scoreFormText). */
  title: FormKind[]
  /** How many clusters on the page ask for a code. */
  codeClusters: number
}

/** Wording a cluster can show that says what else it's for, each group one feature. */
const GROUPS: Array<[string, string[]]> = (
  [
    ["secret", ["secret", "secrets", "api key", "api keys", "token", "tokens", "webhook", "signing secret", "environment variable", "environment variables", "variable"]],
    ["settings", ["settings", "preferences", "save changes"]],
    ["booking", ["reservation", "booking", "booking reference", "confirmation code", "confirmation number", "itinerary", "tracking", "tracking number", "order number", "order id"]],
    ["identity-document", ["social security", "ssn", "tax", "ein", "passport", "national id", "driver s license"]],
    ["badge", ["badge", "employee", "door"]],
    ["wallet", ["recovery phrase", "seed phrase", "wallet", "mnemonic"]],
    ["network", ["wi fi", "wifi", "ssid", "router", "network name"]],
    ["share-link", ["share", "link settings", "protect this link", "link expires", "shared link"]],
    ["strength", ["strength", "how strong", "crack"]],
    ["delete", ["delete", "danger zone", "deactivate"]],
    ["contact", ["comment", "reply", "message", "support", "contact us", "feedback", "how can we help"]],
    ["invite", ["invite", "teammate", "teammates", "refer", "friend", "colleague"]],
    ["sent-code", ["we sent", "we texted", "sent a code", "resend", "resend code"]],
    ["offer", ["gift card", "promo code", "coupon", "voucher", "discount code", "redeem", "balance"]],
    ["file", ["encrypt", "pdf", "upload", "document", "file"]],
    ["payroll", ["direct deposit", "routing number", "payroll", "payee", "withholding"]],
  ] as Array<[string, string[]]>
).map(([name, list]) => [name, list.map((p) => words(p).trim())])

/** A button that moves a sign-in along without naming it: Continue, Next, Verify. */
const PROCEED = ["continue", "next", "verify", "submit", "confirm", "go", "weiter", "suivant", "continuer", "valider", "verifier", "confirmer", "continuar", "siguiente", "confirmar", "verificar", "bestatigen", "prufen", "avanti", "verder", "volgende", "次へ", "続行", "确认", "下一步"].map((p) => words(p).trim())
const KINDS: FormKind[] = ["login", "signup", "change-password", "reset", "mfa", "newsletter"]
const kindsOf = (text: string, min: number) => {
  const score = scoreFormText(text)
  return KINDS.filter((k) => score[k] >= min)
}
/** Kinds a form's words or button name that say it's part of signing in. */
const SIGN_IN_KINDS = new Set(["login", "signup", "change-password", "reset", "mfa"])
const bucket = (n: number, edges: number[]) => {
  const i = edges.findIndex((e) => n <= e)
  return i < 0 ? `${edges[edges.length - 1] + 1}+` : i === 0 || edges[i - 1] + 1 === edges[i] ? String(edges[i]) : `${edges[i - 1] + 1}-${edges[i]}`
}

/**
 * The cluster's features, as sorted ids: the roles the rules gave its fields
 * and their shape, its autocomplete tokens, how many boxes it has and how
 * many no role claims, the form kinds its words and buttons name, the
 * wording groups above, and the page's path and title.
 */
export function clusterFeatures(cluster: FormCluster, fields: ScannedField[], graph: FormGraph, page: PageFacts, buttons: string[]): string[] {
  const out = new Set<string>()
  const claimed = fields.filter((f) => f.role)
  const has = (...roles: FieldRole[]) => claimed.some((f) => roles.includes(f.role!))
  if (has("password")) out.add("role:password")
  if (has("new-password")) out.add("role:new-password")
  if (has("username", "email", "phone")) out.add("role:identifier")
  if (has("otp")) out.add("role:otp")
  if (has("username", "email", "phone") && has("password", "new-password")) out.add("shape:identifier+password")
  if (claimed.length === 1) out.add("shape:one-field")
  if (claimed.filter((f) => f.facts.type === "password").length >= 3) out.add("shape:masked-3+")
  // A masked box whose own words name a password, in any language clues.ts knows: not just a mask.
  const namedPassword = claimed.some((f) => f.facts.type === "password" && namesRole(f.facts, ["password", "new-password"]))
  if (namedPassword) out.add("role:named-password")
  if (claimed.some((f) => f.role === "otp" && f.facts.maxLength >= 4 && f.facts.maxLength <= 8)) out.add("shape:code-length")
  if (has("otp") && page.codeClusters >= 2) out.add("page:other-code-forms")
  const tokens = new Set(claimed.flatMap((f) => f.facts.autocomplete))
  if (LOGIN_TOKENS.some((t) => tokens.has(t))) out.add("autocomplete:login")
  if (tokens.has("off")) out.add("autocomplete:off")
  out.add(`controls:${bucket(cluster.controls.length, [1, 3, 7])}`)
  out.add(`unclaimed:${bucket(unclaimedBoxes(cluster, fields), [0, 1])}`)
  const text = graph.context(cluster)
  const kinds = kindsOf(text, 3)
  for (const k of kinds) out.add(`words:${k}`)
  if (kinds.some((k) => SIGN_IN_KINDS.has(k))) out.add("words:auth")
  // Each group is a feature, and any of them is one more, so a group too rare to weigh alone still counts.
  let elsewhere = false
  for (const [name, list] of GROUPS)
    if (list.some((p) => hasPhrase(text, p))) {
      out.add(`words:${name}`)
      elsewhere = true
    }
  if (elsewhere) out.add("words:non-login")
  let named = false
  for (const label of buttons) {
    const w = words(label)
    // A button is a word or two: "Entrar" counts though it scores under a form's threshold.
    const buttonKinds = kindsOf(w, 2).filter((k) => k === "login" || k === "signup")
    for (const k of buttonKinds) out.add(`button:${k}`)
    const proceed = PROCEED.some((p) => hasPhrase(w, p))
    if (proceed) out.add("button:proceed")
    named ||= buttonKinds.length > 0 || proceed
  }
  out.add(!buttons.length ? "button:none" : named ? "button:named" : "button:other")
  for (const p of page.paths) out.add(`path:${p}`)
  for (const k of page.title) out.add(`title:${k}`)
  // Nothing anywhere says sign-in: not its words, buttons, autocomplete, path or title, nor
  // a box named a password (unless the form's words say it's for something else).
  const said = [...out].some((f) => /^(button:(login|signup)|autocomplete:login)$/.test(f) || (/^(words|path|title):/.test(f) && SIGN_IN_KINDS.has(f.split(":")[1])))
  if (!said && !(namedPassword && !elsewhere)) out.add("signal:none")
  return [...out].sort()
}

/** Features that only ever say "a login": their weights are kept at zero or above. */
const SAYS_LOGIN = /^(words:(auth|login|signup|mfa|reset|change-password)|button:(login|signup)|path:(login|signup|reset|change-password)|title:(login|signup|mfa|reset|change-password)|autocomplete:login|role:named-password)$/
/**
 * Which way a feature may point, for the trainer (corpus/train-weights.ts):
 * 1 for sign-in wording, buttons, paths, titles, autocomplete and named
 * password boxes (kept >= 0, so two of them saying the same thing can't
 * flip one negative); -1 for wording that says the form is for something
 * else and for silence (kept <= 0); 0 for shape, which may go either way.
 */
export function featureSign(feature: string): 1 | -1 | 0 {
  if (SAYS_LOGIN.test(feature)) return 1
  if (ELSEWHERE.has(feature) || feature === "words:non-login" || feature === "signal:none" || feature === "path:settings") return -1
  return 0
}

let model: Weights = WEIGHTS

/** The log-odds that a cluster with these features is a login form. */
export function loginOdds(features: readonly string[], weights: Weights = model): number {
  let odds = weights.bias
  for (const f of features) odds += weights.features[f]?.[0] ?? 0
  return odds
}

/** Wording groups (GROUPS) as features, each a sign the form is for something else. */
const ELSEWHERE = new Set(GROUPS.map(([name]) => `words:${name}`))

/**
 * Whether the cluster says what else it's for: wording from GROUPS (a
 * secret, a booking, an identity number…), a settings path, a button that
 * names some other action ("Save", "Add endpoint") or none at all, or boxes
 * no login role claims. A form that says nothing of signing in may still be
 * a sign-in (an email box and Continue); only one that also says what else
 * it's for is set aside.
 */
export const saysOtherwise = (features: readonly string[]) =>
  features.some((f) => ELSEWHERE.has(f) || f === "path:settings" || f === "button:other" || f === "button:none" || f === "unclaimed:2+" || f === "controls:8+")

/**
 * Whether the cluster isn't a login, whatever its fields look like: its
 * log-odds fall under the model's threshold, and it says what else it's for.
 */
export const notLogin = (odds: number, features: readonly string[], weights: Weights = model) => odds < weights.threshold && saysOtherwise(features)

/** Runs `run` with other weights in place of weights.gen.ts: for the trainer, which scores candidates before writing one. */
export function withWeights<T>(weights: Weights, run: () => T): T {
  const before = model
  model = weights
  try {
    return run()
  } finally {
    model = before
  }
}
