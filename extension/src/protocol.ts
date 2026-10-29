// The messages between the extension and `deadbolt browser-host`, as
// specified in docs/autofill.md. The browser does the framing (a native-endian
// u32 length, then UTF-8 JSON); this file is the JSON.

export const NATIVE_HOST = "pw.deadbolt.browser"
export const PROTOCOL = 3

export type Want = "username" | "password" | "totp"
export type HostStatus = "ready" | "locked" | "not-set-up" | "unavailable"
export type CheckStatus = "new" | "update" | "same"
export type Change = "locked" | "unlocked" | "items" | "stopped" | "started"
/** `passphrase_needed` and `wrong_passphrase` come only from the browser-only vault (bg/standalone.ts), never the native host. */
export type ErrorCode = "locked" | "not_found" | "domain_mismatch" | "bad_request" | "rate_limited" | "weak" | "exists" | "cancelled" | "failed" | "passphrase_needed" | "wrong_passphrase"
export type UserVerification = "required" | "preferred" | "discouraged"
export type FormKind = "identity" | "card"

/** An identity's fields a form may ask for, named after the HTML autocomplete tokens (`city` is `address-level2`, `region` `address-level1`). */
export const IDENTITY_FIELDS = [
  "honorific", "given-name", "additional-name", "family-name", "nickname", "organization", "job-title", "email", "phone",
  "address-line1", "address-line2", "address-line3", "city", "region", "postal-code", "country", "birthday",
] as const
/** A card's fields a form may ask for. `number` and `cvv` raise Touch ID in the agent when it's on; `expiry` is `YYYY-MM`. */
export const CARD_FIELDS = ["cardholder", "number", "expiry", "cvv", "brand"] as const
export type IdentityField = (typeof IDENTITY_FIELDS)[number]
export type CardField = (typeof CARD_FIELDS)[number]
export type FormField = IdentityField | CardField

/** A submitted password: as typed, or the one `generate` made, by its id (the agent holds it). */
export type PasswordValue = { password: string; generated?: never } | { generated: string; password?: never }

/** What a page says about a new-password field: its `passwordrules`, length limits and the characters its `pattern` takes. */
export interface FieldRules {
  rules?: string
  minLength?: number
  maxLength?: number
  allowed?: string
}

export type Request =
  | { id: number; type: "hello" }
  | { id: number; type: "list"; origin: string }
  | { id: number; type: "fill"; origin: string; ref: string; want: Want[] }
  | ({ id: number; type: "generate"; origin: string } & FieldRules)
  | ({ id: number; type: "generate-check"; origin: string } & FieldRules)
  | { id: number; type: "generate-keep"; origin: string; generated: string }
  | { id: number; type: "generate-drop"; origin: string; generated: string }
  | ({ id: number; type: "check"; origin: string; username?: string } & PasswordValue)
  | {
      id: number
      type: "save"
      origin: string
      ref?: string
      entry: { title: string; url: string; username: string } & PasswordValue
    }
  | { id: number; type: "forms"; origin: string; kinds: FormKind[] }
  | { id: number; type: "fill-form"; origin: string; ref: string; fields: FormField[] }
  | { id: number; type: "passkey-list"; origin: string; rpId?: string }
  | {
      id: number
      type: "passkey-create"
      origin: string
      rpId?: string
      challenge: string
      user: { id: string; name: string; displayName?: string }
      exclude: string[]
      userVerification: UserVerification
    }
  | { id: number; type: "passkey-get"; origin: string; rpId?: string; ref: string; challenge: string; userVerification: UserVerification }
  | { id: number; type: "passkey-cancel"; request: number }
  /** Appends one line to the learning log of `session` (see src/learn.ts). No values, ever. */
  | { id: number; type: "learn"; session: string; line: Record<string, unknown> }

export type RequestBody = Request extends infer R ? (R extends { id: number } ? Omit<R, "id"> : never) : never

export interface Account {
  ref: string
  vault: string
  title: string
  username?: string
  hasPassword: boolean
  hasTotp: boolean
  urls: string[]
  /** A "Sign in with Google" login: the provider (a known id such as `google`, or a name), and the linked account's username or title. */
  signIn?: SignIn
}

export interface SignIn {
  provider: string
  account?: string
}

export interface HelloReply {
  type: "hello"
  protocol: number
  version: string
  status: HostStatus
  detail?: string
  capabilities: string[]
}
export interface ListReply {
  type: "list"
  site: string
  accounts: Account[]
}
export interface FillReply {
  type: "fill"
  username?: string
  password?: string
  totp?: string
}
export interface GenerateReply {
  type: "generate"
  password: string
  /** Names it in check and save. */
  generated: string
}
/** `generate-check`, `generate-keep` and `generate-drop` say only that they went through. */
export interface DoneReply<T extends "generate-check" | "generate-keep" | "generate-drop"> {
  type: T
}
export interface CheckReply {
  type: "check"
  status: CheckStatus
  matches: string[]
}
export interface SaveReply {
  type: "save"
  ref: string
  created: boolean
}
/** A passkey saved for the relying party; never its private key. */
export interface Passkey {
  ref: string
  vault: string
  credentialId: string
  username?: string
  created?: string
}
export interface PasskeysReply {
  type: "passkeys"
  rpId: string
  canVerify: boolean
  passkeys: Passkey[]
}
/** Binary fields are base64url, as the page gets them. */
export interface PasskeyCreatedReply {
  type: "passkey-created"
  ref: string
  credentialId: string
  clientDataJSON: string
  attestationObject: string
  authenticatorData: string
  publicKey: string
  verified: boolean
}
export interface PasskeyAssertionReply {
  type: "passkey-assertion"
  credentialId: string
  clientDataJSON: string
  authenticatorData: string
  signature: string
  userHandle: string
  verified: boolean
}
export interface PasskeyCancelledReply {
  type: "passkey-cancelled"
  found: boolean
}
export interface LearnedReply {
  type: "learned"
}
/** An identity a form can be filled from: no values, only which fields it has. */
export interface FormIdentity {
  ref: string
  vault: string
  title: string
  /** "Kit Langton · 123 Main St, Brooklyn"; may be empty. */
  summary: string
  fields: IdentityField[]
}
/** A card a form can be filled from: never its number or code. */
export interface FormCard {
  ref: string
  vault: string
  title: string
  brand?: string
  last4: string
  /** `YYYY-MM`. */
  expiry?: string
  cardholder?: string
  /** The identity whose address is its billing address. */
  billing?: string
  fields: CardField[]
}
export interface FormsReply {
  type: "forms"
  identities: FormIdentity[]
  cards: FormCard[]
  /** Whether filling a card's number or code now raises Touch ID. */
  canVerify: boolean
}
export interface FillFormReply {
  type: "fill-form"
  /** Only the fields asked for that the item has. */
  values: Partial<Record<FormField, string>>
  /** Whether Touch ID verified the user for this fill. */
  verified: boolean
}
export interface ErrorReply {
  type: "error"
  code: ErrorCode
  message: string
}

export type Reply =
  | HelloReply
  | ListReply
  | FillReply
  | GenerateReply
  | DoneReply<"generate-check" | "generate-keep" | "generate-drop">
  | CheckReply
  | SaveReply
  | FormsReply
  | FillFormReply
  | PasskeysReply
  | PasskeyCreatedReply
  | PasskeyAssertionReply
  | PasskeyCancelledReply
  | LearnedReply
  | ErrorReply

/** What a request of each type is answered with, besides an error. */
export interface ReplyFor {
  hello: HelloReply
  list: ListReply
  fill: FillReply
  generate: GenerateReply
  "generate-check": DoneReply<"generate-check">
  "generate-keep": DoneReply<"generate-keep">
  "generate-drop": DoneReply<"generate-drop">
  check: CheckReply
  save: SaveReply
  forms: FormsReply
  "fill-form": FillFormReply
  "passkey-list": PasskeysReply
  "passkey-create": PasskeyCreatedReply
  "passkey-get": PasskeyAssertionReply
  "passkey-cancel": PasskeyCancelledReply
  learn: LearnedReply
}

/** The reply type each request expects. */
export const REPLY_TYPE: { [K in keyof ReplyFor]: ReplyFor[K]["type"] } = {
  hello: "hello",
  list: "list",
  fill: "fill",
  generate: "generate",
  "generate-check": "generate-check",
  "generate-keep": "generate-keep",
  "generate-drop": "generate-drop",
  check: "check",
  save: "save",
  forms: "forms",
  "fill-form": "fill-form",
  "passkey-list": "passkeys",
  "passkey-create": "passkey-created",
  "passkey-get": "passkey-assertion",
  "passkey-cancel": "passkey-cancelled",
  learn: "learned",
}

export type HostMessage =
  | { kind: "reply"; id: number | string | null; reply: Reply }
  | { kind: "changed"; change: Change }

const STATUSES: HostStatus[] = ["ready", "locked", "not-set-up", "unavailable"]
const CHECKS: CheckStatus[] = ["new", "update", "same"]
const CHANGES: Change[] = ["locked", "unlocked", "items", "stopped", "started"]
const CODES: ErrorCode[] = ["locked", "not_found", "domain_mismatch", "bad_request", "rate_limited", "weak", "exists", "cancelled", "failed", "passphrase_needed", "wrong_passphrase"]
const REF = /^[0-9a-f]{64}:[0-9a-f]{32}$/
const B64URL = /^[A-Za-z0-9_-]*$/

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v)
const str = (v: unknown, max = 4096): string | undefined => (typeof v === "string" && v.length <= max ? v : undefined)
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((s): s is string => typeof s === "string") : [])

export const isRef = (v: unknown): v is string => typeof v === "string" && REF.test(v)
/** Base64url without padding, non-empty. */
export const isB64url = (v: unknown, max = 1 << 16): v is string => typeof v === "string" && v.length > 0 && v.length <= max && B64URL.test(v)

function passkey(v: unknown): Passkey | null {
  if (!isObject(v) || !isRef(v.ref) || !isB64url(v.credentialId, 1364)) return null
  return { ref: v.ref, vault: str(v.vault, 500) ?? "", credentialId: v.credentialId, username: str(v.username, 1024), created: str(v.created, 64) }
}

/** The named fields, if every one is base64url. */
function b64Fields<K extends string>(raw: Record<string, unknown>, keys: readonly K[]): Record<K, string> | null {
  const out = {} as Record<K, string>
  for (const k of keys) {
    const v = raw[k]
    if (!isB64url(v)) return null
    out[k] = v
  }
  return out
}

/** A login as the vault describes it, checked; null if it isn't one. */
export function account(v: unknown): Account | null {
  if (!isObject(v) || !isRef(v.ref)) return null
  const title = str(v.title, 500)
  if (title === undefined) return null
  return {
    ref: v.ref,
    vault: str(v.vault, 500) ?? "",
    title,
    username: str(v.username, 500),
    hasPassword: v.hasPassword === true,
    hasTotp: v.hasTotp === true,
    urls: strings(v.urls),
    ...signInOf(v.signIn),
  }
}

const isIdentityField = (v: unknown): v is IdentityField => (IDENTITY_FIELDS as readonly unknown[]).includes(v)
const isCardField = (v: unknown): v is CardField => (CARD_FIELDS as readonly unknown[]).includes(v)

function formIdentity(v: unknown): FormIdentity | null {
  if (!isObject(v) || !isRef(v.ref)) return null
  const title = str(v.title, 500)
  if (title === undefined) return null
  return { ref: v.ref, vault: str(v.vault, 500) ?? "", title, summary: str(v.summary, 1000) ?? "", fields: strings(v.fields).filter(isIdentityField) }
}

function formCard(v: unknown): FormCard | null {
  if (!isObject(v) || !isRef(v.ref)) return null
  const title = str(v.title, 500)
  const last4 = str(v.last4, 4)
  if (title === undefined || last4 === undefined || !/^[0-9]*$/.test(last4)) return null
  const expiry = str(v.expiry, 7)
  return {
    ref: v.ref,
    vault: str(v.vault, 500) ?? "",
    title,
    brand: str(v.brand, 100),
    last4,
    expiry: expiry && /^[0-9]{4}-(0[1-9]|1[0-2])$/.test(expiry) ? expiry : undefined,
    cardholder: str(v.cardholder, 500),
    billing: isRef(v.billing) ? v.billing : undefined,
    fields: strings(v.fields).filter(isCardField),
  }
}

/** One line: no line breaks or other control characters. */
const line = (v: unknown, max: number): string | undefined => {
  const s = str(v, max)
  return s && s.trim() && !/[\u0000-\u001f\u007f]/.test(s) ? s.trim() : undefined
}

/**
 * `signIn`, if it's well formed: a provider of at most 64 characters on one
 * line, and maybe an account of at most 500. Anything else leaves it out
 * (the login still lists, as one without it).
 */
function signInOf(v: unknown): { signIn?: SignIn } {
  if (!isObject(v)) return {}
  const provider = line(v.provider, 64)
  if (!provider) return {}
  const account = v.account === undefined ? undefined : line(v.account, 500)
  if (v.account !== undefined && !account) return {}
  return { signIn: { provider, ...(account ? { account } : {}) } }
}

/**
 * Checks a message from the host and keeps only the documented fields. The
 * host is trusted, but a malformed message should fail here, not deep in the
 * UI.
 */
export function parseHostMessage(raw: unknown): HostMessage | null {
  if (!isObject(raw) || typeof raw.type !== "string") return null
  if (raw.type === "changed") {
    const change = raw.change as Change
    return CHANGES.includes(change) ? { kind: "changed", change } : null
  }
  const id = typeof raw.id === "number" || typeof raw.id === "string" ? raw.id : raw.id === null ? null : undefined
  if (id === undefined) return null
  const reply = parseReply(raw)
  return reply ? { kind: "reply", id, reply } : null
}

export function parseReply(raw: Record<string, unknown>): Reply | null {
  switch (raw.type) {
    case "hello": {
      const status = raw.status as HostStatus
      if (!STATUSES.includes(status) || typeof raw.protocol !== "number") return null
      return {
        type: "hello",
        protocol: raw.protocol,
        version: str(raw.version, 200) ?? "",
        status,
        detail: str(raw.detail, 1000),
        capabilities: strings(raw.capabilities),
      }
    }
    case "list": {
      if (!Array.isArray(raw.accounts)) return null
      const accounts = raw.accounts.map(account).filter((a): a is Account => a !== null)
      return { type: "list", site: str(raw.site, 300) ?? "", accounts }
    }
    case "fill":
      return { type: "fill", username: str(raw.username), password: str(raw.password), totp: str(raw.totp, 16) }
    case "generate": {
      const password = str(raw.password)
      const generated = str(raw.generated, 64)
      return password && generated ? { type: "generate", password, generated } : null
    }
    case "generate-check":
    case "generate-keep":
    case "generate-drop":
      return { type: raw.type }
    case "check": {
      const status = raw.status as CheckStatus
      if (!CHECKS.includes(status)) return null
      return { type: "check", status, matches: strings(raw.matches).filter(isRef) }
    }
    case "save":
      return isRef(raw.ref) ? { type: "save", ref: raw.ref, created: raw.created === true } : null
    case "forms": {
      if (!Array.isArray(raw.identities) || !Array.isArray(raw.cards)) return null
      return {
        type: "forms",
        identities: raw.identities.map(formIdentity).filter((i): i is FormIdentity => i !== null),
        cards: raw.cards.map(formCard).filter((c): c is FormCard => c !== null),
        canVerify: raw.canVerify === true,
      }
    }
    case "fill-form": {
      if (!isObject(raw.values)) return null
      const values: Partial<Record<FormField, string>> = {}
      for (const [k, v] of Object.entries(raw.values)) {
        const s = str(v, 1000)
        if ((isIdentityField(k) || isCardField(k)) && s !== undefined) values[k] = s
      }
      return { type: "fill-form", values, verified: raw.verified === true }
    }
    case "passkeys": {
      if (!Array.isArray(raw.passkeys) || typeof raw.rpId !== "string") return null
      const passkeys = raw.passkeys.map(passkey).filter((p): p is Passkey => p !== null)
      return { type: "passkeys", rpId: raw.rpId, canVerify: raw.canVerify === true, passkeys }
    }
    case "passkey-created": {
      const f = b64Fields(raw, ["credentialId", "clientDataJSON", "attestationObject", "authenticatorData", "publicKey"] as const)
      return f && isRef(raw.ref) ? { type: "passkey-created", ref: raw.ref, ...f, verified: raw.verified === true } : null
    }
    case "passkey-assertion": {
      const f = b64Fields(raw, ["credentialId", "clientDataJSON", "authenticatorData", "signature", "userHandle"] as const)
      return f ? { type: "passkey-assertion", ...f, verified: raw.verified === true } : null
    }
    case "passkey-cancelled":
      return { type: "passkey-cancelled", found: raw.found === true }
    case "learned":
      return { type: "learned" }
    case "error": {
      const code = CODES.includes(raw.code as ErrorCode) ? (raw.code as ErrorCode) : "failed"
      return { type: "error", code, message: str(raw.message, 1000) ?? "" }
    }
    default:
      return null
  }
}
