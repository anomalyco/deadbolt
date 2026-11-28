// The messages between the extension and `deadbolt browser-host`, as
// specified in docs/autofill.md. Their types and constants are generated from
// crates/proto into ./gen/proto.ts (`bun run gen:proto`); this file adds the
// TypeScript-only helpers and checks what the host sends.

import type { Account, Body, CardField, Change, CheckStatus, ErrorCode, FormCard, FormField, FormIdentity, HostStatus, IdentityField, Passkey, SignIn } from "./gen/proto"
import { CARD_FIELDS, IDENTITY_FIELDS } from "./gen/proto"

export * from "./gen/proto"

/** A submitted password: as typed, or the one `generate` made, by its id (the daemon holds it). */
export type PasswordValue = { password: string; generated?: never } | { generated: string; password?: never }

/** What the host answers a request with: everything it sends but a pushed `changed`. */
export type Reply = Exclude<Body, { type: "changed" }>
/** The reply of one type. */
export type ReplyOf<T extends Reply["type"]> = Extract<Reply, { type: T }>
export type HelloReply = ReplyOf<"hello">
export type ListReply = ReplyOf<"list">
export type FillReply = ReplyOf<"fill">
export type GenerateReply = ReplyOf<"generate">
export type CheckReply = ReplyOf<"check">
export type SaveReply = ReplyOf<"save">
export type FormsReply = ReplyOf<"forms">
export type FillFormReply = ReplyOf<"fill-form">
export type SaveFormReply = ReplyOf<"save-form">
export type PasskeysReply = ReplyOf<"passkeys">
export type PasskeyCreatedReply = ReplyOf<"passkey-created">
export type PasskeyAssertionReply = ReplyOf<"passkey-assertion">
export type PasskeyCancelledReply = ReplyOf<"passkey-cancelled">
export type LearnedReply = ReplyOf<"learned">
export type LearnTextReply = ReplyOf<"learn-text">
export type LearnDeletedReply = ReplyOf<"learn-deleted">
export type UnlockPromptReply = ReplyOf<"unlock-prompt">
export type ErrorReply = ReplyOf<"error">

/** What a request of each type is answered with, besides an error. */
export interface ReplyFor {
  hello: HelloReply
  list: ListReply
  fill: FillReply
  generate: GenerateReply
  "generate-check": ReplyOf<"generate-check">
  "generate-keep": ReplyOf<"generate-keep">
  "generate-drop": ReplyOf<"generate-drop">
  check: CheckReply
  save: SaveReply
  forms: FormsReply
  "fill-form": FillFormReply
  "save-form": SaveFormReply
  "passkey-list": PasskeysReply
  "passkey-create": PasskeyCreatedReply
  "passkey-get": PasskeyAssertionReply
  "passkey-cancel": PasskeyCancelledReply
  learn: LearnedReply
  "learn-read": LearnTextReply
  "learn-delete": LearnDeletedReply
  "unlock-prompt": UnlockPromptReply
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
  "save-form": "save-form",
  "passkey-list": "passkeys",
  "passkey-create": "passkey-created",
  "passkey-get": "passkey-assertion",
  "passkey-cancel": "passkey-cancelled",
  learn: "learned",
  "learn-read": "learn-text",
  "learn-delete": "learn-deleted",
  "unlock-prompt": "unlock-prompt",
}

export type HostMessage =
  | { kind: "reply"; id: number | string | null; reply: Reply }
  /** `touchIdReady`: on `locked`, Touch ID can unlock it now. */
  | { kind: "changed"; change: Change; touchIdReady?: true }

/** A check for a member of a generated union. Each set must name every member, so a new one in crates/proto fails the typecheck until it's listed here. */
const memberOf =
  <T extends string>(set: Record<T, true>) =>
  (v: unknown): v is T =>
    typeof v === "string" && Object.hasOwn(set, v)
const isStatus = memberOf<HostStatus>({ ready: true, locked: true, "not-set-up": true, unavailable: true })
const isCheck = memberOf<CheckStatus>({ new: true, update: true, same: true })
const isChange = memberOf<Change>({ locked: true, unlocked: true, items: true, stopped: true, started: true })
const isCode = memberOf<ErrorCode>({
  forbidden: true,
  locked: true,
  not_found: true,
  domain_mismatch: true,
  bad_request: true,
  rate_limited: true,
  exists: true,
  cancelled: true,
  weak: true,
  failed: true,
})
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
    return isChange(raw.change) ? { kind: "changed", change: raw.change, ...(raw.touchIdReady === true ? { touchIdReady: true as const } : {}) } : null
  }
  const id = typeof raw.id === "number" || typeof raw.id === "string" ? raw.id : raw.id === null ? null : undefined
  if (id === undefined) return null
  const reply = parseReply(raw)
  return reply ? { kind: "reply", id, reply } : null
}

export function parseReply(raw: Record<string, unknown>): Reply | null {
  switch (raw.type) {
    case "hello": {
      if (!isStatus(raw.status) || typeof raw.protocol !== "number") return null
      return {
        type: "hello",
        protocol: raw.protocol,
        version: str(raw.version, 200) ?? "",
        status: raw.status,
        detail: str(raw.detail, 1000),
        capabilities: strings(raw.capabilities),
        ...(raw.touchIdReady === true ? { touchIdReady: true } : {}),
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
      if (!isCheck(raw.status)) return null
      return { type: "check", status: raw.status, matches: strings(raw.matches).filter(isRef) }
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
    case "save-form":
      return isRef(raw.ref) ? { type: "save-form", ref: raw.ref, created: raw.created === true } : null
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
    case "learn-text":
      return typeof raw.text === "string" ? { type: "learn-text", text: raw.text, next: typeof raw.next === "number" && raw.next > 0 ? raw.next : null } : null
    case "learn-deleted":
      return { type: "learn-deleted", found: raw.found === true }
    case "unlock-prompt":
      return { type: "unlock-prompt", app: raw.app === true }
    case "error": {
      return { type: "error", code: isCode(raw.code) ? raw.code : "failed", message: str(raw.message, 1000) ?? "" }
    }
    default:
      return null
  }
}
