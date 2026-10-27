// The messages between the extension and `deadbolt browser-host`, as
// specified in docs/autofill.md. The browser does the framing (a native-endian
// u32 length, then UTF-8 JSON); this file is the JSON.

export const NATIVE_HOST = "pw.deadbolt.browser"
export const PROTOCOL = 1

export type Want = "username" | "password" | "totp"
export type HostStatus = "ready" | "locked" | "not-set-up" | "unavailable"
export type CheckStatus = "new" | "update" | "same"
export type Change = "locked" | "unlocked" | "items" | "stopped" | "started"
export type ErrorCode = "locked" | "not_found" | "domain_mismatch" | "bad_request" | "rate_limited" | "failed"

export type Request =
  | { id: number; type: "hello" }
  | { id: number; type: "list"; origin: string }
  | { id: number; type: "fill"; origin: string; ref: string; want: Want[] }
  | { id: number; type: "check"; origin: string; username: string; password: string }
  | {
      id: number
      type: "save"
      origin: string
      ref?: string
      entry: { title: string; url: string; username: string; password: string }
    }

export type RequestBody = Request extends infer R ? (R extends { id: number } ? Omit<R, "id"> : never) : never

export interface Account {
  ref: string
  vault: string
  title: string
  username?: string
  hasPassword: boolean
  hasTotp: boolean
  urls: string[]
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
export interface ErrorReply {
  type: "error"
  code: ErrorCode
  message: string
}

export type Reply = HelloReply | ListReply | FillReply | CheckReply | SaveReply | ErrorReply

/** What a request of each type is answered with, besides an error. */
export interface ReplyFor {
  hello: HelloReply
  list: ListReply
  fill: FillReply
  check: CheckReply
  save: SaveReply
}

export type HostMessage =
  | { kind: "reply"; id: number | string | null; reply: Reply }
  | { kind: "changed"; change: Change }

const STATUSES: HostStatus[] = ["ready", "locked", "not-set-up", "unavailable"]
const CHECKS: CheckStatus[] = ["new", "update", "same"]
const CHANGES: Change[] = ["locked", "unlocked", "items", "stopped", "started"]
const CODES: ErrorCode[] = ["locked", "not_found", "domain_mismatch", "bad_request", "rate_limited", "failed"]
const REF = /^[0-9a-f]{64}:[0-9a-f]{32}$/

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v)
const str = (v: unknown, max = 4096): string | undefined => (typeof v === "string" && v.length <= max ? v : undefined)
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((s): s is string => typeof s === "string") : [])

export const isRef = (v: unknown): v is string => typeof v === "string" && REF.test(v)

function account(v: unknown): Account | null {
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
  }
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

function parseReply(raw: Record<string, unknown>): Reply | null {
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
    case "check": {
      const status = raw.status as CheckStatus
      if (!CHECKS.includes(status)) return null
      return { type: "check", status, matches: strings(raw.matches).filter(isRef) }
    }
    case "save":
      return isRef(raw.ref) ? { type: "save", ref: raw.ref, created: raw.created === true } : null
    case "error": {
      const code = CODES.includes(raw.code as ErrorCode) ? (raw.code as ErrorCode) : "failed"
      return { type: "error", code, message: str(raw.message, 1000) ?? "" }
    }
    default:
      return null
  }
}
