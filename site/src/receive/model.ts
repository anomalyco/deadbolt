// What the WebAssembly receiver (crates/send-web) resolves to, and how the page reads it.

export interface Entry {
  kind: "entry"
  name: string
  data: Uint8Array
  mime: string | null | undefined
  sensitive: boolean
}

export interface Group {
  kind: "group"
  name: string | null | undefined
  entries: Node[]
}

export type Node = Entry | Group

export interface Bundle {
  title: string | null | undefined
  note: string | null | undefined
  entries: Node[]
}

export interface Failure {
  kind: string
  message: string
}

export type Step = "connecting" | "proving" | "downloading" | "decrypting"

const decoder = new TextDecoder("utf-8", { fatal: true })

/** The entry as text, if it is text: a text/* type (or none) and valid UTF-8. */
export function text(entry: Entry): string | undefined {
  if (entry.mime && !entry.mime.startsWith("text/")) return undefined
  try {
    return decoder.decode(entry.data)
  } catch {
    return undefined
  }
}

/** A value rather than a file: short text without a file name's extension. */
export function isValue(entry: Entry): boolean {
  const value = text(entry)
  return value !== undefined && value.length <= 4096 && !/\.[A-Za-z0-9]{1,8}$/.test(entry.name)
}

export function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

/** NAME=value lines when every entry is a short single-line value with a usable name. */
export function dotenv(entries: Node[]): string | undefined {
  if (entries.length === 0) return undefined
  const lines: string[] = []
  for (const node of entries) {
    if (node.kind !== "entry" || !isValue(node)) return undefined
    const value = text(node)
    if (value === undefined || /[\r\n]/.test(value)) return undefined
    const name = node.name.trim().replace(/[^A-Za-z0-9_]+/g, "_").replace(/^_+|_+$/g, "").toUpperCase()
    if (!/^[A-Z_][A-Z0-9_]*$/.test(name)) return undefined
    lines.push(`${name}=${quote(value)}`)
  }
  return lines.join("\n") + "\n"
}

function quote(value: string): string {
  if (/^[A-Za-z0-9_./:@+-]*$/.test(value)) return value
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\$/g, "\\$")}"`
}

export function count(entries: Node[]): number {
  return entries.reduce((n, node) => n + (node.kind === "entry" ? 1 : count(node.entries)), 0)
}

export const messages: Record<string, { title: string; body: string; retry?: boolean }> = {
  "invalid-link": { title: "This link is incomplete", body: "Part of it may have been cut off. Ask the sender for the link again." },
  offline: {
    title: "Can't reach the sender",
    body: "Their computer may be asleep or offline, or Deadbolt stopped running there (shares end when it stops). Ask them to keep it running, then try again. The link hasn't been used.",
    retry: true,
  },
  expired: { title: "This link has expired", body: "Ask the sender to send it again." },
  used: { title: "This link was already opened", body: "Each link opens a set number of times. If you didn't open it, tell the sender: someone else may have." },
  revoked: { title: "The sender cancelled this link", body: "Ask them to send it again if you still need it." },
  unknown: { title: "The sender doesn't recognize this link", body: "It may have ended a while ago. Ask them to send it again." },
  corrupt: { title: "This couldn't be decrypted", body: "The link may be damaged. Ask the sender for it again." },
}
