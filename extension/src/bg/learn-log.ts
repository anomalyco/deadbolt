// The browser-only Deadbolt's learning logs ("Learn this site", src/learn.ts):
// what the native host writes to ~/.local/state/deadbolt/learn/<session>.jsonl,
// kept in this extension's IndexedDB instead, with the host's limits (a log is
// at most 4 MiB, the newest 50 are kept, none past 30 days). Lines carry no
// values (bg/learn.ts drops them before a line is written), so the logs are
// kept outside the vault and work while it's locked, as the host's do. The
// vault's Settings download them for `bun corpus/learned.ts --file`, or delete
// them.

const DB = "deadbolt-learn"
const STORE = "logs"
export const MAX_LEARN_LOG = 4 * 1024 * 1024
export const MAX_LEARN_LOGS = 50
export const LEARN_LOG_AGE_MS = 30 * 24 * 60 * 60 * 1000

/** One session's log: its lines as written, and when it last changed. */
export interface LearnLog {
  session: string
  updated: number
  bytes: number
  lines: string[]
}

/** A session id is a lowercase UUID, as `crypto.randomUUID()` makes it (the host's rule). */
export const learnSession = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v)

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: "session" })
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function done<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function withStore<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => Promise<T>): Promise<T> {
  const db = await open()
  try {
    const tx = db.transaction(STORE, mode)
    const result = await fn(tx.objectStore(STORE))
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error)
      tx.onabort = () => reject(tx.error)
    })
    return result
  } finally {
    db.close()
  }
}

/** Every log, oldest first. */
export function learnLogs(): Promise<LearnLog[]> {
  return withStore("readonly", async (store) => ((await done(store.getAll())) as LearnLog[]).sort((a, b) => a.updated - b.updated))
}

/** Deletes every log. */
export function clearLearnLogs(): Promise<void> {
  return withStore("readwrite", async (store) => void (await done(store.clear())))
}

/**
 * Appends `line` to `session`'s log, as the host's `learn` does: a new
 * session's log first drops the logs older than 30 days, then the oldest
 * until it makes 50; a log never grows past 4 MiB. Answers why it didn't,
 * or null.
 */
export async function appendLearnLine(session: string, line: Record<string, unknown>, now = Date.now()): Promise<string | null> {
  if (!learnSession(session)) return "session is a lowercase UUID"
  const text = JSON.stringify(line)
  return withStore("readwrite", async (store) => {
    const log = (await done(store.get(session))) as LearnLog | undefined
    if (!log) {
      const all = ((await done(store.getAll())) as LearnLog[]).sort((a, b) => a.updated - b.updated)
      const excess = all.length + 1 - MAX_LEARN_LOGS
      for (const [i, old] of all.entries()) if (i < excess || now - old.updated > LEARN_LOG_AGE_MS) store.delete(old.session)
    }
    const bytes = (log?.bytes ?? 0) + new TextEncoder().encode(text).length + 1
    if (bytes > MAX_LEARN_LOG) return `a learning log is at most ${MAX_LEARN_LOG} bytes`
    store.put({ session, updated: now, bytes, lines: [...(log?.lines ?? []), text] } satisfies LearnLog)
    return null
  })
}

/** Every log as one JSONL file: each line as the host writes it, with its session. */
export function learnExport(logs: LearnLog[]): string {
  return logs.flatMap((log) => log.lines.map((line) => JSON.stringify({ session: log.session, ...(JSON.parse(line) as Record<string, unknown>) }))).join("\n") + (logs.length ? "\n" : "")
}
