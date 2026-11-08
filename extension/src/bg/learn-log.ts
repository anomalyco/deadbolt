// The browser-only Deadbolt's recordings (Record, src/learn.ts):
// what the native host writes to ~/.local/state/deadbolt/learn/<session>.jsonl,
// kept in this extension's IndexedDB instead, with the host's limits (a log is
// at most 4 MiB, the newest 10 are kept, none past 7 days). Lines carry no
// values (bg/learn.ts drops them before a line is written), so the logs are
// kept outside the vault and work while it's locked, as the host's do. A log
// is its record (when it last changed, its size) in `logs` and its lines in
// `lines`, each line added on its own, never the log rewritten. The vault's
// Settings download them for `bun corpus/learned.ts --file`, or delete them;
// the popup downloads or deletes the one it just recorded.

const DB = "deadbolt-learn"
const LOGS = "logs"
const LINES = "lines"
export const MAX_LEARN_LOG = 4 * 1024 * 1024
export const MAX_LEARN_LOGS = 10
export const LEARN_LOG_AGE_MS = 7 * 24 * 60 * 60 * 1000

/** One session's log: its lines as written, and when it last changed. */
export interface LearnLog {
  session: string
  updated: number
  bytes: number
  lines: string[]
}

type LogRecord = Omit<LearnLog, "lines"> & { lines?: string[] }

/** A session id is a lowercase UUID, as `crypto.randomUUID()` makes it (the host's rule). */
export const learnSession = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v)

/** Version 2 keeps lines in their own store; version 1's logs, each with its lines in it, move over. */
function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 2)
    req.onupgradeneeded = (event) => {
      const db = req.result
      const logs = event.oldVersion < 1 ? db.createObjectStore(LOGS, { keyPath: "session" }) : req.transaction!.objectStore(LOGS)
      const lines = db.createObjectStore(LINES, { autoIncrement: true })
      lines.createIndex("session", "session")
      if (event.oldVersion < 1) return
      logs.openCursor().onsuccess = (e) => {
        const cursor = (e.target as IDBRequest<IDBCursorWithValue | null>).result
        if (!cursor) return
        const { lines: old = [], ...log } = cursor.value as LogRecord
        for (const text of old) lines.add({ session: log.session, text })
        cursor.update(log)
        cursor.continue()
      }
    }
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

async function withStores<T>(mode: IDBTransactionMode, fn: (logs: IDBObjectStore, lines: IDBObjectStore) => Promise<T>): Promise<T> {
  const db = await open()
  try {
    const tx = db.transaction([LOGS, LINES], mode)
    const complete = new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error)
      tx.onabort = () => reject(tx.error)
    })
    const result = await fn(tx.objectStore(LOGS), tx.objectStore(LINES))
    await complete
    return result
  } finally {
    db.close()
  }
}

const linesOf = async (lines: IDBObjectStore, session: string) => ((await done(lines.index("session").getAll(IDBKeyRange.only(session)))) as Array<{ text: string }>).map((l) => l.text)

async function drop(logs: IDBObjectStore, lines: IDBObjectStore, session: string) {
  for (const key of await done(lines.index("session").getAllKeys(IDBKeyRange.only(session)))) lines.delete(key)
  logs.delete(session)
}

/** Every log, oldest first. */
export function learnLogs(): Promise<LearnLog[]> {
  return withStores("readonly", async (logs, lines) => {
    const all = ((await done(logs.getAll())) as LogRecord[]).sort((a, b) => a.updated - b.updated)
    return Promise.all(all.map(async ({ session, updated, bytes }) => ({ session, updated, bytes, lines: await linesOf(lines, session) })))
  })
}

/** One session's log, if it's kept. */
export function learnLog(session: string): Promise<LearnLog | undefined> {
  return withStores("readonly", async (logs, lines) => {
    const log = (await done(logs.get(session))) as LogRecord | undefined
    return log && { session, updated: log.updated, bytes: log.bytes, lines: await linesOf(lines, session) }
  })
}

/** Deletes one session's log: whether it was there. */
export function deleteLearnLog(session: string): Promise<boolean> {
  return withStores("readwrite", async (logs, lines) => {
    const found = (await done(logs.count(session))) > 0
    await drop(logs, lines, session)
    return found
  })
}

/** Deletes every log. */
export function clearLearnLogs(): Promise<void> {
  return withStores("readwrite", async (logs, lines) => {
    logs.clear()
    lines.clear()
  })
}

/**
 * Appends `line` to `session`'s log, as the host's `learn` does: a new
 * session's log first drops the logs older than 7 days, then the oldest
 * until it makes 10; a log never grows past 4 MiB. Answers why it didn't,
 * or null.
 */
export async function appendLearnLine(session: string, line: Record<string, unknown>, now = Date.now()): Promise<string | null> {
  if (!learnSession(session)) return "session is a lowercase UUID"
  const text = JSON.stringify(line)
  return withStores("readwrite", async (logs, lines) => {
    const log = (await done(logs.get(session))) as LogRecord | undefined
    if (!log) {
      const all = ((await done(logs.getAll())) as LogRecord[]).sort((a, b) => a.updated - b.updated)
      const excess = all.length + 1 - MAX_LEARN_LOGS
      for (const [i, old] of all.entries()) if (i < excess || now - old.updated > LEARN_LOG_AGE_MS) await drop(logs, lines, old.session)
    }
    const bytes = (log?.bytes ?? 0) + new TextEncoder().encode(text).length + 1
    if (bytes > MAX_LEARN_LOG) return `a learning log is at most ${MAX_LEARN_LOG} bytes`
    logs.put({ session, updated: now, bytes })
    lines.add({ session, text })
    return null
  })
}

/** Every log as one JSONL file: each line as the host writes it, with its session. */
export function learnExport(logs: LearnLog[]): string {
  return logs.flatMap((log) => log.lines.map((line) => JSON.stringify({ session: log.session, ...(JSON.parse(line) as Record<string, unknown>) }))).join("\n") + (logs.length ? "\n" : "")
}
