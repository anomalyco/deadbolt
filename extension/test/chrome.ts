// A small stand-in for the chrome.* APIs the background uses, and a fake host,
// for testing the background classes without a browser.

import { HostError, type VaultBackend } from "../src/bg/backend"
import type { PageFacts, Status } from "../src/messages"
import type { Account, FormCard, FormIdentity, RequestBody as Request } from "../src/protocol"

export const ID = "jhocodkhpifjndffenppfmdkmiolngal"
export const MENU_URL = "chrome-extension://0123456789abcdef/menu.html"
export const SITE = "https://www.example.com"
export const POPUP_URL = `chrome-extension://${ID}/popup.html`

/** Web frames only: like Chrome, webNavigation doesn't report extension frames. */
export interface FrameInfo {
  url: string
  documentId: string
  parentFrameId?: number
}

export interface FakeChrome {
  frames: Record<string, FrameInfo>
  delivered: Array<{ tabId: number; message: { type: string; [k: string]: unknown }; options: unknown }>
  /** What content scripts answer to db:fill. */
  fillAck: (message: unknown) => unknown
  /** What the content script in `documentId` answers to anything else; throwing is no content script there. */
  answer: (message: { type: string; [k: string]: unknown }, documentId: string) => unknown
  /** What the top page's content script answers to db:probe: by default, a signed-in page that shows the account. */
  facts: Partial<PageFacts> | ((documentId: string) => Partial<PageFacts> | null)
  badges: Record<number, string>
  popups: number[]
  session: Record<string, unknown>
  local: Record<string, unknown>
  tabs: Record<number, { active: boolean; windowId: number }>
  /** Everything sent with chrome.runtime.sendMessage, and what it's answered with (undefined: nobody listens). */
  sent: unknown[]
  runtimeAnswer: (message: unknown) => unknown
  /** chrome.runtime.onMessage listeners; `deliver` calls them as Chrome would. */
  listeners: Array<(message: unknown, sender: chrome.runtime.MessageSender, respond: (reply: unknown) => void) => unknown>
  alarms: Record<string, { periodInMinutes?: number; when?: number }>
  /** Optional permissions granted (chrome.permissions). */
  granted: Set<string>
  /** How many times each alarm was created. */
  alarmsCreated: Record<string, number>
  alarmListeners: Array<(alarm: { name: string }) => void>
  idleListeners: Array<(state: string) => void>
  /** URLs opened with chrome.tabs.create. */
  opened: string[]
  offscreenOpen: boolean
  /** The open offscreen document's id: a new one each time it's created. */
  offscreenDoc: number
  /** chrome.runtime.onInstalled listeners. */
  installedListeners: Array<(details: { reason: string }) => void>
  /** This build's manifest version. */
  version: string
  /** IndexedDB, as the fake indexedDB keeps it: database, then object store, then key. */
  idb: Record<string, Record<string, Record<string, unknown>>>
  /** Databases whose upgrade was aborted (and rolled back), and connections closed, by name. */
  idbAborted: string[]
  idbClosed: string[]
}

/** A message to the extension from `sender`, answered by the first listener that responds (null if none does). */
export function deliver(fake: FakeChrome, message: unknown, sender: chrome.runtime.MessageSender): Promise<unknown> {
  return new Promise((resolve) => {
    let waiting = false
    for (const l of fake.listeners) if (l(message, sender, resolve) === true) waiting = true
    if (!waiting) setTimeout(() => resolve(null), 0)
  })
}

/** Lets pending promises and zero-delay timers run. */
export async function settle(rounds = 10) {
  for (let i = 0; i < rounds; i++) await new Promise((r) => setTimeout(r, 0))
}

export function installChrome(): FakeChrome {
  const fake: FakeChrome = {
    frames: { "1:0": { url: "https://www.example.com/login", documentId: "top-doc", parentFrameId: -1 } },
    delivered: [],
    fillAck: () => ({ filled: ["email", "password"] }),
    // Every field may be filled.
    answer: (message, documentId) => {
      if (message.type === "db:approve") return { approval: `ok-${message.form}`, roles: ["username", "email", "phone", "password", "otp"] }
      if (message.type === "db:probe") {
        const facts = typeof fake.facts === "function" ? fake.facts(documentId) : fake.facts
        return facts && { ...NO_FACTS, ...facts }
      }
      return true
    },
    facts: { account: true },
    badges: {},
    popups: [],
    session: {},
    local: {},
    tabs: { 1: { active: true, windowId: 7 } },
    sent: [],
    runtimeAnswer: () => undefined,
    listeners: [],
    alarms: {},
    granted: new Set(),
    alarmsCreated: {},
    alarmListeners: [],
    idleListeners: [],
    opened: [],
    offscreenOpen: true,
    offscreenDoc: 1,
    installedListeners: [],
    version: "1.0.0",
    idb: {},
    idbAborted: [],
    idbClosed: [],
  }
  ;(globalThis as unknown as { indexedDB: unknown }).indexedDB = fakeIndexedDB(fake)
  ;(globalThis as unknown as { chrome: unknown }).chrome = {
    runtime: {
      id: ID,
      getURL: (path: string) => `chrome-extension://${ID}/${path}`,
      sendMessage: async (message: unknown) => {
        fake.sent.push(message)
        return fake.runtimeAnswer(message)
      },
      onMessage: { addListener: (l: FakeChrome["listeners"][number]) => void fake.listeners.push(l) },
      getContexts: async () => (fake.offscreenOpen ? [{ contextType: "OFFSCREEN_DOCUMENT", documentId: `offscreen-${fake.offscreenDoc}` }] : []),
      onInstalled: { addListener: (l: (details: { reason: string }) => void) => void fake.installedListeners.push(l) },
      getManifest: () => ({ version: fake.version }),
    },
    offscreen: {
      createDocument: async () => {
        fake.offscreenOpen = true
        fake.offscreenDoc++
      },
      closeDocument: async () => void (fake.offscreenOpen = false),
    },
    alarms: {
      get: async (name: string) => (fake.alarms[name] ? { name, ...fake.alarms[name] } : undefined),
      create: async (name: string, info: { periodInMinutes?: number; when?: number }) => {
        fake.alarms[name] = info
        fake.alarmsCreated[name] = (fake.alarmsCreated[name] ?? 0) + 1
      },
      clear: async (name: string) => delete fake.alarms[name],
      onAlarm: { addListener: (l: (alarm: { name: string }) => void) => void fake.alarmListeners.push(l) },
    },
    permissions: {
      contains: async ({ permissions = [] }: { permissions?: string[] }) => permissions.every((p) => fake.granted.has(p)),
    },
    idle: { onStateChanged: { addListener: (l: (state: string) => void) => void fake.idleListeners.push(l) } },
    webNavigation: {
      getFrame: async ({ tabId, frameId }: { tabId: number; frameId: number }) => fake.frames[`${tabId}:${frameId}`] ?? null,
      getAllFrames: async ({ tabId }: { tabId: number }) =>
        Object.entries(fake.frames)
          .filter(([key]) => key.startsWith(`${tabId}:`))
          .map(([key, f]) => ({ frameId: Number(key.split(":")[1]), parentFrameId: f.parentFrameId ?? -1, url: f.url, documentId: f.documentId })),
    },
    tabs: {
      sendMessage: async (tabId: number, message: { type: string }, options: { documentId: string }) => {
        fake.delivered.push({ tabId, message, options })
        return message.type === "db:fill" ? fake.fillAck(message) : fake.answer(message, options.documentId)
      },
      get: async (tabId: number) => ({ id: tabId, ...fake.tabs[tabId] }),
      create: async ({ url }: { url: string }) => void fake.opened.push(url),
    },
    storage: {
      session: {
        get: async (key: string | string[] | null) =>
          key === null ? { ...fake.session } : Object.fromEntries((Array.isArray(key) ? key : [key]).filter((k) => k in fake.session).map((k) => [k, fake.session[k]])),
        set: async (items: Record<string, unknown>) => void Object.assign(fake.session, items),
        remove: async (key: string | string[]) => void (Array.isArray(key) ? key : [key]).forEach((k) => delete fake.session[k]),
      },
      local: {
        get: async (key: string | string[]) => Object.fromEntries((Array.isArray(key) ? key : [key]).filter((k) => k in fake.local).map((k) => [k, fake.local[k]])),
        set: async (items: Record<string, unknown>) => void Object.assign(fake.local, structuredClone(items)),
        remove: async (key: string | string[]) => void (Array.isArray(key) ? key : [key]).forEach((k) => delete fake.local[k]),
      },
    },
    action: {
      setBadgeText: async ({ tabId, text }: { tabId: number; text: string }) => void (fake.badges[tabId] = text),
      setBadgeBackgroundColor: async () => {},
      openPopup: async ({ windowId }: { windowId: number }) => void fake.popups.push(windowId),
    },
  }
  return fake
}

/** Just enough IndexedDB for a key-value store: open (with its upgrade), get, put, delete and clear, answered asynchronously. */
function fakeIndexedDB(fake: FakeChrome) {
  const answer = <T>(result: () => T) => {
    const req = { result: undefined as T | undefined, error: null, onsuccess: null as null | (() => void), onerror: null as null | (() => void) }
    queueMicrotask(() => {
      req.result = result()
      req.onsuccess?.()
    })
    return req
  }
  return {
    open(name: string) {
      let aborted = false
      const req = {
        result: null as unknown,
        error: null as unknown,
        onupgradeneeded: null as null | (() => void),
        onsuccess: null as null | (() => void),
        onerror: null as null | (() => void),
        // The version change: aborting it rolls a new database back to nothing, as IndexedDB does.
        transaction: null as null | { abort: () => void },
      }
      queueMicrotask(() => {
        const fresh = !fake.idb[name]
        const stores = (fake.idb[name] ??= {})
        if (fresh)
          req.transaction = {
            abort: () => {
              aborted = true
              fake.idbAborted.push(name)
              delete fake.idb[name]
            },
          }
        req.result = {
          createObjectStore: (store: string) => (stores[store] ??= {}),
          transaction: (store: string) => ({
            objectStore: () => {
              const map = (stores[store] ??= {})
              return {
                get: (key: string) => answer(() => structuredClone(map[key])),
                put: (value: unknown, key: string) => answer(() => ((map[key] = structuredClone(value)), key)),
                delete: (key: string) => answer(() => void delete map[key]),
                clear: () => answer(() => void Object.keys(map).forEach((k) => delete map[k])),
              }
            },
          }),
          close: () => void fake.idbClosed.push(name),
        }
        if (fresh) req.onupgradeneeded?.()
        req.transaction = null
        if (aborted) {
          req.error = new DOMException("The upgrade was aborted.", "AbortError")
          return req.onerror?.()
        }
        req.onsuccess?.()
      })
      return req
    },
  }
}

/** A page that shows nothing either way. */
export const NO_FACTS: PageFacts = { loginForm: false, passwordEmpty: false, mfa: false, error: false, challenge: false, account: false, signOut: false, loginish: false }

export const ACCOUNTS: Account[] = [
  { ref: `${"a".repeat(64)}:${"1".repeat(32)}`, vault: "Personal", title: "Example", username: "kit@example.com", hasPassword: true, hasTotp: true, urls: [] },
  { ref: `${"a".repeat(64)}:${"2".repeat(32)}`, vault: "Work", title: "Example admin", username: "admin", hasPassword: true, hasTotp: false, urls: [] },
]

/** The vault's identity and card for forms: Home, and a Visa ending 4242 (which `forms` lists without its number). */
export const HOME_REF = `${"c".repeat(64)}:${"1".repeat(32)}`
export const VISA_REF = `${"c".repeat(64)}:${"3".repeat(32)}`
export const HOME_VALUES: Record<string, string> = {
  "given-name": "Kit", "family-name": "Langton", email: "kit@example.com", phone: "+14155550123",
  "address-line1": "123 Main St", city: "Brooklyn", region: "NY", "postal-code": "11201", country: "US",
}
export const IDENTITIES: FormIdentity[] = [{ ref: HOME_REF, vault: "Personal", title: "Home", summary: "Kit Langton · 123 Main St, Brooklyn", fields: Object.keys(HOME_VALUES) as FormIdentity["fields"] }]
export const CARDS: FormCard[] = [{ ref: VISA_REF, vault: "Personal", title: "Visa •••• 4242", brand: "Visa", last4: "4242", expiry: "2028-08", cardholder: "Kit Langton", fields: ["number", "expiry", "cardholder", "brand"] }]

export interface FakeHost {
  host: VaultBackend
  requests: Request[]
  setStatus(status: Status): void
  /** Holds the host's fill replies until the returned function is called. */
  holdFills(): () => void
}

/** A host with two saved logins: kit@example.com / "correct horse" (with a code) and admin / "hunter2". */
export function fakeHost(): FakeHost {
  const requests: Request[] = []
  const listeners: Array<(s: Status) => void> = []
  let held: Promise<void> | null = null
  const host = {
    status: { state: "ready", version: "0.0.0" } as Status,
    capabilities: ["list", "fill", "check", "save", "generate", "forms", "save-form", "learn"],
    onChange: (l: (s: Status) => void) => void listeners.push(l),
    connect: async () => {},
    reconnectNow: async () => {},
    send: async (req: Request) => {
      requests.push(req)
      switch (req.type) {
        case "list":
          return { type: "list", site: "example.com", accounts: ACCOUNTS }
        case "fill":
          await held
          return { type: "fill", username: "kit@example.com", password: "correct horse", totp: "492039" }
        case "check": {
          // Without a username, by password alone: "same" or nothing.
          if (req.username === undefined) return { type: "check", status: req.password === "hunter2" ? "same" : "new", matches: req.password === "hunter2" ? [ACCOUNTS[1].ref] : [] }
          const known = req.username === "admin" ? [ACCOUNTS[1].ref] : []
          const status = known.length ? (req.password === "hunter2" ? "same" : "update") : "new"
          return { type: "check", status, matches: known }
        }
        case "generate": {
          const n = requests.filter((r) => r.type === "generate").length
          return { type: "generate", password: `generated ${n}`, generated: `g${n}` }
        }
        // Fewer than twelve characters is weak here.
        case "generate-check":
          if ((req.maxLength ?? 99) < 12) throw new HostError("weak", "Only weak passwords fit.")
          return { type: "generate-check" }
        case "generate-keep":
        case "generate-drop":
          return { type: req.type }
        case "save":
          return { type: "save", ref: req.ref ?? "b", created: !req.ref }
        case "forms":
          return { type: "forms", canVerify: true, identities: IDENTITIES, cards: CARDS }
        case "fill-form": {
          const values = req.ref === HOME_REF ? HOME_VALUES : {}
          return { type: "fill-form", verified: false, values: Object.fromEntries(req.fields.filter((f) => f in values).map((f) => [f, values[f]])) }
        }
        case "save-form":
          return { type: "save-form", ref: req.ref ?? `${"d".repeat(64)}:${"9".repeat(32)}`, created: !req.ref }
      }
      throw new Error("unexpected")
    },
  }
  return {
    host: host as unknown as VaultBackend,
    requests,
    setStatus(status) {
      host.status = status
      for (const l of listeners) l(status)
    },
    holdFills() {
      let release = () => {}
      held = new Promise<void>((resolve) => (release = resolve))
      return () => {
        held = null
        release()
      }
    },
  }
}

/** A content script's message from the top frame of tab 1. */
export function pageSender(over: Partial<chrome.runtime.MessageSender> = {}): chrome.runtime.MessageSender {
  return {
    id: ID,
    tab: { id: 1, incognito: false } as chrome.tabs.Tab,
    frameId: 0,
    url: "https://www.example.com/login",
    origin: "https://www.example.com",
    documentId: "top-doc",
    ...over,
  }
}

/** The inline menu frame (frame 5) in tab 1. */
export function menuSender(over: Partial<chrome.runtime.MessageSender> = {}): chrome.runtime.MessageSender {
  return { id: ID, tab: { id: 1, incognito: false } as chrome.tabs.Tab, frameId: 5, url: MENU_URL, origin: "chrome-extension://0123456789abcdef", documentId: "menu-doc", ...over }
}
