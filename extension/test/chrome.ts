// A small stand-in for the chrome.* APIs the background uses, and a fake host,
// for testing the background classes without a browser.

import { HostError, type VaultBackend } from "../src/bg/backend"
import type { PageFacts, Status } from "../src/messages"
import type { Account, RequestBody as Request } from "../src/protocol"

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
  alarms: Record<string, { periodInMinutes?: number }>
  /** How many times each alarm was created. */
  alarmsCreated: Record<string, number>
  alarmListeners: Array<(alarm: { name: string }) => void>
  idleListeners: Array<(state: string) => void>
  /** URLs opened with chrome.tabs.create. */
  opened: string[]
  offscreenOpen: boolean
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
    alarmsCreated: {},
    alarmListeners: [],
    idleListeners: [],
    opened: [],
    offscreenOpen: true,
  }
  ;(globalThis as unknown as { chrome: unknown }).chrome = {
    runtime: {
      id: ID,
      getURL: (path: string) => `chrome-extension://${ID}/${path}`,
      sendMessage: async (message: unknown) => {
        fake.sent.push(message)
        return fake.runtimeAnswer(message)
      },
      onMessage: { addListener: (l: FakeChrome["listeners"][number]) => void fake.listeners.push(l) },
      getContexts: async () => (fake.offscreenOpen ? [{ contextType: "OFFSCREEN_DOCUMENT" }] : []),
    },
    offscreen: {
      createDocument: async () => void (fake.offscreenOpen = true),
      closeDocument: async () => void (fake.offscreenOpen = false),
    },
    alarms: {
      get: async (name: string) => (fake.alarms[name] ? { name, ...fake.alarms[name] } : undefined),
      create: async (name: string, info: { periodInMinutes?: number }) => {
        fake.alarms[name] = info
        fake.alarmsCreated[name] = (fake.alarmsCreated[name] ?? 0) + 1
      },
      onAlarm: { addListener: (l: (alarm: { name: string }) => void) => void fake.alarmListeners.push(l) },
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
        get: async (key: string | null) => (key === null ? { ...fake.session } : key in fake.session ? { [key]: fake.session[key] } : {}),
        set: async (items: Record<string, unknown>) => void Object.assign(fake.session, items),
        remove: async (key: string | string[]) => void (Array.isArray(key) ? key : [key]).forEach((k) => delete fake.session[k]),
      },
      local: {
        get: async (key: string) => (key in fake.local ? { [key]: fake.local[key] } : {}),
        set: async (items: Record<string, unknown>) => void Object.assign(fake.local, structuredClone(items)),
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

/** A page that shows nothing either way. */
export const NO_FACTS: PageFacts = { loginForm: false, passwordEmpty: false, mfa: false, error: false, challenge: false, account: false, signOut: false, loginish: false }

export const ACCOUNTS: Account[] = [
  { ref: `${"a".repeat(64)}:${"1".repeat(32)}`, vault: "Personal", title: "Example", username: "kit@example.com", hasPassword: true, hasTotp: true, urls: [] },
  { ref: `${"a".repeat(64)}:${"2".repeat(32)}`, vault: "Work", title: "Example admin", username: "admin", hasPassword: true, hasTotp: false, urls: [] },
]

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
