// A small stand-in for the chrome.* APIs the background uses, and a fake host,
// for testing the background classes without a browser.

import { HostError, type Host } from "../src/bg/host"
import type { Status } from "../src/messages"
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
  badges: Record<number, string>
  popups: number[]
  session: Record<string, unknown>
  tabs: Record<number, { active: boolean; windowId: number }>
}

export function installChrome(): FakeChrome {
  const fake: FakeChrome = {
    frames: { "1:0": { url: "https://www.example.com/login", documentId: "top-doc", parentFrameId: -1 } },
    delivered: [],
    fillAck: () => ({ filled: ["email", "password"] }),
    // Every field may be filled.
    answer: (message) => (message.type === "db:approve" ? { approval: `ok-${message.form}`, roles: ["username", "email", "phone", "password", "otp"] } : true),
    badges: {},
    popups: [],
    session: {},
    tabs: { 1: { active: true, windowId: 7 } },
  }
  ;(globalThis as unknown as { chrome: unknown }).chrome = {
    runtime: { id: ID },
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
    },
    storage: {
      session: {
        get: async (key: string) => (key in fake.session ? { [key]: fake.session[key] } : {}),
        set: async (items: Record<string, unknown>) => void Object.assign(fake.session, items),
        remove: async (key: string) => void delete fake.session[key],
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

export const ACCOUNTS: Account[] = [
  { ref: `${"a".repeat(64)}:${"1".repeat(32)}`, vault: "Personal", title: "Example", username: "kit@example.com", hasPassword: true, hasTotp: true, urls: [] },
  { ref: `${"a".repeat(64)}:${"2".repeat(32)}`, vault: "Work", title: "Example admin", username: "admin", hasPassword: true, hasTotp: false, urls: [] },
]

export interface FakeHost {
  host: Host
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
    host: host as unknown as Host,
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
