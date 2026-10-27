import { beforeEach, describe, expect, test } from "bun:test"
import { fromExtensionPage, sendToFrame, targetFor } from "../src/bg/frames"

const ID = "jhocodkhpifjndffenppfmdkmiolngal"
let frames: Record<string, { url: string; documentId: string }>
let delivered: Array<{ tabId: number; message: unknown; options: unknown }>

beforeEach(() => {
  frames = { "1:0": { url: "https://www.example.com/login", documentId: "top-doc" } }
  delivered = []
  ;(globalThis as unknown as { chrome: unknown }).chrome = {
    runtime: { id: ID, lastError: undefined },
    webNavigation: {
      getFrame: async ({ tabId, frameId }: { tabId: number; frameId: number }) => frames[`${tabId}:${frameId}`] ?? null,
    },
    tabs: {
      sendMessage: async (tabId: number, message: unknown, options: unknown) => {
        delivered.push({ tabId, message, options })
        return true
      },
    },
  }
})

const sender = (over: Partial<chrome.runtime.MessageSender> = {}): chrome.runtime.MessageSender => ({
  id: ID,
  tab: { id: 1, incognito: false } as chrome.tabs.Tab,
  frameId: 0,
  url: "https://www.example.com/login",
  origin: "https://www.example.com",
  documentId: "top-doc",
  ...over,
})

describe("targetFor", () => {
  test("the top frame of an https page", async () => {
    expect(await targetFor(sender())).toEqual({ tabId: 1, frameId: 0, documentId: "top-doc", origin: "https://www.example.com" })
  })

  test("a same-site subframe", async () => {
    const t = await targetFor(sender({ frameId: 3, url: "https://auth.example.com/embed", origin: "https://auth.example.com", documentId: "f" }))
    expect(t?.origin).toBe("https://auth.example.com")
  })

  test("a cross-site subframe gets nothing", async () => {
    expect(await targetFor(sender({ frameId: 3, url: "https://evil.net/x", origin: "https://evil.net" }))).toBeNull()
  })

  test("a subframe whose top frame can't be read gets nothing", async () => {
    frames = {}
    expect(await targetFor(sender({ frameId: 3, url: "https://auth.example.com/", origin: "https://auth.example.com" }))).toBeNull()
  })

  test("plain http, incognito, other extensions and pages outside tabs get nothing", async () => {
    expect(await targetFor(sender({ url: "http://www.example.com/login", origin: "http://www.example.com" }))).toBeNull()
    expect(await targetFor(sender({ tab: { id: 1, incognito: true } as chrome.tabs.Tab }))).toBeNull()
    expect(await targetFor(sender({ id: "someotherextensionidxxxxxxxxxxx" }))).toBeNull()
    expect(await targetFor(sender({ tab: undefined }))).toBeNull()
  })

  test("sandboxed frames get nothing", async () => {
    expect(await targetFor(sender({ origin: "null" }))).toBeNull()
  })
})

describe("sendToFrame", () => {
  const target = { tabId: 1, frameId: 0, documentId: "top-doc", origin: "https://www.example.com" }

  test("delivers to the exact document", async () => {
    expect(await sendToFrame(target, { type: "db:fill", values: { username: "kit" }, form: 1, approval: "a" })).toBe(true)
    expect(delivered).toEqual([{ tabId: 1, message: { type: "db:fill", values: { username: "kit" }, form: 1, approval: "a" }, options: { documentId: "top-doc" } }])
  })

  test("not after the frame navigated to another document", async () => {
    frames["1:0"] = { url: "https://www.example.com/home", documentId: "next-doc" }
    expect(await sendToFrame(target, { type: "db:fill", values: {}, form: 1, approval: "a" })).toBeNull()
    expect(delivered).toEqual([])
  })

  test("not after the frame moved to another origin", async () => {
    frames["1:0"] = { url: "https://evil.net/", documentId: "top-doc" }
    expect(await sendToFrame(target, { type: "db:fill", values: {}, form: 1, approval: "a" })).toBeNull()
  })
})

test("a sender without a documentId gets nothing", async () => {
  expect(await targetFor(sender({ documentId: undefined }))).toBeNull()
})

test("fromExtensionPage: the menu and popup, not content scripts", () => {
  expect(fromExtensionPage(sender({ url: `chrome-extension://${ID}/popup.html` }))).toBe(true)
  // Menus load through the per-session dynamic id.
  expect(fromExtensionPage(sender({ url: "chrome-extension://0123456789abcdef/menu.html#t" }))).toBe(true)
  expect(fromExtensionPage(sender())).toBe(false)
  expect(fromExtensionPage(sender({ id: "other", url: "chrome-extension://other/popup.html" }))).toBe(false)
  // A named page must be that page.
  expect(fromExtensionPage(sender({ url: `chrome-extension://${ID}/popup.html` }), "popup.html")).toBe(true)
  expect(fromExtensionPage(sender({ url: "chrome-extension://0123456789abcdef/menu.html#t" }), "popup.html")).toBe(false)
})
