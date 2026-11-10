// Where the time goes between a press on the menu's locked row and the toolbar
// panel on screen, in a real headed browser (run.ts --timing <n>). Every step
// is stamped on the one clock the machine has (performance.timeOrigin plus
// performance.now() in each page and the worker, Date.now() here): the press
// in the menu's frame, the background's message and each browser call it makes
// (wrapped from outside, so nothing in the extension changes for this), the
// panel's own loading and painting, and the moment macOS lists the panel's
// window on screen, which is when the user can see it: the browser shows its
// bubble only once the page has loaded, painted and sized itself.
import type { Frame, Worker } from "playwright-core"

/** A named moment, in ms since the epoch. */
export type Stamp = [string, number]

/**
 * Polls macOS's list of on-screen windows for the browser's popup bubble (a
 * window of the browser's narrower than 500 px): when one is ordered in or
 * out, and its opacity as it fades. Null off macOS. JXA takes a few ms a poll,
 * so a stamp is good to about that.
 */
export function watchWindows(): { stamps: () => Stamp[]; stop: () => void } | null {
  if (process.platform !== "darwin") return null
  const script = `ObjC.import("CoreGraphics"); ObjC.import("Foundation")
const seen = {}
while (true) {
  const now = $.NSDate.date.timeIntervalSince1970 * 1000
  const list = ObjC.deepUnwrap(ObjC.castRefToObject($.CGWindowListCopyWindowInfo(1 | 16, 0))) || []
  const here = {}
  for (const w of list) {
    if (!/Brave|Chrom/.test(w.kCGWindowOwnerName || "")) continue
    const b = w.kCGWindowBounds
    if (!b || b.Width < 150 || b.Width > 500 || b.Height < 60 || b.Height > 700) continue
    const id = w.kCGWindowNumber, a = Math.round((w.kCGWindowAlpha ?? 1) * 100) / 100
    here[id] = true
    if (!seen[id] || seen[id] !== a) console.log(JSON.stringify({ t: now, id, w: b.Width, h: b.Height, a }))
    seen[id] = a
  }
  for (const id in seen) if (!here[id]) { console.log(JSON.stringify({ t: now, id: Number(id), gone: true })); delete seen[id] }
  delay(0.004)
}`
  const proc = Bun.spawn(["osascript", "-l", "JavaScript", "-e", script], { stdout: "ignore", stderr: "pipe" })
  const out: Stamp[] = []
  void (async () => {
    let rest = ""
    for await (const chunk of proc.stderr as unknown as AsyncIterable<Uint8Array>) {
      rest += new TextDecoder().decode(chunk)
      const lines = rest.split("\n")
      rest = lines.pop() ?? ""
      for (const line of lines) {
        try {
          const w = JSON.parse(line) as { t: number; w?: number; h?: number; a?: number; gone?: boolean }
          out.push([w.gone ? "screen: the panel's window goes" : `screen: the panel's window is on screen (${w.w}×${w.h}, opacity ${w.a})`, w.t])
        } catch {}
      }
    }
  })()
  return { stamps: () => out.slice(), stop: () => proc.kill() }
}

/** Wraps the worker's browser calls and listens to its messages, from outside: each is stamped in the worker. */
export async function stampWorker(worker: Worker) {
  await worker.evaluate(() => {
    const g = self as unknown as { __dbT?: Array<[string, number]> }
    if (g.__dbT) return
    const out: Array<[string, number]> = (g.__dbT = [])
    const T = (k: string) => out.push([k, performance.timeOrigin + performance.now()])
    chrome.runtime.onMessage.addListener((m: { type?: string }) => void (m?.type?.startsWith("db:menu-unlock") && T(`worker: ${m.type} arrives`)))
    chrome.runtime.onConnect.addListener((p) => void (p.name === "db:panel" && T("worker: the panel's port connects")))
    const wrap = (o: Record<string, unknown>, k: string, label: string) => {
      const f = o[k] as ((...a: unknown[]) => unknown) | undefined
      if (typeof f !== "function") return
      o[k] = function (this: unknown, ...a: unknown[]) {
        T(`worker: ${label} called`)
        const r = f.apply(this, a)
        Promise.resolve(r).then(() => T(`worker: ${label} answers`), () => T(`worker: ${label} refused`))
        return r
      }
    }
    wrap(chrome.tabs as unknown as Record<string, unknown>, "get", "tabs.get")
    wrap(chrome.action as unknown as Record<string, unknown>, "setPopup", "setPopup")
    wrap(chrome.action as unknown as Record<string, unknown>, "openPopup", "openPopup")
  })
}

export const workerStamps = (worker: Worker) => worker.evaluate(() => (self as unknown as { __dbT?: Array<[string, number]> }).__dbT?.splice(0) ?? []).catch(() => [] as Stamp[])

/** The menu frame's press, its message and the reply, and when its row starts to say it's waiting. */
export async function stampMenu(menu: Frame) {
  await menu.evaluate(() => {
    const g = window as unknown as { __dbT?: Array<[string, number]> }
    const out: Array<[string, number]> = (g.__dbT = [])
    const T = (k: string, at = performance.now()) => out.push([k, performance.timeOrigin + at])
    for (const type of ["pointerdown", "pointerup"]) addEventListener(type, (e) => T(`menu: ${type}`, e.timeStamp), true)
    const send = chrome.runtime.sendMessage.bind(chrome.runtime) as (m: unknown) => Promise<unknown>
    ;(chrome.runtime as unknown as { sendMessage: (m: { type?: string }) => Promise<unknown> }).sendMessage = (m) => {
      if (!m?.type?.startsWith("db:menu-unlock")) return send(m)
      T(`menu: sends ${m.type}`)
      const r = send(m)
      void r.then((v) => T(`menu: the reply to ${m.type} (${JSON.stringify(v)})`), () => {})
      return r
    }
    const row = document.querySelector(".row.unlock")
    if (row) new MutationObserver(() => row.classList.contains("waiting") && !out.some(([k]) => k.startsWith("menu: the row")) && T("menu: the row starts to say it's waiting")).observe(row, { attributes: true, subtree: true, childList: true })
  })
}

export const menuStamps = (menu: Frame) => menu.evaluate(() => (window as unknown as { __dbT?: Array<[string, number]> }).__dbT ?? []).catch(() => [] as Stamp[])

/** An expression for the panel (run in it over DevTools): its loading and painting, as stamps. */
export const PANEL_STAMPS = `JSON.stringify((() => {
  const o = performance.timeOrigin, out = [["panel: its navigation starts", o]]
  const n = performance.getEntriesByType("navigation")[0]
  if (n) for (const [k, label] of [["responseEnd", "popup.html has arrived"], ["domInteractive", "popup.html is parsed (its scripts have run)"], ["domContentLoadedEventEnd", "DOMContentLoaded is done"], ["loadEventEnd", "load is done"]]) n[k] && out.push(["panel: " + label, o + n[k]])
  for (const r of performance.getEntriesByType("resource")) { const f = r.name.split("/").pop(); out.push(["panel: " + f + " arrives (" + Math.round(r.decodedBodySize / 1024) + " KB, " + Math.round(r.duration) + " ms)", o + r.responseEnd]) }
  for (const p of performance.getEntriesByType("paint")) out.push(["panel: " + p.name, o + p.startTime])
  for (const m of performance.getEntriesByType("mark")) m.name.startsWith("db:") && out.push(["panel: " + m.name.slice(3), o + m.startTime])
  return out
})())`

/** The stamps of one press, in order, as ms after the press's pointerup ("the click"), each with the step since the one before. */
export function lines(stamps: Stamp[]): { text: string; click: number; shown: number | null } {
  const sorted = [...stamps].sort((a, b) => a[1] - b[1])
  const click = sorted.find(([k]) => k === "menu: pointerup")?.[1] ?? sorted[0]![1]
  const shown = sorted.find(([k, t]) => k.startsWith("screen: the panel's window is on screen") && t >= click)?.[1] ?? null
  let last = click
  const text = sorted
    .map(([k, t]) => {
      const row = `${(t - click).toFixed(1).padStart(8)} ms  (+${(t - last).toFixed(1).padStart(6)})  ${k}`
      last = t
      return row
    })
    .join("\n")
  return { text, click, shown }
}
