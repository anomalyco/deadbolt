// Placement, paint-time visibility, scale, and viewport-resize guards for the inline host.

import { within, type Rect } from "./dom"

export interface GuardHost {
  host(): HTMLElement | null
  frame(): HTMLIFrameElement | null
  port(): MessagePort | null
  written(): Rect | null
  held(): boolean
  closing(): boolean
  raising(): boolean
  tellMoved(): void
  raise(): void
}

export function createPlacementGuard(h: GuardHost) {
  let lastRect: Rect | null = null
  let lastGeometry = ""
  let scaleVisible = false
  let scaleObserver: ResizeObserver | null = null
  let placementObserver: MutationObserver | null = null
  let placementVersion = 0
  let placementChangedAt = -Infinity
  let placementAncestors: Node[] = []
  /** Paint-time evidence (see watchPaint): the host was last drawn where it was written. */
  let paintObserver: IntersectionObserver | null = null
  /** The host and the written rect the paint observer was made for. */
  let paintFor: { box: HTMLElement; at: Rect } | null = null
  let paintKey = ""
  let paintSeen = true
  /** Whether the scale observer has given a verdict yet: a later return to "visible" is a move back. */
  let scaleKnown = false
  /** The last host toggle handled: its own listener and the window's both hear it. */
  let lastToggle: Event | null = null
  /**
   * How much the browser resized the viewport since the frame was last placed
   * (an infobar such as "started debugging this browser" came or went, or the
   * window was resized). A page can't send a trusted resize event, nor resize a
   * tab's viewport (only a popup's, with resizeTo).
   */
  let resized: { dw: number; dh: number } | null = null
  let viewport = { w: innerWidth, h: innerHeight }

  const placementSafe = () => performance.now() - placementChangedAt >= 500

  /** The intended size, not a rect the page may have restyled; only the menu gets it. */
  function tellGeometry() {
    const port = h.port()
    const written = h.written()
    if (!port || !written) return
    // Keep fractional width: rounding it before multiplying by DPR would
    // inflate the physical-pixel tolerance on high-density displays.
    const geometry = { width: written.width, height: Math.round(written.height), dpr: devicePixelRatio, visible: scaleVisible && placementSafe() && paintSeen, version: placementVersion }
    const key = JSON.stringify(geometry)
    if (key === lastGeometry) return
    lastGeometry = key
    port.postMessage({ type: "db:menu-geometry", geometry })
  }

  /** Never let a restoring write erase evidence of a late page restyle. */
  function placementChanged() {
    placementVersion++
    placementChangedAt = performance.now()
    h.tellMoved()
    tellGeometry()
  }

  function placed(): boolean {
    const host = h.host()
    const written = h.written()
    if (!host || !written) return false
    const r = host.getBoundingClientRect()
    return (["left", "top", "width", "height"] as const).every((k) => Math.abs(r[k] - written[k]) <= 2)
  }

  function placementChanges(records: MutationRecord[]) {
    const host = h.host()
    if (!host || !records.length) return
    const changed = records.some((r) => r.target === host || [...r.addedNodes, ...r.removedNodes].some((n) => within(host, n)))
    // Ancestor transforms don't move a top-layer box, but inherited zoom can.
    // Read it in the mutation microtask, before a later task can restore it;
    // unrelated theme/scroll-lock classes mustn't keep a dialog menu unsettled.
    const zoom = (host as HTMLElement & { currentCSSZoom?: number }).currentCSSZoom
    if (changed || (!h.held() && (!placed() || typeof zoom !== "number" || Math.abs(zoom - 1) >= 0.001))) placementChanged()
  }

  /** Watch only the rendered ancestry, not unrelated style churn in the page. */
  function watchPlacement() {
    const host = h.host()
    if (!host || !placementObserver) return
    const ancestors: Node[] = []
    for (let n: Node | null = host; n; n = n.parentNode ?? (n instanceof ShadowRoot ? n.host : null)) ancestors.push(n)
    if (ancestors.length === placementAncestors.length && ancestors.every((n, i) => n === placementAncestors[i])) return
    placementChanges(placementObserver.takeRecords())
    placementObserver.disconnect()
    placementAncestors = ancestors
    for (const n of ancestors) placementObserver.observe(n, { attributes: true, attributeFilter: ["style", "class"], childList: true })
  }

  /**
   * Every entry is evidence, not just the last: a page can hold its
   * notifications back until a later frame has put the host back, so one
   * delivery may carry a displaced paint and then a good one. Any entry drawn
   * elsewhere restarts the wait; the last one says whether it's in place now.
   */
  function judgePaint(entries: IntersectionObserverEntry[]) {
    if (!entries.length || !paintFor || h.host() !== paintFor.box || h.held() || h.closing()) return
    const at = paintFor.at
    const near = (a: number, b: number) => Math.abs(a - b) <= 2
    const verdicts = entries.map(({ boundingClientRect: r }) => near(r.left, at.left) && near(r.top, at.top) && near(r.width, at.width) && near(r.height, at.height))
    const seen = verdicts[verdicts.length - 1]
    const moved = verdicts.includes(false) || seen !== paintSeen
    paintSeen = seen
    // Drawn elsewhere, or back in place: either way it moved, and waits again.
    if (moved) placementChanged()
  }

  /** Judges what the old observer still holds, then drops it. */
  function stopPaint() {
    if (paintObserver) judgePaint(paintObserver.takeRecords())
    paintObserver?.disconnect()
    paintObserver = null
    paintFor = null
    paintKey = ""
  }

  /**
   * Where the host was painted, from the browser's own intersection pass, which
   * runs after every script in the frame. The observer's root is the written
   * rect ± 2 px, so the host leaving it or coming back triggers an entry; each
   * entry is then judged by the host's own rect in it against the written
   * rect. Whatever draws the host elsewhere (a late restyle, an ancestor's
   * transform, a way not listed here) fails that, and a pick waits until it's
   * back and has sat still again. Remade whenever the written rect or the
   * viewport changes, so following a scrolled or reflowed field isn't taken
   * for a displacement; a viewport the page changed after our frame (a
   * scrollbar) only moves the trigger, not the judgement.
   */
  function watchPaint() {
    const host = h.host()
    const written = h.written()
    if (!host || !written || h.held() || h.closing()) {
      stopPaint()
      return
    }
    const view = document.scrollingElement ?? document.documentElement
    const vw = view.clientWidth
    const vh = view.clientHeight
    const w = written
    const key = [w.left, w.top, w.width, w.height, vw, vh].map((n) => Math.round(n * 4)).join()
    if (key === paintKey) return
    stopPaint()
    paintKey = key
    const box = host
    const root = { left: w.left - 2, top: w.top - 2, right: w.left + w.width + 2, bottom: w.top + w.height + 2 }
    const margin = [root.top, vw - root.right, vh - root.bottom, root.left].map((n) => `${-n}px`).join(" ")
    const observer = new IntersectionObserver((entries) => observer === paintObserver && judgePaint(entries), { root: document, rootMargin: margin, threshold: 1 })
    paintObserver = observer
    paintFor = { box, at: { ...w } }
    observer.observe(box)
  }

  /**
   * The host hidden by the page, or by the browser for a modal dialog or full
   * screen: that counts as a raise like any other, and a move. Heard on the
   * host and, from document_start, on the window in the capture phase, before
   * any listener a page can add there, so the page can't stop it reaching here.
   */
  function onHostToggle(e: Event) {
    const box = h.host()
    if (!box || e.target !== box || !e.isTrusted || e === lastToggle || h.raising() || h.held() || (e as ToggleEvent).newState !== "closed") return
    lastToggle = e
    // `toggle` comes a task later: if a raise already put it back, nothing to do.
    if (e.type === "toggle" && box.matches(":popover-open")) return
    queueMicrotask(() => {
      if (h.host() !== box) return
      h.raise()
      if (h.host() === box) placementChanged()
    })
  }

  /**
   * Whether the frame's move from `from` to `to` is only the page reflowing for
   * a viewport resize the browser made: the same size, shifted no further than
   * the viewport changed, in a normal tabbed window (whose size the page can't
   * set). A centred login form moves by half an infobar when one comes or goes;
   * that isn't the page moving the menu, so the dwell isn't restarted for it.
   */
  function followedResize(from: Rect, to: Rect): boolean {
    if (!resized || !window.toolbar.visible) return false
    return Math.abs(to.width - from.width) <= 1 && Math.abs(to.height - from.height) <= 1 && Math.abs(to.left - from.left) <= Math.abs(resized.dw) + 1 && Math.abs(to.top - from.top) <= Math.abs(resized.dh) + 1
  }

  function onResize(event: Event) {
    if (!event.isTrusted) return
    const now = { w: innerWidth, h: innerHeight }
    resized = { dw: (resized?.dw ?? 0) + now.w - viewport.w, dh: (resized?.dh ?? 0) + now.h - viewport.h }
    viewport = now
  }

  function startPlacementObserver() {
    placementObserver = new MutationObserver(placementChanges)
    watchPlacement()
  }

  function startScaleObserver(box: HTMLElement) {
    // ResizeObserver runs after all rAF callbacks, including a page's later
    // restyle. Observe physical pixels so zoom alone triggers it. Keep this
    // verdict until another rendered size arrives: a task can restore layout
    // before a press without undoing the scaled paint the user saw. A deeper
    // page ResizeObserver can run later still: the menu's own observers cover
    // that deferred-host-observation case (see readScale in menu.ts).
    scaleObserver = new ResizeObserver(() => {
      const written = h.written()
      if (h.host() !== box || !written) return
      const r = box.getBoundingClientRect()
      const zoom = (box as HTMLElement & { currentCSSZoom?: number }).currentCSSZoom
      const matches = (a: number, b: number) => Math.abs(a - b) <= 2
      const was = scaleVisible
      scaleVisible =
        typeof zoom === "number" && Math.abs(zoom - 1) < 0.001 &&
        matches(r.left, written.left) && matches(r.top, written.top) && matches(r.width, written.width) && matches(r.height, written.height)
      // Back to its own size after a scaled paint: that's a move too (the
      // menu doesn't restart its wait for "visible" coming back alone).
      if (scaleKnown && !was && scaleVisible) placementChanged()
      scaleKnown = true
      tellGeometry()
    })
    scaleObserver.observe(box, { box: "device-pixel-content-box" })
  }

  function beforePosition() {
    placementChanges(placementObserver?.takeRecords() ?? [])
    watchPlacement()
    if (h.written() && !h.held() && !placed()) placementChanged()
  }

  function afterStyleWrite() {
    const host = h.host()
    // Only this synchronous style assignment is ours. Do not discard additional
    // records: a page may upgrade the random host to a custom element and run
    // an attributeChangedCallback synchronously inside the assignment.
    const own = placementObserver?.takeRecords() ?? []
    if (own.length !== 1 || own[0].target !== host || own[0].attributeName !== "style") placementChanges(own)
    watchPaint()
    // Publish recovery once, not every sub-pixel step of a size spring. The
    // resize observer publishes actual size changes as before.
    if (placementChangedAt !== -Infinity && placementSafe()) {
      placementChangedAt = -Infinity
      tellGeometry()
    }
    // The menu only takes a pick once it has sat still for a moment (see
    // Dwell). From inside its frame it can't tell it was moved, so say so: the
    // page can restyle the host, and the field it follows can move.
    const frame = h.frame()
    if (frame) {
      // This layout read also syncs the child viewport. Its scale observers
      // rely on seeing restored layout as well as a page's later scaled paint.
      const f = frame.getBoundingClientRect()
      const now = { left: f.left, top: f.top, width: f.width, height: f.height }
      const moved = !lastRect || (["left", "top", "width", "height"] as const).some((k) => Math.abs(now[k] - lastRect![k]) > 1)
      if (moved) {
        if (lastRect && !followedResize(lastRect, now)) h.tellMoved()
        lastRect = now
      }
      resized = null
    }
  }

  function checkPlacement(version: unknown): boolean {
    placementChanges(placementObserver?.takeRecords() ?? [])
    // Do not call position(): check the page's layout, not a restored one.
    return !!h.host()?.matches(":popover-open") && version === placementVersion && placementSafe() && scaleVisible && paintSeen && placed()
  }

  function clearLastRect() {
    lastRect = null
  }

  function reset() {
    placementObserver?.disconnect()
    placementObserver = null
    placementAncestors = []
    placementVersion = 0
    placementChangedAt = -Infinity
    paintObserver?.disconnect()
    paintObserver = null
    paintFor = null
    paintKey = ""
    paintSeen = true
    lastToggle = null
    scaleObserver?.disconnect()
    scaleObserver = null
    scaleVisible = false
    scaleKnown = false
    lastGeometry = ""
    lastRect = null
  }

  return {
    placementChanged,
    tellGeometry,
    onHostToggle,
    onResize,
    startPlacementObserver,
    startScaleObserver,
    beforePosition,
    afterStyleWrite,
    checkPlacement,
    clearLastRect,
    reset,
  }
}
