// Folding the inline menu or save offer into its status pill, settling it, and shrinking it away.

import type { SurfaceMode } from "../messages"
import { h, icon } from "../ui/dom"
import { animateTo, MENU_MOTION, reducedMotion, REDUCED_FADE, rollLabel, SHRINK_WAITS_MS, spring, timing } from "../ui/motion"
import { folding, host, MARK_ROOM, PILL_HEIGHT, placePill, riding, whenWide } from "../ui/pill-frame"

/** A pill's flash as its fill lands, or fails: up quickly, then cooling. */
const PILL_FLASH_MS = 1100
/** How far the frame's width leads a pill's label roll. */
const WIDTH_LEAD_MS = 80

export interface PillHost {
  surface: HTMLElement
  setMode(mode: SurfaceMode): void
  report(grow?: number): void
  done(travel?: boolean): void
  relax(): void
}

export function createPillController(p: PillHost) {
  /** The pill's own answer as its ring closes, or goes: its whole ground flashes green, or red, and cools. */
  function land(ok: boolean) {
    // A tinted layer under the pill's content, up fast, then cooling slowly: a light, not a fade.
    const glow = h("span", { class: `pill-glow${ok ? "" : " failed"}`, "aria-hidden": "true" })
    p.surface.append(glow)
    glow
      .animate([{ opacity: 0, easing: "ease-out" }, { opacity: 1, offset: 0.15, easing: "cubic-bezier(.2,.7,.3,1)" }, { opacity: 0 }], PILL_FLASH_MS)
      .finished.then(() => glow.remove(), () => glow.remove())
  }

  /**
   * A filled pill going: its words fade where they are and its green goes,
   * then the frame shrinks into the circle at its right end, the pill
   * narrowing with it frame by frame so the tile rides its left edge there
   * (placePill), and the circle fades as it arrives.
   */
  function toCircle(pill: HTMLElement) {
    if (reducedMotion()) return p.done()
    for (const el of pill.querySelectorAll<HTMLElement>(".pill-label, .pill-mark"))
      el.animate([{ opacity: 1, filter: "blur(0px)" }, { opacity: 0, filter: "blur(2px)" }], { duration: 160, easing: "ease-out", fill: "forwards" })
    const tile = pill.querySelector<HTMLElement>(".avatar, .offer-mark")
    if (tile) tile.style.flexShrink = "0"
    const shrink = spring(MENU_MOTION.frameSize).duration
    setTimeout(() => {
      if (!pill.isConnected) return
      riding.closingUp = pill
      // The ring goes back to its plain track, the rim's light out.
      for (const el of pill.querySelectorAll<HTMLElement>(".ring-comet, .pill-glow"))
        el.animate([{ opacity: getComputedStyle(el).opacity }, { opacity: 0 }], { duration: shrink * 0.5, easing: "ease-out", fill: "forwards" })
      p.report(PILL_HEIGHT - pill.getBoundingClientRect().width)
      pill.style.boxSizing = "border-box"
      pill.style.overflow = "clip"
      whenWide(PILL_HEIGHT, placePill)
      // It starts to fade while it's still closing.
      setTimeout(() => p.done(), shrink * 0.55)
    }, 120)
  }

  /**
   * Folds the surface into a pill at its place on the page (the end of the
   * field the menu belongs to, or the top right for the save offer):
   * `persist` (the picked row's avatar, or the Save button's label) and `lead`
   * travel into it, everything else fades and blurs where it is, and the frame
   * contracts from where it is onto the pill, which is laid out at its final
   * size and place from the start. Returns the pill's label. Without `check`,
   * the pill has no check of its own to open when it's done (a pick's ring says so).
   */
  function fold(
    persist: HTMLElement | null,
    text: string,
    { persistIsLabel = false, lead, check = true }: { persistIsLabel?: boolean; lead?: HTMLElement; check?: boolean } = {},
  ): HTMLElement {
    p.setMode("pill")
    const pill = h("div", { class: "pill waiting" })
    const label = persistIsLabel && persist ? h("span", { class: "pill-label" }) : h("span", { class: "pill-label" }, text)
    label.dataset.text = persistIsLabel && persist ? (persist.dataset.text ?? text) : text
    const slots = { lead: h("span", { class: "pill-slot" }), persist: h("span", { class: "pill-slot" }) }
    // A `persist` that isn't on the menu has nowhere to travel from: it's in the pill from the start.
    const inPlace = !!persist && !persistIsLabel && !persist.isConnected
    if (lead) pill.append(slots.lead)
    if (inPlace) pill.append(persist)
    else if (persist && !persistIsLabel) pill.append(slots.persist)
    pill.append(label)
    if (check) pill.append(h("span", { class: "pill-mark", "aria-hidden": "true" }, icon("check")))
    // Whatever goes fades where it is; the pill is the main change. It keeps
    // its size too, so the narrowing frame closes over it instead of reflowing it.
    const fading = Array.from(p.surface.children) as HTMLElement[]
    for (const el of fading) el.style.width = `${el.getBoundingClientRect().width}px`
    Object.assign(folding, { fading, travellers: [], label: null, pin: null })
    p.surface.classList.add("folded")
    document.body.append(pill)
    for (const el of fading) {
      el.setAttribute("aria-hidden", "true")
      el.style.pointerEvents = "none"
      animateTo(el, reducedMotion() ? { opacity: "0" } : { opacity: "0", filter: "blur(3px)", transform: "scale(0.96)" }, MENU_MOTION.foldOut)
    }
    // The pill's size, before anything moves into it: the label's text and the slots' sizes.
    if (persistIsLabel && persist) label.append(...Array.from(persist.cloneNode(true).childNodes))
    const size = (slot: HTMLElement, el: HTMLElement | null | undefined, w: number) => {
      if (!el) return
      slot.style.cssText = `display:inline-block;flex-shrink:0;width:${w}px;height:${w}px`
    }
    size(slots.lead, lead, 22)
    size(slots.persist, persist && !persistIsLabel && !inPlace ? persist : null, 22)
    p.report()

    // Once the content script says where the frame is going, the pill takes
    // its place and what stays moves in, each from where it was.
    whenWide(null, () => {
      pill.classList.remove("waiting")
      placePill()
      const moveIn = (el: HTMLElement | null | undefined, slot: HTMLElement, asLabel = false) => {
        if (!el?.isConnected) return
        const from = el.getBoundingClientRect()
        // A gap of its size stays behind, so what fades out doesn't shift into the hole.
        const gap = h("span", { "aria-hidden": "true" })
        gap.style.cssText = `display:inline-block;flex-shrink:0;width:${from.width}px;height:${from.height}px`
        el.replaceWith(gap)
        const target = asLabel ? label : slot
        if (asLabel) {
          // The label itself travels; the pill's own copy of its text takes over where it lands.
          label.replaceChildren(...Array.from(el.childNodes))
          el.remove()
        } else slot.replaceWith(el)
        // Reduced motion: it fades in where it lands.
        if (reducedMotion()) return void (asLabel ? label : el).animate([{ opacity: 0 }, { opacity: 1 }], REDUCED_FADE)
        const to = (asLabel ? target : el).getBoundingClientRect()
        const dx = from.left + from.width / 2 - (to.left + to.width / 2)
        const dy = from.top + from.height / 2 - (to.top + to.height / 2)
        const scale = to.width && !asLabel ? from.width / to.width : 1
        // On the frame's springs it goes as far as the frame has (see stepFold); without them, on its own.
        if (host.springs) folding.travellers.push({ el: asLabel ? label : el, dx, dy, scale })
        else (asLabel ? label : el).animate([{ transform: `translate(${dx}px, ${dy}px) scale(${scale})` }, { transform: "none" }], spring(MENU_MOTION.foldIn))
      }
      moveIn(lead, slots.lead)
      if (persistIsLabel) moveIn(persist, slots.persist, true)
      else if (!inPlace) moveIn(persist, slots.persist)
      if (!persistIsLabel) {
        if (host.springs && !reducedMotion()) folding.label = label
        else label.animate([{ opacity: 0 }, { opacity: 1 }], timing(MENU_MOTION.pillLabel))
      }
      placePill()
    })
    return label
  }

  /** The label's width with `text` in it, measured off to the side. */
  function widthOf(label: HTMLElement, text: string): number {
    const probe = h("span", { class: label.className, "aria-hidden": "true" }, text)
    probe.style.cssText = "position:absolute;visibility:hidden;left:0;top:0"
    label.parentElement?.append(probe)
    const w = probe.getBoundingClientRect().width
    probe.remove()
    return w
  }

  /**
   * The pill says how it went. The frame always holds the pill: growing, its
   * width leads (the new width goes to the content script first, and the label
   * rolls, and the check comes in, once the frame has started toward it);
   * shrinking, the label goes first and the frame follows on the same spring.
   */
  function settle(label: HTMLElement, text: string, ok: boolean) {
    const pill = label.parentElement
    if (!pill) return
    const mark = ok ? pill.querySelector<HTMLElement>(".pill-mark") : null
    const grow = widthOf(label, text) - label.getBoundingClientRect().width + (mark ? MARK_ROOM : 0)
    const width = Math.ceil(pill.getBoundingClientRect().width + grow)
    // Only the check comes, the words staying: it opens with the frame itself, from the moment the frame starts toward it.
    if (mark && (label.dataset.text ?? label.textContent) === text && grow > 0) {
      p.report(grow)
      return whenWide(width, () => {
        mark.style.transition = "opacity 200ms ease-out 120ms"
        if (!reducedMotion()) riding.opening = mark
        p.relax()
        pill.classList.remove("failed")
        pill.classList.add("ok")
        placePill()
      })
    }
    const say = () => {
      const mark = pill.querySelector<HTMLElement>(".pill-mark")
      if (mark && !reducedMotion()) {
        const { easing, duration } = spring(0.45)
        mark.style.transition = `width ${duration}ms ${easing}, margin-left ${duration}ms ${easing}, opacity 200ms ease-out 120ms`
      }
      rollLabel(label, text)
      p.relax()
      pill.classList.toggle("ok", ok)
      pill.classList.toggle("failed", !ok)
    }
    if (grow < 0) {
      say()
      return void setTimeout(() => p.report(grow), SHRINK_WAITS_MS)
    }
    p.report(grow)
    // The frame's width springs over .37 s from when the content script hears of
    // it; the label rolls over .45 s, a beat later, so the width stays ahead.
    whenWide(width, () => setTimeout(say, WIDTH_LEAD_MS))
  }

  return { land, toCircle, fold, settle }
}
