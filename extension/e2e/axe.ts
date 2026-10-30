// axe-core for the e2e runs: injected into a page or an extension frame (the
// inline menu's frame included) over DevTools, so the extension pages' CSP
// doesn't stand in its way, and run against WCAG 2.2 A and AA plus axe's best
// practices. Each surface is checked in the state it's in when asked.

import type { Frame, Page } from "playwright-core"

const source = await Bun.file(require.resolve("axe-core/axe.min.js")).text()

/** One rule axe found broken, with where. */
export interface Violation {
  id: string
  impact: string | null
  help: string
  targets: string[]
  /** What axe says about the first node, e.g. the contrast ratio it measured. */
  detail: string
}

/**
 * Rules that don't fit what's checked:
 * - region, landmark-one-main, page-has-heading-one: the inline menu, the
 *   pill and the save offer are small surfaces in a frame inside someone
 *   else's page, not documents of their own.
 */
const SURFACE_ONLY = ["region", "landmark-one-main", "page-has-heading-one"]

/**
 * Places a rule doesn't fit, by rule and selector:
 * - label-content-name-mismatch on the setup choices (.choice): each is named
 *   by its title (aria-labelledby) and described by the line under it
 *   (aria-describedby). The visible label is the name, so WCAG 2.5.3 holds;
 *   axe counts the description's text as label too.
 */
const NOT_APPLICABLE: Array<[string, string]> = [["label-content-name-mismatch", ".choice"]]

/** Runs axe in `target` (a page or a frame) and answers what it found. `surface`: a frame in a page, not a page of its own. */
export async function axe(target: Page | Frame, surface = false): Promise<Violation[]> {
  const loaded = await target.evaluate(() => typeof (globalThis as unknown as { axe?: unknown }).axe === "object")
  if (!loaded) await target.evaluate(source)
  const disabled = surface ? SURFACE_ONLY : []
  return target.evaluate(async ([disabled, skip]) => {
    const axe = (globalThis as unknown as { axe: { run: (ctx: unknown, options: unknown) => Promise<{ violations: Array<{ id: string; impact: string | null; help: string; nodes: Array<{ target: unknown[]; failureSummary?: string; any: Array<{ message: string }> }> }> }> } }).axe
    const result = await axe.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] },
      rules: Object.fromEntries(disabled.map((id) => [id, { enabled: false }])),
      resultTypes: ["violations"],
    })
    for (const v of result.violations) v.nodes = v.nodes.filter((n) => !skip.some(([rule, selector]) => rule === v.id && n.target.every((t) => document.querySelector(String(t))?.matches(selector))))
    return result.violations.filter((v) => v.nodes.length).map((v) => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      targets: v.nodes.map((n) => n.target.map(String).join(" ")),
      detail: v.nodes[0]?.any[0]?.message ?? v.nodes[0]?.failureSummary ?? "",
    }))
  }, [disabled, NOT_APPLICABLE] as const)
}

/** A violation as one line: rule, impact, how many places, the first place and what axe measured there. */
export const describe = (v: Violation) => `${v.id} (${v.impact}, ${v.targets.length}×) ${v.targets[0]}${v.detail ? `: ${v.detail}` : ""}`
