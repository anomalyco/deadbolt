// Settings' About: this build's version, whether its release channel has a
// newer one, and a link that reports an issue. An unpacked extension can't
// update itself, so a newer build comes with the command that fetches it
// (`deadbolt update`, for a copy registered with `deadbolt browser install
// --standalone --extension-dir`) and a download link. Nothing here reads the
// vault: the issue carries the version, browser and OS only.

import { h, icon } from "../ui/dom"
import type { App } from "./app"
import { button, copied, glyph } from "./kit"

/** The release channel a release build was published on (scripts/build.ts); empty for a build from source. */
declare const DEADBOLT_RELEASE_CHANNEL: string | undefined

const RELEASE = "https://anoma.ly/release/deadbolt/extension"
const TARGET = "chromium-standalone"
const ISSUES = "https://github.com/anomalyco/deadbolt/issues/new"
/** The largest feed read: the service's manifests are about 1 KiB. */
const FEED_LIMIT = 64 << 10

export type Channel = "dev" | "beta" | "stable"

/**
 * Whether the Deadbolt CLI keeps this copy (`deadbolt update` writes
 * `.deadbolt-extension` beside the files it installed), so Deadbolt is on
 * this computer. It changes only what the UI suggests: the file grants
 * nothing, and its absence means a copy loaded some other way.
 */
export function fromCli(): Promise<boolean> {
  return fetch(chrome.runtime.getURL(".deadbolt-extension"), { cache: "no-store" }).then(
    (r) => r.ok,
    () => false,
  )
}

/** This build's version as its release shows it, and its channel; no channel for a build from source. */
export function thisBuild(manifest: { version: string; version_name?: string } = chrome.runtime.getManifest(), channel = typeof DEADBOLT_RELEASE_CHANNEL === "string" ? DEADBOLT_RELEASE_CHANNEL : ""): { version: string; channel: Channel | null } {
  return { version: manifest.version_name ?? manifest.version, channel: channel === "dev" || channel === "beta" || channel === "stable" ? channel : null }
}

/** Where this channel's current standalone build downloads from (the service redirects to the file). */
export const downloadLink = (channel: Channel) => `${RELEASE}/${channel}/${TARGET}`

/**
 * The version a release feed (`<channel>.json`, the release service's manifest)
 * offers for the standalone build, or null if it offers none. The feed is
 * data from the network: only a short version string is taken from it, and
 * only shown as text; the download link is ours, never the feed's.
 */
export function feedVersion(text: string, channel: Channel): string | null {
  let feed: unknown
  try {
    feed = JSON.parse(text)
  } catch {
    return null
  }
  const f = feed as { schema?: unknown; app?: unknown; artifact?: unknown; channel?: unknown; release?: { version?: unknown; targets?: Record<string, unknown> } }
  if (f?.schema !== 1 || f.app !== "deadbolt" || f.artifact !== "extension" || f.channel !== channel) return null
  const version = f.release?.version
  if (typeof version !== "string" || !/^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/.test(version)) return null
  return f.release?.targets && typeof f.release.targets[TARGET] === "object" ? version : null
}

/** Asks the release service which standalone build is current on `channel`. */
export async function latest(channel: Channel): Promise<string | null> {
  const response = await fetch(`${RELEASE}/${channel}.json`, { cache: "no-store", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" })
  if (!response.ok) throw new Error(`the release service answered ${response.status}`)
  const text = await response.text()
  if (text.length > FEED_LIMIT) throw new Error("the release feed is too large")
  return feedVersion(text, channel)
}

/** The browser and OS for an issue, e.g. "Chrome 131.0.6778.86" and "mac arm64", from the browser itself. */
async function environment(): Promise<{ browser: string; os: string }> {
  const platform = await chrome.runtime.getPlatformInfo().catch(() => null)
  const os = platform ? `${platform.os} ${platform.arch}` : "unknown"
  const data = (navigator as Navigator & { userAgentData?: { getHighEntropyValues(hints: string[]): Promise<{ fullVersionList?: Array<{ brand: string; version: string }>; platformVersion?: string }> } }).userAgentData
  const values = await data?.getHighEntropyValues(["fullVersionList", "platformVersion"]).catch(() => null)
  const brands = (values?.fullVersionList ?? []).filter((b) => !/not.?a.?brand/i.test(b.brand))
  // The specific browser (Brave, Edge, …) before the engine it shares with others.
  const brand = brands.find((b) => b.brand !== "Chromium") ?? brands[0]
  return { browser: brand ? `${brand.brand} ${brand.version}` : navigator.userAgent, os: values?.platformVersion ? `${os} (${values.platformVersion})` : os }
}

/** A new GitHub issue on anomalyco/deadbolt, labelled standalone, with this build, the browser and the OS: no vault data. */
export function issueUrl(build: { version: string; channel: Channel | null }, env: { browser: string; os: string }): string {
  const body = [
    "**What happened**",
    "",
    "",
    "**What you expected**",
    "",
    "",
    "**Steps to reproduce**",
    "",
    "",
    "---",
    `Deadbolt standalone extension ${build.version} (${build.channel ?? "built from source"})`,
    `Browser: ${env.browser}`,
    `OS: ${env.os}`,
    "",
    "<!-- Please leave out passwords, codes, usernames and other vault data. -->",
  ].join("\n")
  const query = new URLSearchParams({ labels: "standalone", title: "Standalone: ", body })
  return `${ISSUES}?${query}`
}

/** Settings' About section. */
export function aboutSection(app: App): HTMLElement {
  const build = thisBuild()
  const status = h("p", { class: "hint", "aria-live": "polite" })
  const update = h("div", { class: "update-area" })
  update.hidden = true
  if (!build.channel) status.textContent = "Built from source: it doesn't check for updates."
  else {
    const channel = build.channel
    status.textContent = "Checking for a newer build…"
    void latest(channel).then(
      (version) => {
        if (!version) return void (status.textContent = `No ${channel} release of the standalone build yet.`)
        if (version === build.version) return void (status.textContent = `Up to date on ${channel}.`)
        status.textContent = `Deadbolt ${version} is out on ${channel}.`
        status.className = "about-version"
        // A copy the CLI keeps (its marker is here) takes the command; any
        // other unpacked copy is replaced by hand.
        void fromCli().then((cli) => {
          const command = cli ? "deadbolt update" : "deadbolt browser install --standalone --extension-dir <new folder>"
          const copy = button("btn", [icon("copy"), "Copy"], (b) => void copied(b, command, (m) => app.announce(m), "Copied the command"))
          const download = h("a", { href: downloadLink(channel), target: "_blank", rel: "noreferrer" }, "download it")
          update.replaceChildren(
            h("p", { class: "muted" }, cli ? "An unpacked copy can't update itself. Run this, then reload Deadbolt in chrome://extensions:" : "An unpacked copy can't update itself. To keep it current with the Deadbolt CLI, run this, then deadbolt update, and load that folder instead:"),
            h("div", { class: "code-box" }, h("span", { class: "code" }, command), copy),
            h("p", { class: "muted" }, "Or ", download, ", unzip it in place of this copy's folder, and reload Deadbolt in chrome://extensions."),
          )
          update.hidden = false
        })
      },
      () => (status.textContent = "Couldn't reach the release service to check for updates."),
    )
  }
  const report = button("btn", [glyph("open"), "Report an issue"], async () => {
    const url = issueUrl(build, await environment())
    await chrome.tabs.create({ url })
    if (app.surface === "popup") window.close()
  })
  return h(
    "section",
    { class: "group about" },
    h("div", { class: "section-head" }, h("span", { class: "label" }, "About")),
    h("p", { class: "about-version" }, h("span", {}, "Deadbolt "), h("span", { class: "mono", id: "about-version" }, build.version), h("span", { class: "faint" }, ` · standalone${build.channel ? ` · ${build.channel}` : ""}`)),
    status,
    update,
    h("div", { class: "buttons" }, report),
  )
}
