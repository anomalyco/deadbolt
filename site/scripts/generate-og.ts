#!/usr/bin/env bun
// Deterministic generator for Deadbolt's 1200x630 Open Graph cards and PNG icon set.
// Uses local bundled fonts (site/public/fonts/*.woff2), headless Chromium for OG cards,
// and resvg for rasterized icons from site/public/favicon.svg.

import { execFileSync } from "node:child_process"
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { pathToFileURL } from "node:url"

const siteDir = resolve(import.meta.dirname, "..")
const publicDir = join(siteDir, "public")
const fontsDir = join(publicDir, "fonts")

function fontDataUri(filename: string): string {
  const bytes = readFileSync(join(fontsDir, filename))
  return `data:font/woff2;base64,${bytes.toString("base64")}`
}

// Use ibm-plex-mono-400.woff2 (full ASCII subset) for both regular and medium weights
// so no glyph ever falls back to a system serif font.
const ibmPlexMono400 = fontDataUri("ibm-plex-mono-400.woff2")
const anton400 = fontDataUri("anton.woff2")

const fontCss = `
@font-face {
  font-family: "Anton";
  src: url("${anton400}") format("woff2");
  font-weight: 400;
  font-style: normal;
}
@font-face {
  font-family: "IBM Plex Mono";
  src: url("${ibmPlexMono400}") format("woff2");
  font-weight: 400;
  font-style: normal;
}
@font-face {
  font-family: "IBM Plex Mono";
  src: url("${ibmPlexMono400}") format("woff2");
  font-weight: 500;
  font-style: normal;
}
`

// Deterministic halftone cluster echoing KeyholePrint on the landing page:
// dense red core around a razor-sharp black keyhole silhouette, dissolving radially.
function keyholePrintSvg(size: number, seed = 42): string {
  const cols = 44
  const cell = 100 / cols
  let state = seed >>> 0
  const rand = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0
    return state / 0xffffffff
  }
  const dots: string[] = []
  for (let row = 0; row < cols; row++) {
    for (let col = 0; col < cols; col++) {
      const cx = (col + 0.5) * cell
      const cy = (row + 0.5) * cell
      const dx = cx - 50
      const dy = cy - 50
      const dist = Math.hypot(dx, dy)
      if (dist > 49) continue
      // Signed distance outside the keyhole cutout so the rim stays crisp and solid.
      const inCircle = Math.hypot(cx - 50, cy - 37.5) < 13.8
      const inStem = cy >= 45.5 && cy <= 78.5 && Math.abs(cx - 50) < 5.6 + ((cy - 45.5) / 33) * 5.8
      if (inCircle || inStem) continue

      const rimBoost =
        Math.hypot(cx - 50, cy - 37.5) < 22 ||
        (cy >= 43 && cy <= 82 && Math.abs(cx - 50) < 16)
          ? 0.42
          : 0
      const radial = Math.max(0, 1 - dist / 49)
      const p = Math.min(1, Math.pow(radial, 0.85) * 1.05 + rimBoost)
      if (rand() < p) {
        const s = cell * (0.76 + 0.24 * radial)
        dots.push(
          `<rect x="${(cx - s / 2).toFixed(2)}" y="${(cy - s / 2).toFixed(2)}" width="${s.toFixed(2)}" height="${s.toFixed(2)}" fill="#ff2a2a" />`,
        )
      }
    }
  }
  return `<svg width="${size}" height="${size}" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" shape-rendering="crispEdges">
    <rect width="100" height="100" fill="#000000" />
    ${dots.join("")}
    <circle cx="50" cy="37.5" r="13.2" fill="#000000" />
    <path d="M44.8 45.5H55.2L60.8 78H39.2Z" fill="#000000" />
  </svg>`
}

function keyholeMarkSvg(size: number): string {
  return `<svg width="${size}" height="${size}" viewBox="0 0 1024 1024" xmlns="http://www.w3.org/2000/svg">
    <rect x="24" y="24" width="976" height="976" rx="180" fill="#0a0a0a" stroke="#2c2c2c" stroke-width="24" />
    <circle cx="512" cy="382" r="158" fill="#ff2a2a" />
    <path d="M451 490H573L632 780H392Z" fill="#ff2a2a" />
  </svg>`
}

function landingOgHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<style>
${fontCss}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  width: 1200px;
  height: 630px;
  overflow: hidden;
  background: #000000;
  color: #ffffff;
  font-family: "IBM Plex Mono", ui-monospace, Menlo, monospace;
  -webkit-font-smoothing: antialiased;
}
.frame {
  width: 1200px;
  height: 630px;
  padding: 74px 104px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  position: relative;
}
.hairline-frame {
  position: absolute;
  inset: 28px;
  border: 1px solid #1a1a1a;
  pointer-events: none;
}
.top-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 16px;
  letter-spacing: 0.04em;
  color: #7a766f;
}
.top-meta .url {
  color: #e8e4dc;
}
.status {
  display: flex;
  align-items: center;
  gap: 10px;
}
.dot {
  width: 8px;
  height: 8px;
  background: #ff2a2a;
  display: inline-block;
}
.hero {
  display: flex;
  flex-direction: column;
  gap: 28px;
}
.lockup {
  display: flex;
  align-items: center;
  gap: 32px;
}
.keyhole-box {
  width: 172px;
  height: 172px;
  flex: none;
  display: flex;
  align-items: center;
  justify-content: center;
}
.wordmark-wrap {
  flex: 1;
  display: flex;
  flex-direction: column;
  justify-content: center;
}
.wordmark {
  display: block;
  width: 100%;
  height: 172px;
  color: #ff2a2a;
  font-family: "Anton", sans-serif;
  overflow: visible;
}
.tagline-row {
  display: flex;
  align-items: center;
  gap: 20px;
  color: #ff2a2a;
  font-size: 22px;
  letter-spacing: 0.22em;
  text-transform: uppercase;
}
.tagline-row .dots {
  flex: 1;
  border-bottom: 2px dotted rgba(255, 42, 42, 0.5);
  height: 1px;
}
.bottom {
  padding-top: 26px;
  border-top: 1px dotted #383838;
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 24px;
}
.subtitle {
  font-size: 24px;
  color: #e8e4dc;
  letter-spacing: -0.01em;
}
.badge {
  font-size: 16px;
  color: #7a766f;
  white-space: nowrap;
}
</style>
</head>
<body>
  <div class="frame">
    <div class="hairline-frame"></div>
    <div class="top-meta">
      <span class="url">deadbolt.pw</span>
      <span class="status"><span class="dot"></span>end-to-end encrypted · peer-to-peer</span>
    </div>
    <div class="hero">
      <div class="lockup">
        <div class="keyhole-box">${keyholePrintSvg(172, 42)}</div>
        <div class="wordmark-wrap">
          <svg class="wordmark" viewBox="0 0 788 172" preserveAspectRatio="none">
            <text x="0" y="159" textLength="788" lengthAdjust="spacingAndGlyphs" font-family="Anton" font-size="188" fill="#ff2a2a">DEADBOLT</text>
          </svg>
        </div>
      </div>
      <div class="tagline-row">
        <span>secrets kept</span>
        <span class="dots"></span>
        <span>for ever</span>
      </div>
    </div>
    <div class="bottom">
      <div class="subtitle">local-first password manager · no server</div>
      <div class="badge">iroh · rust</div>
    </div>
  </div>
</body>
</html>`
}

function architectureOgHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<style>
${fontCss}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  width: 1200px;
  height: 630px;
  overflow: hidden;
  background: #000000;
  color: #ffffff;
  font-family: "IBM Plex Mono", ui-monospace, Menlo, monospace;
  -webkit-font-smoothing: antialiased;
}
.frame {
  width: 1200px;
  height: 630px;
  padding: 72px 104px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  position: relative;
}
.hairline-frame {
  position: absolute;
  inset: 28px;
  border: 1px solid #1a1a1a;
  pointer-events: none;
}
.top-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 16px;
  letter-spacing: 0.04em;
  color: #7a766f;
}
.top-meta .url {
  color: #e8e4dc;
}
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
}
.header-left {
  display: flex;
  align-items: center;
  gap: 24px;
}
.title-line {
  display: flex;
  align-items: baseline;
  gap: 22px;
  font-family: "Anton", sans-serif;
  font-size: 82px;
  line-height: 1;
  letter-spacing: 0.02em;
  text-transform: uppercase;
}
.title-brand { color: #ff2a2a; }
.title-dash { color: #4a4844; position: relative; top: -6px; }
.title-page { color: #ffffff; }
.diagram {
  width: 100%;
  display: block;
}
.bottom {
  padding-top: 24px;
  border-top: 1px dotted #383838;
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 24px;
}
.topics {
  font-size: 22px;
  color: #e8e4dc;
  letter-spacing: -0.01em;
}
.topics .sep {
  color: #ff2a2a;
  margin: 0 2px;
}
.badge {
  font-size: 16px;
  color: #7a766f;
  white-space: nowrap;
}
</style>
</head>
<body>
  <div class="frame">
    <div class="hairline-frame"></div>
    <div class="top-meta">
      <span class="url">deadbolt.pw/architecture/</span>
      <span>architecture walkthrough</span>
    </div>
    <div class="header">
      <div class="header-left">
        ${keyholeMarkSvg(84)}
        <div class="title-line">
          <span class="title-brand">DEADBOLT</span>
          <span class="title-dash">—</span>
          <span class="title-page">HOW IT WORKS</span>
        </div>
      </div>
    </div>
    <svg class="diagram" viewBox="0 0 992 160" xmlns="http://www.w3.org/2000/svg">
      <!-- Left device -->
      <rect x="1" y="14" width="276" height="132" fill="#050505" stroke="#383838" stroke-width="1.5" />
      <rect x="7" y="20" width="264" height="120" fill="none" stroke="#1f1f1f" stroke-width="1" />
      <text x="26" y="54" fill="#ffffff" font-family="IBM Plex Mono, monospace" font-size="18">device a</text>
      <text x="252" y="54" text-anchor="end" fill="#ff2a2a" font-family="IBM Plex Mono, monospace" font-size="14">ed25519</text>
      <line x1="26" y1="71" x2="252" y2="71" stroke="#262626" stroke-dasharray="2 4" />
      <text x="26" y="98" fill="#a8a39a" font-family="IBM Plex Mono, monospace" font-size="14">signed log  #01 → #02</text>
      <text x="26" y="123" fill="#706d66" font-family="IBM Plex Mono, monospace" font-size="13">local redb · argon2id</text>

      <!-- Wire 1 -->
      <line x1="277" y1="80" x2="358" y2="80" stroke="#383838" stroke-width="1.5" />
      <rect x="287" y="66" width="62" height="28" fill="#000000" />
      <text x="318" y="85" text-anchor="middle" fill="#ff2a2a" font-family="IBM Plex Mono, monospace" font-size="13">SEALED</text>

      <!-- Middle gate -->
      <rect x="358" y="14" width="276" height="132" fill="#050505" stroke="#ff2a2a" stroke-width="1.5" stroke-opacity="0.75" />
      <rect x="364" y="20" width="264" height="120" fill="none" stroke="#2c1414" stroke-width="1" />
      <text x="383" y="54" fill="#ffffff" font-family="IBM Plex Mono, monospace" font-size="18">membership gate</text>
      <line x1="383" y1="71" x2="609" y2="71" stroke="#2c1414" stroke-dasharray="2 4" />
      <text x="383" y="98" fill="#e8e4dc" font-family="IBM Plex Mono, monospace" font-size="14">iroh direct · e2e</text>
      <text x="383" y="123" fill="#ff2a2a" font-family="IBM Plex Mono, monospace" font-size="13">refuse non-members</text>

      <!-- Wire 2 -->
      <line x1="634" y1="80" x2="715" y2="80" stroke="#383838" stroke-width="1.5" />
      <rect x="649" y="66" width="52" height="28" fill="#000000" />
      <text x="675" y="85" text-anchor="middle" fill="#ff2a2a" font-family="IBM Plex Mono, monospace" font-size="13">SYNC</text>

      <!-- Right device -->
      <rect x="715" y="14" width="276" height="132" fill="#050505" stroke="#383838" stroke-width="1.5" />
      <rect x="721" y="20" width="264" height="120" fill="none" stroke="#1f1f1f" stroke-width="1" />
      <text x="740" y="54" fill="#ffffff" font-family="IBM Plex Mono, monospace" font-size="18">device b</text>
      <text x="966" y="54" text-anchor="end" fill="#ff2a2a" font-family="IBM Plex Mono, monospace" font-size="14">ed25519</text>
      <line x1="740" y1="71" x2="966" y2="71" stroke="#262626" stroke-dasharray="2 4" />
      <text x="740" y="98" fill="#a8a39a" font-family="IBM Plex Mono, monospace" font-size="14">heads diff · merge</text>
      <text x="740" y="123" fill="#706d66" font-family="IBM Plex Mono, monospace" font-size="13">6-digit pair code</text>
    </svg>
    <div class="bottom">
      <div class="topics">devices <span class="sep">·</span> keys <span class="sep">·</span> signed logs <span class="sep">·</span> sync <span class="sep">·</span> pairing</div>
      <div class="badge">no server</div>
    </div>
  </div>
</body>
</html>`
}

function findChrome(): string {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) {
    return process.env.CHROME_PATH
  }
  const cacheRoots = [
    join(homedir(), "Library/Caches/ms-playwright"),
    join(homedir(), ".cache/ms-playwright"),
  ]
  for (const root of cacheRoots) {
    if (!existsSync(root)) continue
    for (const entry of readdirSync(root).sort().reverse()) {
      if (!entry.startsWith("chromium_headless_shell-") && !entry.startsWith("chromium-")) continue
      const candidates = [
        join(root, entry, "chrome-headless-shell-mac-arm64/chrome-headless-shell"),
        join(root, entry, "chrome-headless-shell-mac-x64/chrome-headless-shell"),
        join(root, entry, "chrome-headless-shell-linux/chrome-headless-shell"),
        join(root, entry, "chrome-mac/Chromium.app/Contents/MacOS/Chromium"),
        join(root, entry, "chrome-linux/chrome"),
      ]
      for (const candidate of candidates) {
        if (existsSync(candidate)) return candidate
      }
    }
  }
  const systemCandidates = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
  ]
  for (const candidate of systemCandidates) {
    if (existsSync(candidate)) return candidate
  }
  throw new Error("No headless Chromium binary found. Set CHROME_PATH or install Playwright Chromium.")
}

function renderCard(chrome: string, tmp: string, name: string, html: string, outPath: string): void {
  const htmlPath = join(tmp, `${name}.html`)
  writeFileSync(htmlPath, html, "utf8")
  execFileSync(
    chrome,
    [
      "--headless",
      "--disable-gpu",
      "--no-sandbox",
      "--hide-scrollbars",
      "--force-device-scale-factor=1",
      "--window-size=1200,630",
      `--screenshot=${outPath}`,
      pathToFileURL(htmlPath).href,
    ],
    { stdio: "pipe" },
  )
}

// Full-bleed opaque black icon SVG for iOS/PWA icons (Apple & Android apply their own rounding).
const opaqueIconSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">
  <rect width="1024" height="1024" fill="#000000"/>
  <circle cx="512" cy="382" r="160" fill="#ff2a2a"/>
  <path d="M451 490H573L632 780H392Z" fill="#ff2a2a"/>
</svg>
`

function renderIcons(tmp: string): void {
  const faviconSvg = join(publicDir, "favicon.svg")
  const opaqueSvg = join(tmp, "icon-opaque.svg")
  writeFileSync(opaqueSvg, opaqueIconSvg, "utf8")

  const targets: Array<[string, number, string]> = [
    [faviconSvg, 32, join(publicDir, "favicon-32.png")],
    [opaqueSvg, 180, join(publicDir, "apple-touch-icon.png")],
    [opaqueSvg, 192, join(publicDir, "icon-192.png")],
    [opaqueSvg, 512, join(publicDir, "icon-512.png")],
  ]
  for (const [src, size, out] of targets) {
    execFileSync("resvg", ["-w", String(size), "-h", String(size), src, out], { stdio: "pipe" })
  }
}

const tmp = mkdtempSync(join(tmpdir(), "deadbolt-og-"))
try {
  const chrome = findChrome()
  renderCard(chrome, tmp, "og", landingOgHtml(), join(publicDir, "og.png"))
  renderCard(chrome, tmp, "og-architecture", architectureOgHtml(), join(publicDir, "og-architecture.png"))
  renderIcons(tmp)
} finally {
  rmSync(tmp, { recursive: true, force: true })
}

const outputs = [
  "og.png",
  "og-architecture.png",
  "favicon-32.png",
  "apple-touch-icon.png",
  "icon-192.png",
  "icon-512.png",
]
for (const file of outputs) {
  const bytes = statSync(join(publicDir, file)).size
  console.log(`${file.padEnd(22)} ${(bytes / 1024).toFixed(1)} KB`)
}
