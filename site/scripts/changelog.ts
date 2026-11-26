// Builds the changelog from the repo's changelog/ folder (see src/changelog/feed.ts): the /changelog page's data,
// as the `virtual:changelog` module, and the feeds and icons it links to, as files in the build. `vite dev` serves
// the same files and reloads when a release file changes.

import { existsSync, readdirSync, readFileSync } from "node:fs"
import { resolve } from "node:path"
import type { Plugin } from "vite"
import { atom, jsonFeed, markdownFeed, parseEntries, versionOf, type Entry } from "../src/changelog/feed"

const ID = "virtual:changelog"
const RESOLVED = `\0${ID}`
const TYPES: Record<string, string> = {
  md: "text/markdown; charset=utf-8",
  xml: "application/atom+xml; charset=utf-8",
  json: "application/feed+json; charset=utf-8",
  svg: "image/svg+xml",
}

export function changelog(dir: string): Plugin {
  const icons = resolve(dir, "icons")
  const releases = () => readdirSync(dir).filter(file => versionOf(file))
  const read = () => parseEntries(releases().map(file => ({ file, text: readFileSync(resolve(dir, file), "utf8") })))
  const files = (entries: Entry[]): Record<string, string> => {
    const out: Record<string, string> = {
      "changelog.md": markdownFeed(entries),
      "changelog/atom.xml": atom(entries),
      "changelog/feed.json": jsonFeed(entries),
    }
    for (const entry of entries) {
      if (!entry.icon) continue
      const path = resolve(icons, entry.icon)
      if (!existsSync(path)) throw new Error(`changelog/${entry.version}.md: no icon at changelog/icons/${entry.icon}`)
      out[`changelog/icons/${entry.icon}`] = readFileSync(path, "utf8")
    }
    return out
  }

  return {
    name: "deadbolt-changelog",
    resolveId: source => source === ID ? RESOLVED : undefined,
    load(id) {
      if (id !== RESOLVED) return
      for (const file of releases()) this.addWatchFile(resolve(dir, file))
      return `export const entries = ${JSON.stringify(read())}`
    },
    configureServer(server) {
      server.watcher.add(dir)
      server.watcher.on("all", (_, path) => {
        if (!path.startsWith(dir)) return
        const module = server.moduleGraph.getModuleById(RESOLVED)
        if (module) server.moduleGraph.invalidateModule(module)
        server.ws.send({ type: "full-reload" })
      })
      server.middlewares.use((req, res, next) => {
        const path = (req.url ?? "").split("?")[0]!
        // The page is changelog.html, served at /changelog as Cloudflare does.
        if (path === "/changelog") { req.url = "/changelog.html"; return next() }
        const body = files(read())[path.slice(1)]
        if (body === undefined) return next()
        res.setHeader("Content-Type", TYPES[path.split(".").pop()!] ?? "text/plain")
        res.end(body)
      })
    },
    generateBundle() {
      for (const [fileName, source] of Object.entries(files(read()))) this.emitFile({ type: "asset", fileName, source })
    },
  }
}
