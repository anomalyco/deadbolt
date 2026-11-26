// The changelog: one Markdown file per release in the repo's changelog/ folder, with a little YAML frontmatter
// (date, summary, an optional icon). The site build turns them into the /changelog page and three feeds: Atom,
// JSON Feed and plain Markdown. Pure functions only, so the page and the build share them.

export const SITE = "https://deadbolt.pw"
export const PAGE = `${SITE}/changelog`
export const ATOM = `${PAGE}/atom.xml`
export const JSON_FEED = `${PAGE}/feed.json`
export const MARKDOWN = `${SITE}/changelog.md`
const TITLE = "deadbolt changelog"
const DESCRIPTION = "What's new in deadbolt, the password manager with no server, newest first."

export type Entry = {
  version: string
  /** The release day, YYYY-MM-DD. */
  date: string
  summary: string
  /** A file in changelog/icons/, served at /changelog/icons/<icon>. */
  icon?: string
  /** The body as written, and as HTML. */
  markdown: string
  html: string
}

const VERSION = /^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?$/

/** A release file's name, without `.md`, when it's a version. */
export const versionOf = (file: string) => {
  const name = file.replace(/\.md$/, "")
  return file.endsWith(".md") && VERSION.test(name) ? name : undefined
}

/** Parses one release file. Throws on anything malformed, so a bad entry fails the build instead of shipping. */
export function parseEntry(file: string, text: string): Entry {
  const version = versionOf(file)
  if (!version) throw new Error(`changelog/${file}: the name must be <version>.md`)
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text)
  if (!match) throw new Error(`changelog/${file}: no --- frontmatter ---`)
  const meta: Record<string, string> = {}
  for (const line of match[1]!.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith("#")) continue
    const pair = /^([a-z]+):\s*(.*?)\s*$/.exec(line)
    if (!pair) throw new Error(`changelog/${file}: can't read frontmatter line ${JSON.stringify(line)}`)
    meta[pair[1]!] = scalar(pair[2]!)
  }
  const { date, summary, icon } = meta
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date)))
    throw new Error(`changelog/${file}: date must be YYYY-MM-DD`)
  if (!summary) throw new Error(`changelog/${file}: no summary`)
  if (icon !== undefined && !/^[a-z0-9-]+\.svg$/.test(icon)) throw new Error(`changelog/${file}: icon must be a file in icons/`)
  const markdown = match[2]!.trim()
  return { version, date, summary, icon, markdown, html: toHtml(markdown) }
}

/** A YAML scalar as frontmatter uses one: plain, "double-quoted" or 'single-quoted'. */
function scalar(raw: string) {
  if (raw.startsWith('"')) return JSON.parse(raw) as string
  if (raw.startsWith("'")) return raw.slice(1, -1).replaceAll("''", "'")
  return raw.replace(/\s+#.*$/, "")
}

/** Every release, newest first. */
export function parseEntries(files: readonly { file: string; text: string }[]): Entry[] {
  return files.filter(f => versionOf(f.file)).map(f => parseEntry(f.file, f.text)).sort((a, b) => compare(b.version, a.version))
}

function compare(a: string, b: string) {
  const [x, y] = [VERSION.exec(a)!, VERSION.exec(b)!]
  for (let i = 1; i <= 3; i++) if (x[i] !== y[i]) return Number(x[i]) - Number(y[i])
  // A prerelease sorts before its release.
  return Number(a.includes("-") ? 0 : 1) - Number(b.includes("-") ? 0 : 1) || a.localeCompare(b)
}

export const escape = (text: string) =>
  text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;")

/** The Markdown the changelog uses: paragraphs, `- ` lists, `## ` headings, **bold**, `code` and [links](url). */
export function toHtml(markdown: string) {
  return markdown.split(/\r?\n\s*\r?\n/).map(block => block.trim()).filter(Boolean).map(block => {
    const lines = block.split(/\r?\n/)
    if (lines.every(l => /^\s*- /.test(l) || /^\s{2,}\S/.test(l))) {
      const items = block.split(/\r?\n(?=\s*- )/).map(item => item.replace(/^\s*- /, "").replace(/\s*\r?\n\s*/g, " "))
      return `<ul>${items.map(item => `<li>${inline(item)}</li>`).join("")}</ul>`
    }
    const heading = /^(#{2,4}) (.*)$/.exec(block)
    if (heading && lines.length === 1) return `<h${heading[1]!.length + 1}>${inline(heading[2]!)}</h${heading[1]!.length + 1}>`
    return `<p>${inline(lines.join(" "))}</p>`
  }).join("\n")
}

/** Inline Markdown, with code spans taken literally. */
function inline(text: string) {
  return text.split(/(`[^`]+`)/).map(part => {
    if (part.startsWith("`") && part.endsWith("`") && part.length > 1) return `<code>${escape(part.slice(1, -1))}</code>`
    return escape(part)
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, label: string, href: string) => `<a href="${href}">${label}</a>`)
  }).join("")
}

/** The entry's id on the page. */
export const anchor = (entry: Entry) => `v${entry.version}`
const link = (entry: Entry) => `${PAGE}#${anchor(entry)}`
const instant = (date: string) => `${date}T00:00:00Z`
/** Relative links in a body, made absolute for readers that show it away from the site. */
const absolute = (html: string) => html.replace(/href="\//g, `href="${SITE}/`)

/** An Atom 1.0 feed (RFC 4287). */
export function atom(entries: readonly Entry[]) {
  const updated = instant(entries[0]?.date ?? "1970-01-01")
  const items = entries.map(e => `  <entry>
    <title>deadbolt ${escape(e.version)}</title>
    <link rel="alternate" type="text/html" href="${link(e)}"/>
    <id>${link(e)}</id>
    <published>${instant(e.date)}</published>
    <updated>${instant(e.date)}</updated>
    <summary>${escape(e.summary)}</summary>
    <content type="html">${escape(absolute(e.html))}</content>
  </entry>`).join("\n")
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en-US">
  <title>${TITLE}</title>
  <subtitle>${escape(DESCRIPTION)}</subtitle>
  <link rel="self" type="application/atom+xml" href="${ATOM}"/>
  <link rel="alternate" type="text/html" href="${PAGE}"/>
  <id>${PAGE}</id>
  <updated>${updated}</updated>
  <author><name>Anomaly</name><uri>https://anoma.ly</uri></author>
  <icon>${SITE}/icon-192.png</icon>
  <logo>${SITE}/icon-512.png</logo>
${items}
</feed>
`
}

/** A JSON Feed 1.1 (https://jsonfeed.org/version/1.1). */
export function jsonFeed(entries: readonly Entry[]) {
  return JSON.stringify({
    version: "https://jsonfeed.org/version/1.1",
    title: TITLE,
    home_page_url: PAGE,
    feed_url: JSON_FEED,
    description: DESCRIPTION,
    icon: `${SITE}/icon-512.png`,
    favicon: `${SITE}/favicon-32.png`,
    language: "en-US",
    authors: [{ name: "Anomaly", url: "https://anoma.ly" }],
    items: entries.map(e => ({
      id: link(e),
      url: link(e),
      title: `deadbolt ${e.version}`,
      summary: e.summary,
      content_html: absolute(e.html),
      date_published: instant(e.date),
    })),
  }, null, 2) + "\n"
}

/** Every release as one Markdown file, for reading as text. */
export function markdownFeed(entries: readonly Entry[]) {
  const head = `# ${TITLE}\n\n${DESCRIPTION} Also at ${PAGE}, and as Atom (${ATOM}) and JSON Feed (${JSON_FEED}).\n`
  return [head, ...entries.map(e => `## ${e.version} (${e.date})\n\n${e.summary}\n\n${e.markdown.replace(/^(#{2,5}) /gm, "#$1 ")}\n`)].join("\n")
}
