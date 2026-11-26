# Changelog

One file per release, `<version>.md`, newest at the top of the site's
`/changelog` page and its feeds (`/changelog/atom.xml`, `/changelog/feed.json`,
`/changelog.md`). The site build (`site/scripts/changelog.ts`) reads them and
fails on a malformed entry.

```md
---
date: 2026-11-25            # the release day, YYYY-MM-DD
summary: "One line on what the release is."  # quoted, so a colon in it is fine
icon: first-release.svg     # optional, from icons/
---

A short paragraph, then a list. Markdown here is paragraphs, `- ` lists,
`## ` headings, **bold**, `code` and [links](https://example.com).
```
