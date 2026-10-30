import { describe, expect, test } from "bun:test"
import { sanitizeSvg, MAX_SVG_BYTES } from "../src/ui/svg-safe"
import { pageIconOf, SiteIcons } from "../src/bg/site-icons"
import { fakeHost, installChrome } from "./chrome"
import { BAYER8, brandFor, ditherFrame } from "../src/ui/site-icon"
import { iconSettingsOf } from "../src/ui/icon-store"

const wrap = (inner: string, attrs = 'viewBox="0 0 24 24"') => `<svg xmlns="http://www.w3.org/2000/svg" ${attrs}>${inner}</svg>`
const clean = (inner: string, attrs?: string) => sanitizeSvg(wrap(inner, attrs)) ?? ""

// A site's icon markup is the site's to write: whatever it puts there must
// come out as shapes and nothing else.
describe("sanitizeSvg", () => {
  test("keeps shapes, paint and gradients", () => {
    const out = clean('<defs><linearGradient id="g"><stop offset="0" stop-color="#f00"/></linearGradient></defs><path d="M0 0h24v24H0z" fill="url(#g)"/><circle cx="12" cy="12" r="4" fill="#000"/>')
    expect(out).toContain("<path")
    expect(out).toContain('fill="url(#g)"')
    expect(out).toContain("<circle")
    expect(out).toContain("linearGradient")
  })

  test("drops scripts, foreignObject, style, images, use and text", () => {
    const out = clean(
      '<script>alert(1)</script><foreignObject><div xmlns="http://www.w3.org/1999/xhtml">evil</div></foreignObject><style>path{fill:url(https://evil.test/x)}</style><image href="https://evil.test/a.png"/><use href="https://evil.test/s.svg#a"/><text>hi</text><a href="javascript:alert(1)"><path d="M0 0h1v1z"/></a><path d="M1 1h2v2z"/>',
    )
    for (const bad of ["script", "foreignObject", "div", "style", "image", "use", "text", "<a", "evil", "javascript"]) expect(out).not.toContain(bad)
    expect(out).toContain('d="M1 1h2v2z"')
  })

  test("drops event handlers, links and style attributes", () => {
    const out = clean('<path d="M0 0h1v1z" onload="alert(1)" onclick="x()" style="fill:red" xlink:href="https://evil.test" href="https://evil.test" xmlns:xlink="http://www.w3.org/1999/xlink"/>', 'viewBox="0 0 24 24" onload="alert(1)"')
    for (const bad of ["onload", "onclick", "style", "href", "evil"]) expect(out).not.toContain(bad)
  })

  test("references only to the icon itself", () => {
    expect(clean('<path d="M0 0h1v1z" fill="url(https://evil.test/p.svg#g)"/>')).not.toContain("evil")
    expect(clean('<path d="M0 0h1v1z" fill="url(data:image/svg+xml,x)"/>')).not.toContain("data:")
    expect(clean('<path d="M0 0h1v1z" mask="url( #m )"/>')).toContain("mask=")
    expect(clean('<path d="M0 0h1v1z" fill="url(#g) #f00"/>')).toContain('fill="url(#g) #f00"')
    expect(clean('<path d="M0 0h1v1z" fill="url(#g) url(evil.svg#x)"/>')).not.toContain("fill=")
    expect(clean('<path d="M0 0h1v1z" fill="url(#g) rgb(1,2,3)"/>')).not.toContain("fill=")
  })

  test("refuses entity tricks, other roots, broken markup and the oversized", () => {
    expect(sanitizeSvg('<!DOCTYPE svg [<!ENTITY x "&#60;script&#62;">]>' + wrap('<path d="M0 0h1v1z"/>'))).toBeNull()
    expect(sanitizeSvg('<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>')).toBeNull()
    expect(sanitizeSvg("<svg")).toBeNull()
    expect(sanitizeSvg(wrap(`<path d="M0 0${" h1".repeat(MAX_SVG_BYTES / 3)}z"/>`))).toBeNull()
    expect(sanitizeSvg(wrap("<script>x</script>"))).toBeNull()
  })

  test("a drawing with no viewBox gets one from its size", () => {
    expect(clean('<path d="M0 0h1v1z"/>', 'width="32" height="16"')).toContain('viewBox="0 0 32 16"')
    expect(clean('<path d="M0 0h1v1z"/>', "")).toBe("")
  })
})

describe("what the background keeps", () => {
  test("only an icon's own shape from the content script", () => {
    expect(pageIconOf({ svg: "<svg/>", mask: true, color: "#123456", extra: 1 })).toEqual({ svg: "<svg/>", mask: true, color: "#123456" })
    expect(pageIconOf({ svg: "<svg/>", color: "url(x)" })).toEqual({ svg: "<svg/>" })
    expect(pageIconOf({ svg: "<img src=x>" })).toBeNull()
    expect(pageIconOf({ svg: "<svg" + " ".repeat(MAX_SVG_BYTES) })).toBeNull()
    expect(pageIconOf("x")).toBeNull()
  })

})

// Reading a site's icon tells the site nothing only once Deadbolt filled or
// saw a sign-in there; and never from an incognito tab.
describe("when an icon is read", () => {
  const asked = (fake: ReturnType<typeof installChrome>) => fake.delivered.filter((d) => d.message.type === "db:site-icon").length

  test("after a fill on the top page's site, from that exact document", async () => {
    const fake = installChrome()
    await new SiteIcons(fakeHost().host).used(1, "example.com")
    expect(asked(fake)).toBe(1)
    expect(fake.delivered.find((d) => d.message.type === "db:site-icon")?.options).toEqual({ documentId: "top-doc" })
  })

  test("never from an incognito tab", async () => {
    const fake = installChrome()
    ;(fake.tabs[1] as { incognito?: boolean }).incognito = true
    await new SiteIcons(fakeHost().host).used(1, "example.com")
    expect(asked(fake)).toBe(0)
  })

  test("never for another site than the one filled, or with both settings off", async () => {
    let fake = installChrome()
    await new SiteIcons(fakeHost().host).used(1, "evil.test")
    expect(asked(fake)).toBe(0)
    fake = installChrome()
    fake.local.siteIconsMenu = false
    fake.local.siteIconsVault = false
    await new SiteIcons(fakeHost().host).used(1, "example.com")
    expect(asked(fake)).toBe(0)
  })

  test("a page with no cached icon isn't asked again for a while, by a salted hash", async () => {
    const fake = installChrome()
    fake.answer = () => null
    const icons = new SiteIcons(fakeHost().host)
    await icons.used(1, "example.com")
    await icons.used(1, "example.com")
    expect(asked(fake)).toBe(1)
    expect(JSON.stringify(fake.session)).not.toContain("example.com")
  })
})

describe("settings", () => {
  test("menu icons default off, vault icons default on", () => {
    expect(iconSettingsOf({})).toEqual({ menu: false, vault: true })
    expect(iconSettingsOf({ siteIconsMenu: true, siteIconsVault: false })).toEqual({ menu: true, vault: false })
  })
})

describe("Simple Icons", () => {
  const icons = { domains: { "google.com": "google", "github.com": "github" }, brands: { google: ["Google", "4285F4", "M0 0"], github: ["GitHub", "181717", "M1 1"] } } as Parameters<typeof brandFor>[0]
  test("a host's own domain, or the nearest parent in the set", () => {
    expect(brandFor(icons, "accounts.google.com")?.[0]).toBe("Google")
    expect(brandFor(icons, "www.github.com")?.[0]).toBe("GitHub")
    expect(brandFor(icons, "github.com.evil.test")).toBeNull()
    expect(brandFor(icons, "notgithub.com")).toBeNull()
  })
})

describe("the dither reveal", () => {
  test("Bayer 8×8 has every threshold once", () => {
    expect([...BAYER8].sort((a, b) => a - b)).toEqual(Array.from({ length: 64 }, (_, i) => i))
  })

  test("nothing at the start, the whole icon over the tile at the end", () => {
    const size = 16
    const icon = new Uint8ClampedArray(size * size * 4)
    for (let i = 0; i < icon.length; i += 4) icon.set(i % 8 ? [200, 10, 10, 255] : [0, 0, 0, 0], i)
    const out = new Uint8ClampedArray(icon.length)
    ditherFrame(out, icon, size, 2, 0, [50, 50, 50, 255], [240, 240, 240, 255])
    expect(out.every((v, i) => i % 4 !== 3 || v === 0)).toBe(true)
    ditherFrame(out, icon, size, 2, 1, [50, 50, 50, 255], [240, 240, 240, 255])
    for (let i = 0; i < icon.length; i += 4) expect([...out.slice(i, i + 4)]).toEqual(icon[i + 3] ? [200, 10, 10, 255] : [240, 240, 240, 255])
  })

  test("halfway, some dots show and some don't, a CSS pixel at a time", () => {
    const size = 32
    const icon = new Uint8ClampedArray(size * size * 4).fill(255)
    const out = new Uint8ClampedArray(icon.length)
    ditherFrame(out, icon, size, 2, 0.3, [0, 0, 0, 255], [255, 255, 255, 255])
    const shown = (x: number, y: number) => out[(y * size + x) * 4 + 3] > 0
    let n = 0
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (shown(x, y)) n++
    expect(n).toBeGreaterThan(0)
    expect(n).toBeLessThan(size * size)
    // Each 2×2 device block is one dot.
    for (let y = 0; y < size; y += 2) for (let x = 0; x < size; x += 2) expect(shown(x + 1, y + 1)).toBe(shown(x, y))
  })
})
