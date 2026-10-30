import { describe, expect, test } from "bun:test"
import { paymentProvider, securePage } from "../src/payments"
import { fillableOrigin, saveTitle, saveUrl, sameSite, sameSiteChain, senderOrigin, siteOf } from "../src/bg/site"

const u = (s: string) => new URL(s)

describe("fillableOrigin", () => {
  test("https pages", () => {
    expect(fillableOrigin(u("https://github.com/login"))).toBe(true)
    expect(fillableOrigin(u("https://127.0.0.1:8443/"))).toBe(true)
  })

  test("plain http only on local development hosts", () => {
    expect(fillableOrigin(u("http://example.com/login"))).toBe(false)
    expect(fillableOrigin(u("http://192.168.1.10/"))).toBe(false)
    expect(fillableOrigin(u("http://localhost:3000/"))).toBe(true)
    expect(fillableOrigin(u("http://127.0.0.1:5173/"))).toBe(true)
    expect(fillableOrigin(u("http://app.localhost/"))).toBe(true)
    expect(fillableOrigin(u("http://shop.test/"))).toBe(true)
  })

  test("local hosts may end with a dot", () => {
    expect(fillableOrigin(u("http://localhost.:3000/"))).toBe(true)
    expect(fillableOrigin(u("http://app.localhost./"))).toBe(true)
    expect(fillableOrigin(u("http://shop.test./"))).toBe(true)
    expect(fillableOrigin(u("http://localhost.evil.com/"))).toBe(false)
    expect(fillableOrigin(u("http://example.com./"))).toBe(false)
  })

  test("other schemes never", () => {
    expect(fillableOrigin(u("file:///Users/kit/login.html"))).toBe(false)
    expect(fillableOrigin(u("chrome://settings/"))).toBe(false)
    expect(fillableOrigin(u("data:text/html,<input type=password>"))).toBe(false)
  })
})

describe("senderOrigin", () => {
  test("the frame's URL when it matches the browser's origin", () => {
    expect(senderOrigin({ url: "https://github.com/login?x=1", origin: "https://github.com" })?.origin).toBe("https://github.com")
  })

  test("sandboxed frames (opaque origin) get nothing", () => {
    expect(senderOrigin({ url: "https://github.com/login", origin: "null" })).toBeNull()
  })

  test("a URL that disagrees with the origin gets nothing", () => {
    // about:blank and srcdoc frames inherit the parent's origin.
    expect(senderOrigin({ url: "about:blank", origin: "https://github.com" })).toBeNull()
    expect(senderOrigin({ url: "https://evil.com/", origin: "https://github.com" })).toBeNull()
  })

  test("missing fields get nothing", () => {
    expect(senderOrigin({ url: "https://github.com/" })).toBeNull()
    expect(senderOrigin({ origin: "https://github.com" })).toBeNull()
  })
})

describe("siteOf", () => {
  test("registrable domains", () => {
    expect(siteOf("github.com")).toBe("github.com")
    expect(siteOf("gist.github.com")).toBe("github.com")
    expect(siteOf("accounts.google.co.uk")).toBe("google.co.uk")
    expect(siteOf("WWW.Example.COM.")).toBe("example.com")
  })

  test("private suffixes keep tenants apart", () => {
    expect(siteOf("alice.github.io")).toBe("alice.github.io")
    expect(siteOf("bob.github.io")).toBe("bob.github.io")
  })

  test("IPs, localhost and single labels are their own site", () => {
    expect(siteOf("127.0.0.1")).toBe("127.0.0.1")
    expect(siteOf("localhost")).toBe("localhost")
    expect(siteOf("[::1]")).toBe("[::1]")
  })

  test("a public suffix itself has no site", () => {
    expect(siteOf("co.uk")).toBeNull()
    expect(siteOf("github.io")).toBeNull()
  })
})

describe("sameSite", () => {
  test("subdomains of one site", () => {
    expect(sameSite(u("https://auth.example.com/frame"), u("https://www.example.com/"))).toBe(true)
  })

  test("another site's frame", () => {
    expect(sameSite(u("https://ads.tracker.net/"), u("https://example.com/"))).toBe(false)
  })

  test("tenants of a shared host are different sites", () => {
    expect(sameSite(u("https://bob.github.io/"), u("https://alice.github.io/"))).toBe(false)
  })

  test("a frame on a public suffix matches nothing", () => {
    expect(sameSite(u("https://github.io/"), u("https://github.io/"))).toBe(false)
  })
})

describe("saveTitle", () => {
  test("names the site, not the page's action", () => {
    expect(saveTitle("Sign in to GitHub · GitHub", "github.com")).toBe("GitHub")
    expect(saveTitle("Log in | Linear", "linear.app")).toBe("Linear")
    expect(saveTitle("Create your account · Acme", "vogel.dev")).toBe("Acme")
    expect(saveTitle("Sign in - Google Accounts", "google.com")).toBe("Google Accounts")
    expect(saveTitle("Amazon Sign-In", "amazon.com")).toBe("Amazon")
    expect(saveTitle("Kit's Notes", "notes.example")).toBe("Kit's Notes")
    expect(saveTitle("Pay-as-you-go plans", "example.com")).toBe("Pay-as-you-go plans")
  })

  test("the page title, tidied", () => {
    expect(saveTitle("  Sign in \n\t to   Acme\u0000 ", "acme.com")).toBe("Acme")
  })

  test("capped at 128 characters without splitting one", () => {
    const title = saveTitle("🔐".repeat(200), "acme.com")
    expect(Array.from(title)).toHaveLength(128)
    expect(title).toBe("🔐".repeat(128))
  })

  test("the site when the page has no title", () => {
    expect(saveTitle("", "acme.com")).toBe("acme.com")
    expect(saveTitle("Sign in", "acme.com")).toBe("acme.com")
    expect(saveTitle(" \n ", "acme.com")).toBe("acme.com")
    expect(saveTitle(undefined, "acme.com")).toBe("acme.com")
  })
})

describe("saveUrl", () => {
  test("origin and path, without query or fragment", () => {
    expect(saveUrl(u("https://github.com/login?return_to=%2Fsettings#top"))).toBe("https://github.com/login")
    expect(saveUrl(u("http://localhost:3000/"))).toBe("http://localhost:3000/")
  })

  test("spaces stay encoded", () => {
    expect(saveUrl(u("https://acme.com/sign in"))).toBe("https://acme.com/sign%20in")
  })

  test("just the origin when the path is too long", () => {
    expect(saveUrl(u(`https://acme.com/${"a".repeat(3000)}`))).toBe("https://acme.com")
  })
})

describe("payment provider frames", () => {
  const provider = (url: string) => paymentProvider(new URL(url))?.name ?? null
  test("only the listed hosts, over https on the default port", () => {
    expect(provider("https://js.stripe.com/v3/elements-inner-card.html")).toBe("Stripe")
    expect(provider("https://checkoutshopper-live-us.adyen.com/checkoutshopper/securedfields/")).toBe("Adyen")
    expect(provider("https://checkout.pci.shopifyinc.com/build/card-fields")).toBe("Shopify")
    expect(provider("http://js.stripe.com/")).toBeNull()
    expect(provider("https://js.stripe.com:8443/")).toBeNull()
    expect(provider("https://evil-stripe.com/")).toBeNull()
    expect(provider("https://stripe.com.evil.test/")).toBeNull()
    // PayPal's own site takes a card only in its hosted card fields.
    expect(provider("https://www.paypal.com/smart/card-fields?sessionID=x")).toBe("PayPal")
    expect(provider("https://www.paypal.com/smart/card-field?type=number")).toBe("PayPal")
    expect(provider("https://www.paypal.com/myaccount/")).toBeNull()
    expect(provider("https://www.paypal.com/checkoutnow")).toBeNull()
    // The e2e aliases exist only in e2e builds.
    expect(provider("http://js.stripe.test:8080/")).toBeNull()
  })
  test("cards go into them only from an https page", () => {
    expect(securePage(new URL("https://shop.example/checkout"))).toBe(true)
    expect(securePage(new URL("http://localhost:3000/checkout"))).toBe(false)
  })
})

describe("sameSiteChain (a frame's login field and the inline menu)", () => {
  const chain = (...urls: string[]) => sameSiteChain(urls.map(u))

  test("a frame on the top page's site, both https", () => {
    expect(chain("https://idmsa.apple.com/appleauth/auth/signin", "https://appstoreconnect.apple.com/login")).toBe(true)
    expect(chain("https://idmsa.apple.com/", "https://www.apple.com/shell", "https://appstoreconnect.apple.com/")).toBe(true)
  })

  test("a cross-site frame is refused", () => {
    expect(chain("https://idmsa.apple.com/", "https://evil.example/")).toBe(false)
    // Private-section public suffixes are their own sites.
    expect(chain("https://kit.github.io/", "https://evil.github.io/")).toBe(false)
  })

  test("a same-site frame nested in a cross-site frame is refused", () => {
    expect(chain("https://idmsa.apple.com/", "https://ads.example.net/", "https://appstoreconnect.apple.com/")).toBe(false)
  })

  test("plain http is refused, except on local development hosts", () => {
    expect(chain("http://idmsa.apple.com/", "https://appstoreconnect.apple.com/")).toBe(false)
    expect(chain("https://idmsa.apple.com/", "http://appstoreconnect.apple.com/")).toBe(false)
    expect(chain("http://idmsa.apple.test/", "http://appstoreconnect.apple.test/")).toBe(true)
  })

  test("the top page alone isn't a frame", () => {
    expect(chain("https://appstoreconnect.apple.com/")).toBe(false)
  })
})
