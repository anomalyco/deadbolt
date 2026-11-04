// The payment providers whose card fields Deadbolt fills inside their own
// cross-origin frames, on an https page (docs/autofill.md, "Frames and
// payment providers"). Any other cross-origin frame gets no card, and no
// cross-origin frame gets an identity.

declare const DEADBOLT_E2E: boolean | undefined

export interface PaymentProvider {
  name: string
  /** The exact hosts its card frames load from. */
  hosts: string[]
  /** Hosts matched by pattern, for providers with regional hosts. */
  pattern?: RegExp
  /**
   * On a host that serves far more than card fields, only frames whose path
   * starts with one of these: PayPal's own site is www.paypal.com, and only
   * its hosted card fields (the JS SDK's CardFields, `/smart/card-field…`)
   * take a card. If PayPal moves them, they stop filling (fails closed).
   */
  paths?: string[]
}

export const PAYMENT_PROVIDERS: PaymentProvider[] = [
  { name: "Stripe", hosts: ["js.stripe.com"] },
  { name: "Braintree", hosts: ["assets.braintreegateway.com"] },
  { name: "PayPal", hosts: ["www.paypal.com"], paths: ["/smart/card-field"] },
  { name: "Adyen", hosts: [], pattern: /^checkoutshopper-(live|test)(-[a-z]+)?\.adyen\.com$/ },
  { name: "Checkout.com", hosts: ["js.checkout.com"] },
  { name: "Square", hosts: ["web.squarecdn.com", "sandbox.web.squarecdn.com", "pci-connect.squareup.com"] },
  { name: "Shopify", hosts: ["checkout.pci.shopifyinc.com"] },
]

function matches(p: PaymentProvider, host: string, path: string): boolean {
  return (p.hosts.includes(host) || !!p.pattern?.test(host)) && (!p.paths || p.paths.some((x) => path.startsWith(x)))
}

/**
 * The provider a frame at `url` belongs to: https, the default port, one of
 * its hosts. An e2e build also takes the same host with `.test` for `.com`
 * over http on any port (e2e/run.ts maps it to its own server).
 */
export function paymentProvider(url: URL): PaymentProvider | null {
  const host = url.hostname.toLowerCase()
  if (url.protocol === "https:" && !url.port) {
    const p = PAYMENT_PROVIDERS.find((x) => matches(x, host, url.pathname))
    if (p) return p
  }
  // DEADBOLT_E2E is true only in an e2e build (scripts/build.ts --e2e); every
  // other build defines it false, and this branch drops out of its code.
  if (typeof DEADBOLT_E2E !== "undefined" && DEADBOLT_E2E === true && host.endsWith(".test"))
    return PAYMENT_PROVIDERS.find((x) => matches(x, `${host.slice(0, -5)}.com`, url.pathname)) ?? null
  return null
}

/** A page that may hand a card to a provider's frame: https, or in an e2e build, a local http host. */
export function securePage(url: URL): boolean {
  if (url.protocol === "https:") return true
  return typeof DEADBOLT_E2E !== "undefined" && DEADBOLT_E2E === true && url.protocol === "http:" && (url.hostname === "localhost" || url.hostname.endsWith(".test"))
}

/** Whether a card number passes the Luhn check, as every real one does. */
export function luhn(number: string): boolean {
  const d = number.replace(/\D/g, "")
  let sum = 0
  for (let i = 0; i < d.length; i++) {
    let n = +d[d.length - 1 - i]
    if (i % 2) n = n * 2 > 9 ? n * 2 - 9 : n * 2
    sum += n
  }
  return d.length > 0 && sum % 10 === 0
}

/** The brand a card number's first digits say, for the commonest ones. */
export function cardBrand(number: string): string | undefined {
  const d = number.replace(/\D/g, "")
  if (/^4/.test(d)) return "Visa"
  if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(d)) return "Mastercard"
  if (/^3[47]/.test(d)) return "American Express"
  if (/^6(011|5|4[4-9])/.test(d)) return "Discover"
  if (/^35(2[89]|[3-8])/.test(d)) return "JCB"
  if (/^3(0[0-5]|[689])/.test(d)) return "Diners Club"
  if (/^62/.test(d)) return "UnionPay"
  return undefined
}
