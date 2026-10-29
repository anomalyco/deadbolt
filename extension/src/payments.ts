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
}

export const PAYMENT_PROVIDERS: PaymentProvider[] = [
  { name: "Stripe", hosts: ["js.stripe.com"] },
  { name: "Braintree", hosts: ["assets.braintreegateway.com"] },
  { name: "PayPal", hosts: ["www.paypal.com"] },
  { name: "Adyen", hosts: [], pattern: /^checkoutshopper-(live|test)(-[a-z]+)?\.adyen\.com$/ },
  { name: "Checkout.com", hosts: ["js.checkout.com"] },
  { name: "Square", hosts: ["web.squarecdn.com", "sandbox.web.squarecdn.com", "pci-connect.squareup.com"] },
  { name: "Shopify", hosts: ["checkout.pci.shopifyinc.com"] },
]

function matches(p: PaymentProvider, host: string): boolean {
  return p.hosts.includes(host) || !!p.pattern?.test(host)
}

/**
 * The provider a frame at `url` belongs to: https, the default port, one of
 * its hosts. An e2e build also takes the same host with `.test` for `.com`
 * over http on any port (e2e/run.ts maps it to its own server).
 */
export function paymentProvider(url: URL): PaymentProvider | null {
  const host = url.hostname.toLowerCase()
  if (url.protocol === "https:" && !url.port) {
    const p = PAYMENT_PROVIDERS.find((x) => matches(x, host))
    if (p) return p
  }
  // DEADBOLT_E2E is true only in an e2e build (scripts/build.ts --e2e); every
  // other build defines it false, and this branch drops out of its code.
  if (typeof DEADBOLT_E2E !== "undefined" && DEADBOLT_E2E === true && host.endsWith(".test"))
    return PAYMENT_PROVIDERS.find((x) => matches(x, `${host.slice(0, -5)}.com`)) ?? null
  return null
}

/** A page that may hand a card to a provider's frame: https, or in an e2e build, a local http host. */
export function securePage(url: URL): boolean {
  if (url.protocol === "https:") return true
  return typeof DEADBOLT_E2E !== "undefined" && DEADBOLT_E2E === true && url.protocol === "http:" && (url.hostname === "localhost" || url.hostname.endsWith(".test"))
}
