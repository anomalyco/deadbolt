// Development only: open a page with `?motion-lint` to record its stories for motion-lint (motion-lint-live.ts),
// or `?motion-lint=hitches` to record only late frames. Imported once from Story.tsx; without the query it does
// nothing, and production builds drop it.
if (import.meta.env.DEV && typeof location !== "undefined" && new URLSearchParams(location.search).has("motion-lint")) {
  void import("./motion-lint-live").then(m => m.install(new URLSearchParams(location.search).get("motion-lint") ?? ""))
}

export {}
