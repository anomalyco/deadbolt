// device.html: the browser-only Deadbolt's own page (bg/standalone.ts), and
// the extension's options page. It shows the same views as the popup
// (src/vault), in a wider frame: setting up, unlocking, the logins and the
// settings.

import { h } from "./ui/dom"
import { mountVault } from "./vault/app"

declare const DEADBOLT_NATIVE: boolean | undefined
const native = typeof DEADBOLT_NATIVE !== "undefined" && DEADBOLT_NATIVE === true

const root = document.getElementById("app")!
if (native) {
  root.replaceChildren(h("p", { class: "muted" }, "This build talks to Deadbolt through ", h("code", {}, "deadbolt browser-host"), ". Set up and unlock Deadbolt in the app."))
} else mountVault(root, "page")
