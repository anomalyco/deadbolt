import { resolve } from "node:path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import { changelog } from "./scripts/changelog"

// Five pages: the landing page, the architecture walkthrough, the changelog (with its feeds, built from the repo's
// changelog/ folder), the original static mock, and the Deadbolt Send receive page (/r).
export default defineConfig({
  plugins: [react(), changelog(resolve(import.meta.dirname, "../changelog"))],
  // Tailscale Serve proxies https://<machine>.<tailnet>.ts.net:5197 here (tailnet only).
  server: { host: "127.0.0.1", port: Number(process.env.PORT) || 5197, strictPort: true, allowedHosts: [".ts.net"] },
  // knobs peers on React, so keep a single copy in the bundle.
  resolve: { dedupe: ["react", "react-dom"] },
  build: {
    rollupOptions: {
      input: {
        index: resolve(import.meta.dirname, "index.html"),
        architecture: resolve(import.meta.dirname, "architecture/index.html"),
        changelog: resolve(import.meta.dirname, "changelog.html"),
        mock: resolve(import.meta.dirname, "mock.html"),
        r: resolve(import.meta.dirname, "r.html"),
      },
    },
  },
})
